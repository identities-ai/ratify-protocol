package iambridge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPPublisherClassifiesDefinitiveRejection(t *testing.T) {
	for _, status := range []int{400, 403, 409, 503} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		publisher := HTTPPublisher{Client: server.Client(), URL: server.URL, APIKey: "receiver-secret"}
		err := publisher.Publish(context.Background(), []byte("wire"))
		server.Close()
		if errors.Is(err, ErrDefinitivePublication) != (status != 503) {
			t.Fatalf("HTTP %d classification: %v", status, err)
		}
	}
}

func TestHTTPPublisherClassifiesRefreshableConflict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":{"code":"status_publication_refresh_required"}}`))
	}))
	defer server.Close()
	publisher := HTTPPublisher{Client: server.Client(), URL: server.URL}
	if err := publisher.Publish(context.Background(), []byte("wire")); !errors.Is(err, ErrRefreshRequired) {
		t.Fatalf("refreshable status conflict was blocked: %v", err)
	}
}

func TestHTTPPublisherRetriesClockAhead(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":{"code":"status_publication_clock_ahead"}}`))
	}))
	defer server.Close()
	publisher := HTTPPublisher{Client: server.Client(), URL: server.URL}
	if err := publisher.Publish(context.Background(), []byte("wire")); !errors.Is(err, ErrClockAhead) {
		t.Fatalf("clock-ahead status should retry after correction: %v", err)
	}
}

func TestReferenceHTTPBridgeUsesAuthenticatedSnapshotAndReceiverPublication(t *testing.T) {
	bridge, _, _, _ := testBridge(t)
	var publishes, statusReads int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/iam":
			if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer source-secret" {
				t.Errorf("IAM source request was not authenticated")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer_id": bridge.IssuerID, "revision": "42", "complete": true,
				"observed_at":      bridge.Now().UTC().Format(time.RFC3339),
				"revoked_cert_ids": []string{"parent-cert"},
			})
		case "/v1/verify/v2/status-lists":
			if r.Method != http.MethodPost || r.Header.Get("X-Ratify-API-Key") != "receiver-secret" {
				t.Errorf("Verify publication did not use the receiver credential")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			var body struct {
				IssuerID    string `json:"issuer_id"`
				Epoch       uint64 `json:"epoch"`
				PublisherID string `json:"publisher_id"`
				List        []byte `json:"list"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IssuerID != bridge.IssuerID ||
				body.Epoch != 1 || body.PublisherID != "iam-bridge-0123456789abcdef0123456789abcdef" || !strings.Contains(string(body.List), "parent-cert") {
				t.Errorf("publication lost its issuer, epoch, or exact grant: %+v %v", body, err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			publishes++
			_ = json.NewEncoder(w).Encode(map[string]bool{"published": true})
		case "/v1/verify/v2/status":
			if r.Method != http.MethodGet || r.Header.Get("X-Ratify-API-Key") != "receiver-secret" {
				t.Errorf("Verify status read did not use the receiver credential")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			statusReads++
			_, _ = w.Write([]byte(`{"receiver_id":"r","state":"unobserved","status_checkpoint":{"sequence":1,"digest":"head"},"issuers":[{"issuer_id":"` +
				strings.Repeat("b", 64) + `","status_key_epoch":1,"sequence":9},{"issuer_id":"` + bridge.IssuerID +
				`","status_key_epoch":1,"sequence":null,"max_observed_sequence":0,"updated_at":null,"next_update":null,"state":"unobserved"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	store := &FileState{Path: filepath.Join(t.TempDir(), "state.json")}
	if err := store.Lock(); err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	other := &FileState{Path: store.Path}
	if err := other.Lock(); err == nil {
		_ = other.Close()
		t.Fatal("a second bridge writer acquired the same state")
	}
	bridge.Store = store
	bridge.Source = HTTPSource{Client: server.Client(), URL: server.URL + "/iam", Token: "source-secret"}
	bridge.Publisher = HTTPPublisher{Client: server.Client(), URL: server.URL + "/v1/verify/v2/status-lists",
		APIKey: "receiver-secret", IssuerID: bridge.IssuerID, Epoch: 1, PublisherID: "iam-bridge-0123456789abcdef0123456789abcdef"}
	bridge.Status = HTTPStatusReader{Client: server.Client(), URL: server.URL + "/v1/verify/v2/status",
		APIKey: "receiver-secret", IssuerID: bridge.IssuerID}
	if err := bridge.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if publishes != 1 || statusReads != 1 {
		t.Fatalf("expected one accepted publication, got %d", publishes)
	}
	state, err := store.Load()
	if err != nil || state.Sequence != 1 || state.Pending != nil || len(state.Revoked) != 1 {
		t.Fatalf("accepted list was not durably committed: %+v %v", state, err)
	}
}

func TestHTTPPublisherClassifiesLeaseOutcomes(t *testing.T) {
	for code, want := range map[string]error{
		"status_publisher_conflict":   ErrPublisherConflict,
		"status_publisher_superseded": ErrDefinitivePublication,
		"status_publication_conflict": ErrDefinitivePublication,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":{"code":"` + code + `"}}`))
		}))
		err := HTTPPublisher{Client: server.Client(), URL: server.URL}.Publish(context.Background(), []byte("wire"))
		server.Close()
		if !errors.Is(err, want) || code == "status_publisher_conflict" && errors.Is(err, ErrDefinitivePublication) {
			t.Fatalf("%s classified as %v", code, err)
		}
	}
}

func TestHTTPPublisherReleasesOnlyItsOwnLease(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/release" || r.Header.Get("X-Ratify-API-Key") != "receiver-secret" ||
			json.NewDecoder(r.Body).Decode(&got) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"released":true}`))
	}))
	defer server.Close()
	publisher := HTTPPublisher{Client: server.Client(), APIKey: "receiver-secret", IssuerID: "issuer", Epoch: 3,
		PublisherID: "iam-bridge-0123456789abcdef0123456789abcdef"}
	if err := publisher.Release(context.Background(), server.URL+"/release"); err != nil {
		t.Fatal(err)
	}
	if got["publisher_id"] != "iam-bridge-0123456789abcdef0123456789abcdef" || got["epoch"] != float64(3) || got["issuer_id"] != "issuer" {
		t.Fatalf("release did not name this publisher: %+v", got)
	}
}

func TestHTTPStatusReaderRequiresTheBoundIssuer(t *testing.T) {
	digest := "sha384:" + strings.Repeat("d", 96)
	for issuers, wantErr := range map[string]bool{
		`{"issuers":[]}`: true,
		`{"issuers":[{"issuer_id":"i","status_key_epoch":2,"sequence":4,"max_observed_sequence":5,"accepted_list_digest":"` + digest + `"}]}`: false,
		`{"issuers":[{"issuer_id":"i","status_key_epoch":2},{"issuer_id":"i","status_key_epoch":3}]}`:                                         true,
		// Missing or inconsistent checkpoint fields are never read as zero.
		`{"issuers":[{"issuer_id":"i","status_key_epoch":2,"sequence":4,"accepted_list_digest":"` + digest + `"}]}`:                           true,
		`{"issuers":[{"issuer_id":"i","status_key_epoch":2,"sequence":6,"max_observed_sequence":5,"accepted_list_digest":"` + digest + `"}]}`: true,
		`{"issuers":[{"issuer_id":"i","status_key_epoch":2,"sequence":4,"max_observed_sequence":5,"accepted_list_digest":"sha384:d"}]}`:       true,
		`{"issuers":[{"issuer_id":"i","status_key_epoch":2,"max_observed_sequence":5,"accepted_list_digest":"` + digest + `"}]}`:              true,
		`{"issuers":[{"issuer_id":"i","sequence":4,"max_observed_sequence":5}]}`:                                                              true,
		`{"issuers":[{"issuer_id":"i","status_key_epoch":2,"max_observed_sequence":0}]}`:                                                      true,
		`{"issuers":[{"issuer_id":"i","status_key_epoch":2,"sequence":null,"max_observed_sequence":0}]}`:                                      false,
	} {
		body := strings.Replace(issuers, `{"issuers"`, `{"status_checkpoint":{"sequence":3,"digest":"head"},"issuers"`, 1)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		remote, err := HTTPStatusReader{Client: server.Client(), URL: server.URL, IssuerID: "i"}.IssuerStatus(context.Background())
		server.Close()
		if (err != nil) != wantErr || !wantErr && remote.HasFloor && remote != (RemoteStatus{Epoch: 2, HasFloor: true, Floor: 4, MaxObserved: 5, AcceptedDigest: digest}) {
			t.Fatalf("%s: %+v %v", body, remote, err)
		}
	}
}

func TestHTTPStatusReaderRequiresCheckpointBinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuers":[{"issuer_id":"i","status_key_epoch":2,"sequence":null,"max_observed_sequence":0}]}`))
	}))
	defer server.Close()
	if _, err := (HTTPStatusReader{Client: server.Client(), URL: server.URL, IssuerID: "i"}).IssuerStatus(context.Background()); err == nil {
		t.Fatal("status without a checkpoint binding was accepted")
	}
}

// Verify's 409 has several causes. Only status_publication_conflict starts
// stale-sequence reconciliation; status_key_not_bound and a 409 without a
// known code stay definite refusals.
func TestHTTPPublisherDistinguishesConflictCodes(t *testing.T) {
	for code, stale := range map[string]bool{"status_publication_conflict": true, "status_key_not_bound": false,
		"status_publisher_superseded": false, "status_revocation_omitted": false, "": false} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":{"code":"` + code + `"}}`))
		}))
		err := HTTPPublisher{Client: server.Client(), URL: server.URL}.Publish(context.Background(), []byte("wire"))
		server.Close()
		if errors.Is(err, ErrSequenceConflict) != stale || !errors.Is(err, ErrDefinitivePublication) ||
			errors.Is(err, ErrRevocationOmitted) != (code == "status_revocation_omitted") {
			t.Fatalf("409 %q classified as %v", code, err)
		}
	}
}

// The receiver API key is sent only to the configured Verify URL: a
// redirect is never followed, so another host cannot collect the key.
func TestHTTPHelpersDoNotFollowRedirects(t *testing.T) {
	var leaked atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked.Add(1) }))
	defer elsewhere.Close()
	verify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer verify.Close()
	publisher := HTTPPublisher{Client: verify.Client(), URL: verify.URL + "/status-lists", APIKey: "receiver-secret"}
	if err := publisher.Publish(context.Background(), []byte("{}")); err == nil {
		t.Fatal("a redirected publication was reported as accepted")
	}
	if err := publisher.Release(context.Background(), verify.URL+"/release"); err == nil {
		t.Fatal("a redirected release was reported as accepted")
	}
	reader := HTTPStatusReader{Client: verify.Client(), URL: verify.URL + "/status", APIKey: "receiver-secret"}
	if _, err := reader.IssuerStatus(context.Background()); err == nil {
		t.Fatal("a redirected status read was reported as read")
	}
	if n := leaked.Load(); n != 0 {
		t.Fatalf("%d requests followed a redirect to another host", n)
	}
}
