package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// The bodies below are shaped like the Okta Management API responses
// documented at developer.okta.com (Users: getUser; Application Users:
// getApplicationUser; Applications: getApplication; error E0000007). Only
// the fields this source reads matter; the extra fields show it tolerates a
// full Okta object.
const (
	testIssuer = "4f0b5c6a8d7e9f1023456789abcdef0123456789abcdef0123456789abcdef01"
	testApp    = "0oa19z92pnbs25iCd698"
	testToken  = "okta-api-token-for-tests"
)

func oktaUser(id, login, status string) string {
	return `{"id":"` + id + `","status":"` + status + `","created":"2026-11-01T00:00:00.000Z",` +
		`"activated":"2026-11-01T00:00:00.000Z","statusChanged":"2026-11-02T00:00:00.000Z",` +
		`"profile":{"login":"` + login + `","email":"` + login + `","firstName":"A","lastName":"B"},` +
		`"type":{"id":"oty1"},"_links":{"self":{"href":"https://example.okta.com/api/v1/users/` + id + `"}}}`
}

const oktaNotFound = `{"errorCode":"E0000007","errorSummary":"Not found: Resource not found: x (User)",` +
	`"errorLink":"E0000007","errorId":"oae1","errorCauses":[]}`

// fakeOkta serves recorded Okta responses and records every request.
type fakeOkta struct {
	mu        sync.Mutex
	users     map[string]string // path id -> body; missing = 404
	assigned  map[string]bool   // user id -> assigned to testApp
	appStatus string
	appUser   map[string]string // user id -> application user status (default ACTIVE)
	appReads  int
	appGoneAt int    // when non-zero, the app answers 404 from this read on
	fail      string // a path prefix that answers 500
	status    int    // when non-zero, every request answers this
	requests  []string
	auth      []string
}

func newFakeOkta() *fakeOkta {
	return &fakeOkta{appStatus: "ACTIVE", users: map[string]string{
		"00u1alice": oktaUser("00u1alice", "alice@example.com", "ACTIVE"),
		"00u2bob":   oktaUser("00u2bob", "bob@example.com", "ACTIVE"),
	}, assigned: map[string]bool{"00u1alice": true, "00u2bob": true}}
}

func (f *fakeOkta) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	w.Header().Set("Content-Type", "application/json")
	if f.status != 0 {
		w.WriteHeader(f.status)
		_, _ = w.Write([]byte(`{"errorCode":"E0000047","errorSummary":"API call exceeded rate limit"}`))
		return
	}
	if f.fail != "" && strings.HasPrefix(r.URL.Path, f.fail) {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	switch {
	case path == "apps/"+testApp:
		f.appReads++
		if f.appGoneAt != 0 && f.appReads >= f.appGoneAt {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(oktaNotFound))
			return
		}
		_, _ = w.Write([]byte(`{"id":"` + testApp + `","name":"oidc_client","label":"Ratify Verify SSO","status":"` + f.appStatus + `"}`))
	case strings.HasPrefix(path, "apps/"+testApp+"/users/"):
		id := strings.TrimPrefix(path, "apps/"+testApp+"/users/")
		if !f.assigned[id] {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(oktaNotFound))
			return
		}
		status := "ACTIVE"
		if f.appUser[id] != "" {
			status = f.appUser[id]
		}
		_, _ = w.Write([]byte(`{"id":"` + id + `","scope":"GROUP","status":"` + status + `","credentials":{"userName":"x"}}`))
	case strings.HasPrefix(path, "apps/"):
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(oktaNotFound))
	case strings.HasPrefix(path, "users/"):
		body, ok := f.users[strings.TrimPrefix(path, "users/")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(oktaNotFound))
			return
		}
		_, _ = w.Write([]byte(body))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeOkta) set(fn func(*fakeOkta)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

type fixture struct {
	okta   *fakeOkta
	source *oktaSource
	state  string
	now    time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{okta: newFakeOkta(), now: time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)}
	server := httptest.NewTLSServer(f.okta)
	t.Cleanup(server.Close)
	f.state = filepath.Join(t.TempDir(), "revoked.json")
	if err := initState(f.state, testIssuer); err != nil {
		t.Fatal(err)
	}
	f.source = &oktaSource{OrgURL: server.URL, Token: testToken, AppIDs: []string{testApp},
		IssuerID: testIssuer, StatePath: f.state, Client: noRedirectClient(server.Client()),
		Mapping: map[string]string{"cert-alice": "00u1alice", "cert-bob": "00u2bob"},
		Now:     func() time.Time { return f.now }}
	return f
}

func (f *fixture) snapshot(t *testing.T) snapshot {
	t.Helper()
	got, err := f.source.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return got
}

// Everyone active and assigned: a complete snapshot with nothing revoked,
// read with the SSWS API token scheme Okta documents for API tokens.
func TestOktaSourceActiveAssignedUsersAreNotRevoked(t *testing.T) {
	f := newFixture(t)
	got := f.snapshot(t)
	if got.IssuerID != testIssuer || !got.Complete || len(got.RevokedCertIDs) != 0 || got.Revision == "" {
		t.Fatalf("snapshot = %+v", got)
	}
	for _, header := range f.okta.auth {
		if header != "SSWS "+testToken {
			t.Fatalf("Okta authorization header = %q", header)
		}
	}
	for _, request := range f.okta.requests {
		if !strings.HasPrefix(request, "GET ") {
			t.Fatalf("source must be read-only, sent %s", request)
		}
	}
}

// Each IdP fact that ends a person's authority revokes exactly that person's
// certificate: deactivation, suspension, unassignment, and deletion.
func TestOktaSourceRevokesDeactivatedSuspendedUnassignedAndDeletedUsers(t *testing.T) {
	for name, change := range map[string]func(*fakeOkta){
		"deactivated": func(o *fakeOkta) { o.users["00u2bob"] = oktaUser("00u2bob", "bob@example.com", "DEPROVISIONED") },
		"suspended":   func(o *fakeOkta) { o.users["00u2bob"] = oktaUser("00u2bob", "bob@example.com", "SUSPENDED") },
		"unassigned":  func(o *fakeOkta) { delete(o.assigned, "00u2bob") },
		"deleted":     func(o *fakeOkta) { delete(o.users, "00u2bob") },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.okta.set(change)
			if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
				t.Fatalf("revoked = %v, want only cert-bob", got.RevokedCertIDs)
			}
		})
	}
}

// Temporary account states are not a revocation: Protocol revocation is
// permanent, so a lockout or password expiry must not end a grant forever.
func TestOktaSourceTemporaryStatesDoNotRevoke(t *testing.T) {
	for _, status := range []string{"LOCKED_OUT", "PASSWORD_EXPIRED", "RECOVERY", "PROVISIONED", "STAGED"} {
		f := newFixture(t)
		f.okta.set(func(o *fakeOkta) { o.users["00u2bob"] = oktaUser("00u2bob", "bob@example.com", status) })
		if got := f.snapshot(t); len(got.RevokedCertIDs) != 0 {
			t.Fatalf("%s revoked %v", status, got.RevokedCertIDs)
		}
	}
}

// A revocation survives the user's reactivation and reassignment, and a
// certificate ID dropped from the mapping stays revoked. Regrant needs a new
// certificate ID.
func TestOktaSourceNeverOmitsAPreviouslyRevokedID(t *testing.T) {
	f := newFixture(t)
	f.okta.set(func(o *fakeOkta) { delete(o.assigned, "00u2bob") })
	f.snapshot(t)
	f.okta.set(func(o *fakeOkta) { o.assigned["00u2bob"] = true })
	delete(f.source.Mapping, "cert-bob")
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("revoked = %v after reassignment and unmapping", got.RevokedCertIDs)
	}
	// A restarted source reads the same retained set from its state file.
	restarted := &oktaSource{OrgURL: f.source.OrgURL, Token: testToken, AppIDs: f.source.AppIDs,
		IssuerID: testIssuer, StatePath: f.state, Client: f.source.Client, Now: f.source.Now,
		Mapping: map[string]string{"cert-alice": "00u1alice"}}
	got, err := restarted.Snapshot(context.Background())
	if err != nil || !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("restarted revoked = %v %v", got.RevokedCertIDs, err)
	}
}

// Any Okta failure yields no snapshot at all, never a partial one: rate
// limits, server errors, a bad token, a wrong or inactive app, an unknown
// user status, or a user record that is not the mapped person.
func TestOktaSourceFailsClosedOnAnyOktaError(t *testing.T) {
	cases := map[string]func(*fakeOkta, *oktaSource){
		"rate limited":     func(o *fakeOkta, _ *oktaSource) { o.status = http.StatusTooManyRequests },
		"invalid token":    func(o *fakeOkta, _ *oktaSource) { o.status = http.StatusUnauthorized },
		"forbidden":        func(o *fakeOkta, _ *oktaSource) { o.status = http.StatusForbidden },
		"user read error":  func(o *fakeOkta, _ *oktaSource) { o.fail = "/api/v1/users/00u2bob" },
		"assignment error": func(o *fakeOkta, _ *oktaSource) { o.fail = "/api/v1/apps/" + testApp + "/users/00u2bob" },
		"app missing":      func(_ *fakeOkta, s *oktaSource) { s.AppIDs = []string{"0oaMISSING"} },
		"app inactive":     func(o *fakeOkta, _ *oktaSource) { o.appStatus = "INACTIVE" },
		"unknown status": func(o *fakeOkta, _ *oktaSource) {
			o.users["00u2bob"] = oktaUser("00u2bob", "bob@example.com", "NEW_STATE")
		},
		"different person": func(o *fakeOkta, _ *oktaSource) {
			o.users["00u2bob"] = oktaUser("00u9eve", "eve@example.com", "ACTIVE")
		},
		"not JSON": func(o *fakeOkta, _ *oktaSource) { o.users["00u2bob"] = `<html>login</html>` },
		"trailing JSON": func(o *fakeOkta, _ *oktaSource) {
			o.users["00u2bob"] = oktaUser("00u2bob", "bob@example.com", "ACTIVE") + `{}`
		},
		"redirect to login": func(o *fakeOkta, _ *oktaSource) { o.status = http.StatusFound },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.okta.set(func(o *fakeOkta) { change(o, f.source) })
			if got, err := f.source.Snapshot(context.Background()); err == nil {
				t.Fatalf("returned a snapshot during an Okta failure: %+v", got)
			}
		})
	}
}

// observed_at is taken after the last Okta read, not before it and not from
// a cache: every request is a fresh authoritative read.
func TestOktaSourceObservedAtIsTakenAfterTheRead(t *testing.T) {
	f := newFixture(t)
	start := f.now
	reads := 0
	f.source.Now = func() time.Time { return start.Add(time.Duration(reads) * time.Second) }
	f.source.Client.Transport = countingTransport{base: f.source.Client.Transport, n: &reads}
	got := f.snapshot(t)
	if reads == 0 || !got.ObservedAt.Equal(start.Add(time.Duration(reads)*time.Second)) {
		t.Fatalf("observed_at %v after %d reads", got.ObservedAt, reads)
	}
	before := reads
	f.snapshot(t)
	if reads != 2*before {
		t.Fatalf("second snapshot made %d reads, want a fresh full read of %d", reads-before, before)
	}
}

type countingTransport struct {
	base http.RoundTripper
	n    *int
}

func (c countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	*c.n++
	return c.base.RoundTrip(r)
}

// The state file belongs to one issuer; a file for another issuer is refused.
func TestOktaSourceStateIsBoundToTheIssuer(t *testing.T) {
	f := newFixture(t)
	f.source.IssuerID = strings.Repeat("a", 64)
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("used another issuer's state")
	}
	if err := initState(f.state, testIssuer); err == nil {
		t.Fatal("init overwrote an existing state file")
	}
	// A lost state file is not silently recreated empty.
	if err := os.Remove(f.state); err != nil {
		t.Fatal(err)
	}
	if err := initState(f.state, testIssuer); err == nil {
		t.Fatal("init recreated a lost state file")
	}
}

// The HTTP endpoint is the bridge's source contract: bearer-authenticated
// GET, the exact snapshot JSON fields, and no snapshot (503) on failure.
func TestOktaSourceHandlerServesTheBridgeContract(t *testing.T) {
	f := newFixture(t)
	handler := snapshotHandler(f.source, "bridge-bearer")
	call := func(method, auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/v1/revoked-cert-ids", nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, auth := range []string{"", "Bearer wrong", "bridge-bearer", "Basic bridge-bearer"} {
		if w := call(http.MethodGet, auth); w.Code != http.StatusUnauthorized {
			t.Fatalf("auth %q answered %d", auth, w.Code)
		}
	}
	if w := call(http.MethodPost, "Bearer bridge-bearer"); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST answered %d", w.Code)
	}
	f.okta.set(func(o *fakeOkta) { delete(o.assigned, "00u2bob") })
	w := call(http.MethodGet, "Bearer bridge-bearer")
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("GET answered %d %v", w.Code, w.Header())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for k := range body {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"complete", "issuer_id", "observed_at", "revision", "revoked_cert_ids"}) ||
		body["complete"] != true || body["issuer_id"] != testIssuer || body["observed_at"] != "2026-11-17T12:00:00Z" {
		t.Fatalf("body = %s", w.Body.String())
	}
	f.okta.set(func(o *fakeOkta) { o.status = http.StatusTooManyRequests })
	if w := call(http.MethodGet, "Bearer bridge-bearer"); w.Code != http.StatusServiceUnavailable ||
		strings.Contains(w.Body.String(), "revoked") {
		t.Fatalf("Okta failure answered %d %s", w.Code, w.Body.String())
	}
}

func TestOktaSourceConfigRequiresHTTPSAndSecretsFromEnv(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, v any) string {
		data, _ := json.Marshal(v)
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	mapping := write("mapping.json", map[string]string{"cert-alice": "00u1alice"})
	good := map[string]any{"issuer_id": testIssuer, "okta_org_url": "https://example.okta.com",
		"app_ids": []string{testApp}, "mapping_file": mapping, "state_file": filepath.Join(dir, "state.json"),
		"listen_addr": "127.0.0.1:0", "tls_cert_file": "c.pem", "tls_key_file": "k.pem"}
	env := map[string]string{"OKTA_API_TOKEN": "t", "IAM_SOURCE_BEARER_TOKEN": "b"}
	getenv := func(k string) string { return env[k] }
	if _, _, err := loadConfig(write("good.json", good), getenv); err != nil {
		t.Fatalf("good config: %v", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"http okta":       func(c map[string]any) { c["okta_org_url"] = "http://example.okta.com" },
		"okta path":       func(c map[string]any) { c["okta_org_url"] = "https://example.okta.com/api" },
		"no apps":         func(c map[string]any) { c["app_ids"] = []string{} },
		"bad issuer":      func(c map[string]any) { c["issuer_id"] = "ISSUER" },
		"no tls":          func(c map[string]any) { delete(c, "tls_cert_file") },
		"unknown field":   func(c map[string]any) { c["okta_api_token"] = "inline" },
		"bad app id":      func(c map[string]any) { c["app_ids"] = []string{"../users"} },
		"missing mapping": func(c map[string]any) { c["mapping_file"] = filepath.Join(dir, "none.json") },
		"trailing mapping": func(c map[string]any) {
			path := filepath.Join(dir, "trailing.json")
			_ = os.WriteFile(path, []byte(`{"cert-alice":"00u1alice"}{"cert-bob":"00u2bob"}`), 0600)
			c["mapping_file"] = path
		},
		"repeated cert id": func(c map[string]any) {
			path := filepath.Join(dir, "repeated.json")
			_ = os.WriteFile(path, []byte(`{"cert-alice":"00u1alice","cert-alice":"00u2bob"}`), 0600)
			c["mapping_file"] = path
		},
		"login mapping": func(c map[string]any) {
			c["mapping_file"] = write("login-mapping.json", map[string]string{"cert-alice": "alice@example.com"})
		},
	} {
		bad := map[string]any{}
		for k, v := range good {
			bad[k] = v
		}
		mutate(bad)
		if _, _, err := loadConfig(write(name+".json", bad), getenv); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	delete(env, "OKTA_API_TOKEN")
	if _, _, err := loadConfig(write("good2.json", good), getenv); err == nil {
		t.Fatal("accepted a config without OKTA_API_TOKEN")
	}
}

// A certificate removed from the mapping while still active keeps being
// checked against its Okta user, so the snapshot stays complete; a mapping
// that moves a certificate ID to another person is refused.
func TestOktaSourceKeepsCheckingUnmappedActiveCertificates(t *testing.T) {
	f := newFixture(t)
	f.snapshot(t)
	delete(f.source.Mapping, "cert-bob")
	if got := f.snapshot(t); len(got.RevokedCertIDs) != 0 {
		t.Fatalf("unmapping revoked %v", got.RevokedCertIDs)
	}
	f.okta.set(func(o *fakeOkta) { delete(o.assigned, "00u2bob") })
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("revoked = %v after unassigning an unmapped certificate's user", got.RevokedCertIDs)
	}
	f.source.Mapping["cert-alice"] = "00u2bob"
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("accepted a mapping that moves a certificate ID to another user")
	}
}

// One source process owns a state file; a second is refused rather than
// racing it and overwriting retained revocations.
func TestOktaSourceStateHasOneWriter(t *testing.T) {
	f := newFixture(t)
	first, err := lockState(f.state)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := lockState(f.state); err == nil {
		second.Close()
		t.Fatal("a second source locked the same state")
	}
	first.Close()
	again, err := lockState(f.state)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	again.Close()
}

// Mapping edits take effect on the next snapshot without a restart, and a
// mapping first seen during a failed read stays tracked after it is removed.
func TestOktaSourceReloadsMappingAndTracksItBeforeReading(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(t.TempDir(), "mapping.json")
	write := func(m map[string]string) {
		data, _ := json.Marshal(m)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	f.source.MappingFile = path
	write(map[string]string{"cert-alice": "00u1alice"})
	f.snapshot(t)
	f.okta.set(func(o *fakeOkta) { delete(o.assigned, "00u2bob"); o.fail = "/api/v1/users/00u2bob" })
	write(map[string]string{"cert-alice": "00u1alice", "cert-bob": "00u2bob"})
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("snapshot succeeded during an Okta error")
	}
	write(map[string]string{"cert-alice": "00u1alice"})
	f.okta.set(func(o *fakeOkta) { o.fail = "" })
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("revoked = %v; a mapping seen only during a failed read was lost", got.RevokedCertIDs)
	}
	write(map[string]string{"cert-alice": "alice@example.com"})
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("served a snapshot with an invalid mapping file")
	}
}

// A mapping edited while Okta is being read yields no snapshot.
func TestOktaSourceRefusesAMappingEditedDuringTheRead(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(t.TempDir(), "mapping.json")
	_ = os.WriteFile(path, []byte(`{"cert-alice":"00u1alice"}`), 0600)
	f.source.MappingFile = path
	f.source.Client.Transport = editingTransport{base: f.source.Client.Transport, edit: func() {
		_ = os.WriteFile(path, []byte(`{"cert-alice":"00u1alice","cert-bob":"00u2bob"}`), 0600)
	}}
	if got, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatalf("served %+v although the mapping changed during the read", got)
	}
}

type editingTransport struct {
	base http.RoundTripper
	edit func()
}

func (e editingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == "/api/v1/users/00u1alice" { // after the mapping was read
		e.edit()
	}
	return e.base.RoundTrip(r)
}

// A revocation observed before a later Okta error is kept, even though that
// request serves no snapshot, so reactivating the user cannot regrant it.
func TestOktaSourceKeepsRevocationsObservedBeforeAFailure(t *testing.T) {
	f := newFixture(t)
	f.okta.set(func(o *fakeOkta) { delete(o.assigned, "00u1alice"); o.fail = "/api/v1/users/00u2bob" })
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("snapshot succeeded during an Okta error")
	}
	f.okta.set(func(o *fakeOkta) { o.assigned["00u1alice"] = true; o.fail = "" })
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-alice"}) {
		t.Fatalf("revoked = %v after reassigning a user revoked during a failed read", got.RevokedCertIDs)
	}
}

// A state file without its initialization marker is never served.
func TestOktaSourceRequiresTheInitializationMarker(t *testing.T) {
	f := newFixture(t)
	if err := os.Truncate(f.state+".lock", 0); err != nil {
		t.Fatal(err)
	}
	if lock, err := lockState(f.state); err == nil {
		lock.Close()
		t.Fatal("served state without the initialization marker")
	}
}

// A mapping edit that fails a read still keeps the revocations it observed.
func TestOktaSourceKeepsRevocationsWhenTheMappingChangesMidRead(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(t.TempDir(), "mapping.json")
	_ = os.WriteFile(path, []byte(`{"cert-alice":"00u1alice","cert-bob":"00u2bob"}`), 0600)
	f.source.MappingFile = path
	f.okta.set(func(o *fakeOkta) { delete(o.assigned, "00u1alice") })
	f.source.Client.Transport = editingTransport{base: f.source.Client.Transport, edit: func() {
		_ = os.WriteFile(path, []byte(`{"cert-alice":"00u1alice","cert-bob":"00u2bob","cert-x":"00u2bob"}`), 0600)
	}}
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("served a snapshot although the mapping changed")
	}
	f.source.Client.Transport = f.source.Client.Transport.(editingTransport).base
	_ = os.WriteFile(path, []byte(`{"cert-alice":"00u1alice","cert-bob":"00u2bob"}`), 0600)
	f.okta.set(func(o *fakeOkta) { o.assigned["00u1alice"] = true })
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-alice"}) {
		t.Fatalf("revoked = %v; a revocation observed before a mapping edit was lost", got.RevokedCertIDs)
	}
}

// Certificates of one Okta user are decided from a single read of that
// user, so one observed suspension revokes all of them together.
func TestOktaSourceRevokesEveryCertificateOfAUserFromOneRead(t *testing.T) {
	f := newFixture(t)
	f.source.Mapping["cert-bob-2"] = "00u2bob"
	f.okta.set(func(o *fakeOkta) { o.users["00u2bob"] = oktaUser("00u2bob", "bob@example.com", "SUSPENDED") })
	got := f.snapshot(t)
	if !slices.Equal(got.RevokedCertIDs, []string{"cert-bob", "cert-bob-2"}) {
		t.Fatalf("revoked = %v", got.RevokedCertIDs)
	}
	reads := 0
	for _, request := range f.okta.requests {
		if request == "GET /api/v1/users/00u2bob" {
			reads++
		}
	}
	if reads != 1 {
		t.Fatalf("read the user %d times in one snapshot", reads)
	}
}

// A revocation whose save failed is kept in memory and applied again, so a
// user reactivated before the next read is not regranted.
func TestOktaSourceKeepsRevocationsWhoseSaveFailed(t *testing.T) {
	f := newFixture(t)
	f.snapshot(t)
	f.okta.set(func(o *fakeOkta) { delete(o.assigned, "00u2bob") })
	createStateTemp = func(string, string) (*os.File, error) { return nil, errors.New("disk full") }
	_, err := f.source.Snapshot(context.Background())
	createStateTemp = os.CreateTemp
	if err == nil {
		t.Fatal("served a snapshot whose revocation could not be saved")
	}
	if !interruptedScan(f.state) {
		t.Fatal("a read whose revocation was not saved left no marker")
	}
	f.okta.set(func(o *fakeOkta) { o.assigned["00u2bob"] = true })
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("revoked = %v after a failed save and reassignment", got.RevokedCertIDs)
	}
}

// The application user's documented status decides assignment: unassigned,
// revoked, deprovisioned, or suspended app users are revoked; an ambiguous
// status yields no snapshot.
func TestOktaSourceUsesTheApplicationUserStatus(t *testing.T) {
	for status, want := range map[string]string{"UNASSIGNED": "revoked", "REVOKED": "revoked", "DEPROVISIONED": "revoked",
		"SUSPENDED": "revoked", "PROVISIONED": "kept", "IMPLICIT": "kept", "INACTIVE": "error", "SOMETHING_NEW": "error"} {
		f := newFixture(t)
		f.okta.set(func(o *fakeOkta) { o.appUser = map[string]string{"00u2bob": status} })
		got, err := f.source.Snapshot(context.Background())
		switch {
		case want == "error" && err == nil:
			t.Fatalf("%s: served %+v", status, got)
		case want == "revoked" && (err != nil || !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"})):
			t.Fatalf("%s: %v %v", status, got.RevokedCertIDs, err)
		case want == "kept" && (err != nil || len(got.RevokedCertIDs) != 0):
			t.Fatalf("%s: %v %v", status, got.RevokedCertIDs, err)
		}
	}
}

// If the app disappears during the read, an assignment 404 is a
// configuration fault, never a permanent revocation.
func TestOktaSourceDoesNotRevokeWhenTheAppDisappears(t *testing.T) {
	f := newFixture(t)
	f.okta.set(func(o *fakeOkta) { delete(o.assigned, "00u2bob"); o.appGoneAt = 2 })
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("served a snapshot after the app disappeared")
	}
	state, err := loadState(f.state, testIssuer)
	if err != nil || len(state.RevokedCertIDs) != 0 {
		t.Fatalf("app disappearance revoked %v (%v)", state.RevokedCertIDs, err)
	}
}

// A save whose rename landed but whose directory sync failed is not durable:
// the source keeps withholding snapshots until a save fully succeeds.
func TestOktaSourceWithholdsUntilARevocationIsDurable(t *testing.T) {
	f := newFixture(t)
	f.snapshot(t)
	f.okta.set(func(o *fakeOkta) { delete(o.assigned, "00u2bob") })
	failures := 2
	original := syncDir
	syncDir = func(path string) error {
		if failures > 0 {
			failures--
			return errors.New("directory sync failed")
		}
		return original(path)
	}
	defer func() { syncDir = original }()
	for i := 0; i < 2; i++ {
		if got, err := f.source.Snapshot(context.Background()); err == nil {
			t.Fatalf("attempt %d served %+v before the revocation was durable", i, got)
		}
	}
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("revoked = %v", got.RevokedCertIDs)
	}
}

// A new mapping is tracked even when the app check fails on that read, so
// removing the entry before the next read cannot hide its certificate.
func TestOktaSourceTracksNewMappingsBeforeTheAppCheck(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(t.TempDir(), "mapping.json")
	_ = os.WriteFile(path, []byte(`{"cert-alice":"00u1alice","cert-bob":"00u2bob"}`), 0600)
	f.source.MappingFile = path
	f.okta.set(func(o *fakeOkta) { o.appStatus = "INACTIVE" })
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("served a snapshot with an inactive app")
	}
	_ = os.WriteFile(path, []byte(`{"cert-alice":"00u1alice"}`), 0600)
	f.okta.set(func(o *fakeOkta) { o.appStatus = "ACTIVE"; delete(o.assigned, "00u2bob") })
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("revoked = %v; a mapping seen during an app failure was lost", got.RevokedCertIDs)
	}
}

// Restoring a state backup older than a served revocation is refused.
func TestOktaSourceRefusesAnOlderStateBackup(t *testing.T) {
	f := newFixture(t)
	backup, err := os.ReadFile(f.state)
	if err != nil {
		t.Fatal(err)
	}
	f.okta.set(func(o *fakeOkta) { delete(o.assigned, "00u2bob") })
	f.snapshot(t)
	f.okta.set(func(o *fakeOkta) { o.assigned["00u2bob"] = true })
	if err := os.WriteFile(f.state, backup, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatalf("served %+v from a backup that omits a served revocation", got)
	}
}

// An app that becomes inactive after the first checks still withholds the
// snapshot, while revocations already observed are kept.
func TestOktaSourceRechecksAppsAfterTheScan(t *testing.T) {
	f := newFixture(t)
	f.okta.set(func(o *fakeOkta) { o.users["00u1alice"] = oktaUser("00u1alice", "alice@example.com", "SUSPENDED") })
	f.source.Client.Transport = onPathTransport{base: f.source.Client.Transport, path: "/api/v1/users/00u2bob",
		do: func() { f.okta.set(func(o *fakeOkta) { o.appStatus = "INACTIVE" }) }}
	if got, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatalf("served %+v after the app went inactive", got)
	}
	state, err := loadState(f.state, testIssuer)
	if err != nil || !slices.Equal(state.RevokedCertIDs, []string{"cert-alice"}) {
		t.Fatalf("observed revocation not kept: %+v %v", state, err)
	}
}

// Removing the last mapping entry keeps checking the tracked certificate.
func TestOktaSourceAcceptsAnEmptyMapping(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(t.TempDir(), "mapping.json")
	_ = os.WriteFile(path, []byte(`{"cert-bob":"00u2bob"}`), 0600)
	f.source.MappingFile = path
	f.snapshot(t)
	_ = os.WriteFile(path, []byte(`{}`), 0600)
	f.okta.set(func(o *fakeOkta) { delete(o.assigned, "00u2bob") })
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("revoked = %v with an empty mapping", got.RevokedCertIDs)
	}
}

type onPathTransport struct {
	base http.RoundTripper
	path string
	do   func()
}

func (o onPathTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == o.path {
		o.do()
	}
	return o.base.RoundTrip(r)
}

// A backup from before a mapping was tracked is refused even when the
// revoked set did not change, and a missing checkpoint is refused.
func TestOktaSourceRefusesAnyOlderStateGeneration(t *testing.T) {
	f := newFixture(t)
	backup, err := os.ReadFile(f.state)
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot(t) // tracks cert-alice and cert-bob; nothing revoked
	if err := os.WriteFile(f.state, backup, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatalf("served %+v from a backup without the tracked mappings", got)
	}
	if err := os.Remove(f.state + ".checkpoint"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(f.state, testIssuer); err == nil {
		t.Fatal("loaded state without its checkpoint")
	}
}

// A save interrupted before its checkpoint is completed on the next load,
// so a later restore of the older state is still refused; a larger gap is
// refused outright.
func TestOktaSourceRepairsAOneGenerationCheckpointLag(t *testing.T) {
	f := newFixture(t)
	backup, _ := os.ReadFile(f.state)
	f.snapshot(t)                                       // generation 1
	if err := writeCheckpoint(f.state, 0); err != nil { // simulate the crash
		t.Fatal(err)
	}
	if _, err := loadState(f.state, testIssuer); err != nil {
		t.Fatalf("one-generation lag not repaired: %v", err)
	}
	if checkpoint, err := readCheckpoint(f.state); err != nil || checkpoint != 1 {
		t.Fatalf("checkpoint = %d %v, want 1", checkpoint, err)
	}
	_ = os.WriteFile(f.state, backup, 0600)
	if _, err := loadState(f.state, testIssuer); err == nil {
		t.Fatal("accepted the older state after repair")
	}
}

// init can seed revocations an earlier source already made for the issuer.
func TestOktaSourceInitCanSeedPriorRevocations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := initState(path, testIssuer, "cert-old", "cert-old", " cert-a "); err != nil {
		t.Fatal(err)
	}
	state, err := loadState(path, testIssuer)
	if err != nil || !slices.Equal(state.RevokedCertIDs, []string{" cert-a ", "cert-old"}) {
		t.Fatalf("seeded state = %+v %v", state, err)
	}
}

// A read interrupted before its revocations were saved leaves a durable
// marker, so a restarted source cannot silently serve without them; a
// completed read clears it.
func TestOktaSourceMarksReadsUntilTheyAreDurable(t *testing.T) {
	f := newFixture(t)
	f.snapshot(t)
	if interruptedScan(f.state) {
		t.Fatal("a completed read left its marker")
	}
	f.okta.set(func(o *fakeOkta) { o.status = http.StatusTooManyRequests })
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("served during an Okta error")
	}
	if interruptedScan(f.state) {
		t.Fatal("a failed read whose outcome was saved left its marker")
	}
}

// An edit that adds a mapping during the read is tracked before the 503.
func TestOktaSourceTracksMappingsAddedDuringTheRead(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(t.TempDir(), "mapping.json")
	_ = os.WriteFile(path, []byte(`{"cert-alice":"00u1alice"}`), 0600)
	f.source.MappingFile = path
	f.source.Client.Transport = editingTransport{base: f.source.Client.Transport, edit: func() {
		_ = os.WriteFile(path, []byte(`{"cert-alice":"00u1alice","cert-bob":"00u2bob"}`), 0600)
	}}
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("served although the mapping changed")
	}
	f.source.Client.Transport = f.source.Client.Transport.(editingTransport).base
	_ = os.WriteFile(path, []byte(`{"cert-alice":"00u1alice"}`), 0600)
	f.okta.set(func(o *fakeOkta) { delete(o.assigned, "00u2bob") })
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("revoked = %v; a mapping added mid-read was lost", got.RevokedCertIDs)
	}
}

// A mapping added during a read for a user that read showed revoked is
// revoked too, not merely tracked.
func TestOktaSourceRevokesMappingsAddedForAUserRevokedInTheSameRead(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(t.TempDir(), "mapping.json")
	_ = os.WriteFile(path, []byte(`{"cert-bob":"00u2bob"}`), 0600)
	f.source.MappingFile = path
	f.okta.set(func(o *fakeOkta) { o.users["00u2bob"] = oktaUser("00u2bob", "bob@example.com", "SUSPENDED") })
	f.source.Client.Transport = onPathTransport{base: f.source.Client.Transport, path: "/api/v1/users/00u2bob",
		do: func() { _ = os.WriteFile(path, []byte(`{"cert-bob":"00u2bob","cert-bob-2":"00u2bob"}`), 0600) }}
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("served although the mapping changed")
	}
	state, err := loadState(f.state, testIssuer)
	if err != nil || !slices.Equal(state.RevokedCertIDs, []string{"cert-bob", "cert-bob-2"}) {
		t.Fatalf("state = %+v %v", state, err)
	}
}

// A mapping whose tracking save failed is kept for the next read even if
// its entry is removed meanwhile.
func TestOktaSourceKeepsMappingsWhoseSaveFailed(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(t.TempDir(), "mapping.json")
	_ = os.WriteFile(path, []byte(`{"cert-alice":"00u1alice","cert-bob":"00u2bob"}`), 0600)
	f.source.MappingFile = path
	createStateTemp = func(string, string) (*os.File, error) { return nil, errors.New("disk full") }
	_, err := f.source.Snapshot(context.Background())
	createStateTemp = os.CreateTemp
	if err == nil || !interruptedScan(f.state) {
		t.Fatalf("failed tracking save: err=%v marker=%v", err, interruptedScan(f.state))
	}
	_ = os.WriteFile(path, []byte(`{"cert-alice":"00u1alice"}`), 0600)
	f.okta.set(func(o *fakeOkta) { delete(o.assigned, "00u2bob") })
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("revoked = %v; a mapping whose save failed was lost", got.RevokedCertIDs)
	}
	if interruptedScan(f.state) {
		t.Fatal("marker not cleared once everything was durable")
	}
}

// Retries keep the start time of the earliest unresolved read.
func TestOktaSourceMarkerKeepsTheEarliestStart(t *testing.T) {
	f := newFixture(t)
	f.okta.set(func(o *fakeOkta) { delete(o.assigned, "00u2bob") })
	createStateTemp = func(string, string) (*os.File, error) { return nil, errors.New("disk full") }
	defer func() { createStateTemp = os.CreateTemp }()
	_, _ = f.source.Snapshot(context.Background())
	first := interruptedScanStart(f.state)
	f.now = f.now.Add(time.Hour)
	_, _ = f.source.Snapshot(context.Background())
	if first != "2026-11-17T12:00:00Z" || interruptedScanStart(f.state) != first {
		t.Fatalf("marker start %q then %q", first, interruptedScanStart(f.state))
	}
}

// A mapping added for a revoked user during a read that later fails is
// still revoked, so reactivation before the retry cannot regrant it.
func TestOktaSourceAppliesMidReadMappingsAfterAnOktaError(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(t.TempDir(), "mapping.json")
	_ = os.WriteFile(path, []byte(`{"cert-alice":"00u1alice","cert-bob":"00u2bob"}`), 0600)
	f.source.MappingFile = path
	f.okta.set(func(o *fakeOkta) {
		o.users["00u1alice"] = oktaUser("00u1alice", "alice@example.com", "SUSPENDED")
		o.fail = "/api/v1/users/00u2bob"
	})
	f.source.Client.Transport = onPathTransport{base: f.source.Client.Transport, path: "/api/v1/users/00u1alice",
		do: func() {
			_ = os.WriteFile(path, []byte(`{"cert-alice":"00u1alice","cert-alice-2":"00u1alice","cert-bob":"00u2bob"}`), 0600)
		}}
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("served during an Okta error")
	}
	state, err := loadState(f.state, testIssuer)
	if err != nil || !slices.Equal(state.RevokedCertIDs, []string{"cert-alice", "cert-alice-2"}) {
		t.Fatalf("state = %+v %v", state, err)
	}
}

// Recovery from an interrupted read requires the complete inventory, which
// is tracked before the marker is cleared.
func TestOktaSourceRecoveryTracksTheInventory(t *testing.T) {
	f := newFixture(t)
	if err := writeSynced(f.state+".scanning", []byte("2026-11-17T12:00:00Z\n"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC); err != nil {
		t.Fatal(err)
	}
	if err := recoverInterruptedRead(f.state, testIssuer, map[string]string{"cert-lost": "00u2bob"}); err != nil {
		t.Fatal(err)
	}
	state, err := loadState(f.state, testIssuer)
	if err != nil || state.Tracked["cert-lost"] != "00u2bob" || interruptedScan(f.state) {
		t.Fatalf("recovery: %+v %v marker=%v", state, err, interruptedScan(f.state))
	}
}

// A marker whose creation was not durable is synced again before any Okta
// read on the retry.
func TestOktaSourceResyncsAnExistingMarkerBeforeReading(t *testing.T) {
	f := newFixture(t)
	original := syncDir
	defer func() { syncDir = original }()
	failed := false
	syncDir = func(path string) error {
		if !failed {
			failed = true
			return errors.New("directory sync failed")
		}
		return original(path)
	}
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("read Okta without a durable marker")
	}
	before := len(f.okta.requests)
	if before != 0 {
		t.Fatalf("made %d Okta reads before the marker was durable", before)
	}
	syncs := 0
	syncDir = func(path string) error { syncs++; return original(path) }
	f.snapshot(t)
	if syncs == 0 {
		t.Fatal("retry did not sync the existing marker")
	}
}

// A mapping added while the first app check fails is still tracked.
func TestOktaSourceTracksMappingsAddedDuringAFailedAppCheck(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(t.TempDir(), "mapping.json")
	_ = os.WriteFile(path, []byte(`{"cert-alice":"00u1alice"}`), 0600)
	f.source.MappingFile = path
	f.okta.set(func(o *fakeOkta) { o.fail = "/api/v1/apps/" + testApp })
	f.source.Client.Transport = onPathTransport{base: f.source.Client.Transport, path: "/api/v1/apps/" + testApp,
		do: func() { _ = os.WriteFile(path, []byte(`{"cert-alice":"00u1alice","cert-bob":"00u2bob"}`), 0600) }}
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("served during an app check failure")
	}
	state, err := loadState(f.state, testIssuer)
	if err != nil || state.Tracked["cert-bob"] != "00u2bob" {
		t.Fatalf("mapping added during a failed app check was not tracked: %+v %v", state, err)
	}
}

// IDs that JSON decoding would silently replace are refused in mappings and
// seeds, so no certificate ID is changed.
func TestOktaSourceRefusesAlteredIdentifiers(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string][]byte{
		"invalid UTF-8":       append(append([]byte(`{"cert-`), 0xff), []byte(`":"00u1alice"}`)...),
		"unpaired surrogate":  []byte(`{"cert-\ud800":"00u1alice"}`),
		"literal replacement": []byte(`{"cert-\ufffd":"00u1alice"}`),
	} {
		path := filepath.Join(dir, "m.json")
		_ = os.WriteFile(path, body, 0600)
		if _, err := readMapping(path); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if err := initState(filepath.Join(dir, "s2.json"), testIssuer, "cert-"+string(utf8.RuneError)); err == nil {
		t.Fatal("seeded an altered ID")
	}
}

// A malformed existing marker stops the read before any Okta call.
func TestOktaSourceRefusesAMalformedMarker(t *testing.T) {
	f := newFixture(t)
	_ = os.WriteFile(f.state+".scanning", []byte("2026-11-"), 0600)
	if _, err := f.source.Snapshot(context.Background()); err == nil || len(f.okta.requests) != 0 {
		t.Fatalf("read Okta with a malformed marker: err=%v reads=%d", err, len(f.okta.requests))
	}
}

// The startup mapping is tracked before the first request.
func TestOktaSourceTracksTheStartupMapping(t *testing.T) {
	f := newFixture(t)
	if err := trackInventory(f.state, testIssuer, map[string]string{"cert-start": "00u2bob"}); err != nil {
		t.Fatal(err)
	}
	f.okta.set(func(o *fakeOkta) { delete(o.assigned, "00u2bob") })
	delete(f.source.Mapping, "cert-bob")
	if got := f.snapshot(t); !slices.Contains(got.RevokedCertIDs, "cert-start") {
		t.Fatalf("revoked = %v; the startup mapping was not tracked", got.RevokedCertIDs)
	}
}

// A hand-edited state with an altered ID is refused.
func TestOktaSourceStateRefusesAlteredIdentifiers(t *testing.T) {
	f := newFixture(t)
	data, _ := os.ReadFile(f.state)
	edited := strings.Replace(string(data), `"revoked_cert_ids":[]`, `"revoked_cert_ids":["cert-\ud800"]`, 1)
	_ = os.WriteFile(f.state, []byte(edited), 0600)
	if _, err := loadState(f.state, testIssuer); err == nil {
		t.Fatal("loaded a state whose revoked ID JSON decoding altered")
	}
}
