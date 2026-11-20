package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/identities-ai/ratify-protocol/v2/internal/statussource"
)

// The bodies below are shaped like Google's OAuth 2.0 service account token
// response (developers.google.com/identity/protocols/oauth2/service-account)
// and the Admin SDK Directory API v1 responses for users.get (id,
// suspended, archived), members.list (members + nextPageToken), and the
// Google API error envelope (error.errors[].reason notFound).
const (
	testIssuer = "4f0b5c6a8d7e9f1023456789abcdef0123456789abcdef0123456789abcdef01"
	testGroup  = "03ep43zb3kv0wnq"
	testAdmin  = "status-reader@example.com"
	testSA     = "ratify-status@service.example"
	alice      = "114085431213312345678"
	bob        = "103859345678901234567"
	carol      = "109999999999999999999"
)

func googleNotFound(what string) string {
	return `{"error":{"code":404,"message":"Resource Not Found: ` + what + `","errors":[{"message":"Resource Not Found: ` +
		what + `","domain":"global","reason":"notFound"}]}}`
}

func googleUser(id string, suspended, archived bool) string {
	return `{"kind":"admin#directory#user","id":"` + id + `","primaryEmail":"u` + id[:3] + `@example.com",` +
		`"isAdmin":false,"suspended":` + strconv.FormatBool(suspended) + `,"archived":` + strconv.FormatBool(archived) +
		`,"orgUnitPath":"/"}`
}

// fakeGoogle serves recorded Google responses. Group members are paged one
// per page so every listing follows nextPageToken.
type fakeGoogle struct {
	mu        sync.Mutex
	key       *rsa.PublicKey
	users     map[string]string // id -> body; missing = 404 notFound
	members   []string          // members of testGroup (direct and derived), in page order
	tokenCode int
	status    map[string]int // path?query prefix -> forced status
	loopToken bool           // when set, every page answers the same nextPageToken
	extraRow  string         // when set, appended to every member page
	listings  int            // member listings started (first-page reads)
	relisted  []string       // when set, the members every listing after the first sees
	goneAfter int            // when non-zero, testGroup answers 404 from this first-page read on
	requests  []string
	auth      []string
	claims    []map[string]any
}

func newFakeGoogle(key *rsa.PublicKey) *fakeGoogle {
	return &fakeGoogle{key: key, status: map[string]int{}, members: []string{carol, alice, bob},
		users: map[string]string{alice: googleUser(alice, false, false), bob: googleUser(bob, false, false)}}
}

func (g *fakeGoogle) set(fn func(*fakeGoogle)) { g.mu.Lock(); defer g.mu.Unlock(); fn(g) }

func (g *fakeGoogle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requests = append(g.requests, r.Method+" "+r.URL.Path)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if r.URL.Path == "/token" {
		_ = r.ParseForm()
		claims, ok := g.verifyAssertion(r.PostForm)
		if !ok || g.tokenCode != 0 {
			code := g.tokenCode
			if code == 0 {
				code = http.StatusBadRequest
			}
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"error":"unauthorized_client","error_description":"Client is unauthorized to retrieve access tokens using this method, or client not authorized for any of the scopes requested."}`))
			return
		}
		g.claims = append(g.claims, claims)
		_, _ = w.Write([]byte(`{"access_token":"ya29.test","expires_in":3599,"token_type":"Bearer"}`))
		return
	}
	g.auth = append(g.auth, r.Header.Get("Authorization"))
	for prefix, code := range g.status {
		if strings.HasPrefix(r.URL.Path+"?"+r.URL.RawQuery, prefix) {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"error":{"code":` + strconv.Itoa(code) + `,"message":"Quota exceeded","errors":[{"reason":"rateLimitExceeded"}]}}`))
			return
		}
	}
	path := strings.TrimPrefix(r.URL.Path, "/admin/directory/v1/")
	switch {
	case path == "groups/"+testGroup+"/members":
		q := r.URL.Query()
		if q.Get("includeDerivedMembership") != "true" || q.Get("maxResults") != "200" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		page := 0
		if token := q.Get("pageToken"); token != "" {
			page, _ = strconv.Atoi(strings.TrimPrefix(token, "p"))
		} else {
			g.listings++
			if g.goneAfter != 0 && g.listings >= g.goneAfter {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(googleNotFound("groupKey")))
				return
			}
		}
		members := g.members
		if g.relisted != nil && g.listings >= 2 {
			members = g.relisted
		}
		body := `{"kind":"admin#directory#members","etag":"\"e\""`
		if page < len(members) {
			body += `,"members":[{"kind":"admin#directory#member","id":"` + members[page] +
				`","email":"m@example.com","role":"MEMBER","type":"USER","status":"ACTIVE"},` +
				`{"kind":"admin#directory#member","id":"0abc","email":"team@example.com","role":"MEMBER","type":"GROUP","status":"ACTIVE"}` + g.extraRow + `]`
		}
		if g.loopToken {
			body += `,"nextPageToken":"p0"`
		} else if page+1 < len(members) {
			body += `,"nextPageToken":"p` + strconv.Itoa(page+1) + `"`
		}
		_, _ = w.Write([]byte(body + "}"))
	case strings.HasPrefix(path, "groups/"):
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(googleNotFound("groupKey")))
	case strings.HasPrefix(path, "users/"):
		id := strings.TrimPrefix(path, "users/")
		if r.URL.Query().Get("projection") != "basic" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, ok := g.users[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(googleNotFound("userKey")))
			return
		}
		_, _ = w.Write([]byte(body))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// verifyAssertion checks the JWT bearer grant exactly as Google documents
// it: RS256 over header.claims, signed by the service account key.
func (g *fakeGoogle) verifyAssertion(form url.Values) (map[string]any, bool) {
	if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		return nil, false
	}
	parts := strings.Split(form.Get("assertion"), ".")
	if len(parts) != 3 {
		return nil, false
	}
	var header map[string]string
	raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if json.Unmarshal(raw, &header) != nil || header["alg"] != "RS256" || header["typ"] != "JWT" {
		return nil, false
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(g.key, crypto.SHA256, digest[:], sig) != nil {
		return nil, false
	}
	var claims map[string]any
	raw, _ = base64.RawURLEncoding.DecodeString(parts[1])
	return claims, json.Unmarshal(raw, &claims) == nil
}

type fixture struct {
	google *fakeGoogle
	source *statussource.Source
	gp     *googleProvider
	state  string
	now    time.Time
}

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key := testKey(t)
	f := &fixture{google: newFakeGoogle(&key.PublicKey), now: time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)}
	server := httptest.NewTLSServer(f.google)
	t.Cleanup(server.Close)
	f.state = filepath.Join(t.TempDir(), "revoked.json")
	if err := statussource.InitState(f.state, testIssuer); err != nil {
		t.Fatal(err)
	}
	f.gp = &googleProvider{ClientEmail: testSA, Key: key, Subject: testAdmin, GroupIDs: []string{testGroup},
		TokenURL: server.URL + "/token", AdminURL: server.URL + "/admin/directory/v1",
		Client: statussource.NoRedirectClient(server.Client()), Now: func() time.Time { return f.now }}
	f.source = &statussource.Source{Provider: f.gp, RevisionPrefix: "google-", AbsenceConfirm: absenceConfirm, IssuerID: testIssuer, StatePath: f.state,
		Mapping: map[string]string{"cert-alice": alice, "cert-bob": bob}, Now: func() time.Time { return f.now }}
	return f
}

func (f *fixture) snapshot(t *testing.T) statussource.Snapshot {
	t.Helper()
	got, err := f.source.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return got
}

// Active group members are not revoked. The service account signs a JWT
// that impersonates the configured admin with only the two read-only
// Directory scopes, and the source otherwise only GETs.
func TestGoogleSourceActiveMembersAreNotRevoked(t *testing.T) {
	f := newFixture(t)
	got := f.snapshot(t)
	if !got.Complete || len(got.RevokedCertIDs) != 0 || !strings.HasPrefix(got.Revision, "google-") {
		t.Fatalf("snapshot = %+v", got)
	}
	claims := f.google.claims[0]
	if claims["iss"] != testSA || claims["sub"] != testAdmin || claims["aud"] != f.gp.TokenURL ||
		claims["scope"] != "https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.directory.group.member.readonly" ||
		claims["iat"] != float64(f.now.Unix()) || claims["exp"] != float64(f.now.Add(time.Hour).Unix()) {
		t.Fatalf("assertion claims = %v", claims)
	}
	for _, header := range f.google.auth {
		if header != "Bearer ya29.test" {
			t.Fatalf("authorization header = %q", header)
		}
	}
	pages := 0
	for _, r := range f.google.requests {
		if r == "GET /admin/directory/v1/groups/"+testGroup+"/members" {
			pages++
		}
		if !strings.HasPrefix(r, "GET ") && r != "POST /token" {
			t.Fatalf("source must be read-only, sent %s", r)
		}
	}
	if pages != 6 { // all three pages, then all three again to confirm nothing changed
		t.Fatalf("read %d member pages, want all 3 twice", pages)
	}
}

// Suspension and archiving revoke at once; a deleted user or one removed
// from the group is revoked once the absence has lasted the confirmation
// window, because nested membership changes can take minutes to appear.
func TestGoogleSourceRevokesSuspendedArchivedDeletedAndRemovedUsers(t *testing.T) {
	for name, tc := range map[string]struct {
		change    func(*fakeGoogle)
		immediate bool
	}{
		"suspended":      {func(g *fakeGoogle) { g.users[bob] = googleUser(bob, true, false) }, true},
		"archived":       {func(g *fakeGoogle) { g.users[bob] = googleUser(bob, false, true) }, true},
		"deleted":        {func(g *fakeGoogle) { delete(g.users, bob) }, false},
		"left the group": {func(g *fakeGoogle) { g.members = []string{carol, alice} }, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.google.set(tc.change)
			// An explicit revocation is served at once; an absence withholds
			// the snapshot until it is confirmed.
			first, err := f.source.Snapshot(context.Background())
			if tc.immediate != (err == nil && slices.Equal(first.RevokedCertIDs, []string{"cert-bob"})) {
				t.Fatalf("first read = %v %v", first.RevokedCertIDs, err)
			}
			f.now = f.now.Add(absenceConfirm)
			if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
				t.Fatalf("revoked = %v, want only cert-bob", got.RevokedCertIDs)
			}
		})
	}
}

func TestGoogleSourceFollowsEveryMemberPage(t *testing.T) {
	f := newFixture(t)
	f.google.set(func(g *fakeGoogle) { g.members = []string{carol, carol, carol, bob, carol, alice} })
	if got := f.snapshot(t); len(got.RevokedCertIDs) != 0 {
		t.Fatalf("revoked %v although both users are on later pages", got.RevokedCertIDs)
	}
}

func TestGoogleSourceKeepsRevocationsAfterReinstatement(t *testing.T) {
	f := newFixture(t)
	f.google.set(func(g *fakeGoogle) { g.users[bob] = googleUser(bob, true, false) })
	f.snapshot(t)
	f.google.set(func(g *fakeGoogle) { g.users[bob] = googleUser(bob, false, false) })
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("revoked = %v after unsuspending", got.RevokedCertIDs)
	}
}

func TestGoogleSourceFailsClosedOnAnyDirectoryError(t *testing.T) {
	for name, change := range map[string]func(*fakeGoogle, *googleProvider){
		"delegation not granted": func(g *fakeGoogle, _ *googleProvider) { g.tokenCode = http.StatusUnauthorized },
		"throttled user": func(g *fakeGoogle, _ *googleProvider) {
			g.status["/admin/directory/v1/users/"+bob] = http.StatusTooManyRequests
		},
		"forbidden group": func(g *fakeGoogle, _ *googleProvider) { g.status["/admin/directory/v1/groups/"] = http.StatusForbidden },
		"second page fails": func(g *fakeGoogle, _ *googleProvider) {
			g.status["/admin/directory/v1/groups/"+testGroup+"/members?includeDerivedMembership=true&maxResults=200&pageToken=p2"] = http.StatusInternalServerError
		},
		"page token loops": func(g *fakeGoogle, _ *googleProvider) { g.loopToken = true },
		"group missing":    func(_ *fakeGoogle, p *googleProvider) { p.GroupIDs = []string{"03gone00000000"} },
		"whole-domain member": func(g *fakeGoogle, _ *googleProvider) {
			g.extraRow = `,{"kind":"admin#directory#member","id":"C01abc","role":"MEMBER","type":"CUSTOMER","status":"ACTIVE"}`
		},
		"member row without a type": func(g *fakeGoogle, _ *googleProvider) { g.extraRow = `,{"id":"` + carol + `"}` },
		"user row with a bad ID": func(g *fakeGoogle, _ *googleProvider) {
			g.extraRow = `,{"id":"carol@example.com","type":"USER"}`
		},
		"membership changed during the read": func(g *fakeGoogle, _ *googleProvider) {
			g.relisted = []string{carol, alice}
		},
		"group deleted during the read": func(g *fakeGoogle, _ *googleProvider) { g.goneAfter = 2 },
		"404 without notFound": func(g *fakeGoogle, _ *googleProvider) {
			g.status["/admin/directory/v1/users/"+bob] = http.StatusNotFound
		},
		"different person":  func(g *fakeGoogle, _ *googleProvider) { g.users[bob] = googleUser(carol, false, false) },
		"suspended missing": func(g *fakeGoogle, _ *googleProvider) { g.users[bob] = `{"id":"` + bob + `","archived":false}` },
		"not JSON":          func(g *fakeGoogle, _ *googleProvider) { g.users[bob] = `<html>sign in</html>` },
		"trailing JSON": func(g *fakeGoogle, _ *googleProvider) {
			g.users[bob] = googleUser(bob, true, false) + `{}`
		},
		"redirect": func(g *fakeGoogle, _ *googleProvider) { g.status["/admin/directory/v1/users/"] = http.StatusFound },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.google.set(func(g *fakeGoogle) { change(g, f.gp) })
			if got, err := f.source.Snapshot(context.Background()); err == nil {
				t.Fatalf("returned a snapshot during a Directory failure: %+v", got)
			}
			state, err := statussource.LoadState(f.state, testIssuer, f.gp)
			if err != nil || len(state.RevokedCertIDs) != 0 {
				t.Fatalf("a Directory failure revoked %v (%v)", state.RevokedCertIDs, err)
			}
		})
	}
}

func TestGoogleSourceConfigRequiresAKeyFileAndSecretsFromEnv(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, v any) string {
		data, _ := json.Marshal(v)
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	der, _ := x509.MarshalPKCS8PrivateKey(testKey(t))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	saKey := map[string]string{"type": "service_account", "project_id": "p", "private_key_id": "k1",
		"private_key": keyPEM, "client_email": testSA, "client_id": "1", "token_uri": "https://oauth2.googleapis.com/token"}
	keyFile := write("sa.json", saKey)
	mapping := write("mapping.json", map[string]string{"cert-alice": alice})
	good := map[string]any{"issuer_id": testIssuer, "admin_subject": testAdmin, "group_ids": []string{testGroup},
		"mapping_file": mapping, "state_file": filepath.Join(dir, "state.json"),
		"listen_addr": "127.0.0.1:0", "tls_cert_file": "c.pem", "tls_key_file": "k.pem"}
	env := map[string]string{"GOOGLE_SERVICE_ACCOUNT_KEY_FILE": keyFile, "IAM_SOURCE_BEARER_TOKEN": "b"}
	getenv := func(k string) string { return env[k] }
	_, source, err := loadConfig(write("good.json", good), getenv)
	if err != nil {
		t.Fatalf("good config: %v", err)
	}
	p := source.Provider.(*googleProvider)
	if p.TokenURL != "https://oauth2.googleapis.com/token" || p.AdminURL != "https://admin.googleapis.com/admin/directory/v1" || p.ClientEmail != testSA {
		t.Fatalf("provider = %s %s %s", p.TokenURL, p.AdminURL, p.ClientEmail)
	}
	for name, mutate := range map[string]func(map[string]any){
		"no groups":     func(c map[string]any) { c["group_ids"] = []string{} },
		"bad group":     func(c map[string]any) { c["group_ids"] = []string{"../users"} },
		"group email":   func(c map[string]any) { c["group_ids"] = []string{"ratify-agents@example.com"} },
		"no subject":    func(c map[string]any) { c["admin_subject"] = "" },
		"bad issuer":    func(c map[string]any) { c["issuer_id"] = "ISSUER" },
		"unknown field": func(c map[string]any) { c["private_key"] = "inline" },
		"email mapping": func(c map[string]any) {
			c["mapping_file"] = write("email.json", map[string]string{"cert-alice": "alice@example.com"})
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
	for name, mutate := range map[string]func(map[string]string){
		"other token uri": func(k map[string]string) { k["token_uri"] = "https://attacker.example/token" },
		"not a key":       func(k map[string]string) { k["private_key"] = "x" },
		"user account":    func(k map[string]string) { k["type"] = "authorized_user" },
	} {
		bad := map[string]string{}
		for k, v := range saKey {
			bad[k] = v
		}
		mutate(bad)
		env["GOOGLE_SERVICE_ACCOUNT_KEY_FILE"] = write(name+"-sa.json", bad)
		if _, _, err := loadConfig(write("good-"+name+".json", good), getenv); err == nil {
			t.Fatalf("key file %s: accepted", name)
		}
	}
	delete(env, "GOOGLE_SERVICE_ACCOUNT_KEY_FILE")
	if _, _, err := loadConfig(write("good2.json", good), getenv); err == nil {
		t.Fatal("accepted a config without GOOGLE_SERVICE_ACCOUNT_KEY_FILE")
	}
}
