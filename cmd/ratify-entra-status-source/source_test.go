package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/identities-ai/ratify-protocol/v2/internal/statussource"
)

// The bodies below are shaped like the Microsoft identity platform token
// response (learn.microsoft.com, "OAuth 2.0 client credentials flow") and
// the Microsoft Graph v1.0 responses for Get user ($select=id,accountEnabled),
// List group transitive members (value + @odata.nextLink), and the Graph
// error envelope (error.code Request_ResourceNotFound). Extra fields show
// the source tolerates full Graph objects.
const (
	testIssuer = "4f0b5c6a8d7e9f1023456789abcdef0123456789abcdef0123456789abcdef01"
	testTenant = "927c6607-8060-4f4a-a5f8-34964ac78d70"
	testClient = "00001111-aaaa-2222-bbbb-3333cccc4444"
	testGroup  = "02bd9fd6-8f93-4758-87c3-1fb73740a315"
	testSecret = "client-secret-for-tests"
	alice      = "87d349ed-44d7-43e1-9a83-5f2406dee5bd"
	bob        = "4562bcc8-c436-4f95-b7c0-4f8ce89dca5e"
	carol      = "11111111-2222-3333-4444-555555555555"
)

const graphNotFound = `{"error":{"code":"Request_ResourceNotFound","message":"Resource '%s' does not exist or one of its queried reference-property objects are not present.","innerError":{"date":"2026-11-17T12:00:00","request-id":"r1","client-request-id":"c1"}}}`

func graphUser(id string, enabled bool) string {
	return `{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#users(id,accountEnabled)/$entity",` +
		`"id":"` + id + `","accountEnabled":` + map[bool]string{true: "true", false: "false"}[enabled] + `}`
}

// fakeGraph serves recorded Entra responses. Group members are paged one
// per page so every listing follows @odata.nextLink.
type fakeGraph struct {
	mu        sync.Mutex
	url       string
	users     map[string]string // id -> body; missing = 404 Request_ResourceNotFound
	members   []string          // transitive members of testGroup, in page order
	tokenCode int               // when non-zero, the token endpoint answers this
	status    map[string]int    // path prefix -> forced status
	body      map[string]string // path -> forced 200 body
	nextLink  string            // when set, replaces the first page's nextLink
	extraRow  string            // when set, appended to every member page
	listings  int               // member listings started (first-page reads)
	relisted  []string          // when set, the members every listing after the first sees
	goneAfter int               // when non-zero, testGroup answers 404 from this first-page read on
	requests  []string
	auth      []string
	forms     []url.Values
}

func newFakeGraph() *fakeGraph {
	return &fakeGraph{users: map[string]string{alice: graphUser(alice, true), bob: graphUser(bob, true)},
		members: []string{carol, alice, bob}, status: map[string]int{}, body: map[string]string{}}
}

func (g *fakeGraph) set(fn func(*fakeGraph)) { g.mu.Lock(); defer g.mu.Unlock(); fn(g) }

func (g *fakeGraph) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requests = append(g.requests, r.Method+" "+r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/"+testTenant+"/oauth2/v2.0/token" {
		_ = r.ParseForm()
		g.forms = append(g.forms, r.PostForm)
		if g.tokenCode != 0 {
			w.WriteHeader(g.tokenCode)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided.","error_codes":[7000215]}`))
			return
		}
		_, _ = w.Write([]byte(`{"token_type":"Bearer","expires_in":3599,"ext_expires_in":3599,"access_token":"graph-token"}`))
		return
	}
	g.auth = append(g.auth, r.Header.Get("Authorization"))
	for prefix, code := range g.status {
		if strings.HasPrefix(r.URL.Path+"?"+r.URL.RawQuery, prefix) {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"error":{"code":"TooManyRequests","message":"Too many requests."}}`))
			return
		}
	}
	if body, ok := g.body[r.URL.Path]; ok {
		_, _ = w.Write([]byte(body))
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1.0/")
	switch {
	case path == "groups/"+testGroup+"/transitiveMembers":
		page := 0
		if skip := r.URL.Query().Get("$skiptoken"); skip != "" {
			page = int(skip[0] - '0')
		} else {
			g.listings++
			if g.goneAfter != 0 && g.listings >= g.goneAfter {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(graphNotFound))
				return
			}
		}
		members := g.members
		if g.relisted != nil && g.listings >= 2 {
			members = g.relisted
		}
		value := "[]"
		if page < len(members) {
			value = `[{"@odata.type":"#microsoft.graph.user","id":"` + members[page] + `","displayName":"x","mail":"x@example.com"},` +
				`{"@odata.type":"#microsoft.graph.device","id":"aaaaaaaa-0000-0000-0000-00000000000` + string(rune('0'+page)) + `"}` + g.extraRow + `]`
		}
		next := ""
		if page+1 < len(members) {
			link := g.url + "/v1.0/groups/" + testGroup + "/transitiveMembers?$skiptoken=" + string(rune('0'+page+1))
			if page == 0 && g.nextLink != "" {
				link = g.nextLink
			}
			next = `,"@odata.nextLink":"` + link + `"`
		}
		_, _ = w.Write([]byte(`{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#directoryObjects","value":` + value + next + `}`))
	case strings.HasPrefix(path, "groups/"):
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(graphNotFound))
	case strings.HasPrefix(path, "users/"):
		id := strings.TrimPrefix(path, "users/")
		if r.URL.Query().Get("$select") != "id,accountEnabled" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, ok := g.users[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(graphNotFound))
			return
		}
		_, _ = w.Write([]byte(body))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type fixture struct {
	graph  *fakeGraph
	source *statussource.Source
	entra  *entraProvider
	state  string
	now    time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{graph: newFakeGraph()}
	server := httptest.NewTLSServer(f.graph)
	t.Cleanup(server.Close)
	f.graph.url = server.URL
	f.state = filepath.Join(t.TempDir(), "revoked.json")
	if err := statussource.InitState(f.state, testIssuer); err != nil {
		t.Fatal(err)
	}
	f.entra = &entraProvider{TenantID: testTenant, ClientID: testClient, ClientSecret: testSecret,
		GroupIDs: []string{testGroup}, LoginURL: server.URL, GraphURL: server.URL + "/v1.0",
		Client: statussource.NoRedirectClient(server.Client())}
	f.now = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	f.source = &statussource.Source{Provider: f.entra, RevisionPrefix: "entra-", AbsenceConfirm: absenceConfirm,
		IssuerID: testIssuer, StatePath: f.state, Mapping: map[string]string{"cert-alice": alice, "cert-bob": bob},
		Now: func() time.Time { return f.now }}
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

// Enabled group members are not revoked. The source authenticates with the
// client credentials grant for Graph's .default scope, sends the token as a
// Bearer header, reads every page of the group, and otherwise only GETs.
func TestEntraSourceEnabledMembersAreNotRevoked(t *testing.T) {
	f := newFixture(t)
	got := f.snapshot(t)
	if !got.Complete || len(got.RevokedCertIDs) != 0 || !strings.HasPrefix(got.Revision, "entra-") {
		t.Fatalf("snapshot = %+v", got)
	}
	form := f.graph.forms[0]
	if form.Get("grant_type") != "client_credentials" || form.Get("client_id") != testClient ||
		form.Get("client_secret") != testSecret || form.Get("scope") != "https://graph.microsoft.com/.default" {
		t.Fatalf("token request = %v", form)
	}
	for _, header := range f.graph.auth {
		if header != "Bearer graph-token" {
			t.Fatalf("Graph authorization header = %q", header)
		}
	}
	pages := 0
	for _, r := range f.graph.requests {
		if r == "GET /v1.0/groups/"+testGroup+"/transitiveMembers" {
			pages++
		}
		if !strings.HasPrefix(r, "GET ") && r != "POST /"+testTenant+"/oauth2/v2.0/token" {
			t.Fatalf("source must be read-only, sent %s", r)
		}
	}
	if pages != 6 { // all three pages, then all three again to confirm nothing changed
		t.Fatalf("read %d member pages, want all 3 twice", pages)
	}
}

// A disabled account is revoked at once; a deleted user or one removed
// from the group is revoked once the absence has lasted the confirmation
// window, because Graph replication can briefly hide a user or membership.
func TestEntraSourceRevokesDisabledDeletedAndRemovedUsers(t *testing.T) {
	for name, tc := range map[string]struct {
		change    func(*fakeGraph)
		immediate bool
	}{
		"disabled":       {func(g *fakeGraph) { g.users[bob] = graphUser(bob, false) }, true},
		"deleted":        {func(g *fakeGraph) { delete(g.users, bob) }, false},
		"left the group": {func(g *fakeGraph) { g.members = []string{carol, alice} }, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.graph.set(tc.change)
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

// A member found only on a later page is still a member.
func TestEntraSourceFollowsEveryMemberPage(t *testing.T) {
	f := newFixture(t)
	f.graph.set(func(g *fakeGraph) { g.members = []string{carol, carol, carol, carol, bob, alice} })
	if got := f.snapshot(t); len(got.RevokedCertIDs) != 0 {
		t.Fatalf("revoked %v although both users are on later pages", got.RevokedCertIDs)
	}
}

// Every user in the mapping must be in every configured group.
func TestEntraSourceRequiresEveryConfiguredGroup(t *testing.T) {
	f := newFixture(t)
	other := "33333333-4444-5555-6666-777777777777"
	f.entra.GroupIDs = []string{testGroup, other}
	f.graph.set(func(g *fakeGraph) {
		g.body["/v1.0/groups/"+other+"/transitiveMembers"] = `{"value":[{"@odata.type":"#microsoft.graph.user","id":"` + alice + `"}]}`
	})
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("served while cert-bob's absence from the second group was unconfirmed")
	}
	f.now = f.now.Add(absenceConfirm)
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("revoked = %v, want cert-bob (missing from the second group)", got.RevokedCertIDs)
	}
}

// A revocation survives re-enabling the account and re-adding it.
func TestEntraSourceKeepsRevocationsAfterReinstatement(t *testing.T) {
	f := newFixture(t)
	f.graph.set(func(g *fakeGraph) { g.users[bob] = graphUser(bob, false) })
	f.snapshot(t)
	f.graph.set(func(g *fakeGraph) { g.users[bob] = graphUser(bob, true) })
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("revoked = %v after re-enabling", got.RevokedCertIDs)
	}
}

// Any Entra failure yields no snapshot and revokes nothing.
func TestEntraSourceFailsClosedOnAnyGraphError(t *testing.T) {
	for name, change := range map[string]func(*fakeGraph, *entraProvider){
		"bad client secret": func(g *fakeGraph, _ *entraProvider) { g.tokenCode = http.StatusUnauthorized },
		"throttled user":    func(g *fakeGraph, _ *entraProvider) { g.status["/v1.0/users/"+bob] = http.StatusTooManyRequests },
		"forbidden group":   func(g *fakeGraph, _ *entraProvider) { g.status["/v1.0/groups/"] = http.StatusForbidden },
		"second page fails": func(g *fakeGraph, _ *entraProvider) {
			g.status["/v1.0/groups/"+testGroup+"/transitiveMembers?$skiptoken=2"] = http.StatusServiceUnavailable
		},
		"group missing": func(_ *fakeGraph, e *entraProvider) {
			e.GroupIDs = []string{"99999999-9999-9999-9999-999999999999"}
		},
		"next link to another host": func(g *fakeGraph, _ *entraProvider) {
			g.nextLink = "https://attacker.example/v1.0/groups/" + testGroup + "/transitiveMembers?$skiptoken=1"
		},
		"next link to another group": func(g *fakeGraph, _ *entraProvider) {
			g.nextLink = g.url + "/v1.0/groups/33333333-4444-5555-6666-777777777777/transitiveMembers?$skiptoken=1"
		},
		"member row without a type": func(g *fakeGraph, _ *entraProvider) { g.extraRow = `,{"id":"` + carol + `"}` },
		"unknown member type": func(g *fakeGraph, _ *entraProvider) {
			g.extraRow = `,{"@odata.type":"#microsoft.graph.usr","id":"` + carol + `"}`
		},
		"membership changed during the read": func(g *fakeGraph, _ *entraProvider) {
			g.relisted = []string{carol, alice}
		},
		"user row without an ID":        func(g *fakeGraph, _ *entraProvider) { g.extraRow = `,{"@odata.type":"#microsoft.graph.user"}` },
		"group deleted during the read": func(g *fakeGraph, _ *entraProvider) { g.goneAfter = 2 },
		"next link loops": func(g *fakeGraph, _ *entraProvider) {
			g.nextLink = g.url + "/v1.0/groups/" + testGroup + "/transitiveMembers"
		},
		"404 without Graph not-found": func(g *fakeGraph, _ *entraProvider) {
			g.status["/v1.0/users/"+bob] = http.StatusNotFound
		},
		"different person": func(g *fakeGraph, _ *entraProvider) { g.users[bob] = graphUser(carol, true) },
		"accountEnabled missing": func(g *fakeGraph, _ *entraProvider) {
			g.users[bob] = `{"id":"` + bob + `","displayName":"Bob"}`
		},
		"not JSON":      func(g *fakeGraph, _ *entraProvider) { g.users[bob] = `<html>sign in</html>` },
		"trailing JSON": func(g *fakeGraph, _ *entraProvider) { g.users[bob] = graphUser(bob, false) + `{}` },
		"redirect":      func(g *fakeGraph, _ *entraProvider) { g.status["/v1.0/users/"] = http.StatusFound },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.graph.set(func(g *fakeGraph) { change(g, f.entra) })
			if got, err := f.source.Snapshot(context.Background()); err == nil {
				t.Fatalf("returned a snapshot during a Graph failure: %+v", got)
			}
			state, err := statussource.LoadState(f.state, testIssuer, f.entra)
			if err != nil || len(state.RevokedCertIDs) != 0 {
				t.Fatalf("a Graph failure revoked %v (%v)", state.RevokedCertIDs, err)
			}
		})
	}
}

func TestEntraSourceConfigRequiresIDsAndSecretsFromEnv(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, v any) string {
		data, _ := json.Marshal(v)
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	mapping := write("mapping.json", map[string]string{"cert-alice": alice})
	good := map[string]any{"issuer_id": testIssuer, "tenant_id": testTenant, "client_id": testClient,
		"group_ids": []string{testGroup}, "mapping_file": mapping, "state_file": filepath.Join(dir, "state.json"),
		"listen_addr": "127.0.0.1:0", "tls_cert_file": "c.pem", "tls_key_file": "k.pem"}
	env := map[string]string{"ENTRA_CLIENT_SECRET": "s", "IAM_SOURCE_BEARER_TOKEN": "b"}
	getenv := func(k string) string { return env[k] }
	_, source, err := loadConfig(write("good.json", good), getenv)
	if err != nil {
		t.Fatalf("good config: %v", err)
	}
	p := source.Provider.(*entraProvider)
	if p.LoginURL != "https://login.microsoftonline.com" || p.GraphURL != "https://graph.microsoft.com/v1.0" {
		t.Fatalf("endpoints = %s %s", p.LoginURL, p.GraphURL)
	}
	for name, mutate := range map[string]func(map[string]any){
		"no groups":       func(c map[string]any) { c["group_ids"] = []string{} },
		"bad group":       func(c map[string]any) { c["group_ids"] = []string{"../users"} },
		"uppercase group": func(c map[string]any) { c["group_ids"] = []string{strings.ToUpper(testGroup)} },
		"bad tenant":      func(c map[string]any) { c["tenant_id"] = "example.com/../x" },
		"bad client":      func(c map[string]any) { c["client_id"] = "" },
		"bad issuer":      func(c map[string]any) { c["issuer_id"] = "ISSUER" },
		"no tls":          func(c map[string]any) { delete(c, "tls_cert_file") },
		"inline secret":   func(c map[string]any) { c["client_secret"] = "inline" },
		"upn mapping": func(c map[string]any) {
			c["mapping_file"] = write("upn.json", map[string]string{"cert-alice": "alice@example.com"})
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
	delete(env, "ENTRA_CLIENT_SECRET")
	if _, _, err := loadConfig(write("good2.json", good), getenv); err == nil {
		t.Fatal("accepted a config without ENTRA_CLIENT_SECRET")
	}
}
