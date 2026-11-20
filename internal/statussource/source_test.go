package statussource

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// These tests cover the provider-independent state machine every reference
// source shares (ported from the Okta reference source's suite). Provider
// API shapes are tested in each command with recorded responses.

const testIssuer = "4f0b5c6a8d7e9f1023456789abcdef0123456789abcdef0123456789abcdef01"

var fakeUserID = regexp.MustCompile(`^u[0-9a-z]{1,30}$`)

// fakeIdP is an in-memory provider. A user in revoked has lost authority, a
// user in fail answers a read error, and a user in neither holds authority.
type fakeIdP struct {
	mu        sync.Mutex
	revoked   map[string]bool
	absent    map[string]bool
	fail      map[string]bool
	finishErr error
	beginErr  error
	onBegin   func()
	onCheck   map[string]func()
	reads     []string
}

func newFakeIdP() *fakeIdP {
	return &fakeIdP{revoked: map[string]bool{}, absent: map[string]bool{}, fail: map[string]bool{}, onCheck: map[string]func(){}}
}

func (f *fakeIdP) Name() string               { return "TestIdP" }
func (f *fakeIdP) ValidUserID(id string) bool { return fakeUserID.MatchString(id) }
func (f *fakeIdP) UserIDHint() string         { return "a TestIdP user ID (u...)" }
func (f *fakeIdP) set(fn func(*fakeIdP))      { f.mu.Lock(); defer f.mu.Unlock(); fn(f) }
func (f *fakeIdP) readCount() int             { f.mu.Lock(); defer f.mu.Unlock(); return len(f.reads) }

func (f *fakeIdP) Begin(context.Context) (Read, error) {
	f.mu.Lock()
	f.reads = append(f.reads, "begin")
	hook, err := f.onBegin, f.beginErr
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	if err != nil {
		return Read{}, err
	}
	check := func(_ context.Context, user string) error {
		f.mu.Lock()
		f.reads = append(f.reads, "user:"+user)
		hook := f.onCheck[user]
		f.mu.Unlock()
		if hook != nil {
			hook()
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case f.fail[user]:
			return errors.New("read failed")
		case f.revoked[user]:
			return ErrRevoked
		case f.absent[user]:
			return ErrAbsent
		}
		return nil
	}
	finish := func(context.Context) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.reads = append(f.reads, "finish")
		return f.finishErr
	}
	return Read{Check: check, Finish: finish}, nil
}

type fixture struct {
	idp    *fakeIdP
	source *Source
	state  string
	now    time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{idp: newFakeIdP(), now: time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)}
	f.state = filepath.Join(t.TempDir(), "revoked.json")
	if err := InitState(f.state, testIssuer); err != nil {
		t.Fatal(err)
	}
	f.source = &Source{Provider: f.idp, RevisionPrefix: "test-", AbsenceConfirm: 10 * time.Minute, IssuerID: testIssuer, StatePath: f.state,
		Mapping: map[string]string{"cert-alice": "u1alice", "cert-bob": "u2bob"},
		Now:     func() time.Time { return f.now }}
	return f
}

func (f *fixture) snapshot(t *testing.T) Snapshot {
	t.Helper()
	got, err := f.source.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return got
}

func (f *fixture) mappingFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mapping.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	f.source.MappingFile = path
	return path
}

func TestSourceHoldersAreNotRevoked(t *testing.T) {
	f := newFixture(t)
	got := f.snapshot(t)
	if got.IssuerID != testIssuer || !got.Complete || len(got.RevokedCertIDs) != 0 ||
		!strings.HasPrefix(got.Revision, "test-") || !got.ObservedAt.Equal(f.now) {
		t.Fatalf("snapshot = %+v", got)
	}
}

func TestSourceRevokesExactlyTheUserWhoLostAuthority(t *testing.T) {
	f := newFixture(t)
	f.idp.set(func(i *fakeIdP) { i.revoked["u2bob"] = true })
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("revoked = %v, want only cert-bob", got.RevokedCertIDs)
	}
}

// A revocation survives the user's reinstatement, a restart, and removal of
// the mapping entry. Regrant needs a new certificate ID.
func TestSourceNeverOmitsAPreviouslyRevokedID(t *testing.T) {
	f := newFixture(t)
	f.idp.set(func(i *fakeIdP) { i.revoked["u2bob"] = true })
	f.snapshot(t)
	f.idp.set(func(i *fakeIdP) { delete(i.revoked, "u2bob") })
	delete(f.source.Mapping, "cert-bob")
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("revoked = %v after reinstatement and unmapping", got.RevokedCertIDs)
	}
	restarted := &Source{Provider: f.idp, RevisionPrefix: "test-", IssuerID: testIssuer, StatePath: f.state,
		Now: f.source.Now, Mapping: map[string]string{"cert-alice": "u1alice"}}
	got, err := restarted.Snapshot(context.Background())
	if err != nil || !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("restarted revoked = %v %v", got.RevokedCertIDs, err)
	}
}

func TestSourceFailsClosedOnAnyProviderError(t *testing.T) {
	for name, change := range map[string]func(*fakeIdP){
		"begin":     func(i *fakeIdP) { i.beginErr = errors.New("token refused") },
		"user read": func(i *fakeIdP) { i.fail["u2bob"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.idp.set(change)
			if got, err := f.source.Snapshot(context.Background()); err == nil {
				t.Fatalf("returned a snapshot during a provider failure: %+v", got)
			}
		})
	}
}

// observed_at is taken after the last read; every request is a fresh read.
func TestSourceObservedAtIsTakenAfterTheRead(t *testing.T) {
	f := newFixture(t)
	start := f.now
	f.source.Now = func() time.Time { return start.Add(time.Duration(f.idp.readCount()) * time.Second) }
	got := f.snapshot(t)
	reads := f.idp.readCount()
	if reads == 0 || !got.ObservedAt.Equal(start.Add(time.Duration(reads)*time.Second)) {
		t.Fatalf("observed_at %v after %d reads", got.ObservedAt, reads)
	}
	f.snapshot(t)
	if f.idp.readCount() != 2*reads {
		t.Fatalf("second snapshot made %d reads, want a fresh full read of %d", f.idp.readCount()-reads, reads)
	}
}

func TestSourceStateIsBoundToTheIssuer(t *testing.T) {
	f := newFixture(t)
	f.source.IssuerID = strings.Repeat("a", 64)
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("used another issuer's state")
	}
	if err := InitState(f.state, testIssuer); err == nil {
		t.Fatal("init overwrote an existing state file")
	}
	if err := os.Remove(f.state); err != nil {
		t.Fatal(err)
	}
	if err := InitState(f.state, testIssuer); err == nil {
		t.Fatal("init recreated a lost state file")
	}
}

func TestSourceHandlerServesTheBridgeContract(t *testing.T) {
	f := newFixture(t)
	handler := Handler(f.source, "bridge-bearer")
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
	f.idp.set(func(i *fakeIdP) { i.revoked["u2bob"] = true })
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
	f.idp.set(func(i *fakeIdP) { i.beginErr = errors.New("throttled") })
	if w := call(http.MethodGet, "Bearer bridge-bearer"); w.Code != http.StatusServiceUnavailable ||
		strings.Contains(w.Body.String(), "revoked") {
		t.Fatalf("provider failure answered %d %s", w.Code, w.Body.String())
	}
}

func TestSourceConfigValidation(t *testing.T) {
	good := Config{IssuerID: testIssuer, MappingFile: "m.json", StateFile: "s.json", ListenAddr: ":8443",
		TLSCertFile: "c.pem", TLSKeyFile: "k.pem"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"bad issuer": func(c *Config) { c.IssuerID = "ISSUER" },
		"no state":   func(c *Config) { c.StateFile = "" },
		"no tls":     func(c *Config) { c.TLSKeyFile = "" },
		"no listen":  func(c *Config) { c.ListenAddr = "" },
	} {
		bad := good
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestSourceMappingFileValidation(t *testing.T) {
	dir := t.TempDir()
	idp := newFakeIdP()
	for name, body := range map[string]string{
		"trailing":    `{"cert-alice":"u1alice"}{"cert-bob":"u2bob"}`,
		"repeated":    `{"cert-alice":"u1alice","cert-alice":"u2bob"}`,
		"login":       `{"cert-alice":"alice@example.com"}`,
		"not object":  `["cert-alice"]`,
		"number user": `{"cert-alice":7}`,
	} {
		path := filepath.Join(dir, name+".json")
		_ = os.WriteFile(path, []byte(body), 0600)
		if _, err := ReadMapping(path, idp); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	path := filepath.Join(dir, "ok.json")
	_ = os.WriteFile(path, []byte(`{"cert-alice":"u1alice"}`), 0600)
	if m, err := ReadMapping(path, idp); err != nil || m["cert-alice"] != "u1alice" {
		t.Fatalf("valid mapping: %v %v", m, err)
	}
}

func TestSourceKeepsCheckingUnmappedActiveCertificates(t *testing.T) {
	f := newFixture(t)
	f.snapshot(t)
	delete(f.source.Mapping, "cert-bob")
	if got := f.snapshot(t); len(got.RevokedCertIDs) != 0 {
		t.Fatalf("unmapping revoked %v", got.RevokedCertIDs)
	}
	f.idp.set(func(i *fakeIdP) { i.revoked["u2bob"] = true })
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("revoked = %v after an unmapped certificate's user lost authority", got.RevokedCertIDs)
	}
	f.source.Mapping["cert-alice"] = "u2bob"
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("accepted a mapping that moves a certificate ID to another user")
	}
}

func TestSourceStateHasOneWriter(t *testing.T) {
	f := newFixture(t)
	first, err := LockState(f.state)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := LockState(f.state); err == nil {
		second.Close()
		t.Fatal("a second source locked the same state")
	}
	first.Close()
	again, err := LockState(f.state)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	again.Close()
}

func TestSourceReloadsMappingAndTracksItBeforeReading(t *testing.T) {
	f := newFixture(t)
	path := f.mappingFile(t, `{"cert-alice":"u1alice"}`)
	f.snapshot(t)
	f.idp.set(func(i *fakeIdP) { i.revoked["u2bob"] = true; i.fail["u2bob"] = true })
	_ = os.WriteFile(path, []byte(`{"cert-alice":"u1alice","cert-bob":"u2bob"}`), 0600)
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("snapshot succeeded during a provider error")
	}
	_ = os.WriteFile(path, []byte(`{"cert-alice":"u1alice"}`), 0600)
	f.idp.set(func(i *fakeIdP) { delete(i.fail, "u2bob") })
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("revoked = %v; a mapping seen only during a failed read was lost", got.RevokedCertIDs)
	}
	_ = os.WriteFile(path, []byte(`{"cert-alice":"alice@example.com"}`), 0600)
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("served a snapshot with an invalid mapping file")
	}
}

func TestSourceRefusesAMappingEditedDuringTheRead(t *testing.T) {
	f := newFixture(t)
	path := f.mappingFile(t, `{"cert-alice":"u1alice"}`)
	f.idp.onCheck["u1alice"] = func() {
		_ = os.WriteFile(path, []byte(`{"cert-alice":"u1alice","cert-bob":"u2bob"}`), 0600)
	}
	if got, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatalf("served %+v although the mapping changed during the read", got)
	}
}

func TestSourceKeepsRevocationsObservedBeforeAFailure(t *testing.T) {
	f := newFixture(t)
	f.idp.set(func(i *fakeIdP) { i.revoked["u1alice"] = true; i.fail["u2bob"] = true })
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("snapshot succeeded during a provider error")
	}
	f.idp.set(func(i *fakeIdP) { delete(i.revoked, "u1alice"); delete(i.fail, "u2bob") })
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-alice"}) {
		t.Fatalf("revoked = %v after reinstating a user revoked during a failed read", got.RevokedCertIDs)
	}
}

func TestSourceRequiresTheInitializationMarker(t *testing.T) {
	f := newFixture(t)
	if err := os.Truncate(f.state+".lock", 0); err != nil {
		t.Fatal(err)
	}
	if lock, err := LockState(f.state); err == nil {
		lock.Close()
		t.Fatal("served state without the initialization marker")
	}
}

func TestSourceKeepsRevocationsWhenTheMappingChangesMidRead(t *testing.T) {
	f := newFixture(t)
	path := f.mappingFile(t, `{"cert-alice":"u1alice","cert-bob":"u2bob"}`)
	f.idp.set(func(i *fakeIdP) { i.revoked["u1alice"] = true })
	f.idp.onCheck["u1alice"] = func() {
		_ = os.WriteFile(path, []byte(`{"cert-alice":"u1alice","cert-bob":"u2bob","cert-x":"u2bob"}`), 0600)
	}
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("served a snapshot although the mapping changed")
	}
	f.idp.set(func(i *fakeIdP) { delete(i.onCheck, "u1alice"); delete(i.revoked, "u1alice") })
	_ = os.WriteFile(path, []byte(`{"cert-alice":"u1alice","cert-bob":"u2bob"}`), 0600)
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-alice"}) {
		t.Fatalf("revoked = %v; a revocation observed before a mapping edit was lost", got.RevokedCertIDs)
	}
}

func TestSourceRevokesEveryCertificateOfAUserFromOneRead(t *testing.T) {
	f := newFixture(t)
	f.source.Mapping["cert-bob-2"] = "u2bob"
	f.idp.set(func(i *fakeIdP) { i.revoked["u2bob"] = true })
	got := f.snapshot(t)
	if !slices.Equal(got.RevokedCertIDs, []string{"cert-bob", "cert-bob-2"}) {
		t.Fatalf("revoked = %v", got.RevokedCertIDs)
	}
	reads := 0
	for _, r := range f.idp.reads {
		if r == "user:u2bob" {
			reads++
		}
	}
	if reads != 1 {
		t.Fatalf("read the user %d times in one snapshot", reads)
	}
}

func TestSourceKeepsRevocationsWhoseSaveFailed(t *testing.T) {
	f := newFixture(t)
	f.snapshot(t)
	f.idp.set(func(i *fakeIdP) { i.revoked["u2bob"] = true })
	createStateTemp = func(string, string) (*os.File, error) { return nil, errors.New("disk full") }
	_, err := f.source.Snapshot(context.Background())
	createStateTemp = os.CreateTemp
	if err == nil {
		t.Fatal("served a snapshot whose revocation could not be saved")
	}
	if !InterruptedScan(f.state) {
		t.Fatal("a read whose revocation was not saved left no marker")
	}
	f.idp.set(func(i *fakeIdP) { delete(i.revoked, "u2bob") })
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("revoked = %v after a failed save and reinstatement", got.RevokedCertIDs)
	}
}

func TestSourceWithholdsUntilARevocationIsDurable(t *testing.T) {
	f := newFixture(t)
	f.snapshot(t)
	f.idp.set(func(i *fakeIdP) { i.revoked["u2bob"] = true })
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

// A new mapping is tracked even when the provider's first read fails.
func TestSourceTracksNewMappingsBeforeTheFirstRead(t *testing.T) {
	f := newFixture(t)
	path := f.mappingFile(t, `{"cert-alice":"u1alice","cert-bob":"u2bob"}`)
	f.idp.set(func(i *fakeIdP) { i.beginErr = errors.New("group missing") })
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("served a snapshot while the provider failed")
	}
	_ = os.WriteFile(path, []byte(`{"cert-alice":"u1alice"}`), 0600)
	f.idp.set(func(i *fakeIdP) { i.beginErr = nil; i.revoked["u2bob"] = true })
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("revoked = %v; a mapping seen during a provider failure was lost", got.RevokedCertIDs)
	}
}

func TestSourceRefusesAnOlderStateBackup(t *testing.T) {
	f := newFixture(t)
	backup, _ := os.ReadFile(f.state)
	f.idp.set(func(i *fakeIdP) { i.revoked["u2bob"] = true })
	f.snapshot(t)
	f.idp.set(func(i *fakeIdP) { delete(i.revoked, "u2bob") })
	_ = os.WriteFile(f.state, backup, 0600)
	if got, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatalf("served %+v from a backup that omits a served revocation", got)
	}
}

func TestSourceAcceptsAnEmptyMapping(t *testing.T) {
	f := newFixture(t)
	path := f.mappingFile(t, `{"cert-bob":"u2bob"}`)
	f.snapshot(t)
	_ = os.WriteFile(path, []byte(`{}`), 0600)
	f.idp.set(func(i *fakeIdP) { i.revoked["u2bob"] = true })
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("revoked = %v with an empty mapping", got.RevokedCertIDs)
	}
}

func TestSourceRefusesAnyOlderStateGeneration(t *testing.T) {
	f := newFixture(t)
	backup, _ := os.ReadFile(f.state)
	f.snapshot(t)
	_ = os.WriteFile(f.state, backup, 0600)
	if got, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatalf("served %+v from a backup without the tracked mappings", got)
	}
	if err := os.Remove(f.state + ".checkpoint"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(f.state, testIssuer, f.idp); err == nil {
		t.Fatal("loaded state without its checkpoint")
	}
}

func TestSourceRepairsAOneGenerationCheckpointLag(t *testing.T) {
	f := newFixture(t)
	backup, _ := os.ReadFile(f.state)
	f.snapshot(t)
	if err := writeCheckpoint(f.state, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(f.state, testIssuer, f.idp); err != nil {
		t.Fatalf("one-generation lag not repaired: %v", err)
	}
	if checkpoint, err := readCheckpoint(f.state); err != nil || checkpoint != 1 {
		t.Fatalf("checkpoint = %d %v, want 1", checkpoint, err)
	}
	_ = os.WriteFile(f.state, backup, 0600)
	if _, err := LoadState(f.state, testIssuer, f.idp); err == nil {
		t.Fatal("accepted the older state after repair")
	}
}

func TestSourceInitCanSeedPriorRevocations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := InitState(path, testIssuer, "cert-old", "cert-old", " cert-a "); err != nil {
		t.Fatal(err)
	}
	state, err := LoadState(path, testIssuer, newFakeIdP())
	if err != nil || !slices.Equal(state.RevokedCertIDs, []string{" cert-a ", "cert-old"}) {
		t.Fatalf("seeded state = %+v %v", state, err)
	}
}

func TestSourceMarksReadsUntilTheyAreDurable(t *testing.T) {
	f := newFixture(t)
	f.snapshot(t)
	if InterruptedScan(f.state) {
		t.Fatal("a completed read left its marker")
	}
	f.idp.set(func(i *fakeIdP) { i.beginErr = errors.New("throttled") })
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("served during a provider error")
	}
	if InterruptedScan(f.state) {
		t.Fatal("a failed read whose outcome was saved left its marker")
	}
}

func TestSourceTracksMappingsAddedDuringTheRead(t *testing.T) {
	f := newFixture(t)
	path := f.mappingFile(t, `{"cert-alice":"u1alice"}`)
	f.idp.onCheck["u1alice"] = func() {
		_ = os.WriteFile(path, []byte(`{"cert-alice":"u1alice","cert-bob":"u2bob"}`), 0600)
	}
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("served although the mapping changed")
	}
	f.idp.set(func(i *fakeIdP) { delete(i.onCheck, "u1alice"); i.revoked["u2bob"] = true })
	_ = os.WriteFile(path, []byte(`{"cert-alice":"u1alice"}`), 0600)
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("revoked = %v; a mapping added mid-read was lost", got.RevokedCertIDs)
	}
}

func TestSourceRevokesMappingsAddedForAUserRevokedInTheSameRead(t *testing.T) {
	f := newFixture(t)
	path := f.mappingFile(t, `{"cert-bob":"u2bob"}`)
	f.idp.set(func(i *fakeIdP) { i.revoked["u2bob"] = true })
	f.idp.onCheck["u2bob"] = func() {
		_ = os.WriteFile(path, []byte(`{"cert-bob":"u2bob","cert-bob-2":"u2bob"}`), 0600)
	}
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("served although the mapping changed")
	}
	state, err := LoadState(f.state, testIssuer, f.idp)
	if err != nil || !slices.Equal(state.RevokedCertIDs, []string{"cert-bob", "cert-bob-2"}) {
		t.Fatalf("state = %+v %v", state, err)
	}
}

func TestSourceKeepsMappingsWhoseSaveFailed(t *testing.T) {
	f := newFixture(t)
	path := f.mappingFile(t, `{"cert-alice":"u1alice","cert-bob":"u2bob"}`)
	createStateTemp = func(string, string) (*os.File, error) { return nil, errors.New("disk full") }
	_, err := f.source.Snapshot(context.Background())
	createStateTemp = os.CreateTemp
	if err == nil || !InterruptedScan(f.state) {
		t.Fatalf("failed tracking save: err=%v marker=%v", err, InterruptedScan(f.state))
	}
	_ = os.WriteFile(path, []byte(`{"cert-alice":"u1alice"}`), 0600)
	f.idp.set(func(i *fakeIdP) { i.revoked["u2bob"] = true })
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-bob"}) {
		t.Fatalf("revoked = %v; a mapping whose save failed was lost", got.RevokedCertIDs)
	}
	if InterruptedScan(f.state) {
		t.Fatal("marker not cleared once everything was durable")
	}
}

func TestSourceMarkerKeepsTheEarliestStart(t *testing.T) {
	f := newFixture(t)
	f.idp.set(func(i *fakeIdP) { i.revoked["u2bob"] = true })
	createStateTemp = func(string, string) (*os.File, error) { return nil, errors.New("disk full") }
	defer func() { createStateTemp = os.CreateTemp }()
	_, _ = f.source.Snapshot(context.Background())
	first := InterruptedScanStart(f.state)
	f.now = f.now.Add(time.Hour)
	_, _ = f.source.Snapshot(context.Background())
	if first != "2026-11-17T12:00:00Z" || InterruptedScanStart(f.state) != first {
		t.Fatalf("marker start %q then %q", first, InterruptedScanStart(f.state))
	}
}

func TestSourceAppliesMidReadMappingsAfterAProviderError(t *testing.T) {
	f := newFixture(t)
	path := f.mappingFile(t, `{"cert-alice":"u1alice","cert-bob":"u2bob"}`)
	f.idp.set(func(i *fakeIdP) { i.revoked["u1alice"] = true; i.fail["u2bob"] = true })
	f.idp.onCheck["u1alice"] = func() {
		_ = os.WriteFile(path, []byte(`{"cert-alice":"u1alice","cert-alice-2":"u1alice","cert-bob":"u2bob"}`), 0600)
	}
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("served during a provider error")
	}
	state, err := LoadState(f.state, testIssuer, f.idp)
	if err != nil || !slices.Equal(state.RevokedCertIDs, []string{"cert-alice", "cert-alice-2"}) {
		t.Fatalf("state = %+v %v", state, err)
	}
}

func TestSourceRecoveryTracksTheInventory(t *testing.T) {
	f := newFixture(t)
	if err := writeSynced(f.state+".scanning", []byte("2026-11-17T12:00:00Z\n"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC); err != nil {
		t.Fatal(err)
	}
	if err := RecoverInterruptedRead(f.state, testIssuer, f.idp, map[string]string{"cert-lost": "u2bob"}); err != nil {
		t.Fatal(err)
	}
	state, err := LoadState(f.state, testIssuer, f.idp)
	if err != nil || state.Tracked["cert-lost"] != "u2bob" || InterruptedScan(f.state) {
		t.Fatalf("recovery: %+v %v marker=%v", state, err, InterruptedScan(f.state))
	}
}

func TestSourceResyncsAnExistingMarkerBeforeReading(t *testing.T) {
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
		t.Fatal("read the provider without a durable marker")
	}
	if n := f.idp.readCount(); n != 0 {
		t.Fatalf("made %d provider reads before the marker was durable", n)
	}
	syncs := 0
	syncDir = func(path string) error { syncs++; return original(path) }
	f.snapshot(t)
	if syncs == 0 {
		t.Fatal("retry did not sync the existing marker")
	}
}

func TestSourceTracksMappingsAddedDuringAFailedFirstRead(t *testing.T) {
	f := newFixture(t)
	path := f.mappingFile(t, `{"cert-alice":"u1alice"}`)
	f.idp.set(func(i *fakeIdP) {
		i.beginErr = errors.New("group read failed")
		i.onBegin = func() { _ = os.WriteFile(path, []byte(`{"cert-alice":"u1alice","cert-bob":"u2bob"}`), 0600) }
	})
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("served during a provider failure")
	}
	state, err := LoadState(f.state, testIssuer, f.idp)
	if err != nil || state.Tracked["cert-bob"] != "u2bob" {
		t.Fatalf("mapping added during a failed first read was not tracked: %+v %v", state, err)
	}
}

func TestSourceRefusesAlteredIdentifiers(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string][]byte{
		"invalid UTF-8":       append(append([]byte(`{"cert-`), 0xff), []byte(`":"u1alice"}`)...),
		"unpaired surrogate":  []byte(`{"cert-\ud800":"u1alice"}`),
		"literal replacement": []byte(`{"cert-�":"u1alice"}`),
	} {
		path := filepath.Join(dir, "m.json")
		_ = os.WriteFile(path, body, 0600)
		if _, err := ReadMapping(path, newFakeIdP()); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if err := InitState(filepath.Join(dir, "s2.json"), testIssuer, "cert-"+string(utf8.RuneError)); err == nil {
		t.Fatal("seeded an altered ID")
	}
}

func TestSourceRefusesAMalformedMarker(t *testing.T) {
	f := newFixture(t)
	_ = os.WriteFile(f.state+".scanning", []byte("2026-11-"), 0600)
	if _, err := f.source.Snapshot(context.Background()); err == nil || f.idp.readCount() != 0 {
		t.Fatalf("read the provider with a malformed marker: err=%v reads=%d", err, f.idp.readCount())
	}
}

func TestSourceTracksTheStartupMapping(t *testing.T) {
	f := newFixture(t)
	if err := TrackInventory(f.state, testIssuer, f.idp, map[string]string{"cert-start": "u2bob"}); err != nil {
		t.Fatal(err)
	}
	f.idp.set(func(i *fakeIdP) { i.revoked["u2bob"] = true })
	delete(f.source.Mapping, "cert-bob")
	if got := f.snapshot(t); !slices.Contains(got.RevokedCertIDs, "cert-start") {
		t.Fatalf("revoked = %v; the startup mapping was not tracked", got.RevokedCertIDs)
	}
}

func TestSourceStateRefusesAlteredIdentifiers(t *testing.T) {
	f := newFixture(t)
	data, _ := os.ReadFile(f.state)
	edited := strings.Replace(string(data), `"revoked_cert_ids":[]`, `"revoked_cert_ids":["cert-\ud800"]`, 1)
	_ = os.WriteFile(f.state, []byte(edited), 0600)
	if _, err := LoadState(f.state, testIssuer, f.idp); err == nil {
		t.Fatal("loaded a state whose revoked ID JSON decoding altered")
	}
}

// A state that tracks a user ID the provider would not accept is refused.
func TestSourceStateRefusesForeignUserIDs(t *testing.T) {
	f := newFixture(t)
	if err := TrackInventory(f.state, testIssuer, f.idp, map[string]string{"cert-x": "u9x"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(f.state)
	_ = os.WriteFile(f.state, []byte(strings.Replace(string(data), `"u9x"`, `"x@example.com"`, 1)), 0600)
	if _, err := LoadState(f.state, testIssuer, f.idp); err == nil {
		t.Fatal("loaded a state that tracks a login instead of an immutable user ID")
	}
}

// Absence (a deleted user or a missing group membership) can be replication
// lag, and a revocation is permanent. While it is unconfirmed the source
// withholds the snapshot (fail closed); it revokes once the absence has
// lasted the confirmation window across successful reads.
func TestSourceWithholdsUntilAbsenceIsConfirmed(t *testing.T) {
	f := newFixture(t)
	f.idp.set(func(i *fakeIdP) { i.absent["u2bob"] = true; i.revoked["u1alice"] = true })
	for _, wait := range []time.Duration{0, 9 * time.Minute} {
		f.now = f.now.Add(wait)
		if got, err := f.source.Snapshot(context.Background()); err == nil {
			t.Fatalf("served %+v while an absence was unconfirmed", got)
		}
	}
	state, err := LoadState(f.state, testIssuer, f.idp)
	if err != nil || !slices.Equal(state.RevokedCertIDs, []string{"cert-alice"}) {
		t.Fatalf("state = %+v %v; the explicit revocation must be kept while withholding", state, err)
	}
	f.now = f.now.Add(time.Minute)
	if got := f.snapshot(t); !slices.Equal(got.RevokedCertIDs, []string{"cert-alice", "cert-bob"}) {
		t.Fatalf("revoked = %v after a confirmed absence", got.RevokedCertIDs)
	}
}

// A user seen present again ends the absence and the snapshot is served.
func TestSourceAbsenceWindowRestartsWhenTheUserReturns(t *testing.T) {
	f := newFixture(t)
	f.idp.set(func(i *fakeIdP) { i.absent["u2bob"] = true })
	_, _ = f.source.Snapshot(context.Background())
	f.now = f.now.Add(5 * time.Minute)
	f.idp.set(func(i *fakeIdP) { delete(i.absent, "u2bob") })
	if got := f.snapshot(t); len(got.RevokedCertIDs) != 0 {
		t.Fatalf("revoked %v after the user returned", got.RevokedCertIDs)
	}
	f.idp.set(func(i *fakeIdP) { i.absent["u2bob"] = true })
	_, _ = f.source.Snapshot(context.Background())
	f.now = f.now.Add(9 * time.Minute)
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("a returned user's earlier absence counted toward the window")
	}
}

// Only successful reads start or advance the absence clock: an absence seen
// by a failed read does not count, so one later miss cannot revoke.
func TestSourceFailedReadsDoNotStartTheAbsenceClock(t *testing.T) {
	f := newFixture(t)
	f.idp.set(func(i *fakeIdP) { i.absent["u2bob"] = true; i.finishErr = errors.New("group changed") })
	_, _ = f.source.Snapshot(context.Background())
	f.now = f.now.Add(10 * time.Minute)
	f.idp.set(func(i *fakeIdP) { i.finishErr = nil })
	if _, err := f.source.Snapshot(context.Background()); err == nil {
		t.Fatal("served while the absence was first confirmed by a successful read")
	}
	state, err := LoadState(f.state, testIssuer, f.idp)
	if err != nil || len(state.RevokedCertIDs) != 0 {
		t.Fatalf("an absence first seen by a failed read revoked %v (%v)", state.RevokedCertIDs, err)
	}
}

// A confirmed absence is not applied by a read that fails, including the
// end-of-read recheck; an authoritative revocation from that read is kept.
func TestSourceAppliesConfirmedAbsenceOnlyOnASuccessfulRead(t *testing.T) {
	for name, fail := range map[string]func(*fakeIdP){
		"finish fails":     func(i *fakeIdP) { i.finishErr = errors.New("group deleted") },
		"later read fails": func(i *fakeIdP) { i.fail["u3carol"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.source.Mapping["cert-carol"] = "u3carol"
			f.idp.set(func(i *fakeIdP) { i.absent["u2bob"] = true })
			_, _ = f.source.Snapshot(context.Background())
			f.now = f.now.Add(10 * time.Minute)
			f.idp.set(func(i *fakeIdP) { i.revoked["u1alice"] = true; fail(i) })
			if got, err := f.source.Snapshot(context.Background()); err == nil {
				t.Fatalf("served %+v during a failed read", got)
			}
			state, err := LoadState(f.state, testIssuer, f.idp)
			if err != nil || !slices.Equal(state.RevokedCertIDs, []string{"cert-alice"}) {
				t.Fatalf("state = %+v %v; want only the authoritative revocation", state, err)
			}
		})
	}
}

// The end-of-read recheck runs on every successful read, after every user.
func TestSourceFinishesEveryRead(t *testing.T) {
	f := newFixture(t)
	f.snapshot(t)
	if f.idp.reads[len(f.idp.reads)-1] != "finish" {
		t.Fatalf("reads = %v", f.idp.reads)
	}
}
