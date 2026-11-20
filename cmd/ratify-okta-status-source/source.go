package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	ratify "github.com/identities-ai/ratify-protocol/v2"
	"io"
	"log"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

// snapshot is the bridge's source contract (docs/tools/iam-status-bridge.md).
type snapshot struct {
	IssuerID       string    `json:"issuer_id"`
	Revision       string    `json:"revision"`
	Complete       bool      `json:"complete"`
	ObservedAt     time.Time `json:"observed_at"`
	RevokedCertIDs []string  `json:"revoked_cert_ids"`
}

// oktaSource reads the mapped users from the Okta Management API on every
// request. It is read-only: it sends only GET requests.
//
// A certificate is revoked when its Okta user is deactivated
// (DEPROVISIONED), suspended (SUSPENDED), deleted (404), or not assigned to
// every configured app (404 from the application user read). Temporary
// states (LOCKED_OUT, PASSWORD_EXPIRED, RECOVERY) and not-yet-activated
// users (STAGED, PROVISIONED) are not revocations, because a Protocol
// revocation is permanent. Any other status or any read error yields no
// snapshot.
type oktaSource struct {
	OrgURL    string
	Token     string
	AppIDs    []string
	IssuerID  string
	StatePath string
	Mapping   map[string]string // exact cert_id -> immutable Okta user ID
	// MappingFile, when set, is re-read for every snapshot so edits take
	// effect without a restart; an unreadable or invalid file fails closed.
	MappingFile string
	Client      *http.Client
	Now         func() time.Time
	mu          sync.Mutex
	pending     map[string]bool // observed revocations not yet durably saved
	// pendingTracked holds mappings read but not yet durably saved.
	pendingTracked map[string]string
}

var errRevokedUser = errors.New("user no longer holds authority")

var notRevokedStatuses = map[string]bool{"ACTIVE": true, "LOCKED_OUT": true, "PASSWORD_EXPIRED": true,
	"RECOVERY": true, "STAGED": true, "PROVISIONED": true}
var revokedStatuses = map[string]bool{"DEPROVISIONED": true, "SUSPENDED": true}

// Application user statuses (Okta Application Users API). An application
// user that is unassigned, revoked, deprovisioned, or suspended no longer
// holds the app's authority; INACTIVE and unknown statuses yield no snapshot.
var revokedAppUserStatuses = map[string]bool{"UNASSIGNED": true, "REVOKED": true, "DEPROVISIONED": true, "SUSPENDED": true}
var assignedAppUserStatuses = map[string]bool{"ACTIVE": true, "PROVISIONED": true, "IMPLICIT": true, "APPROVED": true,
	"STAGED": true, "PENDING": true, "IMPORTED": true, "MATCHED": true}

func (s *oktaSource) Snapshot(ctx context.Context) (result snapshot, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := loadState(s.StatePath, s.IssuerID)
	if err != nil {
		return snapshot{}, err
	}
	// Mark the read durably before contacting Okta. The marker is cleared
	// only once every observed revocation is durable; a marker left by an
	// interrupted read stops the source until an operator recovers it.
	// The marker records when the earliest unresolved read started; a retry
	// while observations are still unsaved keeps that time.
	if err := ensureScanning(s.StatePath, s.Now().UTC()); err != nil {
		return snapshot{}, err
	}
	defer func() {
		// Unsaved observations (revocations or mappings) exist only when a
		// save failed; then the marker stays.
		if len(s.pending) == 0 && len(s.pendingTracked) == 0 {
			if err := clearScanning(s.StatePath); err != nil && resultErr == nil {
				result, resultErr = snapshot{}, err
			}
		}
	}()
	mapping := s.Mapping
	if s.MappingFile != "" {
		if mapping, err = readMapping(s.MappingFile); err != nil {
			return snapshot{}, err
		}
	}
	revoked := map[string]bool{}
	for _, id := range state.RevokedCertIDs {
		revoked[id] = true
	}
	// Revocations observed earlier whose save failed are still applied.
	for id := range s.pending {
		revoked[id] = true
	}
	// Every certificate ever mapped and not yet revoked stays checked, even
	// after it leaves the mapping, so the snapshot remains complete.
	tracked := map[string]string{}
	for certID, user := range state.Tracked {
		tracked[certID] = user
	}
	// Mappings read earlier whose save failed are still tracked.
	for certID, user := range s.pendingTracked {
		if _, known := tracked[certID]; !known && !revoked[certID] {
			tracked[certID] = user
		}
	}
	for certID, user := range mapping {
		if prior, ok := tracked[certID]; ok && prior != user {
			return snapshot{}, fmt.Errorf("mapping moves certificate %s to another user; issue a new certificate ID", certID)
		}
		if !revoked[certID] {
			tracked[certID] = user
		}
	}
	// Record new mappings before reading Okta, so a certificate stays
	// tracked even if this read fails and the mapping entry is later removed.
	if !maps.Equal(tracked, state.Tracked) {
		state.Tracked = maps.Clone(tracked)
		if err := saveState(s.StatePath, state); err != nil {
			s.keepPendingTracked(tracked)
			return snapshot{}, err
		}
		state, err = loadState(s.StatePath, s.IssuerID)
		if err != nil {
			return snapshot{}, err
		}
	}
	// Apps are checked only after new mappings are durably tracked, so an
	// app lookup failure cannot drop a certificate that is later unmapped.
	var readErr error
	for _, app := range s.AppIDs {
		if readErr = s.appActive(ctx, app); readErr != nil {
			break
		}
	}
	for certID := range revoked {
		delete(tracked, certID)
	}
	// Read each Okta user once, and apply what it shows to every certificate
	// mapped to that user, so one observation revokes them together.
	byUser := map[string][]string{}
	for certID, user := range tracked {
		byUser[user] = append(byUser[user], certID)
	}
	users := slices.Sorted(maps.Keys(byUser))
	revokedUsers := map[string]bool{}
	for _, user := range users {
		if readErr != nil {
			break
		}
		err := s.checkUser(ctx, user)
		if errors.Is(err, errRevokedUser) {
			revokedUsers[user] = true
			for _, certID := range byUser[user] {
				revoked[certID] = true
				delete(tracked, certID)
			}
			continue
		}
		if err != nil {
			readErr = fmt.Errorf("Okta user %s: %w", user, err)
			break
		}
	}
	// The snapshot is complete only for the mapping it read: a mapping edit
	// during the reads fails this request, and the next read includes it.
	// An app that went inactive during the scan withholds the snapshot.
	for _, app := range s.AppIDs {
		if readErr != nil {
			break
		}
		readErr = s.appActive(ctx, app)
	}
	// Even after an Okta error, mappings added during the read are applied
	// before the error is returned, so a revocation this read observed also
	// covers them.
	if s.MappingFile != "" {
		current, err := readMapping(s.MappingFile)
		if err != nil || !maps.Equal(current, mapping) {
			if readErr == nil {
				readErr = errors.New("mapping file changed during the Okta read")
			}
			// Track mappings first seen in the edit so a later removal
			// cannot hide them; a conflicting entry is left for the next read
			// to refuse.
			for certID, user := range current {
				if _, known := tracked[certID]; known || revoked[certID] {
					continue
				}
				if revokedUsers[user] { // this scan saw the user lose authority
					revoked[certID] = true
				} else {
					tracked[certID] = user
				}
			}
		}
	}
	if readErr != nil {
		// Serve nothing, but keep every revocation already observed: a user
		// reactivated before the next read must not be regranted.
		if err := s.saveRevoked(state, tracked, revoked); err != nil {
			s.keepPending(revoked)
			s.keepPendingTracked(tracked)
			return snapshot{}, err
		}
		s.pending, s.pendingTracked = nil, nil
		return snapshot{}, readErr
	}
	observedAt := s.Now().UTC()
	out := make([]string, 0, len(revoked))
	for id := range revoked {
		out = append(out, id)
	}
	slices.Sort(out)
	// Persist before serving so a revocation is never served and then lost.
	next := stateFile{IssuerID: s.IssuerID, Tracked: tracked, RevokedCertIDs: out}
	// Save whenever anything changed or an earlier save of these revocations
	// failed: a renamed file whose directory sync failed is not durable yet.
	if len(s.pending) > 0 || len(s.pendingTracked) > 0 || !slices.Equal(out, state.RevokedCertIDs) || !maps.Equal(tracked, state.Tracked) {
		if err := saveState(s.StatePath, next); err != nil {
			s.keepPending(revoked)
			s.keepPendingTracked(tracked)
			return snapshot{}, err
		}
	}
	s.pending, s.pendingTracked = nil, nil
	digest := sha256.New()
	for _, id := range out {
		digest.Write([]byte(id + "\n"))
	}
	return snapshot{IssuerID: s.IssuerID, Revision: "okta-" + hex.EncodeToString(digest.Sum(nil))[:16],
		Complete: true, ObservedAt: observedAt, RevokedCertIDs: out}, nil
}

// clearScanning removes the read marker once the read's outcome is durable.
func clearScanning(path string) error {
	if err := os.Remove(path + ".scanning"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(path)
}

// interruptedScan reports a read marker left by a process that stopped
// mid-read; the source refuses to start until an operator recovers it.
func interruptedScan(path string) bool {
	_, err := os.Stat(path + ".scanning")
	return err == nil
}

// ensureScanning makes the read marker durable before any Okta read. An
// existing marker (an unresolved earlier read) keeps its start time but is
// synced again, since its creation may not have been durable.
func ensureScanning(path string, now time.Time) error {
	marker := path + ".scanning"
	f, err := os.OpenFile(marker, os.O_RDWR, 0600)
	if errors.Is(err, os.ErrNotExist) {
		// Installed atomically, so a marker is never empty or truncated.
		tmp, err := os.CreateTemp(filepath.Dir(path), ".scanning-*")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		if _, err = tmp.WriteString(now.Format(time.RFC3339) + "\n"); err == nil {
			err = tmp.Sync()
		}
		if cerr := tmp.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		if err := os.Link(tmp.Name(), marker); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		return syncDir(path)
	}
	if err != nil {
		return err
	}
	if _, perr := time.Parse(time.RFC3339, interruptedScanStart(path)); perr != nil {
		f.Close()
		return errors.New("the interrupted-read marker is malformed; reconcile from Okta's system log and run recover")
	}
	err = f.Sync()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return syncDir(path)
}

// interruptedScanStart is when the earliest unresolved read began.
func interruptedScanStart(path string) string {
	data, _ := os.ReadFile(path + ".scanning")
	return strings.TrimSpace(string(data))
}

// keepPending holds observed revocations in memory when their save failed,
// so a later request applies them even if Okta has changed meanwhile.
func (s *oktaSource) keepPending(revoked map[string]bool) {
	if s.pending == nil {
		s.pending = map[string]bool{}
	}
	for id := range revoked {
		s.pending[id] = true
	}
}

// keepPendingTracked holds mappings whose save failed, for the next read.
func (s *oktaSource) keepPendingTracked(tracked map[string]string) {
	if s.pendingTracked == nil {
		s.pendingTracked = map[string]string{}
	}
	for certID, user := range tracked {
		s.pendingTracked[certID] = user
	}
}

// saveRevoked persists the revocations observed so far, if any are new.
func (s *oktaSource) saveRevoked(state stateFile, tracked map[string]string, revoked map[string]bool) error {
	if len(s.pending) == 0 && len(s.pendingTracked) == 0 && len(revoked) == len(state.RevokedCertIDs) && maps.Equal(tracked, state.Tracked) {
		return nil
	}
	out := make([]string, 0, len(revoked))
	for id := range revoked {
		out = append(out, id)
	}
	slices.Sort(out)
	return saveState(s.StatePath, stateFile{IssuerID: s.IssuerID, Tracked: tracked, RevokedCertIDs: out})
}

// appActive confirms a configured app exists and is ACTIVE. A missing or
// inactive app is a configuration fault, not a revocation of every user.
func (s *oktaSource) appActive(ctx context.Context, app string) error {
	var body struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	found, err := s.get(ctx, "apps/"+url.PathEscape(app), &body)
	if err != nil {
		return err
	}
	if !found || body.ID != app || body.Status != "ACTIVE" {
		return fmt.Errorf("Okta app %s is missing or not ACTIVE", app)
	}
	return nil
}

func (s *oktaSource) checkUser(ctx context.Context, mapped string) error {
	var user struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	found, err := s.get(ctx, "users/"+url.PathEscape(mapped), &user)
	if err != nil {
		return err
	}
	if !found {
		return errRevokedUser // deleted users must first be deactivated
	}
	// Only the immutable user ID is trusted: a login can later name someone else.
	if user.ID != mapped {
		return errors.New("Okta returned a different user than the mapping names")
	}
	switch {
	case revokedStatuses[user.Status]:
		return errRevokedUser
	case !notRevokedStatuses[user.Status]:
		return fmt.Errorf("Okta user status %q is not recognized", user.Status)
	}
	for _, app := range s.AppIDs {
		var assignment struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		}
		found, err := s.get(ctx, "apps/"+url.PathEscape(app)+"/users/"+url.PathEscape(user.ID), &assignment)
		if err != nil {
			return err
		}
		if !found {
			// A 404 is an unassignment only while the app itself still
			// exists and is active; otherwise it is a configuration fault.
			if err := s.appActive(ctx, app); err != nil {
				return err
			}
			return errRevokedUser
		}
		if assignment.ID != user.ID {
			return errors.New("Okta returned a different application user")
		}
		switch {
		case revokedAppUserStatuses[assignment.Status]:
			return errRevokedUser
		case !assignedAppUserStatuses[assignment.Status]:
			return fmt.Errorf("Okta application user status %q is not recognized", assignment.Status)
		}
	}
	return nil
}

// get reads one Okta object. It reports found=false only for 404; every
// other non-200 answer, redirect, or malformed body is an error.
func (s *oktaSource) get(ctx context.Context, path string, into any) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.OrgURL+"/api/v1/"+path, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "SSWS "+s.Token)
	req.Header.Set("Accept", "application/json")
	response, err := s.Client.Do(req)
	if err != nil {
		return false, fmt.Errorf("Okta read failed: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(data) > 1<<20 {
		return false, errors.New("Okta response could not be read")
	}
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		var e struct {
			ErrorCode string `json:"errorCode"`
		}
		if json.Unmarshal(data, &e) != nil || e.ErrorCode != "E0000007" {
			return false, errors.New("Okta answered 404 without its not-found error")
		}
		return false, nil
	default:
		return false, fmt.Errorf("Okta answered HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(into); err != nil {
		return false, errors.New("Okta response is not JSON")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return false, errors.New("Okta response has trailing data")
	}
	return true, nil
}

func noRedirectClient(base *http.Client) *http.Client {
	client := *base
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 10 * time.Second
	}
	return &client
}

// The state file retains every revoked certificate ID for one issuer, and
// every mapped certificate not yet revoked with its Okta user.
type stateFile struct {
	IssuerID       string            `json:"issuer_id"`
	Generation     uint64            `json:"generation"`
	Tracked        map[string]string `json:"tracked"`
	RevokedCertIDs []string          `json:"revoked_cert_ids"`
}

// initState creates the empty state once. The lock file then records that
// the state was initialized, so a lost state file cannot be silently
// recreated empty; restore it from a verified backup instead.
func initState(path, issuerID string, revoked ...string) error {
	for _, id := range revoked {
		if !exactID(id) {
			return fmt.Errorf("seeded certificate ID %q is empty, too long, or not exact UTF-8", id)
		}
	}
	marker := path + ".lock"
	if info, err := os.Stat(marker); err == nil && info.Size() > 0 {
		return errors.New("this source was initialized before; restore its state file from backup instead")
	}
	// The durable marker comes first: a crash can leave a marker without
	// state (start refuses; restore or re-run init by hand), never state
	// without a marker.
	if err := writeSynced(marker, []byte("initialized\n"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC); err != nil {
		return err
	}
	seed := append([]string{}, revoked...)
	slices.Sort(seed)
	data, err := json.Marshal(stateFile{IssuerID: issuerID, Tracked: map[string]string{}, RevokedCertIDs: slices.Compact(seed)})
	if err != nil {
		return err
	}
	if err := writeSynced(path, data, os.O_WRONLY|os.O_CREATE|os.O_EXCL); err != nil {
		return fmt.Errorf("create state file: %w", err)
	}
	return writeCheckpoint(path, 0)
}

// The checkpoint beside the state records the generation of the last
// durable save. Every save advances the generation, so any older state (a
// restored backup that could lack a served revocation or a tracked mapping)
// is refused.
func writeCheckpoint(path string, generation uint64) error {
	// Atomic replace: a crash leaves the old or the new checkpoint, never a
	// truncated one.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".checkpoint-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.WriteString(strconv.FormatUint(generation, 10) + "\n"); err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path+".checkpoint"); err != nil {
		return err
	}
	return syncDir(path)
}

func readCheckpoint(path string) (uint64, error) {
	data, err := os.ReadFile(path + ".checkpoint")
	if err != nil {
		return 0, fmt.Errorf("state checkpoint is missing; restore the latest state and checkpoint: %w", err)
	}
	generation, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, errors.New("state checkpoint is invalid")
	}
	return generation, nil
}

func writeSynced(path string, data []byte, flags int) error {
	f, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return syncDir(path)
}

// createStateTemp is a variable so tests can inject a state write failure.
var createStateTemp = os.CreateTemp

// syncDir is a variable so tests can inject a directory sync failure.
var syncDir = func(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// lockState makes this process the only writer of the state file until the
// returned file is closed (at exit).
func lockState(path string) (*os.File, error) {
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("another source process owns %s: %w", path, err)
	}
	if info, err := lock.Stat(); err != nil || info.Size() == 0 {
		lock.Close()
		return nil, errors.New("this source state was never initialized; run init once")
	}
	return lock, nil
}

func loadState(path, issuerID string) (stateFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return stateFile{}, fmt.Errorf("revocation state (run init once, then restore from backup only): %w", err)
	}
	var state stateFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil || state.RevokedCertIDs == nil || state.Tracked == nil {
		return stateFile{}, errors.New("revocation state file is invalid")
	}
	if state.IssuerID != issuerID {
		return stateFile{}, errors.New("revocation state file belongs to another issuer")
	}
	for _, id := range state.RevokedCertIDs {
		if !exactID(id) {
			return stateFile{}, fmt.Errorf("revocation state holds an invalid certificate ID %q", id)
		}
	}
	for certID, user := range state.Tracked {
		if !exactID(certID) || !oktaUserID.MatchString(user) {
			return stateFile{}, fmt.Errorf("revocation state tracks an invalid entry %q", certID)
		}
	}
	checkpoint, err := readCheckpoint(path)
	if err != nil {
		return stateFile{}, err
	}
	switch {
	case state.Generation < checkpoint:
		return stateFile{}, fmt.Errorf("revocation state generation %d is older than its checkpoint %d; restore the latest state", state.Generation, checkpoint)
	case state.Generation == checkpoint+1:
		// A save that crashed before its checkpoint: complete it before
		// serving, so the checkpoint never lags a served state.
		if err := writeCheckpoint(path, state.Generation); err != nil {
			return stateFile{}, err
		}
	case state.Generation > checkpoint+1:
		return stateFile{}, fmt.Errorf("revocation state generation %d is ahead of its checkpoint %d by more than one save", state.Generation, checkpoint)
	}
	return state, nil
}

func saveState(path string, state stateFile) error {
	checkpoint, err := readCheckpoint(path)
	if err != nil {
		return err
	}
	if current, err := loadState(path, state.IssuerID); err == nil && current.Generation > checkpoint {
		checkpoint = current.Generation
	}
	state.Generation = checkpoint + 1
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	tmp, err := createStateTemp(filepath.Dir(path), ".revoked-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if err := syncDir(path); err != nil {
		return err
	}
	return writeCheckpoint(path, state.Generation)
}

// snapshotHandler serves GET with a bearer token. Every request is a fresh
// authoritative read; a failure answers 503 with no snapshot.
func snapshotHandler(source *oktaSource, bearer string) http.Handler {
	want := []byte("Bearer " + bearer)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		got, err := source.Snapshot(r.Context())
		if err != nil {
			log.Printf("Okta snapshot failed; serving no snapshot: %v", err)
			http.Error(w, "IAM snapshot unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(got)
	})
}

type config struct {
	IssuerID    string   `json:"issuer_id"`
	OktaOrgURL  string   `json:"okta_org_url"`
	AppIDs      []string `json:"app_ids"`
	MappingFile string   `json:"mapping_file"`
	StateFile   string   `json:"state_file"`
	ListenAddr  string   `json:"listen_addr"`
	TLSCertFile string   `json:"tls_cert_file"`
	TLSKeyFile  string   `json:"tls_key_file"`
}

var (
	hexIssuer  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	oktaUserID = regexp.MustCompile(`^00u[A-Za-z0-9]{1,61}$`)
	oktaID     = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)
)

// loadConfig reads the JSON config and the two secrets from the
// environment: OKTA_API_TOKEN and IAM_SOURCE_BEARER_TOKEN.
func loadConfig(path string, getenv func(string) string) (config, *oktaSource, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return config{}, nil, err
	}
	var cfg config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return config{}, nil, fmt.Errorf("decode config: %w", err)
	}
	if !hexIssuer.MatchString(cfg.IssuerID) {
		return config{}, nil, errors.New("issuer_id must be the 64-character lowercase hex issuer ID")
	}
	org, err := url.Parse(cfg.OktaOrgURL)
	if err != nil || org.Scheme != "https" || org.Host == "" || org.User != nil ||
		(org.Path != "" && org.Path != "/") || org.RawQuery != "" || org.Fragment != "" {
		return config{}, nil, errors.New("okta_org_url must be https://YOUR-ORG.okta.com")
	}
	if len(cfg.AppIDs) == 0 {
		return config{}, nil, errors.New("app_ids must name at least one Okta app")
	}
	for _, app := range cfg.AppIDs {
		if !oktaID.MatchString(app) {
			return config{}, nil, fmt.Errorf("app ID %q is not an Okta app ID", app)
		}
	}
	if cfg.StateFile == "" || cfg.ListenAddr == "" || cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		return config{}, nil, errors.New("state_file, listen_addr, tls_cert_file, and tls_key_file are required")
	}
	mapping, err := readMapping(cfg.MappingFile)
	if err != nil {
		return config{}, nil, err
	}
	token := getenv("OKTA_API_TOKEN")
	if token == "" || getenv("IAM_SOURCE_BEARER_TOKEN") == "" {
		return config{}, nil, errors.New("OKTA_API_TOKEN and IAM_SOURCE_BEARER_TOKEN are required")
	}
	return cfg, &oktaSource{OrgURL: "https://" + org.Host, Token: token, AppIDs: cfg.AppIDs,
		IssuerID: cfg.IssuerID, StatePath: cfg.StateFile, Mapping: mapping, MappingFile: cfg.MappingFile,
		Client: noRedirectClient(&http.Client{}), Now: time.Now}, nil
}

// readMapping reads and validates the customer's cert_id -> Okta user ID file.
func readMapping(path string) (map[string]string, error) {
	return readMappingLimit(path, 10000)
}

// readInventory reads a recovery inventory, which can hold every certificate
// the source has accumulated across mapping edits.
func readInventory(path string) (map[string]string, error) {
	return readMappingLimit(path, 1_000_000)
}

// exactID rejects identifiers that JSON decoding could have altered: a
// decoded U+FFFD stands for invalid UTF-8 or an unpaired surrogate.
func exactID(id string) bool {
	return id != "" && len(id) <= ratify.MaxIdentifierLengthBytes && utf8.ValidString(id) && !strings.ContainsRune(id, utf8.RuneError)
}

func readMappingLimit(path string, limit int) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("mapping file: %w", err)
	}
	// Parse token by token so trailing content or a repeated certificate
	// ID is refused instead of silently dropping entries.
	invalid := errors.New("mapping file must be one JSON object of at most 10000 distinct cert_id to Okta user ID entries")
	decoder := json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, invalid
	}
	mapping := map[string]string{}
	for decoder.More() {
		key, err := decoder.Token()
		certID, isString := key.(string)
		if err != nil || !isString {
			return nil, invalid
		}
		value, err := decoder.Token()
		user, isString := value.(string)
		if err != nil || !isString {
			return nil, invalid
		}
		if _, repeated := mapping[certID]; repeated {
			return nil, invalid
		}
		mapping[certID] = user
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, invalid
	}
	// An empty mapping is valid: tracked certificates keep being checked.
	if _, err := decoder.Token(); err != io.EOF || len(mapping) > limit {
		return nil, invalid
	}
	for certID, user := range mapping {
		if !exactID(certID) || !oktaUserID.MatchString(user) {
			return nil, fmt.Errorf("mapping for %q must name an immutable Okta user ID (00u...), not a login", certID)
		}
	}
	return mapping, nil
}

// recoverInterruptedRead clears the interrupted-read marker after the
// operator supplies the complete certificate-to-user inventory: every entry
// becomes tracked (unless already revoked), so a mapping whose save was lost
// is checked again on the next read.
func recoverInterruptedRead(path, issuerID string, inventory map[string]string) error {
	if err := trackInventory(path, issuerID, inventory); err != nil {
		return err
	}
	return clearScanning(path)
}

// trackInventory durably tracks every unrevoked certificate in inventory.
// The server also calls it with the startup mapping before listening.
func trackInventory(path, issuerID string, inventory map[string]string) error {
	state, err := loadState(path, issuerID)
	if err != nil {
		return err
	}
	revoked := map[string]bool{}
	for _, id := range state.RevokedCertIDs {
		revoked[id] = true
	}
	for certID, user := range inventory {
		if prior, ok := state.Tracked[certID]; ok && prior != user {
			return fmt.Errorf("inventory moves certificate %s to another user", certID)
		}
		if !revoked[certID] {
			state.Tracked[certID] = user
		}
	}
	return saveState(path, state)
}
