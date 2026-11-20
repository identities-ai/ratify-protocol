// Package statussource is the provider-independent core of the customer-run
// reference IAM snapshot sources for ratify-iam-bridge
// (docs/tools/iam-status-bridge.md). A Provider reads one identity
// provider; this package keeps the cumulative revocation state, the
// customer-owned cert_id mapping, the interrupted-read marker, and serves
// the bridge's source contract. It follows the Okta reference source
// (cmd/ratify-okta-status-source) rule for rule.
package statussource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
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

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// Snapshot is the bridge's source contract (docs/tools/iam-status-bridge.md).
type Snapshot struct {
	IssuerID       string    `json:"issuer_id"`
	Revision       string    `json:"revision"`
	Complete       bool      `json:"complete"`
	ObservedAt     time.Time `json:"observed_at"`
	RevokedCertIDs []string  `json:"revoked_cert_ids"`
}

// ErrRevoked is what a Checker returns when the provider states that the
// user no longer holds authority (disabled, suspended). It revokes at once.
var ErrRevoked = errors.New("user no longer holds authority")

// ErrAbsent is what a Checker returns when the user is missing: deleted, or
// not a member of a configured group. Absence can be replication lag, so it
// revokes only after it has lasted Source.AbsenceConfirm, and only on a read
// that fully succeeds.
var ErrAbsent = errors.New("user is absent")

// Checker reads one mapped user. It returns nil while the user holds
// authority, ErrRevoked or ErrAbsent once the user has lost it, and any
// other error when the answer is not known.
type Checker func(ctx context.Context, userID string) error

// Read is one authoritative read. Finish runs after every user was checked
// and confirms the read's own inputs (such as each configured group) are
// still valid; an error withholds the snapshot.
type Read struct {
	Check  Checker
	Finish func(ctx context.Context) error
}

// Provider reads one identity provider, read-only.
type Provider interface {
	// Name is used in logs and errors, for example "Entra ID".
	Name() string
	// ValidUserID accepts only the provider's immutable user ID format, so
	// a login or email that can later name another person is refused.
	ValidUserID(id string) bool
	// UserIDHint describes the accepted user ID format for error messages.
	UserIDHint() string
	// Begin starts one authoritative read (credentials, group membership)
	// and returns the per-user check and end-of-read recheck for that read.
	Begin(ctx context.Context) (Read, error)
}

// Source serves snapshots from a Provider. Every request is a fresh read.
type Source struct {
	Provider       Provider
	RevisionPrefix string
	// AbsenceConfirm is how long a user must stay absent before the
	// absence revokes.
	AbsenceConfirm time.Duration
	IssuerID       string
	StatePath      string
	Mapping        map[string]string // exact cert_id -> immutable user ID
	// MappingFile, when set, is re-read for every snapshot so edits take
	// effect without a restart; an unreadable or invalid file fails closed.
	MappingFile    string
	Now            func() time.Time
	mu             sync.Mutex
	pending        map[string]bool      // observed revocations not yet durably saved
	pendingTracked map[string]string    // mappings read but not yet durably saved
	absentSince    map[string]time.Time // user -> first read that found the user absent
}

func (s *Source) Snapshot(ctx context.Context) (result Snapshot, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name := s.Provider.Name()
	state, err := LoadState(s.StatePath, s.IssuerID, s.Provider)
	if err != nil {
		return Snapshot{}, err
	}
	// Mark the read durably before contacting the provider. The marker is
	// cleared only once every observed revocation is durable; a marker left
	// by an interrupted read stops the source until an operator recovers it.
	if err := ensureScanning(s.StatePath, s.Now().UTC()); err != nil {
		return Snapshot{}, err
	}
	defer func() {
		if len(s.pending) == 0 && len(s.pendingTracked) == 0 {
			if err := clearScanning(s.StatePath); err != nil && resultErr == nil {
				result, resultErr = Snapshot{}, err
			}
		}
	}()
	mapping := s.Mapping
	if s.MappingFile != "" {
		if mapping, err = ReadMapping(s.MappingFile, s.Provider); err != nil {
			return Snapshot{}, err
		}
	}
	revoked := map[string]bool{}
	for _, id := range state.RevokedCertIDs {
		revoked[id] = true
	}
	for id := range s.pending {
		revoked[id] = true
	}
	// Every certificate ever mapped and not yet revoked stays checked, even
	// after it leaves the mapping, so the snapshot remains complete.
	tracked := maps.Clone(state.Tracked)
	for certID, user := range s.pendingTracked {
		if _, known := tracked[certID]; !known && !revoked[certID] {
			tracked[certID] = user
		}
	}
	for certID, user := range mapping {
		if prior, ok := tracked[certID]; ok && prior != user {
			return Snapshot{}, fmt.Errorf("mapping moves certificate %s to another user; issue a new certificate ID", certID)
		}
		if !revoked[certID] {
			tracked[certID] = user
		}
	}
	// Record new mappings before reading the provider, so a certificate
	// stays tracked even if this read fails and the entry is later removed.
	if !maps.Equal(tracked, state.Tracked) {
		state.Tracked = maps.Clone(tracked)
		if err := saveState(s.StatePath, state); err != nil {
			s.keepPendingTracked(tracked)
			return Snapshot{}, err
		}
		if state, err = LoadState(s.StatePath, s.IssuerID, s.Provider); err != nil {
			return Snapshot{}, err
		}
	}
	read, readErr := s.Provider.Begin(ctx)
	if readErr != nil {
		readErr = fmt.Errorf("%s read: %w", name, readErr)
	}
	for certID := range revoked {
		delete(tracked, certID)
	}
	// Read each user once and apply the result to every certificate mapped
	// to that user, so one observation revokes them together.
	byUser := map[string][]string{}
	for certID, user := range tracked {
		byUser[user] = append(byUser[user], certID)
	}
	revokedUsers := map[string]bool{}
	// Absence observations are staged and only counted if the whole read
	// succeeds, so a failed read can neither start nor advance the clock.
	var absentUsers, presentUsers []string
	if s.absentSince == nil {
		s.absentSince = map[string]time.Time{}
	}
	for _, user := range slices.Sorted(maps.Keys(byUser)) {
		if readErr != nil {
			break
		}
		err := read.Check(ctx, user)
		if errors.Is(err, ErrAbsent) {
			absentUsers = append(absentUsers, user)
			continue
		}
		if err == nil {
			presentUsers = append(presentUsers, user)
			continue
		}
		if errors.Is(err, ErrRevoked) {
			revokedUsers[user] = true
			for _, certID := range byUser[user] {
				revoked[certID] = true
				delete(tracked, certID)
			}
			continue
		}
		if err != nil {
			readErr = fmt.Errorf("%s user %s: %w", name, user, err)
		}
	}
	if readErr == nil {
		if err := read.Finish(ctx); err != nil {
			readErr = fmt.Errorf("%s read: %w", name, err)
		}
	}
	// The snapshot is complete only for the mapping it read: a mapping edit
	// during the reads fails this request, and the next read includes it.
	// Even after a provider error, mappings added during the read are
	// applied, so a revocation this read observed also covers them.
	if s.MappingFile != "" {
		current, err := ReadMapping(s.MappingFile, s.Provider)
		if err != nil || !maps.Equal(current, mapping) {
			if readErr == nil {
				readErr = fmt.Errorf("mapping file changed during the %s read", name)
			}
			for certID, user := range current {
				if _, known := tracked[certID]; known || revoked[certID] {
					continue
				}
				if revokedUsers[user] {
					revoked[certID] = true
				} else {
					tracked[certID] = user
				}
			}
		}
	}
	// On a fully successful read, count the absences. A confirmed absence
	// revokes; an unconfirmed one withholds the snapshot (fail closed) while
	// the explicit and confirmed revocations of this read are still kept.
	if readErr == nil {
		now := s.Now()
		for _, user := range presentUsers {
			delete(s.absentSince, user)
		}
		var unconfirmed []string
		for _, user := range absentUsers {
			since, seen := s.absentSince[user]
			switch {
			case !seen:
				s.absentSince[user] = now
				unconfirmed = append(unconfirmed, user)
			case now.Sub(since) >= s.AbsenceConfirm:
				for _, certID := range byUser[user] {
					revoked[certID] = true
					delete(tracked, certID)
				}
				delete(s.absentSince, user)
			default:
				unconfirmed = append(unconfirmed, user)
			}
		}
		if len(unconfirmed) > 0 {
			readErr = fmt.Errorf("%s reports %d mapped users absent (deleted or not in a configured group); withholding snapshots until the absence has lasted %s",
				name, len(unconfirmed), s.AbsenceConfirm)
		}
	}
	if readErr != nil {
		// Serve nothing, but keep every revocation already observed: a user
		// reinstated before the next read must not be regranted.
		if err := s.saveRevoked(state, tracked, revoked); err != nil {
			s.keepPending(revoked)
			s.keepPendingTracked(tracked)
			return Snapshot{}, err
		}
		s.pending, s.pendingTracked = nil, nil
		return Snapshot{}, readErr
	}
	observedAt := s.Now().UTC()
	out := append([]string{}, slices.Sorted(maps.Keys(revoked))...)
	// Persist before serving so a revocation is never served and then lost.
	if len(s.pending) > 0 || len(s.pendingTracked) > 0 || !slices.Equal(out, state.RevokedCertIDs) || !maps.Equal(tracked, state.Tracked) {
		if err := saveState(s.StatePath, StateFile{IssuerID: s.IssuerID, Tracked: tracked, RevokedCertIDs: out}); err != nil {
			s.keepPending(revoked)
			s.keepPendingTracked(tracked)
			return Snapshot{}, err
		}
	}
	s.pending, s.pendingTracked = nil, nil
	digest := sha256.New()
	for _, id := range out {
		digest.Write([]byte(id + "\n"))
	}
	return Snapshot{IssuerID: s.IssuerID, Revision: s.RevisionPrefix + hex.EncodeToString(digest.Sum(nil))[:16],
		Complete: true, ObservedAt: observedAt, RevokedCertIDs: out}, nil
}

func (s *Source) keepPending(revoked map[string]bool) {
	if s.pending == nil {
		s.pending = map[string]bool{}
	}
	for id := range revoked {
		s.pending[id] = true
	}
}

func (s *Source) keepPendingTracked(tracked map[string]string) {
	if s.pendingTracked == nil {
		s.pendingTracked = map[string]string{}
	}
	maps.Copy(s.pendingTracked, tracked)
}

func (s *Source) saveRevoked(state StateFile, tracked map[string]string, revoked map[string]bool) error {
	if len(s.pending) == 0 && len(s.pendingTracked) == 0 && len(revoked) == len(state.RevokedCertIDs) && maps.Equal(tracked, state.Tracked) {
		return nil
	}
	out := append([]string{}, slices.Sorted(maps.Keys(revoked))...)
	return saveState(s.StatePath, StateFile{IssuerID: s.IssuerID, Tracked: tracked, RevokedCertIDs: out})
}

func clearScanning(path string) error {
	if err := os.Remove(path + ".scanning"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(path)
}

// InterruptedScan reports a read marker left by a process that stopped
// mid-read; the source refuses to start until an operator recovers it.
func InterruptedScan(path string) bool {
	_, err := os.Stat(path + ".scanning")
	return err == nil
}

// InterruptedScanStart is when the earliest unresolved read began.
func InterruptedScanStart(path string) string {
	data, _ := os.ReadFile(path + ".scanning")
	return strings.TrimSpace(string(data))
}

// ensureScanning makes the read marker durable before any provider read. An
// existing marker keeps its start time but is synced again.
func ensureScanning(path string, now time.Time) error {
	marker := path + ".scanning"
	f, err := os.OpenFile(marker, os.O_RDWR, 0600)
	if errors.Is(err, os.ErrNotExist) {
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
	if _, perr := time.Parse(time.RFC3339, InterruptedScanStart(path)); perr != nil {
		f.Close()
		return errors.New("the interrupted-read marker is malformed; reconcile from the identity provider's audit log and run recover")
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

// StateFile retains every revoked certificate ID for one issuer, and every
// mapped certificate not yet revoked with its user ID.
type StateFile struct {
	IssuerID       string            `json:"issuer_id"`
	Generation     uint64            `json:"generation"`
	Tracked        map[string]string `json:"tracked"`
	RevokedCertIDs []string          `json:"revoked_cert_ids"`
}

// InitState creates the empty state once, optionally seeded with prior
// revocations. A lost state file is never silently recreated empty.
func InitState(path, issuerID string, revoked ...string) error {
	for _, id := range revoked {
		if !exactID(id) {
			return fmt.Errorf("seeded certificate ID %q is empty, too long, or not exact UTF-8", id)
		}
	}
	marker := path + ".lock"
	if info, err := os.Stat(marker); err == nil && info.Size() > 0 {
		return errors.New("this source was initialized before; restore its state file from backup instead")
	}
	if err := writeSynced(marker, []byte("initialized\n"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC); err != nil {
		return err
	}
	seed := slices.Clone(revoked)
	slices.Sort(seed)
	data, err := json.Marshal(StateFile{IssuerID: issuerID, Tracked: map[string]string{}, RevokedCertIDs: append([]string{}, slices.Compact(seed)...)})
	if err != nil {
		return err
	}
	if err := writeSynced(path, data, os.O_WRONLY|os.O_CREATE|os.O_EXCL); err != nil {
		return fmt.Errorf("create state file: %w", err)
	}
	return writeCheckpoint(path, 0)
}

// The checkpoint records the generation of the last durable save, so an
// older state (a restored backup) is refused.
func writeCheckpoint(path string, generation uint64) error {
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

// LockState makes this process the only writer of the state file until the
// returned file is closed.
func LockState(path string) (*os.File, error) {
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

// LoadState reads and checks the state against its issuer and checkpoint.
func LoadState(path, issuerID string, p Provider) (StateFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return StateFile{}, fmt.Errorf("revocation state (run init once, then restore from backup only): %w", err)
	}
	var state StateFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil || state.RevokedCertIDs == nil || state.Tracked == nil {
		return StateFile{}, errors.New("revocation state file is invalid")
	}
	if state.IssuerID != issuerID {
		return StateFile{}, errors.New("revocation state file belongs to another issuer")
	}
	for _, id := range state.RevokedCertIDs {
		if !exactID(id) {
			return StateFile{}, fmt.Errorf("revocation state holds an invalid certificate ID %q", id)
		}
	}
	for certID, user := range state.Tracked {
		if !exactID(certID) || !p.ValidUserID(user) {
			return StateFile{}, fmt.Errorf("revocation state tracks an invalid entry %q", certID)
		}
	}
	checkpoint, err := readCheckpoint(path)
	if err != nil {
		return StateFile{}, err
	}
	switch {
	case state.Generation < checkpoint:
		return StateFile{}, fmt.Errorf("revocation state generation %d is older than its checkpoint %d; restore the latest state", state.Generation, checkpoint)
	case state.Generation == checkpoint+1:
		// A save that crashed before its checkpoint: complete it first.
		if err := writeCheckpoint(path, state.Generation); err != nil {
			return StateFile{}, err
		}
	case state.Generation > checkpoint+1:
		return StateFile{}, fmt.Errorf("revocation state generation %d is ahead of its checkpoint %d by more than one save", state.Generation, checkpoint)
	}
	return state, nil
}

func saveState(path string, state StateFile) error {
	checkpoint, err := readCheckpoint(path)
	if err != nil {
		return err
	}
	if data, err := os.ReadFile(path); err == nil {
		var current StateFile
		if json.Unmarshal(data, &current) == nil && current.IssuerID == state.IssuerID && current.Generation > checkpoint {
			checkpoint = current.Generation
		}
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

// Handler serves GET with a bearer token. Every request is a fresh
// authoritative read; a failure answers 503 with no snapshot.
func Handler(source *Source, bearer string) http.Handler {
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
			log.Printf("%s snapshot failed; serving no snapshot: %v", source.Provider.Name(), err)
			http.Error(w, "IAM snapshot unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(got)
	})
}

// Config holds the settings every reference source shares. Each command
// embeds it in its own JSON config beside its provider settings.
type Config struct {
	IssuerID    string `json:"issuer_id"`
	MappingFile string `json:"mapping_file"`
	StateFile   string `json:"state_file"`
	ListenAddr  string `json:"listen_addr"`
	TLSCertFile string `json:"tls_cert_file"`
	TLSKeyFile  string `json:"tls_key_file"`
}

var hexIssuer = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (c Config) Validate() error {
	if !hexIssuer.MatchString(c.IssuerID) {
		return errors.New("issuer_id must be the 64-character lowercase hex issuer ID")
	}
	if c.MappingFile == "" || c.StateFile == "" || c.ListenAddr == "" || c.TLSCertFile == "" || c.TLSKeyFile == "" {
		return errors.New("mapping_file, state_file, listen_addr, tls_cert_file, and tls_key_file are required")
	}
	return nil
}

// ReadMapping reads and validates the customer's cert_id -> user ID file.
func ReadMapping(path string, p Provider) (map[string]string, error) {
	return readMappingLimit(path, p, 10000)
}

// ReadInventory reads a recovery inventory, which can hold every
// certificate the source has accumulated across mapping edits.
func ReadInventory(path string, p Provider) (map[string]string, error) {
	return readMappingLimit(path, p, 1_000_000)
}

// exactID rejects identifiers that JSON decoding could have altered.
func exactID(id string) bool {
	return id != "" && len(id) <= ratify.MaxIdentifierLengthBytes && utf8.ValidString(id) && !strings.ContainsRune(id, utf8.RuneError)
}

func readMappingLimit(path string, p Provider, limit int) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("mapping file: %w", err)
	}
	invalid := fmt.Errorf("mapping file must be one JSON object of at most %d distinct cert_id to user ID entries", limit)
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
	if _, err := decoder.Token(); err != io.EOF || len(mapping) > limit {
		return nil, invalid
	}
	for certID, user := range mapping {
		if !exactID(certID) || !p.ValidUserID(user) {
			return nil, fmt.Errorf("mapping for %q must name %s, not a login or email", certID, p.UserIDHint())
		}
	}
	return mapping, nil
}

// RecoverInterruptedRead tracks the complete inventory, then clears the
// interrupted-read marker.
func RecoverInterruptedRead(path, issuerID string, p Provider, inventory map[string]string) error {
	if err := TrackInventory(path, issuerID, p, inventory); err != nil {
		return err
	}
	return clearScanning(path)
}

// TrackInventory durably tracks every unrevoked certificate in inventory.
func TrackInventory(path, issuerID string, p Provider, inventory map[string]string) error {
	state, err := LoadState(path, issuerID, p)
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
