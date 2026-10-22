package v2vectors

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/v2reference"
)

// SecurityJournalV2 known-answer vectors (SPEC-v2 §6.6). The genesis snapshot
// and every digest are recomputed here independently from the snapshot bytes;
// the snapshot bytes after each transition are produced by the reference
// reducer and pin its behavior for the other SDKs. They are therefore
// reference known answers, not an independent derivation of the reducer.

type journalKeyJSON struct {
	Name      string         `json:"name"`
	KeyIDV2   string         `json:"key_id_v2"`
	PublicKey map[string]any `json:"public_key"`
}

type journalStepJSON struct {
	Op             string            `json:"op"`
	Role           string            `json:"role,omitempty"`
	IssuerID       string            `json:"issuer_id,omitempty"`
	Epoch          uint64            `json:"epoch,omitempty"`
	Key            *journalKeyJSON   `json:"key"`
	ObjectTypeCode int               `json:"object_type_code,omitempty"`
	WireB64        string            `json:"wire_b64,omitempty"`
	Now            int64             `json:"now,omitempty"`
	Policy         *statusPolicyJSON `json:"policy,omitempty"`
	ExpectRejected bool              `json:"expect_rejected,omitempty"`
	ExpectChanged  bool              `json:"expect_changed"`
	ExpectHead     journalHeadJSON   `json:"expect_head"`
	ExpectSnapshot string            `json:"expect_snapshot_b64"`
}

type journalHeadJSON struct {
	Generation uint64 `json:"generation"`
	Digest     string `json:"digest"`
}

type journalScenarioJSON struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Steps       []journalStepJSON `json:"steps"`
}

type journalMigrationJSON struct {
	Description             string          `json:"description"`
	LegacyRecordB64         string          `json:"legacy_record_b64"`
	LegacyDigestInputB64    string          `json:"legacy_digest_input_b64"`
	LegacyDigest            string          `json:"legacy_digest"`
	ExpectHead              journalHeadJSON `json:"expect_head"`
	ExpectPreviousDigest    string          `json:"expect_previous_digest"`
	ExpectSnapshotB64       string          `json:"expect_snapshot_b64"`
	TamperedLegacyRecordB64 string          `json:"tampered_legacy_record_b64"`
}

type journalImportNegativeJSON struct {
	Name             string          `json:"name"`
	Description      string          `json:"description"`
	SnapshotB64      string          `json:"snapshot_b64"`
	Head             journalHeadJSON `json:"head"`
	ExpectErrorClass string          `json:"expect_error_class"`
}

type journalFile struct {
	Version         int                         `json:"version"`
	Description     string                      `json:"description"`
	Operations      map[string]string           `json:"operations"`
	GenesisSnapshot string                      `json:"genesis_snapshot"`
	GenesisDigest   string                      `json:"genesis_digest"`
	Scenarios       []journalScenarioJSON       `json:"scenarios"`
	Migration       journalMigrationJSON        `json:"migration"`
	ImportNegatives []journalImportNegativeJSON `json:"import_negatives"`
}

func journalDigest(snapshot []byte) string {
	return hex.EncodeToString(sha384Prefixed("ratify-protocol-security-journal-v2", snapshot))
}

type journalRun struct {
	g     *gen
	store *v2reference.JournalStore
	sc    journalScenarioJSON
	last  *ratify.SecurityJournalV2
}

func (g *gen) journalRun(name, desc string) *journalRun {
	store := must(v2reference.NewJournalStore())
	return &journalRun{g: g, store: store, sc: journalScenarioJSON{Name: name, Description: desc}}
}

func (r *journalRun) keyJSON(name string) *journalKeyJSON {
	k := r.g.k(name)
	return &journalKeyJSON{Name: name, KeyIDV2: k.ID, PublicKey: pubJSON(k.Pub)}
}

func (r *journalRun) step(step journalStepJSON, apply func(ctx context.Context) (ratify.SecurityJournalV2, error)) *journalRun {
	before := r.store.Head()
	journal, err := apply(context.Background())
	if (err != nil) != step.ExpectRejected {
		panic(fmt.Sprintf("journal scenario %s op %s: rejected=%v want %v", r.sc.Name, step.Op, err, step.ExpectRejected))
	}
	head := r.store.Head()
	loaded, _, loadErr := r.store.Load(context.Background())
	if loadErr != nil {
		panic(loadErr)
	}
	snapshot := must(ratify.ExportSecurityJournalSnapshotV2(loaded))
	if journalDigest(snapshot) != head.Digest {
		panic("journal digest does not match independent recomputation")
	}
	if err == nil && journal.Digest != head.Digest {
		panic("journal transition result differs from anchored head")
	}
	step.ExpectChanged = head != before
	step.ExpectHead = journalHeadJSON{Generation: head.Generation, Digest: head.Digest}
	step.ExpectSnapshot = b64(snapshot)
	r.sc.Steps = append(r.sc.Steps, step)
	r.last = &loaded
	return r
}

func (r *journalRun) recordRole(role, key string, rejected bool) *journalRun {
	return r.step(journalStepJSON{Op: "record_key_role", Role: role, Key: r.keyJSON(key), ExpectRejected: rejected}, func(ctx context.Context) (ratify.SecurityJournalV2, error) {
		return ratify.RecordSecurityKeyRoleV2(ctx, r.store, role, r.g.k(key).Pub)
	})
}

func (r *journalRun) configure(issuer string, epoch uint64, key string, rejected bool) *journalRun {
	issuerID := r.g.k(issuer).ID
	return r.step(journalStepJSON{Op: "configure_status_key_epoch", IssuerID: issuerID, Epoch: epoch, Key: r.keyJSON(key), ExpectRejected: rejected}, func(ctx context.Context) (ratify.SecurityJournalV2, error) {
		return ratify.ConfigureStatusKeyEpochV2(ctx, r.store, issuerID, epoch, r.g.k(key).Pub)
	})
}

var journalPolicy = statusPolicyJSON{MaxListLifetimeSeconds: 3600, MaxStatusAgeSeconds: 600, ClockSkewSeconds: 5}

func (r *journalRun) applyObject(issuer string, epoch uint64, key string, code uint16, wire []byte, now int64, rejected bool) *journalRun {
	issuerID := r.g.k(issuer).ID
	policy := journalPolicy
	op := "apply_revocation_list"
	if code == codePush {
		op = "apply_revocation_push"
	}
	lib := ratify.RevocationStatusPolicyV2{MaxListLifetimeSeconds: policy.MaxListLifetimeSeconds, MaxStatusAgeSeconds: policy.MaxStatusAgeSeconds, ClockSkewSeconds: policy.ClockSkewSeconds}
	return r.step(journalStepJSON{Op: op, IssuerID: issuerID, Epoch: epoch, Key: r.keyJSON(key), ObjectTypeCode: int(code), WireB64: b64(wire), Now: now, Policy: &policy, ExpectRejected: rejected},
		func(ctx context.Context) (ratify.SecurityJournalV2, error) {
			if code == codeList {
				return ratify.ApplyRevocationListToJournalV2(ctx, r.store, must(ratify.DecodeRevocationListV2(wire)), issuerID, epoch, r.g.k(key).Pub, lib, now)
			}
			return ratify.ApplyRevocationPushToJournalV2(ctx, r.store, must(ratify.DecodeRevocationPushV2(wire)), issuerID, epoch, r.g.k(key).Pub, lib, now)
		})
}

func (g *gen) journalFile() any {
	genesis := ratify.EmptySecurityJournalV2()
	genesisSnapshot := `{"generation":0,"issuers":[],"key_role_history":[],"previous_digest":"` + strings.Repeat("0", 96) + `","status_key_history":[],"version":2}`
	if !bytes.Equal(must(ratify.ExportSecurityJournalSnapshotV2(genesis)), []byte(genesisSnapshot)) || journalDigest([]byte(genesisSnapshot)) != genesis.Digest {
		panic("genesis snapshot or digest differs from SPEC-v2 §6.6")
	}
	f := journalFile{
		Version:     2,
		Description: "SecurityJournalV2 logical snapshot and transition known answers (SPEC-v2 §6.6). Each scenario starts at the genesis journal anchored in a fresh store. After each step the anchored head and the exact canonical snapshot must equal the expectation; a rejected step leaves both unchanged. Digests are SHA-384(\"ratify-protocol-security-journal-v2\" || 0x00 || snapshot) in lowercase hex.",
		Operations: map[string]string{
			"record_key_role":            "RecordKeyRole(role, key) for a non-status role",
			"configure_status_key_epoch": "ConfigureStatusKeyEpoch(issuer_id, epoch, key)",
			"apply_revocation_list":      "ApplyRevocationList(issuer_id, epoch, key, list, policy, now) committed as one transition",
			"apply_revocation_push":      "ApplyRevocationPush(issuer_id, epoch, key, push, policy, now) committed as one transition",
			"expect_changed":             "false when the operation is a canonical no-op and the head does not move",
			"migration":                  "decode legacy_record_b64 (the version 1 alpha record), validate it under the alpha digest (SHA-384 of legacy_digest_input_b64), migrate it to version 2 at generation+1 with previous_digest = legacy digest; tampered_legacy_record_b64 must be refused",
			"import_negatives":           "import snapshot_b64 against head; it must be refused with expect_error_class",
		},
		GenesisSnapshot: genesisSnapshot, GenesisDigest: genesis.Digest,
	}
	root, intermediate := "root", "intermediate"

	r := g.journalRun("roles_and_status_epochs", "non-status roles, a first status epoch, idempotent repeats, component reuse rejection, and an epoch transition")
	r.recordRole("verifier", "verifier", false).recordRole("verifier", "verifier", false)
	r.configure(root, 1, "status_root", false).configure(root, 1, "status_root", false)
	r.recordRole("delegation", "status_root", true)
	r.configure(root, 3, "status_root_epoch_2", true)
	r.configure(root, 2, "status_root_epoch_2", false)
	r.configure(intermediate, 1, "status_root", true)
	f.Scenarios = append(f.Scenarios, r.sc)

	r = g.journalRun("status_reducer_transitions", "bootstrap, contiguous push, semantic duplicate, gap, reconciliation, and an epoch transition that keeps the deny union")
	r.configure(root, 1, "status_root", false)
	rootID := g.k(root).ID
	_, l1, _ := g.list(g.k("status_root"), rootID, 1, Now-60, Now+1800, "c1")
	_, p2, _ := g.push(g.k("status_root"), rootID, 2, Now-30, "c2")
	_, p4, _ := g.push(g.k("status_root"), rootID, 4, Now-30, "c4")
	_, l4, _ := g.list(g.k("status_root"), rootID, 4, Now-20, Now+1800, "c1", "c2", "c4")
	_, wrongKey, _ := g.list(g.k("status_party_b"), rootID, 5, Now-20, Now+1800, "c1")
	r.applyObject(root, 1, "status_root", codeList, l1, Now, false)
	r.applyObject(root, 1, "status_root", codePush, p2, Now, false)
	r.applyObject(root, 1, "status_root", codePush, p2, Now, false)
	r.applyObject(root, 1, "status_root", codePush, p4, Now, false)
	r.applyObject(root, 1, "status_root", codeList, l4, Now, false)
	r.applyObject(root, 1, "status_root", codeList, wrongKey, Now, true)
	r.configure(root, 2, "status_root_epoch_2", false)
	_, n1, _ := g.list(g.k("status_root_epoch_2"), rootID, 1, Now-10, Now+1800, "c1", "c2", "c4")
	r.applyObject(root, 2, "status_root_epoch_2", codeList, n1, Now, false)
	f.Scenarios = append(f.Scenarios, r.sc)
	committed := *r.last

	// Migration of a version 1 record with the same logical content.
	legacy := committed
	legacy.Version = 1
	legacy.Digest = ""
	legacyInput := must(json.Marshal(legacy))
	legacy.Digest = hex.EncodeToString(sha384(legacyInput))
	legacyRecord := must(json.Marshal(legacy))
	migrated := must(ratify.MigrateSecurityJournalV2(legacy))
	migratedSnapshot := must(ratify.ExportSecurityJournalSnapshotV2(migrated))
	if journalDigest(migratedSnapshot) != migrated.Digest {
		panic("migrated digest differs from independent recomputation")
	}
	tampered := legacy
	tampered.Generation++
	f.Migration = journalMigrationJSON{
		Description:     "the reducer_transitions final state re-encoded as a version 1 alpha record",
		LegacyRecordB64: b64(legacyRecord), LegacyDigestInputB64: b64(legacyInput), LegacyDigest: legacy.Digest,
		ExpectHead:           journalHeadJSON{Generation: migrated.Generation, Digest: migrated.Digest},
		ExpectPreviousDigest: migrated.PreviousDigest, ExpectSnapshotB64: b64(migratedSnapshot),
		TamperedLegacyRecordB64: b64(must(json.Marshal(tampered))),
	}

	snapshot := must(ratify.ExportSecurityJournalSnapshotV2(committed))
	head := journalHeadJSON{Generation: committed.Generation, Digest: committed.Digest}
	neg := func(name, desc string, data []byte, h journalHeadJSON, class string) {
		f.ImportNegatives = append(f.ImportNegatives, journalImportNegativeJSON{Name: name, Description: desc, SnapshotB64: b64(data), Head: h, ExpectErrorClass: class})
	}
	selfHead := func(data []byte) journalHeadJSON {
		return journalHeadJSON{Generation: committed.Generation, Digest: journalDigest(data)}
	}
	neg("head_digest_mismatch", "a canonical snapshot whose digest differs from the anchored head", snapshot, journalHeadJSON{Generation: head.Generation, Digest: strings.Repeat("e", 96)}, "log_state_mismatch")
	neg("head_generation_mismatch", "a canonical snapshot whose generation differs from the anchored head", snapshot, journalHeadJSON{Generation: head.Generation + 1, Digest: head.Digest}, "log_state_mismatch")
	spaced := append([]byte(" "), snapshot...)
	neg("noncanonical_whitespace", "insignificant whitespace makes a snapshot noncanonical even with a matching head", spaced, selfHead(spaced), "malformed")
	unknown := bytes.Replace(snapshot, []byte(`{"generation"`), []byte(`{"extra":1,"generation"`), 1)
	neg("unknown_member", "an unknown member is rejected", unknown, selfHead(unknown), "malformed")
	snap := parse(snapshot).(map[string]any)
	issuers := arr(snap["issuers"])
	observations := arr(obj(issuers[0])["observations"])
	if len(observations) < 2 {
		panic("reorder negative needs two observations")
	}
	observations[0], observations[len(observations)-1] = observations[len(observations)-1], observations[0]
	reordered := canon(snap)
	neg("observations_out_of_compaction_order", "observations not in compaction order are rejected", reordered, selfHead(reordered), "malformed")
	// Integers above 2^53-1 are malformed under the safe-integer rule of
	// SPEC-v2 §2.1 even where the Go field is a 64-bit integer.
	replaceFirst := func(pattern, replacement string) []byte {
		loc := regexp.MustCompile(pattern).FindIndex(snapshot)
		if loc == nil {
			panic("journal negative pattern not found: " + pattern)
		}
		return append(append(append([]byte(nil), snapshot[:loc[0]]...), replacement...), snapshot[loc[1]:]...)
	}
	for _, c := range []struct{ name, member, value string }{
		{"unsafe_integer_max_observed_sequence", "max_observed_sequence", "9007199254740992"},
		{"unsafe_integer_fork_sequence", "fork_sequence", "9007199254740992"},
		{"unsafe_integer_status_key_epoch", "status_key_epoch", "18446744073709551615"},
	} {
		bad := replaceFirst(`"`+c.member+`":[0-9]+`, `"`+c.member+`":`+c.value)
		neg(c.name, "the first "+c.member+" is "+c.value+", above 2^53-1", bad, selfHead(bad), "malformed")
	}
	caseVariant := bytes.Replace(snapshot, []byte(`"issuers":`), []byte(`"Issuers":`), 1)
	neg("member_name_case", "the member issuers is spelled Issuers", caseVariant, selfHead(caseVariant), "malformed")
	nullElement := replaceFirst(`"accepted_cert_ids":\["[^"]*"`, `"accepted_cert_ids":[null`)
	neg("null_array_element", "the first accepted_cert_ids element is null", nullElement, selfHead(nullElement), "malformed")
	genesisBad := []byte(strings.Replace(genesisSnapshot, strings.Repeat("0", 96), strings.Repeat("1", 96), 1))
	neg("genesis_with_predecessor", "a genesis snapshot whose previous_digest is not all zeros", genesisBad, journalHeadJSON{Generation: 0, Digest: journalDigest(genesisBad)}, "malformed")
	return f
}
