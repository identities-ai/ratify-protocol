package v2vectors

import (
	"bytes"
	"cmp"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"maps"
	"slices"
	"strings"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// Single-device offline complete-state projection known answers (SPEC-v2
// §7.13). Each case gives a primary's durable records in a store-neutral
// form, listed out of order, and the exact RatifyCanonicalJSON of every
// projection member, its SHA-384, the projection object, and the labelled
// complete-state digest. The expected values are derived here from the
// §7.13 record encodings, independently of the reference store; the Go
// reference loads each state into its store and must reproduce every byte.

const deviceStateFile = "device-state.json"

type deviceStateExpectJSON struct {
	Claims                 string `json:"claims_canonical_json"`
	ClaimsSHA384           string `json:"claims_sha384"`
	IssuanceRecords        string `json:"issuance_records_canonical_json"`
	IssuanceRecordsSHA384  string `json:"issuance_records_sha384"`
	RateCounters           string `json:"rate_counters_canonical_json"`
	RateCountersSHA384     string `json:"rate_counters_sha384"`
	ReceiptLog             string `json:"receipt_log_canonical_json"`
	ReceiptLogSHA384       string `json:"receipt_log_sha384"`
	Streams                string `json:"streams_canonical_json"`
	StreamsSHA384          string `json:"streams_sha384"`
	Projection             string `json:"projection_canonical_json"`
	CompleteStateDigestHex string `json:"complete_state_digest_hex"`
}

type deviceStateCaseJSON struct {
	Name        string                `json:"name"`
	Description string                `json:"description"`
	State       map[string]any        `json:"state"`
	Expect      deviceStateExpectJSON `json:"expect"`
}

type deviceStateFileJSON struct {
	Description string                `json:"description"`
	Label       string                `json:"label"`
	Version     int                   `json:"version"`
	Semantics   map[string]string     `json:"semantics"`
	Cases       []deviceStateCaseJSON `json:"cases"`
}

func sha384HexOf(b []byte) string {
	sum := sha512.Sum384(b)
	return hex.EncodeToString(sum[:])
}

// rawSHA384 maps a state's base64 byte string (or null) to the projection's
// lowercase hex SHA-384 of those bytes (or null).
func rawSHA384(v any) any {
	if v == nil {
		return nil
	}
	return sha384HexOf(must(base64.StdEncoding.DecodeString(v.(string))))
}

func b64Bytes(v any) []byte { return must(base64.StdEncoding.DecodeString(v.(string))) }

// projectDeviceState applies the §7.13 record encodings to a state.
func projectDeviceState(state map[string]any) deviceStateExpectJSON {
	claims := []any{}
	for _, c := range state["claims"].([]any) {
		in := c.(map[string]any)
		out := maps.Clone(in)
		delete(out, "terminal_b64")
		delete(out, "receipt_body_b64")
		out["terminal_sha384"] = rawSHA384(in["terminal_b64"])
		out["receipt_body_sha384"] = rawSHA384(in["receipt_body_b64"])
		claims = append(claims, out)
	}
	slices.SortFunc(claims, func(a, b any) int { return strings.Compare(obj(a)["claim_id"].(string), obj(b)["claim_id"].(string)) })

	streams := slices.Clone(state["streams"].([]any))
	slices.SortFunc(streams, func(a, b any) int {
		x, y := obj(a), obj(b)
		return cmp.Or(strings.Compare(x["namespace"].(string), y["namespace"].(string)), strings.Compare(x["agent_id"].(string), y["agent_id"].(string)),
			bytes.Compare(b64Bytes(x["stream_id"]), b64Bytes(y["stream_id"])))
	})

	issuance := slices.Clone(state["issuance_records"].([]any))
	slices.SortFunc(issuance, func(a, b any) int {
		x, y := obj(a), obj(b)
		return cmp.Or(strings.Compare(x["verifier_namespace"].(string), y["verifier_namespace"].(string)),
			cmp.Compare(x["replay_epoch"].(int64), y["replay_epoch"].(int64)), bytes.Compare(b64Bytes(x["value"]), b64Bytes(y["value"])))
	})

	rates := slices.Clone(state["rate_counters"].([]any))
	slices.SortFunc(rates, func(a, b any) int {
		x, y := obj(a), obj(b)
		return cmp.Or(strings.Compare(x["issuer_id"].(string), y["issuer_id"].(string)), strings.Compare(x["cert_id"].(string), y["cert_id"].(string)),
			cmp.Compare(x["window_s"].(int64), y["window_s"].(int64)))
	})

	logIn := obj(state["receipt_log"])
	entries := []any{}
	for i, e := range logIn["entries"].([]any) {
		in := obj(e)
		entries = append(entries, map[string]any{"body_sha384": rawSHA384(in["body_b64"]), "claim_id": in["claim_id"], "entry_hash": in["entry_hash"], "sequence": int64(i + 1)})
	}
	receiptLog := map[string]any{"entries": entries, "frozen": logIn["frozen"], "log_id": state["log_id"]}

	journal := obj(state["security_journal"])
	ex := deviceStateExpectJSON{
		Claims: string(canon(claims)), Streams: string(canon(streams)), IssuanceRecords: string(canon(issuance)),
		RateCounters: string(canon(rates)), ReceiptLog: string(canon(receiptLog)),
	}
	ex.ClaimsSHA384, ex.StreamsSHA384 = sha384HexOf([]byte(ex.Claims)), sha384HexOf([]byte(ex.Streams))
	ex.IssuanceRecordsSHA384, ex.RateCountersSHA384 = sha384HexOf([]byte(ex.IssuanceRecords)), sha384HexOf([]byte(ex.RateCounters))
	ex.ReceiptLogSHA384 = sha384HexOf([]byte(ex.ReceiptLog))
	projection := canon(map[string]any{
		"claims": ex.ClaimsSHA384, "issuance_records": ex.IssuanceRecordsSHA384, "log_id": state["log_id"], "rate_counters": ex.RateCountersSHA384,
		"receipt_log": ex.ReceiptLogSHA384, "replay_epoch": state["replay_epoch"],
		"security_journal": map[string]any{"generation": journal["generation"], "snapshot_sha384": rawSHA384(journal["snapshot_b64"])},
		"streams":          ex.StreamsSHA384, "version": int64(1),
	})
	ex.Projection = string(projection)
	ex.CompleteStateDigestHex = hex.EncodeToString(sha384Prefixed("ratify/device-complete-state/v2", projection))
	return ex
}

func (g *gen) deviceStateFile() any {
	const logID = "dddddddddddddddddddddddddddddd01"
	genesis := must(ratify.ExportSecurityJournalSnapshotV2(ratify.EmptySecurityJournalV2()))
	rep := func(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }
	agentID, verifierID := g.k("agent").ID, g.k("verifier").ID
	rootID, interID := g.k("root").ID, g.k("intermediate").ID
	digest := func(b byte) string { return "sha384:" + hex.EncodeToString(rep(b, 48)) }
	i64 := func(v int64) *int64 { return &v }
	terminal := func(decision, reason, status string) any {
		return b64(canon(map[string]string{"decision": decision, "decision_reason": reason, "identity_status": status}))
	}

	// claimID is the stable claim ID (§2.4) of a labelled test claim: its
	// sealed challenge digest is digest(challenge ^ 0xff) in namespace
	// device-ns, epoch 3, so the projected state is one a store can hold.
	challenges := map[string]byte{"claim-a": 0xa1, "claim-b": 0xb2, "claim-c": 0xc3, "claim-d": 0xd4, "claim-e": 0xe5}
	claimID := func(label string) string {
		id, err := ratify.ProtocolClaimIDFromDigestV2("device-ns", 3, rep(challenges[label]^0xff, 48))
		if err != nil {
			panic(err)
		}
		return id
	}
	// sealed builds the sealed claim object (§6.3, §7.3) of the projection.
	sealed := func(id string, challenge byte, streamID []byte, streamSeq *int64) map[string]any {
		var sid, seq any
		if streamID != nil {
			sid, seq = b64(streamID), *streamSeq
		}
		return map[string]any{
			"agent_id": agentID, "bundle_hash": digest(challenge), "challenge_digest": digest(challenge ^ 0xff), "claim_id": claimID(id),
			"clock_skew_seconds": int64(5), "constraint_evaluators": []any{}, "context_policy_digest": nil, "expires_at": Now + 300,
			"issued_at": Now - 10, "issuer_ids": []any{rootID}, "max_age_seconds": int64(300), "namespace": "device-ns",
			"proof_digest": digest(challenge), "rate_batch": []any{}, "replay_epoch": int64(3),
			"required_scope": "data:read", "requires_rate": false, "stream_id": sid, "stream_seq": seq, "verifier_id": verifierID,
		}
	}
	initialProgress := func() map[string]any {
		return map[string]any{"context_assessment": "not_evaluated", "context_policy_digest": nil, "status_assessment": "not_evaluated", "status_evidence_digests": []any{}, "trust_assessment": "not_evaluated"}
	}
	evidence := func(issuer string, seq int64, b byte) map[string]any {
		return map[string]any{"digest": digest(b), "issuer_id": issuer, "object_type_code": int64(2), "sequence": seq, "status_key_id": g.k("status_root").ID}
	}
	currentProgress := func() map[string]any {
		return map[string]any{"context_assessment": "bound", "context_policy_digest": digest(0xc0), "status_assessment": "current",
			"status_evidence_digests": []any{evidence(interID, 1, 0xe1), evidence(rootID, 7, 0xe2)}, "trust_assessment": "trusted"}
	}
	// claim builds a claim record of the state: raw sealed bytes in base64,
	// which the projection replaces by their SHA-384.
	claim := func(id string, sealedClaim, progress map[string]any) map[string]any {
		return map[string]any{
			"abandoned": false, "allow_horizon": int64(0), "claim": sealedClaim, "claim_id": claimID(id), "claimed_at": Now, "finalized_at": int64(0),
			"lease_expires_at": Now + 30, "log_sequence": nil, "owner_digest": b64(rep(id[len(id)-1], 32)), "progress": progress,
			"receipt_body_b64": nil, "release": nil, "state": "evaluating", "terminal_b64": nil,
		}
	}
	terminalClaim := func(c map[string]any, decision, reason, status string, body string, sequence int64, allowHorizon int64) map[string]any {
		c["state"], c["terminal_b64"], c["receipt_body_b64"] = "terminal", terminal(decision, reason, status), b64([]byte(body))
		c["finalized_at"], c["allow_horizon"], c["log_sequence"] = Now+2, allowHorizon, sequence
		return c
	}
	issuanceRecord := func(namespace string, epoch int64, value byte) map[string]any {
		return map[string]any{
			"context_policy": nil, "expected_agent_id": "", "expected_agent_pub_key": nil, "expected_receiver_id": "", "expected_session_context": nil,
			"expires_at": Now + 300, "issued_at": Now - 10, "replay_epoch": epoch, "value": b64(rep(value, 32)), "verifier_id": verifierID, "verifier_namespace": namespace,
		}
	}
	stream := func(namespace string, id byte, last int64) map[string]any {
		return map[string]any{"agent_id": agentID, "last_sequence": last, "namespace": namespace, "stream_id": b64(rep(id, 32))}
	}
	state := func(epoch int64, frozen bool, claims, streams, issuance, rates, entries []any, generation uint64, snapshot []byte) map[string]any {
		return map[string]any{
			"claims": claims, "issuance_records": issuance, "log_id": logID, "rate_counters": rates,
			"receipt_log": map[string]any{"entries": entries, "frozen": frozen}, "replay_epoch": epoch,
			"security_journal": map[string]any{"generation": generation, "snapshot_b64": b64(snapshot)}, "streams": streams,
		}
	}
	staged := []byte(`{"version":1,"generation":4,"note":"opaque staged snapshot bytes"}`)

	// A primary with every record kind, listed out of order.
	full := func(release map[string]any) map[string]any {
		bodyA, bodyB := `{"receipt":"a"}`, `{"receipt":"b"}`
		released := terminalClaim(claim("claim-a", func() map[string]any {
			c := sealed("claim-a", 0xa1, nil, nil)
			c["context_policy_digest"], c["issuer_ids"] = digest(0xc0), []any{interID, rootID}
			c["constraint_evaluators"] = []any{
				map[string]any{"profile_digest": digest(0x11), "type": "com.ratifyprotocol.allowed_values"},
				map[string]any{"profile_digest": digest(0x12), "type": "com.ratifyprotocol.max_count"},
			}
			c["requires_rate"] = true
			c["rate_batch"] = []any{
				map[string]any{"cert_id": "cert-leaf", "issuer_id": interID, "limit": int64(10), "window_s": int64(60)},
				map[string]any{"cert_id": "cert-root", "issuer_id": rootID, "limit": int64(100), "window_s": int64(3600)},
			}
			return c
		}(), currentProgress()), "allow", "authorized", "authorized_agent", bodyA, 1, Now+120)
		if release != nil {
			released["release"] = release
		}
		pending := terminalClaim(claim("claim-b", sealed("claim-b", 0xb2, rep(0x5a, 32), i64(2)), currentProgress()), "deny", "delegation_revoked", "revoked", bodyB, 2, 0)
		interrupted := claim("claim-c", sealed("claim-c", 0xc3, nil, nil), map[string]any{
			"context_assessment": "not_required", "context_policy_digest": digest(0xc1), "status_assessment": "unavailable",
			"status_evidence_digests": []any{evidence(rootID, 7, 0xe2)}, "trust_assessment": "trusted"})
		interrupted["lease_expires_at"] = Now - 1
		withPolicy := issuanceRecord("device-ns", 3, 0x20)
		withPolicy["context_policy"] = map[string]any{"expected_session_context": b64(rep(0x33, 32)), "profile": "ratify.verify.session-context/v1", "require_bound": true,
			"required_fields": []any{"verifier_id", "workspace_id", "agent_id", "session_id", "invocation_id", "request_hash"}, "version": int64(1)}
		withPolicy["expected_agent_id"], withPolicy["expected_agent_pub_key"] = agentID, pubJSON(g.k("agent").Pub)
		withPolicy["expected_receiver_id"], withPolicy["expected_session_context"] = "receiver-01", b64(rep(0x33, 32))
		unbound := issuanceRecord("device-ns", 3, 0x10)
		unbound["context_policy"] = map[string]any{"expected_session_context": nil, "profile": "example.unbound/v1", "require_bound": false, "required_fields": []any{}, "version": int64(1)}
		return state(3, false,
			[]any{interrupted, pending, released},
			// U+FF61 sorts before U+1F600 in UTF-8 byte order but after it in
			// UTF-16 code-unit order.
			[]any{stream("ns-\U0001F600", 0x01, 9), stream("device-ns", 0x5a, 2), stream("ns-｡", 0x01, 4), stream("device-ns", 0x0f, 1)},
			[]any{withPolicy, issuanceRecord("device-ns", 2, 0x30), unbound, issuanceRecord("ns- line", 3, 0x01)},
			[]any{
				map[string]any{"cert_id": "cert-root", "commits": []any{Now + 2}, "issuer_id": rootID, "window_s": int64(3600)},
				map[string]any{"cert_id": "cert-leaf", "commits": []any{Now - 50, Now - 50, Now + 2}, "issuer_id": interID, "window_s": int64(60)},
				map[string]any{"cert_id": "cert-leaf", "commits": []any{Now + 2}, "issuer_id": interID, "window_s": int64(10)},
			},
			[]any{
				map[string]any{"body_b64": b64([]byte(bodyA)), "claim_id": claimID("claim-a"), "entry_hash": b64(rep(0x5e, 48))},
				map[string]any{"body_b64": b64([]byte(bodyB)), "claim_id": claimID("claim-b"), "entry_hash": nil},
			}, 4, staged)
	}

	abandoned := terminalClaim(claim("claim-d", sealed("claim-d", 0xd4, nil, nil), initialProgress()), "indeterminate", "evaluation_interrupted", "authorization_unverified", `{"receipt":"d"}`, 1, 0)
	abandoned["abandoned"] = true

	cases := []deviceStateCaseJSON{
		{Name: "empty_primary", Description: "a freshly provisioned primary: no records, every collection an empty array, the genesis SecurityJournalV2 snapshot, replay epoch 0",
			State: state(0, false, []any{}, []any{}, []any{}, []any{}, []any{}, 0, genesis)},
		{Name: "evaluating_claim", Description: "one stream-bound claim just created: evaluating, initial progress, no terminal result, receipt body, log position, or release record (all null); its stream advance and its issuance record with no expected agent, receiver, context, or policy",
			State: state(3, false, []any{claim("claim-e", sealed("claim-e", 0xe5, rep(0x5a, 32), i64(1)), initialProgress())}, []any{stream("device-ns", 0x5a, 1)},
				[]any{issuanceRecord("device-ns", 3, 0xe5)}, []any{}, []any{}, 0, genesis)},
		{Name: "every_record_kind", Description: "every record kind, listed out of order: a released allow with a rate batch, evaluator snapshot, two issuer IDs, and an appended receipt; a committed deny whose receipt is not yet appended (entry_hash null); a claim interrupted after lease expiry with recorded progress; streams whose namespaces order differently in UTF-8 and UTF-16; issuance records with a bound and an unbound context policy, a full expected agent key, and a namespace containing U+2028; rate counters ordered by issuer, certificate, and window",
			State: full(map[string]any{"ack_timestamp": Now + 3, "claim_id": claimID("claim-a"), "entry_hash": b64(rep(0x5e, 48)), "outcome": "released", "reason": nil})},
		{Name: "every_record_kind_without_release", Description: "every_record_kind with the release record of claim-a absent: only the claims member and the complete-state digest change",
			State: full(nil)},
		{Name: "every_record_kind_with_withheld_record", Description: "every_record_kind with claim-a's record a recorded withheld result (outcome withheld, reason allow_horizon_passed, SPEC-v2 §6.9) instead of a release: only the claims member and the complete-state digest change",
			State: full(map[string]any{"ack_timestamp": Now + 3, "claim_id": claimID("claim-a"), "entry_hash": b64(rep(0x5e, 48)), "outcome": "withheld", "reason": "allow_horizon_passed"})},
		{Name: "abandoned_frozen_log", Description: "a terminal claim whose receipt was abandoned before it was appended, in a frozen receipt log, at the maximum safe replay epoch and journal generation",
			State: state(9007199254740991, true, []any{abandoned}, []any{}, []any{}, []any{}, []any{map[string]any{"body_b64": b64([]byte(`{"receipt":"d"}`)), "claim_id": claimID("claim-d"), "entry_hash": nil}},
				9007199254740991, staged)},
	}
	for i := range cases {
		cases[i].Expect = projectDeviceState(cases[i].State)
	}
	return deviceStateFileJSON{
		Description: "Single-device offline complete-state projection known answers (SPEC-v2 §7.13). Every SDK that implements the profile loads each state into its primary and MUST reproduce every canonical member byte string, member digest, projection object, and complete-state digest exactly.",
		Label:       "ratify/device-complete-state/v2",
		Version:     1,
		Semantics: map[string]string{
			"state":                     "the primary's durable records in the record encodings of SPEC-v2 §7.13, listed out of order; claims carry the exact sealed terminal-result and receipt-outbox bytes as terminal_b64 and receipt_body_b64 (null when absent), receipt_log entries carry body_b64 in sequence order, and security_journal carries the exact canonical snapshot bytes as snapshot_b64. Byte strings are opaque here: they are hashed, never parsed",
			"<member>_canonical_json":   "the exact RatifyCanonicalJSON of that projection member: each record array sorted by its §7.13 primary key, terminal_b64, receipt_body_b64, and body_b64 replaced by the lowercase hex SHA-384 of their bytes, receipt_log carrying log_id and 1-based sequence",
			"<member>_sha384":           "lowercase hex SHA-384 of the member's canonical bytes",
			"projection_canonical_json": "the exact RatifyCanonicalJSON of the version 1 projection object",
			"complete_state_digest_hex": "lowercase hex SHA-384(ASCII(label) || 0x00 || projection_canonical_json)",
		},
		Cases: cases,
	}
}
