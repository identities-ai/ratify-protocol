package v2vectors

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

const (
	fixtureNamespace   = "verify-test"
	fixtureReplayEpoch = 3
	fixtureWorkspace   = "00000000-0000-4000-8000-000000000001"
	fixtureSession     = "session-01"
	fixtureInvocation  = "invocation-01"
	verifyPolicy       = "ratify.verify.session-context/v1"
	// notRequiredPolicy is a fixture-only generic Protocol context policy that
	// records that action/session context is not required.
	notRequiredPolicy = "ratify.conformance.context-not-required/v1"
)

var verifyPolicyFields = []string{"verifier_id", "workspace_id", "agent_id", "session_id", "invocation_id", "request_hash"}

// lp is SPEC-v2 §2.2 length prefixing.
func lp(b []byte) []byte {
	return append(binary.BigEndian.AppendUint64(nil, uint64(len(b))), b...)
}

func operationContextHash(scope, operation, resource, path string, payload []byte) []byte {
	pre := []byte("ratify/operation-context/v2")
	for _, f := range [][]byte{[]byte(scope), []byte(operation), []byte(resource), []byte(path), payload} {
		pre = append(pre, lp(f)...)
	}
	h := sha256.Sum256(pre)
	return h[:]
}

func sessionContext(verifierID, workspace, agentID, session, invocation string, requestHash []byte) []byte {
	pre := []byte("ratify/session-context/v2")
	for _, f := range [][]byte{[]byte(verifierID), []byte(workspace), []byte(agentID), []byte(session), []byte(invocation), requestHash} {
		pre = append(pre, lp(f)...)
	}
	h := sha256.Sum256(pre)
	return h[:]
}

func policyDigest(profile string, requireBound bool, fields []string) string {
	if fields == nil {
		fields = []string{}
	}
	body := canon(map[string]any{"profile": profile, "require_bound": requireBound, "required_fields": fields, "version": 1})
	return "sha384:" + hex.EncodeToString(sha384(body))
}

// fixtureSessionContext is the session context of the default fixture
// request: data:read on records.get for customer/123.
func (g *gen) fixtureSessionContext(agent *Key) []byte {
	request := operationContextHash("data:read", "records.get", "customer/123", "/v1/customers/123", nil)
	return sessionContext(g.k("verifier").ID, fixtureWorkspace, agent.ID, fixtureSession, fixtureInvocation, request)
}

type chainSpec struct {
	leafScope   []string
	rootScope   []string
	leafCons    []ratify.Constraint
	rootCons    []ratify.Constraint
	leafID      string
	rootID      string
	leafIssued  int64
	leafExpires int64
	root        *Key
}

// chain returns the default two-link chain [intermediate->agent, root->intermediate].
func (g *gen) chain(s chainSpec) []ratify.DelegationCertV2 {
	if s.leafScope == nil {
		s.leafScope = []string{"data:read", "files:read"}
	}
	if s.rootScope == nil {
		s.rootScope = []string{"data:read", "files:read", "identity:delegate"}
	}
	if s.leafID == "" {
		s.leafID = "cert-leaf"
	}
	if s.rootID == "" {
		s.rootID = "cert-root"
	}
	if s.root == nil {
		s.root = g.k("root")
	}
	leaf, _, _ := g.cert(certSpec{issuer: g.k("intermediate"), subject: g.k("agent"), certID: s.leafID, scope: s.leafScope, constraints: s.leafCons, issuedAt: s.leafIssued, expiresAt: s.leafExpires})
	root, _, _ := g.cert(certSpec{issuer: s.root, subject: g.k("intermediate"), certID: s.rootID, scope: s.rootScope, constraints: s.rootCons})
	return []ratify.DelegationCertV2{leaf, root}
}

// Status fixtures: one fresh empty list per issuer and a revocation list
// naming the leaf certificate.
type statusFixture struct {
	wire     []byte
	code     uint16
	issuerID string
	keyName  string
	sequence int64
	digest   string
}

func (g *gen) statusFixtures() map[string]statusFixture {
	out := map[string]statusFixture{}
	add := func(name, keyName, issuerID string, seq int64, revoked ...string) {
		_, wire, _ := g.list(g.k(keyName), issuerID, seq, Now-60, Now+3600, revoked...)
		out[name] = statusFixture{wire, codeList, issuerID, keyName, seq, statusEvidenceDigest(codeList, wire)}
	}
	add("root_current", "status_root", g.k("root").ID, 1)
	add("intermediate_current", "status_intermediate", g.k("intermediate").ID, 1)
	add("intermediate_revoked_leaf", "status_intermediate", g.k("intermediate").ID, 2, "cert-leaf")
	add("intermediate_revoked_shared", "status_intermediate", g.k("intermediate").ID, 2, "shared-id")
	addAt := func(name, keyName, issuerID string, seq, updated, next int64) {
		_, wire, _ := g.list(g.k(keyName), issuerID, seq, updated, next)
		out[name] = statusFixture{wire, codeList, issuerID, keyName, seq, statusEvidenceDigest(codeList, wire)}
	}
	// Fresh when preloaded at Now-3990; at Now its age (4000) reaches the bound.
	addAt("root_stale", "status_root", g.k("root").ID, 1, Now-4000, Now+3000)
	// Exclusive next_update deadline exactly at Now, and one second later.
	addAt("root_next_at_now", "status_root", g.k("root").ID, 1, Now-60, Now)
	addAt("root_next_plus_one", "status_root", g.k("root").ID, 1, Now-60, Now+1)
	// Exclusive status-age deadline: updated_at + 3660 == Now.
	addAt("root_age_at_now", "status_root", g.k("root").ID, 1, Now-3660, Now+100)
	// A correctly shaped intermediate list signed by another issuer's status key.
	addAt("intermediate_signed_by_party_b", "status_party_b", g.k("intermediate").ID, 1, Now-60, Now+3600)
	return out
}

// EvidenceJSON is the language-neutral StatusEvidenceEntry of SPEC-v2 §5.6.
type EvidenceJSON struct {
	IssuerID       string `json:"issuer_id"`
	StatusKeyID    string `json:"status_key_id"`
	Sequence       int64  `json:"sequence"`
	ObjectTypeCode int    `json:"object_type_code"`
	Digest         string `json:"digest"`
}

func (g *gen) evidence(f statusFixture) EvidenceJSON {
	return EvidenceJSON{IssuerID: f.issuerID, StatusKeyID: g.k(f.keyName).ID, Sequence: f.sequence, ObjectTypeCode: int(f.code), Digest: f.digest}
}

func toLibEvidence(e []EvidenceJSON) []ratify.StatusEvidenceEntryV2 {
	out := make([]ratify.StatusEvidenceEntryV2, len(e))
	for i, v := range e {
		out[i] = ratify.StatusEvidenceEntryV2{IssuerID: v.IssuerID, StatusKeyID: v.StatusKeyID, Sequence: v.Sequence, ObjectType: uint16(v.ObjectTypeCode), Digest: v.Digest}
	}
	return out
}

func sortEvidence(e []EvidenceJSON) []EvidenceJSON {
	out := append([]EvidenceJSON{}, e...)
	less := func(a, b EvidenceJSON) bool {
		if a.IssuerID != b.IssuerID {
			return a.IssuerID < b.IssuerID
		}
		if a.StatusKeyID != b.StatusKeyID {
			return a.StatusKeyID < b.StatusKeyID
		}
		if a.Sequence != b.Sequence {
			return a.Sequence < b.Sequence
		}
		if a.ObjectTypeCode != b.ObjectTypeCode {
			return a.ObjectTypeCode < b.ObjectTypeCode
		}
		return a.Digest < b.Digest
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && less(out[j], out[j-1]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	dedup := out[:0]
	for i, v := range out {
		if i == 0 || v != out[i-1] {
			dedup = append(dedup, v)
		}
	}
	return dedup
}

func sha256Array(b []byte) [32]byte { return sha256.Sum256(b) }
