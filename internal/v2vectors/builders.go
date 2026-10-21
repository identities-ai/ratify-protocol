package v2vectors

import (
	"crypto/sha512"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// Codes from the SPEC-v2 §4 registry.
const (
	codeDelegation   uint16 = 0x0001
	codePresentation uint16 = 0x0002
	codeList         uint16 = 0x0003
	codeRotationOld  uint16 = 0x0004
	codePush         uint16 = 0x0005
	codeWitness      uint16 = 0x0006
	codeParty        uint16 = 0x0007
	codeReceipt      uint16 = 0x0008
	codeRotationNew  uint16 = 0x0009
)

// signed records one signature's complete transcript.
type signed struct {
	code     uint16
	signer   *Key
	signable []byte
	sig      ratify.HybridSignature
}

// ---------------------------------------------------------------------------
// Delegation certificates

type certSpec struct {
	issuer, subject *Key
	certID          string
	scope           []string
	constraints     []ratify.Constraint
	issuedAt        int64
	expiresAt       int64
	signer          *Key   // defaults to issuer
	code            uint16 // defaults to 0x0001
}

func (g *gen) cert(s certSpec) (ratify.DelegationCertV2, []byte, signed) {
	if s.constraints == nil {
		s.constraints = []ratify.Constraint{}
	}
	if s.issuedAt == 0 {
		s.issuedAt = Now - 3600
	}
	if s.expiresAt == 0 {
		s.expiresAt = Now + 86400
	}
	if s.signer == nil {
		s.signer = s.issuer
	}
	if s.code == 0 {
		s.code = codeDelegation
	}
	c := ratify.DelegationCertV2{
		Version: 2, CertID: s.certID, IssuerID: s.issuer.ID, IssuerPubKey: s.issuer.Pub,
		SubjectID: s.subject.ID, SubjectPubKey: s.subject.Pub, Scope: s.scope,
		Constraints: s.constraints, IssuedAt: s.issuedAt, ExpiresAt: s.expiresAt,
		Signature: placeholderSig(),
	}
	wire := must(ratify.EncodeDelegationCertV2(&c))
	signable := without(wire, "signature")
	c.Signature = signDet(s.signer, s.code, signable)
	wire = must(ratify.EncodeDelegationCertV2(&c))
	return c, wire, signed{s.code, s.signer, signable, c.Signature}
}

// ---------------------------------------------------------------------------
// Proof bundles

type bundleSpec struct {
	agent       *Key
	verifierID  string
	certs       []ratify.DelegationCertV2
	challenge   []byte
	challengeAt int64
	session     []byte
	streamID    []byte
	streamSeq   int64
	signer      *Key   // defaults to agent
	code        uint16 // defaults to 0x0002
}

// delegationDigest is computed from SPEC-v2 §5.2 over the canonical array of
// complete signed certificate objects.
func delegationDigest(certs []ratify.DelegationCertV2) []byte {
	parts := []byte("[")
	for i := range certs {
		if i > 0 {
			parts = append(parts, ',')
		}
		parts = append(parts, must(ratify.EncodeDelegationCertV2(&certs[i]))...)
	}
	parts = append(parts, ']')
	return sha384Prefixed("ratify-protocol-delegations-v2", parts)
}

func defaultChallenge() []byte {
	c := make([]byte, 32)
	for i := range c {
		c[i] = byte(0xa0 + i)
	}
	return c
}

func (g *gen) bundle(s bundleSpec) (*ratify.ProofBundleV2, []byte, signed) {
	if s.challenge == nil {
		s.challenge = defaultChallenge()
	}
	if s.challengeAt == 0 {
		s.challengeAt = Now - 10
	}
	if s.verifierID == "" {
		s.verifierID = g.k("verifier").ID
	}
	if s.signer == nil {
		s.signer = s.agent
	}
	if s.code == 0 {
		s.code = codePresentation
	}
	if s.certs == nil {
		s.certs = []ratify.DelegationCertV2{}
	}
	b := &ratify.ProofBundleV2{
		Version: 2, VerifierID: s.verifierID, AgentID: s.agent.ID, AgentPubKey: s.agent.Pub,
		Delegations: s.certs, DelegationDigest: delegationDigest(s.certs),
		Challenge: s.challenge, ChallengeAt: s.challengeAt, ChallengeSig: placeholderSig(),
	}
	if s.session != nil {
		session := append([]byte(nil), s.session...)
		b.SessionContext = &session
	}
	if s.streamID != nil {
		id := append([]byte(nil), s.streamID...)
		seq := s.streamSeq
		b.StreamID, b.StreamSeq = &id, &seq
	}
	wire := must(ratify.EncodeProofBundleV2(b))
	signable := without(wire, "delegations", "challenge_sig")
	b.ChallengeSig = signDet(s.signer, s.code, signable)
	wire = must(ratify.EncodeProofBundleV2(b))
	return b, wire, signed{s.code, s.signer, signable, b.ChallengeSig}
}

// resign recomputes the delegation digest and presentation signature of a
// parsed bundle object after a structural edit. Used to build single-fault
// negatives whose only defect is the structural edit itself.
func (g *gen) resign(bundleObj map[string]any, agent *Key) []byte {
	certsWire := canon(bundleObj["delegations"])
	bundleObj["delegation_digest"] = b64(sha384Prefixed("ratify-protocol-delegations-v2", certsWire))
	bundleObj["challenge_sig"] = sigJSON(placeholderSig())
	wire := canon(bundleObj)
	signable := without(wire, "delegations", "challenge_sig")
	bundleObj["challenge_sig"] = sigJSON(signDet(agent, codePresentation, signable))
	return canon(bundleObj)
}

// ---------------------------------------------------------------------------
// Revocation objects

func (g *gen) list(statusKey *Key, issuerID string, sequence, updatedAt, nextUpdate int64, revoked ...string) (*ratify.RevocationListV2, []byte, signed) {
	refs := make([]ratify.RevokedCertV2, 0, len(revoked))
	for _, id := range revoked {
		refs = append(refs, ratify.RevokedCertV2{CertID: id})
	}
	l := &ratify.RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: updatedAt, NextUpdate: nextUpdate, Sequence: sequence, Revoked: refs, Signature: placeholderSig()}
	wire := must(ratify.EncodeRevocationListV2(l))
	signable := without(wire, "signature")
	l.Signature = signDet(statusKey, codeList, signable)
	wire = must(ratify.EncodeRevocationListV2(l))
	return l, wire, signed{codeList, statusKey, signable, l.Signature}
}

func (g *gen) push(statusKey *Key, issuerID string, sequence, pushedAt int64, revoked ...string) (*ratify.RevocationPushV2, []byte, signed) {
	refs := make([]ratify.RevokedCertV2, 0, len(revoked))
	for _, id := range revoked {
		refs = append(refs, ratify.RevokedCertV2{CertID: id})
	}
	p := &ratify.RevocationPushV2{Version: 2, IssuerID: issuerID, Sequence: sequence, PushedAt: pushedAt, Revoked: refs, Signature: placeholderSig()}
	wire := must(ratify.EncodeRevocationPushV2(p))
	signable := without(wire, "signature")
	p.Signature = signDet(statusKey, codePush, signable)
	wire = must(ratify.EncodeRevocationPushV2(p))
	return p, wire, signed{codePush, statusKey, signable, p.Signature}
}

// ---------------------------------------------------------------------------
// Key rotation

type rotationSpec struct {
	authority     string
	epoch         int64
	role          string
	sequence      int64
	prev          []byte
	oldKey        *Key
	newKey        *Key
	issuedAt      int64
	notBefore     int64
	oldSigner     *Key   // defaults to oldKey
	newSigner     *Key   // defaults to newKey
	oldCode       uint16 // defaults to 0x0004
	newCode       uint16 // defaults to 0x0009
	edNonceForOld byte   // nonzero: alternate valid Ed25519 nonce for the old signature
}

const rotationAuthority = "0123456789abcdef0123456789abcdef"

func (g *gen) rotation(s rotationSpec) (*ratify.KeyRotationStatementV2, []byte, []byte, signed, signed) {
	if s.authority == "" {
		s.authority = rotationAuthority
	}
	if s.epoch == 0 {
		s.epoch = 1
	}
	if s.role == "" {
		s.role = "issuer"
	}
	if s.prev == nil {
		s.prev = make([]byte, 48)
	}
	if s.issuedAt == 0 {
		s.issuedAt = Now - 600
	}
	if s.notBefore == 0 {
		s.notBefore = Now - 600
	}
	if s.oldSigner == nil {
		s.oldSigner = s.oldKey
	}
	if s.newSigner == nil {
		s.newSigner = s.newKey
	}
	if s.oldCode == 0 {
		s.oldCode = codeRotationOld
	}
	if s.newCode == 0 {
		s.newCode = codeRotationNew
	}
	stmt := &ratify.KeyRotationStatementV2{
		Version: 2, AuthorityID: s.authority, RecoveryEpoch: s.epoch, Role: s.role,
		Sequence: s.sequence, PreviousStatementHash: s.prev, OldKey: s.oldKey.Pub, NewKey: s.newKey.Pub,
		OldKeyID: s.oldKey.ID, NewKeyID: s.newKey.ID, IssuedAt: s.issuedAt, NotBefore: s.notBefore,
		OldSignature: placeholderSig(), NewSignature: placeholderSig(),
	}
	wire := must(ratify.EncodeKeyRotationStatementV2(stmt))
	signable := without(wire, "old_signature", "new_signature")
	stmt.OldSignature = signDet(s.oldSigner, s.oldCode, signable)
	if s.edNonceForOld != 0 {
		stmt.OldSignature.Ed25519 = ed25519WithNonce(s.oldSigner, message(s.oldCode, signable), s.edNonceForOld)
	}
	stmt.NewSignature = signDet(s.newSigner, s.newCode, signable)
	wire = must(ratify.EncodeKeyRotationStatementV2(stmt))
	return stmt, wire, signable, signed{s.oldCode, s.oldSigner, signable, stmt.OldSignature}, signed{s.newCode, s.newSigner, signable, stmt.NewSignature}
}

// ---------------------------------------------------------------------------
// Witness entries

const (
	witnessLogA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
	witnessLogB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2"
)

func (g *gen) witness(signer *Key, logID string, sequence int64, prev []byte, data string, timestamp int64, witnessID string, edNonce byte) (*ratify.WitnessEntryV2, []byte, signed) {
	if witnessID == "" {
		witnessID = signer.ID
	}
	e := &ratify.WitnessEntryV2{Version: 2, LogID: logID, Sequence: sequence, PrevHash: prev, EntryData: []byte(data), Timestamp: timestamp, WitnessID: witnessID, Signature: placeholderSig()}
	wire := must(ratify.EncodeWitnessEntryV2(e))
	signable := without(wire, "signature")
	e.Signature = signDet(signer, codeWitness, signable)
	if edNonce != 0 {
		e.Signature.Ed25519 = ed25519WithNonce(signer, message(codeWitness, signable), edNonce)
	}
	wire = must(ratify.EncodeWitnessEntryV2(e))
	return e, wire, signed{codeWitness, signer, signable, e.Signature}
}

// ---------------------------------------------------------------------------
// Verification receipts

const receiptLogA = "cccccccccccccccccccccccccccccc01"

func (g *gen) receipt(signer *Key, body *ratify.VerificationReceiptV2, logID string, sequence int64, prev []byte, edNonce byte) (*ratify.VerificationReceiptV2, []byte, signed) {
	r := *body
	r.LogID, r.Sequence, r.PreviousReceiptHash, r.Signature = logID, sequence, prev, placeholderSig()
	wire := must(ratify.EncodeVerificationReceiptV2(&r))
	signable := without(wire, "signature")
	r.Signature = signDet(signer, codeReceipt, signable)
	if edNonce != 0 {
		r.Signature.Ed25519 = ed25519WithNonce(signer, message(codeReceipt, signable), edNonce)
	}
	wire = must(ratify.EncodeVerificationReceiptV2(&r))
	return &r, wire, signed{codeReceipt, signer, signable, r.Signature}
}

func sha384(b []byte) []byte {
	s := sha512.Sum384(b)
	return s[:]
}
