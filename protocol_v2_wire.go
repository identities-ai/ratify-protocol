package ratify

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// BundleHashV2 hashes the complete canonical signed proof bundle, including
// certificate and challenge signatures, under the v2 domain separator.
func BundleHashV2(bundle *ProofBundleV2) (string, error) {
	encoded, err := EncodeProofBundleV2(bundle)
	if err != nil {
		return "", err
	}
	h := sha512.New384()
	h.Write([]byte("ratify-protocol-bundle-v2\x00"))
	h.Write(encoded)
	return "sha384:" + hex.EncodeToString(h.Sum(nil)), nil
}

// DelegationCertV2 is intentionally distinct from the v1 wire type.
type DelegationCertV2 struct {
	Version       int             `json:"version"`
	CertID        string          `json:"cert_id"`
	IssuerID      string          `json:"issuer_id"`
	IssuerPubKey  HybridPublicKey `json:"issuer_pub_key"`
	SubjectID     string          `json:"subject_id"`
	SubjectPubKey HybridPublicKey `json:"subject_pub_key"`
	Scope         []string        `json:"scope"`
	Constraints   []ConstraintV2  `json:"constraints"`
	IssuedAt      int64           `json:"issued_at"`
	ExpiresAt     int64           `json:"expires_at"`
	Signature     HybridSignature `json:"signature"`
}

// ProofBundleV2 has an explicit v2 shape. Pointer fields preserve the required
// JSON null values independently from absent fields.
type ProofBundleV2 struct {
	Version          int                `json:"version"`
	VerifierID       string             `json:"verifier_id"`
	AgentID          string             `json:"agent_id"`
	AgentPubKey      HybridPublicKey    `json:"agent_pub_key"`
	Delegations      []DelegationCertV2 `json:"delegations"`
	DelegationDigest []byte             `json:"delegation_digest"`
	Challenge        []byte             `json:"challenge"`
	ChallengeAt      int64              `json:"challenge_at"`
	ChallengeSig     HybridSignature    `json:"challenge_sig"`
	SessionContext   *[]byte            `json:"session_context"`
	StreamID         *[]byte            `json:"stream_id"`
	StreamSeq        *int64             `json:"stream_seq"`
}

// RevokedCertV2 is issuer-scoped. The issuer ID is carried by its containing
// signed status object, so certificate IDs are never interpreted globally.
type RevokedCertV2 struct {
	CertID string `json:"cert_id"`
}

type RevocationListV2 struct {
	Version    int             `json:"version"`
	IssuerID   string          `json:"issuer_id"`
	UpdatedAt  int64           `json:"updated_at"`
	NextUpdate int64           `json:"next_update"`
	Sequence   int64           `json:"sequence"`
	Revoked    []RevokedCertV2 `json:"revoked"`
	Signature  HybridSignature `json:"signature"`
}

type RevocationPushV2 struct {
	Version   int             `json:"version"`
	IssuerID  string          `json:"issuer_id"`
	Sequence  int64           `json:"sequence"`
	PushedAt  int64           `json:"pushed_at"`
	Revoked   []RevokedCertV2 `json:"revoked"`
	Signature HybridSignature `json:"signature"`
}

// Wire projections keep fields in canonical JSON key order. Go's JSON encoder
// preserves struct declaration order, so the public wire structs are never
// marshaled directly for canonical protocol bytes.
type revocationListCanonicalV2 struct {
	IssuerID   string          `json:"issuer_id"`
	NextUpdate int64           `json:"next_update"`
	Revoked    []RevokedCertV2 `json:"revoked"`
	Sequence   int64           `json:"sequence"`
	Signature  HybridSignature `json:"signature"`
	UpdatedAt  int64           `json:"updated_at"`
	Version    int             `json:"version"`
}

type revocationPushCanonicalV2 struct {
	IssuerID  string          `json:"issuer_id"`
	PushedAt  int64           `json:"pushed_at"`
	Revoked   []RevokedCertV2 `json:"revoked"`
	Sequence  int64           `json:"sequence"`
	Signature HybridSignature `json:"signature"`
	Version   int             `json:"version"`
}

type revocationListSignableV2 struct {
	IssuerID   string          `json:"issuer_id"`
	NextUpdate int64           `json:"next_update"`
	Revoked    []RevokedCertV2 `json:"revoked"`
	Sequence   int64           `json:"sequence"`
	UpdatedAt  int64           `json:"updated_at"`
	Version    int             `json:"version"`
}

type revocationPushSignableV2 struct {
	IssuerID string          `json:"issuer_id"`
	PushedAt int64           `json:"pushed_at"`
	Revoked  []RevokedCertV2 `json:"revoked"`
	Sequence int64           `json:"sequence"`
	Version  int             `json:"version"`
}

type delegationSignableV2 struct {
	CertID        string          `json:"cert_id"`
	Constraints   []ConstraintV2  `json:"constraints"`
	ExpiresAt     int64           `json:"expires_at"`
	IssuedAt      int64           `json:"issued_at"`
	IssuerID      string          `json:"issuer_id"`
	IssuerPubKey  HybridPublicKey `json:"issuer_pub_key"`
	Scope         []string        `json:"scope"`
	SubjectID     string          `json:"subject_id"`
	SubjectPubKey HybridPublicKey `json:"subject_pub_key"`
	Version       int             `json:"version"`
}

type presentationSignableV2 struct {
	AgentID          string          `json:"agent_id"`
	AgentPubKey      HybridPublicKey `json:"agent_pub_key"`
	Challenge        []byte          `json:"challenge"`
	ChallengeAt      int64           `json:"challenge_at"`
	DelegationDigest []byte          `json:"delegation_digest"`
	SessionContext   *[]byte         `json:"session_context"`
	StreamID         *[]byte         `json:"stream_id"`
	StreamSeq        *int64          `json:"stream_seq"`
	VerifierID       string          `json:"verifier_id"`
	Version          int             `json:"version"`
}

type delegationCanonicalV2 struct {
	CertID        string          `json:"cert_id"`
	Constraints   []ConstraintV2  `json:"constraints"`
	ExpiresAt     int64           `json:"expires_at"`
	IssuedAt      int64           `json:"issued_at"`
	IssuerID      string          `json:"issuer_id"`
	IssuerPubKey  HybridPublicKey `json:"issuer_pub_key"`
	Scope         []string        `json:"scope"`
	Signature     HybridSignature `json:"signature"`
	SubjectID     string          `json:"subject_id"`
	SubjectPubKey HybridPublicKey `json:"subject_pub_key"`
	Version       int             `json:"version"`
}

type proofBundleCanonicalV2 struct {
	AgentID          string                  `json:"agent_id"`
	AgentPubKey      HybridPublicKey         `json:"agent_pub_key"`
	Challenge        []byte                  `json:"challenge"`
	ChallengeAt      int64                   `json:"challenge_at"`
	ChallengeSig     HybridSignature         `json:"challenge_sig"`
	DelegationDigest []byte                  `json:"delegation_digest"`
	Delegations      []delegationCanonicalV2 `json:"delegations"`
	SessionContext   *[]byte                 `json:"session_context"`
	StreamID         *[]byte                 `json:"stream_id"`
	StreamSeq        *int64                  `json:"stream_seq"`
	VerifierID       string                  `json:"verifier_id"`
	Version          int                     `json:"version"`
}

var delegationV2Fields = []string{"version", "cert_id", "issuer_id", "issuer_pub_key", "subject_id", "subject_pub_key", "scope", "constraints", "issued_at", "expires_at", "signature"}
var proofBundleV2Fields = []string{"version", "verifier_id", "agent_id", "agent_pub_key", "delegations", "delegation_digest", "challenge", "challenge_at", "challenge_sig", "session_context", "stream_id", "stream_seq"}
var v2SchemaFieldNames = strings.Fields("version cert_id issuer_id issuer_pub_key subject_id subject_pub_key scope constraints signature ed25519 ml_dsa_65 issued_at expires_at verifier_id agent_id agent_pub_key delegations delegation_digest challenge challenge_at challenge_sig session_context stream_id stream_seq type params count currency end lat lon max_alt_m max_amount max_amount_micros max_lat max_lon max_mps min_alt_m min_lat min_lon path_prefix points radius_m resource_id start tz window_s exact_receiver_ids trust_domain_ids max_membership_age_seconds next_update sequence pushed_at revoked authority_id recovery_epoch role previous_statement_hash old_key new_key old_key_id new_key_id not_before old_signature new_signature log_id bundle_hash issuer_ids decision decision_reason identity_status trust_assessment status_assessment challenge_assessment context_assessment context_policy_digest verified_at required_scope granted_scope status_evidence_digests previous_receipt_hash human_id status_key_id object_type_code digest transaction_id created_at terms_schema_uri terms_canonical_json parties party_id proof_bundle_hash proof_bundle party_signatures invocation_id workspace_id session_id")

func requireV2Fields(data []byte, names []string, nullable ...string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	allowedNull := make(map[string]bool, len(nullable))
	for _, name := range nullable {
		allowedNull[name] = true
	}
	for _, name := range names {
		value, ok := fields[name]
		if !ok {
			return fmt.Errorf("wire v2: required field %q is missing", name)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) && !allowedNull[name] {
			return fmt.Errorf("wire v2: required field %q must not be null", name)
		}
	}
	return checkV2SchemaKeyCase(data)
}

// strictUnmarshalV2 decodes data into v and then requires the decoded value
// to re-encode to the same JSON value as the input. encoding/json is lenient
// in ways a v2 decoder must not be: it matches member names
// case-insensitively, decodes null into a zero value, accepts {} for a
// structure whose members are then left empty, and accepts an array of
// numbers for a byte string. Each of those spellings decodes to a Go value
// that encodes differently, so the comparison rejects all of them, at every
// nesting level, before any field is interpreted.
func strictUnmarshalV2(data []byte, v any) error {
	if err := strictUnmarshal(data, v); err != nil {
		return err
	}
	return requireV2RoundTrip(data, v)
}

// requireV2RoundTrip compares the JSON value of data with the JSON value of
// decoded re-encoded. Member names compare byte-exactly; numbers compare by
// their exact token.
func requireV2RoundTrip(data []byte, decoded any) error {
	reencoded, err := json.Marshal(decoded)
	if err != nil {
		return fmt.Errorf("wire v2: decoded value does not re-encode: %w", err)
	}
	input, err := parseV2JSONValue(data)
	if err != nil {
		return err
	}
	output, err := parseV2JSONValue(reencoded)
	if err != nil {
		return err
	}
	if path, equal := equalV2JSONValues(input, output, "$"); !equal {
		return fmt.Errorf("wire v2: %s does not decode to the value it spells (wrong member case, null, empty object, or non-string byte field)", path)
	}
	return rejectV2UnexpectedNull(input, "$")
}

// v2NullableMembers are the only v2 schema members whose value may be null.
// Everywhere else, including every array element, null is malformed: a null
// byte string or array would otherwise decode to the same Go value as an
// empty one. Values inside a constraint "params" object follow the general
// value model, where null is a value.
var v2NullableMembers = map[string]bool{
	"session_context":       true,
	"stream_id":             true,
	"stream_seq":            true,
	"context_policy_digest": true,
	"floor":                 true,
	"accepted_snapshot":     true,
	"preceding_checkpoint":  true,
}

func rejectV2UnexpectedNull(value any, path string) error {
	switch x := value.(type) {
	case nil:
		return fmt.Errorf("wire v2: %s must not be null", path)
	case map[string]any:
		for key, member := range x {
			if key == "params" || (member == nil && v2NullableMembers[key]) {
				continue
			}
			if err := rejectV2UnexpectedNull(member, path+"."+key); err != nil {
				return err
			}
		}
	case []any:
		for i, item := range x {
			if err := rejectV2UnexpectedNull(item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseV2JSONValue(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("wire v2: %w", err)
	}
	return value, nil
}

func equalV2JSONValues(a, b any, path string) (string, bool) {
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return path, false
		}
		for key, value := range x {
			other, ok := y[key]
			if !ok {
				return path + "." + key, false
			}
			if p, equal := equalV2JSONValues(value, other, path+"."+key); !equal {
				return p, false
			}
		}
		return "", true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return path, false
		}
		for i := range x {
			if p, equal := equalV2JSONValues(x[i], y[i], fmt.Sprintf("%s[%d]", path, i)); !equal {
				return p, false
			}
		}
		return "", true
	case json.Number:
		y, ok := b.(json.Number)
		return path, ok && x == y
	case string:
		y, ok := b.(string)
		return path, ok && x == y
	case bool:
		y, ok := b.(bool)
		return path, ok && x == y
	case nil:
		return path, b == nil
	}
	return path, false
}

func checkV2SchemaKeyCase(data []byte) error {
	var walk func(json.RawMessage, bool) error
	walk = func(raw json.RawMessage, inParams bool) error {
		if inParams {
			return nil
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) == nil && object != nil {
			for key, value := range object {
				for _, canonical := range v2SchemaFieldNames {
					if key != canonical && strings.EqualFold(key, canonical) {
						return fmt.Errorf("wire v2: field %q has incorrect case; use %q", key, canonical)
					}
				}
				if err := walk(value, key == "params"); err != nil {
					return err
				}
			}
			return nil
		}
		var array []json.RawMessage
		if json.Unmarshal(raw, &array) == nil {
			for _, value := range array {
				if err := walk(value, false); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(data, false)
}

func DecodeDelegationCertV2(data []byte) (_ *DelegationCertV2, err error) {
	defer func() { err = v2Classify(V2ErrMalformed, err) }()
	if err := checkV2WireSize(data, "certificate", "MAX_DELEGATION_CERT_BYTES_V2", MaxDelegationCertBytesV2); err != nil {
		return nil, err
	}
	if err := checkWireJSONV2(data); err != nil {
		return nil, err
	}
	if err := requireV2Fields(data, delegationV2Fields); err != nil {
		return nil, err
	}
	var certFields map[string]json.RawMessage
	if err := json.Unmarshal(data, &certFields); err != nil {
		return nil, err
	}
	var rawConstraints []json.RawMessage
	if err := json.Unmarshal(certFields["constraints"], &rawConstraints); err != nil || rawConstraints == nil {
		return nil, fmt.Errorf("wire v2: constraints must be an array")
	}
	if err := validateV2ScopeArray(certFields["scope"]); err != nil {
		return nil, err
	}
	for i, raw := range rawConstraints {
		if err := validateV2ConstraintFields(raw); err != nil {
			return nil, fmt.Errorf("wire v2 constraint %d: %w", i, err)
		}
	}
	var cert DelegationCertV2
	if err := strictUnmarshalV2(data, &cert); err != nil {
		return nil, err
	}
	if err := validateDelegationCertV2(&cert); err != nil {
		return nil, err
	}
	if err := validateHybridSignatureV2(cert.Signature); err != nil {
		return nil, err
	}
	return &cert, nil
}

var revocationListV2Fields = []string{"version", "issuer_id", "updated_at", "next_update", "sequence", "revoked", "signature"}
var revocationPushV2Fields = []string{"version", "issuer_id", "sequence", "pushed_at", "revoked", "signature"}

func placeholderV2Signature() HybridSignature {
	return HybridSignature{Ed25519: make([]byte, 64), MLDSA65: make([]byte, 3309)}
}

func DecodeRevocationListV2(data []byte) (_ *RevocationListV2, err error) {
	defer func() { err = v2Classify(V2ErrMalformed, err) }()
	if err := checkV2WireSize(data, "revocation list", "MAX_REVOCATION_LIST_BYTES_V2", MaxRevocationListBytesV2); err != nil {
		return nil, err
	}
	if err := checkWireJSONV2(data); err != nil {
		return nil, err
	}
	if err := requireV2Fields(data, revocationListV2Fields); err != nil {
		return nil, err
	}
	var list RevocationListV2
	if err := strictUnmarshalV2(data, &list); err != nil {
		return nil, err
	}
	if err := validateRevocationListV2(&list); err != nil {
		return nil, err
	}
	if err := validateHybridSignatureV2(list.Signature); err != nil {
		return nil, err
	}
	return &list, nil
}

func DecodeRevocationPushV2(data []byte) (_ *RevocationPushV2, err error) {
	defer func() { err = v2Classify(V2ErrMalformed, err) }()
	if err := checkV2WireSize(data, "revocation push", "MAX_REVOCATION_PUSH_BYTES_V2", MaxRevocationPushBytesV2); err != nil {
		return nil, err
	}
	if err := checkWireJSONV2(data); err != nil {
		return nil, err
	}
	if err := requireV2Fields(data, revocationPushV2Fields); err != nil {
		return nil, err
	}
	var push RevocationPushV2
	if err := strictUnmarshalV2(data, &push); err != nil {
		return nil, err
	}
	if err := validateRevocationPushV2(&push); err != nil {
		return nil, err
	}
	if err := validateHybridSignatureV2(push.Signature); err != nil {
		return nil, err
	}
	return &push, nil
}

func validateRevokedCertsV2(refs []RevokedCertV2) error {
	if refs == nil {
		return fmt.Errorf("v2 revoked must be an array")
	}
	seen := make(map[string]bool, len(refs))
	for _, ref := range refs {
		if ref.CertID == "" || seen[ref.CertID] {
			return fmt.Errorf("v2 revoked cert IDs must be non-empty and unique")
		}
		seen[ref.CertID] = true
	}
	return nil
}

func validateRevocationListV2(list *RevocationListV2) error {
	if list == nil || list.Version != 2 || !validV2ID(list.IssuerID) || list.Sequence <= 0 || list.Sequence > maxSafeInteger || !validV2Timestamp(list.UpdatedAt) || !validV2Timestamp(list.NextUpdate) || list.NextUpdate <= list.UpdatedAt {
		return fmt.Errorf("v2 revocation list has invalid version, issuer, sequence, or time bounds")
	}
	if len(list.Revoked) > MaxRevocationListRefsV2 {
		return fmt.Errorf("v2 revocation list exceeds MAX_REVOCATION_LIST_REFS_V2 (%d)", MaxRevocationListRefsV2)
	}
	return validateRevokedCertsV2(list.Revoked)
}

func validateRevocationPushV2(push *RevocationPushV2) error {
	if push == nil || push.Version != 2 || !validV2ID(push.IssuerID) || push.Sequence <= 0 || push.Sequence > maxSafeInteger || !validV2Timestamp(push.PushedAt) {
		return fmt.Errorf("v2 revocation push has invalid version, issuer, sequence, or timestamp")
	}
	if len(push.Revoked) > MaxRevocationPushRefsV2 {
		return fmt.Errorf("v2 revocation push exceeds MAX_REVOCATION_PUSH_REFS_V2 (%d)", MaxRevocationPushRefsV2)
	}
	return validateRevokedCertsV2(push.Revoked)
}

func revocationListSignableBytesV2(list *RevocationListV2) ([]byte, error) {
	if err := validateRevocationListV2(list); err != nil {
		return nil, err
	}
	return CanonicalJSON(revocationListSignableV2{list.IssuerID, list.NextUpdate, list.Revoked, list.Sequence, list.UpdatedAt, list.Version})
}

func revocationPushSignableBytesV2(push *RevocationPushV2) ([]byte, error) {
	if err := validateRevocationPushV2(push); err != nil {
		return nil, err
	}
	return CanonicalJSON(revocationPushSignableV2{push.IssuerID, push.PushedAt, push.Revoked, push.Sequence, push.Version})
}

func EncodeRevocationListV2(list *RevocationListV2) ([]byte, error) {
	if err := validateRevocationListV2(list); err != nil {
		return nil, err
	}
	if err := validateHybridSignatureV2(list.Signature); err != nil {
		return nil, err
	}
	encoded, err := CanonicalJSON(revocationListCanonicalV2{
		list.IssuerID, list.NextUpdate, list.Revoked, list.Sequence, list.Signature, list.UpdatedAt, list.Version,
	})
	if err != nil {
		return nil, err
	}
	if _, err := DecodeRevocationListV2(encoded); err != nil {
		return nil, err
	}
	return encoded, nil
}

func EncodeRevocationPushV2(push *RevocationPushV2) ([]byte, error) {
	if err := validateRevocationPushV2(push); err != nil {
		return nil, err
	}
	if err := validateHybridSignatureV2(push.Signature); err != nil {
		return nil, err
	}
	encoded, err := CanonicalJSON(revocationPushCanonicalV2{
		push.IssuerID, push.PushedAt, push.Revoked, push.Sequence, push.Signature, push.Version,
	})
	if err != nil {
		return nil, err
	}
	if _, err := DecodeRevocationPushV2(encoded); err != nil {
		return nil, err
	}
	return encoded, nil
}

// SignRevocationListV2 returns a signed copy of list. boundIssuerID and
// boundStatusKey must come from caller-authenticated issuer status configuration.
func SignRevocationListV2(list *RevocationListV2, boundIssuerID string, boundStatusKey HybridPublicKey, statusKey HybridPrivateKey) (*RevocationListV2, error) {
	return SignRevocationListV2WithSigner(context.Background(), list, boundIssuerID, boundStatusKey, localSignerV2{statusKey})
}

// SignRevocationListV2WithSigner is SignRevocationListV2 with an external
// signer whose complete public key must equal boundStatusKey.
func SignRevocationListV2WithSigner(ctx context.Context, list *RevocationListV2, boundIssuerID string, boundStatusKey HybridPublicKey, signer SignerV2) (*RevocationListV2, error) {
	if err := validateRevocationListV2(list); err != nil {
		return nil, err
	}
	if boundIssuerID == "" || list.IssuerID != boundIssuerID {
		return nil, fmt.Errorf("revocation-list issuer does not match caller-authenticated status-key binding")
	}
	derivedStatusKey, err := signerPublicKeyV2(signer)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(boundStatusKey.Ed25519, derivedStatusKey.Ed25519) || !bytes.Equal(boundStatusKey.MLDSA65, derivedStatusKey.MLDSA65) {
		return nil, fmt.Errorf("status private key does not match caller-authenticated issuer status-key binding")
	}
	unsigned := *list
	unsigned.Signature = placeholderV2Signature()
	wire, err := EncodeRevocationListV2(&unsigned)
	if err != nil {
		return nil, err
	}
	prepared, err := DecodeRevocationListV2(wire)
	if err != nil {
		return nil, err
	}
	signable, err := revocationListSignableBytesV2(prepared)
	if err != nil {
		return nil, err
	}
	signature, err := signV2StatementWithSigner(ctx, v2RevocationList, signable, signer, derivedStatusKey)
	if err != nil {
		return nil, err
	}
	prepared.Signature = signature
	wire, err = EncodeRevocationListV2(prepared)
	if err != nil {
		return nil, err
	}
	signed, err := DecodeRevocationListV2(wire)
	if err != nil {
		return nil, err
	}
	if err := VerifyRevocationListV2Signature(signed, boundIssuerID, boundStatusKey); err != nil {
		return nil, fmt.Errorf("signed revocation list failed verification: %w", err)
	}
	return signed, nil
}

// SignRevocationPushV2 returns a signed copy of push. boundIssuerID and
// boundStatusKey must come from caller-authenticated issuer status configuration.
func SignRevocationPushV2(push *RevocationPushV2, boundIssuerID string, boundStatusKey HybridPublicKey, statusKey HybridPrivateKey) (*RevocationPushV2, error) {
	return SignRevocationPushV2WithSigner(context.Background(), push, boundIssuerID, boundStatusKey, localSignerV2{statusKey})
}

// SignRevocationPushV2WithSigner is SignRevocationPushV2 with an external
// signer whose complete public key must equal boundStatusKey.
func SignRevocationPushV2WithSigner(ctx context.Context, push *RevocationPushV2, boundIssuerID string, boundStatusKey HybridPublicKey, signer SignerV2) (*RevocationPushV2, error) {
	if err := validateRevocationPushV2(push); err != nil {
		return nil, err
	}
	if boundIssuerID == "" || push.IssuerID != boundIssuerID {
		return nil, fmt.Errorf("revocation-push issuer does not match caller-authenticated status-key binding")
	}
	derivedStatusKey, err := signerPublicKeyV2(signer)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(boundStatusKey.Ed25519, derivedStatusKey.Ed25519) || !bytes.Equal(boundStatusKey.MLDSA65, derivedStatusKey.MLDSA65) {
		return nil, fmt.Errorf("status private key does not match caller-authenticated issuer status-key binding")
	}
	unsigned := *push
	unsigned.Signature = placeholderV2Signature()
	wire, err := EncodeRevocationPushV2(&unsigned)
	if err != nil {
		return nil, err
	}
	prepared, err := DecodeRevocationPushV2(wire)
	if err != nil {
		return nil, err
	}
	signable, err := revocationPushSignableBytesV2(prepared)
	if err != nil {
		return nil, err
	}
	signature, err := signV2StatementWithSigner(ctx, v2RevocationPush, signable, signer, derivedStatusKey)
	if err != nil {
		return nil, err
	}
	prepared.Signature = signature
	wire, err = EncodeRevocationPushV2(prepared)
	if err != nil {
		return nil, err
	}
	signed, err := DecodeRevocationPushV2(wire)
	if err != nil {
		return nil, err
	}
	if err := VerifyRevocationPushV2Signature(signed, boundIssuerID, boundStatusKey); err != nil {
		return nil, fmt.Errorf("signed revocation push failed verification: %w", err)
	}
	return signed, nil
}

// Status signatures are checked only against the caller-authenticated status
// key bound to this issuer. The signed object never supplies its own key.
func VerifyRevocationListV2Signature(list *RevocationListV2, trustedIssuerID string, statusKey HybridPublicKey) error {
	if err := validateRevocationListV2(list); err != nil {
		return v2Classify(V2ErrMalformed, err)
	}
	if trustedIssuerID != list.IssuerID {
		return v2Errorf(V2ErrStatusKeyBindingMismatch, "v2 revocation list issuer does not match authenticated status-key binding")
	}
	signable, err := revocationListSignableBytesV2(list)
	if err != nil {
		return err
	}
	return verifyV2Statement(v2RevocationList, signable, list.Signature, statusKey)
}

func VerifyRevocationPushV2Signature(push *RevocationPushV2, trustedIssuerID string, statusKey HybridPublicKey) error {
	if err := validateRevocationPushV2(push); err != nil {
		return v2Classify(V2ErrMalformed, err)
	}
	if trustedIssuerID != push.IssuerID {
		return v2Errorf(V2ErrStatusKeyBindingMismatch, "v2 revocation push issuer does not match authenticated status-key binding")
	}
	signable, err := revocationPushSignableBytesV2(push)
	if err != nil {
		return err
	}
	return verifyV2Statement(v2RevocationPush, signable, push.Signature, statusKey)
}

// StatusEvidenceDigest binds an audit reference to the complete canonical
// signed status object. The digest does not establish signature validity,
// freshness, or policy evaluation; callers must verify those separately.
func StatusEvidenceDigest(objectType uint16, object any) ([]byte, error) {
	var encoded []byte
	switch v2ObjectType(objectType) {
	case v2RevocationList:
		var list *RevocationListV2
		switch value := object.(type) {
		case *RevocationListV2:
			list = value
		case RevocationListV2:
			list = &value
		default:
			return nil, fmt.Errorf("status evidence type 0x%04x requires RevocationListV2", objectType)
		}
		var err error
		encoded, err = EncodeRevocationListV2(list)
		if err != nil {
			return nil, err
		}
	case v2RevocationPush:
		var push *RevocationPushV2
		switch value := object.(type) {
		case *RevocationPushV2:
			push = value
		case RevocationPushV2:
			push = &value
		default:
			return nil, fmt.Errorf("status evidence type 0x%04x requires RevocationPushV2", objectType)
		}
		var err error
		encoded, err = EncodeRevocationPushV2(push)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported status evidence object type: %04x", objectType)
	}
	h := sha512.New384()
	h.Write([]byte("ratify-protocol-status-evidence-v2\x00"))
	var code [2]byte
	code[0], code[1] = byte(objectType>>8), byte(objectType)
	h.Write(code[:])
	h.Write(encoded)
	return h.Sum(nil), nil
}

func DecodeProofBundleV2(data []byte) (_ *ProofBundleV2, err error) {
	defer func() { err = v2Classify(V2ErrMalformed, err) }()
	if err := checkV2WireSize(data, "proof bundle", "MAX_PROOF_BUNDLE_BYTES_V2", MaxProofBundleBytesV2); err != nil {
		return nil, err
	}
	if err := checkWireJSONV2(data, "delegation_digest"); err != nil {
		return nil, err
	}
	if err := requireV2Fields(data, proofBundleV2Fields, "session_context", "stream_id", "stream_seq"); err != nil {
		return nil, err
	}
	var rawBundle struct {
		Delegations []json.RawMessage `json:"delegations"`
	}
	if err := json.Unmarshal(data, &rawBundle); err != nil {
		return nil, err
	}
	if rawBundle.Delegations == nil {
		return nil, fmt.Errorf("wire v2: delegations must be an array")
	}
	for i, rawCert := range rawBundle.Delegations {
		if err := requireV2Fields(rawCert, delegationV2Fields); err != nil {
			return nil, fmt.Errorf("wire v2 delegation %d: %w", i, err)
		}
		var certFields map[string]json.RawMessage
		if err := json.Unmarshal(rawCert, &certFields); err != nil {
			return nil, err
		}
		var constraints []json.RawMessage
		if err := json.Unmarshal(certFields["constraints"], &constraints); err != nil || constraints == nil {
			return nil, fmt.Errorf("wire v2 delegation %d: constraints must be an array", i)
		}
		if err := validateV2ScopeArray(certFields["scope"]); err != nil {
			return nil, fmt.Errorf("wire v2 delegation %d: %w", i, err)
		}
		for j, rawConstraint := range constraints {
			if err := validateV2ConstraintFields(rawConstraint); err != nil {
				return nil, fmt.Errorf("wire v2 delegation %d constraint %d: %w", i, j, err)
			}
		}
	}
	var bundle ProofBundleV2
	if err := strictUnmarshalV2(data, &bundle); err != nil {
		return nil, err
	}
	if bundle.Version != 2 {
		return nil, fmt.Errorf("wire v2: version must be 2")
	}
	if !validV2ID(bundle.VerifierID) || !validV2ID(bundle.AgentID) {
		return nil, fmt.Errorf("wire v2: verifier_id and agent_id must be 64 lowercase hexadecimal characters")
	}
	if len(bundle.Delegations) > MaxDelegationChainDepth {
		return nil, fmt.Errorf("wire v2: delegation chain exceeds MAX_DELEGATION_CHAIN_DEPTH (%d)", MaxDelegationChainDepth)
	}
	if bundle.Delegations == nil {
		return nil, fmt.Errorf("wire v2: delegations must be an array")
	}
	if len(bundle.Challenge) != 32 {
		return nil, fmt.Errorf("wire v2: challenge must be 32 bytes")
	}
	if !validV2Timestamp(bundle.ChallengeAt) {
		return nil, fmt.Errorf("wire v2: challenge_at is outside 0..%d", V2MaxTimestampSeconds)
	}
	if len(bundle.DelegationDigest) != sha512.Size384 {
		return nil, fmt.Errorf("wire v2: delegation_digest must be 48 bytes")
	}
	// requireV2Fields distinguishes an explicit null from an omitted field;
	// encoding/json maps null and omission alike for pointer fields here.
	if bundle.SessionContext != nil && len(*bundle.SessionContext) != 32 {
		return nil, fmt.Errorf("wire v2: session_context must be null or 32 bytes")
	}
	if (bundle.StreamID == nil) != (bundle.StreamSeq == nil) {
		return nil, fmt.Errorf("wire v2: stream_id and stream_seq must both be null or both set")
	}
	if bundle.StreamID != nil && (len(*bundle.StreamID) != 32 || *bundle.StreamSeq <= 0) {
		return nil, fmt.Errorf("wire v2: bound stream requires 32-byte stream_id and positive stream_seq")
	}
	if bundle.StreamSeq != nil && *bundle.StreamSeq > maxSafeInteger {
		return nil, fmt.Errorf("wire v2: stream_seq exceeds the safe integer range")
	}
	if err := validateHybridSignatureV2(bundle.ChallengeSig); err != nil {
		return nil, err
	}
	for i := range bundle.Delegations {
		if err := validateDelegationCertV2(&bundle.Delegations[i]); err != nil {
			return nil, fmt.Errorf("wire v2 delegation %d: %w", i, err)
		}
		if err := validateHybridSignatureV2(bundle.Delegations[i].Signature); err != nil {
			return nil, fmt.Errorf("wire v2 delegation %d: %w", i, err)
		}
	}
	return &bundle, nil
}

// validateV2ScopeArray checks only the wire shape and resource bounds.
// Registry and uniqueness checks are post-claim authorization results.
func validateV2ScopeArray(data json.RawMessage) error {
	var scopes []json.RawMessage
	if err := json.Unmarshal(data, &scopes); err != nil || scopes == nil {
		return fmt.Errorf("wire v2: scope must be an array of strings")
	}
	if len(scopes) > MaxScopesPerCert {
		return fmt.Errorf("wire v2: scope count exceeds protocol bound")
	}
	for i, raw := range scopes {
		var scope string
		if err := json.Unmarshal(raw, &scope); err != nil || len(scope) > MaxScopeLengthBytes {
			return fmt.Errorf("wire v2: scope %d must be a bounded string", i)
		}
	}
	return nil
}

func containsV2Field(fields []string, name string) bool {
	for _, field := range fields {
		if field == name {
			return true
		}
	}
	return false
}

func checkV2Nulls(data []byte) error {
	var walk func(json.RawMessage, bool) error
	walk = func(raw json.RawMessage, inParams bool) error {
		if inParams {
			return nil
		}
		trimmed := bytes.TrimSpace(raw)
		if bytes.Equal(trimmed, []byte("null")) {
			return fmt.Errorf("null is not allowed in this v2 object")
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) == nil && object != nil {
			for key, value := range object {
				if err := walk(value, key == "params"); err != nil {
					return fmt.Errorf("field %s: %w", key, err)
				}
			}
			return nil
		}
		var array []json.RawMessage
		if json.Unmarshal(raw, &array) == nil {
			for i, value := range array {
				if err := walk(value, false); err != nil {
					return fmt.Errorf("item %d: %w", i, err)
				}
			}
		}
		return nil
	}
	return walk(data, false)
}

func validateHybridSignatureV2(sig HybridSignature) error {
	if len(sig.Ed25519) != 64 || len(sig.MLDSA65) != 3309 {
		return fmt.Errorf("wire v2: signature must contain 64-byte Ed25519 and 3309-byte ML-DSA-65 components")
	}
	return nil
}

func validateDelegationCertV2(c *DelegationCertV2) error {
	if c.Version != 2 {
		return fmt.Errorf("version must be 2")
	}
	if !validV2Timestamp(c.IssuedAt) || !validV2Timestamp(c.ExpiresAt) {
		return fmt.Errorf("issued_at and expires_at must be safe integers")
	}
	if c.CertID == "" || len(c.CertID) > MaxIdentifierLengthBytes {
		return fmt.Errorf("cert_id must be non-empty and within the identifier byte limit")
	}
	if !validV2ID(c.IssuerID) || !validV2ID(c.SubjectID) {
		return fmt.Errorf("issuer_id and subject_id must be 64 lowercase hexadecimal characters")
	}
	issuer, err := keyIDV2(c.IssuerPubKey)
	if err != nil {
		return fmt.Errorf("issuer key: %w", err)
	}
	subject, err := keyIDV2(c.SubjectPubKey)
	if err != nil {
		return fmt.Errorf("subject key: %w", err)
	}
	if c.IssuerID != issuer || c.SubjectID != subject {
		return v2Errorf(V2ErrKeyIDMismatch, "key ID does not match complete public key")
	}
	if c.Scope == nil {
		return fmt.Errorf("scope must be an array")
	}
	for _, scope := range c.Scope {
		if len(scope) > MaxScopeLengthBytes {
			return fmt.Errorf("scope exceeds the protocol byte limit")
		}
	}
	if c.Constraints == nil {
		return fmt.Errorf("constraints must be an array")
	}
	if len(c.Scope) > MaxScopesPerCert || len(c.Constraints) > MaxConstraintsPerCert {
		return fmt.Errorf("scope or constraint count exceeds protocol bound")
	}
	for i, constraint := range c.Constraints {
		encoded, err := json.Marshal(constraint)
		if err != nil {
			return fmt.Errorf("constraint %d: %w", i, err)
		}
		if err := validateV2ConstraintFields(encoded); err != nil {
			return fmt.Errorf("constraint %d: %w", i, err)
		}
	}
	return nil
}

func validV2ID(id string) bool {
	if len(id) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(id)
	return err == nil && bytes.Equal([]byte(hex.EncodeToString(decoded)), []byte(id))
}

func certSignableBytesV2(c *DelegationCertV2) ([]byte, error) {
	constraints := c.Constraints
	if constraints == nil {
		constraints = []ConstraintV2{}
	}
	return CanonicalJSON(delegationSignableV2{c.CertID, constraints, c.ExpiresAt, c.IssuedAt, c.IssuerID, c.IssuerPubKey, c.Scope, c.SubjectID, c.SubjectPubKey, c.Version})
}

// SignDelegationCertV2 returns a signed copy of cert using the issuer's v2
// hybrid key. The public key and issuer ID in the certificate must match that
// key; the caller still decides whether the issuer is trusted.
func SignDelegationCertV2(cert *DelegationCertV2, issuerKey HybridPrivateKey) (*DelegationCertV2, error) {
	return SignDelegationCertV2WithSigner(context.Background(), cert, localSignerV2{issuerKey})
}

// SignDelegationCertV2WithSigner is SignDelegationCertV2 with an external
// signer whose complete public key must equal the certificate issuer key.
//
// The issuer duties of SPEC-v2 §5.1 and §5.2 are checked before any signer
// method runs: the certificate must decode-validate, carry valid v2 scopes,
// have issued_at < expires_at and a lifetime of at most 315360000 seconds,
// and carry a jointly satisfiable set of resource_path constraints. These
// checks are issuer hygiene only; a verifier still rejects or denies a
// certificate that violates them independently.
func SignDelegationCertV2WithSigner(ctx context.Context, cert *DelegationCertV2, signer SignerV2) (*DelegationCertV2, error) {
	if cert == nil {
		return nil, fmt.Errorf("v2 delegation certificate is nil")
	}
	if err := validateDelegationCertV2(cert); err != nil {
		return nil, err
	}
	if err := ValidateScopesV2(cert.Scope); err != nil {
		return nil, fmt.Errorf("v2 issuer scope: %w", err)
	}
	if err := validateDelegationIssuanceV2(cert); err != nil {
		return nil, err
	}
	issuerPub, err := signerPublicKeyV2(signer)
	if err != nil {
		return nil, err
	}
	issuerID, err := keyIDV2(issuerPub)
	if err != nil {
		return nil, err
	}
	if cert.IssuerID != issuerID || !bytes.Equal(cert.IssuerPubKey.Ed25519, issuerPub.Ed25519) || !bytes.Equal(cert.IssuerPubKey.MLDSA65, issuerPub.MLDSA65) {
		return nil, fmt.Errorf("v2 issuer key does not match certificate issuer")
	}
	unsigned := *cert
	unsigned.Signature = placeholderV2Signature()
	wire, err := EncodeDelegationCertV2(&unsigned)
	if err != nil {
		return nil, err
	}
	prepared, err := DecodeDelegationCertV2(wire)
	if err != nil {
		return nil, err
	}
	signable, err := certSignableBytesV2(prepared)
	if err != nil {
		return nil, err
	}
	signature, err := signV2StatementWithSigner(ctx, v2DelegationCertificate, signable, signer, issuerPub)
	if err != nil {
		return nil, err
	}
	prepared.Signature = signature
	wire, err = EncodeDelegationCertV2(prepared)
	if err != nil {
		return nil, err
	}
	signed, err := DecodeDelegationCertV2(wire)
	if err != nil {
		return nil, err
	}
	if err := verifyV2Statement(v2DelegationCertificate, signable, signed.Signature, issuerPub); err != nil {
		return nil, fmt.Errorf("signed v2 delegation certificate failed verification: %w", err)
	}
	return signed, nil
}

// validateDelegationIssuanceV2 enforces the issuer duties a decoder does
// not (SPEC-v2 §5.1, §5.2): issued_at < expires_at, a lifetime of at most
// V2MaxDelegationLifetimeSeconds, and a jointly satisfiable resource_path
// set. Every resource_path constraint must name the same resource_id, each
// present path_prefix must satisfy the path model, and every two prefixes
// must nest under the segment-prefix relation (an absent prefix orders as
// "/"). A set that fails any rule could never pass verification together.
func validateDelegationIssuanceV2(cert *DelegationCertV2) error {
	if cert.IssuedAt >= cert.ExpiresAt {
		return fmt.Errorf("v2 issuer duty: issued_at must be earlier than expires_at")
	}
	if cert.ExpiresAt-cert.IssuedAt > V2MaxDelegationLifetimeSeconds {
		return fmt.Errorf("v2 issuer duty: delegation lifetime exceeds %d seconds", V2MaxDelegationLifetimeSeconds)
	}
	resourceID := ""
	var prefixes []string
	for i, c := range cert.Constraints {
		if c.Type != ConstraintResourcePath {
			continue
		}
		if c.PathPrefix != "" {
			if _, err := NormalizeResourcePath(c.PathPrefix); err != nil {
				return fmt.Errorf("v2 issuer duty: constraint %d path_prefix can never match: %v", i, err)
			}
		}
		if resourceID == "" {
			resourceID = c.ResourceID
		} else if c.ResourceID != resourceID {
			return fmt.Errorf("v2 issuer duty: constraint %d names a different resource_id; the resource_path set is jointly unsatisfiable", i)
		}
		for _, prior := range prefixes {
			if !resourcePathsNested(prior, c.PathPrefix) {
				return fmt.Errorf("v2 issuer duty: constraint %d path_prefix %q does not nest with %q; the resource_path set is jointly unsatisfiable", i, c.PathPrefix, prior)
			}
		}
		prefixes = append(prefixes, c.PathPrefix)
	}
	return nil
}

func presentationSignableBytesV2(b *ProofBundleV2) ([]byte, error) {
	return CanonicalJSON(presentationSignableV2{b.AgentID, b.AgentPubKey, b.Challenge, b.ChallengeAt, b.DelegationDigest, b.SessionContext, b.StreamID, b.StreamSeq, b.VerifierID, b.Version})
}

func delegationDigestV2(certs []DelegationCertV2) ([]byte, error) {
	ordered := make([]delegationCanonicalV2, len(certs))
	for i, c := range certs {
		constraints := c.Constraints
		if constraints == nil {
			constraints = []ConstraintV2{}
		}
		ordered[i] = delegationCanonicalV2{c.CertID, constraints, c.ExpiresAt, c.IssuedAt, c.IssuerID, c.IssuerPubKey, c.Scope, c.Signature, c.SubjectID, c.SubjectPubKey, c.Version}
	}
	canonical, err := CanonicalJSON(ordered)
	if err != nil {
		return nil, err
	}
	h := sha512.New384()
	h.Write([]byte("ratify-protocol-delegations-v2\x00"))
	h.Write(canonical)
	return h.Sum(nil), nil
}

// VerifyDelegationCertV2Signature checks one certificate's structure, its
// key-ID bindings, and its issuer signature under code 0x0001 using the
// certificate's own issuer key. It does not establish that the issuer is
// trusted; chain and root evaluation remain the verifier's responsibility.
func VerifyDelegationCertV2Signature(cert *DelegationCertV2) error {
	if cert == nil {
		return v2Errorf(V2ErrMalformed, "v2 delegation certificate is nil")
	}
	if err := validateDelegationCertV2(cert); err != nil {
		return v2Classify(V2ErrMalformed, err)
	}
	if err := validateHybridSignatureV2(cert.Signature); err != nil {
		return v2Classify(V2ErrMalformed, err)
	}
	signable, err := certSignableBytesV2(cert)
	if err != nil {
		return v2Classify(V2ErrMalformed, err)
	}
	return verifyV2Statement(v2DelegationCertificate, signable, cert.Signature, cert.IssuerPubKey)
}

// EncodeDelegationCertV2 and EncodeProofBundleV2 emit the exact sorted-key
// canonical wire form used by v2 statements and delegation-chain digests.
func EncodeDelegationCertV2(c *DelegationCertV2) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("v2 delegation certificate is nil")
	}
	if err := validateDelegationCertV2(c); err != nil {
		return nil, err
	}
	if err := validateHybridSignatureV2(c.Signature); err != nil {
		return nil, err
	}
	canonical := delegationCanonicalV2{c.CertID, c.Constraints, c.ExpiresAt, c.IssuedAt, c.IssuerID, c.IssuerPubKey, c.Scope, c.Signature, c.SubjectID, c.SubjectPubKey, c.Version}
	encoded, err := CanonicalJSON(canonical)
	if err != nil {
		return nil, err
	}
	if _, err := DecodeDelegationCertV2(encoded); err != nil {
		return nil, fmt.Errorf("invalid v2 delegation certificate: %w", err)
	}
	return encoded, nil
}

func EncodeProofBundleV2(b *ProofBundleV2) ([]byte, error) {
	if b == nil {
		return nil, fmt.Errorf("v2 proof bundle is nil")
	}
	delegations := make([]delegationCanonicalV2, len(b.Delegations))
	for i, c := range b.Delegations {
		delegations[i] = delegationCanonicalV2{c.CertID, c.Constraints, c.ExpiresAt, c.IssuedAt, c.IssuerID, c.IssuerPubKey, c.Scope, c.Signature, c.SubjectID, c.SubjectPubKey, c.Version}
	}
	wire := proofBundleCanonicalV2{b.AgentID, b.AgentPubKey, b.Challenge, b.ChallengeAt, b.ChallengeSig, b.DelegationDigest, delegations, b.SessionContext, b.StreamID, b.StreamSeq, b.VerifierID, b.Version}
	encoded, err := CanonicalJSON(wire)
	if err != nil {
		return nil, err
	}
	if _, err := DecodeProofBundleV2(encoded); err != nil {
		return nil, fmt.Errorf("invalid v2 proof bundle: %w", err)
	}
	return encoded, nil
}

// SignProofBundleV2 computes the delegation digest and signs the challenge
// presentation with the agent key. It verifies the resulting local chain and
// signatures, but does not establish that the terminal issuer is trusted.
func SignProofBundleV2(bundle *ProofBundleV2, agentKey HybridPrivateKey) (*ProofBundleV2, error) {
	return SignProofBundleV2WithSigner(context.Background(), bundle, localSignerV2{agentKey})
}

// SignProofBundleV2WithSigner is SignProofBundleV2 with an external signer
// whose complete public key must equal the bundle agent key.
func SignProofBundleV2WithSigner(ctx context.Context, bundle *ProofBundleV2, signer SignerV2) (*ProofBundleV2, error) {
	if bundle == nil {
		return nil, fmt.Errorf("v2 proof bundle is nil")
	}
	agentPub, err := signerPublicKeyV2(signer)
	if err != nil {
		return nil, err
	}
	agentID, err := keyIDV2(agentPub)
	if err != nil {
		return nil, err
	}
	if bundle.AgentID != agentID || !bytes.Equal(bundle.AgentPubKey.Ed25519, agentPub.Ed25519) || !bytes.Equal(bundle.AgentPubKey.MLDSA65, agentPub.MLDSA65) {
		return nil, fmt.Errorf("v2 agent key does not match proof bundle agent")
	}
	unsigned := *bundle
	unsigned.ChallengeSig = placeholderV2Signature()
	unsigned.DelegationDigest = make([]byte, sha512.Size384)
	wire, err := EncodeProofBundleV2(&unsigned)
	if err != nil {
		return nil, err
	}
	prepared, err := DecodeProofBundleV2(wire)
	if err != nil {
		return nil, err
	}
	digest, err := delegationDigestV2(prepared.Delegations)
	if err != nil {
		return nil, err
	}
	prepared.DelegationDigest = digest
	signable, err := presentationSignableBytesV2(prepared)
	if err != nil {
		return nil, err
	}
	prepared.ChallengeSig, err = signV2StatementWithSigner(ctx, v2ChallengePresentation, signable, signer, agentPub)
	if err != nil {
		return nil, err
	}
	wire, err = EncodeProofBundleV2(prepared)
	if err != nil {
		return nil, err
	}
	signed, err := DecodeProofBundleV2(wire)
	if err != nil {
		return nil, err
	}
	if err := VerifyProofBundleV2Signatures(signed); err != nil {
		return nil, fmt.Errorf("invalid signed v2 proof bundle: %w", err)
	}
	return signed, nil
}

// VerifyProofBundleV2Signatures checks local structure, chain linkage and every
// hybrid signature. It deliberately does not resolve the root, consume a
// challenge, query status, or issue an authorization decision. Every
// structural check completes before any signature is verified, so a
// structural failure is reported with its structural class.
func VerifyProofBundleV2Signatures(b *ProofBundleV2) error {
	if err := verifyProofBundleV2Structure(b); err != nil {
		return err
	}
	return verifyProofBundleV2SignaturesOnly(b)
}

// verifyProofBundleV2Structure recomputes every key ID and checks the
// delegation digest, chain linkage, and duplicate CertificateRefs.
func verifyProofBundleV2Structure(b *ProofBundleV2) error {
	if b == nil {
		return v2Errorf(V2ErrMalformed, "v2 proof bundle is nil")
	}
	if b.Version != 2 {
		return v2Errorf(V2ErrMalformed, "v2 proof bundle version must be 2")
	}
	if len(b.Delegations) > MaxDelegationChainDepth || len(b.Challenge) != 32 || len(b.DelegationDigest) != sha512.Size384 {
		return v2Errorf(V2ErrMalformed, "v2 proof bundle exceeds a chain bound or has an invalid challenge/digest length")
	}
	if b.Delegations == nil {
		return v2Errorf(V2ErrMalformed, "v2 delegations must be an array")
	}
	if b.StreamSeq != nil && *b.StreamSeq > maxSafeInteger {
		return v2Errorf(V2ErrMalformed, "v2 stream sequence exceeds the safe integer range")
	}
	if b.SessionContext != nil && *b.SessionContext != nil && len(*b.SessionContext) != 32 {
		return v2Errorf(V2ErrMalformed, "v2 session_context must be null or 32 bytes")
	}
	streamNull := b.StreamID == nil || *b.StreamID == nil
	if streamNull != (b.StreamSeq == nil) || (!streamNull && (len(*b.StreamID) != 32 || *b.StreamSeq <= 0)) {
		return v2Errorf(V2ErrMalformed, "v2 stream_id and stream_seq must both be null or a 32-byte ID and positive sequence")
	}
	if !validV2ID(b.AgentID) || !validV2ID(b.VerifierID) {
		return v2Errorf(V2ErrMalformed, "v2 verifier and agent IDs must be canonical")
	}
	agentID, err := keyIDV2(b.AgentPubKey)
	if err != nil {
		return v2Classify(V2ErrMalformed, err)
	}
	if agentID != b.AgentID {
		return v2Errorf(V2ErrKeyIDMismatch, "agent_id does not match agent_pub_key")
	}
	for i := range b.Delegations {
		if err := validateDelegationCertV2(&b.Delegations[i]); err != nil {
			return v2Classify(V2ErrMalformed, fmt.Errorf("delegation %d: %w", i, err))
		}
	}
	digest, err := delegationDigestV2(b.Delegations)
	if err != nil {
		return v2Classify(V2ErrMalformed, err)
	}
	if !bytes.Equal(digest, b.DelegationDigest) {
		return v2Errorf(V2ErrDelegationDigestMismatch, "delegation_digest mismatch")
	}
	seen := map[string]bool{}
	for i := range b.Delegations {
		c := &b.Delegations[i]
		ref := c.IssuerID + "\x00" + c.CertID
		if seen[ref] {
			return v2Errorf(V2ErrDuplicateCertificateRef, "duplicate delegation reference")
		}
		seen[ref] = true
		if i+1 < len(b.Delegations) && (c.IssuerID != b.Delegations[i+1].SubjectID || !bytes.Equal(c.IssuerPubKey.Ed25519, b.Delegations[i+1].SubjectPubKey.Ed25519) || !bytes.Equal(c.IssuerPubKey.MLDSA65, b.Delegations[i+1].SubjectPubKey.MLDSA65)) {
			return v2Errorf(V2ErrChainLinkageMismatch, "delegation chain link %d does not match parent subject", i)
		}
	}
	if len(b.Delegations) > 0 {
		leaf := b.Delegations[0]
		if leaf.SubjectID != b.AgentID || !bytes.Equal(leaf.SubjectPubKey.Ed25519, b.AgentPubKey.Ed25519) || !bytes.Equal(leaf.SubjectPubKey.MLDSA65, b.AgentPubKey.MLDSA65) {
			return v2Errorf(V2ErrChainLinkageMismatch, "agent key does not match leaf delegation subject")
		}
	}
	return nil
}

// verifyProofBundleV2SignaturesOnly verifies every certificate signature and
// then the challenge-presentation signature. Callers run the structural pass
// first. An empty chain verifies only the agent's presentation signature.
func verifyProofBundleV2SignaturesOnly(b *ProofBundleV2) error {
	for i := range b.Delegations {
		c := &b.Delegations[i]
		signable, err := certSignableBytesV2(c)
		if err != nil {
			return v2Classify(V2ErrMalformed, err)
		}
		if err := verifyV2Statement(v2DelegationCertificate, signable, c.Signature, c.IssuerPubKey); err != nil {
			return fmt.Errorf("delegation %d signature: %w", i, err)
		}
	}
	signable, err := presentationSignableBytesV2(b)
	if err != nil {
		return v2Classify(V2ErrMalformed, err)
	}
	return verifyV2Statement(v2ChallengePresentation, signable, b.ChallengeSig, b.AgentPubKey)
}
