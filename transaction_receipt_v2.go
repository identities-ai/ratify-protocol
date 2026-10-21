package ratify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	// MaxTransactionReceiptBytes bounds the complete encoded receipt, including
	// all embedded proof bundles and signatures.
	MaxTransactionReceiptBytes = 5 << 20
	MaxTransactionParties      = 32
)

// TransactionReceiptV2 binds canonical application terms to one signed v2
// proof per party. Each proof still requires independent trust and status
// evaluation by the receiving verifier.
type TransactionReceiptV2 struct {
	Version            int                             `json:"version"`
	TransactionID      string                          `json:"transaction_id"`
	CreatedAt          int64                           `json:"created_at"`
	TermsSchemaURI     string                          `json:"terms_schema_uri"`
	TermsCanonicalJSON []byte                          `json:"terms_canonical_json"`
	Parties            []TransactionReceiptPartyV2     `json:"parties"`
	PartySignatures    []TransactionReceiptSignatureV2 `json:"party_signatures"`
}

type TransactionReceiptPartyV2 struct {
	PartyID         string
	Role            string
	AgentID         string
	AgentPubKey     HybridPublicKey
	VerifierID      string
	WorkspaceID     string
	SessionID       string
	InvocationID    string
	RequiredScope   string
	ProofBundleHash string
	ProofBundle     *ProofBundleV2
}

type TransactionReceiptSignatureV2 struct {
	PartyID   string
	Signature HybridSignature
}

type transactionReceiptPartySignableV2 struct {
	AgentID         string          `json:"agent_id"`
	AgentPubKey     HybridPublicKey `json:"agent_pub_key"`
	InvocationID    string          `json:"invocation_id"`
	PartyID         string          `json:"party_id"`
	ProofBundleHash string          `json:"proof_bundle_hash"`
	RequiredScope   string          `json:"required_scope"`
	Role            string          `json:"role"`
	SessionID       string          `json:"session_id"`
	VerifierID      string          `json:"verifier_id"`
	WorkspaceID     string          `json:"workspace_id"`
}

type transactionReceiptSignableV2 struct {
	CreatedAt          int64                               `json:"created_at"`
	Parties            []transactionReceiptPartySignableV2 `json:"parties"`
	TermsCanonicalJSON []byte                              `json:"terms_canonical_json"`
	TermsSchemaURI     string                              `json:"terms_schema_uri"`
	TransactionID      string                              `json:"transaction_id"`
	Version            int                                 `json:"version"`
}

type transactionReceiptPartyWireV2 struct {
	AgentID         string          `json:"agent_id"`
	AgentPubKey     HybridPublicKey `json:"agent_pub_key"`
	InvocationID    string          `json:"invocation_id"`
	PartyID         string          `json:"party_id"`
	ProofBundle     json.RawMessage `json:"proof_bundle"`
	ProofBundleHash string          `json:"proof_bundle_hash"`
	RequiredScope   string          `json:"required_scope"`
	Role            string          `json:"role"`
	SessionID       string          `json:"session_id"`
	VerifierID      string          `json:"verifier_id"`
	WorkspaceID     string          `json:"workspace_id"`
}

type transactionReceiptSignatureWireV2 struct {
	PartyID   string          `json:"party_id"`
	Signature HybridSignature `json:"signature"`
}

type transactionReceiptWireV2 struct {
	CreatedAt          int64                               `json:"created_at"`
	Parties            []transactionReceiptPartyWireV2     `json:"parties"`
	PartySignatures    []transactionReceiptSignatureWireV2 `json:"party_signatures"`
	TermsCanonicalJSON []byte                              `json:"terms_canonical_json"`
	TermsSchemaURI     string                              `json:"terms_schema_uri"`
	TransactionID      string                              `json:"transaction_id"`
	Version            int                                 `json:"version"`
}

func transactionReceiptV2SignableBytes(receipt *TransactionReceiptV2) ([]byte, error) {
	if receipt == nil || len(receipt.Parties) == 0 {
		return nil, fmt.Errorf("v2 transaction receipt and parties are required")
	}
	if len(receipt.Parties) > MaxTransactionParties {
		return nil, fmt.Errorf("v2 transaction receipt exceeds MAX_TRANSACTION_PARTIES (%d)", MaxTransactionParties)
	}
	parties := make([]transactionReceiptPartySignableV2, len(receipt.Parties))
	for i, party := range receipt.Parties {
		parties[i] = transactionReceiptPartySignableV2{
			AgentID: party.AgentID, AgentPubKey: party.AgentPubKey,
			InvocationID: party.InvocationID, PartyID: party.PartyID,
			ProofBundleHash: party.ProofBundleHash, RequiredScope: party.RequiredScope,
			Role: party.Role, SessionID: party.SessionID, VerifierID: party.VerifierID,
			WorkspaceID: party.WorkspaceID,
		}
	}
	slices.SortFunc(parties, func(a, b transactionReceiptPartySignableV2) int {
		return bytes.Compare([]byte(a.PartyID), []byte(b.PartyID))
	})
	return CanonicalJSON(transactionReceiptSignableV2{
		CreatedAt: receipt.CreatedAt, Parties: parties,
		TermsCanonicalJSON: receipt.TermsCanonicalJSON,
		TermsSchemaURI:     receipt.TermsSchemaURI, TransactionID: receipt.TransactionID,
		Version: receipt.Version,
	})
}

// TransactionReceiptV2SignBytes returns the exact object-type 0x0007 bytes
// signed by each party. Proof bundles and the signature list are excluded.
func TransactionReceiptV2SignBytes(receipt *TransactionReceiptV2) ([]byte, error) {
	return transactionReceiptV2SignableBytes(receipt)
}

// SignTransactionReceiptPartyV2 signs the shared transaction statement with
// one party's hybrid key. The caller attaches the returned signature once per
// listed party.
func SignTransactionReceiptPartyV2(receipt *TransactionReceiptV2, partyID string, key HybridPrivateKey) (TransactionReceiptSignatureV2, error) {
	return SignTransactionReceiptPartyV2WithSigner(context.Background(), receipt, partyID, localSignerV2{key})
}

// SignTransactionReceiptPartyV2WithSigner is SignTransactionReceiptPartyV2
// with an external signer whose complete key must equal the party agent key.
func SignTransactionReceiptPartyV2WithSigner(ctx context.Context, receipt *TransactionReceiptV2, partyID string, signer SignerV2) (TransactionReceiptSignatureV2, error) {
	if receipt == nil {
		return TransactionReceiptSignatureV2{}, fmt.Errorf("transaction receipt is required")
	}
	partyIndex := slices.IndexFunc(receipt.Parties, func(p TransactionReceiptPartyV2) bool { return p.PartyID == partyID })
	if partyIndex < 0 {
		return TransactionReceiptSignatureV2{}, fmt.Errorf("party %q is not listed in the transaction receipt", partyID)
	}
	partyPublic, err := signerPublicKeyV2(signer)
	if err != nil {
		return TransactionReceiptSignatureV2{}, err
	}
	if !equalHybridPublicKeys(partyPublic, receipt.Parties[partyIndex].AgentPubKey) {
		return TransactionReceiptSignatureV2{}, fmt.Errorf("signing key does not match party %q agent public key", partyID)
	}
	if err := validateTransactionReceiptV2(receipt, false); err != nil {
		return TransactionReceiptSignatureV2{}, fmt.Errorf("cannot sign invalid transaction receipt: %w", err)
	}
	signable, err := transactionReceiptV2SignableBytes(receipt)
	if err != nil {
		return TransactionReceiptSignatureV2{}, err
	}
	signature, err := signV2StatementWithSigner(ctx, v2TransactionPartyStatement, signable, signer, partyPublic)
	if err != nil {
		return TransactionReceiptSignatureV2{}, err
	}
	return TransactionReceiptSignatureV2{PartyID: partyID, Signature: signature}, nil
}

// VerifyTransactionReceiptV2Signatures checks the typed party signatures,
// bundle hashes, party-key bindings, and transaction-derived session context.
// It does not resolve trust roots or evaluate current revocation status.
func VerifyTransactionReceiptV2Signatures(receipt *TransactionReceiptV2) error {
	if err := validateTransactionReceiptV2(receipt, true); err != nil {
		return v2Classify(V2ErrMalformed, err)
	}
	signable, err := transactionReceiptV2SignableBytes(receipt)
	if err != nil {
		return v2Classify(V2ErrMalformed, err)
	}
	signatures := make(map[string]HybridSignature, len(receipt.PartySignatures))
	for _, item := range receipt.PartySignatures {
		if _, exists := signatures[item.PartyID]; exists {
			return v2Errorf(V2ErrTransactionSignatureSetBad, "v2 transaction receipt has duplicate signature for party %q", item.PartyID)
		}
		signatures[item.PartyID] = item.Signature
	}
	if len(signatures) != len(receipt.Parties) {
		return v2Errorf(V2ErrTransactionSignatureSetBad, "v2 transaction receipt must contain exactly one signature per party")
	}
	for _, party := range receipt.Parties {
		signature, ok := signatures[party.PartyID]
		if !ok {
			return v2Errorf(V2ErrTransactionSignatureSetBad, "v2 transaction receipt is missing signature for party %q", party.PartyID)
		}
		if err := verifyV2Statement(v2TransactionPartyStatement, signable, signature, party.AgentPubKey); err != nil {
			return fmt.Errorf("v2 transaction receipt signature for party %q: %w", party.PartyID, err)
		}
	}
	return nil
}

func validateTransactionReceiptV2(receipt *TransactionReceiptV2, requireSignatures bool) error {
	if receipt == nil || receipt.Version != 2 || receipt.TransactionID == "" || receipt.CreatedAt < -maxSafeInteger || receipt.CreatedAt > maxSafeInteger || receipt.TermsSchemaURI == "" || len(receipt.TermsCanonicalJSON) == 0 || len(receipt.Parties) == 0 {
		return fmt.Errorf("wire v2: transaction receipt header or terms are invalid")
	}
	if len(receipt.Parties) > MaxTransactionParties {
		return fmt.Errorf("wire v2: transaction receipt exceeds MAX_TRANSACTION_PARTIES (%d)", MaxTransactionParties)
	}
	if err := validateCanonicalTransactionTermsV2(receipt.TermsCanonicalJSON); err != nil {
		return fmt.Errorf("wire v2: transaction terms are not canonical Ratify JSON: %w", err)
	}
	for field, value := range map[string]string{
		"transaction_id": receipt.TransactionID, "terms_schema_uri": receipt.TermsSchemaURI,
	} {
		if !utf8.ValidString(value) {
			return fmt.Errorf("wire v2: %s is not valid UTF-8", field)
		}
	}
	seenParties := make(map[string]bool, len(receipt.Parties))
	seenAgents := make(map[string]bool, len(receipt.Parties))
	transactionHash := transactionContextHashV2(receipt)
	for i, party := range receipt.Parties {
		for field, value := range map[string]string{
			"party_id": party.PartyID, "role": party.Role,
			"session_id": party.SessionID, "invocation_id": party.InvocationID,
		} {
			if !utf8.ValidString(value) {
				return fmt.Errorf("wire v2: transaction party %d %s is not valid UTF-8", i, field)
			}
		}
		if party.PartyID == "" || party.Role == "" || party.SessionID == "" || party.InvocationID == "" || !validV2ID(party.VerifierID) || !protocolV2WorkspacePattern.MatchString(party.WorkspaceID) || !validV2ID(party.AgentID) {
			return fmt.Errorf("wire v2: transaction party %d has invalid identity or context fields", i)
		}
		if i > 0 && bytes.Compare([]byte(receipt.Parties[i-1].PartyID), []byte(party.PartyID)) >= 0 {
			return fmt.Errorf("wire v2: transaction parties must be sorted by unique party_id")
		}
		if seenParties[party.PartyID] {
			return fmt.Errorf("wire v2: duplicate transaction party %q", party.PartyID)
		}
		seenParties[party.PartyID] = true
		if seenAgents[party.AgentID] {
			return fmt.Errorf("wire v2: agent %q cannot represent multiple transaction parties", party.AgentID)
		}
		seenAgents[party.AgentID] = true
		if err := ValidateRequiredScopeV2(party.RequiredScope); err != nil {
			return fmt.Errorf("wire v2: party %q required_scope: %w", party.PartyID, err)
		}
		if party.ProofBundle == nil {
			return fmt.Errorf("wire v2: party %q proof_bundle is required", party.PartyID)
		}
		keyID, err := keyIDV2(party.AgentPubKey)
		if err != nil || keyID != party.AgentID {
			return v2Errorf(V2ErrKeyIDMismatch, "wire v2: party %q agent ID does not match its complete public key", party.PartyID)
		}
		bundle := party.ProofBundle
		bundleHash, err := BundleHashV2(bundle)
		if err != nil || bundleHash != party.ProofBundleHash {
			return v2Errorf(V2ErrBundleHashMismatch, "wire v2: party %q proof_bundle_hash does not match its bundle", party.PartyID)
		}
		if err := VerifyProofBundleV2Signatures(bundle); err != nil {
			return fmt.Errorf("wire v2: party %q proof bundle signature: %w", party.PartyID, err)
		}
		if len(bundle.Delegations) == 0 {
			// SPEC-v2 §5.5: a transaction party must present delegated
			// authority; an empty chain is rejected, never evaluated.
			return v2Errorf(V2ErrTransactionPartyMismatch, "wire v2: party %q proof bundle has no delegation certificates", party.PartyID)
		}
		if bundle.AgentID != party.AgentID || !equalHybridPublicKeys(bundle.AgentPubKey, party.AgentPubKey) || bundle.VerifierID != party.VerifierID || bundle.Delegations[0].SubjectID != party.AgentID {
			return v2Errorf(V2ErrTransactionPartyMismatch, "wire v2: party %q proof bundle identity does not match its signed party", party.PartyID)
		}
		partyHash := transactionPartyRequestHashV2(transactionHash, party.RequiredScope)
		expectedContext, err := BuildSessionContextV2(SessionContextV2Inputs{
			VerifierID: party.VerifierID, WorkspaceID: party.WorkspaceID, AgentID: party.AgentID,
			SessionID: party.SessionID, InvocationID: party.InvocationID, RequestHash: partyHash,
		})
		if err != nil || bundle.SessionContext == nil || *bundle.SessionContext == nil || !bytes.Equal(*bundle.SessionContext, expectedContext) {
			return v2Errorf(V2ErrTransactionContextMismatch, "wire v2: party %q proof bundle session context does not bind this transaction and scope", party.PartyID)
		}
	}
	if requireSignatures {
		if len(receipt.PartySignatures) != len(receipt.Parties) {
			return v2Errorf(V2ErrTransactionSignatureSetBad, "wire v2: transaction receipt must have one signature per party")
		}
		seen := make(map[string]bool, len(receipt.PartySignatures))
		for _, item := range receipt.PartySignatures {
			if !seenParties[item.PartyID] || seen[item.PartyID] {
				return v2Errorf(V2ErrTransactionSignatureSetBad, "wire v2: unknown or duplicate transaction party signature %q", item.PartyID)
			}
			seen[item.PartyID] = true
		}
	}
	_, err := transactionReceiptV2SignableBytes(receipt)
	return err
}

func transactionContextHashV2(receipt *TransactionReceiptV2) []byte {
	termsHash := sha512.Sum384(receipt.TermsCanonicalJSON)
	preimage := append([]byte("ratify/transaction-context/v2"), protocolV2LP([]byte(receipt.TransactionID))...)
	preimage = append(preimage, protocolV2LP([]byte(receipt.TermsSchemaURI))...)
	preimage = append(preimage, termsHash[:]...)
	digest := sha256.Sum256(preimage)
	return digest[:]
}

func transactionPartyRequestHashV2(transactionHash []byte, requiredScope string) []byte {
	preimage := append([]byte("ratify/transaction-party-request/v2"), protocolV2LP(transactionHash)...)
	preimage = append(preimage, protocolV2LP([]byte(requiredScope))...)
	digest := sha256.Sum256(preimage)
	return digest[:]
}

func protocolV2LP(value []byte) []byte {
	var length [8]byte
	length[0] = byte(uint64(len(value)) >> 56)
	length[1] = byte(uint64(len(value)) >> 48)
	length[2] = byte(uint64(len(value)) >> 40)
	length[3] = byte(uint64(len(value)) >> 32)
	length[4] = byte(uint64(len(value)) >> 24)
	length[5] = byte(uint64(len(value)) >> 16)
	length[6] = byte(uint64(len(value)) >> 8)
	length[7] = byte(len(value))
	return append(length[:], value...)
}

func validateCanonicalTransactionTermsV2(data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("terms are not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return fmt.Errorf("terms must be a JSON object")
	}
	if err := validateUniqueTermsJSONObjectV2(decoder, 1); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("terms must contain exactly one JSON object")
	}
	var value any
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	if err := validateRatifyJSONValueV2(value); err != nil {
		return err
	}
	canonical, err := CanonicalJSON(value)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, data) {
		return fmt.Errorf("terms bytes differ from RatifyCanonicalJSON")
	}
	return nil
}

func validateUniqueTermsJSONObjectV2(decoder *json.Decoder, depth int) error {
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("transaction terms object key is not a string")
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate transaction terms key %q", key)
		}
		seen[key] = struct{}{}
		if err := validateUniqueTermsJSONValueV2(decoder, depth); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return fmt.Errorf("invalid transaction terms object ending")
	}
	return nil
}

func validateUniqueTermsJSONValueV2(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= MaxJSONNestingDepth {
		return fmt.Errorf("transaction terms nesting exceeds MAX_JSON_NESTING_DEPTH (%d)", MaxJSONNestingDepth)
	}
	switch delim {
	case '{':
		return validateUniqueTermsJSONObjectV2(decoder, depth+1)
	case '[':
		for decoder.More() {
			if err := validateUniqueTermsJSONValueV2(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return fmt.Errorf("invalid transaction terms array ending")
		}
		return nil
	default:
		return fmt.Errorf("unexpected transaction terms JSON delimiter %q", delim)
	}
}

func validateRatifyJSONValueV2(value any) error {
	switch value := value.(type) {
	case nil, bool, string:
		return nil
	case json.Number:
		if value.String() == "-0" || strings.ContainsAny(value.String(), ".eE") {
			return fmt.Errorf("non-integer JSON numbers are not permitted")
		}
		integer, err := value.Int64()
		if err != nil || integer > maxSafeInteger || integer < -maxSafeInteger {
			return fmt.Errorf("JSON integer is outside the safe-integer range")
		}
		return nil
	case []any:
		for _, item := range value {
			if err := validateRatifyJSONValueV2(item); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		for _, item := range value {
			if err := validateRatifyJSONValueV2(item); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported Ratify JSON value %T", value)
	}
}

// EncodeTransactionReceiptV2 emits canonical v2 wire JSON after validating all
// party signatures and embedded proof signatures.
func EncodeTransactionReceiptV2(receipt *TransactionReceiptV2) ([]byte, error) {
	if err := VerifyTransactionReceiptV2Signatures(receipt); err != nil {
		return nil, err
	}
	return encodeTransactionReceiptV2Canonical(receipt)
}

func encodeTransactionReceiptV2Canonical(receipt *TransactionReceiptV2) ([]byte, error) {
	wire := transactionReceiptWireV2{
		CreatedAt: receipt.CreatedAt, TermsCanonicalJSON: receipt.TermsCanonicalJSON,
		TermsSchemaURI: receipt.TermsSchemaURI, TransactionID: receipt.TransactionID, Version: receipt.Version,
		Parties:         make([]transactionReceiptPartyWireV2, len(receipt.Parties)),
		PartySignatures: make([]transactionReceiptSignatureWireV2, len(receipt.PartySignatures)),
	}
	for i, party := range receipt.Parties {
		bundle, err := EncodeProofBundleV2(party.ProofBundle)
		if err != nil {
			return nil, err
		}
		wire.Parties[i] = transactionReceiptPartyWireV2{
			AgentID: party.AgentID, AgentPubKey: party.AgentPubKey, InvocationID: party.InvocationID,
			PartyID: party.PartyID, ProofBundleHash: party.ProofBundleHash, ProofBundle: bundle,
			RequiredScope: party.RequiredScope, Role: party.Role, SessionID: party.SessionID,
			VerifierID: party.VerifierID, WorkspaceID: party.WorkspaceID,
		}
	}
	signatures := append([]TransactionReceiptSignatureV2(nil), receipt.PartySignatures...)
	slices.SortFunc(signatures, func(a, b TransactionReceiptSignatureV2) int {
		return bytes.Compare([]byte(a.PartyID), []byte(b.PartyID))
	})
	for i, signature := range signatures {
		wire.PartySignatures[i] = transactionReceiptSignatureWireV2{PartyID: signature.PartyID, Signature: signature.Signature}
	}
	encoded, err := CanonicalJSON(wire)
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxTransactionReceiptBytes {
		return nil, fmt.Errorf("wire v2: transaction receipt exceeds MAX_TRANSACTION_RECEIPT_BYTES (%d)", MaxTransactionReceiptBytes)
	}
	return encoded, nil
}

// DecodeTransactionReceiptV2 strictly decodes the v2 transaction receipt and
// verifies party signatures and embedded bundle identity/context bindings.
// Trust, status, freshness, and final scope authorization require verifier
// state and policy and are deliberately not inferred by this codec.
func DecodeTransactionReceiptV2(data []byte) (_ *TransactionReceiptV2, err error) {
	defer func() { err = v2Classify(V2ErrMalformed, err) }()
	if len(data) > MaxTransactionReceiptBytes {
		return nil, fmt.Errorf("wire v2: transaction receipt exceeds MAX_TRANSACTION_RECEIPT_BYTES (%d)", MaxTransactionReceiptBytes)
	}
	if err := checkWireJSONV2(data, "terms_canonical_json"); err != nil {
		return nil, err
	}
	jsonDecoder := json.NewDecoder(bytes.NewReader(data))
	root, err := jsonDecoder.Token()
	if err != nil || root != json.Delim('{') {
		return nil, fmt.Errorf("wire v2: transaction receipt must be a JSON object")
	}
	if err := validateUniqueJSONObjectV2(jsonDecoder); err != nil {
		return nil, fmt.Errorf("wire v2: transaction receipt: %w", err)
	}
	if _, err := jsonDecoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("wire v2: trailing transaction receipt JSON")
	}
	if err := requireV2Fields(data, []string{"version", "transaction_id", "created_at", "terms_schema_uri", "terms_canonical_json", "parties", "party_signatures"}); err != nil {
		return nil, err
	}
	var partyCount struct {
		Parties []json.RawMessage `json:"parties"`
	}
	if err := json.Unmarshal(data, &partyCount); err != nil {
		return nil, err
	}
	if len(partyCount.Parties) > MaxTransactionParties {
		return nil, fmt.Errorf("wire v2: transaction receipt exceeds MAX_TRANSACTION_PARTIES (%d)", MaxTransactionParties)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire transactionReceiptWireV2
	if err := decoder.Decode(&wire); err != nil {
		return nil, fmt.Errorf("wire v2: decode transaction receipt: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("wire v2: trailing transaction receipt JSON")
	}
	receipt := &TransactionReceiptV2{
		Version: wire.Version, TransactionID: wire.TransactionID, CreatedAt: wire.CreatedAt,
		TermsSchemaURI: wire.TermsSchemaURI, TermsCanonicalJSON: wire.TermsCanonicalJSON,
		Parties:         make([]TransactionReceiptPartyV2, len(wire.Parties)),
		PartySignatures: make([]TransactionReceiptSignatureV2, len(wire.PartySignatures)),
	}
	for i, party := range wire.Parties {
		if len(party.ProofBundle) == 0 {
			return nil, fmt.Errorf("wire v2: party %d proof_bundle is required", i)
		}
		hash := sha512.New384()
		hash.Write([]byte("ratify-protocol-bundle-v2\x00"))
		hash.Write(party.ProofBundle)
		if party.ProofBundleHash != "sha384:"+hex.EncodeToString(hash.Sum(nil)) {
			return nil, v2Errorf(V2ErrBundleHashMismatch, "wire v2: party %q proof_bundle_hash does not match its canonical bundle bytes", party.PartyID)
		}
		bundle, err := DecodeProofBundleV2(party.ProofBundle)
		if err != nil {
			return nil, fmt.Errorf("wire v2: party %q proof bundle: %w", party.PartyID, err)
		}
		receipt.Parties[i] = TransactionReceiptPartyV2{
			PartyID: party.PartyID, Role: party.Role, AgentID: party.AgentID,
			AgentPubKey: party.AgentPubKey, VerifierID: party.VerifierID, WorkspaceID: party.WorkspaceID,
			SessionID: party.SessionID, InvocationID: party.InvocationID,
			RequiredScope: party.RequiredScope, ProofBundleHash: party.ProofBundleHash, ProofBundle: bundle,
		}
	}
	for i, signature := range wire.PartySignatures {
		receipt.PartySignatures[i] = TransactionReceiptSignatureV2{PartyID: signature.PartyID, Signature: signature.Signature}
	}
	if err := VerifyTransactionReceiptV2Signatures(receipt); err != nil {
		return nil, err
	}
	canonical, err := encodeTransactionReceiptV2Canonical(receipt)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("wire v2: transaction receipt is not canonical JSON")
	}
	return receipt, nil
}
