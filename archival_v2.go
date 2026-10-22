package ratify

import (
	"encoding/hex"
	"fmt"
	"slices"
)

// FreshnessUnverifiedV2 is the mandatory label of every archival result.
const FreshnessUnverifiedV2 = "freshness_unverified"

// ArchivalVerificationV2 reports that one stored v2 object decoded strictly
// and that its signatures verify. It is NOT an authorization decision and
// MUST NOT be used to allow an action: no challenge was consumed, and no
// trust root, issuer status, revocation, expiry at the current time, receipt
// log position or rotation state was evaluated.
type ArchivalVerificationV2 struct {
	// ObjectType is the SPEC-v2 object code of the verified object.
	ObjectType uint16 `json:"object_type_code"`
	// Freshness is always FreshnessUnverifiedV2.
	Freshness string `json:"freshness"`
	// Actionable is always false.
	Actionable bool `json:"actionable"`
	// Digest identifies the verified content as "sha384:" + 96 hex: the
	// bundle hash for a proof bundle, StatementBodyDigestV2 for rotation,
	// witness and verification-receipt statements, and the status evidence
	// digest for revocation lists and pushes. (Proof bundles use
	// VerifyArchivalProofBundleV2.) It is empty for certificates
	// and transaction receipts, which have no registered object digest.
	Digest string `json:"digest"`
	// SignerKeyIDs lists the v2 key IDs whose signatures were verified, in
	// object order.
	SignerKeyIDs []string `json:"signer_key_ids"`
}

func archivalResultV2(code v2ObjectType, digest []byte, signers ...string) ArchivalVerificationV2 {
	result := ArchivalVerificationV2{
		ObjectType: uint16(code), Freshness: FreshnessUnverifiedV2, Actionable: false, SignerKeyIDs: signers,
	}
	if digest != nil {
		result.Digest = "sha384:" + hex.EncodeToString(digest)
	}
	return result
}

// ArchivalProofBundleResultV2 is the SPEC-v2 §6.10 archival result. It has
// no decision field and is never actionable: no challenge was consumed and
// no provider was invoked. ErrorClass is empty when every check passed.
type ArchivalProofBundleResultV2 struct {
	Assessment string       `json:"assessment"`
	Actionable bool         `json:"actionable"`
	BundleHash string       `json:"bundle_hash"`
	AgentID    string       `json:"agent_id"`
	IssuerIDs  []string     `json:"issuer_ids"`
	ErrorClass V2ErrorClass `json:"error_class"`
	// Err carries the diagnostic for ErrorClass; it is not part of the
	// language-neutral result.
	Err error `json:"-"`
}

// MarshalJSON writes the SPEC-v2 §6.10 members, with error_class null when
// every check passed.
func (r ArchivalProofBundleResultV2) MarshalJSON() ([]byte, error) {
	var class *V2ErrorClass
	if r.ErrorClass != "" {
		c := r.ErrorClass
		class = &c
	}
	issuers := r.IssuerIDs
	if issuers == nil {
		issuers = []string{}
	}
	return CanonicalJSON(struct {
		Actionable bool          `json:"actionable"`
		AgentID    string        `json:"agent_id"`
		Assessment string        `json:"assessment"`
		BundleHash string        `json:"bundle_hash"`
		ErrorClass *V2ErrorClass `json:"error_class"`
		IssuerIDs  []string      `json:"issuer_ids"`
	}{r.Actionable, r.AgentID, r.Assessment, r.BundleHash, class, issuers})
}

// VerifyArchivalProofBundleV2 performs only the signature-and-structure
// pre-claim steps on a stored proof bundle: bounded strict decode, key IDs,
// delegation digest, duplicate CertificateRef and linkage, and every
// certificate and challenge signature. It omits required-scope validation,
// expected-challenge checks and every provider.
func VerifyArchivalProofBundleV2(data []byte) ArchivalProofBundleResultV2 {
	result := ArchivalProofBundleResultV2{Assessment: FreshnessUnverifiedV2, Actionable: false, IssuerIDs: []string{}}
	fail := func(err error) ArchivalProofBundleResultV2 {
		result.ErrorClass, result.Err = V2ErrorClassOf(err), err
		return result
	}
	bundle, err := DecodeProofBundleV2(data)
	if err != nil {
		return fail(err)
	}
	result.AgentID = bundle.AgentID
	if result.BundleHash, err = BundleHashV2(bundle); err != nil {
		return fail(v2Classify(V2ErrMalformed, err))
	}
	for _, cert := range bundle.Delegations {
		result.IssuerIDs = append(result.IssuerIDs, cert.IssuerID)
	}
	slices.Sort(result.IssuerIDs)
	result.IssuerIDs = slices.Compact(result.IssuerIDs)
	if err := VerifyProofBundleV2Signatures(bundle); err != nil {
		return fail(err)
	}
	return result
}

// VerifyArchivalDelegationCertV2 checks one stored certificate and its issuer
// signature under the issuer key it carries.
func VerifyArchivalDelegationCertV2(data []byte) (ArchivalVerificationV2, error) {
	cert, err := DecodeDelegationCertV2(data)
	if err != nil {
		return ArchivalVerificationV2{}, err
	}
	if err := VerifyDelegationCertV2Signature(cert); err != nil {
		return ArchivalVerificationV2{}, err
	}
	return archivalResultV2(v2DelegationCertificate, nil, cert.IssuerID), nil
}

// VerifyArchivalRevocationListV2 checks a stored revocation list under a
// caller-authenticated issuer status key.
func VerifyArchivalRevocationListV2(data []byte, issuerID string, statusKey HybridPublicKey) (ArchivalVerificationV2, error) {
	list, err := DecodeRevocationListV2(data)
	if err != nil {
		return ArchivalVerificationV2{}, err
	}
	if err := VerifyRevocationListV2Signature(list, issuerID, statusKey); err != nil {
		return ArchivalVerificationV2{}, err
	}
	digest, err := StatusEvidenceDigest(uint16(v2RevocationList), list)
	if err != nil {
		return ArchivalVerificationV2{}, v2Classify(V2ErrMalformed, err)
	}
	keyID, _ := keyIDV2(statusKey)
	return archivalResultV2(v2RevocationList, digest, keyID), nil
}

// VerifyArchivalRevocationPushV2 checks a stored revocation push under a
// caller-authenticated issuer status key.
func VerifyArchivalRevocationPushV2(data []byte, issuerID string, statusKey HybridPublicKey) (ArchivalVerificationV2, error) {
	push, err := DecodeRevocationPushV2(data)
	if err != nil {
		return ArchivalVerificationV2{}, err
	}
	if err := VerifyRevocationPushV2Signature(push, issuerID, statusKey); err != nil {
		return ArchivalVerificationV2{}, err
	}
	digest, err := StatusEvidenceDigest(uint16(v2RevocationPush), push)
	if err != nil {
		return ArchivalVerificationV2{}, v2Classify(V2ErrMalformed, err)
	}
	keyID, _ := keyIDV2(statusKey)
	return archivalResultV2(v2RevocationPush, digest, keyID), nil
}

// VerifyArchivalKeyRotationStatementV2 checks a stored rotation statement's
// old-key authorization and new-key proof of possession under the keys it
// names. It does not establish that old_key was the authority's current key.
func VerifyArchivalKeyRotationStatementV2(data []byte) (ArchivalVerificationV2, error) {
	stmt, err := DecodeKeyRotationStatementV2(data)
	if err != nil {
		return ArchivalVerificationV2{}, err
	}
	signable, err := keyRotationSignableBytesV2(stmt)
	if err != nil {
		return ArchivalVerificationV2{}, v2Classify(V2ErrMalformed, err)
	}
	if err := verifyV2Statement(v2KeyRotationAuthorization, signable, stmt.OldSignature, stmt.OldKey); err != nil {
		return ArchivalVerificationV2{}, fmt.Errorf("old-key rotation authorization: %w", err)
	}
	if err := verifyV2Statement(v2KeyRotationProofOfPossession, signable, stmt.NewSignature, stmt.NewKey); err != nil {
		return ArchivalVerificationV2{}, fmt.Errorf("new-key proof of possession: %w", err)
	}
	digest, err := KeyRotationStatementV2Digest(stmt)
	if err != nil {
		return ArchivalVerificationV2{}, v2Classify(V2ErrMalformed, err)
	}
	return archivalResultV2(v2KeyRotationAuthorization, digest, stmt.OldKeyID, stmt.NewKeyID), nil
}

// VerifyArchivalWitnessEntryV2 checks a stored witness entry under a
// caller-authenticated witness key, without log position or fork checks.
func VerifyArchivalWitnessEntryV2(data []byte, witnessPublic HybridPublicKey) (ArchivalVerificationV2, error) {
	entry, err := DecodeWitnessEntryV2(data)
	if err != nil {
		return ArchivalVerificationV2{}, err
	}
	witnessID, err := keyIDV2(witnessPublic)
	if err != nil || witnessID != entry.WitnessID {
		return ArchivalVerificationV2{}, v2Errorf(V2ErrKeyIDMismatch, "witness key does not match witness_id")
	}
	body, err := witnessEntrySignableBytesV2(entry)
	if err != nil {
		return ArchivalVerificationV2{}, v2Classify(V2ErrMalformed, err)
	}
	if err := verifyV2Statement(v2WitnessEntry, body, entry.Signature, witnessPublic); err != nil {
		return ArchivalVerificationV2{}, err
	}
	digest, err := WitnessEntryV2Digest(entry)
	if err != nil {
		return ArchivalVerificationV2{}, v2Classify(V2ErrMalformed, err)
	}
	return archivalResultV2(v2WitnessEntry, digest, witnessID), nil
}

// VerifyArchivalVerificationReceiptV2 checks a stored verification receipt
// under a caller-authenticated verifier key, without log position, fork or
// bundle-binding checks.
func VerifyArchivalVerificationReceiptV2(data []byte, verifierPublic HybridPublicKey) (ArchivalVerificationV2, error) {
	receipt, err := DecodeVerificationReceiptV2(data)
	if err != nil {
		return ArchivalVerificationV2{}, err
	}
	verifierID, err := keyIDV2(verifierPublic)
	if err != nil || verifierID != receipt.VerifierID {
		return ArchivalVerificationV2{}, v2Errorf(V2ErrKeyIDMismatch, "verifier key does not match verifier_id")
	}
	body, err := CanonicalJSON(receiptV2Signable(receipt))
	if err != nil {
		return ArchivalVerificationV2{}, v2Classify(V2ErrMalformed, err)
	}
	if err := verifyV2Statement(v2VerificationReceipt, body, receipt.Signature, verifierPublic); err != nil {
		return ArchivalVerificationV2{}, err
	}
	digest, err := VerificationReceiptV2Digest(receipt)
	if err != nil {
		return ArchivalVerificationV2{}, v2Classify(V2ErrMalformed, err)
	}
	return archivalResultV2(v2VerificationReceipt, digest, verifierID), nil
}

// VerifyArchivalTransactionReceiptV2 checks a stored transaction receipt:
// canonical form, every party signature, and every embedded proof bundle's
// signatures, hash and transaction context. Use VerifyTransactionReceiptV2
// for per-party trust and status.
func VerifyArchivalTransactionReceiptV2(data []byte) (ArchivalVerificationV2, error) {
	receipt, err := DecodeTransactionReceiptV2(data)
	if err != nil {
		return ArchivalVerificationV2{}, err
	}
	signers := make([]string, len(receipt.Parties))
	for i, party := range receipt.Parties {
		signers[i] = party.AgentID
	}
	return archivalResultV2(v2TransactionPartyStatement, nil, signers...), nil
}
