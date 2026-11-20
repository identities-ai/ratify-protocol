package setup

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// Verify Trust Profile signatures: every Verify object is signed under a
// transcript bound to its verify code, with both Ed25519 and ML-DSA-65.
const (
	v2TrustProfileVersion          = 1
	v2VerifyCodeReceiverConfig     = 0x010D
	v2VerifyCodeReceiverConfigHead = 0x010E
	v2ReceiverConfigSchema         = "ratify.verify.receiver_config_content"
	v2ReceiverConfigHeadSchema     = "ratify.verify.receiver_config_head"
	v2MaxReceiverConfigBytes       = 1 << 20
	v2MaxReceiverConfigAgeSeconds  = 30 * 24 * 3600
)

var (
	v2HexID        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	v2ApproverUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// V2KeyID is the Protocol v2 key ID: SHA-256 of the domain tag and both
// public-key components.
func V2KeyID(pub ratify.HybridPublicKey) (string, error) {
	if len(pub.Ed25519) != ed25519.PublicKeySize || len(pub.MLDSA65) != mldsa65.PublicKeySize {
		return "", fmt.Errorf("v2 hybrid public key has the wrong component sizes")
	}
	h := sha256.New()
	h.Write([]byte("ratify-key-id-v2\x00"))
	h.Write(pub.Ed25519)
	h.Write(pub.MLDSA65)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func v2VerifyTranscript(code uint16, signable []byte) ([]byte, []byte) {
	digest := sha256.Sum256(signable)
	message := append([]byte("ratify-verify-signature\x00"), byte(v2TrustProfileVersion), byte(code>>8), byte(code))
	message = append(message, digest[:]...)
	context := append([]byte("ratify-verify/"), byte(v2TrustProfileVersion), byte(code>>8), byte(code))
	return message, context
}

// signV2VerifyObject signs canonical body bytes under the Verify transcript.
func signV2VerifyObject(code uint16, signable []byte, private ratify.HybridPrivateKey) (ratify.HybridSignature, error) {
	message, context := v2VerifyTranscript(code, signable)
	ml := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(private.MLDSA65, message, context, true, ml); err != nil {
		return ratify.HybridSignature{}, err
	}
	return ratify.HybridSignature{Ed25519: ed25519.Sign(private.Ed25519, message), MLDSA65: ml}, nil
}

// verifyV2VerifyObject requires both signature components (strict AND).
func verifyV2VerifyObject(code uint16, signable []byte, signature ratify.HybridSignature, public ratify.HybridPublicKey) error {
	message, context := v2VerifyTranscript(code, signable)
	if len(public.Ed25519) != ed25519.PublicKeySize || len(signature.Ed25519) != ed25519.SignatureSize ||
		!ed25519.Verify(ed25519.PublicKey(public.Ed25519), message, signature.Ed25519) {
		return fmt.Errorf("Verify object Ed25519 signature is invalid")
	}
	var ml mldsa65.PublicKey
	if err := ml.UnmarshalBinary(public.MLDSA65); err != nil || len(signature.MLDSA65) != mldsa65.SignatureSize ||
		!mldsa65.Verify(&ml, message, context, signature.MLDSA65) {
		return fmt.Errorf("Verify object ML-DSA-65 signature is invalid")
	}
	return nil
}

// V2TrustAnchor pins an organization root accepted by the receiver.
type V2TrustAnchor struct {
	PublicKey ratify.HybridPublicKey `json:"public_key"`
	RootID    string                 `json:"root_id"`
}

// V2IssuerStatusKey binds an issuer to its current status-signing key.
type V2IssuerStatusKey struct {
	Epoch     uint64                 `json:"epoch"`
	IssuerID  string                 `json:"issuer_id"`
	StatusKey ratify.HybridPublicKey `json:"status_key"`
}

// V2ReceiverOperation maps (operation_id, action) to exactly one scope.
type V2ReceiverOperation struct {
	Action        string `json:"action"`
	OperationID   string `json:"operation_id"`
	RequiredScope string `json:"required_scope"`
	RiskClass     string `json:"risk_class"`
}

// V2StatusPolicy bounds status freshness for this receiver.
type V2StatusPolicy struct {
	MaxListLifetimeSeconds int64 `json:"max_list_lifetime_seconds"`
	MaxStatusAgeSeconds    int64 `json:"max_status_age_seconds"`
}

// V2ReceiverConfigContent is the receiver-signed configuration content
// (verify_code 0x010D). Field order is canonical.
type V2ReceiverConfigContent struct {
	Anchors          []V2TrustAnchor        `json:"anchors"`
	ConfigSignerKey  ratify.HybridPublicKey `json:"config_signer_key"`
	IssuerStatusKeys []V2IssuerStatusKey    `json:"issuer_status_keys"`
	Operations       []V2ReceiverOperation  `json:"operations"`
	ReceiverID       string                 `json:"receiver_id"`
	Schema           string                 `json:"schema"`
	StatusPolicy     V2StatusPolicy         `json:"status_policy"`
	VerifyCode       uint16                 `json:"verify_code"`
	Version          int                    `json:"version"`
	WorkspaceID      string                 `json:"workspace_id"`
}

// V2ReceiverConfigHead is the receiver-signed freshness head (0x010E).
type V2ReceiverConfigHead struct {
	ContentDigest   string `json:"content_digest"`
	IssuedAt        int64  `json:"issued_at"`
	NotAfter        int64  `json:"not_after"`
	PriorHeadDigest string `json:"prior_head_digest"`
	ReceiverID      string `json:"receiver_id"`
	Schema          string `json:"schema"`
	Sequence        int64  `json:"sequence"`
	VerifyCode      uint16 `json:"verify_code"`
	Version         int    `json:"version"`
}

// v2SignedVerifyObject is the evidence envelope for one signed object.
type v2SignedVerifyObject struct {
	Body           json.RawMessage        `json:"body"`
	ObjectType     string                 `json:"object_type"`
	ProfileVersion int                    `json:"profile_version"`
	Signature      ratify.HybridSignature `json:"signature"`
	SignerKeyID    string                 `json:"signer_key_id"`
	VerifyCode     uint16                 `json:"verify_code"`
}

// V2ReceiverConfig is an accepted signed content and head pair, with its
// exact profile bytes and their digest.
type V2ReceiverConfig struct {
	Content V2ReceiverConfigContent
	Head    V2ReceiverConfigHead
	Bytes   []byte
	Digest  string
}

type v2ReceiverConfigDocument struct {
	Content v2SignedVerifyObject `json:"content"`
	Head    v2SignedVerifyObject `json:"head"`
}

func sha384Hex(data []byte) string {
	sum := sha512.Sum384(data)
	return hex.EncodeToString(sum[:])
}

// SignV2ReceiverConfig is the receiver-side signer for a content and head
// pair. It returns the exact profile bytes to submit.
func SignV2ReceiverConfig(content V2ReceiverConfigContent, head V2ReceiverConfigHead, signer ratify.HybridPrivateKey) ([]byte, error) {
	content.Schema, content.VerifyCode, content.Version = v2ReceiverConfigSchema, v2VerifyCodeReceiverConfig, v2TrustProfileVersion
	contentBytes, err := ratify.CanonicalJSON(content)
	if err != nil {
		return nil, err
	}
	head.Schema, head.VerifyCode, head.Version = v2ReceiverConfigHeadSchema, v2VerifyCodeReceiverConfigHead, v2TrustProfileVersion
	head.ContentDigest = "sha384:" + sha384Hex(contentBytes)
	headBytes, err := ratify.CanonicalJSON(head)
	if err != nil {
		return nil, err
	}
	signerID, err := V2KeyID(signer.Public())
	if err != nil {
		return nil, err
	}
	envelope := func(code uint16, schema string, body []byte) (v2SignedVerifyObject, error) {
		signature, err := signV2VerifyObject(code, body, signer)
		return v2SignedVerifyObject{Body: body, ObjectType: schema, ProfileVersion: v2TrustProfileVersion,
			Signature: signature, SignerKeyID: signerID, VerifyCode: code}, err
	}
	contentObject, err := envelope(v2VerifyCodeReceiverConfig, v2ReceiverConfigSchema, contentBytes)
	if err != nil {
		return nil, err
	}
	headObject, err := envelope(v2VerifyCodeReceiverConfigHead, v2ReceiverConfigHeadSchema, headBytes)
	if err != nil {
		return nil, err
	}
	return ratify.CanonicalJSON(v2ReceiverConfigDocument{Content: contentObject, Head: headObject})
}

func decodeV2Strict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing data")
	}
	canonical, err := ratify.CanonicalJSON(target)
	if err != nil || !bytes.Equal(canonical, data) {
		return fmt.Errorf("noncanonical encoding")
	}
	return nil
}

// ParseV2ReceiverConfig verifies the exact profile bytes. previous is the
// currently accepted configuration for the same receiver, or nil at first
// enrollment, when the content must be signed by its own config_signer_key.
// A later configuration must be signed by the key the previous content named,
// advance the head sequence, and chain the prior head digest.
func ParseV2ReceiverConfig(data []byte, previous *V2ReceiverConfig, now int64) (*V2ReceiverConfig, error) {
	if len(data) < 2 || len(data) > v2MaxReceiverConfigBytes {
		return nil, fmt.Errorf("v2 receiver config size is invalid")
	}
	var document v2ReceiverConfigDocument
	if err := decodeV2Strict(data, &document); err != nil {
		return nil, fmt.Errorf("v2 receiver config document: %w", err)
	}
	config := &V2ReceiverConfig{Bytes: append([]byte(nil), data...), Digest: "sha384:" + sha384Hex(data)}
	if err := decodeV2Strict(document.Content.Body, &config.Content); err != nil {
		return nil, fmt.Errorf("v2 receiver config content: %w", err)
	}
	if err := decodeV2Strict(document.Head.Body, &config.Head); err != nil {
		return nil, fmt.Errorf("v2 receiver config head: %w", err)
	}
	content, head := config.Content, config.Head
	for _, object := range []struct {
		envelope v2SignedVerifyObject
		schema   string
		code     uint16
	}{{document.Content, v2ReceiverConfigSchema, v2VerifyCodeReceiverConfig}, {document.Head, v2ReceiverConfigHeadSchema, v2VerifyCodeReceiverConfigHead}} {
		if object.envelope.ObjectType != object.schema || object.envelope.VerifyCode != object.code ||
			object.envelope.ProfileVersion != v2TrustProfileVersion {
			return nil, fmt.Errorf("v2 receiver config envelope type or code is invalid")
		}
	}
	if content.Schema != v2ReceiverConfigSchema || content.VerifyCode != v2VerifyCodeReceiverConfig || content.Version != v2TrustProfileVersion ||
		head.Schema != v2ReceiverConfigHeadSchema || head.VerifyCode != v2VerifyCodeReceiverConfigHead || head.Version != v2TrustProfileVersion {
		return nil, fmt.Errorf("v2 receiver config body type or code is invalid")
	}
	signerKey := content.ConfigSignerKey
	if previous != nil {
		signerKey = previous.Content.ConfigSignerKey
	}
	signerID, err := V2KeyID(signerKey)
	if err != nil {
		return nil, err
	}
	for _, object := range []v2SignedVerifyObject{document.Content, document.Head} {
		if object.SignerKeyID != signerID {
			return nil, fmt.Errorf("v2 receiver config is not signed by the pinned config signer")
		}
		if err := verifyV2VerifyObject(object.VerifyCode, object.Body, object.Signature, signerKey); err != nil {
			return nil, err
		}
	}
	if head.ContentDigest != "sha384:"+sha384Hex(document.Content.Body) || head.ReceiverID != content.ReceiverID ||
		head.Sequence < 1 || head.IssuedAt > now+60 || head.NotAfter <= now ||
		head.NotAfter-head.IssuedAt > v2MaxReceiverConfigAgeSeconds {
		return nil, fmt.Errorf("v2 receiver config head is stale, future, or does not bind the content")
	}
	if previous == nil {
		if head.Sequence != 1 || head.PriorHeadDigest != "" {
			return nil, fmt.Errorf("v2 first receiver config must start at sequence 1")
		}
	} else {
		var prior v2ReceiverConfigDocument
		if err := decodeV2Strict(previous.Bytes, &prior); err != nil {
			return nil, err
		}
		if content.ReceiverID != previous.Content.ReceiverID || content.WorkspaceID != previous.Content.WorkspaceID ||
			head.Sequence <= previous.Head.Sequence || head.PriorHeadDigest != "sha384:"+sha384Hex(prior.Head.Body) {
			return nil, fmt.Errorf("v2 receiver config does not extend the accepted configuration")
		}
	}
	if err := validateV2ReceiverConfigContent(content); err != nil {
		return nil, err
	}
	return config, nil
}

func validateV2ReceiverConfigContent(content V2ReceiverConfigContent) error {
	if content.ReceiverID == "" || content.WorkspaceID == "" || len(content.Operations) == 0 ||
		content.StatusPolicy.MaxListLifetimeSeconds <= 0 || content.StatusPolicy.MaxStatusAgeSeconds <= 0 ||
		content.StatusPolicy.MaxStatusAgeSeconds > content.StatusPolicy.MaxListLifetimeSeconds {
		return fmt.Errorf("v2 receiver config content is incomplete")
	}
	seenRoots := map[string]bool{}
	for _, anchor := range content.Anchors {
		id, err := V2KeyID(anchor.PublicKey)
		if err != nil || id != anchor.RootID || seenRoots[id] {
			return fmt.Errorf("v2 trust anchor %s does not match its key or repeats", anchor.RootID)
		}
		seenRoots[id] = true
	}
	seenIssuers := map[string]bool{}
	for _, binding := range content.IssuerStatusKeys {
		if !v2HexID.MatchString(binding.IssuerID) || seenIssuers[binding.IssuerID] || binding.Epoch < 1 {
			return fmt.Errorf("v2 issuer status key binding is invalid or repeated")
		}
		if _, err := V2KeyID(binding.StatusKey); err != nil {
			return err
		}
		seenIssuers[binding.IssuerID] = true
	}
	seenOps := map[string]bool{}
	for _, operation := range content.Operations {
		key := operation.OperationID + "\x00" + operation.Action
		if operation.OperationID == "" || operation.Action == "" || operation.RequiredScope == "" || seenOps[key] {
			return fmt.Errorf("v2 receiver operation map entry is invalid or repeated")
		}
		if err := ratify.ValidateScopesV2([]string{operation.RequiredScope}); err != nil {
			return fmt.Errorf("v2 receiver operation required scope is invalid: %w", err)
		}
		// The supported risk classes are standard and high (high requires a
		// customer-held agent key). Any other class fails closed.
		if operation.RiskClass != "standard" && operation.RiskClass != "high" {
			return fmt.Errorf("v2 receiver operation risk class %q is not supported", operation.RiskClass)
		}
		seenOps[key] = true
	}
	return nil
}

// StatusKeys is the caller-authenticated status-key configuration of this
// receiver (SPEC-v2 6.5): one current epoch and key per issuer.
func (c *V2ReceiverConfig) StatusKeys() map[string]ratify.V2StatusKeyConfig {
	keys := make(map[string]ratify.V2StatusKeyConfig, len(c.Content.IssuerStatusKeys))
	for _, binding := range c.Content.IssuerStatusKeys {
		keys[binding.IssuerID] = ratify.V2StatusKeyConfig{Epoch: binding.Epoch, Key: binding.StatusKey}
	}
	return keys
}
