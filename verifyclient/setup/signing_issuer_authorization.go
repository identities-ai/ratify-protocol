package setup

import (
	"bytes"
	"fmt"
	"slices"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

const (
	v2IssuerAuthorizationMaxWire = 28 << 10
	v2IssuerAuthorizationMaxAge  = 90 * 24 * 60 * 60
)

// VerifyV2SigningIssuerAuthorization checks the customer's root-signed
// delegation that gives a newly proved issuer key signing authority.
func VerifyV2SigningIssuerAuthorization(wire []byte, rootID, issuerID string,
	root, issuer ratify.HybridPublicKey, at int64) (*ratify.DelegationCertV2, error) {
	if len(wire) < 2 || len(wire) > v2IssuerAuthorizationMaxWire ||
		!v2HexID.MatchString(rootID) || !v2HexID.MatchString(issuerID) || at < 1 {
		return nil, fmt.Errorf("issuer authorization identity or size is invalid")
	}
	cert, err := ratify.DecodeDelegationCertV2(wire)
	if err != nil || ratify.VerifyDelegationCertV2Signature(cert) != nil {
		return nil, fmt.Errorf("issuer authorization signature or wire is invalid")
	}
	canonical, err := ratify.EncodeDelegationCertV2(cert)
	if err != nil || !bytes.Equal(canonical, wire) || cert.IssuerID != rootID ||
		cert.SubjectID != issuerID || !bytes.Equal(cert.IssuerPubKey.Ed25519, root.Ed25519) ||
		!bytes.Equal(cert.IssuerPubKey.MLDSA65, root.MLDSA65) ||
		!bytes.Equal(cert.SubjectPubKey.Ed25519, issuer.Ed25519) ||
		!bytes.Equal(cert.SubjectPubKey.MLDSA65, issuer.MLDSA65) ||
		!slices.Contains(cert.Scope, "identity:delegate") || cert.IssuedAt > at ||
		at >= cert.ExpiresAt || cert.ExpiresAt-cert.IssuedAt > v2IssuerAuthorizationMaxAge {
		return nil, fmt.Errorf("issuer authorization does not bind the current root and issuer")
	}
	return cert, nil
}
