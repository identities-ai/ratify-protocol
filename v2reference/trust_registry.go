package v2reference

import (
	"bytes"
	"context"
	"fmt"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// TrustRegistry is the REFERENCE candidate-record trust resolver of SPEC-v2
// §6.1. It holds caller-authenticated root records (complete hybrid public
// keys) and resolves a verified chain by its terminal issuer:
//
//   - a record is a candidate when its key ID equals the terminal issuer ID or
//     either of its components equals the matching component of the terminal
//     issuer key;
//   - no candidate is untrusted;
//   - more than one candidate, including the same key configured twice, is
//     ambiguous; the resolver never selects a first match;
//   - exactly one candidate is trusted with that record's complete key, which
//     the verifier then compares with the chain root (a partial match is
//     treated as ambiguous there).
//
// TEST AND CONFORMANCE USE ONLY: it shows the fail-closed resolution rule; a
// deployment loads its records from its own authenticated configuration.
type TrustRegistry struct {
	records []ratify.HybridPublicKey
	ids     []string
}

// NewTrustRegistry returns a registry over the given records in order.
func NewTrustRegistry(records []ratify.HybridPublicKey) (*TrustRegistry, error) {
	r := &TrustRegistry{}
	for i, key := range records {
		id, err := ratify.KeyIDV2(key)
		if err != nil {
			return nil, fmt.Errorf("v2reference: trust record %d: %w", i, err)
		}
		r.records = append(r.records, ratify.HybridPublicKey{Ed25519: bytes.Clone(key.Ed25519), MLDSA65: bytes.Clone(key.MLDSA65)})
		r.ids = append(r.ids, id)
	}
	return r, nil
}

// Resolve implements the V2VerifyCallbacks.Trust provider.
func (r *TrustRegistry) Resolve(_ context.Context, chain []ratify.DelegationCertV2) (ratify.V2TrustResolution, error) {
	if len(chain) == 0 {
		return ratify.V2TrustResolution{Outcome: ratify.V2TrustUntrusted}, nil
	}
	root := chain[len(chain)-1]
	match := -1
	for i, key := range r.records {
		if r.ids[i] != root.IssuerID && !bytes.Equal(key.Ed25519, root.IssuerPubKey.Ed25519) && !bytes.Equal(key.MLDSA65, root.IssuerPubKey.MLDSA65) {
			continue
		}
		if match >= 0 {
			return ratify.V2TrustResolution{Outcome: ratify.V2TrustAmbiguous}, nil
		}
		match = i
	}
	if match < 0 {
		return ratify.V2TrustResolution{Outcome: ratify.V2TrustUntrusted}, nil
	}
	key := r.records[match]
	return ratify.V2TrustResolution{Outcome: ratify.V2TrustTrusted, RootKey: ratify.HybridPublicKey{Ed25519: bytes.Clone(key.Ed25519), MLDSA65: bytes.Clone(key.MLDSA65)}}, nil
}
