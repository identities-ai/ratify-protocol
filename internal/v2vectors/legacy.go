package v2vectors

import (
	"encoding/base64"
	"encoding/hex"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// legacyRotation reproduces key-rotation-signature.json exactly as first
// published by cmd/ratify-v2-rotation-vectors. Its shape is frozen.
type legacyRotation struct {
	Continuation          *legacyRotation        `json:"continuation,omitempty"`
	Version               int                    `json:"version"`
	ObjectTypeCode        int                    `json:"object_type_code"`
	AuthorityID           string                 `json:"authority_id"`
	RecoveryEpoch         int64                  `json:"recovery_epoch"`
	Role                  string                 `json:"role"`
	Sequence              int64                  `json:"sequence"`
	PreviousStatementHash string                 `json:"previous_statement_hash"`
	IssuedAt              int64                  `json:"issued_at"`
	NotBefore             int64                  `json:"not_before"`
	OldKeyID              string                 `json:"old_key_id"`
	NewKeyID              string                 `json:"new_key_id"`
	OldKeySeeds           legacySeeds            `json:"old_key_seeds"`
	NewKeySeeds           legacySeeds            `json:"new_key_seeds"`
	OldKey                ratify.HybridPublicKey `json:"old_key"`
	NewKey                ratify.HybridPublicKey `json:"new_key"`
	SignableBytes         string                 `json:"signable_bytes"`
	StatementBodyDigest   string                 `json:"statement_body_digest"`
	OldMLDSAContext       string                 `json:"old_mldsa_context"`
	NewMLDSAContext       string                 `json:"new_mldsa_context"`
	OldSignature          ratify.HybridSignature `json:"old_signature"`
	NewSignature          ratify.HybridSignature `json:"new_signature"`
	Wire                  string                 `json:"wire"`
}

type legacySeeds struct {
	Ed25519 string `json:"ed25519"`
	MLDSA65 string `json:"ml_dsa_65"`
}

func (g *gen) legacyRotationVector() any {
	keys := map[string]*Key{}
	for _, s := range []struct {
		name   string
		ed, ml byte
	}{{"old", 0x11, 0xfe}, {"new", 0x22, 0xfd}, {"third", 0x33, 0xfc}} {
		var edSeed, mlSeed [32]byte
		for i := range edSeed {
			edSeed[i], mlSeed[i] = s.ed, s.ml
		}
		pub, priv := must2(ratify.HybridKeypairFromSeeds(edSeed, mlSeed))
		keys[s.name] = &Key{Name: s.name, Pub: pub, Priv: priv, ID: keyIDV2(pub), EdSeed: edSeed, MLSeed: mlSeed}
	}
	seeds := func(k *Key) legacySeeds {
		return legacySeeds{hex.EncodeToString(k.EdSeed[:]), hex.EncodeToString(k.MLSeed[:])}
	}
	build := func(old, next *Key, sequence int64, prev []byte, issuedAt, notBefore int64) legacyRotation {
		stmt, wire, signable, _, _ := g.rotation(rotationSpec{
			authority: "11223344556677889900aabbccddeeff", epoch: 7, role: "organization_root",
			sequence: sequence, prev: prev, oldKey: old, newKey: next, issuedAt: issuedAt, notBefore: notBefore,
		})
		return legacyRotation{
			Version: 2, ObjectTypeCode: 4, AuthorityID: stmt.AuthorityID, RecoveryEpoch: stmt.RecoveryEpoch,
			Role: stmt.Role, Sequence: stmt.Sequence,
			PreviousStatementHash: base64.StdEncoding.EncodeToString(stmt.PreviousStatementHash),
			IssuedAt:              stmt.IssuedAt, NotBefore: stmt.NotBefore,
			OldKeyID: stmt.OldKeyID, NewKeyID: stmt.NewKeyID,
			OldKeySeeds: seeds(old), NewKeySeeds: seeds(next), OldKey: old.Pub, NewKey: next.Pub,
			SignableBytes:       base64.StdEncoding.EncodeToString(signable),
			StatementBodyDigest: hex.EncodeToString(statementBodyDigest(codeRotationOld, signable)),
			OldMLDSAContext:     "ratify-protocol/2/0004", NewMLDSAContext: "ratify-protocol/2/0009",
			OldSignature: stmt.OldSignature, NewSignature: stmt.NewSignature,
			Wire: base64.StdEncoding.EncodeToString(wire),
		}
	}
	first := build(keys["old"], keys["new"], 1, make([]byte, 48), 1800000000, 1800000060)
	digest := must(hex.DecodeString(first.StatementBodyDigest))
	second := build(keys["new"], keys["third"], 2, digest, 1800000010, 1800000070)
	first.Continuation = &second
	return first
}
