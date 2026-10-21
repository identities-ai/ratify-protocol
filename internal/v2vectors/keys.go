package v2vectors

import (
	"crypto/sha256"
	"encoding/hex"
)

type keyEntry struct {
	Name           string         `json:"name"`
	Ed25519SeedHex string         `json:"ed25519_seed_hex"`
	MLDSA65SeedHex string         `json:"ml_dsa_65_seed_hex"`
	PublicKey      map[string]any `json:"public_key"`
	KeyIDV2        string         `json:"key_id_v2"`
	V1KeyID128     string         `json:"v1_key_id_128"`
}

type invalidKeyID struct {
	Name               string `json:"name"`
	Value              string `json:"value"`
	ExpectedErrorClass string `json:"expected_error_class"`
}

type keysFile struct {
	Version       int            `json:"version"`
	Description   string         `json:"description"`
	KeyIDPreimage string         `json:"key_id_preimage"`
	Keys          []keyEntry     `json:"keys"`
	InvalidKeyIDs []invalidKeyID `json:"invalid_v2_key_ids"`
}

func (g *gen) keysFile() any {
	f := keysFile{
		Version:       2,
		Description:   "Deterministic fixture keys shared by every v2 vector file. Seeds are public test data. key_id_v2 = lowercase_hex(SHA-256(ASCII(\"ratify-key-id-v2\") || 0x00 || ed25519_public_key || ml_dsa_65_public_key)). v1_key_id_128 is the v1 128-bit ID of the same key and MUST NOT be accepted where a v2 key ID is required.",
		KeyIDPreimage: "ratify-key-id-v2 || 0x00 || ed25519(32) || ml_dsa_65(1952)",
	}
	for _, name := range g.order {
		k := g.k(name)
		v1 := sha256.Sum256(append(append([]byte{}, k.Pub.Ed25519...), k.Pub.MLDSA65...))
		f.Keys = append(f.Keys, keyEntry{
			Name: name, Ed25519SeedHex: hex.EncodeToString(k.EdSeed[:]), MLDSA65SeedHex: hex.EncodeToString(k.MLSeed[:]),
			PublicKey: pubJSON(k.Pub), KeyIDV2: k.ID, V1KeyID128: hex.EncodeToString(v1[:16]),
		})
	}
	agent := g.k("agent")
	v1 := sha256.Sum256(append(append([]byte{}, agent.Pub.Ed25519...), agent.Pub.MLDSA65...))
	upper := []byte(agent.ID)
	for i, c := range upper {
		if c >= 'a' && c <= 'f' {
			upper[i] = c - 32
			break
		}
	}
	f.InvalidKeyIDs = []invalidKeyID{
		{"v1_128_bit_id", hex.EncodeToString(v1[:16]), "malformed"},
		{"uppercase_hex", string(upper), "malformed"},
		{"63_characters", agent.ID[:63], "malformed"},
		{"65_characters", agent.ID + "0", "malformed"},
		{"0x_prefixed", "0x" + agent.ID[2:], "malformed"},
		{"empty", "", "malformed"},
	}
	return f
}
