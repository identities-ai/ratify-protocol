package v2vectors

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// HedgedFile is the name of the hedged-signature vector file. Unlike Files,
// it is NOT regenerated deterministically: its ML-DSA-65 signatures use fresh
// randomness by design. Regenerate it only with
// `go run ./cmd/ratify-v2-vectors -hedged` and commit the result.
const HedgedFile = "hedged-signatures.json"

// HedgedVariants is the number of independently hedged re-signings per object.
const HedgedVariants = 2

type hedgedObject struct {
	Name                 string        `json:"name"`
	Kind                 string        `json:"kind"`
	Verify               verifyContext `json:"verify"`
	ResignedFields       []string      `json:"resigned_fields"`
	DeterministicWireB64 string        `json:"deterministic_wire_b64"`
	HedgedWireB64        []string      `json:"hedged_wire_b64"`
}

type hedgedFile struct {
	Version     int            `json:"version"`
	Description string         `json:"description"`
	Objects     []hedgedObject `json:"objects"`
}

// GenerateHedged returns hedged-signatures.json. Every call returns different
// signature bytes.
func GenerateHedged() ([]byte, error) {
	var out []byte
	err := catch(func() {
		g := newGen()
		objects := g.objectsFile().(objectsFile)
		f := hedgedFile{
			Version:     2,
			Description: "Randomized (hedged) ML-DSA-65 signatures over the exact statements of objects.json. Each object's hedged_wire_b64 variants carry the same signed bodies as deterministic_wire_b64; only the ML-DSA-65 component of each field in resigned_fields was produced with fresh FIPS 204 hedging randomness (Ed25519 is deterministic and unchanged). An implementation MUST decode each variant, re-encode it to identical bytes, and verify it with verify exactly as objects.json; MUST derive identical signable projections and statement body digests for every variant; and MUST NOT require signature bytes to match the deterministic fixture or each other. Idempotency, replay and fork checks compare StatementBodyDigestV2, never signature bytes. This file is not reproducible: the generator writes it only when run with -hedged.",
		}
		for _, o := range objects.Objects {
			fields := hedgedFieldsFor(o)
			if len(fields) == 0 {
				continue
			}
			wire := must(b64d(o.WireB64))
			h := hedgedObject{Name: o.Name, Kind: o.Kind, Verify: o.Verify, DeterministicWireB64: o.WireB64}
			for _, s := range fields {
				h.ResignedFields = append(h.ResignedFields, s.Field)
			}
			for i := 0; i < HedgedVariants; i++ {
				h.HedgedWireB64 = append(h.HedgedWireB64, b64(g.hedgedResign(wire, fields)))
			}
			f.Objects = append(f.Objects, h)
		}
		encoded, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			panic(err)
		}
		out = append(encoded, '\n')
	})
	return out, err
}

// hedgedFieldsFor selects the top-level signature fields of an object. Nested
// certificate signatures inside a bundle are excluded: changing them would
// change delegation_digest and therefore the presentation body.
func hedgedFieldsFor(o objectVector) []sigVector {
	var out []sigVector
	for _, s := range o.Signatures {
		if strings.Contains(s.Field, "delegations[") {
			continue
		}
		out = append(out, s)
	}
	return out
}

func (g *gen) hedgedResign(wire []byte, fields []sigVector) []byte {
	o := parse(wire).(map[string]any)
	for _, s := range fields {
		key := g.k(s.Signer)
		message := must(b64d(s.MessageB64))
		ml := make([]byte, mldsa65.SignatureSize)
		if err := mldsa65.SignTo(key.Priv.MLDSA65, message, []byte(s.MLDSAContext), true, ml); err != nil {
			panic(err)
		}
		var target map[string]any
		if strings.HasPrefix(s.Field, "party_signatures[") {
			party := strings.TrimSuffix(strings.TrimPrefix(s.Field, "party_signatures["), "]")
			for _, item := range arr(o["party_signatures"]) {
				if obj(item)["party_id"] == party {
					target = obj(obj(item)["signature"])
				}
			}
		} else {
			target = obj(o[s.Field])
		}
		if target == nil {
			panic(fmt.Sprintf("signature field %s not found", s.Field))
		}
		target["ml_dsa_65"] = b64(ml)
	}
	return canon(o)
}
