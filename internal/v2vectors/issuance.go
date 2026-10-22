package v2vectors

import (
	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// issuerDutyVector is one unsigned delegation certificate and whether a
// conforming typed signer signs it (SPEC-v2 §3.2, §5.1, §5.2).
type issuerDutyVector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Issuer      string `json:"issuer"`
	// UnsignedB64 is the strict wire encoding with an all-zero placeholder
	// signature; it decodes, because these duties are not decoder rules.
	UnsignedB64 string `json:"unsigned_certificate_b64"`
	Expected    string `json:"expected"`
}

type issuerDutiesFile struct {
	Version     int                `json:"version"`
	Description string             `json:"description"`
	Procedure   string             `json:"procedure"`
	Vectors     []issuerDutyVector `json:"vectors"`
}

func (g *gen) issuerDutiesFile() any {
	root, inter := g.k("root"), g.k("intermediate")
	rp := func(id, prefix string) ratify.ConstraintV2 {
		return ratify.ConstraintV2{Type: ratify.ConstraintResourcePath, ResourceID: id, PathPrefix: prefix}
	}
	const lifetime = ratify.V2MaxDelegationLifetimeSeconds
	f := issuerDutiesFile{
		Version:     1,
		Description: "Delegation issuer duties (SPEC-v2 §3.2, §5.1, §5.2). A typed delegation signer, local or external, refuses a certificate whose issued_at is not earlier than expires_at, whose lifetime exceeds 315360000 seconds, or whose resource_path constraints are jointly unsatisfiable, before it invokes any signer method. These are issuer rules, not decoder or verifier rules: every unsigned certificate here decodes, and a verifier that receives such a certificate signed still applies its own rules (proof_invalid, constraint_denied).",
		Procedure:   "Decode unsigned_certificate_b64 strictly (it MUST decode). Sign it with the typed delegation signer under the private key of the fixture key named by issuer (keys.json). expected sign: signing succeeds and the result verifies under code 0x0001. expected reject: signing fails and no signer method (public key, mode, or sign) is invoked.",
	}
	add := func(name, desc string, issuedAt, expiresAt int64, cons []ratify.ConstraintV2, expected string) {
		if cons == nil {
			cons = []ratify.ConstraintV2{}
		}
		c := ratify.DelegationCertV2{Version: 2, CertID: "cert-" + name, IssuerID: root.ID, IssuerPubKey: root.Pub, SubjectID: inter.ID, SubjectPubKey: inter.Pub,
			Scope: []string{"data:read"}, Constraints: cons, IssuedAt: issuedAt, ExpiresAt: expiresAt, Signature: placeholderSig()}
		wire := must(ratify.EncodeDelegationCertV2(&c))
		must(ratify.DecodeDelegationCertV2(wire))
		f.Vectors = append(f.Vectors, issuerDutyVector{Name: name, Description: desc, Issuer: "root", UnsignedB64: b64(wire), Expected: expected})
	}
	add("valid", "an ordinary certificate signs", Now-3600, Now+86400, nil, "sign")
	add("issued_equals_expires", "issued_at equal to expires_at", Now, Now, nil, "reject")
	add("issued_after_expires", "issued_at later than expires_at", Now+1, Now, nil, "reject")
	add("lifetime_at_bound", "expires_at - issued_at exactly 315360000 signs", Now, Now+lifetime, nil, "sign")
	add("lifetime_past_bound", "expires_at - issued_at one second past 315360000", Now, Now+lifetime+1, nil, "reject")
	add("resource_ids_distinct", "two resource_path constraints naming different resource_id values", Now-3600, Now+86400,
		[]ratify.ConstraintV2{rp("repo/a", ""), rp("repo/b", "")}, "reject")
	add("prefixes_disjoint", "same resource, prefixes /src and /docs do not nest", Now-3600, Now+86400,
		[]ratify.ConstraintV2{rp("repo/a", "/src"), rp("repo/a", "/docs")}, "reject")
	add("prefixes_string_not_segment", "same resource, /src and /srcx share bytes but not a segment boundary", Now-3600, Now+86400,
		[]ratify.ConstraintV2{rp("repo/a", "/src"), rp("repo/a", "/srcx")}, "reject")
	add("prefix_outside_path_model", "a path_prefix with a .. segment can never match", Now-3600, Now+86400,
		[]ratify.ConstraintV2{rp("repo/a", "/src/../etc")}, "reject")
	add("prefixes_nested", "same resource, /src and /src/lib/ nest", Now-3600, Now+86400,
		[]ratify.ConstraintV2{rp("repo/a", "/src"), rp("repo/a", "/src/lib/")}, "sign")
	add("prefix_absent_and_present", "an absent prefix orders as / and nests with any valid prefix", Now-3600, Now+86400,
		[]ratify.ConstraintV2{rp("repo/a", ""), rp("repo/a", "/docs")}, "sign")
	return f
}
