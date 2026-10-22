package v2vectors

import ratify "github.com/identities-ai/ratify-protocol/v2"

// External signer vectors (SPEC-v2 §3.2). A scripted provider reports a
// complete public key and returns fixed signature bytes, so every scenario is
// deterministic: the corpus signs ML-DSA-65 without hedging, and the same
// signature is valid for a direct-mode and an external-mu provider because
// both sign the identical mu.

const externalSignerFile = "external-signer.json"

type signerProviderJSON struct {
	PublicKey string         `json:"public_key"`
	Mode      string         `json:"mode"`
	Response  string         `json:"response"`
	Signature map[string]any `json:"signature,omitempty"`
}

type signerRequestJSON struct {
	Mode         string  `json:"mode"`
	MessageB64   string  `json:"message_b64"`
	MLDSAContext *string `json:"mldsa_context"`
	MLDSAMuB64   *string `json:"mldsa_mu_b64"`
	KeyIDV2      string  `json:"key_id_v2"`
}

type signerExpectJSON struct {
	Result        string             `json:"result"`
	ErrorClass    string             `json:"error_class,omitempty"`
	ProviderCalls int                `json:"provider_calls"`
	Request       *signerRequestJSON `json:"request,omitempty"`
	SignedWireB64 string             `json:"signed_wire_b64,omitempty"`
}

type signerBindingJSON struct {
	IssuerID  string `json:"issuer_id"`
	StatusKey string `json:"status_key"`
}

type signerCaseJSON struct {
	Name            string             `json:"name"`
	Description     string             `json:"description"`
	Kind            string             `json:"kind"`
	ObjectB64       string             `json:"object_b64"`
	Binding         *signerBindingJSON `json:"binding,omitempty"`
	CallerCancelled bool               `json:"caller_cancelled,omitempty"`
	Provider        signerProviderJSON `json:"provider"`
	Expected        signerExpectJSON   `json:"expected"`
}

type externalSignerFileJSON struct {
	Version     int               `json:"version"`
	Description string            `json:"description"`
	Semantics   map[string]string `json:"semantics"`
	Cases       []signerCaseJSON  `json:"cases"`
}

func (g *gen) externalSignerFile() any {
	f := externalSignerFileJSON{
		Version: 1,
		Description: "External signer interface (SPEC-v2 §3.2). Each case decodes object_b64, discards its signature, and signs it again with the SDK's typed signing function for kind through the SDK's external signer interface, bound to a scripted provider. " +
			"The provider records every request and answers with fixed bytes. A signed result must equal signed_wire_b64 byte for byte (the corpus is deterministic), and the recorded request must equal expected.request exactly. An error returns no object and must carry error_class.",
		Semantics: map[string]string{
			"kind":             "delegation_certificate: the typed certificate signer (the signer key must be the issuer key the certificate carries); revocation_list: the typed list signer with binding (the authenticated issuer and status key, a keys.json name; the signer key must be that status key); proof_bundle: the typed presentation signer (the signer key must be the agent key)",
			"provider":         "public_key is the keys.json name of the complete key the provider reports when bound. mode is direct (the provider receives M and the 22-byte registry context) or external_mu (it receives only the 64-byte mu). response signature returns signature as given (a component given as an empty string is missing); error returns a provider error; cancel signals the caller's cancellation during the call and then returns signature",
			"caller_cancelled": "true: the caller's cancellation is signalled before the typed signing function is called",
			"expected.request": "the single request the provider received: mode, M (message_b64), mldsa_context (direct) or mldsa_mu_b64 (external_mu), the other null, and the bound key's key_id_v2",
			"error classes":    "a reported key that is not the key the object names is key_id_mismatch, and for a revocation object a reported key that is not the status key the configuration binds to the issuer is status_key_binding_mismatch; in both cases the provider is never asked to sign; a returned component that is missing, malformed, or does not verify over M under the bound key and registry context is invalid_signature and both components are discarded; a provider error is configuration_invalid; a cancellation before or during the call is evaluation_cancelled and a signature returned after it is discarded",
		},
	}
	root, agent, attacker := g.k("root"), g.k("agent"), g.k("attacker")
	add := func(c signerCaseJSON) { f.Cases = append(f.Cases, c) }
	request := func(mode string, key *Key, code uint16, signable []byte) *signerRequestJSON {
		m := message(code, signable)
		r := &signerRequestJSON{Mode: mode, MessageB64: b64(m), KeyIDV2: key.ID}
		if mode == "direct" {
			r.MLDSAContext = strp(string(mldsaContext(code)))
		} else {
			_, mu := externalMu(key.Pub.MLDSA65, code, m)
			r.MLDSAMuB64 = strp(b64(mu))
		}
		return r
	}
	sig := func(s ratify.HybridSignature) map[string]any { return sigJSON(s) }
	flip := func(s ratify.HybridSignature, component string) map[string]any {
		out := sigJSON(s)
		out[component] = flipB64(out[component])
		return out
	}
	signedOK := func(wire []byte, r *signerRequestJSON) signerExpectJSON {
		return signerExpectJSON{Result: "signed", ProviderCalls: 1, Request: r, SignedWireB64: b64(wire)}
	}
	failed := func(class string, calls int, r *signerRequestJSON) signerExpectJSON {
		return signerExpectJSON{Result: "error", ErrorClass: class, ProviderCalls: calls, Request: r}
	}

	// Delegation certificate: the full provider matrix.
	_, certWire, certSigned := g.cert(certSpec{issuer: root, subject: g.k("intermediate"), certID: "cert-root", scope: []string{"data:read", "files:read", "identity:delegate"}})
	good := certSigned.sig
	cert := func(name, desc string, p signerProviderJSON, cancelled bool, e signerExpectJSON) {
		add(signerCaseJSON{Name: "delegation_certificate_" + name, Description: desc, Kind: "delegation_certificate", ObjectB64: b64(certWire), CallerCancelled: cancelled, Provider: p, Expected: e})
	}
	direct := request("direct", root, codeDelegation, certSigned.signable)
	mu := request("external_mu", root, codeDelegation, certSigned.signable)
	cert("direct", "a direct-mode provider receives M and the registry context and returns a valid signature", signerProviderJSON{PublicKey: "root", Mode: "direct", Response: "signature", Signature: sig(good)}, false, signedOK(certWire, direct))
	cert("external_mu", "an external-mu provider receives only mu, derived from the bound ML-DSA-65 key, the registry context, and M", signerProviderJSON{PublicKey: "root", Mode: "external_mu", Response: "signature", Signature: sig(good)}, false, signedOK(certWire, mu))
	cert("key_binding_mismatch", "the provider reports a complete key other than the certificate's issuer key: key_id_mismatch before any signing request", signerProviderJSON{PublicKey: "attacker", Mode: "direct", Response: "signature", Signature: sig(good)}, false, failed("key_id_mismatch", 0, nil))
	cert("ed25519_component_invalid", "the returned Ed25519 component has one bit flipped: verify-before-use rejects it", signerProviderJSON{PublicKey: "root", Mode: "direct", Response: "signature", Signature: flip(good, "ed25519")}, false, failed("invalid_signature", 1, direct))
	cert("ml_dsa_65_component_invalid", "the returned ML-DSA-65 component has one bit flipped: verify-before-use rejects it", signerProviderJSON{PublicKey: "root", Mode: "external_mu", Response: "signature", Signature: flip(good, "ml_dsa_65")}, false, failed("invalid_signature", 1, mu))
	missing := sig(good)
	missing["ml_dsa_65"] = ""
	cert("ml_dsa_65_component_missing", "the provider returns no ML-DSA-65 component", signerProviderJSON{PublicKey: "root", Mode: "direct", Response: "signature", Signature: missing}, false, failed("invalid_signature", 1, direct))
	cert("signature_by_other_key", "the provider reports the issuer key but returns a valid signature over M made with another key", signerProviderJSON{PublicKey: "root", Mode: "direct", Response: "signature", Signature: sig(signDet(attacker, codeDelegation, certSigned.signable))}, false, failed("invalid_signature", 1, direct))
	cert("signature_under_other_code", "the provider returns the issuer's signature over the same signable bytes under code 0x0002", signerProviderJSON{PublicKey: "root", Mode: "direct", Response: "signature", Signature: sig(signDet(root, codePresentation, certSigned.signable))}, false, failed("invalid_signature", 1, direct))
	cert("provider_error", "the provider fails: signing fails and no object is returned", signerProviderJSON{PublicKey: "root", Mode: "direct", Response: "error"}, false, failed("configuration_invalid", 1, direct))
	cert("cancelled_before_call", "the caller cancelled before signing: the provider is never called", signerProviderJSON{PublicKey: "root", Mode: "direct", Response: "signature", Signature: sig(good)}, true, failed("evaluation_cancelled", 0, nil))
	cert("cancelled_during_call", "the caller cancels while the provider is signing; the valid signature that arrives afterwards is discarded", signerProviderJSON{PublicKey: "root", Mode: "direct", Response: "cancel", Signature: sig(good)}, false, failed("evaluation_cancelled", 1, direct))

	// Revocation list: the status key comes from authenticated configuration.
	statusRoot := g.k("status_root")
	_, listWire, listSigned := g.list(statusRoot, root.ID, 7, Now-60, Now+3600, "cert-a", "cert-b")
	binding := &signerBindingJSON{IssuerID: root.ID, StatusKey: "status_root"}
	add(signerCaseJSON{Name: "revocation_list_external_mu", Description: "the configured status key signs a list through an external-mu provider", Kind: "revocation_list", ObjectB64: b64(listWire), Binding: binding,
		Provider: signerProviderJSON{PublicKey: "status_root", Mode: "external_mu", Response: "signature", Signature: sig(listSigned.sig)}, Expected: signedOK(listWire, request("external_mu", statusRoot, codeList, listSigned.signable))})
	add(signerCaseJSON{Name: "revocation_list_key_binding_mismatch", Description: "the provider reports another issuer's status key than the configuration binds to this issuer", Kind: "revocation_list", ObjectB64: b64(listWire), Binding: binding,
		Provider: signerProviderJSON{PublicKey: "status_intermediate", Mode: "direct", Response: "signature", Signature: sig(listSigned.sig)}, Expected: failed("status_key_binding_mismatch", 0, nil)})
	add(signerCaseJSON{Name: "revocation_list_ml_dsa_65_component_invalid", Description: "the returned ML-DSA-65 component has one bit flipped", Kind: "revocation_list", ObjectB64: b64(listWire), Binding: binding,
		Provider: signerProviderJSON{PublicKey: "status_root", Mode: "direct", Response: "signature", Signature: flip(listSigned.sig, "ml_dsa_65")}, Expected: failed("invalid_signature", 1, request("direct", statusRoot, codeList, listSigned.signable))})

	// Proof bundle: the presenting agent signs the challenge presentation.
	_, bundleWire, bundleSigned := g.bundle(bundleSpec{agent: agent, certs: g.chain(chainSpec{}), session: g.fixtureSessionContext(agent)})
	add(signerCaseJSON{Name: "proof_bundle_direct", Description: "the agent signs the challenge presentation (code 0x0002) through a direct-mode provider", Kind: "proof_bundle", ObjectB64: b64(bundleWire),
		Provider: signerProviderJSON{PublicKey: "agent", Mode: "direct", Response: "signature", Signature: sig(bundleSigned.sig)}, Expected: signedOK(bundleWire, request("direct", agent, codePresentation, bundleSigned.signable))})
	add(signerCaseJSON{Name: "proof_bundle_key_binding_mismatch", Description: "the provider reports a key other than the bundle's agent key", Kind: "proof_bundle", ObjectB64: b64(bundleWire),
		Provider: signerProviderJSON{PublicKey: "attacker", Mode: "external_mu", Response: "signature", Signature: sig(bundleSigned.sig)}, Expected: failed("key_id_mismatch", 0, nil)})
	add(signerCaseJSON{Name: "proof_bundle_ed25519_component_invalid", Description: "the returned Ed25519 component has one bit flipped", Kind: "proof_bundle", ObjectB64: b64(bundleWire),
		Provider: signerProviderJSON{PublicKey: "agent", Mode: "external_mu", Response: "signature", Signature: flip(bundleSigned.sig, "ed25519")}, Expected: failed("invalid_signature", 1, request("external_mu", agent, codePresentation, bundleSigned.signable))})
	return f
}
