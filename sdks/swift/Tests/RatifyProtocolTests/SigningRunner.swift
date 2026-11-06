import Foundation
import RatifyProtocol

/// delegation-signature.json, derive-external-mu.py, key-rotation-signature.json,
/// issuer-duties.json and external-signer.json through the public API
/// (models: sdks/c/tests/v2c_objects.rs, sdks/rust/tests/v2_logs.rs,
/// v2_issuance_profiles.rs, v2_archival_signer.rs).
enum SigningRunner {
    static func delegationSignature() throws {
        let v = Corpus.load("delegation-signature.json")
        let t = Tally("delegation-signature.json")
        precondition(v.int("object_type_code") == 1)
        let signable = v.b64("signable_bytes")
        t.check("transcript", "message", try Ratify.signingMessage(.delegationCertificate, signable: signable) == v.b64("message"))
        let ctx = try Ratify.mldsaContext(.delegationCertificate)
        t.check("transcript", "context", ctx == v.b64("mldsa_context") && ctx != v.b64("alternate_mldsa_context"))
        let key = publicKey(v.obj("issuer_public_key"))
        t.check("keys", "key id", try Ratify.keyId(key) == v.s("key_id_v2"))
        let seeds = v.obj("issuer_seeds")
        let derived = try SoftwarePrivateKey(ed25519Seed: seeds.b64("ed25519"), mlDsa65Seed: seeds.b64("ml_dsa_65"))
        t.check("keys", "seeds", derived.publicKey == key)
        let sig = hybridSignature(v.obj("signature"))
        t.check("verify", "pinned", classOf { try Ratify.verifyStatement(.delegationCertificate, signable: signable, signature: sig, publicKey: key) } == "ok")
        // The same signature under another registered code is a different transcript.
        t.check("verify", "other code", classOf { try Ratify.verifyStatement(.challengePresentation, signable: signable, signature: sig, publicKey: key) } == "invalid_signature")
        let neg = v.obj("negative_mutations")
        let mask = UInt8(neg.int("xor_mask"))
        for target in neg.strings("targets") {
            var sb = signable, s = sig, k = key
            switch target {
            case "signable_bytes": sb[0] ^= mask
            case "signature.ed25519": s.ed25519[0] ^= mask
            case "signature.ml_dsa_65": s.mlDsa65[0] ^= mask
            case "issuer_public_key.ed25519": k.ed25519[0] ^= mask
            case "issuer_public_key.ml_dsa_65": k.mlDsa65[0] ^= mask
            default: preconditionFailure("unknown mutation target \(target)")
            }
            t.check("mutations", target, classOf { try Ratify.verifyStatement(.delegationCertificate, signable: sb, signature: s, publicKey: k) } != "ok")
        }
        // Truncated key components never derive a key ID.
        var short = key
        short.ed25519.removeLast()
        t.check("keys", "short ed25519", classOf { _ = try Ratify.keyId(short) } == "malformed")
        short = key
        short.mlDsa65.removeLast()
        t.check("keys", "short ml-dsa", classOf { _ = try Ratify.keyId(short) } == "malformed")
        t.finish([("transcript", 2), ("keys", 4), ("verify", 2), ("mutations", neg.strings("targets").count)])
    }

    /// The derivation in derive-external-mu.py: tr and mu of the shared
    /// vector, computed independently and through the SDK.
    static func deriveExternalMu() throws {
        let v = Corpus.load("delegation-signature.json")
        let t = Tally("derive-external-mu.py")
        let key = publicKey(v.obj("issuer_public_key"))
        let ctx = v.b64("mldsa_context"), m = v.b64("message")
        precondition(ctx.count == 22 && m.count == 77)
        let tr = Shake256.hash(key.mlDsa65, outputLength: 64)
        t.check("mu", "tr", tr == v.b64("mldsa_tr"))
        var input = tr
        input.append(contentsOf: [0, UInt8(ctx.count)])
        input.append(ctx)
        input.append(m)
        t.check("mu", "independent", Shake256.hash(input, outputLength: 64) == v.b64("mldsa_mu"))
        t.check("mu", "sdk", try Ratify.externalMu(mlDsaPublicKey: key.mlDsa65, mlDsaContext: ctx, message: m) == v.b64("mldsa_mu"))
        let src = try String(contentsOf: Corpus.url("derive-external-mu.py"), encoding: .utf8)
        t.check("mu", "script names the vector", src.contains("delegation-signature.json"))
        t.finish([("mu", 4)])
    }

    static func keyRotationSignature() throws {
        let v = Corpus.load("key-rotation-signature.json")
        let t = Tally("key-rotation-signature.json")
        var cases = [v]
        if let c = v["continuation"] as? [String: Any] { cases.append(c) }
        let row = "key-rotation-signature.json"
        for (n, c) in cases.enumerated() {
            let oldSeeds = c.obj("old_key_seeds"), newSeeds = c.obj("new_key_seeds")
            let old = try SoftwarePrivateKey(ed25519Seed: oldSeeds.hex("ed25519"), mlDsa65Seed: oldSeeds.hex("ml_dsa_65"))
            let new = try SoftwarePrivateKey(ed25519Seed: newSeeds.hex("ed25519"), mlDsa65Seed: newSeeds.hex("ml_dsa_65"))
            t.check(row, "case \(n) keys", old.publicKey == publicKey(c.obj("old_key")) && new.publicKey == publicKey(c.obj("new_key")))
            let stmt = KeyRotationStatement(
                version: Int64(c.int("version")), authorityId: c.s("authority_id"), recoveryEpoch: Int64(c.int("recovery_epoch")),
                role: c.s("role"), sequence: Int64(c.int("sequence")), previousStatementHash: c.b64("previous_statement_hash"),
                oldKey: old.publicKey, newKey: new.publicKey, oldKeyId: c.s("old_key_id"), newKeyId: c.s("new_key_id"),
                issuedAt: Int64(c.int("issued_at")), notBefore: Int64(c.int("not_before")),
                oldSignature: hybridSignature(c.obj("old_signature")), newSignature: hybridSignature(c.obj("new_signature")))
            let signable = try Ratify.keyRotationStatementSignableBytes(stmt)
            t.check(row, "case \(n) signable", signable == c.b64("signable_bytes"))
            t.check(row, "case \(n) digest", try Ratify.keyRotationStatementDigest(stmt).hex == c.s("statement_body_digest"))
            t.check(row, "case \(n) contexts",
                    try Ratify.mldsaContext(.keyRotationAuthorization) == Data(c.s("old_mldsa_context").utf8)
                        && Ratify.mldsaContext(.keyRotationProofOfPossession) == Data(c.s("new_mldsa_context").utf8))
            func bothVerify(_ s: KeyRotationStatement) -> Bool {
                classOf { try Ratify.verifyStatement(.keyRotationAuthorization, signable: signable, signature: s.oldSignature, publicKey: old.publicKey) } == "ok"
                    && classOf { try Ratify.verifyStatement(.keyRotationProofOfPossession, signable: signable, signature: s.newSignature, publicKey: new.publicKey) } == "ok"
            }
            t.check(row, "case \(n) signatures", bothVerify(stmt))
            let wire = try Ratify.encodeKeyRotationStatement(stmt)
            t.check(row, "case \(n) wire", wire == c.b64("wire"))
            t.check(row, "case \(n) decode", classOf { _ = try Ratify.decodeKeyRotationStatement(wire) } == "ok")
            // Fresh signatures from the SDK verify too (hedged ML-DSA).
            let resigned = try Ratify.signKeyRotationStatement(stmt, oldKey: old, newKey: new)
            t.check(row, "case \(n) resign", bothVerify(resigned))
        }
        t.finish([(row, 8 * cases.count)])
        precondition(cases.count == 2)
    }

    static func issuerDuties() async throws {
        let f = Corpus.load("issuer-duties.json")
        let t = Tally("issuer-duties.json")
        let vectors = f.arr("vectors")
        for v in vectors {
            let name = v.s("name")
            let cert = try Ratify.decodeDelegationCert(v.b64("unsigned_certificate_b64"))
            let signer = ProviderSigner(v.s("issuer"))
            var ok: Bool
            var detail = ""
            do {
                let signed = try await Ratify.signDelegationCert(cert, signer: signer)
                ok = v.s("expected") == "sign" && classOf { try Ratify.verifyDelegationCertSignature(signed) } == "ok"
                detail = "signed"
            } catch {
                // V2SignError::class: an issuer-duty refusal is always `malformed`.
                if case .signing(.malformed, .issuerDuty, _) = error { ok = v.s("expected") == "reject" && signer.calls == 0 } else { ok = false }
                detail = "\(error), \(signer.calls) signer calls"
            }
            t.check("issuer-duties", name, ok, detail)
        }
        t.finish([("issuer-duties", vectors.count)])
    }

    /// A provider scripted by external-signer.json: it records every request
    /// and returns a signature, fails, or cancels its caller.
    final class ScriptedSigner: ExternalSigner, @unchecked Sendable {
        let publicKey: HybridPublicKey
        let mode: SignerMode
        let response: String
        let signature: HybridSignature
        private let lock = NSLock()
        private var reqs: [SignRequest] = []
        var cancelCaller: (@Sendable () -> Void)?

        init(publicKey: HybridPublicKey, mode: SignerMode, response: String, signature: HybridSignature) {
            self.publicKey = publicKey
            self.mode = mode
            self.response = response
            self.signature = signature
        }
        var requests: [SignRequest] { lock.lock(); defer { lock.unlock() }; return reqs }

        func sign(_ request: SignRequest) async throws -> HybridSignature {
            lock.withLock { reqs.append(request) }
            switch response {
            case "error": throw ProviderError.scripted
            case "cancel": cancelCaller?()
            default: break
            }
            return signature
        }
    }

    static func externalSigner() async throws {
        let fx = Fixture.shared
        let f = Corpus.load("external-signer.json")
        let t = Tally("external-signer.json")
        let cases = f.arr("cases")
        for c in cases {
            let name = c.s("name")
            let p = c.obj("provider")
            let sig = (p["signature"] as? [String: Any]).map(hybridSignature) ?? HybridSignature(ed25519: Data(), mlDsa65: Data())
            let signer = ScriptedSigner(publicKey: fx.key(p.s("public_key")), mode: p.s("mode") == "direct" ? .direct : .externalMu,
                                        response: p.s("response"), signature: sig)
            let wire = c.b64("object_b64")
            let kind = c.s("kind")
            let precancel = c["caller_cancelled"] as? Bool ?? false
            let binding = c["binding"] as? [String: Any]
            let boundIssuer = binding?.s("issuer_id") ?? ""
            let boundKey = binding.map { fx.key($0.s("status_key")) }
            let task = Task { @Sendable () async throws(RatifyError) -> Data in
                switch kind {
                case "delegation_certificate":
                    return try Ratify.encodeDelegationCert(try await Ratify.signDelegationCert(try Ratify.decodeDelegationCert(wire), signer: signer))
                case "revocation_list":
                    let list = try Ratify.decodeRevocationList(wire)
                    return try Ratify.encodeRevocationList(try await Ratify.signRevocationList(
                        list, boundIssuerId: boundIssuer, boundStatusKey: boundKey!, signer: signer))
                case "proof_bundle":
                    return try Ratify.encodeProofBundle(try await Ratify.signProofBundle(try Ratify.decodeProofBundle(wire), signer: signer))
                default: preconditionFailure("unknown kind \(kind)")
                }
            }
            signer.cancelCaller = { task.cancel() }
            if precancel { task.cancel() }
            let signed = await task.result
            let e = c.obj("expected")
            let reqs = signer.requests
            var ok = reqs.count == e.int("provider_calls")
            var detail = "provider calls \(reqs.count), want \(e.int("provider_calls"))"
            if ok, let want = e["request"] as? [String: Any] {
                let r = reqs[0]
                let mode = r.mode == .direct ? "direct" : "external_mu"
                ok = mode == want.s("mode") && r.message == want.b64("message_b64")
                    && r.mlDsaContext == (want["mldsa_context"] as? String).map { Data($0.utf8) }
                    && r.mlDsaMu == (want["mldsa_mu_b64"] as? String).map { Data(base64Encoded: $0)! }
                    && r.keyId == want.s("key_id_v2") && r.publicKey == signer.publicKey
                detail = "provider request differs"
            }
            if ok {
                switch (e.s("result"), signed) {
                case ("signed", .success(let bytes)): ok = bytes == e.b64("signed_wire_b64"); detail = "signed object differs"
                case ("signed", .failure(let err)): ok = false; detail = "\(err)"
                case (_, .failure(let err)): ok = (err as? RatifyError)?.errorClass?.rawValue == e.s("error_class"); detail = "\(err), want \(e.s("error_class"))"
                case (_, .success): ok = false; detail = "signed, want class \(e.s("error_class"))"
                }
            }
            t.check("external-signer", name, ok, detail)
        }
        t.finish([("external-signer", cases.count)])
        precondition(cases.count == 17, "external signer cases")
    }
}
