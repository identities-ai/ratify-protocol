import CryptoKit
import Foundation
import RatifyProtocol

/// objects.json, object-negatives.json and hedged-signatures.json through
/// the public API (model: sdks/rust/tests/v2_objects.rs).
enum ObjectsRunner {
    static func sessionInputs(_ b: ProofBundle) throws -> SessionContextInputs {
        let op = OperationContext(requiredScope: "data:read", operation: "records.get",
                                  resourceId: "customer/123", requestedPath: "/v1/customers/123")
        return SessionContextInputs(verifierId: b.verifierId, workspaceId: "00000000-0000-4000-8000-000000000001",
                                    agentId: b.agentId, sessionId: "session-01", invocationId: "invocation-01",
                                    requestHash: try Ratify.operationContextHash(op))
    }

    static func lengthPrefixed(_ b: Data) -> Data {
        var n = UInt64(b.count).bigEndian
        var out = Data(bytes: &n, count: 8)
        out.append(b)
        return out
    }

    /// One fixture digest, recomputed through the public API; nil for
    /// inputs that are not digests themselves.
    static func objectDigest(_ name: String, _ kind: String, _ wire: Data, _ digests: [String: Any]) throws -> String? {
        switch name {
        case "issuer_key_id_v2": return KeysRunner.independentKeyId(try Ratify.decodeDelegationCert(wire).issuerPubKey)
        case "subject_key_id_v2": return KeysRunner.independentKeyId(try Ratify.decodeDelegationCert(wire).subjectPubKey)
        case "delegation_digest_hex": return try Ratify.decodeProofBundle(wire).delegationDigest.hex
        case "bundle_hash_v2": return try Ratify.bundleHash(Ratify.decodeProofBundle(wire))
        case "session_context_hex":
            let b = try Ratify.decodeProofBundle(wire)
            let ctx = try Ratify.buildSessionContext(sessionInputs(b))
            if b.sessionContext != ctx { return "bundle session_context does not match the recomputed fixture context" }
            return ctx.hex
        case "challenge_claim_digest_hex":
            return try Ratify.challengeClaimDigest(Ratify.decodeProofBundle(wire).challenge).hex
        case "claim_id":
            let b = try Ratify.decodeProofBundle(wire)
            return try Ratify.protocolClaimId(namespace: digests.s("claim_verifier_namespace"),
                                              replayEpoch: Int64(digests.s("claim_replay_epoch"))!, challenge: b.challenge)
        case "claim_verifier_namespace", "claim_replay_epoch", "transaction_context_hex":
            return nil
        case "receipt_outbox_body_b64":
            return try Ratify.verificationReceiptBody(Ratify.decodeVerificationReceipt(wire)).base64EncodedString()
        case "status_evidence_digest":
            let d = kind == "revocation_list"
                ? try Ratify.statusEvidenceDigest(Ratify.decodeRevocationList(wire))
                : try Ratify.statusEvidenceDigest(Ratify.decodeRevocationPush(wire))
            return "sha384:\(d.hex)"
        case "statement_body_digest_hex":
            switch kind {
            case "key_rotation_statement": return try Ratify.keyRotationStatementDigest(Ratify.decodeKeyRotationStatement(wire)).hex
            case "witness_entry": return try Ratify.witnessEntryDigest(Ratify.decodeWitnessEntry(wire)).hex
            case "verification_receipt": return try Ratify.verificationReceiptDigest(Ratify.decodeVerificationReceipt(wire)).hex
            default: preconditionFailure("statement digest for \(kind)")
            }
        default:
            guard name.hasPrefix("party-") else { preconditionFailure("unknown digest \(name)") }
            let r = try Ratify.decodeTransactionReceipt(wire)
            let parts = name.split(separator: ".", maxSplits: 1).map(String.init)
            var pre = Data("ratify/transaction-context/v2".utf8)
            pre.append(lengthPrefixed(Data(r.transactionId.utf8)))
            pre.append(lengthPrefixed(Data(r.termsSchemaUri.utf8)))
            pre.append(sha384(r.termsCanonicalJson))
            let tx = sha256(pre)
            let sdkTx = try Ratify.transactionContextHash(r)
            if tx.hex != digests.s("transaction_context_hex") || sdkTx != tx {
                return "transaction context differs"
            }
            let p = r.parties.first { $0.partyId == parts[0] }!
            let req = try Ratify.transactionPartyRequestHash(tx, requiredScope: p.requiredScope)
            switch parts[1] {
            case "transaction_party_request_hash_hex": return req.hex
            case "session_context_hex":
                return try Ratify.buildSessionContext(SessionContextInputs(
                    verifierId: p.verifierId, workspaceId: p.workspaceId, agentId: p.agentId,
                    sessionId: p.sessionId, invocationId: p.invocationId, requestHash: req)).hex
            case "proof_bundle_hash": return try Ratify.bundleHash(p.proofBundle!)
            default: preconditionFailure("unknown party digest \(parts[1])")
            }
        }
    }

    static func objects() throws {
        let fx = Fixture.shared
        let f = Corpus.load("objects.json")
        let t = Tally("objects.json")
        var codes = Set<UInt16>()
        let objects = f.arr("objects")
        var nSignatures = 0
        for o in objects {
            let name = o.s("name"), kind = o.s("kind")
            let wire = o.b64("wire_b64")
            let re = Result { try reencode(kind, wire) }
            t.check("re-encode", name, (try? re.get()) == wire, "\(re)")
            let v = classOf { try verifyObject(kind, wire, o.obj("verify")) }
            t.check("verify", name, v == "ok", v)
            for sig in o.arr("signatures") {
                nSignatures += 1
                let field = sig.s("field")
                let code = UInt16(sig.int("object_type_code"))
                codes.insert(code)
                let ty = ObjectType(rawValue: code)!
                let signable = sig.b64("signable_b64")
                let m = try Ratify.signingMessage(ty, signable: signable)
                let ctx = try Ratify.mldsaContext(ty)
                let signer = sig.s("signer")
                let key = fx.key(signer)
                let pinned = hybridSignature(sig.obj("signature"))
                let wireText = String(data: wire, encoding: .utf8)!
                let verified = classOf { try Ratify.verifyStatement(ty, signable: signable, signature: pinned, publicKey: key) }
                let projected = try projection(wire, field)
                let mu = try Ratify.externalMu(mlDsaPublicKey: key.mlDsa65, mlDsaContext: ctx, message: m)
                let ok = projected == signable
                    && sha384(signable).hex == sig.s("signable_sha384_hex")
                    && m == sig.b64("message_b64") && m.count == 77
                    && String(data: ctx, encoding: .utf8) == sig.s("mldsa_context") && ctx.count == 22
                    && fx.keyId(signer) == sig.s("signer_key_id_v2")
                    && Shake256.hash(key.mlDsa65, outputLength: 64) == sig.b64("mldsa_tr_b64")
                    && mu == sig.b64("mldsa_mu_b64")
                    && wireText.contains(pinned.ed25519.base64EncodedString())
                    && wireText.contains(pinned.mlDsa65.base64EncodedString())
                    && verified == "ok"
                t.check("signatures", "\(name)/\(field)", ok, "projection, transcript, or verification differs: \(verified)")
            }
            var nDigests = 0
            if let ds = o["digests"] as? [String: Any] {
                for (dname, want) in ds {
                    if let got = try objectDigest(dname, kind, wire, ds) {
                        nDigests += 1
                        t.check("digests", "\(name)/\(dname)", got == want as! String, "got \(got), want \(want)")
                    }
                }
            }
            _ = nDigests
        }
        for code in UInt16(1)...9 {
            t.check("codes", "code \(code)", codes.contains(code), "no signature for code")
        }
        let expectedDigests = objects.reduce(0) { n, o in
            n + ((o["digests"] as? [String: Any])?.keys.filter {
                !["claim_verifier_namespace", "claim_replay_epoch", "transaction_context_hex"].contains($0)
            }.count ?? 0)
        }
        t.finish([("re-encode", objects.count), ("verify", objects.count), ("signatures", nSignatures),
                  ("codes", 9), ("digests", expectedDigests)])
        precondition(objects.count == 13 && nSignatures == 19, "objects.json shape changed")
    }

    static func negatives() throws {
        let f = Corpus.load("object-negatives.json")
        let t = Tally("object-negatives.json")
        var kinds = Set<String>()
        let vectors = f.arr("vectors")
        for v in vectors {
            let kind = v.s("kind")
            kinds.insert(kind)
            let bundle = v["bundle_b64"] == nil ? Data() : v.b64("bundle_b64")
            let want = v.s("expected_error_class")
            precondition(ErrorClass(rawValue: want) != nil, "corpus class \(want) is outside SPEC-v2 §2.7")
            let got = classOf { try verifyObject(kind, v.b64("wire_b64"), bundle: bundle, v.obj("verify")) }
            t.check("negatives", v.s("name"), got == want, "class \(got), want \(want) (\(v.s("mutation")))")
        }
        precondition(kinds.count == 9, "negative kinds: \(kinds)")
        t.finish([("negatives", vectors.count)])
    }

    static func hedgedIdempotency(_ kind: String, _ vc: [String: Any], _ deterministic: Data, _ hedged: Data) throws -> Bool {
        let fx = Fixture.shared
        switch kind {
        case "witness_entry":
            let first = try Ratify.decodeWitnessEntry(deterministic)
            let again = try Ratify.decodeWitnessEntry(hedged)
            let digest = try Ratify.witnessEntryDigest(first)
            guard try Ratify.witnessEntryDigest(again) == digest else { return false }
            var head = witnessHead(vc.obj("head"))
            head.sequence = first.sequence
            head.headHash = digest
            head.acceptedDigests = [first.sequence: digest]
            return try Ratify.verifyWitnessEntry(again, head: head, witnessKey: fx.key(vc.s("witness_key"))) == .replay
        case "verification_receipt":
            let first = try Ratify.decodeVerificationReceipt(deterministic)
            let again = try Ratify.decodeVerificationReceipt(hedged)
            let digest = try Ratify.verificationReceiptDigest(first)
            guard try Ratify.verificationReceiptDigest(again) == digest else { return false }
            var head = receiptHead(vc.obj("head"))
            head.sequence = first.sequence
            head.headHash = digest
            head.acceptedDigests = [first.sequence: digest]
            return try Ratify.verifyVerificationReceipt(again, verifierKey: fx.key(vc.s("verifier_key")), head: head) == .replay
        case "key_rotation_statement":
            return try Ratify.keyRotationStatementDigest(Ratify.decodeKeyRotationStatement(deterministic))
                == Ratify.keyRotationStatementDigest(Ratify.decodeKeyRotationStatement(hedged))
        default:
            return true
        }
    }

    static func hedged() throws {
        let f = Corpus.load("hedged-signatures.json")
        let t = Tally("hedged-signatures.json")
        var kinds = Set<String>()
        var n = 0
        for o in f.arr("objects") {
            let name = o.s("name"), kind = o.s("kind")
            kinds.insert(kind)
            let deterministic = o.b64("deterministic_wire_b64")
            let fields = o.strings("resigned_fields")
            precondition(!fields.isEmpty)
            var seen = [deterministic]
            for (i, encoded) in (o["hedged_wire_b64"] as! [String]).enumerated() {
                n += 1
                let wire = Data(base64Encoded: encoded)!
                let fresh = !seen.contains(wire)
                seen.append(wire)
                let re = try? reencode(kind, wire)
                let v = classOf { try verifyObject(kind, wire, o.obj("verify")) }
                let sameProjection = try fields.allSatisfy { try projection(wire, $0) == projection(deterministic, $0) }
                let idem = (try? hedgedIdempotency(kind, o.obj("verify"), deterministic, wire)) ?? false
                t.check("hedged", "\(name)#\(i)", fresh && re == wire && v == "ok" && sameProjection && idem,
                        "fresh=\(fresh) verify=\(v) projection=\(sameProjection) idempotency=\(idem)")
            }
        }
        precondition(kinds.count == 8, "hedged kinds: \(kinds)")
        t.finish([("hedged", n)])
    }
}
