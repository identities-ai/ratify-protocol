import Foundation
import RatifyProtocol

/// archival.json and digest-functions.json through the public API
/// (model: sdks/rust/tests/v2_archival_signer.rs).
enum ArchivalRunner {
    static func json(_ r: ArchivalVerification) -> [String: Any] {
        ["object_type_code": Int(r.objectType), "freshness": r.freshness, "actionable": r.actionable,
         "digest": r.digest, "signer_key_ids": r.signerKeyIds]
    }

    static func equalJSON(_ a: Any, _ b: Any) -> Bool {
        NSDictionary(dictionary: ["v": a]).isEqual(to: ["v": b])
    }

    static func archival() throws {
        let fx = Fixture.shared
        let f = Corpus.load("archival.json")
        let t = Tally("archival.json")
        var kinds = Set<String>()
        let cases = f.arr("cases")
        for c in cases {
            let name = c.s("name"), kind = c.s("kind")
            kinds.insert(kind)
            let wire = c.b64("wire_b64")
            let v = c["verify"] as? [String: Any] ?? [:]
            let got = Result { () throws(RatifyError) -> Any in
                switch kind {
                case "proof_bundle":
                    let bytes = try Ratify.verifyArchivalProofBundle(wire).json()
                    return try! JSONSerialization.jsonObject(with: bytes)
                case "delegation_certificate": return json(try Ratify.verifyArchivalDelegationCert(wire))
                case "revocation_list":
                    return json(try Ratify.verifyArchivalRevocationList(wire, issuerId: v.s("issuer_id"), statusKey: fx.key(v.s("status_key"))))
                case "revocation_push":
                    return json(try Ratify.verifyArchivalRevocationPush(wire, issuerId: v.s("issuer_id"), statusKey: fx.key(v.s("status_key"))))
                case "key_rotation_statement": return json(try Ratify.verifyArchivalKeyRotationStatement(wire))
                case "witness_entry": return json(try Ratify.verifyArchivalWitnessEntry(wire, witnessKey: fx.key(v.s("witness_key"))))
                case "verification_receipt":
                    return json(try Ratify.verifyArchivalVerificationReceipt(wire, verifierKey: fx.key(v.s("verifier_key"))))
                case "transaction_receipt": return json(try Ratify.verifyArchivalTransactionReceipt(wire))
                default: preconditionFailure("\(name): unknown kind \(kind)")
                }
            }
            let wantClass = c["expected_error_class"] as? String ?? ""
            if !wantClass.isEmpty {
                var gotClass = "ok"
                if case let .failure(e) = got { gotClass = e.errorClass?.rawValue ?? "internal" }
                t.check("archival", name, gotClass == wantClass, "class \(gotClass), want \(wantClass)")
            } else {
                var ok = false
                if case let .success(r) = got { ok = equalJSON(r, c["expected"]!) }
                t.check("archival", name, ok, "result \(got), want \(c["expected"]!)")
            }
        }
        for k in ["proof_bundle", "delegation_certificate", "revocation_list", "revocation_push",
                  "key_rotation_statement", "witness_entry", "verification_receipt", "transaction_receipt"] {
            precondition(kinds.contains(k), "no archival case for \(k)")
        }
        precondition(cases.count == 19, "archival cases")
        t.finish([("archival", cases.count)])
    }

    static func digestFunctions() throws {
        let f = Corpus.load("digest-functions.json")
        let t = Tally("digest-functions.json")
        let cases = f.arr("cases")
        for c in cases {
            let name = c.s("name")
            let input = c.b64("input_b64")
            let wantClass = c["expected_error_class"] as? String ?? ""
            guard let code = UInt16(exactly: c.int("object_type_code")) else {
                // The code parameter is 16 bits: such a code cannot be passed,
                // and must never be truncated to one that can.
                t.check("digest-functions", name, wantClass == "unsupported_object_type", "code outside 16 bits")
                continue
            }
            let digest = Result { () throws(RatifyError) -> Data in
                switch c.s("function") {
                case "statement_body_digest": return try Ratify.statementBodyDigest(objectTypeCode: code, signableBody: input)
                case "status_evidence_digest":
                    return try Ratify.statusEvidenceDigest(objectTypeCode: code, .list(try Ratify.decodeRevocationList(input)))
                default: preconditionFailure("\(name): unknown function")
                }
            }
            if !wantClass.isEmpty {
                var got = "ok"
                if case let .failure(e) = digest { got = e.errorClass?.rawValue ?? "internal" }
                t.check("digest-functions", name, got == wantClass, "class \(got), want \(wantClass)")
            } else {
                var ok = false
                if case let .success(d) = digest { ok = "sha384:\(d.hex)" == c.s("expected_digest") }
                t.check("digest-functions", name, ok, "\(digest)")
            }
        }
        precondition(cases.count == 25, "digest function cases")
        t.finish([("digest-functions", cases.count)])
    }
}
