import Foundation
import RatifyProtocol

/// provider-evidence/: every device evidence record present, through the
/// public API. Each record's key must issue its certificate, prove
/// possession in its rotation, and sign its revocation list.
enum ProviderEvidenceRunner {
    static func run() throws {
        let dir = Corpus.dir.appendingPathComponent("provider-evidence")
        let files = try FileManager.default.contentsOfDirectory(atPath: dir.path).filter { $0.hasSuffix(".json") }.sorted()
        precondition(!files.isEmpty, "provider-evidence/ has no records")
        let t = Tally("provider-evidence")
        for file in files {
            let r = try JSONSerialization.jsonObject(with: Data(contentsOf: dir.appendingPathComponent(file))) as! [String: Any]
            t.check("records", "\(file) name", file == "\(r.s("platform"))-\(r.s("provider")).json" && r.int("version") == 1)
            let key = publicKey(r.obj("public_key"))
            let id = r.s("key_id_v2")
            let derived = try Ratify.keyId(key)
            t.check("records", "\(file) key ID", derived == id)
            for o in r.arr("objects") {
                let wire = o.b64("wire_b64")
                let name = "\(file) \(o.s("kind"))"
                switch o.s("kind") {
                case "delegation_certificate":
                    let c = try Ratify.decodeDelegationCert(wire)
                    let re = try Ratify.encodeDelegationCert(c)
                    t.check("objects", name, classOf { try Ratify.verifyDelegationCertSignature(c) } == "ok"
                                && c.issuerPubKey == key && c.issuerId == id && re == wire)
                    var bad = c
                    bad.signature.mlDsa65[0] ^= 1
                    t.check("negatives", name, classOf { try Ratify.verifyDelegationCertSignature(bad) } == "invalid_signature")
                case "key_rotation_statement":
                    let s = try Ratify.decodeKeyRotationStatement(wire)
                    let signable = try Ratify.keyRotationStatementSignableBytes(s)
                    let old = classOf { try Ratify.verifyStatement(.keyRotationAuthorization, signable: signable, signature: s.oldSignature, publicKey: s.oldKey) }
                    let new = classOf { try Ratify.verifyStatement(.keyRotationProofOfPossession, signable: signable, signature: s.newSignature, publicKey: s.newKey) }
                    let re = try Ratify.encodeKeyRotationStatement(s)
                    t.check("objects", name, old == "ok" && new == "ok" && s.newKey == key && re == wire)
                case "revocation_list":
                    let l = try Ratify.decodeRevocationList(wire)
                    let re = try Ratify.encodeRevocationList(l)
                    t.check("objects", name, classOf { try Ratify.verifyRevocationListSignature(l, trustedIssuerId: id, statusKey: key) } == "ok"
                                && re == wire)
                default:
                    preconditionFailure("\(name): unknown kind")
                }
            }
        }
        t.finish([("records", 2 * files.count), ("objects", 3 * files.count), ("negatives", files.count)])
    }
}
