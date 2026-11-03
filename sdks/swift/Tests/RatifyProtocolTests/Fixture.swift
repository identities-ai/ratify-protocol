import CryptoKit
import Foundation
import RatifyProtocol

/// The keys.json fixture keys, by name, derived through the public API.
final class Fixture: @unchecked Sendable {
    static let shared = Fixture()
    private(set) var publicKeys: [String: HybridPublicKey] = [:]
    private(set) var keyIds: [String: String] = [:]
    private(set) var privateKeys: [String: SoftwarePrivateKey] = [:]

    private init() {
        for k in Corpus.load("keys.json").arr("keys") {
            let key = try! SoftwarePrivateKey(ed25519Seed: k.hex("ed25519_seed_hex"), mlDsa65Seed: k.hex("ml_dsa_65_seed_hex"))
            publicKeys[k.s("name")] = key.publicKey
            keyIds[k.s("name")] = key.keyId
            privateKeys[k.s("name")] = key
        }
    }

    func key(_ name: String) -> HybridPublicKey { publicKeys[name]! }
    func keyId(_ name: String) -> String { keyIds[name]! }
    func privateKey(_ name: String) -> SoftwarePrivateKey { privateKeys[name]! }
}

func publicKey(_ v: [String: Any]) -> HybridPublicKey {
    HybridPublicKey(ed25519: v.b64("ed25519"), mlDsa65: v.b64("ml_dsa_65"))
}
func hybridSignature(_ v: [String: Any]) -> HybridSignature {
    HybridSignature(ed25519: v.b64("ed25519"), mlDsa65: v.b64("ml_dsa_65"))
}
func sha384(_ d: Data) -> Data { Data(SHA384.hash(data: d)) }
func sha256(_ d: Data) -> Data { Data(SHA256.hash(data: d)) }

func witnessHead(_ h: [String: Any]) -> WitnessHead {
    var accepted: [Int64: Data] = [:]
    if let m = h["accepted_digests_b64"] as? [String: String] {
        for (k, v) in m { accepted[Int64(k)!] = Data(base64Encoded: v)! }
    }
    return WitnessHead(logId: h.s("log_id"), sequence: Int64(h.int("sequence")), headHash: h.b64("head_hash_b64"),
                       acceptedDigests: accepted, frozen: h["frozen"] as? Bool ?? false)
}

func receiptHead(_ h: [String: Any]) -> ReceiptHead {
    let w = witnessHead(h)
    return ReceiptHead(logId: w.logId, verifierId: h.s("verifier_id"), sequence: w.sequence, headHash: w.headHash,
                       acceptedDigests: w.acceptedDigests, frozen: w.frozen)
}

func rotationState(_ v: [String: Any]) -> RotationState {
    RotationState(authorityId: v.s("authority_id"), recoveryEpoch: Int64(v.int("recovery_epoch")), role: v.s("role"),
                  sequence: Int64(v.int("sequence")), headHash: v.b64("head_hash_b64"),
                  currentKey: Fixture.shared.key(v.s("current_key")), usedKeyIds: v.strings("used_key_ids"))
}

/// The per-kind decode and verify procedure of the object corpora
/// (sdks/rust/tests/v2_common verify_object).
func verifyObject(_ kind: String, _ wire: Data, bundle: Data = Data(), _ vc: [String: Any]) throws {
    let fx = Fixture.shared
    switch kind {
    case "delegation_certificate": try Ratify.verifyDelegationCertSignature(Ratify.decodeDelegationCert(wire))
    case "proof_bundle": try Ratify.verifyProofBundleSignatures(Ratify.decodeProofBundle(wire))
    case "revocation_list":
        try Ratify.verifyRevocationListSignature(Ratify.decodeRevocationList(wire), trustedIssuerId: vc.s("bound_issuer_id"),
                                                 statusKey: fx.key(vc.s("status_key")))
    case "revocation_push":
        try Ratify.verifyRevocationPushSignature(Ratify.decodeRevocationPush(wire), trustedIssuerId: vc.s("bound_issuer_id"),
                                                 statusKey: fx.key(vc.s("status_key")))
    case "key_rotation_statement":
        try Ratify.verifyKeyRotationStatement(Ratify.decodeKeyRotationStatement(wire), state: rotationState(vc.obj("rotation_state")),
                                              now: Int64(vc.int("now")), futureSkew: Int64(vc.int("future_skew_seconds")))
    case "witness_entry":
        _ = try Ratify.verifyWitnessEntry(Ratify.decodeWitnessEntry(wire), head: witnessHead(vc.obj("head")),
                                          witnessKey: fx.key(vc.s("witness_key")))
    case "transaction_receipt": try Ratify.verifyTransactionReceiptSignatures(Ratify.decodeTransactionReceipt(wire))
    case "verification_receipt":
        _ = try Ratify.verifyVerificationReceipt(Ratify.decodeVerificationReceipt(wire), verifierKey: fx.key(vc.s("verifier_key")),
                                                 head: receiptHead(vc.obj("head")))
    case "receipt_bundle_binding":
        try Ratify.checkVerificationReceiptBundleBinding(Ratify.decodeVerificationReceipt(wire), bundle: Ratify.decodeProofBundle(bundle))
    default: preconditionFailure("unknown kind \(kind)")
    }
}

func reencode(_ kind: String, _ wire: Data) throws -> Data {
    switch kind {
    case "delegation_certificate": return try Ratify.encodeDelegationCert(Ratify.decodeDelegationCert(wire))
    case "proof_bundle": return try Ratify.encodeProofBundle(Ratify.decodeProofBundle(wire))
    case "revocation_list": return try Ratify.encodeRevocationList(Ratify.decodeRevocationList(wire))
    case "revocation_push": return try Ratify.encodeRevocationPush(Ratify.decodeRevocationPush(wire))
    case "key_rotation_statement": return try Ratify.encodeKeyRotationStatement(Ratify.decodeKeyRotationStatement(wire))
    case "witness_entry": return try Ratify.encodeWitnessEntry(Ratify.decodeWitnessEntry(wire))
    case "transaction_receipt": return try Ratify.encodeTransactionReceipt(Ratify.decodeTransactionReceipt(wire))
    case "verification_receipt": return try Ratify.encodeVerificationReceipt(Ratify.decodeVerificationReceipt(wire))
    default: preconditionFailure("unknown kind \(kind)")
    }
}

/// SPEC-v2 §5 projection for a signature field, recomputed here from the
/// wire JSON (independent of the core's projection functions), except the
/// transaction party statement, whose transcript is the SDK's sign bytes.
func projection(_ wire: Data, _ field: String) throws -> Data {
    var obj = try JSONSerialization.jsonObject(with: wire) as! [String: Any]
    func drop(_ fields: [String]) throws -> Data {
        for f in fields { obj.removeValue(forKey: f) }
        return try Ratify.canonicalJSON(try JSONSerialization.data(withJSONObject: obj))
    }
    switch field {
    case "signature": return try drop(["signature"])
    case "challenge_sig": return try drop(["delegations", "challenge_sig"])
    case "old_signature", "new_signature": return try drop(["old_signature", "new_signature"])
    default:
        if field.hasPrefix("delegations[") {
            let idx = Int(field.dropFirst("delegations[".count).prefix { $0.isNumber })!
            let cert = try JSONSerialization.data(withJSONObject: (obj["delegations"] as! [Any])[idx])
            return try projection(cert, "signature")
        }
        if field.hasPrefix("party_signatures[") {
            return try Ratify.transactionReceiptSignBytes(Ratify.decodeTransactionReceipt(wire))
        }
        preconditionFailure("unknown signature field \(field)")
    }
}
