import CryptoKit
import Foundation
import XCTest
import RatifyProtocol

/// keys.json through the public API. Key IDs are also recomputed here with
/// CryptoKit from the documented preimage, independent of the core.
final class KeysTests: XCTestCase {
    func independentKeyId(_ k: HybridPublicKey) -> String {
        var pre = Data("ratify-key-id-v2".utf8)
        pre.append(0)
        pre.append(k.ed25519)
        pre.append(k.mlDsa65)
        return Data(SHA256.hash(data: pre)).hex
    }

    func testKeysCorpus() throws {
        let f = Corpus.load("keys.json")
        XCTAssertEqual(f.s("key_id_preimage"), "ratify-key-id-v2 || 0x00 || ed25519(32) || ml_dsa_65(1952)")
        let t = Tally()
        let keys = f.arr("keys")
        for k in keys {
            let name = k.s("name")
            let pk = k.obj("public_key")
            let pinned = HybridPublicKey(ed25519: pk.b64("ed25519"), mlDsa65: pk.b64("ml_dsa_65"))
            let id = k.s("key_id_v2")
            let v1 = k.s("v1_key_id_128")
            let derived = try SoftwarePrivateKey(ed25519Seed: k.hex("ed25519_seed_hex"),
                                                 mlDsa65Seed: k.hex("ml_dsa_65_seed_hex"))
            let ok = derived.publicKey == pinned
                && derived.keyId == id
                && (try? Ratify.keyId(pinned)) == id
                && independentKeyId(pinned) == id
                && Ratify.validId(id)
                && !Ratify.validId(v1)
                && v1 != String(id.prefix(32))
            t.check("keys", name, ok, "seeds, key ID, or v1 ID differ")
        }
        let objects = Corpus.load("objects.json")
        let bundle = objectByKind(objects, "proof_bundle").b64("wire_b64")
        let witness = objectByKind(objects, "witness_entry").b64("wire_b64")
        let bad = f.arr("invalid_v2_key_ids")
        for b in bad {
            let value = b.s("value")
            let want = b.s("expected_error_class")
            let asVerifier = classOf { _ = try Ratify.decodeProofBundle(setTopLevelString(bundle, "verifier_id", value)) }
            let asWitness = classOf { _ = try Ratify.decodeWitnessEntry(setTopLevelString(witness, "witness_id", value)) }
            t.check("invalid_v2_key_ids", b.s("name"), asVerifier == want && asWitness == want,
                    "classes \(asVerifier)/\(asWitness), want \(want)")
            t.check("invalid_v2_key_ids format", b.s("name"), !Ratify.validId(value), "accepted")
        }
        t.finish([("keys", keys.count), ("invalid_v2_key_ids", bad.count), ("invalid_v2_key_ids format", bad.count)])
    }

    func testGenerateIsFreshAndConsistent() throws {
        let a = try SoftwarePrivateKey.generate()
        let b = try SoftwarePrivateKey.generate()
        XCTAssertNotEqual(a.keyId, b.keyId)
        XCTAssertEqual(try Ratify.keyId(a.publicKey), a.keyId)
        XCTAssertEqual(a.publicKey.ed25519.count, 32)
        XCTAssertEqual(a.publicKey.mlDsa65.count, 1952)
    }

    func testBadSeedLengthIsMalformed() {
        XCTAssertEqual(classOf { _ = try SoftwarePrivateKey(ed25519Seed: Data(count: 31), mlDsa65Seed: Data(count: 32)) },
                       "malformed")
    }

    func testErrorClassesPinnedToCore() {
        XCTAssertEqual(ErrorClass.allCases.map(\.rawValue), Ratify.errorClassSpellings)
    }
}
