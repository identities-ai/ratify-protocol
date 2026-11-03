import CryptoKit
import Foundation
import Security
import XCTest
@testable import RatifyProtocol

/// The Secure Enclave key (build plan §4.2), on real hardware where the
/// platform has a Secure Enclave (an Apple-silicon Mac on macOS 26+; an
/// iPhone in the device evidence run). Where it has none, the documented
/// refusal is asserted instead: nothing is skipped.
final class SecureEnclaveTests: XCTestCase {
    /// No biometry in tests: the key is usable whenever the device is unlocked.
    static func testAccess() -> SecAccessControl {
        SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], nil)!
    }

    /// A certificate whose issuer is `issuer`, from the fixture certificate.
    static func cert(issuedBy issuer: HybridPublicKey, keyId: String) throws -> DelegationCert {
        var c = try Ratify.decodeDelegationCert(objectByKind(Corpus.load("objects.json"), "delegation_certificate").b64("wire_b64"))
        c.issuerPubKey = issuer
        c.issuerId = keyId
        return c
    }

    func testRefusedWithoutASecureEnclave() throws {
        guard #available(iOS 26, macOS 26, *) else { return }
        if SecureEnclave.isAvailable { return } // the hardware tests below run instead
        XCTAssertEqual(classOf { _ = try SecureEnclaveKey.generate(accessControl: Self.testAccess()) }, "configuration_invalid")
    }

    func testSignsVerifiesAndReloads() async throws {
        guard #available(iOS 26, macOS 26, *), SecureEnclave.isAvailable else { return }
        let key = try SecureEnclaveKey.generate(accessControl: Self.testAccess())
        XCTAssertEqual(key.custody.mlDsa65, .secureEnclave)
        let signed = try await Ratify.signDelegationCert(try Self.cert(issuedBy: key.publicKey, keyId: key.keyId), with: .platform(PlatformKey(key)))
        XCTAssertNoThrow(try Ratify.verifyDelegationCertSignature(signed), "the core verifies both components")
        // Independently: CryptoKit verifies the ML-DSA-65 component over M with the SDK context.
        let signable = try Ratify.delegationCertSignableBytes(signed)
        let m = try Ratify.signingMessage(.delegationCertificate, signable: signable)
        let ctx = try Ratify.mldsaContext(.delegationCertificate)
        let pk = try MLDSA65.PublicKey(rawRepresentation: key.publicKey.mlDsa65)
        XCTAssertTrue(pk.isValidSignature(signed.signature.mlDsa65, for: m, context: ctx))
        XCTAssertTrue(try Curve25519.Signing.PublicKey(rawRepresentation: key.publicKey.ed25519).isValidSignature(signed.signature.ed25519, for: m))
        // The storage record reloads the same hardware key.
        let reloaded = try SecureEnclaveKey(storageRecord: try key.storageRecord())
        XCTAssertEqual(reloaded.keyId, key.keyId)
        let again = try await Ratify.signDelegationCert(try Self.cert(issuedBy: reloaded.publicKey, keyId: reloaded.keyId), with: .platform(PlatformKey(reloaded)))
        XCTAssertNoThrow(try Ratify.verifyDelegationCertSignature(again))
        #if os(macOS)
        // Through the Keychain store. An iOS package test bundle has no host
        // app and so no Keychain entitlement; iOS Keychain runs in the host-app
        // suite (build plan M5) and the device evidence run.
        let store = KeychainKeyStore()
        defer { try? store.delete(keyId: key.keyId) }
        try store.save(key)
        XCTAssertEqual(try store.loadSecureEnclaveKey(keyId: key.keyId)?.keyId, key.keyId)
        #endif
        // A record whose stored ML-DSA public key differs is refused.
        var record = try key.storageRecord()
        record[8 + 64 + 1 + 3 + 32 + 3] ^= 1
        XCTAssertEqual(classOf { _ = try SecureEnclaveKey(storageRecord: record) }, "key_id_mismatch")
    }

    /// Every bad component a platform signer could return is refused.
    @available(iOS 26, macOS 26, *)
    final class Tamper: ExternalSigner, @unchecked Sendable {
        let key: SecureEnclaveKey
        let mutate: (SignRequest, SecureEnclaveKey) throws -> HybridSignature
        init(_ key: SecureEnclaveKey, _ mutate: @escaping (SignRequest, SecureEnclaveKey) throws -> HybridSignature) {
            self.key = key
            self.mutate = mutate
        }
        var publicKey: HybridPublicKey { key.publicKey }
        var mode: SignerMode { .direct }
        func sign(_ request: SignRequest) async throws -> HybridSignature { try mutate(request, key) }
    }

    func testBadComponentsAreRefused() async throws {
        guard #available(iOS 26, macOS 26, *), SecureEnclave.isAvailable else { return }
        let key = try SecureEnclaveKey.generate(accessControl: Self.testAccess())
        let other = try SecureEnclaveKey.generate(accessControl: Self.testAccess())
        let cert = try Self.cert(issuedBy: key.publicKey, keyId: key.keyId)
        let cases: [(String, (SignRequest, SecureEnclaveKey) throws -> HybridSignature)] = [
            ("missing ML-DSA", { r, k in var s = try k.sign(r); s.mlDsa65 = Data(); return s }),
            ("malformed ML-DSA", { r, k in var s = try k.sign(r); s.mlDsa65.removeLast(); return s }),
            ("wrong context", { r, k in try k.sign(r, contextOverride: Data("ratify-v2-wrong-context".utf8)) }),
            ("wrong-key ML-DSA", { r, k in
                var s = try k.sign(r)
                s.mlDsa65 = try other.sign(SignRequestForTest.retarget(r, to: other)).mlDsa65
                return s
            }),
            ("flipped Ed25519", { r, k in var s = try k.sign(r); s.ed25519[0] ^= 1; return s }),
            ("valid Ed25519 from a different key", { r, k in
                var s = try k.sign(r)
                s.ed25519 = try other.sign(SignRequestForTest.retarget(r, to: other)).ed25519
                return s
            }),
        ]
        for (name, mutate) in cases {
            do {
                _ = try await Ratify.signDelegationCert(cert, signer: Tamper(key, mutate))
                XCTFail("\(name): accepted")
            } catch {
                XCTAssertEqual(error.errorClass, .invalidSignature, "\(name): \(error)")
            }
        }
    }

    /// A software root rotates into the Secure Enclave; the core verifies both halves.
    func testSoftwareRootRotatesIntoTheSecureEnclave() async throws {
        guard #available(iOS 26, macOS 26, *), SecureEnclave.isAvailable else { return }
        let software = try SoftwarePrivateKey.generate()
        let platform = try SecureEnclaveKey.generate(accessControl: Self.testAccess())
        let v = Corpus.load("key-rotation-signature.json")
        let stmt = KeyRotationStatement(version: 2, authorityId: v.s("authority_id"), recoveryEpoch: 1, role: v.s("role"),
                                        sequence: 1, previousStatementHash: Data(count: 48), oldKey: software.publicKey,
                                        newKey: platform.publicKey, oldKeyId: software.keyId, newKeyId: platform.keyId,
                                        issuedAt: 1_800_000_000, notBefore: 1_800_000_000,
                                        oldSignature: HybridSignature(ed25519: Data(), mlDsa65: Data()),
                                        newSignature: HybridSignature(ed25519: Data(), mlDsa65: Data()))
        let signed = try await Ratify.signKeyRotationStatement(stmt, oldKey: .software(software), newKey: .platform(PlatformKey(platform)))
        let signable = try Ratify.keyRotationStatementSignableBytes(signed)
        XCTAssertNoThrow(try Ratify.verifyStatement(.keyRotationAuthorization, signable: signable, signature: signed.oldSignature, publicKey: software.publicKey))
        XCTAssertNoThrow(try Ratify.verifyStatement(.keyRotationProofOfPossession, signable: signable, signature: signed.newSignature, publicKey: platform.publicKey))
    }

    /// CryptoKit's software ML-DSA-65 derives the same public key from each
    /// fixture seed as the core: independent evidence for FIPS 204 KeyGen.
    func testCryptoKitDerivesTheCorePublicKeys() throws {
        guard #available(iOS 26, macOS 26, *) else { return }
        for (name, seeds) in Fixture.shared.seeds {
            let ck = try MLDSA65.PrivateKey(seedRepresentation: seeds.1, publicKey: nil)
            XCTAssertEqual(ck.publicKey.rawRepresentation, Fixture.shared.key(name).mlDsa65, name)
            let ed = try Curve25519.Signing.PrivateKey(rawRepresentation: seeds.0)
            XCTAssertEqual(ed.publicKey.rawRepresentation, Fixture.shared.key(name).ed25519, name)
        }
    }
}

/// Builds a request for another key (the "wrong key" case signs the same M).
enum SignRequestForTest {
    @available(iOS 26, macOS 26, *)
    static func retarget(_ r: SignRequest, to key: SecureEnclaveKey) -> SignRequest { r.retargeted(to: key.publicKey, keyId: key.keyId) }
}
