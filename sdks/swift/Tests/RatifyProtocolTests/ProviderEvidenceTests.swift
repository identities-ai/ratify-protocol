import CryptoKit
import Foundation
import Security
import XCTest
@testable import RatifyProtocol

/// Produces the provider evidence record (build plan §6.4) for this device's
/// Secure Enclave: public keys only, and three objects the platform key
/// signed through the public API: a delegation certificate it issues, a key
/// rotation into it (its proof of possession), and a revocation list it
/// signs as status key. Every object is verified here before it is written;
/// the record is printed between markers for the evidence run to collect,
/// and every SDK's generic runner verifies the committed files.
final class ProviderEvidenceTests: XCTestCase {
    static func machine() -> String {
        #if os(macOS)
        var size = 0
        sysctlbyname("hw.model", nil, &size, nil, 0)
        var model = [CChar](repeating: 0, count: size)
        sysctlbyname("hw.model", &model, &size, nil, 0)
        return String(cString: model)
        #else
        var info = utsname()
        uname(&info)
        return withUnsafeBytes(of: &info.machine) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
        #endif
    }

    static func osBuild() -> String {
        var size = 0
        sysctlbyname("kern.osversion", nil, &size, nil, 0)
        var buf = [CChar](repeating: 0, count: size)
        sysctlbyname("kern.osversion", &buf, &size, nil, 0)
        return String(cString: buf)
    }

    func testSecureEnclaveEvidence() async throws {
        guard #available(iOS 26, macOS 26, *), SecureEnclave.isAvailable else { return }
        let key = try SecureEnclaveKey.generate(accessControl: SecureEnclaveTests.testAccess())
        let platform = SigningKey.platform(PlatformKey(key))
        let objects = Corpus.load("objects.json")

        // 1. A delegation certificate the platform key issues.
        let cert = try await Ratify.signDelegationCert(try SecureEnclaveTests.cert(issuedBy: key.publicKey, keyId: key.keyId), with: platform)
        try Ratify.verifyDelegationCertSignature(cert)

        // 2. A rotation from a fresh software key into the platform key.
        let software = try SoftwarePrivateKey.generate()
        let rv = Corpus.load("key-rotation-signature.json")
        let rotation = try await Ratify.signKeyRotationStatement(
            KeyRotationStatement(version: 2, authorityId: rv.s("authority_id"), recoveryEpoch: 1, role: rv.s("role"), sequence: 1,
                                 previousStatementHash: Data(count: 48), oldKey: software.publicKey, newKey: key.publicKey,
                                 oldKeyId: software.keyId, newKeyId: key.keyId, issuedAt: 1_800_000_000, notBefore: 1_800_000_000,
                                 oldSignature: HybridSignature(ed25519: Data(), mlDsa65: Data()),
                                 newSignature: HybridSignature(ed25519: Data(), mlDsa65: Data())),
            oldKey: .software(software), newKey: platform)
        let signable = try Ratify.keyRotationStatementSignableBytes(rotation)
        try Ratify.verifyStatement(.keyRotationProofOfPossession, signable: signable, signature: rotation.newSignature, publicKey: key.publicKey)

        // 3. A revocation list the platform key signs as the issuer's status key.
        var list = try Ratify.decodeRevocationList(objectByKind(objects, "revocation_list").b64("wire_b64"))
        list.issuerId = key.keyId
        let signedList = try await Ratify.signRevocationList(list, boundIssuerId: key.keyId, boundStatusKey: key.publicKey, with: platform)
        try Ratify.verifyRevocationListSignature(signedList, trustedIssuerId: key.keyId, statusKey: key.publicKey)

        #if os(iOS)
        let platformName = "ios"
        #else
        let platformName = "macos"
        #endif
        let os = ProcessInfo.processInfo.operatingSystemVersion
        let record: [String: Any] = [
            "version": 1,
            "description": "Provider evidence: a Secure Enclave key (ML-DSA-65 in the Secure Enclave, Ed25519 from a software seed) signed these objects through the Swift SDK's public API on this device.",
            "platform": platformName,
            "provider": "secure-enclave",
            "sdk": "swift",
            "device_model": Self.machine(),
            "os_version": "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)",
            "os_build": Self.osBuild(),
            "custody": ["ed25519": "software", "ml_dsa_65": "secure_enclave"],
            "public_key": ["ed25519": key.publicKey.ed25519.base64EncodedString(), "ml_dsa_65": key.publicKey.mlDsa65.base64EncodedString()],
            "key_id_v2": key.keyId,
            "objects": [
                ["kind": "delegation_certificate", "role": "issuer", "wire_b64": try Ratify.encodeDelegationCert(cert).base64EncodedString()],
                ["kind": "key_rotation_statement", "role": "new_key", "wire_b64": try Ratify.encodeKeyRotationStatement(rotation).base64EncodedString()],
                ["kind": "revocation_list", "role": "status_key", "wire_b64": try Ratify.encodeRevocationList(signedList).base64EncodedString()],
            ],
        ]
        let json = try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys, .prettyPrinted])
        // Where the run can reach a directory (macOS), it may also write the file.
        if let dir = ProcessInfo.processInfo.environment["RATIFY_EVIDENCE_DIR"] {
            try json.write(to: URL(fileURLWithPath: dir).appendingPathComponent("\(platformName)-secure-enclave.json"))
        }
        print("RATIFY-PROVIDER-EVIDENCE-BEGIN \(platformName)-secure-enclave")
        print(json.base64EncodedString())
        print("RATIFY-PROVIDER-EVIDENCE-END")
    }
}
