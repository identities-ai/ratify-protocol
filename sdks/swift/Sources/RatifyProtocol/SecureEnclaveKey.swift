import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// A hybrid key whose ML-DSA-65 half lives in the Secure Enclave (iOS and
/// macOS 26+) and whose Ed25519 half is a seed held only in its Keychain
/// record (build plan §4.2). It signs only SDK-computed requests through the
/// typed signing functions; there is no API that signs arbitrary bytes. The
/// SDK verifies both returned components before using them.
@available(iOS 26.0, macOS 26.0, *)
public final class SecureEnclaveKey: Sendable {
    // ObjC realizes class metadata on iOS 17 before availability checks; a
    // stored iOS 26-only type crashes the test host during class discovery.
    private let mldsa: any Sendable
    private let edSeed: Data
    public let publicKey: HybridPublicKey
    public let keyId: String

    /// Where each half of the key is held.
    public enum Custody: String, Sendable { case secureEnclave, software }
    /// ML-DSA-65 is in the Secure Enclave; Ed25519 is a software seed.
    public var custody: (ed25519: Custody, mlDsa65: Custody) { (.software, .secureEnclave) }

    private init(mldsa: SecureEnclave.MLDSA65.PrivateKey, edSeed: Data) throws(RatifyError) {
        self.mldsa = mldsa
        self.edSeed = edSeed
        let ed: Curve25519.Signing.PrivateKey
        do { ed = try Curve25519.Signing.PrivateKey(rawRepresentation: edSeed) } catch {
            throw .protocol(.malformed, message: "invalid Ed25519 seed")
        }
        publicKey = HybridPublicKey(ed25519: ed.publicKey.rawRepresentation, mlDsa65: mldsa.publicKey.rawRepresentation)
        keyId = try Ratify.keyId(publicKey)
    }

    /// The default access control for a root key: the current biometry set,
    /// on this device only. Pass your own to change it.
    public static func defaultAccessControl() -> SecAccessControl {
        SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], nil)!
    }

    /// Generate a new key. ML-DSA-65 is generated inside the Secure Enclave
    /// under `accessControl`; the Ed25519 seed comes from the system random source.
    public static func generate(accessControl: SecAccessControl = defaultAccessControl(),
                                authenticationContext: LAContext? = nil) throws(RatifyError) -> SecureEnclaveKey {
        guard SecureEnclave.isAvailable else { throw .protocol(.configurationInvalid, message: "this device has no Secure Enclave") }
        let mldsa: SecureEnclave.MLDSA65.PrivateKey
        do { mldsa = try SecureEnclave.MLDSA65.PrivateKey(accessControl: accessControl, authenticationContext: authenticationContext) } catch {
            throw .protocol(.configurationInvalid, message: "the Secure Enclave refused to create a key: \(error)")
        }
        var seed = Data(count: 32)
        let rc = seed.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard rc == errSecSuccess else { throw .internal(.randomSource, message: "SecRandomCopyBytes failed (\(rc))") }
        return try SecureEnclaveKey(mldsa: mldsa, edSeed: seed)
    }

    /// This key's type 0x02 storage record. It is device-bound by design: the
    /// Secure Enclave data representation works only on this device.
    public func storageRecord() throws(RatifyError) -> Data {
        let mldsa = self.mldsa as! SecureEnclave.MLDSA65.PrivateKey
        let fields = [FfiStorageField(tag: 0x01, value: edSeed),
                      FfiStorageField(tag: 0x03, value: publicKey.mlDsa65),
                      FfiStorageField(tag: 0x04, value: mldsa.dataRepresentation)]
        return try ffi { try ffiEncodeStorageRecord(recordType: 0x02, keyId: keyId, fields: fields) }
    }

    /// Load a key from its type 0x02 storage record. The public key is
    /// re-derived and must match both the recorded ML-DSA public key and the
    /// recorded key ID.
    public convenience init(storageRecord: Data, authenticationContext: LAContext? = nil) throws(RatifyError) {
        var r = try KeyStorageRecord.parse(storageRecord)
        defer { for k in r.fields.keys { r.fields[k]!.resetBytes(in: 0..<r.fields[k]!.count) } }
        guard r.type == .secureEnclaveHybrid else {
            throw .protocol(.malformed, message: "record is not a Secure Enclave key")
        }
        let mldsa: SecureEnclave.MLDSA65.PrivateKey
        do { mldsa = try SecureEnclave.MLDSA65.PrivateKey(dataRepresentation: r.fields[0x04]!, authenticationContext: authenticationContext) } catch {
            throw .protocol(.configurationInvalid, message: "the Secure Enclave refused the key (another device, or deleted): \(error)")
        }
        try self.init(mldsa: mldsa, edSeed: Data(r.fields[0x01]!))
        guard publicKey.mlDsa65 == r.fields[0x03]!, keyId == r.keyId else {
            throw .protocol(.keyIdMismatch, message: "the stored key derives a key other than the recorded one")
        }
    }

    /// Sign one SDK-computed request in direct mode: Ed25519 over `M`, and
    /// ML-DSA-65 over `M` with the SDK's context, in the Secure Enclave.
    func sign(_ request: SignRequest, contextOverride: Data? = nil) throws -> HybridSignature {
        let mldsa = self.mldsa as! SecureEnclave.MLDSA65.PrivateKey
        guard request.mode == .direct, let sdkCtx = request.mlDsaContext, request.publicKey == publicKey else {
            throw RatifyError.signing(.configurationInvalid, kind: .provider, message: "request is not for this key in direct mode")
        }
        let ed = try Curve25519.Signing.PrivateKey(rawRepresentation: edSeed).signature(for: request.message)
        let ml = try mldsa.signature(for: request.message, context: contextOverride ?? sdkCtx)
        return HybridSignature(ed25519: ed, mlDsa65: ml)
    }

    var signer: any ExternalSigner { PlatformSigner(key: self) }
}

/// The SDK-internal signer over a platform key. It is not public, so no
/// caller can ask a platform key to sign bytes the SDK did not compute.
@available(iOS 26.0, macOS 26.0, *)
private struct PlatformSigner: ExternalSigner {
    let key: SecureEnclaveKey
    var publicKey: HybridPublicKey { key.publicKey }
    var mode: SignerMode { .direct }
    func sign(_ request: SignRequest) async throws -> HybridSignature { try key.sign(request) }
}

/// The key a typed signing function signs with (build plan §4.1).
public enum SigningKey: Sendable {
    /// A software key, held as its two seeds.
    case software(SoftwarePrivateKey)
    /// An app-held key (HSM, KMS, remote service) behind your `ExternalSigner`.
    case external(any ExternalSigner)
    /// A Secure Enclave key (iOS and macOS 26+), boxed so the enum is
    /// available on every supported OS.
    case platform(PlatformKey)
}

/// A platform-held key for `SigningKey.platform`.
public struct PlatformKey: Sendable {
    let signer: any ExternalSigner
    public let keyId: String

    @available(iOS 26.0, macOS 26.0, *)
    public init(_ key: SecureEnclaveKey) {
        signer = key.signer
        keyId = key.keyId
    }
}

// Typed signing with any SigningKey (asynchronous: a platform key may prompt).
extension Ratify {
    private static func external(_ k: SigningKey) -> (any ExternalSigner)? {
        switch k {
        case .software: return nil
        case let .external(s): return s
        case let .platform(p): return p.signer
        }
    }

    public static func signDelegationCert(_ cert: DelegationCert, with key: SigningKey) async throws(RatifyError) -> DelegationCert {
        if case let .software(k) = key { return try signDelegationCert(cert, key: k) }
        return try await signDelegationCert(cert, signer: external(key)!)
    }
    public static func signProofBundle(_ bundle: ProofBundle, with key: SigningKey) async throws(RatifyError) -> ProofBundle {
        if case let .software(k) = key { return try signProofBundle(bundle, key: k) }
        return try await signProofBundle(bundle, signer: external(key)!)
    }
    public static func signRevocationList(_ list: RevocationList, boundIssuerId: String, boundStatusKey: HybridPublicKey,
                                          with key: SigningKey) async throws(RatifyError) -> RevocationList {
        if case let .software(k) = key { return try signRevocationList(list, boundIssuerId: boundIssuerId, boundStatusKey: boundStatusKey, key: k) }
        return try await signRevocationList(list, boundIssuerId: boundIssuerId, boundStatusKey: boundStatusKey, signer: external(key)!)
    }
    public static func signRevocationPush(_ push: RevocationPush, boundIssuerId: String, boundStatusKey: HybridPublicKey,
                                          with key: SigningKey) async throws(RatifyError) -> RevocationPush {
        if case let .software(k) = key { return try signRevocationPush(push, boundIssuerId: boundIssuerId, boundStatusKey: boundStatusKey, key: k) }
        return try await signRevocationPush(push, boundIssuerId: boundIssuerId, boundStatusKey: boundStatusKey, signer: external(key)!)
    }
    /// Sign a rotation with any combination of key kinds for the old and new
    /// halves, such as a software root moving into the Secure Enclave. The
    /// core computes both requests and verifies both results.
    public static func signKeyRotationStatement(_ statement: KeyRotationStatement, oldKey: SigningKey,
                                                newKey: SigningKey) async throws(RatifyError) -> KeyRotationStatement {
        if case let .software(o) = oldKey, case let .software(n) = newKey {
            return try signKeyRotationStatement(statement, oldKey: o, newKey: n)
        }
        func slot(_ k: SigningKey) -> (FfiSoftwareKey?, FfiSigner?) {
            if case let .software(s) = k { return (s.handle, nil) }
            return (nil, SignerBridge(external(k)!))
        }
        let st = statement.ffi
        let (os, oe) = slot(oldKey), (ns, ne) = slot(newKey)
        return KeyRotationStatement(try await onWorker { t throws(RatifyError) in
            try ffi {
                try ffiSignKeyRotationStatementWithSlots(cancel: t, statement: st, oldSoftware: os, oldSigner: oe, oldSplit: nil,
                                                         oldSplitEd25519: nil, newSoftware: ns, newSigner: ne, newSplit: nil, newSplitEd25519: nil)
            }
        })
    }
    public static func signWitnessEntry(_ entry: WitnessEntry, with key: SigningKey) async throws(RatifyError) -> WitnessEntry {
        if case let .software(k) = key { return try signWitnessEntry(entry, key: k) }
        return try await signWitnessEntry(entry, signer: external(key)!)
    }
    public static func signVerificationReceipt(_ receipt: VerificationReceipt, with key: SigningKey) async throws(RatifyError) -> VerificationReceipt {
        if case let .software(k) = key { return try signVerificationReceipt(receipt, key: k) }
        return try await signVerificationReceipt(receipt, signer: external(key)!)
    }
    public static func signTransactionReceiptParty(_ receipt: TransactionReceipt, partyId: String,
                                                   with key: SigningKey) async throws(RatifyError) -> TransactionReceiptSignature {
        if case let .software(k) = key { return try signTransactionReceiptParty(receipt, partyId: partyId, key: k) }
        return try await signTransactionReceiptParty(receipt, partyId: partyId, signer: external(key)!)
    }
}
