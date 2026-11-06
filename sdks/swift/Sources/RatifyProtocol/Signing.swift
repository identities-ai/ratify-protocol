import Foundation

/// How an external signer computes its ML-DSA-65 component (SPEC-v2 §3.2).
public enum SignerMode: Sendable, Hashable {
    /// Sign `M` with the supplied 22-byte context.
    case direct
    /// Sign the supplied FIPS 204 external `mu`.
    case externalMu

    init(_ f: FfiSignerMode) { self = f == .direct ? .direct : .externalMu }
    var ffi: FfiSignerMode { self == .direct ? .direct : .externalMu }
}

/// What the SDK asks an external signer to sign. The SDK computed every
/// field; the signer must not substitute its own message or context.
public struct SignRequest: Sendable, Hashable {
    public let mode: SignerMode
    /// The 77-byte signing message `M`; the Ed25519 component signs it.
    public let message: Data
    /// The 22-byte ML-DSA-65 context, in direct mode.
    public let mlDsaContext: Data?
    /// The external `mu`, in external-mu mode.
    public let mlDsaMu: Data?
    public let publicKey: HybridPublicKey
    public let keyId: String

    /// The same request addressed to another key (tests only).
    func retargeted(to key: HybridPublicKey, keyId: String) -> SignRequest {
        SignRequest(mode: mode, message: message, mlDsaContext: mlDsaContext, mlDsaMu: mlDsaMu, publicKey: key, keyId: keyId)
    }

    private init(mode: SignerMode, message: Data, mlDsaContext: Data?, mlDsaMu: Data?, publicKey: HybridPublicKey, keyId: String) {
        self.mode = mode
        self.message = message
        self.mlDsaContext = mlDsaContext
        self.mlDsaMu = mlDsaMu
        self.publicKey = publicKey
        self.keyId = keyId
    }

    init(_ f: FfiSignRequest) {
        mode = SignerMode(f.mode)
        message = f.message
        mlDsaContext = f.mlDsaContext
        mlDsaMu = f.mlDsaMu
        publicKey = HybridPublicKey(f.publicKey)
        keyId = f.keyId
    }
}

/// An app-held key (an HSM, KMS or remote service the app already controls)
/// that signs SDK-computed requests. The SDK verifies both returned
/// components before using them. Task cancellation is how the SDK asks the
/// signer to stop; throwing `CancellationError` reports that it did.
public protocol ExternalSigner: Sendable {
    var publicKey: HybridPublicKey { get }
    var mode: SignerMode { get }
    func sign(_ request: SignRequest) async throws -> HybridSignature
}

/// Runs an async `ExternalSigner` from a blocked SDK worker thread: the
/// signer runs as a task on the global executor (never the SDK thread), and
/// the call's cancellation cancels that task.
final class SignerBridge: FfiSigner, @unchecked Sendable {
    let signer: any ExternalSigner
    init(_ signer: any ExternalSigner) { self.signer = signer }

    func publicKey() -> FfiPublicKey { signer.publicKey.ffi }
    func mode() -> FfiSignerMode { signer.mode.ffi }

    func sign(request: FfiSignRequest, context: FfiSignContext) throws -> FfiSignature {
        let box = ResultBox<HybridSignature>()
        let done = DispatchSemaphore(value: 0)
        let signer = self.signer
        let req = SignRequest(request)
        let task = Task.detached {
            do { box.set(.success(try await signer.sign(req))) } catch { box.set(.failure(error)) }
            done.signal()
        }
        while done.wait(timeout: .now() + .milliseconds(5)) == .timedOut {
            if (try? context.isCancelled()) == true { task.cancel() }
        }
        switch box.value! {
        case let .success(sig): return sig.ffi
        case let .failure(e) where e is CancellationError: throw FfiSignerError.Cancelled
        case let .failure(e): throw FfiSignerError.Provider(detail: "\(e)")
        }
    }
}

final class ResultBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var v: Result<T, Error>?
    func set(_ r: Result<T, Error>) { lock.lock(); v = r; lock.unlock() }
    var value: Result<T, Error>? { lock.lock(); defer { lock.unlock() }; return v }
}

// Typed signing with a software key (synchronous; no callbacks).
extension Ratify {
    public static func signDelegationCert(_ cert: DelegationCert, key: SoftwarePrivateKey) throws(RatifyError) -> DelegationCert {
        DelegationCert(try ffi { try key.handle.signDelegationCert(cert: cert.ffi) })
    }
    public static func signProofBundle(_ bundle: ProofBundle, key: SoftwarePrivateKey) throws(RatifyError) -> ProofBundle {
        ProofBundle(try ffi { try key.handle.signProofBundle(bundle: bundle.ffi) })
    }
    public static func signRevocationList(_ list: RevocationList, boundIssuerId: String, boundStatusKey: HybridPublicKey,
                                          key: SoftwarePrivateKey) throws(RatifyError) -> RevocationList {
        RevocationList(try ffi { try key.handle.signRevocationList(list: list.ffi, boundIssuerId: boundIssuerId, boundStatusKey: boundStatusKey.ffi) })
    }
    public static func signRevocationPush(_ push: RevocationPush, boundIssuerId: String, boundStatusKey: HybridPublicKey,
                                          key: SoftwarePrivateKey) throws(RatifyError) -> RevocationPush {
        RevocationPush(try ffi { try key.handle.signRevocationPush(push: push.ffi, boundIssuerId: boundIssuerId, boundStatusKey: boundStatusKey.ffi) })
    }
    /// The old key signs the authorization; the new key signs the proof of possession.
    public static func signKeyRotationStatement(_ statement: KeyRotationStatement, oldKey: SoftwarePrivateKey,
                                                newKey: SoftwarePrivateKey) throws(RatifyError) -> KeyRotationStatement {
        KeyRotationStatement(try ffi { try oldKey.handle.signKeyRotationStatement(statement: statement.ffi, newKey: newKey.handle) })
    }
    public static func signWitnessEntry(_ entry: WitnessEntry, key: SoftwarePrivateKey) throws(RatifyError) -> WitnessEntry {
        WitnessEntry(try ffi { try key.handle.signWitnessEntry(entry: entry.ffi) })
    }
    public static func signVerificationReceipt(_ receipt: VerificationReceipt, key: SoftwarePrivateKey) throws(RatifyError) -> VerificationReceipt {
        VerificationReceipt(try ffi { try key.handle.signVerificationReceipt(receipt: receipt.ffi) })
    }
    public static func signPreparedVerificationReceipt(_ data: Data, head: ReceiptHead,
                                                       key: SoftwarePrivateKey) throws(RatifyError) -> VerificationReceipt {
        VerificationReceipt(try ffi { try key.handle.signPreparedVerificationReceipt(data: data, head: head.ffi) })
    }
    public static func signTransactionReceiptParty(_ receipt: TransactionReceipt, partyId: String,
                                                   key: SoftwarePrivateKey) throws(RatifyError) -> TransactionReceiptSignature {
        TransactionReceiptSignature(try ffi { try key.handle.signTransactionReceiptParty(receipt: receipt.ffi, partyId: partyId) })
    }
}

// Typed signing with an external signer (asynchronous; the signer may be remote).
extension Ratify {
    public static func signDelegationCert(_ cert: DelegationCert, signer: any ExternalSigner) async throws(RatifyError) -> DelegationCert {
        let c = cert.ffi, s = SignerBridge(signer)
        return DelegationCert(try await onWorker { t throws(RatifyError) in try ffi { try ffiSignDelegationCertWithSigner(cancel: t, cert: c, signer: s) } })
    }
    public static func signProofBundle(_ bundle: ProofBundle, signer: any ExternalSigner) async throws(RatifyError) -> ProofBundle {
        let b = bundle.ffi, s = SignerBridge(signer)
        return ProofBundle(try await onWorker { t throws(RatifyError) in try ffi { try ffiSignProofBundleWithSigner(cancel: t, bundle: b, signer: s) } })
    }
    public static func signRevocationList(_ list: RevocationList, boundIssuerId: String, boundStatusKey: HybridPublicKey,
                                          signer: any ExternalSigner) async throws(RatifyError) -> RevocationList {
        let l = list.ffi, k = boundStatusKey.ffi, s = SignerBridge(signer)
        return RevocationList(try await onWorker { t throws(RatifyError) in
            try ffi { try ffiSignRevocationListWithSigner(cancel: t, list: l, boundIssuerId: boundIssuerId, boundStatusKey: k, signer: s) }
        })
    }
    public static func signRevocationPush(_ push: RevocationPush, boundIssuerId: String, boundStatusKey: HybridPublicKey,
                                          signer: any ExternalSigner) async throws(RatifyError) -> RevocationPush {
        let p = push.ffi, k = boundStatusKey.ffi, s = SignerBridge(signer)
        return RevocationPush(try await onWorker { t throws(RatifyError) in
            try ffi { try ffiSignRevocationPushWithSigner(cancel: t, push: p, boundIssuerId: boundIssuerId, boundStatusKey: k, signer: s) }
        })
    }
    public static func signKeyRotationStatement(_ statement: KeyRotationStatement, oldSigner: any ExternalSigner,
                                                newSigner: any ExternalSigner) async throws(RatifyError) -> KeyRotationStatement {
        let st = statement.ffi, o = SignerBridge(oldSigner), n = SignerBridge(newSigner)
        return KeyRotationStatement(try await onWorker { t throws(RatifyError) in
            try ffi { try ffiSignKeyRotationStatementWithSigners(cancel: t, statement: st, oldSigner: o, newSigner: n) }
        })
    }
    public static func signWitnessEntry(_ entry: WitnessEntry, signer: any ExternalSigner) async throws(RatifyError) -> WitnessEntry {
        let e = entry.ffi, s = SignerBridge(signer)
        return WitnessEntry(try await onWorker { t throws(RatifyError) in try ffi { try ffiSignWitnessEntryWithSigner(cancel: t, entry: e, signer: s) } })
    }
    public static func signVerificationReceipt(_ receipt: VerificationReceipt, signer: any ExternalSigner) async throws(RatifyError) -> VerificationReceipt {
        let r = receipt.ffi, s = SignerBridge(signer)
        return VerificationReceipt(try await onWorker { t throws(RatifyError) in
            try ffi { try ffiSignVerificationReceiptWithSigner(cancel: t, receipt: r, signer: s) }
        })
    }
    public static func signPreparedVerificationReceipt(_ data: Data, head: ReceiptHead,
                                                       signer: any ExternalSigner) async throws(RatifyError) -> VerificationReceipt {
        let h = head.ffi, s = SignerBridge(signer)
        return VerificationReceipt(try await onWorker { t throws(RatifyError) in
            try ffi { try ffiSignPreparedVerificationReceiptWithSigner(cancel: t, data: data, head: h, signer: s) }
        })
    }
    public static func signTransactionReceiptParty(_ receipt: TransactionReceipt, partyId: String,
                                                   signer: any ExternalSigner) async throws(RatifyError) -> TransactionReceiptSignature {
        let r = receipt.ffi, s = SignerBridge(signer)
        return TransactionReceiptSignature(try await onWorker { t throws(RatifyError) in
            try ffi { try ffiSignTransactionReceiptPartyWithSigner(cancel: t, receipt: r, partyId: partyId, signer: s) }
        })
    }
}
