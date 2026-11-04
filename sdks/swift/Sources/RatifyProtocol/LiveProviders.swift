import Foundation

public enum TrustOutcome: String, Sendable { case trusted, untrusted, unavailable, ambiguous }

/// Pure pre-claim receiver binding check. It must not perform I/O or mutate state.
public protocol ReceiverBindingHook: Sendable {
    func validate(bundle: ProofBundle, expected: ExpectedChallenge) throws
}

final class ReceiverBindingBridge: FfiReceiverBindingHook, @unchecked Sendable {
    private let hook: any ReceiverBindingHook
    init(_ hook: any ReceiverBindingHook) { self.hook = hook }
    func validate(bundle: FfiProofBundle, expected: FfiExpectedChallenge) throws {
        do { try hook.validate(bundle: ProofBundle(bundle), expected: ExpectedChallenge(expected)) }
        catch { throw FfiProviderError.Failed(detail: "\(error)") }
    }
}

public struct TrustResolution: Sendable {
    public let outcome: TrustOutcome
    public let rootKey: HybridPublicKey
    public init(outcome: TrustOutcome, rootKey: HybridPublicKey) {
        self.outcome = outcome; self.rootKey = rootKey
    }
    var ffi: FfiTrustResolution { FfiTrustResolution(outcome: outcome.rawValue, rootKey: rootKey.ffi) }
}

/// Resolves a verified chain against caller-authenticated roots.
public protocol TrustProvider: Sendable {
    func resolve(chain: [DelegationCert]) async throws -> TrustResolution
}

public struct DeferredConstraint: Sendable {
    public let delegationIndex: UInt64
    public let constraintIndex: UInt64
    public let issuerId: String
    public let certId: String
    public let kind: String
    public let canonicalJSON: Data
    init(_ f: FfiDeferredConstraint) {
        delegationIndex = f.delegationIndex; constraintIndex = f.constraintIndex
        issuerId = f.issuerId; certId = f.certId; kind = f.kind; canonicalJSON = f.canonicalJson
    }
}

public struct AudienceMembership: Sendable {
    public let delegationIndex: UInt64
    public let constraintIndex: UInt64
    public let receiverId: String
    public let trustDomainIds: [String]
    public let issuedAt: Int64
    public let expiresAt: Int64
    public let evidenceDigest: String
    public init(delegationIndex: UInt64, constraintIndex: UInt64, receiverId: String,
                trustDomainIds: [String], issuedAt: Int64, expiresAt: Int64, evidenceDigest: String) {
        self.delegationIndex = delegationIndex; self.constraintIndex = constraintIndex
        self.receiverId = receiverId; self.trustDomainIds = trustDomainIds
        self.issuedAt = issuedAt; self.expiresAt = expiresAt; self.evidenceDigest = evidenceDigest
    }
    var ffi: FfiAudienceMembership { FfiAudienceMembership(delegationIndex: delegationIndex,
        constraintIndex: constraintIndex, receiverId: receiverId, trustDomainIds: trustDomainIds,
        issuedAt: issuedAt, expiresAt: expiresAt, evidenceDigest: evidenceDigest) }
}

/// Supplies authenticated, complete receiver membership evidence.
public protocol AudienceProvider: Sendable {
    func memberships(for deferred: [DeferredConstraint], receiverId: String) async throws -> [AudienceMembership]
}

public struct CertificateRef: Sendable {
    public let issuerId: String
    public let certId: String
    init(_ f: FfiCertificateRef) { issuerId = f.issuerId; certId = f.certId }
}

public struct StatusEvidenceRequest: Sendable {
    public let issuerId: String
    public let statusKeyEpoch: UInt64
    public let statusKeyId: String
    public let refs: [CertificateRef]
    init(_ f: FfiStatusEvidenceRequest) {
        issuerId = f.issuerId; statusKeyEpoch = f.statusKeyEpoch
        statusKeyId = f.statusKeyId; refs = f.refs.map(CertificateRef.init)
    }
}

/// Returns signed status objects for the authenticated issuer configuration.
public protocol StatusEvidenceProvider: Sendable {
    func provide(_ request: StatusEvidenceRequest) async throws -> [StatusEvidenceObject]
}

private func providerError(_ error: Error, context: FfiStoreContext) -> FfiProviderError {
    if error is CancellationError, (try? context.isCancelled()) == true { return .Cancelled }
    return .Failed(detail: "\(error)")
}

final class TrustProviderBridge: FfiTrustProvider, @unchecked Sendable {
    private let provider: any TrustProvider
    init(_ provider: any TrustProvider) { self.provider = provider }
    func resolve(chain: [FfiDelegationCert], context: FfiStoreContext) throws -> FfiTrustResolution {
        do { return try callbackWait(context: context) {
            try await self.provider.resolve(chain: chain.map(DelegationCert.init)).ffi
        } } catch { throw providerError(error, context: context) }
    }
}

final class AudienceProviderBridge: FfiAudienceProvider, @unchecked Sendable {
    private let provider: any AudienceProvider
    init(_ provider: any AudienceProvider) { self.provider = provider }
    func memberships(deferred: [FfiDeferredConstraint], receiverId: String,
                     context: FfiStoreContext) throws -> [FfiAudienceMembership] {
        do { return try callbackWait(context: context) {
            try await self.provider.memberships(for: deferred.map(DeferredConstraint.init), receiverId: receiverId).map(\.ffi)
        } } catch { throw providerError(error, context: context) }
    }
}

final class StatusEvidenceProviderBridge: FfiStatusEvidenceProvider, @unchecked Sendable {
    private let provider: any StatusEvidenceProvider
    init(_ provider: any StatusEvidenceProvider) { self.provider = provider }
    func provide(request: FfiStatusEvidenceRequest, context: FfiStoreContext) throws -> [FfiStatusEvidenceObject] {
        do { return try callbackWait(context: context) {
            try await self.provider.provide(StatusEvidenceRequest(request)).map(\.ffi)
        } } catch { throw providerError(error, context: context) }
    }
}
