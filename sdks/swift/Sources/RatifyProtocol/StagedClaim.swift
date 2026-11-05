import Foundation

/// A single-use capability returned only for a newly created claim.
public final class EvaluationToken: @unchecked Sendable {
    let handle: FfiEvaluationToken
    init(_ handle: FfiEvaluationToken) { self.handle = handle }
}

public struct StagedClaim: Sendable {
    public let claim: ChallengeClaim
    public let disposition: ClaimDisposition
    public let evaluationToken: EvaluationToken?
    init(_ f: FfiStagedClaim) {
        claim = ChallengeClaim(f.claim)
        disposition = ClaimDisposition(f.disposition)
        evaluationToken = f.evaluationToken.map(EvaluationToken.init)
    }
}

/// The trusted root and context for a direct local assessment.
public struct LocalAuthorizationOptions: Sendable {
    public let futureSkewSeconds: Int64
    public let requiredScope: String
    public let trustedRootId: String
    public let trustedRootKey: HybridPublicKey
    public let trustConfigured: Bool
    public let context: ConstraintContext
    public let tzdbVersion: String
    public let contextPolicy: ContextPolicy?
    public let expectedChallenge: ExpectedChallenge?
    public let claimToken: EvaluationToken

    public init(futureSkewSeconds: Int64, requiredScope: String, trustedRootId: String,
                trustedRootKey: HybridPublicKey, trustConfigured: Bool, context: ConstraintContext,
                tzdbVersion: String, contextPolicy: ContextPolicy?,
                expectedChallenge: ExpectedChallenge?, claimToken: EvaluationToken) {
        self.futureSkewSeconds = futureSkewSeconds; self.requiredScope = requiredScope
        self.trustedRootId = trustedRootId; self.trustedRootKey = trustedRootKey
        self.trustConfigured = trustConfigured; self.context = context; self.tzdbVersion = tzdbVersion
        self.contextPolicy = contextPolicy; self.expectedChallenge = expectedChallenge
        self.claimToken = claimToken
    }

    var ffi: FfiLocalAuthorizationOptions {
        FfiLocalAuthorizationOptions(futureSkewSeconds: futureSkewSeconds,
            requiredScope: requiredScope, trustedRootId: trustedRootId,
            trustedRootKey: trustedRootKey.ffi, trustConfigured: trustConfigured,
            context: context.ffi, tzdbVersion: tzdbVersion, contextPolicy: contextPolicy?.handle,
            expectedChallenge: expectedChallenge?.ffi, claimToken: claimToken.handle)
    }
}

public struct CertificateStatusCheck: Sendable {
    public let delegationIndex: UInt64
    public let issuerId: String
    public let subjectId: String
    public let certId: String
    init(_ f: FfiCertificateStatusCheck) {
        delegationIndex = f.delegationIndex; issuerId = f.issuerId
        subjectId = f.subjectId; certId = f.certId
    }
}

public struct LocalPolicyFailure: Sendable {
    public let status: String
    public let reason: String
    public let detail: String
    init(_ f: FfiLocalPolicyFailure) { status = f.status; reason = f.reason; detail = f.detail }
}

/// A direct local assessment. Successful local checks remain pending because
/// authenticated status resolution is internal to the composed verifier.
/// A pending result is not an allow decision.
public struct LocalAuthorizationAssessment: Sendable {
    public let bundleHash: String
    public let issuerIds: [String]
    public let agentId: String
    public let rootId: String
    public let requiredScope: String
    public let delegationDigest: Data
    public let effectiveScope: [String]
    public let contextAssessment: String
    public let contextPolicyDigest: String?
    public let statusAssessment: String
    public let delegationValidUntil: Int64
    public let localTimeValidUntil: Int64
    public let extensionValidUntil: Int64
    public let statusFreshUntil: Int64
    public let audienceFreshUntil: Int64
    public let statusEvidence: [StatusEvidenceEntry]
    public let audienceEvidenceDigests: [String]
    public let rateStoreUnavailable: Bool
    public let rateAdmissionDeferred: Bool
    public let statusChecks: [CertificateStatusCheck]
    public let deferred: [DeferredConstraint]
    public let localPolicyFailure: LocalPolicyFailure?
    public let status: String
    public let reason: String
    public let detail: String

    init(_ f: FfiLocalAuthorizationAssessment) {
        bundleHash = f.bundleHash; issuerIds = f.issuerIds; agentId = f.agentId
        rootId = f.rootId; requiredScope = f.requiredScope
        delegationDigest = f.delegationDigest; effectiveScope = f.effectiveScope
        contextAssessment = f.contextAssessment; contextPolicyDigest = f.contextPolicyDigest
        statusAssessment = f.statusAssessment; delegationValidUntil = f.delegationValidUntil
        localTimeValidUntil = f.localTimeValidUntil; extensionValidUntil = f.extensionValidUntil
        statusFreshUntil = f.statusFreshUntil; audienceFreshUntil = f.audienceFreshUntil
        statusEvidence = f.statusEvidence.map(StatusEvidenceEntry.init)
        audienceEvidenceDigests = f.audienceEvidenceDigests
        rateStoreUnavailable = f.rateStoreUnavailable; rateAdmissionDeferred = f.rateAdmissionDeferred
        statusChecks = f.statusChecks.map(CertificateStatusCheck.init)
        deferred = f.deferred.map(DeferredConstraint.init)
        localPolicyFailure = f.localPolicyFailure.map(LocalPolicyFailure.init)
        status = f.status; reason = f.reason; detail = f.detail
    }
}

extension Ratify {
    /// Creates a claim after sealed preflight. A pending claim must be recovered after
    /// lease expiry if it cannot reach a terminal result. Use verifyProofBundle for allow decisions.
    public static func claimProofBundle(bundle: Data, preflight: PreflightResult,
                                        namespace: String, replayEpoch: Int64, now: Int64,
                                        store: any ClaimStore, timeout: Duration? = nil) async throws(RatifyError) -> StagedClaim {
        try await onWorker(timeout: timeout) { cancel throws(RatifyError) in
            try StagedClaim(ffi { try ffiClaimProofBundle(bundle: bundle, preflight: preflight.handle,
                configuredNamespace: namespace, configuredReplayEpoch: replayEpoch, now: now,
                store: ClaimStoreBridge(store), token: cancel) })
        }
    }

    /// Evaluates local policy once. Valid proof stays pending until the composed
    /// verifier authenticates status; this direct API cannot reach allow.
    public static func evaluateLocalAuthorization(bundle: Data, options: LocalAuthorizationOptions) async throws(RatifyError) -> LocalAuthorizationAssessment {
        try await onWorker { _ throws(RatifyError) in
            try LocalAuthorizationAssessment(ffi { try ffiEvaluateLocalAuthorization(bundle: bundle, options: options.ffi) })
        }
    }

    /// Requires current authenticated status. A direct pending claim cannot pass this gate.
    public static func resolveClaimAfterAudience(token: EvaluationToken,
                                                  memberships: [AudienceMembership]) throws(RatifyError) -> LocalAuthorizationAssessment {
        try LocalAuthorizationAssessment(ffi { try ffiResolveClaimAfterAudience(
            token: token.handle, memberships: memberships.map(\.ffi)) })
    }

    /// Requires current authenticated status. A direct pending claim cannot reserve a rate.
    public static func resolveClaimAfterRate(token: EvaluationToken, store: (any RateReservationStore)? = nil,
                                              timeout: Duration? = nil) async throws(RatifyError) -> LocalAuthorizationAssessment {
        try await onWorker(timeout: timeout) { cancel throws(RatifyError) in
            try LocalAuthorizationAssessment(ffi { try ffiResolveClaimAfterRate(token: token.handle,
                store: store.map(RateReservationStoreBridge.init), cancel: cancel) })
        }
    }

    /// Requires current authenticated status. The store must be the same one used at claim.
    public static func resolveClaimAfterRate(token: EvaluationToken, store: any RateAtFinalizationClaimStore,
                                              timeout: Duration? = nil) async throws(RatifyError) -> LocalAuthorizationAssessment {
        try await onWorker(timeout: timeout) { cancel throws(RatifyError) in
            try LocalAuthorizationAssessment(ffi { try ffiResolveClaimAfterRateBarrier(token: token.handle,
                store: ClaimStoreBridge(store), cancel: cancel) })
        }
    }

    /// Finalizes only a terminal assessment. Pending claims must be recovered after lease expiry;
    /// this direct path cannot finalize an allow decision. Use the same store used at claim.
    public static func finalizeClaimProofBundle(token: EvaluationToken, store: any ClaimStore,
                                                 terminalResult: Data, receiptBody: Data,
                                                 timeout: Duration? = nil) async throws -> Bool {
        let reply = try await onWorker(timeout: timeout) { cancel throws(RatifyError) in
            try ffi { try ffiFinalizeClaimProofBundle(token: token.handle, store: ClaimStoreBridge(store),
                cancel: cancel, terminalResult: terminalResult, receiptBody: receiptBody) }
        }
        if let failure = reply.failure { throw ReferenceStoreBridge.error(failure) }
        guard let finalized = reply.finalized else { throw RatifyError.internal(.panic, message: "missing finalization result") }
        return finalized
    }

    /// Finalizes only a terminal assessment with the same barrier store used at claim.
    /// Pending claims require lease-expiry recovery; this direct path cannot allow.
    public static func finalizeClaimProofBundle(token: EvaluationToken, store: any RateAtFinalizationClaimStore,
                                                 terminalResult: Data, receiptBody: Data,
                                                 timeout: Duration? = nil) async throws -> Bool {
        let reply = try await onWorker(timeout: timeout) { cancel throws(RatifyError) in
            try ffi { try ffiFinalizeClaimProofBundleBarrier(token: token.handle, store: ClaimStoreBridge(store),
                cancel: cancel, terminalResult: terminalResult, receiptBody: receiptBody) }
        }
        if let failure = reply.failure { throw ReferenceStoreBridge.error(failure) }
        guard let finalized = reply.finalized else { throw RatifyError.internal(.panic, message: "missing finalization result") }
        return finalized
    }
}
