import Foundation

public struct StatusKeyConfig: Sendable {
    public let epoch: UInt64
    public let key: HybridPublicKey
    public init(epoch: UInt64, key: HybridPublicKey) { self.epoch = epoch; self.key = key }
    var ffi: FfiStatusKeyConfig { FfiStatusKeyConfig(epoch: epoch, key: key.ffi) }
}

/// Inputs authenticated by the verifier before any claim or provider callback.
public struct VerifyRequest: Sendable {
    public let bundle: Data
    public let expected: ExpectedChallenge?
    public let contextPolicy: ContextPolicy?
    public let requiredScope: String
    public let verifierNamespace: String
    public let replayEpoch: Int64
    public let verifierId: String
    public let now: Int64
    public let maxChallengeAgeSeconds: Int64
    public let futureSkewSeconds: Int64
    public let context: ConstraintContext
    public let tzdbVersion: String
    public let statusKeys: [String: StatusKeyConfig]
    public let statusPolicy: RevocationStatusPolicy
    public let constraintEvaluators: ConstraintEvaluatorRegistry?

    public init(bundle: Data, expected: ExpectedChallenge?, contextPolicy: ContextPolicy?,
                requiredScope: String, verifierNamespace: String, replayEpoch: Int64,
                verifierId: String, now: Int64, maxChallengeAgeSeconds: Int64,
                futureSkewSeconds: Int64, context: ConstraintContext, tzdbVersion: String,
                statusKeys: [String: StatusKeyConfig], statusPolicy: RevocationStatusPolicy,
                constraintEvaluators: ConstraintEvaluatorRegistry? = nil) {
        self.bundle = bundle; self.expected = expected; self.contextPolicy = contextPolicy
        self.requiredScope = requiredScope; self.verifierNamespace = verifierNamespace
        self.replayEpoch = replayEpoch; self.verifierId = verifierId; self.now = now
        self.maxChallengeAgeSeconds = maxChallengeAgeSeconds; self.futureSkewSeconds = futureSkewSeconds
        self.context = context; self.tzdbVersion = tzdbVersion
        self.statusKeys = statusKeys; self.statusPolicy = statusPolicy
        self.constraintEvaluators = constraintEvaluators
    }

    var ffi: FfiLiveVerifyRequest {
        FfiLiveVerifyRequest(bundle: bundle, expected: expected?.ffi, contextPolicy: contextPolicy?.handle,
            requiredScope: requiredScope, verifierNamespace: verifierNamespace, replayEpoch: replayEpoch,
            verifierId: verifierId, now: now, maxChallengeAgeSeconds: maxChallengeAgeSeconds,
            futureSkewSeconds: futureSkewSeconds, context: context.ffi, tzdbVersion: tzdbVersion,
            statusKeys: statusKeys.mapValues(\.ffi), statusPolicy: statusPolicy.ffi,
            constraintEvaluators: constraintEvaluators?.handle)
    }
}

public enum VerifyStage: String, Sendable {
    case preflight, replay, evaluating, committed
}

/// Inputs for the staged preflight. This checks no receiver hook or extension evaluator.
public struct PreflightRequest: Sendable {
    public let bundle: Data
    public let expected: ExpectedChallenge?
    public let contextPolicy: ContextPolicy?
    public let requiredScope: String
    public let verifierNamespace: String
    public let replayEpoch: Int64
    public let verifierId: String
    public let now: Int64
    public let maxChallengeAgeSeconds: Int64
    public let futureSkewSeconds: Int64

    public init(bundle: Data, expected: ExpectedChallenge?, contextPolicy: ContextPolicy?,
                requiredScope: String, verifierNamespace: String, replayEpoch: Int64,
                verifierId: String, now: Int64, maxChallengeAgeSeconds: Int64,
                futureSkewSeconds: Int64) {
        self.bundle = bundle; self.expected = expected; self.contextPolicy = contextPolicy
        self.requiredScope = requiredScope; self.verifierNamespace = verifierNamespace
        self.replayEpoch = replayEpoch; self.verifierId = verifierId; self.now = now
        self.maxChallengeAgeSeconds = maxChallengeAgeSeconds; self.futureSkewSeconds = futureSkewSeconds
    }

    var ffi: FfiPreflightRequest {
        FfiPreflightRequest(bundle: bundle, expected: expected?.ffi, contextPolicy: contextPolicy?.handle,
            requiredScope: requiredScope, verifierNamespace: verifierNamespace, replayEpoch: replayEpoch,
            verifierId: verifierId, now: now, maxChallengeAgeSeconds: maxChallengeAgeSeconds,
            futureSkewSeconds: futureSkewSeconds)
    }
}

/// Sealed successful preflight state for a later staged claim.
public final class PreflightResult: @unchecked Sendable {
    let handle: FfiPreflightResult
    init(_ handle: FfiPreflightResult) { self.handle = handle }
}

extension Ratify {
    /// Checks proof and challenge bindings without creating a claim.
    public static func preflightProofBundle(_ request: PreflightRequest) throws(RatifyError) -> PreflightResult {
        try PreflightResult(ffi { try ffiPreflightProofBundle(request: request.ffi) })
    }
}

/// A committed result remains non-actionable until release.
public struct VerifyOutcome: Sendable {
    public let stage: VerifyStage
    public let errorClass: ErrorClass?
    public let errorDetail: String?
    public let disposition: ClaimDisposition?
    public let claim: ChallengeClaim
    public let committed: CommittedOutcome?

    init(_ f: FfiLiveVerifyOutcome) throws(RatifyError) {
        stage = VerifyStage(rawValue: f.stage)!
        errorClass = f.errorClass.map(ErrorClass.init(spelling:))
        errorDetail = f.errorDetail
        disposition = f.disposition.map(ClaimDisposition.init)
        claim = ChallengeClaim(f.claim)
        committed = try f.committed.map(CommittedOutcome.init)
    }
}

extension Ratify {
    /// Runs verification with no claim capability. A valid preflight fails
    /// closed before a claim can be created.
    public static func verifyProofBundleWithoutClaimStore(_ request: VerifyRequest,
                                         receiverBinding: (any ReceiverBindingHook)? = nil,
                                         timeout: Duration? = nil) async throws(RatifyError) -> VerifyOutcome {
        try await onWorker(timeout: timeout) { token throws(RatifyError) in
            try VerifyOutcome(ffi { try ffiLiveVerifyProofBundle(request: request.ffi,
                claimStore: nil, receiverBinding: receiverBinding.map(ReceiverBindingBridge.init),
                trust: nil, audience: nil, statusEvidence: nil, statusJournal: nil,
                rate: nil, token: token) })
        }
    }

    public static func verifyProofBundle(_ request: VerifyRequest, claimStore: any RateAtFinalizationClaimStore,
                                         receiverBinding: (any ReceiverBindingHook)? = nil,
                                         trust: (any TrustProvider)? = nil,
                                         audience: (any AudienceProvider)? = nil,
                                         statusEvidence: (any StatusEvidenceProvider)? = nil,
                                         statusJournal: (any SecurityJournalStore)? = nil,
                                         timeout: Duration? = nil) async throws(RatifyError) -> VerifyOutcome {
        try await onWorker(timeout: timeout) { token throws(RatifyError) in
            try VerifyOutcome(ffi { try ffiLiveVerifyProofBundleBarrier(request: request.ffi,
                claimStore: ClaimStoreBridge(claimStore),
                receiverBinding: receiverBinding.map(ReceiverBindingBridge.init),
                trust: trust.map(TrustProviderBridge.init),
                audience: audience.map(AudienceProviderBridge.init),
                statusEvidence: statusEvidence.map(StatusEvidenceProviderBridge.init),
                statusJournal: statusJournal.map(JournalStoreBridge.init), token: token) })
        }
    }

    public static func verifyProofBundle(_ request: VerifyRequest, claimStore: any ClaimStore,
                                         receiverBinding: (any ReceiverBindingHook)? = nil,
                                         trust: (any TrustProvider)? = nil,
                                         audience: (any AudienceProvider)? = nil,
                                         statusEvidence: (any StatusEvidenceProvider)? = nil,
                                         statusJournal: (any SecurityJournalStore)? = nil,
                                         rate: (any RateReservationStore)? = nil,
                                         timeout: Duration? = nil) async throws(RatifyError) -> VerifyOutcome {
        try await onWorker(timeout: timeout) { token throws(RatifyError) in
            try VerifyOutcome(ffi { try ffiLiveVerifyProofBundle(request: request.ffi,
                claimStore: ClaimStoreBridge(claimStore),
                receiverBinding: receiverBinding.map(ReceiverBindingBridge.init),
                trust: trust.map(TrustProviderBridge.init),
                audience: audience.map(AudienceProviderBridge.init),
                statusEvidence: statusEvidence.map(StatusEvidenceProviderBridge.init),
                statusJournal: statusJournal.map(JournalStoreBridge.init),
                rate: rate.map(RateReservationStoreBridge.init), token: token) })
        }
    }
}
