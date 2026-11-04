import Foundation

/// One signed rolling-window counter sealed into a claim.
public struct RateReservation: Sendable, Hashable {
    public let issuerId: String
    public let certId: String
    public let windowSeconds: Int64
    public let limit: Int64
    public init(issuerId: String, certId: String, windowSeconds: Int64, limit: Int64) {
        self.issuerId = issuerId; self.certId = certId; self.windowSeconds = windowSeconds; self.limit = limit
    }
    init(_ f: FfiRateReservation) { self.init(issuerId: f.issuerId, certId: f.certId, windowSeconds: f.windowS, limit: f.limit) }
    var ffi: FfiRateReservation { FfiRateReservation(issuerId: issuerId, certId: certId, windowS: windowSeconds, limit: limit) }
}

/// Immutable values the claim store must compare on every replay.
public struct ChallengeClaim: Sendable, Hashable {
    public let claimId: String
    public let namespace: String
    public let replayEpoch: Int64
    public let challengeDigest: String
    public let proofDigest: String
    public let bundleHash: String
    public let issuerIds: [String]
    public let requiredScope: String
    public let contextPolicyDigest: String
    public let verifierId: String
    public let agentId: String
    public let requiresRate: Bool
    public let rateBatch: [RateReservation]
    public let issuedAt: Int64
    public let expiresAt: Int64
    public let maxAgeSeconds: Int64
    public let clockSkewSeconds: Int64
    public let streamId: Data?
    public let streamSeq: Int64?
    public let constraintEvaluators: [ConstraintEvaluatorRef]

    public init(claimId: String, namespace: String, replayEpoch: Int64, challengeDigest: String,
                proofDigest: String, bundleHash: String, issuerIds: [String], requiredScope: String,
                contextPolicyDigest: String, verifierId: String, agentId: String, requiresRate: Bool,
                rateBatch: [RateReservation], issuedAt: Int64, expiresAt: Int64, maxAgeSeconds: Int64,
                clockSkewSeconds: Int64, streamId: Data?, streamSeq: Int64?,
                constraintEvaluators: [ConstraintEvaluatorRef]) {
        self.claimId = claimId; self.namespace = namespace; self.replayEpoch = replayEpoch
        self.challengeDigest = challengeDigest; self.proofDigest = proofDigest; self.bundleHash = bundleHash
        self.issuerIds = issuerIds; self.requiredScope = requiredScope; self.contextPolicyDigest = contextPolicyDigest
        self.verifierId = verifierId; self.agentId = agentId; self.requiresRate = requiresRate
        self.rateBatch = rateBatch; self.issuedAt = issuedAt; self.expiresAt = expiresAt
        self.maxAgeSeconds = maxAgeSeconds; self.clockSkewSeconds = clockSkewSeconds
        self.streamId = streamId; self.streamSeq = streamSeq; self.constraintEvaluators = constraintEvaluators
    }

    init(_ f: FfiChallengeClaim) {
        self.init(claimId: f.claimId, namespace: f.namespace, replayEpoch: f.replayEpoch,
            challengeDigest: f.challengeDigest, proofDigest: f.proofDigest, bundleHash: f.bundleHash,
            issuerIds: f.issuerIds, requiredScope: f.requiredScope, contextPolicyDigest: f.contextPolicyDigest,
            verifierId: f.verifierId, agentId: f.agentId, requiresRate: f.requiresRate,
            rateBatch: f.rateBatch.map(RateReservation.init), issuedAt: f.issuedAt, expiresAt: f.expiresAt,
            maxAgeSeconds: f.maxAgeSeconds, clockSkewSeconds: f.clockSkewSeconds,
            streamId: f.streamId, streamSeq: f.streamSeq,
            constraintEvaluators: f.constraintEvaluators.map(ConstraintEvaluatorRef.init))
    }

    var ffi: FfiChallengeClaim {
        FfiChallengeClaim(claimId: claimId, namespace: namespace, replayEpoch: replayEpoch,
            challengeDigest: challengeDigest, proofDigest: proofDigest, bundleHash: bundleHash,
            issuerIds: issuerIds, requiredScope: requiredScope, contextPolicyDigest: contextPolicyDigest,
            verifierId: verifierId, agentId: agentId, requiresRate: requiresRate,
            rateBatch: rateBatch.map(\.ffi), issuedAt: issuedAt, expiresAt: expiresAt,
            maxAgeSeconds: maxAgeSeconds, clockSkewSeconds: clockSkewSeconds,
            streamId: streamId, streamSeq: streamSeq,
            constraintEvaluators: constraintEvaluators.map(\.ffi))
    }
}

public enum ClaimDisposition: String, Sendable {
    case created = "created"
    case inProgress = "in_progress"
    case terminalReplay = "terminal_replay"
}

public struct ClaimResult: Sendable {
    public let disposition: ClaimDisposition
    public let claimedAt: Int64
    public let ownerToken: Data
    public init(disposition: ClaimDisposition, claimedAt: Int64, ownerToken: Data) {
        self.disposition = disposition; self.claimedAt = claimedAt; self.ownerToken = ownerToken
    }
    init(_ f: FfiClaimResult) {
        self.init(disposition: ClaimDisposition(f.disposition), claimedAt: f.claimedAt, ownerToken: f.ownerToken)
    }
    var ffi: FfiClaimResult { FfiClaimResult(disposition: disposition.ffi, claimedAt: claimedAt, ownerToken: ownerToken) }
}

extension ClaimDisposition {
    init(_ f: FfiClaimDisposition) {
        switch f {
        case .created: self = .created
        case .inProgress: self = .inProgress
        case .terminalReplay: self = .terminalReplay
        }
    }
    var ffi: FfiClaimDisposition {
        switch self {
        case .created: .created
        case .inProgress: .inProgress
        case .terminalReplay: .terminalReplay
        }
    }
}

public struct EvaluationProgress: Sendable, Hashable {
    public let trustAssessment: String
    public let statusAssessment: String
    public let contextAssessment: String
    public let contextPolicyDigest: String?
    public let statusEvidence: [StatusEvidenceEntry]
    public init(trustAssessment: String, statusAssessment: String, contextAssessment: String,
                contextPolicyDigest: String?, statusEvidence: [StatusEvidenceEntry]) {
        self.trustAssessment = trustAssessment; self.statusAssessment = statusAssessment
        self.contextAssessment = contextAssessment; self.contextPolicyDigest = contextPolicyDigest
        self.statusEvidence = statusEvidence
    }
    init(_ f: FfiEvaluationProgress) {
        self.init(trustAssessment: f.trustAssessment, statusAssessment: f.statusAssessment,
            contextAssessment: f.contextAssessment, contextPolicyDigest: f.contextPolicyDigest,
            statusEvidence: f.statusEvidence.map(StatusEvidenceEntry.init))
    }
    var ffi: FfiEvaluationProgress {
        FfiEvaluationProgress(trustAssessment: trustAssessment, statusAssessment: statusAssessment,
            contextAssessment: contextAssessment, contextPolicyDigest: contextPolicyDigest,
            statusEvidence: statusEvidence.map(\.ffi))
    }
}

public struct InterruptedClaim: Sendable {
    public let claim: ChallengeClaim
    public let claimedAt: Int64
    public let progress: EvaluationProgress
    public init(claim: ChallengeClaim, claimedAt: Int64, progress: EvaluationProgress) {
        self.claim = claim; self.claimedAt = claimedAt; self.progress = progress
    }
    init(_ f: FfiInterruptedClaim) { self.init(claim: ChallengeClaim(f.claim), claimedAt: f.claimedAt, progress: EvaluationProgress(f.progress)) }
    var ffi: FfiInterruptedClaim { FfiInterruptedClaim(claim: claim.ffi, claimedAt: claimedAt, progress: progress.ffi) }
}

public struct CommittedClaim: Sendable {
    public let claim: ChallengeClaim
    public let terminalResult: Data
    public let receiptBody: Data
    public let allowHorizon: Int64
    public init(claim: ChallengeClaim, terminalResult: Data, receiptBody: Data, allowHorizon: Int64) {
        self.claim = claim; self.terminalResult = terminalResult; self.receiptBody = receiptBody; self.allowHorizon = allowHorizon
    }
    init(_ f: FfiCommittedClaim) {
        self.init(claim: ChallengeClaim(f.claim), terminalResult: f.terminalResult,
            receiptBody: f.receiptBody, allowHorizon: f.allowHorizon)
    }
    var ffi: FfiCommittedClaim { FfiCommittedClaim(claim: claim.ffi, terminalResult: terminalResult,
        receiptBody: receiptBody, allowHorizon: allowHorizon) }
}

/// Atomically consumes, progresses, finalizes and recovers claims with one authoritative clock.
public protocol ClaimStore: AuthoritativeClock {
    func claim(_ claim: ChallengeClaim) async throws -> ClaimResult
    func finalize(claimId: String, ownerToken: Data, terminalResult: Data, receiptBody: Data,
                  allowValidUntil: Int64) async throws -> Bool
    func recordProgress(claimId: String, ownerToken: Data, progress: EvaluationProgress) async throws
    func loadInterrupted(claimId: String) async throws -> InterruptedClaim
    func recoverInterrupted(claimId: String, terminalResult: Data, receiptBody: Data) async throws -> Bool
}

/// Loads the exact terminal record for a lost committed handoff.
public protocol CommittedClaimStore: Sendable {
    func loadCommitted(claimId: String) async throws -> CommittedClaim
}

/// Reserves a sealed batch as one durable, all-or-nothing operation.
public protocol RateReservationStore: Sendable {
    func reserve(claimId: String, ownerToken: Data, bundleHash: String,
                 batch: [RateReservation]) async throws
}

private func claimStoreError(_ error: Error, context: FfiStoreContext) -> FfiStoreError {
    if error is CancellationError, (try? context.isCancelled()) == true { return .Cancelled }
    return (error as? StoreError)?.ffi ?? .Unavailable(detail: "\(error)")
}

final class ClaimStoreBridge: FfiClaimStore, @unchecked Sendable {
    private let store: any ClaimStore
    init(_ store: any ClaimStore) { self.store = store }

    func authoritativeTime(context: FfiStoreContext) throws -> Int64 {
        do { return try callbackWait(context: context) { try await self.store.authoritativeTime() } }
        catch { throw claimStoreError(error, context: context) }
    }
    func claim(claim: FfiChallengeClaim, context: FfiStoreContext) throws -> FfiClaimResult {
        do { return try callbackWait(context: context) { try await self.store.claim(ChallengeClaim(claim)).ffi } }
        catch { throw claimStoreError(error, context: context) }
    }
    func finalize(claimId: String, ownerToken: Data, terminalResult: Data, receiptBody: Data,
                  allowValidUntil: Int64, context: FfiStoreContext) throws -> Bool {
        do { return try callbackWait(context: context) {
            try await self.store.finalize(claimId: claimId, ownerToken: ownerToken, terminalResult: terminalResult,
                receiptBody: receiptBody, allowValidUntil: allowValidUntil)
        } } catch { throw claimStoreError(error, context: context) }
    }
    func recordProgress(claimId: String, ownerToken: Data, progress: FfiEvaluationProgress,
                        context: FfiStoreContext) throws {
        do { try callbackWait(context: context) {
            try await self.store.recordProgress(claimId: claimId, ownerToken: ownerToken,
                progress: EvaluationProgress(progress))
        } } catch { throw claimStoreError(error, context: context) }
    }
    func loadInterrupted(claimId: String, context: FfiStoreContext) throws -> FfiInterruptedClaim {
        do { return try callbackWait(context: context) { try await self.store.loadInterrupted(claimId: claimId).ffi } }
        catch { throw claimStoreError(error, context: context) }
    }
    func recoverInterrupted(claimId: String, terminalResult: Data, receiptBody: Data,
                            context: FfiStoreContext) throws -> Bool {
        do { return try callbackWait(context: context) {
            try await self.store.recoverInterrupted(claimId: claimId, terminalResult: terminalResult,
                receiptBody: receiptBody)
        } } catch { throw claimStoreError(error, context: context) }
    }
}

final class CommittedClaimStoreBridge: FfiCommittedClaimStore, @unchecked Sendable {
    private let store: any CommittedClaimStore
    init(_ store: any CommittedClaimStore) { self.store = store }
    func loadCommitted(claimId: String, context: FfiStoreContext) throws -> FfiCommittedClaim {
        do { return try callbackWait(context: context) { try await self.store.loadCommitted(claimId: claimId).ffi } }
        catch { throw claimStoreError(error, context: context) }
    }
}

final class RateReservationStoreBridge: FfiRateReservationStore, @unchecked Sendable {
    private let store: any RateReservationStore
    init(_ store: any RateReservationStore) { self.store = store }
    func reserve(claimId: String, ownerToken: Data, bundleHash: String,
                 batch: [FfiRateReservation], context: FfiStoreContext) throws {
        do { try callbackWait(context: context) {
            try await self.store.reserve(claimId: claimId, ownerToken: ownerToken,
                bundleHash: bundleHash, batch: batch.map(RateReservation.init))
        } } catch { throw claimStoreError(error, context: context) }
    }
}

/// A committed handoff is not actionable; only a released decision can authorize work.
public final class CommittedOutcome: @unchecked Sendable {
    let handle: FfiCommittedOutcome
    public let claimId: String
    public let receiptBody: Data
    public let receiptBodyDigest: String
    public let challengeExpiresAt: Int64
    public let allowHorizon: Int64?

    init(_ handle: FfiCommittedOutcome) throws(RatifyError) {
        self.handle = handle
        claimId = try ffi { try handle.claimId() }
        receiptBody = try ffi { try handle.receiptBody() }
        receiptBodyDigest = try ffi { try handle.receiptBodyDigest() }
        challengeExpiresAt = try ffi { try handle.challengeExpiresAt() }
        allowHorizon = try ffi { try handle.allowHorizon() }
    }
}

extension Ratify {
    public static func resumeCommittedClaim(store: any CommittedClaimStore, claimId: String,
                                             timeout: Duration? = nil) async throws(RatifyError) -> CommittedOutcome {
        try await onWorker(timeout: timeout) { token throws(RatifyError) in
            try CommittedOutcome(ffi { try ffiResumeCommittedClaim(store: CommittedClaimStoreBridge(store),
                token: token, claimId: claimId) })
        }
    }
}
