import Foundation

/// Internal bridge for the separately packaged reference store.
@_spi(TestSupport) public final class ReferenceStoreBridge: Sendable {
    private let handle: FfiReferenceStore

    public init(now: Int64, leaseSeconds: Int64, logId: String, verifierKey: SoftwarePrivateKey) throws(RatifyError) {
        handle = try ffi { try FfiReferenceStore(now: now, leaseSeconds: leaseSeconds, logId: logId, verifierKey: verifierKey.handle) }
    }

    private init(_ handle: FfiReferenceStore) { self.handle = handle }

    public func cloneStore() throws(RatifyError) -> ReferenceStoreBridge {
        try ReferenceStoreBridge(ffi { try handle.cloneStore() })
    }

    public func setTime(_ now: Int64) throws(RatifyError) { try ffi { try handle.setTime(now: now) } }
    public func now() throws(RatifyError) -> Int64 { try ffi { try handle.now() } }
    public func setSignerFailure(_ failing: Bool) throws(RatifyError) { try ffi { try handle.setSignerFailure(failing: failing) } }
    public func setAcknowledgementWithheld(_ withheld: Bool) throws(RatifyError) { try ffi { try handle.setAcknowledgementWithheld(withheld: withheld) } }
    public func logLength() throws(RatifyError) -> UInt64 { try ffi { try handle.logLength() } }
    public func plantReleaseTestOnly(claimId: String, ackTimestamp: Int64) throws(RatifyError) {
        try ffi { try handle.plantReleaseTestOnly(claimId: claimId, ackTimestamp: ackTimestamp) }
    }
    public func abandonPendingReceipts() throws(RatifyError) -> [String] { try ffi { try handle.abandonPendingReceipts() } }

    private func check(_ reply: FfiReferenceStoreReply) throws {
        guard let failure = reply.failure else { return }
        switch failure.kind {
        case "classified":
            guard let cls = ErrorClass(rawValue: failure.`class`) else {
                throw RatifyError.internal(.panic, message: "unknown reference store error class")
            }
            throw StoreError.classified(cls, detail: failure.detail)
        case "unavailable": throw StoreError.unavailable(failure.detail)
        case "claim_proof_conflict": throw StoreError.claimProofConflict
        case "rate_limit_exceeded": throw StoreError.rateLimitExceeded
        case "release_state_mismatch": throw StoreError.releaseStateMismatch
        case "acknowledgement_not_found": throw StoreError.acknowledgementNotFound
        case "challenge_issuance_conflict": throw StoreError.challengeIssuanceConflict
        case "challenge_issuance_not_found": throw StoreError.challengeIssuanceNotFound
        default: throw RatifyError.internal(.panic, message: "unknown reference store failure kind")
        }
    }

    private func value<T>(_ reply: FfiReferenceStoreReply, _ field: KeyPath<FfiReferenceStoreReply, T?>) throws -> T {
        try check(reply)
        guard let value = reply[keyPath: field] else {
            throw RatifyError.internal(.panic, message: "reference store omitted a success value")
        }
        return value
    }

    public func authoritativeTime() throws -> Int64 {
        try value(ffi { try handle.authoritativeTime() }, \.time)
    }
    public func claim(_ claim: ChallengeClaim) throws -> ClaimResult {
        ClaimResult(try value(ffi { try handle.claim(claim: claim.ffi) }, \.claim))
    }
    public func finalize(claimId: String, ownerToken: Data, terminalResult: Data, receiptBody: Data,
                         allowValidUntil: Int64) throws -> Bool {
        try value(ffi { try handle.finalize(claimId: claimId, ownerToken: ownerToken,
            terminalResult: terminalResult, receiptBody: receiptBody, allowValidUntil: allowValidUntil) }, \.boolean)
    }
    public func recordProgress(claimId: String, ownerToken: Data, progress: EvaluationProgress) throws {
        try check(ffi { try handle.recordProgress(claimId: claimId, ownerToken: ownerToken, progress: progress.ffi) })
    }
    public func loadInterrupted(claimId: String) throws -> InterruptedClaim {
        InterruptedClaim(try value(ffi { try handle.loadInterrupted(claimId: claimId) }, \.interrupted))
    }
    public func recoverInterrupted(claimId: String, terminalResult: Data, receiptBody: Data) throws -> Bool {
        try value(ffi { try handle.recoverInterrupted(claimId: claimId, terminalResult: terminalResult,
            receiptBody: receiptBody) }, \.boolean)
    }
}
