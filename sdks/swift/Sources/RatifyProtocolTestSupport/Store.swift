import Foundation
@_spi(TestSupport) import RatifyProtocol

/// Rust Part B reference store for conformance tests.
public final class Store: ClaimStore, CommittedClaimStore, ReleaseClaimStore, ReceiptPublisher, ReceiptCheckpoint {
    private let bridge: ReferenceStoreBridge

    public init(now: Int64, leaseSeconds: Int64, logId: String, verifierKey: SoftwarePrivateKey) throws(RatifyError) {
        bridge = try ReferenceStoreBridge(now: now, leaseSeconds: leaseSeconds, logId: logId, verifierKey: verifierKey)
    }

    private init(_ bridge: ReferenceStoreBridge) { self.bridge = bridge }

    public func cloneStore() throws(RatifyError) -> Store { try Store(bridge.cloneStore()) }
    /// Enables rate admission on this store and returns its verifier capability view.
    public func withRateAtFinalization() throws(RatifyError) -> RateStore {
        try bridge.enableRateAtFinalization()
        return RateStore(self)
    }
    public func setTime(_ now: Int64) throws(RatifyError) { try bridge.setTime(now) }
    public func now() throws(RatifyError) -> Int64 { try bridge.now() }
    public func setSignerFailure(_ failing: Bool) throws(RatifyError) { try bridge.setSignerFailure(failing) }
    public func setAcknowledgementWithheld(_ withheld: Bool) throws(RatifyError) { try bridge.setAcknowledgementWithheld(withheld) }
    public func logLength() throws(RatifyError) -> UInt64 { try bridge.logLength() }
    public func plantReleaseTestOnly(claimId: String, ackTimestamp: Int64) throws(RatifyError) {
        try bridge.plantReleaseTestOnly(claimId: claimId, ackTimestamp: ackTimestamp)
    }
    public func abandonPendingReceipts() throws(RatifyError) -> [String] { try bridge.abandonPendingReceipts() }

    public func authoritativeTime() async throws -> Int64 { try bridge.authoritativeTime() }
    public func claim(_ claim: ChallengeClaim) async throws -> ClaimResult { try bridge.claim(claim) }
    public func finalize(claimId: String, ownerToken: Data, terminalResult: Data, receiptBody: Data,
                         allowValidUntil: Int64) async throws -> Bool {
        try bridge.finalize(claimId: claimId, ownerToken: ownerToken, terminalResult: terminalResult,
            receiptBody: receiptBody, allowValidUntil: allowValidUntil)
    }
    public func recordProgress(claimId: String, ownerToken: Data, progress: EvaluationProgress) async throws {
        try bridge.recordProgress(claimId: claimId, ownerToken: ownerToken, progress: progress)
    }
    public func loadInterrupted(claimId: String) async throws -> InterruptedClaim { try bridge.loadInterrupted(claimId: claimId) }
    public func recoverInterrupted(claimId: String, terminalResult: Data, receiptBody: Data) async throws -> Bool {
        try bridge.recoverInterrupted(claimId: claimId, terminalResult: terminalResult, receiptBody: receiptBody)
    }

    public func loadCommitted(claimId: String) async throws -> CommittedClaim { try bridge.loadCommitted(claimId: claimId) }
    public func loadTerminal(claimId: String) async throws -> TerminalClaimRecord { try bridge.loadTerminal(claimId: claimId) }
    public func recordRelease(_ record: ReleaseRecord) async throws { try bridge.recordRelease(record) }
    public func publish(claimId: String, receiptBody: Data) async throws -> Data {
        try bridge.publish(claimId: claimId, receiptBody: receiptBody)
    }
    public func acknowledge(logId: String, sequence: Int64, previousEntryHash: Data,
                            entryHash: Data) async throws -> CheckpointAcknowledgement {
        try bridge.acknowledge(logId: logId, sequence: sequence, previousEntryHash: previousEntryHash, entryHash: entryHash)
    }
    public func get(logId: String, sequence: Int64) async throws -> CheckpointAcknowledgement {
        try bridge.get(logId: logId, sequence: sequence)
    }
}

/// The same reference store with atomic rate admission during finalization.
public struct RateStore: RateAtFinalizationClaimStore {
    private let store: Store
    fileprivate init(_ store: Store) { self.store = store }
    public func authoritativeTime() async throws -> Int64 { try await store.authoritativeTime() }
    public func claim(_ claim: ChallengeClaim) async throws -> ClaimResult { try await store.claim(claim) }
    public func finalize(claimId: String, ownerToken: Data, terminalResult: Data, receiptBody: Data,
                         allowValidUntil: Int64) async throws -> Bool {
        try await store.finalize(claimId: claimId, ownerToken: ownerToken, terminalResult: terminalResult,
            receiptBody: receiptBody, allowValidUntil: allowValidUntil)
    }
    public func recordProgress(claimId: String, ownerToken: Data, progress: EvaluationProgress) async throws {
        try await store.recordProgress(claimId: claimId, ownerToken: ownerToken, progress: progress)
    }
    public func loadInterrupted(claimId: String) async throws -> InterruptedClaim {
        try await store.loadInterrupted(claimId: claimId)
    }
    public func recoverInterrupted(claimId: String, terminalResult: Data, receiptBody: Data) async throws -> Bool {
        try await store.recoverInterrupted(claimId: claimId, terminalResult: terminalResult, receiptBody: receiptBody)
    }
}
