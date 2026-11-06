import Foundation

public enum ReleaseStatus: String, Sendable { case released, pending, withheld, rejected }

public struct ReleaseRecord: Sendable {
    public let claimId: String
    public let entryHash: Data
    public let ackTimestamp: Int64
    public let outcome: ReleaseStatus
    public let reason: String
    public init(claimId: String, entryHash: Data, ackTimestamp: Int64, outcome: ReleaseStatus, reason: String) {
        self.claimId = claimId; self.entryHash = entryHash; self.ackTimestamp = ackTimestamp
        self.outcome = outcome; self.reason = reason
    }
    init(_ f: FfiReleaseRecord) {
        self.init(claimId: f.claimId, entryHash: f.entryHash, ackTimestamp: f.ackTimestamp,
            outcome: ReleaseStatus(rawValue: f.outcome)!, reason: f.reason)
    }
    var ffi: FfiReleaseRecord { FfiReleaseRecord(claimId: claimId, entryHash: entryHash,
        ackTimestamp: ackTimestamp, outcome: outcome.rawValue, reason: reason) }
}

public struct TerminalClaimRecord: Sendable {
    public let terminal: Bool
    public let receiptOutboxDigest: String
    public let challengeExpiresAt: Int64
    public let allowHorizon: Int64
    public let finalizedAt: Int64
    public let receiptAbandoned: Bool
    public let release: ReleaseRecord?
    public init(terminal: Bool, receiptOutboxDigest: String, challengeExpiresAt: Int64,
                allowHorizon: Int64, finalizedAt: Int64, receiptAbandoned: Bool, release: ReleaseRecord?) {
        self.terminal = terminal; self.receiptOutboxDigest = receiptOutboxDigest
        self.challengeExpiresAt = challengeExpiresAt; self.allowHorizon = allowHorizon
        self.finalizedAt = finalizedAt; self.receiptAbandoned = receiptAbandoned; self.release = release
    }
    init(_ f: FfiTerminalClaimRecord) {
        self.init(terminal: f.terminal, receiptOutboxDigest: f.receiptOutboxDigest,
            challengeExpiresAt: f.challengeExpiresAt, allowHorizon: f.allowHorizon,
            finalizedAt: f.finalizedAt, receiptAbandoned: f.receiptAbandoned,
            release: f.release.map(ReleaseRecord.init))
    }
    var ffi: FfiTerminalClaimRecord { FfiTerminalClaimRecord(terminal: terminal,
        receiptOutboxDigest: receiptOutboxDigest, challengeExpiresAt: challengeExpiresAt,
        allowHorizon: allowHorizon, finalizedAt: finalizedAt,
        receiptAbandoned: receiptAbandoned, release: release?.ffi) }
}

public struct CheckpointAcknowledgement: Sendable {
    public let logId: String
    public let sequence: Int64
    public let entryHash: Data
    public let timestamp: Int64
    public init(logId: String, sequence: Int64, entryHash: Data, timestamp: Int64) {
        self.logId = logId; self.sequence = sequence; self.entryHash = entryHash; self.timestamp = timestamp
    }
    init(_ f: FfiCheckpointAcknowledgement) {
        self.init(logId: f.logId, sequence: f.sequence, entryHash: f.entryHash, timestamp: f.timestamp)
    }
    var ffi: FfiCheckpointAcknowledgement { FfiCheckpointAcknowledgement(logId: logId,
        sequence: sequence, entryHash: entryHash, timestamp: timestamp) }
}

extension Ratify {
    /// Canonical wire form of an independent checkpoint acknowledgement.
    public static func encodeCheckpointAcknowledgement(_ ack: CheckpointAcknowledgement) throws(RatifyError) -> Data {
        try ffi { try ffiEncodeCheckpointAcknowledgement(ack: ack.ffi) }
    }

    /// Strictly decodes only the canonical acknowledgement wire form.
    public static func decodeCheckpointAcknowledgement(_ data: Data) throws(RatifyError) -> CheckpointAcknowledgement {
        try CheckpointAcknowledgement(ffi { try ffiDecodeCheckpointAcknowledgement(data: data) })
    }
}

/// Durable terminal state and first-write-wins release record for the same claim store used by verification.
public protocol ReleaseClaimStore: AuthoritativeClock {
    func loadTerminal(claimId: String) async throws -> TerminalClaimRecord
    func recordRelease(_ record: ReleaseRecord) async throws
}

/// An independently anchored checkpoint, separate from the receipt log.
public protocol ReceiptCheckpoint: Sendable {
    func acknowledge(logId: String, sequence: Int64, previousEntryHash: Data,
                     entryHash: Data) async throws -> CheckpointAcknowledgement
    func get(logId: String, sequence: Int64) async throws -> CheckpointAcknowledgement
}

/// Signs and appends the exact committed body once, returning signed receipt wire.
public protocol ReceiptPublisher: Sendable {
    func publish(claimId: String, receiptBody: Data) async throws -> Data
}

final class ReleaseStoreBridge: FfiReleaseClaimStore, @unchecked Sendable {
    private let store: any ReleaseClaimStore
    init(_ store: any ReleaseClaimStore) { self.store = store }
    func authoritativeTime(context: FfiStoreContext) throws -> Int64 {
        do { return try callbackWait(context: context) { try await self.store.authoritativeTime() } }
        catch { throw claimStoreError(error, context: context) }
    }
    func loadTerminal(claimId: String, context: FfiStoreContext) throws -> FfiTerminalClaimRecord {
        do { return try callbackWait(context: context) { try await self.store.loadTerminal(claimId: claimId).ffi } }
        catch { throw claimStoreError(error, context: context) }
    }
    func recordRelease(record: FfiReleaseRecord, context: FfiStoreContext) throws {
        do { try callbackWait(context: context) { try await self.store.recordRelease(ReleaseRecord(record)) } }
        catch { throw claimStoreError(error, context: context) }
    }
}

final class CheckpointBridge: FfiReceiptCheckpoint, @unchecked Sendable {
    private let checkpoint: any ReceiptCheckpoint
    init(_ checkpoint: any ReceiptCheckpoint) { self.checkpoint = checkpoint }
    func acknowledge(logId: String, sequence: Int64, previousEntryHash: Data, entryHash: Data,
                     context: FfiStoreContext) throws -> FfiCheckpointAcknowledgement {
        do { return try callbackWait(context: context) { try await self.checkpoint.acknowledge(
            logId: logId, sequence: sequence, previousEntryHash: previousEntryHash, entryHash: entryHash).ffi } }
        catch { throw claimStoreError(error, context: context) }
    }
    func get(logId: String, sequence: Int64, context: FfiStoreContext) throws -> FfiCheckpointAcknowledgement {
        do { return try callbackWait(context: context) { try await self.checkpoint.get(logId: logId, sequence: sequence).ffi } }
        catch { throw claimStoreError(error, context: context) }
    }
}

final class PublisherBridge: FfiReceiptPublisher, @unchecked Sendable {
    private let publisher: any ReceiptPublisher
    init(_ publisher: any ReceiptPublisher) { self.publisher = publisher }
    func publish(claimId: String, receiptBody: Data, context: FfiStoreContext) throws -> Data {
        do { return try callbackWait(context: context) { try await self.publisher.publish(
            claimId: claimId, receiptBody: receiptBody) } }
        catch { throw claimStoreError(error, context: context) }
    }
}

/// Created only by the core release gate. Read `isAllowed` immediately before a side effect.
public final class ReleasedDecision: @unchecked Sendable {
    let handle: FfiReleasedDecision
    public let claimId: String
    /// Receipt decision only; use `isAllowed` immediately before a side effect.
    public let decision: String
    public let reason: String
    public let identityStatus: String
    public let grantedScope: [String]
    public let receiptWire: Data
    public let releaseTime: Int64
    public let challengeExpiresAt: Int64
    public let allowHorizon: Int64?
    fileprivate init(_ handle: FfiReleasedDecision) throws(RatifyError) {
        self.handle = handle
        claimId = try ffi { try handle.claimId() }
        decision = try ffi { try handle.decision() }
        reason = try ffi { try handle.reason() }
        identityStatus = try ffi { try handle.identityStatus() }
        grantedScope = try ffi { try handle.grantedScope() }
        receiptWire = try ffi { try handle.receiptWire() }
        releaseTime = try ffi { try handle.releaseTime() }
        challengeExpiresAt = try ffi { try handle.challengeExpiresAt() }
        allowHorizon = try ffi { try handle.allowHorizon() }
    }
    public func receipt() throws(RatifyError) -> VerificationReceipt {
        VerificationReceipt(try ffi { try handle.receipt() })
    }
    public func isAllowed(clock: any AuthoritativeClock, timeout: Duration? = nil) async throws(RatifyError) -> Bool {
        try await onWorker(timeout: timeout) { token throws(RatifyError) in
            try ffi { try self.handle.allowed(clock: ClockBridge(clock), token: token) }
        }
    }
}

public struct ReleaseResult: Sendable {
    public let status: ReleaseStatus
    public let reason: String
    public let decision: ReleasedDecision?
    init(_ f: FfiReleaseResult) throws(RatifyError) {
        status = ReleaseStatus(rawValue: f.status)!
        reason = f.reason
        decision = try f.decision.map(ReleasedDecision.init)
    }
}

extension Ratify {
    public static func receiptOutboxDigest(_ body: Data) throws(RatifyError) -> String {
        try ffi { try ffiReceiptOutboxDigest(body: body) }
    }

    public static func validReleaseRecordOutcome(_ outcome: ReleaseStatus, reason: String) throws(RatifyError) -> Bool {
        try ffi { try ffiValidReleaseRecordOutcome(outcome: outcome.rawValue, reason: reason) }
    }

    public static func publishReceipt(_ committed: CommittedOutcome, using publisher: any ReceiptPublisher,
                                      timeout: Duration? = nil) async throws(RatifyError) -> Data {
        try await onWorker(timeout: timeout) { token throws(RatifyError) in
            try ffi { try ffiPublishReceipt(publisher: PublisherBridge(publisher), claimId: committed.claimId,
                receiptBody: committed.receiptBody, token: token) }
        }
    }

    public static func releaseDecision(_ committed: CommittedOutcome, signedReceipt: Data?,
                                       verifierPublicKey: HybridPublicKey, logId: String,
                                       claimStore: any ReleaseClaimStore, checkpoint: any ReceiptCheckpoint,
                                       timeout: Duration? = nil) async throws(RatifyError) -> ReleaseResult {
        try await onWorker(timeout: timeout) { token throws(RatifyError) in
            try ReleaseResult(ffi { try ffiReleaseDecision(committed: committed.handle, signedReceipt: signedReceipt,
                verifierPublicKey: verifierPublicKey.ffi, logId: logId,
                claimStore: ReleaseStoreBridge(claimStore), checkpoint: CheckpointBridge(checkpoint), token: token) })
        }
    }
}
