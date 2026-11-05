import Foundation
@_spi(TestSupport) import RatifyProtocol

/// Result of one reference approval ledger operation.
public struct ApprovalReply: Sendable {
    public let complete: Bool?
    public let failure: String?
    init(_ value: ApprovalReplyBridge) {
        complete = value.complete
        failure = value.failure
    }
}

/// In-memory dual-root application ledger for conformance tests.
public final class ApprovalLedger: Sendable {
    private let bridge: ApprovalLedgerBridge
    public init() throws(RatifyError) { bridge = try ApprovalLedgerBridge() }

    public func open(id: String, verifierId: String, workspaceId: String, sessionId: String,
                     agentKey: HybridPublicKey, requiredScope: String, requestHash: Data,
                     rootA: HybridPublicKey, rootB: HybridPublicKey) throws(RatifyError) -> ApprovalReply {
        ApprovalReply(try bridge.open(id: id, verifierId: verifierId, workspaceId: workspaceId,
            sessionId: sessionId, agentKey: agentKey, requiredScope: requiredScope,
            requestHash: requestHash, rootA: rootA, rootB: rootB))
    }

    public func record(id: String, slot: UInt32, decision: ReleasedDecision?,
                       bundle: Data) throws(RatifyError) -> ApprovalReply {
        ApprovalReply(try bridge.record(id: id, slot: slot, decision: decision, bundle: bundle))
    }

    public func execute(id: String, clock: Store) throws(RatifyError) -> ApprovalReply {
        ApprovalReply(try bridge.execute(id: id, clock: clock.bridge))
    }
}
