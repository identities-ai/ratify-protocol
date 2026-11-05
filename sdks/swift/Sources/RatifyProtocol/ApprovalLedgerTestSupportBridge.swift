import Foundation

/// Internal bridge for the separately packaged reference approval ledger.
@_spi(TestSupport) public struct ApprovalReplyBridge: Sendable {
    public let complete: Bool?
    public let failure: String?
    init(_ value: FfiApprovalReply) {
        complete = value.complete
        failure = value.failure
    }
}

@_spi(TestSupport) public final class ApprovalLedgerBridge: Sendable {
    private let handle: FfiApprovalLedger

    public init() throws(RatifyError) { handle = try ffi { try FfiApprovalLedger() } }

    public func open(id: String, verifierId: String, workspaceId: String, sessionId: String,
                     agentKey: HybridPublicKey, requiredScope: String, requestHash: Data,
                     rootA: HybridPublicKey, rootB: HybridPublicKey) throws(RatifyError) -> ApprovalReplyBridge {
        let set = FfiApprovalSet(approvalSetId: id, verifierId: verifierId, workspaceId: workspaceId,
            sessionId: sessionId, agentPublicKey: agentKey.ffi, requiredScope: requiredScope,
            requestHash: requestHash, rootA: rootA.ffi, rootB: rootB.ffi)
        return ApprovalReplyBridge(try ffi { try handle.open(set: set) })
    }

    public func record(id: String, slot: UInt32, decision: ReleasedDecision?,
                       bundle: Data) throws(RatifyError) -> ApprovalReplyBridge {
        ApprovalReplyBridge(try ffi { try handle.record(setId: id, slot: slot,
            decision: decision?.handle, bundleWire: bundle) })
    }

    public func execute(id: String, clock: ReferenceStoreBridge) throws(RatifyError) -> ApprovalReplyBridge {
        ApprovalReplyBridge(try ffi { try handle.execute(setId: id, clock: clock.handle) })
    }
}
