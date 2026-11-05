package com.ratifyprotocol.testing

import com.ratifyprotocol.ApprovalLedgerBridge
import com.ratifyprotocol.ApprovalReplyBridge
import com.ratifyprotocol.HybridPublicKey
import com.ratifyprotocol.ReleasedDecision

/** Result of one reference approval ledger operation. */
public class ApprovalReply internal constructor(value: ApprovalReplyBridge) {
    public val complete: Boolean? = value.complete
    public val failure: String? = value.failure
}

/** In-memory dual-root application ledger for conformance tests. */
public class ApprovalLedger {
    private val bridge = ApprovalLedgerBridge()

    public fun open(id: String, verifierId: String, workspaceId: String, sessionId: String,
        agentKey: HybridPublicKey, requiredScope: String, requestHash: ByteArray,
        rootA: HybridPublicKey, rootB: HybridPublicKey): ApprovalReply = ApprovalReply(
        bridge.open(id, verifierId, workspaceId, sessionId, agentKey, requiredScope,
            requestHash, rootA, rootB))

    public fun record(id: String, slot: UInt, decision: ReleasedDecision?, bundle: ByteArray): ApprovalReply =
        ApprovalReply(bridge.record(id, slot, decision, bundle))

    public fun execute(id: String, clock: Store): ApprovalReply = ApprovalReply(bridge.execute(id, clock.bridge))
}
