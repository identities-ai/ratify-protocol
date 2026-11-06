package com.ratifyprotocol

import androidx.annotation.RestrictTo
import com.ratifyprotocol.internal.ffi.FfiApprovalLedger
import com.ratifyprotocol.internal.ffi.FfiApprovalReply
import com.ratifyprotocol.internal.ffi.FfiApprovalSet

/** Bridge for the separate testing artifact. */
@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class ApprovalReplyBridge internal constructor(value: FfiApprovalReply) {
    public val complete: Boolean? = value.complete
    public val failure: String? = value.failure
}

/** Bridge for the separate testing artifact. */
@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class ApprovalLedgerBridge {
    private val handle = ffi { FfiApprovalLedger() }

    public fun open(id: String, verifierId: String, workspaceId: String, sessionId: String,
        agentKey: HybridPublicKey, requiredScope: String, requestHash: ByteArray,
        rootA: HybridPublicKey, rootB: HybridPublicKey): ApprovalReplyBridge {
        val set = FfiApprovalSet(id, verifierId, workspaceId, sessionId, agentKey.toFfi(),
            requiredScope, requestHash, rootA.toFfi(), rootB.toFfi())
        return ApprovalReplyBridge(ffi { handle.open(set) })
    }

    public fun record(id: String, slot: UInt, decision: ReleasedDecision?,
        bundle: ByteArray): ApprovalReplyBridge = ApprovalReplyBridge(ffi {
        handle.record(id, slot, decision?.handle, bundle)
    })

    public fun execute(id: String, clock: ReferenceStoreBridge): ApprovalReplyBridge =
        ApprovalReplyBridge(ffi { handle.execute(id, clock.handle) })
}
