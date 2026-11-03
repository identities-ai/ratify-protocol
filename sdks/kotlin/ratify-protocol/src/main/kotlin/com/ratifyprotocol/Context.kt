package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiContextPolicy
import com.ratifyprotocol.internal.ffi.FfiOperationContext
import com.ratifyprotocol.internal.ffi.FfiSessionContextInputs
import com.ratifyprotocol.internal.ffi.ffiBuildSessionContext
import com.ratifyprotocol.internal.ffi.ffiDecodePayloadDigest
import com.ratifyprotocol.internal.ffi.ffiOperationContextHash
import com.ratifyprotocol.internal.ffi.ffiSessionContextBytes

/** The operation a presentation authorizes (SPEC-v2 operation context). */
public class OperationContext(
    public val requiredScope: String,
    public val operation: String,
    public val resourceId: String,
    public val requestedPath: String,
    payloadDigest: ByteArray = ByteArray(0),
) {
    private val digest = payloadDigest.copyOf()

    /** Empty, or exactly 32 raw SHA-256 bytes. */
    public val payloadDigest: ByteArray get() = digest.copyOf()

    internal fun toFfi(): FfiOperationContext =
        FfiOperationContext(requiredScope, operation, resourceId, requestedPath, digest.copyOf())
}

/** Verifier session and invocation inputs bound to a presentation. */
public class SessionContextInputs(
    public val verifierId: String,
    public val workspaceId: String,
    public val agentId: String,
    public val sessionId: String,
    public val invocationId: String,
    requestHash: ByteArray,
) {
    private val hash = requestHash.copyOf()

    /** Exactly 32 raw bytes from [operationContextHash]. */
    public val requestHash: ByteArray get() = hash.copyOf()

    internal fun toFfi(): FfiSessionContextInputs =
        FfiSessionContextInputs(verifierId, workspaceId, agentId, sessionId, invocationId, hash.copyOf())
}

public fun operationContextHash(context: OperationContext): ByteArray =
    ffi { ffiOperationContextHash(context.toFfi()) }

public fun sessionContextBytes(inputs: SessionContextInputs): ByteArray =
    ffi { ffiSessionContextBytes(inputs.toFfi()) }

public fun buildSessionContext(inputs: SessionContextInputs): ByteArray =
    ffi { ffiBuildSessionContext(inputs.toFfi()) }

/** Decode `sha256:<64 lowercase hex>` into 32 raw bytes; null in, null out. */
public fun decodePayloadDigest(encoded: String?): ByteArray? = ffi { ffiDecodePayloadDigest(encoded) }

/** A validated, fingerprinted context policy. */
public class ContextPolicy(
    profile: String,
    requireBound: Boolean,
    requiredFields: List<String>,
    expectedSessionContext: ByteArray = ByteArray(0),
) {
    private val handle: FfiContextPolicy =
        ffi { FfiContextPolicy(profile, requireBound, requiredFields, expectedSessionContext) }

    /** `sha384:` + 96 lowercase hex characters. */
    public val digest: String get() = handle.digest()
    public val profile: String get() = handle.profile()
    public val requireBound: Boolean get() = handle.requireBound()
    public val requiredFields: List<String> get() = handle.requiredFields()
    public val expectedSessionContext: ByteArray get() = handle.expectedSessionContext()
}
