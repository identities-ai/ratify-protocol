package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiConstraintContext
import com.ratifyprotocol.internal.ffi.FfiConstraintEvaluationInput
import com.ratifyprotocol.internal.ffi.FfiConstraintEvaluationResult
import com.ratifyprotocol.internal.ffi.ffiConstraintProfileDigest
import com.ratifyprotocol.internal.ffi.ffiEvaluateAllowedValues
import com.ratifyprotocol.internal.ffi.ffiEvaluateMaxCount
import com.ratifyprotocol.internal.ffi.ffiValidateRequestContext

public class ConstraintProfileDescriptor(public val profile: String, public val type: String)

public enum class ConstraintOutcome { PASS, DENIED, UNVERIFIABLE, INVALID }

/** Verifier-authenticated values read by built-in and extension constraints. */
public class ConstraintContext(
    public val requestedAmountMicros: Long = 0,
    public val requestedCurrency: String = "",
    public val hasAmount: Boolean = false,
    public val requestedResourceId: String = "",
    public val requestedPath: String = "",
    public val hasResource: Boolean = false,
    extensionCounts: Map<String, Long> = emptyMap(),
    extensionValues: Map<String, String> = emptyMap(),
) {
    public val extensionCounts: Map<String, Long> = extensionCounts.toMap()
    public val extensionValues: Map<String, String> = extensionValues.toMap()
    internal fun toFfi() = FfiConstraintContext(requestedAmountMicros, requestedCurrency, hasAmount,
        requestedResourceId, requestedPath, hasResource, extensionCounts, extensionValues)
}

/** Complete input passed to a standard profile or registered evaluator. */
public class ConstraintEvaluationInput(
    public val type: String,
    paramsJson: ByteArray? = null,
    public val delegationIndex: ULong = 0u,
    public val constraintIndex: ULong = 0u,
    public val issuerId: String = "",
    public val certId: String = "",
    public val context: ConstraintContext = ConstraintContext(),
    public val evaluationTime: Long = 0,
) {
    private val params = paramsJson?.copyOf()
    public val paramsJson: ByteArray? get() = params?.copyOf()
    internal fun toFfi() = FfiConstraintEvaluationInput(type, params?.copyOf(), delegationIndex,
        constraintIndex, issuerId, certId, context.toFfi(), evaluationTime)
}

public class ConstraintEvaluationResult internal constructor(result: FfiConstraintEvaluationResult) {
    public val outcome: ConstraintOutcome = ConstraintOutcome.valueOf(result.outcome.uppercase())
    public val validUntil: Long = result.validUntil
    public val detail: String = result.detail
}

public fun validateRequestContext(context: ConstraintContext): Unit = ffi { ffiValidateRequestContext(context.toFfi()) }
public fun constraintProfileDigest(descriptor: ConstraintProfileDescriptor): String =
    ffi { ffiConstraintProfileDigest(descriptor.profile, descriptor.type) }
public fun evaluateMaxCount(input: ConstraintEvaluationInput): ConstraintEvaluationResult =
    ConstraintEvaluationResult(ffi { ffiEvaluateMaxCount(input.toFfi()) })
public fun evaluateAllowedValues(input: ConstraintEvaluationInput): ConstraintEvaluationResult =
    ConstraintEvaluationResult(ffi { ffiEvaluateAllowedValues(input.toFfi()) })
