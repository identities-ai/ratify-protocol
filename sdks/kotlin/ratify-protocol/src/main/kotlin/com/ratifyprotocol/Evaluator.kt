package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiConstraintContext
import com.ratifyprotocol.internal.ffi.FfiConstraintEvaluationInput
import com.ratifyprotocol.internal.ffi.FfiConstraintEvaluationResult
import com.ratifyprotocol.internal.ffi.FfiConstraintEvaluator
import com.ratifyprotocol.internal.ffi.FfiConstraintEvaluatorRegistration
import com.ratifyprotocol.internal.ffi.FfiConstraintEvaluatorRegistry
import com.ratifyprotocol.internal.ffi.FfiEvaluatorException
import com.ratifyprotocol.internal.ffi.FfiStoreContext
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
    internal constructor(f: FfiConstraintContext) : this(f.requestedAmountMicros, f.requestedCurrency,
        f.hasAmount, f.requestedResourceId, f.requestedPath, f.hasResource, f.extensionCounts, f.extensionValues)
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
    internal constructor(f: FfiConstraintEvaluationInput) : this(f.kind, f.paramsJson, f.delegationIndex,
        f.constraintIndex, f.issuerId, f.certId, ConstraintContext(f.context), f.evaluationTime)
}

public class ConstraintEvaluationResult(public val outcome: ConstraintOutcome,
    public val validUntil: Long = 0, public val detail: String = "") {
    internal constructor(result: FfiConstraintEvaluationResult) : this(
        ConstraintOutcome.valueOf(result.outcome.uppercase()), result.validUntil, result.detail)
    internal fun toFfi() = FfiConstraintEvaluationResult(outcome.name.lowercase(), validUntil, detail)
}

/** A pure extension evaluator. A callback that never returns delays verification. */
public interface ConstraintEvaluator {
    public suspend fun evaluate(input: ConstraintEvaluationInput): ConstraintEvaluationResult
}

public class ConstraintEvaluatorRegistration(public val descriptor: ConstraintProfileDescriptor,
    public val evaluator: ConstraintEvaluator)

internal class ConstraintEvaluatorBridge(private val evaluator: ConstraintEvaluator) : FfiConstraintEvaluator {
    override fun evaluate(input: FfiConstraintEvaluationInput, context: FfiStoreContext): FfiConstraintEvaluationResult = try {
        callbackWait(context) { evaluator.evaluate(ConstraintEvaluationInput(input)).toFfi() }
    } catch (e: Throwable) { throw FfiEvaluatorException.Failed(e.toString()) }
}

/** Immutable, caller-authenticated extension profiles validated by the core. */
public class ConstraintEvaluatorRegistry(public val timeoutMilliseconds: ULong,
    registrations: List<ConstraintEvaluatorRegistration>) {
    internal val handle = ffi { FfiConstraintEvaluatorRegistry(timeoutMilliseconds,
        registrations.map { FfiConstraintEvaluatorRegistration(it.descriptor.profile,
            it.descriptor.type, ConstraintEvaluatorBridge(it.evaluator)) }) }
    public fun refs(): List<ConstraintEvaluatorRef> = ffi { handle.refs().map(::ConstraintEvaluatorRef) }
}

public fun validateRequestContext(context: ConstraintContext): Unit = ffi { ffiValidateRequestContext(context.toFfi()) }
public fun constraintProfileDigest(descriptor: ConstraintProfileDescriptor): String =
    ffi { ffiConstraintProfileDigest(descriptor.profile, descriptor.type) }
public fun evaluateMaxCount(input: ConstraintEvaluationInput): ConstraintEvaluationResult =
    ConstraintEvaluationResult(ffi { ffiEvaluateMaxCount(input.toFfi()) })
public fun evaluateAllowedValues(input: ConstraintEvaluationInput): ConstraintEvaluationResult =
    ConstraintEvaluationResult(ffi { ffiEvaluateAllowedValues(input.toFfi()) })
