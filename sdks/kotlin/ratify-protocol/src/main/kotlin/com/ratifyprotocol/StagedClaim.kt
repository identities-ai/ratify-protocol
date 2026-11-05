package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiEvaluationToken
import com.ratifyprotocol.internal.ffi.FfiLocalAuthorizationAssessment
import com.ratifyprotocol.internal.ffi.FfiLocalAuthorizationOptions
import com.ratifyprotocol.internal.ffi.FfiStagedClaim
import com.ratifyprotocol.internal.ffi.ffiClaimProofBundle
import com.ratifyprotocol.internal.ffi.ffiEvaluateLocalAuthorization
import com.ratifyprotocol.internal.ffi.ffiResolveClaimAfterAudience
import com.ratifyprotocol.internal.ffi.ffiResolveClaimAfterRate
import com.ratifyprotocol.internal.ffi.ffiResolveClaimAfterRateBarrier
import com.ratifyprotocol.internal.ffi.ffiFinalizeClaimProofBundle
import com.ratifyprotocol.internal.ffi.ffiFinalizeClaimProofBundleBarrier
import kotlin.time.Duration

/** A single-use capability returned only for a newly created claim. */
public class EvaluationToken internal constructor(internal val handle: FfiEvaluationToken)

public class StagedClaim internal constructor(f: FfiStagedClaim) {
    public val claim: ChallengeClaim = ChallengeClaim(f.claim)
    public val disposition: ClaimDisposition = ClaimDisposition.valueOf(f.disposition.name)
    public val evaluationToken: EvaluationToken? = f.evaluationToken?.let(::EvaluationToken)
}

/** The trusted root and context for a direct local assessment. */
public class LocalAuthorizationOptions(
    public val futureSkewSeconds: Long, public val requiredScope: String,
    public val trustedRootId: String, public val trustedRootKey: HybridPublicKey,
    public val trustConfigured: Boolean, public val context: ConstraintContext,
    public val tzdbVersion: String, public val contextPolicy: ContextPolicy?,
    public val expectedChallenge: ExpectedChallenge?, public val claimToken: EvaluationToken,
) {
    internal fun toFfi() = FfiLocalAuthorizationOptions(futureSkewSeconds, requiredScope,
        trustedRootId, trustedRootKey.toFfi(), trustConfigured, context.toFfi(), tzdbVersion,
        contextPolicy?.handle, expectedChallenge?.toFfi(), claimToken.handle)
}

public class CertificateStatusCheck internal constructor(f: com.ratifyprotocol.internal.ffi.FfiCertificateStatusCheck) {
    public val delegationIndex: ULong = f.delegationIndex
    public val issuerId: String = f.issuerId
    public val subjectId: String = f.subjectId
    public val certId: String = f.certId
}

public class LocalPolicyFailure internal constructor(f: com.ratifyprotocol.internal.ffi.FfiLocalPolicyFailure) {
    public val status: String = f.status
    public val reason: String = f.reason
    public val detail: String = f.detail
}

/** Successful local checks remain pending because authenticated status is internal to the
 * composed verifier. A pending result is not an allow decision. */
public class LocalAuthorizationAssessment internal constructor(f: FfiLocalAuthorizationAssessment) {
    public val bundleHash: String = f.bundleHash
    public val issuerIds: List<String> = f.issuerIds.toList()
    public val agentId: String = f.agentId
    public val rootId: String = f.rootId
    public val requiredScope: String = f.requiredScope
    private val digest = f.delegationDigest.copyOf()
    public val delegationDigest: ByteArray get() = digest.copyOf()
    public val effectiveScope: List<String> = f.effectiveScope.toList()
    public val contextAssessment: String = f.contextAssessment
    public val contextPolicyDigest: String? = f.contextPolicyDigest
    public val statusAssessment: String = f.statusAssessment
    public val delegationValidUntil: Long = f.delegationValidUntil
    public val localTimeValidUntil: Long = f.localTimeValidUntil
    public val extensionValidUntil: Long = f.extensionValidUntil
    public val statusFreshUntil: Long = f.statusFreshUntil
    public val audienceFreshUntil: Long = f.audienceFreshUntil
    public val statusEvidence: List<StatusEvidenceEntry> = f.statusEvidence.map(::StatusEvidenceEntry)
    public val audienceEvidenceDigests: List<String> = f.audienceEvidenceDigests.toList()
    public val rateStoreUnavailable: Boolean = f.rateStoreUnavailable
    public val rateAdmissionDeferred: Boolean = f.rateAdmissionDeferred
    public val statusChecks: List<CertificateStatusCheck> = f.statusChecks.map(::CertificateStatusCheck)
    public val deferred: List<DeferredConstraint> = f.deferred.map(::DeferredConstraint)
    public val localPolicyFailure: LocalPolicyFailure? = f.localPolicyFailure?.let(::LocalPolicyFailure)
    public val status: String = f.status
    public val reason: String = f.reason
    public val detail: String = f.detail
}

/** Creates a claim after sealed preflight. A pending claim must be recovered after lease
 * expiry if it cannot reach a terminal result. Use verifyProofBundle for allow decisions. */
public suspend fun claimProofBundle(bundle: ByteArray, preflight: PreflightResult,
    namespace: String, replayEpoch: Long, now: Long, store: ClaimStore,
    timeout: Duration? = null): StagedClaim = onWorker(timeout) { cancel ->
    StagedClaim(ffi { ffiClaimProofBundle(bundle.copyOf(), preflight.handle,
        namespace, replayEpoch, now, ClaimStoreBridge(store), cancel) })
}

/** Evaluates local policy once. Valid proof stays pending; this direct API cannot reach allow. */
public suspend fun evaluateLocalAuthorization(bundle: ByteArray, options: LocalAuthorizationOptions):
    LocalAuthorizationAssessment = onWorker(null) { _ ->
    LocalAuthorizationAssessment(ffi { ffiEvaluateLocalAuthorization(bundle.copyOf(), options.toFfi()) })
}

/** Requires current authenticated status. A direct pending claim cannot pass this gate. */
public fun resolveClaimAfterAudience(token: EvaluationToken,
    memberships: List<AudienceMembership>): LocalAuthorizationAssessment =
    LocalAuthorizationAssessment(ffi { ffiResolveClaimAfterAudience(token.handle, memberships.map(AudienceMembership::toFfi)) })

/** Requires current authenticated status. A direct pending claim cannot reserve a rate. */
public suspend fun resolveClaimAfterRate(token: EvaluationToken, store: RateReservationStore? = null,
    timeout: Duration? = null): LocalAuthorizationAssessment = onWorker(timeout) { cancel ->
    LocalAuthorizationAssessment(ffi { ffiResolveClaimAfterRate(token.handle,
        store?.let(::RateReservationStoreBridge), cancel) })
}

/** Requires current authenticated status. Use the same barrier store used at claim. */
public suspend fun resolveClaimAfterRate(token: EvaluationToken, store: RateAtFinalizationClaimStore,
    timeout: Duration? = null): LocalAuthorizationAssessment = onWorker(timeout) { cancel ->
    LocalAuthorizationAssessment(ffi { ffiResolveClaimAfterRateBarrier(token.handle,
        ClaimStoreBridge(store), cancel) })
}

/** Finalizes only a terminal assessment. Pending claims require lease-expiry recovery;
 * this direct path cannot allow. Use the same store used at claim. */
public suspend fun finalizeClaimProofBundle(token: EvaluationToken, store: ClaimStore,
    terminalResult: ByteArray, receiptBody: ByteArray, timeout: Duration? = null): Boolean = onWorker(timeout) { cancel ->
    val reply = ffi { ffiFinalizeClaimProofBundle(token.handle, ClaimStoreBridge(store), cancel,
        terminalResult.copyOf(), receiptBody.copyOf()) }
    reply.failure?.let { throw referenceStoreError(it) }
    reply.finalized ?: throw RatifyException.Internal(InternalErrorKind.PANIC, "missing finalization result")
}

/** Finalizes only a terminal assessment with the same barrier store used at claim.
 * Pending claims require lease-expiry recovery; this direct path cannot allow. */
public suspend fun finalizeClaimProofBundle(token: EvaluationToken, store: RateAtFinalizationClaimStore,
    terminalResult: ByteArray, receiptBody: ByteArray, timeout: Duration? = null): Boolean = onWorker(timeout) { cancel ->
    val reply = ffi { ffiFinalizeClaimProofBundleBarrier(token.handle, ClaimStoreBridge(store), cancel,
        terminalResult.copyOf(), receiptBody.copyOf()) }
    reply.failure?.let { throw referenceStoreError(it) }
    reply.finalized ?: throw RatifyException.Internal(InternalErrorKind.PANIC, "missing finalization result")
}
