package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiLiveVerifyOutcome
import com.ratifyprotocol.internal.ffi.FfiLiveVerifyRequest
import com.ratifyprotocol.internal.ffi.FfiStatusKeyConfig
import com.ratifyprotocol.internal.ffi.FfiPreflightResult
import com.ratifyprotocol.internal.ffi.FfiPreflightRequest
import com.ratifyprotocol.internal.ffi.ffiPreflightProofBundle
import com.ratifyprotocol.internal.ffi.ffiLiveVerifyProofBundle
import com.ratifyprotocol.internal.ffi.ffiLiveVerifyProofBundleBarrier
import kotlin.time.Duration

public class StatusKeyConfig(public val epoch: ULong, public val key: HybridPublicKey) {
    internal fun toFfi() = FfiStatusKeyConfig(epoch, key.toFfi())
}

/** Inputs authenticated by the verifier before any claim or provider callback. */
public class VerifyRequest(
    bundle: ByteArray,
    public val expected: ExpectedChallenge?,
    public val contextPolicy: ContextPolicy?,
    public val requiredScope: String,
    public val verifierNamespace: String,
    public val replayEpoch: Long,
    public val verifierId: String,
    public val now: Long,
    public val maxChallengeAgeSeconds: Long,
    public val futureSkewSeconds: Long,
    public val context: ConstraintContext,
    public val tzdbVersion: String,
    statusKeys: Map<String, StatusKeyConfig>,
    public val statusPolicy: RevocationStatusPolicy,
    public val constraintEvaluators: ConstraintEvaluatorRegistry? = null,
) {
    private val bytes = bundle.copyOf()
    public val bundle: ByteArray get() = bytes.copyOf()
    public val statusKeys: Map<String, StatusKeyConfig> = statusKeys.toMap()
    internal fun toFfi() = FfiLiveVerifyRequest(bytes.copyOf(), expected?.toFfi(), contextPolicy?.handle,
        requiredScope, verifierNamespace, replayEpoch, verifierId, now, maxChallengeAgeSeconds,
        futureSkewSeconds, context.toFfi(), tzdbVersion, statusKeys.mapValues { it.value.toFfi() },
        statusPolicy.toFfi(), constraintEvaluators?.handle)
}

public enum class VerifyStage(public val spelling: String) {
    PREFLIGHT("preflight"), REPLAY("replay"), EVALUATING("evaluating"), COMMITTED("committed")
}

/** Inputs for staged preflight. This checks no receiver hook or extension evaluator. */
public class PreflightRequest(bundle: ByteArray,
    public val expected: ExpectedChallenge?, public val contextPolicy: ContextPolicy?,
    public val requiredScope: String, public val verifierNamespace: String,
    public val replayEpoch: Long, public val verifierId: String, public val now: Long,
    public val maxChallengeAgeSeconds: Long, public val futureSkewSeconds: Long) {
    private val bytes = bundle.copyOf()
    public val bundle: ByteArray get() = bytes.copyOf()
    internal fun toFfi() = FfiPreflightRequest(bytes.copyOf(), expected?.toFfi(), contextPolicy?.handle,
        requiredScope, verifierNamespace, replayEpoch, verifierId, now,
        maxChallengeAgeSeconds, futureSkewSeconds)
}

/** Sealed successful preflight state for a later staged claim. */
public class PreflightResult internal constructor(internal val handle: FfiPreflightResult)

/** Checks proof and challenge bindings without creating a claim. */
public fun preflightProofBundle(request: PreflightRequest): PreflightResult =
    PreflightResult(ffi { ffiPreflightProofBundle(request.toFfi()) })

/** A committed result remains non-actionable until release. */
public class VerifyOutcome internal constructor(f: FfiLiveVerifyOutcome) {
    public val stage: VerifyStage = VerifyStage.valueOf(f.stage.uppercase())
    public val errorClass: ErrorClass? = f.errorClass?.let(ErrorClass::fromSpelling)
    public val errorDetail: String? = f.errorDetail
    public val disposition: ClaimDisposition? = f.disposition?.let { ClaimDisposition.valueOf(it.name) }
    public val claim: ChallengeClaim = ChallengeClaim(f.claim)
    public val committed: CommittedOutcome? = f.committed?.let(::CommittedOutcome)
}

/** Runs verification without a claim capability; valid preflight fails closed before a claim. */
public suspend fun verifyProofBundleWithoutClaimStore(request: VerifyRequest,
    receiverBinding: ReceiverBindingHook? = null, timeout: Duration? = null): VerifyOutcome = onWorker(timeout) { token ->
    VerifyOutcome(ffi { ffiLiveVerifyProofBundle(request.toFfi(), null,
        receiverBinding?.let(::ReceiverBindingBridge), null, null, null, null, null, token) })
}

public suspend fun verifyProofBundle(request: VerifyRequest, claimStore: RateAtFinalizationClaimStore,
    receiverBinding: ReceiverBindingHook? = null,
    trust: TrustProvider? = null, audience: AudienceProvider? = null,
    statusEvidence: StatusEvidenceProvider? = null, statusJournal: SecurityJournalStore? = null,
    timeout: Duration? = null): VerifyOutcome = onWorker(timeout) { token ->
    VerifyOutcome(ffi { ffiLiveVerifyProofBundleBarrier(request.toFfi(), ClaimStoreBridge(claimStore),
        receiverBinding?.let(::ReceiverBindingBridge),
        trust?.let(::TrustProviderBridge), audience?.let(::AudienceProviderBridge),
        statusEvidence?.let(::StatusEvidenceProviderBridge), statusJournal?.let(::JournalStoreBridge), token) })
}

public suspend fun verifyProofBundle(request: VerifyRequest, claimStore: ClaimStore,
    receiverBinding: ReceiverBindingHook? = null,
    trust: TrustProvider? = null, audience: AudienceProvider? = null,
    statusEvidence: StatusEvidenceProvider? = null, statusJournal: SecurityJournalStore? = null,
    rate: RateReservationStore? = null,
    timeout: Duration? = null): VerifyOutcome = onWorker(timeout) { token ->
    VerifyOutcome(ffi { ffiLiveVerifyProofBundle(request.toFfi(), ClaimStoreBridge(claimStore),
        receiverBinding?.let(::ReceiverBindingBridge),
        trust?.let(::TrustProviderBridge), audience?.let(::AudienceProviderBridge),
        statusEvidence?.let(::StatusEvidenceProviderBridge), statusJournal?.let(::JournalStoreBridge),
        rate?.let(::RateReservationStoreBridge), token) })
}
