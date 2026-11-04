package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiAudienceMembership
import com.ratifyprotocol.internal.ffi.FfiAudienceProvider
import com.ratifyprotocol.internal.ffi.FfiCertificateRef
import com.ratifyprotocol.internal.ffi.FfiDeferredConstraint
import com.ratifyprotocol.internal.ffi.FfiProviderException
import com.ratifyprotocol.internal.ffi.FfiStatusEvidenceProvider
import com.ratifyprotocol.internal.ffi.FfiStatusEvidenceRequest
import com.ratifyprotocol.internal.ffi.FfiStatusEvidenceObject
import com.ratifyprotocol.internal.ffi.FfiStoreContext
import com.ratifyprotocol.internal.ffi.FfiTrustProvider
import com.ratifyprotocol.internal.ffi.FfiTrustResolution
import com.ratifyprotocol.internal.ffi.FfiDelegationCert
import com.ratifyprotocol.internal.ffi.FfiExpectedChallenge
import com.ratifyprotocol.internal.ffi.FfiProofBundle
import com.ratifyprotocol.internal.ffi.FfiReceiverBindingHook
import kotlin.coroutines.cancellation.CancellationException

/** Pure pre-claim receiver binding check. It must not perform I/O or mutate state. */
public interface ReceiverBindingHook {
    public fun validate(bundle: ProofBundle, expected: ExpectedChallenge)
}

internal class ReceiverBindingBridge(private val hook: ReceiverBindingHook) : FfiReceiverBindingHook {
    override fun validate(bundle: FfiProofBundle, expected: FfiExpectedChallenge): Unit = try {
        hook.validate(ProofBundle(bundle), ExpectedChallenge(expected))
    } catch (e: Throwable) { throw FfiProviderException.Failed(e.toString()) }
}

public enum class TrustOutcome(public val spelling: String) {
    TRUSTED("trusted"), UNTRUSTED("untrusted"), UNAVAILABLE("unavailable"), AMBIGUOUS("ambiguous");
    public companion object {
        public fun fromSpelling(spelling: String): TrustOutcome? = entries.firstOrNull { it.spelling == spelling }
    }
}

public class TrustResolution(public val outcome: TrustOutcome, public val rootKey: HybridPublicKey) {
    internal fun toFfi() = FfiTrustResolution(outcome.spelling, rootKey.toFfi())
}

/** Resolves a verified chain against caller-authenticated roots. */
public interface TrustProvider {
    public suspend fun resolve(chain: List<DelegationCert>): TrustResolution
}

public class DeferredConstraint internal constructor(f: FfiDeferredConstraint) {
    public val delegationIndex: ULong = f.delegationIndex
    public val constraintIndex: ULong = f.constraintIndex
    public val issuerId: String = f.issuerId
    public val certId: String = f.certId
    public val kind: String = f.kind
    private val canonical = f.canonicalJson.copyOf()
    public val canonicalJson: ByteArray get() = canonical.copyOf()
}

public class AudienceMembership(
    public val delegationIndex: ULong, public val constraintIndex: ULong,
    public val receiverId: String, trustDomainIds: List<String>,
    public val issuedAt: Long, public val expiresAt: Long, public val evidenceDigest: String,
) {
    public val trustDomainIds: List<String> = trustDomainIds.toList()
    internal fun toFfi() = FfiAudienceMembership(delegationIndex, constraintIndex, receiverId,
        trustDomainIds, issuedAt, expiresAt, evidenceDigest)
}

/** Supplies authenticated, complete receiver membership evidence. */
public interface AudienceProvider {
    public suspend fun memberships(deferred: List<DeferredConstraint>, receiverId: String): List<AudienceMembership>
}

public class CertificateRef internal constructor(f: FfiCertificateRef) {
    public val issuerId: String = f.issuerId
    public val certId: String = f.certId
}

public class StatusEvidenceRequest internal constructor(f: FfiStatusEvidenceRequest) {
    public val issuerId: String = f.issuerId
    public val statusKeyEpoch: ULong = f.statusKeyEpoch
    public val statusKeyId: String = f.statusKeyId
    public val refs: List<CertificateRef> = f.refs.map(::CertificateRef)
}

/** Returns signed status objects for the authenticated issuer configuration. */
public interface StatusEvidenceProvider {
    public suspend fun provide(request: StatusEvidenceRequest): List<StatusEvidenceObject>
}

private fun providerError(error: Throwable, context: FfiStoreContext): FfiProviderException = when {
    error is CancellationException && runCatching { context.isCancelled() }.getOrDefault(false) -> FfiProviderException.Cancelled()
    else -> FfiProviderException.Failed(error.toString())
}

internal class TrustProviderBridge(private val provider: TrustProvider) : FfiTrustProvider {
    override fun resolve(chain: List<FfiDelegationCert>, context: FfiStoreContext): FfiTrustResolution = try {
        callbackWait(context) { provider.resolve(chain.map(::DelegationCert)).toFfi() }
    } catch (e: Throwable) { throw providerError(e, context) }
}

internal class AudienceProviderBridge(private val provider: AudienceProvider) : FfiAudienceProvider {
    override fun memberships(deferred: List<FfiDeferredConstraint>, receiverId: String,
        context: FfiStoreContext): List<FfiAudienceMembership> = try {
        callbackWait(context) { provider.memberships(deferred.map(::DeferredConstraint), receiverId).map(AudienceMembership::toFfi) }
    } catch (e: Throwable) { throw providerError(e, context) }
}

internal class StatusEvidenceProviderBridge(private val provider: StatusEvidenceProvider) : FfiStatusEvidenceProvider {
    override fun provide(request: FfiStatusEvidenceRequest, context: FfiStoreContext): List<FfiStatusEvidenceObject> = try {
        callbackWait(context) { provider.provide(StatusEvidenceRequest(request)).map(StatusEvidenceObject::toFfi) }
    } catch (e: Throwable) { throw providerError(e, context) }
}
