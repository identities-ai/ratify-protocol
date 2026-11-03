package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiConstraint
import com.ratifyprotocol.internal.ffi.FfiConstraintEvaluatorRef
import com.ratifyprotocol.internal.ffi.FfiDelegationCert
import com.ratifyprotocol.internal.ffi.FfiKeyRotationStatement
import com.ratifyprotocol.internal.ffi.FfiProofBundle
import com.ratifyprotocol.internal.ffi.FfiRevocationList
import com.ratifyprotocol.internal.ffi.FfiRevocationPush
import com.ratifyprotocol.internal.ffi.FfiSignature
import com.ratifyprotocol.internal.ffi.FfiStatusEvidenceEntry
import com.ratifyprotocol.internal.ffi.FfiStatusEvidenceObject
import com.ratifyprotocol.internal.ffi.FfiTransactionReceipt
import com.ratifyprotocol.internal.ffi.FfiTransactionReceiptParty
import com.ratifyprotocol.internal.ffi.FfiTransactionReceiptSignature
import com.ratifyprotocol.internal.ffi.FfiVerificationReceipt
import com.ratifyprotocol.internal.ffi.FfiWitnessEntry

// Public value types for every v2 signed object. Each mirrors the core type
// field for field; byte arrays are copied in and out, so a value never shares
// mutable storage with its caller.

/** A hybrid signature: Ed25519 (64 bytes) and ML-DSA-65 (3309 bytes). */
public class HybridSignature(
    ed25519: ByteArray,
    mlDsa65: ByteArray,
) {
    private val _ed25519: ByteArray = ed25519.copyOf()
    public val ed25519: ByteArray get() = _ed25519.copyOf()
    private val _mlDsa65: ByteArray = mlDsa65.copyOf()
    public val mlDsa65: ByteArray get() = _mlDsa65.copyOf()

    internal constructor(f: FfiSignature) : this(f.ed25519, f.mlDsa65)

    internal fun toFfi(): FfiSignature = FfiSignature(_ed25519.copyOf(), _mlDsa65.copyOf())

    override fun equals(other: Any?): Boolean =
        other is HybridSignature &&
            _ed25519.contentEquals(other._ed25519) &&
            _mlDsa65.contentEquals(other._mlDsa65)

    override fun hashCode(): Int = listOf(_ed25519.contentHashCode(), _mlDsa65.contentHashCode()).hashCode()
}

/** A delegation constraint. Unused fields for the constraint's kind are empty or zero. */
public class Constraint(
    public val kind: String,
    public val start: String,
    public val end: String,
    public val tz: String,
    public val currency: String,
    public val maxAmountMicros: Long,
    public val count: Long,
    public val windowS: Long,
    public val resourceId: String,
    public val pathPrefix: String,
    public val params: Map<String, ParamsValue>?,
) {

    internal constructor(f: FfiConstraint) : this(f.kind, f.start, f.end, f.tz, f.currency, f.maxAmountMicros, f.count, f.windowS, f.resourceId, f.pathPrefix, f.params?.mapValues { ParamsValue.fromFfi(it.value) })

    internal fun toFfi(): FfiConstraint = FfiConstraint(kind, start, end, tz, currency, maxAmountMicros, count, windowS, resourceId, pathPrefix, params?.mapValues { it.value.toFfi() })

    override fun equals(other: Any?): Boolean =
        other is Constraint &&
            kind == other.kind &&
            start == other.start &&
            end == other.end &&
            tz == other.tz &&
            currency == other.currency &&
            maxAmountMicros == other.maxAmountMicros &&
            count == other.count &&
            windowS == other.windowS &&
            resourceId == other.resourceId &&
            pathPrefix == other.pathPrefix &&
            params == other.params

    override fun hashCode(): Int = listOf(kind.hashCode(), start.hashCode(), end.hashCode(), tz.hashCode(), currency.hashCode(), maxAmountMicros.hashCode(), count.hashCode(), windowS.hashCode(), resourceId.hashCode(), pathPrefix.hashCode(), params.hashCode()).hashCode()
}

/** Delegation certificate (object code 0x0001). */
public class DelegationCert(
    public val version: Long,
    public val certId: String,
    public val issuerId: String,
    public val issuerPubKey: HybridPublicKey,
    public val subjectId: String,
    public val subjectPubKey: HybridPublicKey,
    public val scope: List<String>,
    public val constraints: List<Constraint>,
    public val issuedAt: Long,
    public val expiresAt: Long,
    public val signature: HybridSignature,
) {

    internal constructor(f: FfiDelegationCert) : this(f.version, f.certId, f.issuerId, HybridPublicKey(f.issuerPubKey), f.subjectId, HybridPublicKey(f.subjectPubKey), f.scope, f.constraints.map { Constraint(it) }, f.issuedAt, f.expiresAt, HybridSignature(f.signature))

    internal fun toFfi(): FfiDelegationCert = FfiDelegationCert(version, certId, issuerId, issuerPubKey.toFfi(), subjectId, subjectPubKey.toFfi(), scope, constraints.map { it.toFfi() }, issuedAt, expiresAt, signature.toFfi())

    override fun equals(other: Any?): Boolean =
        other is DelegationCert &&
            version == other.version &&
            certId == other.certId &&
            issuerId == other.issuerId &&
            issuerPubKey == other.issuerPubKey &&
            subjectId == other.subjectId &&
            subjectPubKey == other.subjectPubKey &&
            scope == other.scope &&
            constraints == other.constraints &&
            issuedAt == other.issuedAt &&
            expiresAt == other.expiresAt &&
            signature == other.signature

    override fun hashCode(): Int = listOf(version.hashCode(), certId.hashCode(), issuerId.hashCode(), issuerPubKey.hashCode(), subjectId.hashCode(), subjectPubKey.hashCode(), scope.hashCode(), constraints.hashCode(), issuedAt.hashCode(), expiresAt.hashCode(), signature.hashCode()).hashCode()
}

/** Proof bundle carrying a challenge presentation (object code 0x0002). Nil fields encode as JSON null. */
public class ProofBundle(
    public val version: Long,
    public val verifierId: String,
    public val agentId: String,
    public val agentPubKey: HybridPublicKey,
    public val delegations: List<DelegationCert>,
    delegationDigest: ByteArray,
    challenge: ByteArray,
    public val challengeAt: Long,
    public val challengeSig: HybridSignature,
    sessionContext: ByteArray?,
    streamId: ByteArray?,
    public val streamSeq: Long?,
) {
    private val _delegationDigest: ByteArray = delegationDigest.copyOf()
    public val delegationDigest: ByteArray get() = _delegationDigest.copyOf()
    private val _challenge: ByteArray = challenge.copyOf()
    public val challenge: ByteArray get() = _challenge.copyOf()
    private val _sessionContext: ByteArray? = sessionContext?.copyOf()
    public val sessionContext: ByteArray? get() = _sessionContext?.copyOf()
    private val _streamId: ByteArray? = streamId?.copyOf()
    public val streamId: ByteArray? get() = _streamId?.copyOf()

    internal constructor(f: FfiProofBundle) : this(f.version, f.verifierId, f.agentId, HybridPublicKey(f.agentPubKey), f.delegations.map { DelegationCert(it) }, f.delegationDigest, f.challenge, f.challengeAt, HybridSignature(f.challengeSig), f.sessionContext, f.streamId, f.streamSeq)

    internal fun toFfi(): FfiProofBundle = FfiProofBundle(version, verifierId, agentId, agentPubKey.toFfi(), delegations.map { it.toFfi() }, _delegationDigest.copyOf(), _challenge.copyOf(), challengeAt, challengeSig.toFfi(), _sessionContext?.copyOf(), _streamId?.copyOf(), streamSeq)

    override fun equals(other: Any?): Boolean =
        other is ProofBundle &&
            version == other.version &&
            verifierId == other.verifierId &&
            agentId == other.agentId &&
            agentPubKey == other.agentPubKey &&
            delegations == other.delegations &&
            _delegationDigest.contentEquals(other._delegationDigest) &&
            _challenge.contentEquals(other._challenge) &&
            challengeAt == other.challengeAt &&
            challengeSig == other.challengeSig &&
            (_sessionContext?.contentEquals(other._sessionContext) ?: (other._sessionContext == null)) &&
            (_streamId?.contentEquals(other._streamId) ?: (other._streamId == null)) &&
            streamSeq == other.streamSeq

    override fun hashCode(): Int = listOf(version.hashCode(), verifierId.hashCode(), agentId.hashCode(), agentPubKey.hashCode(), delegations.hashCode(), _delegationDigest.contentHashCode(), _challenge.contentHashCode(), challengeAt.hashCode(), challengeSig.hashCode(), (_sessionContext?.contentHashCode() ?: 0), (_streamId?.contentHashCode() ?: 0), streamSeq.hashCode()).hashCode()
}

/** Full revocation snapshot (object code 0x0003). `revoked` holds the revoked certificate IDs in wire order. */
public class RevocationList(
    public val version: Long,
    public val issuerId: String,
    public val updatedAt: Long,
    public val nextUpdate: Long,
    public val sequence: Long,
    public val revoked: List<String>,
    public val signature: HybridSignature,
) {

    internal constructor(f: FfiRevocationList) : this(f.version, f.issuerId, f.updatedAt, f.nextUpdate, f.sequence, f.revoked, HybridSignature(f.signature))

    internal fun toFfi(): FfiRevocationList = FfiRevocationList(version, issuerId, updatedAt, nextUpdate, sequence, revoked, signature.toFfi())

    override fun equals(other: Any?): Boolean =
        other is RevocationList &&
            version == other.version &&
            issuerId == other.issuerId &&
            updatedAt == other.updatedAt &&
            nextUpdate == other.nextUpdate &&
            sequence == other.sequence &&
            revoked == other.revoked &&
            signature == other.signature

    override fun hashCode(): Int = listOf(version.hashCode(), issuerId.hashCode(), updatedAt.hashCode(), nextUpdate.hashCode(), sequence.hashCode(), revoked.hashCode(), signature.hashCode()).hashCode()
}

/** Incremental revocation push (object code 0x0005). */
public class RevocationPush(
    public val version: Long,
    public val issuerId: String,
    public val sequence: Long,
    public val pushedAt: Long,
    public val revoked: List<String>,
    public val signature: HybridSignature,
) {

    internal constructor(f: FfiRevocationPush) : this(f.version, f.issuerId, f.sequence, f.pushedAt, f.revoked, HybridSignature(f.signature))

    internal fun toFfi(): FfiRevocationPush = FfiRevocationPush(version, issuerId, sequence, pushedAt, revoked, signature.toFfi())

    override fun equals(other: Any?): Boolean =
        other is RevocationPush &&
            version == other.version &&
            issuerId == other.issuerId &&
            sequence == other.sequence &&
            pushedAt == other.pushedAt &&
            revoked == other.revoked &&
            signature == other.signature

    override fun hashCode(): Int = listOf(version.hashCode(), issuerId.hashCode(), sequence.hashCode(), pushedAt.hashCode(), revoked.hashCode(), signature.hashCode()).hashCode()
}

/** Key rotation statement. */
public class KeyRotationStatement(
    public val version: Long,
    public val authorityId: String,
    public val recoveryEpoch: Long,
    public val role: String,
    public val sequence: Long,
    previousStatementHash: ByteArray,
    public val oldKey: HybridPublicKey,
    public val newKey: HybridPublicKey,
    public val oldKeyId: String,
    public val newKeyId: String,
    public val issuedAt: Long,
    public val notBefore: Long,
    public val oldSignature: HybridSignature,
    public val newSignature: HybridSignature,
) {
    private val _previousStatementHash: ByteArray = previousStatementHash.copyOf()
    public val previousStatementHash: ByteArray get() = _previousStatementHash.copyOf()

    internal constructor(f: FfiKeyRotationStatement) : this(f.version, f.authorityId, f.recoveryEpoch, f.role, f.sequence, f.previousStatementHash, HybridPublicKey(f.oldKey), HybridPublicKey(f.newKey), f.oldKeyId, f.newKeyId, f.issuedAt, f.notBefore, HybridSignature(f.oldSignature), HybridSignature(f.newSignature))

    internal fun toFfi(): FfiKeyRotationStatement = FfiKeyRotationStatement(version, authorityId, recoveryEpoch, role, sequence, _previousStatementHash.copyOf(), oldKey.toFfi(), newKey.toFfi(), oldKeyId, newKeyId, issuedAt, notBefore, oldSignature.toFfi(), newSignature.toFfi())

    override fun equals(other: Any?): Boolean =
        other is KeyRotationStatement &&
            version == other.version &&
            authorityId == other.authorityId &&
            recoveryEpoch == other.recoveryEpoch &&
            role == other.role &&
            sequence == other.sequence &&
            _previousStatementHash.contentEquals(other._previousStatementHash) &&
            oldKey == other.oldKey &&
            newKey == other.newKey &&
            oldKeyId == other.oldKeyId &&
            newKeyId == other.newKeyId &&
            issuedAt == other.issuedAt &&
            notBefore == other.notBefore &&
            oldSignature == other.oldSignature &&
            newSignature == other.newSignature

    override fun hashCode(): Int = listOf(version.hashCode(), authorityId.hashCode(), recoveryEpoch.hashCode(), role.hashCode(), sequence.hashCode(), _previousStatementHash.contentHashCode(), oldKey.hashCode(), newKey.hashCode(), oldKeyId.hashCode(), newKeyId.hashCode(), issuedAt.hashCode(), notBefore.hashCode(), oldSignature.hashCode(), newSignature.hashCode()).hashCode()
}

/** Witness log entry. */
public class WitnessEntry(
    public val version: Long,
    public val logId: String,
    public val sequence: Long,
    prevHash: ByteArray,
    entryData: ByteArray,
    public val timestamp: Long,
    public val witnessId: String,
    public val signature: HybridSignature,
) {
    private val _prevHash: ByteArray = prevHash.copyOf()
    public val prevHash: ByteArray get() = _prevHash.copyOf()
    private val _entryData: ByteArray = entryData.copyOf()
    public val entryData: ByteArray get() = _entryData.copyOf()

    internal constructor(f: FfiWitnessEntry) : this(f.version, f.logId, f.sequence, f.prevHash, f.entryData, f.timestamp, f.witnessId, HybridSignature(f.signature))

    internal fun toFfi(): FfiWitnessEntry = FfiWitnessEntry(version, logId, sequence, _prevHash.copyOf(), _entryData.copyOf(), timestamp, witnessId, signature.toFfi())

    override fun equals(other: Any?): Boolean =
        other is WitnessEntry &&
            version == other.version &&
            logId == other.logId &&
            sequence == other.sequence &&
            _prevHash.contentEquals(other._prevHash) &&
            _entryData.contentEquals(other._entryData) &&
            timestamp == other.timestamp &&
            witnessId == other.witnessId &&
            signature == other.signature

    override fun hashCode(): Int = listOf(version.hashCode(), logId.hashCode(), sequence.hashCode(), _prevHash.contentHashCode(), _entryData.contentHashCode(), timestamp.hashCode(), witnessId.hashCode(), signature.hashCode()).hashCode()
}

/** An extension evaluator profile sealed into a claim. */
public class ConstraintEvaluatorRef(
    public val kind: String,
    public val profileDigest: String,
) {

    internal constructor(f: FfiConstraintEvaluatorRef) : this(f.kind, f.profileDigest)

    internal fun toFfi(): FfiConstraintEvaluatorRef = FfiConstraintEvaluatorRef(kind, profileDigest)

    override fun equals(other: Any?): Boolean =
        other is ConstraintEvaluatorRef &&
            kind == other.kind &&
            profileDigest == other.profileDigest

    override fun hashCode(): Int = listOf(kind.hashCode(), profileDigest.hashCode()).hashCode()
}

/** One status evidence reference in a verification receipt. */
public class StatusEvidenceEntry(
    public val issuerId: String,
    public val statusKeyId: String,
    public val sequence: Long,
    public val objectType: UShort,
    public val digest: String,
) {

    internal constructor(f: FfiStatusEvidenceEntry) : this(f.issuerId, f.statusKeyId, f.sequence, f.objectType, f.digest)

    internal fun toFfi(): FfiStatusEvidenceEntry = FfiStatusEvidenceEntry(issuerId, statusKeyId, sequence, objectType, digest)

    override fun equals(other: Any?): Boolean =
        other is StatusEvidenceEntry &&
            issuerId == other.issuerId &&
            statusKeyId == other.statusKeyId &&
            sequence == other.sequence &&
            objectType == other.objectType &&
            digest == other.digest

    override fun hashCode(): Int = listOf(issuerId.hashCode(), statusKeyId.hashCode(), sequence.hashCode(), objectType.hashCode(), digest.hashCode()).hashCode()
}

/** Verification receipt. Empty `agentId` / `humanId` mean absent. */
public class VerificationReceipt(
    public val version: Long,
    public val logId: String,
    public val sequence: Long,
    public val verifierId: String,
    public val agentId: String,
    public val humanId: String,
    public val bundleHash: String,
    public val issuerIds: List<String>,
    public val decision: String,
    public val decisionReason: String,
    public val identityStatus: String,
    public val trustAssessment: String,
    public val statusAssessment: String,
    public val challengeAssessment: String,
    public val constraintEvaluators: List<ConstraintEvaluatorRef>,
    public val contextAssessment: String,
    public val contextPolicyDigest: String?,
    public val verifiedAt: Long,
    public val requiredScope: String,
    public val grantedScope: List<String>,
    public val statusEvidence: List<StatusEvidenceEntry>,
    previousReceiptHash: ByteArray,
    public val signature: HybridSignature,
) {
    private val _previousReceiptHash: ByteArray = previousReceiptHash.copyOf()
    public val previousReceiptHash: ByteArray get() = _previousReceiptHash.copyOf()

    internal constructor(f: FfiVerificationReceipt) : this(f.version, f.logId, f.sequence, f.verifierId, f.agentId, f.humanId, f.bundleHash, f.issuerIds, f.decision, f.decisionReason, f.identityStatus, f.trustAssessment, f.statusAssessment, f.challengeAssessment, f.constraintEvaluators.map { ConstraintEvaluatorRef(it) }, f.contextAssessment, f.contextPolicyDigest, f.verifiedAt, f.requiredScope, f.grantedScope, f.statusEvidence.map { StatusEvidenceEntry(it) }, f.previousReceiptHash, HybridSignature(f.signature))

    internal fun toFfi(): FfiVerificationReceipt = FfiVerificationReceipt(version, logId, sequence, verifierId, agentId, humanId, bundleHash, issuerIds, decision, decisionReason, identityStatus, trustAssessment, statusAssessment, challengeAssessment, constraintEvaluators.map { it.toFfi() }, contextAssessment, contextPolicyDigest, verifiedAt, requiredScope, grantedScope, statusEvidence.map { it.toFfi() }, _previousReceiptHash.copyOf(), signature.toFfi())

    override fun equals(other: Any?): Boolean =
        other is VerificationReceipt &&
            version == other.version &&
            logId == other.logId &&
            sequence == other.sequence &&
            verifierId == other.verifierId &&
            agentId == other.agentId &&
            humanId == other.humanId &&
            bundleHash == other.bundleHash &&
            issuerIds == other.issuerIds &&
            decision == other.decision &&
            decisionReason == other.decisionReason &&
            identityStatus == other.identityStatus &&
            trustAssessment == other.trustAssessment &&
            statusAssessment == other.statusAssessment &&
            challengeAssessment == other.challengeAssessment &&
            constraintEvaluators == other.constraintEvaluators &&
            contextAssessment == other.contextAssessment &&
            contextPolicyDigest == other.contextPolicyDigest &&
            verifiedAt == other.verifiedAt &&
            requiredScope == other.requiredScope &&
            grantedScope == other.grantedScope &&
            statusEvidence == other.statusEvidence &&
            _previousReceiptHash.contentEquals(other._previousReceiptHash) &&
            signature == other.signature

    override fun hashCode(): Int = listOf(version.hashCode(), logId.hashCode(), sequence.hashCode(), verifierId.hashCode(), agentId.hashCode(), humanId.hashCode(), bundleHash.hashCode(), issuerIds.hashCode(), decision.hashCode(), decisionReason.hashCode(), identityStatus.hashCode(), trustAssessment.hashCode(), statusAssessment.hashCode(), challengeAssessment.hashCode(), constraintEvaluators.hashCode(), contextAssessment.hashCode(), contextPolicyDigest.hashCode(), verifiedAt.hashCode(), requiredScope.hashCode(), grantedScope.hashCode(), statusEvidence.hashCode(), _previousReceiptHash.contentHashCode(), signature.hashCode()).hashCode()
}

/** One party to a transaction receipt. */
public class TransactionReceiptParty(
    public val partyId: String,
    public val role: String,
    public val agentId: String,
    public val agentPubKey: HybridPublicKey,
    public val verifierId: String,
    public val workspaceId: String,
    public val sessionId: String,
    public val invocationId: String,
    public val requiredScope: String,
    public val proofBundleHash: String,
    public val proofBundle: ProofBundle?,
) {

    internal constructor(f: FfiTransactionReceiptParty) : this(f.partyId, f.role, f.agentId, HybridPublicKey(f.agentPubKey), f.verifierId, f.workspaceId, f.sessionId, f.invocationId, f.requiredScope, f.proofBundleHash, f.proofBundle?.let { ProofBundle(it) })

    internal fun toFfi(): FfiTransactionReceiptParty = FfiTransactionReceiptParty(partyId, role, agentId, agentPubKey.toFfi(), verifierId, workspaceId, sessionId, invocationId, requiredScope, proofBundleHash, proofBundle?.toFfi())

    override fun equals(other: Any?): Boolean =
        other is TransactionReceiptParty &&
            partyId == other.partyId &&
            role == other.role &&
            agentId == other.agentId &&
            agentPubKey == other.agentPubKey &&
            verifierId == other.verifierId &&
            workspaceId == other.workspaceId &&
            sessionId == other.sessionId &&
            invocationId == other.invocationId &&
            requiredScope == other.requiredScope &&
            proofBundleHash == other.proofBundleHash &&
            proofBundle == other.proofBundle

    override fun hashCode(): Int = listOf(partyId.hashCode(), role.hashCode(), agentId.hashCode(), agentPubKey.hashCode(), verifierId.hashCode(), workspaceId.hashCode(), sessionId.hashCode(), invocationId.hashCode(), requiredScope.hashCode(), proofBundleHash.hashCode(), proofBundle.hashCode()).hashCode()
}

/** One party's signature over a transaction receipt. */
public class TransactionReceiptSignature(
    public val partyId: String,
    public val signature: HybridSignature,
) {

    internal constructor(f: FfiTransactionReceiptSignature) : this(f.partyId, HybridSignature(f.signature))

    internal fun toFfi(): FfiTransactionReceiptSignature = FfiTransactionReceiptSignature(partyId, signature.toFfi())

    override fun equals(other: Any?): Boolean =
        other is TransactionReceiptSignature &&
            partyId == other.partyId &&
            signature == other.signature

    override fun hashCode(): Int = listOf(partyId.hashCode(), signature.hashCode()).hashCode()
}

/** Multi-party transaction receipt. */
public class TransactionReceipt(
    public val version: Long,
    public val transactionId: String,
    public val createdAt: Long,
    public val termsSchemaUri: String,
    termsCanonicalJson: ByteArray,
    public val parties: List<TransactionReceiptParty>,
    public val partySignatures: List<TransactionReceiptSignature>,
) {
    private val _termsCanonicalJson: ByteArray = termsCanonicalJson.copyOf()
    public val termsCanonicalJson: ByteArray get() = _termsCanonicalJson.copyOf()

    internal constructor(f: FfiTransactionReceipt) : this(f.version, f.transactionId, f.createdAt, f.termsSchemaUri, f.termsCanonicalJson, f.parties.map { TransactionReceiptParty(it) }, f.partySignatures.map { TransactionReceiptSignature(it) })

    internal fun toFfi(): FfiTransactionReceipt = FfiTransactionReceipt(version, transactionId, createdAt, termsSchemaUri, _termsCanonicalJson.copyOf(), parties.map { it.toFfi() }, partySignatures.map { it.toFfi() })

    override fun equals(other: Any?): Boolean =
        other is TransactionReceipt &&
            version == other.version &&
            transactionId == other.transactionId &&
            createdAt == other.createdAt &&
            termsSchemaUri == other.termsSchemaUri &&
            _termsCanonicalJson.contentEquals(other._termsCanonicalJson) &&
            parties == other.parties &&
            partySignatures == other.partySignatures

    override fun hashCode(): Int = listOf(version.hashCode(), transactionId.hashCode(), createdAt.hashCode(), termsSchemaUri.hashCode(), _termsCanonicalJson.contentHashCode(), parties.hashCode(), partySignatures.hashCode()).hashCode()
}

/** One status object in a status evidence batch: its object type and wire bytes. */
public class StatusEvidenceObject(
    public val objectType: UShort,
    wire: ByteArray,
) {
    private val _wire: ByteArray = wire.copyOf()
    public val wire: ByteArray get() = _wire.copyOf()

    internal constructor(f: FfiStatusEvidenceObject) : this(f.objectType, f.wire)

    internal fun toFfi(): FfiStatusEvidenceObject = FfiStatusEvidenceObject(objectType, _wire.copyOf())

    override fun equals(other: Any?): Boolean =
        other is StatusEvidenceObject &&
            objectType == other.objectType &&
            _wire.contentEquals(other._wire)

    override fun hashCode(): Int = listOf(objectType.hashCode(), _wire.contentHashCode()).hashCode()
}
