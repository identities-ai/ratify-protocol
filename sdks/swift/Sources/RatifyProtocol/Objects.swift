import Foundation

// Public value types for every v2 signed object. Each mirrors the core type
// field for field; conversion to and from the internal FFI records is one to one.

/// A hybrid signature: Ed25519 (64 bytes) and ML-DSA-65 (3309 bytes).
public struct HybridSignature: Sendable, Hashable {
    public var ed25519: Data
    public var mlDsa65: Data

    public init(ed25519: Data, mlDsa65: Data) {
        self.ed25519 = ed25519
        self.mlDsa65 = mlDsa65
    }

    init(_ f: FfiSignature) {
        self.init(ed25519: f.ed25519, mlDsa65: f.mlDsa65)
    }

    var ffi: FfiSignature { FfiSignature(ed25519: ed25519, mlDsa65: mlDsa65) }
}

/// A delegation constraint. Unused fields for the constraint's kind are empty or zero.
public struct Constraint: Sendable, Hashable {
    public var kind: String
    public var start: String
    public var end: String
    public var tz: String
    public var currency: String
    public var maxAmountMicros: Int64
    public var count: Int64
    public var windowS: Int64
    public var resourceId: String
    public var pathPrefix: String
    public var params: [String: ParamsValue]?

    public init(kind: String, start: String, end: String, tz: String, currency: String, maxAmountMicros: Int64, count: Int64, windowS: Int64, resourceId: String, pathPrefix: String, params: [String: ParamsValue]?) {
        self.kind = kind
        self.start = start
        self.end = end
        self.tz = tz
        self.currency = currency
        self.maxAmountMicros = maxAmountMicros
        self.count = count
        self.windowS = windowS
        self.resourceId = resourceId
        self.pathPrefix = pathPrefix
        self.params = params
    }

    init(_ f: FfiConstraint) {
        self.init(kind: f.kind, start: f.start, end: f.end, tz: f.tz, currency: f.currency, maxAmountMicros: f.maxAmountMicros, count: f.count, windowS: f.windowS, resourceId: f.resourceId, pathPrefix: f.pathPrefix, params: f.params.map { $0.mapValues(ParamsValue.init) })
    }

    var ffi: FfiConstraint { FfiConstraint(kind: kind, start: start, end: end, tz: tz, currency: currency, maxAmountMicros: maxAmountMicros, count: count, windowS: windowS, resourceId: resourceId, pathPrefix: pathPrefix, params: params.map { $0.mapValues(\.ffi) }) }
}

/// Delegation certificate (object code 0x0001).
public struct DelegationCert: Sendable, Hashable {
    public var version: Int64
    public var certId: String
    public var issuerId: String
    public var issuerPubKey: HybridPublicKey
    public var subjectId: String
    public var subjectPubKey: HybridPublicKey
    public var scope: [String]
    public var constraints: [Constraint]
    public var issuedAt: Int64
    public var expiresAt: Int64
    public var signature: HybridSignature

    public init(version: Int64, certId: String, issuerId: String, issuerPubKey: HybridPublicKey, subjectId: String, subjectPubKey: HybridPublicKey, scope: [String], constraints: [Constraint], issuedAt: Int64, expiresAt: Int64, signature: HybridSignature) {
        self.version = version
        self.certId = certId
        self.issuerId = issuerId
        self.issuerPubKey = issuerPubKey
        self.subjectId = subjectId
        self.subjectPubKey = subjectPubKey
        self.scope = scope
        self.constraints = constraints
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.signature = signature
    }

    init(_ f: FfiDelegationCert) {
        self.init(version: f.version, certId: f.certId, issuerId: f.issuerId, issuerPubKey: HybridPublicKey(f.issuerPubKey), subjectId: f.subjectId, subjectPubKey: HybridPublicKey(f.subjectPubKey), scope: f.scope, constraints: f.constraints.map(Constraint.init), issuedAt: f.issuedAt, expiresAt: f.expiresAt, signature: HybridSignature(f.signature))
    }

    var ffi: FfiDelegationCert { FfiDelegationCert(version: version, certId: certId, issuerId: issuerId, issuerPubKey: issuerPubKey.ffi, subjectId: subjectId, subjectPubKey: subjectPubKey.ffi, scope: scope, constraints: constraints.map(\.ffi), issuedAt: issuedAt, expiresAt: expiresAt, signature: signature.ffi) }
}

/// Proof bundle carrying a challenge presentation (object code 0x0002). Nil fields encode as JSON null.
public struct ProofBundle: Sendable, Hashable {
    public var version: Int64
    public var verifierId: String
    public var agentId: String
    public var agentPubKey: HybridPublicKey
    public var delegations: [DelegationCert]
    public var delegationDigest: Data
    public var challenge: Data
    public var challengeAt: Int64
    public var challengeSig: HybridSignature
    public var sessionContext: Data?
    public var streamId: Data?
    public var streamSeq: Int64?

    public init(version: Int64, verifierId: String, agentId: String, agentPubKey: HybridPublicKey, delegations: [DelegationCert], delegationDigest: Data, challenge: Data, challengeAt: Int64, challengeSig: HybridSignature, sessionContext: Data?, streamId: Data?, streamSeq: Int64?) {
        self.version = version
        self.verifierId = verifierId
        self.agentId = agentId
        self.agentPubKey = agentPubKey
        self.delegations = delegations
        self.delegationDigest = delegationDigest
        self.challenge = challenge
        self.challengeAt = challengeAt
        self.challengeSig = challengeSig
        self.sessionContext = sessionContext
        self.streamId = streamId
        self.streamSeq = streamSeq
    }

    init(_ f: FfiProofBundle) {
        self.init(version: f.version, verifierId: f.verifierId, agentId: f.agentId, agentPubKey: HybridPublicKey(f.agentPubKey), delegations: f.delegations.map(DelegationCert.init), delegationDigest: f.delegationDigest, challenge: f.challenge, challengeAt: f.challengeAt, challengeSig: HybridSignature(f.challengeSig), sessionContext: f.sessionContext, streamId: f.streamId, streamSeq: f.streamSeq)
    }

    var ffi: FfiProofBundle { FfiProofBundle(version: version, verifierId: verifierId, agentId: agentId, agentPubKey: agentPubKey.ffi, delegations: delegations.map(\.ffi), delegationDigest: delegationDigest, challenge: challenge, challengeAt: challengeAt, challengeSig: challengeSig.ffi, sessionContext: sessionContext, streamId: streamId, streamSeq: streamSeq) }
}

/// Full revocation snapshot (object code 0x0003). `revoked` holds the revoked certificate IDs in wire order.
public struct RevocationList: Sendable, Hashable {
    public var version: Int64
    public var issuerId: String
    public var updatedAt: Int64
    public var nextUpdate: Int64
    public var sequence: Int64
    public var revoked: [String]
    public var signature: HybridSignature

    public init(version: Int64, issuerId: String, updatedAt: Int64, nextUpdate: Int64, sequence: Int64, revoked: [String], signature: HybridSignature) {
        self.version = version
        self.issuerId = issuerId
        self.updatedAt = updatedAt
        self.nextUpdate = nextUpdate
        self.sequence = sequence
        self.revoked = revoked
        self.signature = signature
    }

    init(_ f: FfiRevocationList) {
        self.init(version: f.version, issuerId: f.issuerId, updatedAt: f.updatedAt, nextUpdate: f.nextUpdate, sequence: f.sequence, revoked: f.revoked, signature: HybridSignature(f.signature))
    }

    var ffi: FfiRevocationList { FfiRevocationList(version: version, issuerId: issuerId, updatedAt: updatedAt, nextUpdate: nextUpdate, sequence: sequence, revoked: revoked, signature: signature.ffi) }
}

/// Incremental revocation push (object code 0x0005).
public struct RevocationPush: Sendable, Hashable {
    public var version: Int64
    public var issuerId: String
    public var sequence: Int64
    public var pushedAt: Int64
    public var revoked: [String]
    public var signature: HybridSignature

    public init(version: Int64, issuerId: String, sequence: Int64, pushedAt: Int64, revoked: [String], signature: HybridSignature) {
        self.version = version
        self.issuerId = issuerId
        self.sequence = sequence
        self.pushedAt = pushedAt
        self.revoked = revoked
        self.signature = signature
    }

    init(_ f: FfiRevocationPush) {
        self.init(version: f.version, issuerId: f.issuerId, sequence: f.sequence, pushedAt: f.pushedAt, revoked: f.revoked, signature: HybridSignature(f.signature))
    }

    var ffi: FfiRevocationPush { FfiRevocationPush(version: version, issuerId: issuerId, sequence: sequence, pushedAt: pushedAt, revoked: revoked, signature: signature.ffi) }
}

/// Key rotation statement.
public struct KeyRotationStatement: Sendable, Hashable {
    public var version: Int64
    public var authorityId: String
    public var recoveryEpoch: Int64
    public var role: String
    public var sequence: Int64
    public var previousStatementHash: Data
    public var oldKey: HybridPublicKey
    public var newKey: HybridPublicKey
    public var oldKeyId: String
    public var newKeyId: String
    public var issuedAt: Int64
    public var notBefore: Int64
    public var oldSignature: HybridSignature
    public var newSignature: HybridSignature

    public init(version: Int64, authorityId: String, recoveryEpoch: Int64, role: String, sequence: Int64, previousStatementHash: Data, oldKey: HybridPublicKey, newKey: HybridPublicKey, oldKeyId: String, newKeyId: String, issuedAt: Int64, notBefore: Int64, oldSignature: HybridSignature, newSignature: HybridSignature) {
        self.version = version
        self.authorityId = authorityId
        self.recoveryEpoch = recoveryEpoch
        self.role = role
        self.sequence = sequence
        self.previousStatementHash = previousStatementHash
        self.oldKey = oldKey
        self.newKey = newKey
        self.oldKeyId = oldKeyId
        self.newKeyId = newKeyId
        self.issuedAt = issuedAt
        self.notBefore = notBefore
        self.oldSignature = oldSignature
        self.newSignature = newSignature
    }

    init(_ f: FfiKeyRotationStatement) {
        self.init(version: f.version, authorityId: f.authorityId, recoveryEpoch: f.recoveryEpoch, role: f.role, sequence: f.sequence, previousStatementHash: f.previousStatementHash, oldKey: HybridPublicKey(f.oldKey), newKey: HybridPublicKey(f.newKey), oldKeyId: f.oldKeyId, newKeyId: f.newKeyId, issuedAt: f.issuedAt, notBefore: f.notBefore, oldSignature: HybridSignature(f.oldSignature), newSignature: HybridSignature(f.newSignature))
    }

    var ffi: FfiKeyRotationStatement { FfiKeyRotationStatement(version: version, authorityId: authorityId, recoveryEpoch: recoveryEpoch, role: role, sequence: sequence, previousStatementHash: previousStatementHash, oldKey: oldKey.ffi, newKey: newKey.ffi, oldKeyId: oldKeyId, newKeyId: newKeyId, issuedAt: issuedAt, notBefore: notBefore, oldSignature: oldSignature.ffi, newSignature: newSignature.ffi) }
}

/// Witness log entry.
public struct WitnessEntry: Sendable, Hashable {
    public var version: Int64
    public var logId: String
    public var sequence: Int64
    public var prevHash: Data
    public var entryData: Data
    public var timestamp: Int64
    public var witnessId: String
    public var signature: HybridSignature

    public init(version: Int64, logId: String, sequence: Int64, prevHash: Data, entryData: Data, timestamp: Int64, witnessId: String, signature: HybridSignature) {
        self.version = version
        self.logId = logId
        self.sequence = sequence
        self.prevHash = prevHash
        self.entryData = entryData
        self.timestamp = timestamp
        self.witnessId = witnessId
        self.signature = signature
    }

    init(_ f: FfiWitnessEntry) {
        self.init(version: f.version, logId: f.logId, sequence: f.sequence, prevHash: f.prevHash, entryData: f.entryData, timestamp: f.timestamp, witnessId: f.witnessId, signature: HybridSignature(f.signature))
    }

    var ffi: FfiWitnessEntry { FfiWitnessEntry(version: version, logId: logId, sequence: sequence, prevHash: prevHash, entryData: entryData, timestamp: timestamp, witnessId: witnessId, signature: signature.ffi) }
}

/// An extension evaluator profile sealed into a claim.
public struct ConstraintEvaluatorRef: Sendable, Hashable {
    public var kind: String
    public var profileDigest: String

    public init(kind: String, profileDigest: String) {
        self.kind = kind
        self.profileDigest = profileDigest
    }

    init(_ f: FfiConstraintEvaluatorRef) {
        self.init(kind: f.kind, profileDigest: f.profileDigest)
    }

    var ffi: FfiConstraintEvaluatorRef { FfiConstraintEvaluatorRef(kind: kind, profileDigest: profileDigest) }
}

/// One status evidence reference in a verification receipt.
public struct StatusEvidenceEntry: Sendable, Hashable {
    public var issuerId: String
    public var statusKeyId: String
    public var sequence: Int64
    public var objectType: UInt16
    public var digest: String

    public init(issuerId: String, statusKeyId: String, sequence: Int64, objectType: UInt16, digest: String) {
        self.issuerId = issuerId
        self.statusKeyId = statusKeyId
        self.sequence = sequence
        self.objectType = objectType
        self.digest = digest
    }

    init(_ f: FfiStatusEvidenceEntry) {
        self.init(issuerId: f.issuerId, statusKeyId: f.statusKeyId, sequence: f.sequence, objectType: f.objectType, digest: f.digest)
    }

    var ffi: FfiStatusEvidenceEntry { FfiStatusEvidenceEntry(issuerId: issuerId, statusKeyId: statusKeyId, sequence: sequence, objectType: objectType, digest: digest) }
}

/// Verification receipt. Empty `agentId` / `humanId` mean absent.
public struct VerificationReceipt: Sendable, Hashable {
    public var version: Int64
    public var logId: String
    public var sequence: Int64
    public var verifierId: String
    public var agentId: String
    public var humanId: String
    public var bundleHash: String
    public var issuerIds: [String]
    public var decision: String
    public var decisionReason: String
    public var identityStatus: String
    public var trustAssessment: String
    public var statusAssessment: String
    public var challengeAssessment: String
    public var constraintEvaluators: [ConstraintEvaluatorRef]
    public var contextAssessment: String
    public var contextPolicyDigest: String?
    public var verifiedAt: Int64
    public var requiredScope: String
    public var grantedScope: [String]
    public var statusEvidence: [StatusEvidenceEntry]
    public var previousReceiptHash: Data
    public var signature: HybridSignature

    public init(version: Int64, logId: String, sequence: Int64, verifierId: String, agentId: String, humanId: String, bundleHash: String, issuerIds: [String], decision: String, decisionReason: String, identityStatus: String, trustAssessment: String, statusAssessment: String, challengeAssessment: String, constraintEvaluators: [ConstraintEvaluatorRef], contextAssessment: String, contextPolicyDigest: String?, verifiedAt: Int64, requiredScope: String, grantedScope: [String], statusEvidence: [StatusEvidenceEntry], previousReceiptHash: Data, signature: HybridSignature) {
        self.version = version
        self.logId = logId
        self.sequence = sequence
        self.verifierId = verifierId
        self.agentId = agentId
        self.humanId = humanId
        self.bundleHash = bundleHash
        self.issuerIds = issuerIds
        self.decision = decision
        self.decisionReason = decisionReason
        self.identityStatus = identityStatus
        self.trustAssessment = trustAssessment
        self.statusAssessment = statusAssessment
        self.challengeAssessment = challengeAssessment
        self.constraintEvaluators = constraintEvaluators
        self.contextAssessment = contextAssessment
        self.contextPolicyDigest = contextPolicyDigest
        self.verifiedAt = verifiedAt
        self.requiredScope = requiredScope
        self.grantedScope = grantedScope
        self.statusEvidence = statusEvidence
        self.previousReceiptHash = previousReceiptHash
        self.signature = signature
    }

    init(_ f: FfiVerificationReceipt) {
        self.init(version: f.version, logId: f.logId, sequence: f.sequence, verifierId: f.verifierId, agentId: f.agentId, humanId: f.humanId, bundleHash: f.bundleHash, issuerIds: f.issuerIds, decision: f.decision, decisionReason: f.decisionReason, identityStatus: f.identityStatus, trustAssessment: f.trustAssessment, statusAssessment: f.statusAssessment, challengeAssessment: f.challengeAssessment, constraintEvaluators: f.constraintEvaluators.map(ConstraintEvaluatorRef.init), contextAssessment: f.contextAssessment, contextPolicyDigest: f.contextPolicyDigest, verifiedAt: f.verifiedAt, requiredScope: f.requiredScope, grantedScope: f.grantedScope, statusEvidence: f.statusEvidence.map(StatusEvidenceEntry.init), previousReceiptHash: f.previousReceiptHash, signature: HybridSignature(f.signature))
    }

    var ffi: FfiVerificationReceipt { FfiVerificationReceipt(version: version, logId: logId, sequence: sequence, verifierId: verifierId, agentId: agentId, humanId: humanId, bundleHash: bundleHash, issuerIds: issuerIds, decision: decision, decisionReason: decisionReason, identityStatus: identityStatus, trustAssessment: trustAssessment, statusAssessment: statusAssessment, challengeAssessment: challengeAssessment, constraintEvaluators: constraintEvaluators.map(\.ffi), contextAssessment: contextAssessment, contextPolicyDigest: contextPolicyDigest, verifiedAt: verifiedAt, requiredScope: requiredScope, grantedScope: grantedScope, statusEvidence: statusEvidence.map(\.ffi), previousReceiptHash: previousReceiptHash, signature: signature.ffi) }
}

/// One party to a transaction receipt.
public struct TransactionReceiptParty: Sendable, Hashable {
    public var partyId: String
    public var role: String
    public var agentId: String
    public var agentPubKey: HybridPublicKey
    public var verifierId: String
    public var workspaceId: String
    public var sessionId: String
    public var invocationId: String
    public var requiredScope: String
    public var proofBundleHash: String
    public var proofBundle: ProofBundle?

    public init(partyId: String, role: String, agentId: String, agentPubKey: HybridPublicKey, verifierId: String, workspaceId: String, sessionId: String, invocationId: String, requiredScope: String, proofBundleHash: String, proofBundle: ProofBundle?) {
        self.partyId = partyId
        self.role = role
        self.agentId = agentId
        self.agentPubKey = agentPubKey
        self.verifierId = verifierId
        self.workspaceId = workspaceId
        self.sessionId = sessionId
        self.invocationId = invocationId
        self.requiredScope = requiredScope
        self.proofBundleHash = proofBundleHash
        self.proofBundle = proofBundle
    }

    init(_ f: FfiTransactionReceiptParty) {
        self.init(partyId: f.partyId, role: f.role, agentId: f.agentId, agentPubKey: HybridPublicKey(f.agentPubKey), verifierId: f.verifierId, workspaceId: f.workspaceId, sessionId: f.sessionId, invocationId: f.invocationId, requiredScope: f.requiredScope, proofBundleHash: f.proofBundleHash, proofBundle: f.proofBundle.map(ProofBundle.init))
    }

    var ffi: FfiTransactionReceiptParty { FfiTransactionReceiptParty(partyId: partyId, role: role, agentId: agentId, agentPubKey: agentPubKey.ffi, verifierId: verifierId, workspaceId: workspaceId, sessionId: sessionId, invocationId: invocationId, requiredScope: requiredScope, proofBundleHash: proofBundleHash, proofBundle: proofBundle?.ffi) }
}

/// One party's signature over a transaction receipt.
public struct TransactionReceiptSignature: Sendable, Hashable {
    public var partyId: String
    public var signature: HybridSignature

    public init(partyId: String, signature: HybridSignature) {
        self.partyId = partyId
        self.signature = signature
    }

    init(_ f: FfiTransactionReceiptSignature) {
        self.init(partyId: f.partyId, signature: HybridSignature(f.signature))
    }

    var ffi: FfiTransactionReceiptSignature { FfiTransactionReceiptSignature(partyId: partyId, signature: signature.ffi) }
}

/// Multi-party transaction receipt.
public struct TransactionReceipt: Sendable, Hashable {
    public var version: Int64
    public var transactionId: String
    public var createdAt: Int64
    public var termsSchemaUri: String
    public var termsCanonicalJson: Data
    public var parties: [TransactionReceiptParty]
    public var partySignatures: [TransactionReceiptSignature]

    public init(version: Int64, transactionId: String, createdAt: Int64, termsSchemaUri: String, termsCanonicalJson: Data, parties: [TransactionReceiptParty], partySignatures: [TransactionReceiptSignature]) {
        self.version = version
        self.transactionId = transactionId
        self.createdAt = createdAt
        self.termsSchemaUri = termsSchemaUri
        self.termsCanonicalJson = termsCanonicalJson
        self.parties = parties
        self.partySignatures = partySignatures
    }

    init(_ f: FfiTransactionReceipt) {
        self.init(version: f.version, transactionId: f.transactionId, createdAt: f.createdAt, termsSchemaUri: f.termsSchemaUri, termsCanonicalJson: f.termsCanonicalJson, parties: f.parties.map(TransactionReceiptParty.init), partySignatures: f.partySignatures.map(TransactionReceiptSignature.init))
    }

    var ffi: FfiTransactionReceipt { FfiTransactionReceipt(version: version, transactionId: transactionId, createdAt: createdAt, termsSchemaUri: termsSchemaUri, termsCanonicalJson: termsCanonicalJson, parties: parties.map(\.ffi), partySignatures: partySignatures.map(\.ffi)) }
}

/// One status object in a status evidence batch: its object type and wire bytes.
public struct StatusEvidenceObject: Sendable, Hashable {
    public var objectType: UInt16
    public var wire: Data

    public init(objectType: UInt16, wire: Data) {
        self.objectType = objectType
        self.wire = wire
    }

    init(_ f: FfiStatusEvidenceObject) {
        self.init(objectType: f.objectType, wire: f.wire)
    }

    var ffi: FfiStatusEvidenceObject { FfiStatusEvidenceObject(objectType: objectType, wire: wire) }
}
