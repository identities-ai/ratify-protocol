import Foundation

/// Caller-authenticated sources for composed transaction receipt verification.
public struct TransactionVerifyRequest: Sendable {
    public let receipt: Data
    public let now: Int64
    public let futureSkewSeconds: Int64
    public let statusKeys: [String: StatusKeyConfig]
    public let statusPolicy: RevocationStatusPolicy

    public init(receipt: Data, now: Int64, futureSkewSeconds: Int64,
                statusKeys: [String: StatusKeyConfig], statusPolicy: RevocationStatusPolicy) {
        self.receipt = receipt; self.now = now; self.futureSkewSeconds = futureSkewSeconds
        self.statusKeys = statusKeys; self.statusPolicy = statusPolicy
    }

    var ffi: FfiTransactionVerifyRequest {
        FfiTransactionVerifyRequest(receipt: receipt, now: now, futureSkewSeconds: futureSkewSeconds,
            statusKeys: statusKeys.mapValues(\.ffi), statusPolicy: statusPolicy.ffi)
    }
}

public struct TransactionPartyVerification: Sendable {
    public let partyId: String
    public let agentId: String
    public let requiredScope: String
    public let trustAssessment: String
    public let delegationAssessment: String
    public let delegationExpiresAt: Int64?
    public let statusAssessment: String
    public let scopeAssessment: String
    public let freshness: String
    public let statusEvidence: [StatusEvidenceEntry]

    init(_ f: FfiTransactionPartyVerification) {
        partyId = f.partyId; agentId = f.agentId; requiredScope = f.requiredScope
        trustAssessment = f.trustAssessment; delegationAssessment = f.delegationAssessment
        delegationExpiresAt = f.delegationExpiresAt; statusAssessment = f.statusAssessment
        scopeAssessment = f.scopeAssessment; freshness = f.freshness
        statusEvidence = f.statusEvidence.map(StatusEvidenceEntry.init)
    }
}

/// Signed authority evidence; it never authorizes an action or consumes a challenge.
public struct TransactionReceiptVerification: Sendable {
    public let transactionId: String
    public let actionable: Bool
    public let parties: [TransactionPartyVerification]

    init(_ f: FfiTransactionVerification) {
        transactionId = f.transactionId; actionable = f.actionable
        parties = f.parties.map(TransactionPartyVerification.init)
    }
}

extension Ratify {
    public static func verifyTransactionReceipt(_ request: TransactionVerifyRequest,
        trust: (any TrustProvider)? = nil,
        statusEvidence: (any StatusEvidenceProvider)? = nil,
        statusJournal: (any SecurityJournalStore)? = nil,
        timeout: Duration? = nil) async throws(RatifyError) -> TransactionReceiptVerification {
        try await onWorker(timeout: timeout) { token throws(RatifyError) in
            try TransactionReceiptVerification(ffi { try ffiVerifyTransactionReceipt(
                request: request.ffi, trust: trust.map(TrustProviderBridge.init),
                statusEvidence: statusEvidence.map(StatusEvidenceProviderBridge.init),
                statusJournal: statusJournal.map(JournalStoreBridge.init), token: token) })
        }
    }
}
