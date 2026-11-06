/// Public v2 wire limits and time bounds. The decoder and verifier enforce
/// these same values; applications can use them before constructing requests.
extension Ratify {
    public static let maxDelegationCertBytes = 32 << 10
    public static let maxProofBundleBytes = 128 << 10
    public static let maxKeyRotationStatementBytes = 32 << 10
    public static let maxRevocationPushBytes = 256 << 10
    public static let maxRevocationPushRefs = 512
    public static let maxRevocationListBytes = 4 << 20
    public static let maxRevocationListRefs = 10_000
    public static let maxWitnessEntryBytes = 64 << 10
    public static let maxWitnessEntryDataBytes = 16 << 10
    public static let maxVerificationReceiptBytes = 64 << 10
    public static let maxVerificationReceiptBodyBytes = 64 << 10
    public static let maxStatusEvidenceBatchBytes = 8 << 20
    public static let maxStatusEvidenceBatchObjects = 64
    public static let maxTransactionReceiptBytes = 5 << 20
    public static let maxTransactionParties = 32
    public static let maxCheckpointAcknowledgementBytes = 1_024
    public static let maxAudienceIds = 64
    public static let maxConstraintEvaluators = 32
    public static let maxExtensionTypeBytes = 128
    public static let maxProfileIdBytes = 128
    public static let maxExtensionContextEntries = 64
    public static let maxExtensionContextNameBytes = 128
    public static let maxExtensionContextValueBytes = 512
    public static let maxAllowedValues = 64
    public static let maxConstraintEvaluatorTimeoutSeconds: Int64 = 10
    public static let maxSecurityJournalSnapshotBytes = 64 << 20
    public static let signingMessageSize = 77

    public static let maxTimestampSeconds: Int64 = 253_402_300_799
    public static let maxFutureSkewSeconds: Int64 = 300
    public static let maxChallengeAgeSeconds: Int64 = 300
    public static let maxStatusLifetimeSeconds: Int64 = 86_400
    public static let maxAudienceMembershipAgeSeconds: Int64 = 86_400
    public static let maxRateWindowSeconds: Int64 = 86_400
    public static let maxDelegationLifetimeSeconds: Int64 = 315_360_000
    public static let maxSafeInteger: Int64 = 9_007_199_254_740_991

    public static let constraintTimeWindow = "time_window"
    public static let constraintMaxAmount = "max_amount"
    public static let constraintMaxRate = "max_rate"
    public static let constraintResourcePath = "resource_path"
    public static let constraintReceiverAudience = "ratify.receiver_audience"
    public static let constraintMaxCount = "com.ratifyprotocol.max_count"
    public static let constraintAllowedValues = "com.ratifyprotocol.allowed_values"
    public static let profileMaxCount = "com.ratifyprotocol.max_count/v1"
    public static let profileAllowedValues = "com.ratifyprotocol.allowed_values/v1"
    public static let freshnessUnverified = "freshness_unverified"
    public static let securityJournalConflictMessage = "security journal compare-and-swap conflict"
    public static let tzdbVersion = "2025c"
}
