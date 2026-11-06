import Foundation

/// A SPEC-v2 signed-object type; the raw value is its 16-bit code.
public enum ObjectType: UInt16, Sendable, CaseIterable, Hashable {
    case delegationCertificate = 0x0001
    case challengePresentation = 0x0002
    case revocationList = 0x0003
    case keyRotationAuthorization = 0x0004
    case revocationPush = 0x0005
    case witnessEntry = 0x0006
    case transactionPartyStatement = 0x0007
    case verificationReceipt = 0x0008
    case keyRotationProofOfPossession = 0x0009
}

/// Caller-authenticated rotation state for one authority and role.
public struct RotationState: Sendable, Hashable {
    public var authorityId: String
    public var recoveryEpoch: Int64
    public var role: String
    public var sequence: Int64
    public var headHash: Data
    public var currentKey: HybridPublicKey
    /// Complete retained history for this authority, including the current key.
    public var usedKeyIds: [String]

    public init(authorityId: String, recoveryEpoch: Int64, role: String, sequence: Int64,
                headHash: Data, currentKey: HybridPublicKey, usedKeyIds: [String]) {
        self.authorityId = authorityId
        self.recoveryEpoch = recoveryEpoch
        self.role = role
        self.sequence = sequence
        self.headHash = headHash
        self.currentKey = currentKey
        self.usedKeyIds = usedKeyIds
    }

    var ffi: FfiRotationState {
        FfiRotationState(authorityId: authorityId, recoveryEpoch: recoveryEpoch, role: role, sequence: sequence,
                         headHash: headHash, currentKey: currentKey.ffi, usedKeyIds: usedKeyIds)
    }
}

/// Caller-authenticated witness-log state before an entry.
public struct WitnessHead: Sendable, Hashable {
    public var logId: String
    public var sequence: Int64
    public var headHash: Data
    /// Every accepted sequence's body digest, for replay and fork checks.
    public var acceptedDigests: [Int64: Data]
    public var frozen: Bool

    public init(logId: String, sequence: Int64, headHash: Data, acceptedDigests: [Int64: Data] = [:], frozen: Bool = false) {
        self.logId = logId
        self.sequence = sequence
        self.headHash = headHash
        self.acceptedDigests = acceptedDigests
        self.frozen = frozen
    }

    var ffi: FfiWitnessHead {
        FfiWitnessHead(logId: logId, sequence: sequence, headHash: headHash, acceptedDigests: acceptedDigests, frozen: frozen)
    }
}

/// Caller-authenticated receipt-log state before a receipt.
public struct ReceiptHead: Sendable, Hashable {
    public var logId: String
    public var verifierId: String
    public var sequence: Int64
    public var headHash: Data
    public var acceptedDigests: [Int64: Data]
    public var frozen: Bool

    public init(logId: String, verifierId: String, sequence: Int64, headHash: Data,
                acceptedDigests: [Int64: Data] = [:], frozen: Bool = false) {
        self.logId = logId
        self.verifierId = verifierId
        self.sequence = sequence
        self.headHash = headHash
        self.acceptedDigests = acceptedDigests
        self.frozen = frozen
    }

    var ffi: FfiReceiptHead {
        FfiReceiptHead(logId: logId, verifierId: verifierId, sequence: sequence, headHash: headHash,
                       acceptedDigests: acceptedDigests, frozen: frozen)
    }
}

/// What a valid log entry does to its log.
public enum LogResult: Sendable, Hashable {
    /// The next valid entry; persist the new head atomically.
    case appended
    /// An exact accepted body at an accepted sequence; state is unchanged.
    case replay

    init(_ f: FfiLogResult) {
        switch f {
        case .appended: self = .appended
        case .replay: self = .replay
        }
    }
}

// Encoders: the canonical wire form of each object (SPEC-v2 §2).
extension Ratify {
    public static func encodeDelegationCert(_ v: DelegationCert) throws(RatifyError) -> Data {
        try ffi { try ffiEncodeDelegationCert(cert: v.ffi) }
    }
    public static func encodeProofBundle(_ v: ProofBundle) throws(RatifyError) -> Data {
        try ffi { try ffiEncodeProofBundle(bundle: v.ffi) }
    }
    public static func encodeRevocationList(_ v: RevocationList) throws(RatifyError) -> Data {
        try ffi { try ffiEncodeRevocationList(list: v.ffi) }
    }
    public static func encodeRevocationPush(_ v: RevocationPush) throws(RatifyError) -> Data {
        try ffi { try ffiEncodeRevocationPush(push: v.ffi) }
    }
    public static func encodeKeyRotationStatement(_ v: KeyRotationStatement) throws(RatifyError) -> Data {
        try ffi { try ffiEncodeKeyRotationStatement(statement: v.ffi) }
    }
    public static func encodeWitnessEntry(_ v: WitnessEntry) throws(RatifyError) -> Data {
        try ffi { try ffiEncodeWitnessEntry(entry: v.ffi) }
    }
    public static func encodeVerificationReceipt(_ v: VerificationReceipt) throws(RatifyError) -> Data {
        try ffi { try ffiEncodeVerificationReceipt(receipt: v.ffi) }
    }
    public static func encodeTransactionReceipt(_ v: TransactionReceipt) throws(RatifyError) -> Data {
        try ffi { try ffiEncodeTransactionReceipt(receipt: v.ffi) }
    }
}

// Signature verification (SPEC-v2 §3, §5). Each throws the failure's §2.7 class.
extension Ratify {
    public static func verifyDelegationCertSignature(_ cert: DelegationCert) throws(RatifyError) {
        try ffi { try ffiVerifyDelegationCertSignature(cert: cert.ffi) }
    }
    public static func verifyProofBundleSignatures(_ bundle: ProofBundle) throws(RatifyError) {
        try ffi { try ffiVerifyProofBundleSignatures(bundle: bundle.ffi) }
    }
    public static func verifyRevocationListSignature(_ list: RevocationList, trustedIssuerId: String,
                                                     statusKey: HybridPublicKey) throws(RatifyError) {
        try ffi { try ffiVerifyRevocationListSignature(list: list.ffi, trustedIssuerId: trustedIssuerId, statusKey: statusKey.ffi) }
    }
    public static func verifyRevocationPushSignature(_ push: RevocationPush, trustedIssuerId: String,
                                                     statusKey: HybridPublicKey) throws(RatifyError) {
        try ffi { try ffiVerifyRevocationPushSignature(push: push.ffi, trustedIssuerId: trustedIssuerId, statusKey: statusKey.ffi) }
    }
    public static func verifyKeyRotationStatement(_ statement: KeyRotationStatement, state: RotationState,
                                                  now: Int64, futureSkew: Int64) throws(RatifyError) {
        try ffi { try ffiVerifyKeyRotationStatement(statement: statement.ffi, state: state.ffi, now: now, futureSkew: futureSkew) }
    }
    public static func verifyWitnessEntry(_ entry: WitnessEntry, head: WitnessHead,
                                          witnessKey: HybridPublicKey) throws(RatifyError) -> LogResult {
        LogResult(try ffi { try ffiVerifyWitnessEntry(entry: entry.ffi, head: head.ffi, witnessKey: witnessKey.ffi) })
    }
    public static func verifyTransactionReceiptSignatures(_ receipt: TransactionReceipt) throws(RatifyError) {
        try ffi { try ffiVerifyTransactionReceiptSignatures(receipt: receipt.ffi) }
    }
    public static func verifyVerificationReceipt(_ receipt: VerificationReceipt, verifierKey: HybridPublicKey,
                                                 head: ReceiptHead) throws(RatifyError) -> LogResult {
        LogResult(try ffi { try ffiVerifyVerificationReceipt(receipt: receipt.ffi, verifierKey: verifierKey.ffi, head: head.ffi) })
    }
    public static func checkVerificationReceiptBundleBinding(_ receipt: VerificationReceipt,
                                                             bundle: ProofBundle) throws(RatifyError) {
        try ffi { try ffiCheckVerificationReceiptBundleBinding(receipt: receipt.ffi, bundle: bundle.ffi) }
    }
}

// The signing transcript (SPEC-v2 §3).
extension Ratify {
    /// The 77-byte signing message `M` over an object's signable bytes.
    public static func signingMessage(_ type: ObjectType, signable: Data) throws(RatifyError) -> Data {
        try ffi { try ffiSigningMessage(objectTypeCode: type.rawValue, signable: signable) }
    }
    /// The 22-byte ML-DSA-65 context string for an object type.
    public static func mldsaContext(_ type: ObjectType) throws(RatifyError) -> Data {
        try ffi { try ffiMldsaContext(objectTypeCode: type.rawValue) }
    }
    /// Verify both components of a hybrid signature over signable bytes.
    public static func verifyStatement(_ type: ObjectType, signable: Data, signature: HybridSignature,
                                       publicKey: HybridPublicKey) throws(RatifyError) {
        try ffi { try ffiVerifyStatement(objectTypeCode: type.rawValue, signable: signable, signature: signature.ffi, publicKey: publicKey.ffi) }
    }
    /// The FIPS 204 external `mu` for an ML-DSA-65 public key, context and message.
    public static func externalMu(mlDsaPublicKey: Data, mlDsaContext: Data, message: Data) throws(RatifyError) -> Data {
        try ffi { try ffiExternalMu(mlDsaPublicKey: mlDsaPublicKey, mlDsaContext: mlDsaContext, message: message) }
    }
}

// Digests (SPEC-v2 §4, §6, §7).
extension Ratify {
    public static func bundleHash(_ bundle: ProofBundle) throws(RatifyError) -> String {
        try ffi { try ffiBundleHash(bundle: bundle.ffi) }
    }
    public static func challengeClaimDigest(_ challenge: Data) throws(RatifyError) -> Data {
        try ffi { try ffiChallengeClaimDigest(challenge: challenge) }
    }
    public static func protocolClaimId(namespace: String, replayEpoch: Int64, challenge: Data) throws(RatifyError) -> String {
        try ffi { try ffiProtocolClaimId(namespace: namespace, replayEpoch: replayEpoch, challenge: challenge) }
    }
    public static func verificationReceiptBody(_ receipt: VerificationReceipt) throws(RatifyError) -> Data {
        try ffi { try ffiVerificationReceiptBody(receipt: receipt.ffi) }
    }
    public static func statusEvidenceDigest(_ list: RevocationList) throws(RatifyError) -> Data {
        try ffi { try ffiStatusEvidenceDigestList(list: list.ffi) }
    }
    public static func statusEvidenceDigest(_ push: RevocationPush) throws(RatifyError) -> Data {
        try ffi { try ffiStatusEvidenceDigestPush(push: push.ffi) }
    }
    public static func keyRotationStatementDigest(_ statement: KeyRotationStatement) throws(RatifyError) -> Data {
        try ffi { try ffiKeyRotationStatementDigest(statement: statement.ffi) }
    }
    public static func witnessEntryDigest(_ entry: WitnessEntry) throws(RatifyError) -> Data {
        try ffi { try ffiWitnessEntryDigest(entry: entry.ffi) }
    }
    public static func verificationReceiptDigest(_ receipt: VerificationReceipt) throws(RatifyError) -> Data {
        try ffi { try ffiVerificationReceiptDigest(receipt: receipt.ffi) }
    }
    public static func transactionContextHash(_ receipt: TransactionReceipt) throws(RatifyError) -> Data {
        try ffi { try ffiTransactionContextHash(receipt: receipt.ffi) }
    }
    public static func transactionPartyRequestHash(_ transactionHash: Data, requiredScope: String) throws(RatifyError) -> Data {
        try ffi { try ffiTransactionPartyRequestHash(transactionHash: transactionHash, requiredScope: requiredScope) }
    }
}

// Signable projections (SPEC-v2 §5): the exact bytes each signature covers.
extension Ratify {
    public static func delegationCertSignableBytes(_ v: DelegationCert) throws(RatifyError) -> Data {
        try ffi { try ffiDelegationCertSignableBytes(cert: v.ffi) }
    }
    public static func presentationSignableBytes(_ v: ProofBundle) throws(RatifyError) -> Data {
        try ffi { try ffiPresentationSignableBytes(bundle: v.ffi) }
    }
    public static func revocationListSignableBytes(_ v: RevocationList) throws(RatifyError) -> Data {
        try ffi { try ffiRevocationListSignableBytes(list: v.ffi) }
    }
    public static func revocationPushSignableBytes(_ v: RevocationPush) throws(RatifyError) -> Data {
        try ffi { try ffiRevocationPushSignableBytes(push: v.ffi) }
    }
    public static func keyRotationStatementSignableBytes(_ v: KeyRotationStatement) throws(RatifyError) -> Data {
        try ffi { try ffiKeyRotationStatementSignableBytes(statement: v.ffi) }
    }
    public static func witnessEntrySignableBytes(_ v: WitnessEntry) throws(RatifyError) -> Data {
        try ffi { try ffiWitnessEntrySignableBytes(entry: v.ffi) }
    }
    public static func verificationReceiptSignableBytes(_ v: VerificationReceipt) throws(RatifyError) -> Data {
        try ffi { try ffiVerificationReceiptSignableBytes(receipt: v.ffi) }
    }
    public static func transactionReceiptSignBytes(_ v: TransactionReceipt) throws(RatifyError) -> Data {
        try ffi { try ffiTransactionReceiptSignBytes(receipt: v.ffi) }
    }
}
