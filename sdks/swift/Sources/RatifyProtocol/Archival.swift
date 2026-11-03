import Foundation

/// One stored object decoded strictly with its signatures verified
/// (SPEC-v2 §6.10). Never an authorization decision: `actionable` is always
/// false and `freshness` is always "unverified".
public struct ArchivalVerification: Sendable, Hashable {
    public let objectType: UInt16
    public let freshness: String
    public let actionable: Bool
    /// `sha384:` + 96 hex of the registered digest; empty when the object has none.
    public let digest: String
    /// The v2 key IDs whose signatures were verified, in object order.
    public let signerKeyIds: [String]

    init(_ f: FfiArchivalVerification) {
        objectType = f.objectType
        freshness = f.freshness
        actionable = f.actionable
        digest = f.digest
        signerKeyIds = f.signerKeyIds
    }
}

/// The §6.10 archival proof-bundle result. It has no decision and is never
/// actionable; `errorClass` is nil when every check passed.
public struct ArchivalProofBundleResult: Sendable, Hashable {
    public let assessment: String
    public let actionable: Bool
    public let bundleHash: String
    public let agentId: String
    public let issuerIds: [String]
    public let errorClass: ErrorClass?
    /// The diagnostic for `errorClass`; not part of the language-neutral result.
    public let errorMessage: String

    init(_ f: FfiArchivalProofBundleResult) {
        assessment = f.assessment
        actionable = f.actionable
        bundleHash = f.bundleHash
        agentId = f.agentId
        issuerIds = f.issuerIds
        errorClass = f.errorClass.map(ErrorClass.init(spelling:))
        errorMessage = f.errorMessage
    }

    var ffi: FfiArchivalProofBundleResult {
        FfiArchivalProofBundleResult(assessment: assessment, actionable: actionable, bundleHash: bundleHash, agentId: agentId,
                                     issuerIds: issuerIds, errorClass: errorClass?.rawValue, errorMessage: errorMessage)
    }

    /// The language-neutral canonical JSON of this result.
    public func json() throws(RatifyError) -> Data {
        let f = ffi
        return try RatifyProtocol.ffi { try ffiArchivalProofBundleResultJson(result: f) }
    }
}

/// A status object: a full revocation list or an incremental push.
public enum StatusObject: Sendable, Hashable {
    case list(RevocationList)
    case push(RevocationPush)

    var ffi: FfiStatusObject {
        switch self {
        case let .list(l): return .list(list: l.ffi)
        case let .push(p): return .push(push: p.ffi)
        }
    }
}

extension Ratify {
    public static func verifyArchivalProofBundle(_ data: Data) throws(RatifyError) -> ArchivalProofBundleResult {
        ArchivalProofBundleResult(try ffi { try ffiVerifyArchivalProofBundle(data: data) })
    }
    public static func verifyArchivalDelegationCert(_ data: Data) throws(RatifyError) -> ArchivalVerification {
        ArchivalVerification(try ffi { try ffiVerifyArchivalDelegationCert(data: data) })
    }
    public static func verifyArchivalRevocationList(_ data: Data, issuerId: String,
                                                    statusKey: HybridPublicKey) throws(RatifyError) -> ArchivalVerification {
        ArchivalVerification(try ffi { try ffiVerifyArchivalRevocationList(data: data, issuerId: issuerId, statusKey: statusKey.ffi) })
    }
    public static func verifyArchivalRevocationPush(_ data: Data, issuerId: String,
                                                    statusKey: HybridPublicKey) throws(RatifyError) -> ArchivalVerification {
        ArchivalVerification(try ffi { try ffiVerifyArchivalRevocationPush(data: data, issuerId: issuerId, statusKey: statusKey.ffi) })
    }
    public static func verifyArchivalKeyRotationStatement(_ data: Data) throws(RatifyError) -> ArchivalVerification {
        ArchivalVerification(try ffi { try ffiVerifyArchivalKeyRotationStatement(data: data) })
    }
    public static func verifyArchivalWitnessEntry(_ data: Data, witnessKey: HybridPublicKey) throws(RatifyError) -> ArchivalVerification {
        ArchivalVerification(try ffi { try ffiVerifyArchivalWitnessEntry(data: data, witnessKey: witnessKey.ffi) })
    }
    public static func verifyArchivalVerificationReceipt(_ data: Data, verifierKey: HybridPublicKey) throws(RatifyError) -> ArchivalVerification {
        ArchivalVerification(try ffi { try ffiVerifyArchivalVerificationReceipt(data: data, verifierKey: verifierKey.ffi) })
    }
    public static func verifyArchivalTransactionReceipt(_ data: Data) throws(RatifyError) -> ArchivalVerification {
        ArchivalVerification(try ffi { try ffiVerifyArchivalTransactionReceipt(data: data) })
    }

    /// `StatementBodyDigestV2` under an explicit object type code (SPEC-v2 §4).
    public static func statementBodyDigest(objectTypeCode: UInt16, signableBody: Data) throws(RatifyError) -> Data {
        try ffi { try ffiStatementBodyDigest(objectTypeCode: objectTypeCode, signableBody: signableBody) }
    }
    /// `StatusEvidenceDigest` under an explicit code: 0x0003 takes a list, 0x0005 a push.
    public static func statusEvidenceDigest(objectTypeCode: UInt16, _ object: StatusObject) throws(RatifyError) -> Data {
        let o = object.ffi
        return try ffi { try ffiStatusEvidenceDigest(objectTypeCode: objectTypeCode, object: o) }
    }
}
