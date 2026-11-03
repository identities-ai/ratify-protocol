import Foundation

/// A constraint `params` value: JSON without floats.
public indirect enum ParamsValue: Sendable, Hashable {
    case null
    case bool(Bool)
    case int(Int64)
    case string(String)
    case array([ParamsValue])
    case object([String: ParamsValue])

    init(_ f: FfiParamsValue) {
        switch f {
        case .null: self = .null
        case let .bool(v): self = .bool(v)
        case let .int(v): self = .int(v)
        case let .str(v): self = .string(v)
        case let .array(items): self = .array(items.map(ParamsValue.init))
        case let .object(entries): self = .object(entries.mapValues(ParamsValue.init))
        }
    }

    var ffi: FfiParamsValue {
        switch self {
        case .null: return .null
        case let .bool(v): return .bool(value: v)
        case let .int(v): return .int(value: v)
        case let .string(v): return .str(value: v)
        case let .array(items): return .array(items: items.map(\.ffi))
        case let .object(entries): return .object(entries: entries.mapValues(\.ffi))
        }
    }
}

/// Strict decoders (SPEC-v2 §2): each accepts only the canonical wire form of
/// one object kind and throws its §2.7 class otherwise.
extension Ratify {
    public static func decodeDelegationCert(_ data: Data) throws(RatifyError) -> DelegationCert {
        DelegationCert(try ffi { try ffiDecodeDelegationCert(data: data) })
    }
    public static func decodeProofBundle(_ data: Data) throws(RatifyError) -> ProofBundle {
        ProofBundle(try ffi { try ffiDecodeProofBundle(data: data) })
    }
    public static func decodeRevocationList(_ data: Data) throws(RatifyError) -> RevocationList {
        RevocationList(try ffi { try ffiDecodeRevocationList(data: data) })
    }
    public static func decodeRevocationPush(_ data: Data) throws(RatifyError) -> RevocationPush {
        RevocationPush(try ffi { try ffiDecodeRevocationPush(data: data) })
    }
    public static func decodeKeyRotationStatement(_ data: Data) throws(RatifyError) -> KeyRotationStatement {
        KeyRotationStatement(try ffi { try ffiDecodeKeyRotationStatement(data: data) })
    }
    public static func decodeWitnessEntry(_ data: Data) throws(RatifyError) -> WitnessEntry {
        WitnessEntry(try ffi { try ffiDecodeWitnessEntry(data: data) })
    }
    public static func decodeVerificationReceipt(_ data: Data) throws(RatifyError) -> VerificationReceipt {
        VerificationReceipt(try ffi { try ffiDecodeVerificationReceipt(data: data) })
    }
    public static func decodeVerificationReceiptBody(_ data: Data) throws(RatifyError) -> VerificationReceipt {
        VerificationReceipt(try ffi { try ffiDecodeVerificationReceiptBody(data: data) })
    }
    public static func decodeTransactionReceipt(_ data: Data) throws(RatifyError) -> TransactionReceipt {
        TransactionReceipt(try ffi { try ffiDecodeTransactionReceipt(data: data) })
    }
    public static func decodeStatusEvidenceBatch(_ data: Data) throws(RatifyError) -> [StatusEvidenceObject] {
        try ffi { try ffiDecodeStatusEvidenceBatch(data: data) }.map(StatusEvidenceObject.init)
    }
}
