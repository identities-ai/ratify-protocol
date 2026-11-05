import CryptoKit
import Foundation
import XCTest
import RatifyProtocol

/// limits.json through the public decoders: every size and count limit is
/// accepted at the limit and rejected one past it, before parsing.
enum LimitsRunner {
    static func build(_ c: [String: Any]) -> Data {
        func opt(_ k: String) -> Data { c[k] == nil ? Data() : c.b64(k) }
        switch c.s("method") {
        case "inline":
            return c.b64("wire_b64")
        case "pad":
            var base = c.b64("base_b64")
            let last = base.removeLast()
            base.append(Data(repeating: UInt8(ascii: " "), count: c.int("pad_count")))
            base.append(last)
            return base
        case "repeat_items":
            var out = opt("prefix_b64")
            let digits = c["item_index_digits"] == nil ? 0 : c.int("item_index_digits")
            let prefix = c["item_prefix"] as? String ?? ""
            let suffix = c["item_suffix"] as? String ?? ""
            for n in 0..<c.int("count") {
                if n > 0 { out.append(UInt8(ascii: ",")) }
                var num = String(n)
                if num.count < digits { num = String(repeating: "0", count: digits - num.count) + num }
                out.append(Data("\(prefix)\(num)\(suffix)".utf8))
            }
            out.append(opt("suffix_b64"))
            return out
        case "repeat_bytes":
            var out = opt("prefix_b64")
            let item = c.b64("item_b64")
            for _ in 0..<c.int("count") { out.append(item) }
            out.append(opt("suffix_b64"))
            return out
        case "repeat_item":
            var out = opt("prefix_b64")
            let item = c.b64("item_b64")
            for n in 0..<c.int("count") {
                if n > 0 { out.append(UInt8(ascii: ",")) }
                out.append(item)
            }
            out.append(opt("suffix_b64"))
            return out
        default:
            preconditionFailure("unknown construction \(c.s("method"))")
        }
    }

    static func decode(_ kind: String, _ data: Data) throws {
        switch kind {
        case "delegation_certificate": _ = try Ratify.decodeDelegationCert(data)
        case "proof_bundle": _ = try Ratify.decodeProofBundle(data)
        case "key_rotation_statement": _ = try Ratify.decodeKeyRotationStatement(data)
        case "revocation_list": _ = try Ratify.decodeRevocationList(data)
        case "revocation_push": _ = try Ratify.decodeRevocationPush(data)
        case "witness_entry": _ = try Ratify.decodeWitnessEntry(data)
        case "verification_receipt": _ = try Ratify.decodeVerificationReceipt(data)
        case "verification_receipt_body": _ = try Ratify.decodeVerificationReceiptBody(data)
        case "transaction_receipt": _ = try Ratify.decodeTransactionReceipt(data)
        case "status_evidence_batch": _ = try Ratify.decodeStatusEvidenceBatch(data)
        default: preconditionFailure("no decoder for \(kind)")
        }
    }

    static func run() throws {
        let f = Corpus.load("limits.json")
        let table = f.obj("limits")
        let exported: [String: Int64] = [
            "MAX_DELEGATION_CERT_BYTES_V2": Int64(Ratify.maxDelegationCertBytes),
            "MAX_KEY_ROTATION_STATEMENT_BYTES_V2": Int64(Ratify.maxKeyRotationStatementBytes),
            "MAX_PROOF_BUNDLE_BYTES_V2": Int64(Ratify.maxProofBundleBytes),
            "MAX_REVOCATION_LIST_BYTES_V2": Int64(Ratify.maxRevocationListBytes),
            "MAX_REVOCATION_LIST_REFS_V2": Int64(Ratify.maxRevocationListRefs),
            "MAX_REVOCATION_PUSH_BYTES_V2": Int64(Ratify.maxRevocationPushBytes),
            "MAX_REVOCATION_PUSH_REFS_V2": Int64(Ratify.maxRevocationPushRefs),
            "MAX_STATUS_EVIDENCE_BATCH_BYTES_V2": Int64(Ratify.maxStatusEvidenceBatchBytes),
            "MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2": Int64(Ratify.maxStatusEvidenceBatchObjects),
            "MAX_TIMESTAMP_SECONDS_V2": Ratify.maxTimestampSeconds,
            "MAX_TRANSACTION_RECEIPT_BYTES_V2": Int64(Ratify.maxTransactionReceiptBytes),
            "MAX_VERIFICATION_RECEIPT_BODY_BYTES_V2": Int64(Ratify.maxVerificationReceiptBodyBytes),
            "MAX_VERIFICATION_RECEIPT_BYTES_V2": Int64(Ratify.maxVerificationReceiptBytes),
            "MAX_WITNESS_ENTRY_BYTES_V2": Int64(Ratify.maxWitnessEntryBytes),
            "MAX_WITNESS_ENTRY_DATA_BYTES_V2": Int64(Ratify.maxWitnessEntryDataBytes),
        ]
        for (name, value) in exported {
            XCTAssertEqual(value, (table[name] as? NSNumber)?.int64Value, "public limit \(name)")
        }
        let t = Tally("limits.json")
        let vectors = f.arr("vectors")
        for v in vectors {
            let name = v.s("name")
            let limit = v.s("limit")
            XCTAssertEqual((table[limit] as! NSNumber).int64Value, (v["limit_value"] as! NSNumber).int64Value, "\(name): limit table")
            let data = build(v.obj("construction"))
            XCTAssertEqual(data.count, v.int("length"), "\(name): length")
            XCTAssertEqual(Data(SHA256.hash(data: data)).hex, v.s("sha256_hex"), "\(name): digest")
            var failure: RatifyError?
            do { try decode(v.s("kind"), data) } catch let e as RatifyError { failure = e } catch { XCTFail("\(error)") }
            let expectationOk: Bool
            switch v.s("expected") {
            case "accept": expectationOk = failure == nil
            case "reject": expectationOk = failure?.errorClass?.rawValue == v.s("expected_error_class")
            default: preconditionFailure("unknown expectation")
            }
            var message = ""
            if case let .protocol(_, m)? = failure { message = m }
            let gateFailed = message.contains("exceeds \(limit) (") && message.contains("rejected before parsing")
            let gateOk = (v.s("size_gate") == "fail") == gateFailed
            t.check("limits", name, expectationOk && gateOk, "\(String(describing: failure))")
        }
        t.finish([("limits", vectors.count)])
    }
}
