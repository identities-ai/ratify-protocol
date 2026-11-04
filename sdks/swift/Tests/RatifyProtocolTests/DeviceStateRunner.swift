import CryptoKit
import Foundation
import RatifyProtocolTestSupport

enum DeviceStateRunner {
    static func run() throws {
        let file = "device-state.json"
        let cases = Corpus.load(file).arr("cases")
        let tally = Tally(file)
        for c in cases {
            let name = c.s("name")
            let state = try JSONSerialization.data(withJSONObject: c.obj("state"))
            let got = try DeviceStateProjection(stateJSON: state)
            let want = c.obj("expect")
            for (member, bytes) in [
                ("claims", got.claims),
                ("streams", got.streams),
                ("rate_counters", got.rateCounters),
                ("receipt_log", got.receiptLog),
                ("issuance_records", got.issuanceRecords),
            ] {
                tally.check("members", "\(name)/\(member)/canonical", String(data: bytes, encoding: .utf8) == want.s("\(member)_canonical_json"))
                tally.check("members", "\(name)/\(member)/digest", Data(SHA384.hash(data: bytes)).hex == want.s("\(member)_sha384"))
            }
            tally.check("projection", name, String(data: got.projection, encoding: .utf8) == want.s("projection_canonical_json"))
            tally.check("digest", name, got.completeStateDigest.hex == want.s("complete_state_digest_hex"))
        }
        tally.finish([("members", cases.count * 10), ("projection", cases.count), ("digest", cases.count)])
    }
}
