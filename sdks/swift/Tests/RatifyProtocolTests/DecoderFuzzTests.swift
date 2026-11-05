import Foundation
import XCTest
import RatifyProtocol

/// Seeded mutations run through the public decoders. The CI default is one
/// minute per input kind; RATIFY_FUZZ_SECONDS shortens local rehearsals.
final class DecoderFuzzTests: XCTestCase {
    func testPublicDecoders() throws {
        let objects = Corpus.load("objects.json").arr("objects")
        let kinds: [(String, (Data) throws -> Void)] = [
            ("delegation_certificate", { _ = try Ratify.decodeDelegationCert($0) }),
            ("proof_bundle", { _ = try Ratify.decodeProofBundle($0) }),
            ("revocation_list", { _ = try Ratify.decodeRevocationList($0) }),
            ("revocation_push", { _ = try Ratify.decodeRevocationPush($0) }),
            ("key_rotation_statement", { _ = try Ratify.decodeKeyRotationStatement($0) }),
            ("witness_entry", { _ = try Ratify.decodeWitnessEntry($0) }),
            ("verification_receipt", { _ = try Ratify.decodeVerificationReceipt($0) }),
            ("transaction_receipt", { _ = try Ratify.decodeTransactionReceipt($0) }),
        ]
        var seeds = kinds.map { kind, decode in
            (kind, objects.first { $0.s("kind") == kind }!.b64("wire_b64"), decode)
        }
        let receipt = try Ratify.decodeVerificationReceipt(
            objects.first { $0.s("kind") == "verification_receipt" }!.b64("wire_b64"))
        seeds.append(("verification_receipt_body", try Ratify.verificationReceiptBody(receipt),
            { _ = try Ratify.decodeVerificationReceiptBody($0) }))
        seeds.append(("status_evidence_batch", Data("[]".utf8),
            { _ = try Ratify.decodeStatusEvidenceBatch($0) }))
        let snapshot = try Ratify.emptySecurityJournalSnapshot()
        seeds.append(("security_journal_snapshot", snapshot.snapshot,
            { try Ratify.validateSecurityJournalSnapshot($0, head: snapshot.head) }))
        let ack = CheckpointAcknowledgement(logId: String(repeating: "0", count: 32),
            sequence: 1, entryHash: Data(repeating: 0, count: 48), timestamp: 1_800_000_000)
        let ackWire = try Ratify.encodeCheckpointAcknowledgement(ack)
        let decodedAck = try Ratify.decodeCheckpointAcknowledgement(ackWire)
        XCTAssertEqual(decodedAck.logId, ack.logId)
        XCTAssertEqual(decodedAck.entryHash, ack.entryHash)
        XCTAssertEqual(try Ratify.encodeCheckpointAcknowledgement(decodedAck), ackWire)
        XCTAssertThrowsError(try Ratify.decodeCheckpointAcknowledgement(ackWire + Data(" ".utf8))) {
            XCTAssertEqual(($0 as? RatifyError)?.errorClass, .malformed)
        }
        seeds.append(("checkpoint_acknowledgement", ackWire,
            { _ = try Ratify.decodeCheckpointAcknowledgement($0) }))

        let seconds = Double(ProcessInfo.processInfo.environment["RATIFY_FUZZ_SECONDS"] ?? "60")!
        XCTAssertGreaterThan(seconds, 0)
        var state: UInt64 = 0x7261746966797632
        func random() -> UInt64 {
            state &+= 0x9e3779b97f4a7c15
            var value = state
            value = (value ^ (value >> 30)) &* 0xbf58476d1ce4e5b9
            value = (value ^ (value >> 27)) &* 0x94d049bb133111eb
            return value ^ (value >> 31)
        }
        for (kind, wire, decode) in seeds {
            try decode(wire)
            let deadline = Date().timeIntervalSinceReferenceDate + seconds
            var iterations = 0
            var peakBytes = 0
            repeat {
                var mutated = wire
                switch iterations % 4 {
                case 0:
                    let offset = Int(random() % UInt64(max(1, mutated.count)))
                    mutated[offset] ^= UInt8(truncatingIfNeeded: random()) | 1
                case 1:
                    mutated = Data(mutated.prefix(Int(random() % UInt64(max(1, mutated.count)))))
                case 2:
                    let offset = Int(random() % UInt64(max(1, mutated.count)))
                    mutated.replaceSubrange(offset..<offset, with: wire.prefix(min(32, wire.count)))
                default:
                    mutated.append(Data(repeating: 0x7b, count: (iterations / 4) % 2 == 0 ? 1_048_576 : 1_048_577))
                }
                do { try decode(mutated) } catch is RatifyError { }
                iterations += 1
                var usage = rusage()
                if getrusage(RUSAGE_SELF, &usage) == 0 { peakBytes = max(peakBytes, Int(usage.ru_maxrss)) }
            } while Date().timeIntervalSinceReferenceDate < deadline
            XCTAssertGreaterThan(iterations, 0, kind)
            print("FUZZ Swift \(kind): iterations=\(iterations) peak_bytes=\(peakBytes)")
        }
    }
}
