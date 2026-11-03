import Foundation
import XCTest

/// Every entry of testvectors/v2 must be consumed by a Swift runner that
/// calls only the public API, or be listed as pending for a named later
/// milestone. A new corpus file, or a runner that stops reading its file,
/// fails here. Pending entries are removed as their runners land; at full
/// parity the pending list is empty.
final class ConsumedTests: XCTestCase {
    static let testsDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()

    /// Corpus entry, runner file, and text the runner must contain to show it reads the entry.
    static let consumed: [(String, String, String)] = [
        ("annex-a.json", "AnnexATests.swift", "\"annex-a.json\""),
        ("keys.json", "KeysTests.swift", "\"keys.json\""),
        ("limits.json", "LimitsTests.swift", "\"limits.json\""),
        ("operation-session-context.json", "OperationContextTests.swift", "\"operation-session-context.json\""),
    ]

    /// Entries whose runners land in a later milestone (build plan §9).
    static let pending: [String: String] = [
        "README.md": "M3",
        "archival.json": "M2",
        "challenge-claim.json": "M2",
        "challenge-issuance.json": "M3",
        "concurrency-scenarios.json": "M4",
        "cross-sdk": "M4",
        "delegation-signature.json": "M2",
        "derive-external-mu.py": "M2",
        "device-state.json": "M3",
        "digest-functions.json": "M2",
        "evaluator-profiles.json": "M3",
        "external-signer.json": "M2",
        "hedged-signatures.json": "M2",
        "issuer-duties.json": "M2",
        "key-rotation-signature.json": "M2",
        "lifecycle-scenarios.json": "M3",
        "log-sequences.json": "M2",
        "object-negatives.json": "M2",
        "objects.json": "M2",
        "rotation-sequences.json": "M2",
        "security-journal.json": "M2",
        "status-publisher.json": "M2",
        "status-sequences.json": "M2",
        "transaction-verification.json": "M3",
        "verifier-ordering.json": "M3",
    ]

    func testEveryCorpusEntryIsConsumedOrPending() throws {
        let entries = Set(try FileManager.default.contentsOfDirectory(atPath: Corpus.dir.path))
        let consumed = Set(Self.consumed.map(\.0))
        XCTAssertTrue(consumed.isDisjoint(with: Self.pending.keys), "an entry is both consumed and pending")
        for e in entries.sorted() {
            XCTAssertTrue(consumed.contains(e) || Self.pending[e] != nil, "corpus entry \(e) has no Swift runner")
        }
        for e in consumed.union(Self.pending.keys) {
            XCTAssertTrue(entries.contains(e), "table lists \(e), which is not in the corpus")
        }
        for (entry, runner, marker) in Self.consumed {
            let src = try String(contentsOf: Self.testsDir.appendingPathComponent(runner), encoding: .utf8)
            XCTAssertTrue(src.contains(marker), "\(runner) no longer reads \(entry)")
        }
    }

    /// No runner may skip: a skipped case is a silent pass.
    func testNoRunnerSkips() throws {
        let banned = ["XCT" + "Skip", "XCTExpect" + "Failure"]
        for f in try FileManager.default.contentsOfDirectory(atPath: Self.testsDir.path) where f.hasSuffix(".swift") {
            let src = try String(contentsOf: Self.testsDir.appendingPathComponent(f), encoding: .utf8)
            for b in banned { XCTAssertFalse(src.contains(b), "\(f) uses \(b)") }
        }
    }
}
