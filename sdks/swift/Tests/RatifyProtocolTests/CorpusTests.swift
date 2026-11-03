import Foundation
import XCTest

/// The whole corpus through the public Swift API, on every platform the
/// suite runs on. Every entry of testvectors/v2 must have a runner here, or
/// be listed as pending for a named later milestone; each runner is executed
/// and must report a nonzero case count for its entry. A new corpus file, or
/// a runner that stops executing, fails here. At full parity `pending` is empty.
final class CorpusTests: XCTestCase {
    static let runners: [String: @Sendable () throws -> Void] = [
        "annex-a.json": AnnexARunner.run,
        "keys.json": KeysRunner.run,
        "limits.json": LimitsRunner.run,
        "operation-session-context.json": OperationContextRunner.run,
        "objects.json": ObjectsRunner.objects,
        "object-negatives.json": ObjectsRunner.negatives,
        "hedged-signatures.json": ObjectsRunner.hedged,
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
        "issuer-duties.json": "M2",
        "key-rotation-signature.json": "M2",
        "lifecycle-scenarios.json": "M3",
        "log-sequences.json": "M2",
        "rotation-sequences.json": "M2",
        "security-journal.json": "M2",
        "status-publisher.json": "M2",
        "status-sequences.json": "M2",
        "transaction-verification.json": "M3",
        "verifier-ordering.json": "M3",
    ]

    func testCorpus() throws {
        let entries = Set(try FileManager.default.contentsOfDirectory(atPath: Corpus.dir.path))
        let consumed = Set(Self.runners.keys)
        XCTAssertTrue(consumed.isDisjoint(with: Self.pending.keys), "an entry is both consumed and pending")
        XCTAssertEqual(consumed.union(Self.pending.keys), entries, "runners + pending must equal the corpus")
        Manifest.reset()
        for (file, run) in Self.runners.sorted(by: { $0.key < $1.key }) {
            try run()
            XCTAssertGreaterThan(Manifest.count(file), 0, "\(file): runner reported no executed cases")
        }
    }

    /// No runner may skip: a skipped case is a silent pass.
    func testNoRunnerSkips() throws {
        let dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        let banned = ["XCT" + "Skip", "XCTExpect" + "Failure"]
        for f in try FileManager.default.contentsOfDirectory(atPath: dir.path) where f.hasSuffix(".swift") {
            let src = try String(contentsOf: dir.appendingPathComponent(f), encoding: .utf8)
            for b in banned { XCTAssertFalse(src.contains(b), "\(f) uses \(b)") }
        }
    }
}
