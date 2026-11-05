import Foundation
import XCTest

/// The whole corpus through the public Swift API, on every platform the
/// suite runs on. Every entry of testvectors/v2 must have a runner here, or
/// be listed as pending for a named later milestone; each runner is executed
/// and must report a nonzero case count for its entry. A new corpus file, or
/// a runner that stops executing, fails here. At full parity `pending` is empty.
final class CorpusTests: XCTestCase {
    static let runners: [String: @Sendable () async throws -> Void] = [
        "README.md": CorpusReadmeRunner.run,
        "annex-a.json": AnnexARunner.run,
        "keys.json": KeysRunner.run,
        "limits.json": LimitsRunner.run,
        "operation-session-context.json": OperationContextRunner.run,
        "objects.json": ObjectsRunner.objects,
        "object-negatives.json": ObjectsRunner.negatives,
        "hedged-signatures.json": ObjectsRunner.hedged,
        "delegation-signature.json": SigningRunner.delegationSignature,
        "derive-external-mu.py": SigningRunner.deriveExternalMu,
        "key-rotation-signature.json": SigningRunner.keyRotationSignature,
        "issuer-duties.json": SigningRunner.issuerDuties,
        "external-signer.json": SigningRunner.externalSigner,
        "archival.json": ArchivalRunner.archival,
        "digest-functions.json": ArchivalRunner.digestFunctions,
        "log-sequences.json": LogsRunner.logSequences,
        "rotation-sequences.json": LogsRunner.rotationSequences,
        "status-sequences.json": StatusRunner.statusSequences,
        "challenge-claim.json": StatusRunner.challengeClaim,
        "challenge-issuance.json": ChallengeIssuanceTests.runCorpus,
        "provider-evidence": ProviderEvidenceRunner.run,
        "security-journal.json": JournalRunner.run,
        "status-publisher.json": PublisherRunner.run,
        "evaluator-profiles.json": EvaluatorRunner.run,
        "transaction-verification.json": TransactionVerifyRunner.run,
        "device-state.json": DeviceStateRunner.run,
        "verifier-ordering.json": VerifierOrderingRunner.run,
        "lifecycle-scenarios.json": {
            let test = ClaimTests(selector: #selector(XCTestCase.invokeTest))
            try await test.testLifecycleBasicReleaseScenarios()
        },
    ]

    /// Entries whose runners land in a later milestone (build plan §9).
    static let pending: [String: String] = [
        "concurrency-scenarios.json": "M4",
        "cross-sdk": "M4",
    ]

    func testCorpus() async throws {
        let entries = Set(try FileManager.default.contentsOfDirectory(atPath: Corpus.dir.path))
        let consumed = Set(Self.runners.keys)
        XCTAssertTrue(consumed.isDisjoint(with: Self.pending.keys), "an entry is both consumed and pending")
        XCTAssertEqual(consumed.union(Self.pending.keys), entries, "runners + pending must equal the corpus")
        Manifest.reset()
        for (file, run) in Self.runners.sorted(by: { $0.key < $1.key }) {
            try await run()
            XCTAssertGreaterThan(Manifest.count(file), 0, "\(file): runner reported no executed cases")
            if file == "lifecycle-scenarios.json" {
                let corpus = Corpus.load(file)
                XCTAssertEqual(Manifest.count(file), corpus.arr("scenarios").count + corpus.arr("profile_scenarios").count)
            }
        }
    }

    #if os(macOS)
    /// No runner may skip: a skipped case is a silent pass. A static lint of
    /// the test sources, so it runs where the sources are (macOS).
    func testNoRunnerSkips() throws {
        let dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        let banned = ["XCT" + "Skip", "XCTExpect" + "Failure"]
        for f in try FileManager.default.contentsOfDirectory(atPath: dir.path) where f.hasSuffix(".swift") {
            let src = try String(contentsOf: dir.appendingPathComponent(f), encoding: .utf8)
            for b in banned { XCTAssertFalse(src.contains(b), "\(f) uses \(b)") }
        }
    }
    #endif
}
