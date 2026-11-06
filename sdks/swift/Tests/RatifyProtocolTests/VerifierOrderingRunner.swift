import Foundation
import XCTest

/// The complete verifier-ordering corpus through the public Swift API.
enum VerifierOrderingRunner {
    static func run() async throws {
        let file = "verifier-ordering.json"
        let vectors = Corpus.load(file).arr("vectors")
        let count = vectors.count
        XCTAssertEqual(count, 515)
        XCTAssertEqual(Set(vectors.map { $0.obj("expected").s("stage") }),
            Set(["preflight", "replay", "evaluating", "committed"]))
        let tests = ClaimTests(selector: #selector(ClaimTests.corpusHarness))
        try await tests.verifierCorpusPreflightOrdering()
        try await tests.verifierCorpusReplay()
        try await tests.verifierCorpusFinalizationRefusals()
        try await tests.verifierCorpusCommittedReceipts()
        Manifest.record(file, count)
    }
}
