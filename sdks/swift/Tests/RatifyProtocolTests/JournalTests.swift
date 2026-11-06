import Foundation
import XCTest
import RatifyProtocol

final class JournalTests: XCTestCase {
    actor BrokenStore: SecurityJournalStore {
        let initial: SecurityJournalSnapshot
        let conflict: Bool
        init(_ initial: SecurityJournalSnapshot, conflict: Bool) {
            self.initial = initial
            self.conflict = conflict
        }
        func load() -> SecurityJournalSnapshot { initial }
        func compareAndSwap(expected: SecurityJournalHead, next: SecurityJournalSnapshot) throws {
            if conflict { throw SecurityJournalStoreError.conflict }
        }
    }

    actor Store: SecurityJournalStore {
        private var current: SecurityJournalSnapshot
        private(set) var writes = 0

        init(_ initial: SecurityJournalSnapshot) { current = initial }
        func load() -> SecurityJournalSnapshot { current }
        func compareAndSwap(expected: SecurityJournalHead, next: SecurityJournalSnapshot) throws {
            guard current.head == expected else { throw SecurityJournalStoreError.conflict }
            current = next
            writes += 1
        }
    }

    func testStoreCallbackCommitsTheSharedJournalTransitionOnce() async throws {
        let vector = Corpus.load("security-journal.json")
        let step = vector.arr("scenarios")[0].arr("steps")[0]
        let store = Store(try Ratify.emptySecurityJournalSnapshot())
        let key = Fixture.shared.key("verifier")
        let result = try await Ratify.recordSecurityKeyRole(store: store, role: "verifier", key: key)
        XCTAssertEqual(result.head.generation, UInt64(step.obj("expect_head").int("generation")))
        XCTAssertEqual(result.head.digest, step.obj("expect_head").s("digest"))
        XCTAssertEqual(result.snapshot, step.b64("expect_snapshot_b64"))
        let firstWrites = await store.writes
        XCTAssertEqual(firstWrites, 1)
        let retry = try await Ratify.recordSecurityKeyRole(store: store, role: "verifier", key: key)
        XCTAssertEqual(retry, result)
        let retryWrites = await store.writes
        XCTAssertEqual(retryWrites, 1)
    }

    func testGenesisRequiresIndependentHead() throws {
        let vector = Corpus.load("security-journal.json")
        let genesis = try Ratify.emptySecurityJournalSnapshot()
        XCTAssertEqual(String(decoding: genesis.snapshot, as: UTF8.self), vector.s("genesis_snapshot"))
        XCTAssertEqual(genesis.head.digest, vector.s("genesis_digest"))
        XCTAssertEqual(try Ratify.securityJournalSnapshotDigest(genesis.snapshot), genesis.head.digest)
        try Ratify.validateSecurityJournalSnapshot(genesis.snapshot, head: genesis.head)
        for negative in vector.arr("import_negatives") {
            let head = negative.obj("head")
            XCTAssertThrowsError(try Ratify.validateSecurityJournalSnapshot(
                negative.b64("snapshot_b64"),
                head: SecurityJournalHead(generation: UInt64(head.int("generation")), digest: head.s("digest"))
            ), negative.s("name")) { error in
                XCTAssertEqual((error as? RatifyError)?.errorClass?.rawValue, negative.s("expect_error_class"))
            }
        }
    }

    func testStoreRejectsRolledBackHeadAndCompareAndSwapConflict() async throws {
        let genesis = try Ratify.emptySecurityJournalSnapshot()
        let rolled = SecurityJournalSnapshot(snapshot: genesis.snapshot,
            head: SecurityJournalHead(generation: genesis.head.generation, digest: String(repeating: "0", count: 64)))
        let key = Fixture.shared.key("verifier")
        do {
            _ = try await Ratify.recordSecurityKeyRole(store: BrokenStore(rolled, conflict: false), role: "verifier", key: key)
            XCTFail("rolled back head accepted")
        } catch {
            XCTAssertEqual(error.errorClass, .statusObjectRejected)
        }
        do {
            _ = try await Ratify.recordSecurityKeyRole(store: BrokenStore(genesis, conflict: true), role: "verifier", key: key)
            XCTFail("compare-and-swap conflict accepted")
        } catch {
            XCTAssertEqual(error.errorClass, .statusObjectRejected)
            XCTAssertTrue(error.description.contains("security journal compare-and-swap conflict"))
        }
    }
}
