import Foundation
import XCTest
import RatifyProtocol

final class ChallengeIssuanceTests: XCTestCase {
    struct Clock: AuthoritativeClock {
        let time: Int64
        func authoritativeTime() -> Int64 { time }
    }

    struct Random: ChallengeRandomSource {
        let bytes: Data
        func fill(count: Int) -> Data { bytes }
    }

    struct SlowClock: AuthoritativeClock {
        func authoritativeTime() async throws -> Int64 {
            try await Task.sleep(for: .seconds(10))
            return 1_799_999_990
        }
    }

    struct CancelledClock: AuthoritativeClock {
        func authoritativeTime() throws -> Int64 { throw CancellationError() }
    }

    struct CancelledRandom: ChallengeRandomSource {
        func fill(count: Int) throws -> Data { throw CancellationError() }
    }

    actor CancelledStore: ChallengeIssuanceStore {
        func persist(_ record: ExpectedChallenge) throws { throw CancellationError() }
        func load(namespace: String, replayEpoch: Int64, claimDigest: Data) throws -> ExpectedChallenge {
            throw StoreError.challengeIssuanceNotFound
        }
    }

    struct SlowRandom: ChallengeRandomSource {
        func fill(count: Int) async throws -> Data {
            try await Task.sleep(for: .seconds(10))
            return Data(repeating: 0x11, count: count)
        }
    }

    actor SlowStore: ChallengeIssuanceStore {
        func persist(_ record: ExpectedChallenge) async throws { try await Task.sleep(for: .seconds(10)) }
        func load(namespace: String, replayEpoch: Int64, claimDigest: Data) throws -> ExpectedChallenge {
            throw StoreError.challengeIssuanceNotFound
        }
    }

    actor ReenteringRandom: ChallengeRandomSource {
        private(set) var calls = 0
        let request: ChallengeIssueRequest
        let innerStore = Store()
        init(request: ChallengeIssueRequest) { self.request = request }
        func fill(count: Int) async throws -> Data {
            calls += 1
            if calls == 1 {
                _ = try await Ratify.issueChallenge(request: request, clock: Clock(time: 1_799_999_990),
                    store: innerStore, random: self, timeout: .seconds(3))
                return Data(repeating: 0x22, count: count)
            }
            return Data(repeating: 0x11, count: count)
        }
    }

    actor CountingRandom: ChallengeRandomSource {
        private(set) var calls = 0
        func fill(count: Int) -> Data {
            calls += 1
            return Data(repeating: UInt8(calls), count: count)
        }
    }

    actor ConflictStore: ChallengeIssuanceStore {
        func persist(_ record: ExpectedChallenge) throws { throw StoreError.challengeIssuanceConflict }
        func load(namespace: String, replayEpoch: Int64, claimDigest: Data) throws -> ExpectedChallenge {
            throw StoreError.challengeIssuanceNotFound
        }
    }

    actor Store: ChallengeIssuanceStore {
        private var record: ExpectedChallenge?
        let failAfterCommit: Bool
        init(failAfterCommit: Bool = false) { self.failAfterCommit = failAfterCommit }
        func persist(_ next: ExpectedChallenge) throws {
            if record != nil { throw StoreError.challengeIssuanceConflict }
            record = next
            if failAfterCommit { throw StoreError.unavailable("commit acknowledgement lost") }
        }
        func load(namespace: String, replayEpoch: Int64, claimDigest: Data) throws -> ExpectedChallenge {
            guard let record, record.verifierNamespace == namespace, record.replayEpoch == replayEpoch,
                  try Ratify.challengeClaimDigest(record.value) == claimDigest else {
                throw StoreError.challengeIssuanceNotFound
            }
            return record
        }
    }

    func testIssuePersistsBeforeExposureAndLoadsByDigest() async throws {
        let step = Corpus.load("challenge-issuance.json").arr("scenarios")[0].arr("steps")[0]
        let request = step.obj("request")
        let store = Store()
        let issued = try await Ratify.issueChallenge(request: ChallengeIssueRequest(
            verifierNamespace: request.s("verifier_namespace"), replayEpoch: Int64(request.int("replay_epoch")),
            verifierId: request.s("verifier_id"), lifetimeSeconds: Int64(request.int("lifetime_seconds")),
            expectedAgentId: Fixture.shared.keyId(request.s("expected_agent")),
            expectedAgentPublicKey: Fixture.shared.key(request.s("expected_agent")),
            expectedSessionContext: request.b64("expected_session_context_b64")),
            clock: Clock(time: Int64(step.int("at"))), store: store, random: Random(bytes: step.obj("expect").b64("challenge_b64")))
        XCTAssertEqual(issued.value, step.obj("expect").b64("challenge_b64"))
        XCTAssertEqual(issued.issuedAt, Int64(step.obj("expect").int("issued_at")))
        XCTAssertEqual(issued.expiresAt, Int64(step.obj("expect").int("expires_at")))
        let loaded = try await Ratify.loadExpectedChallenge(store: store, namespace: issued.verifierNamespace,
            replayEpoch: issued.replayEpoch, challenge: issued.value)
        XCTAssertEqual(loaded.value, issued.value)
        XCTAssertEqual(loaded.expectedAgentId, issued.expectedAgentId)
    }

    func testAmbiguousCommitDoesNotExposeChallenge() async throws {
        let store = Store(failAfterCommit: true)
        let challenge = Data(repeating: 0x11, count: 32)
        let request = ChallengeIssueRequest(verifierNamespace: "test", replayEpoch: 1,
            verifierId: Fixture.shared.keyId("verifier"), lifetimeSeconds: 30)
        do {
            _ = try await Ratify.issueChallenge(request: request, clock: Clock(time: 1_799_999_990),
                store: store, random: Random(bytes: challenge))
            XCTFail("ambiguous commit exposed a challenge")
        } catch {
            XCTAssertEqual(error.errorClass, .claimStoreUnavailable)
        }
        let loaded = try await Ratify.loadExpectedChallenge(store: store, namespace: "test", replayEpoch: 1, challenge: challenge)
        XCTAssertEqual(loaded.value, challenge)
    }

    func testRandomSourceCanReenterIssuance() async throws {
        let request = ChallengeIssueRequest(verifierNamespace: "test", replayEpoch: 1,
            verifierId: Fixture.shared.keyId("verifier"), lifetimeSeconds: 30)
        let random = ReenteringRandom(request: request)
        let outer = try await Ratify.issueChallenge(request: request, clock: Clock(time: 1_799_999_990),
            store: Store(), random: random, timeout: .seconds(3))
        XCTAssertEqual(outer.value, Data(repeating: 0x22, count: 32))
        let calls = await random.calls
        XCTAssertEqual(calls, 2)
    }

    func testThreeConflictsExposeNoChallenge() async throws {
        let request = ChallengeIssueRequest(verifierNamespace: "test", replayEpoch: 1,
            verifierId: Fixture.shared.keyId("verifier"), lifetimeSeconds: 30)
        let random = CountingRandom()
        do {
            _ = try await Ratify.issueChallenge(request: request, clock: Clock(time: 1_799_999_990),
                store: ConflictStore(), random: random)
            XCTFail("conflicting issuance exposed a challenge")
        } catch {
            XCTAssertEqual(error.errorClass, .configurationInvalid)
        }
        let calls = await random.calls
        XCTAssertEqual(calls, 3)
    }

    func testTimeoutAtEachCallbackIsEvaluationCancelled() async throws {
        let request = ChallengeIssueRequest(verifierNamespace: "test", replayEpoch: 1,
            verifierId: Fixture.shared.keyId("verifier"), lifetimeSeconds: 30)
        for phase in 0..<3 {
            let clock: any AuthoritativeClock = phase == 0 ? SlowClock() : Clock(time: 1_799_999_990)
            let store: any ChallengeIssuanceStore = phase == 1 ? SlowStore() : Store()
            let random: any ChallengeRandomSource = phase == 2 ? SlowRandom() : Random(bytes: Data(repeating: 0x11, count: 32))
            do {
                _ = try await Ratify.issueChallenge(request: request,
                    clock: clock, store: store, random: random,
                    timeout: .milliseconds(100))
                XCTFail("timeout exposed a challenge at phase \(phase)")
            } catch {
                XCTAssertEqual(error.errorClass, .evaluationCancelled)
            }
        }
    }

    func testCallbackCancellationWithoutCallCancellationIsFailure() async throws {
        let request = ChallengeIssueRequest(verifierNamespace: "test", replayEpoch: 1,
            verifierId: Fixture.shared.keyId("verifier"), lifetimeSeconds: 30)
        for phase in 0..<3 {
            let clock: any AuthoritativeClock = phase == 0 ? CancelledClock() : Clock(time: 1_799_999_990)
            let store: any ChallengeIssuanceStore = phase == 1 ? CancelledStore() : Store()
            let random: any ChallengeRandomSource = phase == 2 ? CancelledRandom() : Random(bytes: Data(repeating: 0x11, count: 32))
            do {
                _ = try await Ratify.issueChallenge(request: request, clock: clock, store: store, random: random)
                XCTFail("callback cancellation exposed a challenge at phase \(phase)")
            } catch {
                XCTAssertEqual(error.errorClass, phase == 2 ? .configurationInvalid : .claimStoreUnavailable)
            }
        }
    }
}
