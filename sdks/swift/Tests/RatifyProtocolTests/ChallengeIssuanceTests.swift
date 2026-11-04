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

    actor ScenarioStore: ChallengeIssuanceStore {
        private var records: [Data: ExpectedChallenge] = [:]
        private var fault = ""
        var count: Int { records.count }
        func arm(_ next: String) { fault = next }
        func persist(_ record: ExpectedChallenge) throws {
            let active = fault
            fault = ""
            if active == "fail_before_commit" { throw StoreError.unavailable("before commit") }
            let digest = try Ratify.challengeClaimDigest(record.value)
            if records[digest] != nil { throw StoreError.challengeIssuanceConflict }
            records[digest] = record
            if active == "fail_after_commit" { throw StoreError.unavailable("after commit") }
        }
        func load(namespace: String, replayEpoch: Int64, claimDigest: Data) throws -> ExpectedChallenge {
            guard let record = records[claimDigest], record.verifierNamespace == namespace,
                  record.replayEpoch == replayEpoch else { throw StoreError.challengeIssuanceNotFound }
            return record
        }
    }

    actor ScenarioClaimStore: ClaimStore {
        private var claims: [String: (claim: ChallengeClaim, claimedAt: Int64)] = [:]
        private var finalized: Set<String> = []
        private var now: Int64 = 0
        private var claimCalls = 0
        private var finalizeCalls = 0
        private var progressCalls = 0
        private var proofConflicts = 0
        func snapshot() -> [Int] { [claimCalls, finalizeCalls, progressCalls, proofConflicts] }
        func setTime(_ value: Int64) { now = value }
        func authoritativeTime() -> Int64 { now }
        func claim(_ next: ChallengeClaim) throws -> ClaimResult {
            claimCalls += 1
            if let existing = claims[next.claimId] {
                if existing.claim.proofDigest != next.proofDigest {
                    proofConflicts += 1
                    throw StoreError.claimProofConflict
                }
                return ClaimResult(disposition: .inProgress, claimedAt: existing.claimedAt, ownerToken: Data())
            }
            claims[next.claimId] = (next, now)
            return ClaimResult(disposition: .created, claimedAt: now, ownerToken: Data(repeating: 7, count: 32))
        }
        func finalize(claimId: String, ownerToken: Data, terminalResult: Data, receiptBody: Data,
                      allowValidUntil: Int64) throws -> Bool {
            guard claims[claimId] != nil, ownerToken == Data(repeating: 7, count: 32),
                  !finalized.contains(claimId) else { throw StoreError.unavailable("invalid finalization") }
            finalized.insert(claimId)
            finalizeCalls += 1
            return true
        }
        func recordProgress(claimId: String, ownerToken: Data, progress: EvaluationProgress) throws {
            guard claims[claimId] != nil, ownerToken == Data(repeating: 7, count: 32),
                  !finalized.contains(claimId) else { throw StoreError.unavailable("invalid progress") }
            progressCalls += 1
        }
        func loadInterrupted(claimId: String) throws -> InterruptedClaim { throw StoreError.unavailable("no interruption") }
        func recoverInterrupted(claimId: String, terminalResult: Data, receiptBody: Data) -> Bool { false }
    }

    actor ScenarioRandom: ChallengeRandomSource {
        let values: [Data]
        private var index = 0
        private(set) var calls = 0
        private(set) var exhausted = false
        init(_ values: [Data]) { self.values = values }
        func fill(count: Int) throws -> Data {
            calls += 1
            guard index < values.count else {
                exhausted = true
                throw StoreError.unavailable("random fixture exhausted")
            }
            let value = values[index]
            index += 1
            XCTAssertEqual(value.count, count)
            return value
        }
    }

    private func assertBindings(_ record: ExpectedChallenge, _ request: ChallengeIssueRequest, _ label: String) {
        XCTAssertEqual(record.verifierNamespace, request.verifierNamespace, label)
        XCTAssertEqual(record.replayEpoch, request.replayEpoch, label)
        XCTAssertEqual(record.verifierId, request.verifierId, label)
        XCTAssertEqual(record.expectedAgentId, request.expectedAgentId, label)
        XCTAssertEqual(record.expectedAgentPublicKey, request.expectedAgentPublicKey, label)
        XCTAssertEqual(record.expectedReceiverId, request.expectedReceiverId, label)
        XCTAssertEqual(record.expectedSessionContext, request.expectedSessionContext, label)
    }

    private static func presentIssued(_ wire: Data, at: Int64, issuance: ScenarioStore,
                                      claims: ScenarioClaimStore) async -> String {
        let bundle: ProofBundle
        do { bundle = try Ratify.decodeProofBundle(wire) }
        catch { return "preflight:" + (error.errorClass?.rawValue ?? "internal") }
        let expected: ExpectedChallenge
        do {
            expected = try await Ratify.loadExpectedChallenge(store: issuance, namespace: "verify-test",
                replayEpoch: 3, challenge: bundle.challenge)
        } catch { return "preflight:" + (error.errorClass?.rawValue ?? "internal") }
        do {
            let policy = try expected.expectedSessionContext.map {
                try ContextPolicy(profile: "ratify.verify.session-context/v1", requireBound: true,
                    requiredFields: ["verifier_id", "workspace_id", "agent_id", "session_id", "invocation_id", "request_hash"],
                    expectedSessionContext: $0)
            } ?? ContextPolicy(profile: "ratify.conformance.context-not-required/v1", requireBound: false,
                               requiredFields: [])
            let request = VerifyRequest(bundle: wire, expected: expected, contextPolicy: policy,
                requiredScope: "data:read", verifierNamespace: "verify-test", replayEpoch: 3,
                verifierId: expected.verifierId, now: at, maxChallengeAgeSeconds: 300,
                futureSkewSeconds: 5, context: ConstraintContext(), tzdbVersion: "2025a",
                statusKeys: [:], statusPolicy: RevocationStatusPolicy(maxListLifetimeSeconds: 300,
                    maxStatusAgeSeconds: 300, clockSkewSeconds: 5))
            let outcome = try await Ratify.verifyProofBundle(request, claimStore: claims)
            if let disposition = outcome.disposition { return disposition.rawValue }
            if outcome.errorClass == .claimReplay { return "proof_conflict" }
            return "preflight:" + (outcome.errorClass?.rawValue ?? "internal")
        } catch { return "preflight:" + ((error as? RatifyError)?.errorClass?.rawValue ?? "internal") }
    }

    func testChallengeIssuanceCorpusAllSteps() async throws {
        let scenarios = Corpus.load("challenge-issuance.json").arr("scenarios")
        XCTAssertEqual(scenarios.count, 11)
        var checked = 0
        for scenario in scenarios {
            let name = scenario.s("name")
            let store = ScenarioStore()
            let claims = ScenarioClaimStore()
            let random = ScenarioRandom(scenario.strings("random_b64").map { Data(base64Encoded: $0)! })
            var issuedRequests: [Data: ChallengeIssueRequest] = [:]
            let firstRequest = scenario.arr("steps").first { $0.s("op") == "issue" }!.obj("request")
            for (index, step) in scenario.arr("steps").enumerated() {
                let label = "\(name) step \(index)"
                let expect = step.obj("expect")
                if step.s("op") == "issue" {
                    checked += 1
                    let input = step.obj("request")
                    let request = ChallengeIssueRequest(verifierNamespace: input.s("verifier_namespace"),
                        replayEpoch: Int64(input.int("replay_epoch")), verifierId: input.s("verifier_id"),
                        lifetimeSeconds: Int64(input.int("lifetime_seconds")),
                        expectedAgentId: Fixture.shared.keyId(input.s("expected_agent")),
                        expectedAgentPublicKey: Fixture.shared.key(input.s("expected_agent")),
                        expectedReceiverId: input["expected_receiver_id"] as? String ?? "",
                        expectedSessionContext: (input["expected_session_context_b64"] as? String)
                            .map { Data(base64Encoded: $0)! })
                    await store.arm(step["persist_fault"] as? String ?? "")
                    do {
                        let issued = try await Ratify.issueChallenge(request: request,
                            clock: Clock(time: Int64(step.int("at"))), store: store, random: random)
                        XCTAssertEqual(expect.s("result"), "issued", label)
                        if expect.s("result") == "issued" {
                            XCTAssertEqual(issued.value, expect.b64("challenge_b64"), label)
                            XCTAssertEqual(issued.issuedAt, Int64(expect.int("issued_at")), label)
                            XCTAssertEqual(issued.expiresAt, Int64(expect.int("expires_at")), label)
                            assertBindings(issued, request, label)
                            issuedRequests[issued.value] = request
                        }
                    } catch {
                        XCTAssertEqual(expect.s("result"), "error", label + ": \(error)")
                        let expectedClass = expect["error_class"] as? String ??
                            ((step["persist_fault"] as? String) != nil ? "claim_store_unavailable" : "configuration_invalid")
                        XCTAssertEqual(error.errorClass?.rawValue, expectedClass, label)
                    }
                    let recordCount = await store.count
                    XCTAssertEqual(recordCount, expect.int("records_after"), label)
                } else if step.s("op") == "load" {
                    checked += 1
                    XCTAssertNil(step["verifier_namespace"], label)
                    XCTAssertNil(step["replay_epoch"], label)
                    do {
                        let loaded = try await Ratify.loadExpectedChallenge(store: store,
                            namespace: firstRequest.s("verifier_namespace"),
                            replayEpoch: Int64(firstRequest.int("replay_epoch")), challenge: step.b64("challenge_b64"))
                        XCTAssertEqual(expect.s("result"), "found", label)
                        if expect.s("result") == "found" {
                            XCTAssertEqual(loaded.value, step.b64("challenge_b64"), label)
                            XCTAssertEqual(loaded.issuedAt, Int64(expect.int("issued_at")), label)
                            XCTAssertEqual(loaded.expiresAt, Int64(expect.int("expires_at")), label)
                            if let request = issuedRequests[loaded.value] {
                                assertBindings(loaded, request, label)
                            } else { XCTFail("loaded challenge has no issued request: \(label)") }
                            if let receiver = expect["expected_receiver_id"] as? String {
                                XCTAssertEqual(loaded.expectedReceiverId, receiver, label)
                            }
                        }
                    } catch {
                        XCTAssertEqual(error.errorClass, .expectedChallengeUnavailable, label)
                        XCTAssertEqual(expect.s("result"), "expected_challenge_unavailable", label)
                    }
                } else if ["present", "present_concurrent"].contains(step.s("op")) {
                    checked += 1
                    let at = Int64(step.int("at"))
                    await claims.setTime(at)
                    let before = await claims.snapshot()
                    let wires = step.strings("bundles_b64").map { Data(base64Encoded: $0)! }
                    let actual = await withTaskGroup(of: String.self) { group in
                        for wire in wires {
                            group.addTask { await Self.presentIssued(wire, at: at, issuance: store, claims: claims) }
                        }
                        var results: [String] = []
                        for await result in group { results.append(result) }
                        return results.sorted()
                    }
                    let expected = expect.s("result") == "preflight" ?
                        ["preflight:" + expect.s("error_class")] : expect.strings("dispositions").sorted()
                    XCTAssertEqual(actual, expected, label)
                    let after = await claims.snapshot()
                    let delta = zip(after, before).map(-)
                    if expect.s("result") == "preflight" {
                        XCTAssertEqual(delta, [0, 0, 0, 0], label)
                    } else {
                        XCTAssertEqual(delta[0], wires.count, label)
                        XCTAssertEqual(delta[1], expected.filter { $0 == "created" }.count, label)
                        XCTAssertEqual(delta[3], expected.filter { $0 == "proof_conflict" }.count, label)
                    }
                } else {
                    XCTFail("unsupported corpus operation: \(step.s("op"))")
                }
            }
            let calls = await random.calls
            let exhausted = await random.exhausted
            XCTAssertFalse(exhausted, name)
            XCTAssertEqual(calls, random.values.count - (name == "expiry_at_timestamp_domain_end" ? 1 : 0), name)
        }
        XCTAssertEqual(checked, 42)
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
