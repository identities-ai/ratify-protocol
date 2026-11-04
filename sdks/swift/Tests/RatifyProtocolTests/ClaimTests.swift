import Foundation
import XCTest
import RatifyProtocol

final class ClaimTests: XCTestCase {
    actor UnavailableClaimStore: ClaimStore {
        private(set) var calls = 0
        func authoritativeTime() -> Int64 { XCTFail("preflight must not read store time"); return 0 }
        func claim(_ claim: ChallengeClaim) throws -> ClaimResult {
            XCTAssertFalse(claim.claimId.isEmpty)
            calls += 1
            throw StoreError.unavailable("claim store offline")
        }
        func finalize(claimId: String, ownerToken: Data, terminalResult: Data, receiptBody: Data,
                      allowValidUntil: Int64) -> Bool { XCTFail("claim failed"); return false }
        func recordProgress(claimId: String, ownerToken: Data, progress: EvaluationProgress) { XCTFail("claim failed") }
        func loadInterrupted(claimId: String) -> InterruptedClaim { fatalError("claim failed") }
        func recoverInterrupted(claimId: String, terminalResult: Data, receiptBody: Data) -> Bool {
            XCTFail("claim failed"); return false
        }
    }

    private func request(_ name: String) throws -> VerifyRequest {
        let corpus = Corpus.load("verifier-ordering.json")
        let vector = corpus.arr("vectors").first { $0.s("name") == name }!
        let expected = vector.obj("expected_challenge")
        let key = expected.obj("expected_agent_public_key")
        let policy = vector.obj("context_policy")
        let contextPolicy = try ContextPolicy(profile: policy.s("profile"), requireBound: policy.bool("require_bound"),
            requiredFields: policy.strings("required_fields"), expectedSessionContext: policy.b64("expected_session_context_b64"))
        let challenge = ExpectedChallenge(value: expected.b64("value_b64"), issuedAt: Int64(expected.int("issued_at")),
            expiresAt: Int64(expected.int("expires_at")), verifierNamespace: expected.s("verifier_namespace"),
            replayEpoch: Int64(expected.int("replay_epoch")), verifierId: expected.s("verifier_id"),
            expectedAgentId: expected.s("expected_agent_id"),
            expectedAgentPublicKey: HybridPublicKey(ed25519: key.b64("ed25519"), mlDsa65: key.b64("ml_dsa_65")),
            expectedSessionContext: expected.b64("expected_session_context_b64"))
        let statusPolicy = vector.obj("status_policy")
        let statusKeys = vector.obj("status_keys").mapValues { value -> StatusKeyConfig in
            let item = value as! [String: Any]
            let key = item.obj("public_key")
            return StatusKeyConfig(epoch: UInt64(item.int("epoch")),
                key: HybridPublicKey(ed25519: key.b64("ed25519"), mlDsa65: key.b64("ml_dsa_65")))
        }
        return VerifyRequest(bundle: Data(base64Encoded: corpus.obj("bundles_b64").s(vector.s("bundle")))!,
            expected: challenge, contextPolicy: contextPolicy, requiredScope: vector.s("required_scope"),
            verifierNamespace: vector.s("configured_namespace"), replayEpoch: Int64(vector.int("configured_replay_epoch")),
            verifierId: vector.s("configured_verifier_id"), now: Int64(vector.int("now")),
            maxChallengeAgeSeconds: Int64(vector.int("max_challenge_age_seconds")),
            futureSkewSeconds: Int64(vector.int("future_skew_seconds")), context: ConstraintContext(),
            tzdbVersion: vector.s("tzdb_version"), statusKeys: statusKeys,
            statusPolicy: RevocationStatusPolicy(maxListLifetimeSeconds: Int64(statusPolicy.int("max_list_lifetime_seconds")),
                maxStatusAgeSeconds: Int64(statusPolicy.int("max_status_age_seconds")),
                clockSkewSeconds: Int64(statusPolicy.int("clock_skew_seconds"))))
    }

    func testLiveVerifierReachesClaimStoreAfterPreflight() async throws {
        let request = try request("claim_store_unavailable")
        let store = UnavailableClaimStore()
        let outcome = try await Ratify.verifyProofBundle(request, claimStore: store)
        XCTAssertEqual(outcome.stage, .preflight)
        XCTAssertEqual(outcome.errorClass, .claimStoreUnavailable, outcome.errorDetail ?? "")
        let calls = await store.calls
        XCTAssertEqual(calls, 1)
    }

    actor CreatedClaimStore: RateAtFinalizationClaimStore {
        let onFinalize: (@Sendable () async -> Void)?
        private(set) var claims = 0
        private(set) var progressWrites = 0
        private(set) var finalizations = 0
        init(onFinalize: (@Sendable () async -> Void)? = nil) { self.onFinalize = onFinalize }
        func authoritativeTime() -> Int64 { 1_800_000_000 }
        func claim(_ claim: ChallengeClaim) -> ClaimResult {
            claims += 1
            return ClaimResult(disposition: .created, claimedAt: 1_800_000_000,
                ownerToken: Data(repeating: 7, count: 32))
        }
        func finalize(claimId: String, ownerToken: Data, terminalResult: Data, receiptBody: Data,
                      allowValidUntil: Int64) async -> Bool {
            if let onFinalize { await onFinalize() }
            XCTAssertEqual(ownerToken, Data(repeating: 7, count: 32))
            XCTAssertFalse(terminalResult.isEmpty)
            XCTAssertFalse(receiptBody.isEmpty)
            finalizations += 1
            return true
        }
        func recordProgress(claimId: String, ownerToken: Data, progress: EvaluationProgress) {
            progressWrites += 1
        }
        func loadInterrupted(claimId: String) -> InterruptedClaim { fatalError("no interruption") }
        func recoverInterrupted(claimId: String, terminalResult: Data, receiptBody: Data) -> Bool {
            XCTFail("no interruption"); return false
        }
    }

    actor UnavailableTrust: TrustProvider {
        private(set) var calls = 0
        func resolve(chain: [DelegationCert]) -> TrustResolution {
            XCTAssertFalse(chain.isEmpty)
            calls += 1
            return TrustResolution(outcome: .unavailable,
                rootKey: HybridPublicKey(ed25519: Data(), mlDsa65: Data()))
        }
    }

    func testTrustUnavailabilityCommitsOnlyANonactionableHandoff() async throws {
        let store = CreatedClaimStore()
        let trust = UnavailableTrust()
        let outcome = try await Ratify.verifyProofBundle(request("trust_unavailable"),
            claimStore: store, trust: trust)
        XCTAssertEqual(outcome.stage, .committed, outcome.errorDetail ?? "")
        XCTAssertNil(outcome.errorClass)
        XCTAssertNotNil(outcome.committed)
        let claims = await store.claims
        let writes = await store.progressWrites
        let finalizations = await store.finalizations
        let trustCalls = await trust.calls
        XCTAssertEqual(claims, 1)
        XCTAssertEqual(writes, 2)
        XCTAssertEqual(finalizations, 1)
        XCTAssertEqual(trustCalls, 1)
    }

    actor FinalizationGate {
        private var openNow = false
        private var waiter: CheckedContinuation<Void, Never>?
        func wait() async {
            if openNow { return }
            await withCheckedContinuation { waiter = $0 }
        }
        func open() {
            openNow = true
            waiter?.resume()
            waiter = nil
        }
    }

    func testCancellationAfterStoreCommitPreservesCommittedHandoff() async throws {
        let gate = FinalizationGate()
        let (started, signal) = AsyncStream.makeStream(of: Void.self)
        let store = CreatedClaimStore(onFinalize: {
            signal.yield(())
            await gate.wait()
        })
        let trust = UnavailableTrust()
        let request = try request("trust_unavailable")
        let call = Task { try await Ratify.verifyProofBundle(request, claimStore: store, trust: trust) }
        var iterator = started.makeAsyncIterator()
        _ = await iterator.next()
        call.cancel()
        await gate.open()
        let outcome = try await call.value
        XCTAssertEqual(outcome.stage, .committed)
        XCTAssertNotNil(outcome.committed)
    }

    actor MissingCommittedStore: CommittedClaimStore {
        private(set) var calls = 0
        func loadCommitted(claimId: String) throws -> CommittedClaim {
            XCTAssertEqual(claimId, "missing")
            calls += 1
            throw StoreError.classified(.claimNotFound, detail: "no terminal record")
        }
    }

    func testResumePreservesStoreErrorAndCallsOnce() async throws {
        let store = MissingCommittedStore()
        do {
            _ = try await Ratify.resumeCommittedClaim(store: store, claimId: "missing")
            XCTFail("missing committed claim returned a handoff")
        } catch {
            XCTAssertEqual(error.errorClass, .claimNotFound)
        }
        let calls = await store.calls
        XCTAssertEqual(calls, 1)
    }
}
