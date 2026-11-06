import Foundation
import RatifyProtocol
import RatifyProtocolTestSupport
import XCTest

final class ReferenceStoreTests: XCTestCase {
    func testRateCountersKeepSharedCertIdsSeparateByIssuer() async throws {
        let vectors = Corpus.load("verifier-ordering.json").arr("vectors")
        let collision = try XCTUnwrap(vectors.first { $0.s("name") == "issuer_scoped_cert_id_collision" })
        let rates = collision.obj("expected").arr("rate_batch")
        XCTAssertEqual(rates.count, 2)
        XCTAssertEqual(rates.map { $0.s("cert_id") }, ["shared-id", "shared-id"])
        let issuers = rates.map { $0.s("issuer_id") }
        XCTAssertNotEqual(issuers[0], issuers[1])
        let fixture = try XCTUnwrap(vectors.first { $0.s("name") == "allow_bound_context" })
        let receiptBody = fixture.obj("expected").b64("receipt_body_b64")
        let body = try JSONSerialization.jsonObject(with: receiptBody) as! [String: Any]
        let terminal = Data(#"{"decision":"allow","decision_reason":"authorized","identity_status":"authorized_agent"}"#.utf8)
        let store = try Store(now: 1_800_000_000, leaseSeconds: 30,
            logId: String(repeating: "a", count: 32), verifierKey: Fixture.shared.privateKey("verifier"))
        let rateStore = try store.withRateAtFinalization()

        func admit(_ byte: UInt8, issuer: String) async throws -> Bool {
            let challenge = Data(repeating: byte, count: 32)
            let digest = "sha384:" + (try Ratify.challengeClaimDigest(challenge)).hex
            let claim = ChallengeClaim(claimId: try Ratify.protocolClaimId(namespace: "ns", replayEpoch: 1,
                challenge: challenge), namespace: "ns", replayEpoch: 1, challengeDigest: digest,
                proofDigest: "proof-\(byte)", bundleHash: body.s("bundle_hash"),
                issuerIds: body.strings("issuer_ids"), requiredScope: body.s("required_scope"),
                contextPolicyDigest: body.s("context_policy_digest"), verifierId: body.s("verifier_id"),
                agentId: body.s("agent_id"), requiresRate: true,
                rateBatch: [RateReservation(issuerId: issuer, certId: "shared-id", windowSeconds: 60, limit: 1)],
                issuedAt: 1_799_999_990, expiresAt: 1_800_000_290, maxAgeSeconds: 300,
                clockSkewSeconds: 0, streamId: nil, streamSeq: nil, constraintEvaluators: [])
            let created = try await rateStore.claim(claim)
            XCTAssertEqual(created.disposition, .created)
            return try await rateStore.finalize(claimId: claim.claimId, ownerToken: created.ownerToken,
                terminalResult: terminal, receiptBody: receiptBody, allowValidUntil: 1_800_000_100)
        }

        let first = try await admit(1, issuer: issuers[0])
        let second = try await admit(2, issuer: issuers[1])
        XCTAssertTrue(first)
        XCTAssertTrue(second)
        do {
            _ = try await admit(3, issuer: issuers[0])
            XCTFail("an exhausted issuer counter was admitted")
        } catch StoreError.rateLimitExceeded {}
    }

    func testClockAndCloneHaveIndependentState() async throws {
        let key = try SoftwarePrivateKey(ed25519Seed: Data(repeating: 1, count: 32), mlDsa65Seed: Data(repeating: 2, count: 32))
        let store = try Store(now: 100, leaseSeconds: 5, logId: String(repeating: "a", count: 32), verifierKey: key)
        XCTAssertEqual(try store.now(), 100)
        try store.setTime(101)
        let copy = try store.cloneStore()
        XCTAssertEqual(try copy.now(), 101)
        try copy.setTime(200)
        XCTAssertEqual(try store.now(), 101)
        XCTAssertEqual(try copy.now(), 200)
        let authoritative = try await store.authoritativeTime()
        XCTAssertEqual(authoritative, 101)
        try store.setTime(99)
        do {
            _ = try await store.authoritativeTime()
            XCTFail("a regressed store clock was accepted")
        } catch let error as StoreError {
            XCTAssertEqual(error.errorClass, .clockRegressed)
        }
        XCTAssertEqual(try store.logLength(), 0)
        XCTAssertEqual(try store.abandonPendingReceipts(), [])
        XCTAssertEqual(classOf { _ = try Store(now: 100, leaseSeconds: 0, logId: String(repeating: "a", count: 32), verifierKey: key) }, "configuration_invalid")
    }

    func testClaimKeepsReferenceStoreErrorClass() async throws {
        let key = try SoftwarePrivateKey(ed25519Seed: Data(repeating: 1, count: 32), mlDsa65Seed: Data(repeating: 2, count: 32))
        let store = try Store(now: 100, leaseSeconds: 5, logId: String(repeating: "a", count: 32), verifierKey: key)
        let claim = ChallengeClaim(claimId: "invalid", namespace: "test", replayEpoch: 1,
            challengeDigest: "invalid", proofDigest: "invalid", bundleHash: "invalid", issuerIds: [],
            requiredScope: "", contextPolicyDigest: "", verifierId: "", agentId: "", requiresRate: false,
            rateBatch: [], issuedAt: 90, expiresAt: 200, maxAgeSeconds: 100, clockSkewSeconds: 0,
            streamId: nil, streamSeq: nil, constraintEvaluators: [])
        do {
            _ = try await store.claim(claim)
            XCTFail("a claim ID unrelated to its replay key was accepted")
        } catch let error as StoreError {
            XCTAssertEqual(error.errorClass, .configurationInvalid)
        }
    }

    func testClaimReplayAndLeaseThroughPublicStore() async throws {
        let key = try SoftwarePrivateKey(ed25519Seed: Data(repeating: 1, count: 32), mlDsa65Seed: Data(repeating: 2, count: 32))
        let store = try Store(now: 100, leaseSeconds: 5, logId: String(repeating: "a", count: 32), verifierKey: key)
        let challenge = Data(repeating: 3, count: 32)
        let digest = "sha384:" + (try Ratify.challengeClaimDigest(challenge)).hex
        let claim = ChallengeClaim(claimId: try Ratify.protocolClaimId(namespace: "test", replayEpoch: 1, challenge: challenge),
            namespace: "test", replayEpoch: 1, challengeDigest: digest, proofDigest: digest, bundleHash: digest,
            issuerIds: [], requiredScope: "data:read", contextPolicyDigest: "", verifierId: key.keyId,
            agentId: "", requiresRate: false, rateBatch: [], issuedAt: 90, expiresAt: 200,
            maxAgeSeconds: 100, clockSkewSeconds: 0, streamId: nil, streamSeq: nil, constraintEvaluators: [])
        let created = try await store.claim(claim)
        XCTAssertEqual(created.disposition, .created)
        XCTAssertEqual(created.claimedAt, 100)
        XCTAssertEqual(created.ownerToken.count, 32)
        let replay = try await store.claim(claim)
        XCTAssertEqual(replay.disposition, .inProgress)
        XCTAssertTrue(replay.ownerToken.isEmpty)
        let terminal = try await store.loadTerminal(claimId: claim.claimId)
        XCTAssertFalse(terminal.terminal)
        XCTAssertEqual(terminal.challengeExpiresAt, 200)
        do {
            _ = try await store.loadCommitted(claimId: claim.claimId)
            XCTFail("an evaluating claim was reported committed")
        } catch let error as StoreError {
            XCTAssertEqual(error.errorClass, .claimLeaseLive)
        }
        do {
            _ = try await store.get(logId: String(repeating: "a", count: 32), sequence: 1)
            XCTFail("a missing checkpoint was reported acknowledged")
        } catch StoreError.acknowledgementNotFound {}
        do {
            _ = try await store.publish(claimId: claim.claimId, receiptBody: Data())
            XCTFail("an evaluating claim published a receipt")
        } catch StoreError.unavailable(let detail) {
            XCTAssertTrue(detail.contains("no committed outbox body"))
        }
        do {
            try await store.recordRelease(ReleaseRecord(claimId: claim.claimId, entryHash: Data(repeating: 0, count: 48),
                ackTimestamp: 100, outcome: .released, reason: ""))
            XCTFail("an evaluating claim recorded a release")
        } catch StoreError.releaseStateMismatch {}
        do {
            _ = try await store.loadInterrupted(claimId: claim.claimId)
            XCTFail("an unexpired evaluator lease was interrupted")
        } catch let error as StoreError {
            XCTAssertEqual(error.errorClass, .claimLeaseLive)
        }
        do {
            _ = try await Ratify.recoverInterruptedClaim(store: store, claimId: claim.claimId)
            XCTFail("recovery replaced an active evaluator")
        } catch let error {
            XCTAssertEqual(error.errorClass, .claimLeaseLive)
        }
        try store.setTime(106)
        let interrupted = try await store.loadInterrupted(claimId: claim.claimId)
        XCTAssertEqual(interrupted.claim, claim)
        XCTAssertEqual(interrupted.claimedAt, 100)
        do {
            _ = try await store.loadCommitted(claimId: claim.claimId)
            XCTFail("an expired evaluating claim was reported committed")
        } catch let error as StoreError {
            XCTAssertEqual(error.errorClass, .claimLeaseLost)
        }
        let recovered = try await Ratify.recoverInterruptedClaim(store: store, claimId: claim.claimId)
        let body = try JSONSerialization.jsonObject(with: recovered.receiptBody) as! [String: Any]
        XCTAssertEqual(body["decision_reason"] as? String, "evaluation_interrupted")
        let saved = try await store.loadCommitted(claimId: claim.claimId)
        XCTAssertEqual(saved.receiptBody, recovered.receiptBody)
        let repeated = try await Ratify.recoverInterruptedClaim(store: store, claimId: claim.claimId)
        XCTAssertEqual(repeated.receiptBody, recovered.receiptBody)
    }
}
