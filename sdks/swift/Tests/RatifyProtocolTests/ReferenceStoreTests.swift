import Foundation
import RatifyProtocol
import RatifyProtocolTestSupport
import XCTest

final class ReferenceStoreTests: XCTestCase {
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
