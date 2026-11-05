import CryptoKit
import Foundation
import XCTest
import RatifyProtocol
import RatifyProtocolTestSupport

/// Replays the object half of every cross-SDK fixture through Swift's public
/// API. Scenario replay is tracked separately by the corpus inventory.
final class CrossSdkObjectTests: XCTestCase {
    func testOtherSdkObjects() throws {
        let names = try FileManager.default.contentsOfDirectory(atPath: Corpus.url("cross-sdk").path)
            .filter { $0.hasSuffix(".json") }.sorted()
        XCTAssertEqual(Set(names), Set(["c", "go", "kotlin", "python", "rust", "swift", "typescript"].map { "\($0).json" }))
        let t = Tally("cross-sdk-objects")
        var keysCount = 0, objectsCount = 0, signaturesCount = 0, digestsCount = 0
        for file in names {
            let data = Corpus.load("cross-sdk/" + file)
            let sdk = String(file.dropLast(5))
            t.check("files", sdk, data.s("sdk") == sdk)
            XCTAssertEqual(data.arr("keys").count, 11, file)
            XCTAssertEqual(data.arr("objects").count, 15, file)
            var keys: [String: HybridPublicKey] = [:]
            var ids: [String: String] = [:]
            for entry in data.arr("keys") {
                keysCount += 1
                let name = entry.s("name")
                let derived = try SoftwarePrivateKey(ed25519Seed: entry.hex("ed25519_seed_hex"),
                    mlDsa65Seed: entry.hex("ml_dsa_65_seed_hex"))
                let pinned = publicKey(entry.obj("public_key"))
                keys[name] = pinned
                ids[name] = entry.s("key_id_v2")
                t.check("keys", "\(sdk)/\(name)", derived.publicKey == pinned &&
                    derived.keyId == entry.s("key_id_v2") &&
                    KeysRunner.independentKeyId(pinned) == entry.s("key_id_v2"))
            }
            for object in data.arr("objects") {
                objectsCount += 1
                let name = object.s("name"), kind = object.s("kind"), wire = object.b64("wire_b64")
                let id = "\(sdk)/\(name)"
                if kind != "receipt_bundle_binding" {
                    t.check("objects", id, try reencode(kind, wire) == wire)
                } else {
                    t.check("objects", id, try Ratify.encodeVerificationReceipt(
                        Ratify.decodeVerificationReceipt(wire)) == wire)
                }
                let bundle = (object["bundle_b64"] as? String).flatMap { Data(base64Encoded: $0) } ?? Data()
                let result = classOf { try verifyObject(kind, wire, bundle: bundle,
                    object.obj("verify"), key: { keys[$0]! }) }
                t.check("verify", id, result == "ok", result)
                let wireText = String(data: wire, encoding: .utf8)!
                for signature in object.arr("signatures") {
                    signaturesCount += 1
                    let field = signature.s("field"), signer = signature.s("signer")
                    let code = ObjectType(rawValue: UInt16(signature.int("object_type_code")))!
                    let signable = signature.b64("signable_b64")
                    let message = try Ratify.signingMessage(code, signable: signable)
                    let context = try Ratify.mldsaContext(code)
                    let key = keys[signer]!
                    let pinned = hybridSignature(signature.obj("signature"))
                    let mu = try Ratify.externalMu(mlDsaPublicKey: key.mlDsa65,
                        mlDsaContext: context, message: message)
                    let verified = classOf { try Ratify.verifyStatement(code, signable: signable,
                        signature: pinned, publicKey: key) }
                    t.check("signatures", "\(id)/\(field)", try projection(wire, field) == signable &&
                        sha384(signable).hex == signature.s("signable_sha384_hex") &&
                        message == signature.b64("message_b64") &&
                        String(data: context, encoding: .utf8) == signature.s("mldsa_context") &&
                        ids[signer] == signature.s("signer_key_id_v2") &&
                        Shake256.hash(key.mlDsa65, outputLength: 64) == signature.b64("mldsa_tr_b64") &&
                        mu == signature.b64("mldsa_mu_b64") &&
                        wireText.contains(pinned.ed25519.base64EncodedString()) &&
                        wireText.contains(pinned.mlDsa65.base64EncodedString()) && verified == "ok", verified)
                }
                let digests = object.obj("digests")
                for (digestName, value) in digests {
                    if let got = try ObjectsRunner.objectDigest(digestName, kind, wire, digests) {
                        digestsCount += 1
                        t.check("digests", "\(id)/\(digestName)", got == value as? String,
                            "got \(got), want \(value)")
                    }
                }
            }
        }
        t.finish([("files", names.count), ("keys", keysCount), ("objects", objectsCount),
                  ("verify", objectsCount), ("signatures", signaturesCount), ("digests", digestsCount)])
    }

    func testOtherSdkVerifierAndReleaseScenarios() async throws {
        let names = try FileManager.default.contentsOfDirectory(atPath: Corpus.url("cross-sdk").path)
            .filter { $0.hasSuffix(".json") }.sorted()
        let tally = Tally("cross-sdk-scenarios")
        var count = 0
        for file in names {
            let fixture = Corpus.load("cross-sdk/" + file)
            let cfg = fixture.obj("scenario_configuration")
            XCTAssertEqual(Set(fixture.arr("scenarios").map { $0.s("name") }),
                Set(["allow_released", "deny_revoked_released", "indeterminate_status_unavailable_released",
                     "allow_withheld_past_horizon"]), file)
            let keys = try Dictionary(uniqueKeysWithValues: fixture.arr("keys").map { entry in
                (entry.s("name"), try SoftwarePrivateKey(ed25519Seed: entry.hex("ed25519_seed_hex"),
                    mlDsa65Seed: entry.hex("ml_dsa_65_seed_hex")))
            })
            let policy = cfg.obj("status_policy")
            for scenario in fixture.arr("scenarios") {
                count += 1
                let at = "\(file)/\(scenario.s("name"))"
                let verifier = keys[cfg.s("verifier_key")]!
                let store = try Store(now: Int64(scenario.int("verify_time")),
                    leaseSeconds: Int64(cfg.int("lease_seconds")), logId: cfg.s("receipt_log_id"), verifierKey: verifier)
                let journal = ClaimTests.VectorJournal(try Ratify.emptySecurityJournalSnapshot())
                var statusKeys: [String: StatusKeyConfig] = [:]
                for (issuer, raw) in scenario.obj("status_keys").sorted(by: { $0.key < $1.key }) {
                    let binding = raw as! [String: Any]
                    let key = keys[binding.s("key")]!.publicKey
                    let epoch = UInt64(binding.int("epoch"))
                    _ = try await Ratify.configureStatusKeyEpoch(store: journal, issuerId: issuer, epoch: epoch, key: key)
                    statusKeys[issuer] = StatusKeyConfig(epoch: epoch, key: key)
                }
                let challenge = scenario.obj("expected_challenge")
                let expectedKey = (challenge["expected_agent_public_key"] as? [String: Any]).map(publicKey)
                let expected = ExpectedChallenge(value: challenge.b64("value_b64"),
                    issuedAt: Int64(challenge.int("issued_at")), expiresAt: Int64(challenge.int("expires_at")),
                    verifierNamespace: challenge.s("verifier_namespace"), replayEpoch: Int64(challenge.int("replay_epoch")),
                    verifierId: challenge.s("verifier_id"), expectedAgentId: challenge["expected_agent_id"] as? String ?? "",
                    expectedAgentPublicKey: expectedKey, expectedReceiverId: challenge["expected_receiver_id"] as? String ?? "",
                    expectedSessionContext: (challenge["expected_session_context_b64"] as? String).flatMap {
                        Data(base64Encoded: $0) })
                let rawContext = scenario["context_policy"] as? [String: Any]
                let context = try rawContext.map { raw in
                    try ContextPolicy(profile: raw.s("profile"), requireBound: raw.bool("require_bound"),
                        requiredFields: raw.strings("required_fields"),
                        expectedSessionContext: (raw["expected_session_context_b64"] as? String).flatMap {
                            Data(base64Encoded: $0) } ?? Data())
                }
                if let context, let rawContext { tally.check("policy", at, context.digest == rawContext.s("digest")) }
                let statusPolicy = RevocationStatusPolicy(maxListLifetimeSeconds: Int64(policy.int("max_list_lifetime_seconds")),
                    maxStatusAgeSeconds: Int64(policy.int("max_status_age_seconds")),
                    clockSkewSeconds: Int64(policy.int("clock_skew_seconds")))
                let request = VerifyRequest(bundle: scenario.b64("bundle_b64"), expected: expected,
                    contextPolicy: context, requiredScope: scenario.s("required_scope"),
                    verifierNamespace: cfg.s("verifier_namespace"), replayEpoch: Int64(cfg.int("replay_epoch")),
                    verifierId: verifier.keyId, now: Int64(scenario.int("verify_time")),
                    maxChallengeAgeSeconds: Int64(cfg.int("max_challenge_age_seconds")),
                    futureSkewSeconds: Int64(cfg.int("future_skew_seconds")), context: ConstraintContext(),
                    tzdbVersion: cfg.s("tzdb_version"), statusKeys: statusKeys, statusPolicy: statusPolicy)
                let root = keys[scenario.s("trust_root_key")]!.publicKey
                let trust = ClaimTests.VectorTrust(key: root, outcome: .trusted)
                let evidence = scenario.obj("status_evidence").mapValues { raw in
                    (raw as! [[String: Any]]).map { entry in
                        StatusEvidenceObject(objectType: UInt16(entry.int("object_type_code")), wire: entry.b64("wire_b64"))
                    }
                }
                let status = ClaimTests.VectorStatus(byIssuer: evidence)
                let outcome = try await Ratify.verifyProofBundle(request, claimStore: store,
                    trust: trust, statusEvidence: status, statusJournal: journal)
                let committed = try XCTUnwrap(outcome.committed, "\(at): \(outcome.errorDetail ?? "")")
                let want = scenario.obj("expected")
                tally.check("committed", at, outcome.stage == .committed && committed.receiptBody == want.b64("receipt_body_b64") &&
                    committed.allowHorizon == (want["allow_horizon"] as? NSNumber)?.int64Value)
                try store.setTime(Int64(scenario.int("publish_time")))
                let published = try await store.publish(claimId: committed.claimId, receiptBody: committed.receiptBody)
                let receipt = try Ratify.decodeVerificationReceipt(published)
                let head = ReceiptHead(logId: cfg.s("receipt_log_id"), verifierId: verifier.keyId,
                    sequence: 0, headHash: Data(repeating: 0, count: 48))
                tally.check("published", at, try Ratify.verificationReceiptBody(receipt) == committed.receiptBody &&
                    (try Ratify.verifyVerificationReceipt(receipt, verifierKey: verifier.publicKey, head: head)) == .appended)
                try store.setTime(Int64(scenario.int("release_time")))
                let result = try await Ratify.releaseDecision(committed, signedReceipt: want.b64("signed_receipt_b64"),
                    verifierPublicKey: verifier.publicKey, logId: cfg.s("receipt_log_id"),
                    claimStore: store, checkpoint: store)
                let release = want.obj("release")
                tally.check("release", at, result.status.rawValue == release.s("status") &&
                    result.reason == (release["reason"] as? String ?? "") &&
                    result.decision?.decision == (release["decision"] as? String) &&
                    result.decision?.releaseTime == (release["release_time"] as? NSNumber)?.int64Value)
            }
        }
        tally.finish([("policy", count), ("committed", count), ("published", count), ("release", count)])
    }
}
