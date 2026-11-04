import Foundation
import XCTest
import RatifyProtocol

final class ClaimTests: XCTestCase {
    final class ReceiverProbe: ReceiverBindingHook, @unchecked Sendable {
        let reject: Bool
        private let lock = NSLock()
        private var count = 0
        init(reject: Bool) { self.reject = reject }
        var calls: Int { lock.lock(); defer { lock.unlock() }; return count }
        func validate(bundle: ProofBundle, expected: ExpectedChallenge) throws {
            lock.lock(); count += 1; lock.unlock()
            if reject { throw StoreError.unavailable("scripted receiver rejection") }
        }
    }
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

    private func request(_ name: String, evaluators: ConstraintEvaluatorRegistry? = nil) throws -> VerifyRequest {
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
            expectedReceiverId: expected["expected_receiver_id"] as? String ?? "",
            expectedSessionContext: expected.b64("expected_session_context_b64"))
        let statusPolicy = vector.obj("status_policy")
        let statusKeys = vector.obj("status_keys").mapValues { value -> StatusKeyConfig in
            let item = value as! [String: Any]
            let key = item.obj("public_key")
            return StatusKeyConfig(epoch: UInt64(item.int("epoch")),
                key: HybridPublicKey(ed25519: key.b64("ed25519"), mlDsa65: key.b64("ml_dsa_65")))
        }
        let requestContext = vector["request_context"] as? [String: Any] ?? [:]
        let counts = (requestContext["extension_counts"] as? [String: NSNumber] ?? [:]).mapValues(\.int64Value)
        let values = requestContext["extension_values"] as? [String: String] ?? [:]
        return VerifyRequest(bundle: Data(base64Encoded: corpus.obj("bundles_b64").s(vector.s("bundle")))!,
            expected: challenge, contextPolicy: contextPolicy, requiredScope: vector.s("required_scope"),
            verifierNamespace: vector.s("configured_namespace"), replayEpoch: Int64(vector.int("configured_replay_epoch")),
            verifierId: vector.s("configured_verifier_id"), now: Int64(vector.int("now")),
            maxChallengeAgeSeconds: Int64(vector.int("max_challenge_age_seconds")),
            futureSkewSeconds: Int64(vector.int("future_skew_seconds")),
            context: ConstraintContext(requestedAmountMicros: (requestContext["requested_amount_micros"] as? NSNumber)?.int64Value ?? 0,
                requestedCurrency: requestContext["requested_currency"] as? String ?? "",
                hasAmount: requestContext["has_amount"] as? Bool ?? false,
                requestedResourceId: requestContext["requested_resource_id"] as? String ?? "",
                requestedPath: requestContext["requested_path"] as? String ?? "",
                hasResource: requestContext["has_resource"] as? Bool ?? false,
                extensionCounts: counts, extensionValues: values),
            tzdbVersion: vector.s("tzdb_version"), statusKeys: statusKeys,
            statusPolicy: RevocationStatusPolicy(maxListLifetimeSeconds: Int64(statusPolicy.int("max_list_lifetime_seconds")),
                maxStatusAgeSeconds: Int64(statusPolicy.int("max_status_age_seconds")),
                clockSkewSeconds: Int64(statusPolicy.int("clock_skew_seconds"))),
            constraintEvaluators: evaluators)
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

    func testVerifierCorpusPreflightRefusesBeforeClaim() async throws {
        let vectors = Corpus.load("verifier-ordering.json").arr("vectors").filter {
            $0.obj("expected").s("stage") == "preflight" &&
            $0["expected_challenge"] is [String: Any] &&
            $0["context_policy"] is [String: Any] &&
            ($0.obj("expected_challenge")["expected_agent_public_key"] is [String: Any]) &&
            ($0.obj("expected_challenge")["expected_agent_id"] is String) &&
            ($0.obj("expected_challenge")["expected_session_context_b64"] is String) &&
            ($0.obj("context_policy")["expected_session_context_b64"] is String) &&
            $0.s("claim_store") == "create"
        }
        XCTAssertEqual(vectors.count, 129)
        for vector in vectors {
            let name = vector.s("name")
            let store = UnavailableClaimStore()
            let registrations = (vector["constraint_evaluators"] as? [[String: Any]] ?? []).map {
                ConstraintEvaluatorRegistration(descriptor: ConstraintProfileDescriptor(
                    profile: $0.s("profile"), type: $0.s("type")), evaluator: VectorEvaluator(.pass))
            }
            let registry = registrations.isEmpty ? nil : try ConstraintEvaluatorRegistry(
                timeoutMilliseconds: 1000, registrations: registrations)
            let req = try request(name, evaluators: registry)
            let hookMode = vector.s("receiver_binding_hook")
            let probe = hookMode == "absent" ? nil : ReceiverProbe(reject: hookMode == "reject")
            let hook: (any ReceiverBindingHook)? = probe
            let outcome = try await Ratify.verifyProofBundle(req, claimStore: store, receiverBinding: hook)
            XCTAssertEqual(outcome.stage, .preflight, name)
            XCTAssertEqual(outcome.errorClass?.rawValue, vector.obj("expected").s("error_class"), name)
            XCTAssertEqual(probe?.calls ?? 0, vector.obj("expected").obj("callback_counts").int("receiver_binding"), name)
            let calls = await store.calls
            XCTAssertEqual(calls, 0, name)
        }
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

    actor VectorJournal: SecurityJournalStore {
        private var current: SecurityJournalSnapshot
        init(_ initial: SecurityJournalSnapshot) { current = initial }
        func load() -> SecurityJournalSnapshot { current }
        func compareAndSwap(expected: SecurityJournalHead, next: SecurityJournalSnapshot) throws {
            guard current.head == expected else { throw SecurityJournalStoreError.conflict }
            current = next
        }
    }

    struct VectorTrust: TrustProvider {
        let key: HybridPublicKey
        func resolve(chain: [DelegationCert]) -> TrustResolution {
            TrustResolution(outcome: .trusted, rootKey: key)
        }
    }

    struct VectorStatus: StatusEvidenceProvider {
        let byIssuer: [String: [StatusEvidenceObject]]
        func provide(_ request: StatusEvidenceRequest) -> [StatusEvidenceObject] {
            byIssuer[request.issuerId] ?? []
        }
    }

    struct EmptyAudience: AudienceProvider {
        func memberships(for deferred: [DeferredConstraint], receiverId: String) -> [AudienceMembership] { [] }
    }

    actor VectorEvaluator: ConstraintEvaluator {
        enum Mode { case pass, denied, error, timeout }
        let mode: Mode
        private(set) var calls = 0
        init(_ mode: Mode) { self.mode = mode }
        func evaluate(_ input: ConstraintEvaluationInput) async throws -> ConstraintEvaluationResult {
            calls += 1
            XCTAssertEqual(input.type, mode == .error || mode == .timeout ? "com.example.fault" : "com.ratifyprotocol.max_count")
            XCTAssertNotNil(input.paramsJSON)
            if mode == .error { throw StoreError.unavailable("scripted evaluator failure") }
            if mode == .timeout { try await Task.sleep(for: .milliseconds(100)) }
            return ConstraintEvaluationResult(outcome: mode == .denied ? .denied : .pass)
        }
    }

    private func vectorProviders(_ vector: [String: Any], request req: VerifyRequest) async throws
        -> (VectorTrust, VectorStatus, VectorJournal) {
        let root = vector.obj("trust").obj("root_public_key")
        let trust = VectorTrust(key: HybridPublicKey(ed25519: root.b64("ed25519"), mlDsa65: root.b64("ml_dsa_65")))
        let evidence = vector.obj("status_evidence").mapValues { value -> [StatusEvidenceObject] in
            let script = value as! [String: Any]
            return script.arr("objects").map { StatusEvidenceObject(objectType: UInt16($0.int("object_type_code")), wire: $0.b64("wire_b64")) }
        }
        let journal = VectorJournal(try Ratify.emptySecurityJournalSnapshot())
        for issuer in req.statusKeys.keys.sorted() {
            let key = req.statusKeys[issuer]!
            _ = try await Ratify.configureStatusKeyEpoch(store: journal, issuerId: issuer, epoch: key.epoch, key: key.key)
        }
        return (trust, VectorStatus(byIssuer: evidence), journal)
    }

    func testExtensionEvaluatorsRunThroughLiveVerifier() async throws {
        let corpus = Corpus.load("verifier-ordering.json")
        let cases: [(String, VectorEvaluator.Mode, String)] = [
            ("extension_max_count_pass", .pass, "authorized"),
            ("extension_max_count_exceeded", .denied, "constraint_denied"),
            ("extension_evaluator_error", .error, "constraint_unverifiable"),
            ("extension_evaluator_timeout", .timeout, "constraint_unverifiable"),
        ]
        for (name, mode, reason) in cases {
            let vector = corpus.arr("vectors").first { $0.s("name") == name }!
            let registration = vector.arr("constraint_evaluators")[0]
            let evaluator = VectorEvaluator(mode)
            let registry = try ConstraintEvaluatorRegistry(timeoutMilliseconds: mode == .timeout ? 10 : 1000,
                registrations: [ConstraintEvaluatorRegistration(descriptor: ConstraintProfileDescriptor(
                    profile: registration.s("profile"), type: registration.s("type")), evaluator: evaluator)])
            let req = try request(name, evaluators: registry)
            let (trust, status, journal) = try await vectorProviders(vector, request: req)
            let outcome = try await Ratify.verifyProofBundle(req, claimStore: CreatedClaimStore(), trust: trust,
                audience: EmptyAudience(), statusEvidence: status, statusJournal: journal)
            XCTAssertEqual(outcome.stage, .committed, name + ": " + (outcome.errorDetail ?? ""))
            let body = try JSONSerialization.jsonObject(with: outcome.committed!.receiptBody) as! [String: Any]
            XCTAssertEqual(body["decision_reason"] as? String, reason, name)
            let calls = await evaluator.calls
            XCTAssertEqual(calls, 1, name)
        }
    }

    actor ExhaustedBarrierStore: RateAtFinalizationClaimStore {
        private var claim: ChallengeClaim?
        private var counters: [String: Int64] = [:]
        private(set) var observedBatch: [RateReservation] = []
        private(set) var terminalDecisions: [String] = []
        private(set) var finalizations = 0
        private(set) var allowAttempts = 0
        func authoritativeTime() -> Int64 { 1_800_000_000 }
        private func key(_ r: RateReservation) -> String { "\(r.issuerId)|\(r.certId)|\(r.windowSeconds)" }
        func claim(_ value: ChallengeClaim) -> ClaimResult {
            observedBatch = value.rateBatch
            claim = value
            counters[key(value.rateBatch[0])] = value.rateBatch[0].limit
            return ClaimResult(disposition: .created, claimedAt: 1_800_000_000,
                ownerToken: Data(repeating: 7, count: 32))
        }
        func finalize(claimId: String, ownerToken: Data, terminalResult: Data, receiptBody: Data,
                      allowValidUntil: Int64) throws -> Bool {
            finalizations += 1
            let decision = try JSONSerialization.jsonObject(with: terminalResult) as! [String: Any]
            terminalDecisions.append(decision["decision"] as? String ?? "")
            if decision["decision"] as? String == "allow" {
                allowAttempts += 1
                let batch = claim!.rateBatch
                if batch.contains(where: { counters[key($0), default: 0] >= $0.limit }) {
                    throw StoreError.rateLimitExceeded
                }
                for item in batch { counters[key(item), default: 0] += 1 }
            }
            return true
        }
        func recordProgress(claimId: String, ownerToken: Data, progress: EvaluationProgress) {}
        func loadInterrupted(claimId: String) -> InterruptedClaim { fatalError("not interrupted") }
        func recoverInterrupted(claimId: String, terminalResult: Data, receiptBody: Data) -> Bool { false }
        func counterValues() -> [Int64] { claim!.rateBatch.map { counters[key($0), default: 0] } }
    }

    func testRateBarrierMapsCapacityRefusalAndRetriesDeny() async throws {
        let vector = Corpus.load("verifier-ordering.json").arr("vectors").first { $0.s("name") == "rate_multi_batch" }!
        let expectedBatch = vector.obj("expected").arr("rate_batch").map {
            RateReservation(issuerId: $0.s("issuer_id"), certId: $0.s("cert_id"),
                windowSeconds: Int64($0.int("window_s")), limit: Int64($0.int("limit")))
        }
        let req = try request("rate_multi_batch")
        let (trust, status, journal) = try await vectorProviders(vector, request: req)
        let store = ExhaustedBarrierStore()
        let outcome = try await Ratify.verifyProofBundle(req, claimStore: store, trust: trust,
            audience: EmptyAudience(), statusEvidence: status, statusJournal: journal)
        XCTAssertEqual(outcome.stage, .committed, outcome.errorDetail ?? "")
        let body = try JSONSerialization.jsonObject(with: outcome.committed!.receiptBody) as! [String: Any]
        XCTAssertEqual(body["decision_reason"] as? String, "constraint_denied")
        let attempts = await store.allowAttempts
        let finalizations = await store.finalizations
        let counters = await store.counterValues()
        let observedBatch = await store.observedBatch
        let decisions = await store.terminalDecisions
        XCTAssertEqual(observedBatch, expectedBatch)
        XCTAssertEqual(decisions, ["allow", "deny"])
        XCTAssertEqual(attempts, 1)
        XCTAssertEqual(finalizations, 2, "the core must retry a definitive rate refusal as deny")
        XCTAssertEqual(counters, [3, 0, 0], "the host fixture rejects the entire batch")
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

    actor PendingReleaseStore: ReleaseClaimStore {
        let committed: CommittedOutcome
        private(set) var loads = 0
        init(_ committed: CommittedOutcome) { self.committed = committed }
        func authoritativeTime() -> Int64 { XCTFail("no receipt means no clock read"); return 0 }
        func loadTerminal(claimId: String) -> TerminalClaimRecord {
            XCTAssertEqual(claimId, committed.claimId)
            loads += 1
            return TerminalClaimRecord(terminal: true, receiptOutboxDigest: committed.receiptBodyDigest,
                challengeExpiresAt: committed.challengeExpiresAt, allowHorizon: committed.allowHorizon ?? 0,
                finalizedAt: 1_800_000_000, receiptAbandoned: false, release: nil)
        }
        func recordRelease(_ record: ReleaseRecord) { XCTFail("no receipt means no release record") }
    }

    struct NoAcknowledgement: ReceiptCheckpoint {
        func acknowledge(logId: String, sequence: Int64, previousEntryHash: Data,
                         entryHash: Data) throws -> CheckpointAcknowledgement {
            throw StoreError.unavailable("checkpoint unavailable")
        }
        func get(logId: String, sequence: Int64) throws -> CheckpointAcknowledgement {
            throw StoreError.unavailable("checkpoint unavailable")
        }
    }

    func testCommittedHandoffCannotReleaseBeforeReceiptAppend() async throws {
        let verified = try await Ratify.verifyProofBundle(request("trust_unavailable"),
            claimStore: CreatedClaimStore(), trust: UnavailableTrust())
        let committed = try XCTUnwrap(verified.committed)
        let key = Corpus.load("keys.json").arr("keys").first { $0.s("name") == "verifier" }!.obj("public_key")
        let verifierKey = HybridPublicKey(ed25519: key.b64("ed25519"), mlDsa65: key.b64("ml_dsa_65"))
        let store = PendingReleaseStore(committed)
        let result = try await Ratify.releaseDecision(committed, signedReceipt: nil,
            verifierPublicKey: verifierKey, logId: "0123456789abcdef0123456789abcdef",
            claimStore: store, checkpoint: NoAcknowledgement())
        XCTAssertEqual(result.status, .pending)
        XCTAssertEqual(result.reason, "receipt_not_appended")
        XCTAssertNil(result.decision)
        let loads = await store.loads
        XCTAssertEqual(loads, 1)
    }

    actor ReleasedStore: ReleaseClaimStore {
        let committed: CommittedOutcome
        private(set) var recorded: ReleaseRecord?
        init(_ committed: CommittedOutcome) { self.committed = committed }
        func authoritativeTime() -> Int64 { 1_800_000_000 }
        func loadTerminal(claimId: String) -> TerminalClaimRecord {
            TerminalClaimRecord(terminal: true, receiptOutboxDigest: committed.receiptBodyDigest,
                challengeExpiresAt: committed.challengeExpiresAt, allowHorizon: committed.allowHorizon ?? 0,
                finalizedAt: 1_800_000_000, receiptAbandoned: false, release: recorded)
        }
        func recordRelease(_ record: ReleaseRecord) { recorded = record }
    }

    struct AcknowledgedReceipt: ReceiptCheckpoint {
        let receipt: VerificationReceipt
        let digest: Data
        func acknowledge(logId: String, sequence: Int64, previousEntryHash: Data,
                         entryHash: Data) throws -> CheckpointAcknowledgement {
            throw StoreError.unavailable("release only reads acknowledgement")
        }
        func get(logId: String, sequence: Int64) -> CheckpointAcknowledgement {
            CheckpointAcknowledgement(logId: logId, sequence: sequence, entryHash: digest,
                timestamp: 1_800_000_000)
        }
    }

    func testSignedReceiptNeedsIndependentCheckpointToRelease() async throws {
        let verified = try await Ratify.verifyProofBundle(request("trust_unavailable"),
            claimStore: CreatedClaimStore(), trust: UnavailableTrust())
        let committed = try XCTUnwrap(verified.committed)
        let key = Fixture.shared.privateKey("verifier")
        let logId = "0123456789abcdef0123456789abcdef"
        let head = ReceiptHead(logId: logId, verifierId: key.keyId, sequence: 0,
            headHash: Data(repeating: 0, count: 48))
        let receipt = try Ratify.signPreparedVerificationReceipt(committed.receiptBody, head: head, key: key)
        let wire = try Ratify.encodeVerificationReceipt(receipt)
        let digest = try Ratify.verificationReceiptDigest(receipt)
        let store = ReleasedStore(committed)
        let pending = try await Ratify.releaseDecision(committed, signedReceipt: wire,
            verifierPublicKey: key.publicKey, logId: logId, claimStore: store, checkpoint: NoAcknowledgement())
        XCTAssertEqual(pending.status, .pending)
        XCTAssertEqual(pending.reason, "acknowledgement_unavailable")
        XCTAssertNil(pending.decision)
        let beforeCheckpoint = await store.recorded
        XCTAssertNil(beforeCheckpoint)
        let released = try await Ratify.releaseDecision(committed, signedReceipt: wire,
            verifierPublicKey: key.publicKey, logId: logId, claimStore: store,
            checkpoint: AcknowledgedReceipt(receipt: receipt, digest: digest))
        XCTAssertEqual(released.status, .released)
        XCTAssertEqual(released.decision?.receiptWire, wire)
        let allowed = try await released.decision!.isAllowed(clock: store)
        XCTAssertFalse(allowed)
        let recorded = await store.recorded
        XCTAssertEqual(recorded?.outcome, .released)
    }
}
