import Foundation
import XCTest
import RatifyProtocol
import RatifyProtocolTestSupport

final class ClaimTests: XCTestCase {
    @objc func corpusHarness() {}

    func testIssuerScopedStatusJournalKeepsSharedCertIdsSeparate() async throws {
        let now: Int64 = 1_800_000_000
        let policy = RevocationStatusPolicy(maxListLifetimeSeconds: 3600, maxStatusAgeSeconds: 600,
            clockSkewSeconds: 5)
        let journal = VectorJournal(try Ratify.emptySecurityJournalSnapshot())
        let issuers = [Fixture.shared.privateKey("root").keyId,
                       Fixture.shared.privateKey("intermediate").keyId]
        let statusKeys = [Fixture.shared.privateKey("status_root"),
                          Fixture.shared.privateKey("status_intermediate")]
        var signedLists: [RevocationList] = []
        XCTAssertNotEqual(issuers[0], issuers[1])
        for i in 0..<2 {
            _ = try await Ratify.configureStatusKeyEpoch(store: journal, issuerId: issuers[i],
                epoch: 1, key: statusKeys[i].publicKey)
            let list = RevocationList(version: 2, issuerId: issuers[i], updatedAt: now - 10,
                nextUpdate: now + 600, sequence: 1, revoked: i == 0 ? ["shared-id"] : [],
                signature: HybridSignature(ed25519: Data(), mlDsa65: Data()))
            let signed = try Ratify.signRevocationList(list, boundIssuerId: issuers[i],
                boundStatusKey: statusKeys[i].publicKey, key: statusKeys[i])
            signedLists.append(signed)
            _ = try await Ratify.applyRevocationListToJournal(store: journal, list: signed,
                issuerId: issuers[i], epoch: 1, key: statusKeys[i].publicKey, policy: policy, now: now)
        }
        let first = try await Ratify.revocationStatusFromJournal(store: journal, issuerId: issuers[0],
            certId: "shared-id", epoch: 1, key: statusKeys[0].publicKey, policy: policy, now: now)
        let second = try await Ratify.revocationStatusFromJournal(store: journal, issuerId: issuers[1],
            certId: "shared-id", epoch: 1, key: statusKeys[1].publicKey, policy: policy, now: now)
        XCTAssertEqual(first.status, "revoked")
        XCTAssertEqual(second.status, "not_revoked")
        XCTAssertEqual(classOf { try Ratify.verifyRevocationListSignature(signedLists[0],
            trustedIssuerId: issuers[1], statusKey: statusKeys[0].publicKey) },
            "status_key_binding_mismatch")
    }

    func testReferenceTrustRegistryOutcomesBeforeVerification() async throws {
        let vectors = Corpus.load("verifier-ordering.json").arr("vectors")
        let cases: [(String, TrustOutcome)] = [
            ("trust_registry_single_record", .trusted),
            ("trust_registry_duplicate_record", .ambiguous),
            ("trust_registry_two_candidates_sharing_component", .ambiguous),
            ("trust_registry_component_only_candidate", .trusted),
            ("trust_registry_no_candidate", .untrusted),
        ]
        for (name, expected) in cases {
            let vector = try XCTUnwrap(vectors.first { $0.s("name") == name })
            let records = vector.obj("trust").arr("registry").map {
                HybridPublicKey(ed25519: $0.b64("ed25519"), mlDsa65: $0.b64("ml_dsa_65"))
            }
            let registry = try TrustRegistry(records: records)
            let chain = try Ratify.decodeProofBundle(request(name).bundle).delegations
            let answer = try await registry.resolve(chain: chain)
            XCTAssertEqual(answer.outcome, expected, name)
            if expected == .trusted {
                XCTAssertEqual(answer.rootKey,
                    records[name == "trust_registry_single_record" ? 1 : 0], name)
            } else {
                XCTAssertTrue(answer.rootKey.ed25519.isEmpty, name)
                XCTAssertTrue(answer.rootKey.mlDsa65.isEmpty, name)
            }
        }
    }

    func testDualRootLedgerStartsIncomplete() throws {
        let corpus = Corpus.load("lifecycle-scenarios.json")
        let scenario = try XCTUnwrap(corpus.arr("profile_scenarios").first {
            $0.s("name") == "dual_root_both_released_executes_once"
        })
        let first = try XCTUnwrap(scenario.arr("steps").first)
        XCTAssertEqual(first.s("op"), "ledger_open")
        let set = first.obj("approval_set")
        let roots = set.strings("root_keys")
        XCTAssertEqual(roots.count, 2)
        let ledger = try ApprovalLedger()
        let opened = try ledger.open(id: set.s("id"), verifierId: set.s("verifier_id"),
            workspaceId: set.s("workspace_id"), sessionId: set.s("session_id"),
            agentKey: Fixture.shared.privateKey(set.s("agent_key")).publicKey,
            requiredScope: set.s("required_scope"), requestHash: set.b64("request_hash_b64"),
            rootA: Fixture.shared.privateKey(roots[0]).publicKey,
            rootB: Fixture.shared.privateKey(roots[1]).publicKey)
        XCTAssertNil(opened.failure)
        XCTAssertNil(opened.complete)
        let store = try Store(now: Int64(scenario.int("start_time")), leaseSeconds: Int64(corpus.int("lease_seconds")),
            logId: corpus.s("log_id"), verifierKey: Fixture.shared.privateKey(corpus.s("verifier_key")))
        let refused = try ledger.execute(id: set.s("id"), clock: store)
        XCTAssertEqual(refused.failure, "incomplete")
        XCTAssertNil(refused.complete)
        let unreleased = try ledger.record(id: set.s("id"), slot: 0, decision: nil, bundle: Data())
        XCTAssertEqual(unreleased.failure, "not_released")
        XCTAssertNil(unreleased.complete)
    }

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
        let conflict: Bool
        init(conflict: Bool = false) { self.conflict = conflict }
        func authoritativeTime() -> Int64 { XCTFail("preflight must not read store time"); return 0 }
        func claim(_ claim: ChallengeClaim) throws -> ClaimResult {
            XCTAssertFalse(claim.claimId.isEmpty)
            calls += 1
            if conflict { throw StoreError.claimProofConflict }
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

    private func request(_ name: String, corpusName: String = "verifier-ordering.json",
                         evaluators: ConstraintEvaluatorRegistry? = nil, atTime: Int64? = nil,
                         replayEpochOverride: Int64? = nil) throws -> VerifyRequest {
        let corpus = Corpus.load(corpusName)
        let vector = corpusName == "lifecycle-scenarios.json" ? corpus.obj("requests").obj(name)
            : corpus.arr("vectors").first { $0.s("name") == name }!
        let policy = vector["context_policy"] as? [String: Any]
        let contextPolicy = try policy.map { policy in
            try ContextPolicy(profile: policy.s("profile"), requireBound: policy.bool("require_bound"),
                requiredFields: policy.strings("required_fields"),
                expectedSessionContext: (policy["expected_session_context_b64"] as? String).map { Data(base64Encoded: $0)! } ?? Data())
        }
        let challenge = (vector["expected_challenge"] as? [String: Any]).map { expected in
            let key = expected["expected_agent_public_key"] as? [String: Any]
            return ExpectedChallenge(value: expected.b64("value_b64"), issuedAt: Int64(expected.int("issued_at")),
                expiresAt: Int64(expected.int("expires_at")), verifierNamespace: expected.s("verifier_namespace"),
                replayEpoch: Int64(expected.int("replay_epoch")), verifierId: expected.s("verifier_id"),
                expectedAgentId: expected["expected_agent_id"] as? String ?? "",
                expectedAgentPublicKey: key.map { HybridPublicKey(ed25519: $0.b64("ed25519"), mlDsa65: $0.b64("ml_dsa_65")) },
                expectedReceiverId: expected["expected_receiver_id"] as? String ?? "",
                expectedSessionContext: (expected["expected_session_context_b64"] as? String).map { Data(base64Encoded: $0)! })
        }
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
            verifierNamespace: vector.s("configured_namespace"),
            replayEpoch: replayEpochOverride ?? Int64(vector.int("configured_replay_epoch")),
            verifierId: vector.s("configured_verifier_id"), now: atTime ?? Int64(vector.int("now")),
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

    func verifierCorpusPreflightOrdering() async throws {
        let vectors = Corpus.load("verifier-ordering.json").arr("vectors").filter {
            $0.obj("expected").s("stage") == "preflight"
        }
        XCTAssertEqual(vectors.count, 149)
        for vector in vectors {
            let name = vector.s("name")
            let store = UnavailableClaimStore(conflict: vector.s("claim_store") == "proof_conflict")
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
            let outcome = if vector.s("claim_store") == "absent" {
                try await Ratify.verifyProofBundleWithoutClaimStore(req, receiverBinding: hook)
            } else {
                try await Ratify.verifyProofBundle(req, claimStore: store, receiverBinding: hook)
            }
            XCTAssertEqual(outcome.stage, .preflight, name)
            XCTAssertEqual(outcome.errorClass?.rawValue, vector.obj("expected").s("error_class"), name)
            XCTAssertEqual(probe?.calls ?? 0, vector.obj("expected").obj("callback_counts").int("receiver_binding"), name)
            let calls = await store.calls
            XCTAssertEqual(calls, vector.obj("expected").obj("callback_counts").int("claim"), name)
        }
    }

    actor CreatedClaimStore: RateAtFinalizationClaimStore {
        let onFinalize: (@Sendable () async -> Void)?
        let claimedAt: Int64
        let finalizeTimeOffset: Int64
        let disposition: ClaimDisposition
        private var claimed: ChallengeClaim?
        private(set) var claims = 0
        private(set) var progressWrites = 0
        private(set) var progressRecords: [EvaluationProgress] = []
        private(set) var finalizations = 0
        private(set) var allowHorizons: [Int64] = []
        private(set) var lastTerminalResult: Data?
        private(set) var lastReceiptBody: Data?
        init(onFinalize: (@Sendable () async -> Void)? = nil, claimedAt: Int64 = 1_800_000_000,
             finalizeTimeOffset: Int64 = 0, disposition: ClaimDisposition = .created) {
            self.onFinalize = onFinalize; self.claimedAt = claimedAt
            self.finalizeTimeOffset = finalizeTimeOffset; self.disposition = disposition
        }
        func authoritativeTime() -> Int64 { claimedAt }
        func claim(_ claim: ChallengeClaim) -> ClaimResult {
            claims += 1
            if disposition == .created { claimed = claim }
            return ClaimResult(disposition: disposition, claimedAt: claimedAt,
                ownerToken: disposition == .created ? Data(repeating: 7, count: 32) : Data())
        }
        func finalize(claimId: String, ownerToken: Data, terminalResult: Data, receiptBody: Data,
                      allowValidUntil: Int64) async throws -> Bool {
            if let onFinalize { await onFinalize() }
            XCTAssertEqual(ownerToken, Data(repeating: 7, count: 32))
            XCTAssertFalse(terminalResult.isEmpty)
            XCTAssertFalse(receiptBody.isEmpty)
            finalizations += 1
            allowHorizons.append(allowValidUntil)
            lastTerminalResult = terminalResult
            lastReceiptBody = receiptBody
            let finalTime = claimedAt + finalizeTimeOffset
            if finalTime < claimedAt { throw StoreError.classified(.clockRegressed, detail: "finalization clock regressed") }
            if allowValidUntil != 0 && (finalTime >= allowValidUntil || finalTime >= claimed!.expiresAt) {
                throw StoreError.classified(.allowHorizonPassed, detail: "allow horizon passed")
            }
            return true
        }
        func recordProgress(claimId: String, ownerToken: Data, progress: EvaluationProgress) {
            progressWrites += 1
            progressRecords.append(progress)
        }
        func loadInterrupted(claimId: String) -> InterruptedClaim { fatalError("no interruption") }
        func recoverInterrupted(claimId: String, terminalResult: Data, receiptBody: Data) -> Bool {
            XCTFail("no interruption"); return false
        }
    }

    func verifierCorpusReplay() async throws {
        let vectors = Corpus.load("verifier-ordering.json").arr("vectors").filter {
            $0.obj("expected").s("stage") == "replay"
        }
        XCTAssertEqual(vectors.count, 2)
        for vector in vectors {
            let name = vector.s("name")
            let disposition = ClaimDisposition(rawValue: vector.obj("expected").s("disposition"))!
            let store = CreatedClaimStore(disposition: disposition)
            let trust = VectorTrust(key: HybridPublicKey(ed25519: Data(), mlDsa65: Data()), outcome: .trusted)
            let status = VectorStatus(byIssuer: [:])
            let audience = EmptyAudience()
            let outcome = try await Ratify.verifyProofBundle(request(name), claimStore: store,
                trust: trust, audience: audience, statusEvidence: status)
            let callbacks = vector.obj("expected").obj("callback_counts")
            XCTAssertEqual(outcome.stage, .replay, name)
            XCTAssertEqual(outcome.disposition, disposition, name)
            XCTAssertNil(outcome.committed, name)
            let claims = await store.claims
            let finalizations = await store.finalizations
            let progress = await store.progressWrites
            let trustCalls = await trust.calls
            let statusCalls = await status.requests.count
            let audienceCalls = await audience.calls
            XCTAssertEqual(claims, callbacks.int("claim"), name)
            XCTAssertEqual(finalizations, callbacks.int("finalize"), name)
            XCTAssertEqual(progress, callbacks.int("progress"), name)
            XCTAssertEqual(trustCalls, callbacks.int("trust"), name)
            XCTAssertEqual(statusCalls, callbacks.int("status"), name)
            XCTAssertEqual(audienceCalls, callbacks.int("audience"), name)
            XCTAssertEqual(statusCalls, vector.obj("expected").arr("status_requests").count, name)
        }
    }

    func verifierCorpusFinalizationRefusals() async throws {
        let vectors = Corpus.load("verifier-ordering.json").arr("vectors").filter {
            $0.obj("expected").s("stage") == "evaluating"
        }
        XCTAssertEqual(vectors.count, 2)
        for vector in vectors {
            let name = vector.s("name")
            let req = try request(name)
            let (trust, status, journal) = try await vectorProviders(vector, request: req)
            let store = CreatedClaimStore(claimedAt: Int64(vector.int("now")),
                finalizeTimeOffset: Int64(vector.int("finalize_time_offset")))
            let audience = EmptyAudience()
            let outcome = try await Ratify.verifyProofBundle(req, claimStore: store, trust: trust,
                audience: audience, statusEvidence: status, statusJournal: journal)
            let expected = vector.obj("expected")
            let callbacks = expected.obj("callback_counts")
            XCTAssertEqual(outcome.stage, .evaluating, name)
            XCTAssertEqual(outcome.errorClass?.rawValue, expected.s("error_class"), name)
            XCTAssertNil(outcome.committed, name)
            let claims = await store.claims
            let finalizations = await store.finalizations
            let progress = await store.progressWrites
            let trustCalls = await trust.calls
            let requests = await status.requests
            let audienceCalls = await audience.calls
            XCTAssertEqual(claims, callbacks.int("claim"), name)
            XCTAssertEqual(finalizations, callbacks.int("finalize"), name)
            XCTAssertEqual(progress, callbacks.int("progress"), name)
            XCTAssertEqual(trustCalls, callbacks.int("trust"), name)
            XCTAssertEqual(requests.count, callbacks.int("status"), name)
            XCTAssertEqual(audienceCalls, callbacks.int("audience"), name)
            let expectedRequests = expected.arr("status_requests")
            XCTAssertEqual(requests.count, expectedRequests.count, name)
            for (actual, scripted) in zip(requests, expectedRequests) {
                XCTAssertEqual(actual.issuerId, scripted.s("issuer_id"), name)
                XCTAssertEqual(actual.statusKeyEpoch, UInt64(scripted.int("status_key_epoch")), name)
                XCTAssertEqual(actual.statusKeyId, scripted.s("status_key_id"), name)
                let refs = scripted.arr("refs")
                XCTAssertEqual(actual.refs.count, refs.count, name)
                for (actualRef, expectedRef) in zip(actual.refs, refs) {
                    XCTAssertEqual(actualRef.issuerId, expectedRef.s("issuer_id"), name)
                    XCTAssertEqual(actualRef.certId, expectedRef.s("cert_id"), name)
                }
            }
        }
    }

    actor VectorRate: RateReservationStore {
        let mode: String
        private(set) var batches: [[RateReservation]] = []
        init(_ mode: String) { self.mode = mode }
        func reserve(claimId: String, ownerToken: Data, bundleHash: String,
                     batch: [RateReservation]) throws {
            XCTAssertEqual(ownerToken, Data(repeating: 7, count: 32))
            XCTAssertFalse(bundleHash.isEmpty)
            batches.append(batch)
            if mode == "exceeded" { throw StoreError.rateLimitExceeded }
            if mode == "unavailable" { throw StoreError.unavailable("scripted rate failure") }
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
        private var mode = "anchored"
        private var conflicts = 0
        init(_ initial: SecurityJournalSnapshot) { current = initial }
        func setMode(_ value: String) { mode = value }
        func load() throws -> SecurityJournalSnapshot {
            if mode == "load_error" { throw StoreError.unavailable("scripted journal load failure") }
            return current
        }
        func compareAndSwap(expected: SecurityJournalHead, next: SecurityJournalSnapshot) throws {
            if mode == "cas_conflict" || mode == "cas_conflict_once" && conflicts == 0 {
                conflicts += 1
                throw SecurityJournalStoreError.conflict
            }
            guard current.head == expected else { throw SecurityJournalStoreError.conflict }
            current = next
        }
    }

    actor VectorTrust: TrustProvider {
        let key: HybridPublicKey
        let outcome: TrustOutcome
        let fails: Bool
        let registry: TrustRegistry?
        private(set) var calls = 0
        init(key: HybridPublicKey, outcome: TrustOutcome, fails: Bool = false,
             registry: TrustRegistry? = nil) {
            self.key = key; self.outcome = outcome; self.fails = fails; self.registry = registry
        }
        func resolve(chain: [DelegationCert]) async throws -> TrustResolution {
            calls += 1
            if fails { throw StoreError.unavailable("scripted trust failure") }
            if let registry { return try await registry.resolve(chain: chain) }
            return TrustResolution(outcome: outcome, rootKey: key)
        }
    }

    actor VectorStatus: StatusEvidenceProvider {
        let byIssuer: [String: [StatusEvidenceObject]]
        let failures: Set<String>
        let onFirstRequest: (@Sendable () throws -> Void)?
        private(set) var requests: [StatusEvidenceRequest] = []
        init(byIssuer: [String: [StatusEvidenceObject]], failures: Set<String> = [],
             onFirstRequest: (@Sendable () throws -> Void)? = nil) {
            self.byIssuer = byIssuer; self.failures = failures; self.onFirstRequest = onFirstRequest
        }
        func provide(_ request: StatusEvidenceRequest) throws -> [StatusEvidenceObject] {
            requests.append(request)
            if requests.count == 1 { try onFirstRequest?() }
            if failures.contains(request.issuerId) { throw StoreError.unavailable("scripted status failure") }
            return byIssuer[request.issuerId] ?? []
        }
    }

    final class GatedReceiver: ReceiverBindingHook, @unchecked Sendable {
        let started: XCTestExpectation
        let release = DispatchSemaphore(value: 0)
        init(started: XCTestExpectation) { self.started = started }
        func validate(bundle: ProofBundle, expected: ExpectedChallenge) {
            started.fulfill()
            release.wait()
        }
    }

    struct GatedStatus: StatusEvidenceProvider {
        let inner: VectorStatus
        let gate: FinalizationGate
        let started: XCTestExpectation
        func provide(_ request: StatusEvidenceRequest) async throws -> [StatusEvidenceObject] {
            started.fulfill()
            await gate.wait()
            try Task.checkCancellation()
            return try await inner.provide(request)
        }
    }

    actor EmptyAudience: AudienceProvider {
        let values: [AudienceMembership]
        let fails: Bool
        private(set) var calls = 0
        init(memberships: [AudienceMembership] = [], fails: Bool = false) {
            values = memberships; self.fails = fails
        }
        func memberships(for deferred: [DeferredConstraint], receiverId: String) throws -> [AudienceMembership] {
            calls += 1
            if fails { throw StoreError.unavailable("scripted audience failure") }
            return values
        }
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

    actor GatedEvaluator: ConstraintEvaluator {
        let started: XCTestExpectation
        let deadlineSeen: XCTestExpectation?
        let gate: FinalizationGate
        private(set) var cancelledOnReturn = false
        init(started: XCTestExpectation, gate: FinalizationGate, deadlineSeen: XCTestExpectation? = nil) {
            self.started = started; self.gate = gate; self.deadlineSeen = deadlineSeen
        }
        func evaluate(_ input: ConstraintEvaluationInput) async -> ConstraintEvaluationResult {
            started.fulfill()
            if let deadlineSeen {
                while !Task.isCancelled {
                    if await gate.isOpen { break }
                    try? await Task.sleep(for: .milliseconds(5))
                }
                deadlineSeen.fulfill()
            }
            await gate.wait()
            cancelledOnReturn = Task.isCancelled
            return ConstraintEvaluationResult(outcome: .pass)
        }
    }

    actor CompletionFlag {
        private(set) var done = false
        private(set) var gateOpenAtReturn = false
        func markDone(gateOpen: Bool) { gateOpenAtReturn = gateOpen; done = true }
    }

    actor CorpusEvaluator: ConstraintEvaluator {
        let implementation: String
        let validUntil: Int64
        private(set) var calls = 0
        init(implementation: String, validUntil: Int64) {
            self.implementation = implementation
            self.validUntil = validUntil
        }
        func evaluate(_ input: ConstraintEvaluationInput) async throws -> ConstraintEvaluationResult {
            calls += 1
            switch implementation {
            case "com.ratifyprotocol.max_count/v1": return try Ratify.evaluateMaxCount(input)
            case "com.ratifyprotocol.allowed_values/v1": return try Ratify.evaluateAllowedValues(input)
            case "fault:pass_until": return ConstraintEvaluationResult(outcome: .pass, validUntil: validUntil)
            case "fault:error": throw StoreError.unavailable("scripted evaluator failure")
            case "fault:panic": return ConstraintEvaluationResult(outcome: .pass)
            case "fault:invalid_outcome": return ConstraintEvaluationResult(outcome: .invalid)
            case "fault:timeout":
                try await Task.sleep(for: .milliseconds(100))
                return ConstraintEvaluationResult(outcome: .pass)
            default: XCTFail("Unsupported corpus evaluator: \(implementation)"); return ConstraintEvaluationResult(outcome: .invalid)
            }
        }
    }

    private func vectorProviders(_ vector: [String: Any], request req: VerifyRequest,
                                 onFirstStatus: (@Sendable () throws -> Void)? = nil) async throws
        -> (VectorTrust, VectorStatus, VectorJournal) {
        let trustScript = vector["trust"] as? [String: Any] ?? [:]
        let root = trustScript["root_public_key"] as? [String: Any]
        let records = (trustScript["registry"] as? [[String: Any]])?.map {
            HybridPublicKey(ed25519: $0.b64("ed25519"), mlDsa65: $0.b64("ml_dsa_65"))
        }
        let trust = VectorTrust(key: root.map { HybridPublicKey(ed25519: $0.b64("ed25519"), mlDsa65: $0.b64("ml_dsa_65")) }
            ?? HybridPublicKey(ed25519: Data(), mlDsa65: Data()),
            outcome: TrustOutcome(rawValue: trustScript["outcome"] as? String ?? "") ?? .unavailable,
            fails: trustScript["mode"] as? String == "error",
            registry: try records.map { try TrustRegistry(records: $0) })
        let evidence = vector.obj("status_evidence").mapValues { value -> [StatusEvidenceObject] in
            let script = value as! [String: Any]
            return script.arr("objects").map { StatusEvidenceObject(objectType: UInt16($0.int("object_type_code")), wire: $0.b64("wire_b64")) }
        }
        let statusFailures = Set(vector.obj("status_evidence").compactMap { entry in
            (entry.value as? [String: Any])?["mode"] as? String == "error" ? entry.key : nil
        })
        let journal = VectorJournal(try Ratify.emptySecurityJournalSnapshot())
        let script = vector.obj("journal")
        if let setup = script["setup"] as? [[String: Any]] {
            for step in setup {
                let publicKey = step.obj("public_key")
                let key = HybridPublicKey(ed25519: publicKey.b64("ed25519"), mlDsa65: publicKey.b64("ml_dsa_65"))
                if step.s("op") == "configure_status_key" {
                    _ = try await Ratify.configureStatusKeyEpoch(store: journal, issuerId: step.s("issuer_id"),
                        epoch: UInt64(step.int("epoch")), key: key)
                } else {
                    XCTAssertEqual(step.s("op"), "apply")
                    XCTAssertEqual(step.int("object_type_code"), 3)
                    _ = try await Ratify.applyRevocationListToJournal(store: journal,
                        list: Ratify.decodeRevocationList(step.b64("wire_b64")), issuerId: step.s("issuer_id"),
                        epoch: UInt64(step.int("epoch")), key: key, policy: req.statusPolicy,
                        now: Int64(step.int("now")))
                }
            }
        } else if script.s("mode") != "unanchored" && script.s("mode") != "absent" {
            for issuer in req.statusKeys.keys.sorted() {
                let key = req.statusKeys[issuer]!
                _ = try await Ratify.configureStatusKeyEpoch(store: journal, issuerId: issuer, epoch: key.epoch, key: key.key)
            }
            for step in script["preload"] as? [[String: Any]] ?? [] {
                XCTAssertEqual(step.int("object_type_code"), 3)
                let key = req.statusKeys[step.s("issuer_id")]!
                _ = try await Ratify.applyRevocationListToJournal(store: journal,
                    list: Ratify.decodeRevocationList(step.b64("wire_b64")), issuerId: step.s("issuer_id"),
                    epoch: key.epoch, key: key.key, policy: req.statusPolicy, now: Int64(step.int("now")))
            }
        }
        await journal.setMode(script.s("mode"))
        return (trust, VectorStatus(byIssuer: evidence, failures: statusFailures,
            onFirstRequest: onFirstStatus), journal)
    }

    func verifierCorpusCommittedReceipts() async throws {
        let vectors = Corpus.load("verifier-ordering.json").arr("vectors").filter {
            $0.obj("expected").s("stage") == "committed"
        }
        XCTAssertEqual(vectors.count, 362)
        for vector in vectors {
            let name = vector.s("name")
            let evaluators = (vector["constraint_evaluators"] as? [[String: Any]] ?? []).map {
                CorpusEvaluator(implementation: $0.s("implementation"),
                    validUntil: ($0["valid_until"] as? NSNumber)?.int64Value ?? 0)
            }
            let registrations = zip(vector["constraint_evaluators"] as? [[String: Any]] ?? [], evaluators).map {
                ConstraintEvaluatorRegistration(descriptor: ConstraintProfileDescriptor(
                    profile: $0.0.s("profile"), type: $0.0.s("type")), evaluator: $0.1)
            }
            let timeout: UInt64 = evaluators.contains { $0.implementation == "fault:timeout" } ? 10 : 1000
            let registry = registrations.isEmpty ? nil : try ConstraintEvaluatorRegistry(
                timeoutMilliseconds: timeout, registrations: registrations)
            let req = try request(name, evaluators: registry)
            let (trust, status, journal) = try await vectorProviders(vector, request: req)
            let store = CreatedClaimStore(claimedAt: Int64(vector.int("now") +
                ((vector["claim_time_offset"] as? NSNumber)?.intValue ?? 0)),
                finalizeTimeOffset: (vector["finalize_time_offset"] as? NSNumber)?.int64Value ?? 0)
            let baseStore: any ClaimStore = store
            let memberships = (vector["audience_memberships"] as? [[String: Any]] ?? []).map {
                AudienceMembership(delegationIndex: UInt64($0.int("delegation_index")),
                    constraintIndex: UInt64($0.int("constraint_index")), receiverId: $0.s("receiver_id"),
                    trustDomainIds: $0.strings("trust_domain_ids"), issuedAt: Int64($0.int("issued_at")),
                    expiresAt: Int64($0.int("expires_at")), evidenceDigest: $0.s("evidence_digest"))
            }
            let audience = EmptyAudience(memberships: memberships,
                fails: vector.s("audience_mode") == "error")
            let rate = vector.s("rate") == "absent" ? nil : VectorRate(vector.s("rate"))
            let receiver = vector.s("receiver_binding_hook") == "accept" ? ReceiverProbe(reject: false) : nil
            let journalStore: (any SecurityJournalStore)? = vector.obj("journal").s("mode") == "absent" ? nil : journal
            let panicKind: UInt32 = switch name {
            case "trust_provider_panic": 1
            case "status_provider_panic": 2
            case "audience_provider_panic": 3
            case "rate_store_panic": 4
            case "extension_evaluator_panic": 5
            default: 0
            }
            if panicKind == 1 { XCTAssertEqual(vector.obj("trust").s("mode"), "panic", name) }
            if panicKind == 2 { XCTAssertTrue(vector.obj("status_evidence").values.contains { ($0 as? [String: Any])?["mode"] as? String == "panic" }, name) }
            if panicKind == 3 { XCTAssertEqual(vector.s("audience_mode"), "panic", name) }
            if panicKind == 4 { XCTAssertEqual(vector.s("rate"), "panic", name) }
            if panicKind == 5 { XCTAssertTrue(vector.arr("constraint_evaluators").contains { $0.s("implementation") == "fault:panic" }, name) }
            // A Swift trap cannot unwind. The test-only Rust hook panics after
            // the foreign call, preserving its count while exercising core containment.
            if panicKind != 0 { TestHooks.armCallbackPanic(panicKind) }
            defer { TestHooks.armCallbackPanic(0) }
            let outcome = try await Ratify.verifyProofBundle(req, claimStore: baseStore,
                receiverBinding: receiver, trust: trust, audience: audience, statusEvidence: status,
                statusJournal: journalStore, rate: rate)
            XCTAssertEqual(TestHooks.callbackPanicRemaining(), 0, name + ": callback panic hook was not reached")
            XCTAssertEqual(outcome.stage, .committed, name + ": " + (outcome.errorDetail ?? ""))
            XCTAssertEqual(outcome.committed?.receiptBody,
                Data(base64Encoded: vector.obj("expected").s("receipt_body_b64"))!, name)
            let claims = await store.claims
            let finalizations = await store.finalizations
            let allowHorizons = await store.allowHorizons
            let progressWrites = await store.progressWrites
            let progressRecords = await store.progressRecords
            let expectedEvidence = (vector.obj("expected")["status_evidence"] as? [[String: Any]] ?? []).map {
                StatusEvidenceEntry(issuerId: $0.s("issuer_id"), statusKeyId: $0.s("status_key_id"),
                    sequence: Int64($0.int("sequence")), objectType: UInt16($0.int("object_type_code")),
                    digest: $0.s("digest"))
            }
            XCTAssertEqual(progressRecords.last?.statusEvidence ?? [], expectedEvidence, name)
            let trustCalls = await trust.calls
            let statusRequests = await status.requests
            let audienceCalls = await audience.calls
            let expectedCallbacks = vector.obj("expected").obj("callback_counts")
            XCTAssertEqual(receiver?.calls ?? 0, expectedCallbacks.int("receiver_binding"), name)
            XCTAssertEqual(claims, 1, name)
            XCTAssertEqual(finalizations, 1, name)
            XCTAssertEqual(allowHorizons, [(vector.obj("expected")["allow_valid_until"] as? NSNumber)?.int64Value ?? 0], name)
            XCTAssertEqual(progressWrites, expectedCallbacks.int("progress"), name)
            XCTAssertEqual(trustCalls, expectedCallbacks.int("trust"), name)
            XCTAssertEqual(statusRequests.count, expectedCallbacks.int("status"), name)
            XCTAssertEqual(audienceCalls, expectedCallbacks.int("audience"), name)
            let rateBatches = await rate?.batches ?? []
            XCTAssertEqual(rateBatches.count, expectedCallbacks.int("rate"), name)
            if let first = rateBatches.first {
                let expectedBatch = vector.obj("expected").arr("rate_batch").map {
                    RateReservation(issuerId: $0.s("issuer_id"), certId: $0.s("cert_id"),
                        windowSeconds: Int64($0.int("window_s")), limit: Int64($0.int("limit")))
                }
                XCTAssertEqual(first, expectedBatch, name)
            }
            var evaluatorCalls = 0
            for evaluator in evaluators { evaluatorCalls += await evaluator.calls }
            XCTAssertEqual(evaluatorCalls, (expectedCallbacks["evaluator"] as? NSNumber)?.intValue ?? 0, name)
            let expectedRequests = vector.obj("expected").arr("status_requests")
            XCTAssertEqual(statusRequests.count, expectedRequests.count, name)
            for (actual, expected) in zip(statusRequests, expectedRequests) {
                XCTAssertEqual(actual.issuerId, expected.s("issuer_id"), name)
                XCTAssertEqual(actual.statusKeyEpoch, UInt64(expected.int("status_key_epoch")), name)
                XCTAssertEqual(actual.statusKeyId, expected.s("status_key_id"), name)
                let refs = expected.arr("refs")
                XCTAssertEqual(actual.refs.count, refs.count, name)
                for (actualRef, expectedRef) in zip(actual.refs, refs) {
                    XCTAssertEqual(actualRef.issuerId, expectedRef.s("issuer_id"), name)
                    XCTAssertEqual(actualRef.certId, expectedRef.s("cert_id"), name)
                }
            }
        }
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

    private func stagedPreflightRequest(_ name: String) throws -> PreflightRequest {
        let req = try request(name)
        return PreflightRequest(bundle: req.bundle, expected: req.expected, contextPolicy: req.contextPolicy,
            requiredScope: req.requiredScope, verifierNamespace: req.verifierNamespace,
            replayEpoch: req.replayEpoch, verifierId: req.verifierId, now: req.now,
            maxChallengeAgeSeconds: req.maxChallengeAgeSeconds, futureSkewSeconds: req.futureSkewSeconds)
    }

    func testStagedClaimLocalAssessmentStaysPendingWithoutAuthenticatedStatus() async throws {
        let req = try request("allow_bound_context")
        let preflight = try Ratify.preflightProofBundle(stagedPreflightRequest("allow_bound_context"))
        let store = CreatedClaimStore(claimedAt: req.now)
        let staged = try await Ratify.claimProofBundle(bundle: req.bundle, preflight: preflight,
            namespace: req.verifierNamespace, replayEpoch: req.replayEpoch, now: req.now, store: store)
        XCTAssertEqual(staged.disposition, .created)
        let token = try XCTUnwrap(staged.evaluationToken)
        let root = Fixture.shared.privateKey("root")
        let options = LocalAuthorizationOptions(futureSkewSeconds: req.futureSkewSeconds,
            requiredScope: req.requiredScope, trustedRootId: root.keyId,
            trustedRootKey: root.publicKey, trustConfigured: true, context: req.context,
            tzdbVersion: req.tzdbVersion, contextPolicy: req.contextPolicy,
            expectedChallenge: req.expected, claimToken: token)
        let assessment = try await Ratify.evaluateLocalAuthorization(bundle: req.bundle, options: options)
        XCTAssertEqual(assessment.status, "pending_external_checks")
        XCTAssertFalse(assessment.statusChecks.isEmpty)
        let second = try await Ratify.evaluateLocalAuthorization(bundle: req.bundle, options: options)
        XCTAssertEqual(second.status, "evaluation_in_progress")
        XCTAssertEqual(second.reason, "claim_in_progress")
        XCTAssertEqual(classOf { _ = try Ratify.resolveClaimAfterAudience(token: token, memberships: []) },
            "configuration_invalid")
        let replay = try await Ratify.claimProofBundle(bundle: req.bundle, preflight: preflight,
            namespace: req.verifierNamespace, replayEpoch: req.replayEpoch, now: req.now,
            store: CreatedClaimStore(claimedAt: req.now, disposition: .inProgress))
        XCTAssertEqual(replay.disposition, .inProgress)
        XCTAssertNil(replay.evaluationToken)
    }

    actor StagedReentryBox {
        var token: EvaluationToken?
        var store: CreatedClaimStore?
        func set(_ token: EvaluationToken, store: CreatedClaimStore) {
            self.token = token; self.store = store
        }
    }

    func testStagedFinalizeRefusesSameTokenReentry() async throws {
        let req = try request("trust_unavailable")
        let payloadStore = CreatedClaimStore(claimedAt: req.now)
        let composed = try await Ratify.verifyProofBundle(req, claimStore: payloadStore,
            trust: UnavailableTrust())
        XCTAssertEqual(composed.stage, .committed)
        let savedTerminal = await payloadStore.lastTerminalResult
        let savedBody = await payloadStore.lastReceiptBody
        let terminal = try XCTUnwrap(savedTerminal)
        let body = try XCTUnwrap(savedBody)
        let box = StagedReentryBox()
        let store = CreatedClaimStore(onFinalize: {
            guard let nestedToken = await box.token, let nestedStore = await box.store else {
                XCTFail("missing staged token"); return
            }
            do {
                _ = try await Ratify.finalizeClaimProofBundle(token: nestedToken, store: nestedStore,
                    terminalResult: terminal, receiptBody: body)
                XCTFail("same-token reentry succeeded")
            } catch {
                XCTAssertEqual((error as? RatifyError)?.errorClass, .configurationInvalid)
            }
        }, claimedAt: req.now)
        let preflight = try Ratify.preflightProofBundle(stagedPreflightRequest("trust_unavailable"))
        let staged = try await Ratify.claimProofBundle(bundle: req.bundle, preflight: preflight,
            namespace: req.verifierNamespace, replayEpoch: req.replayEpoch, now: req.now, store: store)
        let token = try XCTUnwrap(staged.evaluationToken)
        let options = LocalAuthorizationOptions(futureSkewSeconds: req.futureSkewSeconds,
            requiredScope: req.requiredScope, trustedRootId: "",
            trustedRootKey: HybridPublicKey(ed25519: Data(), mlDsa65: Data()),
            trustConfigured: false, context: req.context, tzdbVersion: req.tzdbVersion,
            contextPolicy: req.contextPolicy, expectedChallenge: req.expected, claimToken: token)
        let assessment = try await Ratify.evaluateLocalAuthorization(bundle: req.bundle, options: options)
        XCTAssertEqual(assessment.reason, "trust_unavailable")
        await box.set(token, store: store)
        let finalized = try await Ratify.finalizeClaimProofBundle(token: token, store: store,
            terminalResult: terminal, receiptBody: body)
        XCTAssertTrue(finalized)
        let finalizations = await store.finalizations
        XCTAssertEqual(finalizations, 1)
    }

    func testSealedPreflightVectors() throws {
        _ = try Ratify.preflightProofBundle(stagedPreflightRequest("allow_bound_context"))
        let vectors = Corpus.load("verifier-ordering.json").arr("vectors").filter {
            $0.obj("expected").s("stage") == "preflight"
        }
        XCTAssertEqual(vectors.count, 149)
        // The composed verifier also checks request context, status config, hooks and claim storage.
        let stagedSuccess: Set<String> = [
            "config_status_lifetime_above_bound", "request_amount_negative", "request_amount_above_safe_integer",
            "request_currency_lowercase", "request_currency_two_letters", "request_amount_without_has_amount",
            "overflow_status_age_max_safe_integer", "overflow_status_lifetime_max_safe_integer",
            "receiver_binding_hook_rejects", "claim_proof_conflict", "claim_store_unavailable",
            "extension_context_negative_count", "extension_context_bad_name", "extension_context_value_too_long",
            "pre_claim_store_absent", "status_skew_verifier0_status300", "status_skew_verifier300_status0",
            "pre_hook_reject_with_in_progress", "pre_hook_reject_and_claim_absent",
            "config_status_skew_one_above_future_skew",
        ]
        let stagedMissingExpected: Set<String> = [
            "pre_config_invalid_and_expected_missing", "pre_reqctx_invalid_and_expected_missing",
            "config_verifier_id_absent_before_expected_challenge", "config_namespace_empty_before_expected_challenge",
        ]
        XCTAssertTrue(stagedSuccess.union(stagedMissingExpected).union([
            "pre_claim_store_absent_before_bad_signature"]).isSubset(of: Set(vectors.map { $0.s("name") })))
        for vector in vectors {
            let name = vector.s("name")
            let actual = classOf { _ = try Ratify.preflightProofBundle(stagedPreflightRequest(name)) }
            let expected = stagedSuccess.contains(name) ? "ok" :
                stagedMissingExpected.contains(name) ? "expected_challenge_unavailable" :
                name == "pre_claim_store_absent_before_bad_signature" ? "invalid_signature" :
                vector.obj("expected").s("error_class")
            if stagedSuccess.contains(name) || stagedMissingExpected.contains(name) ||
                name == "pre_claim_store_absent_before_bad_signature" {
                XCTAssertNotEqual(expected, vector.obj("expected").s("error_class"), name)
            }
            XCTAssertEqual(actual, expected, name)
        }
    }

    func testEvaluatorDeadlineWaitsForBlockedCallback() async throws {
        let vector = Corpus.load("verifier-ordering.json").arr("vectors").first {
            $0.s("name") == "extension_evaluator_timeout"
        }!
        let registration = vector.arr("constraint_evaluators")[0]
        let started = expectation(description: "evaluator entered")
        let deadlineSeen = expectation(description: "evaluator observed deadline cancellation")
        let gate = FinalizationGate()
        let evaluator = GatedEvaluator(started: started, gate: gate, deadlineSeen: deadlineSeen)
        let registry = try ConstraintEvaluatorRegistry(timeoutMilliseconds: 10,
            registrations: [ConstraintEvaluatorRegistration(descriptor: ConstraintProfileDescriptor(
                profile: registration.s("profile"), type: registration.s("type")), evaluator: evaluator)])
        let req = try request(vector.s("name"), evaluators: registry)
        let (trust, status, journal) = try await vectorProviders(vector, request: req)
        let completed = CompletionFlag()
        let call = Task {
            let result = try await Ratify.verifyProofBundle(req, claimStore: CreatedClaimStore(), trust: trust,
                audience: EmptyAudience(), statusEvidence: status, statusJournal: journal)
            let gateOpen = await gate.isOpen
            await completed.markDone(gateOpen: gateOpen)
            return result
        }
        await fulfillment(of: [started, deadlineSeen], timeout: 10)
        try await Task.sleep(for: .milliseconds(50))
        let doneBeforeRelease = await completed.done
        XCTAssertFalse(doneBeforeRelease, "calling-thread evaluator must still own the call")
        await gate.open()
        let outcome = try await call.value
        let gateOpenAtReturn = await completed.gateOpenAtReturn
        XCTAssertTrue(gateOpenAtReturn, "verification returned before its evaluator")
        let cancelledOnReturn = await evaluator.cancelledOnReturn
        XCTAssertTrue(cancelledOnReturn, "deadline did not cancel the evaluator task")
        XCTAssertEqual(outcome.stage, .committed)
        let body = try JSONSerialization.jsonObject(with: outcome.committed!.receiptBody) as! [String: Any]
        XCTAssertEqual(body["decision_reason"] as? String, "constraint_unverifiable")

        let fastGate = FinalizationGate()
        await fastGate.open()
        let fastStarted = expectation(description: "fast evaluator entered")
        let fastEvaluator = GatedEvaluator(started: fastStarted, gate: fastGate)
        let fastRegistry = try ConstraintEvaluatorRegistry(timeoutMilliseconds: 1000,
            registrations: [ConstraintEvaluatorRegistration(descriptor: ConstraintProfileDescriptor(
                profile: registration.s("profile"), type: registration.s("type")), evaluator: fastEvaluator)])
        let fastRequest = try request(vector.s("name"), evaluators: fastRegistry)
        let (fastTrust, fastStatus, fastJournal) = try await vectorProviders(vector, request: fastRequest)
        let fastOutcome = try await Ratify.verifyProofBundle(fastRequest, claimStore: CreatedClaimStore(),
            trust: fastTrust, audience: EmptyAudience(), statusEvidence: fastStatus, statusJournal: fastJournal)
        await fulfillment(of: [fastStarted], timeout: 10)
        XCTAssertEqual(fastOutcome.stage, .committed)
        let fastBody = try JSONSerialization.jsonObject(with: fastOutcome.committed!.receiptBody) as! [String: Any]
        XCTAssertEqual(fastBody["decision_reason"] as? String, "authorized")
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
        var isOpen: Bool { openNow }
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

    struct VectorCommittedStore: CommittedClaimStore {
        let record: CommittedClaim
        func loadCommitted(claimId: String) async throws -> CommittedClaim { record }
    }

    private func committedClaimFromRecord(_ step: [String: Any]) throws -> CommittedClaim {
        let bytes = step.b64("claim_record_b64")
        let record = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
        XCTAssertEqual(Set(record.keys), ["agent_id", "bundle_hash", "challenge_digest", "claim_id",
            "clock_skew_seconds", "constraint_evaluators", "context_policy_digest", "expires_at",
            "issued_at", "issuer_ids", "max_age_seconds", "namespace", "proof_digest", "rate_batch",
            "replay_epoch", "required_scope", "requires_rate", "stream_id", "stream_seq", "verifier_id"])
        let contextPolicyDigest = record["context_policy_digest"] is NSNull
            ? "" : try XCTUnwrap(record["context_policy_digest"] as? String)
        let streamId: Data?
        if record["stream_id"] is NSNull { streamId = nil }
        else { streamId = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(record["stream_id"] as? String))) }
        let streamSeq: Int64?
        if record["stream_seq"] is NSNull { streamSeq = nil }
        else { streamSeq = try XCTUnwrap(record["stream_seq"] as? NSNumber).int64Value }
        let rateBatch = record.arr("rate_batch").map {
            RateReservation(issuerId: $0.s("issuer_id"), certId: $0.s("cert_id"),
                windowSeconds: Int64($0.int("window_s")), limit: Int64($0.int("limit")))
        }
        let evaluators = record.arr("constraint_evaluators").map {
            ConstraintEvaluatorRef(kind: $0.s("type"), profileDigest: $0.s("profile_digest"))
        }
        let claim = ChallengeClaim(claimId: record.s("claim_id"), namespace: record.s("namespace"),
            replayEpoch: Int64(record.int("replay_epoch")), challengeDigest: record.s("challenge_digest"),
            proofDigest: record.s("proof_digest"), bundleHash: record.s("bundle_hash"),
            issuerIds: record.strings("issuer_ids"), requiredScope: record.s("required_scope"),
            contextPolicyDigest: contextPolicyDigest,
            verifierId: record.s("verifier_id"), agentId: record.s("agent_id"),
            requiresRate: record.bool("requires_rate"), rateBatch: rateBatch,
            issuedAt: Int64(record.int("issued_at")), expiresAt: Int64(record.int("expires_at")),
            maxAgeSeconds: Int64(record.int("max_age_seconds")),
            clockSkewSeconds: Int64(record.int("clock_skew_seconds")),
            streamId: streamId, streamSeq: streamSeq,
            constraintEvaluators: evaluators)
        return CommittedClaim(claim: claim, claimRecord: bytes, terminalResult: step.b64("terminal_b64"),
            receiptBody: step.b64("body_b64"), allowHorizon: step["allow_valid_until"] == nil
                ? 0 : Int64(step.int("allow_valid_until")))
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

    func testReferenceStoreCommittedReceiptCheckpointAndRelease() async throws {
        let req = try request("trust_unavailable")
        let key = Fixture.shared.privateKey("verifier")
        let logId = "0123456789abcdef0123456789abcdef"
        let store = try Store(now: req.now, leaseSeconds: 30, logId: logId, verifierKey: key)
        try store.setAcknowledgementWithheld(true)
        let outcome = try await Ratify.verifyProofBundle(req, claimStore: store, trust: UnavailableTrust())
        XCTAssertEqual(outcome.stage, .committed, outcome.errorDetail ?? "")
        let committed = try XCTUnwrap(outcome.committed)
        let saved = try await store.loadCommitted(claimId: committed.claimId)
        XCTAssertEqual(saved.claim.claimId, committed.claimId)
        let terminalResult = try JSONSerialization.jsonObject(with: saved.terminalResult) as! [String: Any]
        XCTAssertEqual(terminalResult["decision_reason"] as? String, "trust_unavailable")
        XCTAssertEqual(saved.receiptBody, committed.receiptBody)
        XCTAssertEqual(saved.allowHorizon, committed.allowHorizon ?? 0)
        let wire = try await store.publish(claimId: committed.claimId, receiptBody: saved.receiptBody)
        let receipt = try Ratify.decodeVerificationReceipt(wire)
        let digest = try Ratify.verificationReceiptDigest(receipt)
        let acknowledgement = try await store.acknowledge(logId: logId, sequence: 1,
            previousEntryHash: Data(repeating: 0, count: 48), entryHash: digest)
        XCTAssertEqual(acknowledgement.logId, logId)
        XCTAssertEqual(acknowledgement.sequence, 1)
        XCTAssertEqual(acknowledgement.entryHash, digest)
        XCTAssertEqual(acknowledgement.timestamp, req.now)
        let storedAcknowledgement = try await store.get(logId: logId, sequence: 1)
        XCTAssertEqual(storedAcknowledgement.entryHash, digest)
        let released = try await Ratify.releaseDecision(committed, signedReceipt: wire,
            verifierPublicKey: key.publicKey, logId: logId, claimStore: store, checkpoint: store)
        XCTAssertEqual(released.status, .released)
        let terminal = try await store.loadTerminal(claimId: committed.claimId)
        XCTAssertEqual(terminal.release?.outcome, .released)
    }

    struct WrongEntryCheckpoint: ReceiptCheckpoint, @unchecked Sendable {
        let store: Store
        func acknowledge(logId: String, sequence: Int64, previousEntryHash: Data,
                         entryHash: Data) async throws -> CheckpointAcknowledgement {
            try await store.acknowledge(logId: logId, sequence: sequence,
                previousEntryHash: previousEntryHash, entryHash: entryHash)
        }
        func get(logId: String, sequence: Int64) async throws -> CheckpointAcknowledgement {
            let ack = try await store.get(logId: logId, sequence: sequence)
            var hash = ack.entryHash
            hash[hash.startIndex] ^= 1
            return CheckpointAcknowledgement(logId: ack.logId, sequence: ack.sequence,
                entryHash: hash, timestamp: ack.timestamp)
        }
    }

    final class FailingReleaseStore: ReleaseClaimStore, @unchecked Sendable {
        let store: Store
        let stateMismatch: Bool
        private let lock = NSLock()
        private var attempts = 0
        init(store: Store, stateMismatch: Bool) { self.store = store; self.stateMismatch = stateMismatch }
        var recordAttempts: Int { lock.withLock { attempts } }
        func authoritativeTime() async throws -> Int64 { try await store.authoritativeTime() }
        func loadTerminal(claimId: String) async throws -> TerminalClaimRecord {
            try await store.loadTerminal(claimId: claimId)
        }
        func recordRelease(_ record: ReleaseRecord) async throws {
            lock.withLock { attempts += 1 }
            if stateMismatch { throw StoreError.releaseStateMismatch }
            throw StoreError.unavailable("claim store unavailable")
        }
    }

    func testConcurrentClaimStormHasOneCommit() async throws {
        let corpus = Corpus.load("concurrency-scenarios.json")
        let scenario = try XCTUnwrap(corpus.arr("scenarios").first { $0.s("name") == "same_challenge_claim_storm" })
        let participant = try XCTUnwrap(scenario.arr("participants").first)
        XCTAssertEqual(participant.s("op"), "verify")
        XCTAssertEqual(participant.s("request"), "A")
        XCTAssertEqual(participant.int("count"), 8)
        let inputs = Corpus.load("lifecycle-scenarios.json")
        let key = Fixture.shared.privateKey(inputs.s("verifier_key"))
        for iteration in 0..<corpus.int("default_iterations") {
            let store = try Store(now: Int64(scenario.int("start_time")),
                leaseSeconds: Int64(inputs.int("lease_seconds")), logId: inputs.s("log_id"), verifierKey: key)
            let req = try request("A", corpusName: "lifecycle-scenarios.json")
            let (trust, status, journal) = try await vectorProviders(inputs.obj("requests").obj("A"), request: req)
            let outcomes = try await withThrowingTaskGroup(of: VerifyOutcome.self) { group in
                for _ in 0..<participant.int("count") {
                    group.addTask { try await Ratify.verifyProofBundle(req, claimStore: store,
                        trust: trust, statusEvidence: status, statusJournal: journal) }
                }
                var results: [VerifyOutcome] = []
                for try await outcome in group { results.append(outcome) }
                return results
            }
            XCTAssertEqual(outcomes.count, 8, "iteration \(iteration)")
            XCTAssertEqual(outcomes.filter { $0.stage == .committed }.count, 1, "iteration \(iteration)")
            XCTAssertTrue(outcomes.allSatisfy { outcome in
                outcome.stage == .committed && outcome.committed != nil && outcome.errorClass == nil ||
                outcome.stage == .replay && [.inProgress, .terminalReplay].contains(outcome.disposition)
            }, "iteration \(iteration)")
            let winner = try XCTUnwrap(outcomes.first { $0.stage == .committed }?.committed)
            let body = try JSONSerialization.jsonObject(with: winner.receiptBody) as! [String: Any]
            XCTAssertEqual(body["decision"] as? String, "allow", "iteration \(iteration)")
            XCTAssertEqual(body["decision_reason"] as? String, "authorized", "iteration \(iteration)")
            let replay = try await Ratify.verifyProofBundle(req, claimStore: store,
                trust: trust, statusEvidence: status, statusJournal: journal)
            XCTAssertEqual(replay.stage, .replay, "iteration \(iteration)")
            XCTAssertEqual(replay.disposition, .terminalReplay, "iteration \(iteration)")
            let wire = try await store.publish(claimId: winner.claimId, receiptBody: winner.receiptBody)
            XCTAssertEqual(try Ratify.decodeVerificationReceipt(wire).sequence, 1, "iteration \(iteration)")
            let republished = try await store.publish(claimId: winner.claimId, receiptBody: winner.receiptBody)
            XCTAssertEqual(republished, wire, "iteration \(iteration)")
            let released = try await Ratify.releaseDecision(winner, signedReceipt: wire,
                verifierPublicKey: key.publicKey, logId: inputs.s("log_id"), claimStore: store, checkpoint: store)
            XCTAssertEqual(released.status, .released, "iteration \(iteration)")
            XCTAssertEqual(released.decision?.decision, "allow", "iteration \(iteration)")
            XCTAssertEqual(released.decision?.releaseTime, Int64(scenario.int("start_time")), "iteration \(iteration)")
        }
    }

    func testConcurrentClaimsRecoverOnceAfterLease() async throws {
        let corpus = Corpus.load("concurrency-scenarios.json")
        let scenario = try XCTUnwrap(corpus.arr("scenarios").first {
            $0.s("name") == "same_challenge_claim_storm_store_level"
        })
        let participant = try XCTUnwrap(scenario.arr("participants").first)
        XCTAssertEqual(participant.s("op"), "claim_only")
        XCTAssertEqual(participant.int("count"), 8)
        let inputs = Corpus.load("lifecycle-scenarios.json")
        let req = try request("A", corpusName: "lifecycle-scenarios.json")
        let expected = try XCTUnwrap(req.expected)
        let bundle = try Ratify.decodeProofBundle(req.bundle)
        let hash = try Ratify.bundleHash(bundle)
        let claim = ChallengeClaim(claimId: try Ratify.protocolClaimId(namespace: expected.verifierNamespace,
            replayEpoch: expected.replayEpoch, challenge: expected.value), namespace: expected.verifierNamespace,
            replayEpoch: expected.replayEpoch, challengeDigest: "sha384:" +
                (try Ratify.challengeClaimDigest(expected.value)).hex,
            proofDigest: hash, bundleHash: hash, issuerIds: Array(Set(bundle.delegations.map(\.issuerId))).sorted(),
            requiredScope: req.requiredScope, contextPolicyDigest: req.contextPolicy?.digest ?? "",
            verifierId: expected.verifierId, agentId: bundle.agentId, requiresRate: false, rateBatch: [],
            issuedAt: expected.issuedAt, expiresAt: expected.expiresAt,
            maxAgeSeconds: req.maxChallengeAgeSeconds, clockSkewSeconds: req.futureSkewSeconds,
            streamId: bundle.streamId, streamSeq: bundle.streamSeq, constraintEvaluators: [])
        let key = Fixture.shared.privateKey(inputs.s("verifier_key"))
        for iteration in 0..<corpus.int("default_iterations") {
            let store = try Store(now: Int64(scenario.int("start_time")),
                leaseSeconds: Int64(inputs.int("lease_seconds")), logId: inputs.s("log_id"), verifierKey: key)
            let results = try await withThrowingTaskGroup(of: ClaimResult.self) { group in
                for _ in 0..<participant.int("count") { group.addTask { try await store.claim(claim) } }
                var values: [ClaimResult] = []
                for try await result in group { values.append(result) }
                return values
            }
            XCTAssertEqual(results.filter { $0.disposition == .created }.count, 1, "iteration \(iteration)")
            XCTAssertTrue(results.allSatisfy { [.created, .inProgress].contains($0.disposition) },
                "iteration \(iteration)")
            let (trust, status, journal) = try await vectorProviders(inputs.obj("requests").obj("A"), request: req)
            let replay = try await Ratify.verifyProofBundle(req, claimStore: store,
                trust: trust, statusEvidence: status, statusJournal: journal)
            XCTAssertEqual(replay.stage, .replay, "iteration \(iteration)")
            XCTAssertEqual(replay.disposition, .inProgress, "iteration \(iteration)")
            try store.setTime(Int64(scenario.arr("after")[1].int("time")))
            let recovered = try await Ratify.recoverInterruptedClaim(store: store, claimId: claim.claimId)
            let body = try JSONSerialization.jsonObject(with: recovered.receiptBody) as! [String: Any]
            XCTAssertEqual(body["decision"] as? String, "indeterminate", "iteration \(iteration)")
            XCTAssertEqual(body["decision_reason"] as? String, "evaluation_interrupted", "iteration \(iteration)")
            let wire = try await store.publish(claimId: recovered.claimId, receiptBody: recovered.receiptBody)
            XCTAssertEqual(try Ratify.decodeVerificationReceipt(wire).sequence, 1, "iteration \(iteration)")
        }
    }

    func testConcurrentReleaseIsIdentical() async throws {
        let corpus = Corpus.load("concurrency-scenarios.json")
        let scenario = try XCTUnwrap(corpus.arr("scenarios").first {
            $0.s("name") == "concurrent_release_of_one_decision"
        })
        let participant = try XCTUnwrap(scenario.arr("participants").first)
        XCTAssertEqual(participant.s("op"), "release")
        XCTAssertEqual(participant.int("count"), 8)
        let inputs = Corpus.load("lifecycle-scenarios.json")
        let key = Fixture.shared.privateKey(inputs.s("verifier_key"))
        let logId = inputs.s("log_id")
        let req = try request("A", corpusName: "lifecycle-scenarios.json")
        let (trust, status, journal) = try await vectorProviders(inputs.obj("requests").obj("A"), request: req)
        for iteration in 0..<corpus.int("default_iterations") {
            let store = try Store(now: Int64(scenario.int("start_time")),
                leaseSeconds: Int64(inputs.int("lease_seconds")), logId: logId, verifierKey: key)
            let verified = try await Ratify.verifyProofBundle(req, claimStore: store,
                trust: trust, statusEvidence: status, statusJournal: journal)
            let committed = try XCTUnwrap(verified.committed, "iteration \(iteration)")
            let wire = try await store.publish(claimId: committed.claimId, receiptBody: committed.receiptBody)
            let releases = try await withThrowingTaskGroup(of: ReleaseResult.self) { group in
                for _ in 0..<participant.int("count") {
                    group.addTask { try await Ratify.releaseDecision(committed, signedReceipt: wire,
                        verifierPublicKey: key.publicKey, logId: logId, claimStore: store, checkpoint: store) }
                }
                var values: [ReleaseResult] = []
                for try await result in group { values.append(result) }
                return values
            }
            XCTAssertEqual(releases.count, 8, "iteration \(iteration)")
            for result in releases {
                XCTAssertEqual(result.status, .released, "iteration \(iteration)")
                XCTAssertEqual(result.decision?.decision, "allow", "iteration \(iteration)")
                XCTAssertEqual(result.decision?.releaseTime, Int64(scenario.int("start_time")), "iteration \(iteration)")
                XCTAssertEqual(result.decision?.receiptWire, wire, "iteration \(iteration)")
            }
            let republished = try await store.publish(claimId: committed.claimId, receiptBody: committed.receiptBody)
            XCTAssertEqual(republished, wire, "iteration \(iteration)")
        }
    }

    func testConcurrentStreamAdvanceAdmitsOneSequenceTwo() async throws {
        let corpus = Corpus.load("concurrency-scenarios.json")
        let scenario = try XCTUnwrap(corpus.arr("scenarios").first { $0.s("name") == "concurrent_stream_advances" })
        let participants = scenario.arr("participants")
        XCTAssertEqual(participants.map { $0.s("request") }, ["S2", "S2b"])
        let inputs = Corpus.load("lifecycle-scenarios.json")
        let key = Fixture.shared.privateKey(inputs.s("verifier_key"))
        let logId = inputs.s("log_id")
        for iteration in 0..<corpus.int("default_iterations") {
            let store = try Store(now: Int64(scenario.int("start_time")),
                leaseSeconds: Int64(inputs.int("lease_seconds")), logId: logId, verifierKey: key)
            func verify(_ name: String) async throws -> VerifyOutcome {
                let req = try request(name, corpusName: "lifecycle-scenarios.json")
                let (trust, status, journal) = try await vectorProviders(inputs.obj("requests").obj(name), request: req)
                return try await Ratify.verifyProofBundle(req, claimStore: store,
                    trust: trust, statusEvidence: status, statusJournal: journal)
            }
            let first = try await verify(scenario.arr("setup")[0].s("request"))
            XCTAssertEqual(first.stage, .committed, "iteration \(iteration)")
            let results = try await withThrowingTaskGroup(of: (String, VerifyOutcome).self) { group in
                for participant in participants {
                    let name = participant.s("request")
                    let req = try request(name, corpusName: "lifecycle-scenarios.json")
                    let (trust, status, journal) = try await vectorProviders(inputs.obj("requests").obj(name), request: req)
                    for _ in 0..<participant.int("count") {
                        group.addTask { (name, try await Ratify.verifyProofBundle(req, claimStore: store,
                            trust: trust, statusEvidence: status, statusJournal: journal)) }
                    }
                }
                var values: [(String, VerifyOutcome)] = []
                for try await value in group { values.append(value) }
                return values
            }
            XCTAssertEqual(results.count, 6, "iteration \(iteration)")
            let winners = results.filter { $0.1.stage == .committed }
            XCTAssertEqual(winners.count, 1, "iteration \(iteration)")
            let winner = try XCTUnwrap(winners.first?.0)
            for (name, outcome) in results {
                if name == winner {
                    XCTAssertTrue(outcome.stage == .committed || outcome.stage == .replay &&
                        [.terminalReplay, .inProgress].contains(outcome.disposition), "iteration \(iteration)")
                } else {
                    XCTAssertEqual(outcome.stage, .preflight, "iteration \(iteration)")
                    XCTAssertEqual(outcome.errorClass, .streamSequenceMismatch, "iteration \(iteration)")
                }
            }
            let skipped = try await verify(scenario.arr("after")[0].s("request"))
            XCTAssertEqual(skipped.stage, .preflight, "iteration \(iteration)")
            XCTAssertEqual(skipped.errorClass, .streamSequenceMismatch, "iteration \(iteration)")
            let next = try await verify(scenario.arr("after")[1].s("request"))
            XCTAssertEqual(next.stage, .committed, "iteration \(iteration)")
        }
    }

    func testConcurrentRateAdmissionHasTwoWinners() async throws {
        let corpus = Corpus.load("concurrency-scenarios.json")
        let scenario = try XCTUnwrap(corpus.arr("scenarios").first { $0.s("name") == "rate_admission_under_contention" })
        let participants = scenario.arr("participants")
        XCTAssertEqual(participants.map { $0.s("request") }, ["R1", "R2", "R3", "R4"])
        XCTAssertTrue(scenario["rate_at_finalization"] as? Bool == true)
        let inputs = Corpus.load("lifecycle-scenarios.json")
        let key = Fixture.shared.privateKey(inputs.s("verifier_key"))
        for iteration in 0..<corpus.int("default_iterations") {
            let store = try Store(now: Int64(scenario.int("start_time")),
                leaseSeconds: Int64(inputs.int("lease_seconds")), logId: inputs.s("log_id"), verifierKey: key)
            let rateStore = try store.withRateAtFinalization()
            let results = try await withThrowingTaskGroup(of: (String, VerifyOutcome).self) { group in
                for participant in participants {
                    let name = participant.s("request")
                    let req = try request(name, corpusName: "lifecycle-scenarios.json")
                    let (trust, status, journal) = try await vectorProviders(inputs.obj("requests").obj(name), request: req)
                    for _ in 0..<participant.int("count") {
                        group.addTask { (name, try await Ratify.verifyProofBundle(req, claimStore: rateStore,
                            trust: trust, statusEvidence: status, statusJournal: journal)) }
                    }
                }
                var values: [(String, VerifyOutcome)] = []
                for try await value in group { values.append(value) }
                return values
            }
            XCTAssertEqual(results.count, 8, "iteration \(iteration)")
            let committed = results.filter { $0.1.stage == .committed }
            XCTAssertEqual(committed.count, 4, "iteration \(iteration)")
            XCTAssertEqual(Set(committed.map(\.0)).count, 4, "iteration \(iteration)")
            var allows = 0
            var denies = 0
            for (_, outcome) in committed {
                let value = try XCTUnwrap(outcome.committed)
                let body = try JSONSerialization.jsonObject(with: value.receiptBody) as! [String: Any]
                switch (body["decision"] as? String, body["decision_reason"] as? String) {
                case ("allow", "authorized"): allows += 1
                case ("deny", "constraint_denied"): denies += 1
                default: XCTFail("unexpected rate decision at iteration \(iteration)")
                }
            }
            XCTAssertEqual(allows, 2, "iteration \(iteration)")
            XCTAssertEqual(denies, 2, "iteration \(iteration)")
            XCTAssertTrue(results.allSatisfy { $0.1.stage == .committed || $0.1.stage == .replay &&
                [.terminalReplay, .inProgress].contains($0.1.disposition) }, "iteration \(iteration)")
        }
    }

    func testConcurrentTwoCounterRateAdmissionIsAtomic() async throws {
        let corpus = Corpus.load("concurrency-scenarios.json")
        let scenario = try XCTUnwrap(corpus.arr("scenarios").first {
            $0.s("name") == "rate_two_counter_admission_under_contention"
        })
        let participants = scenario.arr("participants")
        XCTAssertEqual(participants.map { $0.s("request") }, ["T1", "T2"])
        XCTAssertTrue(scenario["rate_at_finalization"] as? Bool == true)
        let inputs = Corpus.load("lifecycle-scenarios.json")
        let key = Fixture.shared.privateKey(inputs.s("verifier_key"))
        for iteration in 0..<corpus.int("default_iterations") {
            let store = try Store(now: Int64(scenario.int("start_time")),
                leaseSeconds: Int64(inputs.int("lease_seconds")), logId: inputs.s("log_id"), verifierKey: key)
            let rateStore = try store.withRateAtFinalization()
            let results = try await withThrowingTaskGroup(of: (String, VerifyOutcome).self) { group in
                for participant in participants {
                    let name = participant.s("request")
                    let req = try request(name, corpusName: "lifecycle-scenarios.json")
                    let (trust, status, journal) = try await vectorProviders(inputs.obj("requests").obj(name), request: req)
                    for _ in 0..<participant.int("count") {
                        group.addTask { (name, try await Ratify.verifyProofBundle(req, claimStore: rateStore,
                            trust: trust, statusEvidence: status, statusJournal: journal)) }
                    }
                }
                var values: [(String, VerifyOutcome)] = []
                for try await value in group { values.append(value) }
                return values
            }
            XCTAssertEqual(results.count, 4, "iteration \(iteration)")
            let committed = results.filter { $0.1.stage == .committed }
            XCTAssertEqual(committed.count, 2, "iteration \(iteration)")
            XCTAssertEqual(Set(committed.map(\.0)), Set(["T1", "T2"]), "iteration \(iteration)")
            let decisions = try committed.map { (_, outcome) -> String in
                let body = try JSONSerialization.jsonObject(with: XCTUnwrap(outcome.committed).receiptBody) as! [String: Any]
                return "\(body["decision"] ?? "")/\(body["decision_reason"] ?? "")"
            }
            XCTAssertEqual(Set(decisions), Set(["allow/authorized", "deny/constraint_denied"]),
                "iteration \(iteration)")
            XCTAssertTrue(results.allSatisfy { $0.1.stage == .committed || $0.1.stage == .replay &&
                [.terminalReplay, .inProgress].contains($0.1.disposition) }, "iteration \(iteration)")
            let later = try XCTUnwrap(scenario.arr("after").first)
            try store.setTime(Int64(later.int("time")))
            let req = try request("T3", corpusName: "lifecycle-scenarios.json", atTime: Int64(later.int("time")))
            let (trust, status, journal) = try await vectorProviders(inputs.obj("requests").obj("T3"), request: req)
            let outcome = try await Ratify.verifyProofBundle(req, claimStore: rateStore,
                trust: trust, statusEvidence: status, statusJournal: journal)
            XCTAssertEqual(outcome.stage, .committed, "iteration \(iteration)")
            let body = try JSONSerialization.jsonObject(with: XCTUnwrap(outcome.committed).receiptBody) as! [String: Any]
            XCTAssertEqual(body["decision"] as? String, "allow", "iteration \(iteration)")
            XCTAssertEqual(body["decision_reason"] as? String, "authorized", "iteration \(iteration)")
        }
    }

    func testConcurrentConflictingProofsSealOneChallenge() async throws {
        let corpus = Corpus.load("concurrency-scenarios.json")
        let scenario = try XCTUnwrap(corpus.arr("scenarios").first {
            $0.s("name") == "conflicting_proofs_for_one_challenge"
        })
        let participants = scenario.arr("participants")
        XCTAssertEqual(participants.map { $0.s("request") }, ["R1", "R1x"])
        let inputs = Corpus.load("lifecycle-scenarios.json")
        let key = Fixture.shared.privateKey(inputs.s("verifier_key"))
        for iteration in 0..<corpus.int("default_iterations") {
            let store = try Store(now: Int64(scenario.int("start_time")),
                leaseSeconds: Int64(inputs.int("lease_seconds")), logId: inputs.s("log_id"), verifierKey: key)
            let rateStore = try store.withRateAtFinalization()
            let results = try await withThrowingTaskGroup(of: (String, VerifyOutcome).self) { group in
                for participant in participants {
                    let name = participant.s("request")
                    let req = try request(name, corpusName: "lifecycle-scenarios.json")
                    let (trust, status, journal) = try await vectorProviders(inputs.obj("requests").obj(name), request: req)
                    for _ in 0..<participant.int("count") {
                        group.addTask { (name, try await Ratify.verifyProofBundle(req, claimStore: rateStore,
                            trust: trust, statusEvidence: status, statusJournal: journal)) }
                    }
                }
                var values: [(String, VerifyOutcome)] = []
                for try await value in group { values.append(value) }
                return values
            }
            XCTAssertEqual(results.count, 8, "iteration \(iteration)")
            let winners = results.filter { $0.1.stage == .committed }
            XCTAssertEqual(winners.count, 1, "iteration \(iteration)")
            let winner = try XCTUnwrap(winners.first?.0)
            let body = try JSONSerialization.jsonObject(with: try XCTUnwrap(winners.first?.1.committed).receiptBody)
                as! [String: Any]
            XCTAssertEqual(body["decision"] as? String, "allow", "iteration \(iteration)")
            for (name, outcome) in results {
                if name == winner {
                    XCTAssertTrue(outcome.stage == .committed || outcome.stage == .replay &&
                        [.terminalReplay, .inProgress].contains(outcome.disposition), "iteration \(iteration)")
                } else {
                    XCTAssertEqual(outcome.stage, .preflight, "iteration \(iteration)")
                    XCTAssertEqual(outcome.errorClass, .claimReplay, "iteration \(iteration)")
                }
            }
            let nextName = scenario.arr("after")[0].s("request")
            let nextReq = try request(nextName, corpusName: "lifecycle-scenarios.json")
            let (trust, status, journal) = try await vectorProviders(inputs.obj("requests").obj(nextName), request: nextReq)
            let next = try await Ratify.verifyProofBundle(nextReq, claimStore: rateStore,
                trust: trust, statusEvidence: status, statusJournal: journal)
            XCTAssertEqual(next.stage, .committed, "iteration \(iteration)")
            let nextBody = try JSONSerialization.jsonObject(with: try XCTUnwrap(next.committed).receiptBody)
                as! [String: Any]
            XCTAssertEqual(nextBody["decision"] as? String, "allow", "iteration \(iteration)")
        }
    }

    func testConcurrentResumeAndReleaseOfOneAllow() async throws {
        let corpus = Corpus.load("concurrency-scenarios.json")
        let scenario = try XCTUnwrap(corpus.arr("scenarios").first {
            $0.s("name") == "concurrent_resumes_and_releases_of_one_allow"
        })
        let participants = scenario.arr("participants")
        XCTAssertEqual(participants.map { $0.s("op") }, ["resume", "release"])
        let inputs = Corpus.load("lifecycle-scenarios.json")
        let key = Fixture.shared.privateKey(inputs.s("verifier_key"))
        let logId = inputs.s("log_id")
        let req = try request("A", corpusName: "lifecycle-scenarios.json")
        let (trust, status, journal) = try await vectorProviders(inputs.obj("requests").obj("A"), request: req)
        for iteration in 0..<corpus.int("default_iterations") {
            let store = try Store(now: Int64(scenario.int("start_time")),
                leaseSeconds: Int64(inputs.int("lease_seconds")), logId: logId, verifierKey: key)
            let verified = try await Ratify.verifyProofBundle(req, claimStore: store,
                trust: trust, statusEvidence: status, statusJournal: journal)
            let committed = try XCTUnwrap(verified.committed, "iteration \(iteration)")
            let wire = try await store.publish(claimId: committed.claimId, receiptBody: committed.receiptBody)
            let results = try await withThrowingTaskGroup(of: (ReleaseResult, Data?).self) { group in
                for participant in participants {
                    for _ in 0..<participant.int("count") {
                        if participant.s("op") == "resume" {
                            group.addTask {
                                let resumed = try await Ratify.resumeCommittedClaim(store: store, claimId: committed.claimId)
                                return (try await Ratify.releaseDecision(resumed, signedReceipt: wire,
                                    verifierPublicKey: key.publicKey, logId: logId,
                                    claimStore: store, checkpoint: store), resumed.receiptBody)
                            }
                        } else {
                            group.addTask {
                                (try await Ratify.releaseDecision(committed, signedReceipt: wire,
                                    verifierPublicKey: key.publicKey, logId: logId,
                                    claimStore: store, checkpoint: store), nil)
                            }
                        }
                    }
                }
                var values: [(ReleaseResult, Data?)] = []
                for try await value in group { values.append(value) }
                return values
            }
            XCTAssertEqual(results.count, 10, "iteration \(iteration)")
            XCTAssertEqual(results.compactMap(\.1).count, participants[0].int("count"), "iteration \(iteration)")
            for (result, resumedBody) in results {
                XCTAssertEqual(resumedBody ?? committed.receiptBody, committed.receiptBody, "iteration \(iteration)")
                XCTAssertEqual(result.status, .released, "iteration \(iteration)")
                XCTAssertEqual(result.decision?.decision, "allow", "iteration \(iteration)")
                XCTAssertEqual(result.decision?.releaseTime, Int64(scenario.int("start_time")), "iteration \(iteration)")
                XCTAssertEqual(result.decision?.receiptWire, wire, "iteration \(iteration)")
            }
            let resumed = try await Ratify.resumeCommittedClaim(store: store, claimId: committed.claimId)
            XCTAssertEqual(resumed.receiptBody, committed.receiptBody, "iteration \(iteration)")
            let after = try await Ratify.releaseDecision(committed, signedReceipt: wire,
                verifierPublicKey: key.publicKey, logId: logId, claimStore: store, checkpoint: store)
            XCTAssertEqual(after.status, .released, "iteration \(iteration)")
            XCTAssertEqual(after.decision?.receiptWire, wire, "iteration \(iteration)")
        }
    }

    func testConcurrentReleaseWhileAcknowledgementLands() async throws {
        let corpus = Corpus.load("concurrency-scenarios.json")
        let scenario = try XCTUnwrap(corpus.arr("scenarios").first {
            $0.s("name") == "release_while_acknowledgement_lands"
        })
        let participants = scenario.arr("participants")
        XCTAssertEqual(participants.map { $0.s("op") }, ["release", "acknowledge"])
        let inputs = Corpus.load("lifecycle-scenarios.json")
        let key = Fixture.shared.privateKey(inputs.s("verifier_key"))
        let logId = inputs.s("log_id")
        let req = try request("A", corpusName: "lifecycle-scenarios.json")
        let (trust, status, journal) = try await vectorProviders(inputs.obj("requests").obj("A"), request: req)
        for iteration in 0..<corpus.int("default_iterations") {
            let store = try Store(now: Int64(scenario.int("start_time")),
                leaseSeconds: Int64(inputs.int("lease_seconds")), logId: logId, verifierKey: key)
            try store.setAcknowledgementWithheld(true)
            let verified = try await Ratify.verifyProofBundle(req, claimStore: store,
                trust: trust, statusEvidence: status, statusJournal: journal)
            let committed = try XCTUnwrap(verified.committed, "iteration \(iteration)")
            let wire = try await store.publish(claimId: committed.claimId, receiptBody: committed.receiptBody)
            let receipt = try Ratify.decodeVerificationReceipt(wire)
            let digest = try Ratify.verificationReceiptDigest(receipt)
            let results = try await withThrowingTaskGroup(of: String.self) { group in
                for participant in participants {
                    for _ in 0..<participant.int("count") {
                        if participant.s("op") == "acknowledge" {
                            group.addTask {
                                let ack = try await store.acknowledge(logId: logId, sequence: receipt.sequence,
                                    previousEntryHash: receipt.previousReceiptHash, entryHash: digest)
                                return "acknowledged/\(ack.timestamp)"
                            }
                        } else {
                            group.addTask {
                                let result = try await Ratify.releaseDecision(committed, signedReceipt: wire,
                                    verifierPublicKey: key.publicKey, logId: logId,
                                    claimStore: store, checkpoint: store)
                                if let decision = result.decision {
                                    return "released/\(decision.decision)/\(decision.releaseTime)/\(receipt.sequence)"
                                }
                                return "\(result.status.rawValue)/\(result.reason)"
                            }
                        }
                    }
                }
                var values: [String] = []
                for try await value in group { values.append(value) }
                return values
            }
            XCTAssertEqual(results.count, 7, "iteration \(iteration)")
            XCTAssertEqual(results.filter { $0.hasPrefix("acknowledged/") }, ["acknowledged/1800000000"],
                "iteration \(iteration)")
            XCTAssertTrue(results.filter { !$0.hasPrefix("acknowledged/") }.allSatisfy {
                ["pending/acknowledgement_unavailable", "released/allow/1800000000/1"].contains($0)
            }, "iteration \(iteration)")
            let after = try await Ratify.releaseDecision(committed, signedReceipt: wire,
                verifierPublicKey: key.publicKey, logId: logId, claimStore: store, checkpoint: store)
            XCTAssertEqual(after.status, .released, "iteration \(iteration)")
            XCTAssertEqual(after.decision?.receiptWire, wire, "iteration \(iteration)")
        }
    }

    func testConcurrentResumeSeesOwnerFinalizeOrLiveLease() async throws {
        let corpus = Corpus.load("concurrency-scenarios.json")
        let scenario = try XCTUnwrap(corpus.arr("scenarios").first { $0.s("name") == "resume_races_owner_finalize" })
        let participants = scenario.arr("participants")
        XCTAssertEqual(participants.map { $0.s("op") }, ["finalize", "resume"])
        let inputs = Corpus.load("lifecycle-scenarios.json")
        let req = try request("A", corpusName: "lifecycle-scenarios.json")
        let expected = try XCTUnwrap(req.expected)
        let bundle = try Ratify.decodeProofBundle(req.bundle)
        let hash = try Ratify.bundleHash(bundle)
        let claim = ChallengeClaim(claimId: try Ratify.protocolClaimId(namespace: expected.verifierNamespace,
            replayEpoch: expected.replayEpoch, challenge: expected.value), namespace: expected.verifierNamespace,
            replayEpoch: expected.replayEpoch, challengeDigest: "sha384:" +
                (try Ratify.challengeClaimDigest(expected.value)).hex,
            proofDigest: hash, bundleHash: hash, issuerIds: Array(Set(bundle.delegations.map(\.issuerId))).sorted(),
            requiredScope: req.requiredScope, contextPolicyDigest: req.contextPolicy?.digest ?? "",
            verifierId: expected.verifierId, agentId: bundle.agentId, requiresRate: false, rateBatch: [],
            issuedAt: expected.issuedAt, expiresAt: expected.expiresAt,
            maxAgeSeconds: req.maxChallengeAgeSeconds, clockSkewSeconds: req.futureSkewSeconds,
            streamId: bundle.streamId, streamSeq: bundle.streamSeq, constraintEvaluators: [])
        let key = Fixture.shared.privateKey(inputs.s("verifier_key"))
        let terminal = participants[0].b64("terminal_b64"), body = participants[0].b64("body_b64")
        for iteration in 0..<corpus.int("default_iterations") {
            let store = try Store(now: Int64(scenario.int("start_time")),
                leaseSeconds: Int64(inputs.int("lease_seconds")), logId: inputs.s("log_id"), verifierKey: key)
            let claimed = try await store.claim(claim)
            XCTAssertEqual(claimed.disposition, .created, "iteration \(iteration)")
            let results = await withTaskGroup(of: String.self) { group in
                group.addTask {
                    do {
                        let changed = try await store.finalize(claimId: claim.claimId,
                            ownerToken: claimed.ownerToken, terminalResult: terminal,
                            receiptBody: body, allowValidUntil: 0)
                        return changed ? "owner/committed" : "owner/identical"
                    } catch { return "owner/error" }
                }
                for _ in 0..<participants[1].int("count") {
                    group.addTask {
                        do {
                            let value = try await Ratify.resumeCommittedClaim(store: store, claimId: claim.claimId)
                            let receipt = try JSONSerialization.jsonObject(with: value.receiptBody) as! [String: Any]
                            return "resume/committed/\(receipt["decision"] ?? "")/\(receipt["decision_reason"] ?? "")"
                        } catch {
                            let klass = (error as? RatifyError)?.errorClass ?? (error as? StoreError)?.errorClass
                            return "resume/error/" + (klass?.rawValue ?? "unclassified")
                        }
                    }
                }
                var values: [String] = []
                for await value in group { values.append(value) }
                return values
            }
            XCTAssertEqual(results.count, 7, "iteration \(iteration)")
            XCTAssertEqual(results.filter { $0 == "owner/committed" }.count, 1, "iteration \(iteration)")
            XCTAssertTrue(results.filter { $0.hasPrefix("resume/") }.allSatisfy {
                $0 == "resume/error/claim_lease_live" ||
                    $0 == "resume/committed/indeterminate/status_unavailable"
            }, "iteration \(iteration): \(results)")
            let resumed = try await Ratify.resumeCommittedClaim(store: store, claimId: claim.claimId)
            XCTAssertEqual(resumed.receiptBody, body, "iteration \(iteration)")
            let wire = try await store.publish(claimId: claim.claimId, receiptBody: body)
            XCTAssertEqual(try Ratify.decodeVerificationReceipt(wire).sequence, 1, "iteration \(iteration)")
            let release = try await Ratify.releaseDecision(resumed, signedReceipt: wire,
                verifierPublicKey: key.publicKey, logId: inputs.s("log_id"), claimStore: store, checkpoint: store)
            XCTAssertEqual(release.status, .released, "iteration \(iteration)")
            XCTAssertEqual(release.decision?.decision, "indeterminate", "iteration \(iteration)")
        }
    }

    func testConcurrentIdenticalFinalizationsAndProofRetries() async throws {
        let corpus = Corpus.load("concurrency-scenarios.json")
        let scenario = try XCTUnwrap(corpus.arr("scenarios").first { $0.s("name") == "concurrent_identical_retries" })
        let participants = scenario.arr("participants")
        XCTAssertEqual(participants.map { $0.s("op") }, ["finalize", "verify"])
        let inputs = Corpus.load("lifecycle-scenarios.json")
        let req = try request("A", corpusName: "lifecycle-scenarios.json")
        let expected = try XCTUnwrap(req.expected)
        let bundle = try Ratify.decodeProofBundle(req.bundle)
        let hash = try Ratify.bundleHash(bundle)
        let claim = ChallengeClaim(claimId: try Ratify.protocolClaimId(namespace: expected.verifierNamespace,
            replayEpoch: expected.replayEpoch, challenge: expected.value), namespace: expected.verifierNamespace,
            replayEpoch: expected.replayEpoch, challengeDigest: "sha384:" +
                (try Ratify.challengeClaimDigest(expected.value)).hex,
            proofDigest: hash, bundleHash: hash, issuerIds: Array(Set(bundle.delegations.map(\.issuerId))).sorted(),
            requiredScope: req.requiredScope, contextPolicyDigest: req.contextPolicy?.digest ?? "",
            verifierId: expected.verifierId, agentId: bundle.agentId, requiresRate: false, rateBatch: [],
            issuedAt: expected.issuedAt, expiresAt: expected.expiresAt,
            maxAgeSeconds: req.maxChallengeAgeSeconds, clockSkewSeconds: req.futureSkewSeconds,
            streamId: bundle.streamId, streamSeq: bundle.streamSeq, constraintEvaluators: [])
        let key = Fixture.shared.privateKey(inputs.s("verifier_key"))
        let terminal = participants[0].b64("terminal_b64")
        let body = participants[0].b64("body_b64")
        let (trust, status, journal) = try await vectorProviders(inputs.obj("requests").obj("A"), request: req)
        for iteration in 0..<corpus.int("default_iterations") {
            let store = try Store(now: Int64(scenario.int("start_time")),
                leaseSeconds: Int64(inputs.int("lease_seconds")), logId: inputs.s("log_id"), verifierKey: key)
            let claimed = try await store.claim(claim)
            XCTAssertEqual(claimed.disposition, .created, "iteration \(iteration)")
            let results = try await withThrowingTaskGroup(of: (String, String).self) { group in
                for _ in 0..<participants[0].int("count") {
                    group.addTask {
                        let changed = try await store.finalize(claimId: claim.claimId,
                            ownerToken: claimed.ownerToken, terminalResult: terminal,
                            receiptBody: body, allowValidUntil: 0)
                        return ("owner", changed ? "committed" : "identical")
                    }
                }
                for _ in 0..<participants[1].int("count") {
                    group.addTask {
                        let value = try await Ratify.verifyProofBundle(req, claimStore: store,
                            trust: trust, statusEvidence: status, statusJournal: journal)
                        return ("retry", "\(value.stage.rawValue)/\(value.disposition?.rawValue ?? "")")
                    }
                }
                var values: [(String, String)] = []
                for try await value in group { values.append(value) }
                return values
            }
            XCTAssertEqual(results.count, 10, "iteration \(iteration)")
            XCTAssertEqual(results.filter { $0.0 == "owner" && $0.1 == "committed" }.count, 1,
                "iteration \(iteration)")
            XCTAssertTrue(results.filter { $0.0 == "owner" }.allSatisfy { ["committed", "identical"].contains($0.1) },
                "iteration \(iteration)")
            XCTAssertTrue(results.filter { $0.0 == "retry" }.allSatisfy {
                ["replay/terminal_replay", "replay/in_progress"].contains($0.1)
            }, "iteration \(iteration): \(results)")
            let after = try await Ratify.verifyProofBundle(req, claimStore: store,
                trust: trust, statusEvidence: status, statusJournal: journal)
            XCTAssertEqual(after.stage, .replay, "iteration \(iteration)")
            XCTAssertEqual(after.disposition, .terminalReplay, "iteration \(iteration)")
            let wire = try await store.publish(claimId: claim.claimId, receiptBody: body)
            XCTAssertEqual(try Ratify.decodeVerificationReceipt(wire).sequence, 1, "iteration \(iteration)")
        }
    }

    func testConcurrentRecoveryCannotReplaceCommittedAllow() async throws {
        let corpus = Corpus.load("concurrency-scenarios.json")
        let scenario = try XCTUnwrap(corpus.arr("scenarios").first {
            $0.s("name") == "recovery_races_after_owner_committed"
        })
        let participants = scenario.arr("participants")
        XCTAssertEqual(participants.map { $0.s("op") }, ["recover_direct", "recover"])
        let inputs = Corpus.load("lifecycle-scenarios.json")
        let key = Fixture.shared.privateKey(inputs.s("verifier_key"))
        let req = try request("A", corpusName: "lifecycle-scenarios.json")
        let (trust, status, journal) = try await vectorProviders(inputs.obj("requests").obj("A"), request: req)
        for iteration in 0..<corpus.int("default_iterations") {
            let store = try Store(now: Int64(scenario.int("start_time")),
                leaseSeconds: Int64(inputs.int("lease_seconds")), logId: inputs.s("log_id"), verifierKey: key)
            let verified = try await Ratify.verifyProofBundle(req, claimStore: store,
                trust: trust, statusEvidence: status, statusJournal: journal)
            let committed = try XCTUnwrap(verified.committed, "iteration \(iteration)")
            try store.setTime(Int64(scenario.arr("setup")[1].int("time")))
            let results = await withTaskGroup(of: String.self) { group in
                for participant in participants {
                    for _ in 0..<participant.int("count") {
                        if participant.s("op") == "recover_direct" {
                            let terminal = participant.b64("terminal_b64")
                            let body = participant.b64("body_b64")
                            group.addTask {
                                do {
                                    _ = try await store.recoverInterrupted(claimId: committed.claimId,
                                        terminalResult: terminal, receiptBody: body)
                                    return "unexpected/success"
                                } catch {
                                    return "error/" + ((error as? StoreError)?.errorClass?.rawValue ?? "unclassified")
                                }
                            }
                        } else {
                            group.addTask {
                                do {
                                    _ = try await Ratify.recoverInterruptedClaim(store: store, claimId: committed.claimId)
                                    return "unexpected/success"
                                } catch {
                                    return "error/" + ((error as? RatifyError)?.errorClass?.rawValue ?? "unclassified")
                                }
                            }
                        }
                    }
                }
                var values: [String] = []
                for await value in group { values.append(value) }
                return values
            }
            XCTAssertEqual(results.count, 6, "iteration \(iteration)")
            XCTAssertTrue(results.allSatisfy { $0 == "error/claim_already_terminal" }, "iteration \(iteration): \(results)")
            let replay = try await Ratify.verifyProofBundle(req, claimStore: store,
                trust: trust, statusEvidence: status, statusJournal: journal)
            XCTAssertEqual(replay.stage, .replay, "iteration \(iteration)")
            XCTAssertEqual(replay.disposition, .terminalReplay, "iteration \(iteration)")
            let wire = try await store.publish(claimId: committed.claimId, receiptBody: committed.receiptBody)
            XCTAssertEqual(try Ratify.decodeVerificationReceipt(wire).sequence, 1, "iteration \(iteration)")
            let second = try await store.publish(claimId: committed.claimId, receiptBody: committed.receiptBody)
            XCTAssertEqual(second, wire, "iteration \(iteration)")
        }
    }

    func testConcurrentIdenticalRecoveriesCommitOnce() async throws {
        let corpus = Corpus.load("concurrency-scenarios.json")
        let scenario = try XCTUnwrap(corpus.arr("scenarios").first {
            $0.s("name") == "concurrent_identical_recoveries"
        })
        let participant = try XCTUnwrap(scenario.arr("participants").first)
        XCTAssertEqual(participant.s("op"), "recover_direct")
        let inputs = Corpus.load("lifecycle-scenarios.json")
        let req = try request("A", corpusName: "lifecycle-scenarios.json")
        let expected = try XCTUnwrap(req.expected)
        let bundle = try Ratify.decodeProofBundle(req.bundle)
        let hash = try Ratify.bundleHash(bundle)
        let claim = ChallengeClaim(claimId: try Ratify.protocolClaimId(namespace: expected.verifierNamespace,
            replayEpoch: expected.replayEpoch, challenge: expected.value), namespace: expected.verifierNamespace,
            replayEpoch: expected.replayEpoch, challengeDigest: "sha384:" +
                (try Ratify.challengeClaimDigest(expected.value)).hex,
            proofDigest: hash, bundleHash: hash, issuerIds: Array(Set(bundle.delegations.map(\.issuerId))).sorted(),
            requiredScope: req.requiredScope, contextPolicyDigest: req.contextPolicy?.digest ?? "",
            verifierId: expected.verifierId, agentId: bundle.agentId, requiresRate: false, rateBatch: [],
            issuedAt: expected.issuedAt, expiresAt: expected.expiresAt,
            maxAgeSeconds: req.maxChallengeAgeSeconds, clockSkewSeconds: req.futureSkewSeconds,
            streamId: bundle.streamId, streamSeq: bundle.streamSeq, constraintEvaluators: [])
        let key = Fixture.shared.privateKey(inputs.s("verifier_key"))
        let terminal = participant.b64("terminal_b64"), body = participant.b64("body_b64")
        for iteration in 0..<corpus.int("default_iterations") {
            let store = try Store(now: Int64(scenario.int("start_time")),
                leaseSeconds: Int64(inputs.int("lease_seconds")), logId: inputs.s("log_id"), verifierKey: key)
            let claimed = try await store.claim(claim)
            XCTAssertEqual(claimed.disposition, .created, "iteration \(iteration)")
            try store.setTime(Int64(scenario.arr("setup")[1].int("time")))
            let results = try await withThrowingTaskGroup(of: Bool.self) { group in
                for _ in 0..<participant.int("count") {
                    group.addTask { try await store.recoverInterrupted(claimId: claim.claimId,
                        terminalResult: terminal, receiptBody: body) }
                }
                var values: [Bool] = []
                for try await value in group { values.append(value) }
                return values
            }
            XCTAssertEqual(results.count, 6, "iteration \(iteration)")
            XCTAssertEqual(results.filter { $0 }.count, 1, "iteration \(iteration)")
            let recovered = try await Ratify.recoverInterruptedClaim(store: store, claimId: claim.claimId)
            XCTAssertEqual(recovered.receiptBody, body, "iteration \(iteration)")
            let wire = try await store.publish(claimId: claim.claimId, receiptBody: body)
            XCTAssertEqual(try Ratify.decodeVerificationReceipt(wire).sequence, 1, "iteration \(iteration)")
            let republished = try await store.publish(claimId: claim.claimId, receiptBody: body)
            XCTAssertEqual(republished, wire, "iteration \(iteration)")
        }
    }

    func testLifecycleBasicReleaseScenarios() async throws {
        let corpus = Corpus.load("lifecycle-scenarios.json")
        let names: Set<String> = ["allow_published_acknowledged_released", "release_without_receipt_is_pending",
            "forged_committed_outcome_is_rejected",
            "release_without_acknowledgement_is_pending_then_late_ack_releases",
            "late_ack_at_challenge_expiry_is_withheld", "release_one_second_before_challenge_expiry",
            "release_at_challenge_expiry_is_withheld", "release_at_allow_horizon_is_withheld",
            "release_before_allow_horizon", "signer_failure_then_retry", "head_of_line_blocking",
            "acknowledgement_for_another_entry_is_rejected", "repeated_release_reverifies_acknowledgement",
            "receipt_of_another_claim_is_rejected", "corrupt_receipt_signature_is_rejected",
            "resume_replaces_lost_allow_handoff", "resume_abandoned_claim", "crash_after_claim_lease_recovery",
            "resume_refuses_claims_without_a_committed_record", "clock_regression_at_resume_and_recovery",
            "clock_beyond_timestamp_domain_at_resume_and_recovery",
            "lease_expires_during_status_then_recovery", "clock_regression_during_evaluation",
            "clock_regression_at_release_is_withheld", "withheld_after_recorded_release_records_nothing",
            "receipt_abandoned", "clock_regression_at_claim", "different_proof_for_claimed_challenge_is_replay",
            "stream_sequence_rules", "outbox_retained_past_challenge_expiry",
            "finalize_rejects_body_with_other_verifier_id", "finalize_rejects_body_with_other_agent_id",
            "finalize_rejects_body_with_other_bundle_hash", "finalize_rejects_body_with_other_issuer_ids",
            "finalize_rejects_body_with_other_required_scope", "finalize_rejects_body_with_other_context_policy_digest",
            "finalize_rejects_body_with_other_constraint_evaluators", "finalize_rejects_body_with_other_terminal_decision",
            "finalize_rejects_body_with_other_terminal_identity_status", "finalize_rejects_body_with_other_terminal_members",
            "finalize_rejects_body_with_other_terminal_spelling", "finalize_rejects_body_with_other_terminal_without_identity_status",
            "finalize_rejects_body_with_null_context_policy_digest_unverified",
            "finalize_rejects_body_with_null_context_policy_digest_unbound", "finalize_rejects_allow_without_allow_horizon",
            "finalize_rejects_negative_allow_horizon_on_non_allow", "finalize_rejects_allow_horizon_beyond_timestamp_domain",
            "finalize_rejects_allow_horizon_on_non_allow", "finalize_rejects_body_with_context_policy_digest_not_evaluated",
            "resume_finalized_claim_without_handoff", "recover_rejects_malformed_body",
            "recover_rejects_body_for_another_claim", "recover_rejects_context_policy_digest_not_evaluated",
            "recover_rejects_other_decision", "recover_rejects_terminal_result_other_than_body",
            "recover_direct_accepts_canonical_interrupted_body", "recover_rejects_terminal_result_with_other_members",
            "recover_rejects_terminal_result_not_canonical", "recover_rejects_terminal_result_without_identity_status",
            "recover_rejects_terminal_result_other_identity_status",
            "resume_rejects_record_for_another_claim", "resume_rejects_record_of_another_well_formed_claim",
            "resume_rejects_record_claim_id_not_derived_from_replay_key", "resume_rejects_record_uppercase_challenge_digest",
            "resume_rejects_record_non_sha384_challenge_digest", "resume_rejects_record_body_for_another_agent",
            "resume_rejects_record_terminal_result_other_than_body", "resume_rejects_record_terminal_result_other_identity_status",
            "resume_rejects_record_terminal_result_with_other_members", "resume_rejects_record_allow_without_allow_horizon",
            "resume_rejects_record_allow_horizon_beyond_timestamp_domain", "resume_rejects_record_allow_horizon_on_non_allow",
            "resume_rejects_record_body_for_another_verifier", "resume_rejects_record_body_for_another_bundle",
            "resume_rejects_record_body_for_another_scope", "resume_rejects_record_body_with_another_context_policy_digest",
            "resume_rejects_record_body_with_unsealed_constraint_evaluators", "resume_rejects_record_claim_without_context_policy",
            "resume_rejects_record_negative_allow_horizon", "resume_rejects_record_negative_allow_horizon_on_non_allow",
            "resume_rejects_record_non_canonical_claim_record",
            "resume_accepts_interrupted_record", "resume_substituted_record_rejected_at_release",
            "resume_accepts_allow_horizon_at_timestamp_domain_end", "resume_forged_record_longer_allow_horizon",
            "resume_forged_record_later_challenge_expiry", "resume_forged_record_allow_for_unheld_claim",
            "resume_forged_record_allow_over_evaluating_claim", "resume_forged_record_allow_over_interrupted_claim",
            "resume_accepts_honest_record", "restore_exact_state", "restore_lost_state_with_epoch_bump",
            "release_of_claim_the_store_does_not_hold", "planted_release_record_does_not_replace_acknowledgement",
            "recorded_withheld_answers_before_receipt_checks", "withheld_when_recording_fails",
            "withheld_record_conflict_is_rejected", "checkpoint_fork_freezes_log",
            "checkpoint_refusal_without_fork_does_not_freeze", "concurrent_stream_advances",
            "cancel_before_claim_consumes_nothing", "cancel_after_claim_keeps_claim_recoverable",
            "late_worker_fenced_after_recovery", "rate_admission_at_finalization",
            "rate_admission_is_all_or_none", "rate_retry_and_changed_batch_count_once",
            "rate_clock_rollback_keeps_admissions_blocking", "rate_counts_only_allow",
            "dual_root_both_released_executes_once", "dual_root_one_root_missing",
            "dual_root_other_root_missing", "dual_root_duplicate_root", "dual_root_replay",
            "dual_root_mismatched_action", "dual_root_committed_unreleased",
            "dual_root_expired_before_execution", "dual_root_cross_set_reuse",
            "dual_root_same_set_different_action", "dual_root_swapped_verifier",
            "dual_root_set_names_other_verifier", "dual_root_concurrent_completion",
            "device_release_requires_component_ack", "device_power_loss_before_ack",
            "device_power_loss_after_ack", "device_checkpoint_storage_full",
            "device_offline_recovery_upload", "device_staged_status_goes_stale",
            "device_rtc_regression", "device_planted_release_record",
            "device_altered_release_record", "device_state_digest_mismatch",
            "device_primary_rollback", "device_rollback_loses_consumed_challenge",
            "device_rollback_loses_stream_advance", "device_rollback_loses_release_record",
            "device_rollback_loses_rate_state", "device_rollback_loses_journal_state"]
        let scenarios = (corpus.arr("scenarios") + corpus.arr("profile_scenarios"))
            .filter { names.contains($0.s("name")) }
        XCTAssertEqual(scenarios.count, names.count)
        let counts = ["allow_published_acknowledged_released": 6, "release_without_receipt_is_pending": 2,
            "forged_committed_outcome_is_rejected": 1,
            "release_without_acknowledgement_is_pending_then_late_ack_releases": 7,
            "late_ack_at_challenge_expiry_is_withheld": 6, "release_one_second_before_challenge_expiry": 4,
            "release_at_challenge_expiry_is_withheld": 4, "release_at_allow_horizon_is_withheld": 4,
            "release_before_allow_horizon": 3, "signer_failure_then_retry": 5, "head_of_line_blocking": 8,
            "acknowledgement_for_another_entry_is_rejected": 4, "repeated_release_reverifies_acknowledgement": 5,
            "receipt_of_another_claim_is_rejected": 7, "corrupt_receipt_signature_is_rejected": 5,
            "resume_replaces_lost_allow_handoff": 5, "resume_abandoned_claim": 6,
            "crash_after_claim_lease_recovery": 9,
            "resume_refuses_claims_without_a_committed_record": 7,
            "clock_regression_at_resume_and_recovery": 7,
            "clock_beyond_timestamp_domain_at_resume_and_recovery": 7,
            "lease_expires_during_status_then_recovery": 5, "clock_regression_during_evaluation": 3,
            "clock_regression_at_release_is_withheld": 7, "withheld_after_recorded_release_records_nothing": 8,
            "receipt_abandoned": 8, "clock_regression_at_claim": 5,
            "different_proof_for_claimed_challenge_is_replay": 3, "stream_sequence_rules": 7,
            "outbox_retained_past_challenge_expiry": 6,
            "finalize_rejects_body_with_other_verifier_id": 5, "finalize_rejects_body_with_other_agent_id": 5,
            "finalize_rejects_body_with_other_bundle_hash": 5, "finalize_rejects_body_with_other_issuer_ids": 5,
            "finalize_rejects_body_with_other_required_scope": 5, "finalize_rejects_body_with_other_context_policy_digest": 5,
            "finalize_rejects_body_with_other_constraint_evaluators": 5, "finalize_rejects_body_with_other_terminal_decision": 5,
            "finalize_rejects_body_with_other_terminal_identity_status": 5, "finalize_rejects_body_with_other_terminal_members": 5,
            "finalize_rejects_body_with_other_terminal_spelling": 5, "finalize_rejects_body_with_other_terminal_without_identity_status": 5,
            "finalize_rejects_body_with_null_context_policy_digest_unverified": 4,
            "finalize_rejects_body_with_null_context_policy_digest_unbound": 4, "finalize_rejects_allow_without_allow_horizon": 4,
            "finalize_rejects_negative_allow_horizon_on_non_allow": 3, "finalize_rejects_allow_horizon_beyond_timestamp_domain": 3,
            "finalize_rejects_allow_horizon_on_non_allow": 4, "finalize_rejects_body_with_context_policy_digest_not_evaluated": 4,
            "resume_finalized_claim_without_handoff": 6, "recover_rejects_malformed_body": 6,
            "recover_rejects_body_for_another_claim": 6, "recover_rejects_context_policy_digest_not_evaluated": 6,
            "recover_rejects_other_decision": 6, "recover_rejects_terminal_result_other_than_body": 6,
            "recover_direct_accepts_canonical_interrupted_body": 7, "recover_rejects_terminal_result_with_other_members": 6,
            "recover_rejects_terminal_result_not_canonical": 6, "recover_rejects_terminal_result_without_identity_status": 6,
            "recover_rejects_terminal_result_other_identity_status": 6,
            "resume_rejects_record_for_another_claim": 5, "resume_rejects_record_of_another_well_formed_claim": 5,
            "resume_rejects_record_claim_id_not_derived_from_replay_key": 5, "resume_rejects_record_uppercase_challenge_digest": 5,
            "resume_rejects_record_non_sha384_challenge_digest": 5, "resume_rejects_record_body_for_another_agent": 5,
            "resume_rejects_record_terminal_result_other_than_body": 5, "resume_rejects_record_terminal_result_other_identity_status": 5,
            "resume_rejects_record_terminal_result_with_other_members": 5, "resume_rejects_record_allow_without_allow_horizon": 5,
            "resume_rejects_record_allow_horizon_beyond_timestamp_domain": 5, "resume_rejects_record_allow_horizon_on_non_allow": 5,
            "resume_rejects_record_body_for_another_verifier": 5, "resume_rejects_record_body_for_another_bundle": 5,
            "resume_rejects_record_body_for_another_scope": 5, "resume_rejects_record_body_with_another_context_policy_digest": 5,
            "resume_rejects_record_body_with_unsealed_constraint_evaluators": 5, "resume_rejects_record_claim_without_context_policy": 5,
            "resume_rejects_record_negative_allow_horizon": 5, "resume_rejects_record_negative_allow_horizon_on_non_allow": 5,
            "resume_rejects_record_non_canonical_claim_record": 5,
            "resume_accepts_interrupted_record": 1, "resume_substituted_record_rejected_at_release": 6,
            "resume_accepts_allow_horizon_at_timestamp_domain_end": 1, "resume_forged_record_longer_allow_horizon": 6,
            "resume_forged_record_later_challenge_expiry": 6, "resume_forged_record_allow_for_unheld_claim": 3,
            "resume_forged_record_allow_over_evaluating_claim": 4, "resume_forged_record_allow_over_interrupted_claim": 8,
            "resume_accepts_honest_record": 5, "restore_exact_state": 5,
            "restore_lost_state_with_epoch_bump": 6, "release_of_claim_the_store_does_not_hold": 4,
            "planted_release_record_does_not_replace_acknowledgement": 8,
            "recorded_withheld_answers_before_receipt_checks": 7, "withheld_when_recording_fails": 7,
            "withheld_record_conflict_is_rejected": 7, "checkpoint_fork_freezes_log": 11,
            "checkpoint_refusal_without_fork_does_not_freeze": 11, "concurrent_stream_advances": 4,
            "cancel_before_claim_consumes_nothing": 5, "cancel_after_claim_keeps_claim_recoverable": 7,
            "late_worker_fenced_after_recovery": 4, "rate_admission_at_finalization": 5,
            "rate_admission_is_all_or_none": 5, "rate_retry_and_changed_batch_count_once": 5,
            "rate_clock_rollback_keeps_admissions_blocking": 9, "rate_counts_only_allow": 7,
            "dual_root_both_released_executes_once": 12, "dual_root_one_root_missing": 7,
            "dual_root_other_root_missing": 6, "dual_root_duplicate_root": 11,
            "dual_root_replay": 7, "dual_root_mismatched_action": 10,
            "dual_root_committed_unreleased": 16, "dual_root_expired_before_execution": 11,
            "dual_root_cross_set_reuse": 14, "dual_root_same_set_different_action": 10,
            "dual_root_swapped_verifier": 10, "dual_root_set_names_other_verifier": 10,
            "dual_root_concurrent_completion": 9, "device_release_requires_component_ack": 6,
            "device_power_loss_before_ack": 9, "device_power_loss_after_ack": 8,
            "device_checkpoint_storage_full": 7, "device_offline_recovery_upload": 13,
            "device_staged_status_goes_stale": 9, "device_rtc_regression": 17,
            "device_planted_release_record": 7, "device_altered_release_record": 9,
            "device_state_digest_mismatch": 7, "device_primary_rollback": 10,
            "device_rollback_loses_consumed_challenge": 11,
            "device_rollback_loses_stream_advance": 9,
            "device_rollback_loses_release_record": 10,
            "device_rollback_loses_rate_state": 9,
            "device_rollback_loses_journal_state": 9]
        let stepKeys: [String: Set<String>] = ["verify": ["op", "request", "expect"],
            "publish": ["op", "request", "mode", "expect"],
            "release": ["op", "request", "checkpoint", "expect"],
            "set_time": ["op", "time", "expect"], "set_ack_withheld": ["op", "withheld", "expect"],
            "resume": ["op", "request", "expect"], "abandon": ["op", "expect"],
            "release_forged": ["op", "expect"],
            "claim_only": ["op", "request", "expect"], "recover": ["op", "request", "expect"],
            "finalize": ["op", "request", "terminal_b64", "body_b64", "expect"],
            "recover_direct": ["op", "request", "terminal_b64", "body_b64", "expect"],
            "restore": ["op", "mode", "expect"], "plant_release": ["op", "request", "time", "expect"],
            "acknowledge": ["op", "request", "mode", "expect"],
            "verify_concurrent": ["op", "requests", "expect"],
            "ledger_open": ["op", "approval_set", "expect"],
            "ledger_record": ["op", "request", "slot", "expect"],
            "ledger_execute": ["op", "expect"],
            "ledger_record_concurrent": ["op", "requests", "expect"],
            "ledger_execute_concurrent": ["op", "count", "expect"],
            "device_submit": ["op", "expect"], "upload": ["op", "expect"],
            "corrupt_state": ["op", "request", "expect"],
            "snapshot": ["op", "snapshot", "expect"],
            "stage_status": ["op", "request", "expect"],
            "device_power_loss": ["op", "mode", "expect"],
            "device_startup": ["op", "expect"],
            "device_resubmit": ["op", "sequence", "expect"]]
        let key = Fixture.shared.privateKey(corpus.s("verifier_key"))
        for scenario in scenarios {
            let name = scenario.s("name")
            XCTAssertEqual(scenario.arr("steps").count, counts[name], name)
            var store = try Store(now: Int64(scenario.int("start_time")), leaseSeconds: Int64(corpus.int("lease_seconds")),
                logId: corpus.s("log_id"), verifierKey: key)
            let rateAtFinalization = scenario["rate_at_finalization"] as? Bool == true
            var rateStore = rateAtFinalization ? try store.withRateAtFinalization() : nil
            var rateTime = Int64(scenario.int("start_time"))
            var logId = corpus.s("log_id")
            var replayEpochOverride: Int64?
            var committed: [String: CommittedOutcome] = [:]
            var claimed: [String: ChallengeClaim] = [:]
            var owners: [String: Data] = [:]
            var receipts: [String: Data] = [:]
            var publishedWires: [String: Data] = [:]
            var released: [String: ReleasedDecision] = [:]
            let approvalLedger = name.hasPrefix("dual_root_") ? try ApprovalLedger() : nil
            var device = name.hasPrefix("device_") ? try OfflineDevice(store: store,
                replayEpoch: Int64(scenario.obj("device").int("replay_epoch")),
                seed: scenario.obj("device").b64("component_seed_b64"),
                capacity: UInt32(scenario.obj("device").int("capacity"))) : nil
            var deviceSnapshot: OfflineDeviceSnapshot?
            var deviceSnapshotName: String?
            var approvalSetId: String?
            for (index, step) in scenario.arr("steps").enumerated() {
                let op = step.s("op")
                let requestName = step["request"] as? String ?? ""
                let want = step.obj("expect")
                let at = "\(name) step \(index) \(op)"
                var expectedStepKeys = stepKeys[op] ?? []
                if op == "release" && step["receipt_of"] != nil { expectedStepKeys.insert("receipt_of") }
                if op == "release" && step["mode"] != nil { expectedStepKeys.insert("mode") }
                if op == "restore" && step.s("mode") == "lost_state_epoch_bump" {
                    expectedStepKeys.formUnion(["log_id", "replay_epoch"])
                }
                if op == "restore" && step.s("mode") == "snapshot" {
                    expectedStepKeys.insert("snapshot")
                }
                if op == "verify" && step["mode"] != nil { expectedStepKeys.formUnion(["mode", "time"]) }
                if (op == "ledger_record" || op == "ledger_execute") && step["set"] != nil {
                    expectedStepKeys.insert("set")
                }
                if op == "finalize" && step["allow_valid_until"] != nil { expectedStepKeys.insert("allow_valid_until") }
                if op == "resume" && step["claim_record_b64"] != nil {
                    expectedStepKeys.formUnion(["claim_record_b64", "terminal_b64", "body_b64"])
                    if step["mode"] != nil {
                        XCTAssertEqual(step.s("mode"), "record_bytes", at)
                        expectedStepKeys.insert("mode")
                    }
                    if step["allow_valid_until"] != nil { expectedStepKeys.insert("allow_valid_until") }
                    if step["claim_id"] != nil { expectedStepKeys.insert("claim_id") }
                }
                XCTAssertEqual(Set(step.keys), expectedStepKeys, at)
                switch op {
                case "ledger_open":
                    XCTAssertEqual(Set(want.keys), want["ledger_error"] == nil ? [] : ["ledger_error"], at)
                    let set = step.obj("approval_set")
                    XCTAssertEqual(Set(set.keys), ["id", "verifier_id", "workspace_id", "session_id",
                        "agent_key", "required_scope", "request_hash_b64", "root_keys", "session_context_b64"], at)
                    let roots = set.strings("root_keys")
                    XCTAssertEqual(roots.count, 2, at)
                    let ledger = try XCTUnwrap(approvalLedger, at)
                    let agent = Fixture.shared.privateKey(set.s("agent_key"))
                    let context = try Ratify.buildSessionContext(SessionContextInputs(
                        verifierId: set.s("verifier_id"), workspaceId: set.s("workspace_id"),
                        agentId: agent.keyId, sessionId: set.s("session_id"),
                        invocationId: set.s("id"), requestHash: set.b64("request_hash_b64")))
                    XCTAssertEqual(context, set.b64("session_context_b64"), at)
                    let opened = try ledger.open(id: set.s("id"), verifierId: set.s("verifier_id"),
                        workspaceId: set.s("workspace_id"), sessionId: set.s("session_id"),
                        agentKey: agent.publicKey,
                        requiredScope: set.s("required_scope"), requestHash: set.b64("request_hash_b64"),
                        rootA: Fixture.shared.privateKey(roots[0]).publicKey,
                        rootB: Fixture.shared.privateKey(roots[1]).publicKey)
                    XCTAssertEqual(opened.failure, want["ledger_error"] == nil ? nil : want.s("ledger_error"), at)
                    XCTAssertNil(opened.complete, at)
                    if opened.failure == nil { approvalSetId = set.s("id") }
                case "ledger_record":
                    XCTAssertEqual(Set(want.keys), want["ledger_error"] != nil ? ["ledger_error"]
                        : want["ledger_complete"] == nil ? [] : ["ledger_complete"], at)
                    let ledger = try XCTUnwrap(approvalLedger, at)
                    let id = try XCTUnwrap(step["set"] as? String ?? approvalSetId, at)
                    let decision = released[requestName]
                    let bundle = try request(requestName, corpusName: "lifecycle-scenarios.json").bundle
                    let reply = try ledger.record(id: id, slot: UInt32(step.int("slot")),
                        decision: decision, bundle: bundle)
                    XCTAssertEqual(reply.failure, want["ledger_error"] == nil ? nil : want.s("ledger_error"), at)
                    XCTAssertEqual(reply.complete, want["ledger_error"] != nil ? nil
                        : want["ledger_complete"] == nil ? false : want.bool("ledger_complete"), at)
                case "ledger_execute":
                    XCTAssertEqual(Set(want.keys), want["ledger_error"] == nil ? [] : ["ledger_error"], at)
                    let ledger = try XCTUnwrap(approvalLedger, at)
                    let id = try XCTUnwrap(step["set"] as? String ?? approvalSetId, at)
                    let reply = try ledger.execute(id: id, clock: store)
                    XCTAssertEqual(reply.failure, want["ledger_error"] == nil ? nil : want.s("ledger_error"), at)
                    XCTAssertNil(reply.complete, at)
                case "ledger_record_concurrent":
                    XCTAssertEqual(Set(want.keys), ["ledger_complete"], at)
                    let ledger = try XCTUnwrap(approvalLedger, at)
                    let id = try XCTUnwrap(approvalSetId, at)
                    let names = step.strings("requests")
                    XCTAssertEqual(names.count, 2, at)
                    let first = try XCTUnwrap(released[names[0]], at)
                    let second = try XCTUnwrap(released[names[1]], at)
                    let firstBundle = try request(names[0], corpusName: "lifecycle-scenarios.json").bundle
                    let secondBundle = try request(names[1], corpusName: "lifecycle-scenarios.json").bundle
                    async let firstReply = ledger.record(id: id, slot: 0, decision: first, bundle: firstBundle)
                    async let secondReply = ledger.record(id: id, slot: 1, decision: second, bundle: secondBundle)
                    let replies = try await [firstReply, secondReply]
                    XCTAssertTrue(replies.allSatisfy { $0.failure == nil }, at)
                    XCTAssertEqual(replies.filter { $0.complete == true }.count,
                        want.bool("ledger_complete") ? 1 : 0, at)
                case "ledger_execute_concurrent":
                    XCTAssertEqual(Set(want.keys), ["executed"], at)
                    let ledger = try XCTUnwrap(approvalLedger, at)
                    let id = try XCTUnwrap(approvalSetId, at)
                    let count = step.int("count")
                    XCTAssertEqual(count, 8, at)
                    let clock = store
                    let replies = try await withThrowingTaskGroup(of: ApprovalReply.self) { group in
                        for _ in 0..<count { group.addTask { try ledger.execute(id: id, clock: clock) } }
                        var results: [ApprovalReply] = []
                        for try await reply in group { results.append(reply) }
                        return results
                    }
                    XCTAssertEqual(replies.filter { $0.failure == nil }.count, want.int("executed"), at)
                    XCTAssertTrue(replies.filter { $0.failure != nil }
                        .allSatisfy { $0.failure == "already_executed" }, at)
                    XCTAssertTrue(replies.allSatisfy { $0.complete == nil }, at)
                case "device_submit":
                    XCTAssertEqual(Set(want.keys), Set(["acknowledged", "device_error"])
                        .intersection(Set(want.keys)), at)
                    let reply = try XCTUnwrap(device, at).submitPending()
                    XCTAssertEqual(reply.failure, want["device_error"] == nil ? nil : want.s("device_error"), at)
                    XCTAssertEqual(reply.acknowledged, want["acknowledged"] == nil ? []
                        : (want["acknowledged"] as! [NSNumber]).map(\.int64Value), at)
                case "corrupt_state":
                    XCTAssertTrue(want.isEmpty, at)
                    try store.corruptSealedStateTestOnly(claimId: try XCTUnwrap(committed[requestName], at).claimId)
                case "snapshot":
                    XCTAssertTrue(want.isEmpty, at)
                    deviceSnapshot = try XCTUnwrap(device, at).snapshot()
                    deviceSnapshotName = step.s("snapshot")
                case "stage_status":
                    XCTAssertTrue(want.isEmpty, at)
                    let inputs = corpus.obj("requests").obj(requestName)
                    let statusKeys = inputs.obj("status_keys")
                    let journal = inputs.obj("journal")
                    let preload = journal.arr("preload")
                    XCTAssertEqual(journal.s("mode"), "anchored", at)
                    XCTAssertNil(journal["setup"], at)
                    XCTAssertEqual(statusKeys.count, 3, at)
                    XCTAssertEqual(preload.count, 2, at)
                    let staged = try XCTUnwrap(device, at)
                    for issuer in statusKeys.keys.sorted() {
                        let item = statusKeys.obj(issuer)
                        let publicKey = item.obj("public_key")
                        try staged.stageStatusKey(issuerId: issuer, epoch: UInt64(item.int("epoch")),
                            key: HybridPublicKey(ed25519: publicKey.b64("ed25519"),
                                mlDsa65: publicKey.b64("ml_dsa_65")))
                    }
                    let bounds = inputs.obj("status_policy")
                    let policy = RevocationStatusPolicy(maxListLifetimeSeconds: Int64(bounds.int("max_list_lifetime_seconds")),
                        maxStatusAgeSeconds: Int64(bounds.int("max_status_age_seconds")),
                        clockSkewSeconds: Int64(bounds.int("clock_skew_seconds")))
                    for item in preload {
                        XCTAssertEqual(item.int("object_type_code"), 3, at)
                        let issuer = item.s("issuer_id")
                        let keyItem = statusKeys.obj(issuer)
                        let publicKey = keyItem.obj("public_key")
                        try staged.stageRevocationList(wire: item.b64("wire_b64"), issuerId: issuer,
                            epoch: UInt64(keyItem.int("epoch")),
                            key: HybridPublicKey(ed25519: publicKey.b64("ed25519"),
                                mlDsa65: publicKey.b64("ml_dsa_65")), policy: policy,
                            now: Int64(item.int("now")))
                    }
                case "device_power_loss":
                    XCTAssertTrue(want.isEmpty, at)
                    try XCTUnwrap(device, at).setPowerLoss(step.s("mode"))
                case "device_startup":
                    XCTAssertEqual(Set(want.keys), ["device_status"], at)
                    XCTAssertEqual(try XCTUnwrap(device, at).startup(), want.s("device_status"), at)
                case "device_resubmit":
                    XCTAssertEqual(Set(want.keys), ["ack_time"], at)
                    let reply = try XCTUnwrap(device, at).resubmit(Int64(step.int("sequence")))
                    XCTAssertNil(reply.failure, at)
                    XCTAssertEqual(reply.ackTime, Int64(want.int("ack_time")), at)
                case "upload":
                    XCTAssertEqual(Set(want.keys), want["uploaded"] == nil ? [] : ["uploaded"], at)
                    XCTAssertEqual(try XCTUnwrap(device, at).upload(),
                        want["uploaded"] == nil ? [] : (want["uploaded"] as! [NSNumber]).map(\.int64Value), at)
                case "set_time":
                    try store.setTime(Int64(step.int("time")))
                    rateTime = Int64(step.int("time"))
                    XCTAssertTrue(want.isEmpty, at)
                case "set_ack_withheld":
                    try store.setAcknowledgementWithheld(step.bool("withheld"))
                    XCTAssertTrue(want.isEmpty, at)
                case "restore":
                    XCTAssertTrue(want.isEmpty, at)
                    if name.hasPrefix("device_") {
                        XCTAssertEqual(step.s("mode"), "snapshot", at)
                        XCTAssertEqual(step.s("snapshot"), deviceSnapshotName, at)
                        device = try XCTUnwrap(device, at).restore(XCTUnwrap(deviceSnapshot, at))
                        store = try XCTUnwrap(device, at).primaryStore()
                        rateStore = rateAtFinalization ? try store.withRateAtFinalization() : nil
                    } else if step.s("mode") == "exact" {
                        XCTAssertNil(rateStore, at)
                        store = try store.cloneStore()
                    }
                    else {
                        XCTAssertNil(rateStore, at)
                        XCTAssertEqual(step.s("mode"), "lost_state_epoch_bump", at)
                        logId = step.s("log_id")
                        replayEpochOverride = Int64(step.int("replay_epoch"))
                        store = try Store(now: store.now(), leaseSeconds: Int64(corpus.int("lease_seconds")),
                            logId: logId, verifierKey: key)
                    }
                case "plant_release":
                    XCTAssertTrue(want.isEmpty, at)
                    try store.plantReleaseTestOnly(claimId: try XCTUnwrap(committed[requestName], at).claimId,
                        ackTimestamp: Int64(step.int("time")))
                case "acknowledge":
                    XCTAssertEqual(Set(want.keys), want["failed"] == nil ? ["ack_timestamp"] : ["failed"], at)
                    let receipt = try Ratify.decodeVerificationReceipt(try XCTUnwrap(receipts[requestName], at))
                    var entry = try Ratify.verificationReceiptDigest(receipt)
                    let mode = step.s("mode")
                    XCTAssertTrue(mode == "exact" || mode == "fork", at)
                    if mode == "fork" {
                        XCTAssertEqual(want["failed"] as? Bool, true, at)
                        entry[entry.startIndex] ^= 1
                    }
                    do {
                        let ack = try await store.acknowledge(logId: receipt.logId, sequence: receipt.sequence,
                            previousEntryHash: receipt.previousReceiptHash, entryHash: entry)
                        XCTAssertFalse(want.keys.contains("failed"), at)
                        XCTAssertEqual(ack.timestamp, Int64(want.int("ack_timestamp")), at)
                        XCTAssertEqual(ack.sequence, receipt.sequence, at)
                        XCTAssertEqual(ack.entryHash, entry, at)
                    } catch is StoreError {
                        XCTAssertEqual(want["failed"] as? Bool, true, at)
                    }
                case "verify_concurrent":
                    XCTAssertEqual(Set(want.keys), ["outcomes"], at)
                    let names = step.strings("requests")
                    XCTAssertEqual(names.count, 2, at)
                    XCTAssertEqual(Set(names).count, 2, at)
                    let first = try request(names[0], corpusName: "lifecycle-scenarios.json")
                    let second = try request(names[1], corpusName: "lifecycle-scenarios.json")
                    let (firstTrust, firstStatus, firstJournal) = try await vectorProviders(
                        corpus.obj("requests").obj(names[0]), request: first)
                    let (secondTrust, secondStatus, secondJournal) = try await vectorProviders(
                        corpus.obj("requests").obj(names[1]), request: second)
                    let concurrentStore = store
                    async let firstOutcome = Ratify.verifyProofBundle(first, claimStore: concurrentStore,
                        trust: firstTrust, statusEvidence: firstStatus, statusJournal: firstJournal)
                    async let secondOutcome = Ratify.verifyProofBundle(second, claimStore: concurrentStore,
                        trust: secondTrust, statusEvidence: secondStatus, statusJournal: secondJournal)
                    let outcomes = try await [firstOutcome, secondOutcome]
                    var labels: [String] = []
                    for (name, outcome) in zip(names, outcomes) {
                        labels.append(outcome.stage.rawValue + (outcome.errorClass.map { "/" + $0.rawValue } ?? ""))
                        if outcome.stage == .committed { committed[name] = try XCTUnwrap(outcome.committed, at) }
                        else { XCTAssertNil(outcome.committed, at) }
                    }
                    XCTAssertEqual(labels.sorted(), want.strings("outcomes"), at)
                case "claim_only":
                    XCTAssertEqual(Set(want.keys), ["disposition"], at)
                    let req = try request(requestName, corpusName: "lifecycle-scenarios.json")
                    let expected = try XCTUnwrap(req.expected, at)
                    let bundle = try Ratify.decodeProofBundle(req.bundle)
                    XCTAssertTrue(bundle.delegations.allSatisfy {
                        $0.constraints.allSatisfy { $0.kind == "max_rate" }
                    }, at)
                    let rateBatch = bundle.delegations.flatMap { cert in cert.constraints.map {
                        RateReservation(issuerId: cert.issuerId, certId: cert.certId,
                            windowSeconds: $0.windowS, limit: $0.count)
                    }}
                    XCTAssertEqual(rateBatch.isEmpty, rateStore == nil, at)
                    let hash = try Ratify.bundleHash(bundle)
                    let claim = ChallengeClaim(claimId: try Ratify.protocolClaimId(namespace: expected.verifierNamespace,
                        replayEpoch: expected.replayEpoch, challenge: expected.value), namespace: expected.verifierNamespace,
                        replayEpoch: expected.replayEpoch, challengeDigest: "sha384:" + (try Ratify.challengeClaimDigest(expected.value)).hex,
                        proofDigest: hash, bundleHash: hash, issuerIds: Array(Set(bundle.delegations.map(\.issuerId))).sorted(),
                        requiredScope: req.requiredScope, contextPolicyDigest: req.contextPolicy?.digest ?? "",
                        verifierId: expected.verifierId, agentId: bundle.agentId,
                        requiresRate: !rateBatch.isEmpty, rateBatch: rateBatch,
                        issuedAt: expected.issuedAt, expiresAt: expected.expiresAt,
                        maxAgeSeconds: req.maxChallengeAgeSeconds, clockSkewSeconds: req.futureSkewSeconds,
                        streamId: bundle.streamId, streamSeq: bundle.streamSeq, constraintEvaluators: [])
                    claimed[requestName] = claim
                    let claimResult = try await store.claim(claim)
                    XCTAssertEqual(claimResult.disposition.rawValue, want.s("disposition"), at)
                    owners[requestName] = claimResult.ownerToken
                case "finalize", "recover_direct":
                    let claim = try XCTUnwrap(claimed[requestName], at)
                    let terminal = try XCTUnwrap(Data(base64Encoded: step.s("terminal_b64")), at)
                    let body = try XCTUnwrap(Data(base64Encoded: step.s("body_b64")), at)
                    do {
                        let changed: Bool
                        if op == "finalize" {
                            changed = try await store.finalize(claimId: claim.claimId,
                                ownerToken: try XCTUnwrap(owners[requestName], at), terminalResult: terminal,
                                receiptBody: body, allowValidUntil: step["allow_valid_until"] == nil
                                    ? 0 : Int64(step.int("allow_valid_until")))
                        } else {
                            changed = try await store.recoverInterrupted(claimId: claim.claimId,
                                terminalResult: terminal, receiptBody: body)
                        }
                        XCTAssertEqual(Set(want.keys), ["finalize_result"], at)
                        XCTAssertEqual(changed ? "committed" : "identical", want.s("finalize_result"), at)
                    } catch {
                        XCTAssertEqual(Set(want.keys), ["error_class"], at)
                        XCTAssertEqual((error as? StoreError)?.errorClass?.rawValue, want.s("error_class"), at)
                    }
                case "verify":
                    XCTAssertEqual(Set(want.keys), want["recovered"] != nil ? ["stage", "error_class", "recovered"]
                        : want["error_class"] != nil ? ["stage", "error_class"]
                        : want["decision"] == nil ? ["stage", "disposition"]
                        : want["allow_horizon"] == nil ? ["stage", "decision", "decision_reason"]
                        : ["stage", "decision", "decision_reason", "allow_horizon"], at)
                    let fixtureRequest = try request(requestName, corpusName: "lifecycle-scenarios.json")
                    let currentTime = try store.now()
                    if name == "crash_after_claim_lease_recovery" && index == 6 ||
                       name == "lease_expires_during_status_then_recovery" && index == 1 ||
                       name == "late_worker_fenced_after_recovery" && index == 1 {
                        XCTAssertEqual(fixtureRequest.now, Int64(scenario.int("start_time")), at)
                        XCTAssertEqual(currentTime, 1_800_000_030, at)
                    } else if name == "clock_regression_at_claim" && index == 2 {
                        XCTAssertEqual(fixtureRequest.now, Int64(scenario.int("start_time")), at)
                        XCTAssertEqual(currentTime, 1_799_999_999, at)
                    } else if name.hasPrefix("recover_") &&
                        (index == 5 || name == "recover_direct_accepts_canonical_interrupted_body" && index == 6) {
                        XCTAssertEqual(currentTime, 1_800_000_030, at)
                    } else if name == "outbox_retained_past_challenge_expiry" && index == 5 {
                        XCTAssertEqual(fixtureRequest.now, Int64(scenario.int("start_time")), at)
                        XCTAssertEqual(currentTime, 1_800_000_290, at)
                    } else if name == "checkpoint_fork_freezes_log" && index == 6 {
                        XCTAssertEqual(fixtureRequest.now, Int64(scenario.int("start_time")), at)
                        XCTAssertEqual(currentTime, 1_800_000_007, at)
                    } else if name == "device_staged_status_goes_stale" && index == 5 {
                        XCTAssertEqual(fixtureRequest.now, Int64(scenario.int("start_time")), at)
                        XCTAssertEqual(currentTime, 1_800_003_600, at)
                    } else if name == "device_rtc_regression" && [1, 6, 13].contains(index) {
                        XCTAssertEqual(fixtureRequest.now, Int64(scenario.int("start_time")), at)
                        XCTAssertEqual(currentTime, [1: 1_800_000_010, 6: 1_800_000_005,
                            13: 1_800_000_011][index], at)
                    } else if rateStore != nil {
                        XCTAssertEqual(fixtureRequest.now, Int64(scenario.int("start_time")), at)
                        XCTAssertEqual(currentTime, rateTime, at)
                    } else { XCTAssertEqual(fixtureRequest.now, currentTime, at) }
                    let req = fixtureRequest.now == currentTime && replayEpochOverride == nil ? fixtureRequest
                        : try request(requestName, corpusName: "lifecycle-scenarios.json", atTime: currentTime,
                            replayEpochOverride: replayEpochOverride)
                    let mode = step["mode"] as? String
                    if mode != nil {
                        XCTAssertTrue(["expire_lease_during_status", "regress_clock_during_status",
                            "cancel_before_claim", "cancel_during_status", "recover_during_status"].contains(mode!), at)
                    }
                    let callbackTime = mode == nil ? nil : Int64(step.int("time"))
                    if mode == "expire_lease_during_status" { XCTAssertGreaterThan(callbackTime!, currentTime, at) }
                    if mode == "regress_clock_during_status" { XCTAssertLessThan(callbackTime!, currentTime, at) }
                    if mode == "recover_during_status" { XCTAssertGreaterThan(callbackTime!, currentTime, at) }
                    if mode == "cancel_before_claim" || mode == "cancel_during_status" {
                        XCTAssertEqual(callbackTime, currentTime, at)
                    }
                    let onFirstStatus: (@Sendable () throws -> Void)?
                    if let callbackTime, mode != "cancel_before_claim" && mode != "cancel_during_status" &&
                        mode != "recover_during_status" {
                        let statusStore = store
                        onFirstStatus = { try statusStore.setTime(callbackTime) }
                    }
                    else { onFirstStatus = nil }
                    let (trust, status, journal) = try await vectorProviders(corpus.obj("requests").obj(requestName),
                        request: req, onFirstStatus: onFirstStatus)
                    let result: VerifyOutcome
                    if mode == "cancel_before_claim" {
                        XCTAssertNil(rateStore, at)
                        let started = expectation(description: "\(at) receiver reached")
                        let receiver = GatedReceiver(started: started)
                        let verifyStore = store
                        let call = Task { try await Ratify.verifyProofBundle(req, claimStore: verifyStore,
                            receiverBinding: receiver, trust: trust, statusEvidence: status, statusJournal: journal) }
                        await fulfillment(of: [started], timeout: 10)
                        call.cancel()
                        receiver.release.signal()
                        result = try await call.value
                    } else if mode == "recover_during_status" {
                        let gate = FinalizationGate()
                        let started = expectation(description: "\(at) status reached")
                        started.assertForOverFulfill = false
                        let verifyStore = store
                        let call = Task {
                            try await Ratify.verifyProofBundle(req, claimStore: verifyStore,
                                trust: trust, statusEvidence: GatedStatus(inner: status, gate: gate, started: started),
                                statusJournal: journal)
                        }
                        await fulfillment(of: [started], timeout: 10)
                        var recoveredBodyData: Data?
                        do {
                            try store.setTime(callbackTime!)
                            let expected = try XCTUnwrap(req.expected, at)
                            let claimId = try Ratify.protocolClaimId(namespace: expected.verifierNamespace,
                                replayEpoch: expected.replayEpoch, challenge: expected.value)
                            let recovered = try await Ratify.recoverInterruptedClaim(store: store, claimId: claimId)
                            recoveredBodyData = recovered.receiptBody
                            let stored = try await store.loadCommitted(claimId: claimId)
                            XCTAssertEqual(stored.receiptBody, recovered.receiptBody, at)
                            let recoveredBody = try XCTUnwrap(JSONSerialization.jsonObject(with: recovered.receiptBody)
                                as? [String: Any], at)
                            let expectedRecovery = want.obj("recovered")
                            XCTAssertEqual(Set(expectedRecovery.keys), ["stage", "decision", "decision_reason",
                                "trust_assessment", "status_assessment", "context_assessment"], at)
                            XCTAssertEqual(expectedRecovery.s("stage"), "committed", at)
                            for field in ["decision", "decision_reason", "trust_assessment", "status_assessment", "context_assessment"] {
                                XCTAssertEqual(recoveredBody[field] as? String, expectedRecovery.s(field), at)
                            }
                            committed[requestName] = recovered
                        } catch {
                            call.cancel()
                            await gate.open()
                            _ = try? await call.value
                            throw error
                        }
                        await gate.open()
                        result = try await call.value
                        let stored = try await store.loadCommitted(claimId: result.claim.claimId)
                        XCTAssertEqual(stored.receiptBody, recoveredBodyData, at)
                    } else if mode == "cancel_during_status" {
                        XCTAssertNil(rateStore, at)
                        let gate = FinalizationGate()
                        let started = expectation(description: "\(at) status reached")
                        let verifyStore = store
                        let call = Task {
                            try await Ratify.verifyProofBundle(req, claimStore: verifyStore,
                                trust: trust, statusEvidence: GatedStatus(inner: status, gate: gate, started: started),
                                statusJournal: journal)
                        }
                        await fulfillment(of: [started], timeout: 10)
                        call.cancel()
                        await gate.open()
                        result = try await call.value
                    } else if let rateStore {
                        result = try await Ratify.verifyProofBundle(req, claimStore: rateStore, trust: trust,
                            statusEvidence: status, statusJournal: journal)
                    } else {
                        result = try await Ratify.verifyProofBundle(req, claimStore: store, trust: trust,
                            statusEvidence: status, statusJournal: journal)
                    }
                    XCTAssertEqual(result.stage.rawValue, want.s("stage"), at)
                    if let seeded = claimed[requestName] { XCTAssertEqual(result.claim, seeded, at) }
                    if want.keys.contains("error_class") {
                        XCTAssertEqual(Set(want.keys), mode == "recover_during_status"
                            ? ["stage", "error_class", "recovered"] : ["stage", "error_class"], at)
                        XCTAssertEqual(result.errorClass?.rawValue, want.s("error_class"), at)
                        if result.stage == .evaluating {
                            XCTAssertEqual(result.disposition, .created, at)
                            claimed[requestName] = result.claim
                        } else {
                            XCTAssertEqual(result.stage, .preflight, at)
                            XCTAssertNil(result.disposition, at)
                        }
                        XCTAssertNil(result.committed, at)
                    } else if want.keys.contains("disposition") {
                        XCTAssertEqual(result.disposition?.rawValue, want.s("disposition"), at)
                    } else { XCTAssertEqual(result.disposition, .created, at) }
                    if want.keys.contains("decision") {
                        let value = try XCTUnwrap(result.committed, at)
                        committed[requestName] = value
                        let body = try JSONSerialization.jsonObject(with: value.receiptBody) as! [String: Any]
                        XCTAssertEqual(body["decision"] as? String, want.s("decision"), at)
                        XCTAssertEqual(body["decision_reason"] as? String, want.s("decision_reason"), at)
                        XCTAssertEqual(value.allowHorizon, want["allow_horizon"] == nil
                            ? nil : Int64(want.int("allow_horizon")), at)
                    } else { XCTAssertNil(result.committed, at) }
                case "resume":
                    let claimId: String
                    if let override = step["claim_id"] as? String {
                        claimId = override
                    } else if let existing = committed[requestName]?.claimId ?? claimed[requestName]?.claimId {
                        claimId = existing
                    } else {
                        let expected = try XCTUnwrap(request(requestName, corpusName: "lifecycle-scenarios.json").expected, at)
                        claimId = try Ratify.protocolClaimId(namespace: expected.verifierNamespace,
                            replayEpoch: expected.replayEpoch, challenge: expected.value)
                    }
                    let resumeStore: any CommittedClaimStore = try step["claim_record_b64"] == nil
                        ? store : VectorCommittedStore(record: committedClaimFromRecord(step))
                    if want.keys.contains("error_class") {
                        XCTAssertEqual(Set(want.keys), ["error_class"], at)
                        do {
                            _ = try await Ratify.resumeCommittedClaim(store: resumeStore, claimId: claimId)
                            XCTFail("\(at): resume unexpectedly succeeded")
                        } catch let error {
                            XCTAssertEqual(error.errorClass?.rawValue, want.s("error_class"), at)
                        }
                    } else {
                        XCTAssertEqual(Set(want.keys), want.keys.contains("allow_horizon")
                            ? ["stage", "decision", "decision_reason", "allow_horizon"]
                            : ["stage", "decision", "decision_reason"], at)
                        XCTAssertEqual(want.s("stage"), "committed", at)
                        let value = try await Ratify.resumeCommittedClaim(store: resumeStore, claimId: claimId)
                        committed[requestName] = value
                        let body = try JSONSerialization.jsonObject(with: value.receiptBody) as! [String: Any]
                        XCTAssertEqual(body["decision"] as? String, want.s("decision"), at)
                        XCTAssertEqual(body["decision_reason"] as? String, want.s("decision_reason"), at)
                        XCTAssertEqual(value.allowHorizon, want.keys.contains("allow_horizon")
                            ? Int64(want.int("allow_horizon")) : nil, at)
                    }
                case "recover":
                    let claimId: String
                    if let claim = claimed[requestName] { claimId = claim.claimId }
                    else {
                        let expected = try XCTUnwrap(request(requestName, corpusName: "lifecycle-scenarios.json").expected, at)
                        claimId = try Ratify.protocolClaimId(namespace: expected.verifierNamespace,
                            replayEpoch: expected.replayEpoch, challenge: expected.value)
                    }
                    if want.keys.contains("error_class") {
                        XCTAssertEqual(Set(want.keys), ["error_class"], at)
                        do {
                            _ = try await Ratify.recoverInterruptedClaim(store: store, claimId: claimId)
                            XCTFail("\(at): recovery unexpectedly succeeded")
                        } catch let error {
                            XCTAssertEqual(error.errorClass?.rawValue, want.s("error_class"), at)
                        }
                    } else {
                        let fields = name == "resume_forged_record_allow_over_interrupted_claim" && index == 2
                            ? ["decision", "decision_reason"]
                            : ["decision", "decision_reason", "trust_assessment", "status_assessment", "context_assessment"]
                        XCTAssertEqual(Set(want.keys), Set(["stage"] + fields), at)
                        XCTAssertEqual(want.s("stage"), "committed", at)
                        let value = try await Ratify.recoverInterruptedClaim(store: store, claimId: claimId)
                        if let previous = committed[requestName] { XCTAssertEqual(value.receiptBody, previous.receiptBody, at) }
                        committed[requestName] = value
                        let body = try JSONSerialization.jsonObject(with: value.receiptBody) as! [String: Any]
                        for field in fields {
                            XCTAssertEqual(body[field] as? String, want.s(field), at)
                        }
                        XCTAssertNil(value.allowHorizon, at)
                    }
                case "abandon":
                    XCTAssertEqual(Set(want.keys), ["abandoned"], at)
                    let expectedIds = try want.strings("abandoned").map { try XCTUnwrap(committed[$0], at).claimId }
                    XCTAssertEqual(try store.abandonPendingReceipts(), expectedIds, at)
                case "publish":
                    XCTAssertEqual(Set(want.keys), want["failed"] == nil
                        ? ["receipt_sequence"] : ["failed", "publish_error"], at)
                    let mode = step.s("mode")
                    XCTAssertTrue(["ok", "signer_failure", "corrupt_signature"].contains(mode), at)
                    if mode == "signer_failure" { XCTAssertEqual(want.s("publish_error"), "signer_unavailable", at) }
                    if mode == "corrupt_signature" { XCTAssertFalse(want.keys.contains("failed"), at) }
                    let value = try XCTUnwrap(committed[requestName], at)
                    if mode == "signer_failure" { try store.setSignerFailure(true) }
                    if want.keys.contains("failed") {
                        XCTAssertTrue(want.bool("failed"), at)
                        let failureCode = want.s("publish_error")
                        let messages = ["signer_unavailable": "v2reference: receipt signer unavailable",
                            "head_of_line_blocked": "v2reference: an earlier receipt-log entry is still pending",
                            "log_frozen": "v2reference: the receipt log is frozen after abandonment"]
                        let expected = try XCTUnwrap(messages[failureCode], at)
                        if mode == "ok" { XCTAssertTrue(failureCode == "head_of_line_blocked" || failureCode == "log_frozen", at) }
                        do {
                            _ = try await store.publish(claimId: value.claimId, receiptBody: value.receiptBody)
                            XCTFail("\(at): publication unexpectedly succeeded")
                        } catch StoreError.unavailable(let detail) {
                            XCTAssertEqual(detail, expected, at)
                        }
                    } else {
                        let wire = try await store.publish(claimId: value.claimId, receiptBody: value.receiptBody)
                        if let previous = publishedWires[requestName] { XCTAssertEqual(wire, previous, at) }
                        publishedWires[requestName] = wire
                        XCTAssertEqual(try Ratify.decodeVerificationReceipt(wire).sequence,
                            Int64(want.int("receipt_sequence")), at)
                        if mode == "corrupt_signature" {
                            var receipt = try Ratify.decodeVerificationReceipt(wire)
                            receipt.signature.ed25519[receipt.signature.ed25519.startIndex] ^= 1
                            receipts[requestName] = try Ratify.encodeVerificationReceipt(receipt)
                        } else { receipts[requestName] = wire }
                    }
                    if mode == "signer_failure" { try store.setSignerFailure(false) }
                case "release":
                    let checkpointMode = step.s("checkpoint")
                    let releaseMode = step["mode"] as? String ?? ""
                    XCTAssertTrue(["", "no_receipt", "record_release_unavailable",
                        "record_release_state_mismatch"].contains(releaseMode), at)
                    XCTAssertTrue(["reference", "wrong_entry", "device"].contains(checkpointMode), at)
                    XCTAssertEqual(Set(want.keys), want["decision"] == nil
                        ? ["release_status", "release_reason"]
                        : ["release_status", "decision", "release_time", "receipt_sequence"], at)
                    let value = try XCTUnwrap(committed[requestName], at)
                    let checkpoint: any ReceiptCheckpoint = checkpointMode == "wrong_entry"
                        ? WrongEntryCheckpoint(store: store) : checkpointMode == "device"
                        ? try XCTUnwrap(device, at) : store
                    let receiptName = step.keys.contains("receipt_of") ? step.s("receipt_of") : requestName
                    if step.keys.contains("receipt_of") {
                        XCTAssertNotEqual(receiptName, requestName, at)
                        _ = try XCTUnwrap(receipts[receiptName], at)
                    }
                    let failingStore: FailingReleaseStore? = releaseMode.hasPrefix("record_release_")
                        ? FailingReleaseStore(store: store, stateMismatch: releaseMode == "record_release_state_mismatch")
                        : nil
                    let releaseStore: any ReleaseClaimStore = failingStore ?? store
                    let result = try await Ratify.releaseDecision(value,
                        signedReceipt: releaseMode == "no_receipt" ? nil : receipts[receiptName],
                        verifierPublicKey: key.publicKey, logId: logId, claimStore: releaseStore, checkpoint: checkpoint)
                    if let failingStore { XCTAssertEqual(failingStore.recordAttempts, 1, at) }
                    XCTAssertEqual(result.status.rawValue, want.s("release_status"), at)
                    if want.keys.contains("release_reason") {
                        XCTAssertEqual(result.reason, want.s("release_reason"), at)
                    } else { XCTAssertTrue(result.reason.isEmpty, at) }
                    if want.keys.contains("decision") {
                        let decision = try XCTUnwrap(result.decision, at)
                        released[requestName] = decision
                        XCTAssertEqual(decision.decision, want.s("decision"), at)
                        XCTAssertEqual(decision.receiptWire, try XCTUnwrap(receipts[requestName], at), at)
                        XCTAssertEqual(decision.releaseTime, Int64(want.int("release_time")), at)
                        XCTAssertEqual(try Ratify.decodeVerificationReceipt(decision.receiptWire).sequence,
                            Int64(want.int("receipt_sequence")), at)
                    } else { XCTAssertNil(result.decision, at) }
                case "release_forged":
                    XCTAssertEqual(Set(want.keys), ["release_status", "release_reason"], at)
                    let forged = try Store.forgedCommittedOutcome()
                    let result = try await Ratify.releaseDecision(forged, signedReceipt: nil,
                        verifierPublicKey: key.publicKey, logId: logId, claimStore: store, checkpoint: store)
                    XCTAssertEqual(result.status.rawValue, want.s("release_status"), at)
                    XCTAssertEqual(result.reason, want.s("release_reason"), at)
                    XCTAssertNil(result.decision, at)
                default:
                    XCTFail("\(at): unsupported operation")
                }
            }
        }
        Manifest.record("lifecycle-scenarios.json", scenarios.count)
    }
}
