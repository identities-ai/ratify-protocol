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

    private func request(_ name: String, evaluators: ConstraintEvaluatorRegistry? = nil) throws -> VerifyRequest {
        let corpus = Corpus.load("verifier-ordering.json")
        let vector = corpus.arr("vectors").first { $0.s("name") == name }!
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

    func testVerifierCorpusPreflightOrdering() async throws {
        let vectors = Corpus.load("verifier-ordering.json").arr("vectors").filter {
            $0.obj("expected").s("stage") == "preflight" &&
            $0.s("claim_store") != "absent"
        }
        XCTAssertEqual(vectors.count, 145)
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
            let outcome = try await Ratify.verifyProofBundle(req, claimStore: store, receiverBinding: hook)
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
        private(set) var claims = 0
        private(set) var progressWrites = 0
        private(set) var finalizations = 0
        init(onFinalize: (@Sendable () async -> Void)? = nil, claimedAt: Int64 = 1_800_000_000,
             finalizeTimeOffset: Int64 = 0, disposition: ClaimDisposition = .created) {
            self.onFinalize = onFinalize; self.claimedAt = claimedAt
            self.finalizeTimeOffset = finalizeTimeOffset; self.disposition = disposition
        }
        func authoritativeTime() -> Int64 { claimedAt }
        func claim(_ claim: ChallengeClaim) -> ClaimResult {
            claims += 1
            return ClaimResult(disposition: disposition, claimedAt: claimedAt,
                ownerToken: disposition == .created ? Data(repeating: 7, count: 32) : Data())
        }
        func finalize(claimId: String, ownerToken: Data, terminalResult: Data, receiptBody: Data,
                      allowValidUntil: Int64) async -> Bool {
            if let onFinalize { await onFinalize() }
            XCTAssertEqual(ownerToken, Data(repeating: 7, count: 32))
            XCTAssertFalse(terminalResult.isEmpty)
            XCTAssertFalse(receiptBody.isEmpty)
            if finalizeTimeOffset != 0 {
                XCTAssertGreaterThan(allowValidUntil, claimedAt + finalizeTimeOffset)
            }
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

    func testVerifierCorpusReplay() async throws {
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
        let registry: [HybridPublicKey]?
        private(set) var calls = 0
        init(key: HybridPublicKey, outcome: TrustOutcome, fails: Bool = false,
             registry: [HybridPublicKey]? = nil) {
            self.key = key; self.outcome = outcome; self.fails = fails; self.registry = registry
        }
        func resolve(chain: [DelegationCert]) throws -> TrustResolution {
            calls += 1
            if fails { throw StoreError.unavailable("scripted trust failure") }
            if let registry {
                guard let root = chain.last else { return TrustResolution(outcome: .untrusted, rootKey: key) }
                var match: HybridPublicKey?
                for candidate in registry {
                    if try Ratify.keyId(candidate) != root.issuerId &&
                        candidate.ed25519 != root.issuerPubKey.ed25519 &&
                        candidate.mlDsa65 != root.issuerPubKey.mlDsa65 { continue }
                    if match != nil { return TrustResolution(outcome: .ambiguous, rootKey: key) }
                    match = candidate
                }
                return match.map { TrustResolution(outcome: .trusted, rootKey: $0) } ??
                    TrustResolution(outcome: .untrusted, rootKey: key)
            }
            return TrustResolution(outcome: outcome, rootKey: key)
        }
    }

    actor VectorStatus: StatusEvidenceProvider {
        let byIssuer: [String: [StatusEvidenceObject]]
        let failures: Set<String>
        private(set) var requests: [StatusEvidenceRequest] = []
        init(byIssuer: [String: [StatusEvidenceObject]], failures: Set<String> = []) {
            self.byIssuer = byIssuer; self.failures = failures
        }
        func provide(_ request: StatusEvidenceRequest) throws -> [StatusEvidenceObject] {
            requests.append(request)
            if failures.contains(request.issuerId) { throw StoreError.unavailable("scripted status failure") }
            return byIssuer[request.issuerId] ?? []
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
            case "fault:timeout":
                try await Task.sleep(for: .milliseconds(100))
                return ConstraintEvaluationResult(outcome: .pass)
            default: XCTFail("Unsupported corpus evaluator: \(implementation)"); return ConstraintEvaluationResult(outcome: .invalid)
            }
        }
    }

    private func vectorProviders(_ vector: [String: Any], request req: VerifyRequest) async throws
        -> (VectorTrust, VectorStatus, VectorJournal) {
        let trustScript = vector["trust"] as? [String: Any] ?? [:]
        let root = trustScript["root_public_key"] as? [String: Any]
        let records = (trustScript["registry"] as? [[String: Any]])?.map {
            HybridPublicKey(ed25519: $0.b64("ed25519"), mlDsa65: $0.b64("ml_dsa_65"))
        }
        let trust = VectorTrust(key: root.map { HybridPublicKey(ed25519: $0.b64("ed25519"), mlDsa65: $0.b64("ml_dsa_65")) }
            ?? HybridPublicKey(ed25519: Data(), mlDsa65: Data()),
            outcome: TrustOutcome(rawValue: trustScript["outcome"] as? String ?? "") ?? .unavailable,
            fails: trustScript["mode"] as? String == "error", registry: records)
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
        return (trust, VectorStatus(byIssuer: evidence, failures: statusFailures), journal)
    }

    func testVerifierCorpusCommittedReceipts() async throws {
        let vectors = Corpus.load("verifier-ordering.json").arr("vectors").filter { vector in
            let trust = vector["trust"] as? [String: Any] ?? [:]
            let journal = vector["journal"] as? [String: Any] ?? [:]
            let evidence = vector.obj("status_evidence") as! [String: [String: Any]]
            return vector.obj("expected").s("stage") == "committed" &&
                vector.s("claim_store") == "create" &&
                (vector["trust"] is NSNull || trust["mode"] as? String == "error" ||
                    trust["mode"] as? String == "registry" ||
                    trust["mode"] as? String == "ok" &&
                    TrustOutcome(rawValue: trust["outcome"] as? String ?? "") != nil) &&
                ["ok", "error"].contains(vector.s("audience_mode")) &&
                ["absent", "reserve", "exceeded", "unavailable"].contains(vector.s("rate")) &&
                ["anchored", "absent", "unanchored", "load_error", "cas_conflict", "cas_conflict_once"]
                    .contains(journal["mode"] as? String ?? "") &&
                !(vector["constraint_evaluators"] as? [[String: Any]] ?? []).contains {
                    ["fault:panic", "fault:invalid_outcome"].contains($0.s("implementation"))
                } &&
                ["absent", "accept"].contains(vector.s("receiver_binding_hook")) &&
                evidence.values.allSatisfy { $0["mode"] as? String != "panic" }
        }
        XCTAssertEqual(vectors.count, 356)
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
            let outcome = try await Ratify.verifyProofBundle(req, claimStore: baseStore,
                receiverBinding: receiver, trust: trust, audience: audience, statusEvidence: status,
                statusJournal: journalStore, rate: rate)
            XCTAssertEqual(outcome.stage, .committed, name + ": " + (outcome.errorDetail ?? ""))
            XCTAssertEqual(outcome.committed?.receiptBody,
                Data(base64Encoded: vector.obj("expected").s("receipt_body_b64"))!, name)
            let claims = await store.claims
            let finalizations = await store.finalizations
            let progressWrites = await store.progressWrites
            let trustCalls = await trust.calls
            let statusRequests = await status.requests
            let audienceCalls = await audience.calls
            let expectedCallbacks = vector.obj("expected").obj("callback_counts")
            XCTAssertEqual(receiver?.calls ?? 0, expectedCallbacks.int("receiver_binding"), name)
            XCTAssertEqual(claims, 1, name)
            XCTAssertEqual(finalizations, 1, name)
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
