import Foundation
import RatifyProtocol

/// status-sequences.json and challenge-claim.json through the public API
/// (models: sdks/rust/tests/v2_status_sequences.rs, challenge_claim_v2.rs).
enum StatusRunner {
    static func policy(_ v: [String: Any]) -> RevocationStatusPolicy {
        RevocationStatusPolicy(maxListLifetimeSeconds: Int64(v.int("max_list_lifetime_seconds")),
                               maxStatusAgeSeconds: Int64(v.int("max_status_age_seconds")),
                               clockSkewSeconds: Int64(v.int("clock_skew_seconds")))
    }

    static func evidence(_ v: [String: Any]) -> StatusEvidenceEntry {
        StatusEvidenceEntry(issuerId: v.s("issuer_id"), statusKeyId: v.s("status_key_id"), sequence: Int64(v.int("sequence")),
                            objectType: UInt16(v.int("object_type_code")), digest: v.s("digest"))
    }

    /// Every member of an expect_state object is compared; an unknown member fails.
    static func stateMatches(_ st: RevocationStatusState, _ w: [String: Any]) -> String? {
        var checked = 0
        var problems: [String] = []
        func cmp<T: Equatable>(_ name: String, _ got: T, _ want: T?) {
            guard let want else { return }
            checked += 1
            if got != want { problems.append("\(name): got \(got), want \(want)") }
        }
        cmp("has_floor", st.hasFloor, w["has_floor"] as? Bool)
        cmp("floor", st.floor, (w["floor"] as? NSNumber)?.int64Value)
        cmp("max_observed_sequence", st.maxObservedSequence, (w["max_observed_sequence"] as? NSNumber)?.int64Value)
        cmp("fork_sequence", st.forkSequence, (w["fork_sequence"] as? NSNumber)?.int64Value)
        cmp("reconciliation_required", st.reconciliationRequired, w["reconciliation_required"] as? Bool)
        cmp("future_dated_object_observed", st.futureDatedObjectObserved, w["future_dated_object_observed"] as? Bool)
        cmp("accepted_set", st.acceptedCertIds, w["accepted_set"] as? [String])
        cmp("deny_union", st.denyUnionCertIds, w["deny_union"] as? [String])
        if checked != w.count { problems.append("expect_state has members this harness does not check") }
        return problems.isEmpty ? nil : problems.joined(separator: "; ")
    }

    static func statusSequences() throws {
        let fx = Fixture.shared
        let f = Corpus.load("status-sequences.json")
        let t = Tally("status-sequences.json")
        let scenarios = f.arr("scenarios")
        var steps = 0, queries = 0, errors = 0, bodyDigests = 0
        for sc in scenarios {
            let name = sc.s("name"), issuerId = sc.s("issuer_id")
            var state = try Ratify.emptyRevocationStatusState()
            for (n, step) in sc.arr("steps").enumerated() {
                steps += 1
                let key = fx.key(step.s("status_key"))
                let pol = (step["policy"] as? [String: Any]).map(policy) ?? policy(sc.obj("policy"))
                let epoch = UInt64(step.int("status_key_epoch"))
                let now = (step["now"] as? NSNumber)?.int64Value ?? 0
                let op = step.s("op"), label = step["label"] as? String ?? ""
                let id = "\(name) step \(n) \(op) \(label)"
                let next: Result<RevocationStatusState, RatifyError>
                switch op {
                case "apply_list":
                    next = Result { () throws(RatifyError) in
                        try Ratify.applyRevocationList(state, try Ratify.decodeRevocationList(step.b64("wire_b64")), boundIssuerId: issuerId,
                                                       statusKeyEpoch: epoch, statusKey: key, policy: pol, now: now)
                    }
                case "apply_push":
                    next = Result { () throws(RatifyError) in
                        try Ratify.applyRevocationPush(state, try Ratify.decodeRevocationPush(step.b64("wire_b64")), boundIssuerId: issuerId,
                                                       statusKeyEpoch: epoch, statusKey: key, policy: pol, now: now)
                    }
                case "transition_epoch":
                    next = Result { () throws(RatifyError) in
                        try Ratify.transitionRevocationStatusEpoch(state, issuerId: issuerId, nextEpoch: epoch, nextStatusKey: key)
                    }
                case "query":
                    queries += 1
                    let certId = step.s("cert_id")
                    let r = try Ratify.revocationStatusForCert(state, issuerId: issuerId, certId: certId, statusKeyEpoch: epoch,
                                                               statusKey: key, policy: pol, now: now)
                    let want = step.obj("expect_result")
                    let wantEvidence = want.arr("evidence").map(evidence)
                    t.check("steps", id, r.status == want.s("status") && r.reason == (want["reason"] as? String ?? "") && r.evidence == wantEvidence,
                            "\(r.status)/\(r.reason) evidence \(r.evidence.count)")
                    continue
                default:
                    preconditionFailure("unknown op \(op)")
                }
                if let cls = step["expect_error_class"] as? String {
                    errors += 1
                    var got = "ok"
                    if case let .failure(e) = next { got = e.errorClass?.rawValue ?? "internal" }
                    t.check("steps", id, got == cls, "class \(got), want \(cls)")
                    continue
                }
                guard case let .success(s) = next else {
                    t.check("steps", id, false, "\(next)")
                    continue
                }
                state = s
                var ok = true
                var detail = ""
                if let w = step["expect_state"] as? [String: Any], let problem = stateMatches(state, w) {
                    ok = false
                    detail = problem
                }
                // SPEC-v2 §6.6: the observation's body_digest is the unlabelled SHA-384 of the canonical signable body.
                if let want = step["expect_body_digest"] as? String {
                    bodyDigests += 1
                    let code: UInt16 = op == "apply_push" ? 5 : 3
                    if !state.observations.contains(where: { $0.statusKeyEpoch == epoch && $0.objectType == code && "sha384:\($0.bodyDigest.hex)" == want }) {
                        ok = false
                        detail += " no observation with body_digest \(want)"
                    }
                }
                t.check("steps", id, ok, detail)
            }
        }
        precondition(scenarios.count == 22 && steps == 112, "status-sequences shape changed")
        precondition(queries == 43 && errors == 3 && bodyDigests == 63, "status-sequences counts changed")
        t.finish([("steps", steps)])
    }

    static func challengeClaim() throws {
        let v = Corpus.load("challenge-claim.json")
        let t = Tally("challenge-claim.json")
        let challenge = v.hex("challenge_hex")
        let digest = try Ratify.challengeClaimDigest(challenge)
        t.check("claim", "digest", digest.hex == v.s("expected_challenge_claim_digest_hex"))
        var cases = [v.obj("claim_id_input").merging(["expected_claim_id": v.s("expected_claim_id")]) { a, _ in a }]
        cases += v.arr("additional_claim_id_cases")
        for c in cases {
            let ns = c.s("verifier_namespace"), epoch = Int64(c.int("replay_epoch"))
            let want = c.s("expected_claim_id")
            t.check("claim", "\(ns)/\(epoch)", try Ratify.protocolClaimId(namespace: ns, replayEpoch: epoch, challenge: challenge) == want
                        && Ratify.protocolClaimId(namespace: ns, replayEpoch: epoch, digest: digest) == want)
        }
        // Bad lengths and epochs are refused.
        for len in [0, 31, 33] { t.check("refusals", "challenge \(len)", classOf { _ = try Ratify.challengeClaimDigest(Data(count: len)) } != "ok") }
        let zero = Data(count: 32)
        t.check("refusals", "empty namespace", classOf { _ = try Ratify.protocolClaimId(namespace: "", replayEpoch: 7, challenge: zero) } != "ok")
        t.check("refusals", "epoch 2^53", classOf { _ = try Ratify.protocolClaimId(namespace: "verify-prod", replayEpoch: 1 << 53, challenge: zero) } != "ok")
        for len in [0, 47, 49] {
            t.check("refusals", "digest \(len)", classOf { _ = try Ratify.protocolClaimId(namespace: "verify-prod", replayEpoch: 7, digest: Data(count: len)) } != "ok")
        }
        t.finish([("claim", 1 + cases.count), ("refusals", 8)])
    }
}
