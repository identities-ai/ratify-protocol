import Foundation
import RatifyProtocol

enum TransactionVerifyRunner {
    struct Trust: TrustProvider {
        let outcome: TrustOutcome
        let key: HybridPublicKey
        func resolve(chain: [DelegationCert]) -> TrustResolution {
            TrustResolution(outcome: outcome, rootKey: key)
        }
    }

    struct Status: StatusEvidenceProvider {
        let byIssuer: [String: [StatusEvidenceObject]]
        func provide(_ request: StatusEvidenceRequest) -> [StatusEvidenceObject] {
            byIssuer[request.issuerId] ?? []
        }
    }

    actor Journal: SecurityJournalStore {
        private var current: SecurityJournalSnapshot
        init(_ initial: SecurityJournalSnapshot) { current = initial }
        func load() -> SecurityJournalSnapshot { current }
        func compareAndSwap(expected: SecurityJournalHead, next: SecurityJournalSnapshot) throws {
            guard current.head == expected else { throw SecurityJournalStoreError.conflict }
            current = next
        }
    }

    static func run() async throws {
        let vectors = Corpus.load("transaction-verification.json").arr("vectors")
        let tally = Tally("transaction-verification.json")
        for v in vectors {
            let name = v.s("name")
            let journalScript = v.obj("journal")
            let evidenceScripts = v.obj("status_evidence")
            guard journalScript.s("mode") == "anchored",
                  journalScript.arr("preload").isEmpty, journalScript["setup"] == nil,
                  (v["trust"] as? [String: Any]).map({ $0.s("mode") == "ok" }) ?? true,
                  evidenceScripts.values.allSatisfy({ ($0 as! [String: Any]).s("mode") == "ok" }) else {
                tally.check("vectors", name, false, "unsupported fixture mode")
                continue
            }
            let policy = v.obj("status_policy")
            let keys = v.obj("status_keys").mapValues { item -> StatusKeyConfig in
                let k = item as! [String: Any]
                return StatusKeyConfig(epoch: UInt64(k.int("epoch")), key: publicKey(k.obj("public_key")))
            }
            let request = TransactionVerifyRequest(receipt: v.b64("receipt_b64"), now: Int64(v.int("now")),
                futureSkewSeconds: Int64(v.int("future_skew_seconds")), statusKeys: keys,
                statusPolicy: RevocationStatusPolicy(maxListLifetimeSeconds: Int64(policy.int("max_list_lifetime_seconds")),
                    maxStatusAgeSeconds: Int64(policy.int("max_status_age_seconds")),
                    clockSkewSeconds: Int64(policy.int("clock_skew_seconds"))))
            let journal = try Journal(Ratify.emptySecurityJournalSnapshot())
            for issuer in keys.keys.sorted() {
                let k = keys[issuer]!
                _ = try await Ratify.configureStatusKeyEpoch(store: journal, issuerId: issuer, epoch: k.epoch, key: k.key)
            }
            let scripts = v.obj("status_evidence")
            let byIssuer = scripts.mapValues { value -> [StatusEvidenceObject] in
                let script = value as! [String: Any]
                return script.arr("objects").map {
                    StatusEvidenceObject(objectType: UInt16($0.int("object_type_code")), wire: $0.b64("wire_b64"))
                }
            }
            let trust: Trust? = (v["trust"] as? [String: Any]).map { t in
                Trust(outcome: TrustOutcome(rawValue: t.s("outcome"))!,
                    key: (t["root_public_key"] as? [String: Any]).map(publicKey)
                        ?? HybridPublicKey(ed25519: Data(), mlDsa65: Data()))
            }
            let expected = v.obj("expected")
            do {
                let got = try await Ratify.verifyTransactionReceipt(request, trust: trust,
                    statusEvidence: Status(byIssuer: byIssuer), statusJournal: journal)
                if let error = expected["error_class"] as? String, !error.isEmpty {
                    tally.check("vectors", name, false, "expected \(error), got success")
                    continue
                }
                let result = expected.obj("result")
                let wantParties = result.arr("parties")
                let partiesMatch = got.parties.count == wantParties.count && zip(got.parties, wantParties).allSatisfy { p, w in
                    let evidence = w.arr("status_evidence_digests")
                    return p.partyId == w.s("party_id") && p.agentId == w.s("agent_id")
                        && p.requiredScope == w.s("required_scope")
                        && p.trustAssessment == w.s("trust_assessment")
                        && p.delegationAssessment == w.s("delegation_assessment")
                        && p.delegationExpiresAt == (w["delegation_expires_at"] as? NSNumber)?.int64Value
                        && p.statusAssessment == w.s("status_assessment")
                        && p.scopeAssessment == w.s("scope_assessment") && p.freshness == w.s("freshness")
                        && p.statusEvidence.count == evidence.count
                        && zip(p.statusEvidence, evidence).allSatisfy { e, x in
                            e.issuerId == x.s("issuer_id") && e.statusKeyId == x.s("status_key_id")
                                && e.sequence == Int64(x.int("sequence")) && e.objectType == UInt16(x.int("object_type_code"))
                                && e.digest == x.s("digest")
                        }
                }
                tally.check("vectors", name, got.transactionId == result.s("transaction_id")
                    && got.actionable == result.bool("actionable") && !got.actionable && partiesMatch)
            } catch {
                let wantError = expected["error_class"] as? String
                tally.check("vectors", name, wantError != nil && error.errorClass?.rawValue == wantError,
                    "got \(String(describing: error.errorClass))")
            }
        }
        tally.finish([("vectors", 13)])
    }
}
