import Foundation
import RatifyProtocol

/// security-journal.json through the public store callbacks and snapshot API.
enum JournalRunner {
    actor Store: SecurityJournalStore {
        private var state: SecurityJournalSnapshot
        init() throws { state = try Ratify.emptySecurityJournalSnapshot() }
        func load() -> SecurityJournalSnapshot { state }
        func compareAndSwap(expected: SecurityJournalHead, next: SecurityJournalSnapshot) throws {
            guard state.head == expected else { throw SecurityJournalStoreError.conflict }
            try Ratify.validateSecurityJournalTransition(current: state, next: next)
            state = next
        }
    }

    static func head(_ v: [String: Any]) -> SecurityJournalHead {
        SecurityJournalHead(generation: UInt64(v.int("generation")), digest: v.s("digest"))
    }

    static func run() async throws {
        let v = Corpus.load("security-journal.json")
        let t = Tally("security-journal.json")
        let genesis = try Ratify.emptySecurityJournalSnapshot()
        t.check("genesis", "snapshot", String(decoding: genesis.snapshot, as: UTF8.self) == v.s("genesis_snapshot")
                && genesis.head.digest == v.s("genesis_digest"))
        let steps = try await runScenarios(v.arr("scenarios"), t)
        try runMigration(v.obj("migration"), t)
        try runNegatives(v, t)
        precondition(steps == 17 && v.arr("import_negatives").count == 20 && v.arr("transition_negatives").count == 6)
        t.finish([("genesis", 1), ("steps", steps), ("query", 2), ("migration", 2),
                  ("import", 20), ("transition", 6)])
    }

    private static func runScenarios(_ scenarios: [[String: Any]], _ t: Tally) async throws -> Int {
        var steps = 0
        for scenario in scenarios {
            let store = try Store()
            for (index, step) in scenario.arr("steps").enumerated() {
                steps += 1
                let before = await store.load()
                var gotError = false
                do {
                    try await apply(step, store)
                } catch {
                    gotError = true
                }
                let after = await store.load()
                t.check("steps", "\(scenario.s("name")) \(index)",
                    gotError == (step["expect_rejected"] as? Bool ?? false)
                    && (before.head != after.head) == step.bool("expect_changed")
                    && after.head == head(step.obj("expect_head"))
                    && after.snapshot == step.b64("expect_snapshot_b64"))
                try Ratify.validateSecurityJournalSnapshot(after.snapshot, head: after.head)
            }
            if scenario.s("name") == "status_reducer_transitions" {
                let last = scenario.arr("steps").last!
                let key = publicKey(last.obj("key").obj("public_key"))
                for (certId, expected) in [("c1", "revoked"), ("unlisted", "not_revoked")] {
                    let result = try await Ratify.revocationStatusFromJournal(store: store,
                        issuerId: last.s("issuer_id"), certId: certId, epoch: UInt64(last.int("epoch")),
                        key: key, policy: StatusRunner.policy(last.obj("policy")), now: Int64(last.int("now")))
                    t.check("query", certId, result.status == expected && !result.evidence.isEmpty)
                }
            }
        }
        return steps
    }

    private static func apply(_ step: [String: Any], _ store: Store) async throws {
        let key = publicKey(step.obj("key").obj("public_key"))
        switch step.s("op") {
        case "record_key_role":
            _ = try await Ratify.recordSecurityKeyRole(store: store, role: step.s("role"), key: key)
        case "configure_status_key_epoch":
            _ = try await Ratify.configureStatusKeyEpoch(store: store, issuerId: step.s("issuer_id"),
                                                          epoch: UInt64(step.int("epoch")), key: key)
        case "apply_revocation_list":
            _ = try await Ratify.applyRevocationListToJournal(store: store,
                list: Ratify.decodeRevocationList(step.b64("wire_b64")), issuerId: step.s("issuer_id"),
                epoch: UInt64(step.int("epoch")), key: key, policy: StatusRunner.policy(step.obj("policy")),
                now: Int64(step.int("now")))
        case "apply_revocation_push":
            _ = try await Ratify.applyRevocationPushToJournal(store: store,
                push: Ratify.decodeRevocationPush(step.b64("wire_b64")), issuerId: step.s("issuer_id"),
                epoch: UInt64(step.int("epoch")), key: key, policy: StatusRunner.policy(step.obj("policy")),
                now: Int64(step.int("now")))
        default: preconditionFailure("unknown journal operation \(step.s("op"))")
        }
    }

    private static func runMigration(_ m: [String: Any], _ t: Tally) throws {
        let migrated = try Ratify.migrateSecurityJournalJSON(m.b64("legacy_record_b64"))
        t.check("migration", "valid", migrated.head == head(m.obj("expect_head"))
                && migrated.snapshot == m.b64("expect_snapshot_b64"))
        t.check("migration", "tampered", classOf {
            _ = try Ratify.migrateSecurityJournalJSON(m.b64("tampered_legacy_record_b64"))
        } == "configuration_invalid")
    }

    private static func runNegatives(_ v: [String: Any], _ t: Tally) throws {
        for negative in v.arr("import_negatives") {
            t.check("import", negative.s("name"), classOf {
                try Ratify.validateSecurityJournalSnapshot(negative.b64("snapshot_b64"), head: head(negative.obj("head")))
            } == negative.s("expect_error_class"))
        }
        for negative in v.arr("transition_negatives") {
            let current = SecurityJournalSnapshot(snapshot: negative.b64("current_snapshot_b64"), head: head(negative.obj("current_head")))
            let next = SecurityJournalSnapshot(snapshot: negative.b64("next_snapshot_b64"), head: head(negative.obj("next_head")))
            t.check("transition", negative.s("name"), classOf {
                try Ratify.validateSecurityJournalTransition(current: current, next: next)
            } == negative.s("expect_error_class"))
        }
    }
}
