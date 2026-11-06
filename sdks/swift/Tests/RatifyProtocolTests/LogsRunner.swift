import Foundation
import RatifyProtocol

/// log-sequences.json and rotation-sequences.json through the public API
/// (model: sdks/rust/tests/v2_logs.rs).
enum LogsRunner {
    static func logSequences() throws {
        let fx = Fixture.shared
        let f = Corpus.load("log-sequences.json")
        let scenarios = f.arr("scenarios")
        precondition(scenarios.count == 2, "want witness and receipt log scenarios")
        let t = Tally("log-sequences.json")
        var expected: [(String, Int)] = []
        for sc in scenarios {
            let kind = sc.s("kind")
            let row = "log-sequences.json \(kind)"
            func genesis(_ id: String) -> WitnessHead { WitnessHead(logId: id, sequence: 0, headHash: Data(count: 48)) }
            var head = genesis(sc.s("initial_log_id"))
            var nVerify = 0
            for (n, step) in sc.arr("steps").enumerated() {
                if step.s("op") == "recover" { head = genesis(step.s("log_id")); continue }
                precondition(step.s("op") == "verify", "unknown log op")
                nVerify += 1
                let wire = step.b64("wire_b64")
                let key = fx.key(step.s("key"))
                var got: String
                var digest: Data?
                var seq: Int64 = 0
                do {
                    let r: LogResult
                    if kind == "witness_entry" {
                        let e = try Ratify.decodeWitnessEntry(wire)
                        digest = try? Ratify.witnessEntryDigest(e)
                        seq = e.sequence
                        r = try Ratify.verifyWitnessEntry(e, head: head, witnessKey: key)
                    } else {
                        let rc = try Ratify.decodeVerificationReceipt(wire)
                        digest = try? Ratify.verificationReceiptDigest(rc)
                        seq = rc.sequence
                        let rh = ReceiptHead(logId: head.logId, verifierId: sc.s("verifier_id"), sequence: head.sequence,
                                             headHash: head.headHash, acceptedDigests: head.acceptedDigests, frozen: head.frozen)
                        r = try Ratify.verifyVerificationReceipt(rc, verifierKey: key, head: rh)
                    }
                    got = r == .appended ? "appended" : "replay"
                } catch {
                    got = error.errorClass?.rawValue ?? "internal"
                }
                let want = step.s("expect")
                t.check(row, "step \(n) \(step.s("label"))", got == want, "got \(got), want \(want)")
                if got == "appended" {
                    head.sequence = seq
                    head.headHash = digest!
                    head.acceptedDigests[seq] = digest!
                } else if got == "log_fork" {
                    head.frozen = true
                }
            }
            expected.append((row, nVerify))
        }
        t.finish(expected)
    }

    static func rotationSequences() throws {
        let fx = Fixture.shared
        let f = Corpus.load("rotation-sequences.json")
        let t = Tally("rotation-sequences.json")
        var expected: [(String, Int)] = []
        for sc in f.arr("scenarios") {
            var journal = try Ratify.newKeyRotationJournal(authorityId: sc.s("authority_id"), recoveryEpoch: Int64(sc.int("recovery_epoch")),
                                                          role: sc.s("role"), genesisKey: fx.key(sc.s("genesis_key")))
            let row = "rotation-sequences.json \(sc.s("name"))"
            let steps = sc.arr("steps")
            for (n, step) in steps.enumerated() {
                var got: String
                if step.s("op") == "recover" {
                    do {
                        journal = try Ratify.recoverKeyRotation(journal, newRecoveryEpoch: Int64(step.int("new_recovery_epoch")),
                                                                newGenesisKey: fx.key(step.s("new_genesis_key")))
                        got = "recovered"
                    } catch {
                        got = error.errorClass?.rawValue ?? "internal"
                    }
                } else {
                    precondition(step.s("op") == "accept", "unknown rotation op")
                    let stmt = try Ratify.decodeKeyRotationStatement(step.b64("wire_b64"))
                    let (next, result) = try Ratify.acceptKeyRotationStatement(stmt, journal: journal, now: Int64(step.int("now")),
                                                                               futureSkew: Int64(sc.int("future_skew_seconds")))
                    journal = next
                    switch result {
                    case .success(.appended): got = "appended"
                    case .success(.replay): got = "replay"
                    case let .failure(e): got = e.errorClass?.rawValue ?? "internal"
                    }
                }
                let want = step.s("expect")
                let stateOk = journal.state.sequence == Int64(step.int("expect_sequence"))
                    && journal.state.currentKey.mlDsa65 == fx.key(step.s("expect_current_key")).mlDsa65
                    && journal.state.recoveryEpoch == Int64(step.int("expect_recovery_epoch"))
                    && journal.frozen == step.bool("expect_frozen")
                t.check(row, "step \(n) \(step.s("label"))", got == want && stateOk,
                        "got \(got) (want \(want)); seq=\(journal.state.sequence) epoch=\(journal.state.recoveryEpoch) frozen=\(journal.frozen)")
            }
            expected.append((row, steps.count))
        }
        t.finish(expected)
    }
}
