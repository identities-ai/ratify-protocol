import Foundation
import RatifyProtocol

/// status-publisher.json through the public signer, journal and publisher APIs.
enum PublisherRunner {
    static func run() async throws {
        let v = Corpus.load("status-publisher.json")
        let t = Tally("status-publisher.json")
        var steps = 0
        for scenario in v.arr("scenarios") {
            for external in [false, true] {
                steps += try await runScenario(scenario, policy: StatusRunner.policy(v.obj("status_policy")), external: external, t)
            }
        }
        precondition(v.arr("scenarios").count == 13 && steps == 78)
        t.finish([("setup", 26), ("construction", 26), ("steps", 78)])
    }

    private static func runScenario(_ scenario: [String: Any], policy: RevocationStatusPolicy,
                                    external: Bool, _ t: Tally) async throws -> Int {
        let store = try JournalRunner.Store()
        let fx = Fixture.shared
        for role in scenario.arr("role_keys") {
            _ = try await Ratify.recordSecurityKeyRole(store: store, role: role.s("role"), key: fx.key(role.s("key")))
        }
        let issuer = scenario.s("issuer")
        let statusKey = scenario.s("status_key")
        let configuredFor = scenario.s("status_configured_for")
        var setupRejected = false
        if !configuredFor.isEmpty {
            do {
                _ = try await Ratify.configureStatusKeyEpoch(store: store, issuerId: fx.keyId(configuredFor),
                    epoch: 1, key: fx.key(statusKey))
            } catch {
                guard error.errorClass == .statusObjectRejected else { throw error }
                setupRejected = true
            }
        }
        t.check("setup", scenario.s("name"), setupRejected == (scenario.s("journal_setup") == "rejected"))
        let signer = ProviderSigner(statusKey)
        let publisher: StatusPublisher?
        do {
            if external {
                publisher = try await Ratify.newStatusPublisher(store: store, issuerKey: fx.key(issuer),
                    statusSigner: signer, lifetimeSeconds: Int64(scenario.int("lifetime_seconds")))
            } else {
                publisher = try await Ratify.newStatusPublisher(store: store, issuerKey: fx.key(issuer),
                    statusKey: fx.privateKey(statusKey), lifetimeSeconds: Int64(scenario.int("lifetime_seconds")))
            }
        } catch {
            guard error.errorClass == .configurationInvalid else { throw error }
            publisher = nil
        }
        t.check("construction", scenario.s("name"), (publisher != nil) == (scenario.s("publisher") == "ok")
            && (publisher == nil || (publisher!.issuerId == fx.keyId(issuer) && publisher!.statusKey == fx.key(statusKey)))
            && (!external || publisher != nil || signer.signCalls == 0))
        guard let publisher else { return 0 }
        var state: StatusPublisherState?
        var publications: [StatusPublication] = []
        var count = 0
        for step in scenario.arr("steps") {
            count += 1
            let op = step.s("op")
            let expect = step.obj("expect")
            let at = Int64(step.int("at"))
            switch op {
            case "genesis", "heartbeat", "revoke":
                var output: StatusPublication?
                do {
                    switch op {
                    case "genesis": output = try await publisher.genesis(updatedAt: at)
                    case "heartbeat": output = try await publisher.heartbeat(state: state!, updatedAt: at)
                    default: output = try await publisher.revoke(state: state!, certIds: step["cert_ids"] as? [String] ?? [], at: at)
                    }
                } catch {
                    guard error.errorClass == .configurationInvalid else { throw error }
                    output = nil
                }
                if let output {
                    let list = expect.obj("list")
                    let expectedPush = expect["push"] as? [String: Any]
                    let matches = expect.s("result") == "published" && output.list.sequence == Int64(list.int("sequence"))
                        && output.list.updatedAt == Int64(list.int("updated_at"))
                        && output.list.nextUpdate == Int64(list.int("next_update"))
                        && output.list.revoked == list.strings("revoked")
                        && output.state.sequence == output.list.sequence
                        && output.state.updatedAt == output.list.updatedAt
                        && output.state.issuerId == fx.keyId(issuer)
                        && output.state.statusKeyId == fx.keyId(statusKey)
                        && output.state.revoked == output.list.revoked
                        && (expectedPush == nil ? output.push == nil :
                            output.push?.sequence == Int64(expectedPush!.int("sequence"))
                            && output.push?.pushedAt == Int64(expectedPush!.int("pushed_at"))
                            && output.push?.revoked == expectedPush!.strings("revoked"))
                    t.check("steps", "\(scenario.s("name")) \(count)", matches)
                    try Ratify.verifyRevocationListSignature(output.list, trustedIssuerId: fx.keyId(issuer), statusKey: fx.key(statusKey))
                    if let push = output.push {
                        try Ratify.verifyRevocationPushSignature(push, trustedIssuerId: fx.keyId(issuer), statusKey: fx.key(statusKey))
                    }
                    state = output.state
                    publications.append(output)
                } else {
                    t.check("steps", "\(scenario.s("name")) \(count)", expect.s("result") == "refused")
                }
            case "ingest":
                let publication = publications[step.int("publication")]
                if step.s("object") == "list" {
                    _ = try await Ratify.applyRevocationListToJournal(store: store, list: publication.list,
                        issuerId: fx.keyId(issuer), epoch: 1, key: fx.key(statusKey), policy: policy, now: at)
                } else {
                    _ = try await Ratify.applyRevocationPushToJournal(store: store, push: publication.push!,
                        issuerId: fx.keyId(issuer), epoch: 1, key: fx.key(statusKey), policy: policy, now: at)
                }
                t.check("steps", "\(scenario.s("name")) \(count)", expect.s("result") == "applied")
            case "status":
                let result = try await Ratify.revocationStatusFromJournal(store: store, issuerId: fx.keyId(issuer),
                    certId: step.s("cert_id"), epoch: 1, key: fx.key(statusKey), policy: policy, now: at)
                t.check("steps", "\(scenario.s("name")) \(count)", result.status == expect.s("status")
                    && result.reason == (expect["reason"] as? String ?? ""))
            default: preconditionFailure("unknown status publisher operation \(op)")
            }
        }
        return count
    }
}
