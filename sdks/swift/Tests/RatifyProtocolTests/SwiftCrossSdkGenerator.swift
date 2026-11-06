import CryptoKit
import Foundation
import RatifyProtocol
import RatifyProtocolTestSupport
import XCTest

/// Fixture authoring uses only the public SDK for keys, signatures and digests.
struct SwiftCrossSdkGenerator {
    static let now: Int64 = 1_800_000_000
    static let workspace = "00000000-0000-4000-8000-000000000001"
    static let names = ["root", "intermediate", "agent", "verifier", "status_root", "status_intermediate",
                        "witness", "party_b_root", "party_b_agent", "rotation_genesis", "rotation_second"]
    static let emptySignature = HybridSignature(ed25519: Data(), mlDsa65: Data())

    private var keys: [String: SoftwarePrivateKey] = [:]
    private var entries: [[String: Any]] = []
    private var objects: [[String: Any]] = []

    init() throws {
        for name in Self.names {
            let edSeed = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
            let mlSeed = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
            let key = try SoftwarePrivateKey(ed25519Seed: edSeed, mlDsa65Seed: mlSeed)
            keys[name] = key
            entries.append(["name": name, "ed25519_seed_hex": edSeed.hex, "ml_dsa_65_seed_hex": mlSeed.hex,
                "public_key": Self.json(key.publicKey), "key_id_v2": key.keyId,
                "v1_key_id_128": String(sha256(key.publicKey.ed25519 + key.publicKey.mlDsa65).hex.prefix(32))])
        }
    }

    private func key(_ name: String) -> SoftwarePrivateKey { keys[name]! }
    private func id(_ name: String) -> String { key(name).keyId }
    private func pub(_ name: String) -> HybridPublicKey { key(name).publicKey }
    private static func json(_ key: HybridPublicKey) -> [String: String] {
        ["ed25519": key.ed25519.base64EncodedString(), "ml_dsa_65": key.mlDsa65.base64EncodedString()]
    }
    private static func json(_ signature: HybridSignature) -> [String: String] {
        ["ed25519": signature.ed25519.base64EncodedString(), "ml_dsa_65": signature.mlDsa65.base64EncodedString()]
    }

    private func signatureRecord(_ wire: Data, field: String, code: UInt16, signer: String) throws -> [String: Any] {
        let obj = try JSONSerialization.jsonObject(with: wire) as! [String: Any]
        let carried: [String: Any]
        if field.hasPrefix("delegations[") {
            let index = Int(field.dropFirst("delegations[".count).prefix { $0.isNumber })!
            carried = (obj["delegations"] as! [[String: Any]])[index]["signature"] as! [String: Any]
        } else if field.hasPrefix("party_signatures[") {
            let party = String(field.dropFirst("party_signatures[".count).dropLast())
            carried = (obj["party_signatures"] as! [[String: Any]]).first { $0["party_id"] as? String == party }!["signature"] as! [String: Any]
        } else {
            carried = obj[field] as! [String: Any]
        }
        let signable = try projection(wire, field)
        let type = ObjectType(rawValue: code)!
        try Ratify.verifyStatement(type, signable: signable,
            signature: hybridSignature(carried), publicKey: pub(signer))
        let message = try Ratify.signingMessage(type, signable: signable)
        let context = try Ratify.mldsaContext(type)
        let ml = pub(signer).mlDsa65
        return ["field": field, "object_type_code": Int(code), "signer": signer, "signer_key_id_v2": id(signer),
                "signable_b64": signable.base64EncodedString(), "signable_sha384_hex": sha384(signable).hex,
                "message_b64": message.base64EncodedString(), "mldsa_context": String(data: context, encoding: .utf8)!,
                "mldsa_tr_b64": Shake256.hash(ml, outputLength: 64).base64EncodedString(),
                "mldsa_mu_b64": try Ratify.externalMu(mlDsaPublicKey: ml, mlDsaContext: context, message: message).base64EncodedString(),
                "signature": carried]
    }

    private mutating func add(_ name: String, _ kind: String, _ description: String, _ wire: Data,
                              _ fields: [(String, UInt16, String)], _ digests: [String: Any],
                              verify: [String: Any] = [:], bundle: Data? = nil) throws {
        var item: [String: Any] = ["name": name, "kind": kind, "description": description,
            "wire_b64": wire.base64EncodedString(), "verify": verify, "digests": digests,
            "signatures": try fields.map { try signatureRecord(wire, field: $0.0, code: $0.1, signer: $0.2) }]
        if let bundle { item["bundle_b64"] = bundle.base64EncodedString() }
        if kind == "receipt_bundle_binding" {
            try verifyObject(kind, wire, bundle: bundle!, verify, key: pub)
        } else {
            guard try reencode(kind, wire) == wire else { throw GeneratorError.invalid("\(name): noncanonical wire") }
            try verifyObject(kind, wire, bundle: Data(), verify, key: pub)
        }
        objects.append(item)
    }

    private func cert(_ issuer: String, _ subject: String, _ certId: String, _ scope: [String],
                      constraints: [Constraint] = []) throws -> DelegationCert {
        try Ratify.signDelegationCert(DelegationCert(version: 2, certId: certId, issuerId: id(issuer),
            issuerPubKey: pub(issuer), subjectId: id(subject), subjectPubKey: pub(subject), scope: scope,
            constraints: constraints, issuedAt: Self.now - 3600, expiresAt: Self.now + 86400,
            signature: Self.emptySignature), key: key(issuer))
    }

    private func bundle(_ agent: String, _ certs: [DelegationCert], _ session: Data?,
                        challenge: Data = Data(0xA0...0xBF), streamId: Data? = nil, streamSeq: Int64? = nil) throws -> ProofBundle {
        try Ratify.signProofBundle(ProofBundle(version: 2, verifierId: id("verifier"), agentId: id(agent),
            agentPubKey: pub(agent), delegations: certs, delegationDigest: Data(repeating: 0, count: 48),
            challenge: challenge, challengeAt: Self.now - 10, challengeSig: Self.emptySignature,
            sessionContext: session, streamId: streamId, streamSeq: streamSeq), key: key(agent))
    }

    private func statusList(_ issuer: String, _ statusKey: String, sequence: Int64, next: Int64,
                            revoked: [String]) throws -> RevocationList {
        try Ratify.signRevocationList(RevocationList(version: 2, issuerId: id(issuer), updatedAt: Self.now - 60,
            nextUpdate: next, sequence: sequence, revoked: revoked, signature: Self.emptySignature),
            boundIssuerId: id(issuer), boundStatusKey: pub(statusKey), key: key(statusKey))
    }

    private static func constraint(_ kind: String, start: String = "", end: String = "", tz: String = "",
                                   currency: String = "", amount: Int64 = 0, count: Int64 = 0,
                                   window: Int64 = 0, resource: String = "", path: String = "",
                                   params: [String: ParamsValue]? = nil) -> Constraint {
        Constraint(kind: kind, start: start, end: end, tz: tz, currency: currency,
            maxAmountMicros: amount, count: count, windowS: window, resourceId: resource,
            pathPrefix: path, params: params)
    }

    private mutating func buildObjects() throws -> (ProofBundle, ProofBundle, DelegationCert, DelegationCert,
                                                     RevocationList, RevocationList, Data) {
        let root = try cert("root", "intermediate", "cert-root", ["data:read", "files:read", "identity:delegate"])
        let rootWire = try Ratify.encodeDelegationCert(root)
        try add("delegation_root_to_intermediate", "delegation_certificate", "Root delegates to an intermediate.",
            rootWire, [("signature", 1, "root")], ["issuer_key_id_v2": id("root"),
            "subject_key_id_v2": id("intermediate")])
        let constrained = try cert("intermediate", "agent", "cert-leaf-constrained", ["data:read"], constraints: [
            Self.constraint("max_rate", count: 5, window: 60),
            Self.constraint("ratify.receiver_audience", params: [
                "exact_receiver_ids": .array([.string("receiver-1")]),
                "trust_domain_ids": .array([.string("domain-a")]),
                "max_membership_age_seconds": .int(3600)]),
            Self.constraint("resource_path", resource: "customer/123", path: "/v1/customers/"),
            Self.constraint("time_window", start: "22:00", end: "06:00", tz: "America/New_York"),
            Self.constraint("max_amount", currency: "USD", amount: 2_500_000),
            Self.constraint("com.ratifyprotocol.max_count", params: ["counter": .string("nodes"), "max": .int(10)]),
        ])
        let constrainedWire = try Ratify.encodeDelegationCert(constrained)
        try add("delegation_every_registered_constraint_and_extension", "delegation_certificate",
            "Every registered constraint and one extension.", constrainedWire,
            [("signature", 1, "intermediate")], ["issuer_key_id_v2": id("intermediate"),
            "subject_key_id_v2": id("agent")])

        let operation = OperationContext(requiredScope: "data:read", operation: "records.get",
            resourceId: "customer/123", requestedPath: "/v1/customers/123")
        let session = try Ratify.buildSessionContext(SessionContextInputs(verifierId: id("verifier"),
            workspaceId: Self.workspace, agentId: id("agent"), sessionId: "session-01",
            invocationId: "invocation-01", requestHash: Ratify.operationContextHash(operation)))
        let leaf = try cert("intermediate", "agent", "cert-leaf", ["data:read", "files:read"])
        let plain = try bundle("agent", [leaf, root], session)
        let plainWire = try Ratify.encodeProofBundle(plain)
        let plainDigests: [String: Any] = ["delegation_digest_hex": plain.delegationDigest.hex,
            "bundle_hash_v2": try Ratify.bundleHash(plain), "session_context_hex": session.hex,
            "challenge_claim_digest_hex": try Ratify.challengeClaimDigest(plain.challenge).hex,
            "claim_id": try Ratify.protocolClaimId(namespace: "verify-test", replayEpoch: 3, challenge: plain.challenge),
            "claim_verifier_namespace": "verify-test", "claim_replay_epoch": "3"]
        let chainFields: [(String, UInt16, String)] = [("challenge_sig", 2, "agent"),
            ("delegations[0].signature", 1, "intermediate"), ("delegations[1].signature", 1, "root")]
        try add("proof_bundle_two_link_bound_context", "proof_bundle", "Two-link chain with session context.",
            plainWire, chainFields, plainDigests)
        let extended = try bundle("agent", [constrained, root], session, challenge: Data(0xB0...0xCF))
        let extendedWire = try Ratify.encodeProofBundle(extended)
        try add("proof_bundle_constrained_chain", "proof_bundle", "Constrained chain with session context.",
            extendedWire, chainFields, ["delegation_digest_hex": extended.delegationDigest.hex,
                "bundle_hash_v2": try Ratify.bundleHash(extended), "session_context_hex": session.hex])
        let stream = try bundle("agent", [], nil, streamId: Data(repeating: 0x5a, count: 32), streamSeq: 1)
        let streamWire = try Ratify.encodeProofBundle(stream)
        try add("proof_bundle_empty_chain_stream_bound", "proof_bundle", "Empty chain with a stream bound.",
            streamWire, [("challenge_sig", 2, "agent")], ["delegation_digest_hex": stream.delegationDigest.hex,
                "bundle_hash_v2": try Ratify.bundleHash(stream)])

        let rootList = try statusList("root", "status_root", sequence: 7, next: Self.now + 3600,
            revoked: ["cert-a", "cert-b"])
        let rootListWire = try Ratify.encodeRevocationList(rootList)
        try add("revocation_list_root", "revocation_list", "Root issuer status snapshot.", rootListWire,
            [("signature", 3, "status_root")],
            ["status_evidence_digest": "sha384:" + (try Ratify.statusEvidenceDigest(rootList)).hex],
            verify: ["bound_issuer_id": id("root"), "status_key": "status_root"])
        let intermediateList = try statusList("intermediate", "status_intermediate", sequence: 1,
            next: Self.now + 3600, revoked: [])
        let intermediateWire = try Ratify.encodeRevocationList(intermediateList)
        try add("revocation_list_intermediate_empty", "revocation_list", "Empty intermediate issuer status snapshot.",
            intermediateWire, [("signature", 3, "status_intermediate")],
            ["status_evidence_digest": "sha384:" + (try Ratify.statusEvidenceDigest(intermediateList)).hex],
            verify: ["bound_issuer_id": id("intermediate"), "status_key": "status_intermediate"])
        let push = try Ratify.signRevocationPush(RevocationPush(version: 2, issuerId: id("root"), sequence: 8,
            pushedAt: Self.now - 30, revoked: ["cert-c"], signature: Self.emptySignature),
            boundIssuerId: id("root"), boundStatusKey: pub("status_root"), key: key("status_root"))
        let pushWire = try Ratify.encodeRevocationPush(push)
        try add("revocation_push", "revocation_push", "Root issuer status push.", pushWire,
            [("signature", 5, "status_root")],
            ["status_evidence_digest": "sha384:" + (try Ratify.statusEvidenceDigest(push)).hex],
            verify: ["bound_issuer_id": id("root"), "status_key": "status_root"])
        return (plain, extended, root, leaf, rootList, intermediateList, session)
    }

    private mutating func buildStatements(plain: ProofBundle, extended: ProofBundle,
                                          rootList: RevocationList, intermediateList: RevocationList) throws {
        let zeros = Data(repeating: 0, count: 48)
        let authority = "0123456789abcdef0123456789abcdef"
        let rotation = try Ratify.signKeyRotationStatement(KeyRotationStatement(version: 2,
            authorityId: authority, recoveryEpoch: 1, role: "issuer", sequence: 1,
            previousStatementHash: zeros, oldKey: pub("rotation_genesis"), newKey: pub("rotation_second"),
            oldKeyId: id("rotation_genesis"), newKeyId: id("rotation_second"),
            issuedAt: Self.now - 600, notBefore: Self.now - 600,
            oldSignature: Self.emptySignature, newSignature: Self.emptySignature),
            oldKey: key("rotation_genesis"), newKey: key("rotation_second"))
        let rotationWire = try Ratify.encodeKeyRotationStatement(rotation)
        try add("key_rotation_genesis", "key_rotation_statement", "Genesis hybrid key rotation.", rotationWire,
            [("old_signature", 4, "rotation_genesis"), ("new_signature", 9, "rotation_second")],
            ["statement_body_digest_hex": try Ratify.keyRotationStatementDigest(rotation).hex],
            verify: ["rotation_state": ["authority_id": authority, "recovery_epoch": 1, "role": "issuer",
                "sequence": 0, "head_hash_b64": zeros.base64EncodedString(),
                "current_key": "rotation_genesis", "used_key_ids": [id("rotation_genesis")]],
                "now": Self.now, "future_skew_seconds": 5])
        let witnessLog = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
        let witness = try Ratify.signWitnessEntry(WitnessEntry(version: 2, logId: witnessLog,
            sequence: 1, prevHash: zeros, entryData: Data("entry-1".utf8), timestamp: Self.now - 20,
            witnessId: id("witness"), signature: Self.emptySignature), key: key("witness"))
        let witnessWire = try Ratify.encodeWitnessEntry(witness)
        try add("witness_entry_genesis", "witness_entry", "Genesis witness entry.", witnessWire,
            [("signature", 6, "witness")],
            ["statement_body_digest_hex": try Ratify.witnessEntryDigest(witness).hex],
            verify: ["witness_key": "witness", "head": ["log_id": witnessLog, "sequence": 0,
                "head_hash_b64": zeros.base64EncodedString(), "accepted_digests_b64": [:] as [String: String],
                "frozen": false]])

        let terms = Data(#"{"amount":100,"currency":"USD","item":"widget"}"#.utf8)
        var transaction = TransactionReceipt(version: 2, transactionId: "tx-0001", createdAt: Self.now - 5,
            termsSchemaUri: "https://example.com/terms/purchase/v1", termsCanonicalJson: terms,
            parties: [], partySignatures: [])
        let transactionContext = try Ratify.transactionContextHash(transaction)
        var txDigests: [String: Any] = ["transaction_context_hex": transactionContext.hex]
        for (party, role, agent, root, scope) in [
            ("party-a", "buyer", "agent", "root", "transact:purchase"),
            ("party-b", "seller", "party_b_agent", "party_b_root", "transact:sell"),
        ] {
            let request = try Ratify.transactionPartyRequestHash(transactionContext, requiredScope: scope)
            let session = try Ratify.buildSessionContext(SessionContextInputs(verifierId: id("verifier"),
                workspaceId: Self.workspace, agentId: id(agent), sessionId: "session-\(party)",
                invocationId: "invocation-\(party)", requestHash: request))
            let partyCert = try cert(root, agent, "cert-\(party)", [scope])
            let partyBundle = try bundle(agent, [partyCert], session)
            let hash = try Ratify.bundleHash(partyBundle)
            transaction.parties.append(TransactionReceiptParty(partyId: party, role: role,
                agentId: id(agent), agentPubKey: pub(agent), verifierId: id("verifier"),
                workspaceId: Self.workspace, sessionId: "session-\(party)", invocationId: "invocation-\(party)",
                requiredScope: scope, proofBundleHash: hash, proofBundle: partyBundle))
            txDigests["\(party).transaction_party_request_hash_hex"] = request.hex
            txDigests["\(party).session_context_hex"] = session.hex
            txDigests["\(party).proof_bundle_hash"] = hash
        }
        transaction.partySignatures = [
            try Ratify.signTransactionReceiptParty(transaction, partyId: "party-a", key: key("agent")),
            try Ratify.signTransactionReceiptParty(transaction, partyId: "party-b", key: key("party_b_agent")),
        ]
        let transactionWire = try Ratify.encodeTransactionReceipt(transaction)
        try add("transaction_receipt_two_parties", "transaction_receipt", "Two parties sign one transaction.",
            transactionWire, [("party_signatures[party-a]", 7, "agent"),
                ("party_signatures[party-b]", 7, "party_b_agent")], txDigests)

        let evidence = [
            StatusEvidenceEntry(issuerId: id("root"), statusKeyId: id("status_root"), sequence: 7,
                objectType: 3, digest: "sha384:" + (try Ratify.statusEvidenceDigest(rootList)).hex),
            StatusEvidenceEntry(issuerId: id("intermediate"), statusKeyId: id("status_intermediate"), sequence: 1,
                objectType: 3, digest: "sha384:" + (try Ratify.statusEvidenceDigest(intermediateList)).hex),
        ].sorted { ($0.issuerId, $0.statusKeyId) < ($1.issuerId, $1.statusKeyId) }
        try addReceipt("verification_receipt_allow_genesis", bundle: plain,
            granted: ["data:read", "files:read"], logId: "cccccccccccccccccccccccccccccc01", evidence: evidence)
        let digest = try Ratify.constraintProfileDigest(ConstraintProfileDescriptor(
            profile: "com.ratifyprotocol.max_count/v1", type: "com.ratifyprotocol.max_count"))
        try addReceipt("verification_receipt_constraint_evaluators", bundle: extended,
            granted: ["data:read"], logId: "cccccccccccccccccccccccccccccc02", evidence: evidence,
            evaluators: [ConstraintEvaluatorRef(kind: "com.ratifyprotocol.max_count", profileDigest: digest)])
    }

    private mutating func addReceipt(_ name: String, bundle: ProofBundle, granted: [String], logId: String,
                                     evidence: [StatusEvidenceEntry], evaluators: [ConstraintEvaluatorRef] = []) throws {
        let zeros = Data(repeating: 0, count: 48)
        let receipt = try Ratify.signVerificationReceipt(VerificationReceipt(version: 2, logId: logId,
            sequence: 1, verifierId: id("verifier"), agentId: bundle.agentId, humanId: "",
            bundleHash: Ratify.bundleHash(bundle), issuerIds: [id("root"), id("intermediate")].sorted(),
            decision: "allow", decisionReason: "authorized", identityStatus: "authorized_agent",
            trustAssessment: "trusted", statusAssessment: "current", challengeAssessment: "current",
            constraintEvaluators: evaluators, contextAssessment: "bound",
            contextPolicyDigest: "sha384:610c40faa472aa2a4f905988899733758cccf30f243aed35f1f42433228a28dbab1725cb2a4a6811029a8109da0b9b29",
            verifiedAt: Self.now, requiredScope: "data:read", grantedScope: granted,
            statusEvidence: evidence, previousReceiptHash: zeros, signature: Self.emptySignature),
            key: key("verifier"))
        let wire = try Ratify.encodeVerificationReceipt(receipt)
        let bundleWire = try Ratify.encodeProofBundle(bundle)
        try add(name, "verification_receipt", "Signed genesis allow receipt.", wire,
            [("signature", 8, "verifier")],
            ["statement_body_digest_hex": try Ratify.verificationReceiptDigest(receipt).hex,
                "receipt_outbox_body_b64": try Ratify.verificationReceiptBody(receipt).base64EncodedString()],
            verify: ["verifier_key": "verifier", "head": ["log_id": logId, "verifier_id": id("verifier"),
                "sequence": 0, "head_hash_b64": zeros.base64EncodedString(),
                "accepted_digests_b64": [:] as [String: String], "frozen": false]])
        try add(name + "/bundle_binding", "receipt_bundle_binding", "Receipt bound to its proof bundle.",
            wire, [], [:], bundle: bundleWire)
    }

    private func scenario(_ name: String, _ description: String, first: UInt8,
                          rootEvidence: RevocationList, intermediateEvidence: RevocationList?,
                          root: DelegationCert, leaf: DelegationCert, session: Data,
                          publishTime: Int64, releaseTime: Int64) async throws -> [String: Any] {
        let challenge = Data([first] + Array(UInt8(0xA1)...UInt8(0xBF)))
        let presented = try bundle("agent", [leaf, root], session, challenge: challenge)
        let wire = try Ratify.encodeProofBundle(presented)
        let fields = ["verifier_id", "workspace_id", "agent_id", "session_id", "invocation_id", "request_hash"]
        let context = try ContextPolicy(profile: "ratify.verify.session-context/v1", requireBound: true,
            requiredFields: fields, expectedSessionContext: session)
        let expected = ExpectedChallenge(value: challenge, issuedAt: Self.now - 10, expiresAt: Self.now + 290,
            verifierNamespace: "verify-test", replayEpoch: 3, verifierId: id("verifier"),
            expectedAgentId: id("agent"), expectedAgentPublicKey: pub("agent"),
            expectedReceiverId: "", expectedSessionContext: session)
        let journal = ClaimTests.VectorJournal(try Ratify.emptySecurityJournalSnapshot())
        var statusKeys: [String: StatusKeyConfig] = [:]
        for (issuer, statusKey) in [("root", "status_root"), ("intermediate", "status_intermediate")] {
            _ = try await Ratify.configureStatusKeyEpoch(store: journal, issuerId: id(issuer),
                epoch: 1, key: pub(statusKey))
            statusKeys[id(issuer)] = StatusKeyConfig(epoch: 1, key: pub(statusKey))
        }
        let statusPolicy = RevocationStatusPolicy(maxListLifetimeSeconds: 7200,
            maxStatusAgeSeconds: 3660, clockSkewSeconds: 5)
        let request = VerifyRequest(bundle: wire, expected: expected, contextPolicy: context,
            requiredScope: "data:read", verifierNamespace: "verify-test", replayEpoch: 3,
            verifierId: id("verifier"), now: Self.now, maxChallengeAgeSeconds: 300,
            futureSkewSeconds: 5, context: ConstraintContext(), tzdbVersion: "2025c",
            statusKeys: statusKeys, statusPolicy: statusPolicy)
        let store = try Store(now: Self.now, leaseSeconds: 30,
            logId: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeee01", verifierKey: key("verifier"))
        var evidence: [String: [StatusEvidenceObject]] = [id("root"): [StatusEvidenceObject(
            objectType: 3, wire: try Ratify.encodeRevocationList(rootEvidence))]]
        if let intermediateEvidence {
            evidence[id("intermediate")] = [StatusEvidenceObject(objectType: 3,
                wire: try Ratify.encodeRevocationList(intermediateEvidence))]
        }
        let outcome = try await Ratify.verifyProofBundle(request, claimStore: store,
            trust: ClaimTests.VectorTrust(key: pub("root"), outcome: .trusted),
            statusEvidence: ClaimTests.VectorStatus(byIssuer: evidence), statusJournal: journal)
        guard let committed = outcome.committed, outcome.stage == .committed else {
            throw GeneratorError.invalid("\(name): verifier did not commit: \(outcome.errorDetail ?? "")")
        }
        try store.setTime(publishTime)
        let published = try await store.publish(claimId: committed.claimId, receiptBody: committed.receiptBody)
        try store.setTime(releaseTime)
        let released = try await Ratify.releaseDecision(committed, signedReceipt: published,
            verifierPublicKey: pub("verifier"), logId: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeee01",
            claimStore: store, checkpoint: store)
        let statusJSON: [String: Any] = evidence.mapValues { values in
            values.map { ["object_type_code": Int($0.objectType), "wire_b64": $0.wire.base64EncodedString()] }
        }
        let statusKeyJSON: [String: Any] = [id("root"): ["epoch": 1, "key": "status_root"],
            id("intermediate"): ["epoch": 1, "key": "status_intermediate"]]
        let releaseJSON: [String: Any] = ["status": released.status.rawValue,
            "reason": released.reason.isEmpty ? NSNull() : released.reason as Any,
            "decision": released.decision?.decision ?? NSNull() as Any,
            "release_time": released.decision?.releaseTime ?? NSNull() as Any]
        return ["name": name, "description": description, "bundle_b64": wire.base64EncodedString(),
            "required_scope": "data:read",
            "expected_challenge": ["value_b64": challenge.base64EncodedString(), "issued_at": Self.now - 10,
                "expires_at": Self.now + 290, "verifier_namespace": "verify-test", "replay_epoch": 3,
                "verifier_id": id("verifier"), "expected_agent_id": id("agent"),
                "expected_agent_public_key": Self.json(pub("agent")), "expected_receiver_id": NSNull(),
                "expected_session_context_b64": session.base64EncodedString()],
            "context_policy": ["profile": "ratify.verify.session-context/v1", "require_bound": true,
                "required_fields": fields, "expected_session_context_b64": session.base64EncodedString(),
                "digest": context.digest],
            "trust_root_key": "root", "status_keys": statusKeyJSON, "status_evidence": statusJSON,
            "verify_time": Self.now, "publish_time": publishTime, "release_time": releaseTime,
            "expected": ["receipt_body_b64": committed.receiptBody.base64EncodedString(),
                "allow_horizon": committed.allowHorizon ?? NSNull() as Any,
                "signed_receipt_b64": published.base64EncodedString(), "release": releaseJSON]]
    }

    enum GeneratorError: Error { case invalid(String) }

    mutating func generate() async throws -> [String: Any] {
        let (plain, extended, root, leaf, rootList, intermediateList, session) = try buildObjects()
        try buildStatements(plain: plain, extended: extended, rootList: rootList,
            intermediateList: intermediateList)
        let rootCurrent = try statusList("root", "status_root", sequence: 1,
            next: Self.now + 3600, revoked: [])
        let rootShort = try statusList("root", "status_root", sequence: 1,
            next: Self.now + 60, revoked: [])
        let intermediateCurrent = try statusList("intermediate", "status_intermediate", sequence: 1,
            next: Self.now + 3600, revoked: [])
        let intermediateRevoked = try statusList("intermediate", "status_intermediate", sequence: 1,
            next: Self.now + 3600, revoked: ["cert-leaf"])
        let scenarios = try await [
            scenario("allow_released", "An acknowledged allow is released.", first: 0xA1,
                rootEvidence: rootCurrent, intermediateEvidence: intermediateCurrent,
                root: root, leaf: leaf, session: session, publishTime: Self.now, releaseTime: Self.now),
            scenario("deny_revoked_released", "A revoked leaf gives a non-actionable deny.", first: 0xA2,
                rootEvidence: rootCurrent, intermediateEvidence: intermediateRevoked,
                root: root, leaf: leaf, session: session, publishTime: Self.now, releaseTime: Self.now),
            scenario("indeterminate_status_unavailable_released", "Missing status is indeterminate.", first: 0xA3,
                rootEvidence: rootCurrent, intermediateEvidence: nil,
                root: root, leaf: leaf, session: session, publishTime: Self.now, releaseTime: Self.now),
            scenario("allow_withheld_past_horizon", "The allow horizon expires before release.", first: 0xA4,
                rootEvidence: rootShort, intermediateEvidence: intermediateCurrent,
                root: root, leaf: leaf, session: session, publishTime: Self.now + 60, releaseTime: Self.now + 60),
        ]
        return ["version": 2, "sdk": "swift", "sdk_version": "2.0.0-beta.1",
            "generator": "RATIFY_GENERATE_SWIFT_FIXTURE=1 swift test --filter SwiftCrossSdkGeneratorTests",
            "description": "Fresh Swift SDK keys and hedged ML-DSA-65 signatures; verifier and release observations use the Swift public API.",
            "kind_object_type_codes": ["delegation_certificate": 1, "proof_bundle": 2,
                "revocation_list": 3, "key_rotation_statement": 4, "revocation_push": 5,
                "witness_entry": 6, "transaction_receipt": 7, "verification_receipt": 8],
            "keys": entries, "objects": objects,
            "scenario_configuration": ["verifier_namespace": "verify-test", "replay_epoch": 3,
                "verifier_key": "verifier", "receipt_log_id": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeee01",
                "lease_seconds": 30, "max_challenge_age_seconds": 300, "future_skew_seconds": 5,
                "status_policy": ["max_list_lifetime_seconds": 7200, "max_status_age_seconds": 3660,
                    "clock_skew_seconds": 5], "tzdb_version": "2025c"],
            "scenarios": scenarios]
    }
}

final class SwiftCrossSdkGeneratorTests: XCTestCase {
    func testGenerateFixtureWhenRequested() async throws {
        if ProcessInfo.processInfo.environment["RATIFY_GENERATE_SWIFT_FIXTURE"] == "1" {
            var generator = try SwiftCrossSdkGenerator()
            let fixture = try await generator.generate()
            var bytes = try JSONSerialization.data(withJSONObject: fixture, options: [.prettyPrinted, .sortedKeys])
            bytes.append(0x0a)
            try bytes.write(to: Corpus.url("cross-sdk/swift.json"), options: .atomic)
        }
        let fixture = Corpus.load("cross-sdk/swift.json")
        XCTAssertEqual(fixture.s("sdk"), "swift")
        XCTAssertEqual(fixture.arr("keys").count, 11)
        XCTAssertEqual(fixture.arr("objects").count, 15)
        XCTAssertEqual(fixture.arr("scenarios").count, 4)
    }
}
