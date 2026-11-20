import Foundation
import XCTest
import RatifyProtocol

/// mcp/: the Verify MCP signer vectors (Preview) through the public API.
///
/// The hosted service recomputes every value below from the call it
/// receives. A signer that differs in one byte produces proofs the service
/// rejects or, worse, a proof that binds something other than the call the
/// client asked for. Every SDK runs these same files.
enum MCPRunner {
    /// The files this runner reads; the directory must hold exactly these and README.md.
    static let files = ["binding.json", "client-config.json", "connect.json", "tool-call.json"]

    static func load(_ name: String) -> [String: Any] { Corpus.load("mcp/" + name) }

    static func agentKey(_ entry: [String: Any]) throws -> SoftwarePrivateKey {
        try SoftwarePrivateKey(ed25519Seed: entry.hex("ed25519_seed_hex"), mlDsa65Seed: entry.hex("ml_dsa_65_seed_hex"))
    }

    static func utf8(_ s: String) -> Data { Data(s.utf8) }

    /// Identical to `want` except the hedged ML-DSA-65 component of
    /// challenge_sig, and both bundles verify.
    static func sameBundle(_ gotB64: String, _ wantB64: String) -> Bool {
        guard let gotWire = Data(base64Encoded: gotB64), let wantWire = Data(base64Encoded: wantB64),
              let got = try? Ratify.decodeProofBundle(gotWire), let want = try? Ratify.decodeProofBundle(wantWire),
              (try? Ratify.verifyProofBundleSignatures(got)) != nil, (try? Ratify.verifyProofBundleSignatures(want)) != nil
        else { return false }
        let from = Array(got.challengeSig.mlDsa65.base64EncodedString().utf8)
        let to = Array(want.challengeSig.mlDsa65.base64EncodedString().utf8)
        let g = Array(gotWire)
        guard let at = firstRange(of: from, in: g) else { return false }
        return Data(g[..<at] + to + g[(at + from.count)...]) == wantWire
    }

    static func firstRange(of needle: [UInt8], in hay: [UInt8]) -> Int? {
        guard !needle.isEmpty, hay.count >= needle.count else { return nil }
        for i in 0...(hay.count - needle.count) where hay[i] == needle[0] && Array(hay[i..<i + needle.count]) == needle {
            return i
        }
        return nil
    }

    static func refused<T>(_ want: MCP.SignerError, _ body: () throws -> T) -> Bool {
        do {
            _ = try body()
            return false
        } catch let e as MCP.SignerError {
            return e == want
        } catch {
            return false
        }
    }

    static func run() async throws {
        let t = Tally("mcp")

        // Directory inventory: exactly the runner's files and the README.
        let entries = try FileManager.default.contentsOfDirectory(atPath: Corpus.url("mcp").path).sorted()
        t.check("inventory", "mcp/", entries == (files + ["README.md"]).sorted(), "\(entries)")

        // binding.json
        let b = load("binding.json")
        t.check("binding/constants", "action", b.s("action") == MCP.action)
        t.check("binding/constants", "proof_meta_key", b.s("proof_meta_key") == MCP.proofMetaKey)
        let table = b.arr("tools").map { [$0.s("name"), $0.s("scope")] }
        t.check("binding/constants", "tools", table == MCP.tools.map { [$0.name, $0.scope] }, "\(table)")
        let cases = b.arr("cases")
        for c in cases {
            let canonical = try MCP.canonicalArguments(c.s("arguments_json"))
            let digest = MCP.payloadDigest(canonical)
            let req = try MCP.requestHash(tool: c.s("tool"), connectionId: c.s("connection_id"),
                                          audience: c.s("audience"), payloadDigest: digest)
            let sess = try MCP.sessionContext(verifierId: c.s("verifier_id"), workspaceId: c.s("workspace_id"),
                                              agentId: c.s("agent_id"), connectionId: c.s("connection_id"),
                                              invocationId: c.s("invocation_id"), requestHash: req)
            t.check("binding/cases", c.s("name"),
                    canonical == utf8(c.s("canonical_arguments")) && MCP.payloadDigestText(digest) == c.s("payload_digest")
                        && req.hex == c.s("request_hash") && sess.hex == c.s("session_context"),
                    "\(String(decoding: canonical, as: UTF8.self)) \(req.hex) \(sess.hex)")
        }
        let invalidArgs = b.arr("invalid_arguments")
        for c in invalidArgs {
            let raw = (c["arguments_base64"] as? String).map { Data(base64Encoded: $0)! } ?? utf8(c.s("arguments_json"))
            t.check("binding/invalid_arguments", c.s("name"), refused(.invalidArguments) { try MCP.canonicalArguments(raw) })
        }

        // client-config.json
        let cc = load("client-config.json")
        let valid = cc.arr("valid"), invalid = cc.arr("invalid")
        for c in valid {
            let cfg = try MCP.parseClientConfig(c.s("config_json"))
            let e = c.obj("expected")
            t.check("client-config/valid", c.s("name"),
                    [cfg.endpoint, cfg.audience, cfg.verifierId, cfg.workspaceId, cfg.connectionId]
                        == [e.s("endpoint"), e.s("audience"), e.s("verifier_id"), e.s("workspace_id"), e.s("connection_id")]
                        && cfg.delegations.map(\.certId) == e.strings("delegation_cert_ids"))
        }
        for c in invalid {
            t.check("client-config/invalid", c.s("name"), refused(.invalidConfig) { try MCP.parseClientConfig(c.s("config_json")) })
        }

        // tool-call.json
        let tc = load("tool-call.json")
        let agent = try agentKey(tc.obj("agent_key")), wrong = try agentKey(tc.obj("wrong_agent_key"))
        t.check("tool-call/keys", "agent", agent.keyId == tc.obj("agent_key").s("key_id_v2"))
        t.check("tool-call/keys", "wrong_agent", wrong.keyId == tc.obj("wrong_agent_key").s("key_id_v2"))
        let config = try MCP.parseClientConfig(tc.s("client_config_json"))
        let signer = SeedSigner(tc.obj("agent_key"))
        let tcCases = tc.arr("cases")
        for c in tcCases {
            let name = c.s("name")
            let call = try MCP.newToolCall(tool: c.s("tool"), arguments: c.s("arguments_json"))
            let ch = try config.checkChallenge(tool: c.s("tool"), response: utf8(c.s("challenge_response")),
                                               now: Int64(c.int("now")))
            let req = try MCP.requestHash(tool: call.tool, connectionId: config.connectionId, audience: config.audience,
                                          payloadDigest: call.payloadDigest)
            let sess = try MCP.sessionContext(verifierId: config.verifierId, workspaceId: config.workspaceId,
                                              agentId: agent.keyId, connectionId: config.connectionId,
                                              invocationId: ch.invocationId, requestHash: req)
            t.check("tool-call/binding", name,
                    call.canonicalArguments == utf8(c.s("canonical_arguments"))
                        && (try? config.challengeRequest(call)) == utf8(c.s("challenge_request"))
                        && req.hex == c.s("request_hash") && sess.hex == c.s("session_context"))
            let want = c.obj("envelope")
            for (variant, env) in [("software", try MCP.signToolCall(config: config, agentKey: agent, call: call, challenge: ch)),
                                   ("external", try await MCP.signToolCall(config: config, signer: signer, call: call, challenge: ch))] {
                t.check("tool-call/envelopes", "\(name) \(variant)",
                        env.connectionId == want.s("connection_id") && env.invocationId == want.s("invocation_id")
                            && env.challenge == want.s("challenge") && sameBundle(env.bundle, want.s("bundle")))
            }
            t.check("tool-call/wrong_agent_key", name,
                    refused(.challengeRefused) { try MCP.signToolCall(config: config, agentKey: wrong, call: call, challenge: ch) })
        }
        let refusedChallenges = tc.arr("refused_challenges")
        for c in refusedChallenges {
            t.check("tool-call/refused_challenges", c.s("name"), refused(.challengeRefused) {
                try config.checkChallenge(tool: c.s("tool"), response: utf8(c.s("challenge_response")), now: Int64(c.int("now")))
            })
        }
        let refusedSignings = tc.arr("refused_signings")
        for c in refusedSignings {
            let name = c.s("name")
            let ch = try config.checkChallenge(tool: c.s("checked_tool"), response: utf8(c.s("challenge_response")),
                                               now: Int64(c.int("now")))
            let call = try MCP.newToolCall(tool: c.s("signing_tool"), arguments: c.s("signing_arguments_json"))
            let other = c.s("signing_config_json")
            let signing = other.isEmpty ? config : try MCP.parseClientConfig(other)
            t.check("tool-call/refused_signings", name,
                    refused(.challengeRefused) { try MCP.signToolCall(config: signing, agentKey: agent, call: call, challenge: ch) })
        }

        // connect.json
        let cn = load("connect.json")
        t.check("connect/constants", "domain", cn.s("domain") == MCP.connectPossessionDomain)
        t.check("connect/constants", "token_prefix", cn.s("token_prefix") == MCP.connectTokenPrefix)
        let contexts = cn.arr("contexts")
        for c in contexts {
            let ctx = MCP.connectPossessionContext(workspaceId: c.s("workspace_id"), receiverId: c.s("receiver_id"),
                                                   audience: c.s("audience"), challengeId: c.s("challenge_id"),
                                                   agentId: c.s("agent_id"))
            t.check("connect/contexts", c.s("name"), ctx.hex == c.s("session_context"), ctx.hex)
        }
        let cnKey = try agentKey(cn.obj("agent_key"))
        t.check("connect/keys", "agent", cnKey.keyId == cn.obj("agent_key").s("key_id_v2"))
        let cnSigner = SeedSigner(cn.obj("agent_key"))
        let proofs = cn.arr("proofs")
        for c in proofs {
            let name = c.s("name")
            let tok = try MCP.parseConnectToken(c.s("token"))
            let p = c.obj("parsed")
            let ctx = MCP.connectPossessionContext(workspaceId: tok.workspaceId, receiverId: tok.receiverId,
                                                   audience: tok.audience, challengeId: tok.challengeId, agentId: cnKey.keyId)
            t.check("connect/parsed", name,
                    [tok.challengeId, tok.workspaceId, tok.receiverId, tok.audience, tok.verifierId]
                        == [p.s("challenge_id"), p.s("workspace_id"), p.s("receiver_id"), p.s("audience"), p.s("verifier_id")]
                        && tok.challenge == p.b64("challenge") && tok.issuedAt == Int64(p.int("issued_at"))
                        && ctx.hex == c.s("session_context"))
            let want = c.obj("expected")
            for (variant, proof) in [("software", try MCP.provePossession(token: c.s("token"), agentKey: cnKey)),
                                     ("external", try await MCP.provePossession(token: c.s("token"), signer: cnSigner))] {
                t.check("connect/proofs", "\(name) \(variant)",
                        proof.connectChallengeId == want.s("connect_challenge_id")
                            && sameBundle(proof.possessionProof, want.s("possession_proof")))
            }
        }
        let invalidTokens = cn.arr("invalid_tokens")
        for c in invalidTokens {
            let token = c.s("token")
            t.check("connect/invalid_tokens", c.s("name"),
                    refused(.invalidConnectToken) { try MCP.parseConnectToken(token) }
                        && refused(.invalidConnectToken) { try MCP.provePossession(token: token, agentKey: cnKey) })
        }

        t.finish([
            ("inventory", 1),
            ("binding/constants", 3), ("binding/cases", cases.count), ("binding/invalid_arguments", invalidArgs.count),
            ("client-config/valid", valid.count), ("client-config/invalid", invalid.count),
            ("tool-call/keys", 2), ("tool-call/binding", tcCases.count), ("tool-call/envelopes", 2 * tcCases.count),
            ("tool-call/wrong_agent_key", tcCases.count), ("tool-call/refused_challenges", refusedChallenges.count),
            ("tool-call/refused_signings", refusedSignings.count),
            ("connect/constants", 2), ("connect/contexts", contexts.count), ("connect/keys", 1),
            ("connect/parsed", proofs.count), ("connect/proofs", 2 * proofs.count),
            ("connect/invalid_tokens", invalidTokens.count),
        ])
    }
}

/// An external signer over a vector key's seeds (test-hooks build), so the
/// signer variants run against the same expected bundles.
final class SeedSigner: ExternalSigner, @unchecked Sendable {
    let seeds: (Data, Data)
    let publicKey: HybridPublicKey
    var mode: SignerMode { .direct }

    init(_ entry: [String: Any]) {
        seeds = (entry.hex("ed25519_seed_hex"), entry.hex("ml_dsa_65_seed_hex"))
        let pub = entry.obj("public_key")
        publicKey = HybridPublicKey(ed25519: pub.b64("ed25519"), mlDsa65: pub.b64("ml_dsa_65"))
    }

    func sign(_ request: SignRequest) async throws -> HybridSignature {
        guard request.publicKey == publicKey, let ctx = request.mlDsaContext,
              let sig = emulatedProviderSign(seeds: seeds, message: request.message, context: ctx)
        else { throw ProviderError.refused }
        return sig
    }
}
