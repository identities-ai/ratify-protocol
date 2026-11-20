package com.ratifyprotocol

import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertEquals
import java.util.Base64

/**
 * mcp/: the Verify MCP signer (preview; a managed-service contract, not
 * SPEC-v2 conformance) through the public API. The hosted service
 * recomputes every value from the call it receives, so a signer that
 * differs in one byte produces proofs the service rejects, or, worse, a
 * proof that binds something other than the call the client asked for.
 */
object McpVectors {
    private val FILES = listOf("README.md", "binding.json", "client-config.json", "connect.json", "tool-call.json")

    fun run() {
        assertEquals("testvectors/v2/mcp entries", FILES, Corpus.list("v2/mcp").sorted())
        binding()
        clientConfig()
        toolCall()
        connect()
        challengeForAnotherTool()
        toolCallCannotBeAltered()
    }

    private fun load(name: String): JSONObject = Corpus.load("mcp/$name")

    private fun refused(body: () -> Unit): Boolean = try {
        body()
        false
    } catch (e: McpException) {
        true
    }

    private class AgentKey(val key: SoftwarePrivateKey, val seeds: Pair<ByteArray, ByteArray>)

    /** The fixture key from its seeds; its key ID must be the file's. */
    private fun agentKey(k: JSONObject): AgentKey {
        val seeds = k.hex("ed25519_seed_hex") to k.hex("ml_dsa_65_seed_hex")
        val key = SoftwarePrivateKey.fromSeeds(seeds.first, seeds.second)
        assertEquals("key_id_v2", k.getString("key_id_v2"), key.keyId)
        return AgentKey(key, seeds)
    }

    /** An app-held signer for the fixture key, as an HSM or KMS would sign. */
    private class SeedSigner(private val k: AgentKey) : ExternalSigner {
        override val publicKey: HybridPublicKey = k.key.publicKey
        override val mode: SignerMode = SignerMode.DIRECT
        override suspend fun sign(request: SignRequest): HybridSignature =
            emulatedProviderSign(k.seeds, request.message, request.mlDsaContext!!) ?: throw ProviderException("refused")
    }

    /**
     * Whether [got] and [want] are the same proof except for the hedged
     * ML-DSA-65 component of challenge_sig, and both verify.
     */
    private fun sameBundle(got: String, want: String): Boolean {
        val gotWire = Base64.getDecoder().decode(got)
        val wantWire = Base64.getDecoder().decode(want)
        val g = decodeProofBundle(gotWire)
        val w = decodeProofBundle(wantWire)
        verifyProofBundleSignatures(g)
        verifyProofBundleSignatures(w)
        val b64 = Base64.getEncoder()
        val masked = String(gotWire, Charsets.ISO_8859_1)
            .replaceFirst(b64.encodeToString(g.challengeSig.mlDsa65), b64.encodeToString(w.challengeSig.mlDsa65))
        return masked == String(wantWire, Charsets.ISO_8859_1)
    }

    /** Whether [json] is an object with exactly [fields]. */
    private fun sameJson(json: String, fields: Map<String, String>): Boolean {
        val o = JSONObject(json)
        return o.length() == fields.size && fields.all { (k, v) -> o.optString(k, null) == v }
    }

    private fun binding() {
        val f = load("binding.json")
        val t = Tally("mcp")
        t.check("binding/constants", "constants", f.getString("action") == Mcp.ACTION &&
            f.getString("proof_meta_key") == Mcp.PROOF_META_KEY && Mcp.PROTOCOL_VERSION == "2026-07-28" &&
            Mcp.MIN_CHALLENGE_SECONDS_LEFT == 10L && Mcp.MAX_ARGUMENT_DEPTH == 4)
        val tools = f.arr("tools").map { it.getString("name") to it.getString("scope") }
        t.check("binding/constants", "tool table", tools == Mcp.tools.map { it.name to it.scope }) { "${Mcp.tools}" }
        t.check("binding/constants", "tool scopes", tools.all { (n, s) -> Mcp.toolScope(n) == s } && Mcp.toolScope("other") == null)
        val cases = f.arr("cases")
        for (c in cases) {
            val name = c.getString("name")
            val args = c.getString("arguments_json")
            val canonical = Mcp.canonicalArguments(args.toByteArray(Charsets.UTF_8))
            val fromText = Mcp.canonicalArguments(args)
            val digest = Mcp.payloadDigest(canonical)
            val req = Mcp.requestHash(c.getString("tool"), c.getString("connection_id"), c.getString("audience"), digest)
            val sess = Mcp.sessionContext(c.getString("verifier_id"), c.getString("workspace_id"), c.getString("agent_id"),
                c.getString("connection_id"), c.getString("invocation_id"), req)
            t.check("binding/cases", name,
                canonical.contentEquals(c.getString("canonical_arguments").toByteArray(Charsets.UTF_8)) &&
                    fromText.contentEquals(canonical) &&
                    Mcp.payloadDigestText(digest) == c.getString("payload_digest") &&
                    req.hex() == c.getString("request_hash") && sess.hex() == c.getString("session_context")) {
                String(canonical, Charsets.UTF_8)
            }
        }
        val invalid = f.arr("invalid_arguments")
        for (c in invalid) {
            val input = if (c.has("arguments_base64")) c.b64("arguments_base64")
            else c.getString("arguments_json").toByteArray(Charsets.UTF_8)
            t.check("binding/invalid_arguments", c.getString("name"), refused { Mcp.canonicalArguments(input) } &&
                refused { Mcp.newToolCall("get_metrics", input) })
        }
        t.check("binding/invalid_arguments", "unknown-tool", refused { Mcp.newToolCall("delete_everything", "{}") })
        t.finish(listOf("binding/constants" to 3, "binding/cases" to cases.size, "binding/invalid_arguments" to invalid.size + 1))
    }

    private fun clientConfig() {
        val f = load("client-config.json")
        val t = Tally("mcp")
        val valid = f.arr("valid")
        for (c in valid) {
            val cfg = Mcp.parseClientConfig(c.getString("config_json"))
            val e = c.getJSONObject("expected")
            t.check("client-config/valid", c.getString("name"), cfg.endpoint == e.getString("endpoint") &&
                cfg.audience == e.getString("audience") && cfg.verifierId == e.getString("verifier_id") &&
                cfg.workspaceId == e.getString("workspace_id") && cfg.connectionId == e.getString("connection_id") &&
                cfg.delegations.map { it.certId } == e.strings("delegation_cert_ids"))
        }
        val invalid = f.arr("invalid")
        for (c in invalid) {
            val text = c.getString("config_json")
            t.check("client-config/invalid", c.getString("name"), refused { Mcp.parseClientConfig(text) } &&
                refused { Mcp.parseClientConfig(text.toByteArray(Charsets.UTF_8)) })
        }
        t.finish(listOf("client-config/valid" to valid.size, "client-config/invalid" to invalid.size))
    }

    private fun toolCall() = runBlocking {
        val f = load("tool-call.json")
        val t = Tally("mcp")
        val cfg = Mcp.parseClientConfig(f.getString("client_config_json"))
        val agent = agentKey(f.getJSONObject("agent_key"))
        val wrong = agentKey(f.getJSONObject("wrong_agent_key"))
        val cases = f.arr("cases")
        for (c in cases) {
            val name = c.getString("name")
            val tool = c.getString("tool")
            val call = Mcp.newToolCall(tool, c.getString("arguments_json"))
            t.check("tool-call/arguments", name, String(call.canonicalArguments, Charsets.UTF_8) == c.getString("canonical_arguments") &&
                String(cfg.challengeRequest(call), Charsets.UTF_8) == c.getString("challenge_request")) {
                String(cfg.challengeRequest(call), Charsets.UTF_8)
            }
            val ch = cfg.checkChallenge(tool, c.getString("challenge_response"), c.getLong("now"))
            val want = c.getJSONObject("envelope")
            // The software key, an external signer, and the SigningKey form must all produce the vector.
            val envelopes = listOf(
                "software" to Mcp.signToolCall(cfg, agent.key, call, ch),
                "external" to Mcp.signToolCall(cfg, SeedSigner(agent), call, ch),
                "signing-key" to Mcp.signToolCall(cfg, SigningKey.Software(agent.key), call, ch),
            )
            for ((how, env) in envelopes) {
                t.check("tool-call/envelopes", "$name $how", env.connectionId == want.getString("connection_id") &&
                    env.invocationId == want.getString("invocation_id") && env.challenge == want.getString("challenge") &&
                    sameBundle(env.bundle, want.getString("bundle")) &&
                    sameJson(env.toJson(), mapOf("connection_id" to env.connectionId,
                        "invocation_id" to env.invocationId, "challenge" to env.challenge, "bundle" to env.bundle)))
            }
            t.check("tool-call/wrong_agent_key", name, refused { Mcp.signToolCall(cfg, wrong.key, call, ch) } &&
                refused { runBlocking { Mcp.signToolCall(cfg, SeedSigner(wrong), call, ch) } })
        }
        val refusedChallenges = f.arr("refused_challenges")
        for (c in refusedChallenges) {
            t.check("tool-call/refused_challenges", c.getString("name"),
                refused { cfg.checkChallenge(c.getString("tool"), c.getString("challenge_response"), c.getLong("now")) })
        }
        // A challenge accepted for one tool and configuration must not sign
        // a call to another tool or under another configuration.
        val refusedSignings = f.arr("refused_signings")
        check(refusedSignings.isNotEmpty()) { "tool-call.json has no refused_signings" }
        for (c in refusedSignings) {
            val ch = cfg.checkChallenge(c.getString("checked_tool"), c.getString("challenge_response"), c.getLong("now"))
            val signingConfig = c.getString("signing_config_json").let { if (it.isEmpty()) cfg else Mcp.parseClientConfig(it) }
            val call = Mcp.newToolCall(c.getString("signing_tool"), c.getString("signing_arguments_json"))
            t.check("tool-call/refused_signings", c.getString("name"),
                refused { Mcp.signToolCall(signingConfig, agent.key, call, ch) } &&
                    refused { runBlocking { Mcp.signToolCall(signingConfig, SeedSigner(agent), call, ch) } } &&
                    refused { runBlocking { Mcp.signToolCall(signingConfig, SigningKey.Software(agent.key), call, ch) } })
        }
        t.finish(listOf("tool-call/arguments" to cases.size, "tool-call/envelopes" to 3 * cases.size,
            "tool-call/wrong_agent_key" to cases.size, "tool-call/refused_challenges" to refusedChallenges.size,
            "tool-call/refused_signings" to refusedSignings.size))
    }

    private fun connect() = runBlocking {
        val f = load("connect.json")
        val t = Tally("mcp")
        t.check("connect/constants", "constants", f.getString("domain") == Mcp.CONNECT_POSSESSION_DOMAIN &&
            f.getString("token_prefix") == Mcp.CONNECT_TOKEN_PREFIX && Mcp.MAX_CONNECT_TOKEN_LENGTH == 4096)
        val contexts = f.arr("contexts")
        for (c in contexts) {
            val got = Mcp.connectPossessionContext(c.getString("workspace_id"), c.getString("receiver_id"),
                c.getString("audience"), c.getString("challenge_id"), c.getString("agent_id"))
            t.check("connect/contexts", c.getString("name"), got.hex() == c.getString("session_context"))
        }
        val agent = agentKey(f.getJSONObject("agent_key"))
        val proofs = f.arr("proofs")
        for (c in proofs) {
            val name = c.getString("name")
            val token = c.getString("token")
            val tok = Mcp.parseConnectToken(token)
            val p = c.getJSONObject("parsed")
            val sess = Mcp.connectPossessionContext(tok.workspaceId, tok.receiverId, tok.audience, tok.challengeId, agent.key.keyId)
            t.check("connect/parsed", name, tok.challengeId == p.getString("challenge_id") &&
                Base64.getEncoder().encodeToString(tok.challenge) == p.getString("challenge") &&
                tok.issuedAt == p.getLong("issued_at") && tok.workspaceId == p.getString("workspace_id") &&
                tok.receiverId == p.getString("receiver_id") && tok.audience == p.getString("audience") &&
                tok.verifierId == p.getString("verifier_id") && sess.hex() == c.getString("session_context"))
            val want = c.getJSONObject("expected")
            val results = listOf(
                "software" to Mcp.provePossession(token, agent.key),
                "external" to Mcp.provePossession(token, SeedSigner(agent)),
                "signing-key" to Mcp.provePossession(token, SigningKey.Software(agent.key)),
            )
            for ((how, proof) in results) {
                t.check("connect/proofs", "$name $how", proof.connectChallengeId == want.getString("connect_challenge_id") &&
                    sameBundle(proof.possessionProof, want.getString("possession_proof")) &&
                    sameJson(proof.toJson(), mapOf("connect_challenge_id" to proof.connectChallengeId,
                        "possession_proof" to proof.possessionProof)))
            }
        }
        val invalid = f.arr("invalid_tokens")
        for (c in invalid) {
            val token = c.getString("token")
            t.check("connect/invalid_tokens", c.getString("name"), refused { Mcp.parseConnectToken(token) } &&
                refused { Mcp.provePossession(token, agent.key) } &&
                refused { runBlocking { Mcp.provePossession(token, SeedSigner(agent)) } })
        }
        t.finish(listOf("connect/constants" to 1, "connect/contexts" to contexts.size, "connect/parsed" to proofs.size,
            "connect/proofs" to 3 * proofs.size, "connect/invalid_tokens" to invalid.size))
    }

    /**
     * A ToolCall changed after newToolCall must not make the signer bind one
     * argument set (the digest) while the client sends another. A caller
     * cannot construct a ToolCall, and the arrays it hands out are copies,
     * so altering them changes neither the request nor the signed proof.
     */
    private fun toolCallCannotBeAltered() {
        val f = load("tool-call.json")
        val t = Tally("mcp")
        val cfg = Mcp.parseClientConfig(f.getString("client_config_json"))
        val agent = agentKey(f.getJSONObject("agent_key"))
        val c = f.arr("cases").first()
        val call = Mcp.newToolCall(c.getString("tool"), c.getString("arguments_json"))
        val before = cfg.challengeRequest(call)
        call.canonicalArguments.fill(' '.code.toByte())
        call.payloadDigest.fill(0)
        val ch = cfg.checkChallenge(c.getString("tool"), c.getString("challenge_response"), c.getLong("now"))
        val env = Mcp.signToolCall(cfg, agent.key, call, ch)
        t.check("intent", "tool call is immutable", cfg.challengeRequest(call).contentEquals(before) &&
            sameBundle(env.bundle, c.getJSONObject("envelope").getString("bundle")))
        t.finish(listOf("intent" to 1))
    }

    /**
     * A challenge is bound to the tool it was checked for: the server
     * issued it for that tool's scope, so it must never authorize a call to
     * another tool, even one with the same scope and the same arguments.
     */
    private fun challengeForAnotherTool() {
        val f = load("tool-call.json")
        val t = Tally("mcp")
        val cfg = Mcp.parseClientConfig(f.getString("client_config_json"))
        val agent = agentKey(f.getJSONObject("agent_key"))
        val c = f.arr("cases").first { Mcp.toolScope(it.getString("tool")) == "custom:verify.decisions:read" }
        val tool = c.getString("tool")
        val ch = cfg.checkChallenge(tool, c.getString("challenge_response"), c.getLong("now"))
        val other = Mcp.tools.first { it.scope == Mcp.toolScope(tool) && it.name != tool }.name
        val call = Mcp.newToolCall(other, c.getString("arguments_json"))
        t.check("intent", "challenge for $tool signs $other", refused { Mcp.signToolCall(cfg, agent.key, call, ch) })
        t.finish(listOf("intent" to 1))
    }
}
