package com.ratifyprotocol

import android.annotation.SuppressLint
import java.security.MessageDigest
import java.util.Base64

/**
 * Why the Verify MCP signer refused. Preview. Messages never carry key
 * material, proofs or tool arguments. Signing itself can also throw
 * [RatifyException].
 */
public sealed class McpException(message: String) : Exception(message) {
    /** The tool or its arguments are outside the restricted value model; nothing is signed. */
    public class InvalidArguments internal constructor(message: String) : McpException(message)

    /** The console client configuration is missing a field or has a field of the wrong form. */
    public class InvalidConfig internal constructor(message: String) : McpException(message)

    /** The challenge does not match the pinned configuration or the call, or expires too soon. */
    public class ChallengeRefused internal constructor(message: String) : McpException(message)

    /** The text is not a well-formed connect token from the console. */
    public class InvalidConnectToken internal constructor(message: String) : McpException(message)
}

/**
 * The client of the managed Ratify Verify MCP service. Preview: it is not
 * part of SPEC-v2 conformance, and its API may change before it is declared
 * stable.
 *
 * It signs the delegated-authority proof each tool call carries, answers the
 * console's connect challenge with a proof of possession of the agent key,
 * and parses the configuration the console hands out. Every hash is the
 * normative SPEC-v2 operation and session context construction; this object
 * only decides which values go in.
 *
 * Nothing here signs caller-chosen bytes. A tool-call proof is a SPEC-v2
 * challenge presentation whose session context the signer recomputes from
 * the call it was asked to make and the pinned configuration, never from a
 * hash the server supplies: verify before action.
 */
public object Mcp {
    /** The receiver-configuration action of every tool operation. */
    public const val ACTION: String = "mcp.tools/call"

    /** The params._meta key that carries the proof envelope. */
    public const val PROOF_META_KEY: String = "com.ratifyprotocol/proof"

    /** The MCP revision the hosted endpoint speaks. */
    public const val PROTOCOL_VERSION: String = "2026-07-28"

    /** The least lifetime, in seconds by the signer's clock, a challenge must have left to be signed. */
    public const val MIN_CHALLENGE_SECONDS_LEFT: Long = 10

    /** Separates the connect proof of possession from every per-call session context. */
    public const val CONNECT_POSSESSION_DOMAIN: String = "ratify-verify-mcp/connect-possession/v1"

    /** Starts the one-line connect challenge the console issues. */
    public const val CONNECT_TOKEN_PREFIX: String = "ratify-mcp-connect-1."

    /** Bound on a connect token's length. */
    public const val MAX_CONNECT_TOKEN_LENGTH: Int = 4096

    /** The deepest nesting a tool argument may have: the arguments object is depth 0. */
    public const val MAX_ARGUMENT_DEPTH: Int = 4

    /** One hosted tool and the exact custom scope it requires. */
    public class Tool internal constructor(public val name: String, public val scope: String) {
        override fun equals(other: Any?): Boolean = other is Tool && name == other.name && scope == other.scope
        override fun hashCode(): Int = 31 * name.hashCode() + scope.hashCode()
        override fun toString(): String = "Tool($name, $scope)"
    }

    /** The hosted tools, in a fixed order. */
    public val tools: List<Tool> = java.util.Collections.unmodifiableList(listOf(
        Tool("get_metrics", "custom:verify.metrics:read"),
        Tool("list_decisions", "custom:verify.decisions:read"),
        Tool("get_decision", "custom:verify.decisions:read"),
        Tool("list_events", "custom:verify.events:read"),
        Tool("list_agents", "custom:verify.agents:read"),
        Tool("list_evidence", "custom:verify.evidence:read"),
        Tool("get_evidence_package", "custom:verify.evidence:read"),
    ))

    /** The scope [name] requires, or null for a tool the service does not host. */
    public fun toolScope(name: String): String? = tools.firstOrNull { it.name == name }?.scope

    /**
     * The canonical bytes of the JSON text of params.arguments under the
     * restricted value model: objects with unique keys, strings, integers in
     * the safe range (no fraction, exponent or negative zero), booleans, and
     * arrays, nested at most [MAX_ARGUMENT_DEPTH] deep. Strings and keys
     * must be valid UTF-8 without control characters (U+0000 to U+001F,
     * U+007F to U+009F), U+2028, U+2029, or unpaired surrogate escapes. Empty
     * input, JSON whitespace, and the literal null mean the empty object.
     *
     * Canonical form: object keys sorted by their UTF-8 bytes, no
     * insignificant whitespace, strings with only `"` and `\` escaped, all
     * other characters as raw UTF-8, integers in decimal. Throws
     * [McpException.InvalidArguments].
     */
    public fun canonicalArguments(arguments: ByteArray): ByteArray = try {
        canonicalMcpArguments(arguments)
    } catch (e: McpJsonException) {
        throw McpException.InvalidArguments("tool arguments are outside the restricted value model")
    }

    /** [canonicalArguments] of a JSON text; an unpaired surrogate is refused. */
    public fun canonicalArguments(arguments: String): ByteArray =
        canonicalArguments(strictUtf8(arguments) ?: throw McpException.InvalidArguments("tool arguments are not valid Unicode"))

    /** SHA-256 of the canonical argument bytes. */
    public fun payloadDigest(canonicalArguments: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(canonicalArguments)

    /** The `sha256:<lowercase hex>` form the challenge request carries. */
    public fun payloadDigestText(digest: ByteArray): String = "sha256:" + hex(digest)

    /**
     * The SPEC-v2 operation context of one tool call: the tool's scope, the
     * operation `mcp.tools/call:<tool>`, the connection ID as resource, the
     * endpoint audience as requested path, and the 32-byte argument digest.
     * Throws [McpException.InvalidArguments] for an unknown tool.
     */
    public fun requestHash(tool: String, connectionId: String, audience: String, payloadDigest: ByteArray): ByteArray {
        val scope = toolScope(tool) ?: throw McpException.InvalidArguments("unknown tool")
        return operationContextHash(OperationContext(scope, "$ACTION:$tool", connectionId, audience, payloadDigest))
    }

    /** The SPEC-v2 session context a tool-call proof signs; the session ID is the connection ID. */
    public fun sessionContext(
        verifierId: String,
        workspaceId: String,
        agentId: String,
        connectionId: String,
        invocationId: String,
        requestHash: ByteArray,
    ): ByteArray = buildSessionContext(SessionContextInputs(verifierId, workspaceId, agentId, connectionId, invocationId, requestHash))

    /**
     * The 32-byte session context of the connect proof of possession: SHA-256
     * of [CONNECT_POSSESSION_DOMAIN] followed by the workspace ID, receiver
     * ID, audience, challenge ID and agent key ID, each prefixed with the
     * 8-byte big-endian length of its UTF-8 bytes.
     */
    public fun connectPossessionContext(
        workspaceId: String,
        receiverId: String,
        audience: String,
        challengeId: String,
        agentId: String,
    ): ByteArray {
        val h = MessageDigest.getInstance("SHA-256")
        h.update(CONNECT_POSSESSION_DOMAIN.toByteArray(Charsets.UTF_8))
        for (field in listOf(workspaceId, receiverId, audience, challengeId, agentId)) {
            val b = field.toByteArray(Charsets.UTF_8)
            h.update(java.nio.ByteBuffer.allocate(8).putLong(b.size.toLong()).array())
            h.update(b)
        }
        return h.digest()
    }

    /**
     * The configuration the console shows when an agent is connected: the
     * pinned endpoint and audience, the verifier and workspace, the
     * connection, and the delegation chain, root side first; the last
     * certificate is issued to the agent key.
     */
    public class ClientConfig internal constructor(
        public val endpoint: String,
        public val audience: String,
        public val verifierId: String,
        public val workspaceId: String,
        public val connectionId: String,
        delegations: List<DelegationCert>,
    ) {
        public val delegations: List<DelegationCert> = java.util.Collections.unmodifiableList(ArrayList(delegations))

        /**
         * The exact JSON body of `POST <endpoint>/challenge` for [call]. The
         * payload digest is re-derived from the call's canonical arguments.
         * Throws [McpException.InvalidArguments] for an inconsistent call.
         */
        public fun challengeRequest(call: ToolCall): ByteArray =
            ("{\"connection_id\":\"$connectionId\",\"tool\":\"${call.tool}\"," +
                "\"payload_digest\":\"${payloadDigestText(verifiedDigest(call))}\"}").toByteArray(Charsets.UTF_8)

        /**
         * Accept the JSON response (UTF-8) of `POST <endpoint>/challenge` only if
         * verifier_id and workspace_id equal the pinned values,
         * required_scope is the tool's scope, invocation_id is a lowercase
         * UUID, challenge is 32 bytes in canonical standard base64,
         * issued_at and expires_at are JSON integers with
         * 0 < issued_at <= expires_at, and at least
         * [MIN_CHALLENGE_SECONDS_LEFT] seconds remain at [now] (Unix
         * seconds). Other response fields, including any hash the server
         * supplies, are ignored. The challenge can sign only a call to [tool]
         * under this configuration. Throws [McpException.ChallengeRefused].
         */
        public fun checkChallenge(tool: String, response: ByteArray, now: Long): Challenge {
            fun refuse(why: String): Nothing = throw McpException.ChallengeRefused(why)
            val scope = toolScope(tool) ?: refuse("unknown tool")
            val msg = parseJson(response) as? McpJson.Obj ?: refuse("the challenge response is not a JSON object in UTF-8")
            val verifier = msg.string("verifier_id")
            val workspace = msg.string("workspace_id")
            val gotScope = msg.string("required_scope")
            val invocation = msg.string("invocation_id")
            val challengeText = msg.string("challenge")
            val issued = msg.integer("issued_at")
            val expires = msg.integer("expires_at")
            if (verifier == null || workspace == null || gotScope == null || invocation == null ||
                challengeText == null || issued == null || expires == null
            ) refuse("the challenge response is missing a field or has a field of the wrong type")
            if (verifier != verifierId || workspace != workspaceId) refuse("the challenge names another verifier or workspace")
            if (gotScope != scope) refuse("required_scope differs from this tool's scope")
            if (!UUID.matches(invocation)) refuse("invocation_id is not a lowercase UUID")
            val challenge = decodeStdBase64(challengeText)
            if (challenge == null || challenge.size != 32) refuse("challenge is not 32 bytes in canonical base64")
            // expires is within the safe range here, so the subtraction cannot wrap.
            if (issued <= 0 || issued > expires || now > expires - MIN_CHALLENGE_SECONDS_LEFT) {
                refuse("the challenge times are invalid or it expires too soon")
            }
            return Challenge(tool, verifierId, workspaceId, connectionId, challenge, invocation, issued, expires)
        }

        /** [checkChallenge] of a JSON text. */
        public fun checkChallenge(tool: String, response: String, now: Long): Challenge =
            checkChallenge(tool, strictUtf8(response) ?: throw McpException.ChallengeRefused("the challenge response is not valid Unicode"), now)
    }

    /**
     * Parse the console's client configuration: either the client_config
     * object itself or a JSON object that carries it under `client_config`
     * (the console's connect response). Other fields are ignored.
     *
     * - endpoint: `https://` and a lowercase host name with an optional
     *   port, nothing else (no path, query, fragment, credentials, or
     *   trailing slash)
     * - audience: exactly endpoint + `/mcp`
     * - verifier_id: 64 lowercase hex characters
     * - workspace_id, connection_id: lowercase UUIDs
     * - delegations: a non-empty array of canonical padded standard base64
     *   strings, each a SPEC-v2 delegation certificate, root side first: each
     *   certificate's subject (ID and public key) is the next one's issuer
     *
     * The text must be UTF-8.
     *
     * Throws [McpException.InvalidConfig].
     */
    public fun parseClientConfig(data: ByteArray): ClientConfig {
        fun refuse(): Nothing = throw McpException.InvalidConfig("invalid client configuration")
        var top = parseJson(data) as? McpJson.Obj ?: refuse()
        (top.members["client_config"] as? McpJson.Obj)?.let { top = it }
        val endpoint = top.string("endpoint") ?: refuse()
        val audience = top.string("audience") ?: refuse()
        val verifierId = top.string("verifier_id") ?: refuse()
        val workspaceId = top.string("workspace_id") ?: refuse()
        val connectionId = top.string("connection_id") ?: refuse()
        if (!validEndpoint(endpoint, audience) || !HEX64.matches(verifierId) ||
            !UUID.matches(workspaceId) || !UUID.matches(connectionId)
        ) refuse()
        val items = (top.members["delegations"] as? McpJson.Arr)?.items ?: refuse()
        if (items.isEmpty()) refuse()
        val delegations = items.map { item ->
            val wire = decodeStdBase64((item as? McpJson.Str)?.value ?: refuse()) ?: refuse()
            try {
                decodeDelegationCert(wire)
            } catch (e: RatifyException) {
                refuse()
            }
        }
        for (i in 0 until delegations.size - 1) {
            val parent = delegations[i]
            val child = delegations[i + 1]
            if (parent.subjectId != child.issuerId || parent.subjectPubKey != child.issuerPubKey) refuse()
        }
        return ClientConfig(endpoint, audience, verifierId, workspaceId, connectionId, delegations)
    }

    /** [parseClientConfig] of a JSON text. */
    public fun parseClientConfig(data: String): ClientConfig =
        parseClientConfig(strictUtf8(data) ?: throw McpException.InvalidConfig("invalid client configuration"))

    /**
     * One validated tool call: the tool and its canonical arguments. Send
     * [canonicalArguments] as params.arguments so the server computes the
     * same payload digest.
     */
    public class ToolCall internal constructor(public val tool: String, canonicalArguments: ByteArray) {
        private val canonical = canonicalArguments.copyOf()
        private val digest = Mcp.payloadDigest(canonical)

        public val canonicalArguments: ByteArray get() = canonical.copyOf()

        /** SHA-256 of [canonicalArguments]. */
        public val payloadDigest: ByteArray get() = digest.copyOf()
    }

    /** Validate the tool name and the JSON text of its arguments. Throws [McpException.InvalidArguments]. */
    public fun newToolCall(tool: String, arguments: ByteArray): ToolCall {
        if (toolScope(tool) == null) throw McpException.InvalidArguments("unknown tool")
        return ToolCall(tool, canonicalArguments(arguments))
    }

    /** [newToolCall] with the arguments as a JSON text. */
    public fun newToolCall(tool: String, arguments: String): ToolCall {
        if (toolScope(tool) == null) throw McpException.InvalidArguments("unknown tool")
        return ToolCall(tool, canonicalArguments(arguments))
    }

    /**
     * A challenge response [ClientConfig.checkChallenge] accepted. It can
     * sign only a call to the tool, and under the configuration (verifier,
     * workspace, connection), it was checked for.
     */
    public class Challenge internal constructor(
        internal val tool: String,
        internal val verifierId: String,
        internal val workspaceId: String,
        internal val connectionId: String,
        challenge: ByteArray,
        /** The server-generated invocation the proof binds. */
        public val invocationId: String,
        internal val issuedAt: Long,
        /** The challenge expiry in Unix seconds. */
        public val expiresAt: Long,
    ) {
        internal val challenge: ByteArray = challenge.copyOf()
    }

    /** The value of `params._meta["com.ratifyprotocol/proof"]` on tools/call. */
    public class ProofEnvelope internal constructor(
        public val connectionId: String,
        public val invocationId: String,
        /** The challenge, standard base64. */
        public val challenge: String,
        /** The SPEC-v2 proof bundle wire, standard base64. */
        public val bundle: String,
    ) {
        /** The envelope as a JSON object text. */
        public fun toJson(): String =
            "{\"connection_id\":\"$connectionId\",\"invocation_id\":\"$invocationId\"," +
                "\"challenge\":\"$challenge\",\"bundle\":\"$bundle\"}"
    }

    /**
     * Sign the tool-call proof with an in-process agent key. Refuses
     * ([McpException.ChallengeRefused]) a challenge checked for another tool
     * or configuration, and a configuration whose last delegation is not
     * issued to this key; refuses ([McpException.InvalidArguments]) an
     * inconsistent call. The bundle carries the delegations leaf first.
     */
    public fun signToolCall(config: ClientConfig, agentKey: SoftwarePrivateKey, call: ToolCall, challenge: Challenge): ProofEnvelope {
        val session = toolCallSession(config, agentKey.publicKey, call, challenge)
        val wire = encodeProofBundle(signProofBundle(unsignedBundle(config.verifierId, session, leafFirst(config), challenge.challenge, challenge.issuedAt), agentKey))
        return envelope(config, challenge, wire)
    }

    /** Sign the tool-call proof with an app-held [ExternalSigner]. */
    public suspend fun signToolCall(config: ClientConfig, signer: ExternalSigner, call: ToolCall, challenge: Challenge): ProofEnvelope {
        val session = toolCallSession(config, signer.publicKey, call, challenge)
        val wire = encodeProofBundle(signProofBundle(unsignedBundle(config.verifierId, session, leafFirst(config), challenge.challenge, challenge.issuedAt), signer))
        return envelope(config, challenge, wire)
    }

    /** Sign the tool-call proof with any [SigningKey]. */
    public suspend fun signToolCall(config: ClientConfig, with: SigningKey, call: ToolCall, challenge: Challenge): ProofEnvelope {
        val session = toolCallSession(config, publicKeyOf(with), call, challenge)
        val wire = encodeProofBundle(signProofBundle(unsignedBundle(config.verifierId, session, leafFirst(config), challenge.challenge, challenge.issuedAt), with))
        return envelope(config, challenge, wire)
    }

    /** A parsed connect challenge. */
    public class ConnectToken internal constructor(
        public val challengeId: String,
        challenge: ByteArray,
        public val issuedAt: Long,
        public val workspaceId: String,
        public val receiverId: String,
        public val audience: String,
        public val verifierId: String,
    ) {
        private val bytes = challenge.copyOf()

        /** The 32 challenge bytes. */
        public val challenge: ByteArray get() = bytes.copyOf()
    }

    /**
     * Parse [CONNECT_TOKEN_PREFIX] followed by unpadded base64url of a JSON
     * object with exactly the fields challenge_id, challenge, issued_at,
     * workspace_id, receiver_id, audience and verifier_id. IDs are lowercase
     * UUIDs, verifier_id is 64 lowercase hex characters, issued_at is a
     * positive integer, challenge is 32 bytes in canonical standard base64,
     * and audience is an endpoint (as in [parseClientConfig]) followed by
     * `/mcp`. Throws [McpException.InvalidConnectToken].
     */
    public fun parseConnectToken(token: String): ConnectToken {
        fun refuse(): Nothing = throw McpException.InvalidConnectToken("not a ratify-mcp-connect-1 token from the console")
        if (token.length > MAX_CONNECT_TOKEN_LENGTH || !token.startsWith(CONNECT_TOKEN_PREFIX)) refuse()
        val body = token.substring(CONNECT_TOKEN_PREFIX.length)
        if (!BASE64URL.matches(body)) refuse()
        val raw = try {
            Base64.getUrlDecoder().decode(body)
        } catch (e: IllegalArgumentException) {
            refuse()
        }
        if (Base64.getUrlEncoder().withoutPadding().encodeToString(raw) != body) refuse()
        val msg = parseJson(raw) as? McpJson.Obj ?: refuse()
        if (msg.members.size != CONNECT_TOKEN_FIELDS.size || !msg.members.keys.containsAll(CONNECT_TOKEN_FIELDS)) refuse()
        val challengeId = msg.string("challenge_id") ?: refuse()
        val challengeText = msg.string("challenge") ?: refuse()
        val workspaceId = msg.string("workspace_id") ?: refuse()
        val receiverId = msg.string("receiver_id") ?: refuse()
        val audience = msg.string("audience") ?: refuse()
        val verifierId = msg.string("verifier_id") ?: refuse()
        val issuedAt = msg.integer("issued_at") ?: refuse()
        if (issuedAt <= 0) refuse()
        if (!UUID.matches(challengeId) || !UUID.matches(workspaceId) || !UUID.matches(receiverId) ||
            !HEX64.matches(verifierId) || !audience.endsWith("/mcp") ||
            !validEndpoint(audience.removeSuffix("/mcp"), audience)
        ) refuse()
        val challenge = decodeStdBase64(challengeText) ?: refuse()
        if (challenge.size != 32) refuse()
        return ConnectToken(challengeId, challenge, issuedAt, workspaceId, receiverId, audience, verifierId)
    }

    /** What the connect request carries besides the certificate. */
    public class PossessionProof internal constructor(
        public val connectChallengeId: String,
        /** The SPEC-v2 proof bundle wire, standard base64. */
        public val possessionProof: String,
    ) {
        /** The proof as a JSON object text. */
        public fun toJson(): String =
            "{\"connect_challenge_id\":\"$connectChallengeId\",\"possession_proof\":\"$possessionProof\"}"
    }

    /**
     * Sign the connect challenge with the agent key being connected: a
     * SPEC-v2 proof bundle with no delegations whose challenge and
     * challenge_at are the token's, and whose session context is
     * [connectPossessionContext]. It never contacts the network. Throws
     * [McpException.InvalidConnectToken] for a malformed token.
     */
    public fun provePossession(token: String, agentKey: SoftwarePrivateKey): PossessionProof {
        val t = parseConnectToken(token)
        val session = possessionSession(t, agentKey.publicKey)
        return PossessionProof(t.challengeId, b64(encodeProofBundle(signProofBundle(unsignedBundle(t.verifierId, session, emptyList(), t.challenge, t.issuedAt), agentKey))))
    }

    /** [provePossession] with an app-held [ExternalSigner]. */
    public suspend fun provePossession(token: String, signer: ExternalSigner): PossessionProof {
        val t = parseConnectToken(token)
        val session = possessionSession(t, signer.publicKey)
        return PossessionProof(t.challengeId, b64(encodeProofBundle(signProofBundle(unsignedBundle(t.verifierId, session, emptyList(), t.challenge, t.issuedAt), signer))))
    }

    /** [provePossession] with any [SigningKey]. */
    public suspend fun provePossession(token: String, with: SigningKey): PossessionProof {
        val t = parseConnectToken(token)
        val session = possessionSession(t, publicKeyOf(with))
        return PossessionProof(t.challengeId, b64(encodeProofBundle(signProofBundle(unsignedBundle(t.verifierId, session, emptyList(), t.challenge, t.issuedAt), with))))
    }

    // Internals.

    private val ENDPOINT = Regex("^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[1-9][0-9]{0,4})?$")
    private val UUID = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    private val HEX64 = Regex("^[0-9a-f]{64}$")
    private val INTEGER = Regex("^-?(0|[1-9][0-9]*)$")
    private val BASE64URL = Regex("^[A-Za-z0-9_-]*$")
    private val CONNECT_TOKEN_FIELDS = listOf("audience", "challenge", "challenge_id", "issued_at", "receiver_id", "verifier_id", "workspace_id")

    private fun hex(b: ByteArray): String {
        val digits = "0123456789abcdef"
        val sb = StringBuilder(b.size * 2)
        for (x in b) sb.append(digits[x.toInt() shr 4 and 0xf]).append(digits[x.toInt() and 0xf])
        return sb.toString()
    }

    private fun b64(b: ByteArray): String = Base64.getEncoder().encodeToString(b)

    private fun validEndpoint(endpoint: String, audience: String): Boolean =
        ENDPOINT.matches(endpoint) && audience == "$endpoint/mcp"

    /** Canonical padded standard base64 only: re-encoding must give the text back. */
    private fun decodeStdBase64(text: String): ByteArray? {
        val raw = try {
            Base64.getDecoder().decode(text)
        } catch (e: IllegalArgumentException) {
            return null
        }
        return raw.takeIf { b64(it) == text }
    }

    /** A JSON text in valid UTF-8, or null. */
    private fun parseJson(data: ByteArray): McpJson? = if (!validUtf8(data)) null else try {
        McpJson.parse(data)
    } catch (e: McpJsonException) {
        null
    }

    private fun McpJson.Obj.string(name: String): String? = (members[name] as? McpJson.Str)?.value

    /** A JSON integer (no fraction, exponent, string or boolean) in the safe range. */
    private fun McpJson.Obj.integer(name: String): Long? {
        val text = (members[name] as? McpJson.Num)?.text ?: return null
        if (!INTEGER.matches(text)) return null
        val n = text.toLongOrNull() ?: return null
        return n.takeIf { it in -MCP_MAX_SAFE_INTEGER..MCP_MAX_SAFE_INTEGER }
    }

    @SuppressLint("NewApi") // SigningKey.Platform can only be constructed on API 33+.
    private fun publicKeyOf(k: SigningKey): HybridPublicKey = when (k) {
        is SigningKey.Software -> k.key.publicKey
        is SigningKey.External -> k.signer.publicKey
        is SigningKey.Platform -> k.key.publicKey
    }

    /** The agent key, its ID, and the session context of a tool call, after the refusals. */
    private class Session(val agentKey: HybridPublicKey, val agentId: String, val context: ByteArray)

    private fun toolCallSession(config: ClientConfig, agentKey: HybridPublicKey, call: ToolCall, challenge: Challenge): Session {
        if (challenge.tool != call.tool) throw McpException.ChallengeRefused("the challenge was checked for another tool")
        if (challenge.verifierId != config.verifierId || challenge.workspaceId != config.workspaceId ||
            challenge.connectionId != config.connectionId
        ) throw McpException.ChallengeRefused("the challenge was checked under another configuration")
        val digest = verifiedDigest(call)
        val agentId = keyId(agentKey)
        if (config.delegations.isEmpty() || config.delegations.last().subjectId != agentId) {
            throw McpException.ChallengeRefused("the last delegation certificate is not issued to this agent key")
        }
        val req = requestHash(call.tool, config.connectionId, config.audience, digest)
        return Session(agentKey, agentId, sessionContext(config.verifierId, config.workspaceId, agentId, config.connectionId, challenge.invocationId, req))
    }

    /** The configuration lists the chain root side first; a SPEC-v2 bundle carries it leaf first. */
    private fun leafFirst(config: ClientConfig): List<DelegationCert> = config.delegations.reversed()

    /**
     * The payload digest re-derived from the call's canonical arguments, so
     * a call can never make the signer bind one argument set and send
     * another.
     */
    private fun verifiedDigest(call: ToolCall): ByteArray {
        fun refuse(): Nothing = throw McpException.InvalidArguments("the tool call is inconsistent")
        if (toolScope(call.tool) == null) refuse()
        val stored = call.canonicalArguments
        val canonical = try {
            canonicalMcpArguments(stored)
        } catch (e: McpJsonException) {
            refuse()
        }
        if (stored.isEmpty() || !canonical.contentEquals(stored)) refuse()
        val digest = payloadDigest(canonical)
        if (!digest.contentEquals(call.payloadDigest)) refuse()
        return digest
    }

    private fun possessionSession(t: ConnectToken, agentKey: HybridPublicKey): Session {
        val agentId = keyId(agentKey)
        return Session(agentKey, agentId, connectPossessionContext(t.workspaceId, t.receiverId, t.audience, t.challengeId, agentId))
    }

    private fun unsignedBundle(
        verifierId: String,
        session: Session,
        delegations: List<DelegationCert>,
        challenge: ByteArray,
        challengeAt: Long,
    ): ProofBundle = ProofBundle(
        2, verifierId, session.agentId, session.agentKey, delegations, ByteArray(48), challenge, challengeAt,
        HybridSignature(ByteArray(0), ByteArray(0)), session.context, null, null,
    )

    private fun envelope(config: ClientConfig, challenge: Challenge, wire: ByteArray): ProofEnvelope =
        ProofEnvelope(config.connectionId, challenge.invocationId, b64(challenge.challenge), b64(wire))
}
