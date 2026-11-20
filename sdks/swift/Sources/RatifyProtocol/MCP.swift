import CryptoKit
import Foundation

/// The client side of the Ratify Verify MCP server (Preview): it signs the
/// delegated-authority proof each tool call carries, answers the console's
/// connect challenge with a proof of possession of the agent key, and parses
/// the configuration the console hands out.
///
/// Preview. This API talks to the managed Ratify Verify service. It is not
/// part of SPEC-v2 conformance, and it may change before it is declared
/// stable. Every hash is the normative SPEC-v2 operation and session context
/// construction; this namespace only decides which values go in.
///
/// Nothing here signs caller-chosen bytes. A tool-call proof is a SPEC-v2
/// challenge presentation whose session context the signer recomputes from
/// the call it was asked to make and the pinned configuration, never from a
/// hash the server supplies.
///
/// Text is handled as UTF-8 bytes throughout: keys are compared and sorted by
/// their bytes, never by Unicode canonical equivalence.
public enum MCP {
    /// The receiver-configuration action of every tool operation.
    public static let action = "mcp.tools/call"
    /// The params._meta key that carries the proof envelope.
    public static let proofMetaKey = "com.ratifyprotocol/proof"
    /// The MCP revision the hosted endpoint speaks.
    public static let protocolVersion = "2026-07-28"
    /// The least lifetime a challenge must have left, by the signer's clock,
    /// for the signer to sign it.
    public static let minChallengeSecondsLeft: Int64 = 10
    /// Separates the connect proof of possession from every per-call session context.
    public static let connectPossessionDomain = "ratify-verify-mcp/connect-possession/v1"
    /// Starts the one-line connect challenge the console issues.
    public static let connectTokenPrefix = "ratify-mcp-connect-1."
    /// The longest connect token accepted, in bytes.
    public static let maxConnectTokenLength = 4096
    /// The deepest nesting an argument value may have: the arguments object
    /// is depth 0 and each enclosing object or array adds one.
    public static let maxArgumentDepth = 4

    /// One hosted tool and the exact custom scope it requires.
    public struct Tool: Sendable, Hashable {
        public let name: String
        public let scope: String
    }

    /// The hosted tools, in a fixed order.
    public static let tools: [Tool] = [
        Tool(name: "get_metrics", scope: "custom:verify.metrics:read"),
        Tool(name: "list_decisions", scope: "custom:verify.decisions:read"),
        Tool(name: "get_decision", scope: "custom:verify.decisions:read"),
        Tool(name: "list_events", scope: "custom:verify.events:read"),
        Tool(name: "list_agents", scope: "custom:verify.agents:read"),
        Tool(name: "list_evidence", scope: "custom:verify.evidence:read"),
        Tool(name: "get_evidence_package", scope: "custom:verify.evidence:read"),
    ]

    /// The scope a tool requires, or nil for a tool the hosted table does not name.
    public static func toolScope(_ name: String) -> String? {
        let bytes = Array(name.utf8)
        return tools.first { Array($0.name.utf8) == bytes }?.scope
    }

    /// Why the signer refused. Messages never carry key material, proofs or
    /// argument values.
    public enum SignerError: Error, Sendable, Hashable, CustomStringConvertible {
        /// The tool or its arguments are outside the restricted value model; nothing is signed.
        case invalidArguments
        /// The console client configuration is missing a field or has a field of the wrong form.
        case invalidConfig
        /// The challenge does not match the pinned configuration or the call,
        /// expires too soon, or the configuration's last delegation is not
        /// issued to the signing key.
        case challengeRefused
        /// The text is not a well-formed connect token from the console.
        case invalidConnectToken

        public var description: String {
            switch self {
            case .invalidArguments: return "mcp: invalid tool arguments"
            case .invalidConfig: return "mcp: invalid client configuration"
            case .challengeRefused: return "mcp: challenge refused"
            case .invalidConnectToken: return "mcp: not a ratify-mcp-connect-1 token from the console"
            }
        }
    }

    // MARK: Binding

    /// Parse the JSON text of params.arguments under the restricted value
    /// model and return its canonical bytes. The model allows objects with
    /// unique keys, strings, integers in the safe range (no fraction,
    /// exponent, or negative zero), booleans, and arrays, nested at most
    /// `maxArgumentDepth` deep. Strings and keys must be valid UTF-8 without
    /// control characters (U+0000 to U+001F, U+007F to U+009F), U+2028,
    /// U+2029, or unpaired surrogate escapes. Empty input, JSON whitespace,
    /// and the literal null mean the empty object.
    ///
    /// Canonical form: object keys sorted by their UTF-8 bytes, no
    /// insignificant whitespace, strings with only '"' and '\' escaped,
    /// integers in decimal.
    public static func canonicalArguments(_ json: Data) throws(SignerError) -> Data {
        let input = [UInt8](json)
        var lo = 0, hi = input.count
        while lo < hi, isSpace(input[lo]) { lo += 1 }
        while hi > lo, isSpace(input[hi - 1]) { hi -= 1 }
        if lo == hi || input[lo..<hi].elementsEqual("null".utf8) { return Data("{}".utf8) }
        var p = ArgParser(input: input)
        p.space()
        guard p.pos < input.count, input[p.pos] == UInt8(ascii: "{") else { throw .invalidArguments }
        guard let v = p.value(0) else { throw .invalidArguments }
        p.space()
        guard p.pos == input.count else { throw .invalidArguments }
        var out = [UInt8]()
        writeArg(&out, v)
        return Data(out)
    }

    /// `canonicalArguments` of the UTF-8 bytes of `json`.
    public static func canonicalArguments(_ json: String) throws(SignerError) -> Data {
        try canonicalArguments(Data(json.utf8))
    }

    /// SHA-256 of the canonical argument bytes.
    public static func payloadDigest(_ canonicalArguments: Data) -> Data {
        Data(SHA256.hash(data: canonicalArguments))
    }

    /// The `sha256:<hex>` form the challenge request carries.
    public static func payloadDigestText(_ digest: Data) -> String {
        "sha256:" + lowerHex(digest)
    }

    /// The SPEC-v2 operation context of one tool call: the tool's scope, the
    /// operation "mcp.tools/call:<tool>", the connection ID as resource, the
    /// endpoint audience as requested path, and the argument digest. Throws
    /// `SignerError.invalidArguments` for a tool the hosted table does not
    /// name, and `RatifyError` if the core refuses an input.
    public static func requestHash(tool: String, connectionId: String, audience: String, payloadDigest: Data) throws -> Data {
        guard let scope = toolScope(tool) else { throw SignerError.invalidArguments }
        return try Ratify.operationContextHash(OperationContext(
            requiredScope: scope, operation: action + ":" + tool, resourceId: connectionId,
            requestedPath: audience, payloadDigest: payloadDigest))
    }

    /// The SPEC-v2 session context a tool-call proof signs. The session ID
    /// is the connection ID.
    public static func sessionContext(verifierId: String, workspaceId: String, agentId: String, connectionId: String,
                                      invocationId: String, requestHash: Data) throws(RatifyError) -> Data {
        try Ratify.buildSessionContext(SessionContextInputs(
            verifierId: verifierId, workspaceId: workspaceId, agentId: agentId,
            sessionId: connectionId, invocationId: invocationId, requestHash: requestHash))
    }

    /// The 32-byte session context of the connect proof of possession:
    /// SHA-256 of `connectPossessionDomain` followed by the workspace ID,
    /// receiver ID, audience, challenge ID, and agent key ID, each prefixed
    /// with its 8-byte big-endian UTF-8 length.
    public static func connectPossessionContext(workspaceId: String, receiverId: String, audience: String,
                                                challengeId: String, agentId: String) -> Data {
        var h = SHA256()
        h.update(data: Data(connectPossessionDomain.utf8))
        for field in [workspaceId, receiverId, audience, challengeId, agentId] {
            let bytes = Data(field.utf8)
            var n = UInt64(bytes.count).bigEndian
            withUnsafeBytes(of: &n) { h.update(bufferPointer: $0) }
            h.update(data: bytes)
        }
        return Data(h.finalize())
    }

    // MARK: Client configuration

    /// The configuration the console shows when an agent is connected: the
    /// pinned endpoint and audience, the verifier and workspace, the
    /// connection, and the delegation chain ending at the agent key.
    public struct ClientConfig: Sendable, Hashable {
        public let endpoint: String
        public let audience: String
        public let verifierId: String
        public let workspaceId: String
        public let connectionId: String
        /// The decoded certificates, root side first; the last one is issued
        /// to the agent key.
        public let delegations: [DelegationCert]

        /// The exact JSON body of `POST <endpoint>/challenge` for `call`.
        /// Throws `invalidArguments` if the call's fields are inconsistent.
        public func challengeRequest(_ call: ToolCall) throws(SignerError) -> Data {
            let digest = try call.verifiedDigest()
            var out = [UInt8]("{\"connection_id\":".utf8)
            appendJSONString(&out, connectionId)
            out += Array(",\"tool\":".utf8)
            appendJSONString(&out, call.tool)
            out += Array(",\"payload_digest\":".utf8)
            appendJSONString(&out, payloadDigestText(digest))
            out.append(UInt8(ascii: "}"))
            return Data(out)
        }

        /// Accept the JSON response of `POST <endpoint>/challenge` only if
        /// verifier_id and workspace_id equal the pinned values,
        /// required_scope is the tool's scope, invocation_id is a lowercase
        /// UUID, challenge is 32 bytes in canonical standard base64,
        /// issued_at and expires_at are JSON integers with
        /// 0 < issued_at <= expires_at, and at least
        /// `minChallengeSecondsLeft` seconds remain at `now` (Unix seconds).
        /// Unknown response fields are ignored.
        public func checkChallenge(tool: String, response: Data, now: Int64) throws(SignerError) -> Challenge {
            guard let scope = toolScope(tool),
                  case let .object(msg)? = JSONReader.parse(response),
                  let verifier = msg.string("verifier_id"), let workspace = msg.string("workspace_id"),
                  let gotScope = msg.string("required_scope"), let invocation = msg.string("invocation_id"),
                  let challengeText = msg.string("challenge"),
                  let issued = msg.integer("issued_at"), let expires = msg.integer("expires_at")
            else { throw .challengeRefused }
            guard verifier == Array(verifierId.utf8), workspace == Array(workspaceId.utf8),
                  gotScope == Array(scope.utf8), isUUID(invocation)
            else { throw .challengeRefused }
            guard let challenge = decodeStdBase64(challengeText), challenge.count == 32 else { throw .challengeRefused }
            // expires is within the safe range here, so the subtraction cannot wrap.
            guard issued > 0, issued <= expires, now <= expires - minChallengeSecondsLeft else { throw .challengeRefused }
            return Challenge(tool: tool, verifierId: verifierId, workspaceId: workspaceId, connectionId: connectionId,
                             challenge: challenge, invocationId: ascii(invocation), issuedAt: issued, expiresAt: expires)
        }
    }

    /// Parse the console's client configuration: either the client_config
    /// object itself or a JSON object that carries it under "client_config"
    /// (the console's connect response). Fields other than the six below are
    /// ignored, so a signer configuration file that also holds a key
    /// reference parses too.
    ///
    /// - endpoint: "https://" and a lowercase host name with an optional
    ///   port, nothing else (no path, query, fragment, credentials, or
    ///   trailing slash)
    /// - audience: exactly endpoint + "/mcp"
    /// - verifier_id: 64 lowercase hex characters
    /// - workspace_id, connection_id: lowercase UUIDs
    /// - delegations: a non-empty array of canonical padded standard base64
    ///   strings, each a SPEC-v2 delegation certificate, root side first:
    ///   each certificate's subject is the next one's issuer (ID and key)
    ///
    /// The input must be valid UTF-8.
    public static func parseClientConfig(_ json: Data) throws(SignerError) -> ClientConfig {
        guard case var .object(top)? = JSONReader.parse(json) else { throw .invalidConfig }
        if case let .object(nested)? = top[Array("client_config".utf8)] { top = nested }
        guard let endpoint = top.string("endpoint"), let audience = top.string("audience"),
              let verifier = top.string("verifier_id"), let workspace = top.string("workspace_id"),
              let connection = top.string("connection_id")
        else { throw .invalidConfig }
        guard validEndpoint(endpoint, audience: audience), isHex64(verifier), isUUID(workspace), isUUID(connection),
              case let .array(items)? = top[Array("delegations".utf8)], !items.isEmpty
        else { throw .invalidConfig }
        var delegations: [DelegationCert] = []
        for item in items {
            guard case let .string(text) = item, let wire = decodeStdBase64(text),
                  let cert = try? Ratify.decodeDelegationCert(wire)
            else { throw .invalidConfig }
            delegations.append(cert)
        }
        for (parent, child) in zip(delegations, delegations.dropFirst()) {
            guard Array(parent.subjectId.utf8) == Array(child.issuerId.utf8), parent.subjectPubKey == child.issuerPubKey
            else { throw .invalidConfig }
        }
        return ClientConfig(endpoint: ascii(endpoint), audience: ascii(audience), verifierId: ascii(verifier),
                            workspaceId: ascii(workspace), connectionId: ascii(connection), delegations: delegations)
    }

    /// `parseClientConfig` of the UTF-8 bytes of `json`.
    public static func parseClientConfig(_ json: String) throws(SignerError) -> ClientConfig {
        try parseClientConfig(Data(json.utf8))
    }

    // MARK: Tool calls

    /// One validated tool call: the tool and its canonical arguments. Send
    /// `canonicalArguments` as params.arguments so the server computes the
    /// same payload digest.
    public struct ToolCall: Sendable, Hashable {
        public let tool: String
        public let canonicalArguments: Data
        public let payloadDigest: Data

        /// Re-derive the payload digest from the canonical arguments, so the
        /// signer never binds one argument set while another is sent.
        func verifiedDigest() throws(SignerError) -> Data {
            guard toolScope(tool) != nil, !canonicalArguments.isEmpty,
                  try MCP.canonicalArguments(canonicalArguments) == canonicalArguments
            else { throw .invalidArguments }
            let digest = MCP.payloadDigest(canonicalArguments)
            guard digest == payloadDigest else { throw .invalidArguments }
            return digest
        }
    }

    /// Validate the tool name and the JSON text of its arguments.
    public static func newToolCall(tool: String, arguments: Data) throws(SignerError) -> ToolCall {
        guard toolScope(tool) != nil else { throw .invalidArguments }
        let canonical = try canonicalArguments(arguments)
        return ToolCall(tool: tool, canonicalArguments: canonical, payloadDigest: payloadDigest(canonical))
    }

    /// `newToolCall` with the UTF-8 bytes of `arguments`.
    public static func newToolCall(tool: String, arguments: String) throws(SignerError) -> ToolCall {
        try newToolCall(tool: tool, arguments: Data(arguments.utf8))
    }

    /// A challenge response that `ClientConfig.checkChallenge` accepted. It
    /// signs only a call to the tool, and under the configuration (verifier,
    /// workspace, connection), it was checked for.
    public struct Challenge: Sendable, Hashable {
        let tool: String
        let verifierId: String
        let workspaceId: String
        let connectionId: String
        let challenge: Data
        /// The server-generated invocation the proof binds.
        public let invocationId: String
        let issuedAt: Int64
        /// The challenge expiry in Unix seconds.
        public let expiresAt: Int64
    }

    /// The value of params._meta[`proofMetaKey`] on tools/call. Encodes to
    /// the JSON object the hosted service expects.
    public struct ProofEnvelope: Sendable, Hashable, Encodable {
        public let connectionId: String
        public let invocationId: String
        /// The challenge in standard base64.
        public let challenge: String
        /// The SPEC-v2 proof bundle wire in standard base64.
        public let bundle: String

        private enum CodingKeys: String, CodingKey {
            case connectionId = "connection_id", invocationId = "invocation_id", challenge, bundle
        }
    }

    /// Sign the tool-call proof with an in-process agent key. Refuses
    /// (`SignerError.challengeRefused`) a challenge checked for another tool
    /// or under another configuration, and a configuration whose last
    /// delegation is not issued to this key; refuses an inconsistent call
    /// (`SignerError.invalidArguments`); signing failures are `RatifyError`.
    /// The bundle carries the configuration's chain leaf first.
    public static func signToolCall(config: ClientConfig, agentKey: SoftwarePrivateKey, call: ToolCall,
                                    challenge: Challenge) throws -> ProofEnvelope {
        let unsigned = try toolCallBundle(config, agentKey.publicKey, call, challenge)
        return try envelope(config, challenge, Ratify.signProofBundle(unsigned, key: agentKey))
    }

    /// `signToolCall` with an external signer.
    public static func signToolCall(config: ClientConfig, signer: any ExternalSigner, call: ToolCall,
                                    challenge: Challenge) async throws -> ProofEnvelope {
        let unsigned = try toolCallBundle(config, signer.publicKey, call, challenge)
        return try envelope(config, challenge, await Ratify.signProofBundle(unsigned, signer: signer))
    }

    private static func toolCallBundle(_ c: ClientConfig, _ pub: HybridPublicKey, _ call: ToolCall,
                                       _ ch: Challenge) throws -> ProofBundle {
        guard Array(ch.tool.utf8) == Array(call.tool.utf8), let last = c.delegations.last,
              Array(ch.verifierId.utf8) == Array(c.verifierId.utf8), Array(ch.workspaceId.utf8) == Array(c.workspaceId.utf8),
              Array(ch.connectionId.utf8) == Array(c.connectionId.utf8)
        else { throw SignerError.challengeRefused }
        let digest = try call.verifiedDigest()
        let agentId = try Ratify.keyId(pub)
        guard Array(last.subjectId.utf8) == Array(agentId.utf8) else { throw SignerError.challengeRefused }
        let request = try requestHash(tool: call.tool, connectionId: c.connectionId, audience: c.audience,
                                      payloadDigest: digest)
        let session = try sessionContext(verifierId: c.verifierId, workspaceId: c.workspaceId, agentId: agentId,
                                         connectionId: c.connectionId, invocationId: ch.invocationId, requestHash: request)
        // The configuration lists the chain root side first; a SPEC-v2
        // bundle carries it leaf first.
        return presentation(c.verifierId, agentId, pub, c.delegations.reversed(), ch.challenge, ch.issuedAt, session)
    }

    private static func envelope(_ c: ClientConfig, _ ch: Challenge, _ signed: ProofBundle) throws -> ProofEnvelope {
        ProofEnvelope(connectionId: c.connectionId, invocationId: ch.invocationId,
                      challenge: ch.challenge.base64EncodedString(),
                      bundle: try Ratify.encodeProofBundle(signed).base64EncodedString())
    }

    /// The unsigned SPEC-v2 presentation: version 2, no stream fields; the
    /// signing function fills the delegation digest and the signature.
    private static func presentation(_ verifierId: String, _ agentId: String, _ pub: HybridPublicKey,
                                     _ delegations: [DelegationCert], _ challenge: Data, _ challengeAt: Int64,
                                     _ session: Data) -> ProofBundle {
        ProofBundle(version: 2, verifierId: verifierId, agentId: agentId, agentPubKey: pub, delegations: delegations,
                    delegationDigest: Data(count: 48), challenge: challenge, challengeAt: challengeAt,
                    challengeSig: HybridSignature(ed25519: Data(), mlDsa65: Data()), sessionContext: session,
                    streamId: nil, streamSeq: nil)
    }

    // MARK: Connect

    /// A parsed connect challenge.
    public struct ConnectToken: Sendable, Hashable {
        public let challengeId: String
        public let challenge: Data
        public let issuedAt: Int64
        public let workspaceId: String
        public let receiverId: String
        public let audience: String
        public let verifierId: String
    }

    private static let connectTokenFields = ["audience", "challenge", "challenge_id", "issued_at",
                                             "receiver_id", "verifier_id", "workspace_id"]

    /// Parse `connectTokenPrefix` followed by unpadded base64url of a JSON
    /// object with exactly the fields challenge_id, challenge, issued_at,
    /// workspace_id, receiver_id, audience, and verifier_id. IDs are
    /// lowercase UUIDs, verifier_id is 64 lowercase hex characters,
    /// issued_at is a positive integer, challenge is 32 bytes in canonical
    /// standard base64, and audience is an endpoint (as in
    /// `parseClientConfig`) followed by "/mcp".
    public static func parseConnectToken(_ token: String) throws(SignerError) -> ConnectToken {
        let bytes = Array(token.utf8), prefix = Array(connectTokenPrefix.utf8)
        guard bytes.count <= maxConnectTokenLength, bytes.starts(with: prefix) else { throw .invalidConnectToken }
        let body = Array(bytes[prefix.count...])
        guard body.allSatisfy(isBase64URLByte), let raw = decodeRawBase64URL(body),
              case let .object(msg)? = JSONReader.parse(raw), msg.count == connectTokenFields.count,
              connectTokenFields.allSatisfy({ msg[Array($0.utf8)] != nil })
        else { throw .invalidConnectToken }
        guard let challengeId = msg.string("challenge_id"), let challengeText = msg.string("challenge"),
              let workspace = msg.string("workspace_id"), let receiver = msg.string("receiver_id"),
              let audience = msg.string("audience"), let verifier = msg.string("verifier_id"),
              let issued = msg.integer("issued_at"), issued > 0
        else { throw .invalidConnectToken }
        let suffix = Array("/mcp".utf8)
        guard isUUID(challengeId), isUUID(workspace), isUUID(receiver), isHex64(verifier),
              audience.count >= suffix.count, audience.suffix(suffix.count).elementsEqual(suffix),
              validEndpoint(Array(audience.dropLast(suffix.count)), audience: audience)
        else { throw .invalidConnectToken }
        guard let challenge = decodeStdBase64(challengeText), challenge.count == 32 else { throw .invalidConnectToken }
        return ConnectToken(challengeId: ascii(challengeId), challenge: challenge, issuedAt: issued,
                            workspaceId: ascii(workspace), receiverId: ascii(receiver), audience: ascii(audience),
                            verifierId: ascii(verifier))
    }

    /// What the connect request carries besides the certificate: the
    /// challenge ID and the proof bundle in standard base64. Encodes to the
    /// JSON object the console expects.
    public struct PossessionProof: Sendable, Hashable, Encodable {
        public let connectChallengeId: String
        public let possessionProof: String

        private enum CodingKeys: String, CodingKey {
            case connectChallengeId = "connect_challenge_id", possessionProof = "possession_proof"
        }
    }

    /// Sign the connect challenge with the agent key being connected: a
    /// SPEC-v2 proof bundle with no delegations whose challenge and
    /// challenge_at are the token's, and whose session context is
    /// `connectPossessionContext`. It never contacts the network.
    public static func provePossession(token: String, agentKey: SoftwarePrivateKey) throws -> PossessionProof {
        let (t, unsigned) = try possessionBundle(token, agentKey.publicKey)
        return try possessionProof(t, Ratify.signProofBundle(unsigned, key: agentKey))
    }

    /// `provePossession` with an external signer.
    public static func provePossession(token: String, signer: any ExternalSigner) async throws -> PossessionProof {
        let (t, unsigned) = try possessionBundle(token, signer.publicKey)
        return try possessionProof(t, await Ratify.signProofBundle(unsigned, signer: signer))
    }

    private static func possessionBundle(_ token: String, _ pub: HybridPublicKey) throws -> (ConnectToken, ProofBundle) {
        let t = try parseConnectToken(token)
        let agentId = try Ratify.keyId(pub)
        let session = connectPossessionContext(workspaceId: t.workspaceId, receiverId: t.receiverId, audience: t.audience,
                                               challengeId: t.challengeId, agentId: agentId)
        return (t, presentation(t.verifierId, agentId, pub, [], t.challenge, t.issuedAt, session))
    }

    private static func possessionProof(_ t: ConnectToken, _ signed: ProofBundle) throws -> PossessionProof {
        PossessionProof(connectChallengeId: t.challengeId,
                        possessionProof: try Ratify.encodeProofBundle(signed).base64EncodedString())
    }
}

// MARK: - Restricted argument reader (byte level)

private indirect enum ArgValue {
    case object([(key: [UInt8], value: ArgValue)])
    case array([ArgValue])
    case string([UInt8])
    case int(Int64)
    case bool(Bool)
}

private let maxSafeInteger: Int64 = (1 << 53) - 1

private func isSpace(_ c: UInt8) -> Bool { c == 0x20 || c == 0x09 || c == 0x0D || c == 0x0A }

private struct ArgParser {
    let input: [UInt8]
    var pos = 0

    init(input: [UInt8]) { self.input = input }

    mutating func space() {
        while pos < input.count, isSpace(input[pos]) { pos += 1 }
    }

    mutating func literal(_ word: String) -> Bool {
        let w = Array(word.utf8)
        guard input.count - pos >= w.count, input[pos..<pos + w.count].elementsEqual(w) else { return false }
        pos += w.count
        return true
    }

    mutating func value(_ depth: Int) -> ArgValue? {
        guard depth <= MCP.maxArgumentDepth else { return nil }
        space()
        guard pos < input.count else { return nil }
        switch input[pos] {
        case UInt8(ascii: "{"):
            pos += 1
            var entries: [(key: [UInt8], value: ArgValue)] = []
            var seen = Set<[UInt8]>()
            space()
            if pos < input.count, input[pos] == UInt8(ascii: "}") {
                pos += 1
                return .object(entries)
            }
            while true {
                space()
                guard let key = string(), !seen.contains(key) else { return nil }
                space()
                guard pos < input.count, input[pos] == UInt8(ascii: ":") else { return nil }
                pos += 1
                guard let child = value(depth + 1) else { return nil }
                seen.insert(key)
                entries.append((key, child))
                space()
                guard pos < input.count else { return nil }
                if input[pos] == UInt8(ascii: ",") { pos += 1; continue }
                if input[pos] == UInt8(ascii: "}") { pos += 1; return .object(entries) }
                return nil
            }
        case UInt8(ascii: "["):
            pos += 1
            var items: [ArgValue] = []
            space()
            if pos < input.count, input[pos] == UInt8(ascii: "]") {
                pos += 1
                return .array(items)
            }
            while true {
                guard let child = value(depth + 1) else { return nil }
                items.append(child)
                space()
                guard pos < input.count else { return nil }
                if input[pos] == UInt8(ascii: ",") { pos += 1; continue }
                if input[pos] == UInt8(ascii: "]") { pos += 1; return .array(items) }
                return nil
            }
        case UInt8(ascii: "\""):
            return string().map(ArgValue.string)
        case UInt8(ascii: "t"):
            return literal("true") ? .bool(true) : nil
        case UInt8(ascii: "f"):
            return literal("false") ? .bool(false) : nil
        case UInt8(ascii: "-"), UInt8(ascii: "0")...UInt8(ascii: "9"):
            return number()
        default:
            return nil
        }
    }

    /// Only the JSON integer grammar -?(0|[1-9][0-9]*), in the safe range.
    mutating func number() -> ArgValue? {
        let start = pos
        if input[pos] == UInt8(ascii: "-") { pos += 1 }
        guard pos < input.count else { return nil }
        if input[pos] == UInt8(ascii: "0") {
            pos += 1
        } else if (UInt8(ascii: "1")...UInt8(ascii: "9")).contains(input[pos]) {
            while pos < input.count, (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(input[pos]) { pos += 1 }
        } else {
            return nil
        }
        if pos < input.count, [UInt8(ascii: "."), UInt8(ascii: "e"), UInt8(ascii: "E")].contains(input[pos]) {
            return nil
        }
        let text = String(decoding: input[start..<pos], as: UTF8.self)
        guard text != "-0", text.utf8.count <= 17, let n = Int64(text), n <= maxSafeInteger, n >= -maxSafeInteger else {
            return nil
        }
        return .int(n)
    }

    mutating func hex4() -> UInt32? {
        guard input.count - pos >= 4 else { return nil }
        var r: UInt32 = 0
        for c in input[pos..<pos + 4] {
            r <<= 4
            switch c {
            case UInt8(ascii: "0")...UInt8(ascii: "9"): r |= UInt32(c - UInt8(ascii: "0"))
            case UInt8(ascii: "a")...UInt8(ascii: "f"): r |= UInt32(c - UInt8(ascii: "a")) + 10
            case UInt8(ascii: "A")...UInt8(ascii: "F"): r |= UInt32(c - UInt8(ascii: "A")) + 10
            default: return nil
            }
        }
        pos += 4
        return r
    }

    /// A string's exact UTF-8 bytes after unescaping; nil if refused.
    mutating func string() -> [UInt8]? {
        guard pos < input.count, input[pos] == UInt8(ascii: "\"") else { return nil }
        pos += 1
        var out: [UInt8] = []
        while true {
            guard pos < input.count else { return nil }
            let c = input[pos]
            if c == UInt8(ascii: "\"") {
                pos += 1
                return out
            }
            if c == UInt8(ascii: "\\") {
                pos += 1
                guard pos < input.count else { return nil }
                let e = input[pos]
                pos += 1
                switch e {
                case UInt8(ascii: "\""), UInt8(ascii: "\\"), UInt8(ascii: "/"):
                    out.append(e)
                case UInt8(ascii: "u"):
                    guard var r = hex4() else { return nil }
                    if (0xD800...0xDFFF).contains(r) {
                        guard r < 0xDC00, literal("\\u"), let low = hex4(), (0xDC00...0xDFFF).contains(low) else { return nil }
                        r = 0x10000 + ((r - 0xD800) << 10) + (low - 0xDC00)
                    }
                    guard allowedScalar(r) else { return nil }
                    appendUTF8(&out, r)
                default:
                    // \b \f \n \r \t decode to control characters, which the
                    // model refuses; any other escape is not JSON.
                    return nil
                }
                continue
            }
            guard let (r, size) = decodeUTF8(input, pos), allowedScalar(r) else { return nil }
            out.append(contentsOf: input[pos..<pos + size])
            pos += size
        }
    }
}

private func allowedScalar(_ r: UInt32) -> Bool {
    !(r < 0x20 || (0x7F...0x9F).contains(r) || r == 0x2028 || r == 0x2029 || (0xD800...0xDFFF).contains(r))
}

/// Strict UTF-8: no overlong forms, no encoded surrogates, nothing above U+10FFFF.
private func decodeUTF8(_ b: [UInt8], _ i: Int) -> (UInt32, Int)? {
    let b0 = b[i]
    if b0 < 0x80 { return (UInt32(b0), 1) }
    func cont(_ k: Int, _ lo: UInt8 = 0x80, _ hi: UInt8 = 0xBF) -> UInt32? {
        guard i + k < b.count, (lo...hi).contains(b[i + k]) else { return nil }
        return UInt32(b[i + k] & 0x3F)
    }
    switch b0 {
    case 0xC2...0xDF:
        guard let c1 = cont(1) else { return nil }
        return ((UInt32(b0 & 0x1F) << 6) | c1, 2)
    case 0xE0...0xEF:
        let lo: UInt8 = b0 == 0xE0 ? 0xA0 : 0x80, hi: UInt8 = b0 == 0xED ? 0x9F : 0xBF
        guard let c1 = cont(1, lo, hi), let c2 = cont(2) else { return nil }
        return ((UInt32(b0 & 0x0F) << 12) | (c1 << 6) | c2, 3)
    case 0xF0...0xF4:
        let lo: UInt8 = b0 == 0xF0 ? 0x90 : 0x80, hi: UInt8 = b0 == 0xF4 ? 0x8F : 0xBF
        guard let c1 = cont(1, lo, hi), let c2 = cont(2), let c3 = cont(3) else { return nil }
        return ((UInt32(b0 & 0x07) << 18) | (c1 << 12) | (c2 << 6) | c3, 4)
    default:
        return nil
    }
}

private func appendUTF8(_ out: inout [UInt8], _ r: UInt32) {
    switch r {
    case ..<0x80: out.append(UInt8(r))
    case ..<0x800: out += [UInt8(0xC0 | (r >> 6)), UInt8(0x80 | (r & 0x3F))]
    case ..<0x10000: out += [UInt8(0xE0 | (r >> 12)), UInt8(0x80 | ((r >> 6) & 0x3F)), UInt8(0x80 | (r & 0x3F))]
    default:
        out += [UInt8(0xF0 | (r >> 18)), UInt8(0x80 | ((r >> 12) & 0x3F)), UInt8(0x80 | ((r >> 6) & 0x3F)), UInt8(0x80 | (r & 0x3F))]
    }
}

private func writeArg(_ out: inout [UInt8], _ v: ArgValue) {
    switch v {
    case let .object(entries):
        out.append(UInt8(ascii: "{"))
        // Keys sorted by their UTF-8 bytes (unique, so the order is total).
        for (i, e) in entries.sorted(by: { $0.key.lexicographicallyPrecedes($1.key) }).enumerated() {
            if i > 0 { out.append(UInt8(ascii: ",")) }
            writeArgString(&out, e.key)
            out.append(UInt8(ascii: ":"))
            writeArg(&out, e.value)
        }
        out.append(UInt8(ascii: "}"))
    case let .array(items):
        out.append(UInt8(ascii: "["))
        for (i, item) in items.enumerated() {
            if i > 0 { out.append(UInt8(ascii: ",")) }
            writeArg(&out, item)
        }
        out.append(UInt8(ascii: "]"))
    case let .string(s):
        writeArgString(&out, s)
    case let .int(n):
        out += Array(String(n).utf8)
    case let .bool(b):
        out += Array((b ? "true" : "false").utf8)
    }
}

private func writeArgString(_ out: inout [UInt8], _ s: [UInt8]) {
    out.append(UInt8(ascii: "\""))
    for c in s {
        if c == UInt8(ascii: "\"") || c == UInt8(ascii: "\\") { out.append(UInt8(ascii: "\\")) }
        out.append(c)
    }
    out.append(UInt8(ascii: "\""))
}

/// A JSON string for the challenge request. Its values are a validated
/// lowercase UUID, a tool name from the hosted table, and a digest text, all
/// plain ASCII, so this is the reference encoding byte for byte.
private func appendJSONString(_ out: inout [UInt8], _ s: String) { writeArgString(&out, Array(s.utf8)) }

// MARK: - General JSON reader (configuration, challenge, connect token)

/// A JSON value as the reference reads it into a map of raw messages:
/// objects keep the last of duplicate keys, keyed by their exact bytes;
/// numbers keep their text.
private indirect enum JSONValue {
    case object([[UInt8]: JSONValue])
    case array([JSONValue])
    case string([UInt8])
    case number([UInt8])
    case bool(Bool)
    case null
}

private extension Dictionary where Key == [UInt8], Value == JSONValue {
    /// The member's bytes if it is a JSON string (`null` is not a string).
    func string(_ name: String) -> [UInt8]? {
        if case let .string(s)? = self[Array(name.utf8)] { return s }
        return nil
    }

    /// The member if it is a JSON integer (no fraction, exponent, or
    /// boolean) in the safe range.
    func integer(_ name: String) -> Int64? {
        guard case let .number(text)? = self[Array(name.utf8)],
              !text.contains(UInt8(ascii: ".")), !text.contains(UInt8(ascii: "e")), !text.contains(UInt8(ascii: "E")),
              text.count <= 20, let n = Int64(String(decoding: text, as: UTF8.self)),
              n <= maxSafeInteger, n >= -maxSafeInteger
        else { return nil }
        return n
    }
}

/// A strict RFC 8259 reader over valid UTF-8 only. Strings keep their bytes after unescaping (an
/// unpaired surrogate escape becomes U+FFFD); raw control characters are
/// refused. Nesting is bounded so a hostile document cannot exhaust the stack.
private struct JSONReader {
    static let maxDepth = 512
    let b: [UInt8]
    var i = 0

    static func parse(_ data: Data) -> JSONValue? {
        var r = JSONReader(b: [UInt8](data))
        var k = 0
        while k < r.b.count {
            guard let (_, size) = decodeUTF8(r.b, k) else { return nil }
            k += size
        }
        r.space()
        guard let v = r.value(0) else { return nil }
        r.space()
        return r.i == r.b.count ? v : nil
    }

    mutating func space() {
        while i < b.count, isSpace(b[i]) { i += 1 }
    }

    mutating func expect(_ word: String) -> Bool {
        let w = Array(word.utf8)
        guard b.count - i >= w.count, b[i..<i + w.count].elementsEqual(w) else { return false }
        i += w.count
        return true
    }

    mutating func value(_ depth: Int) -> JSONValue? {
        guard depth <= Self.maxDepth, i < b.count else { return nil }
        switch b[i] {
        case UInt8(ascii: "{"):
            i += 1
            var obj: [[UInt8]: JSONValue] = [:]
            space()
            if i < b.count, b[i] == UInt8(ascii: "}") { i += 1; return .object(obj) }
            while true {
                space()
                guard let key = string() else { return nil }
                space()
                guard expect(":") else { return nil }
                space()
                guard let v = value(depth + 1) else { return nil }
                obj[key] = v
                space()
                if expect(",") { continue }
                if expect("}") { return .object(obj) }
                return nil
            }
        case UInt8(ascii: "["):
            i += 1
            var items: [JSONValue] = []
            space()
            if i < b.count, b[i] == UInt8(ascii: "]") { i += 1; return .array(items) }
            while true {
                space()
                guard let v = value(depth + 1) else { return nil }
                items.append(v)
                space()
                if expect(",") { continue }
                if expect("]") { return .array(items) }
                return nil
            }
        case UInt8(ascii: "\""):
            return string().map(JSONValue.string)
        case UInt8(ascii: "t"):
            return expect("true") ? .bool(true) : nil
        case UInt8(ascii: "f"):
            return expect("false") ? .bool(false) : nil
        case UInt8(ascii: "n"):
            return expect("null") ? .null : nil
        case UInt8(ascii: "-"), UInt8(ascii: "0")...UInt8(ascii: "9"):
            return number()
        default:
            return nil
        }
    }

    mutating func digits() -> Int {
        let start = i
        while i < b.count, (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(b[i]) { i += 1 }
        return i - start
    }

    /// -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?, kept as text.
    mutating func number() -> JSONValue? {
        let start = i
        if b[i] == UInt8(ascii: "-") { i += 1 }
        guard i < b.count else { return nil }
        if b[i] == UInt8(ascii: "0") {
            i += 1
        } else {
            guard digits() > 0 else { return nil }
        }
        if i < b.count, b[i] == UInt8(ascii: ".") {
            i += 1
            guard digits() > 0 else { return nil }
        }
        if i < b.count, b[i] == UInt8(ascii: "e") || b[i] == UInt8(ascii: "E") {
            i += 1
            if i < b.count, b[i] == UInt8(ascii: "+") || b[i] == UInt8(ascii: "-") { i += 1 }
            guard digits() > 0 else { return nil }
        }
        return .number(Array(b[start..<i]))
    }

    mutating func hex4() -> UInt32? {
        guard b.count - i >= 4 else { return nil }
        var r: UInt32 = 0
        for c in b[i..<i + 4] {
            r <<= 4
            switch c {
            case UInt8(ascii: "0")...UInt8(ascii: "9"): r |= UInt32(c - UInt8(ascii: "0"))
            case UInt8(ascii: "a")...UInt8(ascii: "f"): r |= UInt32(c - UInt8(ascii: "a")) + 10
            case UInt8(ascii: "A")...UInt8(ascii: "F"): r |= UInt32(c - UInt8(ascii: "A")) + 10
            default: return nil
            }
        }
        i += 4
        return r
    }

    mutating func string() -> [UInt8]? {
        guard i < b.count, b[i] == UInt8(ascii: "\"") else { return nil }
        i += 1
        var out: [UInt8] = []
        while true {
            guard i < b.count else { return nil }
            let c = b[i]
            i += 1
            switch c {
            case UInt8(ascii: "\""):
                return out
            case ..<0x20:
                return nil
            case UInt8(ascii: "\\"):
                guard i < b.count else { return nil }
                let e = b[i]
                i += 1
                switch e {
                case UInt8(ascii: "\""), UInt8(ascii: "\\"), UInt8(ascii: "/"): out.append(e)
                case UInt8(ascii: "b"): out.append(0x08)
                case UInt8(ascii: "f"): out.append(0x0C)
                case UInt8(ascii: "n"): out.append(0x0A)
                case UInt8(ascii: "r"): out.append(0x0D)
                case UInt8(ascii: "t"): out.append(0x09)
                case UInt8(ascii: "u"):
                    guard var r = hex4() else { return nil }
                    if (0xD800...0xDBFF).contains(r) {
                        let save = i
                        if expect("\\u"), let low = hex4(), (0xDC00...0xDFFF).contains(low) {
                            r = 0x10000 + ((r - 0xD800) << 10) + (low - 0xDC00)
                        } else {
                            i = save
                            r = 0xFFFD
                        }
                    } else if (0xDC00...0xDFFF).contains(r) {
                        r = 0xFFFD
                    }
                    appendUTF8(&out, r)
                default:
                    return nil
                }
            default:
                out.append(c)
            }
        }
    }
}

// MARK: - Field forms (byte level, ASCII only)

private func isLowerHex(_ c: UInt8) -> Bool {
    (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(c) || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains(c)
}

/// ^[0-9a-f]{64}$
private func isHex64(_ s: [UInt8]) -> Bool { s.count == 64 && s.allSatisfy(isLowerHex) }

/// ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$
private func isUUID(_ s: [UInt8]) -> Bool {
    guard s.count == 36 else { return false }
    for (k, c) in s.enumerated() {
        if [8, 13, 18, 23].contains(k) {
            if c != UInt8(ascii: "-") { return false }
        } else if !isLowerHex(c) {
            return false
        }
    }
    return true
}

/// ^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[1-9][0-9]{0,4})?$ and
/// audience == endpoint + "/mcp".
private func validEndpoint(_ endpoint: [UInt8], audience: [UInt8]) -> Bool {
    guard audience == endpoint + Array("/mcp".utf8) else { return false }
    let scheme = Array("https://".utf8)
    guard endpoint.starts(with: scheme) else { return false }
    let rest = endpoint[scheme.count...]
    let colon = rest.firstIndex(of: UInt8(ascii: ":"))
    let host = rest[..<(colon ?? rest.endIndex)]
    func alnum(_ c: UInt8) -> Bool {
        (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(c) || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(c)
    }
    guard let first = host.first, let last = host.last, alnum(first), alnum(last),
          host.allSatisfy({ alnum($0) || $0 == UInt8(ascii: ".") || $0 == UInt8(ascii: "-") })
    else { return false }
    if let colon {
        let port = rest[(colon + 1)...]
        guard (1...5).contains(port.count), let p0 = port.first, (UInt8(ascii: "1")...UInt8(ascii: "9")).contains(p0),
              port.allSatisfy({ (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0) })
        else { return false }
    }
    return true
}

private func isBase64URLByte(_ c: UInt8) -> Bool {
    (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(c) || (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(c)
        || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(c) || c == UInt8(ascii: "-") || c == UInt8(ascii: "_")
}

/// Canonical padded standard base64 only: re-encoding must give the text back.
private func decodeStdBase64(_ text: [UInt8]) -> Data? {
    guard text.allSatisfy({ $0 < 0x80 }), let raw = Data(base64Encoded: Data(text)),
          Array(raw.base64EncodedString().utf8) == text
    else { return nil }
    return raw
}

/// Canonical unpadded base64url only (the caller checked the alphabet).
private func decodeRawBase64URL(_ body: [UInt8]) -> Data? {
    var std = body.map { c -> UInt8 in
        c == UInt8(ascii: "-") ? UInt8(ascii: "+") : c == UInt8(ascii: "_") ? UInt8(ascii: "/") : c
    }
    guard std.count % 4 != 1 else { return nil }
    while std.count % 4 != 0 { std.append(UInt8(ascii: "=")) }
    guard let raw = Data(base64Encoded: Data(std)) else { return nil }
    let again = raw.base64EncodedString().utf8.compactMap { c -> UInt8? in
        c == UInt8(ascii: "=") ? nil : c == UInt8(ascii: "+") ? UInt8(ascii: "-") : c == UInt8(ascii: "/") ? UInt8(ascii: "_") : c
    }
    return again == body ? raw : nil
}

private func ascii(_ s: [UInt8]) -> String { String(decoding: s, as: UTF8.self) }

private func lowerHex(_ d: Data) -> String {
    let digits = Array("0123456789abcdef".utf8)
    var out = [UInt8]()
    out.reserveCapacity(d.count * 2)
    for byte in d { out += [digits[Int(byte >> 4)], digits[Int(byte & 0x0F)]] }
    return String(decoding: out, as: UTF8.self)
}
