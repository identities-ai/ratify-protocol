# Verify MCP signer (Preview)

> **Preview.** This is the client side of the managed Ratify Verify MCP
> server. It is not part of SPEC-v2 conformance, and its API, file formats
> and vectors may change before it is declared stable.

The Ratify Verify MCP server answers an agent's MCP tool calls only after
Verify has decided on a delegated-authority proof made for that exact call.
The signer is the piece that runs next to the agent: it holds the agent key,
asks Verify for a challenge, signs a SPEC-v2 proof bundle bound to the call,
and sends the call with the proof attached. Verify before action, for every
call.

Every SDK ships the signer as a library, and the Python SDK also ships it as
a stdio MCP server (`ratify-mcp-signer`) that any MCP client able to launch a
local process can use.

## What a tool-call proof binds

A tool-call proof is an ordinary SPEC-v2 challenge presentation. The MCP
binding lives entirely in its `session_context`, built with the normative
SPEC-v2 operation and session context constructions:

```
canonical       = canonical JSON of params.arguments (restricted value model)
payload_digest  = SHA-256(canonical)
request_hash    = operation context (required scope   = the tool's scope,
                                     operation        = "mcp.tools/call:" + tool,
                                     resource         = connection ID,
                                     requested path   = endpoint audience,
                                     payload digest   = payload_digest)
session_context = session context   (verifier ID, workspace ID, agent key ID,
                                     session = connection ID,
                                     invocation ID from the challenge,
                                     request_hash)
```

The signer computes `request_hash` and `session_context` itself, from the
call it was asked to make and the configuration it pinned. It never uses a
hash the server suggests, and it never signs caller-chosen bytes. A proof for
one tool, argument set, connection, endpoint or workspace is useless for any
other.

## Flows

**Connect (once per agent key).** The agent's machine generates the key
locally; the private key never leaves it. The console issues a one-line
connect challenge (`ratify-mcp-connect-1.` and a token). The signer answers
with a proof of possession: a proof bundle with no delegations whose session
context is SHA-256 of `ratify-verify-mcp/connect-possession/v1` followed by
the length-prefixed workspace ID, receiver ID, audience, challenge ID and
agent key ID. It is domain-separated, so it can never serve as a tool-call
proof. The console then shows the client configuration.

**Each tool call.**

1. Canonicalize the arguments and compute `payload_digest`.
2. `POST <endpoint>/challenge` with
   `{"connection_id":…,"tool":…,"payload_digest":"sha256:…"}`.
3. Check the response: `verifier_id` and `workspace_id` equal the pinned
   values, `required_scope` is the tool's scope, `invocation_id` is a
   lowercase UUID, the challenge is 32 bytes in canonical base64, and at
   least 10 seconds of its lifetime remain. Anything else is refused and
   nothing is signed.
4. Sign the proof (a checked challenge signs only the tool and the
   configuration it was checked for) and send `tools/call` with the envelope
   `{connection_id, invocation_id, challenge, bundle}` under
   `params._meta["com.ratifyprotocol/proof"]`.

## Arguments: the restricted value model

Arguments must be a JSON object of objects with unique keys, strings,
integers in the safe range (no fraction, exponent or negative zero),
booleans and arrays, nested at most four levels below the arguments object.
Strings refuse control characters, U+2028, U+2029, unpaired surrogates and
invalid UTF-8. `null` arguments mean `{}`. The canonical form sorts keys by
their UTF-8 bytes, has no insignificant whitespace, and escapes only `"` and
`\`. A call outside the model is refused before any challenge is requested.

## Client configuration

The console hands out this object (or a connect response carrying it under
`client_config`); unknown fields are ignored:

```json
{
  "endpoint": "https://verify.example",
  "audience": "https://verify.example/mcp",
  "verifier_id": "<64 lowercase hex>",
  "workspace_id": "<lowercase UUID>",
  "connection_id": "<lowercase UUID>",
  "delegations": ["<standard base64 delegation certificate>", "…"]
}
```

`endpoint` is `https://` and a lowercase host with an optional port, nothing
else; `audience` is exactly the endpoint followed by `/mcp`. `delegations`
are root side first: each certificate's subject is the next one's issuer, and
the last is issued to the agent key that signs. The signed proof bundle
carries them leaf first, as SPEC-v2 requires.

## Library API by SDK

| SDK | Where | Main entry points |
|-----|-------|-------------------|
| Go | `github.com/identities-ai/ratify-protocol/v2/verifyclient/mcp` | `ParseClientConfig`, `NewToolCall`, `(*ClientConfig).ChallengeRequest`, `(*ClientConfig).CheckChallenge`, `SignToolCall`, `ParseConnectToken`, `ProvePossession` (and `…WithSigner` for an external signer) |
| Python | `ratify_protocol.v2.mcp` | `parse_client_config`, `new_tool_call`, `ClientConfig.challenge_request`, `ClientConfig.check_challenge`, `sign_tool_call`, `parse_connect_token`, `prove_possession` (and `…_with_signer`); `ratify_protocol.v2.mcp.signer.Signer` does the HTTPS round trips |
| TypeScript | `@identities-ai/ratify-protocol/v2/mcp` | `parseClientConfig`, `newToolCall`, `challengeRequest`, `checkChallenge`, `signToolCall`, `parseConnectToken`, `provePossession` (and `…WithSigner`) |
| Rust | `ratify_protocol::v2::mcp` | `parse_client_config`, `ToolCall::new`, `ClientConfig::challenge_request`, `ClientConfig::check_challenge`, `sign_tool_call`, `parse_connect_token`, `prove_possession` (and `…_with_signer`) |
| C | `ratify_v2_mcp_*` in `ratify.h` | `ratify_v2_mcp_client_config_parse`, `ratify_v2_mcp_challenge_request`, `ratify_v2_mcp_check_challenge`, `ratify_v2_mcp_sign_tool_call`, `ratify_v2_mcp_parse_connect_token`, `ratify_v2_mcp_prove_possession` (local key pair or external signer) |
| Swift | `MCP` in `RatifyProtocol` | `MCP.parseClientConfig`, `MCP.newToolCall`, `ClientConfig.challengeRequest`, `ClientConfig.checkChallenge`, `MCP.signToolCall`, `MCP.parseConnectToken`, `MCP.provePossession` (`agentKey:` or `signer:`) |
| Kotlin | `Mcp` in `com.ratifyprotocol` | `Mcp.parseClientConfig`, `Mcp.newToolCall`, `ClientConfig.challengeRequest`, `ClientConfig.checkChallenge`, `Mcp.signToolCall`, `Mcp.parseConnectToken`, `Mcp.provePossession` (software key, `ExternalSigner` or `SigningKey`) |

## The Python stdio signer

```sh
pip install "ratify-protocol[protocol-v2,mcp-signer]==<version>"
ratify-mcp-signer init --dir ~/.config/ratify-mcp/laptop
ratify-mcp-signer prove-possession --config ~/.config/ratify-mcp/laptop/config.json --challenge 'ratify-mcp-connect-1.…'
ratify-mcp-signer configure --config ~/.config/ratify-mcp/laptop/config.json --from console-config.json
ratify-mcp-signer test --config ~/.config/ratify-mcp/laptop/config.json
```

Pin `<version>` to the v2 release you use: an unpinned install can resolve to
a v1 release. Then point
the MCP client at `ratify-mcp-signer serve --config <path>`. The key is kept
in the OS credential store, or in a mode 0600 file inside a mode 0700
directory where no store exists; the signer refuses to start if either is
wider. Keys are per connection and per machine.

The `ratify-mcp-signer` command is installed with every wheel. Without the
`mcp-signer` extra it exits and prints the install command.

If you used an earlier standalone `ratify-mcp-signer` package, uninstall it
before installing the extra (`pip uninstall ratify-mcp-signer`). Both
install a command with the same name, and uninstalling the standalone
package afterwards removes the command; reinstall with
`pip install --force-reinstall "ratify-protocol[protocol-v2,mcp-signer]==<version>"`
if that happened.

## Shared vectors

[`testvectors/v2/mcp`](../testvectors/v2/mcp/README.md) pins the binding,
the client configuration rules, the challenge checks, tool-call proofs and
connect proofs. Every SDK reproduces them byte for byte (a signed bundle is
compared except its hedged ML-DSA-65 signature component, and both must
verify).
