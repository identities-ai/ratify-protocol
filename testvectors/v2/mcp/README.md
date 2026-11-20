# Verify MCP signer vectors (preview)

These files pin the client contract of the Ratify Verify MCP server: the
binding each tool-call proof signs, the console configuration, the checks a
signer applies to a challenge before it signs, and the connect proof of
possession. They describe a managed-service contract, not SPEC-v2
conformance, and may change while the signer is a preview.

Every SDK's MCP signer reproduces them: canonical arguments, digests, request
hashes, session contexts, challenge requests, and envelopes byte for byte. A
signed proof bundle is compared byte for byte except the ML-DSA-65 component
of its challenge signature, which SDKs sign with hedging; the Ed25519
component is deterministic and must match, and both bundles must verify.

| File | Contents |
|------|----------|
| `binding.json` | Tool table, argument canonicalization, payload digest, request hash, session context, and inputs a signer must refuse |
| `client-config.json` | Console client configurations that parse, and ones that must be refused |
| `tool-call.json` | Fixture agent key, configuration, challenge responses to accept and sign, and challenge responses to refuse |
| `connect.json` | Connect possession contexts, connect tokens to parse and sign, and tokens to refuse |

Regenerate with `go run ./cmd/ratify-mcp-vectors` from the repository root
(source: `internal/mcpvectors`). Output is deterministic, and
`TestGeneratedMCPVectorsMatchCommittedFiles` fails if a committed file
differs from the generator. Seeds in these files are public test data and
must never be used as production keys.
