# Protocol v2 examples

Runnable Ratify Protocol v2 programs in Go, TypeScript, Python, Rust and C.
Every language implements the same four programs with the same behavior, and
each program prints the same text in every language. CI runs every program
against this source tree and compares its output with
[`expected/`](expected/), so the examples cannot drift from the SDKs.

**Development only.** The programs use the in-memory reference stores that
each SDK ships for tests (claim store, receipt log, checkpoint, journal store
and challenge issuance store). They are not durable and must not back a
production verifier. A production deployment supplies durable Part B stores
and an independent checkpoint ([SPEC-v2 §7](../../SPEC-v2.md)). Protocol v2 is
a prerelease: review so far is the project's own pre-release security review, and external
independent review is a gate for `2.0.0`.

## Programs

| Program | What it shows | Expected output |
| --- | --- | --- |
| `quickstart` | Generate keys; issue a delegation with a `max_amount` constraint in micro-units; sign a genesis status list with a separate status key; issue a challenge with the issuance helper (persisted before it is returned); the agent signs a proof; verify (a committed, non-actionable outcome); publish the signed receipt; read the checkpoint acknowledgement; release; gate on `Allowed` at the receiver's clock; a replay is rejected before evaluation; the allow ends at the challenge expiry. | [`expected/quickstart.txt`](expected/quickstart.txt) |
| `signed_status` | Record key roles and the status key in the journal; the root key is refused as a status key; the status publisher signs a genesis list; the journal ingests it; a verification is allowed; the publisher revokes the certificate (a push and the cumulative list); the journal ingests the push; a later verification is denied with `delegation_revoked`. | [`expected/signed_status.txt`](expected/signed_status.txt) |
| `custom_scope` | `custom:*` is refused at issuance; a delegation for the exact scope `custom:acme:deploy` carries a `com.ratifyprotocol.max_count` constraint; the verifier registers the `com.ratifyprotocol.max_count/v1` profile (its digest is printed and signed into each receipt); a request within the count is allowed, one above it is denied with `constraint_denied`, and a verifier without the profile denies with `constraint_unknown`. | [`expected/custom_scope.txt`](expected/custom_scope.txt) |
| `external_signer` | A signing provider holds the issuer and agent keys; the SDK prepares each typed statement (a 77-byte message and a fixed ML-DSA context per object type), verifies every returned signature, and refuses a faulty provider with `invalid_signature`. | [`expected/external_signer.txt`](expected/external_signer.txt) |

Keys and signatures are random on every run, so the programs print no key
IDs or signatures. The clock is fixed, so times and deadlines are
reproducible.

## Files and how to run them

Each language directory has a `test.sh` that builds what it needs, runs every
program, and diffs the output against `expected/`.

| Language | Files | Run one program | Test all |
| --- | --- | --- | --- |
| Go | [`go/quickstart/main.go`](go/quickstart/main.go), [`go/signed_status/main.go`](go/signed_status/main.go), [`go/custom_scope/main.go`](go/custom_scope/main.go), [`go/external_signer/main.go`](go/external_signer/main.go) | `go run ./examples/v2/go/quickstart` (repository root) | `examples/v2/go/test.sh` |
| TypeScript | [`typescript/quickstart.ts`](typescript/quickstart.ts), [`typescript/signed_status.ts`](typescript/signed_status.ts), [`typescript/custom_scope.ts`](typescript/custom_scope.ts), [`typescript/external_signer.ts`](typescript/external_signer.ts) | `node quickstart.ts` in `examples/v2/typescript` after `test.sh` has built the SDK (Node.js 22.18 or later) | `examples/v2/typescript/test.sh` |
| Python | [`python/quickstart.py`](python/quickstart.py), [`python/signed_status.py`](python/signed_status.py), [`python/custom_scope.py`](python/custom_scope.py), [`python/external_signer.py`](python/external_signer.py) | `python examples/v2/python/quickstart.py` with `ratify-protocol` (with its `protocol-v2` extra) and `ratify-protocol-native-v2` installed | `examples/v2/python/test.sh` (builds a temporary venv; set `RATIFY_V2_PYTHON` to reuse an interpreter that has both installed) |
| Rust | [`rust/src/bin/quickstart.rs`](rust/src/bin/quickstart.rs), [`rust/src/bin/signed_status.rs`](rust/src/bin/signed_status.rs), [`rust/src/bin/custom_scope.rs`](rust/src/bin/custom_scope.rs), [`rust/src/bin/external_signer.rs`](rust/src/bin/external_signer.rs) | `cargo run --release --bin quickstart` in `examples/v2/rust` | `examples/v2/rust/test.sh` |
| C | [`c/quickstart.c`](c/quickstart.c), [`c/signed_status.c`](c/signed_status.c), [`c/custom_scope.c`](c/custom_scope.c), [`c/external_signer.c`](c/external_signer.c), helpers in [`c/example_util.h`](c/example_util.h) | see `test.sh` for the build flags | `examples/v2/c/test.sh` (needs OpenSSL 3.5 or later for `external_signer`; set `OPENSSL_PREFIX` if pkg-config cannot find it) |

Notes per language:

- **TypeScript** imports `@identities-ai/ratify-protocol/v2` and
  `@identities-ai/ratify-protocol/v2/reference` through a `file:` dependency
  on `sdks/typescript`; the external signer's provider uses `@noble/ed25519`
  and `@noble/post-quantum`.
- **Python**'s external-signer provider uses the key type of the
  `ratify-protocol-native-v2` extension as a stand-in signing service,
  because no public Python dependency offers ML-DSA-65 signing with a context
  string. A real provider uses its own signing service.
- **Rust**'s external-signer provider uses `ed25519-dalek` and `fips204`
  directly.
- **C** builds the library with the test-only `test-reference` feature and
  compiles with `-DRATIFY_V2_TEST_REFERENCE`; a shipped build never enables
  the reference stores. The external signer's provider uses OpenSSL.

The upgrade guide from Protocol v1 is
[`docs/PROTOCOL_V2_MIGRATION.md`](../../docs/PROTOCOL_V2_MIGRATION.md).
