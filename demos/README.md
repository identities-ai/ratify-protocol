# Ratify Protocol — Runnable Demos

**End-to-end narrative demos in every supported language. Run one, see the full protocol lifecycle happen in front of you.**

Each demo walks through:

1. Alice generates a hybrid root identity.
2. An AI agent generates its own hybrid keypair.
3. Alice signs a delegation cert (scope: `meeting:attend`, expires in 7 days).
4. The agent builds a proof bundle with a fresh challenge signature.
5. A verifier runs `verify_bundle()` — expected ✅ `VALID`.

Then four negative scenarios:

6. Attacker tampers the cert scope post-signature — rejected with `bad_signature`.
7. Agent tries to use a `meeting:attend` cert for `meeting:record` — rejected with `scope_denied`.
8. Verifier's clock reports a future time — cert appears expired, rejected.
9. Alice revokes the cert — bundle rejected as `revoked`.

Each scenario prints what happened and why, so anyone on the team can read the output and understand the protocol without reading code.

---

## Running each demo

### Python

```bash
# From repo root
cd sdks/python && python -m venv .venv && source .venv/bin/activate && pip install -e . && cd ../..
python demos/python/demo.py
```

### Go

```bash
# From repo root
go run ./demos/go
```

### TypeScript

```bash
# From repo root — first build the SDK
cd sdks/typescript && node node_modules/typescript/bin/tsc && cd ../..
# Then install demo deps and run
cd demos/typescript && npm install && npm run demo
```

### Rust

```bash
# From repo root
cd demos/rust && cargo run
```

## Reading the output

Every demo prints the same nine scenarios in the same order. You can compare outputs side-by-side across languages — they should all tell the same story, with:

- Different IDs (because each run generates fresh keys)
- Different signatures (randomness differs, not a bug)
- Identical `identity_status` and `error_reason` strings
- Identical scope expansions

If any two languages disagree on *what* happens (identity_status values, whether a scenario is rejected), that's a bug worth investigating.

## What this proves

- Every SDK implements the same verifier algorithm (per `SPEC.md` §10).
- Every SDK produces canonical sign bytes that match byte-for-byte.
- Hybrid Ed25519 + ML-DSA-65 signing works correctly in every language.
- The attack-rejection paths are consistent across implementations.
- You can demo the protocol to a skeptical audience in ~15 seconds of scrolling.

## What this does NOT test

These demos are narrative, not exhaustive. For the rigorous validation:

- `testvectors/v1/` — 20 canonical fixtures, every SDK passes byte-identical.
- Go unit tests: `go test ./...`
- TS conformance: `cd sdks/typescript && npm test`
- Python conformance: `cd sdks/python && pytest`
- Rust conformance: `cd sdks/rust && cargo test`

See `docs/TEST_PLAN.md` for the full testing methodology.
