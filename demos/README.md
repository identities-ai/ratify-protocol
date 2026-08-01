# Ratify Protocol — Runnable Demos

**End-to-end narrative demos in four languages (Go, Python, Rust, TypeScript). Run one, see the full protocol lifecycle happen in front of you.**

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

## Start here: bounded tool call

The shortest demo follows a portable authorization across an actual HTTP
boundary. Alice allows Atlas to call `place_order` up to $5,000, Atlas narrows
Scout to $500, and an independent vendor gateway verifies Scout's proof before
its tool handler can run.

```bash
# Terminal 1: issue the delegation and configure the vendor's trust root
go run ./demos/bounded-tool-call issue
go run ./demos/bounded-tool-call serve

# Terminal 2: send real tool requests with vendor-issued challenges
go run ./demos/bounded-tool-call call --tool place_order --amount 200
go run ./demos/bounded-tool-call call --tool place_order --amount 2000
go run ./demos/bounded-tool-call call --tool cancel_order --amount 200

# Optional: synchronize revocation state, then retry the valid call
go run ./demos/bounded-tool-call revoke
go run ./demos/bounded-tool-call call --tool place_order --amount 200
```

The gateway pins Alice's public root and issues each single-use challenge
bound to the exact tool and amount. The agent signs that operation-bound
challenge, the tool is checked as an exact application scope, and the amount
is evaluated against the signed constraint. Only an `ALLOW` decision invokes
the order handler. Ratify authorizes the tool call; the vendor still processes
the order through its existing systems.

`issue` writes disposable demo keys and state to `.ratify-demo/`, which is
gitignored. Do not reuse these keys outside the demo.

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

- Each of the four narrative demos (Go, TypeScript, Python, Rust) runs the same verifier algorithm (per `SPEC.md` §10).
- Each produces canonical sign bytes that match byte-for-byte.
- Hybrid Ed25519 + ML-DSA-65 signing works correctly in each of the four demo languages.
- The attack-rejection paths are consistent across those implementations.
- You can demo the protocol to a skeptical audience in ~15 seconds of scrolling.
- Full five-SDK conformance, including C, is established by the canonical fixture suites below, not by these demos.

## What this does NOT test

These demos are narrative, not exhaustive. For the rigorous validation:

- `testvectors/v1/` — 79 canonical fixtures, every SDK passes byte-identical.
- Go unit tests: `go test ./...`
- TS conformance: `cd sdks/typescript && npm test`
- Python conformance: `cd sdks/python && pytest`
- Rust conformance: `cd sdks/rust && cargo test`
- C conformance: `cd sdks/c && cargo test --test conformance`

See `docs/TEST_PLAN.md` for the full testing methodology.
