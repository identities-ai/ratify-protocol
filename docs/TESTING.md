# Testing Guide

**Everything you can run today to exercise Ratify Protocol v1 before a release.**

Four testing levels, from fastest to most realistic:

| Level | What | Time | Shows |
|---|---|---|---|
| 1 | Conformance suite | <10 s | Library primitives work in all 5 SDKs |
| 2 | Narrative demo (any language) | ~5 s | Full lifecycle + attack rejections |
| 3 | Bash-only end-to-end | ~2 s | CLI-only flow, no code |
| 4 | HTTP wire protocol | ~5 s | Real network flow with server + client |

---

## Level 1 — Conformance suites

Exercises the protocol primitives in each SDK against the 59 canonical test vectors.

```bash
cd ~/projects/IdentitiesAI/ratify-protocol

# Go
go test ./...

# TypeScript
cd sdks/typescript && npm install && npm run test:conformance && cd ../..

# Python
cd sdks/python && python -m venv .venv && source .venv/bin/activate && \
  pip install -e . pytest && pytest -q && deactivate && cd ../..

# Rust
cd sdks/rust && cargo test --quiet && cd ../..
```

**Pass criterion:** all five print green, all 59 fixtures pass in every language.

---

## Level 2 — Narrative demos

Walks through Alice → cert → agent → bundle → verifier with printed output at every step, then four attack scenarios rejected.

```bash
# Python
python demos/python/demo.py

# Go
go run ./demos/go

# TypeScript (first build the SDK once)
cd sdks/typescript && node node_modules/typescript/bin/tsc && cd ../..
cd demos/typescript && npm install && npm run demo && cd ../..

# Rust
cd demos/rust && cargo run && cd ../..
```

**Pass criterion:** `STEP 5` prints `✅ VALID` with the correct human/agent IDs and granted scope. Each `ATTACK N` prints `❌ REJECTED` with the specific deterministic reason. Output is essentially identical across all five languages (only random IDs differ).

---

## Level 3 — Bash-only end-to-end

Uses the `ratify` CLI for every step. No code, no server.

```bash
# Build the CLI
cd ~/projects/IdentitiesAI/ratify-protocol
go build -o /tmp/rat/ratify ./cmd/ratify

# Create a clean workspace
mkdir -p /tmp/fab && cd /tmp/fab

# 1. Alice generates her root
HOME=$PWD /tmp/rat/ratify init

# 2. Agent generates its keypair (emits agent-pubkey.json + agent.priv)
HOME=$PWD /tmp/rat/ratify agent-init

# 3. Alice signs a delegation
HOME=$PWD /tmp/rat/ratify delegate \
  --agent-pubkey-file agent-pubkey.json \
  --scope "meeting:attend" \
  --days 7 --out delegation.json

# 4. Verifier issues a challenge
C=$(HOME=$PWD /tmp/rat/ratify challenge)

# 5. Agent assembles a proof bundle
HOME=$PWD /tmp/rat/ratify agent-bundle \
  --cert delegation.json \
  --priv agent.priv \
  --challenge-hex $C \
  --out bundle.json

# 6. Verifier checks the bundle
HOME=$PWD /tmp/rat/ratify verify \
  --bundle bundle.json \
  --scope meeting:attend
```

**Pass criterion:** last command prints `VALID` with the human + agent IDs and scope.

**Try the attacks:**

```bash
# Bad scope
HOME=$PWD /tmp/rat/ratify verify --bundle bundle.json --scope meeting:record
# → INVALID   Reason: scope_denied: required scope "meeting:record" not in effective delegation scope

# Tamper the cert (use jq to append a sensitive scope post-signature)
jq '.scope += ["files:write"]' delegation.json > tampered.json
# Rebuild a bundle using the tampered cert
HOME=$PWD /tmp/rat/ratify agent-bundle --cert tampered.json --priv agent.priv \
  --challenge-hex $(HOME=$PWD /tmp/rat/ratify challenge) --out tampered-bundle.json
HOME=$PWD /tmp/rat/ratify verify --bundle tampered-bundle.json --scope files:write
# → INVALID   Reason: bad_signature: cert 0: Ed25519 signature invalid
```

---

## Level 4 — HTTP wire protocol

A minimal reference HTTP verifier plus the CLI agent. Exercises the real wire protocol, not just library calls.

### Start the verifier server

```bash
cd ~/projects/IdentitiesAI/ratify-protocol
go run ./cmd/ratify-verifier -addr :8080
# Listens on :8080 with two endpoints:
#   POST /v1/ratify/challenge
#   POST /v1/ratify/verify
```

### In another shell — client flow

```bash
# Build the CLI and create workspace
go build -o /tmp/rat/ratify ./cmd/ratify
mkdir -p /tmp/fab && cd /tmp/fab

HOME=$PWD /tmp/rat/ratify init
HOME=$PWD /tmp/rat/ratify agent-init
HOME=$PWD /tmp/rat/ratify delegate \
  --agent-pubkey-file agent-pubkey.json \
  --scope "meeting:attend" --out delegation.json

# 1. Get a challenge from the HTTP verifier
CHAL_JSON=$(curl -s -X POST http://localhost:8080/v1/ratify/challenge)
echo "$CHAL_JSON"

# Decode challenge to hex for the CLI
CHAL_B64=$(echo "$CHAL_JSON" | jq -r .challenge)
CHAL_HEX=$(echo -n "$CHAL_B64" | base64 -d | xxd -p -c 64)

# 2. Agent builds a bundle bound to that challenge
HOME=$PWD /tmp/rat/ratify agent-bundle \
  --cert delegation.json --priv agent.priv \
  --challenge-hex $CHAL_HEX --out bundle.json

# 3. Present the bundle to the verifier over HTTP
BUNDLE_B64=$(base64 < bundle.json | tr -d '\n')
curl -s -X POST http://localhost:8080/v1/ratify/verify \
  -H 'Content-Type: application/json' \
  -d "{\"proof_bundle\":\"$BUNDLE_B64\",\"required_scope\":\"meeting:attend\"}"
```

**Pass criterion:** response is `{"valid":true, ..., "identity_status":"authorized_agent"}`. The server log shows `verify ✅`.

**Try attacks over HTTP:**

- Reuse the bundle — the server's challenge store is single-use, so replay fails with `unknown_challenge: challenge was not issued by this verifier or has already been used`.
- Send a bundle signed against a different challenge — fails with `unknown_challenge`.
- Wait 5 minutes then replay — fails with `stale_challenge`.
- Tamper the cert before bundling — fails with `bad_signature`.

---

## What each level proves

| Level | Proves |
|---|---|
| 1 | Every SDK's primitives produce byte-identical canonical bytes; verifier behavior matches across languages. |
| 2 | Every SDK can run the full lifecycle in-process; attack paths are rejected deterministically. |
| 3 | Real users can run Ratify end-to-end with just bash and a CLI; no code required. |
| 4 | Real wire protocol works: HTTP-exposed verifier, challenge single-use enforcement, real network serialization. |

## What levels 1-4 do NOT prove

- **Deployment / scale.** No production load testing yet. Allocated for `TEST_PLAN.md` §8 with k6/vegeta; gated on first production deployment.
- **Adversarial security audit.** External audit (Trail of Bits / NCC / Cure53) scheduled before v1.0.0 stable — see `RELEASES.md`.
- **Interop with third-party agent platforms.** Third-party platform integrations are gated on design partner engagement; meanwhile, cross-language interop across our five SDKs is a reasonable proxy.
- **Long-term session / streaming properties.** See `ROADMAP.md` §2 for v1.1 gaps (session binding, sequence numbers, session cert cache).

---

## Recommended daily development loop

```bash
# Before any PR:
cd ~/projects/IdentitiesAI/ratify-protocol
go test ./... && \
  cd sdks/typescript && npm run test:conformance && cd ../.. && \
  cd sdks/python && source .venv/bin/activate && pytest -q && deactivate && cd ../.. && \
  cd sdks/rust && cargo test --quiet && cd ../..
```

If all five are green, your change doesn't drift the protocol. That's the contract.

For broader changes (new canonical rules, new field), also run:

```bash
# Determinism — regen must produce byte-identical fixtures (or you intended a protocol change).
go run ./cmd/ratify-testvectors -out /tmp/regen && diff -rq testvectors/v1/ /tmp/regen/
```
