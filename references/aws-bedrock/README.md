# Ratify-authorized directory access between two Bedrock agents

Two Claude-on-Bedrock clients, operated as if by two different parties.

- **Agent 1** wants a listing of `C:\SideEvents`. It has no access to it.
- **Agent 2** owns `C:\SideEvents`. It has no reason to trust agent 1.

Between them travels a Ratify delegated-authority proof: a signed statement that
a named principal authorized *this* agent to do *this* thing to *this* resource
until *this* time. Agent 2 verifies that proof before its filesystem handler runs.
Nothing else crosses — no API key, no shared process, no shared disk.

```
principal ──signs──▶ DelegationCert { files:read, file:sideevents under "/", +1h }
                          │
                          ▼
   Agent 1 (Bedrock) ──── ProofBundle ────▶ Agent 2 (Bedrock)
   decides it needs         cert chain            reviews the request,
   the listing              + challenge sig       calls verify_and_list
                            bound to this
                            exact request                │
                                                         ▼
                                            verify_bundle → allow → os.scandir
                                                         └→ deny  → handler untouched
```

## Run it

```bash
python -m venv .venv && ./.venv/Scripts/pip install ratify-protocol "anthropic[bedrock]" pytest
./.venv/Scripts/python -m bedrock_ratify.run --offline    # no AWS needed
./.venv/Scripts/python -m bedrock_ratify.run              # two live Bedrock clients
./.venv/Scripts/python -m pytest tests -q
```

`--offline` swaps the two models for scripted callers. The Ratify path is
byte-identical either way — which is the point: the authority decision does not
depend on what the model said, or on which runtime hosted it.

Live mode needs AWS credentials with Bedrock access in `AWS_REGION`
(default `us-west-2`) and uses `anthropic.claude-opus-5` via the Bedrock Mantle
endpoint. Override with `BEDROCK_MODEL_ID`.

## Two consoles

```bash
./.venv/Scripts/python -m bedrock_ratify.web.keys          # once — splits the key material
./.venv/Scripts/python -m bedrock_ratify.web.server_app    # custodian  → http://localhost:3200
./.venv/Scripts/python -m bedrock_ratify.web.client_app    # requester  → http://localhost:3100
```

Two processes, real HTTP between them, no shared state.

`keys` writes `keys/`: the client process gets the principal's and agent 1's
private keys, the server process gets agent 2's private key and the principal's
**public** key only. The server can therefore check a proof and cannot mint one —
that asymmetry only shows if the key files are actually separate.

**Both consoles run a Bedrock model.** Agent 1 lives in the client process and
agent 2 in the server process, each with its own `AnthropicBedrockMantle` client
and its own tool. Each console shows in its header which model it is on, or why
it is not — never silently. Without credentials the buttons still drive the same
Ratify path with the verifier called directly, and the header says so.

**Client (:3100)** — DELEGATE, PRESENT, RESULT stacked down the page. Sign a
certificate (pick scope, resource, path prefix, TTL), then either present it by
hand or hand agent 1 an instruction and let the model choose the path and call
`request_directory`. The client verifies the signed receipt itself rather than
taking the server's answer on trust. A revoke button exercises the kill switch.

**Server (:3200)** — a live feed of what arrives: the request, agent 2's own
account of it, the seven checks, the decision as the verifier stated it, the
receipt hash, and whether the protected handler was reached. On a refusal the
failing check is marked and the rest are left *unreported* — the verifier
reports one reason, and the console does not claim the others passed.

Neither model is load-bearing. Agent 1 chooses *what to ask for*; agent 2
chooses *whether to call the verifier*. Neither can approve a proof, and if
agent 2 declines to call its tool the request fails closed as
`no_verification_attempted`.

The dropdowns are wired so every deny path is reachable from the UI: a
certificate bound to `/tools` asked for `/`, a resource the custodian does not
serve, a `files:write` grant against a `files:read` requirement, and revocation
mid-session.

## What the run shows

Allow path — agent 1 asks, agent 2 verifies, the real directory comes back:

```
  ALLOW  3 entries, receipt oHVDjFEW1xrrOTJN...
         file  agenda.md  51B
         file  attendees.csv  35B
         dir   notes
```

Refusal matrix — the same custodian, the same code path, eight requests each
broken in exactly one way, each refused for its own stated reason:

| Case | Verifier's reason |
| --- | --- |
| path outside the granted prefix (`/tools` granted, `/` asked) | `constraint_denied: requested path "/" is outside the authorized prefix "/tools"` |
| resource the custodian does not serve | `constraint_denied: requested resource does not match the authorized resource` |
| scope not delegated (`files:write` held, `files:read` required) | `scope_denied: required scope "files:read" not in effective delegation scope` |
| valid signatures, principal the custodian does not trust | `untrusted_root` |
| delegation expired | `expired: delegation certificate has expired` |
| scope widened after signing | `bad_signature: cert 0: Ed25519 signature invalid` |
| challenge replayed after a successful use | `unknown_challenge: challenge was not issued by this verifier or has already been used` |
| revoked mid-flight, 3600s of validity remaining | `revoked: delegation certificate has been revoked` |

Every deny asserts that `handler_invocations` did not move. The refusals are
what makes the acceptance evidence: a verifier that accepts everything proves
nothing.

## Where enforcement actually happens

Ratify supplies the portable proof — who delegated what, to whom, bounded how,
and whether it still stands, checkable offline by either side. It does not
enforce a filesystem boundary from inside a signature.

`SideEventsCustodian._read` is the enforcement point. It runs only on the allow
branch, and it independently re-resolves the path and refuses anything that
escapes the protected root. The Bedrock models never gate anything: agent 2's
model chooses *whether to call* the verifier, and if it declined to call it, the
run reports `no_verification_attempted` and reads nothing.

## Layout

| File | Role |
| --- | --- |
| `bedrock_ratify/identity.py` | principals, agents, delegation issuance, narrowing sub-delegation with lifetime clamp |
| `bedrock_ratify/presenter.py` | agent 1's side: sign the challenge, assemble the bundle |
| `bedrock_ratify/receiver.py` | agent 2's side: verify, then read; signed chained receipts |
| `bedrock_ratify/a2a.py` | the envelope that crosses between them |
| `bedrock_ratify/agents.py` | the two Bedrock clients and their tool loops |
| `bedrock_ratify/run.py` | the engagement and the refusal matrix |
| `bedrock_ratify/trace.py` | the three verbs printed end to end, both sides |
| `bedrock_ratify/web/` | the two consoles — client :3100, custodian :3200 |
| `benchmark/BENCHMARK.md` | Ratify vs. Amazon Bedrock AgentCore Gateway |
| `research/` | the two source documents this was built against |

## Limits

- The consoles are two processes over real HTTP on one machine, with separate
  key material. Two hosts on two networks is the next step, not something this
  shows. The CLI demos (`run`, `trace`) stay in one process.
- The challenge store and revocation set are in memory and die with the server
  process. Revocation is applied by a plain `POST /revoke` rather than a signed
  `RevocationPush`, so this shows the kill switch working, not that a receiver
  can prove who sent the withdrawal.
- Revocation propagation latency — the interval between a principal sending a
  withdrawal and a remote deployment applying it — is not measured here, and
  nothing in this repository says anything about it.
- Both sides run the same Python SDK. This does not demonstrate two independently
  written verifiers agreeing; Ratify publishes five SDKs and a conformance suite
  for that question.
- **No model call in this repository has ever run.** There are no AWS credentials
  on this machine, so both consoles and `run.py` report
  `no AWS credentials resolved from the environment` and fall back. Everything
  demonstrated so far — the refusal matrix, the trace, the two consoles — ran with
  Bedrock switched off. The wiring is written and import-clean; it is not tested.
