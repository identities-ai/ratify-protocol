# Proof-Carrying Delegated Authority for Open AI Agents

**A proposed open reference contribution to the Open Secure AI Alliance ecosystem**

| | |
|---|---|
| Status | Draft proposal, independent reference implementation |
| Version | Requires Ratify Protocol v1.0.0-alpha.16 or later; verified against it |
| Reference demo | `demos/nvidia-nooa-delegated-authority/` |
| Integration target | NOOA (`nooa==0.0.8`, Apache-2.0) |
| License | Apache-2.0 |

**Relationship disclosure.** Ratify Protocol is an NVIDIA Inception member. This document is an unsolicited, independent proposal. It is not an NVIDIA partnership, not an NVIDIA-approved or official integration, not an Open Secure AI Alliance membership artifact, and not an NVIDIA reference architecture. No NVIDIA repository is modified by this contribution. Every claim about NOOA and OpenShell below is cited to public source at a pinned version.

**Current NVIDIA alignment.** NVIDIA's Secure Agent Workspace materials describe a
layered identity surface, per-engagement delegation records, and ODIS as an open
interoperability standard for agent identity and delegation. This reference is
therefore proposed as an executable interoperability and conformance profile to
evaluate against that direction, not as a claim that NVIDIA lacks or should adopt
Ratify's delegation model.

---

## 1. Executive summary

The Open Secure AI Alliance names identity, permissions, harnesses, guardrails, logs, evaluation, and isolation as components of an open agent-defense stack. Existing contributions address these. A complementary authorization question sits alongside them:

> When an agent asks a service to do something consequential, how does the *receiving service* independently establish that some principal actually authorized this specific agent to take this specific action, within these specific bounds?

Workload identity answers *which process is calling*. Runtime isolation answers *what the sandbox may touch*. Policy engines answer *what this deployment permits*. None of them carry, across an organizational boundary, a principal-signed, agent-bound, revocable statement of delegated authority that a receiver can verify offline with no dependency on the caller's infrastructure.

This proposal contributes a small, runnable reference that demonstrates this delegated-authority pattern using an existing open protocol. It shows a principal delegating bounded refund authority to a NOOA agent, and an independent receiving service that verifies the delegation cryptographically before executing, including the negative cases, and including a hash-chained, verifier-signed receipt for every authenticated authorization outcome.

The architectural claim being tested is narrow and falsifiable: **the authorization decision belongs to the receiver, and the proof must travel with the request.** The reference is deliberately structured so a skeptical reviewer can verify that the agent is not authorizing itself.

## 2. Problem and concrete threat

Consider a refund agent operated by Company A, calling a payments service operated by Company B.

Company A's principal intends: *this agent may issue refunds up to $100, for the next 24 hours.*

By the time the request reaches Company B, that intent is typically reduced to an API key or a bearer token in a header. Company B learns that *some* caller holding *some* credential from Company A wants $150 refunded. It does not learn who authorized it, whether the bound was $100 or $10,000, whether the authority was revoked ninety seconds ago, or whether the agent presenting the credential is the agent it was issued to.

Three concrete failure modes follow:

1. **Bound erasure.** The principal's $100 limit exists only in Company A's infrastructure. Company B executes $150 and owns the loss. Any compromise, misconfiguration, or prompt injection inside A silently becomes B's liability.
2. **Credential portability.** A bearer token exfiltrated from the agent's runtime is replayable by anyone. Nothing binds it to the agent's key.
3. **No durable record of the decision.** When the refund is disputed, neither party holds evidence of what authority was presented and what was decided. Logs are assertions, not artifacts bound to the proof.

The receiver executes the action and carries the liability, yet has the least evidence of anyone in the chain. That inversion is the problem.

## 3. Layer separation

This contribution is meaningful only if it is not duplicating an existing layer. The separation:

| Layer | Question answered | Representative | Ratify overlap |
|---|---|---|---|
| Workload identity | *Which workload is calling?* | SPIFFE/SPIRE (contributed by HPE) | None. Complementary, see §13. |
| Runtime isolation | *What may this runtime touch?* | NVIDIA OpenShell | None. Complementary, see §14. |
| Agent harness / orchestration / trace | *What is the agent doing, and how is it observed?* | NOOA, NeMo | None. Ratify is the payload NOOA carries. |
| Policy engine | *What does this deployment permit?* | OPA, Cedar, receiver-local rules | None. Ratify runs before policy and feeds it. |
| **Delegated authority** | ***Who authorized this agent to do this, under what bounds, and can the receiver verify it independently?*** | **Ratify** |, |

The distinction that matters most: SPIFFE and OpenShell are both **deployment-scoped**. An SVID is meaningful inside the trust domain that issued it; an OpenShell policy is enforced by the runtime the operator controls. Neither travels to a receiver in a different organization as verifiable evidence of a principal's intent. A delegation proof does, that is its entire purpose.

## 4. Non-goals

Ratify does not, and this reference does not:

- Authenticate workloads or issue workload identity. Use SPIFFE/SPIRE.
- Isolate or sandbox a runtime. Use OpenShell, containers, or VMs.
- Evaluate deployment policy. Ratify establishes authority; the receiver's policy engine remains in force afterward and may still deny.
- Provide model guardrails, prompt-injection defense, or agent safety evaluation.
- Replace OAuth for user-to-application consent, or IAM for employee access.
- Make the agent trustworthy. It makes the agent's *authority* checkable.

Ratify is not a runtime dependency of the receiver in any commercial sense: verification is a local library call against public keys. There is no vendor in the verification path.

## 5. Architecture

```
  PRINCIPAL (Company A, offline)
    │  signs a bounded DelegationCert
    │  scope: payments:send · max_amount $100 USD · expires +24h
    ▼
  AGENT  (NOOA process, Company A)
    │  holds the cert + its own private key
    │  NOOA presentation adapter attaches the proof
    │                                        ┌─────────────── trust boundary
    │  ── phase 1: describe intended action ─┼──▶  RECEIVER (Company B)
    │                                        │      parses amount ITSELF
    │  ◀── challenge bound to receiver's ────┤      builds OperationContext ITSELF
    │       own OperationContext             │      derives session_context ITSELF
    │                                        │      issues single-use challenge
    │  ── phase 2: proof + challenge sig ────┼──▶  consumes challenge atomically
    │                                        │      verify_bundle(...)
    │  ◀── decision + receipt id ────────────┤      applies receiver-local policy
    │                                        │      executes or refuses
    ▼                                        │      signs + chains a receipt
  NOOA TRACE                                 └───────────────
    records decision + receipt id
```

Two properties are load-bearing and are enforced by construction, not convention:

1. **The receiver defines what is being authorized.** The agent describes its intent; the receiver parses it, canonicalizes it, and binds it into the challenge. The agent then signs a context it did not author.
2. **The agent's process contains no decision logic.** The NOOA adapter presents and reports. It cannot allow anything.

## 6. Trust boundaries

**Trusted by the receiver:** the principal's root public key (an explicit deployment decision, first trust is always configured, never inferred); the receiver's own clock, verification code, and challenge store; the revocation source it chooses.

Trust anchoring is normative, not a convention of this reference: SPEC §15.4 requires that a verifier obtain principal public keys out of band and **MUST NOT** treat a key arriving in-band with the proof bundle as a trust root. The SDK cannot enforce this, it has no way to know whose roots a deployment accepts, so the receiver checks that the chain terminates at its configured principal before granting any authority. Omitting that check is the difference between "this chain is internally consistent" and "this chain is one I accept": an attacker can always mint a valid root and delegate to itself.

**Untrusted by the receiver, everything the agent sends**, including the requested amount, the resource identifier, the claimed operation, and any decision the agent believes it reached. These are inputs to be parsed, never facts to be accepted.

**Business inputs are part of the trust boundary, not hygiene around it.** The `max_amount` constraint is enforced as `requested_amount > max_amount`, and every ordered comparison against NaN is false, so a NaN amount satisfies any ceiling. Python's JSON parser accepts a bare `NaN` literal, which made this reachable by any caller: an early version of this reference authorized a NaN refund and poisoned its ledger permanently. Negative infinity and ordinary negative values pass the same check for the same reason, and a negative refund is a charge. The receiver therefore rejects non-finite, non-positive, and non-numeric amounts before it constructs an `OperationContext` or issues a challenge. The general lesson is worth stating plainly: **handing an unvalidated float to a verifier and expecting the verifier to save you is the mistake.** A verifier evaluates the constraint it was given against the context it was given; domain validity of that context belongs to the receiver.

This does raise a protocol-hardening question, whether constraint evaluation should fail closed on non-finite `VerifierContext` values rather than silently comparing false, which is recorded as a separate design issue rather than changed across five SDKs inside a demonstration.

**Error paths are part of the boundary.** An unexpected internal failure returns a generic denial with no exception text, stack trace, proof content, or key material, and the challenge it had already claimed is deliberately not restored, handing it back would reopen the replay window the claim exists to close. The caller learns one actionable thing: obtain a new challenge. Money and the decision record are written in a single critical section, so the reference cannot pay out and then lose the record. That last property is a demonstration convenience, not a production guarantee: a real financial service needs durable transactions and idempotency keys, which this in-memory reference does not implement and does not pretend to.

**Not defended against:** a compromised receiver (it executes the action; no protocol can prevent it from lying about its own decision), and a compromised agent runtime *within the bounds already delegated*, an attacker holding the agent's key can issue refunds up to $100 for the remaining validity window. Ratify bounds the blast radius and makes it revocable; it does not eliminate it. This is stated plainly because the alternative claim would be false.

## 7. Two-phase verification sequence

Phase 1, the agent describes; the receiver decides what the request *is*:

```
agent  →  POST /refunds/challenge  {order_id, amount, currency, agent_id}

receiver:
  amount, order_id       ← parsed from ITS OWN read of the request
  required_scope         ← chosen by the receiver ("payments:send")
  oc = OperationContext(required_scope, operation="refund.issue",
                        resource_id=order_id, payload_digest=sha256(canonical))
  request_hash   = operation_context_hash(oc)
  session_ctx    = build_session_context(SessionContextInputs(
                       verifier_id, workspace_id, agent_id,
                       session_id, invocation_id, request_hash))
  challenge, exp = challenge_store.issue(session_ctx, ttl)
  pending[challenge] = {amount, currency, order_id, required_scope, session_ctx}

receiver →  {challenge, expires_at, session_context, echo_of_parsed_request}
```

Phase 2, the agent proves possession; the receiver decides *whether*:

```
agent:    challenge_sig = sign_challenge(challenge, now, agent_priv, session_ctx)
agent  →  POST /refunds  {challenge, ProofBundle}

receiver:
  record = pending[challenge]                    ← the receiver's own parse
  verify_bundle(bundle, VerifyOptions(
      required_scope  = record.required_scope,   ← never from the request body
      session_context = record.session_ctx,      ← never echoed from the agent
      challenge_store = store,                   ← atomic single-use consume
      revocation      = provider,                ← fails closed on error
      context = VerifierContext(requested_amount   = record.amount,
                                requested_currency = record.currency)))
  → decision → execute or refuse → sign + chain receipt

receiver →  {decision, status, reason, refunded, receipt_id}
```

The response carries a receipt *identifier*; the signed receipt itself stays in receiver-side audit state, where the reference exposes it for inspection. Returning the receipt over the wire would mean choosing a serialization, and alpha.16 adds `VerificationReceipt` wire codecs. A future revision can return the receipt in that canonical form; inventing an interim format here would only create something to migrate off.

The `session_context` the verifier compares against is re-read from its own pending record, not from the bundle. `verify_bundle` rejects any mismatch as `session_context_mismatch`. This is what makes request substitution a cryptographic failure rather than a policy failure.

**Replay prevention.** `MemoryChallengeStore.consume()` is a check-and-delete under a single lock, and `verify_bundle` invokes it *after* the challenge signature verifies but *before* authorization is evaluated. Two consequences, both intentional: of two concurrent presentations of one challenge, exactly one survives; and a denied presentation still burns its challenge, so denial outcomes cannot be probed repeatedly with one liveness proof. A session-context mismatch is the deliberate exception, it fails without touching the record, so a presentation under the wrong binding cannot burn the legitimate one.

**Request substitution prevention.** The amount used for constraint evaluation is `record.amount`, the receiver's phase-1 parse. An agent that obtains a challenge for $75 and then submits a phase-2 body claiming $150 is evaluated at $75, because the body's amount is never read. An agent that instead constructs its own `session_context` for $150 and signs that produces a bundle whose `session_context` does not match the receiver's record, and is rejected before authorization is considered.

## 8. NOOA integration seam

**Confirmed, public, and released.** `EventManager.intercept(kind, fn)` with `kind="agent_call"`, from `nooa.runtime.middleware`, exported in `__all__`, documented in the repo's `skills/nooa-middleware-hooks/SKILL.md`, covered by `tests/test_event_middleware.py`. Verified present and **byte-identical between released `nooa==0.0.8` (PyPI) and `main`**; the released `middleware.py` diffs clean against the branch.

`AgentCallContext` exposes `agent`, `method_name`, `args`, `kwargs`, and `result`. Registration order is execution order; middleware exceptions propagate rather than being swallowed.

NVIDIA has already established this exact pattern for third-party security integration: `src/nooa/nemo_flow_middleware.py` routes agent calls through NeMo Flow guardrails using all three middleware kinds, with a `nemo_flow_scope(agent, name)` install/uninstall helper. The Ratify presentation adapter deliberately mirrors that shape.

**Deliberately rejected seam.** `InstrumentationHooks.before_tool_execution` via `nooa.runtime.hooks.set_hooks()` is unsuitable twice over: hook exceptions are swallowed by design, so it *cannot* block; and it occupies a single contextvar slot that `enable_tracing()` already uses, so installing hooks there silently disables NOOA tracing. Both are documented in NOOA's own materials.

**Naming.** The component is a **presentation adapter**, not authorization middleware. It attaches a proof and reports a decision. It does not make one. The name is chosen to make the misreading harder.

## 9. Why verification remains receiver-side

NOOA middleware executes inside the agent's own process. Anything it "decides" is decided by the party being authorized. An agent-side check is a usability feature, it fails fast and saves a round trip, but it is worth exactly zero as a security control, because a compromised or misaligned agent simply does not run it.

The reference therefore places no verification in the adapter at all, not even an advisory pre-check. This is a testable property, and it is tested: the integration test asserts that the receiving service performs verification and that the adapter's only outputs are a presented proof and a reported decision.

## 10. Adversarial scenarios

Each row is a test in the reference. Expected statuses are those the implementation must be shown to produce; none are asserted here in advance of the tests demonstrating them.

| # | Scenario | Why it matters |
|---|---|---|
| 1 | $75 refund, $100 bound, valid window | Baseline: bounded authority succeeds |
| 2 | $150 refund against a $100 `max_amount` | The principal's bound survives transit and binds a receiver in another org |
| 3 | Expired delegation | Authority is time-bounded without a revocation round trip |
| 4 | Revoked delegation | Authority can be withdrawn before natural expiry |
| 5 | Proof presented by a different agent key | Delegations are not bearer tokens; theft alone is insufficient |
| 6 | Replayed challenge | A captured valid presentation cannot be reused (refused pre-authentication; no receipt) |
| 7 | Proof bound to one operation, presented for another | An intermediary cannot retarget a valid proof (refused pre-authentication; no receipt) |
| 8 | Child cert claims a scope the parent never granted | Non-amplification of scope (see §12) |
| 9 | Child cert claims `max_amount` $1,000 under a $100 parent | Non-amplification of constraints (see §12) |
| 10 | Every case above | Each produces a structured decision; those reaching authentication also produce a signed receipt |
| 11 | NOOA agent invocation end-to-end | The adapter presents; the receiver decides |

## 11. Receipts and audit semantics

A Ratify `VerificationReceipt` is precisely this and no more:

- **A verifier-signed assertion of the receiver's decision**, hybrid-signed by the verifier's key.
- **Cryptographically bound to the exact proof presented**, via `bundle_hash`. Anyone holding the bundle can recompute the hash and confirm the receipt refers to that presentation and no other.
- **Issued for denials as well as approvals**, carrying the decision status and error reason.

**What chaining does and does not detect.** Receipts chain by `prev_hash` over the previous receipt's canonical signable bytes. That makes four things detectable within a verifier's own sequence: modification of a retained earlier receipt, removal from the middle when a later receipt is retained, reordering, and forking. It does **not** independently detect deletion of the final receipt, or truncation of the entire suffix, a chain that has been cut short is internally consistent and verifies perfectly. Detecting truncation requires something outside the verifier: an externally published checkpoint, a witness, a trusted counter, or any other party retaining a later chain head. The protocol defines a `WitnessEntry` structure for hash-chained witness logs, but **no witness service is implemented**, so that remains future work.

The receipt is explicitly **not** independent third-party attestation. It establishes what the verifier said, not that the verifier was honest; a colluding or compromised verifier can sign whatever it likes.

**Receipts cover authenticated presentations only.** A receipt is issued once the presenter has proved possession of the agent key named in the receiver's own pending record, and at most once per issued challenge. Traffic rejected before that gate (unknown challenge, a challenge issued to a different agent, a presentation that never answers the challenge, malformed input) produces a structured decision and an entry in an unsigned operational log, but no receipt. The reason is concrete: if unauthenticated callers could make the verifier append signed entries, they would hold a write primitive into the audit trail, able to grow it without bound and bury real decisions in noise. Bounding issuance to consumed challenges reduces that to ordinary rate limiting.

**Failure receipts do not assert an authenticated identity, this reference's policy.** Expiry and revocation are evaluated before the chain signature is verified, so the identifiers available at that moment come from a certificate nobody has authenticated. This receiver therefore leaves those fields empty on any failure rather than populating them from unverified claims, and the presentation stays recoverable through `bundle_hash`. It is a conservative receiver-side choice and a tested property of this reference, not a settled protocol requirement. Whether the protocol should change the fields themselves is a separate design question, deliberately not resolved here.

## 12. Subdelegation and non-amplification, precise semantics

Ratify enforces non-amplification, but through two different mechanisms with different observable behavior. Conflating them would misrepresent the protocol.

**Scope** is *intersected* across the chain. A child certificate claiming a scope its parent never granted is not rejected as malformed, the amplified scope simply never enters the effective scope set. An action relying solely on that scope is therefore denied as `scope_denied`. The enforcement is semantic, not structural.

**Constraints** are evaluated *per-certificate and conjunctively*: every certificate in the chain has its constraints evaluated against the same verifier-supplied context. A child claiming `max_amount` $1,000 beneath a parent bounded at $100 does not raise the ceiling, because the parent's constraint is still evaluated and still fails.

**Subdelegation is additionally gated**: a certificate may only issue a child if its own parent explicitly granted `identity:delegate`, and that scope is never conferred by wildcard expansion.

The reference tests assert the exact status and error classification produced in each case rather than asserting a narrative. Any claim in this section is subordinate to what those tests demonstrate.

## 13. Revocation assumptions

Ratify's SDK deliberately ships no revocation transport. `VerifyOptions.revocation` takes a caller-supplied provider returning `(revoked, error)`, and a lookup error fails the verification closed as `revocation_error` rather than being treated as "not revoked". `force_revocation_check` makes a live check mandatory for high-stakes endpoints and refuses to run if no provider is configured.

The honest consequence: **revocation is only as timely as the receiver's chosen source.** Offline verification with no revocation provider is cryptographically sound but blind to withdrawal until natural expiry. This is the standard offline-credential tradeoff and the reason short expiry windows matter. Deployments needing near-immediate withdrawal must accept an online dependency; the protocol makes that a receiver-side choice rather than imposing one. The reference demonstrates an online provider and a fail-closed error path.

## 14. SPIFFE/SPIRE interoperability, proposed future work

SPIFFE answers *which workload*; Ratify answers *who authorized what*. Conflating them would weaken both. The proposed non-conflating binding: the receiver authenticates the connection via mTLS and obtains the caller's SVID, then includes the SPIFFE ID among the session-context inputs bound into the challenge. A valid proof replayed from a different workload identity then fails cryptographically rather than by policy.

This is **not implemented in v1, deliberately.** A normative binding of an external identity format into the session-context construction is a specification change requiring protocol review. Shipping an unreviewed binding inside a demonstration would be the wrong order of operations, and would set a de facto standard by accident.

## 15. OpenShell composition, executed

OpenShell (Rust, Apache-2.0) enforces declarative YAML policy across filesystem, network, process, and inference layers, intercepting outbound connections to allow, reroute, or deny. The composition is now executed rather than proposed. `demos/nvidia-nooa-delegated-authority/run-openshell-profile.sh` runs the full path against a pinned v0.0.102 gateway and writes a machine-readable artifact.

### 15.1 Layer separation

Isolation bounds *where a proof can go*; delegation bounds *what it can do*. Both must permit execution, and neither substitutes for the other.

| Decided by OpenShell | Decided by Ratify |
|---|---|
| Destination host, port, and path | Principal identity and the delegation chain |
| MCP method | Tenant-qualified resource (alpha.16 `resource_path`) |
| MCP tool name | Amount and currency ceiling |
| Envelope size admitted for inspection | Expiry, revocation, and revocation-source failure |

v0.0.102 states that "tool argument matching is not supported yet; allowed tools accept all argument payloads by default." OpenShell therefore cannot see the refund amount or the order id, and is not asked to. This is why the receiver exposes the two-phase flow as **two tools**, `refund.prepare` and `refund.execute`: a single tool with a phase argument would be invisible to a runtime policy. Ratify does not replace isolation, and OpenShell does not evaluate Ratify's semantic constraints.

### 15.2 What execution established

All seven groups, including the unified NOOA path, pass against the published
`ratify-protocol==1.0.0a16`: 52 required cases, 64 gates, and zero skips. One
full compatibility run passed 64/64 on OpenShell v0.0.102. The earlier v0.0.96
stability campaign passed twice sequentially and twice concurrently on
`RATIFY_SDK=published`; these are version-separated claims, not four v0.0.102
runs.
The unified path's early instability, four consecutive `nooa` imports exhausting
one sandbox, was resolved by importing `nooa` exactly once in a single suite
process rather than by isolating each case into its own sandbox; the import
count is measured by a `sys.addaudithook` on the `import` audit event, not
declared. Full run-by-run evidence, including a disclosed bounded retry added
for a transient `sandbox download` flake observed twice under concurrent load:
[`docs/evidence/nvidia-reference-evidence.md`](evidence/nvidia-reference-evidence.md).

Each case declares an expected outcome and every boundary delta it may produce, and is judged against control-plane snapshots taken immediately either side of it. A missing case, missing snapshot, stale sequence, partial result, or unexplained event is a failure, never a skip.

- **Proof carriage is measured, not asserted.** The proof travels in `_meta` under `com.ratifyprotocol/proof`. The receiver records the SHA-256 and length of the exact inbound base64 string, the runner records the same for what it signed, and the two are compared. The proof itself is never written anywhere.
- **A maximum-depth chain crosses inline.** Eight certificates, 88,990 raw bytes, 118,656 base64, 118,940 as a complete MCP body, admitted by the policy and authorized by the receiver. No compression, no detached retrieval.
- **Three size limits are independently observable.** The MCP/HTTP body limit (the pinned SDK's 4 MiB default, inherited rather than enforced here), OpenShell's `mcp.max_body_bytes` at 262,144, and the receiver's decoded-proof ceiling at 131,072. The receiver's bound was originally 196,608, which corresponds to a 262,148-byte encoded ceiling: four bytes above the envelope limit, so every proof large enough to trip it was already large enough for OpenShell to refuse first. A defense-in-depth check that can never fire is not defense in depth, so the bound was lowered to a value inside the envelope limit, still leaving 42,082 bytes of headroom over the largest chain the protocol permits.
- **The invariant held.** Fifteen parser-differential probes, duplicate JSON members in both orders and header-versus-body disagreement in both directions, produced no case where OpenShell admitted a request as one method and tool and the MCP server dispatched another.

### 15.3 Findings and constraints observed in the v0.0.96 campaign

Reported as observations of the pinned version, not as defects claimed against it.

1. **Concurrent gateway bootstrap collides.** The gateway creates its supervisor-extraction container under the fixed name `openshell-supervisor-extract-1-0`, so two gateways starting against one container runtime fail with a Docker 409. The profile serializes bootstrap only, and records this in the artifact rather than working around it silently.
2. **The sandbox endpoint derives from the gateway's own bind port.** `OPENSHELL_ENDPOINT` is built from the port the gateway binds, not from `grpc_endpoint`, so publishing an internal 8080 on a dynamic host port leaves every sandbox unable to fetch its policy. The container port must be dynamic too.
3. **An oversized envelope is refused before policy evaluation,** as HTTP 400 with `invalid_jsonrpc_request`, not as a policy denial. A harness that detects refusals by matching `policy_denied` will misread it; the receiver's ingress counter is the reliable discriminator.
4. **`sandbox exec` does not bound the CLI.** `--timeout` bounds the remote command, but with stdin inherited and not at EOF the CLI blocks before that timeout is armed. Every exec here passes `--no-tty`, closes stdin, and is externally bounded.
5. **`sandbox upload` resolves its destination by basename.** Uploading `openshell_client.py` to `.../client.py` created a `client.py` *directory* containing the file. The profile names local files exactly as they must appear in the sandbox and asserts the result is a regular file.
6. **`sandbox download` is confined to `/sandbox`.** The working directory sits there so results can be downloaded rather than scraped from stdout.

### 15.4 Still open

An OpenShell policy conditioned on a Ratify verification outcome would require an external-decision hook that does not currently exist. That remains a question for NVIDIA rather than an assumption to build on.

## 16. Deliverables

Entirely within the Ratify Protocol repository. **No NVIDIA repository is modified.**

- `demos/nvidia-nooa-delegated-authority/`, principal, receiving service, presentation adapter, scenario driver
- Hermetic verification suites, no LLM, no network beyond loopback, no NOOA dependency, no container runtime
- A reproducible OpenShell profile: one command, pinned by immutable digest, 52 cases across 64 gates, machine-readable artifact
- One real NOOA integration test against released `nooa==0.0.8`, hermetic via NOOA's own `FakeLLMClient`
- This proposal
- A README for engineers, with a five-minute path from clone to observed denials

Dependencies are held to the existing floor: the receiving service uses only the Python standard library. No web framework is introduced for a protocol reference.

**Protocol version.** The reference requires Ratify Protocol v1.0.0-alpha.16, published and installed from PyPI, and is verified against it: all 181 tests pass with `nooa==0.0.8` on Python 3.12 under `RATIFY_SDK=published ./scripts/nvidia-reference-check.sh`, which fails on any skip and asserts that `ratify_protocol` resolves outside this repository rather than from the checkout. The dependency is real rather than nominal. The reference uses alpha.16's `resource_path` constraint to bind a refund to one tenant-qualified order, and those tests fail on alpha.15 because the constraint type does not exist there.

## 17. Evaluation plan

The reference is built and its tests pass. There is no build schedule to propose, and presenting one would misrepresent the state of the work, the calendar here is set by NVIDIA's review availability, not by engineering time on our side.

| Step | Work | Blocking dependency |
|---|---|---|
| 1 | Technical review; confirm delegated authority is in scope; identify the integration owner | NVIDIA |
| 2 | Adapt the reference to feedback, trace attributes, hooks, or seam changes the NOOA team prefers | NVIDIA guidance; then days |
| 3 | Adversarial and interoperability testing beyond what the profile already covers | NVIDIA confirmation of the seam |
| 4 | Joint review; decide upstream form | Joint |

Steps 2 and 3 are days of work once unblocked. Everything on the critical path is a decision, not an implementation.

One item is gated on our side and stated for transparency: the reference tracks the current protocol release, and is re-verified against each new one.

## 18. Success criteria

A skeptical NVIDIA engineer can, in under five minutes:

1. State why this is not SPIFFE and not OpenShell, and why OpenShell and Ratify are both required.
2. Run the deterministic suite locally from a clean checkout, with no API key.
3. Observe an authorized action and at least six distinct, correctly classified denials.
4. Confirm from the code that the receiver, not the agent, decides.
5. Inspect a delegation, a decision, and a signed receipt.
6. Identify the integration seam, and see that it is a public, released NOOA API.

Failure to meet any of these is a defect in the contribution, not in the reviewer.

## 19. Questions for NVIDIA

**NOOA**
1. Is `event_manager.intercept("agent_call", ...)` considered stable public API for third-party integrations, or is the `nemo_flow_middleware.py` pattern privileged/internal?
2. What is the supported way for middleware to attach custom attributes to the current OpenInference span, so a verification decision and receipt identifier appear in the trace as first-class attributes rather than return values?
3. Is `FakeLLMClient` supported for third-party hermetic integration tests, or is a different test double preferred?
4. Is there a compatibility policy for `nooa` pre-1.0 releases that a downstream adapter should pin against?

**OpenShell**
5. Is an external authorization hook, allowing a policy decision to consult a verified delegation, in scope, or is the intended composition strictly layered?
6. Would an OpenShell policy example demonstrating egress restriction for an agent holding a delegation proof be a welcome contribution?

**Alliance**
7. Is delegated authority considered in scope for the open agent-defense stack, or covered under "identity and permissions" by existing contributions?
8. Is there interest in an interoperability profile describing how workload identity (SPIFFE) and delegated authority compose without conflation?
9. What is the preferred upstream form: a standalone reference, an example in a project repository, or a written interoperability profile?

## 20. Centralized runtime policy (F5 / NeMo Guardrails), future work

F5 is integrating AI Guardrails with NVIDIA NeMo Guardrails to centralize AI runtime policy across models, frameworks, and applications, positioned as inline or out-of-band inspection covering prompt injection, data leakage, harmful interactions, and excessive agent autonomy.

The overlap is apparent rather than real, and the distinction is worth stating precisely because "excessive agent autonomy" sounds like the same problem:

- **Guardrails policy** answers *does this interaction comply with enterprise safety and runtime policy?*, authored centrally by the operator.
- **Ratify** answers *did an accepted principal cryptographically delegate authority for this exact action, to this agent, under these constraints?*, authored by the principal, verified by the receiver.

They fail differently. A guardrail cannot tell you whether a customer authorized a $100 refund ceiling; a delegation proof cannot tell you whether a response leaks PII. An enforcement point should require both verdicts:

| Delegated authority | Enterprise policy | Outcome |
|---|---|---|
| PASS | PASS | Allow |
| FAIL | PASS | Deny, no delegated authority |
| PASS | FAIL | Deny, enterprise policy |
| FAIL | FAIL | Deny, both controls |

Two seams look plausible and **neither is implemented or claimed**:

1. **`VerifyOptions.policy` (`PolicyProvider`).** Ratify already evaluates a caller-supplied policy provider after cryptographic verification succeeds, failing closed on provider error. A provider could carry the receiver-defined action context to a guardrails evaluation, making the final decision conjunctive. Open question: whether that API evaluates consequential tool and API actions, or only prompts and responses.
2. **An API gateway as the receiving enforcement point.** The gateway authenticates and inspects the request, verifies the Ratify proof locally, and proceeds only when both pass. This requires confirming the exact supported extension mechanism before it is described as an integration.

Ratify's HMAC `PolicyVerdict` may be relevant as a cached fast path, but calling it an integration would require the policy backend to securely issue or participate in that verdict, a live `PolicyProvider` is the more honest first hypothesis. This section is included as evidence that receiver-side verification composes with centralized enforcement infrastructure, not as a second implementation for v1.

## 21. Physical-AI extension, future work

The protocol's constraint vocabulary includes geofences (`geo_circle`, `geo_polygon`, `geo_bbox`) and kinematic bounds (`max_speed_mps`) alongside the monetary and rate bounds used here, evaluated by the same verifier against a caller-supplied context. The same receiver-side pattern therefore extends to an actuation boundary on Jetson or IGX: a principal delegates bounded authority to a robot or drone control agent, and the actuation service verifies the delegation, including geofence and speed bounds, before commanding motion, emitting a signed receipt per decision.

This is a plausible extension of the same architecture, not a validated one. It requires real hardware, latency measurement at the actuation boundary, and a safety analysis that is out of scope here. It is listed to indicate direction, and is explicitly not claimed as working.

---

## Appendix: verification evidence

Claims about third-party software in this document were verified against source at the following versions, not inferred from documentation.

| Claim | Source | Verification |
|---|---|---|
| `intercept("agent_call", fn)` is public and released | `nooa==0.0.8` (PyPI sdist) `src/nooa/runtime/middleware.py`, `runtime/event_manager.py` | Exported in `__all__`; released file diffs byte-identical against `main` |
| Ordinary (non-generating) async agent methods reach `agent_call` middleware with no LLM call | `nooa==0.0.8` `src/nooa/runtime/method_wrapper.py` | Executed: middleware observed `method_name`, `args`, and `result`; no LLM invoked |
| Sync methods bypass `agent_call` middleware | `nooa==0.0.8` `src/nooa/runtime/method_wrapper.py` | Stated in source; adapter therefore targets async methods |
| `InstrumentationHooks` shares one slot with tracing | NOOA `skills/nooa-middleware-hooks/SKILL.md`; `tracing/__init__.py` | Documented; seam rejected on this basis |
| `FakeLLMClient` is a public export | `nooa==0.0.8` `src/nooa/unifiedllm/__init__.py` | Present in `__all__` |
| OpenShell policy model and absence of an external-authorization hook | NVIDIA/OpenShell public documentation | Reviewed; absence stated as "not documented", not as "does not exist" |
| Alliance component list and SPIFFE/SPIRE contribution by HPE | NVIDIA Open Secure AI Alliance announcement | Reviewed |

Ratify Protocol claims are cited to the implementation in this repository and are subordinate to the reference test suite.
