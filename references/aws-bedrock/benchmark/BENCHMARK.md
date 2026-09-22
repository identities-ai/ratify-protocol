# Ratify Protocol vs. Amazon Bedrock AgentCore Gateway

Benchmarked documents:

- Ratify, [Agent Relay × Ratify Phase 2 Technical Note](https://ratifyprotocol.com/writing/agent-relay-phase2-technical-note) (25 Aug 2026)
- AWS, [Introducing Amazon Bedrock AgentCore Gateway](https://aws.amazon.com/blogs/machine-learning/introducing-amazon-bedrock-agentcore-gateway-transforming-enterprise-ai-agent-tool-development/)

Both are about an agent reaching a tool it does not own. They are not competitors,
and reading them as competitors is the most common way to get this wrong. They
answer different questions, and a deployment that needs one usually needs both.

## The one-line difference

**AgentCore Gateway answers "can this agent reach this tool?"**
**Ratify answers "did a principal authorize this exact action, and does that authorization still stand?"**

A Gateway request carries an OAuth bearer token. That token says an approved
client is calling. It does not say who asked for the call, what mandate they
gave, what resource it was bounded to, or whether they have since withdrawn it.
Those facts are exactly what a Ratify delegation certificate carries, and they
are checkable by the receiving system offline, without calling the issuer.

## Side by side

| | AgentCore Gateway | Ratify Protocol |
| --- | --- | --- |
| **Kind of thing** | Managed AWS service | Open protocol + 5 SDKs (Go, TS, Python, Rust, C), Apache-2.0, spec CC-BY-4.0 |
| **Primary job** | Solve the M×N tool-integration problem; turn REST/OpenAPI/Smithy/Lambda into MCP tools | Prove delegated authority before a consequential action |
| **Transport** | MCP over streamable HTTP; it *is* the transport | Transport-agnostic; rides MCP, A2A, HTTP, or a queue |
| **Inbound auth** | OAuth resource server; 3LO and 2LO against Cognito / Okta / Auth0 / your IdP; approved client IDs and audiences | Not its job. Ratify assumes you already authenticated the caller |
| **Outbound auth** | IAM role assumption (Lambda/Smithy); API key or 2LO OAuth (OpenAPI), via AgentCore Identity | Not its job |
| **What the receiver learns** | A valid token from an approved client | Issuer identity, subject identity, scope, resource + path bounds, issue/expiry times, full delegation chain |
| **Delegation** | Not modeled. A token does not narrow when passed on | First-class. Chains up to depth 8; authority can only shrink, and a child's lifetime is clamped to the parent's remaining window |
| **Resource binding** | Per-target credentials; scoping is IAM/API policy | `resource_path` constraint signed into the certificate; segment-boundary prefix matching at verify time |
| **Revocation** | Token lifetime and IdP revocation; introspection is a network call | Signed `RevocationPush`, checked fail-closed on the verifier's hot path with no synchronous round trip |
| **Offline verification** | No — the Gateway is in the path | Yes — hybrid Ed25519 + ML-DSA-65, verified against the issuer's public key with no live call |
| **Post-quantum** | Not stated | Every signature is hybrid Ed25519 + ML-DSA-65 (FIPS 204); both must verify |
| **Audit artifact** | CloudTrail management + data events; CloudWatch metrics (p50/p90/p99) | Signed `VerificationReceipt`, hash-named and chained by `prev_hash`, verifiable by a third party who trusts neither side |
| **Tool discovery** | `x_amz_bedrock_agentcore_search` — semantic search over the tool catalogue | Out of scope |
| **Who can check the record** | Whoever holds the AWS account | Anyone holding the public keys, including a skeptic who trusts neither party |
| **Operational maturity** | GA managed service, serverless, per-target config | alpha; 79 canonical test vectors; cross-language interop proven; one published five-week cross-company engagement |

## Where the two documents differ most: what counts as evidence

This is the sharpest contrast, and it is about the writing as much as the tech.

The AWS post is a launch announcement. It describes capabilities, shows
`create_gateway` / `create_gateway_target` calls, and lists the observability
dimensions. It reports no failures, publishes no numbers, and names no
limitations. That is the genre working as intended — it is not a defect, but it
means nothing in it can be independently checked.

The Ratify note is a run record, and roughly a third of it is about what did not
work:

- The health endpoint returned `{"ok":true}` throughout while holding no key — it
  asked the artifact, not the process.
- The publishing path imported nothing from Ratify and asked no verifier
  anything. What had been proven was that a GitHub account could open a pull
  request.
- A GitHub first-time-contributor gate was silently cleared by merging a
  rehearsal PR, so later tests passed invisibly.

It also declines to publish a number it has: send-to-applied was 1.417s, published
"as a bound and not as a measurement" because the contractor's drain poll runs
every three seconds and two samples from one poll interval do not support a
latency figure. And it names what it did not show: both deployments ran the same
software, so it does not demonstrate interoperability between independent
implementations; two confinement cases skip loudly rather than pass silently.

The strongest single piece of evidence in it is three lines — the same
certificate, same path, same command, answering `authorized_agent` at 18:00:08
and `revoked` at 18:03:05, with 12,835 seconds of validity remaining, ruling out
expiry, and an unrelated certificate answering in between, ruling out a verifier
that went dark.

**Benchmark verdict on evidence:** these are not comparable claims. AWS asserts
capability; Ratify demonstrates a bounded, revocable mandate surviving a real
organizational boundary and publishes the ways it was wrong. If you are
evaluating for production, the AWS service is the one you can deploy today and
the Ratify claim is the one you can verify today.

## Where each is weak

**AgentCore Gateway**

- The Gateway is a party to every transaction *and* the record-keeper for it.
  CloudTrail is excellent, and it is the coordination layer's own log. The Ratify
  note's framing applies: the coordination layer cannot also be the referee.
- Nothing in the model narrows when an agent hands work to another agent. Agent A
  holding a token and passing it to agent B passes the whole token.
- Cross-organizational is awkward. Two companies both need identity in a shared
  OAuth arrangement, and the receiving side gets a token, not a mandate.
- Everything is inside one cloud account boundary. The audit trail does not
  travel to a counterparty who does not trust you.

**Ratify**

- alpha. Fixture bytes may change between pre-releases; the note itself says it
  does not establish production hardening or commercial adoption.
- It enforces nothing. A signature cannot stop a filesystem write — the receiving
  system does that, under its own isolation model, which Ratify separates out and
  declines to vouch for.
- No tool integration, no transport, no discovery, no managed anything. Everything
  AgentCore Gateway sells, you still have to build or buy.
- The published engagement ran the same binary on both sides. Two independently
  written verifiers agreeing across a live boundary is explicitly unproven and
  explicitly unscheduled.
- ML-DSA-65 signatures are large. Sub-millisecond verify in the compiled SDKs,
  but the wire is not free.

## How they compose

They stack cleanly, because they cut at different layers:

```
Agent ──▶ AgentCore Gateway ──▶ Lambda target ──▶ your handler
          │                     │                 │
          │ OAuth: is this      │ IAM: may this   │ Ratify: did a principal
          │ client approved?    │ gateway call    │ authorize THIS action on
          │                     │ this function?  │ THIS resource, and does
          │                     │                 │ that still stand?
```

The Gateway's own guidance is that each target gets exactly one outbound
credential, for clear security boundaries and audit trails. That credential is
the same for every caller of that target. Ratify is what makes one invocation of
that target distinguishable from another in terms of mandate: the proof travels
in the tool call's arguments, and the Lambda verifies it before doing the work.

Concretely, the Lambda target becomes:

```python
result = verify_bundle(bundle, VerifyOptions(
    required_scope="files:read",
    session_context=ctx,            # binds this proof to this exact request
    challenge_store=store,          # single-use nonce; replay is refused
    force_revocation_check=True,    # fail closed if revocation state is unavailable
    revocation=provider,
    context=VerifierContext(has_resource=True,
                            requested_resource_id=..., requested_path=...),
))
if not result.valid or result.human_id != TRUSTED_ROOT:
    return refuse(result)           # protected handler untouched
return do_the_work()
```

The working implementation of exactly that gate is in this repository:
`bedrock_ratify/receiver.py`, with the two Bedrock clients on either side of it
in `bedrock_ratify/agents.py`. It uses the Bedrock Messages API directly rather
than AgentCore Gateway; the verification code is identical either way, which is
the portability claim in practice.

## Choosing

| If you need | Use |
| --- | --- |
| Many agents, many enterprise APIs, one MCP endpoint, today | AgentCore Gateway |
| Tool discovery at scale without tool overload | AgentCore Gateway (`x_amz_bedrock_agentcore_search`) |
| An answer to "who authorized this, and is it still authorized?" that a counterparty can check | Ratify |
| Authority that narrows when one agent hands work to another | Ratify |
| Withdrawal that lands while work is in flight, without the middleware getting a vote | Ratify |
| An audit record a skeptic who trusts neither party can verify offline | Ratify |
| Agents crossing an organizational boundary into consequential actions | Both |
| A production commitment this quarter | AgentCore Gateway now; Ratify as the proof layer as it matures past alpha |

## The honest summary

AgentCore Gateway is a mature answer to a connectivity problem: it removes the
M×N integration burden and gives you managed inbound/outbound auth and a real
audit trail inside your account. It does not attempt to model delegated authority,
and reading its OAuth layer as an authorization-of-the-action layer is a category
error that gets more dangerous as agents hand work to other agents.

Ratify is an early answer to an authorization problem that the Gateway explicitly
does not solve, with unusually good evidence discipline for its stage and
unusually candid limitations. It is alpha, it enforces nothing itself, and it
needs a runtime like the Gateway to be useful at all.

The interesting question is not which wins. It is whether the managed-gateway
category absorbs portable delegated-authority proofs as a feature, or whether
proofs stay a separate portable layer precisely because the value comes from not
being issued by the party in the middle. The Ratify note's own closing gap — a
verifier written by someone other than the adapter's author, checking proofs
across a live boundary — is the test that would settle it.
