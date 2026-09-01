# Ratify reference profiles

Reference profiles answer a practical question: **where does Ratify fit in the
agent stack I already use, and which system must verify authority before the
action occurs?**

They are executable integrations for specific agent frameworks, transports,
runtimes, and platforms. Each turns the protocol into a visible outcome: one
properly authorized request reaches a protected handler, while an out-of-scope,
changed, expired, revoked, replayed, or untrusted request does not.

## Adding a reference

Every reference README follows the required structure in
[`REFERENCE-README-STANDARD.md`](REFERENCE-README-STANDARD.md): ten sections in a
fixed order, a table naming what each role implements including the platform,
and diagrams that show the deny path as well as the allow path. The GitHub
Copilot reference is the worked example.

## Available references

| Platform | What it demonstrates | Run it |
| --- | --- | --- |
| [GitHub Copilot and MCP](github-copilot/README.md) | Copilot invokes a deployment tool; an independent receiver verifies exact delegated authority first | `cd references/github-copilot && ./run-reference-check.sh` |
| [Google ADK and MCP](google-adk/README.md) | An ADK agent requests cloud provisioning; an independent MCP receiver verifies the signed ceiling and resource before anything is created | `./scripts/google-adk-reference-check.sh` |
| [LangChain and MCP](langchain/README.md) | A LangChain agent crosses an MCP boundary; the receiver verifies who authorized the exact action and which bounds still apply | `./scripts/langchain-reference-check.sh` |
| [NVIDIA OpenShell and NOOA](nvidia-nooa-openshell/README.md) | An agent at one company asks another company's service to move money; the receiver verifies the signed ceiling, named order, and expiry before refunding | `./scripts/nvidia-reference-check.sh` |
| [Ratify Edge Physical AI](physical-ai-edge-sentinel/README.md) | A Linux edge receiver verifies a bounded physical-action request before sending one safe actuator command to an Arduino Uno | `RATIFY_SDK=/path/to/ratify-c ./references/physical-ai-edge-sentinel/run-reference-check.sh` |

Only references merged into `main` appear here. The
[`registry/`](registry/README.md) records exact versions, evidence, and whether
the named platform reviewed or endorsed each integration.

## Why use a reference?

- **Developer:** start from working adapter and receiver code instead of
  inventing the integration and trust boundary yourself.
- **Platform team:** see exactly where authority presentation belongs in the
  runtime and where enforcement must remain independent.
- **Security or IAM team:** evaluate concrete allow and deny evidence before
  considering production deployment.
- **MCP or SaaS provider:** test how to accept consequential calls from agents
  issued by customers, partners, or other organizations.

References are larger and more platform-specific than the small examples in
[`demos/`](../demos/README.md).

These are open-source interoperability references, not hosted services or
production support commitments. Use them now for evaluation, integration work,
or as the basis of a self-operated implementation. **Ratify Verify** is the
managed commercial surface under development for organizations that need
operated trust configuration, revocation, policy, replay protection, audit
retention, observability, availability, and supported deployment adapters.
Each profile explains how to join the design-partner path when that is the
better fit. Proof bytes and verifier semantics remain portable.

Every accepted profile should contain:

- an explicit trust boundary and layer-separation statement;
- exact tested dependency versions;
- a deterministic path that does not depend on model judgment;
- adversarial allow/deny cases with protected-handler invocation evidence;
- a one-command published-package gate;
- limitations and non-goals;
- evidence generated from executed tests, not projected results; and
- a disclosure of endorsement, partnership, and standardization status.

## Registry

Each profile owns one entry under [`registry/`](registry/README.md). Keeping
entries in separate files lets platform references branch from `main` and merge
independently without competing for a shared table row.

## Lifecycle

Profiles begin as independent drafts on feature branches. Passing tests do not
make a profile official for the named platform. The registry entry must state
whether a platform reviewed, contributed to, or endorsed the work.

A profile remains in this repository while Ratify owns its maintenance and it
shares the protocol release cadence. It may move to a dedicated or jointly
maintained repository when it needs independent releases, external maintainers,
or partner-owned governance. A move should leave a compatibility pointer at the
old path so public evidence links do not silently break.
