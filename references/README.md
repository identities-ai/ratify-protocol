# Ratify reference profiles

Reference profiles show how Ratify composes with a specific agent framework,
transport, runtime, or platform without changing the Ratify verifier contract.
They are larger and more platform-specific than the small examples in
[`demos/`](../demos/README.md).

These are open-source interoperability references, not hosted services or
production support commitments. They make the integration pattern inspectable,
portable, and reproducible. **Ratify Verify** is the separate managed commercial
surface for operating the same protocol at scale: managed trust configuration,
revocation, policy, audit retention, observability, availability, and supported
deployment adapters. The proof bytes and verifier semantics remain portable;
customers choose whether to operate them themselves or use the managed service.

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

| Profile | Status | Ratify version | Platform version | Gate |
|---|---|---|---|---|
| [Google ADK](google-adk/README.md) | Independent draft; 20/20 gate green | `1.0.0a16` | `google-adk==2.6.3` | `./scripts/google-adk-reference-check.sh` |

## Lifecycle

Profiles begin as independent drafts on feature branches. Passing tests do not
make a profile official for the named platform. The registry entry must state
whether a platform reviewed, contributed to, or endorsed the work.

A profile remains in this repository while Ratify owns its maintenance and it
shares the protocol release cadence. It may move to a dedicated or jointly
maintained repository when it needs independent releases, external maintainers,
or partner-owned governance. A move should leave a compatibility pointer at the
old path so public evidence links do not silently break.
