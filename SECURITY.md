# Security Policy

## Reporting a vulnerability

**Please do not open public GitHub issues for security reports.**

Email: **security@identities.ai**

We commit to:

- Acknowledging receipt within 48 hours.
- Providing an initial severity assessment within 5 business days.
- Keeping you updated on remediation progress.
- Crediting you in the advisory unless you prefer otherwise.

## Supported versions

| Version | Supported |
|---|---|
| `v1.0.0-alpha.*` | ⚠️ Active development; security fixes forward-ported |
| `< v1.0.0-alpha.1` | ❌ Not supported |

Once v1.0.0 stable is released, the support policy will specify which major/minor versions receive backported security fixes.

## Embargo and disclosure

- We follow a **90-day embargo** from the initial report to public disclosure as the default.
- For actively-exploited vulnerabilities, we may shorten the embargo after coordinated patching.
- The full coordinated advisory (CVE, scope, impact, mitigation) will be published in the `security/` directory of this repository and on our public advisories channel.

## Scope

**In scope:**

- Cryptographic correctness of the reference implementation (Go) and published SDKs (TypeScript, others as released).
- The canonical serialization implementation — any interop-breaking behavior where implementations produce divergent signable bytes.
- The verifier algorithm — any case where `Verify()` returns an incorrect result.
- The scope-vocabulary implementation — any privilege-escalation path.
- The `cmd/ratify` CLI's handling of private key material.
- Resource-exhaustion or DoS against the verifier.

**Out of scope** (report to the relevant party, not us):

- Vulnerabilities in third-party dependencies that are already known and patched upstream. Report to the dependency, then open a PR here to bump the version.
- Operational issues at any Identities AI-hosted service (Registry, Verify API). Those are reported via `security@identities.ai` with the service name in the subject line — a separate handling path.
- Attacks against out-of-protocol concerns listed in `docs/EXPLAINED.md` §5.2 (endpoint malware, social engineering of delegators, etc.). These are real risks but are not protocol defects.

## Responsible disclosure examples

| Scenario | Handling |
|---|---|
| You find a way to verify a maliciously-crafted proof bundle | **In scope — email us first.** Classic responsible disclosure. |
| You find a way to produce canonical JSON bytes that differ from the Go reference for a valid v1 data model | **In scope — email us first.** Interop breaks trust. |
| You notice the recommended challenge window is too long | **Not a vulnerability — open a GitHub issue or PR.** Policy discussion is public. |
| You find a logic bug in an Identities AI-hosted service | **Email us with `[hosted-service]` in subject.** Separate from the protocol project. |

## Hall of fame

*Reporters who responsibly disclose verified vulnerabilities will be credited here (with consent) once the first advisory is published.*
