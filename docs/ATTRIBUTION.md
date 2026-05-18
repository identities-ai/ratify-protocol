# Attribution & Badge Program

Ratify Protocol is open source (Apache 2.0 for code, CC-BY-4.0 for the spec).
You can use it commercially, build products on it, and modify it freely.

This document describes what we ask — not require — when you do.

---

## Why attribution matters here

Ratify Protocol is trust infrastructure. The whole point is that a party
receiving a proof bundle can verify it cryptographically without trusting the
sender. Attribution to the protocol makes that trust chain legible to end users:
they can look up what "Verified by Ratify Protocol" means, inspect the spec,
audit the SDKs, and form an independent opinion on the security of what they're
relying on.

This is the same reason Signal Protocol users display "Messages are end-to-end
encrypted with the Signal Protocol" — not because they're legally required to,
but because their users' trust is grounded in a verifiable open standard, and
saying so increases rather than decreases confidence.

---

## What we ask

### 1. Credit in developer-facing materials

If your product documentation, README, or security page describes how your AI
agent authorization works, include a reference like:

> Agent authorization is built on [Ratify Protocol](https://identities.ai/protocol),
> an open cryptographic identity protocol for AI agents with a published
> specification and cross-SDK conformance test suite.

Or the short form:

> Powered by [Ratify Protocol](https://identities.ai/protocol)

### 2. "Verified by Ratify Protocol" badge in verification UIs

When your product surfaces a verification result to an end user — a meeting
participant confirmed, an API call authorized, a delegation cert checked — use
the "Verified by Ratify Protocol" badge.

The badge makes the trust claim inspectable: a user who wonders "what does
'verified' mean?" can follow it to the open spec rather than having to trust
your marketing copy.

**Badge assets:**

| Variant | Use |
|---|---|
| [`badge-verified-dark.svg`](../assets/badge-verified-dark.svg) | On dark or colored backgrounds |
| [`badge-verified-light.svg`](../assets/badge-verified-light.svg) | On white or light backgrounds |
| [`badge-powered-dark.svg`](../assets/badge-powered-dark.svg) | Infrastructure / "powered by" placement |
| [`badge-powered-light.svg`](../assets/badge-powered-light.svg) | Infrastructure / "powered by" placement |

Usage guidelines:
- Do not alter the badge colors, proportions, or text.
- Do not place it in a context that implies Identities AI endorses your product.
- Do not use it as a primary branding element — it belongs alongside your own brand.
- Link the badge to `https://identities.ai/protocol` so users can learn more.

### 3. Public marketing

If you publicly announce that your product is integrated with Ratify Protocol —
in press releases, on your website, or in partner announcements — we ask that
you identify it clearly as "Ratify Protocol" (not just "Ratify" alone, since
the Ratify™ product brand belongs to Identities AI, Inc.).

---

## What the Apache 2.0 license requires (mandatory)

These are requirements under the Apache 2.0 license, not requests:

- Retain the copyright notice in the `LICENSE` file.
- Retain the `NOTICE` file in any distribution.
- State clearly if you modified the source code.

---

## Trademark policy

**Ratify Protocol™** and **identities.ai™** are registered trademarks of
Identities AI, Inc.

You may:
- Say your product "uses Ratify Protocol", "is built on Ratify Protocol",
  "is Ratify Protocol-compatible", or "implements the Ratify Protocol spec."
- Use "Ratify Protocol" as a noun to accurately describe the protocol.

You may not:
- Use "Ratify Protocol" or any confusingly similar name as the name of your own
  protocol, product, or service.
- Use the trademark in a way that implies Identities AI, Inc. sponsors,
  endorses, or is affiliated with your product unless you have a written
  agreement with us.
- Register any trademark, domain name, or handle that includes "Ratify" in a
  way that could be confused with Identities AI, Inc.

---

## Patent

A U.S. patent application is pending on aspects of the Ratify Protocol. The
Apache 2.0 license includes a patent grant: by contributing to or distributing
the code under Apache 2.0, Identities AI, Inc. grants you a perpetual,
worldwide, royalty-free patent license for any patent claims necessarily
infringed by using, making, or distributing the software as distributed.

This grant does not extend to uses that are outside the scope of the
distributed software — for example, independent implementations that reimpleme
the patented methods without using the distributed SDK code should seek
independent legal advice.

---

## Questions

Questions about attribution, trademark, or commercial licensing:
[legal@identities.ai](mailto:legal@identities.ai)

To report a misuse of the "Verified by Ratify Protocol" badge or the trademark:
[security@identities.ai](mailto:security@identities.ai)
