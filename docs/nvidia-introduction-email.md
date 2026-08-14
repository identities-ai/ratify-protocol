# Cover communication for NVIDIA and the Open Secure AI Alliance

Three variants. Attach the brief (`nvidia-open-secure-ai-contribution-brief.md`); the engineering appendix is for engineers who ask for depth.

Rules for all three. Lead with the brand, Ratify Protocol, not the company. Ratify Protocol is published by Identities.AI, Inc., and is an NVIDIA Inception member. Never a partner, approved integration, or Alliance member. Ask for the right people, not for endorsement.

---

## A. Direct email to Sydney Sykes, 122 words

**Subject:** Open Secure AI Alliance, delegated authority reference

Hi Sydney,

I'm Chuks Onwuneme, founder of Ratify Protocol, an NVIDIA Inception member. I took your advice at VC Unleashed literally: identify a concrete contribution and the responsible team before requesting an introduction.

We built an open NOOA reference showing an agent carrying a principal-signed, bounded delegation to an independent service, which verifies the agent's authority before acting. Over-scoped, expired, revoked, replayed, and amplified delegations are denied. The adversarial cases are executable tests, not slides, and the whole path runs end to end through a pinned OpenShell gateway.

Could you connect me with the owner for Secure Agent Workspace or the ODIS delegation contract, plus the appropriate NOOA/OpenShell technical lead, for one 45-minute architecture-mapping session? The specific question is whether ODIS-style authority should also be independently verifiable by a receiver across an organizational boundary.

I've attached a short brief. The working reference and engineering appendix are ready.

Best,
Chuks Onwuneme
Ratify Protocol

---

## B. Forwardable introduction, 123 words

**Subject:** Intro request, delegated authority reference for the Open Secure AI Alliance

Ratify Protocol is an NVIDIA Inception member proposing an open reference contribution to the Open Secure AI Alliance, and we're looking for the right technical owner.

NVIDIA's stack covers orchestration, guardrails, tracing, and runtime isolation, and SPIFFE covers workload identity. A complementary authorization question arises when an agent crosses an organizational boundary: proving *who authorized it for this action, under what constraints*, in a form the receiving system can verify itself.

We built a working NOOA reference. An independent service verifies the delegation before acting, and denies over-scoped, expired, revoked, replayed, and amplified delegations. Each authenticated decision produces a verifier-signed receipt. Deterministic, no LLM required, and the composition through OpenShell runtime policy is executed rather than described.

We'd like one 45-minute architecture-mapping session with the Secure Agent Workspace or ODIS owner and a NOOA/OpenShell engineer. The desired outcome is a technical disposition, including if the work is redundant with planned ODIS capabilities.

---

## C. Inception channel, 121 words

**Subject:** Inception member, routing request for an Open Secure AI Alliance contribution

Hi [Inception contact],

Ratify Protocol is an Inception member, and we'd like help reaching the right team.

We've prepared an open reference contribution for the Open Secure AI Alliance on delegated authority: how an agent can carry a principal-signed, bounded grant to an independent action boundary, where the receiver verifies who authorized it and whether the action is in scope before executing. It complements workload identity and runtime isolation.

The reference works today against the released NOOA package and a pinned OpenShell gateway, with adversarial denial cases as executable tests. It is proposed for evaluation against NVIDIA's ODIS direction and does not claim ODIS conformance. We're not asking for endorsement, just the right contacts and one review session.

Could you route us to the Secure Agent Workspace or ODIS delegation owner, and the appropriate NOOA/OpenShell technical lead?

Thanks,
Chuks Onwuneme
Ratify Protocol

---

## Notes before sending

- Confirm Sydney Sykes is the right first contact, and that the VC Unleashed reference in variant A is accurate.
- Alliance interest form (<https://www.nvidia.com/en-us/open-secure-ai-alliance-contact-us/>) is the fallback if no warm route exists. Variant B suits it.
- Attach the brief and link the repository. Do not attach the appendix unless asked.
- Do not describe the brief by page count until the final artifact has been rendered and checked.
- Lead with Ratify Protocol as the brand. Identities.AI, Inc. appears only as the publisher, in the disclosure line.
- Avoid "missing layer" or "the identity layer for AI agents," and anything implying NVIDIA has a deficiency. The framing is complementary.
- Do not claim every request produces a signed receipt. Only authenticated authorization decisions do.
- No em dashes in outbound copy.
- The OpenShell claims are executed results, recorded in the profile artifact. Do not soften them into intentions, and do not extend them past the one architecture that was executed.
- The unified NOOA-through-OpenShell path passed 64/64 in one full v0.0.102 compatibility run against the published `ratify-protocol==1.0.0a16` package. The earlier v0.0.96 campaign passed twice sequentially and twice concurrently. Keep those version-separated rather than implying four v0.0.102 runs.
- Six observations from the OpenShell v0.0.96 campaign are written up in appendix section 15.3. They are reported as historical observations of that pinned version, never as defects or automatically attributed to v0.0.102. If an engineer engages, that section is useful supporting context.
- Do not describe the work as an OpenShell integration or an NVIDIA-approved composition. It composes with OpenShell as an external operator would, using released commands and no forks.
