<!--
Thanks for the PR. Please read CONTRIBUTING.md and complete this checklist
before requesting review. Anything checked off here without it actually being
done is worse than an empty checklist — it means triage has to verify by hand.
-->

## Summary

<!-- One or two sentences. What does this change and why? -->

## Type of change

<!-- Check one. -->

- [ ] Bug fix (no fixture-byte change, no SPEC change)
- [ ] Documentation only
- [ ] SDK improvement (no fixture-byte change)
- [ ] Protocol change (changes signable bytes, scope vocab, or SPEC.md normative behavior) — **must have a design-discussion issue linked**
- [ ] New language SDK — **must have a coordination issue linked**
- [ ] Tooling / CI / build

## Related issues

<!-- "Closes #123" — protocol changes and new SDKs require a linked design issue. -->

## Checklist

- [ ] DCO sign-off on every commit (`git commit -s`). CI rejects PRs without it.
- [ ] If protocol behavior changed: `SPEC.md` updated, every SDK updated in this PR, every fixture in `testvectors/v1/` regenerated and committed.
- [ ] If an SDK was touched: `make test-all` passes locally (Go + TypeScript + Python + Rust + determinism + release-sync).
- [ ] If the threat model changed: `docs/EXPLAINED.md` updated.
- [ ] If the public docs reference a new field, method, or scope: `docs.identities.ai` (separate repo) follow-up is filed.
- [ ] Commit messages use conventional prefixes (`fix:`, `feat:`, `spec:`, `docs:`, `chore:`); first line under 72 chars.

## Cross-SDK impact

<!-- For SDK or protocol PRs, briefly note any divergence-risk surface that should be eyeballed. -->

## How to verify

<!-- Reviewers will run `make test-all`. If there's something else they should try, say so here. -->
