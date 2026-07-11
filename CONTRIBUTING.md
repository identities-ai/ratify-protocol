# Contributing to Ratify Protocol

Thanks for considering a contribution. Ratify is a protocol project, which means the quality bar is higher than for most application codebases — a change that passes tests can still be wrong if it breaks interop with other implementations. Read this before opening a pull request.

## Before you start

- **Bug reports and small fixes:** open an issue first if the fix isn't obvious, then a PR.
- **Protocol changes:** open a design discussion issue first. Any change that affects the wire format, signable bytes, verifier algorithm, or scope vocabulary is a protocol change.
- **New language SDKs:** open an issue to coordinate. We want to keep SDK quality and naming consistent across languages.
- **Breaking changes to v1:** extremely unlikely at this stage. Breaking changes require a version bump (v2) per `SPEC.md` §10.

## How changes land in `main`

`main` is protected. **No direct pushes are accepted, including from maintainers — and including releases.** Every change goes through a pull request, and the CI checks must pass before merge. Release version bumps travel the same path: `make release-prepare` opens a release PR, and only after it merges does `make release-tag` push tags (see [`docs/RELEASES.md`](docs/RELEASES.md) §4). The branch ruleset enforces this with no standing bypass.

The flow:

```
1. git checkout -b feat/short-descriptive-name
2. ... do the work, commit with -s (DCO) ...
3. git push -u origin feat/short-descriptive-name
4. gh pr create     (or open the PR in the GitHub UI)
5. Wait for CI to go green. Required checks:
     • Go tests
     • Test vectors regenerate byte-identical
     • Release metadata stays in sync
     • TypeScript / Python / Rust SDK conformance (59 fixtures each)
     • DCO sign-off
6. Address review feedback. Every inline comment thread must be resolved.
7. If `main` moved while the PR was open: click "Update branch" — strict
   merging is enabled, so the PR must be up to date with main.
8. Squash-and-merge is the default. The feature branch is auto-deleted.
```

Force-pushes to `main` are blocked. Branch deletion of `main` is blocked. Linear history is required (no merge commits). If a PR conflicts with the linear-history rule, rebase locally and force-push to your own feature branch — that's fine; only `main` is protected.

Branch naming:

- `feat/...` — new feature or SDK improvement
- `fix/...` — bug fix
- `docs/...` — documentation only
- `chore/...` — tooling, CI, build, dependencies
- `spec/...` — normative protocol change (requires a linked design issue)

## Developer Certificate of Origin (DCO)

By contributing, you certify the [DCO](https://developercertificate.org/) v1.1 — the short form is: *you have the right to submit what you're submitting, under the project's license.* Sign off every commit with `git commit -s`, which appends `Signed-off-by: Your Name <your@email>` to the message.

We use DCO rather than a CLA. Commits without the sign-off will be refused by CI.

## Commit and PR messages are public

This repository is open source: commit messages, PR titles and bodies, and
review threads are permanently public, and they are read by people evaluating
the protocol. Write them for an outside reader:

- Describe the change and its reasoning in project terms — what changed in the
  spec, SDKs, or docs, and why it is correct.
- Do not reference internal tools, private repositories, internal review
  processes, or company planning. "fix: scope-intersection edge case found in
  adversarial review" is public-friendly; naming the internal tool or process
  that found it is not.
- No AI-tool attribution footers or "generated with" banners.
- Squash-and-merge means the merge-time message is what lands on `main` —
  proofread it at merge time, not only the branch commits.

## Running the tests

### Go

```bash
go test ./...                           # unit tests + conformance loader
go run ./cmd/ratify-testvectors         # regenerate fixtures deterministically
```

The regenerated fixtures MUST be byte-identical to the committed ones. If `go run` produces a diff, either your change is non-deterministic (map iteration, time.Now, RNG without a seed) or you have intentionally changed a signable format, which is a breaking protocol change and belongs in v2.

### TypeScript

```bash
cd sdks/typescript
npm install
npm test
```

All 59 fixtures must pass in every SDK. If a change breaks the TS conformance but passes Go, or vice versa, the implementations have drifted — fix the divergence before the PR is merged.

## Canonical serialization

The canonicalizer in `crypto.go` (Go) and `sdks/typescript/src/canonical.ts` (TS) is the single most sensitive file in the project. Changes here can invalidate every existing signature, everywhere, forever. Rules:

- Do not change the canonical rules in §6 of `SPEC.md` without a version bump.
- Do not accept PRs that replace the hand-written canonicalizer with a third-party library unless the library is demonstrably byte-identical on every test vector and has stronger maintenance guarantees than what we have.
- Test vectors are the authority. If a change passes tests, ship it. If it doesn't, do not ship it.

## Style

- **Go:** standard `go fmt`, idiomatic Go. No framework-style abstraction layers. Prefer plain structs and functions.
- **TypeScript:** strict mode (already enforced by `tsconfig.json`). No runtime dependencies beyond `@noble/ed25519` and `@noble/hashes`.
- **Documentation:** if a change affects protocol behavior, update `SPEC.md` and `docs/EXPLAINED.md` in the same PR.
- **Commit messages:** conventional commit prefixes preferred (`fix:`, `feat:`, `spec:`, `docs:`). The first line under 72 characters. Body wrapped to 72. A new commit, never `--amend --force-push` to shared branches.

## Pull request checklist

Before requesting review:

- [ ] Tests pass locally: `go test ./...` and `npm test`
- [ ] `go mod tidy` leaves no diff
- [ ] Fixtures unchanged if no protocol change; regenerated if yes
- [ ] `SPEC.md` / `docs/EXPLAINED.md` updated for protocol-affecting changes
- [ ] DCO sign-off on every commit
- [ ] PR description explains the change and, for non-trivial changes, the threat-model or interop implications

## Security

**Do not open public PRs for security issues.** See [`SECURITY.md`](SECURITY.md).

## Governance

Ratify Protocol is maintained by its contributors under the stewardship of Identities AI. The project follows a standard open-source governance model: changes to the normative specification require an RFC and review period (see §6 above), while SDK contributions follow the standard PR review process. As the community grows, governance will evolve to reflect active contributors.

## Code of Conduct

This project adheres to the [Contributor Covenant](CODE_OF_CONDUCT.md). Report unacceptable behavior to `conduct@identities.ai`.
