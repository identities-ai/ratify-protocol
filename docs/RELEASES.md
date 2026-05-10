# Release Process

**How the Ratify Protocol, its test vectors, and every SDK stay in lockstep — and how a single `make release` action creates coordinated protocol / SDK tags. Registry publishing is explicit (`PUBLISH=1`) so package publication never happens accidentally.**

Companion to [`SPEC.md`](../SPEC.md), [`SDKS.md`](SDKS.md), and [`TEST_PLAN.md`](TEST_PLAN.md).

---

## 1. Why this matters

Ratify is a cryptographic protocol with multiple language implementations. If the Go reference ships a v1.0.1 bugfix but the Python SDK is still at v1.0.0, a user who installs both ends up with implementations that produce different bytes — and their signatures stop verifying across languages. That is how protocols die.

The release process exists to guarantee one property: **at any tagged version, every SDK and the reference pass the exact same fixture set byte-for-byte.** No exceptions, no negotiated drift, no "we'll update Python later."

## 2. The monorepo invariant

All reference implementations live in this single repository:

```
ratify-protocol/
├── SPEC.md              ← the spec
├── testvectors/v1/      ← 59 canonical fixtures
├── *.go (at root)       ← Go reference
├── cmd/ratify-testvectors/  ← the generator; anyone can reproduce fixtures from seeds
└── sdks/
    ├── typescript/      ← @identitiesai/ratify-protocol
    ├── python/          ← ratify-protocol
    └── rust/            ← ratify-protocol
    (future: swift, java, c, etc.)
```

**Why monorepo, not per-SDK repos:** a spec change (or even a clarification that affects canonical bytes) must land in every SDK atomically. Monorepo makes that a single PR that touches every language. Multi-repo makes it N PRs coordinated across N release cycles — that is how drift happens.

Contributors who prefer to iterate on a language in their own repository may do so (the `sdks/` tree is just one home among many possibilities, not an exclusive one), but the *canonical* release comes from this repo.

## 3. Version numbering

### 3.1 Protocol version vs SDK version

- **Protocol version** is the `version` field on every signed object (`1` currently). It changes only for wire-breaking changes (new algorithm, new required field, semantic shift in verifier algorithm). Protocol version bumps are rare and coordinated across all implementations.
- **SDK version** is per-SDK semver (`1.2.3`). Same major version = same protocol version. Minor/patch bumps can happen independently per SDK for bug fixes and quality improvements that don't change fixture behavior.

### 3.2 The alpha → stable ladder

```
1.0.0-alpha.1  →  initial open-source drop (hybrid Ed25519 + ML-DSA-65 shipped)
1.0.0-alpha.5  →  current release
…
1.0.0-beta.1   →  after first external security audit of Go reference
1.0.0-rc.1     →  when Python + Rust + TS all pass + external audit of at least 2 SDKs
1.0.0          →  stable; at least 3 SDKs in mainstream registries; first design-
                  partner production deployment live
1.0.1          →  patch: any bugfix that doesn't change fixture bytes
1.1.0          →  minor: backward-compatible additions (new optional fields,
                  new scope vocabulary entries, new canonical helpers) — MUST
                  still pass every v1.0 fixture
2.0.0          →  major: wire-incompatible changes. Triggers protocol version=2.
                  testvectors/v2/ coexists alongside v1 fixtures. v2 SDKs MAY
                  accept v1 bundles during a documented migration window.
```

### 3.3 Pre-1.0 semantics

During the alpha/beta/rc phase, **fixture bytes MAY change between versions**. Any change is documented in the release notes with a before/after hash. Consumers pinning to alpha versions should expect to update when a new alpha ships. Starting with `1.0.0`, fixture bytes are frozen for the v1 lifetime.

### 3.4 SDK version tags

Every SDK release is tagged in git as `sdk-<language>-<version>`:

```
sdk-go-v1.0.0-alpha.5
sdk-typescript-v1.0.0-alpha.5
sdk-python-v1.0.0-alpha.5
sdk-rust-v1.0.0-alpha.5
v1.0.0-alpha.5          ← the protocol-level tag; implies all above at the same version
```

The protocol-level tag `v1.0.0-alpha.5` is what Go modules consume (`go get github.com/identities-ai/ratify-protocol@v1.0.0-alpha.5`). The SDK-specific tags are what the release workflow uses to decide which registries to push to.

## 4. The release workflow

### 4.1 One-command release

From a clean main branch:

```bash
make release VERSION=v1.0.0-alpha.5 PUSH=1
```

That single command runs the steps below in order. Any failure aborts. By default the release is local-only (`PUSH=0`, `PUBLISH=0`, `GITHUB_RELEASE=0`) so maintainers can verify the exact commit and tags before pushing. Use `PUSH=1` to push `main` and all coordinated tags. Use `PUBLISH=1` only when publishing to npm / PyPI / crates.io is intended.

While the repository is private, use `PUSH=1 PUBLISH=0 GITHUB_RELEASE=0` for coordinated private tags only. After the public open-source launch, use `PUBLISH=1 GITHUB_RELEASE=1` only for versions that should be visible in public registries and GitHub Releases.

### 4.2 What the workflow does, step-by-step

1. **Preflight — working tree clean.** Refuse to proceed if uncommitted changes exist.
2. **Preflight — version sanity.** Reject versions that don't match `vX.Y.Z(-\w+\.\d+)?`. Reject if the tag already exists locally or remotely.
3. **Bump SDK versions in-place.** Update `go.mod` (implicit — Go tags directly), `sdks/typescript/package.json`, `sdks/python/pyproject.toml`, `sdks/rust/Cargo.toml` to the target version. Commit as "chore: bump to VERSION."
4. **Regenerate test vectors deterministically.** `go run ./cmd/ratify-testvectors`. If the result differs from committed, the release is aborted and the user is told to investigate.
5. **Run the full conformance suite across all SDKs.**
   - Go: `go vet ./...` and `go test -race -count=1 ./...`
   - Determinism: regenerate fixtures to `/tmp` and `diff -rq` against `testvectors/v1/`
   - TypeScript: `cd sdks/typescript && npm ci && npx tsc --noEmit && npm run test:conformance`
   - Python: `cd sdks/python && python -m pip install -e '.[dev]' && python -m pytest -q`
   - Rust: `cd sdks/rust && cargo build --all-targets && cargo test`
   - Release sync: package versions, lockfiles, docs, and SDK constants must agree
   - Any failure aborts the release.
6. **Tag the protocol version.** `git tag v1.0.0-alpha.5`.
7. **Tag each SDK.** `git tag sdk-go-v1.0.0-alpha.5`, etc.
8. **Push main and tags if `PUSH=1`.** The script pushes `main`, then `vX.Y.Z...` plus every `sdk-*` tag explicitly.
9. **Publish to registries if `PUBLISH=1`, per SDK.**
   - **Go:** `git push` publishes the module; `go get` works against the tag directly. No registry action needed.
   - **npm:** `cd sdks/typescript && npm publish --access public` — publishes `@identitiesai/ratify-protocol@1.0.0-alpha.5`.
   - **PyPI:** `cd sdks/python && python -m build && twine upload dist/*` — publishes `ratify-protocol==1.0.0a3`.
   - **crates.io:** `cd sdks/rust && cargo publish` — publishes `ratify-protocol = "1.0.0-alpha.5"`.
10. **GitHub release if `GITHUB_RELEASE=1`.** Auto-generate release notes from commits since last tag, attach the `testvectors/v1/` bundle as a release asset, post to GitHub Releases.
11. **Announce.** Optional: Slack/Discord bot post, HN submission draft, community channel update.

### 4.3 What happens on failure mid-publish

Publishing to four registries is not atomic. If step 9 fails partway through (npm publishes succeed but PyPI rejects, say), the workflow:

1. Stops immediately.
2. Documents which registries have the release and which don't.
3. Does NOT roll back already-published versions (npm and PyPI do not generally allow un-publishing of installed packages; crates.io explicitly forbids it).
4. Marks the release as "partial" in the GitHub release page.
5. Requires manual reconciliation — typically by publishing a patch version (`v1.0.0-alpha.5`) with the missing SDKs.

This is why steps 1-8 (preflight + test + tag) must all succeed before step 9 runs.

### 4.4 Required secrets for automation

Wiring this up in GitHub Actions requires these repository secrets:

- `NPM_TOKEN` — npm automation token with `publish` scope on `@identitiesai`.
- `PYPI_API_TOKEN` — PyPI token scoped to `ratify-protocol`.
- `CARGO_REGISTRY_TOKEN` — crates.io API token.
- `GITHUB_TOKEN` — automatic; used for the release.

All tokens MUST be scoped to specific packages / orgs. No "full account" tokens.

## 5. The Makefile

```make
.PHONY: test-all release release-check

VERSION ?=
PUSH ?= 0
PUBLISH ?= 0
GITHUB_RELEASE ?= 0
GOCACHE ?= /tmp/ratify-protocol-go-cache

test-all:
	@GOCACHE="$(GOCACHE)" ./scripts/test-all.sh

release-check:
	@./scripts/check-release-sync.sh

release:
	@test -n "$(VERSION)" || (echo "usage: make release VERSION=vX.Y.Z[-tag.N] [PUSH=1] [PUBLISH=1] [GITHUB_RELEASE=1]"; exit 1)
	@GOCACHE="$(GOCACHE)" PUSH="$(PUSH)" PUBLISH="$(PUBLISH)" GITHUB_RELEASE="$(GITHUB_RELEASE)" ./scripts/release.sh "$(VERSION)"
```

The release logic lives in:

- `scripts/check-release-sync.sh` — fails if package versions, lockfiles, docs, or SDK constants drift.
- `scripts/test-all.sh` — runs the same conformance and determinism gates as CI, with stricter local Go race tests.
- `scripts/release.sh` — bumps versions, runs all gates, commits, tags protocol + SDKs, and optionally pushes / publishes / creates the GitHub release.

## 6. Continuous integration

Every push and every pull request runs a matrix across all four SDKs. `.github/workflows/ci.yml` already defines the Go + determinism + TS jobs; Python and Rust are added now.

Every PR must pass the full conformance grid before merge. The NxN interop matrix (see [`SDKS.md`](SDKS.md) §5) is enforced — a bundle produced by any implementation must verify in every implementation.

## 7. Fixture versioning

- `testvectors/v1/*.json` is frozen at `v1.0.0` stable. Bytes MUST NOT change after that release.
- A future `testvectors/v2/*.json` MAY coexist during a major-version migration window. v2 SDKs will target v2 fixtures; during migration, SDKs MAY support both.
- The Go reference's `cmd/ratify-testvectors` generator is the single source of truth for fixtures; all SDKs consume them.

## 8. How to propose protocol changes

Protocol changes fall into three categories:

### 8.1 Clarifications (no wire change)

Documentation-only improvements that make the spec clearer without changing implementation behavior. Typical example: specifying the lex-sorted output order of `ExpandScopes` more explicitly.

**Process:** PR to `SPEC.md`. No version bump required. Can ship in any patch release.

### 8.2 Additions (backward-compatible)

New fields, new scope vocabulary entries, new canonical helpers. Must not change the byte output of any existing fixture.

**Process:** Issue first for discussion, then PR touching SPEC + generator + all SDKs + new fixtures. Minor version bump (`v1.1.0`).

### 8.3 Wire-breaking changes

Anything that changes the byte output of a canonical operation for a previously-valid input. New required algorithm, removed field, semantic change in verifier.

**Process:** Issue + design doc + reference-implementation prototype, then a dedicated RFC-style discussion period (30+ days), then full implementation across SDKs. Major version bump (`v2.0.0`). Involves a coordinated migration window during which v1 bundles remain verifiable.

## 9. Embargoed security releases

Critical security fixes (e.g., a verifier algorithm bug that accepts forgeries) follow an embargoed process that overlaps the normal release workflow:

1. Report received via `security@identities.ai` per [`SECURITY.md`](../SECURITY.md).
2. Private fix developed in a private fork with limited maintainer access.
3. Coordinated 14-day embargo; major downstream integrators notified privately with the fix.
4. Release day: the fix is merged to public main, a patch version is tagged, all SDKs publish, and the advisory is posted to the public security advisories channel.
5. Post-embargo, a public retro is posted at `ratify.dev/security` (or equivalent) documenting the issue, impact, and fix.

## 10. The stable point

A release cycle is considered stable when:

- All four SDKs (Go, TS, Python, Rust) pass all 59 fixtures (20 original v1 + 2 sub-delegation + 12 constraint + 2 session-binding + 2 key-rotation + 6 stream-sequence + 5 session-token + 5 transaction-receipt + 1 revocation-push + 1 witness-entry + 1 challenge-forwarding fixtures).
- Determinism check passes (regen = zero diff).
- The generator itself hasn't changed since the last release, OR its change is reviewed and new fixtures have been committed.
- CI is green on main.
- No open security advisories affect this version.

Only then does `make release VERSION=…` run without aborting on any of the preflight gates.

---

## Appendix A — today's release checklist (manual, until automation ships)

```bash
# From a clean main with no uncommitted changes:

# 1. Update versions in:
#    - sdks/typescript/package.json
#    - sdks/python/pyproject.toml
#    - sdks/rust/Cargo.toml

# 2. Regenerate and verify.
cd <repo root>
go run ./cmd/ratify-testvectors -out /tmp/regen
diff -rq testvectors/v1/ /tmp/regen/          # must be empty

# 3. Run conformance everywhere.
go test ./...
cd sdks/typescript && npm ci && npm run test:conformance && cd ../..
cd sdks/python && source .venv/bin/activate && pytest -q && deactivate && cd ../..
cd sdks/rust && cargo test --quiet && cd ../..

# 4. Commit version bumps.
git commit -sm "chore: bump to v1.0.0-alpha.5"

# 5. Tag.
git tag v1.0.0-alpha.5
git tag sdk-go-v1.0.0-alpha.5
git tag sdk-typescript-v1.0.0-alpha.5
git tag sdk-python-v1.0.0-alpha.5
git tag sdk-rust-v1.0.0-alpha.5

# 6. Push.
git push && git push --tags

# 7. Publish (after GitHub tags are pushed).
cd sdks/typescript && npm publish --access public && cd ../..
cd sdks/python && python -m build && twine upload dist/* && cd ../..
cd sdks/rust && cargo publish && cd ../..

# 8. Create GitHub release with auto-generated notes + testvectors bundle.
```

The manual checklist above is retained as explanatory context. The authoritative command is:

```bash
make release VERSION=v1.0.0-alpha.5 PUSH=1
```
