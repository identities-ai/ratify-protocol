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
    ├── typescript/      ← @identities-ai/ratify-protocol
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
v1.0.0-alpha.7  →  current release  (Provider Interfaces, SPEC §17)
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
sdk-go-v1.0.0-alpha.6
sdk-typescript-v1.0.0-alpha.6
sdk-python-v1.0.0-alpha.6
sdk-rust-v1.0.0-alpha.6
v1.0.0-alpha.6          ← the protocol-level tag; implies all above at the same version
```

The protocol-level tag `v1.0.0-alpha.6` is what Go modules consume (`go get github.com/identities-ai/ratify-protocol@v1.0.0-alpha.6`). The SDK-specific tags are what the release workflow uses to decide which registries to push to.

## 4. The release workflow

### 4.1 One-command release

From a clean main branch:

```bash
make release VERSION=v1.0.0-alpha.6 PUSH=1
```

That single command runs the steps below in order. Any failure aborts. By default the release is local-only (`PUSH=0`, `PUBLISH=0`, `GITHUB_RELEASE=0`) so maintainers can verify the exact commit and tags before pushing. Use `PUSH=1` to push `main` and all coordinated tags.

**After the public launch, registry publishing is handled by CI**, not by `PUBLISH=1` on the local `make release` invocation. See [§5 — CI-driven publishing](#5-cidriven-publishing-tagtriggered) below. The local `make release` flow still owns version bumping, fixture regeneration, the cross-SDK gate, and tagging — but pushing the tag to GitHub is what causes the registries to receive the package, not a local `cargo publish` / `twine upload` / `npm publish`. This eliminates the "I forgot which `PUBLISH=1` step I ran from which laptop" failure mode entirely.

`PUBLISH=1` remains as an escape hatch for emergency manual publishes (e.g. CI is broken and a security fix needs to ship). It should be the exception, not the rule.

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
6. **Tag the protocol version.** `git tag v1.0.0-alpha.6`.
7. **Tag each SDK.** `git tag sdk-go-v1.0.0-alpha.6`, etc.
8. **Push main and tags if `PUSH=1`.** The script pushes `main`, then `vX.Y.Z...` plus every `sdk-*` tag explicitly.
9. **(Optional / emergency only) Publish to registries if `PUBLISH=1`, per SDK.** Prefer CI publishing instead — see §5. The manual commands are kept here for break-glass use.
   - **Go:** `git push` publishes the module; `go get` works against the tag directly. No registry action needed.
   - **npm:** `cd sdks/typescript && npm publish --access public` — publishes `@identities-ai/ratify-protocol@1.0.0-alpha.6`.
   - **PyPI:** `cd sdks/python && python -m build && twine upload dist/*` — publishes `ratify-protocol==1.0.0a5`.
   - **crates.io:** `cd sdks/rust && cargo publish` — publishes `ratify-protocol = "1.0.0-alpha.6"`.
10. **GitHub release if `GITHUB_RELEASE=1`.** (Also handled by CI now — see §5.) Auto-generate release notes from commits since last tag, attach the `testvectors/v1/` bundle as a release asset, post to GitHub Releases.
11. **Announce.** Optional: Slack/Discord bot post, HN submission draft, community channel update.

### 4.3 What happens on failure mid-publish

Publishing to four registries is not atomic. If step 9 fails partway through (npm publishes succeed but PyPI rejects, say), the workflow:

1. Stops immediately.
2. Documents which registries have the release and which don't.
3. Does NOT roll back already-published versions (npm and PyPI do not generally allow un-publishing of installed packages; crates.io explicitly forbids it).
4. Marks the release as "partial" in the GitHub release page.
5. Requires manual reconciliation — typically by publishing a patch version (`v1.0.0-alpha.6`) with the missing SDKs.

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
git commit -sm "chore: bump to v1.0.0-alpha.6"

# 5. Tag.
git tag v1.0.0-alpha.6
git tag sdk-go-v1.0.0-alpha.6
git tag sdk-typescript-v1.0.0-alpha.6
git tag sdk-python-v1.0.0-alpha.6
git tag sdk-rust-v1.0.0-alpha.6

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
make release VERSION=v1.0.0-alpha.6 PUSH=1
```

---

## 5. CI-driven publishing (tag-triggered)

After the public launch, the canonical publishing path is **push a tag → CI publishes**. The workflow lives at [`.github/workflows/release.yml`](../.github/workflows/release.yml). Nothing on your laptop ever calls `cargo publish` / `twine upload` / `npm publish` — those commands run inside an ephemeral GitHub Actions runner, with credentials that GitHub Actions exclusively controls.

This is a stronger trust model than the manual flow for three reasons:

1. **No long-lived registry credentials on developer laptops.** A stolen laptop can no longer publish a hostile version of the SDK.
2. **Every published artifact is provably built from a known commit.** PyPI's Trusted Publisher records the GitHub Actions run that built each wheel; npm provenance attaches a Sigstore signature linking the package to the build run; crates.io publishes are constrained to the workflow's environment.
3. **Tests gate every publish, every time.** Even if you skipped tests locally, the runner re-runs them on a fresh checkout and refuses to publish on red.

### 5.1 The release flow, end-to-end

```
[ make release VERSION=v1.0.0-alpha.6 PUSH=1 ]   ←  on your laptop
                       │
                       │  bumps SDK versions, runs full test matrix locally,
                       │  creates the protocol tag v1.0.0-alpha.6 and the
                       │  four sdk-* sub-tags, pushes main + tags.
                       ▼
[ GitHub receives tag v* push ]
                       │
                       ▼
[ .github/workflows/release.yml fires ]
                       │
                       ├─→ gate-tests              ← Go vet/test, TS conformance,
                       │   (fresh runner)            Python conformance, Rust
                       │                             conformance, testvector
                       │                             determinism, release-sync,
                       │                             tag ↔ SDK version coherence.
                       │   ↓ red? everything stops.
                       │
                       ├─→ publish-pypi            ← OIDC via Trusted Publisher.
                       │   environment: pypi-publish  No token. May require
                       │                             reviewer approval.
                       │
                       ├─→ publish-crates          ← CARGO_REGISTRY_TOKEN
                       │   environment: crates-publish
                       │
                       ├─→ publish-npm             ← Disabled until org is
                       │   if NPM_PUBLISH_ENABLED=true   approved (variable
                       │   environment: npm-publish      gated). NPM_TOKEN +
                       │                                 provenance.
                       │
                       ├─→ publish-go              ← pkg.go.dev auto-discovery
                       │                             pre-warm via proxy fetch.
                       │
                       └─→ github-release          ← runs after publishes.
                           Notes + testvectors bundle. Marked pre-release
                           if tag contains alpha/beta/rc.
```

### 5.2 Secrets and environments

These are configured once on the GitHub repo. See [`docs/REGISTRY_SETUP.md`](./REGISTRY_SETUP.md) for the step-by-step.

| Secret / variable           | Used by         | Notes                                                          |
|-----------------------------|-----------------|----------------------------------------------------------------|
| `CARGO_REGISTRY_TOKEN`      | publish-crates  | crates.io API token scoped to `publish-update` on `ratify-protocol`. |
| `NPM_TOKEN`                 | publish-npm     | npm granular token scoped to `@identities-ai` org. Not used until variable below is set. |
| `NPM_PUBLISH_ENABLED` (var) | publish-npm     | Repo variable. Set to `true` to activate the npm job after the npm org is approved. |
| _(no secret for PyPI)_      | publish-pypi    | Trusted Publisher via OIDC — no long-lived secret stored anywhere. |

Each publish job runs in its own GitHub Actions environment (`pypi-publish`, `crates-publish`, `npm-publish`). Adding a required reviewer to an environment turns that publish into a manual-approval step — useful for prod-grade releases.

### 5.3 What `gate-tests` checks before any publish runs

1. `go vet ./...` clean
2. `go test -race -count=1 ./...` passes
3. `go mod tidy` produces no diff
4. Test vectors regenerate byte-identical to committed
5. `scripts/check-release-sync.sh` confirms package versions, lockfiles, docs, and SDK constants are all aligned
6. TypeScript `tsc --noEmit` clean, conformance tests pass against all 59 fixtures
7. Python `pip install -e '.[dev]'` cold install succeeds, conformance tests pass against all 59 fixtures
8. Rust `cargo build --all-targets` clean, conformance tests pass against all 59 fixtures
9. Pushed tag matches every SDK's declared version (PEP 440 normalization included for Python)

If any check fails, all publish jobs are skipped. No partial state is created. You fix the failure, force-delete the tag (`git tag -d`, `git push --delete origin tagname`), re-run `make release`, push again.

### 5.4 Recovery from partial publish

Publishing to four registries is not atomic. If PyPI succeeds and crates.io fails (or vice versa):

1. **Do not delete the tag.** Same-version re-publishing is rejected by the successful registry but is idempotent.
2. **Inspect the failed job.** crates.io / npm / PyPI all have specific error messages — usually network, transient quota, or "version already exists" (which means another runner published before this one).
3. **Re-run the failed job from the GitHub Actions UI.** The successful jobs are skipped (PyPI rejects same-version upload cleanly with `skip-existing: true`; crates.io rejects with a clean error code; npm rejects with a clean error code).
4. **If a published artifact is genuinely bad** (security issue, broken build), yank rather than unpublish. See [`docs/REGISTRY_SETUP.md`](./REGISTRY_SETUP.md) §6.

### 5.5 Pre-release vs stable

The release workflow marks the GitHub Release as pre-release automatically if the tag contains `alpha`, `beta`, or `rc`. PyPI / crates.io / npm all understand semver pre-release suffixes natively — installers default to skipping them unless explicitly asked. This means alpha consumers self-select via `pip install ratify-protocol==1.0.0a5` (explicit) rather than catching alphas accidentally on `pip install ratify-protocol`.

This is the right behavior during the alpha series. When `v1.0.0` (stable) ships, the same workflow will produce a non-prerelease GitHub Release and the registries will surface it as the default install target.
