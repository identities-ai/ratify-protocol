# Release Process

**How the Ratify Protocol, its test vectors, and every SDK stay in lockstep — and how the two-phase `make release-prepare` → PR merge → `make release-tag` flow creates coordinated protocol / SDK tags without ever pushing to main directly. Registry publishing is CI-driven off the tag; manual publishing (`PUBLISH=1`) is break-glass only.**

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
├── testvectors/v1/      ← 63 canonical fixtures
├── *.go (at root)       ← Go reference
├── cmd/ratify-testvectors/  ← the generator; anyone can reproduce fixtures from seeds
└── sdks/
    ├── typescript/      ← @identities-ai/ratify-protocol
    ├── python/          ← ratify-protocol
    ├── rust/            ← ratify-protocol
    └── c/               ← libratify_c (static + shared, cbindgen header)
    (future: swift, java)
```

**Why monorepo, not per-SDK repos:** a spec change (or even a clarification that affects canonical bytes) must land in every SDK atomically. Monorepo makes that a single PR that touches every language. Multi-repo makes it N PRs coordinated across N release cycles — that is how drift happens.

Contributors who prefer to iterate on a language in their own repository may do so (the `sdks/` tree is just one home among many possibilities, not an exclusive one), but the *canonical* release comes from this repo.

## 3. Version numbering

### 3.1 Protocol version vs SDK version

- **Protocol version** is the `version` field on every signed object (`1` currently). It changes only for wire-breaking changes (new algorithm, new required field, semantic shift in verifier algorithm). Protocol version bumps are rare and coordinated across all implementations.
- **SDK version** is per-SDK semver (`1.2.3`). Same major version = same protocol version. Minor/patch bumps can happen independently per SDK for bug fixes and quality improvements that don't change fixture behavior.

### 3.2 The alpha → stable ladder

```
1.0.0-alpha.1   →  initial open-source drop (hybrid Ed25519 + ML-DSA-65 shipped)
v1.0.0-alpha.7  →  Provider Interfaces, SPEC §17
v1.0.0-alpha.8  →  C/C++ SDK, Rust no_std, fips204 migration
v1.0.0-alpha.10 →  C SDK 59/59 conformance, 13 new C ABI functions,
                   pre-built release binaries
v1.0.0-alpha.11 →  docs & spec truth pass (trust anchors, revocation
                   freshness, clock discipline); C/C++ added to local gate.
                   59 fixtures, byte-identical to alpha.10
v1.0.0-alpha.12 →  next: no-expiry sentinel, presence:represent (54th scope),
                   invalid_scope verifier check, 63-fixture suite
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
sdk-go-v1.0.0-alpha.11
sdk-typescript-v1.0.0-alpha.11
sdk-python-v1.0.0-alpha.11
sdk-rust-v1.0.0-alpha.11
sdk-c-v1.0.0-alpha.11
v1.0.0-alpha.11          ← the protocol-level tag; implies all above at the same version
```

The protocol-level tag `v1.0.0-alpha.11` is what Go modules consume (`go get github.com/identities-ai/ratify-protocol@v1.0.0-alpha.11`). The SDK-specific tags are what the release workflow uses to decide which registries to push to.

## 4. The release workflow

### 4.1 Two-phase release — through a PR, like every other change

**Releases do not push to main.** `main` accepts changes only via pull request — including release version bumps. The old single-step `make release` required a direct (ruleset-bypassing) push to main and was removed. The flow is now:

```bash
# Phase 1 — from clean, up-to-date main:
make release-prepare VERSION=v1.0.0-alpha.12
#   → creates release/v1.0.0-alpha.12, bumps all SDK versions, runs the
#     full cross-SDK gate, commits (signed-off), pushes, opens the PR.

# Phase 2 — merge the release PR (CI + DCO run on it like any PR), then:
git checkout main && git pull
make release-tag VERSION=v1.0.0-alpha.12
#   → verifies main carries the bump, creates the protocol + sdk-* tags,
#     pushes them. The protocol tag triggers the CI publish workflow.
```

Any failure in either phase aborts. `release-tag` refuses to run if main's versions don't match the target (i.e. the release PR hasn't merged).

**Registry publishing is handled by CI**, not by `PUBLISH=1` on a local invocation. See [§5 — CI-driven publishing](#5-cidriven-publishing-tagtriggered) below. The local two-phase flow owns version bumping, fixture regeneration, the cross-SDK gate, and tagging — but pushing the tag to GitHub is what causes the registries to receive the package, not a local `cargo publish` / `twine upload` / `npm publish`. This eliminates the "I forgot which `PUBLISH=1` step I ran from which laptop" failure mode entirely.

`PUBLISH=1` remains as an escape hatch for emergency manual publishes (e.g. CI is broken and a security fix needs to ship). It should be the exception, not the rule.

### 4.2 What the workflow does, step-by-step

**Phase 1 — `make release-prepare`:**

1. **Preflight.** Working tree clean; on main and in sync with `origin/main`; version matches `vX.Y.Z(-\w+\.\d+)?`; no target tag exists locally or remotely.
2. **Create `release/<version>`.**
3. **Bump SDK versions in-place.** `sdks/typescript/package.json` (+lockfile), `sdks/python/pyproject.toml` (+`__init__.py`), `sdks/rust/Cargo.toml` (+lockfile), and version strings in docs. (`go.mod` needs nothing — Go consumes the git tag directly.)
4. **Regenerate test vectors deterministically.** `go run ./cmd/ratify-testvectors`. If the result differs from committed, the release is aborted and the user is told to investigate.
5. **Run the full conformance suite across all SDKs.**
   - Go: `go vet ./...` and `go test -race -count=1 ./...`
   - Determinism: regenerate fixtures to `/tmp` and `diff -rq` against `testvectors/v1/`
   - TypeScript: `cd sdks/typescript && npm ci && npx tsc --noEmit && npm test`
   - Python: `cd sdks/python && python -m pip install -e '.[dev]' && python -m pytest -q`
   - Rust: `cd sdks/rust && cargo build --all-targets && cargo test`
   - C/C++: `cd sdks/c && cargo test --test conformance -- --nocapture && cargo test --test api`
   - Release sync: package versions, lockfiles, docs, and SDK constants must agree
   - Any failure aborts the release.
6. **Commit (signed-off), push the branch, open the PR.** CI and the DCO check run on the release PR exactly as on any other PR.

**Phase 2 — `make release-tag` (after the PR merges):**

7. **Preflight.** On clean, up-to-date main; main's versions match the target (refuses otherwise); release-sync check passes; tags still absent.
8. **Tag the protocol version and each SDK.** `git tag v1.0.0-alpha.12`, then `sdk-go-v1.0.0-alpha.12`, etc.
8a. **Push the protocol tag alone, then the `sdk-*` tags.** GitHub creates no push event when more than three tags arrive at once (see §5.3.1) — the protocol tag must travel by itself to trigger the Release workflow.
9. **(Optional / emergency only) Publish to registries if `PUBLISH=1`, per SDK.** Prefer CI publishing instead — see §5. The manual commands are kept here for break-glass use.
   - **Go:** `git push` publishes the module; `go get` works against the tag directly. No registry action needed.
   - **npm:** `cd sdks/typescript && npm publish --access public` — publishes `@identities-ai/ratify-protocol@<version>`.
   - **PyPI:** `cd sdks/python && python -m build && twine upload dist/*` — publishes `ratify-protocol==<PEP 440 version>`.
   - **crates.io:** `cd sdks/rust && cargo publish` — publishes `ratify-protocol = "<version>"`.
10. **GitHub release if `GITHUB_RELEASE=1`.** (Also handled by CI now — see §5.) Auto-generate release notes from commits since last tag, attach the `testvectors/v1/` bundle as a release asset, post to GitHub Releases.
11. **Update downstream claims.** The docs site (`ratify-docs`) and marketing site (`identities-marketing`) each carry protocol facts — version, fixture count, scope count, SDK list — centralized in one constants file per repo (`src/constants/protocol.ts` / `lib/protocol-facts.ts`, plus each repo's bump checklist for literals in code snippets). Bump them via a normal PR in each repo as part of release day. `check-release-sync.sh` cannot reach those repos; this step is the manual bridge.
12. **Announce.** Optional: Slack/Discord bot post, HN submission draft, community channel update.

### 4.3 What happens on failure mid-publish

Publishing to four registries is not atomic. If step 9 fails partway through (npm publishes succeed but PyPI rejects, say), the workflow:

1. Stops immediately.
2. Documents which registries have the release and which don't.
3. Does NOT roll back already-published versions (npm and PyPI do not generally allow un-publishing of installed packages; crates.io explicitly forbids it).
4. Marks the release as "partial" in the GitHub release page.
5. Requires manual reconciliation — typically by publishing a patch version (`v1.0.0-alpha.11`) with the missing SDKs.

This is why steps 1-8 (preflight + test + tag) must all succeed before step 9 runs.

### 4.4 Required secrets and variables for automation

Wiring this up in GitHub Actions requires these repository secrets and variables:

- `CARGO_REGISTRY_TOKEN` — crates.io API token.
- `NPM_PUBLISH_ENABLED` — repository variable that enables the npm Trusted Publisher job.
- `GITHUB_TOKEN` — automatic; used for the release.

PyPI and npm publishing use GitHub Actions OIDC Trusted Publisher flows, so no long-lived PyPI or npm token is required.

## 5. The Makefile

```make
.PHONY: test-all release release-prepare release-tag release-check

test-all:
	@GOCACHE="$(GOCACHE)" ./scripts/test-all.sh

release-check:
	@./scripts/check-release-sync.sh

release-prepare:
	@GOCACHE="$(GOCACHE)" ./scripts/release.sh prepare "$(VERSION)"

release-tag:
	@GOCACHE="$(GOCACHE)" PUBLISH="$(PUBLISH)" GITHUB_RELEASE="$(GITHUB_RELEASE)" ./scripts/release.sh tag "$(VERSION)"

release:   # removed — prints the two-phase instructions and exits 1
```

The release logic lives in:

- `scripts/check-release-sync.sh` — fails if package versions, lockfiles, docs, or SDK constants drift.
- `scripts/test-all.sh` — runs the same conformance and determinism gates as CI, with stricter local Go race tests.
- `scripts/release.sh` — `prepare` bumps versions, runs all gates, commits to a release branch and opens the PR; `tag` verifies the merged bump, then creates and pushes the protocol + SDK tags (and carries the break-glass `PUBLISH=1` / `GITHUB_RELEASE=1` paths).

## 6. Continuous integration

Every push and every pull request runs a matrix across all five SDKs (Go, TypeScript, Python, Rust, C/C++). `.github/workflows/ci.yml` already defines the Go + determinism + TS jobs; Python and Rust are added now.

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

- All five SDKs (Go, TS, Python, Rust, C/C++) pass all 63 fixtures (by kind: 46 verify + 2 scope + 5 session-token + 5 transaction-receipt + 2 key-rotation + 1 revocation-list + 1 revocation-push + 1 witness-entry).
- Determinism check passes (regen = zero diff).
- The generator itself hasn't changed since the last release, OR its change is reviewed and new fixtures have been committed.
- CI is green on main.
- No open security advisories affect this version.

Only then do `make release-prepare VERSION=…` and `make release-tag VERSION=…` run without aborting on any of the preflight gates.

---

## Appendix A — the release checklist

```bash
# Phase 1 — from clean, up-to-date main:
make release-prepare VERSION=v1.0.0-alpha.12
#   branch release/v1.0.0-alpha.12 + version bumps + full gate + PR

# Phase 2 — after the release PR merges:
git checkout main && git pull
make release-tag VERSION=v1.0.0-alpha.12
#   coordinated tags pushed; protocol tag triggers CI publishing

# Phase 3 — verify the workflow fired:
gh run list --workflow=release.yml --limit 1
#   if no run appeared (see §5.3.1):
gh workflow run release.yml -f tag=v1.0.0-alpha.12

# Phase 4 — verify EVERY registry actually serves the new version.
# A green publish job is NOT proof: at alpha.13 a real 403 was masked as
# success and only this step caught it. PyPI's index can lag ~1 minute.
npm view @identities-ai/ratify-protocol version
curl -s https://crates.io/api/v1/crates/ratify-protocol -A release-check | python3 -c 'import sys,json; print(json.load(sys.stdin)["crate"]["newest_version"])'
curl -s https://crates.io/api/v1/crates/ratify-c -A release-check | python3 -c 'import sys,json; print(json.load(sys.stdin)["crate"]["newest_version"])'
curl -s https://pypi.org/pypi/ratify-protocol/json | python3 -c 'import sys,json; print(json.load(sys.stdin)["info"]["version"])'
gh release view <tag> --json assets --jq '[.assets[].name]'   # 6 C/C++ archives + testvectors
```

**Never `git push --tags`** — it pushes every local tag in one push, which suppresses the workflow trigger (§5.3.1) and may push stray local tags. The script pushes the protocol tag alone, then the `sdk-*` tags.

---

## 5. CI-driven publishing (tag-triggered)

After the public launch, the canonical publishing path is **push a tag → CI publishes**. The workflow lives at [`.github/workflows/release.yml`](../.github/workflows/release.yml). Nothing on your laptop ever calls `cargo publish` / `twine upload` / `npm publish` — those commands run inside an ephemeral GitHub Actions runner, with credentials that GitHub Actions exclusively controls.

This is a stronger trust model than the manual flow for three reasons:

1. **No long-lived registry credentials on developer laptops.** A stolen laptop can no longer publish a hostile version of the SDK.
2. **Every published artifact is provably built from a known commit.** PyPI's Trusted Publisher records the GitHub Actions run that built each wheel; npm provenance attaches a Sigstore signature linking the package to the build run; crates.io publishes are constrained to the workflow's environment.
3. **Tests gate every publish, every time.** Even if you skipped tests locally, the runner re-runs them on a fresh checkout and refuses to publish on red.

### 5.1 The release flow, end-to-end

```
[ make release-prepare VERSION=v1.0.0-alpha.12 ]  ←  on your laptop
                       │
                       │  release branch + version bumps + full local test
                       │  matrix + PR. Merged through the normal PR path
                       │  (CI + DCO). No direct push to main, ever.
                       ▼
[ make release-tag VERSION=v1.0.0-alpha.12 ]      ←  on your laptop, post-merge
                       │
                       │  verifies main carries the bump, creates the
                       │  protocol tag + five sdk-* sub-tags, pushes the
                       │  protocol tag alone, then the sdk-* tags.
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
                       │   environment: npm-publish      gated). OIDC +
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
| `CARGO_REGISTRY_TOKEN`      | publish-crates  | crates.io API token scoped to `publish-update` on **both** `ratify-protocol` and `ratify-c`. Single-crate scoping 403s the other publish (bit at alpha.13). |
| `NPM_PUBLISH_ENABLED` (var) | publish-npm     | Repo variable. Set to `true` to activate the npm job after the npm org is approved. |
| _(no secret for PyPI)_      | publish-pypi    | Trusted Publisher via OIDC — no long-lived secret stored anywhere. |

Each publish job runs in its own GitHub Actions environment (`pypi-publish`, `crates-publish`, `npm-publish`). Adding a required reviewer to an environment turns that publish into a manual-approval step — useful for prod-grade releases.

### 5.3 What `gate-tests` checks before any publish runs

1. `go vet ./...` clean
2. `go test -race -count=1 ./...` passes
3. `go mod tidy` produces no diff
4. Test vectors regenerate byte-identical to committed
5. `scripts/check-release-sync.sh` confirms package versions, lockfiles, docs, and SDK constants are all aligned
6. TypeScript `tsc --noEmit` clean, conformance tests pass against all 63 fixtures
7. Python `pip install -e '.[dev]'` cold install succeeds, conformance tests pass against all 63 fixtures
8. Rust `cargo build --all-targets` clean, conformance tests pass against all 63 fixtures
9. C/C++ conformance and API tests pass through the C ABI
10. Pushed tag matches every SDK's declared version (PEP 440 normalization included for Python)

If any check fails, all publish jobs are skipped. No partial state is created. You fix the failure (via a normal PR to main), force-delete the tag (`git tag -d`, `git push --delete origin tagname`), then re-run `make release-tag`.

### 5.3.1 If the Release workflow never started

GitHub does not create push events when **more than three tags arrive in a single push**. The release script used to push the protocol tag and all five `sdk-*` tags together (six tags, one push), which silently suppressed the `v*` trigger — the tag landed on GitHub but no Release run appeared. This is why the v1.0.0-alpha.11 release had to be published via manual dispatch.

`scripts/release.sh` now pushes the protocol tag on its own (fires the trigger), then the `sdk-*` tags together (they trigger nothing). If a Release run still doesn't appear within a minute of the tag push:

```bash
gh run list --workflow=release.yml --limit 1        # confirm nothing started
gh workflow run release.yml -f tag=v1.0.0-alpha.11  # documented fallback — same gates, same publishes
```

The dispatch path is byte-equivalent to the tag path: `RELEASE_TAG` is normalized at the top of the workflow, and gate-tests re-run everything on a fresh runner either way.

### 5.4 Recovery from partial publish

Publishing to four registries is not atomic. If PyPI succeeds and crates.io fails (or vice versa):

1. **Do not delete the tag.** Same-version re-publishing is rejected by the successful registry but is idempotent.
2. **Inspect the failed job.** crates.io / npm / PyPI all have specific error messages — usually network, transient quota, or "version already exists" (which means another runner published before this one).
3. **Re-run the failed job from the GitHub Actions UI.** The successful jobs are skipped (PyPI rejects same-version upload cleanly with `skip-existing: true`; crates.io rejects with a clean error code; npm rejects with a clean error code).
4. **If a published artifact is genuinely bad** (security issue, broken build), yank rather than unpublish. See [`docs/REGISTRY_SETUP.md`](./REGISTRY_SETUP.md) §6.

### 5.5 Pre-release vs stable

The release workflow marks the GitHub Release as pre-release automatically if the tag contains `alpha`, `beta`, or `rc`. PyPI / crates.io / npm all understand semver pre-release suffixes natively — installers default to skipping them unless explicitly asked. This means alpha consumers self-select via `pip install ratify-protocol==1.0.0a10` (explicit) rather than catching alphas accidentally on `pip install ratify-protocol`.

This is the right behavior during the alpha series. When `v1.0.0` (stable) ships, the same workflow will produce a non-prerelease GitHub Release and the registries will surface it as the default install target.
