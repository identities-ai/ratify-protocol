# Registry Setup — Identities AI ownership of Ratify SDKs

How to move the Ratify Protocol SDK packages from personal publisher accounts
to **Identities AI, Inc.** ownership across PyPI, crates.io, and npm, with
the correct company-level metadata (URL, GitHub link, description, social
links).

This is the one-time configuration. Once it's done, the tag-driven workflow
at [`.github/workflows/release.yml`](../.github/workflows/release.yml) handles
all future publishing without manual steps.

---

## 0. Why this matters

The packages on PyPI and crates.io were initially published from a personal
account to reserve the `ratify-protocol` name. That account now appears as
the maintainer on every package page — which is wrong for an open-source
protocol owned by **Identities AI, Inc.**

End state we want:

| Registry          | Package                                    | Owner shown        | Links to       |
|-------------------|--------------------------------------------|--------------------|----------------|
| PyPI              | `ratify-protocol`                          | `identities-ai` org | identities.ai + GitHub |
| crates.io         | `ratify-protocol`                          | `gh:identities-ai:maintainers` team | identities.ai + GitHub |
| npm               | `@identities-ai/ratify-protocol`           | `identities-ai` org | identities.ai + GitHub |
| Go (pkg.go.dev)   | `github.com/identities-ai/ratify-protocol` | GitHub org         | (inherited)    |

Go is the easy case: pkg.go.dev derives everything from the GitHub repo, so
the GitHub org is the only thing to get right. The other three require
explicit org/team setup in the registry UI.

---

## 1. PyPI — Organizations + Trusted Publisher

PyPI Organizations is in beta but works for our case. We create an
organization, transfer the project into it, then attach Trusted Publisher
configuration so the GitHub Actions workflow can publish without a long-lived
API token.

### 1.1 Create the organization

1. Log in to PyPI as the account that currently owns `ratify-protocol`.
2. Go to **Your account → Organizations → Create new organization**.
3. Fill in:
   - **Name:** `identities-ai` (this becomes the URL slug — must match
     across registries; the lowercase hyphenated form mirrors the GitHub org)
   - **Display name:** `Identities AI`
   - **Description:** `Identities AI builds the cryptographic identity and authorization layer for AI agents. We make Ratify Protocol — the open standard — and Ratify Verify, the managed control plane for enterprises. https://identities.ai · Patent pending.`
   - **Type:** Company (you may need to upgrade or pay a fee for org features
     depending on PyPI's current pricing — at the time of writing,
     Organizations is free during the beta for the company tier).
4. Confirm the org's email address.

### 1.2 Transfer the project

1. Go to **`ratify-protocol` → Manage → Settings → Transfer ownership**.
2. Set the new owner to the `identities-ai` organization.
3. Confirm.

After transfer the project page at <https://pypi.org/project/ratify-protocol/>
should list `identities-ai` as the maintainer, with a clickable link to the
org page that shows your description, URL, and email.

### 1.3 Set Trusted Publisher (no API token needed)

This is the security upgrade — instead of a long-lived API token sitting in
GitHub Secrets, PyPI verifies a short-lived OIDC token from the GitHub
Actions workflow itself. Anyone who steals our repo secrets cannot publish a
malicious version because they can't forge that token.

1. On PyPI, go to the project page **→ Manage → Publishing**.
2. Click **Add a new pending publisher**.
3. Fill in:
   - **Owner:** `identities-ai` (the GitHub org)
   - **Repository name:** `ratify-protocol`
   - **Workflow filename:** `release.yml`
   - **Environment name:** `pypi-publish` (this matches the
     `environment.name` in the publish-pypi job)
4. Save.

### 1.4 Create the GitHub Actions environment

1. On the GitHub repo, go to **Settings → Environments → New environment**.
2. Name it `pypi-publish`.
3. Optional but recommended: add yourself as a **Required reviewer** so a
   publish requires manual approval before PyPI receives the request. This
   is a strong safety net during alpha.

### 1.5 Verify

After the next tag push, the `publish-pypi` job should run, pause on
required-reviewer approval (if you set one), then publish. The package page
will show the new release within seconds; pip cache invalidation may take a
few minutes.

If you want to confirm without doing a real release, tag a `v0.0.0-test` →
the release workflow will run gate-tests, refuse to publish (version mismatch
against SDK metadata), and exit cleanly without touching PyPI. That's the
"safe smoke test" for the gate logic.

---

## 2. crates.io — GitHub team co-ownership

crates.io doesn't have organizations the way PyPI/npm do. The pattern is to
add a **GitHub team** as a co-owner of the crate; then anyone in that team
can publish, and the crate page links to the team via the GitHub URL.

### 2.1 Prepare the GitHub team

1. On GitHub: go to <https://github.com/orgs/identities-ai/teams>.
2. Create a team named `maintainers`.
3. Add yourself.

### 2.2 Add the team as a crate owner

Run this **locally** (you need to be logged in to crates.io as the current
owner). It uses your existing `cargo login` token — no GitHub Actions
involved at this step.

```bash
cd sdks/rust
cargo owner --add github:identities-ai:maintainers ratify-protocol
```

You can verify with:

```bash
cargo owner --list ratify-protocol
# expected output includes:
#   github:identities-ai:maintainers (Identities AI maintainers)
#   (your personal account)
```

### 2.3 Update crate metadata (already done)

The `Cargo.toml` already has the correct `repository`, `description`, and
`license` fields. Confirm with `cargo publish --dry-run` from
`sdks/rust/`.

### 2.4 Remove personal owner (optional but recommended)

Once the team is added and we've confirmed publishing works through CI:

```bash
cargo owner --remove <your-personal-handle> ratify-protocol
```

This removes the personal-account attribution from the crate page entirely.

### 2.5 Create the API token for CI

1. On <https://crates.io/me>, click **API Tokens → New Token**.
2. Name: `gh-actions-release-ratify`.
3. Scopes: select **publish-update** only, and scope to **both crates this
   repo publishes: `ratify-protocol` AND `ratify-c`** (not "all crates").
   This minimizes blast radius if the token leaks. A token scoped to only
   one crate fails the other's publish with a 403 — this happened at
   v1.0.0-alpha.13 and was initially masked by the publish step's old
   error handling.
4. Set an expiry (a year is fine) and copy the token.
5. On the GitHub repo: **Settings → Secrets and variables → Actions →
   New repository secret**. Name `CARGO_REGISTRY_TOKEN`, paste the value.

### 2.6 (Optional) Add a `crates-publish` GitHub environment

Same idea as PyPI — create a `crates-publish` environment with required
reviewers if you want manual approval on every release. This matches the
`environment.name` already set in the `publish-crates` job.

---

## 3. npm — `@identities-ai` scoped org

**Status: ACTIVE.** The `@identities-ai` org is approved on npm and the package is live
at <https://www.npmjs.com/package/@identities-ai/ratify-protocol>.

The `publish-npm` job in `release.yml` runs on every tagged release (when
`NPM_PUBLISH_ENABLED=true` is set in repo variables, which it is).

### 3.1 npm org ownership

1. Log in to <https://www.npmjs.com/>.
2. Verify you have **Owner** role on the `identities-ai` org at
   <https://www.npmjs.com/settings/identities-ai/packages>.
3. Org **Settings → Profile**:
   - **Description:** `Identities AI builds the cryptographic identity and authorization layer for AI agents. We make Ratify Protocol — the open standard — and Ratify Verify, the managed control plane for enterprises.`
   - **URL:** `https://identities.ai`
   - **Email:** `hello@identities.ai`

### 3.2 Configure Trusted Publisher (no token needed)

Publishing uses npm's OIDC Trusted Publisher — no long-lived token stored in GitHub Secrets.

The Trusted Publisher is already configured on the npm package page with:
- **Repository:** `identities-ai/ratify-protocol`
- **Workflow:** `release.yml`
- **Environment:** `npm-publish`

If it ever needs to be reconfigured: go to
<https://www.npmjs.com/package/@identities-ai/ratify-protocol> → **Settings** →
**Trusted Publishers** → add the values above.

The `release.yml` job has `id-token: write` and `environment: npm-publish` already set.
No `NPM_TOKEN` secret is required or used.

### 3.3 Enable the workflow's npm job

1. **Settings → Secrets and variables → Actions → Variables → New repository
   variable**.
2. Name `NPM_PUBLISH_ENABLED`, value `true` (already set).

The next tag push will exercise the full four-registry pipeline.

### 3.4 Provenance attestations

The workflow uses `npm publish --provenance` which creates a Sigstore
attestation linking the published package back to the exact GitHub Actions
run that built it. The badge appears on the npm package page as "Published
by GitHub Actions". No extra config needed — the OIDC exchange and provenance
signing both use the `id-token: write` permission already set in the job.

---

## 4. GitHub org settings (one-time hygiene)

These should already match — verify and fix if not:

1. <https://github.com/identities-ai> **profile**:
   - **Display name:** `Identities AI`
   - **URL:** `https://identities.ai`
   - **Description:** `Cryptographic identity and authorization for AI agents. Ratify Protocol™ + Ratify Verify. Patent pending.`
   - **Email:** `hello@identities.ai`
   - **Twitter username:** `IdentitiesAI`
2. **Settings → Security**:
   - Require 2FA for all members
   - Branch protection on `main` (already configured for releases): require
     PR review, require status checks (the `gate-tests` job in `release.yml`
     and the CI workflow's gates).

---

## 5. Smoke test the pipeline

Once one or more registries are set up, run a normal release through the
two-phase flow ([`RELEASES.md`](RELEASES.md) §4). There is no direct push to
main — the branch ruleset forbids it, releases included; the single-step
`make release` this section used to describe was removed for that reason.

1. `make release-prepare VERSION=<next version>` — creates the release
   branch, bumps all SDK versions and README pins, runs the full cross-SDK
   gate, and opens the release PR.
2. Merge the release PR through the normal path (CI + DCO run on it), then
   `git checkout main && git pull`.
3. `make release-tag VERSION=<next version>` — verifies main carries the
   bump, pushes the protocol tag alone (then the `sdk-*` tags), which
   triggers the Release workflow.
4. Watch <https://github.com/identities-ai/ratify-protocol/actions> for the
   Release workflow.
5. After it completes, verify each registry ACTUALLY serves the new version
   (a green publish job is not proof — see `RELEASES.md` Appendix A Phase 4):
   - PyPI: <https://pypi.org/project/ratify-protocol/>
   - crates.io: <https://crates.io/crates/ratify-protocol> and
     <https://crates.io/crates/ratify-c> — the token must be scoped to
     BOTH crates
   - npm: <https://www.npmjs.com/package/@identities-ai/ratify-protocol> (if enabled)
   - Go: <https://pkg.go.dev/github.com/identities-ai/ratify-protocol>
   - GitHub Release: <https://github.com/identities-ai/ratify-protocol/releases>

---

## 6. Recovery — what to do if a publish fails partway

The four registries are not atomic. PyPI may succeed and crates.io may fail
(or vice versa). The release workflow tolerates this by design:

- Each publish job is independent. A crates.io failure does not stop the
  PyPI job from completing.
- Re-running the workflow on the same tag re-attempts only the failed
  registry. PyPI and crates.io both reject same-version re-uploads cleanly,
  so re-running is idempotent for the successful jobs.
- If a critical bug is discovered post-publish: yank, do not unpublish.
  - PyPI: `twine` cannot delete; use the project page UI → "Delete release".
    Then publish a `vX.Y.Z+1` with the fix.
  - crates.io: `cargo yank --version X.Y.Z ratify-protocol`. The version
    remains available to existing consumers but new resolutions skip it.
  - npm: `npm deprecate @identities-ai/ratify-protocol@X.Y.Z "use X.Y.Z+1"`.
    Then publish the fix.

Yanking is the right tool 99% of the time. Outright unpublish breaks anyone
who has the broken version pinned and is the equivalent of `force-push` for
package registries. Do not use it without a security-grade reason.
