# Resource-identifier profiles

A `resource_path` constraint (SPEC §5.7.3) names its target with an opaque `resource_id` compared by exact byte equality. The verifier never dereferences, fetches, or normalizes it. That opacity is what keeps verification offline and deterministic — but it moves one problem to the edges: the issuer and the verifier must construct **the same bytes** for the same real-world resource, or every verification fails closed.

A **resource-identifier profile** is the shared recipe that solves this. It defines, for one class of resources, a single canonical byte representation and a deterministic construction algorithm. Profiles are:

- **Normative for parties that adopt them.** An issuer and a receiver who both follow a profile always agree on the bytes.
- **Invisible to everyone else.** A verifier that has never heard of a profile still verifies correctly, because it only ever compares bytes. Nothing in the core constraint semantics changes.
- **Versioned independently of the protocol.** A profile revision never changes wire format or verifier behavior.

Every profile must define: one canonical byte-identical representation per resource; a deterministic construction algorithm with no heuristic name normalization; type separation (the same underlying ID must never be interpretable as more than one resource kind); lifecycle rules (rename, archive, delete, recreate — identifiers must not silently transfer authority to a newly created resource); a no-secrets guarantee (identifiers appear in signed certificates, receipts, logs, and public test vectors); versioning from first release; and known-answer plus negative vectors.

## Profile registry

| Profile | Version | Resource kinds | Status |
|---|---|---|---|
| Git | v1 (this document) | Git repositories | Draft — under adversarial review for v1.0.0-alpha.16 |
| Platform-authored profiles | — | Defined by the authoring platform (e.g. workspaces, channels, conversations, compute nodes) | Linked here when published |

---

## Git resource-identifier profile v1

### 1. What a Git resource identifier is — and is not

- A Git resource identifier **identifies a repository.**
- It does **not** identify a branch, a commit, a tag, a checkout, or a worktree.
- A `path_prefix` combined with a Git resource identifier binds a **logical path within the repository**. It does **not** bind a revision: a cert authorizing `/docs` in repo X authorizes `/docs` at any revision of X the application operates on. Revision-bound authorization (a path *at* a commit or branch) is deferred to a future profile, and any published integration using this profile must state that limitation.
- **Repository renames and transfers create a new resource identity.** Existing delegations naming the old identity fail closed against the renamed repository and must be reissued. This is deliberate: a transfer changes who controls the resource, which is exactly when stale authority should die.

### 2. Canonical form

```
git:<host>/<owner>/<repo>
```

Example: `git:github.com/acme/widgets`

### 3. Accepted input grammars and construction algorithm

Constructors accept **exactly four input grammars** and reject everything else *before* canonical construction. Constructors MUST NOT delegate parsing to a general-purpose URL library — different languages' URL parsers disagree on edge cases, and this profile's determinism depends on every SDK matching the same explicit grammar.

```
https-form:  "https://" HOST "/" OWNER "/" REPO [ ".git" ] [ "/" ]
ssh-form:    "ssh://git@" HOST "/" OWNER "/" REPO [ ".git" ]
scp-form:    "git@" HOST ":" OWNER "/" REPO [ ".git" ]
bare-form:   HOST "/" OWNER "/" REPO
```

Component rules (v1):

- `HOST` — matches `github.com` case-insensitively, and nothing else. No port, no trailing dot, no IP literal. Any other host requires a profile extension that states that host's case rule, port normalization (default ports omitted, non-default retained), and trailing-dot rejection before identifiers for it may be constructed.
- `OWNER` — one or more characters from `A-Za-z0-9-`. Empty is rejected.
- `REPO` — one or more characters from `A-Za-z0-9._-`. Empty is rejected.
- **No** query string, fragment, extra path segments, or empty components anywhere.
- **No userinfo** other than the literal `git@` shown in the ssh and scp forms. `https://user@github.com/...` and any other credential form are rejected, not stripped.
- **No percent signs.** GitHub owner and repository names never require encoding, so a `%` anywhere in the input is rejected — never decoded.
- An scp-style input that does not match `scp-form` exactly (e.g. a second `:`, a missing `/`) is rejected as ambiguous, not repaired.

Construction, after an input matches exactly one grammar:

1. Strip a trailing `.git` from `REPO`, matched **case-insensitively**. This is unambiguous for the v1 host: GitHub forbids repository names ending in `.git` in any case, so a `.git` suffix is always the clone-URL decoration, never part of the name.
2. Lowercase `HOST`, `OWNER`, and `REPO` (GitHub is case-insensitive).
3. Join as `git:<host>/<owner>/<repo>`.

Constructors emit only the canonical form. Parsers and verifiers of profile conformance reject non-canonical strings rather than normalizing them (uppercase characters, retained `.git`, embedded scheme, port suffix, trailing dot in the host).

### 4. Why human-readable names, not provider node IDs

v1 chooses the normalized human-readable name over provider-internal node IDs (e.g. GitHub GraphQL node IDs) because normalized names are **offline-verifiable and inspectable**: a verifier or auditor can confirm what a cert authorizes by reading it, with no provider API call, preserving the protocol's offline verification property. The cost is the rename caveat in §1 — node IDs survive renames, names do not — and that caveat is documented rather than traded away. A future profile may define a node-ID-based identifier for deployments that prioritize rename continuity over inspectability.

### 5. Lifecycle rules

| Event | Effect on the identifier |
|---|---|
| Default-branch change, force-push, history rewrite | None. Identity is the repository, not a revision. |
| Repository rename | New identity. Delegations naming the old identity fail closed; reissue. |
| Ownership transfer | New identity (owner is part of the identifier). Fail closed; reissue. |
| Delete | Identifier retired. A later repository created under the same owner/name yields the same bytes — issuers should treat delete-and-recreate under a reused name as a control change and consider prior grants: short expiries and revocation are the mitigations, and this reuse property is a stated limitation of name-based identity (see §4). |
| Fork | The fork is a different repository under a different owner: a different identity. Authority never follows a fork. |

### 6. Security and privacy considerations

- **No secrets.** The identifier contains a hostname and a public repository path — no credential, token, or key material can appear by construction. Safe for signed certificates, receipts, logs, and public test vectors.
- **Private repository names** are metadata: an identifier in a public receipt reveals that a repository with that name exists. Deployments authorizing private repositories should treat receipts naming them with the same sensitivity as the repository's existence itself.
- **Name reuse** (delete-and-recreate, §5) is the known limitation of name-based identity, accepted for offline inspectability and bounded by expiry and revocation.

### 7. Known-answer and negative vectors

**Equivalent inputs — all MUST construct to `git:github.com/acme/widgets`:**

```
https://github.com/Acme/Widgets.git      (https-form)
https://github.com/Acme/Widgets/         (https-form, trailing slash)
ssh://git@github.com/Acme/Widgets        (ssh-form)
git@github.com:Acme/Widgets.git          (scp-form)
git@github.com:Acme/Widgets.GIT          (scp-form, case-insensitive .git strip)
GITHUB.COM/acme/widgets                  (bare-form)
```

**Inputs that MUST remain distinct:**

```
git:github.com/acme/widgets
git:github.com/acme/widgets-docs      (different repository)
git:github.com/acme-labs/widgets      (different owner)
```

**Invalid construction inputs — constructors MUST reject, not repair:**

```
https://github.com/acme/widgets?ref=main         (query string)
https://github.com/acme/widgets#readme           (fragment)
https://github.com/acme/widgets/tree/main        (extra path segments)
https://user@github.com/acme/widgets             (userinfo)
https://github.com:443/acme/widgets              (port)
https://github.com/acme%2Fwidgets                (percent sign anywhere)
https://github.com//widgets                      (empty owner)
git@github.com:acme:widgets                      (ambiguous scp form)
http://github.com/acme/widgets                   (scheme not in any grammar)
git@gitlab.com:acme/widgets                      (host not covered by v1)
```

**Invalid canonical strings — parsers MUST reject, not normalize:**

```
git:github.com/Acme/Widgets           (uppercase for a case-insensitive host)
git:github.com/acme/widgets.git       (retained .git)
git:https://github.com/acme/widgets   (embedded scheme)
git:github.com:443/acme/widgets       (port on the v1 host)
git:github.com./acme/widgets          (trailing-dot host)
git:github.com/acme                   (missing repository component)
```

---

## Platform-authored profiles

Platforms whose resources are authorization targets — workspaces, channels, conversations, compute nodes — author their own identifier profiles: the platform owns its resource semantics, so the platform defines the canonical forms, with review against the interoperability requirements above. Published platform profiles will be linked from the registry table.
