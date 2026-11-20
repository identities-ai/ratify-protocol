# IAM status bridge

`ratify-iam-bridge` is a customer-hosted reference bridge. It reads a
complete, authenticated snapshot of revoked grants for one issuer from the
customer's IAM system and publishes a customer-signed Protocol v2 status
list through Verify's receiver status-list API. The status key stays on the
customer host; Verify receives only signed lists.

The exact grant identifier is the `DelegationCertV2.cert_id`. IAM user IDs,
names and application labels are never substituted for that certificate ID.

## Source contract

The customer provides an HTTPS `GET` endpoint protected by a bearer token.
It returns a fresh, complete view of revoked certificate IDs for the
configured issuer:

```json
{
  "issuer_id": "<64-character lowercase hex issuer ID>",
  "revision": "iam-change-582",
  "complete": true,
  "observed_at": "2026-11-13T00:00:00Z",
  "revoked_cert_ids": ["exact-delegation-cert-id"]
}
```

- `observed_at` is the time the source finished an authoritative read, not
  the time a cache last refreshed.
- A snapshot older than 30 seconds, a partial snapshot, a different issuer
  or an unavailable source prevents publication.
- The snapshot includes every certificate ID ever revoked for the issuer.
  The bridge also keeps prior revocations locally, so an omitted ID cannot
  regrant it. Regrant needs a new certificate ID.
- The Protocol limit is 10,000 revoked IDs per list. Exceeding it stops
  publication and must be resolved before the current list expires.

Events from the IAM system are wake-up hints, never authority. Send
`SIGHUP` to the bridge after an event and it re-reads the snapshot. The
bridge also polls every minute, so duplicate, out-of-order and missed events
converge on the source's current complete state.

## Configure and run

With `RATIFY_TAG` set to the exact release tag:

```sh
go install "github.com/identities-ai/ratify-protocol/v2/cmd/ratify-iam-bridge@$RATIFY_TAG"
IAM_BRIDGE_CONFIG=bridge.json ratify-iam-bridge
```

`IAM_BRIDGE_CONFIG` names a JSON file with `issuer_id`, `epoch`,
`status_public_key`, `status_private_file`, `state_file`, `source_url` and
`verify_url`, and optionally `source_ca_file`.

- Both URLs use HTTPS. `verify_url` is the complete
  `/v1/verify/v2/status-lists` URL of your Verify API; the bridge derives the
  receiver status read and publisher release URLs from it.
- `source_ca_file` names PEM roots for a source behind a private CA. They
  are trusted for the source connection only, never for Verify.
- `status_private_file` is an owner-only key file: the one
  `ratify-keys generate` writes (the same file used to enroll the status
  key), or JSON with base64 `ed25519` and `ml_dsa_65` private key bytes. It
  must match `status_public_key` and the issuer status key the receiver
  configuration pins.
- Secrets come from the environment, supplied by your secret manager:
  `IAM_BRIDGE_SOURCE_TOKEN` (the source bearer token) and
  `IAM_BRIDGE_RECEIVER_API_KEY` (the receiver API key).

The receiver configuration must pin this issuer, status key and epoch
before the first publication.

Keep `state_file` on persistent storage. The bridge saves each signed list
before sending it and takes an exclusive file lock. After the first save,
a missing state file stops startup instead of silently resetting the
sequence and revocations; restore it from a verified backup. Do not delete
or edit the state file to resolve a publication conflict.

## One writer per issuer

Verify admits one publisher per issuer at a time. Each bridge process
creates a random secret publisher ID at startup and sends it with every
list. Verify and the bridge log show only a short fingerprint of it, so
reading status cannot impersonate or release the holder. A publication
signed under the pinned status key and epoch holds the issuer for 90
seconds, renewed by each publication. While it is held:

- another publisher gets 409 `status_publisher_conflict`. Its list is not
  kept. The bridge retries every 10 seconds and reconciles with Verify's
  checkpoint (below) before publishing again;
- a writer on an older status-key epoch gets 409
  `status_publisher_superseded` and stops. A newer epoch takes the issuer
  once the old writer has released it or its hold has expired.

A publisher that takes over the issuer must publish above every sequence
Verify has accepted or observed in the epoch; otherwise Verify refuses the
list with `status_publication_conflict`. Before signing each new list, the
bridge reads Verify's status for the issuer and stops if Verify is ahead of
its own accepted sequence.

On SIGTERM or SIGINT the bridge releases the issuer
(`POST /v1/verify/v2/status-publisher/release`), so a planned restart or a
successor takes over at once. After a crash a successor waits up to 90
seconds; decisions fail closed if status goes stale meanwhile.

## Initial sync and uncertain delivery

On first start with empty state, the bridge reads the issuer's status with
`GET /v1/verify/v2/status` and publishes above the accepted floor and the
highest observed sequence, so it never forks earlier history. The IAM
snapshot must include every certificate ID already revoked for the issuer,
because Verify's status does not list revoked IDs.

Every send, including a retry, first reads a fresh complete snapshot, so
nothing is published during an IAM outage. After an uncertain response the
bridge retries the same bytes for 90 seconds while the snapshot still has
the same revoked set. After that, or when Verify asks for a fresh list
(`status_publication_refresh_required`), it reads Verify's status and never
signs blindly:

- if Verify's accepted floor equals the pending sequence and the accepted
  digest is one the bridge signed, the pending list was accepted and is
  committed;
- if Verify's floor is at or above the pending sequence otherwise, the
  pending list is stale and the bridge continues above Verify's history;
- if Verify's floor equals the bridge's last accepted sequence and nothing
  higher was observed, the bridge re-reads the snapshot: an unchanged set
  re-signs the same sequence, a changed set takes the next one;
- anything else means another writer or a stale restored state, and the
  bridge blocks for an operator.

A status response with missing or inconsistent fields is an error and
publishes nothing. In every case the bridge signs the cumulative revoked set
and never re-signs an accepted sequence.

If the snapshot omits an ID that another publisher revoked, Verify refuses
the list with 409 `status_revocation_omitted` and the bridge blocks. If the
list also revokes something new, the new denial still takes effect at once,
and decisions for the issuer fail closed until a complete list is accepted.
To recover, find the missing certificate ID, add it to the IAM system's
revoked set, then stop the bridge and run `unblock` as below.

These refusals block publication: a definite 400, 401, 403 or 404,
`status_publication_conflict` above Verify's accepted floor,
`status_revocation_omitted`, `status_key_not_bound` and
`status_publisher_superseded`. A 503 is retried with the same pending list.
`status_key_not_bound` means the receiver pins a status key and epoch that
is not yet bound for the issuer: bind it, then run `unblock`.
`status_publication_clock_ahead` is retried; synchronize the bridge host's
clock. The bridge dates each list 30 seconds behind its clock to tolerate
ordinary drift.

To clear a block, read the accepted floor (`sequence`) and
`max_observed_sequence` from `GET /v1/verify/v2/status`. If the floor matches
the local state file's sequence and no other publisher advanced the issuer,
stop the bridge and run:

```sh
ratify-iam-bridge unblock ACCEPTED_SEQUENCE MAX_OBSERVED_SEQUENCE
```

This clears the block, advances above any observed fork and forces a fresh
reconciliation on restart. If the floor differs, find the other publisher
and reconcile before resuming; do not reset the state file.

## Operation and freshness

The bridge publishes on startup, every minute and on SIGHUP. Each list is
valid for five minutes. If the IAM source, the signer, the network or Verify
fails, no fresh list arrives and verification fails closed when status goes
stale.

The signed receiver configuration must allow a list lifetime of at least
five minutes and a status age of at least 150 seconds. This covers the
one-minute interval, up to 30 seconds per attempt, the 30-second backdate,
clock margin and an exact retry of a 90-second-old pending list.

## Status-key rotation

1. Enroll the new customer-held status key and bind it with the next epoch.
   Decisions for grants that are not already revoked fail closed until the
   new epoch publishes; earlier denials are kept.
2. Install a successor receiver configuration that pins the new key and
   epoch for every receiver of the issuer.
3. The old bridge's next publication is refused and it blocks. Stop it; it
   releases the issuer.
4. Start a bridge with the new epoch, key and a separate state file. It
   publishes sequence 1 of the new epoch with the complete revoked set,
   which must include every certificate ID revoked under the old epoch.

Parent issuers need their own bridge and status list; the verifier checks
revoked parents in the certificate chain.

## Reference sources

Three read-only reference sources serve the contract above over HTTPS with
the bridge's bearer token (`GET /v1/revoked-cert-ids`). They share these
rules:

- A customer-owned mapping file maps each exact `cert_id` to an immutable
  user ID. Logins and email addresses are refused, because they can later
  name someone else. A mapping that moves a `cert_id` to another user fails
  closed, and a certificate removed from the mapping while unrevoked keeps
  being checked.
- The provider is read on every request; nothing is cached, and
  `observed_at` is taken after the last read.
- Any token, network, throttling (429), permission (401, 403), server,
  redirect or malformed answer yields HTTP 503 and no snapshot, so status
  goes stale and decisions fail closed.
- Revocations and tracked mappings are kept in an owner-only state file,
  created once with `<source> init [REVOKED_IDS.json]` (the optional JSON
  array seeds revocations an earlier source made). One process holds its
  lock. A `STATE.checkpoint` generation refuses an older backup, so back up
  both files together. A `STATE.scanning` marker records an interrupted
  read; the source then stops until an operator checks the provider's audit
  log from the recorded start, adds any revoked IDs, and runs
  `<source> recover INVENTORY.json` with the complete `cert_id` to user ID
  inventory. Reactivating a user or removing a mapping entry never
  regrants.
- Only permanent facts revoke, because a Protocol revocation is permanent.
  The rules below are the reference's customer policy; copy and change a
  source to apply another.

Secrets come only from the environment, and `IAM_SOURCE_BEARER_TOKEN` is
always required. Each read costs about one request per mapped user (plus
group or app requests), so keep the mapping within the provider's rate
limits and the bridge's 30-second attempt.

### Okta

`ratify-okta-status-source`, configured with `OKTA_STATUS_SOURCE_CONFIG`
(JSON: `issuer_id`, `okta_org_url`, `app_ids`, `mapping_file`, `state_file`,
`listen_addr`, `tls_cert_file`, `tls_key_file`), `OKTA_API_TOKEN` and
`IAM_SOURCE_BEARER_TOKEN`. On every request it reads, with
`Authorization: SSWS <token>`:

- `GET /api/v1/apps/{appId}` for each configured app, which must exist and
  be `ACTIVE` (scope `okta.apps.read`);
- `GET /api/v1/users/{id}` for each mapped user (scope `okta.users.read`),
  whose returned `id` must equal the mapped ID;
- `GET /api/v1/apps/{appId}/users/{userId}` for each app, where 200 means
  assigned directly or through a group and 404 `E0000007` means not
  assigned.

A certificate is revoked when its user is `DEPROVISIONED`, `SUSPENDED`,
deleted (404 `E0000007`) or not assigned to a configured app. `ACTIVE`,
`LOCKED_OUT`, `PASSWORD_EXPIRED`, `RECOVERY`, `STAGED` and `PROVISIONED` are
not revocations. Any other answer yields no snapshot. Okta API tokens carry
the privileges of the admin who creates them, so create the token as a
dedicated Read-Only Administrator.

### Microsoft Entra ID and Google Workspace

`ratify-entra-status-source` and `ratify-google-status-source` read group
membership in full for every snapshot, following every page, and read it
again at the end of the read; a group that disappeared or changed meanwhile
withholds the snapshot. A missing group, or a member row the source cannot
evaluate, is a configuration fault, never a revocation.

A disabled, suspended or archived account revokes on the read that sees it.
Absence (a deleted user, or a user no longer in a configured group) can be
replication delay, so it revokes only after the user has stayed absent
across successful reads for 10 minutes. Until then the source withholds
snapshots, so decisions fail closed once status goes stale, while explicit
revocations seen meanwhile are still saved. To withdraw one person's
authority at once, disable or suspend the account. Add a person to the
configured group before mapping a certificate to them.

The configuration JSON holds `issuer_id`, `mapping_file`, `state_file`,
`listen_addr`, `tls_cert_file` and `tls_key_file`, plus the provider fields
below.

**Microsoft Entra ID.** Configure with `ENTRA_STATUS_SOURCE_CONFIG` (shared
fields plus `tenant_id`, `client_id` and `group_ids`, all lowercase GUIDs),
`ENTRA_CLIENT_SECRET` and `IAM_SOURCE_BEARER_TOKEN`. The source gets an
app-only token with the client credentials grant, lists
`GET /v1.0/groups/{id}/transitiveMembers` for each group (users only), and
reads `GET /v1.0/users/{id}?$select=id,accountEnabled` for each mapped user.
`accountEnabled: false` revokes at once; a deleted user or one outside every
configured group revokes after the absence window. Entra has no temporary
account state, so disabling an account is a permanent revocation in this
reference. Setup:

1. Create a single-tenant app registration with no redirect URI.
2. Add Microsoft Graph application permissions `User.Read.All` and
   `GroupMember.ReadBasic.All` (or `GroupMember.Read.All`), and grant admin
   consent. Groups with hidden membership also need `Member.Read.Hidden`.
   Grant nothing else; the source never writes.
3. Create a client secret, store it as `ENTRA_CLIENT_SECRET` and rotate it
   before it expires. An expired secret fails closed.
4. Choose the security group whose members may hold agent authority and
   note its Object ID.
5. Map each certificate to the user's Object ID, never the user principal
   name.

**Google Workspace.** Configure with `GOOGLE_STATUS_SOURCE_CONFIG` (shared
fields plus `admin_subject` and `group_ids`),
`GOOGLE_SERVICE_ACCOUNT_KEY_FILE` and `IAM_SOURCE_BEARER_TOKEN`. The source
signs a service-account JWT for `admin_subject`, lists
`GET /admin/directory/v1/groups/{groupKey}/members?includeDerivedMembership=true`
for each group by immutable group ID (users only; a `CUSTOMER` member yields
no snapshot), and reads `GET /admin/directory/v1/users/{userKey}?projection=basic`
for each mapped user. `suspended` or `archived` revokes at once; a deleted
user or one outside every configured group revokes after the absence
window, which also covers Google's documented delay of up to 10 minutes for
nested membership changes. Setup:

1. Enable the Admin SDK API in a Google Cloud project, create a service
   account and a JSON key, store it owner-only, and point
   `GOOGLE_SERVICE_ACCOUNT_KEY_FILE` at it.
2. In the Google Admin console, add the service account's client ID to
   domain-wide delegation with exactly
   `https://www.googleapis.com/auth/admin.directory.user.readonly` and
   `https://www.googleapis.com/auth/admin.directory.group.member.readonly`.
3. Create a dedicated admin user with a custom role holding only Users read
   and Groups read, and set `admin_subject` to its email. The key can act as
   any user within those read-only scopes, so keep it owner-only, rotate it
   and watch its use in your audit logs.
4. Note the group's immutable ID (the `id` from `groups.get`), not its
   email address.
5. Map each certificate to the user's numeric `id` from `users.get`, never
   the email address.

## Write your own source

An HR system, a contractor register or any other system of record can be a
source. Serve the contract above and keep these rules:

- Identify each person by an ID that never moves to someone else, and map
  each exact `cert_id` to it in a file you own.
- Read the system of record on every request and set `observed_at` after
  the read finishes. Never serve a cached or partial answer; on any doubt
  answer 503 and let status go stale.
- Keep every revocation and keep checking every certificate ever mapped.
  Only a new certificate ID regrants.
- Revoke only on permanent facts, and treat a missing record as absence to
  confirm, not as proof.

Inside this repository, a new source under `cmd/` can implement
`statussource.Provider` from `internal/statussource` and call
`statussource.Run`, as the Entra and Google sources do, to reuse the state,
mapping, recovery and HTTP handling.
