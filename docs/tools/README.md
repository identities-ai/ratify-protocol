# Ratify Verify customer tools

These are the tools a Ratify Verify customer runs on their own machines to
hold their own keys and sign their own status lists. Keys are created and
used where the customer runs these tools; Verify receives public keys,
proofs and signed objects, never private keys. The source is here so
customers can audit the code that touches their keys.

The tools are not part of the Protocol v2 specification or its conformance
suite. A verifier that checks Protocol v2 proofs needs none of them.

| Tool | Purpose |
|------|---------|
| `ratify-keys` | Create keys, set up an organization root, issuer and issuer status key, answer enrollment challenges, renew an issuer authorization, sign delegation certificates, receiver profiles and status lists, and check Verify exports and evidence feed deliveries offline |
| `ratify-reference-receiver` | A minimal receiver: signs its receiver configuration with its own key and asks Verify for a decision before acting. A reference for integrators, not a replacement for a production receiver |
| `ratify-iam-bridge` | Reads a complete revoked-set snapshot from the customer's IAM system and publishes a customer-signed Protocol v2 status list for one issuer. See [iam-status-bridge.md](iam-status-bridge.md) |
| `ratify-okta-status-source`, `ratify-entra-status-source`, `ratify-google-status-source` | Read-only reference snapshot sources for the bridge, for Okta, Microsoft Entra ID and Google Workspace |

Each tool prints its version with `--version`. `ratify-keys` prints its
usage with `--help`, `ratify-reference-receiver` documents its commands in
its source, and the bridge and sources are configured through environment
variables described in [iam-status-bridge.md](iam-status-bridge.md).

## Install

From source, with Go 1.25 or later, at an exact Protocol v2 release tag
that contains the tools (the first is the release after `v2.0.0-beta.2`):

```sh
RATIFY_TAG=v2.0.0-beta.N   # set to the exact release tag
go install "github.com/identities-ai/ratify-protocol/v2/cmd/ratify-keys@$RATIFY_TAG"
go install "github.com/identities-ai/ratify-protocol/v2/cmd/ratify-iam-bridge@$RATIFY_TAG"
```

The Go checksum database confirms that the source you build is the source
at that tag. A tool built with `go install` reports the module version it was
built from.

The tools run on Linux and macOS. Their owner-only checks on key and state
files use Unix permissions, and the IAM bridge and status sources use
`flock(2)` for their state lock; Windows is not supported yet.

## Key setup with ratify-keys

A typical organization setup, run on the machine that will hold the keys:

```sh
ratify-keys setup issuer --offline --org ORGANIZATION_ID --out keys
# upload keys/setup-request.json on the console's setup page; it returns a challenge bundle
ratify-keys prove --bundle bundle.json --dir keys --out proofs.json
# upload proofs.json; Verify confirms the enrolled key IDs
```

`ratify-keys --help` lists every command: issuer renewal, single-key
enrollment, delegation certificates, receiver profiles, status-list
signing, and offline checks of Verify exports (`verify-export`) and evidence
feed deliveries (`verify-feed`). Key files are written readable only by
their owner, and every command refuses a challenge or bundle for a key it
does not hold.

## Reference receiver

`ratify-reference-receiver config` signs a receiver configuration with the
receiver's own configuration-signer key; install the result with
`PUT /v1/verify/v2/receiver-config`. `ratify-reference-receiver decide`
asks Verify for a decision on one agent action, the way a protected API
would before acting, using the receiver API key from
`RATIFY_RECEIVER_API_KEY`. It prints one JSON line and exits 0 for allow, 2
for deny and 1 for any error or withheld decision.

## Go packages

The tools are built on the packages under
[`verifyclient`](../../verifyclient): the file formats exchanged with Verify
(`setup`), export and evidence feed signature checks (`exportsig`,
`feedbatch`) and the status bridge loop (`iambridge`).

These packages are **experimental until 2.0.0**: their Go API may change in
any earlier release. The file formats they read and write stay compatible
with files already in use. Every exported symbol is listed in
`verifyclient/PUBLIC_API.txt`, and a test fails on any change that is not
reflected there. No protocol package imports `verifyclient`.

A successful parse by these packages is necessary, never sufficient: Verify
decides independently whether a request is authorized, fresh and not a
replay.

## License

The tool and package source is licensed under Apache-2.0
([LICENSE](../../LICENSE)); this documentation under CC-BY-4.0
([docs/LICENSES.md](../LICENSES.md)), as for the rest of this repository.
