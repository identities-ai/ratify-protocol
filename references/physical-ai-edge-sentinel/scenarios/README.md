# Scenarios

Checked-in deterministic allow/deny fixtures will live here. The initial matrix
is authorized, wrong scope, wildcard non-expansion, expired, not-yet-valid,
stale challenge, replayed, revoked, tampered, constraint-unverifiable,
clock-unavailable, restart replay, and unknown signer.

Use canonical Ratify scopes such as `infrastructure:monitor` and
`physical:actuate`; these are scopes, not action names. The action proposal and
the authority required for it are separate fields.

Fixture authors must remember that `expires_at = 0` means no expiry in Ratify; it
does not represent an expired timestamp. Every row that reaches cryptographic
verification must receive a fresh Pi-issued challenge because valid but denied
presentations consume their challenges.

The fixture runner must start with the real quarantine enabled and run one
dedicated quarantine-denial case without an override. It may then launch a
separate test build with an explicit quarantine override for the remaining
protocol cases. The override must be off by default and recorded in every test
decision; it must never be accepted by the normal edge binary.
