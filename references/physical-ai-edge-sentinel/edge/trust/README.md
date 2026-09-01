# Trust and clock inputs

Planned contents:

- provisioned operator `human_id` trust anchor
- signed local `RevocationList`
- DS3231-class RTC integration and explicit `now_unix` handling
- local policy and revocation freshness configuration

Key rotation is out of scope for the MVP. The initial operator key is pinned
out of band.
