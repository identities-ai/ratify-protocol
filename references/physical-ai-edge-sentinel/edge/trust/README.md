# Trust and clock inputs

Planned contents:

- provisioned operator public key plus its derived `human_id` label
- signed local `RevocationList`
- DS3231-class RTC integration and explicit `now_unix` handling
- local policy and revocation freshness configuration

Key rotation is out of scope for the MVP. The initial operator public key is
pinned out of band, and the edge receiver rejects a configuration whose
`human_id` does not derive from that key.
