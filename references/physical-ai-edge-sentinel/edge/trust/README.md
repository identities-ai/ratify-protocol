# Trust and clock inputs

The receiver's trust directory is provisioned out of band. `controller
provision` writes one for demonstrations.

| File | Content |
| --- | --- |
| `root_pub.json` | The pinned root public key (complete Ed25519 and ML-DSA-65 key) |
| `status_pub.json` | The root's separate status key, bound at epoch 1; must differ from the root key |
| `agent_pub.json` | The agent expected to present proofs; bound into every challenge |
| `checkpoint_pub.json` | The checkpoint process's public key |
| `policy.conf` | `zone`, `max_activation_ms`, `workspace_id`, `status_max_age_s`, `challenge_lifetime_s`, `max_challenge_age_s` |
| `status-list.json` | The signed status list staged into the journal at initialization |

Trust is pinned to complete public keys, never to a key ID alone, and no key
may serve two roles. The receiver reads time only from the DS3231 RTC through
`/dev/rtc0`; the user running the receiver and the user running the checkpoint
both need read access to it.
