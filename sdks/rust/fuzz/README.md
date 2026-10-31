# v2 decoder fuzzing

cargo-fuzz targets for every Protocol v2 decoder in the crate. The fuzz crate
has its own `[workspace]`, so it is never part of the main build.

```sh
cd sdks/rust
cargo +nightly fuzz run proof_bundle_v2 -- -max_total_time=30
```

| Target | Decoder | Property |
| --- | --- | --- |
| `delegation_cert_v2` | `decode_delegation_cert_v2` | no panic; accepted input re-encodes to itself and round-trips again |
| `proof_bundle_v2` | `decode_proof_bundle_v2` | same |
| `revocation_list_v2` | `decode_revocation_list_v2` | same |
| `revocation_push_v2` | `decode_revocation_push_v2` | same |
| `key_rotation_statement_v2` | `decode_key_rotation_statement_v2` | same |
| `witness_entry_v2` | `decode_witness_entry_v2` | same |
| `verification_receipt_v2` | `decode_verification_receipt_v2` | same |
| `verification_receipt_body_v2` | `decode_verification_receipt_body_v2` (re-encoded with `verification_receipt_v2_body`) | same |
| `transaction_receipt_v2` | `decode_transaction_receipt_v2` | same |
| `canonical_json_v2` | `canonical_json_v2` | no panic; output is a fixed point |
| `constraint_v2` | `ConstraintV2::decode` | no panic; decode, canonical encode, decode gives the same constraint and bytes |
| `status_evidence_batch_v2` | `decode_v2_status_evidence_batch` | no panic; a refusal is `malformed`; at most the object cap; a re-encoded batch round-trips stably |
| `checkpoint_acknowledgement_v2` | `decode_v2_checkpoint_acknowledgement` | no panic; a refusal is `malformed`; accepted input re-encodes to itself |
| `journal_snapshot_import_v2` | `import_security_journal_snapshot_v2` | no panic; an imported snapshot re-exports to itself |
| `archival_proof_bundle_v2` | `verify_archival_proof_bundle_v2` | no panic; never actionable; always `freshness_unverified`; an accepted bundle carries its hash |

Seeding `corpus/<target>/` with the wire objects of `testvectors/v2/objects.json`,
`object-negatives.json`, `hedged-signatures.json`, and `cross-sdk/*.json` (and each
certificate constraint for `constraint_v2`) reaches far more code in a short run.
`corpus/` and `artifacts/` are not committed.

## Strict decoding

Every v2 decoder applies the strict-decode rules of SPEC-v2 §2.1: member names
must match byte for byte, `null` appears only for the members the schema
declares nullable, a required hybrid key or signature cannot be `{}`, and a
byte string must be a base64 string. A decoder that accepts input must
therefore have been handed the canonical encoding of what it decoded.
`tests/v2_proptest.rs` pins the two spellings that earlier decoders accepted
(an `agent_pub_key` of `{}` and `null` in a delegation `scope`).
