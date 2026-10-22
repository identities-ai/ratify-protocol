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

Seeding `corpus/<target>/` with the wire objects of `testvectors/v2/objects.json`,
`object-negatives.json`, `hedged-signatures.json`, and `cross-sdk/*.json` (and each
certificate constraint for `constraint_v2`) reaches far more code in a short run.
`corpus/` and `artifacts/` are not committed.

## Known gaps

Two non-canonical spellings are accepted by the decoders (the Go reference
behaves the same). A long run of `delegation_cert_v2` or `proof_bundle_v2` may
report them as round-trip failures:

- a proof bundle `agent_pub_key` that omits a component, such as `{}`, decodes
  with that component empty and re-encodes it as `""`;
- `null` inside a delegation certificate `scope` array decodes as `""`.

`tests/v2_proptest.rs` pins both (`known_gap_*`).

## Still to add

These decoders are not in this crate yet and get targets once the status
subsystem port lands:

- status evidence batch
- checkpoint acknowledgement
- security journal snapshot import
- archival result objects
