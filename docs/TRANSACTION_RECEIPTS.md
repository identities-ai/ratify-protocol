# Transaction Receipt Envelope

**Status:** Normative as of v1.0.0-alpha.5 (SPEC §5.14, §6.4.7). Implemented in Go, TypeScript, Python, Rust, and C/C++. Five canonical fixtures prove the envelope and tamper cases.

Ratify v1 already gives each party a `ProofBundle` that proves identity, authorization, and freshness. A transaction receipt adds a durable, multi-party artifact that says: these parties committed to the same application-defined terms at the same time, under these Ratify proofs.

This document explains the normative v1.1 envelope specified in `SPEC.md` §5.14.

---

## 1. Goals

- Keep application business terms opaque to Ratify.
- Make the receipt envelope canonical and verifiable by generic tooling.
- Bind every party to the same transaction ID, creation time, terms bytes, schema URI, and party set.
- Prevent asymmetric disclosure where one party presents a partial receipt that omits another party.
- Leave execution, settlement, delivery, and business interpretation to application-specific schemas.

## 2. Non-goals

- Ratify does not define whether a transaction was performed after signing.
- Ratify does not hide transaction amounts or counterparty identities.
- Ratify does not make multi-party signing atomic over the network. It defines an atomic final artifact: either every required signature is present and valid, or the receipt is incomplete.
- Ratify does not standardize all possible `terms` schemas in v1.1.

## 3. Envelope

```text
TransactionReceipt:
  version:              1
  transaction_id:       string
  created_at:           int64
  terms_schema_uri:     string
  terms_canonical_json: bytes
  parties:              [ReceiptParty, ...]
  party_signatures:     [ReceiptPartySignature, ...]
```

```text
ReceiptParty:
  party_id:             string
  role:                 string
  agent_id:             string
  agent_pub_key:        HybridPublicKey
  proof_bundle:         ProofBundle
```

```text
ReceiptPartySignature:
  party_id:             string
  signature:            HybridSignature
```

`terms_canonical_json` is the canonical JSON byte sequence for the application-defined terms object. It is encoded as base64-standard in JSON, following the same byte-array convention as the rest of Ratify.

`terms_schema_uri` identifies the application schema used to interpret the terms. Generic Ratify tooling verifies the envelope and signatures; schema-aware application tooling interprets the terms.

## 4. Signable Bytes

Each party signs the same canonical object:

```text
TransactionReceiptSignable:
  version:              1
  transaction_id:       string
  created_at:           int64
  terms_schema_uri:     string
  terms_canonical_json: bytes
  parties:              [ReceiptPartySignable, ...]
```

```text
ReceiptPartySignable:
  party_id:             string
  role:                 string
  agent_id:             string
  agent_pub_key:        HybridPublicKey
```

`proof_bundle` and `party_signatures` are excluded from the signable bytes. The proof bundle is verified independently by `Verify(ProofBundle)`, and signatures cannot include themselves.

The `parties` array MUST be sorted by `party_id` before canonicalization. `party_id` values MUST be unique. Because the full sorted party set is inside every party's signable bytes, removing, adding, or changing a party invalidates every existing party signature.

## 5. Verification

A generic verifier MUST:

1. Check `version == 1`.
2. Check `transaction_id`, `terms_schema_uri`, and `terms_canonical_json` are non-empty.
3. Check every `party_id` is unique and every `party_signatures[i].party_id` refers to a listed party.
4. Check every listed party has exactly one signature.
5. Verify each party's `proof_bundle` with the required scope chosen by the application for that party role.
6. Check `proof_bundle.agent_id == party.agent_id`.
7. Check `proof_bundle.agent_pub_key == party.agent_pub_key`.
8. Recompute `TransactionReceiptSignable`.
9. Verify each `ReceiptPartySignature.signature` over those bytes with that party's `agent_pub_key`.

If any step fails, the receipt is invalid. There is no partial-valid receipt state in the generic verifier.

## 6. Reference Schema URIs

v1.1 reserves two example schema URI patterns for application-specific schemas:

```text
ratify://schemas/receipt/compute-purchase/v1
ratify://schemas/receipt/scheduling/v1
```

These schemas are intentionally not normative yet. Each reference schema should define:

- a JSON schema,
- positive and negative canonical fixtures,
- role-to-required-scope rules,
- examples in at least Go and TypeScript.

## 7. Fixtures

The canonical receipt fixture set includes:

- `transaction_receipt_two_party_valid`
- `reject_transaction_receipt_missing_party_signature`
- `reject_transaction_receipt_party_tampered`
- `reject_transaction_receipt_terms_tampered`
- `reject_transaction_receipt_wrong_party_key`

Those fixtures gate every SDK's `TransactionReceiptSignBytes` and `VerifyTransactionReceipt` behavior.

## 8. Relationship To Witness

`TransactionReceipt` proves that all listed parties signed the same envelope. It does not prove ordering, inclusion, or absence. A `WitnessEntry` can later log the canonical receipt bytes to provide append-only ordering and deletion detection.
