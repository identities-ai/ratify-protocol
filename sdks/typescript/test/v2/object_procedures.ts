// Per-kind object procedures shared by objects.json, object-negatives.json,
// hedged-signatures.json and the cross-SDK fixtures (object-negatives.json
// procedure_by_kind). Key names resolve through the supplied key map.

import assert from "node:assert/strict";
import { sha256, sha384 } from "@noble/hashes/sha2";
import { shake256 } from "@noble/hashes/sha3";

import { challengeClaimDigestV2, protocolClaimIDV2 } from "../../src/challenge_claim_v2.js";
import { deriveKeyIDV2, v2MLDSAContext, v2SigningMessage, type HybridKeyPairV2 } from "../../src/crypto_v2.js";
import { base64Encode, canonicalJSONV2, gAny, hexOf, parseJSONV2, type JNode } from "../../src/json_v2.js";
import {
  decodeKeyRotationStatementV2,
  encodeKeyRotationStatementV2,
  keyRotationStatementV2Digest,
  verifyKeyRotationStatementV2,
  type KeyRotationV2State,
} from "../../src/key_rotation_v2.js";
import { buildSessionContextV2, operationContextV2Hash } from "../../src/operation_context_v2.js";
import {
  bundleHashV2,
  decodeDelegationCertV2,
  decodeProofBundleV2,
  decodeRevocationListV2,
  decodeRevocationPushV2,
  encodeDelegationCertV2,
  encodeProofBundleV2,
  encodeRevocationListV2,
  encodeRevocationPushV2,
  statusEvidenceDigestV2,
  verifyDelegationCertV2Signature,
  verifyProofBundleV2Signatures,
  verifyRevocationListV2Signature,
  verifyRevocationPushV2Signature,
} from "../../src/protocol_v2_wire.js";
import { signV2StatementWithKeyPair } from "../../src/signer_v2.js";
import {
  decodeTransactionReceiptV2,
  encodeTransactionReceiptV2,
  transactionReceiptV2SignBytes,
  verifyTransactionReceiptV2Signatures,
} from "../../src/transaction_receipt_v2.js";
import {
  checkVerificationReceiptV2BundleBinding,
  decodeVerificationReceiptV2,
  encodeVerificationReceiptV2,
  verificationReceiptV2Body,
  verificationReceiptV2Digest,
  verifyVerificationReceiptV2,
  type ReceiptV2Head,
} from "../../src/verification_receipt_v2.js";
import { decodeWitnessEntryV2, encodeWitnessEntryV2, verifyWitnessEntryV2, witnessEntryV2Digest, type WitnessV2Head } from "../../src/witness_v2.js";
import type { HybridPublicKey } from "../../src/types.js";
import { eqBytes, unb64, type Any } from "./helpers.js";

export type KeyMap = Map<string, HybridKeyPairV2>;

export const OBJECT_KINDS = [
  "delegation_certificate", "proof_bundle", "revocation_list", "revocation_push", "key_rotation_statement",
  "witness_entry", "transaction_receipt", "verification_receipt", "receipt_bundle_binding",
] as const;

const utf8 = (b: Uint8Array): string => new TextDecoder().decode(b);

export function pubByName(keys: KeyMap, name: string): HybridPublicKey {
  const p = keys.get(name);
  assert.ok(p, `unknown fixture key ${name}`);
  return p.publicKey;
}

export function witnessHead(h: Any): WitnessV2Head {
  const accepted = new Map<number, Uint8Array>();
  for (const [seq, d] of Object.entries(h.accepted_digests_b64 ?? {})) accepted.set(Number(seq), unb64(d as string));
  return { logID: h.log_id, sequence: h.sequence, headHash: unb64(h.head_hash_b64), acceptedDigests: accepted, frozen: h.frozen };
}

export const receiptHead = (h: Any): ReceiptV2Head => ({ ...witnessHead(h), verifierID: h.verifier_id });

export function rotationState(s: Any, keys: KeyMap): KeyRotationV2State {
  return {
    authorityID: s.authority_id, recoveryEpoch: s.recovery_epoch, role: s.role, sequence: s.sequence,
    headHash: unb64(s.head_hash_b64), currentKey: pubByName(keys, s.current_key), usedKeyIDs: [...s.used_key_ids],
  };
}

/** The procedure_by_kind of object-negatives.json. */
export async function verifyObject(keys: KeyMap, kind: string, wire: Uint8Array, bundleWire: Uint8Array | null, vc: Any): Promise<void> {
  switch (kind) {
    case "delegation_certificate":
      return verifyDelegationCertV2Signature(decodeDelegationCertV2(wire));
    case "proof_bundle":
      return verifyProofBundleV2Signatures(decodeProofBundleV2(wire));
    case "revocation_list":
      return verifyRevocationListV2Signature(decodeRevocationListV2(wire), vc.bound_issuer_id, pubByName(keys, vc.status_key));
    case "revocation_push":
      return verifyRevocationPushV2Signature(decodeRevocationPushV2(wire), vc.bound_issuer_id, pubByName(keys, vc.status_key));
    case "key_rotation_statement":
      return verifyKeyRotationStatementV2(decodeKeyRotationStatementV2(wire), rotationState(vc.rotation_state, keys), vc.now, vc.future_skew_seconds);
    case "witness_entry":
      await verifyWitnessEntryV2(decodeWitnessEntryV2(wire), witnessHead(vc.head), pubByName(keys, vc.witness_key));
      return;
    case "transaction_receipt":
      return verifyTransactionReceiptV2Signatures(await decodeTransactionReceiptV2(wire));
    case "verification_receipt":
      await verifyVerificationReceiptV2(decodeVerificationReceiptV2(wire), pubByName(keys, vc.verifier_key), receiptHead(vc.head));
      return;
    case "receipt_bundle_binding": {
      const r = decodeVerificationReceiptV2(wire);
      const b = decodeProofBundleV2(bundleWire!);
      return checkVerificationReceiptV2BundleBinding(r, b);
    }
  }
  assert.fail(`unknown kind ${kind}`);
}

/** Decode then re-encode under the kind's codec. */
export async function reencode(kind: string, wire: Uint8Array): Promise<Uint8Array> {
  switch (kind) {
    case "delegation_certificate": return encodeDelegationCertV2(decodeDelegationCertV2(wire));
    case "proof_bundle": return encodeProofBundleV2(decodeProofBundleV2(wire));
    case "revocation_list": return encodeRevocationListV2(decodeRevocationListV2(wire));
    case "revocation_push": return encodeRevocationPushV2(decodeRevocationPushV2(wire));
    case "key_rotation_statement": return encodeKeyRotationStatementV2(decodeKeyRotationStatementV2(wire));
    case "witness_entry": return encodeWitnessEntryV2(decodeWitnessEntryV2(wire));
    case "transaction_receipt": return encodeTransactionReceiptV2(await decodeTransactionReceiptV2(wire));
    case "verification_receipt": return encodeVerificationReceiptV2(decodeVerificationReceiptV2(wire));
  }
  assert.fail(`unknown kind ${kind}`);
}

/** The signable projection of one signature field, derived independently from the wire JSON. */
export async function projection(wire: Uint8Array, field: string): Promise<Uint8Array> {
  const root = parseJSONV2(wire);
  assert.equal(root.k, "obj");
  const drop = (n: JNode, ...fields: string[]) => {
    const obj = gAny(n) as Record<string, unknown>;
    for (const f of fields) delete obj[f];
    return canonicalJSONV2(obj);
  };
  if (field === "signature") return drop(root, "signature");
  if (field === "challenge_sig") return drop(root, "delegations", "challenge_sig");
  if (field === "old_signature" || field === "new_signature") return drop(root, "old_signature", "new_signature");
  const m = /^delegations\[(\d+)\]\.signature$/.exec(field);
  if (m) {
    const certs = (root as Extract<JNode, { k: "obj" }>).m.get("delegations")!;
    assert.equal(certs.k, "arr");
    return drop((certs as Extract<JNode, { k: "arr" }>).a[Number(m[1])]!, "signature");
  }
  if (field.startsWith("party_signatures[")) return transactionReceiptV2SignBytes(await decodeTransactionReceiptV2(wire));
  assert.fail(`unknown signature field ${field}`);
}

function lp(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(8 + b.length);
  new DataView(out.buffer).setBigUint64(0, BigInt(b.length));
  out.set(b, 8);
  return out;
}

async function transactionPartyDigest(wire: Uint8Array, name: string, txContextHex: string): Promise<string> {
  const r = await decodeTransactionReceiptV2(wire);
  const enc = (s: string) => new TextEncoder().encode(s);
  const txContext = sha256(new Uint8Array([
    ...enc("ratify/transaction-context/v2"), ...lp(enc(r.transaction_id)), ...lp(enc(r.terms_schema_uri)), ...sha384(r.terms_canonical_json),
  ]));
  assert.equal(hexOf(txContext), txContextHex, "transaction context differs");
  const [partyID, field] = [name.slice(0, name.indexOf(".")), name.slice(name.indexOf(".") + 1)];
  const p = r.parties.find((x) => x.party_id === partyID);
  assert.ok(p, `unknown party ${partyID}`);
  const req = sha256(new Uint8Array([...enc("ratify/transaction-party-request/v2"), ...lp(txContext), ...lp(enc(p.required_scope))]));
  switch (field) {
    case "transaction_party_request_hash_hex": return hexOf(req);
    case "session_context_hex":
      return hexOf(buildSessionContextV2({
        verifier_id: p.verifier_id, workspace_id: p.workspace_id, agent_id: p.agent_id, session_id: p.session_id,
        invocation_id: p.invocation_id, request_hash: req,
      }));
    case "proof_bundle_hash": return bundleHashV2(p.proof_bundle!);
  }
  assert.fail(`unknown transaction digest ${name}`);
}

/** Reproduces every digest of an objects.json-shaped object. */
export async function checkObjectDigests(o: Any, wire: Uint8Array): Promise<void> {
  for (const [name, want] of Object.entries(o.digests as Record<string, string>)) {
    let got: string;
    switch (name) {
      case "issuer_key_id_v2":
        got = deriveKeyIDV2(decodeDelegationCertV2(wire).issuer_pub_key);
        break;
      case "subject_key_id_v2":
        got = deriveKeyIDV2(decodeDelegationCertV2(wire).subject_pub_key);
        break;
      case "delegation_digest_hex":
        got = hexOf(decodeProofBundleV2(wire).delegation_digest);
        break;
      case "bundle_hash_v2":
        got = bundleHashV2(decodeProofBundleV2(wire));
        break;
      case "session_context_hex": {
        const b = decodeProofBundleV2(wire);
        const ctx = buildSessionContextV2({
          verifier_id: b.verifier_id, workspace_id: "00000000-0000-4000-8000-000000000001", agent_id: b.agent_id,
          session_id: "session-01", invocation_id: "invocation-01",
          request_hash: operationContextV2Hash({ required_scope: "data:read", operation: "records.get", resource_id: "customer/123", requested_path: "/v1/customers/123" }),
        });
        assert.ok(b.session_context && eqBytes(b.session_context, ctx), "bundle session_context does not match the recomputed fixture context");
        got = hexOf(ctx);
        break;
      }
      case "challenge_claim_digest_hex":
        got = hexOf(challengeClaimDigestV2(decodeProofBundleV2(wire).challenge));
        break;
      case "claim_id":
        got = protocolClaimIDV2(o.digests.claim_verifier_namespace, Number(o.digests.claim_replay_epoch), decodeProofBundleV2(wire).challenge);
        break;
      case "claim_verifier_namespace":
      case "claim_replay_epoch":
      case "transaction_context_hex":
        continue;
      case "receipt_outbox_body_b64":
        got = base64Encode(verificationReceiptV2Body(decodeVerificationReceiptV2(wire)));
        break;
      case "status_evidence_digest":
        got = "sha384:" + hexOf(o.kind === "revocation_list"
          ? statusEvidenceDigestV2(3, decodeRevocationListV2(wire))
          : statusEvidenceDigestV2(5, decodeRevocationPushV2(wire)));
        break;
      case "statement_body_digest_hex":
        if (o.kind === "key_rotation_statement") got = hexOf(keyRotationStatementV2Digest(decodeKeyRotationStatementV2(wire)));
        else if (o.kind === "witness_entry") got = hexOf(witnessEntryV2Digest(decodeWitnessEntryV2(wire)));
        else got = hexOf(verificationReceiptV2Digest(decodeVerificationReceiptV2(wire)));
        break;
      default:
        assert.ok(/^[^.]+\.(transaction_party_request_hash_hex|session_context_hex|proof_bundle_hash)$/.test(name), `unknown digest ${name}`);
        got = await transactionPartyDigest(wire, name, o.digests.transaction_context_hex);
    }
    assert.equal(got, want, `${o.name}: digest ${name}`);
  }
}

/**
 * The objects.json positive procedure for one object: re-encode, verify,
 * every signature transcript, and every digest. With `deterministic`, each
 * signature is also reproduced byte-for-byte by deterministic signing.
 * Returns the object type codes of the checked signatures.
 */
export async function checkPositiveObject(keys: KeyMap, o: Any, opts: { deterministic: boolean }): Promise<number[]> {
  const codes: number[] = [];
  const wire = unb64(o.wire_b64);
  if (o.kind === "receipt_bundle_binding") {
    const bundle = unb64(o.bundle_b64);
    assert.ok(eqBytes(await reencode("verification_receipt", wire), wire), "receipt re-encoding is not byte-identical");
    assert.ok(eqBytes(await reencode("proof_bundle", bundle), bundle), "bundle re-encoding is not byte-identical");
    await verifyObject(keys, o.kind, wire, bundle, o.verify);
    return codes;
  }
  assert.ok(eqBytes(await reencode(o.kind, wire), wire), "re-encoding is not byte-identical");
  await verifyObject(keys, o.kind, wire, null, o.verify);
  for (const s of o.signatures) {
    codes.push(s.object_type_code);
    const signable = unb64(s.signable_b64);
    assert.equal(utf8(await projection(wire, s.field)), utf8(signable), `${s.field}: signable projection`);
    assert.equal(hexOf(sha384(signable)), s.signable_sha384_hex, `${s.field}: signable SHA-384`);
    const m = v2SigningMessage(s.object_type_code, signable);
    assert.ok(eqBytes(m, unb64(s.message_b64)) && m.length === 77, `${s.field}: transcript M`);
    const ctx = utf8(v2MLDSAContext(s.object_type_code));
    assert.equal(s.mldsa_context, ctx, `${s.field}: ML-DSA context`);
    assert.equal(ctx.length, 22);
    const signer = keys.get(s.signer);
    assert.ok(signer, `unknown signer ${s.signer}`);
    assert.equal(deriveKeyIDV2(signer.publicKey), s.signer_key_id_v2, `${s.field}: signer key ID`);
    const tr = shake256(signer.publicKey.ml_dsa_65, { dkLen: 64 });
    const ctxBytes = new TextEncoder().encode(ctx);
    const mu = shake256(new Uint8Array([...tr, 0, ctxBytes.length, ...ctxBytes, ...m]), { dkLen: 64 });
    assert.ok(eqBytes(tr, unb64(s.mldsa_tr_b64)) && eqBytes(mu, unb64(s.mldsa_mu_b64)), `${s.field}: external-mu tr/mu`);
    const text = utf8(wire);
    assert.ok(text.includes(s.signature.ml_dsa_65) && text.includes(s.signature.ed25519), `${s.field}: pinned signature is carried by the wire object`);
    if (opts.deterministic) {
      const resigned = await signV2StatementWithKeyPair(s.object_type_code, signable, signer, { deterministic: true });
      assert.equal(base64Encode(resigned.ed25519), s.signature.ed25519, `${s.field}: Ed25519 signature bytes`);
      assert.equal(base64Encode(resigned.ml_dsa_65), s.signature.ml_dsa_65, `${s.field}: ML-DSA-65 signature bytes`);
    }
  }
  await checkObjectDigests(o, wire);
  return codes;
}
