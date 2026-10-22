// Archival (signature-only) verification of stored v2 objects (SPEC-v2
// §6.10; Go archival_v2.go). Every result is labeled freshness_unverified and
// is never actionable: no challenge is consumed and no provider is invoked.

import { V2_OBJECT_TYPE, keyIDV2, verifyV2Statement } from "./crypto_v2.js";
import { v2Classify, v2ErrorClassOf, v2Errorf, wrapError, type V2ErrorClass } from "./errors_v2.js";
import { canonicalJSONV2, compareStrings, hexOf } from "./json_v2.js";
import { decodeKeyRotationStatementV2, keyRotationStatementV2Digest, keyRotationStatementV2SignBytes } from "./key_rotation_v2.js";
import {
  bundleHashV2,
  decodeDelegationCertV2,
  decodeProofBundleV2,
  decodeRevocationListV2,
  decodeRevocationPushV2,
  statusEvidenceDigestV2,
  verifyDelegationCertV2Signature,
  verifyProofBundleV2Signatures,
  verifyRevocationListV2Signature,
  verifyRevocationPushV2Signature,
} from "./protocol_v2_wire.js";
import { decodeTransactionReceiptV2 } from "./transaction_receipt_v2.js";
import { decodeVerificationReceiptV2, verificationReceiptV2Digest, verificationReceiptV2SignBytes } from "./verification_receipt_v2.js";
import { decodeWitnessEntryV2, witnessEntryV2Digest, witnessEntryV2SignBytes } from "./witness_v2.js";
import type { HybridPublicKey } from "./types.js";

/** The mandatory label of every archival result. */
export const FRESHNESS_UNVERIFIED_V2 = "freshness_unverified";

/**
 * One stored object decoded strictly and its signatures verify. Not an
 * authorization decision. `digest` is "sha384:" + 96 hex of
 * StatementBodyDigest (rotation, witness, verification receipt) or
 * StatusEvidenceDigest (list, push), and "" for a certificate or
 * transaction receipt.
 */
export interface ArchivalVerificationV2 {
  readonly object_type_code: number;
  readonly freshness: "freshness_unverified";
  readonly actionable: false;
  readonly digest: string;
  readonly signer_key_ids: string[];
}

function archivalResultV2(code: number, digest: Uint8Array | null, ...signers: string[]): ArchivalVerificationV2 {
  return {
    object_type_code: code, freshness: FRESHNESS_UNVERIFIED_V2, actionable: false,
    digest: digest === null ? "" : "sha384:" + hexOf(digest), signer_key_ids: signers,
  };
}

/** The SPEC-v2 §6.10 archival proof-bundle result; error_class null on success. */
export interface ArchivalProofBundleResultV2 {
  readonly assessment: "freshness_unverified";
  readonly actionable: false;
  readonly bundle_hash: string;
  readonly agent_id: string;
  readonly issuer_ids: string[];
  readonly error_class: V2ErrorClass | null;
}

/** Canonical JSON of the archival proof-bundle result (Go MarshalJSON). */
export function encodeArchivalProofBundleResultV2(r: ArchivalProofBundleResultV2): Uint8Array {
  return canonicalJSONV2({
    actionable: r.actionable, agent_id: r.agent_id, assessment: r.assessment, bundle_hash: r.bundle_hash,
    error_class: r.error_class, issuer_ids: r.issuer_ids,
  });
}

/**
 * Pre-claim steps 1, 4 and 5 only (strict decode, key IDs, digest,
 * duplicates, linkage, every signature) on a stored proof bundle.
 */
export async function verifyArchivalProofBundleV2(data: Uint8Array): Promise<ArchivalProofBundleResultV2> {
  let bundleHash = "";
  let agentID = "";
  let issuerIDs: string[] = [];
  const result = (cls: V2ErrorClass | null): ArchivalProofBundleResultV2 => ({
    assessment: FRESHNESS_UNVERIFIED_V2, actionable: false, bundle_hash: bundleHash, agent_id: agentID, issuer_ids: issuerIDs, error_class: cls,
  });
  const fail = (err: unknown) => {
    const cls = v2ErrorClassOf(err);
    return result(cls === "" ? "unclassified" : cls);
  };
  let bundle;
  try {
    bundle = decodeProofBundleV2(data);
  } catch (err) {
    return fail(err);
  }
  agentID = bundle.agent_id;
  try {
    bundleHash = bundleHashV2(bundle);
  } catch (err) {
    return fail(v2Classify("malformed", err));
  }
  issuerIDs = [...new Set((bundle.delegations ?? []).map((c) => c.issuer_id))].sort(compareStrings);
  try {
    await verifyProofBundleV2Signatures(bundle);
  } catch (err) {
    return fail(err);
  }
  return result(null);
}

/** A stored certificate under the issuer key it carries. */
export async function verifyArchivalDelegationCertV2(data: Uint8Array): Promise<ArchivalVerificationV2> {
  const cert = decodeDelegationCertV2(data);
  await verifyDelegationCertV2Signature(cert);
  return archivalResultV2(V2_OBJECT_TYPE.delegationCertificate, null, cert.issuer_id);
}

/** A stored revocation list under a caller-authenticated issuer status key. */
export async function verifyArchivalRevocationListV2(data: Uint8Array, issuerID: string, statusKey: HybridPublicKey): Promise<ArchivalVerificationV2> {
  const list = decodeRevocationListV2(data);
  await verifyRevocationListV2Signature(list, issuerID, statusKey);
  let digest: Uint8Array;
  try {
    digest = statusEvidenceDigestV2(V2_OBJECT_TYPE.revocationList, list);
  } catch (err) {
    throw v2Classify("malformed", err);
  }
  return archivalResultV2(V2_OBJECT_TYPE.revocationList, digest, keyIDV2(statusKey));
}

/** A stored revocation push under a caller-authenticated issuer status key. */
export async function verifyArchivalRevocationPushV2(data: Uint8Array, issuerID: string, statusKey: HybridPublicKey): Promise<ArchivalVerificationV2> {
  const push = decodeRevocationPushV2(data);
  await verifyRevocationPushV2Signature(push, issuerID, statusKey);
  let digest: Uint8Array;
  try {
    digest = statusEvidenceDigestV2(V2_OBJECT_TYPE.revocationPush, push);
  } catch (err) {
    throw v2Classify("malformed", err);
  }
  return archivalResultV2(V2_OBJECT_TYPE.revocationPush, digest, keyIDV2(statusKey));
}

/**
 * A stored rotation statement under the keys it names. It does not
 * establish that old_key was the authority's current key.
 */
export async function verifyArchivalKeyRotationStatementV2(data: Uint8Array): Promise<ArchivalVerificationV2> {
  const stmt = decodeKeyRotationStatementV2(data);
  let signable: Uint8Array;
  try {
    signable = keyRotationStatementV2SignBytes(stmt);
  } catch (err) {
    throw v2Classify("malformed", err);
  }
  try {
    await verifyV2Statement(V2_OBJECT_TYPE.keyRotationAuthorization, signable, stmt.old_signature, stmt.old_key);
  } catch (err) {
    throw wrapError("old-key rotation authorization", err);
  }
  try {
    await verifyV2Statement(V2_OBJECT_TYPE.keyRotationProofOfPossession, signable, stmt.new_signature, stmt.new_key);
  } catch (err) {
    throw wrapError("new-key proof of possession", err);
  }
  return archivalResultV2(V2_OBJECT_TYPE.keyRotationAuthorization, keyRotationStatementV2Digest(stmt), stmt.old_key_id, stmt.new_key_id);
}

/** A stored witness entry under a caller-authenticated witness key (no log checks). */
export async function verifyArchivalWitnessEntryV2(data: Uint8Array, witnessPublic: HybridPublicKey): Promise<ArchivalVerificationV2> {
  const entry = decodeWitnessEntryV2(data);
  let witnessID = "";
  try {
    witnessID = keyIDV2(witnessPublic);
  } catch {
    witnessID = "";
  }
  if (witnessID === "" || witnessID !== entry.witness_id) throw v2Errorf("key_id_mismatch", "witness key does not match witness_id");
  let body: Uint8Array;
  try {
    body = witnessEntryV2SignBytes(entry);
  } catch (err) {
    throw v2Classify("malformed", err);
  }
  await verifyV2Statement(V2_OBJECT_TYPE.witnessEntry, body, entry.signature, witnessPublic);
  return archivalResultV2(V2_OBJECT_TYPE.witnessEntry, witnessEntryV2Digest(entry), witnessID);
}

/** A stored verification receipt under a caller-authenticated verifier key (no log or bundle checks). */
export async function verifyArchivalVerificationReceiptV2(data: Uint8Array, verifierPublic: HybridPublicKey): Promise<ArchivalVerificationV2> {
  const receipt = decodeVerificationReceiptV2(data);
  let verifierID = "";
  try {
    verifierID = keyIDV2(verifierPublic);
  } catch {
    verifierID = "";
  }
  if (verifierID === "" || verifierID !== receipt.verifier_id) throw v2Errorf("key_id_mismatch", "verifier key does not match verifier_id");
  let body: Uint8Array;
  try {
    body = verificationReceiptV2SignBytes(receipt);
  } catch (err) {
    throw v2Classify("malformed", err);
  }
  await verifyV2Statement(V2_OBJECT_TYPE.verificationReceipt, body, receipt.signature, verifierPublic);
  return archivalResultV2(V2_OBJECT_TYPE.verificationReceipt, verificationReceiptV2Digest(receipt), verifierID);
}

/**
 * A stored transaction receipt: canonical form, every party signature, and
 * every embedded bundle's signatures, hash and transaction context.
 */
export async function verifyArchivalTransactionReceiptV2(data: Uint8Array): Promise<ArchivalVerificationV2> {
  const receipt = await decodeTransactionReceiptV2(data);
  return archivalResultV2(V2_OBJECT_TYPE.transactionPartyStatement, null, ...receipt.parties.map((p) => p.agent_id));
}
