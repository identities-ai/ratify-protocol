// Protocol v2 witness entry (0x0006) and caller-head log verification.
// Port of witness_v2.go.

import { V2_OBJECT_TYPE, validateHybridKeyPairV2, type HybridKeyPairV2, type V2SignOptions } from "./crypto_v2.js";
import { validV2Timestamp } from "./clock_bounds_v2.js";
import { MAX_WITNESS_ENTRY_BYTES_V2, MAX_WITNESS_ENTRY_DATA_BYTES_V2, checkV2WireSize } from "./limits_v2.js";
import { newLocalSignerV2, signV2StatementWithSigner, signerPublicKeyV2, type SignOptionsV2, type SignerV2 } from "./signer_v2.js";
import {
  ErrWitnessLogFork,
  ErrWitnessLogFrozen,
  ErrWitnessLogGap,
  ErrWitnessLogOrphan,
  classified,
  v2Classify,
  v2Errorf,
  wrapError,
} from "./errors_v2.js";
import {
  MAX_SAFE_INTEGER_V2,
  bytesEqual,
  canonicalJSONV2,
  checkWireJSONV2,
  gBytes,
  gInt,
  gString,
  gStruct,
  requireV2Fields,
  type JNode,
} from "./json_v2.js";
import { type V2AppendResult, statementBodyDigestV2 } from "./key_rotation_v2.js";
import {
  decodeHybridSignature,
  keyIDV2,
  keyWire,
  lowerHexString,
  validV2ID,
  validateHybridSignatureV2,
  verifyV2Statement,
} from "./protocol_v2_wire.js";
import type { HybridPublicKey, HybridSignature } from "./types.js";

const MAX_SAFE = MAX_SAFE_INTEGER_V2;
const ZERO48 = new Uint8Array(48);

export interface WitnessEntryV2 {
  version: number;
  log_id: string;
  sequence: number;
  prev_hash: Uint8Array;
  /** null is the JSON null (rejected); an empty array is an empty byte string. */
  entry_data: Uint8Array | null;
  timestamp: number;
  witness_id: string;
  signature: HybridSignature;
}

/**
 * Caller-authenticated log state before an entry. acceptedDigests holds
 * every accepted sequence digest; the caller persists transitions atomically.
 */
export interface WitnessV2Head {
  logID: string;
  sequence: number;
  headHash: Uint8Array;
  acceptedDigests: Map<number, Uint8Array>;
  frozen: boolean;
}

const WITNESS_ENTRY_V2_FIELDS = ["version", "log_id", "sequence", "prev_hash", "entry_data", "timestamp", "witness_id", "signature"];
const WITNESS_SIGNABLE_FIELDS = ["entry_data", "log_id", "prev_hash", "sequence", "timestamp", "version", "witness_id"];

export function validateWitnessEntryV2(e: WitnessEntryV2, signature: boolean): void {
  if (!e || e.version !== 2) throw new Error("wire v2: witness entry version must be 2");
  if (typeof e.log_id !== "string" || e.log_id.length !== 32 || !lowerHexString(e.log_id)) {
    throw new Error("wire v2: log_id must be 32 lowercase hexadecimal characters");
  }
  if (!(e.sequence > 0) || e.sequence > MAX_SAFE || !Number.isInteger(e.sequence) || !validV2Timestamp(e.timestamp)) {
    throw new Error("wire v2: sequence and timestamp must be safe integers");
  }
  if (!(e.prev_hash instanceof Uint8Array) || e.prev_hash.length !== 48) throw new Error("wire v2: prev_hash must be 48 bytes");
  if (e.entry_data === null || !(e.entry_data instanceof Uint8Array)) {
    throw new Error("wire v2: entry_data must be a base64 byte string, not null");
  }
  if (e.entry_data.length > MAX_WITNESS_ENTRY_DATA_BYTES_V2) {
    throw new Error(`wire v2: entry_data exceeds MAX_WITNESS_ENTRY_DATA_BYTES_V2 (${MAX_WITNESS_ENTRY_DATA_BYTES_V2} bytes)`);
  }
  if (e.sequence === 1 && !bytesEqual(e.prev_hash, ZERO48)) throw new Error("wire v2: genesis witness entry must use a zero prev_hash");
  if (e.sequence > 1 && bytesEqual(e.prev_hash, ZERO48)) throw new Error("wire v2: non-genesis witness entry must link to a prior entry");
  if (!validV2ID(e.witness_id)) throw new Error("wire v2: witness_id must be a 64-character lowercase hexadecimal v2 key ID");
  if (signature) validateHybridSignatureV2(e.signature);
}

function witnessSignableObject(e: WitnessEntryV2): Record<string, unknown> {
  return {
    entry_data: e.entry_data, log_id: e.log_id, prev_hash: e.prev_hash, sequence: e.sequence,
    timestamp: e.timestamp, version: e.version, witness_id: e.witness_id,
  };
}

function decodeWitnessStruct(root: JNode, allowed: readonly string[]): WitnessEntryV2 {
  const f = gStruct(root, allowed, "witness entry");
  return {
    version: gInt(f.get("version"), "version"),
    log_id: gString(f.get("log_id"), "log_id"),
    sequence: gInt(f.get("sequence"), "sequence"),
    prev_hash: gBytes(f.get("prev_hash"), "prev_hash") ?? new Uint8Array(0),
    entry_data: gBytes(f.get("entry_data"), "entry_data"),
    timestamp: gInt(f.get("timestamp"), "timestamp"),
    witness_id: gString(f.get("witness_id"), "witness_id"),
    signature: decodeHybridSignature(f.get("signature"), "signature"),
  };
}

export function validateWitnessSignableBodyV2(root: JNode, body: Uint8Array): void {
  let e: WitnessEntryV2;
  try {
    requireV2Fields(root, WITNESS_SIGNABLE_FIELDS);
    e = decodeWitnessStruct(root, WITNESS_SIGNABLE_FIELDS);
  } catch (err) {
    throw wrapError("witness signable body", err);
  }
  let canonical: Uint8Array | null = null;
  try {
    canonical = canonicalJSONV2(witnessSignableObject(e));
  } catch {
    canonical = null;
  }
  if (canonical === null || !bytesEqual(canonical, body)) throw new Error("witness signable body must use RatifyCanonicalJSON");
  validateWitnessEntryV2(e, false);
}

export function witnessEntryV2SignBytes(e: WitnessEntryV2): Uint8Array {
  validateWitnessEntryV2(e, false);
  return canonicalJSONV2(witnessSignableObject(e));
}

export function witnessEntryV2Digest(e: WitnessEntryV2): Uint8Array {
  return statementBodyDigestV2(V2_OBJECT_TYPE.witnessEntry, witnessEntryV2SignBytes(e));
}

export function encodeWitnessEntryV2(e: WitnessEntryV2): Uint8Array {
  validateWitnessEntryV2(e, true);
  const o = witnessSignableObject(e);
  o.signature = keyWire(e.signature);
  const wire = canonicalJSONV2(o);
  checkV2WireSize(wire, "witness entry", "MAX_WITNESS_ENTRY_BYTES_V2", MAX_WITNESS_ENTRY_BYTES_V2);
  return wire;
}

export function decodeWitnessEntryV2(data: Uint8Array): WitnessEntryV2 {
  return classified("malformed", () => {
    checkV2WireSize(data, "witness entry", "MAX_WITNESS_ENTRY_BYTES_V2", MAX_WITNESS_ENTRY_BYTES_V2);
    const root = checkWireJSONV2(data);
    requireV2Fields(root, WITNESS_ENTRY_V2_FIELDS);
    const e = decodeWitnessStruct(root, WITNESS_ENTRY_V2_FIELDS);
    validateWitnessEntryV2(e, true);
    let canonical: Uint8Array | null = null;
    try {
      canonical = encodeWitnessEntryV2(e);
    } catch {
      canonical = null;
    }
    if (canonical === null || !bytesEqual(canonical, data)) throw new Error("wire v2: witness entry is not canonical Ratify JSON");
    return e;
  });
}

export async function signWitnessEntryV2(e: WitnessEntryV2, witness: HybridKeyPairV2, opts: V2SignOptions = {}): Promise<WitnessEntryV2> {
  validateWitnessEntryV2(e, false);
  await validateHybridKeyPairV2(witness);
  return signWitnessEntryV2WithSigner(e, await newLocalSignerV2(witness, { deterministic: opts.deterministic }));
}

/** signWitnessEntryV2 through a signer whose key ID must equal witness_id. */
export async function signWitnessEntryV2WithSigner(e: WitnessEntryV2, signer: SignerV2, opts: SignOptionsV2 = {}): Promise<WitnessEntryV2> {
  validateWitnessEntryV2(e, false);
  const witnessPublic = await signerPublicKeyV2(signer);
  if (keyIDV2(witnessPublic) !== e.witness_id) throw new Error("witness_id does not match signing key");
  const signature = await signV2StatementWithSigner(V2_OBJECT_TYPE.witnessEntry, witnessEntryV2SignBytes(e), signer, witnessPublic, opts);
  const result: WitnessEntryV2 = {
    ...e, prev_hash: Uint8Array.from(e.prev_hash), entry_data: Uint8Array.from(e.entry_data ?? []), signature,
  };
  encodeWitnessEntryV2(result);
  return result;
}

/** Shared caller-head validation for witness and receipt logs. */
export function validateLogHeadV2(head: WitnessV2Head, kind: string): void {
  if (!head || typeof head.logID !== "string" || head.logID.length !== 32 || !lowerHexString(head.logID) ||
      !(head.sequence >= 0) || head.sequence > MAX_SAFE || !Number.isInteger(head.sequence) ||
      !(head.headHash instanceof Uint8Array) || head.headHash.length !== 48) {
    throw v2Errorf("configuration_invalid", `caller ${kind} head is invalid`);
  }
  const accepted = head.acceptedDigests ?? new Map<number, Uint8Array>();
  if ((head.sequence === 0 && (!bytesEqual(head.headHash, ZERO48) || accepted.size !== 0)) ||
      (head.sequence > 0 && bytesEqual(head.headHash, ZERO48))) {
    throw v2Errorf("configuration_invalid", `caller ${kind} head has inconsistent genesis state`);
  }
  if (head.sequence > 0 && accepted.size !== head.sequence) {
    throw v2Errorf("configuration_invalid", `caller ${kind} head is missing accepted sequence digests`);
  }
  if (head.sequence > 0 && !bytesEqual(accepted.get(head.sequence), head.headHash)) {
    throw v2Errorf("configuration_invalid", `caller ${kind} head hash does not match its accepted digest history`);
  }
  for (const [sequence, digest] of accepted) {
    if (!(sequence > 0) || sequence > head.sequence || !(digest instanceof Uint8Array) || digest.length !== 48) {
      throw v2Errorf("configuration_invalid", `caller ${kind} head contains invalid accepted digest history`);
    }
  }
}

/** Position checks after a valid signature (shared by witness and receipt logs). */
export function logPositionV2(sequence: number, prevHash: Uint8Array, digest: Uint8Array, head: WitnessV2Head): V2AppendResult {
  if (sequence <= head.sequence) {
    if (bytesEqual(head.acceptedDigests.get(sequence), digest)) return "replay";
    throw wrapError(`witness log fork at sequence ${sequence}; caller must freeze log ${head.logID}`, ErrWitnessLogFork);
  }
  if (head.frozen) throw wrapError(ErrWitnessLogFrozen.message, ErrWitnessLogFrozen);
  if (sequence > head.sequence + 1) throw wrapError(`witness log sequence gap: got ${sequence} after ${head.sequence}`, ErrWitnessLogGap);
  if (sequence !== head.sequence + 1 || !bytesEqual(prevHash, head.headHash)) {
    throw wrapError("orphaned witness entry: entry does not link to the current head", ErrWitnessLogOrphan);
  }
  return "appended";
}

/**
 * Checks key identity, log position and both signatures against
 * caller-authenticated state. A log_fork result is authenticated fork
 * evidence; the caller must durably freeze the log. Never mutates state.
 */
export async function verifyWitnessEntryV2(e: WitnessEntryV2, head: WitnessV2Head, witnessPublic: HybridPublicKey): Promise<V2AppendResult> {
  try {
    validateWitnessEntryV2(e, true);
    encodeWitnessEntryV2(e);
  } catch (err) {
    throw v2Classify("malformed", err);
  }
  validateLogHeadV2(head, "witness");
  const witnessID = keyIDV2(witnessPublic);
  if (e.witness_id !== witnessID || e.log_id !== head.logID) {
    throw v2Errorf("log_state_mismatch", "witness entry key or log ID does not match caller-authenticated state");
  }
  await verifyV2Statement(V2_OBJECT_TYPE.witnessEntry, witnessEntryV2SignBytes(e), e.signature, witnessPublic);
  return logPositionV2(e.sequence, e.prev_hash, witnessEntryV2Digest(e), head);
}
