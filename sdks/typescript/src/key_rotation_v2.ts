// Protocol v2 key rotation (0x0004 old-key authorization, 0x0009 new-key
// proof of possession), the statement-body digest, and the AcceptRotation
// journal (SPEC-v2 §5.4). Port of key_rotation_v2.go and
// key_rotation_journal_v2.go.

import { sha384 } from "@noble/hashes/sha2";

import { V2_OBJECT_TYPE, validateHybridKeyPairV2, type HybridKeyPairV2, type V2SignOptions } from "./crypto_v2.js";
import { V2_MAX_FUTURE_SKEW_SECONDS, V2_MAX_TIMESTAMP_SECONDS, validV2Timestamp } from "./clock_bounds_v2.js";
import { MAX_KEY_ROTATION_STATEMENT_BYTES_V2, checkV2WireSize } from "./limits_v2.js";
import { disposeLocalSignerV2, newLocalSignerV2, signV2StatementWithSigner, signerPublicKeyV2, type SignOptionsV2, type SignerV2 } from "./signer_v2.js";
import {
  classified,
  classifiedAsync,
  ErrKeyRotationForkV2,
  ErrKeyRotationFrozenV2,
  v2Classify,
  v2Errorf,
  wrapError,
} from "./errors_v2.js";
import {
  MAX_SAFE_INTEGER_V2,
  bytesEqual,
  canonicalJSONV2,
  checkWireJSONV2,
  concatBytes,
  gAny,
  gBytes,
  gInt,
  gString,
  gStruct,
  rejectV2UnexpectedNull,
  requireV2Fields,
  uint16BE,
  utf8,
  type JNode,
} from "./json_v2.js";
import {
  cloneHybridPublicKey,
  decodeHybridKey,
  decodeHybridSignature,
  equalHybridPublicKeys,
  keyIDV2,
  keyWire,
  lowerHexString,
  validV2ID,
  validateHybridSignatureV2,
  validateRevocationListSignableBodyV2,
  validateRevocationPushSignableBodyV2,
  verifyV2Statement,
} from "./protocol_v2_wire.js";
import { validateWitnessSignableBodyV2 } from "./witness_v2.js";
import { validateVerificationReceiptSignableV2 } from "./verification_receipt_v2.js";
import type { HybridPublicKey, HybridSignature } from "./types.js";

const MAX_SAFE = MAX_SAFE_INTEGER_V2;

/** Appended or Replay (Go WitnessEntryV2Result), shared by logs and rotation. */
export type V2AppendResult = "appended" | "replay";

export interface KeyRotationStatementV2 {
  version: number;
  authority_id: string;
  recovery_epoch: number;
  role: string;
  sequence: number;
  previous_statement_hash: Uint8Array;
  old_key: HybridPublicKey;
  new_key: HybridPublicKey;
  old_key_id: string;
  new_key_id: string;
  issued_at: number;
  not_before: number;
  old_signature: HybridSignature;
  new_signature: HybridSignature;
}

/**
 * Caller-authenticated authority state immediately before a candidate.
 * usedKeyIDs is the complete retained history including currentKey's ID.
 */
export interface KeyRotationV2State {
  authorityID: string;
  recoveryEpoch: number;
  role: string;
  sequence: number;
  headHash: Uint8Array;
  currentKey: HybridPublicKey;
  usedKeyIDs: string[];
}

const KEY_ROTATION_V2_FIELDS = [
  "version", "authority_id", "recovery_epoch", "role", "sequence", "previous_statement_hash", "old_key", "new_key",
  "old_key_id", "new_key_id", "issued_at", "not_before", "old_signature", "new_signature",
];
const KEY_ROTATION_SIGNABLE_FIELDS = ["authority_id", "issued_at", "new_key", "new_key_id", "not_before", "old_key", "old_key_id", "previous_statement_hash", "recovery_epoch", "role", "sequence", "version"];
const ROLES = new Set(["organization_root", "issuer", "agent"]);
const ZERO48 = new Uint8Array(48);

const isSafe = (n: number) => Number.isInteger(n) && n >= -MAX_SAFE && n <= MAX_SAFE;

export function validateKeyRotationStatementV2(s: KeyRotationStatementV2, signatures: boolean): void {
  if (!s || s.version !== 2) throw new Error("wire v2: rotation version must be 2");
  if (typeof s.authority_id !== "string" || s.authority_id.length !== 32 || !lowerHexString(s.authority_id)) {
    throw new Error("wire v2: authority_id must be 32 lowercase hexadecimal characters");
  }
  if (!(s.recovery_epoch > 0) || s.recovery_epoch > MAX_SAFE || !(s.sequence > 0) || s.sequence > MAX_SAFE ||
      !Number.isInteger(s.recovery_epoch) || !Number.isInteger(s.sequence)) {
    throw new Error("wire v2: recovery_epoch and sequence must be positive safe integers");
  }
  if (!validV2Timestamp(s.issued_at) || !validV2Timestamp(s.not_before)) throw new Error("wire v2: issued_at and not_before must be safe integers");
  if (!ROLES.has(s.role)) throw new Error("wire v2: rotation role is invalid");
  if (!(s.previous_statement_hash instanceof Uint8Array) || s.previous_statement_hash.length !== 48) {
    throw new Error("wire v2: previous_statement_hash must be 48 bytes");
  }
  if (s.sequence === 1 && !bytesEqual(s.previous_statement_hash, ZERO48)) {
    throw new Error("wire v2: genesis rotation must use a zero previous_statement_hash");
  }
  if (s.sequence > 1 && bytesEqual(s.previous_statement_hash, ZERO48)) {
    throw new Error("wire v2: non-genesis rotation must link to a prior statement");
  }
  if (!validV2ID(s.old_key_id) || !validV2ID(s.new_key_id)) {
    throw new Error("wire v2: old_key_id and new_key_id must be 64 lowercase hexadecimal characters");
  }
  let oldID: string;
  let newID: string;
  try {
    oldID = keyIDV2(s.old_key);
  } catch (err) {
    throw wrapError("wire v2: old_key", err);
  }
  try {
    newID = keyIDV2(s.new_key);
  } catch (err) {
    throw wrapError("wire v2: new_key", err);
  }
  if (oldID !== s.old_key_id || newID !== s.new_key_id) {
    throw v2Errorf("key_id_mismatch", "wire v2: rotation key IDs must match distinct complete keys");
  }
  if (oldID === newID || equalHybridPublicKeys(s.old_key, s.new_key)) {
    throw new Error("wire v2: rotation key IDs must match distinct complete keys");
  }
  if (signatures) {
    try {
      validateHybridSignatureV2(s.old_signature);
    } catch (err) {
      throw wrapError("wire v2: old_signature", err);
    }
    try {
      validateHybridSignatureV2(s.new_signature);
    } catch (err) {
      throw wrapError("wire v2: new_signature", err);
    }
  }
}

function rotationSignableObject(s: KeyRotationStatementV2): Record<string, unknown> {
  return {
    authority_id: s.authority_id, issued_at: s.issued_at, new_key: keyWire(s.new_key), new_key_id: s.new_key_id,
    not_before: s.not_before, old_key: keyWire(s.old_key), old_key_id: s.old_key_id,
    previous_statement_hash: s.previous_statement_hash, recovery_epoch: s.recovery_epoch, role: s.role,
    sequence: s.sequence, version: s.version,
  };
}

export function keyRotationStatementV2SignBytes(s: KeyRotationStatementV2): Uint8Array {
  validateKeyRotationStatementV2(s, false);
  return canonicalJSONV2(rotationSignableObject(s));
}

/**
 * StatementBodyDigestV2 hashes the canonical signable projection of a
 * revocation list (0x0003), rotation (0x0004), revocation push (0x0005),
 * witness entry (0x0006) or verification receipt (0x0008) body after
 * validating it against its schema; any other code is
 * unsupported_object_type.
 */
export function statementBodyDigestV2(objectType: number, body: Uint8Array): Uint8Array {
  return classified("malformed", () => {
    const code = objectType;
    if (code !== V2_OBJECT_TYPE.revocationList && code !== V2_OBJECT_TYPE.keyRotationAuthorization && code !== V2_OBJECT_TYPE.revocationPush &&
      code !== V2_OBJECT_TYPE.witnessEntry && code !== V2_OBJECT_TYPE.verificationReceipt) {
      throw v2Errorf("unsupported_object_type", `object type 0x${code.toString(16).padStart(4, "0")} does not use StatementBodyDigestV2`);
    }
    let root: JNode;
    try {
      if (code === V2_OBJECT_TYPE.revocationList || code === V2_OBJECT_TYPE.revocationPush) root = checkWireJSONV2(body);
      else if (code === V2_OBJECT_TYPE.verificationReceipt) root = checkWireJSONV2(body, ["previous_receipt_hash"], ["bundle_hash"]);
      else root = checkWireJSONV2(body, ["previous_statement_hash", "delegation_digest", "previous_receipt_hash"]);
    } catch (err) {
      throw wrapError("signable body", err);
    }
    const value = gAny(root);
    if (code !== V2_OBJECT_TYPE.keyRotationAuthorization) {
      if (root.k !== "obj") throw new Error("signable body: expected a JSON object");
      for (const f of ["signature", "old_signature", "new_signature"]) {
        if (root.m.has(f)) throw new Error(`signable body must exclude ${JSON.stringify(f)}`);
      }
    }
    let canonical: Uint8Array | null = null;
    try {
      canonical = canonicalJSONV2(value);
    } catch {
      canonical = null;
    }
    if (canonical === null || !bytesEqual(canonical, body)) throw new Error("signable body must use RatifyCanonicalJSON");
    if (code === V2_OBJECT_TYPE.revocationList) validateRevocationListSignableBodyV2(root, body);
    else if (code === V2_OBJECT_TYPE.revocationPush) validateRevocationPushSignableBodyV2(root, body);
    else if (code === V2_OBJECT_TYPE.keyRotationAuthorization) validateKeyRotationSignableBodyV2(root, body);
    else if (code === V2_OBJECT_TYPE.witnessEntry) validateWitnessSignableBodyV2(root, body);
    else validateVerificationReceiptSignableV2(body);
    return sha384(concatBytes(utf8("ratify-protocol-statement-body-v2\0"), uint16BE(code), body));
  });
}

function decodeRotationStruct(root: JNode, allowed: readonly string[]): KeyRotationStatementV2 {
  const f = gStruct(root, allowed, "rotation statement");
  return {
    version: gInt(f.get("version"), "version"),
    authority_id: gString(f.get("authority_id"), "authority_id"),
    recovery_epoch: gInt(f.get("recovery_epoch"), "recovery_epoch"),
    role: gString(f.get("role"), "role"),
    sequence: gInt(f.get("sequence"), "sequence"),
    previous_statement_hash: gBytes(f.get("previous_statement_hash"), "previous_statement_hash") ?? new Uint8Array(0),
    old_key: decodeHybridKey(f.get("old_key"), "old_key"),
    new_key: decodeHybridKey(f.get("new_key"), "new_key"),
    old_key_id: gString(f.get("old_key_id"), "old_key_id"),
    new_key_id: gString(f.get("new_key_id"), "new_key_id"),
    issued_at: gInt(f.get("issued_at"), "issued_at"),
    not_before: gInt(f.get("not_before"), "not_before"),
    old_signature: decodeHybridSignature(f.get("old_signature"), "old_signature"),
    new_signature: decodeHybridSignature(f.get("new_signature"), "new_signature"),
  };
}

function validateKeyRotationSignableBodyV2(root: JNode, body: Uint8Array): void {
  let s: KeyRotationStatementV2;
  try {
    requireV2Fields(root, KEY_ROTATION_SIGNABLE_FIELDS);
    rejectV2UnexpectedNull(root);
    s = decodeRotationStruct(root, KEY_ROTATION_SIGNABLE_FIELDS);
  } catch (err) {
    throw wrapError("rotation signable body", err);
  }
  let canonical: Uint8Array | null = null;
  try {
    canonical = canonicalJSONV2(rotationSignableObject(s));
  } catch {
    canonical = null;
  }
  if (canonical === null || !bytesEqual(canonical, body)) throw new Error("rotation signable body must use RatifyCanonicalJSON");
  try {
    validateKeyRotationStatementV2(s, false);
  } catch (err) {
    throw wrapError("rotation signable body", err);
  }
}

export function keyRotationStatementV2Digest(s: KeyRotationStatementV2): Uint8Array {
  return classified("malformed", () => {
    return statementBodyDigestV2(V2_OBJECT_TYPE.keyRotationAuthorization, keyRotationStatementV2SignBytes(s));
  });
}

export function decodeKeyRotationStatementV2(data: Uint8Array): KeyRotationStatementV2 {
  return classified("malformed", () => {
    checkV2WireSize(data, "rotation statement", "MAX_KEY_ROTATION_STATEMENT_BYTES_V2", MAX_KEY_ROTATION_STATEMENT_BYTES_V2);
    const root = checkWireJSONV2(data, ["previous_statement_hash"]);
    requireV2Fields(root, KEY_ROTATION_V2_FIELDS);
    rejectV2UnexpectedNull(root);
    const s = decodeRotationStruct(root, KEY_ROTATION_V2_FIELDS);
    validateKeyRotationStatementV2(s, true);
    return s;
  });
}

export function encodeKeyRotationStatementV2(s: KeyRotationStatementV2): Uint8Array {
  return classified("malformed", () => {
    validateKeyRotationStatementV2(s, true);
    const o = rotationSignableObject(s);
    o.old_signature = keyWire(s.old_signature);
    o.new_signature = keyWire(s.new_signature);
    return canonicalJSONV2(o);
  });
}

/** Signs with the old key (0x0004) and the new key (0x0009) over the same body. */
export async function signKeyRotationStatementV2(
  s: KeyRotationStatementV2,
  oldKey: HybridKeyPairV2,
  newKey: HybridKeyPairV2,
  opts: V2SignOptions = {},
): Promise<KeyRotationStatementV2> {
  return classifiedAsync("malformed", async () => {
    validateKeyRotationStatementV2(s, false);
    let oldSigner: SignerV2 | null = null;
    let newSigner: SignerV2 | null = null;
    try {
      try {
        await validateHybridKeyPairV2(oldKey);
        oldSigner = await newLocalSignerV2(oldKey, { deterministic: opts.deterministic });
      } catch (err) {
        throw wrapError("old rotation key", err);
      }
      try {
        await validateHybridKeyPairV2(newKey);
        newSigner = await newLocalSignerV2(newKey, { deterministic: opts.deterministic });
      } catch (err) {
        throw wrapError("new rotation key", err);
      }
      return await signKeyRotationStatementV2WithSigners(s, oldSigner, newSigner);
    } finally {
      disposeLocalSignerV2(oldSigner);
      disposeLocalSignerV2(newSigner);
    }
  });
}

/**
 * signKeyRotationStatementV2 with external signers: oldSigner signs 0x0004
 * under the statement old key and newSigner signs 0x0009 under the new key.
 */
export async function signKeyRotationStatementV2WithSigners(
  s: KeyRotationStatementV2,
  oldSigner: SignerV2,
  newSigner: SignerV2,
  opts: SignOptionsV2 = {},
): Promise<KeyRotationStatementV2> {
  return classifiedAsync("malformed", async () => {
    validateKeyRotationStatementV2(s, false);
    let oldPub: HybridPublicKey;
    let newPub: HybridPublicKey;
    try {
      oldPub = await signerPublicKeyV2(oldSigner);
    } catch (err) {
      throw wrapError("old rotation key", err);
    }
    try {
      newPub = await signerPublicKeyV2(newSigner);
    } catch (err) {
      throw wrapError("new rotation key", err);
    }
    if (!equalHybridPublicKeys(oldPub, s.old_key) || !equalHybridPublicKeys(newPub, s.new_key)) {
      throw v2Errorf("key_id_mismatch", "rotation private keys do not match the statement keys");
    }
    const signable = keyRotationStatementV2SignBytes(s);
    const old_signature = await signV2StatementWithSigner(V2_OBJECT_TYPE.keyRotationAuthorization, signable, oldSigner, oldPub, opts);
    const new_signature = await signV2StatementWithSigner(V2_OBJECT_TYPE.keyRotationProofOfPossession, signable, newSigner, newPub, opts);
    return {
      ...s,
      previous_statement_hash: Uint8Array.from(s.previous_statement_hash),
      old_key: cloneHybridPublicKey(s.old_key),
      new_key: cloneHybridPublicKey(s.new_key),
      old_signature,
      new_signature,
    };
  });
}

/**
 * Checks signatures and linkage against caller-authenticated state. Success
 * is not acceptance: the caller persists the new head atomically.
 */
export async function verifyKeyRotationStatementV2(s: KeyRotationStatementV2, state: KeyRotationV2State, nowUnix: number, futureSkew: number): Promise<void> {
  return classifiedAsync("malformed", async () => {
    try {
      validateKeyRotationStatementV2(s, true);
    } catch (err) {
      throw v2Classify("malformed", err);
    }
    let currentID: string;
    try {
      currentID = keyIDV2(state.currentKey);
    } catch (err) {
      throw v2Errorf("configuration_invalid", `caller state current key: ${(err as Error).message}`, err);
    }
    if (!(state.sequence >= 0) || state.sequence >= MAX_SAFE || !(state.recoveryEpoch > 0) || state.recoveryEpoch > MAX_SAFE ||
        !(state.headHash instanceof Uint8Array) || state.headHash.length !== 48) {
      throw v2Errorf("configuration_invalid", "caller rotation state is invalid");
    }
    if (state.sequence === 0 && !bytesEqual(state.headHash, ZERO48)) {
      throw v2Errorf("configuration_invalid", "caller genesis state must have a zero head hash");
    }
    if (state.sequence > 0 && bytesEqual(state.headHash, ZERO48)) {
      throw v2Errorf("configuration_invalid", "caller non-genesis state must have a linked head hash");
    }
    if (!state.usedKeyIDs || state.usedKeyIDs.length === 0) {
      throw v2Errorf("configuration_invalid", "caller state must include retained used key IDs");
    }
    const used = new Set<string>();
    for (const id of state.usedKeyIDs) {
      if (!validV2ID(id)) throw v2Errorf("configuration_invalid", "caller state contains an invalid used key ID");
      if (used.has(id)) throw v2Errorf("configuration_invalid", "caller state contains duplicate used key IDs");
      used.add(id);
    }
    if (!used.has(currentID)) throw v2Errorf("configuration_invalid", "caller used-key history does not contain the current key");
    if (used.has(s.new_key_id)) throw v2Errorf("rotation_key_reused", "rotation replacement key was already used by this authority");
    // SPEC-v2 §2.5: the caller's time is in the timestamp domain and the
    // configured future skew is 0..300 seconds.
    if (!validV2Timestamp(nowUnix) || !Number.isSafeInteger(futureSkew) || futureSkew < 0 || futureSkew > V2_MAX_FUTURE_SKEW_SECONDS) {
      throw v2Errorf("configuration_invalid", `rotation verification time must be 0..${V2_MAX_TIMESTAMP_SECONDS} and future skew 0..${V2_MAX_FUTURE_SKEW_SECONDS} seconds`);
    }
    if (!equalHybridPublicKeys(s.old_key, state.currentKey) || s.authority_id !== state.authorityID ||
        s.recovery_epoch !== state.recoveryEpoch || s.role !== state.role || s.sequence !== state.sequence + 1 ||
        !bytesEqual(s.previous_statement_hash, state.headHash)) {
      throw v2Errorf("rotation_state_mismatch", "rotation statement does not extend the caller-authenticated authority state");
    }
    if (s.issued_at > nowUnix + futureSkew || s.not_before > nowUnix + futureSkew) {
      throw v2Errorf("rotation_future_dated", "rotation statement is future-dated");
    }
    const signable = keyRotationStatementV2SignBytes(s);
    try {
      await verifyV2Statement(V2_OBJECT_TYPE.keyRotationAuthorization, signable, s.old_signature, state.currentKey);
    } catch (err) {
      throw wrapError("old-key rotation authorization", err);
    }
    try {
      await verifyV2Statement(V2_OBJECT_TYPE.keyRotationProofOfPossession, signable, s.new_signature, s.new_key);
    } catch (err) {
      throw wrapError("new-key proof of possession", err);
    }
  });
}

// ---------------------------------------------------------------------------
// AcceptRotation journal

export interface KeyRotationV2AcceptedEntry {
  sequence: number;
  bodyDigest: Uint8Array;
  oldKey: HybridPublicKey;
}

/** Caller-persisted continuity state for one authority. */
export interface KeyRotationV2Journal {
  state: KeyRotationV2State;
  accepted: KeyRotationV2AcceptedEntry[];
  frozen: boolean;
}

export function newKeyRotationV2Journal(authorityID: string, recoveryEpoch: number, role: string, genesisKey: HybridPublicKey): KeyRotationV2Journal {
  return classified("configuration_invalid", () => {
    let genesisID: string;
    try {
      genesisID = keyIDV2(genesisKey);
    } catch (err) {
      throw v2Errorf("configuration_invalid", `rotation genesis key: ${(err as Error).message}`, err);
    }
    if (typeof authorityID !== "string" || authorityID.length !== 32 || !lowerHexString(authorityID) ||
        !(recoveryEpoch > 0) || recoveryEpoch > MAX_SAFE || !Number.isInteger(recoveryEpoch)) {
      throw v2Errorf("configuration_invalid", "rotation authority or recovery epoch is invalid");
    }
    if (!ROLES.has(role)) throw v2Errorf("configuration_invalid", "rotation role is invalid");
    return {
      state: {
        authorityID, recoveryEpoch, role, sequence: 0, headHash: new Uint8Array(48),
        currentKey: cloneHybridPublicKey(genesisKey), usedKeyIDs: [genesisID],
      },
      accepted: [],
      frozen: false,
    };
  });
}

function cloneJournal(j: KeyRotationV2Journal): KeyRotationV2Journal {
  return {
    state: {
      ...j.state,
      headHash: Uint8Array.from(j.state.headHash),
      currentKey: cloneHybridPublicKey(j.state.currentKey),
      usedKeyIDs: [...j.state.usedKeyIDs],
    },
    accepted: j.accepted.map((e) => ({ sequence: e.sequence, bodyDigest: Uint8Array.from(e.bodyDigest), oldKey: cloneHybridPublicKey(e.oldKey) })),
    frozen: j.frozen,
  };
}

export interface KeyRotationV2AcceptOutcome {
  journal: KeyRotationV2Journal;
  result?: V2AppendResult;
  error?: Error;
}

/**
 * AcceptRotation (SPEC-v2 §5.4). Returns appended with the advanced journal,
 * replay with the unchanged journal for an accepted body digest, or an error.
 * A validly signed different body at an accepted sequence returns
 * rotation_fork with a frozen journal the caller must persist. Any other
 * error leaves the journal unchanged.
 */
export async function acceptKeyRotationStatementV2(
  s: KeyRotationStatementV2,
  journal: KeyRotationV2Journal,
  nowUnix: number,
  futureSkew: number,
): Promise<KeyRotationV2AcceptOutcome> {
  const fail = (error: Error, j = journal): KeyRotationV2AcceptOutcome => ({ journal: j, error: v2Classify("rotation_state_mismatch", error) });
  try {
    validateKeyRotationStatementV2(s, true);
  } catch (err) {
    return fail(v2Classify("malformed", err));
  }
  if (journal.accepted.length !== journal.state.sequence) {
    return fail(v2Errorf("configuration_invalid", "rotation journal accepted history does not match its sequence"));
  }
  if (journal.frozen) {
    return fail(wrapError(ErrKeyRotationFrozenV2.message, ErrKeyRotationFrozenV2));
  }
  const state = journal.state;
  if (s.authority_id !== state.authorityID || s.recovery_epoch !== state.recoveryEpoch || s.role !== state.role) {
    return fail(v2Errorf("rotation_state_mismatch", "rotation statement authority, recovery epoch, or role does not match caller state"));
  }
  if (s.sequence <= state.sequence) {
    const accepted = journal.accepted[s.sequence - 1]!;
    if (accepted.sequence !== s.sequence || !equalHybridPublicKeys(s.old_key, accepted.oldKey)) {
      return fail(v2Errorf("rotation_state_mismatch", `rotation statement old key does not match the key accepted at sequence ${s.sequence}`));
    }
    let signable: Uint8Array;
    try {
      signable = keyRotationStatementV2SignBytes(s);
    } catch (err) {
      return fail(v2Classify("malformed", err));
    }
    try {
      await verifyV2Statement(V2_OBJECT_TYPE.keyRotationAuthorization, signable, s.old_signature, accepted.oldKey);
    } catch (err) {
      return fail(wrapError("old-key rotation authorization", err));
    }
    try {
      await verifyV2Statement(V2_OBJECT_TYPE.keyRotationProofOfPossession, signable, s.new_signature, s.new_key);
    } catch (err) {
      return fail(wrapError("new-key proof of possession", err));
    }
    let digest: Uint8Array;
    try {
      digest = statementBodyDigestV2(V2_OBJECT_TYPE.keyRotationAuthorization, signable);
    } catch (err) {
      return fail(v2Classify("malformed", err));
    }
    if (bytesEqual(digest, accepted.bodyDigest)) return { journal, result: "replay" };
    const frozen = cloneJournal(journal);
    frozen.frozen = true;
    return fail(wrapError(`key rotation fork at sequence ${s.sequence} for authority ${state.authorityID}`, ErrKeyRotationForkV2), frozen);
  }
  try {
    await verifyKeyRotationStatementV2(s, state, nowUnix, futureSkew);
  } catch (err) {
    return fail(err as Error);
  }
  let digest: Uint8Array;
  try {
    digest = keyRotationStatementV2Digest(s);
  } catch (err) {
    return fail(v2Classify("malformed", err));
  }
  const next = cloneJournal(journal);
  next.accepted.push({ sequence: s.sequence, bodyDigest: digest, oldKey: cloneHybridPublicKey(s.old_key) });
  next.state.sequence = s.sequence;
  next.state.headHash = Uint8Array.from(digest);
  next.state.currentKey = cloneHybridPublicKey(s.new_key);
  next.state.usedKeyIDs.push(s.new_key_id);
  return { journal: next, result: "appended" };
}

/**
 * Applies a root-authorized recovery from the caller's control plane: the
 * recovery epoch increases, a never-used key becomes genesis, and the full
 * used-key history is preserved.
 */
export function recoverKeyRotationV2(journal: KeyRotationV2Journal, newRecoveryEpoch: number, newGenesisKey: HybridPublicKey): KeyRotationV2Journal {
  return classified("rotation_recovery_invalid", () => {
    let newID: string;
    try {
      newID = keyIDV2(newGenesisKey);
    } catch (err) {
      throw v2Errorf("rotation_recovery_invalid", `recovery genesis key: ${(err as Error).message}`, err);
    }
    if (!(newRecoveryEpoch > journal.state.recoveryEpoch) || newRecoveryEpoch > MAX_SAFE) {
      throw v2Errorf("rotation_recovery_invalid", "rotation recovery must increase the recovery epoch");
    }
    if (journal.state.usedKeyIDs.includes(newID)) {
      throw v2Errorf("rotation_recovery_invalid", "rotation recovery cannot anchor a previously used key");
    }
    const next = cloneJournal(journal);
    next.state.recoveryEpoch = newRecoveryEpoch;
    next.state.sequence = 0;
    next.state.headHash = new Uint8Array(48);
    next.state.currentKey = cloneHybridPublicKey(newGenesisKey);
    next.state.usedKeyIDs.push(newID);
    next.accepted = [];
    next.frozen = false;
    return next;
  });
}
