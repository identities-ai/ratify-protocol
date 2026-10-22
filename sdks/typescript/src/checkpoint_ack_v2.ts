// Independent checkpoint acknowledgement wire codec (SPEC-v2 §7.8; Go
// checkpoint_ack_v2.go):
// {"entry_hash":<base64 of 48 bytes>,"log_id":<32 lowercase hex>,"sequence":<integer>,"timestamp":<integer>}.

import { validV2Timestamp } from "./clock_bounds_v2.js";
import { classified, v2Classify } from "./errors_v2.js";
import {
  MAX_SAFE_INTEGER_V2,
  base64DecodeCanonical,
  base64Encode,
  bytesEqual,
  canonicalJSONV2,
  checkWireJSONV2,
  gInt,
  gString,
  gStruct,
  requireV2Fields,
} from "./json_v2.js";
import { checkV2WireSize } from "./limits_v2.js";
import { lowerHexString } from "./protocol_v2_wire.js";

/** Bounds one encoded checkpoint acknowledgement. */
export const MAX_CHECKPOINT_ACKNOWLEDGEMENT_BYTES_V2 = 1024;

/** One immutable acknowledgement of a receipt-log entry. */
export interface V2CheckpointAcknowledgement {
  logID: string;
  sequence: number;
  /** StatementBodyDigest(0x0008, receipt signable body), 48 bytes. */
  entryHash: Uint8Array;
  timestamp: number;
}

const ACK_FIELDS = ["entry_hash", "log_id", "sequence", "timestamp"];

function validateV2CheckpointAcknowledgement(ack: V2CheckpointAcknowledgement): void {
  if (!ack || typeof ack.logID !== "string" || ack.logID.length !== 32 || !lowerHexString(ack.logID) ||
      !Number.isSafeInteger(ack.sequence) || ack.sequence < 1 || ack.sequence > MAX_SAFE_INTEGER_V2 ||
      !(ack.entryHash instanceof Uint8Array) || ack.entryHash.length !== 48 || !validV2Timestamp(ack.timestamp)) {
    throw new Error("wire v2: checkpoint acknowledgement log_id, sequence, entry_hash, or timestamp is invalid");
  }
}

/** The canonical wire form of an acknowledgement; malformed class on invalid input. */
export function encodeV2CheckpointAcknowledgement(ack: V2CheckpointAcknowledgement): Uint8Array {
  try {
    validateV2CheckpointAcknowledgement(ack);
  } catch (err) {
    throw v2Classify("malformed", err);
  }
  return canonicalJSONV2({ entry_hash: base64Encode(ack.entryHash), log_id: ack.logID, sequence: ack.sequence, timestamp: ack.timestamp });
}

/** Strict decode accepting only the canonical encoding (malformed otherwise). */
export function decodeV2CheckpointAcknowledgement(data: Uint8Array): V2CheckpointAcknowledgement {
  return classified("malformed", () => {
    checkV2WireSize(data, "checkpoint acknowledgement", "MAX_CHECKPOINT_ACKNOWLEDGEMENT_BYTES_V2", MAX_CHECKPOINT_ACKNOWLEDGEMENT_BYTES_V2);
    const root = checkWireJSONV2(data, ["entry_hash"]);
    requireV2Fields(root, ACK_FIELDS);
    const f = gStruct(root, ACK_FIELDS, "checkpoint acknowledgement");
    const hash = base64DecodeCanonical(gString(f.get("entry_hash"), "entry_hash"));
    if (hash === null) throw new Error("wire v2: checkpoint acknowledgement entry_hash is not canonical base64");
    const ack: V2CheckpointAcknowledgement = {
      logID: gString(f.get("log_id"), "log_id"),
      sequence: gInt(f.get("sequence"), "sequence"),
      entryHash: hash,
      timestamp: gInt(f.get("timestamp"), "timestamp"),
    };
    const canonical = encodeV2CheckpointAcknowledgement(ack);
    if (!bytesEqual(canonical, data)) throw new Error("wire v2: checkpoint acknowledgement is not canonically encoded");
    return ack;
  });
}
