// Status evidence batch wire form (SPEC-v2 §6.5 step 3; Go status_batch_v2.go):
//
//   [{"object":<complete signed RevocationList or RevocationPush>,"object_type_code":3|5}, ...]
//
// with at most 64 entries and at most 8388608 encoded bytes. Each entry has
// exactly these two members; the batch may be empty. The canonical encoding
// re-encodes each object canonically; a decoder accepts any strict JSON
// spelling and keeps each object's exact received bytes, which the verifier
// then decodes and authenticates under the object's own limits.

import { v2Classify, v2Errorf } from "./errors_v2.js";
import { checkWireJSONV2, concatBytes, utf8, type JNode } from "./json_v2.js";
import { MAX_STATUS_EVIDENCE_BATCH_BYTES_V2, MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2, checkV2WireSize } from "./limits_v2.js";
import { decodeRevocationListV2, decodeRevocationPushV2, encodeRevocationListV2, encodeRevocationPushV2 } from "./protocol_v2_wire.js";

/** One signed status object exactly as received. objectType is 3 (list) or 5 (push). */
export interface V2StatusEvidenceObject {
  objectType: number;
  wire: Uint8Array;
}

/** A provider's bounded response for one issuer. An empty batch is valid. */
export interface V2StatusEvidenceBatch {
  objects: V2StatusEvidenceObject[];
}

/** The canonical JSON encoding of a batch. Every object must decode strictly under its code. */
export function encodeV2StatusEvidenceBatch(batch: V2StatusEvidenceBatch): Uint8Array {
  const objects = batch?.objects ?? [];
  if (objects.length > MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2) {
    throw v2Errorf("malformed", `v2 status batch exceeds ${MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2} objects`);
  }
  const parts: Uint8Array[] = [utf8("[")];
  objects.forEach((object, i) => {
    let canonical: Uint8Array;
    try {
      if (object.objectType === 3) canonical = encodeRevocationListV2(decodeRevocationListV2(object.wire));
      else if (object.objectType === 5) canonical = encodeRevocationPushV2(decodeRevocationPushV2(object.wire));
      else throw new Error(`v2 status batch object type 0x${object.objectType.toString(16).padStart(4, "0")} is not 3 or 5`);
    } catch (err) {
      throw v2Classify("malformed", err);
    }
    if (i > 0) parts.push(utf8(","));
    parts.push(utf8('{"object":'), canonical, utf8(`,"object_type_code":${object.objectType}}`));
  });
  parts.push(utf8("]"));
  const out = concatBytes(...parts);
  if (out.length > MAX_STATUS_EVIDENCE_BATCH_BYTES_V2) {
    throw v2Errorf("malformed", `v2 status batch exceeds ${MAX_STATUS_EVIDENCE_BATCH_BYTES_V2} bytes`);
  }
  return out;
}

/**
 * Strictly decodes a status evidence batch. The byte limit is checked
 * before parsing; any violation is malformed. It does not authenticate.
 */
export function decodeV2StatusEvidenceBatch(data: Uint8Array): V2StatusEvidenceBatch {
  try {
    checkV2WireSize(data, "status evidence batch", "MAX_STATUS_EVIDENCE_BATCH_BYTES_V2", MAX_STATUS_EVIDENCE_BATCH_BYTES_V2);
    const root = checkWireJSONV2(data);
    if (root.k !== "arr") throw new Error("wire v2: status evidence batch must be a JSON array of objects");
    for (const entry of root.a) {
      if (entry.k !== "obj" && entry.k !== "null") throw new Error("wire v2: status evidence batch must be a JSON array of objects");
    }
    if (root.a.length > MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2) {
      throw new Error(`wire v2: status evidence batch exceeds ${MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2} objects`);
    }
    const objects: V2StatusEvidenceObject[] = [];
    for (const entry of root.a) {
      const m = entry.k === "obj" ? entry.m : new Map<string, JNode>();
      const code = m.get("object_type_code");
      const object = m.get("object");
      if (m.size !== 2 || code === undefined || object === undefined) {
        throw new Error("wire v2: status evidence entry must have exactly object and object_type_code");
      }
      const token = code.k === "num" ? code.raw : "";
      if (token !== "3" && token !== "5") throw new Error("wire v2: status evidence object_type_code must be 3 or 5");
      if (object.k !== "obj") throw new Error("wire v2: status evidence object must be a JSON object");
      objects.push({ objectType: Number(token), wire: Uint8Array.from(data.subarray(object.s, object.e)) });
    }
    return { objects };
  } catch (err) {
    throw v2Classify("malformed", err);
  }
}

/**
 * The length of the batch wire form carrying each object's bytes exactly as
 * received: what the byte limit bounds for a batch handed over as values.
 */
export function v2StatusEvidenceBatchEncodedLength(batch: V2StatusEvidenceBatch): number {
  let total = 2;
  (batch?.objects ?? []).forEach((object, i) => {
    if (i > 0) total++;
    total += '{"object":'.length + object.wire.length + ',"object_type_code":'.length + String(object.objectType).length + 1;
  });
  return total;
}
