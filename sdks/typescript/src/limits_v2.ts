// Protocol v2 per-object wire limits (SPEC-v2 §2.6; Go limits_v2.go). Each
// byte limit bounds the complete encoded object exactly as received,
// including every signature and any insignificant whitespace, and is checked
// before the bytes are parsed. A limit violation is the malformed class.

export const MAX_DELEGATION_CERT_BYTES_V2 = 32 << 10;
export const MAX_PROOF_BUNDLE_BYTES_V2 = 128 << 10;
export const MAX_KEY_ROTATION_STATEMENT_BYTES_V2 = 32 << 10;
export const MAX_REVOCATION_PUSH_BYTES_V2 = 256 << 10;
export const MAX_REVOCATION_PUSH_REFS_V2 = 512;
export const MAX_REVOCATION_LIST_BYTES_V2 = 4 << 20;
export const MAX_REVOCATION_LIST_REFS_V2 = 10000;
export const MAX_WITNESS_ENTRY_BYTES_V2 = 64 << 10;
export const MAX_WITNESS_ENTRY_DATA_BYTES_V2 = 16 << 10;
export const MAX_VERIFICATION_RECEIPT_BYTES_V2 = 64 << 10;
export const MAX_VERIFICATION_RECEIPT_BODY_BYTES_V2 = 64 << 10;
export const MAX_STATUS_EVIDENCE_BATCH_BYTES_V2 = 8 << 20;
export const MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2 = 64;
export const MAX_TRANSACTION_RECEIPT_BYTES_V2 = 5 << 20;

/** The pre-parse size gate shared by every v2 decoder (Go checkV2WireSize). */
export function checkV2WireSize(data: Uint8Array, object: string, limitName: string, limit: number): void {
  if (data.length > limit) {
    throw new Error(`wire v2: ${object} exceeds ${limitName} (${limit} bytes); rejected before parsing`);
  }
}
