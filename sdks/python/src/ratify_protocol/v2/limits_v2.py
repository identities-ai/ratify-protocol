"""Protocol v2 per-object wire limits (Go limits_v2.go, SPEC-v2 §2.6).

Each byte limit bounds the complete encoded object exactly as received,
including every signature and any insignificant whitespace, and is checked
before the bytes are parsed. A violation is the ``malformed`` class.
"""
from __future__ import annotations

MAX_DELEGATION_CERT_BYTES_V2 = 32 << 10
MAX_PROOF_BUNDLE_BYTES_V2 = 128 << 10
MAX_KEY_ROTATION_STATEMENT_BYTES_V2 = 32 << 10
MAX_REVOCATION_PUSH_BYTES_V2 = 256 << 10
MAX_REVOCATION_PUSH_REFS_V2 = 512
MAX_REVOCATION_LIST_BYTES_V2 = 4 << 20
MAX_REVOCATION_LIST_REFS_V2 = 10000
MAX_WITNESS_ENTRY_BYTES_V2 = 64 << 10
MAX_WITNESS_ENTRY_DATA_BYTES_V2 = 16 << 10
MAX_VERIFICATION_RECEIPT_BYTES_V2 = 64 << 10
MAX_VERIFICATION_RECEIPT_BODY_BYTES_V2 = 64 << 10
MAX_STATUS_EVIDENCE_BATCH_BYTES_V2 = 8 << 20
MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2 = 64
MAX_TRANSACTION_RECEIPT_BYTES = 5 << 20
MAX_TRANSACTION_PARTIES = 32
MAX_TRANSACTION_RECEIPT_BYTES_V2 = MAX_TRANSACTION_RECEIPT_BYTES
MAX_CHECKPOINT_ACKNOWLEDGEMENT_BYTES_V2 = 1024

# Limits shared with v1 (SPEC-v2 §2.6).
MAX_DELEGATION_CHAIN_DEPTH = 8
MAX_SCOPES_PER_CERT = 128
MAX_SCOPE_LENGTH_BYTES = 256
MAX_CONSTRAINTS_PER_CERT = 32
MAX_IDENTIFIER_LENGTH_BYTES = 512
MAX_JSON_NESTING_DEPTH = 16


def check_v2_wire_size(data: object, obj: str, limit_name: str, limit: int) -> None:
    """Go ``checkV2WireSize``: the pre-parse size gate shared by every decoder.
    Raises ``ValueError`` (classified malformed by decoders) for non-bytes
    input or input longer than ``limit``."""
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError(f"wire v2: {obj} must be bytes")
    if len(data) > limit:
        raise ValueError(f"wire v2: {obj} exceeds {limit_name} ({limit} bytes); rejected before parsing")
