"""Protocol v2 witness entries and the shared statement-body digest
(mirrors Go witness_v2.go and StatementBodyDigestV2)."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import IntEnum
from hashlib import sha384
from typing import Optional

from . import _v2json
from ._v2json import MAX_SAFE_INTEGER, canonical
from .errors_v2 import (
    V2Error,
    V2ErrorClass,
    WitnessLogForkError,
    WitnessLogFrozenError,
    WitnessLogGapError,
    WitnessLogOrphanError,
)
from .protocol_v2 import (
    _run,
    check_keys,
    decode_signature,
    get_bytes,
    get_int,
    get_str,
    key_dict,
    lower_hex_string,
    require_fields,
    valid_v2_id,
    validate_hybrid_signature_v2,
)
from .clock_bounds_v2 import valid_v2_timestamp
from .context_v2 import Context, background
from .limits_v2 import MAX_WITNESS_ENTRY_BYTES_V2, MAX_WITNESS_ENTRY_DATA_BYTES_V2, check_v2_wire_size
from .signing_v2 import (
    KEY_ROTATION_AUTHORIZATION,
    VERIFICATION_RECEIPT,
    WITNESS_ENTRY,
    SignerV2,
    V2SigningError,
    _as_signer,
    key_id_v2,
    sign_v2_statement_with_signer,
    signer_public_key_v2,
    verify_v2_statement,
)
from .types import HybridPrivateKey, HybridPublicKey, HybridSignature


class WitnessEntryV2Result(IntEnum):
    APPENDED = 1
    REPLAY = 2


ZERO_HASH = bytes(48)


@dataclass
class WitnessEntryV2:
    version: int
    log_id: str
    sequence: int
    prev_hash: bytes
    entry_data: Optional[bytes]
    timestamp: int
    witness_id: str
    signature: HybridSignature


@dataclass
class WitnessV2Head:
    """Caller-authenticated log state; ``accepted_digests`` maps every
    accepted sequence to its body digest."""
    log_id: str
    sequence: int = 0
    head_hash: bytes = ZERO_HASH
    accepted_digests: dict[int, bytes] = field(default_factory=dict)
    frozen: bool = False


WITNESS_ENTRY_V2_FIELDS = ("version", "log_id", "sequence", "prev_hash", "entry_data", "timestamp", "witness_id", "signature")
_WITNESS_SIGNABLE_FIELDS = ("entry_data", "log_id", "prev_hash", "sequence", "timestamp", "version", "witness_id")


def validate_witness_entry_v2(entry: WitnessEntryV2, signature: bool) -> None:
    if not isinstance(entry, WitnessEntryV2) or entry.version != 2:
        raise ValueError("wire v2: witness entry version must be 2")
    if len(entry.log_id) != 32 or not lower_hex_string(entry.log_id):
        raise ValueError("wire v2: log_id must be 32 lowercase hexadecimal characters")
    if type(entry.sequence) is not int or entry.sequence <= 0 or entry.sequence > MAX_SAFE_INTEGER or not valid_v2_timestamp(entry.timestamp):
        raise ValueError("wire v2: sequence and timestamp must be safe integers")
    if len(entry.prev_hash or b"") != 48:
        raise ValueError("wire v2: prev_hash must be 48 bytes")
    if entry.entry_data is None:
        raise ValueError("wire v2: entry_data must be a base64 byte string, not null")
    if len(entry.entry_data) > MAX_WITNESS_ENTRY_DATA_BYTES_V2:
        raise ValueError(f"wire v2: entry_data exceeds MAX_WITNESS_ENTRY_DATA_BYTES_V2 ({MAX_WITNESS_ENTRY_DATA_BYTES_V2} bytes)")
    if entry.sequence == 1 and bytes(entry.prev_hash) != ZERO_HASH:
        raise ValueError("wire v2: genesis witness entry must use a zero prev_hash")
    if entry.sequence > 1 and bytes(entry.prev_hash) == ZERO_HASH:
        raise ValueError("wire v2: non-genesis witness entry must link to a prior entry")
    if not valid_v2_id(entry.witness_id):
        raise ValueError("wire v2: witness_id must be a 64-character lowercase hexadecimal v2 key ID")
    if signature:
        validate_hybrid_signature_v2(entry.signature)


def _witness_signable_dict(entry: WitnessEntryV2) -> dict:
    return {
        "entry_data": entry.entry_data, "log_id": entry.log_id, "prev_hash": bytes(entry.prev_hash),
        "sequence": entry.sequence, "timestamp": entry.timestamp, "version": entry.version,
        "witness_id": entry.witness_id,
    }


def witness_entry_signable_bytes_v2(entry: WitnessEntryV2) -> bytes:
    validate_witness_entry_v2(entry, False)
    return canonical(_witness_signable_dict(entry))


def _witness_from_obj(obj: dict, allowed) -> WitnessEntryV2:
    check_keys(obj, allowed, "witness entry")
    return WitnessEntryV2(
        version=get_int(obj, "version"), log_id=get_str(obj, "log_id"), sequence=get_int(obj, "sequence"),
        prev_hash=get_bytes(obj, "prev_hash") or b"", entry_data=get_bytes(obj, "entry_data"),
        timestamp=get_int(obj, "timestamp"), witness_id=get_str(obj, "witness_id"),
        signature=decode_signature(obj.get("signature")),
    )


def _validate_witness_signable_body(body: bytes) -> None:
    obj = _v2json.parse(body)
    require_fields(obj, _WITNESS_SIGNABLE_FIELDS)
    entry = _witness_from_obj(obj, _WITNESS_SIGNABLE_FIELDS)
    if canonical(_witness_signable_dict(entry)) != body:
        raise ValueError("witness signable body must use RatifyCanonicalJSON")
    validate_witness_entry_v2(entry, False)


def statement_body_digest_v2(object_type: int, signable_body: bytes) -> bytes:
    """StatementBodyDigestV2 for rotation (0x0004), witness (0x0006), and
    verification-receipt (0x0008) signable bodies; each body is schema-validated."""
    if object_type not in (KEY_ROTATION_AUTHORIZATION, WITNESS_ENTRY, VERIFICATION_RECEIPT):
        raise ValueError(f"object type 0x{object_type:04x} does not use StatementBodyDigestV2")
    if object_type == VERIFICATION_RECEIPT:
        value = _v2json.check_wire_json(signable_body, ("previous_receipt_hash",), ("bundle_hash",))
    else:
        value = _v2json.check_wire_json(
            signable_body, ("previous_statement_hash", "delegation_digest", "previous_receipt_hash")
        )
    if object_type != KEY_ROTATION_AUTHORIZATION:
        if not isinstance(value, dict):
            raise ValueError("signable body must be a JSON object")
        for name in ("signature", "old_signature", "new_signature"):
            if name in value:
                raise ValueError(f"signable body must exclude {name!r}")
    if canonical(value) != signable_body:
        raise ValueError("signable body must use RatifyCanonicalJSON")
    if object_type == KEY_ROTATION_AUTHORIZATION:
        from .key_rotation_v2 import validate_key_rotation_signable_body_v2

        validate_key_rotation_signable_body_v2(signable_body)
    elif object_type == WITNESS_ENTRY:
        _validate_witness_signable_body(signable_body)
    else:
        from .verification_receipt_v2 import validate_verification_receipt_signable_v2

        validate_verification_receipt_signable_v2(signable_body)
    return sha384(
        b"ratify-protocol-statement-body-v2\x00" + object_type.to_bytes(2, "big") + signable_body
    ).digest()


def witness_entry_v2_digest(entry: WitnessEntryV2) -> bytes:
    return statement_body_digest_v2(WITNESS_ENTRY, witness_entry_signable_bytes_v2(entry))


def encode_witness_entry_v2(entry: WitnessEntryV2) -> bytes:
    validate_witness_entry_v2(entry, True)
    wire = canonical({**_witness_signable_dict(entry), "signature": key_dict(entry.signature)})
    check_v2_wire_size(wire, "witness entry", "MAX_WITNESS_ENTRY_BYTES_V2", MAX_WITNESS_ENTRY_BYTES_V2)
    return wire


def decode_witness_entry_v2(data: bytes) -> WitnessEntryV2:
    def run() -> WitnessEntryV2:
        check_v2_wire_size(data, "witness entry", "MAX_WITNESS_ENTRY_BYTES_V2", MAX_WITNESS_ENTRY_BYTES_V2)
        obj = _v2json.check_wire_json(data)
        require_fields(obj, WITNESS_ENTRY_V2_FIELDS)
        entry = _witness_from_obj(obj, WITNESS_ENTRY_V2_FIELDS)
        validate_witness_entry_v2(entry, True)
        try:
            canonical_bytes = encode_witness_entry_v2(entry)
        except ValueError:
            canonical_bytes = None
        if canonical_bytes != data:
            raise ValueError("wire v2: witness entry is not canonical Ratify JSON")
        return entry

    return _run(V2ErrorClass.MALFORMED, run)


def sign_witness_entry_v2(entry: WitnessEntryV2, witness_private: HybridPrivateKey) -> WitnessEntryV2:
    """Go ``SignWitnessEntryV2``: sign the witness body under code 0x0006."""
    return sign_witness_entry_v2_with_signer(background(), entry, _as_signer(witness_private))


def sign_witness_entry_v2_with_signer(ctx: Context, entry: WitnessEntryV2, signer: SignerV2) -> WitnessEntryV2:
    """Go ``SignWitnessEntryV2WithSigner``: the signer's key ID must equal witness_id."""
    validate_witness_entry_v2(entry, False)
    witness_public = signer_public_key_v2(signer)
    if key_id_v2(witness_public) != entry.witness_id:
        raise V2SigningError("witness_id does not match signing key")
    body = witness_entry_signable_bytes_v2(entry)
    signature = sign_v2_statement_with_signer(ctx, WITNESS_ENTRY, body, signer, witness_public)
    result = replace(entry, prev_hash=bytes(entry.prev_hash), entry_data=bytes(entry.entry_data), signature=signature)
    encode_witness_entry_v2(result)
    return result


def _validate_log_head(log_id: str, sequence: int, head_hash: bytes, accepted: dict, label: str) -> None:
    cfg = V2ErrorClass.CONFIGURATION_INVALID
    if not isinstance(log_id, str) or len(log_id) != 32 or not lower_hex_string(log_id) or type(sequence) is not int or sequence < 0 or sequence > MAX_SAFE_INTEGER or len(head_hash) != 48:
        raise V2Error(cfg, f"caller {label} head is invalid")
    if (sequence == 0 and (bytes(head_hash) != ZERO_HASH or len(accepted) != 0)) or (sequence > 0 and bytes(head_hash) == ZERO_HASH):
        raise V2Error(cfg, f"caller {label} head has inconsistent genesis state")
    if sequence > 0 and len(accepted) != sequence:
        raise V2Error(cfg, f"caller {label} head is missing accepted sequence digests")
    if sequence > 0 and accepted.get(sequence) != bytes(head_hash):
        raise V2Error(cfg, f"caller {label} head hash does not match its accepted digest history")
    for seq, digest in accepted.items():
        if seq <= 0 or seq > sequence or len(digest) != 48:
            raise V2Error(cfg, f"caller {label} head contains invalid accepted digest history")


def log_position_result(sequence: int, prev_hash: bytes, digest: bytes, head_sequence: int, head_hash: bytes,
                        accepted: dict, frozen: bool, log_id: str) -> WitnessEntryV2Result:
    """Shared replay / fork / frozen / gap / orphan decision."""
    if sequence <= head_sequence:
        if accepted.get(sequence) == digest:
            return WitnessEntryV2Result.REPLAY
        raise WitnessLogForkError(f"witness log fork at sequence {sequence}; caller must freeze log {log_id}")
    if frozen:
        raise WitnessLogFrozenError()
    if sequence > head_sequence + 1:
        raise WitnessLogGapError(f"witness log sequence gap: got {sequence} after {head_sequence}")
    if sequence != head_sequence + 1 or bytes(prev_hash) != bytes(head_hash):
        raise WitnessLogOrphanError("orphaned witness entry: entry does not link to the current head")
    return WitnessEntryV2Result.APPENDED


def verify_witness_entry_v2(entry: WitnessEntryV2, head: WitnessV2Head, witness_public: HybridPublicKey) -> WitnessEntryV2Result:
    _run(V2ErrorClass.MALFORMED, lambda: validate_witness_entry_v2(entry, True))
    _run(V2ErrorClass.MALFORMED, lambda: encode_witness_entry_v2(entry))
    _validate_log_head(head.log_id, head.sequence, head.head_hash, head.accepted_digests, "witness")
    witness_id = _run(V2ErrorClass.UNCLASSIFIED, lambda: key_id_v2(witness_public))
    if entry.witness_id != witness_id or entry.log_id != head.log_id:
        raise V2Error(V2ErrorClass.LOG_STATE_MISMATCH,
                      "witness entry key or log ID does not match caller-authenticated state")
    body = witness_entry_signable_bytes_v2(entry)
    verify_v2_statement(WITNESS_ENTRY, body, entry.signature, witness_public)
    digest = witness_entry_v2_digest(entry)
    return log_position_result(entry.sequence, entry.prev_hash, digest, head.sequence, head.head_hash,
                               head.accepted_digests, head.frozen, head.log_id)
