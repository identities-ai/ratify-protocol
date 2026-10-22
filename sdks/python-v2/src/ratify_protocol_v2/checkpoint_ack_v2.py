"""Checkpoint acknowledgement wire form (Go checkpoint_ack_v2.go, SPEC-v2 §7.8).

``{"entry_hash":<base64 of 48 bytes>,"log_id":<32 lowercase hex>,
"sequence":<integer>,"timestamp":<integer>}``; only the canonical encoding
decodes.
"""
from __future__ import annotations

import base64
import binascii

from . import _v2json
from .clock_bounds_v2 import valid_v2_timestamp
from .errors_v2 import V2Error, V2ErrorClass, classified
from .limits_v2 import MAX_CHECKPOINT_ACKNOWLEDGEMENT_BYTES_V2, check_v2_wire_size
from .protocol_v2 import _run, check_keys, get_int, get_str, require_fields
from .types_v2 import MAX_SAFE_INTEGER, V2CheckpointAcknowledgement, lower_hex_string

CHECKPOINT_ACKNOWLEDGEMENT_V2_FIELDS = ("entry_hash", "log_id", "sequence", "timestamp")


def validate_v2_checkpoint_acknowledgement(ack: V2CheckpointAcknowledgement) -> None:
    """Go ``validateV2CheckpointAcknowledgement``. Raises ``ValueError``."""
    if (
        not isinstance(ack, V2CheckpointAcknowledgement) or not isinstance(ack.log_id, str)
        or len(ack.log_id) != 32 or not lower_hex_string(ack.log_id)
        or type(ack.sequence) is not int or ack.sequence < 1 or ack.sequence > MAX_SAFE_INTEGER
        or not isinstance(ack.entry_hash, (bytes, bytearray)) or len(ack.entry_hash) != 48
        or not valid_v2_timestamp(ack.timestamp)
    ):
        raise ValueError("wire v2: checkpoint acknowledgement log_id, sequence, entry_hash, or timestamp is invalid")


@classified(V2ErrorClass.MALFORMED)
def encode_v2_checkpoint_acknowledgement(ack: V2CheckpointAcknowledgement) -> bytes:
    """Go ``EncodeV2CheckpointAcknowledgement``: the canonical wire form."""
    _run(V2ErrorClass.MALFORMED, lambda: validate_v2_checkpoint_acknowledgement(ack))
    return _v2json.canonical({
        "entry_hash": base64.b64encode(bytes(ack.entry_hash)).decode("ascii"),
        "log_id": ack.log_id,
        "sequence": ack.sequence,
        "timestamp": ack.timestamp,
    })


def decode_v2_checkpoint_acknowledgement(data: bytes) -> V2CheckpointAcknowledgement:
    """Go ``DecodeV2CheckpointAcknowledgement``: strict and canonical only."""

    def run() -> V2CheckpointAcknowledgement:
        check_v2_wire_size(data, "checkpoint acknowledgement", "MAX_CHECKPOINT_ACKNOWLEDGEMENT_BYTES_V2",
                           MAX_CHECKPOINT_ACKNOWLEDGEMENT_BYTES_V2)
        obj = _v2json.check_wire_json(data, ("entry_hash",))
        require_fields(obj, CHECKPOINT_ACKNOWLEDGEMENT_V2_FIELDS)
        check_keys(obj, CHECKPOINT_ACKNOWLEDGEMENT_V2_FIELDS, "checkpoint acknowledgement")
        try:
            entry_hash = base64.b64decode(get_str(obj, "entry_hash"), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("wire v2: checkpoint acknowledgement entry_hash is not canonical base64") from exc
        ack = V2CheckpointAcknowledgement(log_id=get_str(obj, "log_id"), sequence=get_int(obj, "sequence"),
                                          entry_hash=entry_hash, timestamp=get_int(obj, "timestamp"))
        if encode_v2_checkpoint_acknowledgement(ack) != bytes(data):
            raise ValueError("wire v2: checkpoint acknowledgement is not canonically encoded")
        return ack

    return _run(V2ErrorClass.MALFORMED, run)


__all__ = [
    "V2CheckpointAcknowledgement", "V2Error", "decode_v2_checkpoint_acknowledgement",
    "encode_v2_checkpoint_acknowledgement", "validate_v2_checkpoint_acknowledgement",
]
