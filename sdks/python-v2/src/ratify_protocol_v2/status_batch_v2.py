"""Status evidence batch wire form (Go status_batch_v2.go, SPEC-v2 §6.5).

A status provider that crosses a process or language boundary returns::

    [{"object":<complete signed RevocationList or RevocationPush>,"object_type_code":3|5}, ...]

with at most 64 entries and at most 8388608 encoded bytes. Each entry has
exactly these two members; the batch may be empty. A decoder accepts any
strict JSON spelling and keeps each object's exact received bytes, which the
verifier then decodes and authenticates under the object's own limits. The
canonical encoding sorts each entry's members and re-encodes each object.

``V2StatusEvidenceObject`` and ``V2StatusEvidenceBatch`` (declared in Go
status_provenance_v2.go) are defined here so the codec and the status
provenance stage share one type.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import _v2json
from .errors_v2 import V2Error, V2ErrorClass, classify, classified
from .limits_v2 import MAX_STATUS_EVIDENCE_BATCH_BYTES_V2, MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2, check_v2_wire_size
from .protocol_v2 import (
    decode_revocation_list_v2,
    decode_revocation_push_v2,
    encode_revocation_list_v2,
    encode_revocation_push_v2,
)
from .signing_v2 import REVOCATION_LIST, REVOCATION_PUSH


@dataclass(frozen=True)
class V2StatusEvidenceObject:
    """One signed status object exactly as received. ``object_type`` is
    0x0003 (revocation list) or 0x0005 (revocation push)."""

    object_type: int
    wire: bytes


@dataclass(frozen=True)
class V2StatusEvidenceBatch:
    """A provider's bounded response for one issuer. An empty batch is
    valid: the result then comes from retained journal state."""

    objects: tuple = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "objects", tuple(self.objects))


@classified(V2ErrorClass.MALFORMED)
def encode_v2_status_evidence_batch(batch: V2StatusEvidenceBatch) -> bytes:
    """Go ``EncodeV2StatusEvidenceBatch``: the canonical encoding. Every
    object must decode strictly under its code."""
    if not isinstance(batch, V2StatusEvidenceBatch):
        raise V2Error(V2ErrorClass.MALFORMED, "v2 status batch is required")
    if len(batch.objects) > MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2:
        raise V2Error(V2ErrorClass.MALFORMED, f"v2 status batch exceeds {MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2} objects")
    parts = []
    for obj in batch.objects:
        try:
            if not isinstance(obj, V2StatusEvidenceObject):
                raise ValueError("v2 status batch entries must be V2StatusEvidenceObject")
            if obj.object_type == REVOCATION_LIST and type(obj.object_type) is int:
                canonical = encode_revocation_list_v2(decode_revocation_list_v2(bytes(obj.wire)))
            elif obj.object_type == REVOCATION_PUSH and type(obj.object_type) is int:
                canonical = encode_revocation_push_v2(decode_revocation_push_v2(bytes(obj.wire)))
            else:
                raise ValueError(f"v2 status batch object type {obj.object_type!r} is not 3 or 5")
        except (ValueError, TypeError, V2Error) as exc:
            raise classify(V2ErrorClass.MALFORMED, exc) from exc
        parts.append(b'{"object":' + canonical + b',"object_type_code":' + str(obj.object_type).encode() + b"}")
    out = b"[" + b",".join(parts) + b"]"
    if len(out) > MAX_STATUS_EVIDENCE_BATCH_BYTES_V2:
        raise V2Error(V2ErrorClass.MALFORMED, f"v2 status batch exceeds {MAX_STATUS_EVIDENCE_BATCH_BYTES_V2} bytes")
    return out


def decode_v2_status_evidence_batch(data: bytes) -> V2StatusEvidenceBatch:
    """Go ``DecodeV2StatusEvidenceBatch``: strict, bounded, and
    unauthenticated. Every failure is ``malformed``."""
    try:
        check_v2_wire_size(data, "status evidence batch", "MAX_STATUS_EVIDENCE_BATCH_BYTES_V2",
                           MAX_STATUS_EVIDENCE_BATCH_BYTES_V2)
        value = _v2json.check_wire_json(data)
        if not isinstance(value, list) or not all(e is None or isinstance(e, dict) for e in value):
            raise ValueError("wire v2: status evidence batch must be a JSON array of objects")
        if len(value) > MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2:
            raise ValueError(f"wire v2: status evidence batch exceeds {MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2} objects")
        text = bytes(data).decode("utf-8")
        spans = _v2json.raw_array_spans(text, 0)
        objects = []
        for entry, span in zip(value, spans):
            entry = {} if entry is None else entry
            if len(entry) != 2 or "object_type_code" not in entry or "object" not in entry:
                raise ValueError("wire v2: status evidence entry must have exactly object and object_type_code")
            code = entry["object_type_code"]
            if type(code) is not int or code not in (3, 5):
                raise ValueError("wire v2: status evidence object_type_code must be 3 or 5")
            if not isinstance(entry["object"], dict):
                raise ValueError("wire v2: status evidence object must be a JSON object")
            start, end = _v2json.raw_member_spans(text, span[0])["object"]
            objects.append(V2StatusEvidenceObject(object_type=code, wire=text[start:end].encode("utf-8")))
        return V2StatusEvidenceBatch(objects=tuple(objects))
    except V2Error as exc:
        raise classify(V2ErrorClass.MALFORMED, exc) from exc
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        raise classify(V2ErrorClass.MALFORMED, exc) from exc


def v2_status_evidence_batch_encoded_length(batch: V2StatusEvidenceBatch) -> int:
    """Go ``v2StatusEvidenceBatchEncodedLength``: the length of the batch wire
    form carrying each object's bytes exactly as received."""
    total = 2
    for i, obj in enumerate(batch.objects):
        if i > 0:
            total += 1
        total += len('{"object":') + len(obj.wire) + len(',"object_type_code":') + len(str(obj.object_type)) + 1
    return total
