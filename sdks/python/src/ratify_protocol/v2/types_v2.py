"""Plain Protocol v2 value types shared by several modules.

Go declares these next to their main users (``StatusEvidenceEntryV2`` in
status_state_v2.go, ``ConstraintEvaluatorRefV2`` in
constraint_evaluator_v2.go, ``V2CheckpointAcknowledgement`` in release_v2.go).
Receipts, status, evaluation and release all need them, so the Python port
declares them once here and the owning modules re-export them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

MAX_SAFE_INTEGER = 2**53 - 1

# Extension evaluator profile bounds (SPEC-v2 §5.2), Go constraint_evaluator_v2.go.
MAX_CONSTRAINT_EVALUATORS_V2 = 32
MAX_EXTENSION_TYPE_BYTES_V2 = 128
MAX_PROFILE_ID_BYTES_V2 = 128

_LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}")
_LOWER_HEX_ANY = re.compile(r"[0-9a-f]*")
_LOWER_HEX_96 = re.compile(r"[0-9a-f]{96}")
_LABEL = re.compile(r"[a-z0-9_-]+")


def is_int(value: object) -> bool:
    """A Python ``int`` that is not a ``bool`` (Go integer typing)."""
    return type(value) is int


def valid_v2_id(value: object) -> bool:
    """Go ``validV2ID``: exactly 64 lowercase hexadecimal characters."""
    return isinstance(value, str) and len(value) == 64 and _LOWER_HEX_64.fullmatch(value) is not None


def lower_hex_string(value: object) -> bool:
    """Go ``lowerHexString``: only lowercase hexadecimal characters."""
    return isinstance(value, str) and _LOWER_HEX_ANY.fullmatch(value) is not None


def valid_prefixed_digest_v2(value: object) -> bool:
    """Go ``validPrefixedDigestV2``: ``sha384:`` and 96 lowercase hex characters."""
    return (
        isinstance(value, str)
        and value.startswith("sha384:")
        and len(value) == 7 + 96
        and _LOWER_HEX_96.fullmatch(value[7:]) is not None
    )


@dataclass(frozen=True)
class StatusEvidenceEntryV2:
    """One authenticated status object a decision relied on (SPEC-v2 §5.8).

    Wire members: ``issuer_id``, ``status_key_id``, ``sequence``,
    ``object_type_code`` (3 or 5), and ``digest`` (``sha384:`` hex of
    StatusEvidenceDigest)."""

    issuer_id: str
    status_key_id: str
    sequence: int
    object_type: int
    digest: str

    def to_canonical_dict(self) -> dict:
        return {
            "digest": self.digest,
            "issuer_id": self.issuer_id,
            "object_type_code": self.object_type,
            "sequence": self.sequence,
            "status_key_id": self.status_key_id,
        }


@dataclass(frozen=True)
class ConstraintEvaluatorRefV2:
    """One entry of a receipt's ``constraint_evaluators`` member and of a
    claim's sealed evaluator snapshot: ``{"profile_digest","type"}``."""

    profile_digest: str
    type: str

    def to_canonical_dict(self) -> dict:
        return {"profile_digest": self.profile_digest, "type": self.type}


def valid_extension_type_v2(t: object) -> bool:
    """Go ``validExtensionTypeV2``: 3 to 128 bytes of at least three
    '.'-separated labels of [a-z0-9_-], not in the reserved ``ratify.``
    namespace."""
    if not isinstance(t, str):
        return False
    raw = t.encode("utf-8", "surrogatepass")
    if len(raw) == 0 or len(raw) > MAX_EXTENSION_TYPE_BYTES_V2 or t.startswith("ratify."):
        return False
    labels = t.split(".")
    if len(labels) < 3:
        return False
    return all(label != "" and _LABEL.fullmatch(label) is not None for label in labels)


def valid_profile_id_v2(profile_id: object) -> bool:
    """Go ``validProfileIDV2``: ``<name>/v<n>``, at most 128 bytes, name is
    '.'-separated labels of [a-z0-9_-], n a positive integer without leading
    zeros."""
    if not isinstance(profile_id, str):
        return False
    if len(profile_id.encode("utf-8", "surrogatepass")) > MAX_PROFILE_ID_BYTES_V2:
        return False
    name, sep, version = profile_id.partition("/v")
    if not sep or name == "" or version == "" or version[0] == "0" or "/" in version:
        return False
    if not all("0" <= c <= "9" for c in version):
        return False
    return all(label != "" and _LABEL.fullmatch(label) is not None for label in name.split("."))


def valid_constraint_evaluator_refs_v2(refs: Optional[list]) -> bool:
    """Go ``validConstraintEvaluatorRefsV2``: at most 32 entries, each a
    registrable type with a ``sha384:`` digest, strictly sorted by type."""
    if refs is None:
        return True
    if len(refs) > MAX_CONSTRAINT_EVALUATORS_V2:
        return False
    previous: Optional[bytes] = None
    for ref in refs:
        if not isinstance(ref, ConstraintEvaluatorRefV2):
            return False
        if not valid_extension_type_v2(ref.type) or not valid_prefixed_digest_v2(ref.profile_digest):
            return False
        current = ref.type.encode("utf-8")
        if previous is not None and previous >= current:
            return False
        previous = current
    return True


def clone_constraint_evaluator_refs_v2(refs: Optional[list]) -> Optional[list]:
    """Go ``cloneConstraintEvaluatorRefsV2``: ``None`` for an empty list."""
    if not refs:
        return None
    return list(refs)


@dataclass(frozen=True)
class V2CheckpointAcknowledgement:
    """An independent checkpoint's acknowledgement of one receipt-log entry
    (SPEC-v2 §7.8). ``entry_hash`` is StatementBodyDigest(0x0008, receipt
    signable body); ``timestamp`` is immutable."""

    log_id: str
    sequence: int
    entry_hash: bytes
    timestamp: int
