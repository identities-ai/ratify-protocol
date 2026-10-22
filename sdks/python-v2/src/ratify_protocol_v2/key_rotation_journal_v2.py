"""The AcceptRotation journal of SPEC-v2 §5.5 (Go key_rotation_journal_v2.go).

The implementation lives in :mod:`ratify_protocol_v2.key_rotation_v2` next to
the statement codec; this module is its Go-file-named entry point.
"""
from __future__ import annotations

from .errors_v2 import KeyRotationForkError, KeyRotationFrozenError
from .key_rotation_v2 import (
    KeyRotationV2AcceptedEntry,
    KeyRotationV2Journal,
    KeyRotationV2State,
    accept_key_rotation_statement_v2,
    new_key_rotation_v2_journal,
    recover_key_rotation_v2,
)

__all__ = [
    "KeyRotationForkError", "KeyRotationFrozenError", "KeyRotationV2AcceptedEntry", "KeyRotationV2Journal",
    "KeyRotationV2State", "accept_key_rotation_statement_v2", "new_key_rotation_v2_journal", "recover_key_rotation_v2",
]
