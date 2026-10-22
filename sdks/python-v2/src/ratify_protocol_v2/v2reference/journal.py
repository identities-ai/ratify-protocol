"""Reference anchored SecurityJournalV2 store (Go v2reference/journal.go).

TEST/REFERENCE ONLY: it persists the canonical snapshot bytes and an anchored
head and advances both under one lock by compare-and-swap. An in-process
anchor is not an independent, rollback-resistant head.
"""
from __future__ import annotations

import threading

from ..context_v2 import Context
from ..security_journal_snapshot_v2 import export_security_journal_snapshot_v2, import_security_journal_snapshot_v2
from ..security_journal_v2 import (
    SecurityJournalConflictV2,
    SecurityJournalHeadV2,
    SecurityJournalV2,
    empty_security_journal_v2,
    validate_security_journal_transition_v2,
)


class JournalStore:
    """In-memory anchored journal store, anchored at genesis."""

    def __init__(self) -> None:
        genesis = empty_security_journal_v2()
        self._lock = threading.Lock()
        self._snapshot = export_security_journal_snapshot_v2(genesis)
        self._head = SecurityJournalHeadV2(generation=genesis.generation, digest=genesis.digest)

    def load(self, ctx: Context) -> tuple:
        """Import the stored snapshot against the anchored head."""
        with self._lock:
            journal = import_security_journal_snapshot_v2(self._snapshot, self._head)
            return journal, self._head

    def compare_and_swap(self, ctx: Context, expected: SecurityJournalHeadV2, next_journal: SecurityJournalV2) -> None:
        with self._lock:
            if expected != self._head:
                raise SecurityJournalConflictV2()
            current = import_security_journal_snapshot_v2(self._snapshot, self._head)
            validate_security_journal_transition_v2(current, next_journal)
            snapshot = export_security_journal_snapshot_v2(next_journal)
            self._snapshot = snapshot
            self._head = SecurityJournalHeadV2(generation=next_journal.generation, digest=next_journal.digest)

    def head(self) -> SecurityJournalHeadV2:
        with self._lock:
            return self._head


def new_journal_store() -> JournalStore:
    """Go ``NewJournalStore``."""
    return JournalStore()
