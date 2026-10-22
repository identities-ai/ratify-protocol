//! The reference anchored `SecurityJournalV2` store. Mirrors Go
//! `v2reference/journal.go`.

use std::sync::{Mutex, MutexGuard};

use crate::v2::context::V2Context;
use crate::v2::errors::V2Result;
use crate::v2::journal::{
    empty_security_journal_v2, validate_security_journal_transition_inner, SecurityJournalHeadV2,
    SecurityJournalStoreErrorV2, SecurityJournalStoreV2, SecurityJournalV2,
};
use crate::v2::journal_snapshot::{
    export_security_journal_snapshot_v2, import_security_journal_snapshot_v2,
};

struct Anchored {
    head: SecurityJournalHeadV2,
    snapshot: Vec<u8>,
}

/// The reference anchored `SecurityJournalV2` store. It persists the
/// canonical snapshot bytes and an anchored head, and advances both under one
/// lock by compare-and-swap. TEST/REFERENCE ONLY: an in-process anchor is not
/// an independent, rollback-resistant head.
pub struct JournalStore {
    state: Mutex<Anchored>,
}

impl std::fmt::Debug for JournalStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JournalStore")
            .field("head", &self.head())
            .finish()
    }
}

impl JournalStore {
    /// A store anchored at the genesis journal.
    pub fn new() -> V2Result<Self> {
        let genesis = empty_security_journal_v2();
        let snapshot = export_security_journal_snapshot_v2(&genesis)?;
        Ok(JournalStore {
            state: Mutex::new(Anchored {
                head: SecurityJournalHeadV2 {
                    generation: genesis.generation,
                    digest: genesis.digest,
                },
                snapshot,
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Anchored> {
        // A panic while holding the lock never leaves a half-written state:
        // head and snapshot are replaced together after every check passed.
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The anchored head.
    pub fn head(&self) -> SecurityJournalHeadV2 {
        self.lock().head.clone()
    }
}

impl SecurityJournalStoreV2 for JournalStore {
    /// Imports the stored snapshot against the anchored head.
    fn load(&self, _ctx: &V2Context) -> V2Result<(SecurityJournalV2, SecurityJournalHeadV2)> {
        let state = self.lock();
        let journal = import_security_journal_snapshot_v2(&state.snapshot, &state.head)?;
        Ok((journal, state.head.clone()))
    }

    fn compare_and_swap(
        &self,
        _ctx: &V2Context,
        expected: &SecurityJournalHeadV2,
        next: &SecurityJournalV2,
    ) -> Result<(), SecurityJournalStoreErrorV2> {
        let mut state = self.lock();
        if *expected != state.head {
            return Err(SecurityJournalStoreErrorV2::Conflict);
        }
        let current = import_security_journal_snapshot_v2(&state.snapshot, &state.head)?;
        validate_security_journal_transition_inner(&current, next)?;
        let snapshot = export_security_journal_snapshot_v2(next)?;
        state.snapshot = snapshot;
        state.head = SecurityJournalHeadV2 {
            generation: next.generation,
            digest: next.digest.clone(),
        };
        Ok(())
    }
}
