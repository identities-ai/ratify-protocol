//! Concurrent writers through the reference anchored journal store: every
//! status transition is serialized by the store's compare-and-swap, a
//! conflict is reported (never a lost update), and the final state equals a
//! serial application of the same operations.

use std::sync::Arc;
use std::thread;

use ratify_protocol::v2::reference::JournalStore;
use ratify_protocol::v2::{
    apply_revocation_list_to_journal_v2, apply_revocation_push_to_journal_v2,
    configure_status_key_epoch_v2, is_security_journal_conflict_v2, key_id_v2,
    sign_revocation_list_v2, sign_revocation_push_v2, RevocationListV2, RevocationPushV2,
    RevocationStatusPolicyV2, RevokedCertV2, SecurityJournalStoreV2, SecurityJournalV2, V2Context,
    V2Result,
};
use ratify_protocol::{hybrid_keypair_from_seeds, HybridPublicKey, HybridSignature};

const NOW: i64 = 1_800_000_000;
const WRITERS: u8 = 4;
const PUSHES: i64 = 5;

const POLICY: RevocationStatusPolicyV2 = RevocationStatusPolicyV2 {
    max_list_lifetime_seconds: 3600,
    max_status_age_seconds: 600,
    clock_skew_seconds: 5,
};

enum Op {
    Configure,
    List(RevocationListV2),
    Push(RevocationPushV2),
}

struct Writer {
    issuer_id: String,
    status_key: HybridPublicKey,
    ops: Vec<Op>,
}

fn empty_signature() -> HybridSignature {
    HybridSignature {
        ed25519: Vec::new(),
        ml_dsa_65: Vec::new(),
    }
}

/// One issuer per writer: configure its status key, bootstrap with a list,
/// extend with contiguous pushes, then a cumulative heartbeat list.
fn writer(n: u8) -> Writer {
    let (issuer_key, _) = hybrid_keypair_from_seeds(&[n; 32], &[n.wrapping_add(100); 32]);
    let (status_key, status_private) =
        hybrid_keypair_from_seeds(&[n.wrapping_add(50); 32], &[n.wrapping_add(150); 32]);
    let issuer_id = key_id_v2(&issuer_key).expect("issuer id");
    let cert = |seq: i64| RevokedCertV2 {
        cert_id: format!("w{n}-c{seq}"),
    };
    let list = |sequence: i64, updated_at: i64, revoked: Vec<RevokedCertV2>| {
        let unsigned = RevocationListV2 {
            version: 2,
            issuer_id: issuer_id.clone(),
            updated_at,
            next_update: NOW + 600,
            sequence,
            revoked,
            signature: empty_signature(),
        };
        sign_revocation_list_v2(&unsigned, &issuer_id, &status_key, &status_private)
            .expect("sign list")
    };
    let mut ops = vec![Op::Configure, Op::List(list(1, NOW - 20, vec![]))];
    for seq in 2..=PUSHES + 1 {
        let unsigned = RevocationPushV2 {
            version: 2,
            issuer_id: issuer_id.clone(),
            sequence: seq,
            pushed_at: NOW - 15,
            revoked: vec![cert(seq)],
            signature: empty_signature(),
        };
        ops.push(Op::Push(
            sign_revocation_push_v2(&unsigned, &issuer_id, &status_key, &status_private)
                .expect("sign push"),
        ));
    }
    ops.push(Op::List(list(
        PUSHES + 1,
        NOW - 10,
        (2..=PUSHES + 1).map(cert).collect(),
    )));
    Writer {
        issuer_id,
        status_key,
        ops,
    }
}

fn apply(
    ctx: &V2Context,
    store: &JournalStore,
    w: &Writer,
    op: &Op,
) -> V2Result<SecurityJournalV2> {
    match op {
        Op::Configure => configure_status_key_epoch_v2(ctx, store, &w.issuer_id, 1, &w.status_key),
        Op::List(l) => apply_revocation_list_to_journal_v2(
            ctx,
            store,
            l,
            &w.issuer_id,
            1,
            &w.status_key,
            &POLICY,
            NOW,
        ),
        Op::Push(p) => apply_revocation_push_to_journal_v2(
            ctx,
            store,
            p,
            &w.issuer_id,
            1,
            &w.status_key,
            &POLICY,
            NOW,
        ),
    }
}

/// Applies every op, reloading and re-evaluating on a conflict; returns the
/// number of conflicts seen.
fn run_writer(store: &JournalStore, w: &Writer) -> usize {
    let ctx = V2Context::background();
    let mut conflicts = 0;
    for op in &w.ops {
        loop {
            match apply(&ctx, store, w, op) {
                Ok(_) => break,
                Err(e) if is_security_journal_conflict_v2(&e) => {
                    conflicts += 1;
                    thread::yield_now();
                }
                Err(e) => panic!("writer {}: {e}", w.issuer_id),
            }
        }
    }
    conflicts
}

/// Logical content independent of the interleaving: the digest chain and
/// generation order differ by schedule, the per-issuer states and key
/// histories must not.
fn content(store: &JournalStore) -> (u64, String) {
    let (journal, head) = store.load(&V2Context::background()).expect("load");
    assert_eq!(head.generation, journal.generation);
    (
        journal.generation,
        format!(
            "{:?}|{:?}|{:?}",
            journal.status_by_issuer, journal.key_role_history, journal.status_key_history
        ),
    )
}

#[test]
fn concurrent_writers_match_serial_application_without_lost_updates() {
    let writers: Vec<Arc<Writer>> = (1..=WRITERS).map(|n| Arc::new(writer(n))).collect();
    let total_ops: usize = writers.iter().map(|w| w.ops.len()).sum();

    let serial = JournalStore::new().expect("serial store");
    for w in &writers {
        assert_eq!(run_writer(&serial, w), 0, "a single writer never conflicts");
    }
    let (serial_generation, serial_content) = content(&serial);
    assert_eq!(
        serial_generation, total_ops as u64,
        "every operation commits exactly one transition"
    );

    let mut saw_conflict = false;
    for _round in 0..3 {
        let shared = Arc::new(JournalStore::new().expect("shared store"));
        let handles: Vec<_> = writers
            .iter()
            .map(|w| {
                let (store, w) = (shared.clone(), w.clone());
                thread::spawn(move || run_writer(&store, &w))
            })
            .collect();
        let conflicts: usize = handles
            .into_iter()
            .map(|h| h.join().expect("writer thread"))
            .sum();
        saw_conflict |= conflicts > 0;
        let (generation, concurrent_content) = content(&shared);
        assert_eq!(
            generation, serial_generation,
            "no lost or duplicated transitions"
        );
        assert_eq!(
            concurrent_content, serial_content,
            "final state equals the serial application"
        );
    }
    // Writers overlap heavily (each transition re-imports and re-validates
    // the snapshot), so the store must have reported conflicts that the
    // writers resolved by reloading.
    assert!(
        saw_conflict,
        "the writers never contended; the test did not exercise concurrency"
    );
}
