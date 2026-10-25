//! Concurrency through the reference Part B store (Go
//! v2reference/store_test.go plus Rust-specific races): finalization,
//! stream advances, and identical versus conflicting presentations.

mod v2_status_common;
mod v2_verify_common;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Barrier};

use ratify_protocol::v2::reference::Store;
use ratify_protocol::v2::*;
use v2_verify_common::*;

const NOW: i64 = 1_800_000_000;
const WORKERS: usize = 32;

fn new_store() -> Arc<Store> {
    let fx = v2_status_common::load_v2_keys();
    let private = fx.private.get("verifier").expect("verifier").clone();
    Arc::new(Store::new(NOW, 30, "dddddddddddddddddddddddddddddd01", &private).expect("store"))
}

/// Go `claimFor`.
fn claim_for(id: &str, proof: &str, seq: Option<i64>) -> V2ChallengeClaim {
    V2ChallengeClaim {
        claim_id: id.into(),
        namespace: "ns".into(),
        agent_id: "agent".into(),
        proof_digest: proof.into(),
        issued_at: NOW - 10,
        expires_at: NOW + 290,
        max_age_seconds: 300,
        clock_skew_seconds: 5,
        stream_id: seq.map(|_| vec![0; 32]),
        stream_seq: seq,
        ..Default::default()
    }
}

/// Run `f(i)` on `n` threads released together.
fn race<T: Send>(n: usize, f: impl Fn(usize) -> T + Sync) -> Vec<T> {
    let barrier = Barrier::new(n);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..n)
            .map(|i| {
                let (barrier, f) = (&barrier, &f);
                scope.spawn(move || {
                    barrier.wait();
                    f(i)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    })
}

fn class(e: &V2StoreError) -> Option<V2ErrorClass> {
    e.class()
}

#[test]
fn racing_finalizations_commit_exactly_once() {
    let store = new_store();
    let ctx = V2Context::background();
    // The bound body is an allow, which carries an allow horizon inside the
    // claim's lifetime (SPEC-v2 §6.8).
    const HORIZON: i64 = NOW + 60;
    let mut claim = claim_for("c", "proof", None);
    // Bodies that differ only in verified_at, each bound to the claim.
    let payloads: Vec<(Vec<u8>, Vec<u8>)> =
        (0..WORKERS).map(|i| bind_claim_to_receipt_body(&mut claim, NOW + i as i64)).collect();
    let created = store.claim_v2(&ctx, claim).expect("claim");
    let owner = created.owner_token;
    // Conflicting payloads: one commits, every other is claim_already_terminal.
    let results = race(WORKERS, |i| {
        let (terminal, body) = &payloads[i];
        store.finalize_v2_claim(&ctx, "c", &owner, terminal, body, HORIZON)
    });
    assert_eq!(results.iter().filter(|r| **r == Ok(true)).count(), 1, "{results:?}");
    for r in results.iter().filter(|r| **r != Ok(true)) {
        assert_eq!(r.as_ref().err().and_then(class), Some(V2ErrorClass::ClaimAlreadyTerminal), "{r:?}");
    }
    assert_eq!(store.log_length(), 0, "one outbox entry, not yet appended");

    // Identical payloads: one commits, every repeat is an idempotent false.
    let store = new_store();
    let mut claim = claim_for("d", "proof", None);
    let (terminal, body) = bind_claim_to_receipt_body(&mut claim, NOW);
    let created = store.claim_v2(&ctx, claim).expect("claim");
    let owner = created.owner_token;
    let results = race(WORKERS, |_| store.finalize_v2_claim(&ctx, "d", &owner, &terminal, &body, HORIZON));
    assert_eq!(results.iter().filter(|r| **r == Ok(true)).count(), 1);
    assert_eq!(results.iter().filter(|r| **r == Ok(false)).count(), WORKERS - 1);

    // A different owner never finalizes.
    let lost = store.finalize_v2_claim(&ctx, "d", &[9; 32], &terminal, &body, HORIZON).expect_err("owner");
    assert_eq!(class(&lost), Some(V2ErrorClass::ClaimLeaseLost));
}

/// Go TestStoreSerializesConcurrentStreamClaims, extended over several
/// sequence numbers: per sequence exactly one presentation advances the
/// stream; every other is stream_sequence_mismatch and consumes nothing.
#[test]
fn racing_stream_advances_accept_exactly_one_per_sequence() {
    let store = new_store();
    let ctx = V2Context::background();
    for seq in 1..=4 {
        let results = race(WORKERS, |i| store.claim_v2(&ctx, claim_for(&format!("s{seq}-{i}"), &format!("p{seq}-{i}"), Some(seq))));
        let created = results
            .iter()
            .filter(|r| r.as_ref().is_ok_and(|c| c.disposition == V2ClaimDisposition::Created && c.owner_token.len() == 32))
            .count();
        assert_eq!(created, 1, "sequence {seq}");
        for r in results.iter().filter(|r| r.is_err()) {
            assert_eq!(r.as_ref().err().and_then(class), Some(V2ErrorClass::StreamSequenceMismatch), "{r:?}");
        }
    }
    // A gap, a duplicate and a reorder are all rejected.
    for seq in [6, 4, 2] {
        let e = store.claim_v2(&ctx, claim_for(&format!("late-{seq}"), "late", Some(seq))).expect_err("rejected");
        assert_eq!(class(&e), Some(V2ErrorClass::StreamSequenceMismatch));
    }
    // A rejected advance consumed nothing: the challenge still claims with
    // the next sequence.
    let next = store.claim_v2(&ctx, claim_for("late-6", "late", Some(5))).expect("next");
    assert_eq!(next.disposition, V2ClaimDisposition::Created);
}

/// Go TestStoreConcurrentExactRetriesCreateOnce plus conflicting proofs:
/// identical presentations create once and never hand the capability to a
/// retry; a different proof for the same claim is claim_replay.
#[test]
fn identical_and_conflicting_presentations() {
    let store = new_store();
    let ctx = V2Context::background();
    let results = race(WORKERS, |_| store.claim_v2(&ctx, claim_for("same", "proof", Some(1))));
    let created = results
        .iter()
        .filter(|r| r.as_ref().is_ok_and(|c| c.disposition == V2ClaimDisposition::Created && c.owner_token.len() == 32))
        .count();
    let in_progress = results
        .iter()
        .filter(|r| r.as_ref().is_ok_and(|c| c.disposition == V2ClaimDisposition::InProgress && c.owner_token.is_empty()))
        .count();
    assert_eq!((created, in_progress), (1, WORKERS - 1), "{results:?}");
    let results = race(WORKERS, |i| store.claim_v2(&ctx, claim_for("same", &format!("other-{i}"), Some(1))));
    for r in &results {
        assert_eq!(r.as_ref().err().and_then(class), Some(V2ErrorClass::ClaimReplay), "{r:?}");
    }
}

/// End to end: concurrent identical verifications of one presentation
/// commit exactly one terminal result; every other one is a replay.
#[test]
fn concurrent_live_verifications_commit_once() {
    let store = new_store();
    let f = load_v2_vector("verifier-ordering.json");
    let v = arr(&f["vectors"]).into_iter().find(|v| s(&v["name"]) == "allow_bound_context").expect("vector");
    let bundle = unb64(&f["bundles_b64"][s(&v["bundle"])]);
    let counts = Arc::new(Counts::default());
    let (req, mut cb, _) = build_verify_request(&v, bundle, &counts);
    cb.claim_store = Some(store.clone());
    let outcomes = race(8, |_| verify_proof_bundle_v2(&V2Context::background(), &req, &cb).stage);
    assert_eq!(outcomes.iter().filter(|s| **s == V2VerifyStage::Committed).count(), 1, "{outcomes:?}");
    assert_eq!(outcomes.iter().filter(|s| **s == V2VerifyStage::Replay).count(), 7, "{outcomes:?}");
    assert_eq!(counts.finalize.load(Ordering::SeqCst), 0, "the scripted counter is not used by the reference store");
    assert_eq!(counts.trust.load(Ordering::SeqCst), 1, "only the claim owner evaluates");
}

/// Go TestCheckV2StreamSequenceRule.
#[test]
fn stream_sequence_rule() {
    for (has_last, last, seq, ok) in [
        (false, 0, 1, true),
        (false, 0, 2, false),
        (true, 1, 2, true),
        (true, 2, 2, false),
        (true, 3, 2, false),
        (true, 2, 4, false),
        (false, 0, 0, false),
    ] {
        assert_eq!(check_v2_stream_sequence(has_last, last, seq).is_ok(), ok, "{has_last} {last} {seq}");
    }
    assert_eq!(check_v2_stream_sequence(false, 0, 0).unwrap_err().class, V2ErrorClass::Malformed);
    assert_eq!(
        check_v2_stream_sequence(true, 9_007_199_254_740_991, 1).unwrap_err().class,
        V2ErrorClass::StreamSequenceMismatch
    );
}
