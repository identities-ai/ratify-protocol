//! Release permanence (SPEC-v2 §6.9): Go `release_v2_withheld_test.go`. A
//! withheld result is recorded through the claim store's release record and
//! answered before any later step; the reference store keeps the first
//! record.

mod v2_status_common;
mod v2_verify_common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ratify_protocol::v2::reference::Store;
use ratify_protocol::v2::*;
use ratify_protocol::HybridPublicKey;
use v2_verify_common::*;

/// Go `v2ReleaseFixture`: commit and publish lifecycle request A against a
/// fresh reference store.
fn fixture() -> (Arc<Store>, CommittedV2Outcome, Vec<u8>, HybridPublicKey, String) {
    let f = load_v2_vector("lifecycle-scenarios.json");
    let keys = v2_status_common::load_v2_keys();
    let request = &f["requests"]["A"];
    let verifier = s(&f["verifier_key"]);
    let log_id = s(&f["log_id"]);
    let store = Arc::new(
        Store::new(i(&request["now"]), i(&f["lease_seconds"]), &log_id, &keys.private[&verifier]).expect("store"),
    );
    let bundle = unb64(&f["bundles_b64"][s(&request["bundle"])]);
    let (req, mut cb, _) = build_verify_request(request, bundle, &Arc::new(Counts::default()));
    cb.claim_store = Some(store.clone());
    let outcome = verify_proof_bundle_v2(&V2Context::background(), &req, &cb);
    let committed = outcome.committed.expect("fixture did not commit");
    let wire = store
        .publish_v2_receipt(&V2Context::background(), &committed.claim_id(), &committed.receipt_body())
        .expect("publish");
    (store, committed, wire, keys.public(&verifier), log_id)
}

/// Go `v2RecordFailingStore`: fails every `record_v2_release` with `err`.
struct RecordFailingStore {
    inner: Arc<Store>,
    err: V2StoreError,
    calls: AtomicUsize,
}

impl V2AuthoritativeClock for RecordFailingStore {
    fn authoritative_time_v2(&self, ctx: &V2Context) -> Result<i64, V2StoreError> {
        self.inner.authoritative_time_v2(ctx)
    }
}

impl V2ReleaseClaimStore for RecordFailingStore {
    fn load_v2_terminal_claim(&self, ctx: &V2Context, claim_id: &str) -> Result<V2TerminalClaimRecord, V2StoreError> {
        self.inner.load_v2_terminal_claim(ctx, claim_id)
    }
    fn record_v2_release(&self, _ctx: &V2Context, _record: V2ReleaseRecord) -> Result<(), V2StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(self.err.clone())
    }
}

fn release(
    committed: &CommittedV2Outcome,
    wire: Option<&[u8]>,
    public: &HybridPublicKey,
    log_id: &str,
    claim_store: &dyn V2ReleaseClaimStore,
    checkpoint: &dyn V2ReceiptCheckpoint,
) -> (V2ReleaseStatus, String, bool) {
    let result = release_v2_decision(
        &V2Context::background(),
        committed,
        wire,
        V2ReleaseConfig {
            verifier_public_key: public,
            log_id,
            claim_store,
            checkpoint,
        },
    );
    let released = result.decision().is_some();
    (result.status, result.reason, released)
}

// A withheld result must never become released. If recording it fails, the
// call is still withheld: failing open to pending would let a later call with
// a recovered clock release a decision already withheld.
#[test]
fn withholds_when_recording_withheld_fails() {
    let (store, committed, wire, public, log_id) = fixture();
    let failing = RecordFailingStore {
        inner: store.clone(),
        err: V2StoreError::Unavailable("store unavailable".into()),
        calls: AtomicUsize::new(0),
    };
    store.set_time(committed.challenge_expires_at());
    let got = release(&committed, Some(&wire), &public, &log_id, &failing, store.as_ref());
    assert_eq!(got, (V2ReleaseStatus::Withheld, "challenge_expired".into(), false));
    assert_eq!(failing.calls.load(Ordering::SeqCst), 1);
}

// The first record wins: a different record already present when release
// tries to record its withheld result is a state mismatch.
#[test]
fn withheld_record_conflict_is_rejected() {
    let (store, committed, wire, public, log_id) = fixture();
    let conflicting = RecordFailingStore {
        inner: store.clone(),
        err: V2StoreError::ReleaseStateMismatch,
        calls: AtomicUsize::new(0),
    };
    store.set_time(committed.challenge_expires_at());
    let got = release(&committed, Some(&wire), &public, &log_id, &conflicting, store.as_ref());
    assert_eq!(got, (V2ReleaseStatus::Rejected, "release_state_mismatch".into(), false));
}

// A recorded withheld result is returned right after the committed-state
// step, before any receipt or acknowledgement is consulted.
#[test]
fn answers_recorded_withheld_first() {
    let (store, committed, wire, public, log_id) = fixture();
    store.set_time(committed.challenge_expires_at());
    let withheld = (V2ReleaseStatus::Withheld, "challenge_expired".to_string(), false);
    assert_eq!(release(&committed, Some(&wire), &public, &log_id, store.as_ref(), store.as_ref()), withheld);
    assert_eq!(release(&committed, None, &public, &log_id, store.as_ref(), store.as_ref()), withheld);
}

// The reference store keeps the first release record: an identical repeat
// is a no-op, a different outcome or reason is a state mismatch, and an
// outcome that is not a release record is refused before anything is stored.
#[test]
fn reference_store_records_withheld_first_wins() {
    let (store, committed, wire, _, _) = fixture();
    let receipt = decode_verification_receipt_v2(&wire).expect("receipt");
    let entry = verification_receipt_v2_digest(&receipt).expect("entry hash");
    let ctx = V2Context::background();
    let record = |outcome: V2ReleaseStatus, reason: &str| V2ReleaseRecord {
        claim_id: committed.claim_id(),
        entry_hash: entry.clone(),
        ack_timestamp: 7,
        outcome,
        reason: reason.into(),
    };
    for (name, invalid) in [
        ("released with reason", record(V2ReleaseStatus::Released, "clock_regressed")),
        ("withheld, other cause", record(V2ReleaseStatus::Withheld, "receipt_invalid")),
        ("withheld, no reason", record(V2ReleaseStatus::Withheld, "")),
        ("rejected outcome", record(V2ReleaseStatus::Rejected, "receipt_invalid")),
        ("pending outcome", record(V2ReleaseStatus::Pending, "")),
    ] {
        let got = store.record_v2_release(&ctx, invalid);
        assert_eq!(
            got.as_ref().err().and_then(V2StoreError::class),
            Some(V2ErrorClass::ConfigurationInvalid),
            "{name}: {got:?}"
        );
    }
    let withheld = record(V2ReleaseStatus::Withheld, "clock_regressed");
    store.record_v2_release(&ctx, withheld.clone()).expect("first record");
    store.record_v2_release(&ctx, withheld).expect("identical repeat");
    for (name, other) in [
        ("released", record(V2ReleaseStatus::Released, "")),
        ("other reason", record(V2ReleaseStatus::Withheld, "challenge_expired")),
    ] {
        assert_eq!(
            store.record_v2_release(&ctx, other),
            Err(V2StoreError::ReleaseStateMismatch),
            "{name} after withheld"
        );
    }
    let loaded = store.load_v2_terminal_claim(&ctx, &committed.claim_id()).expect("load");
    let release = loaded.release.expect("stored record");
    assert_eq!((release.outcome, release.reason.as_str()), (V2ReleaseStatus::Withheld, "clock_regressed"));
}

#[test]
fn release_record_outcome_validity() {
    use V2ReleaseStatus::*;
    assert!(valid_v2_release_record_outcome(Released, ""));
    for reason in ["clock_regressed", "challenge_expired", "allow_horizon_passed"] {
        assert!(valid_v2_release_record_outcome(Withheld, reason));
        assert!(!valid_v2_release_record_outcome(Released, reason));
    }
    for reason in ["", "receipt_abandoned", "receipt_invalid"] {
        assert!(!valid_v2_release_record_outcome(Withheld, reason));
    }
    assert!(!valid_v2_release_record_outcome(Rejected, ""));
    assert!(!valid_v2_release_record_outcome(Pending, ""));
}
