//! Resumption of committed work from the claim store (SPEC-v2 §7.11),
//! porting Go `resume_committed_v2_test.go` onto the reference Part B store.

mod v2_status_common;
mod v2_verify_common;

use std::sync::Arc;

use ratify_protocol::v2::reference::Store;
use ratify_protocol::v2::*;
use ratify_protocol::{protocol_claim_id_from_digest_v2, HybridPrivateKey, HybridPublicKey};
use v2_verify_common::*;

const LOG_ID: &str = "0123456789abcdef0123456789abcdef";
const LEASE: i64 = 30;

fn verifier_keys() -> (HybridPublicKey, HybridPrivateKey) {
    let fx = v2_status_common::load_v2_keys();
    (fx.public("verifier"), fx.private.get("verifier").expect("verifier").clone())
}

/// Go `v2ReleaseFixture`: a committed allow on the reference store.
fn committed_allow() -> (Arc<Store>, CommittedV2Outcome) {
    let (_, private) = verifier_keys();
    let store = Arc::new(Store::new(1_800_000_000, LEASE, LOG_ID, &private).expect("store"));
    let f = load_v2_vector("verifier-ordering.json");
    let v = arr(&f["vectors"])
        .into_iter()
        .find(|v| s(&v["name"]) == "allow_bound_context")
        .expect("allow vector");
    let bundle = unb64(&f["bundles_b64"][s(&v["bundle"])]);
    let counts = Arc::new(Counts::default());
    let (req, mut cb, _) = build_verify_request(&v, bundle, &counts);
    cb.claim_store = Some(store.clone());
    let outcome = verify_proof_bundle_v2(&V2Context::background(), &req, &cb);
    assert_eq!(outcome.stage, V2VerifyStage::Committed, "{:?}", outcome.error);
    let committed = outcome.committed.expect("committed");
    (store, committed)
}

fn release(store: &Arc<Store>, committed: &CommittedV2Outcome, wire: &[u8]) -> V2ReleaseResult {
    let (public, _) = verifier_keys();
    release_v2_decision(
        &V2Context::background(),
        committed,
        Some(wire),
        V2ReleaseConfig {
            verifier_public_key: &public,
            log_id: LOG_ID,
            claim_store: store.as_ref(),
            checkpoint: store.as_ref(),
        },
    )
}

type Edit = dyn Fn(&mut V2CommittedClaim) -> Result<(), V2StoreError>;

/// Go `v2CommittedRecordStore`: answers through `edit`, so a test can stand
/// in for a claim store that returns a damaged record.
struct EditedStore<'a> {
    inner: &'a Store,
    edit: &'a Edit,
}

impl V2CommittedClaimStore for EditedStore<'_> {
    fn load_v2_committed_claim(&self, ctx: &V2Context, claim_id: &str) -> Result<V2CommittedClaim, V2StoreError> {
        let mut record = self.inner.load_v2_committed_claim(ctx, claim_id)?;
        (self.edit)(&mut record)?;
        Ok(record)
    }
}

fn class<T>(r: V2Result<T>) -> Option<V2ErrorClass> {
    r.err().map(|e| e.class)
}

// SPEC-v2 §7.11: a service whose handoff died after the terminal commit
// resumes it from the store, and the resumed handoff is the committed one:
// release answers it exactly as the original.
#[test]
fn resume_returns_the_committed_handoff() {
    let (store, committed) = committed_allow();
    let ctx = V2Context::background();
    let resumed = resume_committed_claim_v2(&ctx, store.as_ref(), &committed.claim_id()).expect("resume");
    assert_eq!(resumed.claim_id(), committed.claim_id());
    assert_eq!(resumed.receipt_body(), committed.receipt_body());
    assert_eq!(resumed.challenge_expires_at(), committed.challenge_expires_at());
    assert!(committed.allow_horizon().is_some());
    assert_eq!(resumed.allow_horizon(), committed.allow_horizon());
    let wire = store
        .publish_v2_receipt(&ctx, &resumed.claim_id(), &resumed.receipt_body())
        .expect("publish");
    let result = release(&store, &resumed, &wire);
    assert_eq!(result.status, V2ReleaseStatus::Released, "{}", result.reason);
    assert_eq!(result.into_decision().expect("decision").decision(), "allow");
    let again = release(&store, &committed, &wire);
    assert_eq!(again.status, V2ReleaseStatus::Released, "release of the original handoff is idempotent");
}

// The store's answers for a claim with no committed record pass through with
// their class; resumption commits nothing.
#[test]
fn resume_refuses_a_claim_with_no_committed_record() {
    let ctx = V2Context::background();
    let (store, committed) = committed_allow();
    assert_eq!(
        class(resume_committed_claim_v2(&ctx, store.as_ref(), "unknown-claim")),
        Some(V2ErrorClass::ClaimNotFound)
    );
    let record = store.load_v2_committed_claim(&ctx, &committed.claim_id()).expect("record");
    let (_, private) = verifier_keys();
    let evaluating = Store::new(store.now(), LEASE, &"ab".repeat(16), &private).expect("store");
    evaluating.claim_v2(&ctx, record.claim.clone()).expect("claim");
    assert_eq!(
        class(resume_committed_claim_v2(&ctx, &evaluating, &record.claim.claim_id)),
        Some(V2ErrorClass::ClaimLeaseLive)
    );
    evaluating.set_time(evaluating.now() + LEASE);
    assert_eq!(
        class(resume_committed_claim_v2(&ctx, &evaluating, &record.claim.claim_id)),
        Some(V2ErrorClass::ClaimLeaseLost)
    );
    let terminal = evaluating.load_v2_terminal_claim(&ctx, &record.claim.claim_id).expect("load");
    assert!(!terminal.terminal, "resumption committed a result");
    // Go's nil-store case has no Rust counterpart: the store is a reference.
    assert_eq!(
        class(resume_committed_claim_v2(&ctx, store.as_ref(), "")),
        Some(V2ErrorClass::ConfigurationInvalid)
    );
}

fn interrupted_terminal(r: &mut V2CommittedClaim) -> Result<(), V2StoreError> {
    let (terminal, body) =
        v2_evaluation_interrupted_result(&r.claim, r.claim.issued_at, &initial_v2_evaluation_progress())
            .map_err(V2StoreError::Classified)?;
    r.terminal_result = terminal;
    r.receipt_body = body;
    Ok(())
}

// Resumption applies the terminal compare-and-set's checks to the record the
// store returns (§7.3, §7.5, §6.8). A record that fails one is the store's
// failure, never a handoff, so no damaged record can reach release.
#[test]
fn resume_refuses_a_record_that_fails_its_checks() {
    let ctx = V2Context::background();
    let (base, committed) = committed_allow();
    let cases: Vec<(&str, Box<Edit>)> = vec![
        (
            "record for another claim",
            Box::new(|r| {
                r.claim.claim_id = "0".repeat(r.claim.claim_id.len());
                Ok(())
            }),
        ),
        (
            "well-formed record of a different claim",
            Box::new(|r| {
                r.claim.replay_epoch += 1;
                let digest = hex::decode(r.claim.challenge_digest.trim_start_matches("sha384:")).expect("digest");
                r.claim.claim_id =
                    protocol_claim_id_from_digest_v2(&r.claim.namespace, r.claim.replay_epoch, &digest).expect("id");
                Ok(())
            }),
        ),
        (
            "claim ID not derived from the replay key",
            Box::new(|r| {
                r.claim.replay_epoch += 1;
                Ok(())
            }),
        ),
        (
            "challenge digest not a sha384 digest",
            Box::new(|r| {
                r.claim.challenge_digest = r.claim.challenge_digest.to_uppercase();
                Ok(())
            }),
        ),
        (
            "body for another agent",
            Box::new(|r| {
                r.claim.agent_id.push('x');
                Ok(())
            }),
        ),
        (
            "terminal result differs from the body",
            Box::new(|r| {
                let text = String::from_utf8(r.terminal_result.clone()).expect("utf-8");
                r.terminal_result = text.replacen("\"allow\"", "\"deny\"", 1).into_bytes();
                Ok(())
            }),
        ),
        (
            "allow with no horizon",
            Box::new(|r| {
                r.allow_horizon = 0;
                Ok(())
            }),
        ),
        (
            "allow horizon outside the timestamp domain",
            Box::new(|r| {
                r.allow_horizon = V2_MAX_TIMESTAMP_SECONDS + 1;
                Ok(())
            }),
        ),
        ("interrupted result with an allow horizon", Box::new(interrupted_terminal)),
        (
            "store failure without a class",
            Box::new(|_| Err(V2StoreError::Unavailable("disk read failed".into()))),
        ),
        ("store panics", Box::new(|_| panic!("disk read failed"))),
    ];
    let mut failures = Vec::new();
    for (name, edit) in &cases {
        let store = EditedStore { inner: base.as_ref(), edit: edit.as_ref() };
        match resume_committed_claim_v2(&ctx, &store, &committed.claim_id()) {
            Err(e) if e.class == V2ErrorClass::ClaimStoreUnavailable => {}
            Err(e) => failures.push(format!("{name}: {}, want claim_store_unavailable", e.class)),
            Ok(_) => failures.push(format!("{name}: a handoff was returned")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    // The interrupted result itself, with no horizon, is a valid record.
    let valid: &Edit = &|r| {
        interrupted_terminal(r)?;
        r.allow_horizon = 0;
        Ok(())
    };
    let store = EditedStore { inner: base.as_ref(), edit: valid };
    resume_committed_claim_v2(&ctx, &store, &committed.claim_id()).expect("a valid interrupted record");
}
