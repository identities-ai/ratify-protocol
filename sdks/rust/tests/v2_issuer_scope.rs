//! Issuer-scoped CertificateRefs (SPEC-v2 §6.2 step 4, §6.5, §5.2): the
//! same cert_id under different issuers is valid, a repeated exact
//! (issuer_id, cert_id) is duplicate_certificate_ref, and status and rate
//! counters never collide across issuers.

mod v2_status_common;
mod v2_verify_common;

use std::sync::Arc;

use ratify_protocol::v2::reference::{JournalStore, Store};
use ratify_protocol::v2::*;
use ratify_protocol::{hybrid_keypair_from_seeds, HybridSignature};
use v2_verify_common::*;

fn corpus_case(name: &str) -> (serde_json::Value, Vec<u8>) {
    let f = load_v2_vector("verifier-ordering.json");
    let v = arr(&f["vectors"]).into_iter().find(|v| s(&v["name"]) == name).expect("vector");
    let bundle = unb64(&f["bundles_b64"][s(&v["bundle"])]);
    (v, bundle)
}

#[test]
fn same_cert_id_under_different_issuers_is_valid() {
    let (_, wire) = corpus_case("issuer_scoped_cert_id_collision");
    let bundle = decode_proof_bundle_v2(&wire).expect("bundle");
    let ids: Vec<(&str, &str)> = bundle.delegations.iter().map(|c| (c.issuer_id.as_str(), c.cert_id.as_str())).collect();
    assert!(ids.len() >= 2 && ids.iter().all(|(_, c)| *c == "shared-id"), "{ids:?}");
    assert_ne!(ids[0].0, ids[1].0);
    verify_proof_bundle_v2_signatures(&bundle).expect("issuer-scoped duplicate cert IDs are valid");

    let (_, wire) = corpus_case("duplicate_certificate_ref");
    let e = decode_proof_bundle_v2(&wire)
        .and_then(|b| verify_proof_bundle_v2_signatures(&b))
        .expect_err("repeated exact ref");
    assert_eq!(e.class, V2ErrorClass::DuplicateCertificateRef);
}

#[test]
fn rate_batches_are_issuer_scoped() {
    let (_, wire) = corpus_case("issuer_scoped_cert_id_collision");
    let bundle = decode_proof_bundle_v2(&wire).expect("bundle");
    let mut deferred = Vec::new();
    for (i, cert) in bundle.delegations.iter().enumerate() {
        for (j, c) in cert.constraints.iter().enumerate() {
            if c.kind == CONSTRAINT_MAX_RATE {
                deferred.push(V2DeferredConstraint {
                    delegation_index: i,
                    constraint_index: j,
                    issuer_id: cert.issuer_id.clone(),
                    cert_id: cert.cert_id.clone(),
                    kind: c.kind.clone(),
                    canonical_json: c.canonical_json().unwrap(),
                });
            }
        }
    }
    let batch = build_v2_rate_reservation_batch(&deferred).expect("batch");
    assert_eq!(batch.len(), 2, "one counter per issuer: {batch:?}");
    assert_ne!(batch[0].issuer_id, batch[1].issuer_id);
    assert!(batch.iter().all(|r| r.cert_id == "shared-id"));

    // Admission at finalization keeps the counters apart: exhausting one
    // issuer's counter leaves the other issuer's counter for the same
    // cert_id untouched.
    let fx = v2_status_common::load_v2_keys();
    let store = Arc::new(
        Store::new(1_800_000_000, 30, "0123456789abcdef0123456789abcdef", fx.private.get("verifier").unwrap())
            .unwrap(),
    );
    let view = store.with_rate_at_finalization();
    let ctx = V2Context::background();
    let claim = |id: &str, item: &V2RateReservation| V2ChallengeClaim {
        claim_id: id.into(),
        namespace: "ns".into(),
        proof_digest: id.into(),
        issued_at: 1_799_999_990,
        expires_at: 1_800_000_290,
        max_age_seconds: 300,
        rate_batch: vec![V2RateReservation { limit: 1, ..item.clone() }],
        requires_rate: true,
        ..Default::default()
    };
    let admit = |id: &str, item: &V2RateReservation| {
        let created = view.claim_v2(&ctx, claim(id, item)).expect("claim");
        view.finalize_v2_claim(&ctx, id, &created.owner_token, b"{}", id.as_bytes(), 1_800_000_100)
    };
    assert_eq!(admit("a1", &batch[0]), Ok(true));
    assert_eq!(admit("b1", &batch[1]), Ok(true), "another issuer's counter is independent");
    assert_eq!(admit("a2", &batch[0]), Err(V2StoreError::RateLimitExceeded));
}

#[test]
fn status_is_issuer_scoped() {
    let ctx = V2Context::background();
    let store = JournalStore::new().expect("journal");
    let issuer_a = "a".repeat(64);
    let issuer_b = "b".repeat(64);
    let (key_a, private_a) = hybrid_keypair_from_seeds(&[21; 32], &[22; 32]);
    let (key_b, private_b) = hybrid_keypair_from_seeds(&[23; 32], &[24; 32]);
    let policy = RevocationStatusPolicyV2 {
        max_list_lifetime_seconds: 3600,
        max_status_age_seconds: 600,
        clock_skew_seconds: 5,
    };
    const NOW: i64 = 1_800_000_000;
    for (issuer, key) in [(&issuer_a, &key_a), (&issuer_b, &key_b)] {
        configure_status_key_epoch_v2(&ctx, &store, issuer, 1, key).expect("configure");
    }
    let list = |issuer: &str, revoked: &[&str]| RevocationListV2 {
        version: 2,
        issuer_id: issuer.into(),
        updated_at: NOW - 10,
        next_update: NOW + 600,
        sequence: 1,
        revoked: revoked.iter().map(|c| RevokedCertV2 { cert_id: c.to_string() }).collect(),
        signature: HybridSignature {
            ed25519: Vec::new(),
            ml_dsa_65: Vec::new(),
        },
    };
    let a = sign_revocation_list_v2(&list(&issuer_a, &["shared-id"]), &issuer_a, &key_a, &private_a).unwrap();
    let b = sign_revocation_list_v2(&list(&issuer_b, &[]), &issuer_b, &key_b, &private_b).unwrap();
    apply_revocation_list_to_journal_v2(&ctx, &store, &a, &issuer_a, 1, &key_a, &policy, NOW).expect("apply a");
    apply_revocation_list_to_journal_v2(&ctx, &store, &b, &issuer_b, 1, &key_b, &policy, NOW).expect("apply b");
    let status_a = revocation_status_from_journal_v2(&ctx, &store, &issuer_a, "shared-id", 1, &key_a, &policy, NOW).unwrap();
    let status_b = revocation_status_from_journal_v2(&ctx, &store, &issuer_b, "shared-id", 1, &key_b, &policy, NOW).unwrap();
    assert_eq!(status_a.status, "revoked");
    assert_eq!(status_b.status, "not_revoked", "a revocation never crosses issuers");
    // A list for one issuer never authenticates under another issuer's binding.
    let e = verify_revocation_list_v2_signature(&a, &issuer_b, &key_a).expect_err("cross-issuer");
    assert_eq!(e.class, V2ErrorClass::StatusKeyBindingMismatch);
}
