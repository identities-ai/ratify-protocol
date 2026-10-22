//! testvectors/v2/transaction-verification.json against
//! `verify_transaction_receipt_v2`, mirroring Go
//! `TestV2ConformanceTransactionVerification` (v2_conformance_tx_test.go):
//! the same provider and journal construction as the verifier-ordering
//! vectors.

mod v2_verify_common;

use std::sync::Arc;

use ratify_protocol::v2::*;
use serde_json::Value;
use v2_verify_common::*;

fn party_json(p: &Value) -> TransactionPartyVerificationV2 {
    TransactionPartyVerificationV2 {
        party_id: s(&p["party_id"]),
        agent_id: s(&p["agent_id"]),
        required_scope: s(&p["required_scope"]),
        trust_assessment: s(&p["trust_assessment"]),
        delegation_assessment: s(&p["delegation_assessment"]),
        delegation_expires_at: p["delegation_expires_at"].as_i64(),
        status_assessment: s(&p["status_assessment"]),
        scope_assessment: s(&p["scope_assessment"]),
        freshness: s(&p["freshness"]),
        status_evidence: arr(&p["status_evidence_digests"]).iter().map(evidence_json).collect(),
    }
}

/// Every member of the expected result is one of the struct's fields (Go
/// decodes the result into the struct and compares with DeepEqual).
fn check_members(result: &Value) {
    let top: Vec<&str> = result.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(top, ["actionable", "parties", "transaction_id"]);
    for p in arr(&result["parties"]) {
        let keys: Vec<&str> = p.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "agent_id",
                "delegation_assessment",
                "delegation_expires_at",
                "freshness",
                "party_id",
                "required_scope",
                "scope_assessment",
                "status_assessment",
                "status_evidence_digests",
                "trust_assessment"
            ]
        );
    }
}

#[test]
fn v2_conformance_transaction_verification() {
    let f = load_v2_vector("transaction-verification.json");
    let vectors = arr(&f["vectors"]);
    assert!(!vectors.is_empty(), "no transaction verification vectors");
    let (mut results, mut errors) = (0usize, 0usize);
    for v in &vectors {
        let name = s(&v["name"]);
        let counts = Arc::new(Counts::default());
        let (req, cb, _) = build_verify_request(v, Vec::new(), &counts);
        let sources = TransactionVerifySourcesV2 {
            trust: if v["trust"].is_null() { None } else { cb.trust.clone() },
            status_evidence: cb.status_evidence.clone(),
            status_journal: cb.status_journal.clone(),
            status_keys: req.status_keys.clone(),
            status_policy: req.status_policy,
        };
        let got = verify_transaction_receipt_v2(
            &V2Context::background(),
            &TransactionVerifyRequestV2 {
                receipt: unb64(&v["receipt_b64"]),
                now: i(&v["now"]),
                future_skew_seconds: i(&v["future_skew_seconds"]),
            },
            &sources,
        );
        let want_class = s(&v["expected"]["error_class"]);
        if !want_class.is_empty() {
            let got_class = got.as_ref().err().map(|e| e.class.as_str().to_string());
            assert_eq!(got_class.as_deref(), Some(want_class.as_str()), "{name}: {got:?}");
            errors += 1;
            continue;
        }
        let got = got.unwrap_or_else(|e| panic!("{name}: {e}"));
        let result = &v["expected"]["result"];
        check_members(result);
        let want = TransactionReceiptVerificationV2 {
            transaction_id: s(&result["transaction_id"]),
            actionable: b(&result["actionable"]),
            parties: arr(&result["parties"]).iter().map(party_json).collect(),
        };
        assert_eq!(got, want, "{name}");
        assert!(!got.actionable, "{name}: a transaction verification is never actionable");
        results += 1;
    }
    assert_eq!(vectors.len(), 12);
    assert_eq!((results, errors), (10, 2));
    let readme = readme_line("transaction-verification.json");
    assert!(readme.contains("12 composed transaction-receipt verification cases"), "README row: {readme}");
}
