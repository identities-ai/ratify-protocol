//! issuer-duties.json and evaluator-profiles.json.

mod v2_common;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use ratify_protocol::v2::*;
use ratify_protocol::{HybridPublicKey, HybridSignature};
use serde_json::Value;
use v2_common::*;

/// Wraps a local signer and counts every method call, so a vector can
/// require that no signer method ran before a refusal.
struct CountingSigner {
    inner: LocalSignerV2,
    calls: AtomicUsize,
}

impl SignerV2 for CountingSigner {
    fn public_key_v2(&self) -> HybridPublicKey {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.public_key_v2()
    }
    fn mode_v2(&self) -> SignerModeV2 {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.mode_v2()
    }
    fn sign_v2(&self, ctx: &V2Context, request: &SignRequestV2) -> V2SignResult<HybridSignature> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sign_v2(ctx, request)
    }
}

#[test]
fn v2_issuer_duties() {
    let fx = fixture();
    let f = load("issuer-duties.json");
    let mut t = Tally::default();
    for v in arr(&f["vectors"]) {
        let name = s(&v["name"]);
        let cert = decode_delegation_cert_v2(&b64(&v["unsigned_certificate_b64"])).expect("unsigned certificate decodes");
        let signer = CountingSigner {
            inner: LocalSignerV2::new(&fx.private(&s(&v["issuer"]))).expect("signer"),
            calls: AtomicUsize::new(0),
        };
        let signed = sign_delegation_cert_v2_with_signer(&V2Context::background(), &cert, &signer);
        let calls = signer.calls.load(Ordering::SeqCst);
        let ok = match s(&v["expected"]).as_str() {
            "sign" => signed.as_ref().is_ok_and(|c| verify_delegation_cert_v2_signature(c).is_ok()),
            "reject" => matches!(signed, Err(V2SignError::IssuerDuty(_))) && calls == 0,
            other => panic!("unknown expectation {other}"),
        };
        t.check("issuer-duties", &name, ok, || format!("{signed:?}, {calls} signer calls"));
    }
    t.finish(&[("issuer-duties", 11)]);
}

fn context(v: &Value) -> ConstraintContextV2 {
    let mut c = ConstraintContextV2::default();
    if let Some(m) = v["extension_counts"].as_object() {
        c.extension_counts = m.iter().map(|(k, n)| (k.clone(), i(n))).collect::<BTreeMap<_, _>>();
    }
    if let Some(m) = v["extension_values"].as_object() {
        c.extension_values = m.iter().map(|(k, x)| (k.clone(), s(x))).collect::<BTreeMap<_, _>>();
    }
    c
}

#[test]
fn v2_evaluator_profiles() {
    let f = load("evaluator-profiles.json");
    assert_eq!(i(&f["version"]), 1);
    let standard = [standard_max_count_evaluator_v2(), standard_allowed_values_evaluator_v2()];
    let mut t = Tally::default();
    let suites = arr(&f["profiles"]);
    assert_eq!(suites.len(), 2);
    for suite in suites {
        let profile = s(&suite["profile"]);
        let registration = standard
            .iter()
            .find(|r| r.descriptor.profile == profile && r.descriptor.kind == s(&suite["type"]))
            .unwrap_or_else(|| panic!("unknown standard profile {profile}"));
        assert_eq!(
            constraint_profile_digest_v2(&registration.descriptor).unwrap(),
            s(&suite["profile_digest"]),
            "{profile} digest"
        );
        let mut outcomes: BTreeMap<String, usize> = BTreeMap::new();
        for c in arr(&suite["cases"]) {
            let params = if c["params_absent"].as_bool().unwrap_or(false) {
                None
            } else {
                let raw = serde_json::to_vec(&c["params"]).unwrap();
                Some(canonical_json_v2(&raw).unwrap_or_else(|e| panic!("{}: params: {e}", s(&c["name"]))))
            };
            let ctx = context(&c["context"]);
            validate_v2_request_context(&ctx).expect("case context is inside the request-context bounds");
            let input = ConstraintEvaluationInputV2 {
                kind: registration.descriptor.kind.clone(),
                params_json: params,
                delegation_index: 0,
                constraint_index: 0,
                issuer_id: "issuer-1".into(),
                cert_id: "cert-1".into(),
                context: ctx,
                evaluation_time: 1_000,
            };
            let result = (registration.evaluate)(&V2Context::background(), &input).expect("standard profiles never error");
            let got = match result.outcome {
                ConstraintOutcomeV2::Pass => "pass",
                ConstraintOutcomeV2::Denied => "denied",
                ConstraintOutcomeV2::Unverifiable => "unverifiable",
                ConstraintOutcomeV2::Invalid => "invalid",
            };
            let want = s(&c["outcome"]);
            *outcomes.entry(want.clone()).or_default() += 1;
            t.check(&profile, &s(&c["name"]), got == want && result.valid_until == 0, || {
                format!("{got} ({}), want {want}", result.detail)
            });
        }
        assert!(outcomes.len() == 3, "{profile} outcomes {outcomes:?}");
    }
    for c in arr(&f["context_bounds"]) {
        let got = class_of(&validate_v2_request_context(&context(&c["context"])));
        let want = c["error_class"].as_str().unwrap_or("").to_string();
        let want = if want.is_empty() { "ok".to_string() } else { want };
        t.check("context_bounds", &s(&c["name"]), got == want, || format!("{got}, want {want}"));
    }
    t.finish(&[
        (PROFILE_MAX_COUNT_V2, 34),
        (PROFILE_ALLOWED_VALUES_V2, 36),
        ("context_bounds", 13),
    ]);
}
