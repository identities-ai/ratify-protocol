//! Shared builders for the live-verifier corpus runners (Go
//! `v2BuildVerifyRequest`, `v2BuildStatusJournal`, the scripted providers
//! and the modal journal store of `v2_conformance_ordering_test.go`).
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ratify_protocol::v2::reference::{JournalStore, TrustRegistry};
use ratify_protocol::v2::*;
use ratify_protocol::HybridPublicKey;
use serde_json::Value;

pub fn load_v2_vector(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testvectors/v2").join(name);
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&data).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

/// The README row for a corpus file.
pub fn readme_line(file: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testvectors/v2/README.md");
    let readme = std::fs::read_to_string(path).expect("read README");
    readme
        .lines()
        .find(|l| l.starts_with(&format!("| `{file}`")))
        .unwrap_or_else(|| panic!("README has no row for {file}"))
        .to_string()
}

pub fn unb64(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().expect("base64 string")).expect("valid base64")
}

/// Go zero-value accessors: absent or null is the zero value.
pub fn s(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_string()
}

pub fn i(v: &Value) -> i64 {
    v.as_i64().unwrap_or_default()
}

pub fn u(v: &Value) -> u64 {
    v.as_u64().unwrap_or_default()
}

pub fn b(v: &Value) -> bool {
    v.as_bool().unwrap_or_default()
}

pub fn arr(v: &Value) -> Vec<Value> {
    v.as_array().cloned().unwrap_or_default()
}

pub fn public_key_json(v: &Value) -> HybridPublicKey {
    HybridPublicKey {
        ed25519: unb64(&v["ed25519"]),
        ml_dsa_65: unb64(&v["ml_dsa_65"]),
    }
}

pub fn status_policy(v: &Value) -> RevocationStatusPolicyV2 {
    RevocationStatusPolicyV2 {
        max_list_lifetime_seconds: i(&v["max_list_lifetime_seconds"]),
        max_status_age_seconds: i(&v["max_status_age_seconds"]),
        clock_skew_seconds: i(&v["clock_skew_seconds"]),
    }
}

/// Go `v2Counts`: the number of times every callback ran.
#[derive(Default, Debug)]
pub struct Counts {
    pub receiver_binding: AtomicUsize,
    pub claim: AtomicUsize,
    pub trust: AtomicUsize,
    pub status: AtomicUsize,
    pub audience: AtomicUsize,
    pub rate: AtomicUsize,
    pub finalize: AtomicUsize,
    pub progress: AtomicUsize,
    pub evaluator: AtomicUsize,
}

impl Counts {
    pub fn snapshot(&self) -> BTreeMap<&'static str, usize> {
        BTreeMap::from([
            ("receiver_binding", self.receiver_binding.load(Ordering::SeqCst)),
            ("claim", self.claim.load(Ordering::SeqCst)),
            ("trust", self.trust.load(Ordering::SeqCst)),
            ("status", self.status.load(Ordering::SeqCst)),
            ("audience", self.audience.load(Ordering::SeqCst)),
            ("rate", self.rate.load(Ordering::SeqCst)),
            ("finalize", self.finalize.load(Ordering::SeqCst)),
            ("progress", self.progress.load(Ordering::SeqCst)),
            ("evaluator", self.evaluator.load(Ordering::SeqCst)),
        ])
    }

    /// The expected counts of a vector (a missing member is zero, as Go's
    /// struct decoding gives).
    pub fn expected(v: &Value) -> BTreeMap<&'static str, usize> {
        [
            "receiver_binding",
            "claim",
            "trust",
            "status",
            "audience",
            "rate",
            "finalize",
            "progress",
            "evaluator",
        ]
        .into_iter()
        .map(|k| (k, u(&v[k]) as usize))
        .collect()
    }
}

fn bump(c: &AtomicUsize) {
    c.fetch_add(1, Ordering::SeqCst);
}

/// Go `v2ScriptedRateStore`.
pub struct ScriptedRateStore {
    pub mode: String,
    pub counts: Arc<Counts>,
    pub batch: Mutex<Vec<V2RateReservation>>,
}

impl V2RateReservationStore for ScriptedRateStore {
    fn reserve_v2_rate_batch(
        &self,
        _ctx: &V2Context,
        _claim_id: &str,
        _owner_token: &[u8],
        _bundle_hash: &str,
        batch: &[V2RateReservation],
    ) -> Result<(), V2StoreError> {
        bump(&self.counts.rate);
        *self.batch.lock().unwrap() = batch.to_vec();
        match self.mode.as_str() {
            "reserve" => Ok(()),
            "exceeded" => Err(V2StoreError::RateLimitExceeded),
            "panic" => panic!("scripted rate store panic"),
            _ => Err(V2StoreError::Unavailable("scripted rate store unavailable".into())),
        }
    }
}

/// Go `v2ModalJournalStore`: the reference journal with scripted failure
/// modes.
pub struct ModalJournalStore {
    pub inner: JournalStore,
    pub mode: String,
    pub cas_calls: AtomicUsize,
}

impl SecurityJournalStoreV2 for ModalJournalStore {
    fn load(&self, ctx: &V2Context) -> V2Result<(SecurityJournalV2, SecurityJournalHeadV2)> {
        match self.mode.as_str() {
            "load_error" => Err(V2Error::new(V2ErrorClass::StatusObjectRejected, "scripted journal load failure")),
            "unanchored" => {
                let (journal, mut head) = self.inner.load(ctx)?;
                head.digest = "e".repeat(96);
                Ok((journal, head))
            }
            _ => self.inner.load(ctx),
        }
    }

    fn compare_and_swap(
        &self,
        ctx: &V2Context,
        expected: &SecurityJournalHeadV2,
        next: &SecurityJournalV2,
    ) -> Result<(), SecurityJournalStoreErrorV2> {
        let calls = self.cas_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.mode == "cas_conflict" || (self.mode == "cas_conflict_once" && calls % 2 == 1) {
            return Err(SecurityJournalStoreErrorV2::Conflict);
        }
        self.inner.compare_and_swap(ctx, expected, next)
    }
}

/// Go `v2PopulateStatusJournal`: every status key configured at its epoch
/// in ascending issuer order, then each preload object applied at its time;
/// or, when `journal.setup` is present, exactly those steps in order.
pub fn populate_status_journal(store: &dyn SecurityJournalStoreV2, inputs: &Value) {
    let ctx = V2Context::background();
    let policy = status_policy(&inputs["status_policy"]);
    let apply = |issuer: &str, code: u64, wire: &[u8], epoch: u64, public: &HybridPublicKey, now: i64| match code {
        3 => {
            let list = decode_revocation_list_v2(wire).unwrap();
            apply_revocation_list_to_journal_v2(&ctx, store, &list, issuer, epoch, public, &policy, now)
                .unwrap_or_else(|e| panic!("journal list: {e}"));
        }
        5 => {
            let push = decode_revocation_push_v2(wire).unwrap();
            apply_revocation_push_to_journal_v2(&ctx, store, &push, issuer, epoch, public, &policy, now)
                .unwrap_or_else(|e| panic!("journal push: {e}"));
        }
        other => panic!("unknown journal object type {other}"),
    };
    if let Some(setup) = inputs["journal"]["setup"].as_array() {
        for step in setup {
            let issuer = s(&step["issuer_id"]);
            let (epoch, public) = (u(&step["epoch"]), public_key_json(&step["public_key"]));
            match s(&step["op"]).as_str() {
                "configure_status_key" => {
                    configure_status_key_epoch_v2(&ctx, store, &issuer, epoch, &public)
                        .unwrap_or_else(|e| panic!("setup configure {issuer} epoch {epoch}: {e}"));
                }
                "apply" => apply(&issuer, u(&step["object_type_code"]), &unb64(&step["wire_b64"]), epoch, &public, i(&step["now"])),
                other => panic!("unknown journal setup op {other}"),
            }
        }
        return;
    }
    let keys = inputs["status_keys"].as_object().cloned().unwrap_or_default();
    // serde_json maps iterate in ascending key order.
    for (issuer, key) in &keys {
        configure_status_key_epoch_v2(&ctx, store, issuer, u(&key["epoch"]), &public_key_json(&key["public_key"]))
            .unwrap_or_else(|e| panic!("configure status key for {issuer}: {e}"));
    }
    for p in arr(&inputs["journal"]["preload"]) {
        let issuer = s(&p["issuer_id"]);
        let key = &keys[&issuer];
        apply(&issuer, u(&p["object_type_code"]), &unb64(&p["wire_b64"]), u(&key["epoch"]), &public_key_json(&key["public_key"]), i(&p["now"]));
    }
}

thread_local! {
    /// The invocation mode of registries built on this test thread.
    pub static EVALUATOR_INVOCATION: std::cell::Cell<ConstraintEvaluatorInvocationV2> =
        const { std::cell::Cell::new(ConstraintEvaluatorInvocationV2::WorkerThread) };
}

/// Go `v2BuildEvaluatorRegistry`.
fn build_evaluator_registry(inputs: &Value, counts: &Arc<Counts>) -> ConstraintEvaluatorRegistryV2 {
    let mut registrations = Vec::new();
    for e in arr(&inputs["constraint_evaluators"]) {
        let implementation = s(&e["implementation"]);
        let valid_until = i(&e["valid_until"]);
        let inner: ConstraintEvaluatorFnV2 = match implementation.as_str() {
            "fault:error" => Arc::new(|_, _| Err(ConstraintEvaluatorError("scripted evaluator failure".into()))),
            "fault:panic" => Arc::new(|_, _| panic!("scripted evaluator panic")),
            "fault:timeout" => Arc::new(|ctx: &V2Context, _| {
                while !ctx.is_done() {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(ConstraintEvaluationResultV2 {
                    outcome: ConstraintOutcomeV2::Pass,
                    valid_until: 0,
                    detail: String::new(),
                })
            }),
            "fault:invalid_outcome" => Arc::new(|_, _| {
                Ok(ConstraintEvaluationResultV2 {
                    outcome: ConstraintOutcomeV2::Invalid,
                    valid_until: 0,
                    detail: String::new(),
                })
            }),
            "fault:pass_until" => Arc::new(move |_, _| {
                Ok(ConstraintEvaluationResultV2 {
                    outcome: ConstraintOutcomeV2::Pass,
                    valid_until,
                    detail: String::new(),
                })
            }),
            PROFILE_MAX_COUNT_V2 => standard_max_count_evaluator_v2().evaluate,
            PROFILE_ALLOWED_VALUES_V2 => standard_allowed_values_evaluator_v2().evaluate,
            other => panic!("unknown evaluator implementation {other:?}"),
        };
        let counts = Arc::clone(counts);
        registrations.push(ConstraintEvaluatorRegistrationV2 {
            descriptor: ConstraintProfileDescriptorV2 {
                profile: s(&e["profile"]),
                kind: s(&e["type"]),
            },
            evaluate: Arc::new(move |ctx, input| {
                bump(&counts.evaluator);
                inner(ctx, input)
            }),
        });
    }
    ConstraintEvaluatorRegistryV2::new_with_invocation(
        Duration::from_secs(1),
        registrations,
        EVALUATOR_INVOCATION.with(|m| m.get()),
    )
    .expect("evaluator registry")
}

/// Go `v2BuildVerifyRequest`: the request and callbacks shared by the
/// ordering and transaction runners. The claim store is supplied by the
/// caller.
pub fn build_verify_request(
    inputs: &Value,
    bundle: Vec<u8>,
    counts: &Arc<Counts>,
) -> (V2VerifyRequest, V2VerifyCallbacks, Option<Arc<ScriptedRateStore>>) {
    let mut req = V2VerifyRequest {
        bundle,
        required_scope: s(&inputs["required_scope"]),
        verifier_namespace: s(&inputs["configured_namespace"]),
        replay_epoch: i(&inputs["configured_replay_epoch"]),
        verifier_id: s(&inputs["configured_verifier_id"]),
        now: i(&inputs["now"]),
        max_challenge_age_seconds: i(&inputs["max_challenge_age_seconds"]),
        future_skew_seconds: i(&inputs["future_skew_seconds"]),
        status_policy: status_policy(&inputs["status_policy"]),
        tzdb_version: s(&inputs["tzdb_version"]),
        ..Default::default()
    };
    for (issuer, key) in inputs["status_keys"].as_object().cloned().unwrap_or_default() {
        req.status_keys.insert(
            issuer,
            V2StatusKeyConfig {
                epoch: u(&key["epoch"]),
                key: public_key_json(&key["public_key"]),
            },
        );
    }
    let e = &inputs["expected_challenge"];
    if !e.is_null() {
        let mut exp = ExpectedChallengeV2 {
            value: unb64(&e["value_b64"]),
            issued_at: i(&e["issued_at"]),
            expires_at: i(&e["expires_at"]),
            verifier_namespace: s(&e["verifier_namespace"]),
            replay_epoch: i(&e["replay_epoch"]),
            verifier_id: s(&e["verifier_id"]),
            ..Default::default()
        };
        // The agent ID and key pass through independently, so a vector can
        // configure either one alone (SPEC-v2 §6.2 step 7).
        if !e["expected_agent_id"].is_null() {
            exp.expected_agent_id = s(&e["expected_agent_id"]);
        }
        if !e["expected_agent_public_key"].is_null() {
            exp.expected_agent_public_key = Some(public_key_json(&e["expected_agent_public_key"]));
        }
        if !e["expected_receiver_id"].is_null() {
            exp.expected_receiver_id = s(&e["expected_receiver_id"]);
        }
        if !e["expected_session_context_b64"].is_null() {
            exp.expected_session_context = Some(unb64(&e["expected_session_context_b64"]));
        }
        req.expected = Some(exp);
    }
    let p = &inputs["context_policy"];
    if !p.is_null() {
        let expected = if p["expected_session_context_b64"].is_null() {
            Vec::new()
        } else {
            unb64(&p["expected_session_context_b64"])
        };
        let fields: Vec<String> = arr(&p["required_fields"]).iter().map(s).collect();
        let policy = V2ContextPolicy::new(&s(&p["profile"]), b(&p["require_bound"]), &fields, &expected)
            .expect("context policy");
        assert_eq!(policy.digest(), s(&p["digest"]), "context policy digest");
        req.context_policy = Some(policy);
    }
    let c = &inputs["request_context"];
    if !c.is_null() {
        req.context = ConstraintContextV2 {
            has_resource: b(&c["has_resource"]),
            requested_resource_id: s(&c["requested_resource_id"]),
            requested_path: s(&c["requested_path"]),
            has_amount: b(&c["has_amount"]),
            requested_amount_micros: i(&c["requested_amount_micros"]),
            requested_currency: s(&c["requested_currency"]),
            extension_counts: c["extension_counts"]
                .as_object()
                .map(|m| m.iter().map(|(k, v)| (k.clone(), i(v))).collect())
                .unwrap_or_default(),
            extension_values: c["extension_values"]
                .as_object()
                .map(|m| m.iter().map(|(k, v)| (k.clone(), s(v))).collect())
                .unwrap_or_default(),
        };
    }
    if !arr(&inputs["constraint_evaluators"]).is_empty() {
        req.constraint_evaluators = Some(build_evaluator_registry(inputs, counts));
    }

    let mut cb = V2VerifyCallbacks::default();
    {
        let counts = Arc::clone(counts);
        let trust = inputs["trust"].clone();
        // `registry` mode resolves through the reference candidate-record
        // trust registry (SPEC-v2 §6.1).
        let registry = (s(&trust["mode"]) == "registry").then(|| {
            let records: Vec<HybridPublicKey> =
                trust["registry"].as_array().expect("trust registry").iter().map(public_key_json).collect();
            TrustRegistry::new(&records).expect("trust registry")
        });
        cb.trust = Some(Arc::new(move |ctx: &V2Context, chain: &[DelegationCertV2]| {
            bump(&counts.trust);
            if let Some(registry) = &registry {
                return registry.resolve(ctx, chain);
            }
            if trust.is_null() {
                return Ok(V2TrustResolution {
                    outcome: V2TrustOutcome::Unavailable,
                    root_key: HybridPublicKey {
                        ed25519: Vec::new(),
                        ml_dsa_65: Vec::new(),
                    },
                });
            }
            match s(&trust["mode"]).as_str() {
                "error" => return Err(V2ProviderError::new("scripted trust provider failure")),
                "panic" => panic!("scripted trust provider panic"),
                _ => {}
            }
            let outcome = V2TrustOutcome::parse(&s(&trust["outcome"]))
                .unwrap_or_else(|| panic!("unknown trust outcome {}", trust["outcome"]));
            let root_key = if trust["root_public_key"].is_null() {
                HybridPublicKey {
                    ed25519: Vec::new(),
                    ml_dsa_65: Vec::new(),
                }
            } else {
                public_key_json(&trust["root_public_key"])
            };
            Ok(V2TrustResolution { outcome, root_key })
        }));
    }
    {
        let counts = Arc::clone(counts);
        let evidence = inputs["status_evidence"].clone();
        cb.status_evidence = Some(Arc::new(move |_ctx: &V2Context, r: &V2StatusEvidenceRequest| {
            bump(&counts.status);
            let script = &evidence[&r.issuer_id];
            if script.is_null() {
                return Ok(V2StatusEvidenceBatch::default());
            }
            match s(&script["mode"]).as_str() {
                "error" => return Err(V2StatusProviderError::new("scripted status provider failure")),
                "panic" => panic!("scripted status provider panic"),
                _ => {}
            }
            Ok(V2StatusEvidenceBatch {
                objects: arr(&script["objects"])
                    .iter()
                    .map(|o| V2StatusEvidenceObject {
                        object_type: u(&o["object_type_code"]) as u16,
                        wire: unb64(&o["wire_b64"]),
                    })
                    .collect(),
            })
        }));
    }
    {
        let counts = Arc::clone(counts);
        let mode = s(&inputs["audience_mode"]);
        let memberships: Vec<V2AudienceMembership> = arr(&inputs["audience_memberships"])
            .iter()
            .map(|m| V2AudienceMembership {
                delegation_index: u(&m["delegation_index"]) as usize,
                constraint_index: u(&m["constraint_index"]) as usize,
                receiver_id: s(&m["receiver_id"]),
                trust_domain_ids: arr(&m["trust_domain_ids"]).iter().map(s).collect(),
                issued_at: i(&m["issued_at"]),
                expires_at: i(&m["expires_at"]),
                evidence_digest: s(&m["evidence_digest"]),
            })
            .collect();
        cb.audience = Some(Arc::new(move |_ctx: &V2Context, _d: &[V2DeferredConstraint], _r: &str| {
            bump(&counts.audience);
            match mode.as_str() {
                "error" => Err(V2ProviderError::new("scripted audience provider failure")),
                "panic" => panic!("scripted audience provider panic"),
                _ => Ok(memberships.clone()),
            }
        }));
    }
    let journal_mode = s(&inputs["journal"]["mode"]);
    if journal_mode != "absent" {
        let inner = JournalStore::new().expect("journal store");
        populate_status_journal(&inner, inputs);
        cb.status_journal = Some(Arc::new(ModalJournalStore {
            inner,
            mode: journal_mode,
            cas_calls: AtomicUsize::new(0),
        }));
    }
    let hook = s(&inputs["receiver_binding_hook"]);
    if hook == "accept" || hook == "reject" {
        let counts = Arc::clone(counts);
        cb.receiver_binding = Some(Arc::new(move |_b: &ProofBundleV2, _e: &ExpectedChallengeV2| {
            bump(&counts.receiver_binding);
            if hook == "reject" {
                return Err(V2ProviderError::new("application receiver binding rejected"));
            }
            Ok(())
        }));
    }
    let mut rate = None;
    let rate_mode = s(&inputs["rate"]);
    if rate_mode != "absent" && !rate_mode.is_empty() {
        let store = Arc::new(ScriptedRateStore {
            mode: rate_mode,
            counts: Arc::clone(counts),
            batch: Mutex::new(Vec::new()),
        });
        cb.rate = Some(store.clone());
        rate = Some(store);
    }
    (req, cb, rate)
}

pub fn evidence_json(v: &Value) -> StatusEvidenceEntryV2 {
    StatusEvidenceEntryV2 {
        issuer_id: s(&v["issuer_id"]),
        status_key_id: s(&v["status_key_id"]),
        sequence: i(&v["sequence"]),
        object_type: u(&v["object_type_code"]) as u16,
        digest: s(&v["digest"]),
    }
}

/// A terminal result and receipt outbox body that a claim store accepts for
/// `claim` (SPEC-v2 §7.5): a genuine committed body from the
/// verifier-ordering corpus, with `verified_at` set (it is not bound), and
/// the claim's bound members set to that body's values. Tests that drive a
/// store's finalization directly use it in place of placeholder payloads.
pub fn bind_claim_to_receipt_body(claim: &mut V2ChallengeClaim, verified_at: i64) -> (Vec<u8>, Vec<u8>) {
    let f = load_v2_vector("verifier-ordering.json");
    let v = arr(&f["vectors"])
        .into_iter()
        .find(|v| s(&v["name"]) == "allow_bound_context")
        .expect("allow_bound_context");
    let mut body = decode_verification_receipt_body_v2(&unb64(&v["expected"]["receipt_body_b64"])).expect("body");
    body.verified_at = verified_at;
    claim.verifier_id = body.verifier_id.clone();
    claim.agent_id = body.agent_id.clone();
    claim.bundle_hash = body.bundle_hash.clone();
    claim.issuer_ids = body.issuer_ids.clone();
    claim.required_scope = body.required_scope.clone();
    claim.context_policy_digest = body.context_policy_digest.clone().unwrap_or_default();
    claim.constraint_evaluators = body.constraint_evaluators.clone();
    let terminal = format!(
        r#"{{"decision":"{}","decision_reason":"{}","identity_status":"{}"}}"#,
        body.decision, body.decision_reason, body.identity_status
    );
    (terminal.into_bytes(), verification_receipt_v2_body(&body).expect("body"))
}

/// A hand-built test claim with the challenge digest of `label` and the claim
/// ID derived from its replay key (SPEC-v2 §2.4); the reference store refuses
/// any other ID (§7.3).
#[allow(dead_code)]
pub fn keyed(mut claim: V2ChallengeClaim, label: &str) -> V2ChallengeClaim {
    use sha2::{Digest, Sha384};
    let digest = Sha384::digest(label.as_bytes());
    claim.challenge_digest = format!("sha384:{}", hex::encode(digest));
    claim.claim_id = protocol_claim_id_from_digest_v2(&claim.namespace, claim.replay_epoch, &digest).expect("claim id");
    claim
}
