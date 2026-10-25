//! JSON representations used by the v2 C ABI for structured inputs and
//! outputs (verification requests, heads, claim and progress records,
//! results). Every schema is documented on the export that uses it. Inputs
//! reject unknown members; an absent member is its zero value unless stated.

use std::collections::BTreeMap;

use ratify_protocol::v2::*;
use ratify_protocol::{base64_std_decode, base64_std_encode, HybridPublicKey};
use serde_json::{json, Map, Value};

use super::{bad_arg, AbiResult};

/// A configured verifier namespace. The library passes it to the claim and
/// issuance store callbacks as a C string, which cannot carry U+0000, so a
/// namespace containing one is `configuration_invalid` before any callback.
fn configured_namespace(o: &Obj, k: &str) -> AbiResult<String> {
    let ns = o.str(k)?;
    match namespace_error(o, k, &ns) {
        Some(e) => Err(e.into()),
        None => Ok(ns),
    }
}

fn namespace_error(o: &Obj, k: &str, ns: &str) -> Option<V2Error> {
    ns.contains('\0').then(|| {
        V2Error::new(
            V2ErrorClass::ConfigurationInvalid,
            format!("{}.{k} contains U+0000", o.name),
        )
    })
}

pub(crate) fn b64(data: &[u8]) -> String {
    base64_std_encode(data)
}

/// A strict JSON object reader: unknown members are rejected; absent or null
/// members read as zero values through the plain getters.
pub(crate) struct Obj<'a> {
    name: String,
    map: &'a Map<String, Value>,
}

static EMPTY: std::sync::OnceLock<Map<String, Value>> = std::sync::OnceLock::new();

impl<'a> Obj<'a> {
    pub fn new(v: &'a Value, name: &str, allowed: &[&str]) -> AbiResult<Obj<'a>> {
        let map = match v {
            Value::Object(m) => m,
            Value::Null => EMPTY.get_or_init(Map::new),
            _ => return Err(bad_arg(format!("{name} must be a JSON object"))),
        };
        for k in map.keys() {
            if !allowed.contains(&k.as_str()) {
                return Err(bad_arg(format!("{name} has unknown member {k:?}")));
            }
        }
        Ok(Obj {
            name: name.to_string(),
            map,
        })
    }

    fn get(&self, k: &str) -> Option<&'a Value> {
        self.map.get(k).filter(|v| !v.is_null())
    }

    pub fn has(&self, k: &str) -> bool {
        self.get(k).is_some()
    }

    pub fn raw(&self, k: &str) -> Option<&'a Value> {
        self.get(k)
    }

    pub fn str(&self, k: &str) -> AbiResult<String> {
        match self.get(k) {
            None => Ok(String::new()),
            Some(Value::String(s)) => Ok(s.clone()),
            Some(_) => Err(bad_arg(format!("{}.{k} must be a string", self.name))),
        }
    }

    pub fn i64(&self, k: &str) -> AbiResult<i64> {
        match self.get(k) {
            None => Ok(0),
            Some(v) => v.as_i64().ok_or_else(|| {
                bad_arg(format!("{}.{k} must be a signed 64-bit integer", self.name))
            }),
        }
    }

    pub fn u64(&self, k: &str) -> AbiResult<u64> {
        match self.get(k) {
            None => Ok(0),
            Some(v) => v.as_u64().ok_or_else(|| {
                bad_arg(format!(
                    "{}.{k} must be an unsigned 64-bit integer",
                    self.name
                ))
            }),
        }
    }

    pub fn bool(&self, k: &str) -> AbiResult<bool> {
        match self.get(k) {
            None => Ok(false),
            Some(Value::Bool(b)) => Ok(*b),
            Some(_) => Err(bad_arg(format!("{}.{k} must be a boolean", self.name))),
        }
    }

    pub fn b64(&self, k: &str) -> AbiResult<Vec<u8>> {
        match self.get(k) {
            None => Ok(Vec::new()),
            Some(Value::String(s)) => base64_std_decode(s)
                .map_err(|e| bad_arg(format!("{}.{k}: invalid base64: {e}", self.name))),
            Some(_) => Err(bad_arg(format!(
                "{}.{k} must be a base64 string",
                self.name
            ))),
        }
    }

    pub fn opt_b64(&self, k: &str) -> AbiResult<Option<Vec<u8>>> {
        if self.has(k) {
            self.b64(k).map(Some)
        } else {
            Ok(None)
        }
    }

    pub fn strings(&self, k: &str) -> AbiResult<Vec<String>> {
        match self.get(k) {
            None => Ok(Vec::new()),
            Some(Value::Array(a)) => a
                .iter()
                .map(|x| {
                    x.as_str().map(str::to_owned).ok_or_else(|| {
                        bad_arg(format!("{}.{k} entries must be strings", self.name))
                    })
                })
                .collect(),
            Some(_) => Err(bad_arg(format!(
                "{}.{k} must be an array of strings",
                self.name
            ))),
        }
    }

    pub fn array(&self, k: &str) -> AbiResult<Vec<&'a Value>> {
        match self.get(k) {
            None => Ok(Vec::new()),
            Some(Value::Array(a)) => Ok(a.iter().collect()),
            Some(_) => Err(bad_arg(format!("{}.{k} must be an array", self.name))),
        }
    }

    pub fn key(&self, k: &str) -> AbiResult<HybridPublicKey> {
        match self.get(k) {
            None => Err(bad_arg(format!("{}.{k} is required", self.name))),
            Some(v) => public_key(v, &format!("{}.{k}", self.name)),
        }
    }

    pub fn opt_key(&self, k: &str) -> AbiResult<Option<HybridPublicKey>> {
        match self.get(k) {
            None => Ok(None),
            Some(v) => public_key(v, &format!("{}.{k}", self.name)).map(Some),
        }
    }

    pub fn object(&self, k: &str) -> Option<&'a Value> {
        self.get(k)
    }
}

/// `{"ed25519": "<b64>", "ml_dsa_65": "<b64>"}`. Component lengths are not
/// checked here; the Protocol functions classify a wrong length.
pub(crate) fn public_key(v: &Value, name: &str) -> AbiResult<HybridPublicKey> {
    let o = Obj::new(v, name, &["ed25519", "ml_dsa_65"])?;
    Ok(HybridPublicKey {
        ed25519: o.b64("ed25519")?,
        ml_dsa_65: o.b64("ml_dsa_65")?,
    })
}

pub(crate) fn public_key_json(k: &HybridPublicKey) -> Value {
    json!({"ed25519": b64(&k.ed25519), "ml_dsa_65": b64(&k.ml_dsa_65)})
}

fn accepted_digests(o: &Obj<'_>) -> AbiResult<BTreeMap<i64, Vec<u8>>> {
    let mut out = BTreeMap::new();
    if let Some(v) = o.object("accepted_digests_b64") {
        let m = v
            .as_object()
            .ok_or_else(|| bad_arg("accepted_digests_b64 must be an object"))?;
        for (k, v) in m {
            let seq = k.parse::<i64>().map_err(|_| {
                bad_arg(format!("accepted_digests_b64 key {k:?} is not an integer"))
            })?;
            let s = v
                .as_str()
                .ok_or_else(|| bad_arg("accepted_digests_b64 values must be base64 strings"))?;
            out.insert(
                seq,
                base64_std_decode(s).map_err(|e| bad_arg(format!("accepted_digests_b64: {e}")))?,
            );
        }
    }
    Ok(out)
}

const HEAD_FIELDS: &[&str] = &[
    "log_id",
    "verifier_id",
    "sequence",
    "head_hash_b64",
    "accepted_digests_b64",
    "frozen",
];

/// A witness or receipt log head: `{"log_id", "sequence", "head_hash_b64",
/// "accepted_digests_b64": {"<seq>": "<b64>"}, "frozen"}` (plus
/// `"verifier_id"` for a receipt log).
pub(crate) fn witness_head(v: &Value) -> AbiResult<WitnessV2Head> {
    let o = Obj::new(v, "head", HEAD_FIELDS)?;
    Ok(WitnessV2Head {
        log_id: o.str("log_id")?,
        sequence: o.i64("sequence")?,
        head_hash: o.b64("head_hash_b64")?,
        accepted_digests: accepted_digests(&o)?,
        frozen: o.bool("frozen")?,
    })
}

pub(crate) fn receipt_head(v: &Value) -> AbiResult<ReceiptV2Head> {
    let o = Obj::new(v, "head", HEAD_FIELDS)?;
    let w = witness_head(v)?;
    Ok(ReceiptV2Head {
        log_id: w.log_id,
        verifier_id: o.str("verifier_id")?,
        sequence: w.sequence,
        head_hash: w.head_hash,
        accepted_digests: w.accepted_digests,
        frozen: w.frozen,
    })
}

/// `{"authority_id", "recovery_epoch", "role", "sequence", "head_hash_b64",
/// "current_key": <key>, "used_key_ids": [..]}`.
pub(crate) fn rotation_state(v: &Value) -> AbiResult<KeyRotationV2State> {
    let o = Obj::new(
        v,
        "rotation_state",
        &[
            "authority_id",
            "recovery_epoch",
            "role",
            "sequence",
            "head_hash_b64",
            "current_key",
            "used_key_ids",
        ],
    )?;
    Ok(KeyRotationV2State {
        authority_id: o.str("authority_id")?,
        recovery_epoch: o.i64("recovery_epoch")?,
        role: o.str("role")?,
        sequence: o.i64("sequence")?,
        head_hash: o.b64("head_hash_b64")?,
        current_key: o.key("current_key")?,
        used_key_ids: o.strings("used_key_ids")?,
    })
}

pub(crate) fn rotation_journal_json(j: &KeyRotationV2Journal) -> Value {
    let s = &j.state;
    json!({
        "authority_id": s.authority_id,
        "recovery_epoch": s.recovery_epoch,
        "role": s.role,
        "sequence": s.sequence,
        "head_hash_b64": b64(&s.head_hash),
        "current_key": public_key_json(&s.current_key),
        "used_key_ids": s.used_key_ids,
        "frozen": j.frozen,
        "accepted_count": j.accepted.len(),
    })
}

/// `{"max_list_lifetime_seconds", "max_status_age_seconds", "clock_skew_seconds"}`.
pub(crate) fn status_policy(v: &Value) -> AbiResult<RevocationStatusPolicyV2> {
    let o = Obj::new(
        v,
        "status_policy",
        &[
            "max_list_lifetime_seconds",
            "max_status_age_seconds",
            "clock_skew_seconds",
        ],
    )?;
    Ok(RevocationStatusPolicyV2 {
        max_list_lifetime_seconds: o.i64("max_list_lifetime_seconds")?,
        max_status_age_seconds: o.i64("max_status_age_seconds")?,
        clock_skew_seconds: o.i64("clock_skew_seconds")?,
    })
}

/// `{"<issuer_id>": {"epoch": <uint>, "public_key": <key>}}`.
pub(crate) fn status_keys(v: Option<&Value>) -> AbiResult<BTreeMap<String, V2StatusKeyConfig>> {
    let mut out = BTreeMap::new();
    let Some(v) = v else { return Ok(out) };
    let m = v
        .as_object()
        .ok_or_else(|| bad_arg("status_keys must be an object"))?;
    for (issuer, cfg) in m {
        let o = Obj::new(cfg, "status_keys entry", &["epoch", "public_key"])?;
        out.insert(
            issuer.clone(),
            V2StatusKeyConfig {
                epoch: o.u64("epoch")?,
                key: o.key("public_key")?,
            },
        );
    }
    Ok(out)
}

const EXPECTED_FIELDS: &[&str] = &[
    "value_b64",
    "issued_at",
    "expires_at",
    "verifier_namespace",
    "replay_epoch",
    "verifier_id",
    "expected_agent_id",
    "expected_agent_public_key",
    "expected_receiver_id",
    "expected_session_context_b64",
];

/// The authenticated `ExpectedChallenge`: `{"value_b64", "issued_at",
/// "expires_at", "verifier_namespace", "replay_epoch", "verifier_id",
/// "expected_agent_id"?, "expected_agent_public_key"?,
/// "expected_receiver_id"?, "expected_session_context_b64"?}`.
pub(crate) fn expected_challenge(v: &Value) -> AbiResult<ExpectedChallengeV2> {
    let o = Obj::new(v, "expected_challenge", EXPECTED_FIELDS)?;
    Ok(ExpectedChallengeV2 {
        value: o.b64("value_b64")?,
        issued_at: o.i64("issued_at")?,
        expires_at: o.i64("expires_at")?,
        verifier_namespace: o.str("verifier_namespace")?,
        replay_epoch: o.i64("replay_epoch")?,
        verifier_id: o.str("verifier_id")?,
        expected_agent_id: o.str("expected_agent_id")?,
        expected_agent_public_key: o.opt_key("expected_agent_public_key")?,
        expected_receiver_id: o.str("expected_receiver_id")?,
        expected_session_context: o.opt_b64("expected_session_context_b64")?,
        context_policy: None,
    })
}

pub(crate) fn expected_challenge_json(e: &ExpectedChallengeV2) -> Value {
    let mut m = Map::new();
    m.insert("value_b64".into(), json!(b64(&e.value)));
    m.insert("issued_at".into(), json!(e.issued_at));
    m.insert("expires_at".into(), json!(e.expires_at));
    m.insert("verifier_namespace".into(), json!(e.verifier_namespace));
    m.insert("replay_epoch".into(), json!(e.replay_epoch));
    m.insert("verifier_id".into(), json!(e.verifier_id));
    if !e.expected_agent_id.is_empty() {
        m.insert("expected_agent_id".into(), json!(e.expected_agent_id));
    }
    if let Some(k) = &e.expected_agent_public_key {
        m.insert("expected_agent_public_key".into(), public_key_json(k));
    }
    if !e.expected_receiver_id.is_empty() {
        m.insert("expected_receiver_id".into(), json!(e.expected_receiver_id));
    }
    if let Some(c) = &e.expected_session_context {
        m.insert("expected_session_context_b64".into(), json!(b64(c)));
    }
    Value::Object(m)
}

/// `{"profile", "require_bound", "required_fields": [..],
/// "expected_session_context_b64": <b64>|null}`.
pub(crate) fn context_policy(v: &Value) -> AbiResult<V2Result<V2ContextPolicy>> {
    let o = Obj::new(
        v,
        "context_policy",
        &[
            "profile",
            "require_bound",
            "required_fields",
            "expected_session_context_b64",
        ],
    )?;
    let expected = o.b64("expected_session_context_b64")?;
    Ok(V2ContextPolicy::new(
        &o.str("profile")?,
        o.bool("require_bound")?,
        &o.strings("required_fields")?,
        &expected,
    ))
}

/// `{"has_resource", "requested_resource_id", "requested_path",
/// "has_amount", "requested_amount_micros", "requested_currency",
/// "extension_counts": {"<name>": <int>}, "extension_values": {"<name>": "<text>"}}`.
pub(crate) fn constraint_context(v: &Value) -> AbiResult<ConstraintContextV2> {
    let o = Obj::new(
        v,
        "context",
        &[
            "has_resource",
            "requested_resource_id",
            "requested_path",
            "has_amount",
            "requested_amount_micros",
            "requested_currency",
            "extension_counts",
            "extension_values",
        ],
    )?;
    let mut counts = BTreeMap::new();
    if let Some(m) = o.object("extension_counts") {
        for (k, n) in m
            .as_object()
            .ok_or_else(|| bad_arg("extension_counts must be an object"))?
        {
            counts.insert(
                k.clone(),
                n.as_i64()
                    .ok_or_else(|| bad_arg("extension_counts values must be integers"))?,
            );
        }
    }
    let mut values = BTreeMap::new();
    if let Some(m) = o.object("extension_values") {
        for (k, s) in m
            .as_object()
            .ok_or_else(|| bad_arg("extension_values must be an object"))?
        {
            values.insert(
                k.clone(),
                s.as_str()
                    .ok_or_else(|| bad_arg("extension_values values must be strings"))?
                    .to_string(),
            );
        }
    }
    Ok(ConstraintContextV2 {
        has_resource: o.bool("has_resource")?,
        requested_resource_id: o.str("requested_resource_id")?,
        requested_path: o.str("requested_path")?,
        has_amount: o.bool("has_amount")?,
        requested_amount_micros: o.i64("requested_amount_micros")?,
        requested_currency: o.str("requested_currency")?,
        extension_counts: counts,
        extension_values: values,
    })
}

pub(crate) fn constraint_context_json(c: &ConstraintContextV2) -> Value {
    json!({
        "has_resource": c.has_resource,
        "requested_resource_id": c.requested_resource_id,
        "requested_path": c.requested_path,
        "has_amount": c.has_amount,
        "requested_amount_micros": c.requested_amount_micros,
        "requested_currency": c.requested_currency,
        "extension_counts": c.extension_counts,
        "extension_values": c.extension_values,
    })
}

/// The request members shared by the live verifier and the claim stage.
pub(crate) const REQUEST_FIELDS: &[&str] = &[
    "required_scope",
    "verifier_namespace",
    "replay_epoch",
    "verifier_id",
    "now",
    "max_challenge_age_seconds",
    "future_skew_seconds",
    "tzdb_version",
    "status_keys",
    "status_policy",
    "expected_challenge",
    "context_policy",
    "context",
];

/// A verification request (everything but the bundle, the evaluator
/// registry, and the callbacks), with the SPEC-v2 §6.2 step-2 failures found
/// while reading it. Step 1 (bundle decode) comes first, so the caller
/// reports these only for a bundle that decodes, as a preflight outcome.
pub(crate) struct ParsedVerifyRequest {
    pub(crate) req: V2VerifyRequest,
    /// The configured namespace contains U+0000, which no callback can
    /// receive (a configured bound; `verifier_namespace` keeps the value).
    pub(crate) namespace_error: Option<V2Error>,
    /// The context policy failed construction (`context_policy` is `None`).
    pub(crate) policy_error: Option<V2Error>,
}

impl ParsedVerifyRequest {
    /// The step-2 failure to report in place of
    /// `expected_challenge_unavailable` from a verification run without the
    /// challenge record. The configured bounds precede the challenge record
    /// in step 2, and the context policy follows it.
    pub(crate) fn step2_failure(&self) -> Option<V2Error> {
        if let Some(e) = &self.namespace_error {
            return Some(e.clone());
        }
        self.policy_error.clone().filter(|_| self.req.expected.is_some())
    }

    pub(crate) fn has_step2_failure(&self) -> bool {
        self.namespace_error.is_some() || self.policy_error.is_some()
    }
}

pub(crate) fn verify_request(v: &Value) -> AbiResult<ParsedVerifyRequest> {
    let o = Obj::new(v, "request", REQUEST_FIELDS)?;
    let namespace = o.str("verifier_namespace")?;
    let namespace_error = namespace_error(&o, "verifier_namespace", &namespace);
    let mut req = V2VerifyRequest {
        required_scope: o.str("required_scope")?,
        verifier_namespace: namespace,
        replay_epoch: o.i64("replay_epoch")?,
        verifier_id: o.str("verifier_id")?,
        now: o.i64("now")?,
        max_challenge_age_seconds: o.i64("max_challenge_age_seconds")?,
        future_skew_seconds: o.i64("future_skew_seconds")?,
        tzdb_version: o.str("tzdb_version")?,
        status_keys: status_keys(o.object("status_keys"))?,
        ..Default::default()
    };
    if let Some(p) = o.object("status_policy") {
        req.status_policy = status_policy(p)?;
    }
    if let Some(e) = o.object("expected_challenge") {
        req.expected = Some(expected_challenge(e)?);
    }
    if let Some(c) = o.object("context") {
        req.context = constraint_context(c)?;
    }
    let mut policy_error = None;
    if let Some(p) = o.object("context_policy") {
        match context_policy(p)? {
            Ok(policy) => req.context_policy = Some(policy),
            Err(e) => policy_error = Some(e),
        }
    }
    Ok(ParsedVerifyRequest {
        req,
        namespace_error,
        policy_error,
    })
}

pub(crate) fn evidence_json(e: &StatusEvidenceEntryV2) -> Value {
    json!({
        "issuer_id": e.issuer_id,
        "status_key_id": e.status_key_id,
        "sequence": e.sequence,
        "object_type_code": e.object_type,
        "digest": e.digest,
    })
}

pub(crate) fn evidence(v: &Value) -> AbiResult<StatusEvidenceEntryV2> {
    let o = Obj::new(
        v,
        "status_evidence entry",
        &[
            "issuer_id",
            "status_key_id",
            "sequence",
            "object_type_code",
            "digest",
        ],
    )?;
    Ok(StatusEvidenceEntryV2 {
        issuer_id: o.str("issuer_id")?,
        status_key_id: o.str("status_key_id")?,
        sequence: o.i64("sequence")?,
        object_type: u16::try_from(o.u64("object_type_code")?)
            .map_err(|_| bad_arg("object_type_code is outside 0..65535"))?,
        digest: o.str("digest")?,
    })
}

// ---------------------------------------------------------------------------
// Claim and progress records (the claim-store callback representations)

fn opt_json<T: Into<Value> + Clone>(v: &Option<T>) -> Value {
    match v {
        Some(x) => x.clone().into(),
        None => Value::Null,
    }
}

/// The claim record handed to a claim store: a deterministic JSON encoding of
/// every immutable claim field (sorted members, no insignificant
/// whitespace). Equal records encode to equal bytes.
pub(crate) fn claim_json(c: &V2ChallengeClaim) -> Vec<u8> {
    let v = json!({
        "claim_id": c.claim_id,
        "namespace": c.namespace,
        "replay_epoch": c.replay_epoch,
        "challenge_digest": c.challenge_digest,
        "proof_digest": c.proof_digest,
        "bundle_hash": c.bundle_hash,
        "issuer_ids": c.issuer_ids,
        "required_scope": c.required_scope,
        "context_policy_digest": c.context_policy_digest,
        "verifier_id": c.verifier_id,
        "agent_id": c.agent_id,
        "requires_rate": c.requires_rate,
        "rate_batch": c.rate_batch.iter().map(|r| json!({
            "issuer_id": r.issuer_id, "cert_id": r.cert_id, "window_s": r.window_s, "limit": r.limit,
        })).collect::<Vec<_>>(),
        "issued_at": c.issued_at,
        "expires_at": c.expires_at,
        "max_age_seconds": c.max_age_seconds,
        "clock_skew_seconds": c.clock_skew_seconds,
        "stream_id_b64": opt_json(&c.stream_id.as_ref().map(|s| b64(s))),
        "stream_seq": opt_json(&c.stream_seq),
        "constraint_evaluators": c.constraint_evaluators.iter().map(|e| json!({
            "type": e.kind, "profile_digest": e.profile_digest,
        })).collect::<Vec<_>>(),
    });
    serde_json::to_vec(&v).unwrap_or_default()
}

pub(crate) fn claim_from_json(data: &[u8]) -> AbiResult<V2ChallengeClaim> {
    let v: Value = super::strict_json(data).map_err(|e| bad_arg(format!("claim record: {e}")))?;
    let o = Obj::new(
        &v,
        "claim record",
        &[
            "claim_id",
            "namespace",
            "replay_epoch",
            "challenge_digest",
            "proof_digest",
            "bundle_hash",
            "issuer_ids",
            "required_scope",
            "context_policy_digest",
            "verifier_id",
            "agent_id",
            "requires_rate",
            "rate_batch",
            "issued_at",
            "expires_at",
            "max_age_seconds",
            "clock_skew_seconds",
            "stream_id_b64",
            "stream_seq",
            "constraint_evaluators",
        ],
    )?;
    let mut rate_batch = Vec::new();
    for r in o.array("rate_batch")? {
        let r = Obj::new(
            r,
            "rate_batch entry",
            &["issuer_id", "cert_id", "window_s", "limit"],
        )?;
        rate_batch.push(V2RateReservation {
            issuer_id: r.str("issuer_id")?,
            cert_id: r.str("cert_id")?,
            window_s: r.i64("window_s")?,
            limit: r.i64("limit")?,
        });
    }
    let mut evaluators = Vec::new();
    for e in o.array("constraint_evaluators")? {
        let e = Obj::new(
            e,
            "constraint_evaluators entry",
            &["type", "profile_digest"],
        )?;
        evaluators.push(ConstraintEvaluatorRefV2 {
            kind: e.str("type")?,
            profile_digest: e.str("profile_digest")?,
        });
    }
    Ok(V2ChallengeClaim {
        claim_id: o.str("claim_id")?,
        namespace: o.str("namespace")?,
        replay_epoch: o.i64("replay_epoch")?,
        challenge_digest: o.str("challenge_digest")?,
        proof_digest: o.str("proof_digest")?,
        bundle_hash: o.str("bundle_hash")?,
        issuer_ids: o.strings("issuer_ids")?,
        required_scope: o.str("required_scope")?,
        context_policy_digest: o.str("context_policy_digest")?,
        verifier_id: o.str("verifier_id")?,
        agent_id: o.str("agent_id")?,
        requires_rate: o.bool("requires_rate")?,
        rate_batch,
        issued_at: o.i64("issued_at")?,
        expires_at: o.i64("expires_at")?,
        max_age_seconds: o.i64("max_age_seconds")?,
        clock_skew_seconds: o.i64("clock_skew_seconds")?,
        stream_id: o.opt_b64("stream_id_b64")?,
        stream_seq: if o.has("stream_seq") {
            Some(o.i64("stream_seq")?)
        } else {
            None
        },
        constraint_evaluators: evaluators,
    })
}

/// The evaluation progress record: `{"trust_assessment",
/// "status_assessment", "context_assessment", "context_policy_digest":
/// <str>|null, "status_evidence": [<evidence>]}`.
pub(crate) fn progress_json(p: &V2EvaluationProgress) -> Vec<u8> {
    let v = json!({
        "trust_assessment": p.trust_assessment,
        "status_assessment": p.status_assessment,
        "context_assessment": p.context_assessment,
        "context_policy_digest": opt_json(&p.context_policy_digest),
        "status_evidence": p.status_evidence.iter().map(evidence_json).collect::<Vec<_>>(),
    });
    serde_json::to_vec(&v).unwrap_or_default()
}

pub(crate) fn progress_from_json(data: &[u8]) -> AbiResult<V2EvaluationProgress> {
    let v: Value =
        super::strict_json(data).map_err(|e| bad_arg(format!("progress record: {e}")))?;
    let o = Obj::new(
        &v,
        "progress record",
        &[
            "trust_assessment",
            "status_assessment",
            "context_assessment",
            "context_policy_digest",
            "status_evidence",
        ],
    )?;
    Ok(V2EvaluationProgress {
        trust_assessment: o.str("trust_assessment")?,
        status_assessment: o.str("status_assessment")?,
        context_assessment: o.str("context_assessment")?,
        context_policy_digest: if o.has("context_policy_digest") {
            Some(o.str("context_policy_digest")?)
        } else {
            None
        },
        status_evidence: o
            .array("status_evidence")?
            .into_iter()
            .map(evidence)
            .collect::<AbiResult<_>>()?,
    })
}

// ---------------------------------------------------------------------------
// Results

pub(crate) fn status_result_json(r: &RevocationStatusResultV2) -> Value {
    json!({
        "status": r.status,
        "reason": r.reason,
        "evidence": r.evidence.iter().map(evidence_json).collect::<Vec<_>>(),
        "fresh_until": r.fresh_until,
    })
}

pub(crate) fn status_state_json(s: &RevocationStatusStateV2) -> Value {
    json!({
        "issuer_id": s.issuer_id,
        "status_key_epoch": s.status_key_epoch,
        "status_key_id": s.status_key_id,
        "retired_status_key_ids": s.retired_status_key_ids,
        "has_floor": s.has_floor,
        "floor": s.floor,
        "accepted_cert_ids": s.accepted_cert_ids,
        "has_preceding_checkpoint": s.has_preceding_checkpoint,
        "preceding_floor": s.preceding_floor,
        "preceding_accepted_cert_ids": s.preceding_accepted_cert_ids,
        "deny_union_cert_ids": s.deny_union_cert_ids,
        "observation_count": s.observations.len(),
        "observations": s.observations.iter().map(|o| json!({
            "object_type_code": o.object_type,
            "status_key_epoch": o.status_key_epoch,
            "status_key_id": o.status_key_id,
            "sequence": o.sequence,
            "evidence_digest": b64(&o.evidence_digest),
            "body_digest": b64(&o.body_digest),
            "revoked_set_digest": b64(&o.revoked_set_digest),
            "revoked_cert_ids": o.revoked_cert_ids,
            "future_dated": o.future_dated,
            "fork": o.fork,
            "gap": o.gap,
            "accepted": o.accepted,
        })).collect::<Vec<_>>(),
        "max_observed_sequence": s.max_observed_sequence,
        "fork_sequence": s.fork_sequence,
        "reconciliation_required": s.reconciliation_required,
        "future_dated_object_observed": s.future_dated_object_observed,
    })
}

pub(crate) fn transaction_result_json(r: &TransactionReceiptVerificationV2) -> Value {
    json!({
        "transaction_id": r.transaction_id,
        "actionable": r.actionable,
        "parties": r.parties.iter().map(|p| json!({
            "party_id": p.party_id,
            "agent_id": p.agent_id,
            "required_scope": p.required_scope,
            "trust_assessment": p.trust_assessment,
            "delegation_assessment": p.delegation_assessment,
            "delegation_expires_at": opt_json(&p.delegation_expires_at),
            "status_assessment": p.status_assessment,
            "scope_assessment": p.scope_assessment,
            "freshness": p.freshness,
            "status_evidence_digests": p.status_evidence.iter().map(evidence_json).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

pub(crate) fn archival_json(r: &ArchivalVerificationV2) -> Value {
    json!({
        "object_type_code": r.object_type,
        "freshness": r.freshness,
        "actionable": r.actionable,
        "digest": r.digest,
        "signer_key_ids": r.signer_key_ids,
    })
}

/// `{"verifier_namespace", "replay_epoch", "verifier_id",
/// "lifetime_seconds", "expected_agent_id"?, "expected_agent_public_key"?,
/// "expected_receiver_id"?, "expected_session_context_b64"?}`.
pub(crate) fn issue_request(v: &Value) -> AbiResult<V2ChallengeIssueRequest> {
    let o = Obj::new(
        v,
        "issue request",
        &[
            "verifier_namespace",
            "replay_epoch",
            "verifier_id",
            "lifetime_seconds",
            "expected_agent_id",
            "expected_agent_public_key",
            "expected_receiver_id",
            "expected_session_context_b64",
        ],
    )?;
    Ok(V2ChallengeIssueRequest {
        verifier_namespace: configured_namespace(&o, "verifier_namespace")?,
        replay_epoch: o.i64("replay_epoch")?,
        verifier_id: o.str("verifier_id")?,
        lifetime_seconds: o.i64("lifetime_seconds")?,
        expected_agent_id: o.str("expected_agent_id")?,
        expected_agent_public_key: o.opt_key("expected_agent_public_key")?,
        expected_receiver_id: o.str("expected_receiver_id")?,
        expected_session_context: o.opt_b64("expected_session_context_b64")?,
    })
}

/// `{"verifier_id", "workspace_id", "agent_id", "session_id",
/// "invocation_id", "request_hash_b64"}`.
pub(crate) fn session_inputs(v: &Value) -> AbiResult<SessionContextV2Inputs> {
    let o = Obj::new(
        v,
        "session inputs",
        &[
            "verifier_id",
            "workspace_id",
            "agent_id",
            "session_id",
            "invocation_id",
            "request_hash_b64",
        ],
    )?;
    Ok(SessionContextV2Inputs {
        verifier_id: o.str("verifier_id")?,
        workspace_id: o.str("workspace_id")?,
        agent_id: o.str("agent_id")?,
        session_id: o.str("session_id")?,
        invocation_id: o.str("invocation_id")?,
        request_hash: o.b64("request_hash_b64")?,
    })
}

/// `{"required_scope", "operation", "resource_id", "requested_path",
/// "payload_digest_b64"}`.
pub(crate) fn operation_context(v: &Value) -> AbiResult<OperationContextV2> {
    let o = Obj::new(
        v,
        "operation context",
        &[
            "required_scope",
            "operation",
            "resource_id",
            "requested_path",
            "payload_digest_b64",
        ],
    )?;
    Ok(OperationContextV2 {
        required_scope: o.str("required_scope")?,
        operation: o.str("operation")?,
        resource_id: o.str("resource_id")?,
        requested_path: o.str("requested_path")?,
        payload_digest: o.b64("payload_digest_b64")?,
    })
}

pub(crate) fn to_bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}
