//! Cross-SDK fixtures (SPEC-v2 §8.1, `testvectors/v2/README.md` section
//! `cross-sdk/`; Go `internal/v2vectors/crosssdk.go`).
//!
//! Every SDK writes `testvectors/v2/cross-sdk/<sdk>.json` from freshly
//! generated keys and hedged ML-DSA-65 signatures, and every SDK verifies
//! every file present. [`generate_cross_sdk_fixture_v2`] produces such a file
//! through this crate's public typed signers and checks it with
//! [`verify_cross_sdk_fixture_v2`] before returning it. Seeds in a fixture are
//! throwaway test data and must never be used as production keys.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use super::constraints::{
    is_registered_constraint_type_v2, ConstraintV2, CONSTRAINT_MAX_AMOUNT, CONSTRAINT_MAX_RATE,
    CONSTRAINT_RECEIVER_AUDIENCE, CONSTRAINT_RESOURCE_PATH, CONSTRAINT_TIME_WINDOW,
};
use super::crypto::{key_id_v2, v2_mldsa_context, v2_signing_message, V2ObjectType};
use super::errors::{V2Error, V2ErrorClass, V2Result, V2SignError};
use super::evaluator::{
    constraint_profile_digest_v2, ConstraintEvaluatorRefV2, ConstraintProfileDescriptorV2, CONSTRAINT_MAX_COUNT_V2,
    PROFILE_MAX_COUNT_V2,
};
use super::json::canonical_json_v2;
use super::operation_context::{
    build_session_context_v2, challenge_claim_digest_v2, operation_context_v2_hash, protocol_claim_id_v2,
    OperationContextV2, SessionContextV2Inputs,
};
use super::receipt::{
    check_verification_receipt_v2_bundle_binding, decode_verification_receipt_v2, encode_verification_receipt_v2,
    sign_verification_receipt_v2, verification_receipt_v2_body, verification_receipt_v2_digest,
    verify_verification_receipt_v2, ReceiptV2Head, StatusEvidenceEntryV2, VerificationReceiptV2,
};
use super::rotation::{
    decode_key_rotation_statement_v2, encode_key_rotation_statement_v2, key_rotation_statement_v2_digest,
    sign_key_rotation_statement_v2, verify_key_rotation_statement_v2, KeyRotationStatementV2, KeyRotationV2State,
};
use super::signer::external_mu_v2;
use super::transaction::{
    decode_transaction_receipt_v2, encode_transaction_receipt_v2, sign_transaction_receipt_party_v2,
    transaction_context_hash_v2, transaction_party_request_hash_v2, transaction_receipt_v2_sign_bytes,
    verify_transaction_receipt_v2_signatures, TransactionReceiptPartyV2, TransactionReceiptV2,
};
use super::wire::{
    bundle_hash_v2, decode_delegation_cert_v2, decode_proof_bundle_v2, decode_revocation_list_v2,
    decode_revocation_push_v2, delegation_digest_v2, encode_delegation_cert_v2, encode_proof_bundle_v2,
    encode_revocation_list_v2, encode_revocation_push_v2, sign_delegation_cert_v2, sign_proof_bundle_v2,
    sign_revocation_list_v2, sign_revocation_push_v2, status_evidence_digest_list_v2, status_evidence_digest_push_v2,
    verify_delegation_cert_v2_signature, verify_proof_bundle_v2_signatures, verify_revocation_list_v2_signature,
    verify_revocation_push_v2_signature, DelegationCertV2, ProofBundleV2, RevocationListV2, RevocationPushV2,
    RevokedCertV2,
};
use super::witness::{
    decode_witness_entry_v2, encode_witness_entry_v2, sign_witness_entry_v2, verify_witness_entry_v2,
    witness_entry_v2_digest, WitnessEntryV2, WitnessV2Head,
};
use super::authorization::TZDB_VERSION_V2;
use super::context::V2Context;
use super::context_policy::V2ContextPolicy;
use super::journal::configure_status_key_epoch_v2;
use super::preflight::ExpectedChallengeV2;
use super::reference::{JournalStore, Store};
use super::release::{release_v2_decision, V2ReceiptPublisher, V2ReleaseConfig};
use super::status::RevocationStatusPolicyV2;
use super::status_provenance::{
    V2StatusEvidenceBatch, V2StatusEvidenceObject, V2StatusEvidenceRequest, V2StatusKeyConfig,
};
use super::verify::{
    verify_proof_bundle_v2, V2TrustOutcome, V2TrustResolution, V2VerifyCallbacks, V2VerifyRequest, V2VerifyStage,
};
use crate::crypto::{derive_id, hybrid_keypair_from_seeds};
use crate::types::{HybridPrivateKey, HybridPublicKey, HybridSignature, ParamsValue};

/// SDK names a cross-SDK fixture file may carry (`cross-sdk/<sdk>.json`).
pub const CROSS_SDK_NAMES_V2: [&str; 5] = ["go", "typescript", "python", "rust", "c"];

/// Key names every cross-SDK fixture defines, in file order.
pub const CROSS_SDK_KEY_NAMES_V2: [&str; 11] = [
    "root",
    "intermediate",
    "agent",
    "verifier",
    "status_root",
    "status_intermediate",
    "witness",
    "party_b_root",
    "party_b_agent",
    "rotation_genesis",
    "rotation_second",
];

/// Object kinds every cross-SDK fixture contains at least once.
pub const CROSS_SDK_KINDS_V2: [&str; 9] = [
    "delegation_certificate",
    "proof_bundle",
    "revocation_list",
    "revocation_push",
    "key_rotation_statement",
    "witness_entry",
    "transaction_receipt",
    "verification_receipt",
    "receipt_bundle_binding",
];

/// The fixed evaluation time every fixture timestamp is relative to.
pub const CROSS_SDK_NOW_V2: i64 = 1_800_000_000;

const DESCRIPTION: &str = "Cross-SDK fixture (SPEC-v2 §8.1). keys are freshly generated by the producing SDK (keys.json entry schema; seeds are throwaway test data). objects follow the objects.json object schema: every ML-DSA-65 component is hedged, so signature bytes are not reproducible. A verifying SDK MUST derive each public key and key_id_v2 from its seeds, and for every object decode wire_b64, re-encode it to identical bytes, derive each signable projection, transcript M, context, tr and mu, find each pinned signature in the wire object, verify every signature with the named verify context (key names resolve to this file's keys), and reproduce every digest. A receipt_bundle_binding object is verified by strict decode of wire_b64 (verification receipt) and bundle_b64 (proof bundle) and the receipt/bundle binding check. scenarios are verifier and release scenarios produced by this SDK: replay each through your own verifier, reference store and release gate under scenario_configuration (testvectors/v2/README.md, cross-sdk), release with the scenario's signed_receipt_b64, and require the same receipt outbox body, allow horizon and release result. Timestamps are relative to the fixed evaluation time 1800000000.";

const NOW: i64 = CROSS_SDK_NOW_V2;
const WORKSPACE: &str = "00000000-0000-4000-8000-000000000001";
const NAMESPACE: &str = "verify-test";
const REPLAY_EPOCH: i64 = 3;
const VERIFY_POLICY: &str = "ratify.verify.session-context/v1";
const VERIFY_POLICY_FIELDS: [&str; 6] = [
    "verifier_id",
    "workspace_id",
    "agent_id",
    "session_id",
    "invocation_id",
    "request_hash",
];
const ROTATION_AUTHORITY: &str = "0123456789abcdef0123456789abcdef";
const WITNESS_LOG: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1";
const RECEIPT_LOG_A: &str = "cccccccccccccccccccccccccccccc01";
const RECEIPT_LOG_B: &str = "cccccccccccccccccccccccccccccc02";
const TX_TERMS: &str = r#"{"amount":100,"currency":"USD","item":"widget"}"#;

// ---------------------------------------------------------------------------
// File schema

/// One cross-SDK fixture file. Field order is the file order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSdkFixtureV2 {
    pub version: i64,
    pub description: String,
    pub sdk: String,
    pub sdk_version: String,
    pub generator: String,
    pub kind_object_type_codes: BTreeMap<String, i64>,
    pub keys: Vec<CrossSdkKeyV2>,
    pub objects: Vec<CrossSdkObjectV2>,
    /// The fixed configuration of the verifier and release scenarios
    /// (SPEC-v2 §8.1). A fixture without it predates the scenarios.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scenario_configuration: Option<CrossSdkScenarioConfigV2>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scenarios: Vec<CrossSdkScenarioV2>,
}

/// A `keys.json` key entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSdkKeyV2 {
    pub name: String,
    pub ed25519_seed_hex: String,
    pub ml_dsa_65_seed_hex: String,
    pub public_key: BTreeMap<String, String>,
    pub key_id_v2: String,
    pub v1_key_id_128: String,
}

/// An `objects.json` object entry plus the optional `bundle_b64`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSdkObjectV2 {
    pub name: String,
    pub kind: String,
    pub description: String,
    pub wire_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_b64: Option<String>,
    pub verify: CrossSdkVerifyV2,
    pub signatures: Vec<CrossSdkSignatureV2>,
    pub digests: BTreeMap<String, String>,
}

/// One signature transcript record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSdkSignatureV2 {
    pub field: String,
    pub object_type_code: i64,
    pub signer: String,
    pub signer_key_id_v2: String,
    pub signable_b64: String,
    pub signable_sha384_hex: String,
    pub message_b64: String,
    pub mldsa_context: String,
    pub mldsa_tr_b64: String,
    pub mldsa_mu_b64: String,
    pub signature: BTreeMap<String, String>,
}

/// The per-kind verify context of `objects.json`. Key names resolve to the
/// fixture's own keys.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSdkVerifyV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_issuer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_state: Option<CrossSdkRotationStateV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<CrossSdkHeadV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub now: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub future_skew_seconds: Option<i64>,
}

/// Caller-authenticated witness or receipt log head.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSdkHeadV2 {
    pub log_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_id: Option<String>,
    pub sequence: i64,
    pub head_hash_b64: String,
    pub accepted_digests_b64: BTreeMap<String, String>,
    pub frozen: bool,
}

/// Caller-authenticated rotation state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSdkRotationStateV2 {
    pub authority_id: String,
    pub recovery_epoch: i64,
    pub role: String,
    pub sequence: i64,
    pub head_hash_b64: String,
    pub current_key: String,
    pub used_key_ids: Vec<String>,
}

/// The fixed `scenario_configuration` of every cross-SDK fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSdkScenarioConfigV2 {
    pub verifier_namespace: String,
    pub replay_epoch: i64,
    /// Key name; it signs receipts and is configured for release.
    pub verifier_key: String,
    pub receipt_log_id: String,
    pub lease_seconds: i64,
    pub max_challenge_age_seconds: i64,
    pub future_skew_seconds: i64,
    pub status_policy: CrossSdkStatusPolicyV2,
    pub tzdb_version: String,
}

/// The scenario status policy (verifier-ordering.json `status_policy`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSdkStatusPolicyV2 {
    pub max_list_lifetime_seconds: i64,
    pub max_status_age_seconds: i64,
    pub clock_skew_seconds: i64,
}

/// One verifier and release scenario (testvectors/v2/README.md, cross-sdk).
/// Key names resolve to the fixture's own keys.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSdkScenarioV2 {
    pub name: String,
    pub description: String,
    pub bundle_b64: String,
    pub required_scope: String,
    pub expected_challenge: CrossSdkExpectedChallengeV2,
    pub context_policy: Option<CrossSdkContextPolicyV2>,
    pub trust_root_key: String,
    pub status_keys: BTreeMap<String, CrossSdkStatusKeyV2>,
    pub status_evidence: BTreeMap<String, Vec<CrossSdkEvidenceObjectV2>>,
    pub verify_time: i64,
    pub publish_time: i64,
    pub release_time: i64,
    pub expected: CrossSdkScenarioExpectV2,
}

/// The verifier-ordering.json `expected_challenge` schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSdkExpectedChallengeV2 {
    pub value_b64: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub verifier_namespace: String,
    pub replay_epoch: i64,
    pub verifier_id: String,
    pub expected_agent_id: Option<String>,
    pub expected_agent_public_key: Option<BTreeMap<String, String>>,
    pub expected_receiver_id: Option<String>,
    pub expected_session_context_b64: Option<String>,
}

/// The verifier-ordering.json `context_policy` schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSdkContextPolicyV2 {
    pub profile: String,
    pub require_bound: bool,
    pub required_fields: Vec<String>,
    pub expected_session_context_b64: Option<String>,
    pub digest: String,
}

/// A status key configured for one issuer at one epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSdkStatusKeyV2 {
    pub epoch: u64,
    pub key: String,
}

/// One signed status object the scenario's status provider returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSdkEvidenceObjectV2 {
    pub object_type_code: i64,
    pub wire_b64: String,
}

/// What the producing SDK observed for one scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSdkScenarioExpectV2 {
    /// The exact sealed receipt outbox body.
    pub receipt_body_b64: String,
    /// The handoff allow horizon; `None` unless allow.
    pub allow_horizon: Option<i64>,
    /// The producer's signed receipt (log `receipt_log_id`, sequence 1).
    pub signed_receipt_b64: String,
    pub release: CrossSdkReleaseV2,
}

/// The `ReleaseV2Decision` result of one scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSdkReleaseV2 {
    pub status: String,
    /// `None` when released.
    pub reason: Option<String>,
    /// The released decision; `None` unless released.
    pub decision: Option<String>,
    /// `None` unless released.
    pub release_time: Option<i64>,
}

// ---------------------------------------------------------------------------
// Shared helpers

fn malformed(message: impl Into<String>) -> V2Error {
    V2Error::new(V2ErrorClass::Malformed, message)
}

fn sign_err(e: V2SignError) -> V2Error {
    match e {
        V2SignError::InvalidObject(e) | V2SignError::SignatureRejected(e) => e,
        other => V2Error::new(V2ErrorClass::ConfigurationInvalid, other.to_string()),
    }
}

fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

fn b64d(s: &str) -> V2Result<Vec<u8>> {
    STANDARD
        .decode(s)
        .map_err(|e| malformed(format!("cross-SDK fixture: invalid base64: {e}")))
}

fn sha384(b: &[u8]) -> Vec<u8> {
    Sha384::digest(b).to_vec()
}

fn shake256_64(b: &[u8]) -> Vec<u8> {
    let mut h = Shake256::default();
    h.update(b);
    let mut out = vec![0u8; 64];
    h.finalize_xof().read(&mut out);
    out
}

fn object_type(code: i64) -> V2Result<V2ObjectType> {
    u16::try_from(code)
        .ok()
        .and_then(V2ObjectType::from_code)
        .ok_or_else(|| malformed(format!("cross-SDK fixture: unregistered object_type_code {code}")))
}

/// Canonical JSON of `wire` minus the named top-level members.
fn without(wire: &[u8], fields: &[&str]) -> V2Result<Vec<u8>> {
    let mut v: serde_json::Value =
        serde_json::from_slice(wire).map_err(|e| malformed(format!("cross-SDK projection: {e}")))?;
    let obj = v
        .as_object_mut()
        .ok_or_else(|| malformed("cross-SDK projection: wire is not an object"))?;
    for f in fields {
        obj.remove(*f);
    }
    let text = serde_json::to_vec(&v).map_err(|e| malformed(format!("cross-SDK projection: {e}")))?;
    canonical_json_v2(&text)
}

/// The SPEC-v2 §5 signable projection of one signature field, recomputed
/// from the wire object.
fn projection(wire: &[u8], field: &str) -> V2Result<Vec<u8>> {
    match field {
        "signature" => without(wire, &["signature"]),
        "challenge_sig" => without(wire, &["delegations", "challenge_sig"]),
        "old_signature" | "new_signature" => without(wire, &["old_signature", "new_signature"]),
        _ => {
            if let Some(rest) = field.strip_prefix("delegations[") {
                let index: usize = rest
                    .strip_suffix("].signature")
                    .and_then(|i| i.parse().ok())
                    .ok_or_else(|| malformed(format!("unknown signature field {field:?}")))?;
                let v: serde_json::Value =
                    serde_json::from_slice(wire).map_err(|e| malformed(format!("cross-SDK projection: {e}")))?;
                let cert = v
                    .get("delegations")
                    .and_then(|d| d.get(index))
                    .ok_or_else(|| malformed(format!("signature field {field:?} names no delegation")))?;
                let text = serde_json::to_vec(cert).map_err(|e| malformed(format!("cross-SDK projection: {e}")))?;
                return without(&text, &["signature"]);
            }
            if field.starts_with("party_signatures[") && field.ends_with(']') {
                return transaction_receipt_v2_sign_bytes(&decode_transaction_receipt_v2(wire)?);
            }
            Err(malformed(format!("unknown signature field {field:?}")))
        }
    }
}

// ---------------------------------------------------------------------------
// Generator

struct Key {
    name: &'static str,
    public: HybridPublicKey,
    private: HybridPrivateKey,
    id: String,
    entry: CrossSdkKeyV2,
}

impl Key {
    fn fresh(name: &'static str) -> V2Result<Key> {
        let mut ed = [0u8; 32];
        let mut ml = [0u8; 32];
        OsRng.fill_bytes(&mut ed);
        OsRng.fill_bytes(&mut ml);
        let (public, private) = hybrid_keypair_from_seeds(&ed, &ml);
        let id = key_id_v2(&public)?;
        let entry = CrossSdkKeyV2 {
            name: name.into(),
            ed25519_seed_hex: hex::encode(ed),
            ml_dsa_65_seed_hex: hex::encode(ml),
            public_key: pub_json(&public),
            key_id_v2: id.clone(),
            v1_key_id_128: derive_id(&public),
        };
        Ok(Key {
            name,
            public,
            private,
            id,
            entry,
        })
    }
}

struct Keys {
    root: Key,
    intermediate: Key,
    agent: Key,
    verifier: Key,
    status_root: Key,
    status_intermediate: Key,
    witness: Key,
    party_b_root: Key,
    party_b_agent: Key,
    rotation_genesis: Key,
    rotation_second: Key,
}

impl Keys {
    fn fresh() -> V2Result<Keys> {
        Ok(Keys {
            root: Key::fresh("root")?,
            intermediate: Key::fresh("intermediate")?,
            agent: Key::fresh("agent")?,
            verifier: Key::fresh("verifier")?,
            status_root: Key::fresh("status_root")?,
            status_intermediate: Key::fresh("status_intermediate")?,
            witness: Key::fresh("witness")?,
            party_b_root: Key::fresh("party_b_root")?,
            party_b_agent: Key::fresh("party_b_agent")?,
            rotation_genesis: Key::fresh("rotation_genesis")?,
            rotation_second: Key::fresh("rotation_second")?,
        })
    }

    fn entries(&self) -> Vec<CrossSdkKeyV2> {
        [
            &self.root,
            &self.intermediate,
            &self.agent,
            &self.verifier,
            &self.status_root,
            &self.status_intermediate,
            &self.witness,
            &self.party_b_root,
            &self.party_b_agent,
            &self.rotation_genesis,
            &self.rotation_second,
        ]
        .iter()
        .map(|k| k.entry.clone())
        .collect()
    }
}

fn pub_json(k: &HybridPublicKey) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("ed25519".into(), b64(&k.ed25519)),
        ("ml_dsa_65".into(), b64(&k.ml_dsa_65)),
    ])
}

fn sig_json(s: &HybridSignature) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("ed25519".into(), b64(&s.ed25519)),
        ("ml_dsa_65".into(), b64(&s.ml_dsa_65)),
    ])
}

fn empty_sig() -> HybridSignature {
    HybridSignature {
        ed25519: Vec::new(),
        ml_dsa_65: Vec::new(),
    }
}

/// The objects.json signature record for `field` of `wire`.
fn sig_vec(
    field: &str,
    ty: V2ObjectType,
    signer: &Key,
    wire: &[u8],
    sig: &HybridSignature,
) -> V2Result<CrossSdkSignatureV2> {
    let signable = projection(wire, field)?;
    let m = v2_signing_message(ty, &signable);
    let ctx = v2_mldsa_context(ty);
    Ok(CrossSdkSignatureV2 {
        field: field.into(),
        object_type_code: i64::from(ty.code()),
        signer: signer.name.into(),
        signer_key_id_v2: signer.id.clone(),
        signable_b64: b64(&signable),
        signable_sha384_hex: hex::encode(sha384(&signable)),
        message_b64: b64(&m),
        mldsa_context: String::from_utf8_lossy(&ctx).into_owned(),
        mldsa_tr_b64: b64(&shake256_64(&signer.public.ml_dsa_65)),
        mldsa_mu_b64: b64(&external_mu_v2(&signer.public.ml_dsa_65, &ctx, &m)),
        signature: sig_json(sig),
    })
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn cert(
    issuer: &Key,
    subject: &Key,
    cert_id: &str,
    scope: &[&str],
    constraints: Vec<ConstraintV2>,
) -> V2Result<DelegationCertV2> {
    let c = DelegationCertV2 {
        version: 2,
        cert_id: cert_id.into(),
        issuer_id: issuer.id.clone(),
        issuer_pub_key: issuer.public.clone(),
        subject_id: subject.id.clone(),
        subject_pub_key: subject.public.clone(),
        scope: strings(scope),
        constraints,
        issued_at: NOW - 3600,
        expires_at: NOW + 86400,
        signature: empty_sig(),
    };
    sign_delegation_cert_v2(&c, &issuer.private).map_err(sign_err)
}

fn bundle(
    agent: &Key,
    verifier_id: &str,
    certs: Vec<DelegationCertV2>,
    challenge: Vec<u8>,
    session: Option<Vec<u8>>,
    stream: Option<(Vec<u8>, i64)>,
) -> V2Result<(ProofBundleV2, Vec<u8>)> {
    let (stream_id, stream_seq) = match stream {
        Some((id, seq)) => (Some(id), Some(seq)),
        None => (None, None),
    };
    let b = ProofBundleV2 {
        version: 2,
        verifier_id: verifier_id.into(),
        agent_id: agent.id.clone(),
        agent_pub_key: agent.public.clone(),
        delegation_digest: delegation_digest_v2(&certs)?,
        delegations: certs,
        challenge,
        challenge_at: NOW - 10,
        challenge_sig: empty_sig(),
        session_context: session,
        stream_id,
        stream_seq,
    };
    let signed = sign_proof_bundle_v2(&b, &agent.private).map_err(sign_err)?;
    let wire = encode_proof_bundle_v2(&signed)?;
    Ok((signed, wire))
}

fn bundle_sigs(wire: &[u8], b: &ProofBundleV2, k: &Keys) -> V2Result<Vec<CrossSdkSignatureV2>> {
    let mut out = vec![sig_vec(
        "challenge_sig",
        V2ObjectType::ChallengePresentation,
        &k.agent,
        wire,
        &b.challenge_sig,
    )?];
    for (i, c) in b.delegations.iter().enumerate() {
        let issuer = if c.issuer_id == k.root.id {
            &k.root
        } else {
            &k.intermediate
        };
        out.push(sig_vec(
            &format!("delegations[{i}].signature"),
            V2ObjectType::DelegationCertificate,
            issuer,
            wire,
            &c.signature,
        )?);
    }
    Ok(out)
}

fn session_context(
    verifier_id: &str,
    agent_id: &str,
    session: &str,
    invocation: &str,
    request_hash: Vec<u8>,
) -> V2Result<Vec<u8>> {
    build_session_context_v2(&SessionContextV2Inputs {
        verifier_id: verifier_id.into(),
        workspace_id: WORKSPACE.into(),
        agent_id: agent_id.into(),
        session_id: session.into(),
        invocation_id: invocation.into(),
        request_hash,
    })
}

fn genesis_head(log_id: &str, verifier_id: Option<&str>) -> CrossSdkHeadV2 {
    CrossSdkHeadV2 {
        log_id: log_id.into(),
        verifier_id: verifier_id.map(str::to_string),
        sequence: 0,
        head_hash_b64: b64(&[0u8; 48]),
        accepted_digests_b64: BTreeMap::new(),
        frozen: false,
    }
}

fn policy_digest() -> V2Result<String> {
    let body = serde_json::json!({
        "profile": VERIFY_POLICY,
        "require_bound": true,
        "required_fields": VERIFY_POLICY_FIELDS,
        "version": 1,
    });
    let text = serde_json::to_vec(&body).map_err(|e| malformed(e.to_string()))?;
    Ok(format!("sha384:{}", hex::encode(sha384(&canonical_json_v2(&text)?))))
}

fn object(name: &str, kind: &str, description: &str, wire: &[u8]) -> CrossSdkObjectV2 {
    CrossSdkObjectV2 {
        name: name.into(),
        kind: kind.into(),
        description: description.into(),
        wire_b64: b64(wire),
        bundle_b64: None,
        verify: CrossSdkVerifyV2::default(),
        signatures: Vec::new(),
        digests: BTreeMap::new(),
    }
}

fn digests(pairs: Vec<(&str, String)>) -> BTreeMap<String, String> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

fn audience_params() -> BTreeMap<String, ParamsValue> {
    BTreeMap::from([
        (
            "exact_receiver_ids".into(),
            ParamsValue::Array(vec![ParamsValue::Str("receiver-1".into())]),
        ),
        (
            "trust_domain_ids".into(),
            ParamsValue::Array(vec![ParamsValue::Str("domain-a".into())]),
        ),
        ("max_membership_age_seconds".into(), ParamsValue::Int(3600)),
    ])
}

/// Every closed-registry constraint type plus the extension evaluator type
/// `com.ratifyprotocol.max_count` with params `{"counter":"nodes","max":10}`.
fn every_constraint() -> Vec<ConstraintV2> {
    vec![
        ConstraintV2 {
            kind: CONSTRAINT_MAX_RATE.into(),
            count: 5,
            window_s: 60,
            ..Default::default()
        },
        ConstraintV2 {
            kind: CONSTRAINT_RECEIVER_AUDIENCE.into(),
            params: Some(audience_params()),
            ..Default::default()
        },
        ConstraintV2 {
            kind: CONSTRAINT_RESOURCE_PATH.into(),
            resource_id: "customer/123".into(),
            path_prefix: "/v1/customers/".into(),
            ..Default::default()
        },
        ConstraintV2 {
            kind: CONSTRAINT_TIME_WINDOW.into(),
            start: "22:00".into(),
            end: "06:00".into(),
            tz: "America/New_York".into(),
            ..Default::default()
        },
        ConstraintV2 {
            kind: CONSTRAINT_MAX_AMOUNT.into(),
            currency: "USD".into(),
            max_amount_micros: 2_500_000,
            ..Default::default()
        },
        ConstraintV2 {
            kind: CONSTRAINT_MAX_COUNT_V2.into(),
            params: Some(BTreeMap::from([
                ("counter".into(), ParamsValue::Str("nodes".into())),
                ("max".into(), ParamsValue::Int(10)),
            ])),
            ..Default::default()
        },
    ]
}

/// Generate a fresh cross-SDK fixture for `sdk` (one of
/// [`CROSS_SDK_NAMES_V2`]) and return the exact file bytes: two-space
/// indented JSON in the field order of the Go reference, with a trailing
/// newline. Every call draws new seeds from OS randomness and every ML-DSA-65
/// component is hedged (the public typed signers are used throughout). The
/// fixture is verified with [`verify_cross_sdk_fixture_v2`] before it is
/// returned. Signing refusals that are not object errors are reported as
/// `configuration_invalid`.
pub fn generate_cross_sdk_fixture_v2(sdk: &str, sdk_version: &str, generator: &str) -> V2Result<Vec<u8>> {
    if !CROSS_SDK_NAMES_V2.contains(&sdk) || sdk_version.is_empty() || generator.is_empty() {
        return Err(V2Error::new(
            V2ErrorClass::ConfigurationInvalid,
            "cross-SDK fixture needs a registered sdk name, an sdk_version, and a generator note",
        ));
    }
    let k = Keys::fresh()?;
    let f = CrossSdkFixtureV2 {
        version: 2,
        description: DESCRIPTION.into(),
        sdk: sdk.into(),
        sdk_version: sdk_version.into(),
        generator: generator.into(),
        kind_object_type_codes: [
            ("delegation_certificate", 1),
            ("proof_bundle", 2),
            ("revocation_list", 3),
            ("key_rotation_statement", 4),
            ("revocation_push", 5),
            ("witness_entry", 6),
            ("transaction_receipt", 7),
            ("verification_receipt", 8),
        ]
        .into_iter()
        .map(|(n, c)| (n.to_string(), c))
        .collect(),
        keys: k.entries(),
        objects: objects(&k)?,
        scenario_configuration: Some(scenario_config()),
        scenarios: fill_scenarios(&k)?,
    };
    let mut out = serde_json::to_vec_pretty(&f).map_err(|e| malformed(format!("cross-SDK fixture: {e}")))?;
    out.push(b'\n');
    verify_cross_sdk_fixture_v2(&out, sdk).map_err(|e| e.context("generated fixture does not verify"))?;
    Ok(out)
}

fn objects(k: &Keys) -> V2Result<Vec<CrossSdkObjectV2>> {
    let mut out = Vec::new();
    let (root, inter, agent, verifier) = (&k.root, &k.intermediate, &k.agent, &k.verifier);
    let cert_obj =
        |name: &str, desc: &str, c: &DelegationCertV2, issuer: &Key, subject: &Key| -> V2Result<CrossSdkObjectV2> {
            let wire = encode_delegation_cert_v2(c)?;
            let mut o = object(name, "delegation_certificate", desc, &wire);
            o.signatures = vec![sig_vec(
                "signature",
                V2ObjectType::DelegationCertificate,
                issuer,
                &wire,
                &c.signature,
            )?];
            o.digests = digests(vec![
                ("issuer_key_id_v2", issuer.id.clone()),
                ("subject_key_id_v2", subject.id.clone()),
            ]);
            Ok(o)
        };

    // Delegation certificates.
    let root_cert = cert(
        root,
        inter,
        "cert-root",
        &["data:read", "files:read", "identity:delegate"],
        vec![],
    )?;
    out.push(cert_obj(
        "delegation_root_to_intermediate",
        "Root delegates to an intermediate, including identity:delegate.",
        &root_cert,
        root,
        inter,
    )?);
    let leaf_cons = cert(
        inter,
        agent,
        "cert-leaf-constrained",
        &["data:read"],
        every_constraint(),
    )?;
    out.push(cert_obj(
        "delegation_every_registered_constraint_and_extension",
        "Every type in the closed v2 constraint registry (max_rate, ratify.receiver_audience, resource_path, time_window, max_amount) plus the extension evaluator type com.ratifyprotocol.max_count.",
        &leaf_cons,
        inter,
        agent,
    )?);

    // Proof bundles.
    let request = operation_context_v2_hash(&OperationContextV2 {
        required_scope: "data:read".into(),
        operation: "records.get".into(),
        resource_id: "customer/123".into(),
        requested_path: "/v1/customers/123".into(),
        payload_digest: vec![],
    })?;
    let session = session_context(&verifier.id, &agent.id, "session-01", "invocation-01", request)?;
    let bundle_digests = |b: &ProofBundleV2| -> V2Result<BTreeMap<String, String>> {
        Ok(digests(vec![
            (
                "delegation_digest_hex",
                hex::encode(delegation_digest_v2(&b.delegations)?),
            ),
            ("bundle_hash_v2", bundle_hash_v2(b)?),
            ("session_context_hex", hex::encode(&session)),
        ]))
    };
    let challenge_a: Vec<u8> = (0..32u8).map(|i| 0xa0 + i).collect();
    let challenge_b: Vec<u8> = (0..32u8).map(|i| 0xb0 + i).collect();

    let plain_leaf = cert(inter, agent, "cert-leaf", &["data:read", "files:read"], vec![])?;
    let (plain_bundle, plain_wire) = bundle(
        agent,
        &verifier.id,
        vec![plain_leaf, root_cert.clone()],
        challenge_a.clone(),
        Some(session.clone()),
        None,
    )?;
    let mut o = object(
        "proof_bundle_two_link_bound_context",
        "proof_bundle",
        "Leaf-to-root chain with a bound session_context and null stream fields.",
        &plain_wire,
    );
    o.signatures = bundle_sigs(&plain_wire, &plain_bundle, k)?;
    o.digests = bundle_digests(&plain_bundle)?;
    o.digests.insert(
        "challenge_claim_digest_hex".into(),
        hex::encode(challenge_claim_digest_v2(&challenge_a)?),
    );
    o.digests.insert(
        "claim_id".into(),
        protocol_claim_id_v2(NAMESPACE, REPLAY_EPOCH, &challenge_a)?,
    );
    o.digests.insert("claim_verifier_namespace".into(), NAMESPACE.into());
    o.digests.insert("claim_replay_epoch".into(), REPLAY_EPOCH.to_string());
    out.push(o);

    let (ext_bundle, ext_wire) = bundle(
        agent,
        &verifier.id,
        vec![leaf_cons, root_cert],
        challenge_b,
        Some(session.clone()),
        None,
    )?;
    let mut o = object(
        "proof_bundle_constrained_chain",
        "proof_bundle",
        "Chain whose leaf is the constrained certificate above, with a bound session_context.",
        &ext_wire,
    );
    o.signatures = bundle_sigs(&ext_wire, &ext_bundle, k)?;
    o.digests = bundle_digests(&ext_bundle)?;
    out.push(o);

    let (stream_bundle, stream_wire) = bundle(
        agent,
        &verifier.id,
        vec![],
        challenge_a,
        None,
        Some((vec![0x5a; 32], 1)),
    )?;
    let mut o = object(
        "proof_bundle_empty_chain_stream_bound",
        "proof_bundle",
        "Empty delegations array, null session_context, and a bound stream at sequence 1.",
        &stream_wire,
    );
    o.signatures = bundle_sigs(&stream_wire, &stream_bundle, k)?;
    o.digests = digests(vec![
        ("delegation_digest_hex", hex::encode(delegation_digest_v2(&[])?)),
        ("bundle_hash_v2", bundle_hash_v2(&stream_bundle)?),
    ]);
    out.push(o);

    // Status objects.
    let list = |status: &Key, issuer: &Key, sequence: i64, revoked: &[&str]| -> V2Result<RevocationListV2> {
        let l = RevocationListV2 {
            version: 2,
            issuer_id: issuer.id.clone(),
            updated_at: NOW - 60,
            next_update: NOW + 3600,
            sequence,
            revoked: revoked
                .iter()
                .map(|id| RevokedCertV2 {
                    cert_id: id.to_string(),
                })
                .collect(),
            signature: empty_sig(),
        };
        sign_revocation_list_v2(&l, &issuer.id, &status.public, &status.private).map_err(sign_err)
    };
    let status_obj = |name: &str,
                      kind: &str,
                      desc: &str,
                      wire: &[u8],
                      issuer: &Key,
                      status: &Key,
                      ty: V2ObjectType,
                      sig: &HybridSignature,
                      digest: Vec<u8>|
     -> V2Result<CrossSdkObjectV2> {
        let mut o = object(name, kind, desc, wire);
        o.verify = CrossSdkVerifyV2 {
            bound_issuer_id: Some(issuer.id.clone()),
            status_key: Some(status.name.into()),
            ..Default::default()
        };
        o.signatures = vec![sig_vec("signature", ty, status, wire, sig)?];
        o.digests = digests(vec![(
            "status_evidence_digest",
            format!("sha384:{}", hex::encode(digest)),
        )]);
        Ok(o)
    };
    let root_list = list(&k.status_root, root, 7, &["cert-a", "cert-b"])?;
    let root_list_digest = status_evidence_digest_list_v2(&root_list)?;
    out.push(status_obj(
        "revocation_list_root",
        "revocation_list",
        "Snapshot signed under code 0x0003 by the status key bound to the root issuer.",
        &encode_revocation_list_v2(&root_list)?,
        root,
        &k.status_root,
        V2ObjectType::RevocationList,
        &root_list.signature,
        root_list_digest.clone(),
    )?);
    let inter_list = list(&k.status_intermediate, inter, 1, &[])?;
    let inter_list_digest = status_evidence_digest_list_v2(&inter_list)?;
    out.push(status_obj(
        "revocation_list_intermediate_empty",
        "revocation_list",
        "Empty snapshot signed by the status key bound to the intermediate issuer.",
        &encode_revocation_list_v2(&inter_list)?,
        inter,
        &k.status_intermediate,
        V2ObjectType::RevocationList,
        &inter_list.signature,
        inter_list_digest.clone(),
    )?);
    let push = sign_revocation_push_v2(
        &RevocationPushV2 {
            version: 2,
            issuer_id: root.id.clone(),
            sequence: 8,
            pushed_at: NOW - 30,
            revoked: vec![RevokedCertV2 {
                cert_id: "cert-c".into(),
            }],
            signature: empty_sig(),
        },
        &root.id,
        &k.status_root.public,
        &k.status_root.private,
    )
    .map_err(sign_err)?;
    out.push(status_obj(
        "revocation_push",
        "revocation_push",
        "Push signed under code 0x0005 by the bound status key.",
        &encode_revocation_push_v2(&push)?,
        root,
        &k.status_root,
        V2ObjectType::RevocationPush,
        &push.signature,
        status_evidence_digest_push_v2(&push)?,
    )?);

    // Key rotation.
    let (old, new) = (&k.rotation_genesis, &k.rotation_second);
    let stmt = sign_key_rotation_statement_v2(
        &KeyRotationStatementV2 {
            version: 2,
            authority_id: ROTATION_AUTHORITY.into(),
            recovery_epoch: 1,
            role: "issuer".into(),
            sequence: 1,
            previous_statement_hash: vec![0; 48],
            old_key: old.public.clone(),
            new_key: new.public.clone(),
            old_key_id: old.id.clone(),
            new_key_id: new.id.clone(),
            issued_at: NOW - 600,
            not_before: NOW - 600,
            old_signature: empty_sig(),
            new_signature: empty_sig(),
        },
        &old.private,
        &new.private,
    )
    .map_err(sign_err)?;
    let wire = encode_key_rotation_statement_v2(&stmt)?;
    let mut o = object(
        "key_rotation_genesis",
        "key_rotation_statement",
        "Genesis rotation: the old key signs code 0x0004 and the new key signs the identical body under code 0x0009.",
        &wire,
    );
    o.verify = CrossSdkVerifyV2 {
        rotation_state: Some(CrossSdkRotationStateV2 {
            authority_id: ROTATION_AUTHORITY.into(),
            recovery_epoch: 1,
            role: "issuer".into(),
            sequence: 0,
            head_hash_b64: b64(&[0u8; 48]),
            current_key: old.name.into(),
            used_key_ids: vec![old.id.clone()],
        }),
        now: Some(NOW),
        future_skew_seconds: Some(5),
        ..Default::default()
    };
    o.signatures = vec![
        sig_vec(
            "old_signature",
            V2ObjectType::KeyRotationAuthorization,
            old,
            &wire,
            &stmt.old_signature,
        )?,
        sig_vec(
            "new_signature",
            V2ObjectType::KeyRotationProofOfPossession,
            new,
            &wire,
            &stmt.new_signature,
        )?,
    ];
    o.digests = digests(vec![(
        "statement_body_digest_hex",
        hex::encode(key_rotation_statement_v2_digest(&stmt)?),
    )]);
    out.push(o);

    // Witness entry.
    let entry = sign_witness_entry_v2(
        &WitnessEntryV2 {
            version: 2,
            log_id: WITNESS_LOG.into(),
            sequence: 1,
            prev_hash: vec![0; 48],
            entry_data: b"entry-1".to_vec(),
            timestamp: NOW - 20,
            witness_id: k.witness.id.clone(),
            signature: empty_sig(),
        },
        &k.witness.private,
    )
    .map_err(sign_err)?;
    let wire = encode_witness_entry_v2(&entry)?;
    let mut o = object(
        "witness_entry_genesis",
        "witness_entry",
        "Genesis witness entry; prev_hash is 48 zero bytes.",
        &wire,
    );
    o.verify = CrossSdkVerifyV2 {
        witness_key: Some(k.witness.name.into()),
        head: Some(genesis_head(WITNESS_LOG, None)),
        ..Default::default()
    };
    o.signatures = vec![sig_vec(
        "signature",
        V2ObjectType::WitnessEntry,
        &k.witness,
        &wire,
        &entry.signature,
    )?];
    o.digests = digests(vec![(
        "statement_body_digest_hex",
        hex::encode(witness_entry_v2_digest(&entry)?),
    )]);
    out.push(o);

    // Transaction receipt.
    out.push(transaction_object(k)?);

    // Verification receipts, each paired with its bundle.
    let mut evidence = vec![
        StatusEvidenceEntryV2 {
            issuer_id: root.id.clone(),
            status_key_id: k.status_root.id.clone(),
            sequence: 7,
            object_type: 0x0003,
            digest: format!("sha384:{}", hex::encode(&root_list_digest)),
        },
        StatusEvidenceEntryV2 {
            issuer_id: inter.id.clone(),
            status_key_id: k.status_intermediate.id.clone(),
            sequence: 1,
            object_type: 0x0003,
            digest: format!("sha384:{}", hex::encode(&inter_list_digest)),
        },
    ];
    evidence.sort();
    let mut issuer_ids = vec![root.id.clone(), inter.id.clone()];
    issuer_ids.sort();
    let policy = policy_digest()?;
    let receipt_body = |b: &ProofBundleV2, granted: &[&str]| -> V2Result<VerificationReceiptV2> {
        Ok(VerificationReceiptV2 {
            version: 2,
            log_id: String::new(),
            sequence: 0,
            verifier_id: verifier.id.clone(),
            agent_id: b.agent_id.clone(),
            human_id: String::new(),
            bundle_hash: bundle_hash_v2(b)?,
            issuer_ids: issuer_ids.clone(),
            decision: "allow".into(),
            decision_reason: "authorized".into(),
            identity_status: "authorized_agent".into(),
            trust_assessment: "trusted".into(),
            status_assessment: "current".into(),
            challenge_assessment: "current".into(),
            constraint_evaluators: vec![],
            context_assessment: "bound".into(),
            context_policy_digest: Some(policy.clone()),
            verified_at: NOW,
            required_scope: "data:read".into(),
            granted_scope: strings(granted),
            status_evidence: evidence.clone(),
            previous_receipt_hash: vec![],
            signature: empty_sig(),
        })
    };
    let mut add_receipt = |name: &str,
                           desc: &str,
                           log_id: &str,
                           body: VerificationReceiptV2,
                           bundle_wire: &[u8]|
     -> V2Result<()> {
        let mut r = body.clone();
        r.log_id = log_id.into();
        r.sequence = 1;
        r.previous_receipt_hash = vec![0; 48];
        let r = sign_verification_receipt_v2(&r, &verifier.private).map_err(sign_err)?;
        let wire = encode_verification_receipt_v2(&r)?;
        let mut o = object(name, "verification_receipt", desc, &wire);
        o.verify = CrossSdkVerifyV2 {
            verifier_key: Some(verifier.name.into()),
            head: Some(genesis_head(log_id, Some(&verifier.id))),
            ..Default::default()
        };
        o.signatures = vec![sig_vec(
            "signature",
            V2ObjectType::VerificationReceipt,
            verifier,
            &wire,
            &r.signature,
        )?];
        o.digests = digests(vec![
            (
                "statement_body_digest_hex",
                hex::encode(verification_receipt_v2_digest(&r)?),
            ),
            ("receipt_outbox_body_b64", b64(&verification_receipt_v2_body(&body)?)),
        ]);
        out.push(o);
        let mut binding = object(
            &format!("{name}/bundle_binding"),
            "receipt_bundle_binding",
            "The receipt above (wire_b64) with the proof bundle it was issued for (bundle_b64): bundle_hash, verifier_id, agent_id, and issuer_ids bind.",
            &wire,
        );
        binding.bundle_b64 = Some(b64(bundle_wire));
        out.push(binding);
        Ok(())
    };
    add_receipt(
        "verification_receipt_allow_genesis",
        "Genesis allow receipt for proof_bundle_two_link_bound_context, signed under code 0x0008 by the caller-authenticated verifier key.",
        RECEIPT_LOG_A,
        receipt_body(&plain_bundle, &["data:read", "files:read"])?,
        &plain_wire,
    )?;
    let mut evaluated = receipt_body(&ext_bundle, &["data:read"])?;
    evaluated.constraint_evaluators = vec![ConstraintEvaluatorRefV2 {
        kind: CONSTRAINT_MAX_COUNT_V2.into(),
        profile_digest: constraint_profile_digest_v2(&ConstraintProfileDescriptorV2 {
            profile: PROFILE_MAX_COUNT_V2.into(),
            kind: CONSTRAINT_MAX_COUNT_V2.into(),
        })?,
    }];
    add_receipt(
        "verification_receipt_constraint_evaluators",
        "Genesis allow receipt for proof_bundle_constrained_chain carrying the signed constraint_evaluators member for com.ratifyprotocol.max_count/v1.",
        RECEIPT_LOG_B,
        evaluated,
        &ext_wire,
    )?;
    Ok(out)
}

fn transaction_object(k: &Keys) -> V2Result<CrossSdkObjectV2> {
    let mut receipt = TransactionReceiptV2 {
        version: 2,
        transaction_id: "tx-0001".into(),
        created_at: NOW - 5,
        terms_schema_uri: "https://example.com/terms/purchase/v1".into(),
        terms_canonical_json: TX_TERMS.as_bytes().to_vec(),
        parties: vec![],
        party_signatures: vec![],
    };
    let tx_context = transaction_context_hash_v2(&receipt);
    let mut d = digests(vec![("transaction_context_hex", hex::encode(&tx_context))]);
    let parties: [(&str, &str, &str, &Key, &Key); 2] = [
        ("party-a", "buyer", "transact:purchase", &k.agent, &k.root),
        ("party-b", "seller", "transact:sell", &k.party_b_agent, &k.party_b_root),
    ];
    for (id, role, scope, agent, root) in parties {
        let req = transaction_party_request_hash_v2(&tx_context, scope);
        let (session, invocation) = (format!("session-{id}"), format!("invocation-{id}"));
        let ctx = session_context(&k.verifier.id, &agent.id, &session, &invocation, req.clone())?;
        let c = cert(root, agent, &format!("cert-{id}"), &[scope], vec![])?;
        let challenge: Vec<u8> = (0..32u8).map(|i| 0xa0 + i).collect();
        let (b, _) = bundle(agent, &k.verifier.id, vec![c], challenge, Some(ctx.clone()), None)?;
        let hash = bundle_hash_v2(&b)?;
        d.insert(format!("{id}.transaction_party_request_hash_hex"), hex::encode(&req));
        d.insert(format!("{id}.session_context_hex"), hex::encode(&ctx));
        d.insert(format!("{id}.proof_bundle_hash"), hash.clone());
        receipt.parties.push(TransactionReceiptPartyV2 {
            party_id: id.into(),
            role: role.into(),
            agent_id: agent.id.clone(),
            agent_pub_key: agent.public.clone(),
            verifier_id: k.verifier.id.clone(),
            workspace_id: WORKSPACE.into(),
            session_id: session,
            invocation_id: invocation,
            required_scope: scope.into(),
            proof_bundle_hash: hash,
            proof_bundle: Some(b),
        });
    }
    for (id, _, _, agent, _) in parties {
        let sig = sign_transaction_receipt_party_v2(&receipt, id, &agent.private).map_err(sign_err)?;
        receipt.party_signatures.push(sig);
    }
    let wire = encode_transaction_receipt_v2(&receipt)?;
    let mut o = object(
        "transaction_receipt_two_parties",
        "transaction_receipt",
        "Two parties sign the identical signable object under code 0x0007.",
        &wire,
    );
    for (s, (id, _, _, agent, _)) in receipt.party_signatures.iter().zip(parties) {
        o.signatures.push(sig_vec(
            &format!("party_signatures[{id}]"),
            V2ObjectType::TransactionPartyStatement,
            agent,
            &wire,
            &s.signature,
        )?);
    }
    o.digests = d;
    Ok(o)
}

// ---------------------------------------------------------------------------
// Verifier and release scenarios (SPEC-v2 §8.1)

/// The receipt log of every cross-SDK scenario.
const SCENARIO_LOG_ID: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeee01";

/// The scenarios every cross-SDK fixture contains.
pub const CROSS_SDK_SCENARIO_NAMES_V2: [&str; 4] = [
    "allow_released",
    "deny_revoked_released",
    "indeterminate_status_unavailable_released",
    "allow_withheld_past_horizon",
];

fn scenario_config() -> CrossSdkScenarioConfigV2 {
    CrossSdkScenarioConfigV2 {
        verifier_namespace: NAMESPACE.into(),
        replay_epoch: REPLAY_EPOCH,
        verifier_key: "verifier".into(),
        receipt_log_id: SCENARIO_LOG_ID.into(),
        lease_seconds: 30,
        max_challenge_age_seconds: 300,
        future_skew_seconds: 5,
        status_policy: CrossSdkStatusPolicyV2 {
            max_list_lifetime_seconds: 7200,
            max_status_age_seconds: 3660,
            clock_skew_seconds: 5,
        },
        tzdb_version: TZDB_VERSION_V2.into(),
    }
}

fn signed_list(status: &Key, issuer: &Key, next_update: i64, revoked: &[&str]) -> V2Result<Vec<u8>> {
    let l = RevocationListV2 {
        version: 2,
        issuer_id: issuer.id.clone(),
        updated_at: NOW - 60,
        next_update,
        sequence: 1,
        revoked: revoked
            .iter()
            .map(|id| RevokedCertV2 {
                cert_id: id.to_string(),
            })
            .collect(),
        signature: empty_sig(),
    };
    encode_revocation_list_v2(&sign_revocation_list_v2(&l, &issuer.id, &status.public, &status.private).map_err(sign_err)?)
}

/// The scenario inputs; expectations are filled by running each through
/// this SDK ([`fill_scenarios`]).
fn scenarios(k: &Keys) -> V2Result<Vec<CrossSdkScenarioV2>> {
    let (agent, root, inter, verifier) = (&k.agent, &k.root, &k.intermediate, &k.verifier);
    let request = operation_context_v2_hash(&OperationContextV2 {
        required_scope: "data:read".into(),
        operation: "records.get".into(),
        resource_id: "customer/123".into(),
        requested_path: "/v1/customers/123".into(),
        payload_digest: vec![],
    })?;
    let session = session_context(&verifier.id, &agent.id, "session-01", "invocation-01", request)?;
    let certs = vec![
        cert(inter, agent, "cert-leaf", &["data:read", "files:read"], vec![])?,
        cert(root, inter, "cert-root", &["data:read", "files:read", "identity:delegate"], vec![])?,
    ];
    let ev = |wire: Vec<u8>| CrossSdkEvidenceObjectV2 {
        object_type_code: 3,
        wire_b64: b64(&wire),
    };
    let root_list = || signed_list(&k.status_root, root, NOW + 3600, &[]).map(ev);
    let root_short = signed_list(&k.status_root, root, NOW + 60, &[]).map(ev)?;
    let inter_list = || signed_list(&k.status_intermediate, inter, NOW + 3600, &[]).map(ev);
    let inter_revoked = signed_list(&k.status_intermediate, inter, NOW + 3600, &["cert-leaf"]).map(ev)?;
    let policy = CrossSdkContextPolicyV2 {
        profile: VERIFY_POLICY.into(),
        require_bound: true,
        required_fields: strings(&VERIFY_POLICY_FIELDS),
        expected_session_context_b64: Some(b64(&session)),
        digest: policy_digest()?,
    };
    let status_keys = BTreeMap::from([
        (
            root.id.clone(),
            CrossSdkStatusKeyV2 {
                epoch: 1,
                key: k.status_root.name.into(),
            },
        ),
        (
            inter.id.clone(),
            CrossSdkStatusKeyV2 {
                epoch: 1,
                key: k.status_intermediate.name.into(),
            },
        ),
    ]);
    let mk = |name: &str,
              description: &str,
              challenge_byte: u8,
              evidence: Vec<(&Key, CrossSdkEvidenceObjectV2)>,
              publish_time: i64,
              release_time: i64|
     -> V2Result<CrossSdkScenarioV2> {
        let mut challenge: Vec<u8> = (0..32u8).map(|i| 0xa0 + i).collect();
        challenge[0] = challenge_byte;
        let (_, wire) = bundle(agent, &verifier.id, certs.clone(), challenge.clone(), Some(session.clone()), None)?;
        Ok(CrossSdkScenarioV2 {
            name: name.into(),
            description: description.into(),
            bundle_b64: b64(&wire),
            required_scope: "data:read".into(),
            expected_challenge: CrossSdkExpectedChallengeV2 {
                value_b64: b64(&challenge),
                issued_at: NOW - 10,
                expires_at: NOW + 290,
                verifier_namespace: NAMESPACE.into(),
                replay_epoch: REPLAY_EPOCH,
                verifier_id: verifier.id.clone(),
                expected_agent_id: Some(agent.id.clone()),
                expected_agent_public_key: Some(pub_json(&agent.public)),
                expected_receiver_id: None,
                expected_session_context_b64: Some(b64(&session)),
            },
            context_policy: Some(policy.clone()),
            trust_root_key: root.name.into(),
            status_keys: status_keys.clone(),
            status_evidence: evidence
                .into_iter()
                .map(|(issuer, o)| (issuer.id.clone(), vec![o]))
                .collect(),
            verify_time: NOW,
            publish_time,
            release_time,
            expected: CrossSdkScenarioExpectV2 {
                receipt_body_b64: String::new(),
                allow_horizon: None,
                signed_receipt_b64: String::new(),
                release: CrossSdkReleaseV2 {
                    status: String::new(),
                    reason: None,
                    decision: None,
                    release_time: None,
                },
            },
        })
    };
    Ok(vec![
        mk(
            "allow_released",
            "every check passes; the published, acknowledged allow is released at the acknowledgement time",
            0xa1,
            vec![(root, root_list()?), (inter, inter_list()?)],
            NOW,
            NOW,
        )?,
        mk(
            "deny_revoked_released",
            "the intermediate's signed list revokes the leaf: a committed deny / delegation_revoked, released as a non-actionable deny",
            0xa2,
            vec![(root, root_list()?), (inter, inter_revoked)],
            NOW,
            NOW,
        )?,
        mk(
            "indeterminate_status_unavailable_released",
            "the status provider returns no evidence for the intermediate: indeterminate / status_unavailable, released as a non-actionable indeterminate",
            0xa3,
            vec![(root, root_list()?)],
            NOW,
            NOW,
        )?,
        mk(
            "allow_withheld_past_horizon",
            "the root list's next_update makes the allow horizon verify_time + 60; the receipt is acknowledged at that horizon, so release is withheld as allow_horizon_passed and never becomes released",
            0xa4,
            vec![(root, root_short), (inter, inter_list()?)],
            NOW + 60,
            NOW + 60,
        )?,
    ])
}

/// Run every scenario through this SDK and record what it observed.
fn fill_scenarios(k: &Keys) -> V2Result<Vec<CrossSdkScenarioV2>> {
    let cfg = scenario_config();
    let keys: BTreeMap<String, HybridPublicKey> = k
        .entries()
        .into_iter()
        .zip([
            &k.root,
            &k.intermediate,
            &k.agent,
            &k.verifier,
            &k.status_root,
            &k.status_intermediate,
            &k.witness,
            &k.party_b_root,
            &k.party_b_agent,
            &k.rotation_genesis,
            &k.rotation_second,
        ])
        .map(|(e, key)| (e.name, key.public.clone()))
        .collect();
    let mut out = scenarios(k)?;
    for sc in &mut out {
        sc.expected = replay_scenario(&cfg, sc, &keys, &k.verifier.private, None)
            .map_err(|e| e.context(format!("scenario {}", sc.name)))?;
    }
    Ok(out)
}

/// Replay one scenario (README cross-sdk replay procedure): a fresh
/// reference store at `verify_time` and a fresh anchored journal configured
/// with every status key, the live verifier, publication at `publish_time`,
/// and `release_v2_decision` at `release_time` with `release_receipt` (the
/// receipt just published when `None`).
fn replay_scenario(
    cfg: &CrossSdkScenarioConfigV2,
    sc: &CrossSdkScenarioV2,
    keys: &BTreeMap<String, HybridPublicKey>,
    verifier_private: &HybridPrivateKey,
    release_receipt: Option<&[u8]>,
) -> V2Result<CrossSdkScenarioExpectV2> {
    let ctx = V2Context::background();
    let key = |name: &str| -> V2Result<HybridPublicKey> {
        keys.get(name)
            .cloned()
            .ok_or_else(|| malformed(format!("key {name:?} is not in the fixture")))
    };
    let store = Arc::new(Store::new(sc.verify_time, cfg.lease_seconds, &cfg.receipt_log_id, verifier_private)?);
    let journal = Arc::new(JournalStore::new()?);
    let mut req = V2VerifyRequest {
        bundle: b64d(&sc.bundle_b64)?,
        required_scope: sc.required_scope.clone(),
        verifier_namespace: cfg.verifier_namespace.clone(),
        replay_epoch: cfg.replay_epoch,
        verifier_id: key_id_v2(&key(&cfg.verifier_key)?)?,
        now: sc.verify_time,
        max_challenge_age_seconds: cfg.max_challenge_age_seconds,
        future_skew_seconds: cfg.future_skew_seconds,
        tzdb_version: cfg.tzdb_version.clone(),
        status_policy: RevocationStatusPolicyV2 {
            max_list_lifetime_seconds: cfg.status_policy.max_list_lifetime_seconds,
            max_status_age_seconds: cfg.status_policy.max_status_age_seconds,
            clock_skew_seconds: cfg.status_policy.clock_skew_seconds,
        },
        ..Default::default()
    };
    // BTreeMap order is the ascending issuer_id order the procedure requires.
    for (issuer, k) in &sc.status_keys {
        let public = key(&k.key)?;
        configure_status_key_epoch_v2(&ctx, journal.as_ref(), issuer, k.epoch, &public)?;
        req.status_keys.insert(
            issuer.clone(),
            V2StatusKeyConfig {
                epoch: k.epoch,
                key: public,
            },
        );
    }
    let e = &sc.expected_challenge;
    req.expected = Some(ExpectedChallengeV2 {
        value: b64d(&e.value_b64)?,
        issued_at: e.issued_at,
        expires_at: e.expires_at,
        verifier_namespace: e.verifier_namespace.clone(),
        replay_epoch: e.replay_epoch,
        verifier_id: e.verifier_id.clone(),
        expected_agent_id: e.expected_agent_id.clone().unwrap_or_default(),
        expected_agent_public_key: match (&e.expected_agent_id, &e.expected_agent_public_key) {
            (Some(_), Some(k)) => Some(HybridPublicKey {
                ed25519: b64d(k.get("ed25519").map(String::as_str).unwrap_or_default())?,
                ml_dsa_65: b64d(k.get("ml_dsa_65").map(String::as_str).unwrap_or_default())?,
            }),
            _ => None,
        },
        expected_receiver_id: e.expected_receiver_id.clone().unwrap_or_default(),
        expected_session_context: e.expected_session_context_b64.as_deref().map(b64d).transpose()?,
        ..Default::default()
    });
    if let Some(p) = &sc.context_policy {
        let expected = p.expected_session_context_b64.as_deref().map(b64d).transpose()?.unwrap_or_default();
        let policy = V2ContextPolicy::new(&p.profile, p.require_bound, &p.required_fields, &expected)?;
        if policy.digest() != p.digest {
            return Err(malformed("context policy digest differs"));
        }
        req.context_policy = Some(policy);
    }
    let root_key = key(&sc.trust_root_key)?;
    let mut evidence: BTreeMap<String, Vec<V2StatusEvidenceObject>> = BTreeMap::new();
    for (issuer, objects) in &sc.status_evidence {
        let mut batch = Vec::with_capacity(objects.len());
        for o in objects {
            batch.push(V2StatusEvidenceObject {
                object_type: u16::try_from(o.object_type_code).map_err(|_| malformed("bad object_type_code"))?,
                wire: b64d(&o.wire_b64)?,
            });
        }
        evidence.insert(issuer.clone(), batch);
    }
    let cb = V2VerifyCallbacks {
        claim_store: Some(store.clone()),
        status_journal: Some(journal),
        trust: Some(Arc::new(move |_: &V2Context, _: &[DelegationCertV2]| {
            Ok(V2TrustResolution {
                outcome: V2TrustOutcome::Trusted,
                root_key: root_key.clone(),
            })
        })),
        status_evidence: Some(Arc::new(move |_: &V2Context, r: &V2StatusEvidenceRequest| {
            Ok(V2StatusEvidenceBatch {
                objects: evidence.get(&r.issuer_id).cloned().unwrap_or_default(),
            })
        })),
        ..Default::default()
    };
    let outcome = verify_proof_bundle_v2(&ctx, &req, &cb);
    let committed = match (outcome.stage, outcome.committed) {
        (V2VerifyStage::Committed, Some(c)) => c,
        (stage, _) => {
            return Err(malformed(format!(
                "stage {} ({:?}): {:?}",
                stage.as_str(),
                outcome.error_class,
                outcome.error
            )))
        }
    };
    store.set_time(sc.publish_time);
    let published = store
        .publish_v2_receipt(&ctx, &committed.claim_id(), &committed.receipt_body())
        .map_err(|e| malformed(format!("publish: {e:?}")))?;
    store.set_time(sc.release_time);
    let verifier_public = key(&cfg.verifier_key)?;
    let result = release_v2_decision(
        &ctx,
        &committed,
        Some(release_receipt.unwrap_or(&published)),
        V2ReleaseConfig {
            verifier_public_key: &verifier_public,
            log_id: &cfg.receipt_log_id,
            claim_store: store.as_ref(),
            checkpoint: store.as_ref(),
        },
    );
    Ok(CrossSdkScenarioExpectV2 {
        receipt_body_b64: b64(&committed.receipt_body()),
        allow_horizon: committed.allow_horizon(),
        signed_receipt_b64: b64(&published),
        release: CrossSdkReleaseV2 {
            status: result.status.as_str().into(),
            reason: (!result.reason.is_empty()).then(|| result.reason.clone()),
            decision: result.decision().map(|d| d.decision()),
            release_time: result.decision().map(|d| d.release_time()),
        },
    })
}

/// Replay every scenario of a fixture through this SDK, releasing with the
/// fixture's own signed receipt, and compare the committed outcome and
/// release result (Go `checkCrossScenarios`).
fn check_scenarios(
    cfg: &CrossSdkScenarioConfigV2,
    scenarios: &[CrossSdkScenarioV2],
    keys: &BTreeMap<String, HybridPublicKey>,
    verifier_private: &HybridPrivateKey,
) -> V2Result<()> {
    if *cfg != scenario_config() {
        return Err(malformed("scenario_configuration differs from the fixed values"));
    }
    let mut seen = BTreeSet::new();
    for sc in scenarios {
        seen.insert(sc.name.as_str());
        let want = &sc.expected;
        let got = replay_scenario(cfg, sc, keys, verifier_private, Some(&b64d(&want.signed_receipt_b64)?))
            .map_err(|e| e.context(format!("scenario {}", sc.name)))?;
        if got.receipt_body_b64 != want.receipt_body_b64 || got.allow_horizon != want.allow_horizon {
            return Err(malformed(format!("scenario {}: committed outcome differs", sc.name)));
        }
        if got.release != want.release {
            return Err(malformed(format!(
                "scenario {}: release {:?}, want {:?}",
                sc.name, got.release, want.release
            )));
        }
    }
    for name in CROSS_SDK_SCENARIO_NAMES_V2 {
        if !seen.contains(name) {
            return Err(malformed(format!("missing scenario {name}")));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Verifier

/// Verify one cross-SDK fixture file (README `cross-sdk/` verification
/// procedure, Go `VerifyCrossSDK`): strict decode, `version` 2 and `sdk`
/// equal to `expected_sdk` (the file stem), key derivation from seeds, the
/// required key names, byte-identical re-encoding, the per-kind verify
/// procedure, every signature transcript (projection, SHA-384, `M`,
/// context, `tr`, `mu`, signer key ID, both components carried by the wire
/// object), and the required kinds, codes, and constraint coverage, and
/// replays every verifier and release scenario through this SDK (releasing
/// with the fixture's own signed receipt). A fixture that predates the
/// scenarios carries neither `scenario_configuration` nor `scenarios`; it
/// still verifies here, and [`CrossSdkFixtureV2::scenarios`] tells the caller
/// whether SPEC-v2 §8.1 is met for its producer. Digest reproduction is left
/// to the conformance suite, as in Go. Fixture-shape failures are
/// `malformed`; verify failures keep their own class.
pub fn verify_cross_sdk_fixture_v2(data: &[u8], expected_sdk: &str) -> V2Result<()> {
    let f: CrossSdkFixtureV2 =
        serde_json::from_slice(data).map_err(|e| malformed(format!("cross-SDK fixture decode: {e}")))?;
    if f.version != 2 || f.sdk.is_empty() || f.sdk_version.is_empty() || f.generator.is_empty() {
        return Err(malformed("version, sdk, sdk_version and generator are required"));
    }
    if f.sdk != expected_sdk {
        return Err(malformed(format!("sdk {:?} does not match {expected_sdk:?}", f.sdk)));
    }
    let mut keys: BTreeMap<String, (HybridPublicKey, String)> = BTreeMap::new();
    let mut privates: BTreeMap<String, HybridPrivateKey> = BTreeMap::new();
    for k in &f.keys {
        let seed = |s: &str| -> V2Result<[u8; 32]> {
            hex::decode(s)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or_else(|| malformed(format!("key {}: bad seed", k.name)))
        };
        let (public, private) = hybrid_keypair_from_seeds(&seed(&k.ed25519_seed_hex)?, &seed(&k.ml_dsa_65_seed_hex)?);
        if k.public_key != pub_json(&public) {
            return Err(malformed(format!("key {}: seeds do not derive the public key", k.name)));
        }
        if key_id_v2(&public)? != k.key_id_v2 {
            return Err(malformed(format!("key {}: key_id_v2 differs", k.name)));
        }
        if derive_id(&public) != k.v1_key_id_128 {
            return Err(malformed(format!("key {}: v1_key_id_128 differs", k.name)));
        }
        if keys.insert(k.name.clone(), (public, k.key_id_v2.clone())).is_some() {
            return Err(malformed(format!("key {}: duplicate name", k.name)));
        }
        privates.insert(k.name.clone(), private);
    }
    for name in CROSS_SDK_KEY_NAMES_V2 {
        if !keys.contains_key(name) {
            return Err(malformed(format!("missing key {name}")));
        }
    }
    let mut kinds = BTreeSet::new();
    let mut codes = BTreeSet::new();
    for o in &f.objects {
        kinds.insert(o.kind.as_str());
        verify_object(o, &keys, &mut codes).map_err(|e| e.context(&o.name))?;
    }
    for kind in CROSS_SDK_KINDS_V2 {
        if !kinds.contains(kind) {
            return Err(malformed(format!("no {kind} object")));
        }
    }
    for code in 1..=9i64 {
        if !codes.contains(&code) {
            return Err(malformed(format!("no signature for object_type_code {code}")));
        }
    }
    if !coverage(&f.objects)? {
        return Err(malformed(
            "no delegation certificate with every registered constraint type and an extension type, or no receipt with constraint_evaluators",
        ));
    }
    match (&f.scenario_configuration, f.scenarios.is_empty()) {
        (None, true) => {}
        (Some(cfg), false) => {
            let public: BTreeMap<String, HybridPublicKey> =
                keys.iter().map(|(name, (k, _))| (name.clone(), k.clone())).collect();
            let verifier = privates
                .get(&cfg.verifier_key)
                .ok_or_else(|| malformed(format!("scenario verifier key {:?} is not in the fixture", cfg.verifier_key)))?;
            check_scenarios(cfg, &f.scenarios, &public, verifier)?;
        }
        _ => return Err(malformed("scenario_configuration and scenarios must appear together")),
    }
    Ok(())
}

fn coverage(objects: &[CrossSdkObjectV2]) -> V2Result<bool> {
    let (mut constraints, mut evaluators) = (false, false);
    for o in objects {
        let wire = b64d(&o.wire_b64)?;
        match o.kind.as_str() {
            "delegation_certificate" => {
                let c = decode_delegation_cert_v2(&wire)?;
                let types: BTreeSet<&str> = c.constraints.iter().map(|k| k.kind.as_str()).collect();
                let extension = types.iter().any(|t| !is_registered_constraint_type_v2(t));
                constraints |= extension
                    && [
                        CONSTRAINT_MAX_RATE,
                        CONSTRAINT_RECEIVER_AUDIENCE,
                        CONSTRAINT_RESOURCE_PATH,
                        CONSTRAINT_TIME_WINDOW,
                        CONSTRAINT_MAX_AMOUNT,
                    ]
                    .iter()
                    .all(|t| types.contains(t));
            }
            "verification_receipt" => {
                evaluators |= !decode_verification_receipt_v2(&wire)?.constraint_evaluators.is_empty();
            }
            _ => {}
        }
    }
    Ok(constraints && evaluators)
}

fn reencode(kind: &str, wire: &[u8]) -> V2Result<Vec<u8>> {
    match kind {
        "delegation_certificate" => encode_delegation_cert_v2(&decode_delegation_cert_v2(wire)?),
        "proof_bundle" => encode_proof_bundle_v2(&decode_proof_bundle_v2(wire)?),
        "revocation_list" => encode_revocation_list_v2(&decode_revocation_list_v2(wire)?),
        "revocation_push" => encode_revocation_push_v2(&decode_revocation_push_v2(wire)?),
        "key_rotation_statement" => encode_key_rotation_statement_v2(&decode_key_rotation_statement_v2(wire)?),
        "witness_entry" => encode_witness_entry_v2(&decode_witness_entry_v2(wire)?),
        "transaction_receipt" => encode_transaction_receipt_v2(&decode_transaction_receipt_v2(wire)?),
        "verification_receipt" | "receipt_bundle_binding" => {
            encode_verification_receipt_v2(&decode_verification_receipt_v2(wire)?)
        }
        other => Err(malformed(format!("unknown kind {other:?}"))),
    }
}

fn verify_object(
    o: &CrossSdkObjectV2,
    keys: &BTreeMap<String, (HybridPublicKey, String)>,
    codes: &mut BTreeSet<i64>,
) -> V2Result<()> {
    let wire = b64d(&o.wire_b64)?;
    if reencode(&o.kind, &wire)? != wire {
        return Err(malformed("re-encoding is not byte-identical"));
    }
    if o.kind == "receipt_bundle_binding" {
        let bundle = b64d(o.bundle_b64.as_deref().unwrap_or_default())?;
        if reencode("proof_bundle", &bundle)? != bundle {
            return Err(malformed("bundle re-encoding is not byte-identical"));
        }
        if !o.signatures.is_empty() || !o.digests.is_empty() {
            return Err(malformed("receipt_bundle_binding carries signatures or digests"));
        }
    } else if o.bundle_b64.is_some() {
        return Err(malformed("bundle_b64 is only used by receipt_bundle_binding"));
    }
    verify_kind(o, &wire, keys).map_err(|e| e.context("verify"))?;
    let wire_text = String::from_utf8_lossy(&wire);
    for s in &o.signatures {
        codes.insert(s.object_type_code);
        let signable = projection(&wire, &s.field)?;
        if b64(&signable) != s.signable_b64 || hex::encode(sha384(&signable)) != s.signable_sha384_hex {
            return Err(malformed(format!("{}: signable projection differs", s.field)));
        }
        let ty = object_type(s.object_type_code)?;
        let m = v2_signing_message(ty, &signable);
        let (public, id) = keys
            .get(&s.signer)
            .ok_or_else(|| malformed(format!("{}: unknown signer {}", s.field, s.signer)))?;
        if *id != s.signer_key_id_v2 {
            return Err(malformed(format!("{}: signer key ID differs", s.field)));
        }
        let ctx = v2_mldsa_context(ty);
        if b64(&m) != s.message_b64
            || ctx != s.mldsa_context.as_bytes()
            || b64(&shake256_64(&public.ml_dsa_65)) != s.mldsa_tr_b64
            || b64(&external_mu_v2(&public.ml_dsa_65, &ctx, &m)) != s.mldsa_mu_b64
        {
            return Err(malformed(format!("{}: transcript differs", s.field)));
        }
        for component in ["ed25519", "ml_dsa_65"] {
            let v = s.signature.get(component).map(String::as_str).unwrap_or_default();
            if v.is_empty() || !wire_text.contains(&format!("\"{v}\"")) {
                return Err(malformed(format!(
                    "{}: pinned {component} signature is not carried by the wire object",
                    s.field
                )));
            }
        }
    }
    Ok(())
}

fn verify_kind(o: &CrossSdkObjectV2, wire: &[u8], keys: &BTreeMap<String, (HybridPublicKey, String)>) -> V2Result<()> {
    let vc = &o.verify;
    let key = |name: &Option<String>| -> V2Result<&HybridPublicKey> {
        name.as_ref()
            .and_then(|n| keys.get(n))
            .map(|(k, _)| k)
            .ok_or_else(|| malformed(format!("verify context names an unknown key {name:?}")))
    };
    let head = |h: &Option<CrossSdkHeadV2>| -> V2Result<WitnessV2Head> {
        let h = h.as_ref().ok_or_else(|| malformed("verify context has no head"))?;
        let mut accepted = BTreeMap::new();
        for (seq, d) in &h.accepted_digests_b64 {
            let seq: i64 = seq.parse().map_err(|_| malformed("bad accepted digest sequence"))?;
            accepted.insert(seq, b64d(d)?);
        }
        Ok(WitnessV2Head {
            log_id: h.log_id.clone(),
            sequence: h.sequence,
            head_hash: b64d(&h.head_hash_b64)?,
            accepted_digests: accepted,
            frozen: h.frozen,
        })
    };
    let bound = || vc.bound_issuer_id.clone().unwrap_or_default();
    match o.kind.as_str() {
        "delegation_certificate" => verify_delegation_cert_v2_signature(&decode_delegation_cert_v2(wire)?),
        "proof_bundle" => verify_proof_bundle_v2_signatures(&decode_proof_bundle_v2(wire)?),
        "revocation_list" => {
            verify_revocation_list_v2_signature(&decode_revocation_list_v2(wire)?, &bound(), key(&vc.status_key)?)
        }
        "revocation_push" => {
            verify_revocation_push_v2_signature(&decode_revocation_push_v2(wire)?, &bound(), key(&vc.status_key)?)
        }
        "key_rotation_statement" => {
            let s = vc
                .rotation_state
                .as_ref()
                .ok_or_else(|| malformed("verify context has no rotation_state"))?;
            let state = KeyRotationV2State {
                authority_id: s.authority_id.clone(),
                recovery_epoch: s.recovery_epoch,
                role: s.role.clone(),
                sequence: s.sequence,
                head_hash: b64d(&s.head_hash_b64)?,
                current_key: key(&Some(s.current_key.clone()))?.clone(),
                used_key_ids: s.used_key_ids.clone(),
            };
            verify_key_rotation_statement_v2(
                &decode_key_rotation_statement_v2(wire)?,
                &state,
                vc.now.unwrap_or_default(),
                vc.future_skew_seconds.unwrap_or_default(),
            )
        }
        "witness_entry" => {
            verify_witness_entry_v2(&decode_witness_entry_v2(wire)?, &head(&vc.head)?, key(&vc.witness_key)?)
                .map(|_| ())
        }
        "transaction_receipt" => verify_transaction_receipt_v2_signatures(&decode_transaction_receipt_v2(wire)?),
        "verification_receipt" => {
            let w = head(&vc.head)?;
            let verifier_id = vc.head.as_ref().and_then(|h| h.verifier_id.clone()).unwrap_or_default();
            let head = ReceiptV2Head {
                log_id: w.log_id,
                verifier_id,
                sequence: w.sequence,
                head_hash: w.head_hash,
                accepted_digests: w.accepted_digests,
                frozen: w.frozen,
            };
            verify_verification_receipt_v2(&decode_verification_receipt_v2(wire)?, key(&vc.verifier_key)?, &head)
                .map(|_| ())
        }
        "receipt_bundle_binding" => {
            let bundle = decode_proof_bundle_v2(&b64d(o.bundle_b64.as_deref().unwrap_or_default())?)?;
            check_verification_receipt_v2_bundle_binding(&decode_verification_receipt_v2(wire)?, &bundle)
        }
        other => Err(malformed(format!("unknown kind {other:?}"))),
    }
}
