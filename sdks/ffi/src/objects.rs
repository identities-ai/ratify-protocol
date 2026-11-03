//! Owned records mirroring every v2 signed object, and the strict decoders.
//! Conversions copy fields one for one; they contain no protocol logic.

use std::collections::{BTreeMap, HashMap};

use ratify_protocol::v2::status_provenance::V2StatusEvidenceBatch;
use ratify_protocol::v2::{
    ConstraintEvaluatorRefV2, ConstraintV2, DelegationCertV2, KeyRotationStatementV2, ProofBundleV2,
    RevocationListV2, RevocationPushV2, RevokedCertV2, StatusEvidenceEntryV2, TransactionReceiptPartyV2,
    TransactionReceiptSignatureV2, TransactionReceiptV2, VerificationReceiptV2, WitnessEntryV2,
};
use ratify_protocol::{HybridPublicKey, HybridSignature, ParamsValue};

use crate::error::FfiResult;
use crate::keys::FfiPublicKey;

fn pk(k: &HybridPublicKey) -> FfiPublicKey {
    k.into()
}

/// A hybrid signature: Ed25519 (64 bytes) and ML-DSA-65 (3309 bytes).
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiSignature {
    pub ed25519: Vec<u8>,
    pub ml_dsa_65: Vec<u8>,
}

impl From<&HybridSignature> for FfiSignature {
    fn from(s: &HybridSignature) -> Self {
        FfiSignature { ed25519: s.ed25519.clone(), ml_dsa_65: s.ml_dsa_65.clone() }
    }
}
impl From<FfiSignature> for HybridSignature {
    fn from(s: FfiSignature) -> Self {
        HybridSignature { ed25519: s.ed25519, ml_dsa_65: s.ml_dsa_65 }
    }
}

/// A constraint `params` value (JSON without floats).
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum FfiParamsValue {
    Null,
    Bool { value: bool },
    Int { value: i64 },
    Str { value: String },
    Array { items: Vec<FfiParamsValue> },
    Object { entries: HashMap<String, FfiParamsValue> },
}

impl From<&ParamsValue> for FfiParamsValue {
    fn from(v: &ParamsValue) -> Self {
        match v {
            ParamsValue::Null => FfiParamsValue::Null,
            ParamsValue::Bool(b) => FfiParamsValue::Bool { value: *b },
            ParamsValue::Int(i) => FfiParamsValue::Int { value: *i },
            ParamsValue::Str(s) => FfiParamsValue::Str { value: s.clone() },
            ParamsValue::Array(a) => FfiParamsValue::Array { items: a.iter().map(Into::into).collect() },
            ParamsValue::Object(o) => FfiParamsValue::Object { entries: params_out(o) },
        }
    }
}
impl From<FfiParamsValue> for ParamsValue {
    fn from(v: FfiParamsValue) -> Self {
        match v {
            FfiParamsValue::Null => ParamsValue::Null,
            FfiParamsValue::Bool { value } => ParamsValue::Bool(value),
            FfiParamsValue::Int { value } => ParamsValue::Int(value),
            FfiParamsValue::Str { value } => ParamsValue::Str(value),
            FfiParamsValue::Array { items } => ParamsValue::Array(items.into_iter().map(Into::into).collect()),
            FfiParamsValue::Object { entries } => ParamsValue::Object(params_in(entries)),
        }
    }
}
fn params_out(o: &BTreeMap<String, ParamsValue>) -> HashMap<String, FfiParamsValue> {
    o.iter().map(|(k, v)| (k.clone(), v.into())).collect()
}
fn params_in(o: HashMap<String, FfiParamsValue>) -> BTreeMap<String, ParamsValue> {
    o.into_iter().map(|(k, v)| (k, v.into())).collect()
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiConstraint {
    pub kind: String,
    pub start: String,
    pub end: String,
    pub tz: String,
    pub currency: String,
    pub max_amount_micros: i64,
    pub count: i64,
    pub window_s: i64,
    pub resource_id: String,
    pub path_prefix: String,
    pub params: Option<HashMap<String, FfiParamsValue>>,
}

impl From<&ConstraintV2> for FfiConstraint {
    fn from(c: &ConstraintV2) -> Self {
        FfiConstraint {
            kind: c.kind.clone(),
            start: c.start.clone(),
            end: c.end.clone(),
            tz: c.tz.clone(),
            currency: c.currency.clone(),
            max_amount_micros: c.max_amount_micros,
            count: c.count,
            window_s: c.window_s,
            resource_id: c.resource_id.clone(),
            path_prefix: c.path_prefix.clone(),
            params: c.params.as_ref().map(params_out),
        }
    }
}
impl From<FfiConstraint> for ConstraintV2 {
    fn from(c: FfiConstraint) -> Self {
        ConstraintV2 {
            kind: c.kind,
            start: c.start,
            end: c.end,
            tz: c.tz,
            currency: c.currency,
            max_amount_micros: c.max_amount_micros,
            count: c.count,
            window_s: c.window_s,
            resource_id: c.resource_id,
            path_prefix: c.path_prefix,
            params: c.params.map(params_in),
        }
    }
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiDelegationCert {
    pub version: i64,
    pub cert_id: String,
    pub issuer_id: String,
    pub issuer_pub_key: FfiPublicKey,
    pub subject_id: String,
    pub subject_pub_key: FfiPublicKey,
    pub scope: Vec<String>,
    pub constraints: Vec<FfiConstraint>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub signature: FfiSignature,
}

impl From<&DelegationCertV2> for FfiDelegationCert {
    fn from(c: &DelegationCertV2) -> Self {
        FfiDelegationCert {
            version: c.version,
            cert_id: c.cert_id.clone(),
            issuer_id: c.issuer_id.clone(),
            issuer_pub_key: pk(&c.issuer_pub_key),
            subject_id: c.subject_id.clone(),
            subject_pub_key: pk(&c.subject_pub_key),
            scope: c.scope.clone(),
            constraints: c.constraints.iter().map(Into::into).collect(),
            issued_at: c.issued_at,
            expires_at: c.expires_at,
            signature: (&c.signature).into(),
        }
    }
}
impl From<FfiDelegationCert> for DelegationCertV2 {
    fn from(c: FfiDelegationCert) -> Self {
        DelegationCertV2 {
            version: c.version,
            cert_id: c.cert_id,
            issuer_id: c.issuer_id,
            issuer_pub_key: c.issuer_pub_key.into(),
            subject_id: c.subject_id,
            subject_pub_key: c.subject_pub_key.into(),
            scope: c.scope,
            constraints: c.constraints.into_iter().map(Into::into).collect(),
            issued_at: c.issued_at,
            expires_at: c.expires_at,
            signature: c.signature.into(),
        }
    }
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiProofBundle {
    pub version: i64,
    pub verifier_id: String,
    pub agent_id: String,
    pub agent_pub_key: FfiPublicKey,
    pub delegations: Vec<FfiDelegationCert>,
    pub delegation_digest: Vec<u8>,
    pub challenge: Vec<u8>,
    pub challenge_at: i64,
    pub challenge_sig: FfiSignature,
    pub session_context: Option<Vec<u8>>,
    pub stream_id: Option<Vec<u8>>,
    pub stream_seq: Option<i64>,
}

impl From<&ProofBundleV2> for FfiProofBundle {
    fn from(b: &ProofBundleV2) -> Self {
        FfiProofBundle {
            version: b.version,
            verifier_id: b.verifier_id.clone(),
            agent_id: b.agent_id.clone(),
            agent_pub_key: pk(&b.agent_pub_key),
            delegations: b.delegations.iter().map(Into::into).collect(),
            delegation_digest: b.delegation_digest.clone(),
            challenge: b.challenge.clone(),
            challenge_at: b.challenge_at,
            challenge_sig: (&b.challenge_sig).into(),
            session_context: b.session_context.clone(),
            stream_id: b.stream_id.clone(),
            stream_seq: b.stream_seq,
        }
    }
}
impl From<FfiProofBundle> for ProofBundleV2 {
    fn from(b: FfiProofBundle) -> Self {
        ProofBundleV2 {
            version: b.version,
            verifier_id: b.verifier_id,
            agent_id: b.agent_id,
            agent_pub_key: b.agent_pub_key.into(),
            delegations: b.delegations.into_iter().map(Into::into).collect(),
            delegation_digest: b.delegation_digest,
            challenge: b.challenge,
            challenge_at: b.challenge_at,
            challenge_sig: b.challenge_sig.into(),
            session_context: b.session_context,
            stream_id: b.stream_id,
            stream_seq: b.stream_seq,
        }
    }
}

fn revoked_out(r: &[RevokedCertV2]) -> Vec<String> {
    r.iter().map(|c| c.cert_id.clone()).collect()
}
fn revoked_in(r: Vec<String>) -> Vec<RevokedCertV2> {
    r.into_iter().map(|cert_id| RevokedCertV2 { cert_id }).collect()
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiRevocationList {
    pub version: i64,
    pub issuer_id: String,
    pub updated_at: i64,
    pub next_update: i64,
    pub sequence: i64,
    /// The revoked certificate IDs (`RevokedCertV2.cert_id`), in wire order.
    pub revoked: Vec<String>,
    pub signature: FfiSignature,
}

impl From<&RevocationListV2> for FfiRevocationList {
    fn from(l: &RevocationListV2) -> Self {
        FfiRevocationList {
            version: l.version,
            issuer_id: l.issuer_id.clone(),
            updated_at: l.updated_at,
            next_update: l.next_update,
            sequence: l.sequence,
            revoked: revoked_out(&l.revoked),
            signature: (&l.signature).into(),
        }
    }
}
impl From<FfiRevocationList> for RevocationListV2 {
    fn from(l: FfiRevocationList) -> Self {
        RevocationListV2 {
            version: l.version,
            issuer_id: l.issuer_id,
            updated_at: l.updated_at,
            next_update: l.next_update,
            sequence: l.sequence,
            revoked: revoked_in(l.revoked),
            signature: l.signature.into(),
        }
    }
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiRevocationPush {
    pub version: i64,
    pub issuer_id: String,
    pub sequence: i64,
    pub pushed_at: i64,
    pub revoked: Vec<String>,
    pub signature: FfiSignature,
}

impl From<&RevocationPushV2> for FfiRevocationPush {
    fn from(p: &RevocationPushV2) -> Self {
        FfiRevocationPush {
            version: p.version,
            issuer_id: p.issuer_id.clone(),
            sequence: p.sequence,
            pushed_at: p.pushed_at,
            revoked: revoked_out(&p.revoked),
            signature: (&p.signature).into(),
        }
    }
}
impl From<FfiRevocationPush> for RevocationPushV2 {
    fn from(p: FfiRevocationPush) -> Self {
        RevocationPushV2 {
            version: p.version,
            issuer_id: p.issuer_id,
            sequence: p.sequence,
            pushed_at: p.pushed_at,
            revoked: revoked_in(p.revoked),
            signature: p.signature.into(),
        }
    }
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiKeyRotationStatement {
    pub version: i64,
    pub authority_id: String,
    pub recovery_epoch: i64,
    pub role: String,
    pub sequence: i64,
    pub previous_statement_hash: Vec<u8>,
    pub old_key: FfiPublicKey,
    pub new_key: FfiPublicKey,
    pub old_key_id: String,
    pub new_key_id: String,
    pub issued_at: i64,
    pub not_before: i64,
    pub old_signature: FfiSignature,
    pub new_signature: FfiSignature,
}

impl From<&KeyRotationStatementV2> for FfiKeyRotationStatement {
    fn from(s: &KeyRotationStatementV2) -> Self {
        FfiKeyRotationStatement {
            version: s.version,
            authority_id: s.authority_id.clone(),
            recovery_epoch: s.recovery_epoch,
            role: s.role.clone(),
            sequence: s.sequence,
            previous_statement_hash: s.previous_statement_hash.clone(),
            old_key: pk(&s.old_key),
            new_key: pk(&s.new_key),
            old_key_id: s.old_key_id.clone(),
            new_key_id: s.new_key_id.clone(),
            issued_at: s.issued_at,
            not_before: s.not_before,
            old_signature: (&s.old_signature).into(),
            new_signature: (&s.new_signature).into(),
        }
    }
}
impl From<FfiKeyRotationStatement> for KeyRotationStatementV2 {
    fn from(s: FfiKeyRotationStatement) -> Self {
        KeyRotationStatementV2 {
            version: s.version,
            authority_id: s.authority_id,
            recovery_epoch: s.recovery_epoch,
            role: s.role,
            sequence: s.sequence,
            previous_statement_hash: s.previous_statement_hash,
            old_key: s.old_key.into(),
            new_key: s.new_key.into(),
            old_key_id: s.old_key_id,
            new_key_id: s.new_key_id,
            issued_at: s.issued_at,
            not_before: s.not_before,
            old_signature: s.old_signature.into(),
            new_signature: s.new_signature.into(),
        }
    }
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiWitnessEntry {
    pub version: i64,
    pub log_id: String,
    pub sequence: i64,
    pub prev_hash: Vec<u8>,
    pub entry_data: Vec<u8>,
    pub timestamp: i64,
    pub witness_id: String,
    pub signature: FfiSignature,
}

impl From<&WitnessEntryV2> for FfiWitnessEntry {
    fn from(w: &WitnessEntryV2) -> Self {
        FfiWitnessEntry {
            version: w.version,
            log_id: w.log_id.clone(),
            sequence: w.sequence,
            prev_hash: w.prev_hash.clone(),
            entry_data: w.entry_data.clone(),
            timestamp: w.timestamp,
            witness_id: w.witness_id.clone(),
            signature: (&w.signature).into(),
        }
    }
}
impl From<FfiWitnessEntry> for WitnessEntryV2 {
    fn from(w: FfiWitnessEntry) -> Self {
        WitnessEntryV2 {
            version: w.version,
            log_id: w.log_id,
            sequence: w.sequence,
            prev_hash: w.prev_hash,
            entry_data: w.entry_data,
            timestamp: w.timestamp,
            witness_id: w.witness_id,
            signature: w.signature.into(),
        }
    }
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiConstraintEvaluatorRef {
    pub kind: String,
    pub profile_digest: String,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiStatusEvidenceEntry {
    pub issuer_id: String,
    pub status_key_id: String,
    pub sequence: i64,
    pub object_type: u16,
    pub digest: String,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiVerificationReceipt {
    pub version: i64,
    pub log_id: String,
    pub sequence: i64,
    pub verifier_id: String,
    pub agent_id: String,
    pub human_id: String,
    pub bundle_hash: String,
    pub issuer_ids: Vec<String>,
    pub decision: String,
    pub decision_reason: String,
    pub identity_status: String,
    pub trust_assessment: String,
    pub status_assessment: String,
    pub challenge_assessment: String,
    pub constraint_evaluators: Vec<FfiConstraintEvaluatorRef>,
    pub context_assessment: String,
    pub context_policy_digest: Option<String>,
    pub verified_at: i64,
    pub required_scope: String,
    pub granted_scope: Vec<String>,
    pub status_evidence: Vec<FfiStatusEvidenceEntry>,
    pub previous_receipt_hash: Vec<u8>,
    pub signature: FfiSignature,
}

impl From<&VerificationReceiptV2> for FfiVerificationReceipt {
    fn from(r: &VerificationReceiptV2) -> Self {
        FfiVerificationReceipt {
            version: r.version,
            log_id: r.log_id.clone(),
            sequence: r.sequence,
            verifier_id: r.verifier_id.clone(),
            agent_id: r.agent_id.clone(),
            human_id: r.human_id.clone(),
            bundle_hash: r.bundle_hash.clone(),
            issuer_ids: r.issuer_ids.clone(),
            decision: r.decision.clone(),
            decision_reason: r.decision_reason.clone(),
            identity_status: r.identity_status.clone(),
            trust_assessment: r.trust_assessment.clone(),
            status_assessment: r.status_assessment.clone(),
            challenge_assessment: r.challenge_assessment.clone(),
            constraint_evaluators: r
                .constraint_evaluators
                .iter()
                .map(|e| FfiConstraintEvaluatorRef { kind: e.kind.clone(), profile_digest: e.profile_digest.clone() })
                .collect(),
            context_assessment: r.context_assessment.clone(),
            context_policy_digest: r.context_policy_digest.clone(),
            verified_at: r.verified_at,
            required_scope: r.required_scope.clone(),
            granted_scope: r.granted_scope.clone(),
            status_evidence: r
                .status_evidence
                .iter()
                .map(|e| FfiStatusEvidenceEntry {
                    issuer_id: e.issuer_id.clone(),
                    status_key_id: e.status_key_id.clone(),
                    sequence: e.sequence,
                    object_type: e.object_type,
                    digest: e.digest.clone(),
                })
                .collect(),
            previous_receipt_hash: r.previous_receipt_hash.clone(),
            signature: (&r.signature).into(),
        }
    }
}
impl From<FfiVerificationReceipt> for VerificationReceiptV2 {
    fn from(r: FfiVerificationReceipt) -> Self {
        VerificationReceiptV2 {
            version: r.version,
            log_id: r.log_id,
            sequence: r.sequence,
            verifier_id: r.verifier_id,
            agent_id: r.agent_id,
            human_id: r.human_id,
            bundle_hash: r.bundle_hash,
            issuer_ids: r.issuer_ids,
            decision: r.decision,
            decision_reason: r.decision_reason,
            identity_status: r.identity_status,
            trust_assessment: r.trust_assessment,
            status_assessment: r.status_assessment,
            challenge_assessment: r.challenge_assessment,
            constraint_evaluators: r
                .constraint_evaluators
                .into_iter()
                .map(|e| ConstraintEvaluatorRefV2 { kind: e.kind, profile_digest: e.profile_digest })
                .collect(),
            context_assessment: r.context_assessment,
            context_policy_digest: r.context_policy_digest,
            verified_at: r.verified_at,
            required_scope: r.required_scope,
            granted_scope: r.granted_scope,
            status_evidence: r
                .status_evidence
                .into_iter()
                .map(|e| StatusEvidenceEntryV2 {
                    issuer_id: e.issuer_id,
                    status_key_id: e.status_key_id,
                    sequence: e.sequence,
                    object_type: e.object_type,
                    digest: e.digest,
                })
                .collect(),
            previous_receipt_hash: r.previous_receipt_hash,
            signature: r.signature.into(),
        }
    }
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiTransactionReceiptParty {
    pub party_id: String,
    pub role: String,
    pub agent_id: String,
    pub agent_pub_key: FfiPublicKey,
    pub verifier_id: String,
    pub workspace_id: String,
    pub session_id: String,
    pub invocation_id: String,
    pub required_scope: String,
    pub proof_bundle_hash: String,
    pub proof_bundle: Option<FfiProofBundle>,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiTransactionReceiptSignature {
    pub party_id: String,
    pub signature: FfiSignature,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiTransactionReceipt {
    pub version: i64,
    pub transaction_id: String,
    pub created_at: i64,
    pub terms_schema_uri: String,
    pub terms_canonical_json: Vec<u8>,
    pub parties: Vec<FfiTransactionReceiptParty>,
    pub party_signatures: Vec<FfiTransactionReceiptSignature>,
}

impl From<&TransactionReceiptV2> for FfiTransactionReceipt {
    fn from(t: &TransactionReceiptV2) -> Self {
        FfiTransactionReceipt {
            version: t.version,
            transaction_id: t.transaction_id.clone(),
            created_at: t.created_at,
            terms_schema_uri: t.terms_schema_uri.clone(),
            terms_canonical_json: t.terms_canonical_json.clone(),
            parties: t
                .parties
                .iter()
                .map(|p| FfiTransactionReceiptParty {
                    party_id: p.party_id.clone(),
                    role: p.role.clone(),
                    agent_id: p.agent_id.clone(),
                    agent_pub_key: pk(&p.agent_pub_key),
                    verifier_id: p.verifier_id.clone(),
                    workspace_id: p.workspace_id.clone(),
                    session_id: p.session_id.clone(),
                    invocation_id: p.invocation_id.clone(),
                    required_scope: p.required_scope.clone(),
                    proof_bundle_hash: p.proof_bundle_hash.clone(),
                    proof_bundle: p.proof_bundle.as_ref().map(Into::into),
                })
                .collect(),
            party_signatures: t
                .party_signatures
                .iter()
                .map(|s| FfiTransactionReceiptSignature { party_id: s.party_id.clone(), signature: (&s.signature).into() })
                .collect(),
        }
    }
}
impl From<FfiTransactionReceipt> for TransactionReceiptV2 {
    fn from(t: FfiTransactionReceipt) -> Self {
        TransactionReceiptV2 {
            version: t.version,
            transaction_id: t.transaction_id,
            created_at: t.created_at,
            terms_schema_uri: t.terms_schema_uri,
            terms_canonical_json: t.terms_canonical_json,
            parties: t
                .parties
                .into_iter()
                .map(|p| TransactionReceiptPartyV2 {
                    party_id: p.party_id,
                    role: p.role,
                    agent_id: p.agent_id,
                    agent_pub_key: p.agent_pub_key.into(),
                    verifier_id: p.verifier_id,
                    workspace_id: p.workspace_id,
                    session_id: p.session_id,
                    invocation_id: p.invocation_id,
                    required_scope: p.required_scope,
                    proof_bundle_hash: p.proof_bundle_hash,
                    proof_bundle: p.proof_bundle.map(Into::into),
                })
                .collect(),
            party_signatures: t
                .party_signatures
                .into_iter()
                .map(|s| TransactionReceiptSignatureV2 { party_id: s.party_id, signature: s.signature.into() })
                .collect(),
        }
    }
}

/// One status object in a status evidence batch: its object type and wire.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiStatusEvidenceObject {
    pub object_type: u16,
    pub wire: Vec<u8>,
}

pub(crate) fn batch_out(b: &V2StatusEvidenceBatch) -> Vec<FfiStatusEvidenceObject> {
    b.objects.iter().map(|o| FfiStatusEvidenceObject { object_type: o.object_type, wire: o.wire.clone() }).collect()
}

// Strict decoders: one per object kind, each a single core call.

#[uniffi::export]
pub fn ffi_decode_delegation_cert(data: Vec<u8>) -> FfiResult<FfiDelegationCert> {
    crate::guard::call(|| Ok((&ratify_protocol::v2::decode_delegation_cert_v2(&data)?).into()))
}
#[uniffi::export]
pub fn ffi_decode_proof_bundle(data: Vec<u8>) -> FfiResult<FfiProofBundle> {
    crate::guard::call(|| Ok((&ratify_protocol::v2::decode_proof_bundle_v2(&data)?).into()))
}
#[uniffi::export]
pub fn ffi_decode_revocation_list(data: Vec<u8>) -> FfiResult<FfiRevocationList> {
    crate::guard::call(|| Ok((&ratify_protocol::v2::decode_revocation_list_v2(&data)?).into()))
}
#[uniffi::export]
pub fn ffi_decode_revocation_push(data: Vec<u8>) -> FfiResult<FfiRevocationPush> {
    crate::guard::call(|| Ok((&ratify_protocol::v2::decode_revocation_push_v2(&data)?).into()))
}
#[uniffi::export]
pub fn ffi_decode_key_rotation_statement(data: Vec<u8>) -> FfiResult<FfiKeyRotationStatement> {
    crate::guard::call(|| Ok((&ratify_protocol::v2::decode_key_rotation_statement_v2(&data)?).into()))
}
#[uniffi::export]
pub fn ffi_decode_witness_entry(data: Vec<u8>) -> FfiResult<FfiWitnessEntry> {
    crate::guard::call(|| Ok((&ratify_protocol::v2::decode_witness_entry_v2(&data)?).into()))
}
#[uniffi::export]
pub fn ffi_decode_verification_receipt(data: Vec<u8>) -> FfiResult<FfiVerificationReceipt> {
    crate::guard::call(|| Ok((&ratify_protocol::v2::decode_verification_receipt_v2(&data)?).into()))
}
#[uniffi::export]
pub fn ffi_decode_verification_receipt_body(data: Vec<u8>) -> FfiResult<FfiVerificationReceipt> {
    crate::guard::call(|| Ok((&ratify_protocol::v2::decode_verification_receipt_body_v2(&data)?).into()))
}
#[uniffi::export]
pub fn ffi_decode_transaction_receipt(data: Vec<u8>) -> FfiResult<FfiTransactionReceipt> {
    crate::guard::call(|| Ok((&ratify_protocol::v2::decode_transaction_receipt_v2(&data)?).into()))
}
#[uniffi::export]
pub fn ffi_decode_status_evidence_batch(data: Vec<u8>) -> FfiResult<Vec<FfiStatusEvidenceObject>> {
    crate::guard::call(|| Ok(batch_out(&ratify_protocol::v2::decode_v2_status_evidence_batch(&data)?)))
}
