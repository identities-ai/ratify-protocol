//! Delegation certificates (0x0001), proof bundles and challenge
//! presentations (0x0002), revocation lists (0x0003) and pushes (0x0005).
//! Mirrors Go `protocol_v2_wire.go`.

use super::constraints::{validate_v2_constraint_fields, ConstraintV2, CONSTRAINT_RESOURCE_PATH};
use super::context::V2Context;
use super::crypto::{equal_keys, key_id_v2, sha384, valid_v2_id, verify_v2_statement, V2ObjectType};
use super::errors::{err, plain, Classify, V2Error, V2ErrorClass, V2Result, V2SignError, V2SignResult};
use super::json::{canonical, obj, parse_wire, JNode, CJ, JV};
use super::limits::{
    check_v2_wire_size, valid_v2_timestamp, MAX_DELEGATION_CERT_BYTES_V2, MAX_PROOF_BUNDLE_BYTES_V2,
    MAX_REVOCATION_LIST_BYTES_V2, MAX_REVOCATION_LIST_REFS_V2, MAX_REVOCATION_PUSH_BYTES_V2,
    MAX_REVOCATION_PUSH_REFS_V2, V2_MAX_DELEGATION_LIFETIME_SECONDS, V2_MAX_TIMESTAMP_SECONDS,
};
use super::signer::{sign_v2_statement_with_signer, signer_public_key_v2, LocalSignerV2, SignerV2};
use crate::resource_path::{normalize_resource_path, resource_paths_nested};
use crate::scope::{scope_wildcards, validate_scopes, vocabulary, CUSTOM_SCOPE_PREFIX};
use crate::types::{
    HybridPrivateKey, HybridPublicKey, HybridSignature, MAX_CONSTRAINTS_PER_CERT,
    MAX_DELEGATION_CHAIN_DEPTH, MAX_IDENTIFIER_LENGTH_BYTES, MAX_SCOPES_PER_CERT,
    MAX_SCOPE_LENGTH_BYTES,
};

pub(crate) const MAX_SAFE: i64 = crate::canonical::wire_int::MAX_SAFE_INTEGER;

pub(crate) fn safe(v: i64) -> bool {
    (-MAX_SAFE..=MAX_SAFE).contains(&v)
}

/// Delegation certificate (object code 0x0001).
#[derive(Debug, Clone)]
pub struct DelegationCertV2 {
    pub version: i64,
    pub cert_id: String,
    pub issuer_id: String,
    pub issuer_pub_key: HybridPublicKey,
    pub subject_id: String,
    pub subject_pub_key: HybridPublicKey,
    pub scope: Vec<String>,
    pub constraints: Vec<ConstraintV2>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub signature: HybridSignature,
}

/// Proof bundle carrying a challenge presentation (object code 0x0002).
/// `None` fields encode as JSON `null`.
#[derive(Debug, Clone)]
pub struct ProofBundleV2 {
    pub version: i64,
    pub verifier_id: String,
    pub agent_id: String,
    pub agent_pub_key: HybridPublicKey,
    pub delegations: Vec<DelegationCertV2>,
    pub delegation_digest: Vec<u8>,
    pub challenge: Vec<u8>,
    pub challenge_at: i64,
    pub challenge_sig: HybridSignature,
    pub session_context: Option<Vec<u8>>,
    pub stream_id: Option<Vec<u8>>,
    pub stream_seq: Option<i64>,
}

/// Issuer-scoped revoked certificate reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedCertV2 {
    pub cert_id: String,
}

/// Full revocation snapshot (object code 0x0003).
#[derive(Debug, Clone)]
pub struct RevocationListV2 {
    pub version: i64,
    pub issuer_id: String,
    pub updated_at: i64,
    pub next_update: i64,
    pub sequence: i64,
    pub revoked: Vec<RevokedCertV2>,
    pub signature: HybridSignature,
}

/// Incremental revocation push (object code 0x0005).
#[derive(Debug, Clone)]
pub struct RevocationPushV2 {
    pub version: i64,
    pub issuer_id: String,
    pub sequence: i64,
    pub pushed_at: i64,
    pub revoked: Vec<RevokedCertV2>,
    pub signature: HybridSignature,
}

const DELEGATION_FIELDS: &[&str] = &[
    "version",
    "cert_id",
    "issuer_id",
    "issuer_pub_key",
    "subject_id",
    "subject_pub_key",
    "scope",
    "constraints",
    "issued_at",
    "expires_at",
    "signature",
];
const BUNDLE_FIELDS: &[&str] = &[
    "version",
    "verifier_id",
    "agent_id",
    "agent_pub_key",
    "delegations",
    "delegation_digest",
    "challenge",
    "challenge_at",
    "challenge_sig",
    "session_context",
    "stream_id",
    "stream_seq",
];
const LIST_FIELDS: &[&str] = &[
    "version",
    "issuer_id",
    "updated_at",
    "next_update",
    "sequence",
    "revoked",
    "signature",
];
const PUSH_FIELDS: &[&str] = &[
    "version",
    "issuer_id",
    "sequence",
    "pushed_at",
    "revoked",
    "signature",
];

// ---------------------------------------------------------------------------
// Scopes

fn is_wildcard(scope: &str) -> bool {
    scope_wildcards().contains_key(scope)
}

/// Protocol v2 delegation scope rules (post-claim): non-empty, registered or
/// custom, no `custom:*`, no duplicates.
pub fn validate_scopes_v2(scopes: &[String]) -> V2Result<()> {
    if scopes.is_empty() {
        return plain("scope must be a non-empty array");
    }
    if let Some(e) = validate_scopes(scopes) {
        return plain(e);
    }
    for (i, scope) in scopes.iter().enumerate() {
        if scope == "custom:*" {
            return plain("custom:* is not a valid scope");
        }
        if scopes[..i].contains(scope) {
            return plain(format!("duplicate scope {scope:?}"));
        }
    }
    Ok(())
}

/// Exactly one requestable action scope (SPEC-v2 §2.4): a registered
/// canonical non-wildcard scope, or one exact `custom:` extension scope. A
/// canonical wildcard, `custom:*`, the bare prefix `custom:`, an empty string,
/// and a scope longer than `MAX_SCOPE_LENGTH_BYTES` are rejected. A custom
/// required scope is an exact string matched by byte equality.
pub fn validate_required_scope_v2(scope: &str) -> V2Result<()> {
    required_scope_v2(scope).classify(V2ErrorClass::InvalidRequiredScope)
}

/// Unclassified form for decoders, which report an invalid embedded required
/// scope as `malformed` (Go `ValidateRequiredScopeV2` inside a decoder).
pub(crate) fn required_scope_v2(scope: &str) -> V2Result<()> {
    if vocabulary().contains(&scope) && !is_wildcard(scope) {
        return Ok(());
    }
    if scope.starts_with(CUSTOM_SCOPE_PREFIX)
        && scope.len() > CUSTOM_SCOPE_PREFIX.len()
        && scope != "custom:*"
        && scope.len() <= MAX_SCOPE_LENGTH_BYTES
    {
        return Ok(());
    }
    plain("required scope must be one canonical scope or one exact custom: scope")
}

pub(crate) fn is_wildcard_scope(scope: &str) -> bool {
    is_wildcard(scope)
}

fn constraints_cj(cs: &[ConstraintV2]) -> V2Result<CJ> {
    Ok(CJ::Arr(cs.iter().map(ConstraintV2::to_cj).collect::<V2Result<_>>()?))
}

// ---------------------------------------------------------------------------
// Delegation certificate

fn validate_signature_lengths(sig: &HybridSignature) -> V2Result<()> {
    if sig.ed25519.len() != 64 || sig.ml_dsa_65.len() != 3309 {
        return plain(
            "wire v2: signature must contain 64-byte Ed25519 and 3309-byte ML-DSA-65 components",
        );
    }
    Ok(())
}

pub(crate) fn placeholder_signature() -> HybridSignature {
    HybridSignature {
        ed25519: vec![0; 64],
        ml_dsa_65: vec![0; 3309],
    }
}

pub(crate) fn validate_delegation_cert_v2(c: &DelegationCertV2) -> V2Result<()> {
    if c.version != 2 {
        return plain("version must be 2");
    }
    if !valid_v2_timestamp(c.issued_at) || !valid_v2_timestamp(c.expires_at) {
        return plain(format!(
            "issued_at and expires_at must be inside 0..{V2_MAX_TIMESTAMP_SECONDS}"
        ));
    }
    if c.cert_id.is_empty() || c.cert_id.len() > MAX_IDENTIFIER_LENGTH_BYTES {
        return plain("cert_id must be non-empty and within the identifier byte limit");
    }
    if !valid_v2_id(&c.issuer_id) || !valid_v2_id(&c.subject_id) {
        return plain("issuer_id and subject_id must be 64 lowercase hexadecimal characters");
    }
    let issuer = key_id_v2(&c.issuer_pub_key).map_err(|e| e.context("issuer key"))?;
    let subject = key_id_v2(&c.subject_pub_key).map_err(|e| e.context("subject key"))?;
    if c.issuer_id != issuer || c.subject_id != subject {
        return err(
            V2ErrorClass::KeyIdMismatch,
            "key ID does not match complete public key",
        );
    }
    if c.scope.iter().any(|s| s.len() > MAX_SCOPE_LENGTH_BYTES) {
        return plain("scope exceeds the protocol byte limit");
    }
    if c.scope.len() > MAX_SCOPES_PER_CERT || c.constraints.len() > MAX_CONSTRAINTS_PER_CERT {
        return plain("scope or constraint count exceeds protocol bound");
    }
    for (i, constraint) in c.constraints.iter().enumerate() {
        constraint
            .to_cj()
            .map_err(|e| e.context(format!("constraint {i}")))?;
    }
    Ok(())
}

fn cert_cj(c: &DelegationCertV2, with_signature: bool) -> V2Result<CJ> {
    let mut fields = vec![
        ("cert_id", CJ::s(&c.cert_id)),
        ("constraints", constraints_cj(&c.constraints)?),
        ("expires_at", CJ::Int(c.expires_at)),
        ("issued_at", CJ::Int(c.issued_at)),
        ("issuer_id", CJ::s(&c.issuer_id)),
        ("issuer_pub_key", CJ::key(&c.issuer_pub_key)),
        ("scope", CJ::strs(&c.scope)),
        ("subject_id", CJ::s(&c.subject_id)),
        ("subject_pub_key", CJ::key(&c.subject_pub_key)),
        ("version", CJ::Int(c.version)),
    ];
    if with_signature {
        fields.push(("signature", CJ::sig(&c.signature)));
    }
    Ok(CJ::obj(fields))
}

/// Canonical signable projection of a certificate (all fields but `signature`).
pub fn delegation_cert_v2_signable_bytes(c: &DelegationCertV2) -> V2Result<Vec<u8>> {
    canonical(&cert_cj(c, false)?)
}

/// Shape checks on a raw certificate that Go performs before struct decoding.
fn precheck_cert_node(node: &JNode) -> V2Result<()> {
    let o = obj(node)?;
    o.require(DELEGATION_FIELDS, &[])?;
    let constraints = match o.get("constraints").map(|n| &n.v) {
        Some(JV::Arr(items)) => items,
        _ => return plain("wire v2: constraints must be an array"),
    };
    match o.get("scope") {
        Some(scope) => validate_v2_scope_array(scope)?,
        None => return plain("wire v2: required field \"scope\" is missing"),
    }
    for (i, raw) in constraints.iter().enumerate() {
        validate_v2_constraint_fields(raw).map_err(|e| e.context(format!("wire v2 constraint {i}")))?;
    }
    Ok(())
}

fn validate_v2_scope_array(node: &JNode) -> V2Result<()> {
    let JV::Arr(items) = &node.v else {
        return plain("wire v2: scope must be an array of strings");
    };
    if items.len() > MAX_SCOPES_PER_CERT {
        return plain("wire v2: scope count exceeds protocol bound");
    }
    for (i, item) in items.iter().enumerate() {
        match &item.v {
            JV::Str(s) if s.len() <= MAX_SCOPE_LENGTH_BYTES => {}
            _ => return plain(format!("wire v2: scope {i} must be a bounded string")),
        }
    }
    Ok(())
}

fn cert_from_node(node: &JNode) -> V2Result<DelegationCertV2> {
    let o = obj(node)?;
    o.only(DELEGATION_FIELDS)?;
    let mut constraints = Vec::new();
    for c in o.array("constraints")? {
        constraints.push(ConstraintV2::from_node(c)?);
    }
    Ok(DelegationCertV2 {
        version: o.i64("version")?,
        cert_id: o.str("cert_id")?,
        issuer_id: o.str("issuer_id")?,
        issuer_pub_key: o.pub_key("issuer_pub_key")?,
        subject_id: o.str("subject_id")?,
        subject_pub_key: o.pub_key("subject_pub_key")?,
        scope: o.str_array("scope")?,
        constraints,
        issued_at: o.i64("issued_at")?,
        expires_at: o.i64("expires_at")?,
        signature: o.sig("signature")?,
    })
}

/// Strictly decode one v2 delegation certificate.
pub fn decode_delegation_cert_v2(data: &[u8]) -> V2Result<DelegationCertV2> {
    decode_cert_inner(data).classify(V2ErrorClass::Malformed)
}

fn decode_cert_inner(data: &[u8]) -> V2Result<DelegationCertV2> {
    check_v2_wire_size(data, "certificate", "MAX_DELEGATION_CERT_BYTES_V2", MAX_DELEGATION_CERT_BYTES_V2)?;
    let root = parse_wire(data, &[], &[])?;
    precheck_cert_node(&root)?;
    let cert = cert_from_node(&root)?;
    validate_delegation_cert_v2(&cert)?;
    validate_signature_lengths(&cert.signature)?;
    Ok(cert)
}

/// Canonical wire bytes of a certificate (validated, then round-trip checked).
pub fn encode_delegation_cert_v2(c: &DelegationCertV2) -> V2Result<Vec<u8>> {
    validate_delegation_cert_v2(c)?;
    validate_signature_lengths(&c.signature)?;
    let encoded = canonical(&cert_cj(c, true)?)?;
    decode_delegation_cert_v2(&encoded)
        .map_err(|e| e.context("invalid v2 delegation certificate"))?;
    Ok(encoded)
}

/// Verify one certificate's structure, key-ID bindings, and issuer signature
/// (code 0x0001) with its own issuer key. Trust is not established here.
pub fn verify_delegation_cert_v2_signature(c: &DelegationCertV2) -> V2Result<()> {
    validate_delegation_cert_v2(c).classify(V2ErrorClass::Malformed)?;
    validate_signature_lengths(&c.signature).classify(V2ErrorClass::Malformed)?;
    let signable = delegation_cert_v2_signable_bytes(c).classify(V2ErrorClass::Malformed)?;
    verify_v2_statement(
        V2ObjectType::DelegationCertificate,
        &signable,
        &c.signature,
        &c.issuer_pub_key,
    )
}

/// Return a signed copy of `cert` under the issuer's v2 private key. The
/// issuer duties of [`sign_delegation_cert_v2_with_signer`] apply.
pub fn sign_delegation_cert_v2(
    cert: &DelegationCertV2,
    issuer_key: &HybridPrivateKey,
) -> V2SignResult<DelegationCertV2> {
    sign_delegation_cert_v2_with_signer(&V2Context::background(), cert, &LocalSignerV2::new(issuer_key)?)
}

/// Sign `cert` with an external signer whose complete public key must equal
/// the certificate issuer key.
///
/// The issuer duties of SPEC-v2 §5.1 and §5.2 are checked before any signer
/// method runs: the certificate must validate, carry valid v2 scopes, have
/// `issued_at < expires_at` and a lifetime of at most 315360000 seconds, and
/// carry a jointly satisfiable set of `resource_path` constraints. These are
/// issuer hygiene only; verifiers apply their own rules independently.
pub fn sign_delegation_cert_v2_with_signer(
    ctx: &V2Context,
    cert: &DelegationCertV2,
    signer: &dyn SignerV2,
) -> V2SignResult<DelegationCertV2> {
    validate_delegation_cert_v2(cert).classify(V2ErrorClass::Malformed)?;
    validate_scopes_v2(cert.scope.as_slice())
        .map_err(|e| V2SignError::IssuerDuty(format!("v2 issuer scope: {}", e.message)))?;
    validate_delegation_issuance_v2(cert)?;
    let issuer_pub = signer_public_key_v2(signer)?;
    let issuer_id = key_id_v2(&issuer_pub).classify(V2ErrorClass::Malformed)?;
    if cert.issuer_id != issuer_id || !equal_keys(&cert.issuer_pub_key, &issuer_pub) {
        return Err(V2SignError::KeyBinding(
            "v2 issuer key does not match certificate issuer".into(),
        ));
    }
    let mut unsigned = cert.clone();
    unsigned.signature = placeholder_signature();
    let mut prepared = decode_delegation_cert_v2(&encode_delegation_cert_v2(&unsigned)?)?;
    let signable = delegation_cert_v2_signable_bytes(&prepared)?;
    prepared.signature = sign_v2_statement_with_signer(
        ctx,
        V2ObjectType::DelegationCertificate,
        &signable,
        signer,
        &issuer_pub,
    )?;
    let signed = decode_delegation_cert_v2(&encode_delegation_cert_v2(&prepared)?)?;
    verify_v2_statement(
        V2ObjectType::DelegationCertificate,
        &signable,
        &signed.signature,
        &issuer_pub,
    )
    .map_err(V2SignError::SignatureRejected)?;
    Ok(signed)
}

/// Issuer duties a decoder does not enforce (Go `validateDelegationIssuanceV2`).
pub(crate) fn validate_delegation_issuance_v2(cert: &DelegationCertV2) -> V2SignResult<()> {
    let duty = |m: String| Err(V2SignError::IssuerDuty(m));
    if cert.issued_at >= cert.expires_at {
        return duty("issued_at must be earlier than expires_at".into());
    }
    if cert.expires_at - cert.issued_at > V2_MAX_DELEGATION_LIFETIME_SECONDS {
        return duty(format!(
            "delegation lifetime exceeds {V2_MAX_DELEGATION_LIFETIME_SECONDS} seconds"
        ));
    }
    let mut resource_id = "";
    let mut prefixes: Vec<&str> = Vec::new();
    for (i, c) in cert.constraints.iter().enumerate() {
        if c.kind != CONSTRAINT_RESOURCE_PATH {
            continue;
        }
        if !c.path_prefix.is_empty() {
            if let Err(e) = normalize_resource_path(&c.path_prefix) {
                return duty(format!("constraint {i} path_prefix can never match: {e}"));
            }
        }
        if resource_id.is_empty() {
            resource_id = &c.resource_id;
        } else if c.resource_id != resource_id {
            return duty(format!(
                "constraint {i} names a different resource_id; the resource_path set is jointly unsatisfiable"
            ));
        }
        for prior in &prefixes {
            if !resource_paths_nested(prior, &c.path_prefix) {
                return duty(format!(
                    "constraint {i} path_prefix {:?} does not nest with {prior:?}; the resource_path set is jointly unsatisfiable",
                    c.path_prefix
                ));
            }
        }
        prefixes.push(&c.path_prefix);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Proof bundle

fn opt_bytes_cj(v: &Option<Vec<u8>>) -> CJ {
    v.as_ref().map_or(CJ::Null, |b| CJ::Bytes(b.clone()))
}

fn bundle_cj(b: &ProofBundleV2) -> V2Result<CJ> {
    Ok(CJ::obj(vec![
        ("agent_id", CJ::s(&b.agent_id)),
        ("agent_pub_key", CJ::key(&b.agent_pub_key)),
        ("challenge", CJ::Bytes(b.challenge.clone())),
        ("challenge_at", CJ::Int(b.challenge_at)),
        ("challenge_sig", CJ::sig(&b.challenge_sig)),
        ("delegation_digest", CJ::Bytes(b.delegation_digest.clone())),
        (
            "delegations",
            CJ::Arr(
                b.delegations
                    .iter()
                    .map(|c| cert_cj(c, true))
                    .collect::<V2Result<_>>()?,
            ),
        ),
        ("session_context", opt_bytes_cj(&b.session_context)),
        ("stream_id", opt_bytes_cj(&b.stream_id)),
        ("stream_seq", b.stream_seq.map_or(CJ::Null, CJ::Int)),
        ("verifier_id", CJ::s(&b.verifier_id)),
        ("version", CJ::Int(b.version)),
    ]))
}

/// Canonical challenge-presentation signable (code 0x0002): the bundle
/// without `delegations` and `challenge_sig`.
pub fn presentation_v2_signable_bytes(b: &ProofBundleV2) -> V2Result<Vec<u8>> {
    canonical(&CJ::obj(vec![
        ("agent_id", CJ::s(&b.agent_id)),
        ("agent_pub_key", CJ::key(&b.agent_pub_key)),
        ("challenge", CJ::Bytes(b.challenge.clone())),
        ("challenge_at", CJ::Int(b.challenge_at)),
        ("delegation_digest", CJ::Bytes(b.delegation_digest.clone())),
        ("session_context", opt_bytes_cj(&b.session_context)),
        ("stream_id", opt_bytes_cj(&b.stream_id)),
        ("stream_seq", b.stream_seq.map_or(CJ::Null, CJ::Int)),
        ("verifier_id", CJ::s(&b.verifier_id)),
        ("version", CJ::Int(b.version)),
    ]))
}

/// SHA-384("ratify-protocol-delegations-v2\0" || canonical(certs)).
pub fn delegation_digest_v2(certs: &[DelegationCertV2]) -> V2Result<Vec<u8>> {
    let canonical_certs = canonical(&CJ::Arr(
        certs
            .iter()
            .map(|c| cert_cj(c, true))
            .collect::<V2Result<_>>()?,
    ))?;
    Ok(sha384(&[
        b"ratify-protocol-delegations-v2\0",
        &canonical_certs,
    ]))
}

/// "sha384:" + hex(SHA-384("ratify-protocol-bundle-v2\0" || canonical bundle)).
pub fn bundle_hash_v2(b: &ProofBundleV2) -> V2Result<String> {
    let encoded = encode_proof_bundle_v2(b)?;
    Ok(bundle_hash_of_bytes(&encoded))
}

pub(crate) fn bundle_hash_of_bytes(encoded: &[u8]) -> String {
    format!(
        "sha384:{}",
        hex::encode(sha384(&[b"ratify-protocol-bundle-v2\0", encoded]))
    )
}

/// Strictly decode a v2 proof bundle.
pub fn decode_proof_bundle_v2(data: &[u8]) -> V2Result<ProofBundleV2> {
    decode_bundle_inner(data).classify(V2ErrorClass::Malformed)
}

fn decode_bundle_inner(data: &[u8]) -> V2Result<ProofBundleV2> {
    check_v2_wire_size(data, "proof bundle", "MAX_PROOF_BUNDLE_BYTES_V2", MAX_PROOF_BUNDLE_BYTES_V2)?;
    let root = parse_wire(data, &["delegation_digest"], &[])?;
    let o = obj(&root)?;
    o.require(
        BUNDLE_FIELDS,
        &["session_context", "stream_id", "stream_seq"],
    )?;
    let Some(JV::Arr(raw_certs)) = o.get("delegations").map(|n| &n.v) else {
        return plain("wire v2: delegations must be an array");
    };
    for (i, raw) in raw_certs.iter().enumerate() {
        precheck_cert_node(raw).map_err(|e| e.context(format!("wire v2 delegation {i}")))?;
    }
    o.only(BUNDLE_FIELDS)?;
    let mut delegations = Vec::new();
    for raw in raw_certs {
        delegations.push(cert_from_node(raw)?);
    }
    let bundle = ProofBundleV2 {
        version: o.i64("version")?,
        verifier_id: o.str("verifier_id")?,
        agent_id: o.str("agent_id")?,
        agent_pub_key: o.pub_key("agent_pub_key")?,
        delegations,
        delegation_digest: o.bytes("delegation_digest")?,
        challenge: o.bytes("challenge")?,
        challenge_at: o.i64("challenge_at")?,
        challenge_sig: o.sig("challenge_sig")?,
        session_context: o.opt_bytes("session_context")?,
        stream_id: o.opt_bytes("stream_id")?,
        stream_seq: o.opt_i64("stream_seq")?,
    };
    if bundle.version != 2 {
        return plain("wire v2: version must be 2");
    }
    if !valid_v2_id(&bundle.verifier_id) || !valid_v2_id(&bundle.agent_id) {
        return plain(
            "wire v2: verifier_id and agent_id must be 64 lowercase hexadecimal characters",
        );
    }
    if bundle.delegations.len() > MAX_DELEGATION_CHAIN_DEPTH {
        return plain("wire v2: delegation chain exceeds MAX_DELEGATION_CHAIN_DEPTH");
    }
    if bundle.challenge.len() != 32 {
        return plain("wire v2: challenge must be 32 bytes");
    }
    if !valid_v2_timestamp(bundle.challenge_at) {
        return plain(format!("wire v2: challenge_at is outside 0..{V2_MAX_TIMESTAMP_SECONDS}"));
    }
    if bundle.delegation_digest.len() != 48 {
        return plain("wire v2: delegation_digest must be 48 bytes");
    }
    if bundle
        .session_context
        .as_ref()
        .is_some_and(|s| s.len() != 32)
    {
        return plain("wire v2: session_context must be null or 32 bytes");
    }
    if bundle.stream_id.is_some() != bundle.stream_seq.is_some() {
        return plain("wire v2: stream_id and stream_seq must both be null or both set");
    }
    if let (Some(id), Some(seq)) = (&bundle.stream_id, bundle.stream_seq) {
        if id.len() != 32 || seq <= 0 {
            return plain(
                "wire v2: bound stream requires 32-byte stream_id and positive stream_seq",
            );
        }
    }
    validate_signature_lengths(&bundle.challenge_sig)?;
    for (i, c) in bundle.delegations.iter().enumerate() {
        validate_delegation_cert_v2(c).map_err(|e| e.context(format!("wire v2 delegation {i}")))?;
        validate_signature_lengths(&c.signature)
            .map_err(|e| e.context(format!("wire v2 delegation {i}")))?;
    }
    Ok(bundle)
}

/// Canonical wire bytes of a proof bundle (round-trip checked).
pub fn encode_proof_bundle_v2(b: &ProofBundleV2) -> V2Result<Vec<u8>> {
    let encoded = canonical(&bundle_cj(b)?)?;
    decode_proof_bundle_v2(&encoded).map_err(|e| e.context("invalid v2 proof bundle"))?;
    Ok(encoded)
}

/// Compute the delegation digest and sign the presentation with the agent
/// private key. Trust in the terminal issuer is not established.
pub fn sign_proof_bundle_v2(
    bundle: &ProofBundleV2,
    agent_key: &HybridPrivateKey,
) -> V2SignResult<ProofBundleV2> {
    sign_proof_bundle_v2_with_signer(&V2Context::background(), bundle, &LocalSignerV2::new(agent_key)?)
}

/// [`sign_proof_bundle_v2`] with an external signer whose complete public
/// key must equal the bundle agent key.
pub fn sign_proof_bundle_v2_with_signer(
    ctx: &V2Context,
    bundle: &ProofBundleV2,
    signer: &dyn SignerV2,
) -> V2SignResult<ProofBundleV2> {
    let agent_pub = signer_public_key_v2(signer)?;
    let agent_id = key_id_v2(&agent_pub).classify(V2ErrorClass::Malformed)?;
    if bundle.agent_id != agent_id || !equal_keys(&bundle.agent_pub_key, &agent_pub) {
        return Err(V2SignError::KeyBinding(
            "v2 agent key does not match proof bundle agent".into(),
        ));
    }
    let mut unsigned = bundle.clone();
    unsigned.challenge_sig = placeholder_signature();
    unsigned.delegation_digest = vec![0; 48];
    let mut prepared = decode_proof_bundle_v2(&encode_proof_bundle_v2(&unsigned)?)?;
    prepared.delegation_digest = delegation_digest_v2(&prepared.delegations)?;
    let signable = presentation_v2_signable_bytes(&prepared)?;
    prepared.challenge_sig = sign_v2_statement_with_signer(
        ctx,
        V2ObjectType::ChallengePresentation,
        &signable,
        signer,
        &agent_pub,
    )?;
    let signed = decode_proof_bundle_v2(&encode_proof_bundle_v2(&prepared)?)?;
    verify_proof_bundle_v2_signatures(&signed).map_err(V2SignError::SignatureRejected)?;
    Ok(signed)
}

/// Structure (key IDs, digest, duplicates, linkage) first, then every
/// certificate signature and the challenge signature. Trust is not evaluated.
pub fn verify_proof_bundle_v2_signatures(b: &ProofBundleV2) -> V2Result<()> {
    verify_proof_bundle_v2_structure(b)?;
    for (i, c) in b.delegations.iter().enumerate() {
        let signable = delegation_cert_v2_signable_bytes(c).classify(V2ErrorClass::Malformed)?;
        verify_v2_statement(
            V2ObjectType::DelegationCertificate,
            &signable,
            &c.signature,
            &c.issuer_pub_key,
        )
        .map_err(|e| e.context(format!("delegation {i} signature")))?;
    }
    let signable = presentation_v2_signable_bytes(b).classify(V2ErrorClass::Malformed)?;
    verify_v2_statement(
        V2ObjectType::ChallengePresentation,
        &signable,
        &b.challenge_sig,
        &b.agent_pub_key,
    )
}

pub(crate) fn verify_proof_bundle_v2_structure(b: &ProofBundleV2) -> V2Result<()> {
    use V2ErrorClass::*;
    if b.version != 2 {
        return err(Malformed, "v2 proof bundle version must be 2");
    }
    if b.delegations.len() > MAX_DELEGATION_CHAIN_DEPTH
        || b.challenge.len() != 32
        || b.delegation_digest.len() != 48
    {
        return err(
            Malformed,
            "v2 proof bundle exceeds a chain bound or has an invalid challenge/digest length",
        );
    }
    if b.stream_seq.is_some_and(|s| s > MAX_SAFE) {
        return err(
            Malformed,
            "v2 stream sequence exceeds the safe integer range",
        );
    }
    if b.session_context.as_ref().is_some_and(|s| s.len() != 32) {
        return err(Malformed, "v2 session_context must be null or 32 bytes");
    }
    let stream_ok = match (&b.stream_id, b.stream_seq) {
        (None, None) => true,
        (Some(id), Some(seq)) => id.len() == 32 && seq > 0,
        _ => false,
    };
    if !stream_ok {
        return err(
            Malformed,
            "v2 stream_id and stream_seq must both be null or a 32-byte ID and positive sequence",
        );
    }
    if !valid_v2_id(&b.agent_id) || !valid_v2_id(&b.verifier_id) {
        return err(Malformed, "v2 verifier and agent IDs must be canonical");
    }
    let agent_id = key_id_v2(&b.agent_pub_key).classify(Malformed)?;
    if agent_id != b.agent_id {
        return err(KeyIdMismatch, "agent_id does not match agent_pub_key");
    }
    for (i, c) in b.delegations.iter().enumerate() {
        validate_delegation_cert_v2(c)
            .map_err(|e| e.context(format!("delegation {i}")))
            .classify(Malformed)?;
    }
    let digest = delegation_digest_v2(&b.delegations).classify(Malformed)?;
    if digest != b.delegation_digest {
        return err(DelegationDigestMismatch, "delegation_digest mismatch");
    }
    let mut seen: Vec<(&str, &str)> = Vec::new();
    for (i, c) in b.delegations.iter().enumerate() {
        let r = (c.issuer_id.as_str(), c.cert_id.as_str());
        if seen.contains(&r) {
            return err(DuplicateCertificateRef, "duplicate delegation reference");
        }
        seen.push(r);
        if let Some(parent) = b.delegations.get(i + 1) {
            if c.issuer_id != parent.subject_id
                || !equal_keys(&c.issuer_pub_key, &parent.subject_pub_key)
            {
                return err(
                    ChainLinkageMismatch,
                    format!("delegation chain link {i} does not match parent subject"),
                );
            }
        }
    }
    if let Some(leaf) = b.delegations.first() {
        if leaf.subject_id != b.agent_id || !equal_keys(&leaf.subject_pub_key, &b.agent_pub_key) {
            return err(
                ChainLinkageMismatch,
                "agent key does not match leaf delegation subject",
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Revocation list and push

fn validate_revoked(refs: &[RevokedCertV2]) -> V2Result<()> {
    let mut seen = std::collections::HashSet::with_capacity(refs.len());
    for r in refs {
        if r.cert_id.is_empty() || !seen.insert(r.cert_id.as_str()) {
            return plain("v2 revoked cert IDs must be non-empty and unique");
        }
    }
    Ok(())
}

pub(crate) fn validate_revocation_list_v2(l: &RevocationListV2) -> V2Result<()> {
    if l.version != 2
        || !valid_v2_id(&l.issuer_id)
        || l.sequence <= 0
        || l.sequence > MAX_SAFE
        || !valid_v2_timestamp(l.updated_at)
        || !valid_v2_timestamp(l.next_update)
        || l.next_update <= l.updated_at
    {
        return plain("v2 revocation list has invalid version, issuer, sequence, or time bounds");
    }
    if l.revoked.len() > MAX_REVOCATION_LIST_REFS_V2 {
        return plain(format!(
            "v2 revocation list exceeds MAX_REVOCATION_LIST_REFS_V2 ({MAX_REVOCATION_LIST_REFS_V2})"
        ));
    }
    validate_revoked(&l.revoked)
}

pub(crate) fn validate_revocation_push_v2(p: &RevocationPushV2) -> V2Result<()> {
    if p.version != 2
        || !valid_v2_id(&p.issuer_id)
        || p.sequence <= 0
        || p.sequence > MAX_SAFE
        || !valid_v2_timestamp(p.pushed_at)
    {
        return plain("v2 revocation push has invalid version, issuer, sequence, or timestamp");
    }
    if p.revoked.len() > MAX_REVOCATION_PUSH_REFS_V2 {
        return plain(format!(
            "v2 revocation push exceeds MAX_REVOCATION_PUSH_REFS_V2 ({MAX_REVOCATION_PUSH_REFS_V2})"
        ));
    }
    validate_revoked(&p.revoked)
}

fn revoked_cj(refs: &[RevokedCertV2]) -> CJ {
    CJ::Arr(
        refs.iter()
            .map(|r| CJ::obj(vec![("cert_id", CJ::s(&r.cert_id))]))
            .collect(),
    )
}

fn list_cj(l: &RevocationListV2, with_signature: bool) -> CJ {
    let mut f = vec![
        ("issuer_id", CJ::s(&l.issuer_id)),
        ("next_update", CJ::Int(l.next_update)),
        ("revoked", revoked_cj(&l.revoked)),
        ("sequence", CJ::Int(l.sequence)),
        ("updated_at", CJ::Int(l.updated_at)),
        ("version", CJ::Int(l.version)),
    ];
    if with_signature {
        f.push(("signature", CJ::sig(&l.signature)));
    }
    CJ::obj(f)
}

fn push_cj(p: &RevocationPushV2, with_signature: bool) -> CJ {
    let mut f = vec![
        ("issuer_id", CJ::s(&p.issuer_id)),
        ("pushed_at", CJ::Int(p.pushed_at)),
        ("revoked", revoked_cj(&p.revoked)),
        ("sequence", CJ::Int(p.sequence)),
        ("version", CJ::Int(p.version)),
    ];
    if with_signature {
        f.push(("signature", CJ::sig(&p.signature)));
    }
    CJ::obj(f)
}

/// Canonical revocation-list signable (code 0x0003).
pub fn revocation_list_v2_signable_bytes(l: &RevocationListV2) -> V2Result<Vec<u8>> {
    validate_revocation_list_v2(l)?;
    canonical(&list_cj(l, false))
}

/// Canonical revocation-push signable (code 0x0005).
pub fn revocation_push_v2_signable_bytes(p: &RevocationPushV2) -> V2Result<Vec<u8>> {
    validate_revocation_push_v2(p)?;
    canonical(&push_cj(p, false))
}

fn revoked_from(o: &super::json::Obj<'_>) -> V2Result<Vec<RevokedCertV2>> {
    o.array("revoked")?
        .iter()
        .map(|n| {
            if n.is_null() {
                return Ok(RevokedCertV2 {
                    cert_id: String::new(),
                });
            }
            let e = obj(n)?;
            e.only(&["cert_id"])?;
            Ok(RevokedCertV2 {
                cert_id: e.str("cert_id")?,
            })
        })
        .collect()
}

/// Strictly decode a v2 revocation list.
pub fn decode_revocation_list_v2(data: &[u8]) -> V2Result<RevocationListV2> {
    (|| {
        check_v2_wire_size(data, "revocation list", "MAX_REVOCATION_LIST_BYTES_V2", MAX_REVOCATION_LIST_BYTES_V2)?;
        let root = parse_wire(data, &[], &[])?;
        let o = obj(&root)?;
        o.require(LIST_FIELDS, &[])?;
        o.only(LIST_FIELDS)?;
        let l = RevocationListV2 {
            version: o.i64("version")?,
            issuer_id: o.str("issuer_id")?,
            updated_at: o.i64("updated_at")?,
            next_update: o.i64("next_update")?,
            sequence: o.i64("sequence")?,
            revoked: revoked_from(&o)?,
            signature: o.sig("signature")?,
        };
        validate_revocation_list_v2(&l)?;
        validate_signature_lengths(&l.signature)?;
        Ok(l)
    })()
    .classify(V2ErrorClass::Malformed)
}

/// Strictly decode a v2 revocation push.
pub fn decode_revocation_push_v2(data: &[u8]) -> V2Result<RevocationPushV2> {
    (|| {
        check_v2_wire_size(data, "revocation push", "MAX_REVOCATION_PUSH_BYTES_V2", MAX_REVOCATION_PUSH_BYTES_V2)?;
        let root = parse_wire(data, &[], &[])?;
        let o = obj(&root)?;
        o.require(PUSH_FIELDS, &[])?;
        o.only(PUSH_FIELDS)?;
        let p = RevocationPushV2 {
            version: o.i64("version")?,
            issuer_id: o.str("issuer_id")?,
            sequence: o.i64("sequence")?,
            pushed_at: o.i64("pushed_at")?,
            revoked: revoked_from(&o)?,
            signature: o.sig("signature")?,
        };
        validate_revocation_push_v2(&p)?;
        validate_signature_lengths(&p.signature)?;
        Ok(p)
    })()
    .classify(V2ErrorClass::Malformed)
}

/// Canonical wire bytes of a revocation list.
pub fn encode_revocation_list_v2(l: &RevocationListV2) -> V2Result<Vec<u8>> {
    validate_revocation_list_v2(l)?;
    validate_signature_lengths(&l.signature)?;
    let encoded = canonical(&list_cj(l, true))?;
    decode_revocation_list_v2(&encoded)?;
    Ok(encoded)
}

/// Canonical wire bytes of a revocation push.
pub fn encode_revocation_push_v2(p: &RevocationPushV2) -> V2Result<Vec<u8>> {
    validate_revocation_push_v2(p)?;
    validate_signature_lengths(&p.signature)?;
    let encoded = canonical(&push_cj(p, true))?;
    decode_revocation_push_v2(&encoded)?;
    Ok(encoded)
}

/// Verify a list under the caller-authenticated status key bound to `trusted_issuer_id`.
pub fn verify_revocation_list_v2_signature(
    l: &RevocationListV2,
    trusted_issuer_id: &str,
    status_key: &HybridPublicKey,
) -> V2Result<()> {
    validate_revocation_list_v2(l).classify(V2ErrorClass::Malformed)?;
    if trusted_issuer_id != l.issuer_id {
        return err(
            V2ErrorClass::StatusKeyBindingMismatch,
            "v2 revocation list issuer does not match authenticated status-key binding",
        );
    }
    let signable = revocation_list_v2_signable_bytes(l)?;
    verify_v2_statement(
        V2ObjectType::RevocationList,
        &signable,
        &l.signature,
        status_key,
    )
}

/// Verify a push under the caller-authenticated status key bound to `trusted_issuer_id`.
pub fn verify_revocation_push_v2_signature(
    p: &RevocationPushV2,
    trusted_issuer_id: &str,
    status_key: &HybridPublicKey,
) -> V2Result<()> {
    validate_revocation_push_v2(p).classify(V2ErrorClass::Malformed)?;
    if trusted_issuer_id != p.issuer_id {
        return err(
            V2ErrorClass::StatusKeyBindingMismatch,
            "v2 revocation push issuer does not match authenticated status-key binding",
        );
    }
    let signable = revocation_push_v2_signable_bytes(p)?;
    verify_v2_statement(
        V2ObjectType::RevocationPush,
        &signable,
        &p.signature,
        status_key,
    )
}

fn check_status_signer(
    issuer_id: &str,
    bound_issuer_id: &str,
    bound_status_key: &HybridPublicKey,
    signer: &dyn SignerV2,
) -> V2SignResult<HybridPublicKey> {
    let binding = |m: &str| V2SignError::InvalidObject(V2Error::new(V2ErrorClass::StatusKeyBindingMismatch, m));
    if bound_issuer_id.is_empty() || issuer_id != bound_issuer_id {
        return Err(binding("status object issuer does not match caller-authenticated status-key binding"));
    }
    let derived = signer_public_key_v2(signer)?;
    if !equal_keys(&derived, bound_status_key) {
        return Err(binding("status key does not match caller-authenticated issuer status-key binding"));
    }
    Ok(derived)
}

/// Return a signed copy of `list` under the caller-authenticated status key.
pub fn sign_revocation_list_v2(
    list: &RevocationListV2,
    bound_issuer_id: &str,
    bound_status_key: &HybridPublicKey,
    status_key: &HybridPrivateKey,
) -> V2SignResult<RevocationListV2> {
    sign_revocation_list_v2_with_signer(
        &V2Context::background(),
        list,
        bound_issuer_id,
        bound_status_key,
        &LocalSignerV2::new(status_key)?,
    )
}

/// [`sign_revocation_list_v2`] with an external signer whose complete public
/// key must equal `bound_status_key`.
pub fn sign_revocation_list_v2_with_signer(
    ctx: &V2Context,
    list: &RevocationListV2,
    bound_issuer_id: &str,
    bound_status_key: &HybridPublicKey,
    signer: &dyn SignerV2,
) -> V2SignResult<RevocationListV2> {
    validate_revocation_list_v2(list).classify(V2ErrorClass::Malformed)?;
    let status_pub = check_status_signer(&list.issuer_id, bound_issuer_id, bound_status_key, signer)?;
    let mut prepared = list.clone();
    prepared.signature = placeholder_signature();
    let mut prepared = decode_revocation_list_v2(&encode_revocation_list_v2(&prepared)?)?;
    let signable = revocation_list_v2_signable_bytes(&prepared)?;
    prepared.signature =
        sign_v2_statement_with_signer(ctx, V2ObjectType::RevocationList, &signable, signer, &status_pub)?;
    let signed = decode_revocation_list_v2(&encode_revocation_list_v2(&prepared)?)?;
    verify_revocation_list_v2_signature(&signed, bound_issuer_id, bound_status_key)
        .map_err(V2SignError::SignatureRejected)?;
    Ok(signed)
}

/// Return a signed copy of `push` under the caller-authenticated status key.
pub fn sign_revocation_push_v2(
    push: &RevocationPushV2,
    bound_issuer_id: &str,
    bound_status_key: &HybridPublicKey,
    status_key: &HybridPrivateKey,
) -> V2SignResult<RevocationPushV2> {
    sign_revocation_push_v2_with_signer(
        &V2Context::background(),
        push,
        bound_issuer_id,
        bound_status_key,
        &LocalSignerV2::new(status_key)?,
    )
}

/// [`sign_revocation_push_v2`] with an external signer whose complete public
/// key must equal `bound_status_key`.
pub fn sign_revocation_push_v2_with_signer(
    ctx: &V2Context,
    push: &RevocationPushV2,
    bound_issuer_id: &str,
    bound_status_key: &HybridPublicKey,
    signer: &dyn SignerV2,
) -> V2SignResult<RevocationPushV2> {
    validate_revocation_push_v2(push).classify(V2ErrorClass::Malformed)?;
    let status_pub = check_status_signer(&push.issuer_id, bound_issuer_id, bound_status_key, signer)?;
    let mut prepared = push.clone();
    prepared.signature = placeholder_signature();
    let mut prepared = decode_revocation_push_v2(&encode_revocation_push_v2(&prepared)?)?;
    let signable = revocation_push_v2_signable_bytes(&prepared)?;
    prepared.signature =
        sign_v2_statement_with_signer(ctx, V2ObjectType::RevocationPush, &signable, signer, &status_pub)?;
    let signed = decode_revocation_push_v2(&encode_revocation_push_v2(&prepared)?)?;
    verify_revocation_push_v2_signature(&signed, bound_issuer_id, bound_status_key)
        .map_err(V2SignError::SignatureRejected)?;
    Ok(signed)
}

fn status_digest(code: u16, encoded: &[u8]) -> Vec<u8> {
    sha384(&[
        b"ratify-protocol-status-evidence-v2\0",
        &code.to_be_bytes(),
        encoded,
    ])
}

/// StatusEvidenceDigest(0x0003, list): binds audit evidence to the complete
/// signed canonical list. It does not establish validity or freshness.
pub fn status_evidence_digest_list_v2(l: &RevocationListV2) -> V2Result<Vec<u8>> {
    Ok(status_digest(0x0003, &encode_revocation_list_v2(l)?))
}

/// StatusEvidenceDigest(0x0005, push).
pub fn status_evidence_digest_push_v2(p: &RevocationPushV2) -> V2Result<Vec<u8>> {
    Ok(status_digest(0x0005, &encode_revocation_push_v2(p)?))
}
