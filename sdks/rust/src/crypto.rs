//! Ratify Protocol v1 — hybrid (Ed25519 + ML-DSA-65) crypto primitives.
//!
//! Uses:
//!   - `ed25519-dalek` — audited Ed25519, pure Rust.
//!   - `fips204` — pure-Rust ML-DSA-65 (FIPS 204), no_std compatible.
//!
//! Every sign produces BOTH component signatures. Every verify checks BOTH;
//! either failure fails the whole signature.

use ed25519_dalek::{Signature as EdSignature, Signer as _, SigningKey, Verifier, VerifyingKey};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer as MlSigner, Verifier as MlVerifier};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::canonical::canonical_json;
use crate::types::{
    AgentIdentity, DelegationCert, HumanRoot, HybridPrivateKey, HybridPublicKey, HybridSignature,
    KeyRotationStatement, ProofBundle, ReceiptPartySignature, RevocationList, RevocationPush,
    SessionToken, TransactionReceipt, VerifyResult, WitnessEntry,
};
use serde_json::json;

type HmacSha256 = Hmac<Sha256>;

// ----------------------------------------------------------------------
// ID derivation
// ----------------------------------------------------------------------

/// `hex(SHA-256(ed25519_pub || ml_dsa_65_pub)[:16])`.
pub fn derive_id(pub_key: &HybridPublicKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&pub_key.ed25519);
    hasher.update(&pub_key.ml_dsa_65);
    let digest = hasher.finalize();
    hex::encode(&digest[..16])
}

// ----------------------------------------------------------------------
// Keypair generation
// ----------------------------------------------------------------------

/// Fresh hybrid keypair from OS randomness. Two independent seeds.
pub fn generate_hybrid_keypair() -> (HybridPublicKey, HybridPrivateKey) {
    use rand_core::OsRng;
    let mut seed = [0u8; 32];
    use rand_core::RngCore;
    OsRng.fill_bytes(&mut seed);
    let ed_sk = SigningKey::from_bytes(&seed);
    let ed_pk = ed_sk.verifying_key();

    let (ml_pk, ml_sk) = ml_dsa_65::try_keygen().expect("ML-DSA-65 keygen");

    (
        HybridPublicKey {
            ed25519: ed_pk.to_bytes().to_vec(),
            ml_dsa_65: ml_pk.into_bytes().to_vec(),
        },
        HybridPrivateKey {
            ed25519: seed.to_vec(),
            ml_dsa_65: ml_sk.into_bytes().to_vec(),
        },
    )
}

/// Generate a fresh HumanRoot (public + private).
pub fn generate_human_root() -> (HumanRoot, HybridPrivateKey) {
    let (pub_key, priv_key) = generate_hybrid_keypair();
    let id = derive_id(&pub_key);
    (
        HumanRoot {
            id,
            public_key: pub_key,
            created_at: now_unix(),
            anchors: None,
        },
        priv_key,
    )
}

/// Generate a fresh AgentIdentity.
pub fn generate_agent(name: &str, agent_type: &str) -> (AgentIdentity, HybridPrivateKey) {
    let (pub_key, priv_key) = generate_hybrid_keypair();
    let id = derive_id(&pub_key);
    (
        AgentIdentity {
            id,
            public_key: pub_key,
            name: name.to_string(),
            agent_type: agent_type.to_string(),
            created_at: now_unix(),
        },
        priv_key,
    )
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ----------------------------------------------------------------------
// Canonical signing bytes — MUST match Go reference byte-for-byte.
// ----------------------------------------------------------------------

/// Canonical bytes signed to produce DelegationCert.signature.
///
/// `constraints` is always serialized — as `[]` when empty — so canonical
/// bytes are deterministic across issuers and cross-SDK. Each Constraint
/// round-trips through serde_json with `skip_serializing_if` matching Go's
/// `omitempty` behavior.
pub fn delegation_sign_bytes(cert: &DelegationCert) -> Vec<u8> {
    let signable = json!({
        "cert_id": cert.cert_id,
        "constraints": cert.constraints,
        "expires_at": cert.expires_at,
        "issued_at": cert.issued_at,
        "issuer_id": cert.issuer_id,
        "issuer_pub_key": {
            "ed25519": crate::canonical::base64_std_encode(&cert.issuer_pub_key.ed25519),
            "ml_dsa_65": crate::canonical::base64_std_encode(&cert.issuer_pub_key.ml_dsa_65),
        },
        "scope": cert.scope,
        "subject_id": cert.subject_id,
        "subject_pub_key": {
            "ed25519": crate::canonical::base64_std_encode(&cert.subject_pub_key.ed25519),
            "ml_dsa_65": crate::canonical::base64_std_encode(&cert.subject_pub_key.ml_dsa_65),
        },
        "version": cert.version,
    });
    canonical_json(&signable)
}

/// Canonical bytes signed to produce ProofBundle.challenge_sig.
///
/// NOT JSON. Raw binary: challenge || big-endian uint64(ts).
pub fn challenge_sign_bytes(challenge: &[u8], ts: i64) -> Vec<u8> {
    challenge_sign_bytes_with_stream(challenge, ts, &[], &[], 0)
}

/// v1.1 session-bound challenge signable bytes:
/// challenge || big-endian uint64(ts) || session_context.
pub fn challenge_sign_bytes_with_session_context(
    challenge: &[u8],
    ts: i64,
    session_context: &[u8],
) -> Vec<u8> {
    challenge_sign_bytes_with_stream(challenge, ts, session_context, &[], 0)
}

/// v1.1 stream-bound challenge signable bytes. Layout:
/// `challenge || big-endian uint64(ts) || [session_context] || stream_id || big-endian int64(stream_seq)`.
///
/// `session_context` may be empty or 32 bytes; `stream_id` may be empty (no
/// stream binding) or 32 bytes. When `stream_id` is empty, `stream_seq` is
/// ignored.
pub fn challenge_sign_bytes_with_stream(
    challenge: &[u8],
    ts: i64,
    session_context: &[u8],
    stream_id: &[u8],
    stream_seq: i64,
) -> Vec<u8> {
    let stream_len = if stream_id.is_empty() {
        0
    } else {
        stream_id.len() + 8
    };
    let mut out = Vec::with_capacity(challenge.len() + 8 + session_context.len() + stream_len);
    out.extend_from_slice(challenge);
    out.extend_from_slice(&(ts as u64).to_be_bytes());
    out.extend_from_slice(session_context);
    if !stream_id.is_empty() {
        out.extend_from_slice(stream_id);
        out.extend_from_slice(&(stream_seq as u64).to_be_bytes());
    }
    out
}

/// Canonical bytes signed to produce RevocationList.signature.
pub fn revocation_sign_bytes(list: &RevocationList) -> Vec<u8> {
    let signable = json!({
        "issuer_id": list.issuer_id,
        "revoked_certs": list.revoked_certs,
        "updated_at": list.updated_at,
    });
    canonical_json(&signable)
}

/// Canonical bytes signed by both old and new keys in KeyRotationStatement.
pub fn key_rotation_sign_bytes(stmt: &KeyRotationStatement) -> Vec<u8> {
    let signable = json!({
        "new_id": stmt.new_id,
        "new_pub_key": {
            "ed25519": crate::canonical::base64_std_encode(&stmt.new_pub_key.ed25519),
            "ml_dsa_65": crate::canonical::base64_std_encode(&stmt.new_pub_key.ml_dsa_65),
        },
        "old_id": stmt.old_id,
        "old_pub_key": {
            "ed25519": crate::canonical::base64_std_encode(&stmt.old_pub_key.ed25519),
            "ml_dsa_65": crate::canonical::base64_std_encode(&stmt.old_pub_key.ml_dsa_65),
        },
        "reason": stmt.reason,
        "rotated_at": stmt.rotated_at,
        "version": stmt.version,
    });
    canonical_json(&signable)
}

// ----------------------------------------------------------------------
// Hybrid sign / verify
// ----------------------------------------------------------------------

/// Produce a hybrid signature. Both components over identical `msg`.
pub fn sign_both(msg: &[u8], priv_key: &HybridPrivateKey) -> HybridSignature {
    let mut ed_seed = [0u8; 32];
    ed_seed.copy_from_slice(&priv_key.ed25519[..32]);
    let ed_sk = SigningKey::from_bytes(&ed_seed);
    let ed_sig = ed_sk.sign(msg);

    let mut ml_sk_bytes = [0u8; ml_dsa_65::SK_LEN];
    ml_sk_bytes.copy_from_slice(&priv_key.ml_dsa_65);
    let ml_sk = ml_dsa_65::PrivateKey::try_from_bytes(ml_sk_bytes)
        .expect("ML-DSA-65 secret key malformed");
    let ml_sig = ml_sk.try_sign(msg, &[]).expect("ML-DSA-65 sign");

    HybridSignature {
        ed25519: ed_sig.to_bytes().to_vec(),
        ml_dsa_65: ml_sig.to_vec(),
    }
}

/// Verify both components. Returns Ok iff both verify; Err with diagnostic.
pub fn verify_both(
    msg: &[u8],
    sig: &HybridSignature,
    pub_key: &HybridPublicKey,
) -> Result<(), String> {
    if pub_key.ed25519.len() != 32 {
        return Err(format!(
            "Ed25519 public key wrong length: {}",
            pub_key.ed25519.len()
        ));
    }
    if pub_key.ml_dsa_65.len() != 1952 {
        return Err(format!(
            "ML-DSA-65 public key wrong length: {}",
            pub_key.ml_dsa_65.len()
        ));
    }
    if sig.ed25519.len() != 64 {
        return Err(format!(
            "Ed25519 signature wrong length: {}",
            sig.ed25519.len()
        ));
    }
    if sig.ml_dsa_65.len() != 3309 {
        return Err(format!(
            "ML-DSA-65 signature wrong length: {}",
            sig.ml_dsa_65.len()
        ));
    }

    let mut ed_pk_bytes = [0u8; 32];
    ed_pk_bytes.copy_from_slice(&pub_key.ed25519);
    let ed_pk = VerifyingKey::from_bytes(&ed_pk_bytes)
        .map_err(|_| "Ed25519 public key invalid".to_string())?;
    let ed_sig = EdSignature::from_slice(&sig.ed25519)
        .map_err(|_| "Ed25519 signature invalid".to_string())?;
    ed_pk
        .verify(msg, &ed_sig)
        .map_err(|_| "Ed25519 signature invalid".to_string())?;

    let mut ml_pk_bytes = [0u8; ml_dsa_65::PK_LEN];
    ml_pk_bytes.copy_from_slice(&pub_key.ml_dsa_65);
    let ml_pk = ml_dsa_65::PublicKey::try_from_bytes(ml_pk_bytes)
        .map_err(|_| "ML-DSA-65 public key malformed".to_string())?;
    let mut ml_sig_bytes = [0u8; ml_dsa_65::SIG_LEN];
    ml_sig_bytes.copy_from_slice(&sig.ml_dsa_65);
    if !ml_pk.verify(msg, &ml_sig_bytes, &[]) {
        return Err("ML-DSA-65 signature invalid".to_string());
    }

    Ok(())
}

// ----------------------------------------------------------------------
// High-level sign/verify helpers
// ----------------------------------------------------------------------

pub fn issue_delegation(cert: &mut DelegationCert, issuer_priv: &HybridPrivateKey) {
    cert.signature = sign_both(&delegation_sign_bytes(cert), issuer_priv);
}

pub fn verify_delegation_signature(cert: &DelegationCert) -> bool {
    verify_delegation_signature_e(cert).is_ok()
}

pub fn verify_delegation_signature_e(cert: &DelegationCert) -> Result<(), String> {
    verify_both(
        &delegation_sign_bytes(cert),
        &cert.signature,
        &cert.issuer_pub_key,
    )
}

pub fn sign_challenge(challenge: &[u8], ts: i64, agent_priv: &HybridPrivateKey) -> HybridSignature {
    sign_challenge_with_session_context(challenge, ts, &[], agent_priv)
}

pub fn sign_challenge_with_session_context(
    challenge: &[u8],
    ts: i64,
    session_context: &[u8],
    agent_priv: &HybridPrivateKey,
) -> HybridSignature {
    assert!(
        session_context.is_empty() || session_context.len() == 32,
        "session_context must be 32 bytes"
    );
    sign_both(
        &challenge_sign_bytes_with_session_context(challenge, ts, session_context),
        agent_priv,
    )
}

pub fn sign_challenge_with_stream(
    challenge: &[u8],
    ts: i64,
    session_context: &[u8],
    stream_id: &[u8],
    stream_seq: i64,
    agent_priv: &HybridPrivateKey,
) -> HybridSignature {
    assert!(
        session_context.is_empty() || session_context.len() == 32,
        "session_context must be 32 bytes"
    );
    assert_eq!(stream_id.len(), 32, "stream_id must be 32 bytes");
    assert!(stream_seq >= 1, "stream_seq must be >=1");
    sign_both(
        &challenge_sign_bytes_with_stream(challenge, ts, session_context, stream_id, stream_seq),
        agent_priv,
    )
}

pub fn verify_challenge_signature(
    challenge: &[u8],
    ts: i64,
    sig: &HybridSignature,
    agent_pub: &HybridPublicKey,
) -> Result<(), String> {
    verify_challenge_signature_with_stream(challenge, ts, &[], &[], 0, sig, agent_pub)
}

pub fn verify_challenge_signature_with_session_context(
    challenge: &[u8],
    ts: i64,
    session_context: &[u8],
    sig: &HybridSignature,
    agent_pub: &HybridPublicKey,
) -> Result<(), String> {
    verify_challenge_signature_with_stream(challenge, ts, session_context, &[], 0, sig, agent_pub)
}

pub fn verify_challenge_signature_with_stream(
    challenge: &[u8],
    ts: i64,
    session_context: &[u8],
    stream_id: &[u8],
    stream_seq: i64,
    sig: &HybridSignature,
    agent_pub: &HybridPublicKey,
) -> Result<(), String> {
    if !session_context.is_empty() && session_context.len() != 32 {
        return Err(format!(
            "session_context must be 32 bytes, got {}",
            session_context.len()
        ));
    }
    if !stream_id.is_empty() && stream_id.len() != 32 {
        return Err(format!(
            "stream_id must be 32 bytes, got {}",
            stream_id.len()
        ));
    }
    if !stream_id.is_empty() && stream_seq < 1 {
        return Err(format!("stream_seq must be >=1, got {}", stream_seq));
    }
    verify_both(
        &challenge_sign_bytes_with_stream(challenge, ts, session_context, stream_id, stream_seq),
        sig,
        agent_pub,
    )
}

pub fn issue_revocation_list(list: &mut RevocationList, issuer_priv: &HybridPrivateKey) {
    list.signature = sign_both(&revocation_sign_bytes(list), issuer_priv);
}

pub fn verify_revocation_list(list: &RevocationList, issuer_pub: &HybridPublicKey) -> bool {
    verify_both(&revocation_sign_bytes(list), &list.signature, issuer_pub).is_ok()
}

/// Canonical bytes signed to produce RevocationPush.signature.
pub fn revocation_push_sign_bytes(push: &RevocationPush) -> Vec<u8> {
    let signable = json!({
        "entries": push.entries,
        "issuer_id": push.issuer_id,
        "pushed_at": push.pushed_at,
        "seq_no": push.seq_no,
    });
    canonical_json(&signable)
}

pub fn issue_revocation_push(push: &mut RevocationPush, issuer_priv: &HybridPrivateKey) {
    push.signature = sign_both(&revocation_push_sign_bytes(push), issuer_priv);
}

pub fn verify_revocation_push(push: &RevocationPush, issuer_pub: &HybridPublicKey) -> bool {
    verify_both(
        &revocation_push_sign_bytes(push),
        &push.signature,
        issuer_pub,
    )
    .is_ok()
}

/// Canonical bytes signed to produce WitnessEntry.signature.
pub fn witness_entry_sign_bytes(entry: &WitnessEntry) -> Vec<u8> {
    let signable = json!({
        "entry_data": crate::canonical::base64_std_encode(&entry.entry_data),
        "prev_hash": crate::canonical::base64_std_encode(&entry.prev_hash),
        "timestamp": entry.timestamp,
        "witness_id": entry.witness_id,
    });
    canonical_json(&signable)
}

pub fn issue_witness_entry(entry: &mut WitnessEntry, witness_priv: &HybridPrivateKey) {
    entry.signature = sign_both(&witness_entry_sign_bytes(entry), witness_priv);
}

pub fn verify_witness_entry(entry: &WitnessEntry, witness_pub: &HybridPublicKey) -> bool {
    verify_both(
        &witness_entry_sign_bytes(entry),
        &entry.signature,
        witness_pub,
    )
    .is_ok()
}

pub fn issue_key_rotation_statement(
    stmt: &mut KeyRotationStatement,
    old_priv: &HybridPrivateKey,
    new_priv: &HybridPrivateKey,
) {
    let bytes = key_rotation_sign_bytes(stmt);
    stmt.signature_old = sign_both(&bytes, old_priv);
    stmt.signature_new = sign_both(&bytes, new_priv);
}

pub fn verify_key_rotation_statement(stmt: &KeyRotationStatement) -> Result<(), String> {
    if stmt.version != 1 {
        return Err(format!(
            "version_mismatch: unsupported version {}",
            stmt.version
        ));
    }
    if stmt.old_id != derive_id(&stmt.old_pub_key) {
        return Err("old_id does not match old_pub_key".to_string());
    }
    if stmt.new_id != derive_id(&stmt.new_pub_key) {
        return Err("new_id does not match new_pub_key".to_string());
    }
    if stmt.old_id == stmt.new_id {
        return Err("old_id and new_id must differ".to_string());
    }
    if !is_key_rotation_reason_known(&stmt.reason) {
        return Err(format!("unknown key rotation reason: {}", stmt.reason));
    }
    let bytes = key_rotation_sign_bytes(stmt);
    verify_both(&bytes, &stmt.signature_old, &stmt.old_pub_key)
        .map_err(|e| format!("old signature invalid: {}", e))?;
    verify_both(&bytes, &stmt.signature_new, &stmt.new_pub_key)
        .map_err(|e| format!("new signature invalid: {}", e))?;
    Ok(())
}

fn is_key_rotation_reason_known(reason: &str) -> bool {
    matches!(
        reason,
        "routine" | "compromise_suspected" | "device_lost" | "recovery" | "other"
    )
}

/// 32 cryptographically random bytes from OS RNG.
pub fn generate_challenge() -> Vec<u8> {
    use rand_core::{OsRng, RngCore};
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b.to_vec()
}

// ----------------------------------------------------------------------
// v1.1 transaction receipts
// ----------------------------------------------------------------------

/// Canonical bytes that every party signs to bind a TransactionReceipt.
/// Parties are sorted lex by party_id.
pub fn transaction_receipt_sign_bytes(receipt: &TransactionReceipt) -> Vec<u8> {
    let mut parties: Vec<serde_json::Value> = receipt
        .parties
        .iter()
        .map(|p| {
            json!({
                "agent_id": p.agent_id,
                "agent_pub_key": {
                    "ed25519": crate::canonical::base64_std_encode(&p.agent_pub_key.ed25519),
                    "ml_dsa_65": crate::canonical::base64_std_encode(&p.agent_pub_key.ml_dsa_65),
                },
                "party_id": p.party_id,
                "role": p.role,
            })
        })
        .collect();
    parties.sort_by(|a, b| {
        let a_id = a["party_id"].as_str().unwrap_or("");
        let b_id = b["party_id"].as_str().unwrap_or("");
        a_id.cmp(b_id)
    });
    let signable = json!({
        "created_at": receipt.created_at,
        "parties": parties,
        "terms_canonical_json": crate::canonical::base64_std_encode(&receipt.terms_canonical_json),
        "terms_schema_uri": receipt.terms_schema_uri,
        "transaction_id": receipt.transaction_id,
        "version": receipt.version,
    });
    canonical_json(&signable)
}

/// Produce a party's hybrid signature over the receipt's canonical signable.
pub fn sign_transaction_receipt_party(
    receipt: &TransactionReceipt,
    party_id: &str,
    agent_priv: &HybridPrivateKey,
) -> ReceiptPartySignature {
    let data = transaction_receipt_sign_bytes(receipt);
    let sig = sign_both(&data, agent_priv);
    ReceiptPartySignature {
        party_id: party_id.to_string(),
        signature: sig,
    }
}

// ----------------------------------------------------------------------
// v1.1 session cert cache (ROADMAP 2.3)
// ----------------------------------------------------------------------

/// 32-byte SHA-256 of the concatenated delegation_sign_bytes of each cert.
/// Used as a stable chain identity inside SessionToken — a cert rotation
/// changes chain_hash, invalidating every token issued against the old chain.
pub fn chain_hash(chain: &[DelegationCert]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for cert in chain {
        hasher.update(delegation_sign_bytes(cert));
    }
    hasher.finalize().to_vec()
}

/// Canonical MAC-input bytes for a SessionToken. The MAC itself is excluded
/// from the signable (a MAC cannot cover itself).
pub fn session_token_sign_bytes(token: &SessionToken) -> Vec<u8> {
    let mut scope = token.granted_scope.clone();
    scope.sort();
    let signable = json!({
        "agent_id": token.agent_id,
        "agent_pub_key": {
            "ed25519": crate::canonical::base64_std_encode(&token.agent_pub_key.ed25519),
            "ml_dsa_65": crate::canonical::base64_std_encode(&token.agent_pub_key.ml_dsa_65),
        },
        "chain_hash": crate::canonical::base64_std_encode(&token.chain_hash),
        "granted_scope": scope,
        "human_id": token.human_id,
        "issued_at": token.issued_at,
        "session_id": token.session_id,
        "valid_until": token.valid_until,
        "version": token.version,
    });
    canonical_json(&signable)
}

/// Issue a SessionToken from a previously verified bundle's result. Callers
/// MUST only invoke this after verify_bundle returned valid=true.
pub fn issue_session_token(
    bundle: &ProofBundle,
    result: &VerifyResult,
    session_id: &str,
    issued_at: i64,
    valid_until: i64,
    session_secret: &[u8],
) -> Result<SessionToken, String> {
    if session_secret.is_empty() {
        return Err("session_secret must not be empty".to_string());
    }
    if session_id.is_empty() {
        return Err("session_id must not be empty".to_string());
    }
    if valid_until <= issued_at {
        return Err("valid_until must be strictly after issued_at".to_string());
    }
    let mut scope = result.granted_scope.clone();
    scope.sort();
    let mut token = SessionToken {
        version: 1,
        session_id: session_id.to_string(),
        agent_id: result.agent_id.clone(),
        agent_pub_key: bundle.agent_pub_key.clone(),
        human_id: result.human_id.clone(),
        granted_scope: scope,
        issued_at,
        valid_until,
        chain_hash: chain_hash(&bundle.delegations),
        mac: Vec::new(),
    };
    let signable = session_token_sign_bytes(&token);
    let mut mac =
        HmacSha256::new_from_slice(session_secret).map_err(|e| format!("init HMAC: {}", e))?;
    mac.update(&signable);
    token.mac = mac.finalize().into_bytes().to_vec();
    Ok(token)
}

/// Check a SessionToken's HMAC against session_secret and its validity
/// window against `now` (unix seconds). Returns Ok on success.
pub fn verify_session_token_e(
    token: &SessionToken,
    session_secret: &[u8],
    now: i64,
) -> Result<(), String> {
    if session_secret.is_empty() {
        return Err("session_secret must not be empty".to_string());
    }
    if token.version != 1 {
        return Err(format!(
            "version_mismatch: unsupported version {}",
            token.version
        ));
    }
    if token.chain_hash.len() != 32 {
        return Err(format!(
            "chain_hash must be 32 bytes, got {}",
            token.chain_hash.len()
        ));
    }
    if token.mac.len() != 32 {
        return Err(format!("mac must be 32 bytes, got {}", token.mac.len()));
    }
    let mut mac =
        HmacSha256::new_from_slice(session_secret).map_err(|e| format!("init HMAC: {}", e))?;
    mac.update(&session_token_sign_bytes(token));
    mac.verify_slice(&token.mac)
        .map_err(|_| "session_token MAC invalid".to_string())?;
    if now < token.issued_at {
        return Err("session_token not yet valid".to_string());
    }
    if now > token.valid_until {
        return Err("session_token expired".to_string());
    }
    Ok(())
}

pub fn verify_session_token(token: &SessionToken, session_secret: &[u8], now: i64) -> bool {
    verify_session_token_e(token, session_secret, now).is_ok()
}
