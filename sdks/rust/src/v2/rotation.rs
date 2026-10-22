//! Key rotation statements (codes 0x0004 old-key authorization and 0x0009
//! new-key proof of possession), `StatementBodyDigestV2`, and the
//! AcceptRotation journal. Mirrors Go `key_rotation_v2.go` and
//! `key_rotation_journal_v2.go`.

use super::context::V2Context;
use super::crypto::{
    equal_keys, key_id_v2, lower_hex, sha384, valid_v2_id, verify_v2_statement, V2ObjectType,
};
use super::errors::{V2SignError, V2SignResult};
use super::limits::{check_v2_wire_size, valid_v2_timestamp, MAX_KEY_ROTATION_STATEMENT_BYTES_V2};
use super::signer::{sign_v2_statement_with_signer, signer_public_key_v2, LocalSignerV2, SignerV2};
use super::errors::{err, plain, Classify, V2Error, V2ErrorClass, V2Result};
use super::json::{canonical, node_to_cj, obj, parse_wire, CJ, JV};
use super::wire::{safe, MAX_SAFE};
use crate::types::{HybridPrivateKey, HybridPublicKey, HybridSignature};

/// Outcome of a log or journal acceptance check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessEntryV2Result {
    /// The next valid entry; the caller must atomically persist the new head.
    Appended,
    /// An exact accepted body at an accepted sequence; state is unchanged.
    Replay,
}

/// Continuity proof from a caller-authenticated current key to a replacement.
#[derive(Debug, Clone)]
pub struct KeyRotationStatementV2 {
    pub version: i64,
    pub authority_id: String,
    pub recovery_epoch: i64,
    pub role: String,
    pub sequence: i64,
    pub previous_statement_hash: Vec<u8>,
    pub old_key: HybridPublicKey,
    pub new_key: HybridPublicKey,
    pub old_key_id: String,
    pub new_key_id: String,
    pub issued_at: i64,
    pub not_before: i64,
    pub old_signature: HybridSignature,
    pub new_signature: HybridSignature,
}

/// Caller-authenticated state immediately before a candidate statement.
#[derive(Debug, Clone)]
pub struct KeyRotationV2State {
    pub authority_id: String,
    pub recovery_epoch: i64,
    pub role: String,
    pub sequence: i64,
    pub head_hash: Vec<u8>,
    pub current_key: HybridPublicKey,
    /// Complete retained history for this authority, including the current key.
    pub used_key_ids: Vec<String>,
}

const ROTATION_FIELDS: &[&str] = &[
    "version",
    "authority_id",
    "recovery_epoch",
    "role",
    "sequence",
    "previous_statement_hash",
    "old_key",
    "new_key",
    "old_key_id",
    "new_key_id",
    "issued_at",
    "not_before",
    "old_signature",
    "new_signature",
];

fn valid_role(role: &str) -> bool {
    matches!(role, "organization_root" | "issuer" | "agent")
}

fn validate_statement(s: &KeyRotationStatementV2, signatures: bool) -> V2Result<()> {
    if s.version != 2 {
        return plain("wire v2: rotation version must be 2");
    }
    if s.authority_id.len() != 32 || !lower_hex(&s.authority_id) {
        return plain("wire v2: authority_id must be 32 lowercase hexadecimal characters");
    }
    if s.recovery_epoch <= 0
        || s.recovery_epoch > MAX_SAFE
        || s.sequence <= 0
        || s.sequence > MAX_SAFE
    {
        return plain("wire v2: recovery_epoch and sequence must be positive safe integers");
    }
    if !valid_v2_timestamp(s.issued_at) || !valid_v2_timestamp(s.not_before) {
        return plain("wire v2: issued_at and not_before must be safe integers");
    }
    if !valid_role(&s.role) {
        return plain("wire v2: rotation role is invalid");
    }
    if s.previous_statement_hash.len() != 48 {
        return plain("wire v2: previous_statement_hash must be 48 bytes");
    }
    let zero = s.previous_statement_hash.iter().all(|b| *b == 0);
    if s.sequence == 1 && !zero {
        return plain("wire v2: genesis rotation must use a zero previous_statement_hash");
    }
    if s.sequence > 1 && zero {
        return plain("wire v2: non-genesis rotation must link to a prior statement");
    }
    if !valid_v2_id(&s.old_key_id) || !valid_v2_id(&s.new_key_id) {
        return plain(
            "wire v2: old_key_id and new_key_id must be 64 lowercase hexadecimal characters",
        );
    }
    let old_id = key_id_v2(&s.old_key).map_err(|e| e.context("wire v2: old_key"))?;
    let new_id = key_id_v2(&s.new_key).map_err(|e| e.context("wire v2: new_key"))?;
    if old_id != s.old_key_id || new_id != s.new_key_id {
        return err(
            V2ErrorClass::KeyIdMismatch,
            "wire v2: rotation key IDs must match distinct complete keys",
        );
    }
    if old_id == new_id || equal_keys(&s.old_key, &s.new_key) {
        return plain("wire v2: rotation key IDs must match distinct complete keys");
    }
    if signatures {
        sig_len(&s.old_signature).map_err(|e| e.context("wire v2: old_signature"))?;
        sig_len(&s.new_signature).map_err(|e| e.context("wire v2: new_signature"))?;
    }
    Ok(())
}

fn sig_len(sig: &HybridSignature) -> V2Result<()> {
    if sig.ed25519.len() != 64 || sig.ml_dsa_65.len() != 3309 {
        return plain("signature must contain 64-byte Ed25519 and 3309-byte ML-DSA-65 components");
    }
    Ok(())
}

fn statement_cj(s: &KeyRotationStatementV2, signatures: bool) -> CJ {
    let mut f = vec![
        ("authority_id", CJ::s(&s.authority_id)),
        ("issued_at", CJ::Int(s.issued_at)),
        ("new_key", CJ::key(&s.new_key)),
        ("new_key_id", CJ::s(&s.new_key_id)),
        ("not_before", CJ::Int(s.not_before)),
        ("old_key", CJ::key(&s.old_key)),
        ("old_key_id", CJ::s(&s.old_key_id)),
        (
            "previous_statement_hash",
            CJ::Bytes(s.previous_statement_hash.clone()),
        ),
        ("recovery_epoch", CJ::Int(s.recovery_epoch)),
        ("role", CJ::s(&s.role)),
        ("sequence", CJ::Int(s.sequence)),
        ("version", CJ::Int(s.version)),
    ];
    if signatures {
        f.push(("old_signature", CJ::sig(&s.old_signature)));
        f.push(("new_signature", CJ::sig(&s.new_signature)));
    }
    CJ::obj(f)
}

/// Canonical signable body shared by both rotation signatures.
pub fn key_rotation_statement_v2_signable_bytes(s: &KeyRotationStatementV2) -> V2Result<Vec<u8>> {
    validate_statement(s, false)?;
    canonical(&statement_cj(s, false))
}

/// SHA-384("ratify-protocol-statement-body-v2\0" || code_be16 || body) for a
/// rotation (0x0004), witness (0x0006), or verification receipt (0x0008)
/// signable body, which is schema-validated first.
pub fn statement_body_digest_v2(object_type: u16, signable_body: &[u8]) -> V2Result<Vec<u8>> {
    if ![0x0004, 0x0006, 0x0008].contains(&object_type) {
        return err(
            V2ErrorClass::UnsupportedObjectType,
            format!("object type 0x{object_type:04x} does not use StatementBodyDigestV2"),
        );
    }
    let root = if object_type == 0x0008 {
        parse_wire(signable_body, &["previous_receipt_hash"], &["bundle_hash"])
    } else {
        parse_wire(
            signable_body,
            &[
                "previous_statement_hash",
                "delegation_digest",
                "previous_receipt_hash",
            ],
            &[],
        )
    }
    .map_err(|e| e.context("signable body"))?;
    if object_type != 0x0004 {
        if let JV::Obj(fields) = &root.v {
            for f in ["signature", "old_signature", "new_signature"] {
                if fields.iter().any(|(k, _)| k == f) {
                    return plain(format!("signable body must exclude {f:?}"));
                }
            }
        }
    }
    if canonical(&node_to_cj(&root))? != signable_body {
        return plain("signable body must use RatifyCanonicalJSON");
    }
    match object_type {
        0x0004 => validate_rotation_signable_body(signable_body)?,
        0x0006 => super::witness::validate_witness_signable_body(signable_body)?,
        _ => super::receipt::validate_receipt_signable_body(signable_body)?,
    }
    Ok(sha384(&[
        b"ratify-protocol-statement-body-v2\0",
        &object_type.to_be_bytes(),
        signable_body,
    ]))
}

fn validate_rotation_signable_body(body: &[u8]) -> V2Result<()> {
    let names: &[&str] = &ROTATION_FIELDS[..12];
    let root = parse_wire(body, &["previous_statement_hash"], &[])?;
    let o = obj(&root)?;
    o.require(names, &[])
        .map_err(|e| e.context("rotation signable body"))?;
    o.only(names)
        .map_err(|e| e.context("rotation signable body"))?;
    let s = statement_from(&o)?;
    if canonical(&statement_cj(&s, false))? != body {
        return plain("rotation signable body must use RatifyCanonicalJSON");
    }
    validate_statement(&s, false).map_err(|e| e.context("rotation signable body"))
}

/// StatementBodyDigestV2(0x0004, body); both signatures are excluded.
pub fn key_rotation_statement_v2_digest(s: &KeyRotationStatementV2) -> V2Result<Vec<u8>> {
    statement_body_digest_v2(0x0004, &key_rotation_statement_v2_signable_bytes(s)?)
}

fn statement_from(o: &super::json::Obj<'_>) -> V2Result<KeyRotationStatementV2> {
    Ok(KeyRotationStatementV2 {
        version: o.i64("version")?,
        authority_id: o.str("authority_id")?,
        recovery_epoch: o.i64("recovery_epoch")?,
        role: o.str("role")?,
        sequence: o.i64("sequence")?,
        previous_statement_hash: o.bytes("previous_statement_hash")?,
        old_key: o.pub_key("old_key")?,
        new_key: o.pub_key("new_key")?,
        old_key_id: o.str("old_key_id")?,
        new_key_id: o.str("new_key_id")?,
        issued_at: o.i64("issued_at")?,
        not_before: o.i64("not_before")?,
        old_signature: o.sig("old_signature")?,
        new_signature: o.sig("new_signature")?,
    })
}

/// Strictly decode one v2 rotation statement.
pub fn decode_key_rotation_statement_v2(data: &[u8]) -> V2Result<KeyRotationStatementV2> {
    (|| {
        check_v2_wire_size(
            data,
            "rotation statement",
            "MAX_KEY_ROTATION_STATEMENT_BYTES_V2",
            MAX_KEY_ROTATION_STATEMENT_BYTES_V2,
        )?;
        let root = parse_wire(data, &["previous_statement_hash"], &[])?;
        let o = obj(&root)?;
        o.require(ROTATION_FIELDS, &[])?;
        o.only(ROTATION_FIELDS)?;
        let s = statement_from(&o)?;
        validate_statement(&s, true)?;
        Ok(s)
    })()
    .classify(V2ErrorClass::Malformed)
}

/// Canonical wire bytes of a rotation statement.
pub fn encode_key_rotation_statement_v2(s: &KeyRotationStatementV2) -> V2Result<Vec<u8>> {
    validate_statement(s, true)?;
    canonical(&statement_cj(s, true))
}

/// Return a copy signed by the old key (0x0004) and the new key (0x0009).
pub fn sign_key_rotation_statement_v2(
    s: &KeyRotationStatementV2,
    old_key: &HybridPrivateKey,
    new_key: &HybridPrivateKey,
) -> V2SignResult<KeyRotationStatementV2> {
    sign_key_rotation_statement_v2_with_signers(
        &V2Context::background(),
        s,
        &LocalSignerV2::new(old_key)?,
        &LocalSignerV2::new(new_key)?,
    )
}

/// [`sign_key_rotation_statement_v2`] with external signers: `old_signer`
/// signs 0x0004 under the statement old key and `new_signer` signs 0x0009
/// under the statement new key.
pub fn sign_key_rotation_statement_v2_with_signers(
    ctx: &V2Context,
    s: &KeyRotationStatementV2,
    old_signer: &dyn SignerV2,
    new_signer: &dyn SignerV2,
) -> V2SignResult<KeyRotationStatementV2> {
    validate_statement(s, false).classify(V2ErrorClass::Malformed)?;
    let old_pub = signer_public_key_v2(old_signer)?;
    let new_pub = signer_public_key_v2(new_signer)?;
    if !equal_keys(&old_pub, &s.old_key) || !equal_keys(&new_pub, &s.new_key) {
        return Err(V2SignError::KeyBinding(
            "rotation signer keys do not match the statement keys".into(),
        ));
    }
    let signable = key_rotation_statement_v2_signable_bytes(s).classify(V2ErrorClass::Malformed)?;
    let mut out = s.clone();
    out.old_signature = sign_v2_statement_with_signer(
        ctx,
        V2ObjectType::KeyRotationAuthorization,
        &signable,
        old_signer,
        &old_pub,
    )?;
    out.new_signature = sign_v2_statement_with_signer(
        ctx,
        V2ObjectType::KeyRotationProofOfPossession,
        &signable,
        new_signer,
        &new_pub,
    )?;
    Ok(out)
}

/// Check signatures and linkage against caller-authenticated state. Success
/// is not acceptance: callers persist state through the journal.
pub fn verify_key_rotation_statement_v2(
    s: &KeyRotationStatementV2,
    state: &KeyRotationV2State,
    now: i64,
    future_skew: i64,
) -> V2Result<()> {
    use V2ErrorClass::*;
    validate_statement(s, true).classify(Malformed)?;
    let current_id = key_id_v2(&state.current_key).map_err(|e| {
        V2Error::new(
            ConfigurationInvalid,
            format!("caller state current key: {}", e.message),
        )
    })?;
    if state.sequence < 0
        || state.sequence >= MAX_SAFE
        || state.recovery_epoch <= 0
        || state.recovery_epoch > MAX_SAFE
        || state.head_hash.len() != 48
    {
        return err(ConfigurationInvalid, "caller rotation state is invalid");
    }
    let zero_head = state.head_hash.iter().all(|b| *b == 0);
    if state.sequence == 0 && !zero_head {
        return err(
            ConfigurationInvalid,
            "caller genesis state must have a zero head hash",
        );
    }
    if state.sequence > 0 && zero_head {
        return err(
            ConfigurationInvalid,
            "caller non-genesis state must have a linked head hash",
        );
    }
    if state.used_key_ids.is_empty() {
        return err(
            ConfigurationInvalid,
            "caller state must include retained used key IDs",
        );
    }
    for (i, id) in state.used_key_ids.iter().enumerate() {
        if !valid_v2_id(id) {
            return err(
                ConfigurationInvalid,
                "caller state contains an invalid used key ID",
            );
        }
        if state.used_key_ids[..i].contains(id) {
            return err(
                ConfigurationInvalid,
                "caller state contains duplicate used key IDs",
            );
        }
    }
    if !state.used_key_ids.contains(&current_id) {
        return err(
            ConfigurationInvalid,
            "caller used-key history does not contain the current key",
        );
    }
    if state.used_key_ids.contains(&s.new_key_id) {
        return err(
            RotationKeyReused,
            "rotation replacement key was already used by this authority",
        );
    }
    let mut skew = future_skew;
    if skew < 0 || !safe(now) || skew > MAX_SAFE {
        return err(
            ConfigurationInvalid,
            "rotation verification clock inputs are outside safe bounds",
        );
    }
    if now > MAX_SAFE - skew {
        skew = MAX_SAFE - now;
    }
    if !equal_keys(&s.old_key, &state.current_key)
        || s.authority_id != state.authority_id
        || s.recovery_epoch != state.recovery_epoch
        || s.role != state.role
        || s.sequence != state.sequence + 1
        || s.previous_statement_hash != state.head_hash
    {
        return err(
            RotationStateMismatch,
            "rotation statement does not extend the caller-authenticated authority state",
        );
    }
    if s.issued_at > now + skew || s.not_before > now + skew {
        return err(RotationFutureDated, "rotation statement is future-dated");
    }
    let signable = key_rotation_statement_v2_signable_bytes(s)?;
    verify_v2_statement(
        V2ObjectType::KeyRotationAuthorization,
        &signable,
        &s.old_signature,
        &state.current_key,
    )
    .map_err(|e| e.context("old-key rotation authorization"))?;
    verify_v2_statement(
        V2ObjectType::KeyRotationProofOfPossession,
        &signable,
        &s.new_signature,
        &s.new_key,
    )
    .map_err(|e| e.context("new-key proof of possession"))
}

/// One accepted statement in the current recovery epoch.
#[derive(Debug, Clone)]
pub struct KeyRotationV2AcceptedEntry {
    pub sequence: i64,
    pub body_digest: Vec<u8>,
    pub old_key: HybridPublicKey,
}

/// Caller-persisted continuity state for one authority.
#[derive(Debug, Clone)]
pub struct KeyRotationV2Journal {
    pub state: KeyRotationV2State,
    pub accepted: Vec<KeyRotationV2AcceptedEntry>,
    pub frozen: bool,
}

/// SPEC-v2 §5.4 initial state from a caller-authenticated genesis key.
pub fn new_key_rotation_v2_journal(
    authority_id: &str,
    recovery_epoch: i64,
    role: &str,
    genesis_key: &HybridPublicKey,
) -> V2Result<KeyRotationV2Journal> {
    let genesis_id = key_id_v2(genesis_key).classify(V2ErrorClass::ConfigurationInvalid)?;
    if authority_id.len() != 32
        || !lower_hex(authority_id)
        || recovery_epoch <= 0
        || recovery_epoch > MAX_SAFE
    {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            "rotation authority or recovery epoch is invalid",
        );
    }
    if !valid_role(role) {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            "rotation role is invalid",
        );
    }
    Ok(KeyRotationV2Journal {
        state: KeyRotationV2State {
            authority_id: authority_id.to_string(),
            recovery_epoch,
            role: role.to_string(),
            sequence: 0,
            head_hash: vec![0; 48],
            current_key: genesis_key.clone(),
            used_key_ids: vec![genesis_id],
        },
        accepted: Vec::new(),
        frozen: false,
    })
}

/// AcceptRotation (SPEC-v2 §5.4). Returns the (possibly advanced) journal
/// and the result. A validly signed different body at an accepted sequence
/// returns `rotation_fork` together with a frozen journal the caller must
/// persist; every other error leaves the journal unchanged.
pub fn accept_key_rotation_statement_v2(
    s: &KeyRotationStatementV2,
    journal: &KeyRotationV2Journal,
    now: i64,
    future_skew: i64,
) -> (KeyRotationV2Journal, V2Result<WitnessEntryV2Result>) {
    use V2ErrorClass::*;
    let unchanged = |e: V2Error| (journal.clone(), Err(e));
    if let Err(e) = validate_statement(s, true) {
        return unchanged(e.classify(Malformed));
    }
    if journal.accepted.len() as i64 != journal.state.sequence {
        return unchanged(V2Error::new(
            ConfigurationInvalid,
            "rotation journal accepted history does not match its sequence",
        ));
    }
    if journal.frozen {
        return unchanged(V2Error::new(
            RotationFrozen,
            "key rotation authority is frozen: authority requires recovery",
        ));
    }
    let state = &journal.state;
    if s.authority_id != state.authority_id
        || s.recovery_epoch != state.recovery_epoch
        || s.role != state.role
    {
        return unchanged(V2Error::new(
            RotationStateMismatch,
            "rotation statement authority, recovery epoch, or role does not match caller state",
        ));
    }
    if s.sequence <= state.sequence {
        let accepted = &journal.accepted[(s.sequence - 1) as usize];
        if accepted.sequence != s.sequence || !equal_keys(&s.old_key, &accepted.old_key) {
            return unchanged(V2Error::new(
                RotationStateMismatch,
                format!(
                    "rotation statement old key does not match the key accepted at sequence {}",
                    s.sequence
                ),
            ));
        }
        let signable = match key_rotation_statement_v2_signable_bytes(s) {
            Ok(b) => b,
            Err(e) => return unchanged(e.classify(Malformed)),
        };
        if let Err(e) = verify_v2_statement(
            V2ObjectType::KeyRotationAuthorization,
            &signable,
            &s.old_signature,
            &accepted.old_key,
        ) {
            return unchanged(e.context("old-key rotation authorization"));
        }
        if let Err(e) = verify_v2_statement(
            V2ObjectType::KeyRotationProofOfPossession,
            &signable,
            &s.new_signature,
            &s.new_key,
        ) {
            return unchanged(e.context("new-key proof of possession"));
        }
        let digest = match statement_body_digest_v2(0x0004, &signable) {
            Ok(d) => d,
            Err(e) => return unchanged(e.classify(Malformed)),
        };
        if digest == accepted.body_digest {
            return (journal.clone(), Ok(WitnessEntryV2Result::Replay));
        }
        let mut frozen = journal.clone();
        frozen.frozen = true;
        return (
            frozen,
            Err(V2Error::new(
                RotationFork,
                format!(
                    "key rotation fork at sequence {} for authority {}",
                    s.sequence, state.authority_id
                ),
            )),
        );
    }
    if let Err(e) = verify_key_rotation_statement_v2(s, state, now, future_skew) {
        return unchanged(e);
    }
    let digest = match key_rotation_statement_v2_digest(s) {
        Ok(d) => d,
        Err(e) => return unchanged(e.classify(Malformed)),
    };
    let mut next = journal.clone();
    next.accepted.push(KeyRotationV2AcceptedEntry {
        sequence: s.sequence,
        body_digest: digest.clone(),
        old_key: s.old_key.clone(),
    });
    next.state.sequence = s.sequence;
    next.state.head_hash = digest;
    next.state.current_key = s.new_key.clone();
    next.state.used_key_ids.push(s.new_key_id.clone());
    (next, Ok(WitnessEntryV2Result::Appended))
}

/// Root-authorized recovery: increase the epoch, anchor a never-used key,
/// keep the complete used-key history.
pub fn recover_key_rotation_v2(
    journal: &KeyRotationV2Journal,
    new_recovery_epoch: i64,
    new_genesis_key: &HybridPublicKey,
) -> V2Result<KeyRotationV2Journal> {
    use V2ErrorClass::RotationRecoveryInvalid;
    let new_id =
        key_id_v2(new_genesis_key).map_err(|e| V2Error::new(RotationRecoveryInvalid, e.message))?;
    if new_recovery_epoch <= journal.state.recovery_epoch || new_recovery_epoch > MAX_SAFE {
        return err(
            RotationRecoveryInvalid,
            "rotation recovery must increase the recovery epoch",
        );
    }
    if journal.state.used_key_ids.contains(&new_id) {
        return err(
            RotationRecoveryInvalid,
            "rotation recovery cannot anchor a previously used key",
        );
    }
    let mut next = journal.clone();
    next.state.recovery_epoch = new_recovery_epoch;
    next.state.sequence = 0;
    next.state.head_hash = vec![0; 48];
    next.state.current_key = new_genesis_key.clone();
    next.state.used_key_ids.push(new_id);
    next.accepted.clear();
    next.frozen = false;
    Ok(next)
}
