//! Witness entries (object code 0x0006) and caller-head log verification.
//! Mirrors Go `witness_v2.go`.

use std::collections::BTreeMap;

use super::crypto::{
    key_id_v2, lower_hex, public_key_v2, sign_v2_statement, valid_v2_id, verify_v2_statement,
    V2ObjectType,
};
use super::errors::{err, plain, Classify, V2Error, V2ErrorClass, V2Result};
use super::json::{canonical, obj, parse_wire, CJ};
use super::rotation::{statement_body_digest_v2, WitnessEntryV2Result};
use super::wire::{safe, MAX_SAFE};
use crate::types::{HybridPrivateKey, HybridPublicKey, HybridSignature, MAX_PROOF_BUNDLE_BYTES};

/// One signed entry in a caller-operated v2 witness log.
#[derive(Debug, Clone)]
pub struct WitnessEntryV2 {
    pub version: i64,
    pub log_id: String,
    pub sequence: i64,
    pub prev_hash: Vec<u8>,
    pub entry_data: Vec<u8>,
    pub timestamp: i64,
    pub witness_id: String,
    pub signature: HybridSignature,
}

/// Caller-authenticated log state before an entry. `accepted_digests` holds
/// every accepted sequence's body digest for replay and fork checks.
#[derive(Debug, Clone, Default)]
pub struct WitnessV2Head {
    pub log_id: String,
    pub sequence: i64,
    pub head_hash: Vec<u8>,
    pub accepted_digests: BTreeMap<i64, Vec<u8>>,
    pub frozen: bool,
}

const FIELDS: &[&str] = &[
    "version",
    "log_id",
    "sequence",
    "prev_hash",
    "entry_data",
    "timestamp",
    "witness_id",
    "signature",
];

fn validate(e: &WitnessEntryV2, signature: bool) -> V2Result<()> {
    if e.version != 2 {
        return plain("wire v2: witness entry version must be 2");
    }
    if e.log_id.len() != 32 || !lower_hex(&e.log_id) {
        return plain("wire v2: log_id must be 32 lowercase hexadecimal characters");
    }
    if e.sequence <= 0 || e.sequence > MAX_SAFE || !safe(e.timestamp) {
        return plain("wire v2: sequence and timestamp must be safe integers");
    }
    if e.prev_hash.len() != 48 {
        return plain("wire v2: prev_hash must be 48 bytes");
    }
    if e.entry_data.len() > MAX_PROOF_BUNDLE_BYTES {
        return plain("wire v2: entry_data exceeds the witness wire size limit");
    }
    let zero = e.prev_hash.iter().all(|b| *b == 0);
    if e.sequence == 1 && !zero {
        return plain("wire v2: genesis witness entry must use a zero prev_hash");
    }
    if e.sequence > 1 && zero {
        return plain("wire v2: non-genesis witness entry must link to a prior entry");
    }
    if !valid_v2_id(&e.witness_id) {
        return plain("wire v2: witness_id must be a 64-character lowercase hexadecimal v2 key ID");
    }
    if signature && (e.signature.ed25519.len() != 64 || e.signature.ml_dsa_65.len() != 3309) {
        return plain(
            "wire v2: signature must contain 64-byte Ed25519 and 3309-byte ML-DSA-65 components",
        );
    }
    Ok(())
}

fn entry_cj(e: &WitnessEntryV2, signature: bool) -> CJ {
    let mut f = vec![
        ("entry_data", CJ::Bytes(e.entry_data.clone())),
        ("log_id", CJ::s(&e.log_id)),
        ("prev_hash", CJ::Bytes(e.prev_hash.clone())),
        ("sequence", CJ::Int(e.sequence)),
        ("timestamp", CJ::Int(e.timestamp)),
        ("version", CJ::Int(e.version)),
        ("witness_id", CJ::s(&e.witness_id)),
    ];
    if signature {
        f.push(("signature", CJ::sig(&e.signature)));
    }
    CJ::obj(f)
}

fn entry_from(o: &super::json::Obj<'_>) -> V2Result<WitnessEntryV2> {
    Ok(WitnessEntryV2 {
        version: o.i64("version")?,
        log_id: o.str("log_id")?,
        sequence: o.i64("sequence")?,
        prev_hash: o.bytes("prev_hash")?,
        entry_data: o.bytes("entry_data")?,
        timestamp: o.i64("timestamp")?,
        witness_id: o.str("witness_id")?,
        signature: o.sig("signature")?,
    })
}

pub(crate) fn validate_witness_signable_body(body: &[u8]) -> V2Result<()> {
    let names: &[&str] = &[
        "entry_data",
        "log_id",
        "prev_hash",
        "sequence",
        "timestamp",
        "version",
        "witness_id",
    ];
    let root = parse_wire(body, &[], &[])?;
    let o = obj(&root)?;
    o.require(names, &[])
        .map_err(|e| e.context("witness signable body"))?;
    o.only(names)
        .map_err(|e| e.context("witness signable body"))?;
    let e = entry_from(&o)?;
    if canonical(&entry_cj(&e, false))? != body {
        return plain("witness signable body must use RatifyCanonicalJSON");
    }
    validate(&e, false)
}

/// Canonical signable body (all fields but `signature`).
pub fn witness_entry_v2_signable_bytes(e: &WitnessEntryV2) -> V2Result<Vec<u8>> {
    validate(e, false)?;
    canonical(&entry_cj(e, false))
}

/// StatementBodyDigestV2(0x0006, signable body).
pub fn witness_entry_v2_digest(e: &WitnessEntryV2) -> V2Result<Vec<u8>> {
    statement_body_digest_v2(0x0006, &witness_entry_v2_signable_bytes(e)?)
}

/// Canonical wire bytes.
pub fn encode_witness_entry_v2(e: &WitnessEntryV2) -> V2Result<Vec<u8>> {
    validate(e, true)?;
    let wire = canonical(&entry_cj(e, true))?;
    if wire.len() > MAX_PROOF_BUNDLE_BYTES {
        return plain("wire v2: witness entry exceeds the wire size limit");
    }
    Ok(wire)
}

/// Strictly decode one canonical v2 witness entry.
pub fn decode_witness_entry_v2(data: &[u8]) -> V2Result<WitnessEntryV2> {
    (|| {
        if data.len() > MAX_PROOF_BUNDLE_BYTES {
            return plain("wire v2: witness entry exceeds the wire size limit");
        }
        let root = parse_wire(data, &[], &[])?;
        let o = obj(&root)?;
        o.require(FIELDS, &[])?;
        o.only(FIELDS)?;
        let e = entry_from(&o)?;
        validate(&e, true)?;
        match encode_witness_entry_v2(&e) {
            Ok(c) if c == data => Ok(e),
            _ => plain("wire v2: witness entry is not canonical Ratify JSON"),
        }
    })()
    .classify(V2ErrorClass::Malformed)
}

/// Sign the witness body under code 0x0006.
pub fn sign_witness_entry_v2(
    e: &WitnessEntryV2,
    witness_key: &HybridPrivateKey,
) -> V2Result<WitnessEntryV2> {
    validate(e, false)?;
    if key_id_v2(&public_key_v2(witness_key)?)? != e.witness_id {
        return plain("witness_id does not match signing key");
    }
    let body = witness_entry_v2_signable_bytes(e)?;
    let mut out = e.clone();
    out.signature = sign_v2_statement(V2ObjectType::WitnessEntry, &body, witness_key)?;
    encode_witness_entry_v2(&out)?;
    Ok(out)
}

pub(crate) fn validate_head(
    log_id: &str,
    sequence: i64,
    head_hash: &[u8],
    accepted: &BTreeMap<i64, Vec<u8>>,
) -> V2Result<()> {
    use V2ErrorClass::ConfigurationInvalid;
    if log_id.len() != 32
        || !lower_hex(log_id)
        || !(0..=MAX_SAFE).contains(&sequence)
        || head_hash.len() != 48
    {
        return err(ConfigurationInvalid, "caller log head is invalid");
    }
    let zero = head_hash.iter().all(|b| *b == 0);
    if (sequence == 0 && (!zero || !accepted.is_empty())) || (sequence > 0 && zero) {
        return err(
            ConfigurationInvalid,
            "caller log head has inconsistent genesis state",
        );
    }
    if sequence > 0 && accepted.len() as i64 != sequence {
        return err(
            ConfigurationInvalid,
            "caller log head is missing accepted sequence digests",
        );
    }
    if sequence > 0 && accepted.get(&sequence).map(Vec::as_slice) != Some(head_hash) {
        return err(
            ConfigurationInvalid,
            "caller log head hash does not match its accepted digest history",
        );
    }
    for (seq, digest) in accepted {
        if *seq <= 0 || *seq > sequence || digest.len() != 48 {
            return err(
                ConfigurationInvalid,
                "caller log head contains invalid accepted digest history",
            );
        }
    }
    Ok(())
}

/// Shared replay/fork/frozen/gap/orphan decision for witness and receipt logs.
#[allow(clippy::too_many_arguments)]
pub(crate) fn log_position(
    sequence: i64,
    previous: &[u8],
    digest: &[u8],
    head_sequence: i64,
    head_hash: &[u8],
    accepted: &BTreeMap<i64, Vec<u8>>,
    frozen: bool,
    log_id: &str,
) -> V2Result<WitnessEntryV2Result> {
    use V2ErrorClass::*;
    if sequence <= head_sequence {
        if accepted.get(&sequence).map(Vec::as_slice) == Some(digest) {
            return Ok(WitnessEntryV2Result::Replay);
        }
        return err(
            LogFork,
            format!("log fork at sequence {sequence}; caller must freeze log {log_id}"),
        );
    }
    if frozen {
        return err(LogFrozen, "log is frozen");
    }
    if sequence > head_sequence + 1 {
        return err(
            LogGap,
            format!("log sequence gap: got {sequence} after {head_sequence}"),
        );
    }
    if previous != head_hash {
        return err(LogOrphan, "entry does not link to the current head");
    }
    Ok(WitnessEntryV2Result::Appended)
}

/// Verify key identity, log position, and signature against caller state.
/// `log_fork` is authenticated fork evidence; the caller must freeze the log.
pub fn verify_witness_entry_v2(
    e: &WitnessEntryV2,
    head: &WitnessV2Head,
    witness_key: &HybridPublicKey,
) -> V2Result<WitnessEntryV2Result> {
    validate(e, true).classify(V2ErrorClass::Malformed)?;
    encode_witness_entry_v2(e).classify(V2ErrorClass::Malformed)?;
    validate_head(
        &head.log_id,
        head.sequence,
        &head.head_hash,
        &head.accepted_digests,
    )?;
    let witness_id = key_id_v2(witness_key)?;
    if e.witness_id != witness_id || e.log_id != head.log_id {
        return err(
            V2ErrorClass::LogStateMismatch,
            "witness entry key or log ID does not match caller-authenticated state",
        );
    }
    let body = witness_entry_v2_signable_bytes(e)?;
    verify_v2_statement(V2ObjectType::WitnessEntry, &body, &e.signature, witness_key)?;
    let digest = witness_entry_v2_digest(e).map_err(|x: V2Error| x)?;
    log_position(
        e.sequence,
        &e.prev_hash,
        &digest,
        head.sequence,
        &head.head_hash,
        &head.accepted_digests,
        head.frozen,
        &head.log_id,
    )
}
