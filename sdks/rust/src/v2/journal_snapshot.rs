//! `SecurityJournalV2` logical snapshot (SPEC-v2 §6.6). Mirrors Go
//! `security_journal_snapshot_v2.go`.
//!
//! The snapshot is the portable, canonical projection of a
//! [`SecurityJournalV2`]. Its bytes are RatifyCanonicalJSON of the object
//! below and its digest is
//!
//! ```text
//! SecurityJournalDigest = SHA-384("ratify-protocol-security-journal-v2" || 0x00 || snapshot)
//! ```
//!
//! rendered as 96 lowercase hex characters. Members are never omitted (an
//! absent value is `null`, an empty set is `[]`); `previous_digest` is 96 `0`
//! characters at genesis; histories, issuers and string sets are sorted;
//! observations keep compaction order. Version 1 records (unlabelled SHA-384
//! over Go `encoding/json`) are migrated with [`migrate_security_journal_v2`].
//!
//! A valid digest chain is not rollback protection: the head must be anchored
//! independently and advanced by atomic compare-and-swap (§7.10).

use std::cmp::Ordering;
use std::collections::BTreeSet;

use base64::{engine::general_purpose::STANDARD, Engine as _};

use super::crypto::sha384;
use super::errors::{err, plain, Classify, V2Error, V2ErrorClass, V2Result};
use super::journal::{
    canonicalize_security_journal_v2, validate_security_journal_inner,
    validate_security_journal_transition_inner, KeyRoleBindingV2, SecurityJournalHeadV2,
    SecurityJournalV2, StatusKeyBindingV2, SECURITY_JOURNAL_LEGACY_VERSION,
    SECURITY_JOURNAL_VERSION_V2,
};
use super::json::{canonical, obj, parse_json, JNode, Obj, CJ, JV};
use super::status::{sorted_unique, RevocationObservationV2, RevocationStatusStateV2};
use super::wire::{
    decode_revocation_list_v2, encode_revocation_list_v2, RevocationListV2, RevokedCertV2, MAX_SAFE,
};
use crate::types::HybridSignature;

const SECURITY_JOURNAL_DIGEST_LABEL_V2: &[u8] = b"ratify-protocol-security-journal-v2";

/// Bounds an imported snapshot.
pub const MAX_SECURITY_JOURNAL_SNAPSHOT_BYTES: usize = 64 << 20;

fn genesis_previous_digest() -> String {
    "0".repeat(96)
}

fn uint(value: u64) -> V2Result<CJ> {
    match i64::try_from(value) {
        Ok(v) => Ok(CJ::Int(v)),
        Err(_) => plain(format!(
            "canonical JSON: integer {value} outside the safe-integer range"
        )),
    }
}

/// Go `compareCompactionOrderV2`, the §6.6 compaction sort key.
pub(crate) fn compare_compaction_order(
    a: &RevocationObservationV2,
    b: &RevocationObservationV2,
) -> Ordering {
    (
        a.status_key_epoch,
        a.sequence,
        a.object_type,
        &a.revoked_set_digest,
        &a.body_digest,
    )
        .cmp(&(
            b.status_key_epoch,
            b.sequence,
            b.object_type,
            &b.revoked_set_digest,
            &b.body_digest,
        ))
}

fn observation_cj(o: &RevocationObservationV2) -> V2Result<CJ> {
    Ok(CJ::obj(vec![
        ("accepted", CJ::Bool(o.accepted)),
        ("body_digest", CJ::Bytes(o.body_digest.clone())),
        ("evidence_digest", CJ::Bytes(o.evidence_digest.clone())),
        ("fork", CJ::Bool(o.fork)),
        ("future_dated", CJ::Bool(o.future_dated)),
        ("gap", CJ::Bool(o.gap)),
        ("object_type_code", CJ::Int(i64::from(o.object_type))),
        (
            "revoked_cert_ids",
            CJ::strs(&sorted_unique(&o.revoked_cert_ids)),
        ),
        (
            "revoked_set_digest",
            CJ::Bytes(o.revoked_set_digest.clone()),
        ),
        ("sequence", CJ::Int(o.sequence)),
        ("status_key_epoch", uint(o.status_key_epoch)?),
        ("status_key_id", CJ::s(&o.status_key_id)),
    ]))
}

fn issuer_cj(issuer_id: &str, state: &RevocationStatusStateV2) -> V2Result<CJ> {
    if state.has_floor != state.accepted_snapshot.is_some() {
        return plain(format!(
            "security journal issuer {issuer_id:?} has an accepted snapshot inconsistent with its floor"
        ));
    }
    let (floor, accepted_snapshot) = match (&state.accepted_snapshot, state.has_floor) {
        (Some(list), true) => {
            let wire = encode_revocation_list_v2(list).map_err(|e| {
                e.context(format!("encode accepted snapshot for issuer {issuer_id:?}"))
            })?;
            let text = String::from_utf8(wire)
                .map_err(|_| V2Error::plain("accepted snapshot is not UTF-8"))?;
            (CJ::Int(state.floor), CJ::Raw(text))
        }
        _ => (CJ::Null, CJ::Null),
    };
    let preceding = if state.has_preceding_checkpoint {
        CJ::obj(vec![
            (
                "accepted_cert_ids",
                CJ::strs(&state.preceding_accepted_cert_ids),
            ),
            ("floor", CJ::Int(state.preceding_floor)),
        ])
    } else {
        CJ::Null
    };
    let observations = state
        .observations
        .iter()
        .map(observation_cj)
        .collect::<V2Result<Vec<_>>>()?;
    Ok(CJ::obj(vec![
        ("accepted_cert_ids", CJ::strs(&state.accepted_cert_ids)),
        ("accepted_snapshot", accepted_snapshot),
        ("deny_union_cert_ids", CJ::strs(&state.deny_union_cert_ids)),
        ("floor", floor),
        ("fork_sequence", CJ::Int(state.fork_sequence)),
        (
            "future_dated_object_observed",
            CJ::Bool(state.future_dated_object_observed),
        ),
        ("issuer_id", CJ::s(&state.issuer_id)),
        (
            "max_observed_sequence",
            CJ::Int(state.max_observed_sequence),
        ),
        ("observations", CJ::Arr(observations)),
        ("preceding_checkpoint", preceding),
        (
            "reconciliation_required",
            CJ::Bool(state.reconciliation_required),
        ),
        (
            "retired_status_key_ids",
            CJ::strs(&state.retired_status_key_ids),
        ),
        ("status_key_epoch", uint(state.status_key_epoch)?),
        ("status_key_id", CJ::s(&state.status_key_id)),
    ]))
}

/// Go `securityJournalSnapshotStructV2`: canonicalizes a private copy (the
/// caller's journal is not mutated) and projects it.
fn snapshot_cj(journal: &SecurityJournalV2) -> V2Result<CJ> {
    let mut journal = journal.clone();
    canonicalize_security_journal_v2(&mut journal);
    if journal.generation == 0 && !journal.previous_digest.is_empty() {
        return plain("security journal genesis has a predecessor");
    }
    let previous = if journal.generation == 0 {
        genesis_previous_digest()
    } else {
        journal.previous_digest.clone()
    };
    let roles = journal
        .key_role_history
        .iter()
        .map(|r| {
            CJ::obj(vec![
                ("ed25519_digest", CJ::s(&r.ed25519_digest)),
                ("key_id", CJ::s(&r.key_id)),
                ("ml_dsa_65_digest", CJ::s(&r.ml_dsa_65_digest)),
                ("role", CJ::s(&r.role)),
            ])
        })
        .collect();
    let status_keys = journal
        .status_key_history
        .iter()
        .map(|b| {
            Ok(CJ::obj(vec![
                ("ed25519_digest", CJ::s(&b.ed25519_digest)),
                ("epoch", uint(b.epoch)?),
                ("issuer_id", CJ::s(&b.issuer_id)),
                ("ml_dsa_65_digest", CJ::s(&b.ml_dsa_65_digest)),
                ("status_key_id", CJ::s(&b.status_key_id)),
            ]))
        })
        .collect::<V2Result<Vec<_>>>()?;
    let issuers = journal
        .status_by_issuer
        .iter()
        .map(|(id, state)| issuer_cj(id, state))
        .collect::<V2Result<Vec<_>>>()?;
    Ok(CJ::obj(vec![
        ("generation", uint(journal.generation)?),
        ("issuers", CJ::Arr(issuers)),
        ("key_role_history", CJ::Arr(roles)),
        ("previous_digest", CJ::Str(previous)),
        ("status_key_history", CJ::Arr(status_keys)),
        ("version", CJ::Int(i64::from(journal.version))),
    ]))
}

/// Go `securityJournalSnapshotBytesV2`: the canonical snapshot bytes of a
/// version 2 journal, without validating it.
pub(crate) fn security_journal_snapshot_bytes_v2(journal: &SecurityJournalV2) -> V2Result<Vec<u8>> {
    canonical(&snapshot_cj(journal)?)
}

/// The labelled SHA-384 digest of canonical snapshot bytes as 96 lowercase
/// hex characters.
pub fn security_journal_snapshot_digest_v2(snapshot: &[u8]) -> String {
    hex::encode(sha384(&[SECURITY_JOURNAL_DIGEST_LABEL_V2, &[0], snapshot]))
}

/// Go `securityJournalDigestV2`.
pub(crate) fn security_journal_digest_v2(journal: &SecurityJournalV2) -> V2Result<String> {
    match journal.version {
        SECURITY_JOURNAL_VERSION_V2 => Ok(security_journal_snapshot_digest_v2(
            &security_journal_snapshot_bytes_v2(journal)?,
        )),
        SECURITY_JOURNAL_LEGACY_VERSION => legacy_security_journal_digest_v1(journal),
        v => plain(format!("security journal version {v} is unsupported")),
    }
}

/// The pre-snapshot digest: unlabelled SHA-384 over Go `encoding/json` of
/// the record with an empty digest field. Retained only to validate a record
/// before migration.
fn legacy_security_journal_digest_v1(journal: &SecurityJournalV2) -> V2Result<String> {
    let mut copy = journal.clone();
    copy.digest = String::new();
    let wire = encode_security_journal_json_v2(&copy)
        .map_err(|e| e.context("encode legacy security journal"))?;
    Ok(hex::encode(sha384(&[&wire])))
}

/// Validate a version 2 journal and return its canonical snapshot bytes. The
/// journal's digest is [`security_journal_snapshot_digest_v2`] of the bytes.
pub fn export_security_journal_snapshot_v2(journal: &SecurityJournalV2) -> V2Result<Vec<u8>> {
    if journal.version != SECURITY_JOURNAL_VERSION_V2 {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            format!("only version {SECURITY_JOURNAL_VERSION_V2} security journals can be exported; migrate first"),
        );
    }
    validate_security_journal_inner(journal).classify(V2ErrorClass::ConfigurationInvalid)?;
    // Go returns this (unreachable after validation) error unclassified.
    security_journal_snapshot_bytes_v2(journal).classify(V2ErrorClass::ConfigurationInvalid)
}

fn u64_member(o: &Obj<'_>, key: &str) -> V2Result<u64> {
    u64::try_from(o.i64(key)?)
        .map_err(|_| V2Error::plain(format!("{key} must be a non-negative integer")))
}

fn bool_member(o: &Obj<'_>, key: &str) -> V2Result<bool> {
    match o.get(key).map(|n| &n.v) {
        None | Some(JV::Null) => Ok(false),
        Some(JV::Bool(b)) => Ok(*b),
        Some(_) => plain(format!("{key} must be a boolean")),
    }
}

fn objects<'a>(o: &Obj<'a>, key: &str) -> V2Result<Vec<Obj<'a>>> {
    o.array(key)?.iter().map(obj).collect()
}

/// Decode canonical snapshot bytes, check that they are exactly canonical,
/// that their digest and generation equal the independently anchored head
/// (`log_state_mismatch` otherwise), and that the record is valid. Any other
/// failure is `malformed`; there is no partial import.
pub fn import_security_journal_snapshot_v2(
    snapshot: &[u8],
    head: &SecurityJournalHeadV2,
) -> V2Result<SecurityJournalV2> {
    import_inner(snapshot, head).classify(V2ErrorClass::Malformed)
}

fn import_inner(snapshot: &[u8], head: &SecurityJournalHeadV2) -> V2Result<SecurityJournalV2> {
    if snapshot.len() > MAX_SECURITY_JOURNAL_SNAPSHOT_BYTES {
        return plain(format!(
            "security journal snapshot exceeds {MAX_SECURITY_JOURNAL_SNAPSHOT_BYTES} bytes"
        ));
    }
    if std::str::from_utf8(snapshot).is_err() {
        return plain("security journal snapshot is not UTF-8");
    }
    // Strict JSON: one value, unique keys, no trailing data.
    let root = parse_json(snapshot).map_err(|e| {
        e.context("security journal snapshot is not a single object with unique keys")
    })?;
    let o = obj(&root).map_err(|_| {
        V2Error::plain("security journal snapshot is not a single object with unique keys")
    })?;
    o.only(&[
        "generation",
        "issuers",
        "key_role_history",
        "previous_digest",
        "status_key_history",
        "version",
    ])
    .map_err(|e| e.context("decode security journal snapshot"))?;
    let version = o.u16("version")?;
    if version != SECURITY_JOURNAL_VERSION_V2 {
        return plain(format!(
            "security journal snapshot version {version} is unsupported"
        ));
    }
    let generation = u64_member(&o, "generation")?;
    let mut previous = o.str("previous_digest")?;
    if generation == 0 {
        if previous != genesis_previous_digest() {
            return plain("security journal genesis must have the all-zero predecessor");
        }
        previous = String::new();
    }
    let mut journal = SecurityJournalV2 {
        version,
        generation,
        previous_digest: previous,
        ..Default::default()
    };
    for r in objects(&o, "key_role_history")? {
        r.only(&["ed25519_digest", "key_id", "ml_dsa_65_digest", "role"])?;
        journal.key_role_history.push(KeyRoleBindingV2 {
            key_id: r.str("key_id")?,
            ed25519_digest: r.str("ed25519_digest")?,
            ml_dsa_65_digest: r.str("ml_dsa_65_digest")?,
            role: r.str("role")?,
        });
    }
    for b in objects(&o, "status_key_history")? {
        b.only(&[
            "ed25519_digest",
            "epoch",
            "issuer_id",
            "ml_dsa_65_digest",
            "status_key_id",
        ])?;
        journal.status_key_history.push(StatusKeyBindingV2 {
            issuer_id: b.str("issuer_id")?,
            epoch: u64_member(&b, "epoch")?,
            status_key_id: b.str("status_key_id")?,
            ed25519_digest: b.str("ed25519_digest")?,
            ml_dsa_65_digest: b.str("ml_dsa_65_digest")?,
        });
    }
    for p in o.array("issuers")? {
        let state = import_issuer(snapshot, p)?;
        if journal.status_by_issuer.contains_key(&state.issuer_id) {
            return plain(format!(
                "security journal snapshot repeats issuer {:?}",
                state.issuer_id
            ));
        }
        journal
            .status_by_issuer
            .insert(state.issuer_id.clone(), state);
    }
    let canonical_bytes = security_journal_snapshot_bytes_v2(&journal)?;
    if canonical_bytes != snapshot {
        return plain("security journal snapshot is not in canonical form");
    }
    journal.digest = security_journal_snapshot_digest_v2(snapshot);
    if head.generation != journal.generation || head.digest != journal.digest {
        return err(
            V2ErrorClass::LogStateMismatch,
            "security journal snapshot does not match the anchored head",
        );
    }
    validate_security_journal_inner(&journal)?;
    Ok(journal)
}

fn import_issuer(snapshot: &[u8], node: &JNode) -> V2Result<RevocationStatusStateV2> {
    let p = obj(node)?;
    p.only(&[
        "accepted_cert_ids",
        "accepted_snapshot",
        "deny_union_cert_ids",
        "floor",
        "fork_sequence",
        "future_dated_object_observed",
        "issuer_id",
        "max_observed_sequence",
        "observations",
        "preceding_checkpoint",
        "reconciliation_required",
        "retired_status_key_ids",
        "status_key_epoch",
        "status_key_id",
    ])?;
    let issuer_id = p.str("issuer_id")?;
    let mut state = RevocationStatusStateV2 {
        issuer_id: issuer_id.clone(),
        status_key_epoch: u64_member(&p, "status_key_epoch")?,
        status_key_id: p.str("status_key_id")?,
        retired_status_key_ids: p.str_array("retired_status_key_ids")?,
        accepted_cert_ids: p.str_array("accepted_cert_ids")?,
        deny_union_cert_ids: p.str_array("deny_union_cert_ids")?,
        max_observed_sequence: p.i64("max_observed_sequence")?,
        fork_sequence: p.i64("fork_sequence")?,
        reconciliation_required: bool_member(&p, "reconciliation_required")?,
        future_dated_object_observed: bool_member(&p, "future_dated_object_observed")?,
        ..Default::default()
    };
    if let Some(floor) = p.opt_i64("floor")? {
        state.has_floor = true;
        state.floor = floor;
    }
    if let Some(raw) = p.get("accepted_snapshot").filter(|n| !n.is_null()) {
        let bytes = snapshot
            .get(raw.start..raw.end)
            .ok_or_else(|| V2Error::plain("accepted snapshot span is out of range"))?;
        let list = decode_revocation_list_v2(bytes)
            .map_err(|e| e.context(format!("accepted snapshot for issuer {issuer_id:?}")))?;
        state.accepted_snapshot = Some(list);
    }
    if let Some(cp) = p.get("preceding_checkpoint").filter(|n| !n.is_null()) {
        let cp = obj(cp)?;
        cp.only(&["accepted_cert_ids", "floor"])?;
        state.has_preceding_checkpoint = true;
        state.preceding_floor = cp.i64("floor")?;
        state.preceding_accepted_cert_ids = cp.str_array("accepted_cert_ids")?;
    }
    for ob in objects(&p, "observations")? {
        ob.only(&[
            "accepted",
            "body_digest",
            "evidence_digest",
            "fork",
            "future_dated",
            "gap",
            "object_type_code",
            "revoked_cert_ids",
            "revoked_set_digest",
            "sequence",
            "status_key_epoch",
            "status_key_id",
        ])?;
        let o = RevocationObservationV2 {
            object_type: ob.u16("object_type_code")?,
            status_key_epoch: u64_member(&ob, "status_key_epoch")?,
            status_key_id: ob.str("status_key_id")?,
            sequence: ob.i64("sequence")?,
            evidence_digest: ob.bytes("evidence_digest")?,
            body_digest: ob.bytes("body_digest")?,
            revoked_set_digest: ob.bytes("revoked_set_digest")?,
            revoked_cert_ids: ob.str_array("revoked_cert_ids")?,
            future_dated: bool_member(&ob, "future_dated")?,
            fork: bool_member(&ob, "fork")?,
            gap: bool_member(&ob, "gap")?,
            accepted: bool_member(&ob, "accepted")?,
        };
        if o.evidence_digest.len() != 48
            || o.body_digest.len() != 48
            || o.revoked_set_digest.len() != 48
        {
            return plain(format!(
                "observation digest for issuer {issuer_id:?} is not 48 bytes"
            ));
        }
        state.observations.push(o);
    }
    if state
        .observations
        .windows(2)
        .any(|w| compare_compaction_order(&w[0], &w[1]) == Ordering::Greater)
    {
        return plain(format!(
            "observations for issuer {issuer_id:?} are not in compaction order"
        ));
    }
    Ok(state)
}

/// Convert a valid version 1 record (legacy Go `encoding/json` digest) into
/// its version 2 successor: the same logical content at generation + 1,
/// `previous_digest` set to the legacy digest, and the canonical snapshot
/// digest. The caller commits it with the store's anchored compare-and-swap
/// from the legacy head, like any other transition. Every failure is
/// `configuration_invalid`.
pub fn migrate_security_journal_v2(legacy: &SecurityJournalV2) -> V2Result<SecurityJournalV2> {
    if legacy.version != SECURITY_JOURNAL_LEGACY_VERSION {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            format!("security journal migration requires a version {SECURITY_JOURNAL_LEGACY_VERSION} record"),
        );
    }
    validate_security_journal_inner(legacy).classify(V2ErrorClass::ConfigurationInvalid)?;
    let mut next = legacy.clone();
    if legacy.generation >= MAX_SAFE as u64 {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            "security journal generation exhausted",
        );
    }
    next.version = SECURITY_JOURNAL_VERSION_V2;
    next.generation = legacy.generation + 1;
    next.previous_digest = legacy.digest.clone();
    // Go's canonicalization replaces every nil history with an empty one;
    // the legacy null record is meaningless for a version 2 record.
    next.legacy_null_members = BTreeSet::new();
    canonicalize_security_journal_v2(&mut next);
    // Go returns this digest error unclassified.
    next.digest = security_journal_digest_v2(&next).classify(V2ErrorClass::ConfigurationInvalid)?;
    validate_security_journal_transition_inner(legacy, &next)
        .classify(V2ErrorClass::ConfigurationInvalid)?;
    Ok(next)
}

/// Go `sameSecurityJournalContentV2`: compares two journals' logical
/// content, ignoring version, generation and digests.
pub(crate) fn same_security_journal_content_v2(
    a: &SecurityJournalV2,
    b: &SecurityJournalV2,
) -> bool {
    let normalize = |j: &SecurityJournalV2| {
        let mut j = j.clone();
        j.version = SECURITY_JOURNAL_VERSION_V2;
        j.generation = 1;
        j.previous_digest = String::new();
        security_journal_snapshot_bytes_v2(&j)
    };
    matches!((normalize(a), normalize(b)), (Ok(left), Ok(right)) if left == right)
}

// ---------------------------------------------------------------------------
// The record's Go `encoding/json` form (version 1 records).

const NUL: char = '\u{0}';

fn go_json_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

struct GoJson<'a> {
    out: String,
    nulls: &'a BTreeSet<String>,
}

impl GoJson<'_> {
    fn key(&mut self, first: bool, name: &str) {
        if !first {
            self.out.push(',');
        }
        go_json_str(name, &mut self.out);
        self.out.push(':');
    }

    fn null_or<F: FnOnce(&mut Self)>(&mut self, empty: bool, path: &str, f: F) {
        if empty && self.nulls.contains(path) {
            self.out.push_str("null");
        } else {
            f(self);
        }
    }

    fn strs(&mut self, values: &[String], path: &str) {
        self.null_or(values.is_empty(), path, |g| {
            g.out.push('[');
            for (i, v) in values.iter().enumerate() {
                if i > 0 {
                    g.out.push(',');
                }
                go_json_str(v, &mut g.out);
            }
            g.out.push(']');
        });
    }

    fn bytes(&mut self, value: &[u8], path: &str) {
        self.null_or(value.is_empty(), path, |g| {
            go_json_str(&STANDARD.encode(value), &mut g.out)
        });
    }

    fn list(&mut self, l: &RevocationListV2, path: &str) {
        self.out.push('{');
        self.key(true, "version");
        self.out.push_str(&l.version.to_string());
        self.key(false, "issuer_id");
        go_json_str(&l.issuer_id, &mut self.out);
        self.key(false, "updated_at");
        self.out.push_str(&l.updated_at.to_string());
        self.key(false, "next_update");
        self.out.push_str(&l.next_update.to_string());
        self.key(false, "sequence");
        self.out.push_str(&l.sequence.to_string());
        self.key(false, "revoked");
        self.null_or(l.revoked.is_empty(), &format!("{path}{NUL}revoked"), |g| {
            g.out.push('[');
            for (i, r) in l.revoked.iter().enumerate() {
                if i > 0 {
                    g.out.push(',');
                }
                g.out.push('{');
                g.key(true, "cert_id");
                go_json_str(&r.cert_id, &mut g.out);
                g.out.push('}');
            }
            g.out.push(']');
        });
        self.key(false, "signature");
        self.out.push('{');
        self.key(true, "ed25519");
        self.bytes(
            &l.signature.ed25519,
            &format!("{path}{NUL}signature{NUL}ed25519"),
        );
        self.key(false, "ml_dsa_65");
        self.bytes(
            &l.signature.ml_dsa_65,
            &format!("{path}{NUL}signature{NUL}ml_dsa_65"),
        );
        self.out.push('}');
        self.out.push('}');
    }

    fn observation(&mut self, o: &RevocationObservationV2, path: &str) {
        self.out.push('{');
        self.key(true, "object_type");
        self.out.push_str(&o.object_type.to_string());
        self.key(false, "status_key_epoch");
        self.out.push_str(&o.status_key_epoch.to_string());
        self.key(false, "status_key_id");
        go_json_str(&o.status_key_id, &mut self.out);
        self.key(false, "sequence");
        self.out.push_str(&o.sequence.to_string());
        self.key(false, "evidence_digest");
        self.bytes(&o.evidence_digest, &format!("{path}{NUL}evidence_digest"));
        self.key(false, "body_digest");
        self.bytes(&o.body_digest, &format!("{path}{NUL}body_digest"));
        self.key(false, "revoked_set_digest");
        self.bytes(
            &o.revoked_set_digest,
            &format!("{path}{NUL}revoked_set_digest"),
        );
        self.key(false, "revoked_cert_ids");
        self.strs(&o.revoked_cert_ids, &format!("{path}{NUL}revoked_cert_ids"));
        for (name, value) in [
            ("future_dated", o.future_dated),
            ("fork", o.fork),
            ("gap", o.gap),
            ("accepted", o.accepted),
        ] {
            self.key(false, name);
            self.out.push_str(if value { "true" } else { "false" });
        }
        self.out.push('}');
    }

    fn state(&mut self, s: &RevocationStatusStateV2, path: &str) {
        let bool_text = |b: bool| if b { "true" } else { "false" };
        self.out.push('{');
        self.key(true, "issuer_id");
        go_json_str(&s.issuer_id, &mut self.out);
        self.key(false, "status_key_epoch");
        self.out.push_str(&s.status_key_epoch.to_string());
        self.key(false, "status_key_id");
        go_json_str(&s.status_key_id, &mut self.out);
        self.key(false, "retired_status_key_ids");
        self.strs(
            &s.retired_status_key_ids,
            &format!("{path}{NUL}retired_status_key_ids"),
        );
        self.key(false, "has_floor");
        self.out.push_str(bool_text(s.has_floor));
        self.key(false, "floor");
        self.out.push_str(&s.floor.to_string());
        self.key(false, "accepted_snapshot");
        match &s.accepted_snapshot {
            None => self.out.push_str("null"),
            Some(l) => self.list(l, &format!("{path}{NUL}accepted_snapshot")),
        }
        self.key(false, "accepted_cert_ids");
        self.strs(
            &s.accepted_cert_ids,
            &format!("{path}{NUL}accepted_cert_ids"),
        );
        self.key(false, "has_preceding_checkpoint");
        self.out.push_str(bool_text(s.has_preceding_checkpoint));
        self.key(false, "preceding_floor");
        self.out.push_str(&s.preceding_floor.to_string());
        self.key(false, "preceding_accepted_cert_ids");
        self.strs(
            &s.preceding_accepted_cert_ids,
            &format!("{path}{NUL}preceding_accepted_cert_ids"),
        );
        self.key(false, "deny_union_cert_ids");
        self.strs(
            &s.deny_union_cert_ids,
            &format!("{path}{NUL}deny_union_cert_ids"),
        );
        self.key(false, "observations");
        let observations_path = format!("{path}{NUL}observations");
        self.null_or(s.observations.is_empty(), &observations_path, |g| {
            g.out.push('[');
            for (i, o) in s.observations.iter().enumerate() {
                if i > 0 {
                    g.out.push(',');
                }
                g.observation(o, &format!("{observations_path}{NUL}{i}"));
            }
            g.out.push(']');
        });
        self.key(false, "max_observed_sequence");
        self.out.push_str(&s.max_observed_sequence.to_string());
        self.key(false, "fork_sequence");
        self.out.push_str(&s.fork_sequence.to_string());
        self.key(false, "reconciliation_required");
        self.out.push_str(bool_text(s.reconciliation_required));
        self.key(false, "future_dated_object_observed");
        self.out.push_str(bool_text(s.future_dated_object_observed));
        self.out.push('}');
    }
}

/// The journal record in Go `encoding/json` form (Go `json.Marshal` of
/// `SecurityJournalV2`): struct member order, maps sorted by key, byte
/// fields as standard base64, HTML-escaped strings, and `null` for members
/// that were `null` when the record was decoded by
/// [`decode_security_journal_json_v2`]. This is the encoding the version 1
/// (alpha) digest is computed over; version 2 records use the canonical
/// snapshot instead.
pub fn encode_security_journal_json_v2(journal: &SecurityJournalV2) -> V2Result<Vec<u8>> {
    let mut g = GoJson {
        out: String::new(),
        nulls: &journal.legacy_null_members,
    };
    g.out.push('{');
    g.key(true, "version");
    g.out.push_str(&journal.version.to_string());
    g.key(false, "generation");
    g.out.push_str(&journal.generation.to_string());
    g.key(false, "previous_digest");
    go_json_str(&journal.previous_digest, &mut g.out);
    g.key(false, "digest");
    go_json_str(&journal.digest, &mut g.out);
    g.key(false, "status_by_issuer");
    g.null_or(
        journal.status_by_issuer.is_empty(),
        "status_by_issuer",
        |g| {
            g.out.push('{');
            for (i, (id, state)) in journal.status_by_issuer.iter().enumerate() {
                g.key(i == 0, id);
                g.state(state, &format!("status_by_issuer{NUL}{id}"));
            }
            g.out.push('}');
        },
    );
    g.key(false, "key_role_history");
    g.null_or(
        journal.key_role_history.is_empty(),
        "key_role_history",
        |g| {
            g.out.push('[');
            for (i, r) in journal.key_role_history.iter().enumerate() {
                if i > 0 {
                    g.out.push(',');
                }
                g.out.push('{');
                g.key(true, "key_id");
                go_json_str(&r.key_id, &mut g.out);
                g.key(false, "ed25519_digest");
                go_json_str(&r.ed25519_digest, &mut g.out);
                g.key(false, "ml_dsa_65_digest");
                go_json_str(&r.ml_dsa_65_digest, &mut g.out);
                g.key(false, "role");
                go_json_str(&r.role, &mut g.out);
                g.out.push('}');
            }
            g.out.push(']');
        },
    );
    g.key(false, "status_key_history");
    g.null_or(
        journal.status_key_history.is_empty(),
        "status_key_history",
        |g| {
            g.out.push('[');
            for (i, b) in journal.status_key_history.iter().enumerate() {
                if i > 0 {
                    g.out.push(',');
                }
                g.out.push('{');
                g.key(true, "issuer_id");
                go_json_str(&b.issuer_id, &mut g.out);
                g.key(false, "epoch");
                g.out.push_str(&b.epoch.to_string());
                g.key(false, "status_key_id");
                go_json_str(&b.status_key_id, &mut g.out);
                g.key(false, "ed25519_digest");
                go_json_str(&b.ed25519_digest, &mut g.out);
                g.key(false, "ml_dsa_65_digest");
                go_json_str(&b.ml_dsa_65_digest, &mut g.out);
                g.out.push('}');
            }
            g.out.push(']');
        },
    );
    g.out.push('}');
    Ok(g.out.into_bytes())
}

static EMPTY_FIELDS: [(String, JNode); 0] = [];

/// An object member as an object view; an absent or `null` member decodes as
/// Go's zero value, which is the empty object here.
fn member_obj<'a>(o: &Obj<'a>, key: &str) -> V2Result<Obj<'a>> {
    match o.get(key) {
        None => Ok(Obj {
            fields: &EMPTY_FIELDS,
        }),
        Some(n) => element_obj(n),
    }
}

fn element_obj(n: &JNode) -> V2Result<Obj<'_>> {
    if n.is_null() {
        Ok(Obj {
            fields: &EMPTY_FIELDS,
        })
    } else {
        obj(n)
    }
}

struct GoDecoder {
    nulls: BTreeSet<String>,
}

impl GoDecoder {
    /// Records `path` when the member is absent or `null` (Go: a nil slice,
    /// map, or byte slice, which re-encodes as `null`).
    fn mark(&mut self, o: &Obj<'_>, key: &str, path: &str) {
        if o.get(key).is_none_or(JNode::is_null) {
            self.nulls.insert(path.to_string());
        }
    }

    fn strs(&mut self, o: &Obj<'_>, key: &str, path: &str) -> V2Result<Vec<String>> {
        self.mark(o, key, path);
        o.str_array(key)
    }

    fn bytes(&mut self, o: &Obj<'_>, key: &str, path: &str) -> V2Result<Vec<u8>> {
        self.mark(o, key, path);
        o.bytes(key)
    }

    fn list(&mut self, l: &Obj<'_>, path: &str) -> V2Result<RevocationListV2> {
        self.mark(l, "revoked", &format!("{path}{NUL}revoked"));
        let revoked = l
            .array("revoked")?
            .iter()
            .map(|n| {
                Ok(RevokedCertV2 {
                    cert_id: element_obj(n)?.str("cert_id")?,
                })
            })
            .collect::<V2Result<Vec<_>>>()?;
        let sig = member_obj(l, "signature")?;
        Ok(RevocationListV2 {
            version: l.i64("version")?,
            issuer_id: l.str("issuer_id")?,
            updated_at: l.i64("updated_at")?,
            next_update: l.i64("next_update")?,
            sequence: l.i64("sequence")?,
            revoked,
            signature: HybridSignature {
                ed25519: self.bytes(
                    &sig,
                    "ed25519",
                    &format!("{path}{NUL}signature{NUL}ed25519"),
                )?,
                ml_dsa_65: self.bytes(
                    &sig,
                    "ml_dsa_65",
                    &format!("{path}{NUL}signature{NUL}ml_dsa_65"),
                )?,
            },
        })
    }

    fn observation(&mut self, ob: &Obj<'_>, path: &str) -> V2Result<RevocationObservationV2> {
        Ok(RevocationObservationV2 {
            object_type: ob.u16("object_type")?,
            status_key_epoch: u64_member(ob, "status_key_epoch")?,
            status_key_id: ob.str("status_key_id")?,
            sequence: ob.i64("sequence")?,
            evidence_digest: self.bytes(
                ob,
                "evidence_digest",
                &format!("{path}{NUL}evidence_digest"),
            )?,
            body_digest: self.bytes(ob, "body_digest", &format!("{path}{NUL}body_digest"))?,
            revoked_set_digest: self.bytes(
                ob,
                "revoked_set_digest",
                &format!("{path}{NUL}revoked_set_digest"),
            )?,
            revoked_cert_ids: self.strs(
                ob,
                "revoked_cert_ids",
                &format!("{path}{NUL}revoked_cert_ids"),
            )?,
            future_dated: bool_member(ob, "future_dated")?,
            fork: bool_member(ob, "fork")?,
            gap: bool_member(ob, "gap")?,
            accepted: bool_member(ob, "accepted")?,
        })
    }

    fn state(&mut self, s: &Obj<'_>, path: &str) -> V2Result<RevocationStatusStateV2> {
        let accepted_snapshot = match s.get("accepted_snapshot").filter(|n| !n.is_null()) {
            None => None,
            Some(n) => Some(self.list(&obj(n)?, &format!("{path}{NUL}accepted_snapshot"))?),
        };
        let observations_path = format!("{path}{NUL}observations");
        self.mark(s, "observations", &observations_path);
        let mut observations = Vec::new();
        for (i, n) in s.array("observations")?.iter().enumerate() {
            observations
                .push(self.observation(&element_obj(n)?, &format!("{observations_path}{NUL}{i}"))?);
        }
        Ok(RevocationStatusStateV2 {
            issuer_id: s.str("issuer_id")?,
            status_key_epoch: u64_member(s, "status_key_epoch")?,
            status_key_id: s.str("status_key_id")?,
            retired_status_key_ids: self.strs(
                s,
                "retired_status_key_ids",
                &format!("{path}{NUL}retired_status_key_ids"),
            )?,
            has_floor: bool_member(s, "has_floor")?,
            floor: s.i64("floor")?,
            accepted_snapshot,
            accepted_cert_ids: self.strs(
                s,
                "accepted_cert_ids",
                &format!("{path}{NUL}accepted_cert_ids"),
            )?,
            has_preceding_checkpoint: bool_member(s, "has_preceding_checkpoint")?,
            preceding_floor: s.i64("preceding_floor")?,
            preceding_accepted_cert_ids: self.strs(
                s,
                "preceding_accepted_cert_ids",
                &format!("{path}{NUL}preceding_accepted_cert_ids"),
            )?,
            deny_union_cert_ids: self.strs(
                s,
                "deny_union_cert_ids",
                &format!("{path}{NUL}deny_union_cert_ids"),
            )?,
            observations,
            max_observed_sequence: s.i64("max_observed_sequence")?,
            fork_sequence: s.i64("fork_sequence")?,
            reconciliation_required: bool_member(s, "reconciliation_required")?,
            future_dated_object_observed: bool_member(s, "future_dated_object_observed")?,
        })
    }
}

/// Decode the record's Go `encoding/json` form (Go `json.Unmarshal` into
/// `SecurityJournalV2`), as written by version 1 (alpha) deployments. As in
/// Go, unknown members are ignored and an absent or `null` member is its zero
/// value; `null` collections are remembered so that the version 1 digest
/// re-encodes them as `null`. It is stricter than Go in three ways, all fail
/// closed (`malformed`): member names match exactly (Go matches
/// case-insensitively), duplicate member names and integers outside
/// ±(2^53 − 1) are rejected, and base64 must be canonical. The result is not
/// validated; [`migrate_security_journal_v2`] validates it.
pub fn decode_security_journal_json_v2(data: &[u8]) -> V2Result<SecurityJournalV2> {
    (|| {
        let root = parse_json(data)?;
        let o = obj(&root)?;
        let mut d = GoDecoder {
            nulls: BTreeSet::new(),
        };
        let mut journal = SecurityJournalV2 {
            version: o.u16("version")?,
            generation: u64_member(&o, "generation")?,
            previous_digest: o.str("previous_digest")?,
            digest: o.str("digest")?,
            ..Default::default()
        };
        d.mark(&o, "status_by_issuer", "status_by_issuer");
        let issuers = member_obj(&o, "status_by_issuer")?;
        for (id, n) in issuers.fields {
            let state = d.state(&element_obj(n)?, &format!("status_by_issuer{NUL}{id}"))?;
            journal.status_by_issuer.insert(id.clone(), state);
        }
        d.mark(&o, "key_role_history", "key_role_history");
        for n in o.array("key_role_history")? {
            let r = element_obj(n)?;
            journal.key_role_history.push(KeyRoleBindingV2 {
                key_id: r.str("key_id")?,
                ed25519_digest: r.str("ed25519_digest")?,
                ml_dsa_65_digest: r.str("ml_dsa_65_digest")?,
                role: r.str("role")?,
            });
        }
        d.mark(&o, "status_key_history", "status_key_history");
        for n in o.array("status_key_history")? {
            let b = element_obj(n)?;
            journal.status_key_history.push(StatusKeyBindingV2 {
                issuer_id: b.str("issuer_id")?,
                epoch: u64_member(&b, "epoch")?,
                status_key_id: b.str("status_key_id")?,
                ed25519_digest: b.str("ed25519_digest")?,
                ml_dsa_65_digest: b.str("ml_dsa_65_digest")?,
            });
        }
        journal.legacy_null_members = d.nulls;
        Ok(journal)
    })()
    .classify(V2ErrorClass::Malformed)
}
