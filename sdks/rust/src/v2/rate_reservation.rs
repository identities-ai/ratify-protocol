//! Signed `max_rate` reservation batches (SPEC-v2 §5.2, §6.2). Mirrors Go
//! `rate_reservation_v2.go`.

use std::collections::{BTreeMap, BTreeSet};

use super::authorization::V2DeferredConstraint;
use super::constraints::{
    validate_v2_constraint_fields, ConstraintV2, CONSTRAINT_MAX_RATE, CONSTRAINT_RECEIVER_AUDIENCE,
};
use super::crypto::valid_v2_id;
use super::errors::{plain, V2ErrorClass, V2Result};
use super::json::parse_json;
use super::limits::V2_MAX_RATE_WINDOW_SECONDS;
use super::wire::{ProofBundleV2, MAX_SAFE};
use crate::types::MAX_IDENTIFIER_LENGTH_BYTES;

/// One issuer-scoped rolling-window counter. The effective limit is the
/// smallest signed limit for this certificate and window; duplicate
/// constraints never consume more than one slot per claim.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct V2RateReservation {
    pub issuer_id: String,
    pub cert_id: String,
    pub window_s: i64,
    pub limit: i64,
}

/// Go `signedV2RateReservationBatch`: seal every rate counter from an
/// already preflight-verified proof into the immutable challenge claim.
pub(crate) fn signed_v2_rate_reservation_batch(bundle: &ProofBundleV2) -> V2Result<Vec<V2RateReservation>> {
    let mut deferred = Vec::new();
    for (i, cert) in bundle.delegations.iter().enumerate() {
        for (j, constraint) in cert.constraints.iter().enumerate() {
            if constraint.kind != CONSTRAINT_MAX_RATE {
                continue;
            }
            let encoded = constraint.canonical_json()?;
            deferred.push(V2DeferredConstraint {
                delegation_index: i,
                constraint_index: j,
                issuer_id: cert.issuer_id.clone(),
                cert_id: cert.cert_id.clone(),
                kind: CONSTRAINT_MAX_RATE.into(),
                canonical_json: encoded,
            });
        }
    }
    build_v2_rate_reservation_batch_inner(&deferred)
}

/// Go `BuildV2RateReservationBatch`: a deterministic atomic reservation
/// request from signed `max_rate` constraints retained in the claimed proof.
/// Go returns unclassified errors; this public function reports them as
/// `malformed`.
pub fn build_v2_rate_reservation_batch(
    deferred: &[V2DeferredConstraint],
) -> V2Result<Vec<V2RateReservation>> {
    build_v2_rate_reservation_batch_inner(deferred).map_err(|e| e.classify(V2ErrorClass::Malformed))
}

pub(crate) fn build_v2_rate_reservation_batch_inner(
    deferred: &[V2DeferredConstraint],
) -> V2Result<Vec<V2RateReservation>> {
    let mut counters: BTreeMap<(String, String, i64), i64> = BTreeMap::new();
    let mut seen_positions: BTreeSet<(usize, usize)> = BTreeSet::new();
    for item in deferred {
        let position = (item.delegation_index, item.constraint_index);
        if seen_positions.contains(&position)
            || !valid_v2_id(&item.issuer_id)
            || item.cert_id.is_empty()
            || item.cert_id.len() > MAX_IDENTIFIER_LENGTH_BYTES
        {
            return plain("v2 rate constraint has invalid identity or duplicate position");
        }
        seen_positions.insert(position);
        let node = parse_json(&item.canonical_json)
            .map_err(|e| e.context("v2 rate constraint is invalid"))?;
        validate_v2_constraint_fields(&node).map_err(|e| e.context("v2 rate constraint is invalid"))?;
        let constraint = match ConstraintV2::from_node(&node) {
            Ok(c) if c.kind == item.kind => c,
            _ => return plain("v2 rate constraint has wrong type"),
        };
        match constraint.canonical_json() {
            Ok(canonical) if canonical == item.canonical_json => {}
            _ => return plain("v2 rate constraint has noncanonical fields"),
        }
        if item.kind != CONSTRAINT_MAX_RATE && item.kind != CONSTRAINT_RECEIVER_AUDIENCE {
            return plain("v2 rate batch contains an unexpected deferred constraint type");
        }
        if item.kind == CONSTRAINT_RECEIVER_AUDIENCE {
            continue;
        }
        if constraint.count <= 0
            || constraint.count > MAX_SAFE
            || constraint.window_s <= 0
            || constraint.window_s > V2_MAX_RATE_WINDOW_SECONDS
        {
            return plain("v2 rate constraint has noncanonical or invalid limits");
        }
        let key = (item.issuer_id.clone(), item.cert_id.clone(), constraint.window_s);
        let limit = constraint.count;
        counters
            .entry(key)
            .and_modify(|previous| *previous = (*previous).min(limit))
            .or_insert(limit);
    }
    // BTreeMap order is (issuer_id, cert_id, window_s) ascending, exactly the
    // Go sort (byte order of strings, then window).
    Ok(counters
        .into_iter()
        .map(|((issuer_id, cert_id, window_s), limit)| V2RateReservation {
            issuer_id,
            cert_id,
            window_s,
            limit,
        })
        .collect())
}
