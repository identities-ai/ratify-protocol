//! The reference candidate-record trust resolver of SPEC-v2 §6.1. Mirrors Go
//! `v2reference/trust_registry.go`.

use crate::types::HybridPublicKey;
use crate::v2::context::V2Context;
use crate::v2::crypto::key_id_v2;
use crate::v2::errors::V2Result;
use crate::v2::verify::{V2ProviderError, V2TrustOutcome, V2TrustResolution};
use crate::v2::wire::DelegationCertV2;

/// The REFERENCE candidate-record trust resolver of SPEC-v2 §6.1. It holds
/// caller-authenticated root records (complete hybrid public keys) and
/// resolves a verified chain by its terminal issuer:
///
/// - a record is a candidate when its key ID equals the terminal issuer ID or
///   either of its components equals the matching component of the terminal
///   issuer key;
/// - no candidate is untrusted;
/// - more than one candidate, including the same key configured twice, is
///   ambiguous; the resolver never selects a first match;
/// - exactly one candidate is trusted with that record's complete key, which
///   the verifier then compares with the chain root (a partial match is
///   treated as ambiguous there).
///
/// TEST AND CONFORMANCE USE ONLY: it shows the fail-closed resolution rule; a
/// deployment loads its records from its own authenticated configuration.
#[derive(Debug, Clone)]
pub struct TrustRegistry {
    records: Vec<HybridPublicKey>,
    ids: Vec<String>,
}

impl TrustRegistry {
    /// A registry over the given records in order.
    pub fn new(records: &[HybridPublicKey]) -> V2Result<Self> {
        let mut ids = Vec::with_capacity(records.len());
        for (i, key) in records.iter().enumerate() {
            ids.push(
                key_id_v2(key).map_err(|e| e.context(format!("v2reference: trust record {i}")))?,
            );
        }
        Ok(TrustRegistry {
            records: records.to_vec(),
            ids,
        })
    }

    /// The `V2VerifyCallbacks::trust` provider.
    pub fn resolve(
        &self,
        _ctx: &V2Context,
        chain: &[DelegationCertV2],
    ) -> Result<V2TrustResolution, V2ProviderError> {
        let empty = || HybridPublicKey {
            ed25519: Vec::new(),
            ml_dsa_65: Vec::new(),
        };
        let Some(root) = chain.last() else {
            return Ok(V2TrustResolution {
                outcome: V2TrustOutcome::Untrusted,
                root_key: empty(),
            });
        };
        let mut matched = None;
        for (i, key) in self.records.iter().enumerate() {
            if self.ids[i] != root.issuer_id
                && key.ed25519 != root.issuer_pub_key.ed25519
                && key.ml_dsa_65 != root.issuer_pub_key.ml_dsa_65
            {
                continue;
            }
            if matched.is_some() {
                return Ok(V2TrustResolution {
                    outcome: V2TrustOutcome::Ambiguous,
                    root_key: empty(),
                });
            }
            matched = Some(i);
        }
        Ok(match matched {
            None => V2TrustResolution {
                outcome: V2TrustOutcome::Untrusted,
                root_key: empty(),
            },
            Some(i) => V2TrustResolution {
                outcome: V2TrustOutcome::Trusted,
                root_key: self.records[i].clone(),
            },
        })
    }
}
