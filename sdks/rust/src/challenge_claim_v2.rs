//! Protocol v2 replay identifier primitives. Storage and freshness are caller-owned.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use sha2::{Digest, Sha256, Sha384};

const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
const CLAIM_DIGEST_TAG: &[u8] = b"ratify-protocol-challenge-claim-v2\0";
const CLAIM_ID_TAG: &[u8] = b"ratify-protocol-claim-id-v2\0";

/// Return the SHA-384 replay digest for exactly 32 decoded challenge bytes.
pub fn challenge_claim_digest_v2(challenge: &[u8]) -> Result<Vec<u8>, String> {
    if challenge.len() != 32 {
        return Err("v2 challenge claim requires exactly 32 challenge bytes".to_string());
    }
    let mut hash = Sha384::new();
    hash.update(CLAIM_DIGEST_TAG);
    hash.update(challenge);
    Ok(hash.finalize().to_vec())
}

/// Bind namespace and rollback-protected epoch to one challenge.
pub fn protocol_claim_id_v2(
    namespace: &str,
    replay_epoch: u64,
    challenge: &[u8],
) -> Result<String, String> {
    validate_namespace_epoch(namespace, replay_epoch)?;
    protocol_claim_id_from_digest_v2(
        namespace,
        replay_epoch,
        &challenge_claim_digest_v2(challenge)?,
    )
}

/// Derive the same ID from a precomputed 48-byte challenge claim digest.
pub fn protocol_claim_id_from_digest_v2(
    namespace: &str,
    replay_epoch: u64,
    claim_digest: &[u8],
) -> Result<String, String> {
    validate_namespace_epoch(namespace, replay_epoch)?;
    if claim_digest.len() != 48 {
        return Err("v2 challenge claim digest must be exactly 48 bytes".to_string());
    }
    let mut hash = Sha256::new();
    hash.update(CLAIM_ID_TAG);
    hash.update((namespace.len() as u64).to_be_bytes());
    hash.update(namespace.as_bytes());
    hash.update(replay_epoch.to_be_bytes());
    hash.update(claim_digest);
    Ok(hex::encode(hash.finalize()))
}

fn validate_namespace_epoch(namespace: &str, replay_epoch: u64) -> Result<(), String> {
    if namespace.is_empty() {
        return Err("v2 verifier namespace must be non-empty valid UTF-8".to_string());
    }
    if replay_epoch > MAX_SAFE_INTEGER {
        return Err("v2 replay epoch is outside the safe integer range".to_string());
    }
    Ok(())
}
