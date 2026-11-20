//! The connect proof of possession (Go `verifyclient/mcp/connect.go`).

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde::Serialize;

use super::super::context::V2Context;
use super::super::crypto::key_id_v2;
use super::super::errors::V2SignError;
use super::super::signer::SignerV2;
use super::super::wire::{sign_proof_bundle_v2, sign_proof_bundle_v2_with_signer, ProofBundleV2};
use super::config::{
    decode_std_base64, is_hex64, is_uuid, json_integer, json_object, json_string, valid_endpoint,
};
use super::toolcall::{local_public_key, sign_presentation};
use super::{connect_possession_context, McpError, CONNECT_TOKEN_PREFIX, MAX_CONNECT_TOKEN_LENGTH};
use crate::{HybridPrivateKey, HybridPublicKey};

const CONNECT_TOKEN_FIELDS: [&str; 7] = [
    "audience",
    "challenge",
    "challenge_id",
    "issued_at",
    "receiver_id",
    "verifier_id",
    "workspace_id",
];

/// A parsed connect challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectToken {
    pub challenge_id: String,
    /// The 32 challenge bytes.
    pub challenge: Vec<u8>,
    pub issued_at: i64,
    pub workspace_id: String,
    pub receiver_id: String,
    pub audience: String,
    pub verifier_id: String,
}

/// Parse [`CONNECT_TOKEN_PREFIX`] followed by unpadded base64url of a JSON
/// object with exactly the fields `challenge_id`, `challenge`, `issued_at`,
/// `workspace_id`, `receiver_id`, `audience`, and `verifier_id`. IDs are
/// lowercase UUIDs, `verifier_id` is 64 lowercase hex characters,
/// `issued_at` is a positive integer, `challenge` is 32 bytes in canonical
/// standard base64, and `audience` is an endpoint (as in
/// [`super::parse_client_config`]) followed by `/mcp`. The token is at most
/// [`MAX_CONNECT_TOKEN_LENGTH`] bytes.
pub fn parse_connect_token(token: &str) -> Result<ConnectToken, McpError> {
    let refuse = || McpError::InvalidConnectToken;
    if token.len() > MAX_CONNECT_TOKEN_LENGTH {
        return Err(refuse());
    }
    let body = token
        .strip_prefix(CONNECT_TOKEN_PREFIX)
        .ok_or_else(refuse)?;
    if !body
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    {
        return Err(refuse());
    }
    let raw = URL_SAFE_NO_PAD.decode(body).map_err(|_| refuse())?;
    if URL_SAFE_NO_PAD.encode(&raw) != body {
        return Err(refuse());
    }
    let msg = json_object(&raw).ok_or_else(refuse)?;
    if msg.len() != CONNECT_TOKEN_FIELDS.len()
        || !CONNECT_TOKEN_FIELDS.iter().all(|f| msg.contains_key(*f))
    {
        return Err(refuse());
    }
    let string = |name: &str| json_string(&msg, name).ok_or_else(refuse);
    let challenge_id = string("challenge_id")?;
    let workspace_id = string("workspace_id")?;
    let receiver_id = string("receiver_id")?;
    let audience = string("audience")?;
    let verifier_id = string("verifier_id")?;
    let challenge_text = string("challenge")?;
    let issued_at = json_integer(&msg, "issued_at")
        .filter(|n| *n > 0)
        .ok_or_else(refuse)?;
    let endpoint = audience.strip_suffix("/mcp").ok_or_else(refuse)?;
    if !is_uuid(&challenge_id)
        || !is_uuid(&workspace_id)
        || !is_uuid(&receiver_id)
        || !is_hex64(&verifier_id)
        || !valid_endpoint(endpoint, &audience)
    {
        return Err(refuse());
    }
    let challenge = decode_std_base64(&challenge_text)
        .filter(|c| c.len() == 32)
        .ok_or_else(refuse)?;
    Ok(ConnectToken {
        challenge_id,
        challenge,
        issued_at,
        workspace_id,
        receiver_id,
        audience,
        verifier_id,
    })
}

/// What the connect request carries besides the certificate: the challenge
/// ID and the proof bundle wire in standard base64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PossessionProof {
    pub connect_challenge_id: String,
    pub possession_proof: String,
}

/// Sign the connect challenge with the agent key being connected: a SPEC-v2
/// proof bundle with no delegations whose challenge and `challenge_at` are
/// the token's, whose verifier is the token's, and whose session context is
/// [`connect_possession_context`]. It never contacts the network.
pub fn prove_possession(
    token: &str,
    agent_key: &HybridPrivateKey,
) -> Result<PossessionProof, McpError> {
    let t = parse_connect_token(token)?;
    let public = local_public_key(agent_key)?;
    prove(&t, &public, |b| sign_proof_bundle_v2(b, agent_key))
}

/// [`prove_possession`] with an external signer.
pub fn prove_possession_with_signer(
    ctx: &V2Context,
    token: &str,
    signer: &dyn SignerV2,
) -> Result<PossessionProof, McpError> {
    let t = parse_connect_token(token)?;
    prove(&t, &signer.public_key_v2(), |b| {
        sign_proof_bundle_v2_with_signer(ctx, b, signer)
    })
}

fn prove(
    t: &ConnectToken,
    public: &HybridPublicKey,
    signer: impl FnOnce(&ProofBundleV2) -> Result<ProofBundleV2, V2SignError>,
) -> Result<PossessionProof, McpError> {
    let agent_id = key_id_v2(public)?;
    let session = connect_possession_context(
        &t.workspace_id,
        &t.receiver_id,
        &t.audience,
        &t.challenge_id,
        &agent_id,
    );
    let wire = sign_presentation(
        &t.verifier_id,
        &agent_id,
        public,
        &[],
        &t.challenge,
        t.issued_at,
        session.to_vec(),
        signer,
    )?;
    Ok(PossessionProof {
        connect_challenge_id: t.challenge_id.clone(),
        possession_proof: STANDARD.encode(wire),
    })
}
