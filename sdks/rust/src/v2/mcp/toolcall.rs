//! Tool-call proofs (Go `verifyclient/mcp/toolcall.go`).

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Serialize;

use super::super::context::V2Context;
use super::super::crypto::{key_id_v2, public_key_v2};
use super::super::errors::V2SignError;
use super::super::signer::SignerV2;
use super::super::wire::{
    encode_proof_bundle_v2, placeholder_signature, sign_proof_bundle_v2,
    sign_proof_bundle_v2_with_signer, DelegationCertV2, ProofBundleV2,
};
use super::config::{
    decode_std_base64, is_uuid, json_integer, json_object, json_string, ClientConfig,
};
use super::{
    canonical_arguments, payload_digest, payload_digest_text, request_hash, session_context,
    tool_scope, McpError, MIN_CHALLENGE_SECONDS_LEFT,
};
use crate::{HybridPrivateKey, HybridPublicKey};

/// One validated tool call: the tool and its canonical arguments. Send
/// [`ToolCall::canonical_arguments`] as `params.arguments` so the server
/// computes the same payload digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    tool: String,
    canonical_arguments: Vec<u8>,
    payload_digest: [u8; 32],
}

impl ToolCall {
    /// Validate the tool name and the JSON text of its arguments. An unknown
    /// tool or arguments outside the value model are
    /// [`McpError::InvalidArguments`].
    pub fn new(tool: &str, arguments: impl AsRef<[u8]>) -> Result<ToolCall, McpError> {
        if tool_scope(tool).is_none() {
            return Err(McpError::InvalidArguments);
        }
        let canonical = canonical_arguments(arguments)?;
        Ok(ToolCall {
            tool: tool.to_string(),
            payload_digest: payload_digest(&canonical),
            canonical_arguments: canonical,
        })
    }

    pub fn tool(&self) -> &str {
        &self.tool
    }

    pub fn canonical_arguments(&self) -> &[u8] {
        &self.canonical_arguments
    }

    /// SHA-256 of the canonical arguments.
    pub fn payload_digest(&self) -> &[u8; 32] {
        &self.payload_digest
    }

    /// Re-derive the payload digest from the canonical arguments, so a call
    /// whose fields disagree can never make the signer bind one argument set
    /// and send another.
    fn verified_digest(&self) -> Result<[u8; 32], McpError> {
        if tool_scope(&self.tool).is_none() || self.canonical_arguments.is_empty() {
            return Err(McpError::InvalidArguments);
        }
        let canonical = canonical_arguments(&self.canonical_arguments)?;
        let digest = payload_digest(&canonical);
        if canonical != self.canonical_arguments || digest != self.payload_digest {
            return Err(McpError::InvalidArguments);
        }
        Ok(digest)
    }
}

/// A challenge response [`ClientConfig::check_challenge`] accepted. It signs
/// only a call to the tool, and under the configuration (verifier,
/// workspace, connection), it was checked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    tool: String,
    verifier_id: String,
    workspace_id: String,
    connection_id: String,
    challenge: Vec<u8>,
    invocation_id: String,
    issued_at: i64,
    expires_at: i64,
}

impl Challenge {
    /// The tool the challenge was checked for; it signs only a call to it.
    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// The 32 challenge bytes.
    pub fn challenge(&self) -> &[u8] {
        &self.challenge
    }

    /// The server-generated invocation the proof binds.
    pub fn invocation_id(&self) -> &str {
        &self.invocation_id
    }

    /// Issue time in Unix seconds; the proof's `challenge_at`.
    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }

    /// Expiry in Unix seconds.
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

impl ClientConfig {
    /// The exact JSON body of `POST <endpoint>/challenge` for `call`:
    /// `{"connection_id":...,"tool":...,"payload_digest":"sha256:..."}`.
    /// The payload digest is re-derived from the call's canonical arguments;
    /// a call whose fields disagree is [`McpError::InvalidArguments`].
    pub fn challenge_request(&self, call: &ToolCall) -> Result<Vec<u8>, McpError> {
        let digest = call.verified_digest()?;
        #[derive(Serialize)]
        struct Body<'a> {
            connection_id: &'a str,
            tool: &'a str,
            payload_digest: String,
        }
        serde_json::to_vec(&Body {
            connection_id: &self.connection_id,
            tool: &call.tool,
            payload_digest: payload_digest_text(&digest),
        })
        .map_err(|_| McpError::InvalidArguments)
    }

    /// Accept the JSON response of `POST <endpoint>/challenge` only if
    /// `verifier_id` and `workspace_id` equal the pinned values,
    /// `required_scope` is the tool's scope, `invocation_id` is a lowercase
    /// UUID, `challenge` is 32 bytes in canonical standard base64, `issued_at`
    /// and `expires_at` are JSON integers with 0 < issued_at <= expires_at,
    /// and at least [`MIN_CHALLENGE_SECONDS_LEFT`] seconds remain at `now`
    /// (Unix seconds). The response must be valid UTF-8 JSON. Unknown
    /// response fields, including any hash the server supplies, are ignored.
    pub fn check_challenge(
        &self,
        tool: &str,
        response: impl AsRef<[u8]>,
        now: i64,
    ) -> Result<Challenge, McpError> {
        let refuse = || McpError::ChallengeRefused;
        let scope = tool_scope(tool).ok_or_else(refuse)?;
        let msg = json_object(response.as_ref()).ok_or_else(refuse)?;
        let verifier = json_string(&msg, "verifier_id").ok_or_else(refuse)?;
        let workspace = json_string(&msg, "workspace_id").ok_or_else(refuse)?;
        let got_scope = json_string(&msg, "required_scope").ok_or_else(refuse)?;
        let invocation = json_string(&msg, "invocation_id").ok_or_else(refuse)?;
        let challenge_text = json_string(&msg, "challenge").ok_or_else(refuse)?;
        let issued = json_integer(&msg, "issued_at").ok_or_else(refuse)?;
        let expires = json_integer(&msg, "expires_at").ok_or_else(refuse)?;
        if verifier != self.verifier_id
            || workspace != self.workspace_id
            || got_scope != scope
            || !is_uuid(&invocation)
        {
            return Err(refuse());
        }
        let challenge = decode_std_base64(&challenge_text)
            .filter(|c| c.len() == 32)
            .ok_or_else(refuse)?;
        // expires is in the safe range, so the subtraction cannot wrap.
        if issued <= 0 || issued > expires || now > expires - MIN_CHALLENGE_SECONDS_LEFT {
            return Err(refuse());
        }
        Ok(Challenge {
            tool: tool.to_string(),
            verifier_id: self.verifier_id.clone(),
            workspace_id: self.workspace_id.clone(),
            connection_id: self.connection_id.clone(),
            challenge,
            invocation_id: invocation,
            issued_at: issued,
            expires_at: expires,
        })
    }
}

/// The value of `params._meta["com.ratifyprotocol/proof"]` on `tools/call`.
/// `challenge` and `bundle` are standard base64; `bundle` is the SPEC-v2
/// proof bundle wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProofEnvelope {
    pub connection_id: String,
    pub invocation_id: String,
    pub challenge: String,
    pub bundle: String,
}

/// Sign the tool-call proof with an in-process agent key.
pub fn sign_tool_call(
    config: &ClientConfig,
    agent_key: &HybridPrivateKey,
    call: &ToolCall,
    challenge: &Challenge,
) -> Result<ProofEnvelope, McpError> {
    let public = local_public_key(agent_key)?;
    sign(config, &public, call, challenge, |b| {
        sign_proof_bundle_v2(b, agent_key)
    })
}

/// Sign the tool-call proof with an external signer.
pub fn sign_tool_call_with_signer(
    ctx: &V2Context,
    config: &ClientConfig,
    signer: &dyn SignerV2,
    call: &ToolCall,
    challenge: &Challenge,
) -> Result<ProofEnvelope, McpError> {
    sign(config, &signer.public_key_v2(), call, challenge, |b| {
        sign_proof_bundle_v2_with_signer(ctx, b, signer)
    })
}

pub(crate) fn local_public_key(agent_key: &HybridPrivateKey) -> Result<HybridPublicKey, McpError> {
    public_key_v2(agent_key)
        .map_err(|e| McpError::Signing(V2SignError::InvalidSignerKey(e.message)))
}

fn sign(
    config: &ClientConfig,
    public: &HybridPublicKey,
    call: &ToolCall,
    challenge: &Challenge,
    signer: impl FnOnce(&ProofBundleV2) -> Result<ProofBundleV2, V2SignError>,
) -> Result<ProofEnvelope, McpError> {
    if challenge.tool != call.tool
        || challenge.verifier_id != config.verifier_id
        || challenge.workspace_id != config.workspace_id
        || challenge.connection_id != config.connection_id
    {
        return Err(McpError::ChallengeRefused);
    }
    let Some(last) = config.delegations.last() else {
        return Err(McpError::ChallengeRefused);
    };
    let digest = call.verified_digest()?;
    let agent_id = key_id_v2(public)?;
    if last.subject_id != agent_id {
        return Err(McpError::AgentNotDelegated);
    }
    let request = request_hash(&call.tool, &config.connection_id, &config.audience, &digest)?;
    let session = session_context(
        &config.verifier_id,
        &config.workspace_id,
        &agent_id,
        &config.connection_id,
        &challenge.invocation_id,
        &request,
    )?;
    // The configuration lists the chain root side first; a SPEC-v2 bundle
    // carries it leaf first.
    let leaf_first: Vec<DelegationCertV2> = config.delegations.iter().rev().cloned().collect();
    let wire = sign_presentation(
        &config.verifier_id,
        &agent_id,
        public,
        &leaf_first,
        &challenge.challenge,
        challenge.issued_at,
        session,
        signer,
    )?;
    Ok(ProofEnvelope {
        connection_id: config.connection_id.clone(),
        invocation_id: challenge.invocation_id.clone(),
        challenge: STANDARD.encode(&challenge.challenge),
        bundle: STANDARD.encode(wire),
    })
}

/// Build the unsigned SPEC-v2 challenge presentation (no stream fields),
/// sign it with the SDK's proof-bundle signing, and encode the wire.
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_presentation(
    verifier_id: &str,
    agent_id: &str,
    public: &HybridPublicKey,
    delegations: &[DelegationCertV2],
    challenge: &[u8],
    challenge_at: i64,
    session: Vec<u8>,
    signer: impl FnOnce(&ProofBundleV2) -> Result<ProofBundleV2, V2SignError>,
) -> Result<Vec<u8>, McpError> {
    let unsigned = ProofBundleV2 {
        version: 2,
        verifier_id: verifier_id.to_string(),
        agent_id: agent_id.to_string(),
        agent_pub_key: public.clone(),
        delegations: delegations.to_vec(),
        delegation_digest: vec![0; 48],
        challenge: challenge.to_vec(),
        challenge_at,
        challenge_sig: placeholder_signature(),
        session_context: Some(session),
        stream_id: None,
        stream_seq: None,
    };
    let signed = signer(&unsigned)?;
    Ok(encode_proof_bundle_v2(&signed)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ToolCall fields are private, so a caller cannot make them disagree;
    // the signer still re-derives the digest. A call that binds one argument
    // set and sends another must never be signed or requested.
    #[test]
    fn a_tool_call_with_inconsistent_fields_is_refused() {
        let mut call = ToolCall::new("get_metrics", r#"{"limit":1}"#).unwrap();
        call.payload_digest = *ToolCall::new("get_metrics", r#"{"limit":2}"#)
            .unwrap()
            .payload_digest();
        assert!(matches!(
            call.verified_digest(),
            Err(McpError::InvalidArguments)
        ));
        call.canonical_arguments = br#"{ "limit":2}"#.to_vec();
        assert!(matches!(
            call.verified_digest(),
            Err(McpError::InvalidArguments)
        ));
        call.canonical_arguments = Vec::new();
        call.payload_digest = payload_digest(b"");
        assert!(matches!(
            call.verified_digest(),
            Err(McpError::InvalidArguments)
        ));
    }
}
