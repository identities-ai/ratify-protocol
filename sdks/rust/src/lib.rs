//! Ratify Protocol v1 — Rust reference SDK.
//!
//! A cryptographic trust protocol for human-agent and agent-agent interactions
//! as agents start to transact. Every signature is hybrid Ed25519 + ML-DSA-65
//! (FIPS 204): quantum-safe by design.
//!
//! See docs/EXPLAINED.md and docs/AGENT_TO_AGENT.md in the repository for
//! architecture, threat model, and agent-to-agent patterns.

pub mod canonical;
pub mod constraints;
pub mod crypto;
pub mod scope;
pub mod types;
pub mod verify;

pub use canonical::{base64_std_decode, base64_std_encode, canonical_json, hex_decode, hex_encode};
pub use crypto::{
    chain_hash, challenge_sign_bytes, challenge_sign_bytes_with_session_context,
    challenge_sign_bytes_with_stream, delegation_sign_bytes, derive_id, generate_agent,
    generate_challenge, generate_human_root, generate_hybrid_keypair, issue_delegation,
    issue_key_rotation_statement, issue_revocation_list, issue_revocation_push,
    issue_session_token, issue_witness_entry, key_rotation_sign_bytes, revocation_push_sign_bytes,
    revocation_sign_bytes, session_token_sign_bytes, sign_both, sign_challenge,
    sign_challenge_with_session_context, sign_challenge_with_stream,
    sign_transaction_receipt_party, transaction_receipt_sign_bytes, verify_both,
    verify_challenge_signature, verify_challenge_signature_with_session_context,
    verify_challenge_signature_with_stream, verify_delegation_signature,
    verify_delegation_signature_e, verify_key_rotation_statement, verify_revocation_list,
    verify_revocation_push, verify_session_token, verify_session_token_e, verify_witness_entry,
    witness_entry_sign_bytes,
};
pub use scope::{
    expand_scopes, has_scope, intersect_scopes, is_sensitive, validate_scopes, CUSTOM_SCOPE_PREFIX,
    SCOPE_COMMS_CALENDAR_READ, SCOPE_COMMS_CALENDAR_WRITE, SCOPE_COMMS_EMAIL_DELETE,
    SCOPE_COMMS_EMAIL_READ, SCOPE_COMMS_EMAIL_SEND, SCOPE_COMMS_MESSAGE_DELETE,
    SCOPE_COMMS_MESSAGE_READ, SCOPE_COMMS_MESSAGE_SEND, SCOPE_CONTRACT_READ, SCOPE_CONTRACT_SIGN,
    SCOPE_DATA_DELETE, SCOPE_DATA_EXPORT, SCOPE_DATA_READ, SCOPE_DATA_SHARE, SCOPE_DATA_WRITE,
    SCOPE_EXECUTE_CODE, SCOPE_EXECUTE_TOOL, SCOPE_FILES_READ, SCOPE_FILES_WRITE,
    SCOPE_GENERATE_CONTENT, SCOPE_GENERATE_DEEPFAKE, SCOPE_IDENTITY_DELEGATE, SCOPE_IDENTITY_PROVE,
    SCOPE_MEETING_ATTEND, SCOPE_MEETING_CHAT, SCOPE_MEETING_RECORD, SCOPE_MEETING_SHARE_SCREEN,
    SCOPE_MEETING_SPEAK, SCOPE_MEETING_VIDEO, SCOPE_PAYMENTS_AUTHORIZE, SCOPE_PAYMENTS_RECEIVE,
    SCOPE_PAYMENTS_SEND, SCOPE_TRANSACT_PURCHASE, SCOPE_TRANSACT_SELL,
};
pub use types::{
    AgentIdentity, Anchor, AuditProvider, Constraint, DelegationCert, HumanRoot, HybridPrivateKey,
    HybridPublicKey, HybridSignature, IdentityStatus, KeyRotationStatement, PolicyProvider,
    ProofBundle, ReceiptParty, ReceiptPartySignature, RevocationList, RevocationProvider,
    RevocationPush, SessionToken, StreamContext, TransactionReceipt, TransactionReceiptResult,
    VerifierContext, VerifyOptions, VerifyResult, WitnessEntry, CHALLENGE_WINDOW_SECONDS,
    ED25519_PUBLIC_KEY_SIZE, ED25519_SIGNATURE_SIZE, MAX_DELEGATION_CHAIN_DEPTH,
    MLDSA65_PUBLIC_KEY_SIZE, MLDSA65_SIGNATURE_SIZE, PROTOCOL_VERSION,
};
pub use verify::{verify_bundle, verify_streamed_turn, verify_transaction_receipt};
