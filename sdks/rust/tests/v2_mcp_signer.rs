//! Preview Verify MCP signer over the shared vectors in testvectors/v2/mcp
//! (Go `verifyclient/mcp/vectors_test.go`). The hosted service recomputes
//! every value below from the call it receives. A signer that differs in one
//! byte produces proofs the service rejects, or, worse, a proof that binds
//! something other than the call the client asked for. Every SDK runs these
//! same files.

mod v2_provider_common;

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ratify_protocol::v2::mcp::*;
use ratify_protocol::v2::{
    decode_proof_bundle_v2, key_id_v2, verify_proof_bundle_v2_signatures, V2Context,
};
use ratify_protocol::{hybrid_keypair_from_seeds, HybridPrivateKey};
use serde_json::Value;
use v2_provider_common::ProviderSigner;

/// The corpus directory this runner consumes.
const CORPUS_DIR: &str = "mcp";

/// Every file the directory must hold; a new or missing file fails here.
const FILES: &[&str] = &[
    "README.md",
    "binding.json",
    "client-config.json",
    "connect.json",
    "tool-call.json",
];

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testvectors/v2")
        .join(CORPUS_DIR)
}

fn load(name: &str) -> Value {
    let p = dir().join(name);
    serde_json::from_slice(&fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display())))
        .unwrap()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str()
        .unwrap_or_else(|| panic!("{k} is not a string"))
}

fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array()
        .unwrap_or_else(|| panic!("{k} is not an array"))
}

fn load_key(v: &Value) -> HybridPrivateKey {
    let seed = |k: &str| -> [u8; 32] { hex::decode(s(v, k)).unwrap().try_into().unwrap() };
    let (public, private) =
        hybrid_keypair_from_seeds(&seed("ed25519_seed_hex"), &seed("ml_dsa_65_seed_hex"));
    assert_eq!(
        key_id_v2(&public).unwrap(),
        s(v, "key_id_v2"),
        "fixture key ID"
    );
    private
}

/// `got` and `want` are the same proof except the hedged ML-DSA-65
/// component of challenge_sig, and both verify.
fn same_bundle(name: &str, got_b64: &str, want_b64: &str) {
    let decode = |text: &str| {
        let wire = STANDARD
            .decode(text)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let b = decode_proof_bundle_v2(&wire).unwrap_or_else(|e| panic!("{name}: {e}"));
        verify_proof_bundle_v2_signatures(&b)
            .unwrap_or_else(|e| panic!("{name}: does not verify: {e}"));
        (b, String::from_utf8(wire).unwrap())
    };
    let (got, got_wire) = decode(got_b64);
    let (want, want_wire) = decode(want_b64);
    let masked = got_wire.replacen(
        &STANDARD.encode(&got.challenge_sig.ml_dsa_65),
        &STANDARD.encode(&want.challenge_sig.ml_dsa_65),
        1,
    );
    assert!(
        masked == want_wire,
        "{name}: proof differs from the vector beyond the hedged ML-DSA-65 signature"
    );
}

#[test]
fn mcp_corpus_directory_holds_exactly_the_consumed_files() {
    let present: BTreeSet<String> = fs::read_dir(dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    let expected: BTreeSet<String> = FILES.iter().map(|f| f.to_string()).collect();
    assert_eq!(
        present, expected,
        "testvectors/v2/mcp differs from the files this runner consumes"
    );
    let readme = fs::read_to_string(dir().join("README.md")).unwrap();
    for file in FILES.iter().filter(|f| f.ends_with(".json")) {
        assert!(
            readme.contains(&format!("| `{file}`")),
            "README has no row for {file}"
        );
    }
}

#[test]
fn binding_vectors() {
    let f = load("binding.json");
    assert_eq!(s(&f, "action"), ACTION);
    assert_eq!(s(&f, "proof_meta_key"), PROOF_META_KEY);
    let tools = arr(&f, "tools");
    assert_eq!(tools.len(), TOOLS.len(), "tool table length");
    for (want, got) in tools.iter().zip(TOOLS) {
        assert_eq!(
            (s(want, "name"), s(want, "scope")),
            (got.name, got.scope),
            "tool table order"
        );
        assert_eq!(tool_scope(got.name), Some(got.scope));
    }
    assert_eq!(tool_scope("delete_everything"), None);
    let cases = arr(&f, "cases");
    assert!(!cases.is_empty());
    for c in cases {
        let name = s(c, "name");
        let canonical =
            canonical_arguments(s(c, "arguments_json")).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            canonical,
            s(c, "canonical_arguments").as_bytes(),
            "{name}: canonical"
        );
        let digest = payload_digest(&canonical);
        assert_eq!(
            payload_digest_text(&digest),
            s(c, "payload_digest"),
            "{name}: payload digest"
        );
        let req = request_hash(
            s(c, "tool"),
            s(c, "connection_id"),
            s(c, "audience"),
            &digest,
        )
        .unwrap();
        assert_eq!(
            hex::encode(&req),
            s(c, "request_hash"),
            "{name}: request hash"
        );
        let sess = session_context(
            s(c, "verifier_id"),
            s(c, "workspace_id"),
            s(c, "agent_id"),
            s(c, "connection_id"),
            s(c, "invocation_id"),
            &req,
        )
        .unwrap();
        assert_eq!(
            hex::encode(&sess),
            s(c, "session_context"),
            "{name}: session context"
        );
    }
    let invalid = arr(&f, "invalid_arguments");
    assert!(!invalid.is_empty());
    for c in invalid {
        let input = match c.get("arguments_base64").and_then(Value::as_str) {
            Some(b) if !b.is_empty() => STANDARD.decode(b).unwrap(),
            _ => s(c, "arguments_json").as_bytes().to_vec(),
        };
        assert!(
            matches!(canonical_arguments(&input), Err(McpError::InvalidArguments)),
            "{}: accepted",
            s(c, "name")
        );
    }
}

#[test]
fn client_config_vectors() {
    let f = load("client-config.json");
    for c in arr(&f, "valid") {
        let name = s(c, "name");
        let cfg =
            parse_client_config(s(c, "config_json")).unwrap_or_else(|e| panic!("{name}: {e}"));
        let e = &c["expected"];
        assert_eq!(cfg.endpoint, s(e, "endpoint"), "{name}");
        assert_eq!(cfg.audience, s(e, "audience"), "{name}");
        assert_eq!(cfg.verifier_id, s(e, "verifier_id"), "{name}");
        assert_eq!(cfg.workspace_id, s(e, "workspace_id"), "{name}");
        assert_eq!(cfg.connection_id, s(e, "connection_id"), "{name}");
        let ids: Vec<&str> = cfg.delegations.iter().map(|d| d.cert_id.as_str()).collect();
        let want: Vec<&str> = arr(e, "delegation_cert_ids")
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(ids, want, "{name}: delegations");
    }
    for c in arr(&f, "invalid") {
        assert!(
            matches!(
                parse_client_config(s(c, "config_json")),
                Err(McpError::InvalidConfig)
            ),
            "{}: accepted",
            s(c, "name")
        );
    }
}

#[test]
fn tool_call_vectors() {
    let f = load("tool-call.json");
    let cfg = parse_client_config(s(&f, "client_config_json")).unwrap();
    let agent = load_key(&f["agent_key"]);
    let wrong = load_key(&f["wrong_agent_key"]);
    let cases = arr(&f, "cases");
    assert!(!cases.is_empty());
    for c in cases {
        let name = s(c, "name");
        let call = ToolCall::new(s(c, "tool"), s(c, "arguments_json"))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            call.canonical_arguments(),
            s(c, "canonical_arguments").as_bytes(),
            "{name}: arguments"
        );
        assert_eq!(
            cfg.challenge_request(&call).unwrap(),
            s(c, "challenge_request").as_bytes(),
            "{name}: challenge request"
        );
        let now = c["now"].as_i64().unwrap();
        let ch = cfg
            .check_challenge(s(c, "tool"), s(c, "challenge_response"), now)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let env =
            sign_tool_call(&cfg, &agent, &call, &ch).unwrap_or_else(|e| panic!("{name}: {e}"));
        let want = &c["envelope"];
        assert_eq!(env.connection_id, s(want, "connection_id"), "{name}");
        assert_eq!(env.invocation_id, s(want, "invocation_id"), "{name}");
        assert_eq!(env.challenge, s(want, "challenge"), "{name}");
        same_bundle(name, &env.bundle, s(want, "bundle"));
        assert!(
            matches!(
                sign_tool_call(&cfg, &wrong, &call, &ch),
                Err(McpError::AgentNotDelegated)
            ),
            "{name}: a key the delegation does not name signed"
        );
    }
    let refused = arr(&f, "refused_challenges");
    assert!(!refused.is_empty());
    for c in refused {
        let got = cfg.check_challenge(
            s(c, "tool"),
            s(c, "challenge_response"),
            c["now"].as_i64().unwrap(),
        );
        assert!(
            matches!(got, Err(McpError::ChallengeRefused)),
            "{}: accepted",
            s(c, "name")
        );
    }
    // A challenge accepted for one tool and configuration never signs a call
    // to another tool or under another connection or verifier.
    let refused_signings = arr(&f, "refused_signings");
    assert!(!refused_signings.is_empty());
    for c in refused_signings {
        let name = s(c, "name");
        let ch = cfg
            .check_challenge(
                s(c, "checked_tool"),
                s(c, "challenge_response"),
                c["now"].as_i64().unwrap(),
            )
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let sign_cfg = match s(c, "signing_config_json") {
            "" => cfg.clone(),
            other => parse_client_config(other).unwrap_or_else(|e| panic!("{name}: {e}")),
        };
        let call = ToolCall::new(s(c, "signing_tool"), s(c, "signing_arguments_json")).unwrap();
        assert!(
            matches!(
                sign_tool_call(&sign_cfg, &agent, &call, &ch),
                Err(McpError::ChallengeRefused)
            ),
            "{name}: signed"
        );
    }
}

#[test]
fn connect_vectors() {
    let f = load("connect.json");
    assert_eq!(s(&f, "domain"), CONNECT_POSSESSION_DOMAIN);
    assert_eq!(s(&f, "token_prefix"), CONNECT_TOKEN_PREFIX);
    for c in arr(&f, "contexts") {
        let got = connect_possession_context(
            s(c, "workspace_id"),
            s(c, "receiver_id"),
            s(c, "audience"),
            s(c, "challenge_id"),
            s(c, "agent_id"),
        );
        assert_eq!(
            hex::encode(got),
            s(c, "session_context"),
            "{}: context",
            s(c, "name")
        );
    }
    let agent = load_key(&f["agent_key"]);
    let agent_id = s(&f["agent_key"], "key_id_v2");
    let proofs = arr(&f, "proofs");
    assert!(!proofs.is_empty());
    for c in proofs {
        let name = s(c, "name");
        let tok = parse_connect_token(s(c, "token")).unwrap_or_else(|e| panic!("{name}: {e}"));
        let p = &c["parsed"];
        assert_eq!(tok.challenge_id, s(p, "challenge_id"), "{name}");
        assert_eq!(STANDARD.encode(&tok.challenge), s(p, "challenge"), "{name}");
        assert_eq!(tok.issued_at, p["issued_at"].as_i64().unwrap(), "{name}");
        assert_eq!(tok.workspace_id, s(p, "workspace_id"), "{name}");
        assert_eq!(tok.receiver_id, s(p, "receiver_id"), "{name}");
        assert_eq!(tok.audience, s(p, "audience"), "{name}");
        assert_eq!(tok.verifier_id, s(p, "verifier_id"), "{name}");
        let sess = connect_possession_context(
            &tok.workspace_id,
            &tok.receiver_id,
            &tok.audience,
            &tok.challenge_id,
            agent_id,
        );
        assert_eq!(
            hex::encode(sess),
            s(c, "session_context"),
            "{name}: session context"
        );
        let proof =
            prove_possession(s(c, "token"), &agent).unwrap_or_else(|e| panic!("{name}: {e}"));
        let want = &c["expected"];
        assert_eq!(
            proof.connect_challenge_id,
            s(want, "connect_challenge_id"),
            "{name}"
        );
        same_bundle(name, &proof.possession_proof, s(want, "possession_proof"));
    }
    let invalid = arr(&f, "invalid_tokens");
    assert!(!invalid.is_empty());
    for c in invalid {
        let name = s(c, "name");
        assert!(
            matches!(
                parse_connect_token(s(c, "token")),
                Err(McpError::InvalidConnectToken)
            ),
            "{name}: accepted"
        );
        assert!(
            matches!(
                prove_possession(s(c, "token"), &agent),
                Err(McpError::InvalidConnectToken)
            ),
            "{name}: signed"
        );
    }
}

/// A challenge is issued for one tool's scope and request hash. Letting it
/// sign a call to another tool would hand the server a proof whose binding
/// the signer never checked against the challenge it accepted. The second
/// tool here has the same scope, so only the remembered tool stops it.
#[test]
fn a_challenge_signs_only_the_tool_it_was_checked_for() {
    let f = load("tool-call.json");
    let cfg = parse_client_config(s(&f, "client_config_json")).unwrap();
    let agent = load_key(&f["agent_key"]);
    let c = &arr(&f, "cases")[0];
    let ch = cfg
        .check_challenge(
            s(c, "tool"),
            s(c, "challenge_response"),
            c["now"].as_i64().unwrap(),
        )
        .unwrap();
    for other in TOOLS.iter().filter(|t| t.name != ch.tool()) {
        let call = ToolCall::new(other.name, "{}").unwrap();
        assert!(
            matches!(
                sign_tool_call(&cfg, &agent, &call, &ch),
                Err(McpError::ChallengeRefused)
            ),
            "a challenge checked for {} signed a call to {}",
            ch.tool(),
            other.name
        );
    }
}

/// The signer never signs a tool the hosted table does not name: the scope
/// it would bind is unknown, so the server could not recompute the hash.
#[test]
fn an_unknown_tool_is_refused_before_any_request() {
    assert!(matches!(
        ToolCall::new("delete_everything", "{}"),
        Err(McpError::InvalidArguments)
    ));
    assert!(matches!(
        request_hash(
            "delete_everything",
            "c",
            "https://verify.example/mcp",
            &[0; 32]
        ),
        Err(McpError::InvalidArguments)
    ));
}

/// The external-signer variants produce the same proofs as in-process
/// signing, so a key held in an HSM or KMS signs exactly what a local key
/// would.
#[test]
fn external_signer_variants_match_the_vectors() {
    let f = load("tool-call.json");
    let cfg = parse_client_config(s(&f, "client_config_json")).unwrap();
    let signer = ProviderSigner::new(&load_key(&f["agent_key"]));
    let ctx = V2Context::background();
    for c in arr(&f, "cases") {
        let name = s(c, "name");
        let call = ToolCall::new(s(c, "tool"), s(c, "arguments_json")).unwrap();
        let ch = cfg
            .check_challenge(
                s(c, "tool"),
                s(c, "challenge_response"),
                c["now"].as_i64().unwrap(),
            )
            .unwrap();
        let env = sign_tool_call_with_signer(&ctx, &cfg, &signer, &call, &ch)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        same_bundle(name, &env.bundle, s(&c["envelope"], "bundle"));
    }
    let wrong = ProviderSigner::new(&load_key(&f["wrong_agent_key"]));
    let c = &arr(&f, "cases")[0];
    let call = ToolCall::new(s(c, "tool"), s(c, "arguments_json")).unwrap();
    let ch = cfg
        .check_challenge(
            s(c, "tool"),
            s(c, "challenge_response"),
            c["now"].as_i64().unwrap(),
        )
        .unwrap();
    assert!(matches!(
        sign_tool_call_with_signer(&ctx, &cfg, &wrong, &call, &ch),
        Err(McpError::AgentNotDelegated)
    ));
    let f = load("connect.json");
    let signer = ProviderSigner::new(&load_key(&f["agent_key"]));
    for c in arr(&f, "proofs") {
        let name = s(c, "name");
        let proof = prove_possession_with_signer(&ctx, s(c, "token"), &signer)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            proof.connect_challenge_id,
            s(&c["expected"], "connect_challenge_id")
        );
        same_bundle(
            name,
            &proof.possession_proof,
            s(&c["expected"], "possession_proof"),
        );
    }
}
