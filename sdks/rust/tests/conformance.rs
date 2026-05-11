//! Conformance tests — validate the Rust SDK against the Go-generated
//! canonical test vectors. If this suite passes, the Rust implementation
//! is byte-identical to the Go reference.

use ratify_protocol::{
    base64_std_decode, challenge_sign_bytes_with_stream, delegation_sign_bytes, expand_scopes,
    hex_encode, key_rotation_sign_bytes, revocation_push_sign_bytes, revocation_sign_bytes,
    session_token_sign_bytes, transaction_receipt_sign_bytes, verify_bundle,
    verify_key_rotation_statement, verify_revocation_list, verify_revocation_push,
    verify_streamed_turn, verify_transaction_receipt, verify_witness_entry,
    witness_entry_sign_bytes, DelegationCert, HybridPublicKey, IdentityStatus,
    KeyRotationStatement, ProofBundle, RevocationList, RevocationPush, SessionToken, StreamContext,
    TransactionReceipt, VerifierContext, VerifyOptions, WitnessEntry,
};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

// Fixture schema (only the fields we actually use).

#[derive(Debug, Deserialize)]
struct Fixture {
    name: String,
    protocol_version: i32,
    kind: String,
    #[serde(default)]
    entities: Vec<FixtureEntity>,
    #[serde(default)]
    cert_chain: Vec<serde_json::Value>,
    bundle: Option<serde_json::Value>,
    key_rotation: Option<serde_json::Value>,
    revocation_list: Option<serde_json::Value>,
    revocation_push: Option<serde_json::Value>,
    witness_entry: Option<serde_json::Value>,
    session_token: Option<FixtureSessionToken>,
    transaction_receipt: Option<serde_json::Value>,
    #[serde(default)]
    timestamps: std::collections::HashMap<String, i64>,
    scope_input: Option<Vec<String>>,
    #[serde(default)]
    verifier_context: Option<FixtureVerifierContext>,
    expected: FixtureExpected,
}

#[derive(Debug, Default, Deserialize)]
struct FixtureVerifierContext {
    current_lat: Option<f64>,
    current_lon: Option<f64>,
    current_alt_m: Option<f64>,
    current_speed_mps: Option<f64>,
    requested_amount: Option<f64>,
    #[serde(default)]
    requested_currency: String,
    invocations_in_window_count: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct FixtureEntity {
    public_key: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct FixtureExpected {
    #[serde(default)]
    delegation_sign_bytes_hex: Vec<String>,
    challenge_sign_bytes_hex: Option<String>,
    verify_options: Option<FixtureVerifyOpts>,
    verify_result: Option<FixtureVerifyResult>,
    expanded_scopes: Option<Vec<String>>,
    revocation_sign_bytes_hex: Option<String>,
    key_rotation_sign_bytes_hex: Option<String>,
    key_rotation_verify_ok: Option<bool>,
    #[serde(default)]
    key_rotation_error_reason: String,
    session_token_sign_bytes_hex: Option<String>,
    session_token_mac_hex: Option<String>,
    streamed_turn: Option<FixtureStreamedTurn>,
    receipt_sign_bytes_hex: Option<String>,
    receipt_valid: Option<bool>,
    #[serde(default)]
    receipt_error_reason: String,
    revocation_push_sign_bytes_hex: Option<String>,
    revocation_push_signature_ed25519_hex: Option<String>,
    revocation_push_signature_ml_dsa_65_hex: Option<String>,
    witness_entry_sign_bytes_hex: Option<String>,
    witness_entry_signature_ed25519_hex: Option<String>,
    witness_entry_signature_ml_dsa_65_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FixtureStreamedTurn {
    valid: bool,
    identity_status: String,
    #[serde(default)]
    human_id: String,
    #[serde(default)]
    agent_id: String,
    #[serde(default)]
    granted_scope: Vec<String>,
    #[serde(default)]
    error_reason: String,
}

#[derive(Debug, Deserialize)]
struct FixtureSessionToken {
    session_secret_hex: String,
    token: serde_json::Value,
    challenge: String, // base64-standard
    challenge_at: i64,
    challenge_sig: serde_json::Value,
    verify_now: i64,
}

#[derive(Debug, Deserialize)]
struct FixtureVerifyOpts {
    #[serde(default)]
    required_scope: String,
    now: i64,
    #[serde(default)]
    session_context: String,
    #[serde(default)]
    stream: Option<FixtureStreamContext>,
}

#[derive(Debug, Deserialize)]
struct FixtureStreamContext {
    stream_id: String, // base64-standard
    #[serde(default)]
    last_seen_seq: i64,
}

#[derive(Debug, Deserialize)]
struct FixtureVerifyResult {
    valid: bool,
    identity_status: String,
    #[serde(default)]
    human_id: String,
    #[serde(default)]
    agent_id: String,
    #[serde(default)]
    granted_scope: Vec<String>,
    #[serde(default)]
    error_reason: String,
}

fn fixture_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("testvectors")
        .join("v1")
}

fn parse_cert(raw: &serde_json::Value) -> DelegationCert {
    serde_json::from_value(raw.clone()).expect("parse cert")
}

fn parse_bundle(raw: &serde_json::Value) -> ProofBundle {
    serde_json::from_value(raw.clone()).expect("parse bundle")
}

fn parse_rev(raw: &serde_json::Value) -> RevocationList {
    serde_json::from_value(raw.clone()).expect("parse revocation list")
}

fn parse_key_rotation(raw: &serde_json::Value) -> KeyRotationStatement {
    serde_json::from_value(raw.clone()).expect("parse key rotation")
}

fn parse_pub(raw: &serde_json::Value) -> HybridPublicKey {
    serde_json::from_value(raw.clone()).expect("parse hybrid pubkey")
}

fn identity_status_matches(got: &IdentityStatus, want: &str) -> bool {
    got.as_str() == want
}

fn run_verify_fixture(fx: &Fixture) {
    assert_eq!(
        fx.cert_chain.len(),
        fx.expected.delegation_sign_bytes_hex.len(),
        "cert chain len mismatch"
    );

    let chain: Vec<DelegationCert> = fx.cert_chain.iter().map(parse_cert).collect();

    // Canonical signing bytes per cert.
    for (i, cert) in chain.iter().enumerate() {
        let got = hex_encode(&delegation_sign_bytes(cert));
        let want = &fx.expected.delegation_sign_bytes_hex[i];
        assert_eq!(
            &got, want,
            "cert {} canonical sign bytes drift in fixture {}",
            i, fx.name
        );
    }

    // Challenge signing bytes.
    if let (Some(bundle_raw), Some(expected_hex)) =
        (&fx.bundle, &fx.expected.challenge_sign_bytes_hex)
    {
        let bundle = parse_bundle(bundle_raw);
        let got = hex_encode(&challenge_sign_bytes_with_stream(
            &bundle.challenge,
            bundle.challenge_at,
            &bundle.session_context,
            &bundle.stream_id,
            bundle.stream_seq,
        ));
        assert_eq!(
            &got, expected_hex,
            "challenge sign bytes drift in fixture {}",
            fx.name
        );
    }

    // Full verify.
    let (Some(bundle_raw), Some(opts_raw), Some(want)) = (
        &fx.bundle,
        &fx.expected.verify_options,
        &fx.expected.verify_result,
    ) else {
        return;
    };
    let bundle = parse_bundle(bundle_raw);

    // revocation_middle_cert: reconstruct a RevocationProvider from expected
    // result shape. Use the SPEC §17.1 interface — the legacy is_revoked
    // closure is deprecated and using it would emit a `deprecated` lint
    // warning in this test target.
    struct ConformanceRevocation {
        revoked_id: String,
    }
    impl ratify_protocol::RevocationProvider for ConformanceRevocation {
        fn is_revoked(&self, cert_id: &str) -> Result<bool, String> {
            Ok(cert_id == self.revoked_id)
        }
    }
    let revocation: Option<Box<dyn ratify_protocol::RevocationProvider>> =
        if want.identity_status == "revoked" && bundle.delegations.len() > 1 {
            let revoked_id = bundle.delegations[1].cert_id.clone();
            Some(Box::new(ConformanceRevocation { revoked_id }))
        } else {
            None
        };

    // Thread fixture verifier_context into the real verifier. Pointer-like
    // optionals distinguish absent from zero.
    let mut context = VerifierContext::default();
    if let Some(vc) = &fx.verifier_context {
        context.current_lat = vc.current_lat;
        context.current_lon = vc.current_lon;
        context.current_alt_m = vc.current_alt_m;
        context.current_speed_mps = vc.current_speed_mps;
        context.requested_amount = vc.requested_amount;
        if !vc.requested_currency.is_empty() {
            context.requested_currency = Some(vc.requested_currency.clone());
        }
        if let Some(n) = vc.invocations_in_window_count {
            context.invocations_in_window = Some(Box::new(move |_cid, _w| n));
        }
    }

    let stream = opts_raw.stream.as_ref().map(|s| StreamContext {
        stream_id: base64_std_decode(&s.stream_id).expect("decode stream_id"),
        last_seen_seq: s.last_seen_seq,
    });
    // VerifyOptions struct literal must mention every field; the deprecated
    // legacy `is_revoked` is set to None here. #[allow(deprecated)] suppresses
    // the lint at this single isolated site — the test fixture uses the new
    // RevocationProvider (built above) for the actual revocation check.
    #[allow(deprecated)]
    let opts = VerifyOptions {
        required_scope: opts_raw.required_scope.clone(),
        is_revoked: None,
        revocation,
        force_revocation_check: false,
        now: Some(opts_raw.now),
        session_context: if opts_raw.session_context.is_empty() {
            Vec::new()
        } else {
            base64_std_decode(&opts_raw.session_context).expect("decode session_context")
        },
        stream,
        context,
        policy: None,
        audit: None,
        constraint_evaluators: None,
        policy_verdict: None,
        policy_secret: None,
        anchor_resolver: None,
    };
    let got = verify_bundle(&bundle, &opts);

    assert_eq!(
        got.valid, want.valid,
        "valid mismatch in fixture {}",
        fx.name
    );
    assert!(
        identity_status_matches(&got.identity_status, &want.identity_status),
        "identity_status mismatch in fixture {}: got {:?}, want {}",
        fx.name,
        got.identity_status,
        want.identity_status
    );
    assert_eq!(
        got.human_id, want.human_id,
        "human_id mismatch in {}",
        fx.name
    );
    assert_eq!(
        got.agent_id, want.agent_id,
        "agent_id mismatch in {}",
        fx.name
    );
    assert_eq!(
        got.error_reason, want.error_reason,
        "error_reason mismatch in {}",
        fx.name
    );
    let mut got_scope = got.granted_scope.clone();
    got_scope.sort();
    let mut want_scope = want.granted_scope.clone();
    want_scope.sort();
    assert_eq!(
        got_scope, want_scope,
        "granted_scope mismatch in {}",
        fx.name
    );
}

fn run_scope_fixture(fx: &Fixture) {
    let input = fx
        .scope_input
        .as_ref()
        .expect("scope fixture has scope_input");
    let got = expand_scopes(input);
    let mut want = fx
        .expected
        .expanded_scopes
        .clone()
        .expect("expanded_scopes");
    want.sort();
    assert_eq!(got, want, "expand_scopes mismatch in {}", fx.name);
}

fn run_revocation_fixture(fx: &Fixture) {
    let raw = fx.revocation_list.as_ref().expect("revocation_list");
    let list = parse_rev(raw);
    let got = hex_encode(&revocation_sign_bytes(&list));
    let want = fx
        .expected
        .revocation_sign_bytes_hex
        .as_ref()
        .expect("revocation_sign_bytes_hex");
    assert_eq!(&got, want, "revocation sign bytes drift in {}", fx.name);

    assert!(!fx.entities.is_empty(), "revocation fixture needs issuer");
    let issuer_pub = parse_pub(&fx.entities[0].public_key);
    assert!(
        verify_revocation_list(&list, &issuer_pub),
        "revocation signature failed to verify in {}",
        fx.name
    );
}

fn run_session_token_fixture(fx: &Fixture) {
    let st = fx
        .session_token
        .as_ref()
        .expect("session_token fixture missing session_token block");
    let token: SessionToken =
        serde_json::from_value(st.token.clone()).expect("parse session_token");
    let got_sign = hex_encode(&session_token_sign_bytes(&token));
    let want_sign = fx
        .expected
        .session_token_sign_bytes_hex
        .as_ref()
        .expect("session_token_sign_bytes_hex");
    assert_eq!(
        &got_sign, want_sign,
        "session_token sign bytes drift in {}",
        fx.name
    );
    assert_eq!(
        hex_encode(&token.mac),
        *fx.expected
            .session_token_mac_hex
            .as_ref()
            .expect("session_token_mac_hex"),
        "session_token MAC drift in {}",
        fx.name
    );

    let secret = hex::decode(&st.session_secret_hex).expect("decode session_secret_hex");
    let challenge = base64_std_decode(&st.challenge).expect("decode challenge");
    let challenge_sig: ratify_protocol::HybridSignature =
        serde_json::from_value(st.challenge_sig.clone()).expect("parse challenge_sig");
    let result = verify_streamed_turn(
        &token,
        &secret,
        &challenge,
        st.challenge_at,
        &challenge_sig,
        &[],
        &[],
        0,
        st.verify_now,
    );
    let want = fx.expected.streamed_turn.as_ref().expect("streamed_turn");
    assert_eq!(
        result.valid, want.valid,
        "streamed_turn.valid in {} (reason={:?})",
        fx.name, result.error_reason
    );
    assert!(
        identity_status_matches(&result.identity_status, &want.identity_status),
        "streamed_turn.identity_status in {}: got {:?}, want {}",
        fx.name,
        result.identity_status,
        want.identity_status
    );
    assert_eq!(result.human_id, want.human_id, "human_id in {}", fx.name);
    assert_eq!(result.agent_id, want.agent_id, "agent_id in {}", fx.name);
    assert_eq!(
        result.error_reason, want.error_reason,
        "error_reason in {}",
        fx.name
    );
    let mut got_scope = result.granted_scope.clone();
    got_scope.sort();
    let mut want_scope = want.granted_scope.clone();
    want_scope.sort();
    assert_eq!(got_scope, want_scope, "granted_scope in {}", fx.name);
}

fn run_transaction_receipt_fixture(fx: &Fixture) {
    let raw = fx
        .transaction_receipt
        .as_ref()
        .expect("transaction_receipt fixture missing transaction_receipt block");
    let receipt: TransactionReceipt =
        serde_json::from_value(raw.clone()).expect("parse transaction_receipt");

    // Cross-check canonical signing bytes.
    let got_sign = hex_encode(&transaction_receipt_sign_bytes(&receipt));
    let want_sign = fx
        .expected
        .receipt_sign_bytes_hex
        .as_ref()
        .expect("receipt_sign_bytes_hex");
    assert_eq!(
        &got_sign, want_sign,
        "receipt sign bytes drift in {}",
        fx.name
    );

    // Run the generic envelope verifier.
    let now = *fx
        .timestamps
        .get("verifier_now")
        .expect("timestamps.verifier_now");
    let result = verify_transaction_receipt(&receipt, now);
    let want_valid = fx
        .expected
        .receipt_valid
        .expect("receipt fixture missing expected.receipt_valid");
    assert_eq!(
        result.valid, want_valid,
        "receipt valid={}, want {} (reason={}) in {}",
        result.valid, want_valid, result.error_reason, fx.name
    );
    assert_eq!(
        result.error_reason, fx.expected.receipt_error_reason,
        "receipt error_reason mismatch in {}",
        fx.name
    );
}

fn run_revocation_push_fixture(fx: &Fixture) {
    let raw = fx.revocation_push.as_ref().expect("revocation_push");
    let push: RevocationPush = serde_json::from_value(raw.clone()).expect("parse revocation_push");
    let got = hex_encode(&revocation_push_sign_bytes(&push));
    let want = fx
        .expected
        .revocation_push_sign_bytes_hex
        .as_ref()
        .expect("revocation_push_sign_bytes_hex");
    assert_eq!(
        &got, want,
        "revocation push sign bytes drift in {}",
        fx.name
    );

    // Verify signature components match expected hex.
    assert_eq!(
        hex_encode(&push.signature.ed25519),
        *fx.expected
            .revocation_push_signature_ed25519_hex
            .as_ref()
            .expect("revocation_push_signature_ed25519_hex"),
        "revocation push ed25519 sig hex drift in {}",
        fx.name
    );
    assert_eq!(
        hex_encode(&push.signature.ml_dsa_65),
        *fx.expected
            .revocation_push_signature_ml_dsa_65_hex
            .as_ref()
            .expect("revocation_push_signature_ml_dsa_65_hex"),
        "revocation push ml_dsa_65 sig hex drift in {}",
        fx.name
    );

    assert!(
        !fx.entities.is_empty(),
        "revocation_push fixture needs issuer"
    );
    let issuer_pub = parse_pub(&fx.entities[0].public_key);
    assert!(
        verify_revocation_push(&push, &issuer_pub),
        "revocation push signature failed to verify in {}",
        fx.name
    );
}

fn run_witness_entry_fixture(fx: &Fixture) {
    let raw = fx.witness_entry.as_ref().expect("witness_entry");
    let entry: WitnessEntry = serde_json::from_value(raw.clone()).expect("parse witness_entry");
    let got = hex_encode(&witness_entry_sign_bytes(&entry));
    let want = fx
        .expected
        .witness_entry_sign_bytes_hex
        .as_ref()
        .expect("witness_entry_sign_bytes_hex");
    assert_eq!(&got, want, "witness entry sign bytes drift in {}", fx.name);

    // Verify signature components match expected hex.
    assert_eq!(
        hex_encode(&entry.signature.ed25519),
        *fx.expected
            .witness_entry_signature_ed25519_hex
            .as_ref()
            .expect("witness_entry_signature_ed25519_hex"),
        "witness entry ed25519 sig hex drift in {}",
        fx.name
    );
    assert_eq!(
        hex_encode(&entry.signature.ml_dsa_65),
        *fx.expected
            .witness_entry_signature_ml_dsa_65_hex
            .as_ref()
            .expect("witness_entry_signature_ml_dsa_65_hex"),
        "witness entry ml_dsa_65 sig hex drift in {}",
        fx.name
    );

    assert!(
        !fx.entities.is_empty(),
        "witness_entry fixture needs witness"
    );
    let witness_pub = parse_pub(&fx.entities[0].public_key);
    assert!(
        verify_witness_entry(&entry, &witness_pub),
        "witness entry signature failed to verify in {}",
        fx.name
    );
}

fn run_key_rotation_fixture(fx: &Fixture) {
    let raw = fx.key_rotation.as_ref().expect("key_rotation");
    let stmt = parse_key_rotation(raw);
    let got = hex_encode(&key_rotation_sign_bytes(&stmt));
    let want = fx
        .expected
        .key_rotation_sign_bytes_hex
        .as_ref()
        .expect("key_rotation_sign_bytes_hex");
    assert_eq!(&got, want, "key rotation sign bytes drift in {}", fx.name);

    let err = verify_key_rotation_statement(&stmt).err();
    let got_ok = err.is_none();
    assert_eq!(
        got_ok,
        fx.expected.key_rotation_verify_ok.unwrap_or(false),
        "key rotation verify bool mismatch in {}",
        fx.name
    );
    assert_eq!(
        err.unwrap_or_default(),
        fx.expected.key_rotation_error_reason,
        "key rotation error mismatch in {}",
        fx.name
    );
}

#[test]
fn run_all_fixtures() {
    let dir = fixture_dir();
    let mut paths: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read fixture dir {:?}: {}", dir, e))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().map(|e| e == "json").unwrap_or(false))
        // cross_sdk_vectors.json has a different schema and is loaded by
        // tests/cross_sdk.rs.
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n != "cross_sdk_vectors.json")
                .unwrap_or(true)
        })
        .collect();
    paths.sort();

    assert!(!paths.is_empty(), "no fixtures in {:?}", dir);

    let mut pass = 0usize;
    for path in &paths {
        let data = fs::read_to_string(path).expect("read fixture");
        let fx: Fixture = serde_json::from_str(&data)
            .unwrap_or_else(|e| panic!("parse fixture {:?}: {}", path, e));
        assert_eq!(
            fx.protocol_version, 1,
            "protocol version mismatch in {}",
            fx.name
        );

        match fx.kind.as_str() {
            "verify" => run_verify_fixture(&fx),
            "scope" => run_scope_fixture(&fx),
            "revocation" => run_revocation_fixture(&fx),
            "key_rotation" => run_key_rotation_fixture(&fx),
            "session_token" => run_session_token_fixture(&fx),
            "transaction_receipt" => run_transaction_receipt_fixture(&fx),
            "revocation_push" => run_revocation_push_fixture(&fx),
            "witness_entry" => run_witness_entry_fixture(&fx),
            other => panic!("unknown fixture kind {:?}", other),
        }
        pass += 1;
    }
    assert_eq!(
        pass,
        paths.len(),
        "{}/{} fixtures passed",
        pass,
        paths.len()
    );
    println!("✓ {} fixtures passed", pass);
}
