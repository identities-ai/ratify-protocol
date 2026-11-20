//! Preview Verify MCP signer through the C ABI (`ratify_v2_mcp_*`) over the
//! shared vectors in testvectors/v2/mcp. The hosted service recomputes every
//! value from the call it receives; a signer that differs in one byte
//! produces proofs the service rejects, or a proof that binds something
//! other than the call the client asked for.
//!
//! The emulated external provider below signs with `fips204` and
//! `ed25519-dalek` directly, as an HSM or KMS outside the SDK would; the ABI
//! verifies what it returns.

mod v2c_common;

use std::collections::BTreeSet;
use std::os::raw::{c_char, c_void};
use std::ptr;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer as _, SigningKey};
use fips204::ml_dsa_65;
use fips204::traits::Signer as _;
use ratify_c::*;
use serde_json::Value;
use v2c_common::*;

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

fn mcp(name: &str) -> Value {
    load(&format!("{CORPUS_DIR}/{name}"))
}

fn st<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str()
        .unwrap_or_else(|| panic!("{k} is not a string"))
}

fn seed(v: &Value, k: &str) -> [u8; 32] {
    hex::decode(st(v, k)).unwrap().try_into().unwrap()
}

fn load_key(v: &Value) -> Kp {
    let kp = Kp::from_seeds(&seed(v, "ed25519_seed_hex"), &seed(v, "ml_dsa_65_seed_hex"));
    assert_eq!(kp.id(), st(v, "key_id_v2"), "fixture key ID");
    kp
}

fn code_of<T>(r: &R<T>) -> i32 {
    match r {
        Ok(_) => 0,
        Err(f) => f.code,
    }
}

/// A parsed client configuration handle.
struct Config(*mut RatifyV2McpClientConfig);

impl Drop for Config {
    fn drop(&mut self) {
        unsafe { ratify_v2_mcp_client_config_free(self.0) };
    }
}

fn parse_config(text: &str) -> R<(Config, Value)> {
    let mut h = ptr::null_mut();
    let fields = string(|o| unsafe {
        ratify_v2_mcp_client_config_parse(ptr_of(text.as_bytes()), text.len(), &mut h, o)
    })?;
    Ok((Config(h), parse(fields.as_bytes())))
}

/// A checked challenge handle.
struct Challenge(*mut RatifyV2McpChallenge);

impl Drop for Challenge {
    fn drop(&mut self) {
        unsafe { ratify_v2_mcp_challenge_free(self.0) };
    }
}

fn check_challenge(cfg: &Config, tool: &str, response: &str, now: i64) -> R<(Challenge, Value)> {
    let tool = cs(tool);
    let mut h = ptr::null_mut();
    let fields = string(|o| unsafe {
        ratify_v2_mcp_check_challenge(
            cfg.0,
            tool.as_ptr(),
            ptr_of(response.as_bytes()),
            response.len(),
            now,
            &mut h,
            o,
        )
    })?;
    Ok((Challenge(h), parse(fields.as_bytes())))
}

fn sign(
    cfg: &Config,
    tool: &str,
    arguments: &str,
    ch: &Challenge,
    local: *const RatifyV2KeyPair,
    external: *const RatifyV2ExternalSigner,
) -> R<Value> {
    let tool = cs(tool);
    let env = string(|o| unsafe {
        ratify_v2_mcp_sign_tool_call(
            cfg.0,
            tool.as_ptr(),
            ptr_of(arguments.as_bytes()),
            arguments.len(),
            ch.0,
            local,
            external,
            o,
        )
    })?;
    Ok(parse(env.as_bytes()))
}

fn prove(
    token: &str,
    local: *const RatifyV2KeyPair,
    external: *const RatifyV2ExternalSigner,
) -> R<Value> {
    let token = cs(token);
    let out =
        string(|o| unsafe { ratify_v2_mcp_prove_possession(token.as_ptr(), local, external, o) })?;
    Ok(parse(out.as_bytes()))
}

/// `got` and `want` are the same proof except the hedged ML-DSA-65
/// component of challenge_sig, and both verify through the ABI.
fn same_bundle(name: &str, got_b64: &str, want_b64: &str) {
    let decode = |text: &str| {
        let wire = STANDARD
            .decode(text)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        check(unsafe {
            ratify_v2_proof_bundle_verify_signatures(
                wire.as_ptr(),
                wire.len(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
            )
        })
        .unwrap_or_else(|e| panic!("{name}: does not verify: {e:?}"));
        let sig = parse(&wire)["challenge_sig"]["ml_dsa_65"]
            .as_str()
            .unwrap()
            .to_string();
        (String::from_utf8(wire).unwrap(), sig)
    };
    let (got, got_sig) = decode(got_b64);
    let (want, want_sig) = decode(want_b64);
    assert!(
        got.replacen(&got_sig, &want_sig, 1) == want,
        "{name}: proof differs from the vector beyond the hedged ML-DSA-65 signature"
    );
}

// ---------------------------------------------------------------------------
// An emulated direct-mode external provider.

struct SeedOnce([u8; 32], bool);

impl rand_core::RngCore for SeedOnce {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        assert!(!self.1 && dest.len() == 32, "seed is used once, whole");
        dest.copy_from_slice(&self.0);
        self.1 = true;
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for SeedOnce {}

struct Provider {
    ed: SigningKey,
    ml: ml_dsa_65::PrivateKey,
    public: RatifyV2PublicKey,
}

impl Provider {
    fn new(v: &Value, kp: &Kp) -> Provider {
        let (_, ml) =
            ml_dsa_65::try_keygen_with_rng(&mut SeedOnce(seed(v, "ml_dsa_65_seed_hex"), false))
                .expect("keygen");
        Provider {
            ed: SigningKey::from_bytes(&seed(v, "ed25519_seed_hex")),
            ml,
            public: kp.public(),
        }
    }

    fn signer(&self) -> RatifyV2ExternalSigner {
        RatifyV2ExternalSigner {
            user: self as *const Provider as *mut c_void,
            mode: RatifyV2SignerMode::RatifyV2SignerDirect as i32,
            public_key: Some(provider_public_key),
            sign: Some(provider_sign),
        }
    }
}

unsafe extern "C" fn provider_public_key(user: *mut c_void, out: *mut RatifyV2PublicKey) -> i32 {
    *out = (*(user as *const Provider)).public;
    0
}

unsafe extern "C" fn provider_sign(
    user: *mut c_void,
    req: *const RatifyV2SignRequest,
    out: *mut RatifyV2Signature,
) -> i32 {
    let p = &*(user as *const Provider);
    let r = &*req;
    let (m, ctx) = (slice_in(r.message), slice_in(r.ml_dsa_context));
    let o = &mut *out;
    o.ed25519.copy_from_slice(&p.ed.sign(&m).to_bytes());
    o.ed25519_len = 64;
    o.ml_dsa_65
        .copy_from_slice(&p.ml.try_sign(&m, &ctx).expect("ML-DSA sign"));
    o.ml_dsa_65_len = 3309;
    0
}

// ---------------------------------------------------------------------------

#[test]
fn v2c_mcp_corpus_directory_holds_exactly_the_consumed_files() {
    let present: BTreeSet<String> = std::fs::read_dir(corpus_dir().join(CORPUS_DIR))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    let expected: BTreeSet<String> = FILES.iter().map(|f| f.to_string()).collect();
    assert_eq!(
        present, expected,
        "testvectors/v2/mcp differs from the files this runner consumes"
    );
}

#[test]
fn v2c_mcp_binding_vectors() {
    let f = mcp("binding.json");
    let constants = parse(
        string(|o| unsafe { ratify_v2_mcp_constants_json(o) })
            .unwrap()
            .as_bytes(),
    );
    assert_eq!(st(&constants, "action"), st(&f, "action"));
    assert_eq!(st(&constants, "proof_meta_key"), st(&f, "proof_meta_key"));
    assert_eq!(st(&constants, "protocol_version"), "2026-07-28");
    assert_eq!(constants["min_challenge_seconds_left"], 10);
    assert_eq!(constants["max_connect_token_length"], 4096);
    assert_eq!(constants["max_argument_depth"], 4);
    assert_eq!(constants["tools"], f["tools"], "tool table and order");
    let cases = arr(&f["cases"]);
    assert!(!cases.is_empty());
    for c in &cases {
        let name = st(c, "name");
        let args = st(c, "arguments_json").as_bytes();
        let canonical =
            buf(|o| unsafe { ratify_v2_mcp_canonical_arguments(ptr_of(args), args.len(), o) })
                .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(
            canonical,
            st(c, "canonical_arguments").as_bytes(),
            "{name}: canonical"
        );
        let mut text: *mut c_char = ptr::null_mut();
        let digest = buf(|o| unsafe {
            ratify_v2_mcp_payload_digest(ptr_of(&canonical), canonical.len(), o, &mut text)
        })
        .unwrap();
        assert_eq!(
            take_str(text),
            st(c, "payload_digest"),
            "{name}: payload digest"
        );
        let (tool, conn, aud) = (
            cs(st(c, "tool")),
            cs(st(c, "connection_id")),
            cs(st(c, "audience")),
        );
        let req = buf(|o| unsafe {
            ratify_v2_mcp_request_hash(
                tool.as_ptr(),
                conn.as_ptr(),
                aud.as_ptr(),
                digest.as_ptr(),
                digest.len(),
                o,
            )
        })
        .unwrap();
        assert_eq!(
            hex::encode(&req),
            st(c, "request_hash"),
            "{name}: request hash"
        );
        let (v, w, a, i) = (
            cs(st(c, "verifier_id")),
            cs(st(c, "workspace_id")),
            cs(st(c, "agent_id")),
            cs(st(c, "invocation_id")),
        );
        let sess = buf(|o| unsafe {
            ratify_v2_mcp_session_context(
                v.as_ptr(),
                w.as_ptr(),
                a.as_ptr(),
                conn.as_ptr(),
                i.as_ptr(),
                req.as_ptr(),
                req.len(),
                o,
            )
        })
        .unwrap();
        assert_eq!(
            hex::encode(&sess),
            st(c, "session_context"),
            "{name}: session context"
        );
    }
    let invalid = arr(&f["invalid_arguments"]);
    assert!(!invalid.is_empty());
    for c in &invalid {
        let input = match c["arguments_base64"].as_str() {
            Some(b) if !b.is_empty() => STANDARD.decode(b).unwrap(),
            _ => st(c, "arguments_json").as_bytes().to_vec(),
        };
        let r =
            buf(|o| unsafe { ratify_v2_mcp_canonical_arguments(ptr_of(&input), input.len(), o) });
        assert_eq!(
            code_of(&r),
            RatifyV2Code::RatifyV2McpInvalidArguments as i32,
            "{}: accepted",
            st(c, "name")
        );
    }
    // An unknown tool binds no scope.
    let (tool, conn, aud) = (
        cs("delete_everything"),
        cs("c"),
        cs("https://verify.example/mcp"),
    );
    let r = buf(|o| unsafe {
        ratify_v2_mcp_request_hash(
            tool.as_ptr(),
            conn.as_ptr(),
            aud.as_ptr(),
            [0u8; 32].as_ptr(),
            32,
            o,
        )
    });
    assert_eq!(
        code_of(&r),
        RatifyV2Code::RatifyV2McpInvalidArguments as i32
    );
    assert_eq!(class_of(&r), "mcp_invalid_arguments");
}

#[test]
fn v2c_mcp_client_config_vectors() {
    let f = mcp("client-config.json");
    for c in arr(&f["valid"]) {
        let name = st(&c, "name");
        let (_cfg, fields) =
            parse_config(st(&c, "config_json")).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(fields, c["expected"], "{name}");
    }
    for c in arr(&f["invalid"]) {
        let r = parse_config(st(&c, "config_json"));
        assert_eq!(
            code_of(&r),
            RatifyV2Code::RatifyV2McpInvalidConfig as i32,
            "{}: accepted",
            st(&c, "name")
        );
    }
}

#[test]
fn v2c_mcp_tool_call_vectors() {
    let f = mcp("tool-call.json");
    let (cfg, _) = parse_config(st(&f, "client_config_json")).unwrap();
    let agent = load_key(&f["agent_key"]);
    let wrong = load_key(&f["wrong_agent_key"]);
    let provider = Provider::new(&f["agent_key"], &agent);
    let external = provider.signer();
    let cases = arr(&f["cases"]);
    assert!(!cases.is_empty());
    for c in &cases {
        let name = st(c, "name");
        let (tool, args) = (st(c, "tool"), st(c, "arguments_json"));
        let canonical = buf(|o| unsafe {
            ratify_v2_mcp_canonical_arguments(ptr_of(args.as_bytes()), args.len(), o)
        })
        .unwrap();
        assert_eq!(
            canonical,
            st(c, "canonical_arguments").as_bytes(),
            "{name}: arguments"
        );
        let ctool = cs(tool);
        let body = buf(|o| unsafe {
            ratify_v2_mcp_challenge_request(
                cfg.0,
                ctool.as_ptr(),
                ptr_of(args.as_bytes()),
                args.len(),
                o,
            )
        })
        .unwrap();
        assert_eq!(
            body,
            st(c, "challenge_request").as_bytes(),
            "{name}: challenge request"
        );
        let now = c["now"].as_i64().unwrap();
        let (ch, fields) = check_challenge(&cfg, tool, st(c, "challenge_response"), now)
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(st(&fields, "tool"), tool);
        assert_eq!(
            st(&fields, "invocation_id"),
            st(&c["envelope"], "invocation_id")
        );
        let want = &c["envelope"];
        for (label, local, ext) in [
            ("local", agent.0 as *const RatifyV2KeyPair, ptr::null()),
            (
                "external",
                ptr::null(),
                &external as *const RatifyV2ExternalSigner,
            ),
        ] {
            let env = sign(&cfg, tool, args, &ch, local, ext)
                .unwrap_or_else(|e| panic!("{name} {label}: {e:?}"));
            assert_eq!(
                st(&env, "connection_id"),
                st(want, "connection_id"),
                "{name}"
            );
            assert_eq!(
                st(&env, "invocation_id"),
                st(want, "invocation_id"),
                "{name}"
            );
            assert_eq!(st(&env, "challenge"), st(want, "challenge"), "{name}");
            same_bundle(name, st(&env, "bundle"), st(want, "bundle"));
        }
        let r = sign(&cfg, tool, args, &ch, wrong.0, ptr::null());
        assert_eq!(
            code_of(&r),
            RatifyV2Code::RatifyV2McpAgentNotDelegated as i32,
            "{name}: a key the delegation does not name signed"
        );
    }
    let refused = arr(&f["refused_challenges"]);
    assert!(!refused.is_empty());
    for c in &refused {
        let r = check_challenge(
            &cfg,
            st(c, "tool"),
            st(c, "challenge_response"),
            c["now"].as_i64().unwrap(),
        );
        assert_eq!(
            code_of(&r),
            RatifyV2Code::RatifyV2McpChallengeRefused as i32,
            "{}: accepted",
            st(c, "name")
        );
    }
    // A challenge accepted for one tool and configuration never signs a call
    // to another tool or under another connection or verifier.
    let refused_signings = arr(&f["refused_signings"]);
    assert!(!refused_signings.is_empty());
    for c in &refused_signings {
        let name = st(c, "name");
        let (ch, _) = check_challenge(
            &cfg,
            st(c, "checked_tool"),
            st(c, "challenge_response"),
            c["now"].as_i64().unwrap(),
        )
        .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let other = match st(c, "signing_config_json") {
            "" => None,
            text => Some(
                parse_config(text)
                    .unwrap_or_else(|e| panic!("{name}: {e:?}"))
                    .0,
            ),
        };
        let sign_cfg = other.as_ref().unwrap_or(&cfg);
        let r = sign(
            sign_cfg,
            st(c, "signing_tool"),
            st(c, "signing_arguments_json"),
            &ch,
            agent.0,
            ptr::null(),
        );
        assert_eq!(
            code_of(&r),
            RatifyV2Code::RatifyV2McpChallengeRefused as i32,
            "{name}: signed"
        );
    }
}

#[test]
fn v2c_mcp_connect_vectors() {
    let f = mcp("connect.json");
    let constants = parse(
        string(|o| unsafe { ratify_v2_mcp_constants_json(o) })
            .unwrap()
            .as_bytes(),
    );
    assert_eq!(
        st(&constants, "connect_possession_domain"),
        st(&f, "domain")
    );
    assert_eq!(
        st(&constants, "connect_token_prefix"),
        st(&f, "token_prefix")
    );
    let context = |w: &str, r: &str, a: &str, ch: &str, agent: &str| {
        let (w, r, a, ch, agent) = (cs(w), cs(r), cs(a), cs(ch), cs(agent));
        buf(|o| unsafe {
            ratify_v2_mcp_connect_possession_context(
                w.as_ptr(),
                r.as_ptr(),
                a.as_ptr(),
                ch.as_ptr(),
                agent.as_ptr(),
                o,
            )
        })
        .unwrap()
    };
    for c in arr(&f["contexts"]) {
        let got = context(
            st(&c, "workspace_id"),
            st(&c, "receiver_id"),
            st(&c, "audience"),
            st(&c, "challenge_id"),
            st(&c, "agent_id"),
        );
        assert_eq!(
            hex::encode(got),
            st(&c, "session_context"),
            "{}",
            st(&c, "name")
        );
    }
    let agent = load_key(&f["agent_key"]);
    let agent_id = agent.id();
    let provider = Provider::new(&f["agent_key"], &agent);
    let external = provider.signer();
    let proofs = arr(&f["proofs"]);
    assert!(!proofs.is_empty());
    for c in &proofs {
        let name = st(c, "name");
        let token = cs(st(c, "token"));
        let parsed = string(|o| unsafe { ratify_v2_mcp_parse_connect_token(token.as_ptr(), o) })
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let parsed = parse(parsed.as_bytes());
        assert_eq!(parsed, c["parsed"], "{name}: parsed");
        let sess = context(
            st(&parsed, "workspace_id"),
            st(&parsed, "receiver_id"),
            st(&parsed, "audience"),
            st(&parsed, "challenge_id"),
            &agent_id,
        );
        assert_eq!(
            hex::encode(sess),
            st(c, "session_context"),
            "{name}: session context"
        );
        let want = &c["expected"];
        for (label, local, ext) in [
            ("local", agent.0 as *const RatifyV2KeyPair, ptr::null()),
            (
                "external",
                ptr::null(),
                &external as *const RatifyV2ExternalSigner,
            ),
        ] {
            let proof = prove(st(c, "token"), local, ext)
                .unwrap_or_else(|e| panic!("{name} {label}: {e:?}"));
            assert_eq!(
                st(&proof, "connect_challenge_id"),
                st(want, "connect_challenge_id")
            );
            same_bundle(
                name,
                st(&proof, "possession_proof"),
                st(want, "possession_proof"),
            );
        }
    }
    let invalid = arr(&f["invalid_tokens"]);
    assert!(!invalid.is_empty());
    for c in &invalid {
        let name = st(c, "name");
        let token = cs(st(c, "token"));
        let r = string(|o| unsafe { ratify_v2_mcp_parse_connect_token(token.as_ptr(), o) });
        assert_eq!(
            code_of(&r),
            RatifyV2Code::RatifyV2McpInvalidConnectToken as i32,
            "{name}: accepted"
        );
        let r = prove(st(c, "token"), agent.0, ptr::null());
        assert_eq!(
            code_of(&r),
            RatifyV2Code::RatifyV2McpInvalidConnectToken as i32,
            "{name}: signed"
        );
    }
    // Text that is not UTF-8 is not a connect token.
    let raw = b"ratify-mcp-connect-1.\xff\0";
    let r =
        string(|o| unsafe { ratify_v2_mcp_parse_connect_token(raw.as_ptr() as *const c_char, o) });
    assert_eq!(
        code_of(&r),
        RatifyV2Code::RatifyV2McpInvalidConnectToken as i32
    );
}

/// A challenge is issued for one tool's scope and request hash. Letting it
/// sign a call to another tool would hand the server a proof whose binding
/// the signer never checked against the challenge it accepted.
#[test]
fn v2c_mcp_a_challenge_signs_only_the_tool_it_was_checked_for() {
    let f = mcp("tool-call.json");
    let (cfg, _) = parse_config(st(&f, "client_config_json")).unwrap();
    let agent = load_key(&f["agent_key"]);
    let c = &arr(&f["cases"])[0];
    let tool = st(c, "tool");
    let (ch, _) = check_challenge(
        &cfg,
        tool,
        st(c, "challenge_response"),
        c["now"].as_i64().unwrap(),
    )
    .unwrap();
    let constants = parse(
        string(|o| unsafe { ratify_v2_mcp_constants_json(o) })
            .unwrap()
            .as_bytes(),
    );
    for other in arr(&constants["tools"]) {
        let other = st(&other, "name");
        if other == tool {
            continue;
        }
        let r = sign(&cfg, other, "{}", &ch, agent.0, ptr::null());
        assert_eq!(
            code_of(&r),
            RatifyV2Code::RatifyV2McpChallengeRefused as i32,
            "a challenge checked for {tool} signed a call to {other}"
        );
    }
    // A NULL handle is an ABI condition, not a signature.
    let ctool = cs(tool);
    let r = string(|o| unsafe {
        ratify_v2_mcp_sign_tool_call(
            cfg.0,
            ctool.as_ptr(),
            b"{}".as_ptr(),
            2,
            ptr::null(),
            agent.0,
            ptr::null(),
            o,
        )
    });
    assert_eq!(code_of(&r), RatifyV2Code::RatifyV2ErrNullPointer as i32);
    assert_eq!(class_of(&r), "null_pointer");
}
