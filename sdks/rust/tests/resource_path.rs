//! Unit tests for the alpha.16 resource-bound authority surface — mirrors
//! Go's resource_path_test.go. Covers the path model, segment-boundary
//! matching, the params value model, issuance hygiene, the path_prefix
//! presence rule (SECURITY CRITICAL), the VerificationReceipt codec, the
//! wire input bounds, and the agent-name boundary.

use std::collections::BTreeMap;

use ratify_protocol::{
    check_json_nesting_depth, decode_delegation_cert, decode_proof_bundle,
    decode_verification_receipt, encode_verification_receipt, generate_agent,
    generate_hybrid_keypair, issue_delegation, normalize_resource_path, resource_path_matches,
    sign_both, sign_challenge, validate_params_value, validate_resource_constraints,
    verification_receipt_sign_bytes_buf, Constraint, DelegationCert, HybridSignature, ParamsValue,
    ProofBundle, VerificationReceipt, MAX_AGENT_NAME_LENGTH_BYTES, MAX_CONSTRAINTS_PER_CERT,
    MAX_IDENTIFIER_LENGTH_BYTES, MAX_JSON_NESTING_DEPTH, MAX_PROOF_BUNDLE_BYTES, MAX_SCOPES_PER_CERT,
    MAX_SCOPE_LENGTH_BYTES, PROTOCOL_VERSION,
};

fn rp(id: &str, prefix: Option<&str>) -> Constraint {
    Constraint {
        kind: "resource_path".into(),
        resource_id: id.into(),
        path_prefix: prefix.map(|s| s.into()),
        ..Default::default()
    }
}

#[test]
fn normalize_resource_path_valid_and_invalid() {
    let valid = [
        ("/", "/"),
        ("/docs", "/docs"),
        ("/docs/", "/docs"),
        ("/docs/setup/g.md", "/docs/setup/g.md"),
        ("/docs/%2e%2e/notes", "/docs/%2e%2e/notes"), // % is a literal byte
        ("/a b/c", "/a b/c"),
        ("/UPPER/Case", "/UPPER/Case"), // byte-exact; no case folding
    ];
    for (input, want) in valid {
        let got = normalize_resource_path(input)
            .unwrap_or_else(|e| panic!("normalize({input:?}) unexpected error {e}"));
        assert_eq!(got, want, "normalize({input:?})");
    }

    let invalid = [
        "",             // empty
        "docs",         // no leading slash
        "docs/",        // no leading slash
        "/docs/../x",   // dot-segment
        "/./x",         // dot-segment
        "/..",          // dot-segment
        "/a//b",        // empty interior segment
        "/docs//",      // empty segment after one-trailing-slash trim
        "//",           // empty segment
        "/a\\b",        // backslash
        "\\docs",       // backslash, no leading slash
        "/a\0b",        // NUL
        "/docs/./g.md", // dot-segment mid-path
    ];
    for input in invalid {
        assert!(
            normalize_resource_path(input).is_err(),
            "normalize({input:?}) expected error"
        );
    }
}

#[test]
fn resource_path_matches_segment_boundary() {
    let cases = [
        ("/docs", "/docs", true),
        ("/docs", "/docs/a.md", true),
        ("/docs/", "/docs", true),      // trailing slash trims
        ("/docs", "/docs/", true),      // both directions
        ("/", "/anything", true),       // root matches everything
        ("/", "/", true),               // root matches root
        ("/docs", "/docs-old", false),  // segment boundary, not string prefix
        ("/docs", "/docsx/a", false),   // segment boundary
        ("/docs", "/doc", false),       // shorter
        ("/docs", "/", false),          // parent of prefix
        ("/src/security", "/src", false), // narrower prefix does not match wider path
        ("/docs", "/docs/../x", false), // invalid path never matches
        ("/docs/../x", "/docs", false), // invalid prefix never matches
    ];
    for (prefix, path, want) in cases {
        assert_eq!(
            resource_path_matches(prefix, path),
            want,
            "matches({prefix:?}, {path:?})"
        );
    }
}

#[test]
fn validate_resource_constraints_issuance_rule() {
    let ok: Vec<Vec<Constraint>> = vec![
        vec![],
        vec![rp("git:github.com/acme/widgets", Some("/docs"))],
        vec![rp("git:github.com/acme/widgets", None)], // whole resource
        vec![
            rp("git:github.com/acme/widgets", Some("/src")),
            rp("git:github.com/acme/widgets", Some("/src/security")),
        ], // nested
        vec![
            rp("git:github.com/acme/widgets", None),
            rp("git:github.com/acme/widgets", Some("/docs")),
        ], // absent orders as /
        vec![Constraint {
            kind: "geo_circle".into(),
            lat: 1.0,
            lon: 1.0,
            radius_m: 5.0,
            ..Default::default()
        }], // non-resource untouched
    ];
    for (i, cs) in ok.iter().enumerate() {
        assert!(
            validate_resource_constraints(cs).is_ok(),
            "ok case {i}: unexpected rejection"
        );
    }

    let big_id = "x".repeat(MAX_IDENTIFIER_LENGTH_BYTES + 1);
    let bad: Vec<Vec<Constraint>> = vec![
        vec![rp("", Some("/docs"))],       // empty resource_id
        vec![rp(&big_id, None)],           // oversized id
        vec![rp("git:github.com/acme/widgets", Some("docs"))], // invalid prefix
        vec![
            rp("git:github.com/acme/widgets", Some("/docs")),
            rp("git:github.com/acme/other", Some("/docs")),
        ], // different resources
        vec![
            rp("git:github.com/acme/widgets", Some("/src")),
            rp("git:github.com/acme/widgets", Some("/docs")),
        ], // incomparable prefixes
    ];
    for (i, cs) in bad.iter().enumerate() {
        assert!(
            validate_resource_constraints(cs).is_err(),
            "bad case {i}: expected rejection"
        );
    }
}

#[test]
fn validate_params_value_model() {
    let obj: BTreeMap<String, ParamsValue> = {
        let mut m = BTreeMap::new();
        m.insert("a".to_string(), ParamsValue::Int(1));
        m.insert("b".to_string(), ParamsValue::Array(vec![ParamsValue::Bool(true)]));
        m
    };
    let ok = [
        ParamsValue::Null,
        ParamsValue::Bool(true),
        ParamsValue::Str("s".into()),
        ParamsValue::Int(5),
        ParamsValue::Int(-9007199254740991),
        ParamsValue::Array(vec![
            ParamsValue::Int(1),
            ParamsValue::Str("two".into()),
            ParamsValue::Null,
        ]),
        ParamsValue::Object(obj),
    ];
    for (i, v) in ok.iter().enumerate() {
        assert!(validate_params_value(v, 0).is_ok(), "ok params case {i}");
    }

    let bad = [
        ParamsValue::Int(9007199254740992),  // beyond safe range
        ParamsValue::Int(-9007199254740992), // beyond safe range (negative)
    ];
    for (i, v) in bad.iter().enumerate() {
        assert!(validate_params_value(v, 0).is_err(), "bad params case {i}");
    }

    // Nesting bound: a chain of arrays deeper than MAX_JSON_NESTING_DEPTH.
    let mut deep = ParamsValue::Str("leaf".into());
    for _ in 0..(MAX_JSON_NESTING_DEPTH + 1) {
        deep = ParamsValue::Array(vec![deep]);
    }
    assert!(
        validate_params_value(&deep, 0).is_err(),
        "expected nesting-depth rejection"
    );
}

// ------------------------------------------------------------------
// path_prefix presence — SECURITY CRITICAL (SPEC §5.7.3)
// ------------------------------------------------------------------

#[test]
fn constraint_path_prefix_presence() {
    // Absent path_prefix → None (whole resource); the constraint decodes.
    let absent: Constraint =
        serde_json::from_str(r#"{"resource_id":"r","type":"resource_path"}"#).unwrap();
    assert_eq!(absent.path_prefix, None);

    // A present, non-empty string decodes to Some.
    let present: Constraint =
        serde_json::from_str(r#"{"path_prefix":"/docs","resource_id":"r","type":"resource_path"}"#)
            .unwrap();
    assert_eq!(present.path_prefix.as_deref(), Some("/docs"));

    // Present-but-forbidden forms MUST be rejected: a malformed restriction
    // must never silently widen into whole-resource authority.
    let forbidden = [
        r#"{"path_prefix":"","resource_id":"r","type":"resource_path"}"#, // empty string
        r#"{"path_prefix":null,"resource_id":"r","type":"resource_path"}"#, // null
        r#"{"path_prefix":42,"resource_id":"r","type":"resource_path"}"#, // non-string
    ];
    for doc in forbidden {
        assert!(
            serde_json::from_str::<Constraint>(doc).is_err(),
            "accepted a forbidden path_prefix: {doc}"
        );
    }
}

#[test]
fn decode_rejects_forbidden_path_prefix_in_cert_and_bundle() {
    let (root_pub, root_priv) = generate_hybrid_keypair();
    let (agent_pub, agent_priv) = generate_hybrid_keypair();
    let root_id = ratify_protocol::derive_id(&root_pub);
    let agent_id = ratify_protocol::derive_id(&agent_pub);

    let mut cert = DelegationCert {
        cert_id: "t-presence-1".into(),
        version: PROTOCOL_VERSION,
        issuer_id: root_id,
        issuer_pub_key: root_pub,
        subject_id: agent_id.clone(),
        subject_pub_key: agent_pub.clone(),
        scope: vec!["files:write".into()],
        constraints: vec![rp("git:github.com/acme/widgets", Some("/docs"))],
        issued_at: 1000,
        expires_at: 4070908799,
        signature: HybridSignature {
            ed25519: vec![],
            ml_dsa_65: vec![],
        },
    };
    issue_delegation(&mut cert, &root_priv).unwrap();
    let cert_json = serde_json::to_string(&cert).unwrap();
    assert!(decode_delegation_cert(cert_json.as_bytes()).is_ok());

    let forbidden = [r#""path_prefix":"""#, r#""path_prefix":null"#, r#""path_prefix":42"#];
    for repl in forbidden {
        let doc = cert_json.replacen(r#""path_prefix":"/docs""#, repl, 1);
        assert_ne!(doc, cert_json, "mutation not applied: {repl}");
        assert!(
            decode_delegation_cert(doc.as_bytes()).is_err(),
            "decode_delegation_cert accepted forbidden {repl}"
        );
    }

    // Same forms inside a full bundle must be rejected by decode_proof_bundle.
    let challenge = vec![7u8; 32];
    let sig = sign_challenge(&challenge, 2000, &agent_priv);
    let bundle = ProofBundle {
        agent_id,
        agent_pub_key: agent_pub,
        delegations: vec![cert],
        challenge,
        challenge_at: 2000,
        challenge_sig: sig,
        session_context: vec![],
        stream_id: vec![],
        stream_seq: 0,
    };
    let bundle_json = serde_json::to_string(&bundle).unwrap();
    assert!(decode_proof_bundle(bundle_json.as_bytes()).is_ok());
    for repl in forbidden {
        let doc = bundle_json.replacen(r#""path_prefix":"/docs""#, repl, 1);
        assert_ne!(doc, bundle_json, "mutation not applied: {repl}");
        assert!(
            decode_proof_bundle(doc.as_bytes()).is_err(),
            "decode_proof_bundle accepted forbidden {repl}"
        );
    }
}

#[test]
fn resource_id_required_non_empty_at_decode() {
    // SPEC §5.7.3: resource_id on a resource_path MUST be non-empty. Strict
    // wire acceptance is uniform across SDKs — this is enforced at the
    // deserialize boundary (direct Constraint, cert, and bundle), not deferred
    // to verify. null/non-string already fail as String type errors; absent
    // and empty are the cases the try_from closes.

    // Direct Constraint deserialization.
    let ok: Constraint =
        serde_json::from_str(r#"{"resource_id":"r","type":"resource_path"}"#).unwrap();
    assert_eq!(ok.resource_id, "r");
    let bad = [
        r#"{"type":"resource_path"}"#,                       // absent
        r#"{"resource_id":"","type":"resource_path"}"#,      // empty
        r#"{"resource_id":null,"type":"resource_path"}"#,    // null
        r#"{"resource_id":42,"type":"resource_path"}"#,      // non-string
    ];
    for doc in bad {
        assert!(
            serde_json::from_str::<Constraint>(doc).is_err(),
            "direct decode accepted an invalid resource_id: {doc}"
        );
    }
    // A non-resource_path constraint legitimately has no resource_id.
    let geo: Constraint = serde_json::from_str(
        r#"{"lat":1.0,"lon":2.0,"radius_m":5.0,"type":"geo_circle"}"#,
    )
    .unwrap();
    assert!(geo.resource_id.is_empty());

    // Same rejection through the cert and bundle decoders. Build a valid
    // resource-bound cert, then blank its resource_id on the wire.
    let (root_pub, root_priv) = generate_hybrid_keypair();
    let (agent_pub, agent_priv) = generate_hybrid_keypair();
    let root_id = ratify_protocol::derive_id(&root_pub);
    let agent_id = ratify_protocol::derive_id(&agent_pub);
    let mut cert = DelegationCert {
        cert_id: "t-rid-1".into(),
        version: PROTOCOL_VERSION,
        issuer_id: root_id,
        issuer_pub_key: root_pub,
        subject_id: agent_id.clone(),
        subject_pub_key: agent_pub.clone(),
        scope: vec!["files:write".into()],
        constraints: vec![rp("git:github.com/acme/widgets", Some("/docs"))],
        issued_at: 1000,
        expires_at: 4070908799,
        signature: HybridSignature { ed25519: vec![], ml_dsa_65: vec![] },
    };
    issue_delegation(&mut cert, &root_priv).unwrap();
    let cert_json = serde_json::to_string(&cert).unwrap();
    let blanked = cert_json.replacen(
        r#""resource_id":"git:github.com/acme/widgets""#,
        r#""resource_id":"""#,
        1,
    );
    assert_ne!(blanked, cert_json, "mutation not applied");
    assert!(
        decode_delegation_cert(blanked.as_bytes()).is_err(),
        "decode_delegation_cert accepted an empty resource_id"
    );

    let challenge = vec![9u8; 32];
    let sig = sign_challenge(&challenge, 2000, &agent_priv);
    let bundle = ProofBundle {
        agent_id,
        agent_pub_key: agent_pub,
        delegations: vec![cert],
        challenge,
        challenge_at: 2000,
        challenge_sig: sig,
        session_context: vec![],
        stream_id: vec![],
        stream_seq: 0,
    };
    let bundle_json = serde_json::to_string(&bundle).unwrap();
    let blanked_bundle = bundle_json.replacen(
        r#""resource_id":"git:github.com/acme/widgets""#,
        r#""resource_id":"""#,
        1,
    );
    assert_ne!(blanked_bundle, bundle_json, "mutation not applied");
    assert!(
        decode_proof_bundle(blanked_bundle.as_bytes()).is_err(),
        "decode_proof_bundle accepted an empty resource_id"
    );
}

// ------------------------------------------------------------------
// Issuance hygiene (SPEC §5.7.1, §5.7.3)
// ------------------------------------------------------------------

#[test]
fn issue_delegation_rejects_unsatisfiable_and_params_on_canonical() {
    let (root_pub, root_priv) = generate_hybrid_keypair();
    let (agent_pub, _agent_priv) = generate_hybrid_keypair();
    let base = |constraints: Vec<Constraint>| DelegationCert {
        cert_id: "t-issue-1".into(),
        version: PROTOCOL_VERSION,
        issuer_id: ratify_protocol::derive_id(&root_pub),
        issuer_pub_key: root_pub.clone(),
        subject_id: ratify_protocol::derive_id(&agent_pub),
        subject_pub_key: agent_pub.clone(),
        scope: vec!["files:write".into()],
        constraints,
        issued_at: 1000,
        expires_at: 2000,
        signature: HybridSignature { ed25519: vec![], ml_dsa_65: vec![] },
    };

    // Different-resource pair → jointly unsatisfiable.
    let mut c1 = base(vec![rp("r1", Some("/docs")), rp("r2", Some("/docs"))]);
    assert!(issue_delegation(&mut c1, &root_priv).is_err());

    // Params on a canonical type → rejected.
    let mut params = BTreeMap::new();
    params.insert("x".to_string(), ParamsValue::Int(1));
    let mut c2 = base(vec![Constraint {
        kind: "geo_circle".into(),
        lat: 1.0,
        lon: 1.0,
        radius_m: 5.0,
        params: Some(params),
        ..Default::default()
    }]);
    assert!(issue_delegation(&mut c2, &root_priv).is_err());

    // Out-of-range params integer on an extension type → rejected.
    let mut big = BTreeMap::new();
    big.insert("max".to_string(), ParamsValue::Int(9007199254740992));
    let mut c3 = base(vec![Constraint {
        kind: "com.example.limit".into(),
        params: Some(big),
        ..Default::default()
    }]);
    assert!(issue_delegation(&mut c3, &root_priv).is_err());

    // A valid single resource_path constraint issues fine.
    let mut ok = base(vec![rp("git:github.com/acme/widgets", Some("/docs"))]);
    assert!(issue_delegation(&mut ok, &root_priv).is_ok());
}

// ------------------------------------------------------------------
// Wire input bounds
// ------------------------------------------------------------------

#[test]
fn decode_proof_bundle_size_and_nesting_bounds() {
    // MAX_PROOF_BUNDLE_BYTES, both sides. At exactly the limit the size gate
    // passes and parsing is reached, so the error is a parse error and does
    // NOT name the size bound.
    let at_limit = vec![b'x'; MAX_PROOF_BUNDLE_BYTES];
    let at_err = decode_proof_bundle(&at_limit).unwrap_err();
    assert!(!at_err.contains("MAX_PROOF_BUNDLE_BYTES"), "at-limit must reach parsing, got: {at_err}");
    // One past the limit is rejected before parsing; error names the bound.
    let oversized = vec![b'x'; MAX_PROOF_BUNDLE_BYTES + 1];
    let err = decode_proof_bundle(&oversized).unwrap_err();
    assert!(err.contains("MAX_PROOF_BUNDLE_BYTES"), "got: {err}");

    // Nesting beyond MAX_JSON_NESTING_DEPTH is rejected during the scan.
    let mut deep = String::new();
    for _ in 0..(MAX_JSON_NESTING_DEPTH + 1) {
        deep.push('[');
    }
    for _ in 0..(MAX_JSON_NESTING_DEPTH + 1) {
        deep.push(']');
    }
    let err = decode_proof_bundle(deep.as_bytes()).unwrap_err();
    assert!(err.contains("MAX_JSON_NESTING_DEPTH"), "got: {err}");
}

// input_bound_boundaries exercises every SPEC §5.1 input bound at exactly the
// limit (accept) and one past it (reject) through the public decoders. Mirrors
// Go's TestInputBoundBoundaries. The at-limit accept cases matter as much as
// the rejects: an off-by-one that rejected a legal maximum would be a silent
// availability regression.
#[test]
fn input_bound_boundaries() {
    // A syntactically decodable base cert. Decoders do not verify signatures,
    // so a real keypair with a placeholder (empty) signature suffices.
    let (issuer_pub, _issuer_priv) = generate_hybrid_keypair();
    let (subject_pub, _subject_priv) = generate_hybrid_keypair();
    let base_cert = || DelegationCert {
        cert_id: "bound".into(),
        version: PROTOCOL_VERSION,
        issuer_id: ratify_protocol::derive_id(&issuer_pub),
        issuer_pub_key: issuer_pub.clone(),
        subject_id: ratify_protocol::derive_id(&subject_pub),
        subject_pub_key: subject_pub.clone(),
        scope: vec!["meeting:attend".into()],
        constraints: vec![],
        issued_at: 1000,
        expires_at: 2000,
        signature: HybridSignature { ed25519: vec![], ml_dsa_65: vec![] },
    };
    // Encode with serde (applies no bound checks), then decode (applies them).
    let decode_cert = |c: &DelegationCert| -> Result<DelegationCert, String> {
        let enc = serde_json::to_vec(c).expect("serialize cert");
        decode_delegation_cert(&enc)
    };

    // MAX_SCOPES_PER_CERT
    let scopes = |n: usize| -> Vec<String> {
        (0..n).map(|i| format!("custom:com.example:s{i}")).collect()
    };
    let mut c = base_cert();
    c.scope = scopes(MAX_SCOPES_PER_CERT);
    assert!(
        decode_cert(&c).is_ok(),
        "MAX_SCOPES_PER_CERT at limit ({MAX_SCOPES_PER_CERT}) must decode"
    );
    c.scope = scopes(MAX_SCOPES_PER_CERT + 1);
    assert!(
        decode_cert(&c).is_err(),
        "MAX_SCOPES_PER_CERT+1 ({}) must be rejected",
        MAX_SCOPES_PER_CERT + 1
    );

    // MAX_CONSTRAINTS_PER_CERT (geo_circle: no cross-field satisfiability rule
    // at decode).
    let geos = |n: usize| -> Vec<Constraint> {
        (0..n)
            .map(|_| Constraint {
                kind: "geo_circle".into(),
                lat: 1.0,
                lon: 1.0,
                radius_m: 5.0,
                ..Default::default()
            })
            .collect()
    };
    let mut c = base_cert();
    c.constraints = geos(MAX_CONSTRAINTS_PER_CERT);
    assert!(
        decode_cert(&c).is_ok(),
        "MAX_CONSTRAINTS_PER_CERT at limit ({MAX_CONSTRAINTS_PER_CERT}) must decode"
    );
    c.constraints = geos(MAX_CONSTRAINTS_PER_CERT + 1);
    assert!(
        decode_cert(&c).is_err(),
        "MAX_CONSTRAINTS_PER_CERT+1 ({}) must be rejected",
        MAX_CONSTRAINTS_PER_CERT + 1
    );

    // MAX_SCOPE_LENGTH_BYTES (a custom: scope so it is vocabulary-valid).
    let scope_of_len = |n: usize| -> String {
        let prefix = "custom:x:";
        format!("{prefix}{}", "a".repeat(n - prefix.len()))
    };
    let mut c = base_cert();
    c.scope = vec![scope_of_len(MAX_SCOPE_LENGTH_BYTES)];
    assert!(
        decode_cert(&c).is_ok(),
        "MAX_SCOPE_LENGTH_BYTES at limit ({MAX_SCOPE_LENGTH_BYTES}) must decode"
    );
    c.scope = vec![scope_of_len(MAX_SCOPE_LENGTH_BYTES + 1)];
    assert!(
        decode_cert(&c).is_err(),
        "MAX_SCOPE_LENGTH_BYTES+1 ({}) must be rejected",
        MAX_SCOPE_LENGTH_BYTES + 1
    );

    // MAX_IDENTIFIER_LENGTH_BYTES (resource_path resource_id).
    let rp_id = |n: usize| -> Vec<Constraint> { vec![rp(&"r".repeat(n), None)] };
    let mut c = base_cert();
    c.constraints = rp_id(MAX_IDENTIFIER_LENGTH_BYTES);
    assert!(
        decode_cert(&c).is_ok(),
        "MAX_IDENTIFIER_LENGTH_BYTES at limit ({MAX_IDENTIFIER_LENGTH_BYTES}) must decode"
    );
    c.constraints = rp_id(MAX_IDENTIFIER_LENGTH_BYTES + 1);
    assert!(
        decode_cert(&c).is_err(),
        "MAX_IDENTIFIER_LENGTH_BYTES+1 ({}) must be rejected",
        MAX_IDENTIFIER_LENGTH_BYTES + 1
    );

    // MAX_JSON_NESTING_DEPTH (container nesting via check_json_nesting_depth).
    let at_limit: String =
        "[".repeat(MAX_JSON_NESTING_DEPTH) + &"]".repeat(MAX_JSON_NESTING_DEPTH);
    assert!(
        check_json_nesting_depth(at_limit.as_bytes()).is_ok(),
        "MAX_JSON_NESTING_DEPTH at limit ({MAX_JSON_NESTING_DEPTH}) must be accepted"
    );
    let over_limit: String =
        "[".repeat(MAX_JSON_NESTING_DEPTH + 1) + &"]".repeat(MAX_JSON_NESTING_DEPTH + 1);
    assert!(
        check_json_nesting_depth(over_limit.as_bytes()).is_err(),
        "MAX_JSON_NESTING_DEPTH+1 ({}) must be rejected",
        MAX_JSON_NESTING_DEPTH + 1
    );

    // MAX_AGENT_NAME_LENGTH_BYTES (construction bound via generate_agent).
    assert!(
        generate_agent(&"n".repeat(MAX_AGENT_NAME_LENGTH_BYTES), "custom").is_ok(),
        "MAX_AGENT_NAME_LENGTH_BYTES at limit ({MAX_AGENT_NAME_LENGTH_BYTES}) must be accepted"
    );
    assert!(
        generate_agent(&"n".repeat(MAX_AGENT_NAME_LENGTH_BYTES + 1), "custom").is_err(),
        "MAX_AGENT_NAME_LENGTH_BYTES+1 ({}) must be rejected",
        MAX_AGENT_NAME_LENGTH_BYTES + 1
    );
}

// ------------------------------------------------------------------
// VerificationReceipt codec (SPEC §17.5)
// ------------------------------------------------------------------

fn signed_receipt(decision: &str) -> VerificationReceipt {
    let (v_pub, v_priv) = generate_hybrid_keypair();
    let mut r = VerificationReceipt {
        version: PROTOCOL_VERSION,
        verifier_id: ratify_protocol::derive_id(&v_pub),
        verifier_pub: v_pub,
        bundle_hash: vec![0xAB; 32],
        decision: decision.into(),
        human_id: String::new(),
        agent_id: "b4a4c71795d676b69f454881a8300000".into(),
        granted_scope: vec![],
        error_reason: String::new(),
        verified_at: 1_800_000_000,
        prev_hash: vec![0u8; 32],
        signature: HybridSignature { ed25519: vec![], ml_dsa_65: vec![] },
    };
    let signable = verification_receipt_sign_bytes_buf(&r).unwrap();
    r.signature = sign_both(&signable, &v_priv);
    r
}

#[test]
fn verification_receipt_codec_round_trip() {
    let r = signed_receipt("revoked");
    let encoded = encode_verification_receipt(&r).unwrap();
    let decoded = decode_verification_receipt(&encoded).unwrap();
    let re_encoded = encode_verification_receipt(&decoded).unwrap();
    assert_eq!(encoded, re_encoded, "receipt round-trip not byte-identical");
}

#[test]
fn verification_receipt_encoder_rejects_invalid() {
    // Valid receipt encodes.
    let valid = signed_receipt("authorized_agent");
    assert!(encode_verification_receipt(&valid).is_ok());

    let mut short_hash = valid.clone();
    short_hash.bundle_hash.truncate(16);
    assert!(encode_verification_receipt(&short_hash).is_err());

    let mut short_prev = valid.clone();
    short_prev.prev_hash.truncate(31);
    assert!(encode_verification_receipt(&short_prev).is_err());

    let mut bad_decision = valid.clone();
    bad_decision.decision = "approved".into();
    assert!(encode_verification_receipt(&bad_decision).is_err());

    let mut empty_verifier = valid.clone();
    empty_verifier.verifier_id = String::new();
    assert!(encode_verification_receipt(&empty_verifier).is_err());

    let mut wrong_version = valid.clone();
    wrong_version.version = 2;
    assert!(encode_verification_receipt(&wrong_version).is_err());

    let mut short_sig = valid.clone();
    short_sig.signature.ed25519.truncate(63);
    assert!(encode_verification_receipt(&short_sig).is_err());
}

#[test]
fn verification_receipt_decoder_rejects_malformed_wire() {
    let r = signed_receipt("authorized_agent");
    let encoded = encode_verification_receipt(&r).unwrap();
    let text = String::from_utf8(encoded).unwrap();

    let mutate = |old: &str, new: &str| -> String {
        let out = text.replacen(old, new, 1);
        assert_ne!(out, text, "mutation {old:?} not applied");
        out
    };

    let cases = vec![
        mutate(r#""version":"#, r#""versionx":1,"version":"#), // unknown field
        mutate(r#""version":1"#, r#""version":2"#),            // wrong version
        mutate(
            r#""decision":"authorized_agent""#,
            r#""decision":"approved""#,
        ), // unknown decision
        mutate(
            &format!(r#""verifier_id":"{}""#, r.verifier_id),
            r#""verifier_id":"""#,
        ), // empty verifier_id
        "[1,2,3]".to_string(), // non-object
    ];
    for doc in cases {
        assert!(
            decode_verification_receipt(doc.as_bytes()).is_err(),
            "decoder accepted malformed wire: {doc}"
        );
    }
}

// ------------------------------------------------------------------
// Agent-name boundary (SPEC §5.1)
// ------------------------------------------------------------------

#[test]
fn generate_agent_name_bound() {
    let at_limit = "n".repeat(MAX_AGENT_NAME_LENGTH_BYTES);
    assert!(
        generate_agent(&at_limit, "custom").is_ok(),
        "name of exactly {MAX_AGENT_NAME_LENGTH_BYTES} bytes must be accepted"
    );
    let over_limit = "n".repeat(MAX_AGENT_NAME_LENGTH_BYTES + 1);
    assert!(
        generate_agent(&over_limit, "custom").is_err(),
        "name of {} bytes must be rejected",
        MAX_AGENT_NAME_LENGTH_BYTES + 1
    );
}
