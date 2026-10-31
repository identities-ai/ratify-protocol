use ratify_protocol::{
    build_session_context_v2, decode_payload_digest_v2, operation_context_v2_hash,
    session_context_v2_bytes, OperationContextV2, SessionContextV2Inputs,
};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../../testvectors/v2/operation-session-context.json"))
        .expect("valid shared operation/session fixture")
}

fn decode_hex(value: &str) -> Vec<u8> {
    hex::decode(value).expect("valid fixture hex")
}

fn operation_from(value: &Value) -> OperationContextV2 {
    OperationContextV2 {
        required_scope: value["required_scope"].as_str().unwrap().into(),
        operation: value["operation"].as_str().unwrap().into(),
        resource_id: value["resource_id"].as_str().unwrap().into(),
        requested_path: value["requested_path"].as_str().unwrap().into(),
        payload_digest: value["payload_digest_hex"].as_str().map(decode_hex).unwrap_or_default(),
    }
}

fn session_from(value: &Value, request_hash: Vec<u8>) -> SessionContextV2Inputs {
    SessionContextV2Inputs {
        verifier_id: value["verifier_id"].as_str().unwrap().into(),
        workspace_id: value["workspace_id"].as_str().unwrap().into(),
        agent_id: value["agent_id"].as_str().unwrap().into(),
        session_id: value["session_id"].as_str().unwrap().into(),
        invocation_id: value["invocation_id"].as_str().unwrap().into(),
        request_hash,
    }
}

#[test]
fn operation_and_session_context_match_shared_v2_vectors() {
    let vector = fixture();
    let request_hash = operation_context_v2_hash(&operation_from(&vector["operation_input"])).unwrap();
    assert_eq!(hex::encode(&request_hash), vector["expected_request_hash_hex"].as_str().unwrap());
    let session = session_from(
        &vector["input"],
        decode_hex(vector["input"]["request_hash_hex"].as_str().unwrap()),
    );
    assert_eq!(hex::encode(build_session_context_v2(&session).unwrap()), vector["expected_session_context_hex"].as_str().unwrap());

    let empty_hash = operation_context_v2_hash(&operation_from(&vector["empty_payload_operation_input"])).unwrap();
    assert_eq!(hex::encode(&empty_hash), vector["expected_empty_request_hash_hex"].as_str().unwrap());
    let empty_session = session_from(&vector["input"], empty_hash);
    assert_eq!(hex::encode(build_session_context_v2(&empty_session).unwrap()), vector["expected_empty_session_context_hex"].as_str().unwrap());
}

#[test]
fn operation_context_rejects_noncanonical_required_scopes() {
    let vector = fixture();
    let base = operation_from(&vector["operation_input"]);
    for scope in vector["invalid_required_scopes"].as_array().unwrap() {
        let mut operation = base.clone();
        operation.required_scope = scope.as_str().unwrap().into();
        assert!(operation_context_v2_hash(&operation).is_err(), "accepted {scope}");
    }
}

#[test]
fn payload_digest_decoder_matches_shared_accept_and_reject_cases() {
    let vector = fixture();
    for case in vector["verify_api_payload_digest_decode_cases"].as_array().unwrap() {
        let encoded = case["encoded"].as_str();
        let result = decode_payload_digest_v2(encoded);
        assert_eq!(result.is_ok(), case["valid"].as_bool().unwrap(), "case {}", case["name"]);
        if let Ok(decoded) = result {
            let expected = case["expected_hex"].as_str().unwrap();
            assert_eq!(decoded.map(hex::encode).unwrap_or_default(), expected, "case {}", case["name"]);
        }
    }
}

#[test]
fn verify_api_digest_text_decodes_into_the_expected_operation_hash() {
    let vector = fixture();
    let input = &vector["verify_api_operation_input"];
    let digest = decode_payload_digest_v2(input["payload_digest"].as_str()).unwrap().unwrap();
    let context = OperationContextV2 {
        required_scope: input["required_scope"].as_str().unwrap().into(),
        operation: input["operation"].as_str().unwrap().into(),
        resource_id: input["resource_id"].as_str().unwrap().into(),
        requested_path: input["requested_path"].as_str().unwrap().into(),
        payload_digest: digest,
    };
    assert_eq!(
        hex::encode(operation_context_v2_hash(&context).unwrap()),
        vector["expected_verify_api_request_hash_hex"].as_str().unwrap(),
    );
    assert_eq!(
        operation_context_v2_hash(&context).unwrap(),
        operation_context_v2_hash(&operation_from(&vector["operation_input"])).unwrap(),
        "Verify text digest and canonical raw digest must bind the same action",
    );
}

#[test]
fn v2_context_rejects_malformed_ids_hashes_and_payload_lengths() {
    let vector = fixture();
    let mut operation = operation_from(&vector["operation_input"]);
    operation.payload_digest.pop();
    assert!(operation_context_v2_hash(&operation).is_err());

    let mut session = session_from(&vector["input"], vec![0; 32]);
    session.verifier_id.make_ascii_uppercase();
    assert!(session_context_v2_bytes(&session).is_err());
    session.verifier_id = vector["input"]["verifier_id"].as_str().unwrap().into();
    session.verifier_id.truncate(32);
    assert!(session_context_v2_bytes(&session).is_err());
    session.verifier_id = vector["input"]["verifier_id"].as_str().unwrap().into();
    session.workspace_id = "00000000-0000-4000-8000-00000000000A".into();
    assert!(session_context_v2_bytes(&session).is_err());
    session.workspace_id = vector["input"]["workspace_id"].as_str().unwrap().into();
    session.agent_id = "not-a-key-id".into();
    assert!(session_context_v2_bytes(&session).is_err());
    session.agent_id = vector["input"]["agent_id"].as_str().unwrap().into();
    session.agent_id.truncate(32);
    assert!(session_context_v2_bytes(&session).is_err());
    session.agent_id = vector["input"]["agent_id"].as_str().unwrap().into();
    session.request_hash = vec![0; 31];
    assert!(session_context_v2_bytes(&session).is_err());
}

#[test]
fn operation_context_length_prefixes_prevent_boundary_collisions() {
    let left = OperationContextV2 {
        required_scope: "data:read".into(),
        operation: "records.get".into(),
        resource_id: "r1".into(),
        requested_path: "/records/1".into(),
        payload_digest: Vec::new(),
    };
    let right = OperationContextV2 {
        resource_id: "r1/records".into(),
        requested_path: "/1".into(),
        ..left.clone()
    };
    assert_ne!(operation_context_v2_hash(&left).unwrap(), operation_context_v2_hash(&right).unwrap());
}
