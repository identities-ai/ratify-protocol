// Operation-context / session-context construction tests (SPEC §6.4.9).
// The known-answer hex values are duplicated across all five SDK test
// suites so the implementations provably produce byte-identical hashes.

use ratify_protocol::{
    build_session_context, hex_encode, operation_context_hash, OperationContext,
    SessionContextInputs,
};

const KAT_EMPTY_OPERATION_HASH: &str =
    "d135e239f4a5a5a0ad6385b204d6c81f3c10e6b2f5debfa3cc8079488970f82f";
const KAT_FULL_OPERATION_HASH: &str =
    "6b70b5f404f61624ab2379fee2756639d8629141ecb3593b53e5a22346e0c3e5";
const KAT_SESSION_CONTEXT: &str =
    "788c692b5dafae52dd896eb5f7580f61d42b8c7a2abeed4d4eea9dcd4d7d4dfd";

fn full_operation() -> OperationContext {
    OperationContext {
        required_scope: "files:write".into(),
        operation: "git.push".into(),
        resource_id: "git:github.com/acme/api".into(),
        requested_path: "/src/handlers".into(),
        payload_digest: vec![0xAB; 32],
    }
}

fn session_inputs() -> SessionContextInputs {
    SessionContextInputs {
        verifier_id: "verifier-1".into(),
        workspace_id: "ws-42".into(),
        agent_id: "agent-7".into(),
        session_id: "sess-9".into(),
        invocation_id: "inv-3".into(),
        request_hash: operation_context_hash(&full_operation()).unwrap(),
    }
}

#[test]
fn known_answers_match_the_go_reference() {
    let empty = operation_context_hash(&OperationContext::default()).unwrap();
    assert_eq!(hex_encode(&empty), KAT_EMPTY_OPERATION_HASH);

    let full = operation_context_hash(&full_operation()).unwrap();
    assert_eq!(hex_encode(&full), KAT_FULL_OPERATION_HASH);

    let session = build_session_context(&session_inputs()).unwrap();
    assert_eq!(session.len(), 32);
    assert_eq!(hex_encode(&session), KAT_SESSION_CONTEXT);
}

#[test]
fn length_prefixing_disambiguates_shifted_boundaries() {
    let a = operation_context_hash(&OperationContext {
        operation: "ab".into(),
        resource_id: "c".into(),
        ..OperationContext::default()
    })
    .unwrap();
    let b = operation_context_hash(&OperationContext {
        operation: "a".into(),
        resource_id: "bc".into(),
        ..OperationContext::default()
    })
    .unwrap();
    assert_ne!(a, b);
}

#[test]
fn domain_separation_between_the_two_constructions() {
    let op_hash = operation_context_hash(&OperationContext::default()).unwrap();
    let session = build_session_context(&SessionContextInputs {
        request_hash: op_hash.clone(),
        ..SessionContextInputs::default()
    })
    .unwrap();
    assert_ne!(op_hash, session);
}

#[test]
fn input_validation() {
    let err = operation_context_hash(&OperationContext {
        payload_digest: vec![0u8; 5],
        ..OperationContext::default()
    })
    .unwrap_err();
    assert!(err.contains("payload digest"), "{err}");

    let err = build_session_context(&SessionContextInputs::default()).unwrap_err();
    assert!(err.contains("request hash"), "{err}");

    let err = build_session_context(&SessionContextInputs {
        request_hash: vec![0u8; 16],
        ..SessionContextInputs::default()
    })
    .unwrap_err();
    assert!(err.contains("request hash"), "{err}");
}

#[test]
fn every_field_is_load_bearing() {
    let base = operation_context_hash(&full_operation()).unwrap();
    let mut mutations = Vec::new();
    let mut m = full_operation();
    m.required_scope = "files:read".into();
    mutations.push(m);
    let mut m = full_operation();
    m.operation = "git.pull".into();
    mutations.push(m);
    let mut m = full_operation();
    m.resource_id = "git:github.com/acme/api2".into();
    mutations.push(m);
    let mut m = full_operation();
    m.requested_path = "/src".into();
    mutations.push(m);
    let mut m = full_operation();
    m.payload_digest = vec![0xAC; 32];
    mutations.push(m);
    for (i, m) in mutations.iter().enumerate() {
        assert_ne!(
            operation_context_hash(m).unwrap(),
            base,
            "operation mutation {i} not bound"
        );
    }

    let session_base = build_session_context(&session_inputs()).unwrap();
    let other_hash = operation_context_hash(&OperationContext {
        operation: "other".into(),
        ..OperationContext::default()
    })
    .unwrap();
    let mut mutations = Vec::new();
    let mut s = session_inputs();
    s.verifier_id = "verifier-2".into();
    mutations.push(s);
    let mut s = session_inputs();
    s.workspace_id = "ws-43".into();
    mutations.push(s);
    let mut s = session_inputs();
    s.agent_id = "agent-8".into();
    mutations.push(s);
    let mut s = session_inputs();
    s.session_id = "sess-10".into();
    mutations.push(s);
    let mut s = session_inputs();
    s.invocation_id = "inv-4".into();
    mutations.push(s);
    let mut s = session_inputs();
    s.request_hash = other_hash;
    mutations.push(s);
    for (i, s) in mutations.iter().enumerate() {
        assert_ne!(
            build_session_context(s).unwrap(),
            session_base,
            "session mutation {i} not bound"
        );
    }
}
