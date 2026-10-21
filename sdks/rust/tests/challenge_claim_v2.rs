use ratify_protocol::{
    challenge_claim_digest_v2, protocol_claim_id_from_digest_v2, protocol_claim_id_v2,
};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../../testvectors/v2/challenge-claim.json")).unwrap()
}

#[test]
fn claim_identifiers_match_shared_go_vectors() {
    let vector = fixture();
    let challenge = hex::decode(vector["challenge_hex"].as_str().unwrap()).unwrap();
    let digest = challenge_claim_digest_v2(&challenge).unwrap();
    assert_eq!(
        hex::encode(&digest),
        vector["expected_challenge_claim_digest_hex"]
            .as_str()
            .unwrap()
    );
    let primary = &vector["claim_id_input"];
    let namespace = primary["verifier_namespace"].as_str().unwrap();
    let epoch = primary["replay_epoch"].as_u64().unwrap();
    assert_eq!(
        protocol_claim_id_v2(namespace, epoch, &challenge).unwrap(),
        vector["expected_claim_id"].as_str().unwrap()
    );
    assert_eq!(
        protocol_claim_id_from_digest_v2(namespace, epoch, &digest).unwrap(),
        vector["expected_claim_id"].as_str().unwrap()
    );
    for item in vector["additional_claim_id_cases"].as_array().unwrap() {
        let namespace = item["verifier_namespace"].as_str().unwrap();
        let epoch = item["replay_epoch"].as_u64().unwrap();
        assert_eq!(
            protocol_claim_id_v2(namespace, epoch, &challenge).unwrap(),
            item["expected_claim_id"].as_str().unwrap()
        );
        assert_eq!(
            protocol_claim_id_from_digest_v2(namespace, epoch, &digest).unwrap(),
            item["expected_claim_id"].as_str().unwrap()
        );
    }
}

#[test]
fn claim_identifiers_reject_bad_lengths_and_epochs() {
    for len in [0, 31, 33] {
        assert!(challenge_claim_digest_v2(&vec![0; len]).is_err());
    }
    let challenge = [0u8; 32];
    assert!(protocol_claim_id_v2("", 7, &challenge).is_err());
    assert!(protocol_claim_id_v2("verify-prod", 1 << 53, &challenge).is_err());
    for len in [0, 47, 49] {
        assert!(protocol_claim_id_from_digest_v2("verify-prod", 7, &vec![0; len]).is_err());
    }
}
