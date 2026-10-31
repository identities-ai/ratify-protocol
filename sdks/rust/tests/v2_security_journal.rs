//! testvectors/v2/security-journal.json, mirroring Go
//! `TestV2ConformanceSecurityJournal` (v2_conformance_partb_test.go).

mod v2_status_common;

use ratify_protocol::v2::reference::JournalStore;
use ratify_protocol::v2::{
    apply_revocation_list_to_journal_v2, apply_revocation_push_to_journal_v2,
    configure_status_key_epoch_v2, decode_revocation_list_v2, decode_revocation_push_v2,
    decode_security_journal_json_v2, empty_security_journal_v2, encode_security_journal_json_v2,
    export_security_journal_snapshot_v2, import_security_journal_snapshot_v2,
    migrate_security_journal_v2, record_security_key_role_v2, security_journal_snapshot_digest_v2,
    validate_security_journal_transition_v2, SecurityJournalHeadV2, SecurityJournalStoreV2,
    V2Context, V2Result,
};
use serde_json::Value;
use sha2::{Digest, Sha384};
use v2_status_common::{i, load_v2_vector, policy, public_key_json, readme_line, s, u, unb64};

fn head(v: &Value) -> SecurityJournalHeadV2 {
    SecurityJournalHeadV2 {
        generation: u(&v["generation"]),
        digest: s(&v["digest"]),
    }
}

#[test]
fn v2_conformance_security_journal() {
    let f = load_v2_vector("security-journal.json");
    let ctx = V2Context::background();

    // Genesis snapshot and digest.
    let genesis = empty_security_journal_v2();
    let snapshot = export_security_journal_snapshot_v2(&genesis).expect("export genesis");
    assert_eq!(
        String::from_utf8(snapshot.clone()).expect("utf8"),
        s(&f["genesis_snapshot"])
    );
    assert_eq!(genesis.digest, s(&f["genesis_digest"]));
    assert_eq!(
        security_journal_snapshot_digest_v2(&snapshot),
        s(&f["genesis_digest"])
    );

    // Transition scenarios.
    let (mut scenarios, mut steps) = (0usize, 0usize);
    for sc in f["scenarios"].as_array().expect("scenarios") {
        let name = s(&sc["name"]);
        let store = JournalStore::new().expect("store");
        for (n, step) in sc["steps"].as_array().expect("steps").iter().enumerate() {
            steps += 1;
            let before = store.head();
            let op = s(&step["op"]);
            let key = public_key_json(&step["key"]["public_key"]);
            let issuer_id = s(&step["issuer_id"]);
            let epoch = u(&step["epoch"]);
            let result: V2Result<_> = match op.as_str() {
                "record_key_role" => {
                    record_security_key_role_v2(&ctx, &store, &s(&step["role"]), &key).map(|_| ())
                }
                "configure_status_key_epoch" => {
                    configure_status_key_epoch_v2(&ctx, &store, &issuer_id, epoch, &key).map(|_| ())
                }
                "apply_revocation_list" => {
                    let list =
                        decode_revocation_list_v2(&unb64(&step["wire_b64"])).expect("decode list");
                    apply_revocation_list_to_journal_v2(
                        &ctx,
                        &store,
                        &list,
                        &issuer_id,
                        epoch,
                        &key,
                        &policy(&step["policy"]),
                        i(&step["now"]),
                    )
                    .map(|_| ())
                }
                "apply_revocation_push" => {
                    let push =
                        decode_revocation_push_v2(&unb64(&step["wire_b64"])).expect("decode push");
                    apply_revocation_push_to_journal_v2(
                        &ctx,
                        &store,
                        &push,
                        &issuer_id,
                        epoch,
                        &key,
                        &policy(&step["policy"]),
                        i(&step["now"]),
                    )
                    .map(|_| ())
                }
                other => panic!("unknown op {other}"),
            };
            let expect_rejected = step["expect_rejected"].as_bool().unwrap_or(false);
            assert_eq!(
                result.is_err(),
                expect_rejected,
                "{name} step {n} {op}: {result:?}"
            );
            let after = store.head();
            let expect_changed = step["expect_changed"].as_bool().unwrap_or(false);
            assert_eq!(
                after != before,
                expect_changed,
                "{name} step {n} {op}: changed"
            );
            assert_eq!(
                after,
                head(&step["expect_head"]),
                "{name} step {n} {op}: head"
            );
            let (journal, _) = store.load(&ctx).expect("load");
            let got = export_security_journal_snapshot_v2(&journal).expect("export");
            assert_eq!(
                String::from_utf8_lossy(&got),
                String::from_utf8_lossy(&unb64(&step["expect_snapshot_b64"])),
                "{name} step {n} {op}: snapshot"
            );
            assert_eq!(
                security_journal_snapshot_digest_v2(&got),
                after.digest,
                "{name} step {n}"
            );
        }
        scenarios += 1;
    }
    assert_eq!((scenarios, steps), (2, 17));

    // Version 1 migration.
    let m = &f["migration"];
    let input = unb64(&m["legacy_digest_input_b64"]);
    assert_eq!(
        hex::encode(Sha384::digest(&input)),
        s(&m["legacy_digest"]),
        "legacy digest is not SHA-384 of its input"
    );
    let legacy = decode_security_journal_json_v2(&unb64(&m["legacy_record_b64"]))
        .expect("decode legacy record");
    // The Go encoding/json re-encoding with an empty digest is exactly the
    // legacy digest input.
    let mut cleared = legacy.clone();
    cleared.digest = String::new();
    assert_eq!(
        String::from_utf8(encode_security_journal_json_v2(&cleared).expect("encode legacy"))
            .expect("utf8"),
        String::from_utf8(input).expect("utf8")
    );
    let migrated = migrate_security_journal_v2(&legacy).expect("migrate");
    let snapshot = export_security_journal_snapshot_v2(&migrated).expect("export migrated");
    assert_eq!(
        SecurityJournalHeadV2 {
            generation: migrated.generation,
            digest: migrated.digest.clone()
        },
        head(&m["expect_head"])
    );
    assert_eq!(migrated.previous_digest, s(&m["expect_previous_digest"]));
    assert_eq!(snapshot, unb64(&m["expect_snapshot_b64"]));
    let tampered = decode_security_journal_json_v2(&unb64(&m["tampered_legacy_record_b64"]))
        .expect("decode tampered record");
    assert!(
        migrate_security_journal_v2(&tampered).is_err(),
        "migrated a tampered legacy record"
    );
    let migrations = 1usize;

    // Import negatives.
    let mut negatives = 0usize;
    for neg in f["import_negatives"].as_array().expect("import_negatives") {
        let name = s(&neg["name"]);
        let e =
            import_security_journal_snapshot_v2(&unb64(&neg["snapshot_b64"]), &head(&neg["head"]))
                .err()
                .unwrap_or_else(|| panic!("import_{name} accepted"));
        assert_eq!(
            e.class.as_str(),
            s(&neg["expect_error_class"]),
            "import_{name}: {e}"
        );
        negatives += 1;
    }
    assert_eq!((migrations, negatives), (1, 20));

    // Transition negatives: valid snapshot pairs whose transition fails.
    let mut transitions = 0usize;
    for neg in f["transition_negatives"]
        .as_array()
        .expect("transition_negatives")
    {
        let name = s(&neg["name"]);
        let current = import_security_journal_snapshot_v2(
            &unb64(&neg["current_snapshot_b64"]),
            &head(&neg["current_head"]),
        )
        .unwrap_or_else(|e| panic!("transition_{name}: current snapshot: {e}"));
        let next = import_security_journal_snapshot_v2(
            &unb64(&neg["next_snapshot_b64"]),
            &head(&neg["next_head"]),
        )
        .unwrap_or_else(|e| panic!("transition_{name}: next snapshot: {e}"));
        let e = validate_security_journal_transition_v2(&current, &next)
            .err()
            .unwrap_or_else(|| panic!("transition_{name} accepted"));
        assert_eq!(
            e.class.as_str(),
            s(&neg["expect_error_class"]),
            "transition_{name}: {e}"
        );
        transitions += 1;
    }
    assert_eq!(transitions, 6);
    let readme = readme_line("security-journal.json");
    assert!(
        readme.contains(&format!("{scenarios} transition scenarios ({steps} steps"))
            && readme.contains(&format!("{negatives} import negatives"))
            && readme.contains(&format!("{transitions} `transition_negatives`")),
        "README disagrees: {readme}"
    );
}
