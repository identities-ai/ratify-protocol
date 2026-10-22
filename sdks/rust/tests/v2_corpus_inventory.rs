//! Every entry of testvectors/v2 (and every fixture in its cross-sdk
//! directory) must have a Rust runner. A new corpus file, a new cross-SDK
//! fixture, or a runner that stops reading its file fails here until the
//! Rust SDK consumes it.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

/// Each corpus entry, the test source that consumes it, and the text that
/// source must contain to show it does (the file name, or for the
/// external-mu script the Rust test that performs the same derivation).
const CONSUMED: &[(&str, &str, &str)] = &[
    ("README.md", "v2_verifier_ordering.rs", "readme_line("),
    ("annex-a.json", "v2_annex_a.rs", "annex-a.json"),
    ("archival.json", "v2_archival_signer.rs", "archival.json"),
    ("challenge-claim.json", "challenge_claim_v2.rs", "challenge-claim.json"),
    ("challenge-issuance.json", "v2_challenge_issuance.rs", "challenge-issuance.json"),
    ("cross-sdk", "v2_cross_sdk.rs", "\"cross-sdk\""),
    ("delegation-signature.json", "v2_crypto.rs", "delegation-signature.json"),
    ("device-state.json", "v2_device_state.rs", "device-state.json"),
    ("digest-functions.json", "v2_archival_signer.rs", "digest-functions.json"),
    ("derive-external-mu.py", "v2_crypto.rs", "fn v2_external_mu_matches_shared_signature_vector"),
    ("evaluator-profiles.json", "v2_issuance_profiles.rs", "evaluator-profiles.json"),
    ("external-signer.json", "v2_archival_signer.rs", "external-signer.json"),
    ("hedged-signatures.json", "v2_objects.rs", "hedged-signatures.json"),
    ("issuer-duties.json", "v2_issuance_profiles.rs", "issuer-duties.json"),
    ("key-rotation-signature.json", "v2_logs.rs", "key-rotation-signature.json"),
    ("keys.json", "v2_status_common/mod.rs", "keys.json"),
    ("lifecycle-scenarios.json", "v2_lifecycle.rs", "lifecycle-scenarios.json"),
    ("limits.json", "v2_objects.rs", "limits.json"),
    ("log-sequences.json", "v2_logs.rs", "log-sequences.json"),
    ("object-negatives.json", "v2_objects.rs", "object-negatives.json"),
    ("objects.json", "v2_objects.rs", "objects.json"),
    ("operation-session-context.json", "operation_context_v2.rs", "operation-session-context.json"),
    ("rotation-sequences.json", "v2_logs.rs", "rotation-sequences.json"),
    ("security-journal.json", "v2_security_journal.rs", "security-journal.json"),
    ("status-publisher.json", "v2_status_publisher.rs", "status-publisher.json"),
    ("status-sequences.json", "v2_status_sequences.rs", "status-sequences.json"),
    ("transaction-verification.json", "v2_transaction_verification.rs", "transaction-verification.json"),
    ("verifier-ordering.json", "v2_verifier_ordering.rs", "verifier-ordering.json"),
];

/// The cross-SDK fixtures `v2_cross_sdk_fixtures` must verify.
const CROSS_SDK_FIXTURES: &[&str] = &["c.json", "go.json", "python.json", "rust.json", "typescript.json"];

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn names(dir: PathBuf) -> BTreeSet<String> {
    fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

#[test]
fn every_v2_corpus_entry_has_a_rust_runner() {
    let corpus = manifest().join("../../testvectors/v2");
    let present = names(corpus.clone());
    let consumed: BTreeSet<String> = CONSUMED.iter().map(|(f, _, _)| f.to_string()).collect();
    let unknown: Vec<_> = present.difference(&consumed).collect();
    let missing: Vec<_> = consumed.difference(&present).collect();
    assert!(unknown.is_empty(), "corpus entries with no Rust runner: {unknown:?}");
    assert!(missing.is_empty(), "runner expects entries that are absent: {missing:?}");
    for (file, source, marker) in CONSUMED {
        let path = manifest().join("tests").join(source);
        let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert!(text.contains(marker), "{source} no longer consumes {file} (missing {marker:?})");
    }
    let fixtures = names(corpus.join("cross-sdk"));
    let expected: BTreeSet<String> = CROSS_SDK_FIXTURES.iter().map(|s| s.to_string()).collect();
    assert_eq!(fixtures, expected, "cross-sdk fixtures differ from those v2_cross_sdk_fixtures requires");
    let cross = fs::read_to_string(manifest().join("tests/v2_cross_sdk.rs")).unwrap();
    for fixture in CROSS_SDK_FIXTURES {
        let stem = fixture.trim_end_matches(".json");
        assert!(cross.contains(&format!("\"{stem}\"")), "v2_cross_sdk.rs does not require {fixture}");
    }
}
