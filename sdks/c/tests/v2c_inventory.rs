//! Every entry of testvectors/v2 must be consumed by a C-ABI runner
//! (`tests/v2c_*.rs`, which call only `ratify_v2_*` exports). A new corpus
//! file, or a runner that stops reading its file, fails here until the C ABI
//! runs it. Cross-SDK fixtures are verified generically by
//! `tests/v2c_cross_sdk.rs`, which reads every file in `cross-sdk/`.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

/// Each corpus entry, the C-ABI runner that consumes it, and the text that
/// runner must contain to show it does.
const CONSUMED: &[(&str, &str, &str)] = &[
    ("README.md", "v2c_verifier.rs", "readme_line("),
    ("annex-a.json", "v2c_objects.rs", "\"annex-a.json\""),
    (
        "challenge-claim.json",
        "v2c_objects.rs",
        "\"challenge-claim.json\"",
    ),
    (
        "challenge-issuance.json",
        "v2c_issuance.rs",
        "\"challenge-issuance.json\"",
    ),
    ("cross-sdk", "v2c_cross_sdk.rs", "\"cross-sdk\""),
    (
        "delegation-signature.json",
        "v2c_objects.rs",
        "\"delegation-signature.json\"",
    ),
    (
        "derive-external-mu.py",
        "v2c_objects.rs",
        "fn v2c_external_mu_matches_shared_signature_vector",
    ),
    (
        "device-state.json",
        "v2c_device_state.rs",
        "\"device-state.json\"",
    ),
    (
        "evaluator-profiles.json",
        "v2c_objects.rs",
        "\"evaluator-profiles.json\"",
    ),
    (
        "hedged-signatures.json",
        "v2c_objects.rs",
        "\"hedged-signatures.json\"",
    ),
    (
        "issuer-duties.json",
        "v2c_objects.rs",
        "\"issuer-duties.json\"",
    ),
    (
        "key-rotation-signature.json",
        "v2c_objects.rs",
        "\"key-rotation-signature.json\"",
    ),
    ("keys.json", "v2c_common/mod.rs", "\"keys.json\""),
    (
        "lifecycle-scenarios.json",
        "v2c_lifecycle.rs",
        "\"lifecycle-scenarios.json\"",
    ),
    ("limits.json", "v2c_objects.rs", "\"limits.json\""),
    (
        "log-sequences.json",
        "v2c_logs.rs",
        "\"log-sequences.json\"",
    ),
    (
        "object-negatives.json",
        "v2c_objects.rs",
        "\"object-negatives.json\"",
    ),
    ("objects.json", "v2c_objects.rs", "\"objects.json\""),
    (
        "operation-session-context.json",
        "v2c_objects.rs",
        "\"operation-session-context.json\"",
    ),
    (
        "rotation-sequences.json",
        "v2c_logs.rs",
        "\"rotation-sequences.json\"",
    ),
    (
        "security-journal.json",
        "v2c_status.rs",
        "\"security-journal.json\"",
    ),
    (
        "status-publisher.json",
        "v2c_status.rs",
        "\"status-publisher.json\"",
    ),
    (
        "status-sequences.json",
        "v2c_status.rs",
        "\"status-sequences.json\"",
    ),
    (
        "transaction-verification.json",
        "v2c_verifier.rs",
        "\"transaction-verification.json\"",
    ),
    (
        "verifier-ordering.json",
        "v2c_verifier.rs",
        "\"verifier-ordering.json\"",
    ),
];

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn every_v2_corpus_entry_has_a_c_abi_runner() {
    let corpus = manifest().join("../../testvectors/v2");
    let present: BTreeSet<String> = fs::read_dir(&corpus)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    let consumed: BTreeSet<String> = CONSUMED.iter().map(|(f, _, _)| f.to_string()).collect();
    let unknown: Vec<_> = present.difference(&consumed).collect();
    let missing: Vec<_> = consumed.difference(&present).collect();
    assert!(
        unknown.is_empty(),
        "corpus entries with no C-ABI runner: {unknown:?}"
    );
    assert!(
        missing.is_empty(),
        "C-ABI runner expects entries that are absent: {missing:?}"
    );
    for (file, source, marker) in CONSUMED {
        let path = manifest().join("tests").join(source);
        let text =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert!(
            text.contains(marker),
            "{source} no longer consumes {file} (missing {marker:?})"
        );
        // A runner must never reach around the ABI into the Rust crate.
        assert!(
            !text.contains("ratify_protocol::"),
            "{source} calls the Rust crate directly"
        );
    }
    // The C-ABI runners themselves call only the ABI.
    for e in fs::read_dir(manifest().join("tests")).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let p = if p.is_dir() { p.join("mod.rs") } else { p };
        if name.starts_with("v2c_") && name != "v2c_inventory.rs" && p.is_file() {
            let text = fs::read_to_string(&p).unwrap();
            assert!(
                !text.contains("ratify_protocol"),
                "{name} uses the Rust crate"
            );
        }
    }
    let fixtures: BTreeSet<String> = fs::read_dir(corpus.join("cross-sdk"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        fixtures.contains("c.json"),
        "the C ABI's own cross-SDK fixture is missing"
    );
}
