//! The v2 error enum is exactly the closed SPEC-v2 §2.7 list: every
//! backticked class in the first column of the §2.7 table, in table order,
//! and nothing else.

use std::path::PathBuf;

use ratify_protocol::v2::V2ErrorClass;

fn spec_classes() -> Vec<String> {
    let spec = std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../SPEC-v2.md"))
        .expect("read SPEC-v2.md");
    let section = spec
        .split("\n### 2.7 Error classes")
        .nth(1)
        .expect("§2.7 heading")
        .split("\n## ")
        .next()
        .expect("§2.7 body");
    let mut classes = Vec::new();
    let mut in_table = false;
    for line in section.lines() {
        if line.starts_with("| Class |") {
            in_table = true;
            continue;
        }
        if !in_table {
            continue;
        }
        if !line.starts_with('|') {
            break;
        }
        let first = line.trim_start_matches('|').split('|').next().unwrap_or_default();
        if first.trim().starts_with("---") {
            continue;
        }
        let mut rest = first;
        while let Some(start) = rest.find('`') {
            let after = &rest[start + 1..];
            let end = after.find('`').expect("closing backtick");
            classes.push(after[..end].to_string());
            rest = &after[end + 1..];
        }
    }
    classes
}

#[test]
fn error_enum_is_exactly_the_spec_table() {
    let spec = spec_classes();
    assert_eq!(spec.len(), 49, "SPEC-v2 §2.7 lists 49 classes: {spec:?}");
    let mut sorted_spec = spec.clone();
    sorted_spec.sort();
    sorted_spec.dedup();
    assert_eq!(sorted_spec.len(), 49, "no class is listed twice");
    let ours: Vec<String> = V2ErrorClass::ALL.iter().map(|c| c.as_str().to_string()).collect();
    let mut sorted_ours = ours.clone();
    sorted_ours.sort();
    assert_eq!(sorted_ours, sorted_spec);
    for class in V2ErrorClass::ALL {
        assert_eq!(V2ErrorClass::parse(class.as_str()), Some(*class));
    }
    assert_eq!(V2ErrorClass::parse("unclassified"), None);
}
