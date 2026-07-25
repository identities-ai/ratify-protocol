// Vocabulary parity tests — the public scope vocabulary accessors must
// match the Go reference's Vocabulary(): 54 canonical scopes, sorted
// lexicographically, returned as fresh copies.

use ratify_protocol::{
    expand_scopes, is_sensitive, scope_wildcards, validate_scopes, vocabulary,
    SCOPE_PRESENCE_REPRESENT,
};

#[test]
fn vocabulary_54_entries_sorted_all_canonical() {
    let v = vocabulary();
    assert_eq!(v.len(), 54, "canonical vocabulary size drift");
    let mut sorted = v.clone();
    sorted.sort_unstable();
    assert_eq!(v, sorted, "vocabulary must be lex-sorted");
    let dedup: std::collections::BTreeSet<_> = v.iter().collect();
    assert_eq!(dedup.len(), v.len(), "vocabulary must not contain duplicates");
    assert!(v.contains(&SCOPE_PRESENCE_REPRESENT));
    // Every entry is a valid canonical scope.
    let owned: Vec<String> = v.iter().map(|s| s.to_string()).collect();
    assert_eq!(validate_scopes(&owned), None);
}

#[test]
fn vocabulary_returns_fresh_copy() {
    let mut v = vocabulary();
    v[0] = "tampered:scope";
    assert_ne!(vocabulary()[0], "tampered:scope");
}

#[test]
fn scope_wildcards_expansions_are_non_sensitive_vocabulary_members() {
    let wildcards = scope_wildcards();
    let vocab: std::collections::BTreeSet<_> = vocabulary().into_iter().collect();
    assert_eq!(wildcards.len(), 14, "wildcard count drift");
    for (wildcard, children) in &wildcards {
        assert!(wildcard.ends_with(":*"), "{wildcard} must end with \":*\"");
        assert!(!children.is_empty(), "{wildcard} must expand to something");
        for c in *children {
            assert!(vocab.contains(c), "{wildcard} expands to unknown scope {c}");
            assert!(!is_sensitive(c), "{wildcard} must not expand to sensitive {c}");
        }
        // The map agrees with expand_scopes.
        let mut expected: Vec<String> = children.iter().map(|s| s.to_string()).collect();
        expected.sort_unstable();
        assert_eq!(expand_scopes(&[wildcard.to_string()]), expected);
    }
}
