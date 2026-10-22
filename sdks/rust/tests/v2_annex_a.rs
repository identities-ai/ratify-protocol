//! Annex A corpus (annex-a.json): pinned v1 clauses, canonical JSON and
//! strict-decode cases, and the scope vocabulary, expansion, and
//! intersection rules.

mod v2_common;

use ratify_protocol::v2::{canonical_json_v2, validate_scopes_v2};
use ratify_protocol::{expand_scopes, intersect_scopes, is_sensitive, scope_wildcards, vocabulary};
use serde_json::Value;
use sha2::{Digest, Sha256};
use v2_common::*;

fn strings(v: &Value) -> Vec<String> {
    arr(v).iter().map(s).collect()
}

fn is_canonical_object(input: &[u8]) -> bool {
    input.first() == Some(&b'{') && canonical_json_v2(input).is_ok_and(|c| c == input)
}

#[test]
fn v2_annex_a() {
    let f = load("annex-a.json");
    let mut t = Tally::default();

    let annex = std::fs::read_to_string(corpus_dir().join("../../SPEC-v2-ANNEX-A.md")).expect("annex");
    let lines: Vec<&str> = annex.split('\n').collect();
    for c in arr(&f["clauses"]) {
        let id = s(&c["id"]);
        let begin = lines.iter().position(|l| *l == format!("<!-- annex-a:begin {id} -->"));
        let end = lines.iter().position(|l| *l == format!("<!-- annex-a:end {id} -->"));
        let ok = match (begin, end) {
            (Some(b), Some(e)) if e > b + 1 => {
                let block = lines[b + 1..e].join("\n");
                block.len() as i64 == i(&c["bytes"])
                    && hex::encode(Sha256::digest(block.as_bytes())) == s(&c["sha256"])
                    && annex.contains(&format!("`{}`", s(&c["sha256"])))
            }
            _ => false,
        };
        t.check("clauses", &id, ok, || "clause bytes or digest differ".into());
    }

    for v in arr(&f["canonical_json"]) {
        let input = b64(&v["input_b64"]);
        let got = canonical_json_v2(&input);
        let want = s(&v["canonical"]);
        let canonical_input = is_canonical_object(&input);
        let ok = got.as_ref().is_ok_and(|g| g == want.as_bytes())
            && is_canonical_object(want.as_bytes())
            && canonical_input == v["input_is_canonical"].as_bool().unwrap()
            && canonical_input == (got.as_ref().ok().map(Vec::as_slice) == Some(input.as_slice()));
        t.check("canonical_json", &s(&v["name"]), ok, || format!("{got:?}"));
    }
    for v in arr(&f["strict_decode_rejections"]) {
        let input = b64(&v["input_b64"]);
        t.check("strict_decode_rejections", &s(&v["name"]), canonical_json_v2(&input).is_err(), || {
            format!("{:?} accepted", String::from_utf8_lossy(&input))
        });
    }

    let vocab = &f["vocabulary"];
    let canonical: Vec<String> = strings(&vocab["canonical"]);
    let ours: Vec<String> = vocabulary().into_iter().map(String::from).collect();
    t.check("vocabulary", "canonical", ours == canonical, || format!("{ours:?}"));
    let sensitive: Vec<String> = canonical.iter().filter(|c| is_sensitive(c)).cloned().collect();
    t.check("vocabulary", "sensitive", sensitive == strings(&vocab["sensitive"]), || format!("{sensitive:?}"));
    for c in &canonical {
        t.check("vocabulary", c, validate_scopes_v2(std::slice::from_ref(c)).is_ok(), || "rejected".into());
    }
    let wildcards = vocab["wildcards"].as_object().unwrap();
    t.check("vocabulary", "wildcard count", wildcards.len() == scope_wildcards().len(), || "count".into());
    for (w, want) in wildcards {
        let got = expand_scopes(std::slice::from_ref(w));
        let want = strings(want);
        t.check("wildcards", w, got == want && want.iter().all(|x| !is_sensitive(x)), || format!("{got:?}"));
    }
    for v in arr(&f["scope_validation"]) {
        let valid = validate_scopes_v2(&strings(&v["scopes"])).is_ok();
        t.check("scope_validation", &s(&v["name"]), valid == v["valid"].as_bool().unwrap(), || {
            format!("valid={valid}")
        });
    }
    for v in arr(&f["scope_expansion"]) {
        let got = expand_scopes(&strings(&v["scopes"]));
        t.check("scope_expansion", &s(&v["name"]), got == strings(&v["expanded"]), || format!("{got:?}"));
    }
    for v in arr(&f["scope_intersection"]) {
        let lists: Vec<Vec<String>> = arr(&v["lists"]).iter().map(strings).collect();
        let refs: Vec<&[String]> = lists.iter().map(Vec::as_slice).collect();
        let got = intersect_scopes(&refs);
        t.check("scope_intersection", &s(&v["name"]), got == strings(&v["effective"]), || format!("{got:?}"));
    }
    t.finish(&[
        ("clauses", 3),
        ("canonical_json", 8),
        ("strict_decode_rejections", 16),
        ("vocabulary", 54 + 3),
        ("wildcards", 14),
        ("scope_validation", 17),
        ("scope_expansion", 6),
        ("scope_intersection", 8),
    ]);
}
