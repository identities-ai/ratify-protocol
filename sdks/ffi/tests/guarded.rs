//! Every UniFFI export must return `FfiResult` and run its body through the
//! panic guard (`guard::call` or `guard::call_on`), so a Rust panic always
//! surfaces as an internal error, never as UniFFI's trapping `try!` path. A
//! new export that skips the guard fails here.

use std::fs;

fn bodies(src: &str) -> Vec<(String, String)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim() == "#[uniffi::export]" {
            let next = lines[i + 1].trim_start();
            if next.starts_with("impl ") {
                // An exported impl block: every `pub fn` up to the closing `}` at column 0.
                let mut j = i + 2;
                while j < lines.len() && lines[j] != "}" {
                    if lines[j].trim_start().starts_with("pub fn ") {
                        out.push(function(&lines, j));
                    }
                    j += 1;
                }
                i = j;
            } else if next.starts_with("pub fn ") {
                out.push(function(&lines, i + 1));
            }
        }
        i += 1;
    }
    out
}

/// The signature and body of the function starting at `start`.
fn function(lines: &[&str], start: usize) -> (String, String) {
    let indent = lines[start].len() - lines[start].trim_start().len();
    let close = format!("{}}}", " ".repeat(indent));
    let mut end = start;
    while lines[end] != close {
        end += 1;
    }
    (lines[start].trim().to_string(), lines[start..=end].join("\n"))
}

#[test]
fn every_export_is_fallible_and_guarded() {
    let mut n = 0;
    for entry in fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/src")).unwrap() {
        let path = entry.unwrap().path();
        let src = fs::read_to_string(&path).unwrap();
        for (sig, body) in bodies(&src) {
            n += 1;
            let name = path.file_name().unwrap().to_string_lossy();
            assert!(body.contains("-> FfiResult<"), "{name}: `{sig}` must return FfiResult");
            assert!(
                body.contains("call(") || body.contains("call_on("),
                "{name}: `{sig}` must run its body through guard::call or guard::call_on"
            );
        }
    }
    // Every export in this crate today (keeps the scan itself from going vacuous).
    assert!(n >= 27, "found only {n} exports; the scanner missed some");
}
