//! Every UniFFI export must return `FfiResult` and be exactly one call to the
//! panic guard (`call(..)` or `call_on(..)`) as its whole body, so a Rust
//! panic always surfaces as an internal error, never as UniFFI's trapping
//! `try!` path. The sources are parsed with syn, and the set of exports found
//! must equal the set UniFFI generated (one checksum per export in the
//! committed bindings), so an export the scan cannot see also fails.

use std::collections::BTreeSet;
use std::fs;

use quote::ToTokens;
use syn::{Attribute, Block, Expr, ImplItem, Item, ReturnType, Stmt, Type};

fn is_export(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| {
        let p = a.path();
        p.segments.len() == 2 && p.segments[0].ident == "uniffi" && p.segments[1].ident == "export"
    })
}

fn returns_ffi_result(out: &ReturnType) -> bool {
    match out {
        ReturnType::Type(_, t) => match &**t {
            Type::Path(p) => p.path.segments.last().is_some_and(|s| s.ident == "FfiResult"),
            _ => false,
        },
        ReturnType::Default => false,
    }
}

/// The body is a single expression: a call to `call` or `call_on`.
fn guarded(body: &Block) -> bool {
    let [Stmt::Expr(Expr::Call(c), None)] = body.stmts.as_slice() else {
        return false;
    };
    let Expr::Path(p) = &*c.func else { return false };
    p.path.segments.last().is_some_and(|s| s.ident == "call" || s.ident == "call_on")
}

fn check(name: String, sig: &syn::Signature, body: &Block, found: &mut BTreeSet<String>, errors: &mut Vec<String>) {
    if !returns_ffi_result(&sig.output) {
        errors.push(format!("{name}: must return FfiResult"));
    }
    if !guarded(body) {
        errors.push(format!("{name}: body must be one guard::call or guard::call_on"));
    }
    found.insert(name);
}

#[test]
fn every_export_is_fallible_and_guarded() {
    let mut found = BTreeSet::new();
    let mut errors = Vec::new();
    for entry in fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/src")).unwrap() {
        let path = entry.unwrap().path();
        let file = syn::parse_file(&fs::read_to_string(&path).unwrap()).unwrap();
        for item in file.items {
            match item {
                Item::Fn(f) if is_export(&f.attrs) => {
                    check(format!("func_{}", f.sig.ident), &f.sig, &f.block, &mut found, &mut errors)
                }
                Item::Impl(imp) if is_export(&imp.attrs) => {
                    let ty = imp.self_ty.to_token_stream().to_string().to_lowercase();
                    for it in imp.items {
                        if let ImplItem::Fn(m) = it {
                            if !matches!(m.vis, syn::Visibility::Public(_)) {
                                continue;
                            }
                            let ctor = m.attrs.iter().any(|a| a.path().segments.last().is_some_and(|s| s.ident == "constructor"));
                            let kind = if ctor { "constructor" } else { "method" };
                            check(format!("{kind}_{ty}_{}", m.sig.ident), &m.sig, &m.block, &mut found, &mut errors);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    let bindings = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../kotlin/ratify-protocol/src/main/kotlin/com/ratifyprotocol/internal/ffi/ratify_ffi.kt"
    ))
    .unwrap();
    let generated: BTreeSet<String> = bindings
        .split("uniffi_ratify_protocol_ffi_checksum_")
        .skip(1)
        .map(|s| s.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect())
        .collect();
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    assert_eq!(found, generated, "exports found in the sources differ from the exports UniFFI generated");
}
