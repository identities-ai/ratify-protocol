//! Every UniFFI export must return `FfiResult` and be exactly one call to the
//! panic guard (`call(..)`, `call_on(..)`, or `call_with(..)`) as its whole body, so a Rust
//! panic always surfaces as an internal error, never as UniFFI's trapping
//! `try!` path. The sources are parsed with syn, and the set of exports found
//! must equal the set UniFFI generated (one checksum per export in the
//! committed bindings), so an export the scan cannot see also fails.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use quote::ToTokens;
use syn::{Attribute, Block, Expr, FnArg, GenericArgument, ImplItem, Item, PathArguments, ReturnType, Stmt, Type};

fn token_in_type(ty: &Type, records: &BTreeMap<String, Vec<Type>>, visiting: &mut BTreeSet<String>) -> usize {
    fn capped_sum(values: impl IntoIterator<Item = usize>) -> usize {
        values.into_iter().fold(0usize, |sum, next| sum.saturating_add(next).min(2))
    }
    match ty {
        Type::Path(path) => path.path.segments.last().map_or(0, |segment| {
            let name = segment.ident.to_string();
            if name == "FfiEvaluationToken" { return 1; }
            if !visiting.insert(name.clone()) { return 0; }
            let fields = records.get(&name).map_or(0, |fields|
                capped_sum(fields.iter().map(|field| token_in_type(field, records, visiting))));
            visiting.remove(&name);
            let generic = match &segment.arguments {
                PathArguments::AngleBracketed(args) => capped_sum(args.args.iter().filter_map(|arg|
                    match arg { GenericArgument::Type(inner) => Some(token_in_type(inner, records, visiting)), _ => None })),
                PathArguments::Parenthesized(args) => {
                    let inputs = capped_sum(args.inputs.iter().map(|input| token_in_type(input, records, visiting)));
                    let output = match &args.output {
                        ReturnType::Type(_, output) => token_in_type(output, records, visiting),
                        ReturnType::Default => 0,
                    };
                    inputs.saturating_add(output).min(2)
                }
                PathArguments::None => 0,
            };
            let count = fields.saturating_add(generic).min(2);
            if count > 0 && !matches!(name.as_str(), "Arc" | "Box" | "Option" | "Pin")
                && !records.contains_key(&name) { 2 } else { count }
        }),
        Type::Reference(r) => token_in_type(&r.elem, records, visiting),
        Type::Ptr(p) => token_in_type(&p.elem, records, visiting),
        Type::Tuple(t) => capped_sum(t.elems.iter().map(|item| token_in_type(item, records, visiting))),
        Type::Array(a) => usize::from(token_in_type(&a.elem, records, visiting) > 0) * 2,
        Type::Slice(s) => usize::from(token_in_type(&s.elem, records, visiting) > 0) * 2,
        Type::Paren(p) => token_in_type(&p.elem, records, visiting),
        Type::Group(g) => token_in_type(&g.elem, records, visiting),
        _ => 0,
    }
}

fn token_count(sig: &syn::Signature, owner: Option<&Type>, records: &BTreeMap<String, Vec<Type>>) -> usize {
    let self_token = owner.is_some_and(|ty| token_in_type(ty, records, &mut BTreeSet::new()) > 0);
    let inputs = sig.inputs.iter().filter_map(|arg| match arg {
        FnArg::Typed(typed) => Some(token_in_type(&typed.ty, records, &mut BTreeSet::new())),
        FnArg::Receiver(_) => None,
    }).fold(0usize, |sum, next| sum.saturating_add(next).min(2));
    (usize::from(self_token) + inputs).min(2)
}

fn collect_types(items: &[Item], records: &mut BTreeMap<String, Vec<Type>>, errors: &mut Vec<String>) {
    fn insert(name: String, fields: Vec<Type>, records: &mut BTreeMap<String, Vec<Type>>,
              errors: &mut Vec<String>) {
        if records.insert(name.clone(), fields).is_some() {
            errors.push(format!("ambiguous FFI type name {name} in guard reachability scan"));
        }
    }
    fn aliases(tree: &syn::UseTree, records: &mut BTreeMap<String, Vec<Type>>, errors: &mut Vec<String>) {
        match tree {
            syn::UseTree::Rename(rename) if rename.ident.to_string().starts_with("Ffi") => {
                let target = &rename.ident;
                insert(rename.rename.to_string(), vec![syn::parse_quote!(#target)], records, errors);
            }
            syn::UseTree::Path(path) => aliases(&path.tree, records, errors),
            syn::UseTree::Group(group) => for item in &group.items { aliases(item, records, errors); },
            _ => {}
        }
    }
    for item in items {
        match item {
            Item::Struct(s) => insert(s.ident.to_string(), s.fields.iter().map(|f| f.ty.clone()).collect(), records, errors),
            Item::Enum(e) => insert(e.ident.to_string(), e.variants.iter()
                .flat_map(|v| v.fields.iter().map(|f| f.ty.clone())).collect(), records, errors),
            Item::Type(t) => insert(t.ident.to_string(), vec![*t.ty.clone()], records, errors),
            Item::Use(u) => aliases(&u.tree, records, errors),
            Item::Mod(m) => if let Some((_, inner)) = &m.content { collect_types(inner, records, errors); },
            _ => {}
        }
    }
}

fn is_export(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| {
        let p = a.path();
        p.segments.len() == 2 && p.segments[0].ident == "uniffi" && p.segments[1].ident == "export"
    })
}

fn returns_ffi_result(out: &ReturnType) -> bool {
    match out {
        ReturnType::Type(_, t) => match &**t {
            Type::Path(p) => p
                .path
                .segments
                .last()
                .is_some_and(|s| s.ident == "FfiResult"),
            _ => false,
        },
        ReturnType::Default => false,
    }
}

/// The body is a single expression: a call to `want` (`call`, or `call_on`
/// for a method with a receiver, so a panic poisons that handle).
fn guarded(body: &Block, want: &str) -> bool {
    let [Stmt::Expr(Expr::Call(c), None)] = body.stmts.as_slice() else {
        return false;
    };
    let Expr::Path(p) = &*c.func else {
        return false;
    };
    p.path.segments.last().is_some_and(|s| s.ident == want)
}

fn token_guard_uses_input(body: &Block, sig: &syn::Signature) -> bool {
    let [Stmt::Expr(Expr::Call(call), None)] = body.stmts.as_slice() else { return false; };
    if call.args.len() != 3 { return false; }
    let inputs = sig.inputs.iter().map(|arg| match arg {
        FnArg::Typed(typed) => typed.pat.to_token_stream().to_string().replace(' ', ""),
        FnArg::Receiver(_) => "self".to_string(),
    }).collect::<Vec<_>>();
    let first = call.args[0].to_token_stream().to_string().replace(' ', "");
    let second = call.args[1].to_token_stream().to_string().replace(' ', "");
    inputs.iter().any(|input| {
        first == format!("&{input}.poison") && second == format!("&{input}.busy")
            || first == format!("&{input}.claim_token.poison")
                && second == format!("&{input}.claim_token.busy")
    })
}

fn check(
    name: String,
    sig: &syn::Signature,
    body: &Block,
    owner: Option<&Type>,
    records: &BTreeMap<String, Vec<Type>>,
    found: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if !returns_ffi_result(&sig.output) {
        errors.push(format!("{name}: must return FfiResult"));
    }
    // A function that receives a poisonable SDK handle (besides its receiver) must
    // poison every participating handle on a panic.
    let takes_handle = sig.inputs.iter().any(|a| {
        let t = a.to_token_stream().to_string().replace(' ', "");
        t.contains("Arc<FfiSoftwareKey>") || t.contains("Arc<FfiSplitKey>")
            || t.contains("FfiCommittedOutcome>") || t.contains("Arc<FfiReferenceStore>")
            || t.contains("Arc<FfiDeviceSnapshot>") || t.contains("Arc<FfiReleasedDecision>")
    });
    let token_count = token_count(sig, owner, records);
    let takes_token = token_count > 0;
    if token_count > 1 {
        errors.push(format!("{name}: multiple reachable evaluation tokens need a multi-token guard"));
    }
    if takes_token && name.starts_with("constructor_") {
        errors.push(format!("{name}: evaluation-token constructor cannot use an instance guard"));
    }
    if takes_token && takes_handle {
        errors.push(format!("{name}: token and another poisonable handle need a combined guard"));
    }
    let want = if takes_token {
        "call_token_on"
    } else if takes_handle {
        "call_with"
    } else if sig.receiver().is_some() {
        "call_on"
    } else {
        "call"
    };
    if !guarded(body, want) {
        errors.push(format!("{name}: body must be exactly one guard::{want}"));
    } else if takes_token && !token_guard_uses_input(body, sig) {
        errors.push(format!("{name}: token guard must use the input token's poison and busy flags"));
    }
    found.insert(name);
}

#[test]
fn token_reachability_walks_nested_records_and_container_types() {
    let mut records = BTreeMap::new();
    records.insert("Inner".to_string(), vec![syn::parse_quote!(Option<Arc<FfiEvaluationToken>>)]);
    records.insert("Outer".to_string(), vec![syn::parse_quote!(Vec<Inner>)]);
    records.insert("FfiLocalAuthorizationOptions".to_string(),
        vec![syn::parse_quote!(Arc<FfiEvaluationToken>)]);
    let nested: syn::Signature = syn::parse_quote!(fn evaluate(input: Outer));
    let unrelated: syn::Signature = syn::parse_quote!(fn evaluate(input: Vec<String>));
    assert_eq!(token_count(&nested, None, &records), 2); // Vec can hold multiple tokens.
    let owner: Type = syn::parse_quote!(crate::FfiEvaluationToken);
    assert_eq!(token_count(&unrelated, Some(&owner), &records), 1);
    assert_eq!(token_count(&unrelated, None, &records), 0);

    let wrong: syn::ItemFn = syn::parse_quote! {
        fn evaluate(input: Outer) -> FfiResult<()> { call(|| Ok(())) }
    };
    let mut found = BTreeSet::new();
    let mut errors = Vec::new();
    check("func_evaluate".into(), &wrong.sig, &wrong.block, None, &records,
        &mut found, &mut errors);
    assert!(errors.iter().any(|e| e.contains("call_token_on")));
    assert!(errors.iter().any(|e| e.contains("multi-token guard")));

    let alias: syn::File = syn::parse_quote! {
        use crate::staged_claim::FfiLocalAuthorizationOptions as Opts;
    };
    collect_types(&alias.items, &mut records, &mut errors);
    assert_eq!(token_count(&syn::parse_quote!(fn evaluate(input: Opts)), None, &records), 1);
    let wrong_flags: syn::ItemFn = syn::parse_quote! {
        fn evaluate(token: Arc<FfiEvaluationToken>) -> FfiResult<()> {
            call_token_on(&Poison::default(), &TokenBusy::default(), || Ok(()))
        }
    };
    errors.clear();
    check("func_evaluate".into(), &wrong_flags.sig, &wrong_flags.block, None,
        &records, &mut found, &mut errors);
    assert!(errors.iter().any(|e| e.contains("input token's poison")));
}

#[test]
fn every_export_is_fallible_and_guarded() {
    let mut found = BTreeSet::new();
    let mut token_exports = BTreeSet::new();
    let mut errors = Vec::new();
    let files = fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/src")).unwrap()
        .map(|entry| syn::parse_file(&fs::read_to_string(entry.unwrap().path()).unwrap()).unwrap())
        .collect::<Vec<_>>();
    let mut records = BTreeMap::new();
    for file in &files { collect_types(&file.items, &mut records, &mut errors); }
    for file in files {
        for item in file.items {
            match item {
                Item::Fn(f) if is_export(&f.attrs) => {
                    let name = format!("func_{}", f.sig.ident);
                    if token_count(&f.sig, None, &records) > 0 { token_exports.insert(name.clone()); }
                    check(name, &f.sig, &f.block, None, &records, &mut found, &mut errors);
                }
                Item::Impl(imp) if is_export(&imp.attrs) => {
                    let ty = imp.self_ty.to_token_stream().to_string().to_lowercase();
                    for it in imp.items {
                        if let ImplItem::Fn(m) = it {
                            if !matches!(m.vis, syn::Visibility::Public(_)) {
                                continue;
                            }
                            let ctor = m.attrs.iter().any(|a| {
                                a.path()
                                    .segments
                                    .last()
                                    .is_some_and(|s| s.ident == "constructor")
                            });
                            let kind = if ctor { "constructor" } else { "method" };
                            let name = format!("{kind}_{ty}_{}", m.sig.ident);
                            if token_count(&m.sig, Some(&imp.self_ty), &records) > 0 {
                                token_exports.insert(name.clone());
                            }
                            check(
                                name,
                                &m.sig,
                                &m.block,
                                Some(&imp.self_ty),
                                &records,
                                &mut found,
                                &mut errors,
                            );
                        }
                    }
                }
                // A foreign trait: its methods are implemented in Swift and
                // Kotlin, so they are exports without a Rust body to guard.
                Item::Trait(tr) if is_export(&tr.attrs) => {
                    let ty = tr.ident.to_string().to_lowercase();
                    for it in tr.items {
                        if let syn::TraitItem::Fn(m) = it {
                            found.insert(format!("method_{ty}_{}", m.sig.ident));
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
        .map(|s| {
            s.chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect()
        })
        .collect();
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    let marked: BTreeSet<String> = [
        "func_ffi_evaluate_local_authorization",
        "func_ffi_resolve_claim_after_audience",
        "func_ffi_resolve_claim_after_rate",
        "func_ffi_resolve_claim_after_rate_barrier",
        "func_ffi_finalize_claim_proof_bundle",
        "func_ffi_finalize_claim_proof_bundle_barrier",
    ].into_iter().map(str::to_string).collect();
    assert_eq!(token_exports, marked, "token-reaching exports differ from the reviewed set");
    assert_eq!(
        found, generated,
        "exports found in the sources differ from the exports UniFFI generated"
    );
}
