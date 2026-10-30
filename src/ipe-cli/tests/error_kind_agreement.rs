//! The `ErrorKind` constructor list agrees across the runtime boundary.
//!
//! The runtime's `IpeErrorKind` (`src/runtime/rust/src/error.rs`) cannot import
//! the compiler crates, so canon's `BuiltinUnion` row for `ErrorKind` is a
//! second copy of the same list. Emitted code names each constructor as
//! `IpeErrorKind::<Name>` and serde carries it by name, so the two lists must
//! agree in names, order and discriminants: a drift is an `ipe`-accepts,
//! `cargo`-fails program (or a silent renumbering on the wire).
//!
//! The runtime source is read with `syn`, so the scan sees the enum rustc
//! compiles: comments and doc text are never variants, and a variant whose
//! shape the scan does not model (a `cfg` or other non-doc attribute, a payload,
//! a missing or non-literal discriminant) is a refusal, never a skipped line.

use ipe_canon::builtins::BUILTIN_UNIONS;
use syn::{Expr, ExprLit, Fields, Item, Lit};

/// The runtime source, embedded at compile time so an edit to it rebuilds this
/// test.
const RUNTIME_ERROR_RS: &str = include_str!("../../runtime/rust/src/error.rs");

/// The stdlib module that documents `ErrorKind` for Ipê authors.
const STDLIB_ERROR_IPE: &str = include_str!("../../stdlib/Ipe/Error.ipe");

/// The runtime enum the scan reads.
const RUNTIME_ENUM: &str = "IpeErrorKind";

/// Why the runtime source does not yield a variant list the scan can trust.
#[derive(Debug, PartialEq, Eq)]
enum ScanRefusal {
    /// The source does not parse as a Rust file.
    Unparsable,
    /// No top-level `enum IpeErrorKind`, or more than one.
    EnumCount(usize),
    /// The enum carries generics, which `ErrorKind` never has.
    Generic,
    /// A variant carries an attribute other than a doc comment (a `cfg` could
    /// remove it on some target; a `serde` attribute could rename it on the wire).
    VariantAttribute(String),
    /// A variant carries a payload; every `ErrorKind` constructor is nullary.
    Payload(String),
    /// A variant has no discriminant, or one that is not a `u8` integer literal.
    Discriminant(String),
}

/// `(name, discriminant)` for every variant of the runtime `IpeErrorKind`, in
/// declaration order.
fn runtime_error_kinds(src: &str) -> Result<Vec<(String, usize)>, ScanRefusal> {
    let file = syn::parse_file(src).map_err(|_| ScanRefusal::Unparsable)?;
    let enums: Vec<&syn::ItemEnum> = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Enum(e) if e.ident == RUNTIME_ENUM => Some(e),
            _ => None,
        })
        .collect();
    let [item] = enums.as_slice() else {
        return Err(ScanRefusal::EnumCount(enums.len()));
    };
    if !item.generics.params.is_empty() || item.generics.where_clause.is_some() {
        return Err(ScanRefusal::Generic);
    }
    item.variants
        .iter()
        .map(|variant| {
            let name = variant.ident.to_string();
            if variant.attrs.iter().any(|a| !a.path().is_ident("doc")) {
                return Err(ScanRefusal::VariantAttribute(name));
            }
            if !matches!(variant.fields, Fields::Unit) {
                return Err(ScanRefusal::Payload(name));
            }
            let Some((
                _,
                Expr::Lit(ExprLit {
                    lit: Lit::Int(lit), ..
                }),
            )) = &variant.discriminant
            else {
                return Err(ScanRefusal::Discriminant(name));
            };
            let Ok(value) = lit.base10_parse::<u8>() else {
                return Err(ScanRefusal::Discriminant(name));
            };
            Ok((name, usize::from(value)))
        })
        .collect()
}

/// Canon's `ErrorKind` constructors as `(name, index, arity)`; `None` when
/// canon registers no `ErrorKind`.
fn canon_error_kind_rows() -> Option<Vec<(String, usize, usize)>> {
    let union = BUILTIN_UNIONS.iter().find(|u| u.type_name == "ErrorKind")?;
    Some(
        union
            .ctors
            .iter()
            .map(|(name, index, arity)| ((*name).to_owned(), *index, *arity))
            .collect(),
    )
}

/// Canon's `ErrorKind` constructors as `(name, index)`.
fn canon_error_kinds() -> Vec<(String, usize)> {
    canon_error_kind_rows()
        .unwrap_or_default()
        .into_iter()
        .map(|(name, index, _)| (name, index))
        .collect()
}

/// `RUNTIME_ERROR_RS` with `from` replaced once by `to`; the edit must apply.
fn drift(from: &str, to: &str) -> String {
    let drifted = RUNTIME_ERROR_RS.replacen(from, to, 1);
    assert_ne!(drifted, RUNTIME_ERROR_RS, "the fixture edit applies");
    drifted
}

#[test]
fn every_canon_error_kind_is_nullary() {
    let rows = canon_error_kind_rows().expect("canon registers ErrorKind");
    assert!(!rows.is_empty());
    assert!(rows.iter().all(|(_, _, arity)| *arity == 0));
}

#[test]
fn runtime_and_canon_error_kinds_agree_in_name_order_and_discriminant() {
    let runtime = runtime_error_kinds(RUNTIME_ERROR_RS).expect("IpeErrorKind parses");
    assert_eq!(
        runtime,
        canon_error_kinds(),
        "src/runtime/rust/src/error.rs `IpeErrorKind` and canon's `ErrorKind` row must list \
         the same constructors with the same discriminants, in the same order"
    );
}

#[test]
fn the_agreement_scan_refuses_a_runtime_variant_canon_lacks() {
    let drifted = drift(
        "    UpdateRequired = 12,\n",
        "    UpdateRequired = 12,\n    Overloaded = 13,\n",
    );
    let runtime = runtime_error_kinds(&drifted).expect("drifted enum still parses");
    assert_ne!(runtime, canon_error_kinds());
}

#[test]
fn the_agreement_scan_refuses_a_renumbered_variant() {
    let drifted = drift("    Io = 0,\n", "    Io = 12,\n");
    let runtime = runtime_error_kinds(&drifted).expect("drifted enum still parses");
    assert_ne!(runtime, canon_error_kinds());
}

/// A brace inside a doc comment is text, not the end of the enum: a variant
/// declared after it is still read.
#[test]
fn the_agreement_scan_reads_variants_past_a_brace_in_a_doc_comment() {
    let drifted = drift(
        "    UpdateRequired = 12,\n",
        "    UpdateRequired = 12,\n    /// Renders as `{}`.\n    Overloaded = 13,\n",
    );
    let runtime = runtime_error_kinds(&drifted).expect("drifted enum still parses");
    assert_eq!(
        runtime.last(),
        Some(&("Overloaded".to_owned(), 13)),
        "the variant after the doc brace is read"
    );
    assert_ne!(runtime, canon_error_kinds());
}

/// A `cfg`-gated variant exists on some targets only, so the scan refuses it
/// rather than counting it present.
#[test]
fn the_agreement_scan_refuses_a_cfg_gated_variant() {
    let drifted = drift(
        "    LimitExceeded = 11,\n",
        "    #[cfg(not(target_arch = \"wasm32\"))]\n    LimitExceeded = 11,\n",
    );
    assert_eq!(
        runtime_error_kinds(&drifted),
        Err(ScanRefusal::VariantAttribute("LimitExceeded".to_owned()))
    );
}

#[test]
fn the_agreement_scan_refuses_a_variant_without_a_discriminant() {
    let drifted = drift("    LimitExceeded = 11,\n", "    LimitExceeded,\n");
    assert_eq!(
        runtime_error_kinds(&drifted),
        Err(ScanRefusal::Discriminant("LimitExceeded".to_owned()))
    );
}

#[test]
fn the_agreement_scan_refuses_a_missing_enum() {
    let drifted = drift("pub enum IpeErrorKind {", "pub enum IpeErrorClass {");
    assert_eq!(
        runtime_error_kinds(&drifted),
        Err(ScanRefusal::EnumCount(0))
    );
}

/// `Ipe.Error`'s module doc names every runtime kind, so `ipe doc Ipe.Error`
/// never omits a variant an exhaustive `case` must cover.
#[test]
fn the_stdlib_error_module_doc_names_every_runtime_kind() {
    let runtime = runtime_error_kinds(RUNTIME_ERROR_RS).expect("IpeErrorKind parses");
    let doc: Vec<&str> = STDLIB_ERROR_IPE
        .lines()
        .take_while(|line| line.starts_with("--"))
        .collect();
    let doc = doc.join("\n");
    let missing: Vec<&str> = runtime
        .iter()
        .map(|(name, _)| name.as_str())
        .filter(|name| !doc.contains(&format!("`{name}`")))
        .collect();
    assert!(
        missing.is_empty(),
        "src/stdlib/Ipe/Error.ipe module doc must name every `ErrorKind`: missing {missing:?}"
    );
}
