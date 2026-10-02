//! The `ErrorKind` constructor list agrees across the runtime boundary.
//!
//! The runtime's `IpeErrorKind` (`src/runtime/rust/src/error.rs`) cannot import
//! the compiler crates, so canon's `BuiltinUnion` row for `ErrorKind` is a
//! second copy of the same list. Emitted code names each constructor as
//! `IpeErrorKind::<Name>` and serde carries it by name, so the two lists must
//! agree in names, order and discriminants: a drift is an `ipe`-accepts,
//! `cargo`-fails program (or a silent renumbering on the wire).

use ipe_canon::builtins::BUILTIN_UNIONS;

/// The runtime source, embedded at compile time so an edit to it rebuilds this
/// test.
const RUNTIME_ERROR_RS: &str = include_str!("../../../runtime/rust/src/error.rs");

/// `(name, discriminant)` for every variant of the runtime `IpeErrorKind`, in
/// declaration order; `None` when the enum or a variant line does not parse.
fn runtime_error_kinds(src: &str) -> Option<Vec<(String, usize)>> {
    let body_start = src.find("pub enum IpeErrorKind {")?;
    let rest = src.get(body_start..)?;
    let open = rest.find('{')?;
    let close = rest.find('}')?;
    let body = rest.get(open + 1..close)?;
    let mut kinds = Vec::new();
    for line in body.lines().map(str::trim) {
        if line.is_empty() || line.starts_with("//") || line.starts_with("#[") {
            continue;
        }
        let (name, value) = line.strip_suffix(',')?.split_once('=')?;
        kinds.push((name.trim().to_owned(), value.trim().parse().ok()?));
    }
    Some(kinds)
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
    let drifted = RUNTIME_ERROR_RS.replacen(
        "    LimitExceeded = 11,\n",
        "    LimitExceeded = 11,\n    Overloaded = 12,\n",
        1,
    );
    assert_ne!(drifted, RUNTIME_ERROR_RS, "the fixture edit applies");
    let runtime = runtime_error_kinds(&drifted).expect("drifted enum still parses");
    assert_ne!(runtime, canon_error_kinds());
}

#[test]
fn the_agreement_scan_refuses_a_renumbered_variant() {
    let drifted = RUNTIME_ERROR_RS.replacen("    Io = 0,\n", "    Io = 12,\n", 1);
    assert_ne!(drifted, RUNTIME_ERROR_RS, "the fixture edit applies");
    let runtime = runtime_error_kinds(&drifted).expect("drifted enum still parses");
    assert_ne!(runtime, canon_error_kinds());
}
