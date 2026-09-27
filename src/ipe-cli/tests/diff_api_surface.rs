#![forbid(unsafe_code)]
//! Public-API extraction (`ipe diff`'s front half): a package's typed module
//! interfaces project into a canonical, order-independent [`PublicApi`], and a
//! module whose interface is open or un-typecheckable fails closed.

// Test fixture setup: a failed `expect`/`panic` IS the failure signal — the
// harness reports it as the test failure, which is the intended behaviour here.
#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use ipe::api_surface::{DiffError, extract_tree};

/// A fresh temp package directory tagged unique to this test binary + name.
fn temp_pkg(tag: &str) -> PathBuf {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "ipe-diff-{}-{}-{}",
        std::process::id(),
        tag,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(dir.join("src")).expect("create temp src dir");
    dir
}

/// Write one module's source into `<pkg>/src/<Name>.ipe`.
fn write_module(pkg: &std::path::Path, name: &str, source: &str) {
    std::fs::write(pkg.join("src").join(format!("{name}.ipe")), source).expect("write module");
}

const LIB: &str = r"module Lib exposing (double, wrap)



double : Int -> Int
double n =
    n + n


wrap : a -> List a
wrap x =
    [ x ]
";

#[test]
fn extracts_exported_values_with_canonical_signatures() {
    let pkg = temp_pkg("values");
    write_module(&pkg, "Lib", LIB);

    let api = extract_tree(&pkg).expect("extract public api");
    let module = api
        .modules
        .get(&vec!["Lib".to_owned()])
        .expect("Lib module present");

    assert_eq!(
        module.values.get("double").map(String::as_str),
        Some("Int -> Int"),
        "double's signature"
    );
    assert_eq!(
        module.values.get("wrap").map(String::as_str),
        Some("a -> List a"),
        "wrap's polymorphic signature"
    );
    assert!(
        !module.values.contains_key("hidden"),
        "only exposed names appear"
    );
}

#[test]
fn source_order_does_not_affect_the_public_api() {
    let a = temp_pkg("order-a");
    let b = temp_pkg("order-b");
    write_module(&a, "Lib", LIB);
    // Same two exports, declared in the opposite order.
    write_module(
        &b,
        "Lib",
        r"module Lib exposing (wrap, double)



wrap : a -> List a
wrap x =
    [ x ]


double : Int -> Int
double n =
    n + n
",
    );

    let api_a = extract_tree(&a).expect("extract a");
    let api_b = extract_tree(&b).expect("extract b");
    assert_eq!(api_a, api_b, "source order must not perturb the public API");
}

#[test]
fn type_variable_spelling_does_not_affect_signatures() {
    let a = temp_pkg("alpha-a");
    let b = temp_pkg("alpha-b");
    write_module(
        &a,
        "Lib",
        r"module Lib exposing (pair)



pair : a -> b -> ( a, b )
pair x y =
    ( x, y )
",
    );
    write_module(
        &b,
        "Lib",
        r"module Lib exposing (pair)



pair : x -> y -> ( x, y )
pair a b =
    ( a, b )
",
    );

    let api_a = extract_tree(&a).expect("extract a");
    let api_b = extract_tree(&b).expect("extract b");
    assert_eq!(
        api_a, api_b,
        "signatures must be compared up to type-variable renaming"
    );
}

#[test]
fn extracts_an_exposed_union_with_its_constructors() {
    let pkg = temp_pkg("union");
    write_module(
        &pkg,
        "Lib",
        r"module Lib exposing (Shape(..), area)



type Shape
    = Circle Int
    | Rect Int Int


area : Shape -> Int
area shape =
    case shape of
        Circle r ->
            r * r

        Rect w h ->
            w * h
",
    );

    let api = extract_tree(&pkg).expect("extract public api");
    let module = api.modules.get(&vec!["Lib".to_owned()]).expect("Lib");
    let shape = module.unions.get("Shape").expect("Shape union present");
    assert_eq!(shape.params, 0, "Shape is monomorphic");
    assert_eq!(
        shape.ctors.get("Circle").map(Vec::as_slice),
        Some(["Int".to_owned()].as_slice()),
        "Circle carries one Int"
    );
    assert_eq!(
        shape.ctors.get("Rect").map(Vec::as_slice),
        Some(["Int".to_owned(), "Int".to_owned()].as_slice()),
        "Rect carries two Ints"
    );
}

#[test]
fn a_package_that_does_not_typecheck_fails_closed() {
    let pkg = temp_pkg("illtyped");
    write_module(
        &pkg,
        "Lib",
        r"module Lib exposing (bad)



bad : Int -> Int
bad n =
    n ++ n
",
    );

    match extract_tree(&pkg) {
        Err(DiffError::Typecheck { .. }) => {}
        other => panic!("expected a typecheck failure, got {other:?}"),
    }
}
