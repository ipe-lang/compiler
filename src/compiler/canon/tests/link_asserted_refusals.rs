//! Refusal tests for the asserted-path keyword gate and the linker's
//! duplicate-definition gate. Each pins a fail-closed branch that turns a
//! representable-but-illegal pipeline state (un-buildable emitted Rust) away at
//! ipe time.

use ipe_canon::asserted::AssertedPath;
use ipe_canon::ast::{Ctor, Def, Expr_, Module, Union};
use ipe_canon::link::link;
use ipe_diagnostics::{Diagnostic, Located, NameError, Span};
use ipe_intern::Interner;
use std::collections::BTreeSet;

/// A path segment spelled as a Rust keyword is rejected: it would be spliced
/// verbatim into the generated shim (`::sha2::match(...)`) and fail to compile.
#[test]
fn asserted_path_rejects_keyword_segment() {
    assert!(AssertedPath::parse("sha2::match").is_err());
    assert!(AssertedPath::parse("mycrate::fn").is_err());
    assert!(AssertedPath::parse("mycrate::self::helper").is_err());
    assert!(AssertedPath::parse("mycrate::type").is_err());
}

/// A plain, keyword-free path still parses.
#[test]
fn asserted_path_accepts_plain_segments() {
    assert!(AssertedPath::parse("sha2::digest").is_ok());
    assert!(AssertedPath::parse("some_crate::module::frobnicate").is_ok());
}

/// A single value-only module linked twice produces two defs with the same
/// nominal identity `(home, name)`; the linker rejects it rather than emit
/// duplicate Rust fns.
#[test]
fn link_rejects_duplicate_def_identity() {
    let mut i = Interner::new();
    let home = vec![i.intern("Lib").expect("intern Lib")];
    let helper = i.intern("helper").expect("intern helper");
    let make_module = || Module {
        name: home.clone(),
        unions: Vec::new(),
        defs: vec![Def::Untyped {
            home: home.clone(),
            name: Located::new(Span::DUMMY, helper),
            patterns: Vec::new(),
            body: Located::new(Span::DUMMY, Expr_::Unit),
        }],
        imports_unsafe_submodule: false,
        imported_web_capabilities: BTreeSet::new(),
    };
    let result = link(home.clone(), vec![make_module(), make_module()], &i);
    assert!(
        result.is_err(),
        "a twice-linked value module must be a duplicate-def error"
    );
}

/// A duplicate top-level def diagnostic carries the location of BOTH
/// declarations: `span` (the rejected second one) and `first` (the original).
/// Before this test's fix, `first` was always `Span::DUMMY`, so the rendered
/// diagnostic could point at the duplicate but never show where the name was
/// first declared.
#[test]
fn link_rejects_duplicate_def_identity_reports_both_spans() {
    let mut i = Interner::new();
    let home = vec![i.intern("Lib").expect("intern Lib")];
    let helper = i.intern("helper").expect("intern helper");
    let first_span = Span::new(10, 16);
    let second_span = Span::new(40, 46);
    let make_module = |name_span: Span| Module {
        name: home.clone(),
        unions: Vec::new(),
        defs: vec![Def::Untyped {
            home: home.clone(),
            name: Located::new(name_span, helper),
            patterns: Vec::new(),
            body: Located::new(Span::DUMMY, Expr_::Unit),
        }],
        imports_unsafe_submodule: false,
        imported_web_capabilities: BTreeSet::new(),
    };
    let result = link(
        home.clone(),
        vec![make_module(first_span), make_module(second_span)],
        &i,
    );
    assert!(
        matches!(
            result,
            Err(Diagnostic::Name {
                msg: NameError::DuplicateValue { .. },
                ..
            })
        ),
        "expected a DuplicateValue diagnostic, got {result:?}"
    );
    if let Err(Diagnostic::Name {
        span,
        msg: NameError::DuplicateValue { first, .. },
    }) = result
    {
        assert_eq!(
            span, second_span,
            "diagnostic span must point at the rejected (second) declaration"
        );
        assert_eq!(
            first, first_span,
            "`first` must point at the original declaration's real source span, not Span::DUMMY"
        );
    }
}

/// The same class-closing property for types: a cross-module duplicate union
/// diagnostic carries both the rejected declaration's span and the original
/// declaration's real `first` span.
#[test]
fn link_rejects_duplicate_type_identity_reports_both_spans() {
    let mut i = Interner::new();
    let home = vec![i.intern("Lib").expect("intern Lib")];
    let color = i.intern("Color").expect("intern Color");
    let red = i.intern("Red").expect("intern Red");
    let first_span = Span::new(5, 10);
    let second_span = Span::new(50, 55);
    let make_module = |name_span: Span| Module {
        name: home.clone(),
        unions: vec![Union {
            home: home.clone(),
            name: color,
            name_span,
            vars: Vec::new(),
            ctors: vec![Ctor {
                name: red,
                index: 0,
                arity: 0,
                args: Vec::new(),
                span: Span::DUMMY,
            }],
        }],
        defs: Vec::new(),
        imports_unsafe_submodule: false,
        imported_web_capabilities: BTreeSet::new(),
    };
    let result = link(
        home.clone(),
        vec![make_module(first_span), make_module(second_span)],
        &i,
    );
    assert!(
        matches!(
            result,
            Err(Diagnostic::Name {
                msg: NameError::DuplicateType { .. },
                ..
            })
        ),
        "expected a DuplicateType diagnostic, got {result:?}"
    );
    if let Err(Diagnostic::Name {
        span,
        msg: NameError::DuplicateType { first, .. },
    }) = result
    {
        assert_eq!(
            span, second_span,
            "diagnostic span must point at the rejected (second) declaration"
        );
        assert_eq!(
            first, first_span,
            "`first` must point at the original declaration's real source span, not Span::DUMMY"
        );
    }
}

/// Two distinct homes sharing a short name are NOT a duplicate — they mangle to
/// distinct Rust fns downstream.
#[test]
fn link_allows_same_name_distinct_homes() {
    let mut i = Interner::new();
    let helper = i.intern("helper").expect("intern helper");
    let lib_home = vec![i.intern("Lib").expect("intern Lib")];
    let main_home = vec![i.intern("Main").expect("intern Main")];
    let make_module = |home: Vec<_>| Module {
        name: home.clone(),
        unions: Vec::new(),
        defs: vec![Def::Untyped {
            home,
            name: Located::new(Span::DUMMY, helper),
            patterns: Vec::new(),
            body: Located::new(Span::DUMMY, Expr_::Unit),
        }],
        imports_unsafe_submodule: false,
        imported_web_capabilities: BTreeSet::new(),
    };
    let result = link(
        main_home.clone(),
        vec![make_module(lib_home), make_module(main_home)],
        &i,
    );
    assert!(
        result.is_ok(),
        "same short name in distinct homes must link cleanly"
    );
}
