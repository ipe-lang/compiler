//! File-based render-golden harness.
//!
//! Each test case renders a [`Diagnostic`] against a small source snippet and
//! compares the output byte-for-byte to a checked-in `.txt` file under
//! `tests/render_goldens/`. The golden files lock the CURRENT output layout so
//! that a later tone/layout pass produces a reviewable diff rather than a
//! silent regression.
//!
//! **Updating goldens:** set `UPDATE_GOLDENS=1` in the environment before
//! running the suite. Every failing assertion will overwrite its golden file
//! with the actual output instead of failing.
//!
//! **Adding a case:** append an entry at the bottom following the existing
//! pattern (name, source, diagnostic), run with `UPDATE_GOLDENS=1` once to
//! capture the current output, commit the new `.txt`.

use std::path::PathBuf;

use ipe_diagnostics::{
    AliasExpansionKind, Candidates, Construct, Diagnostic, EditTarget, Expected, ExpectedSet,
    Feature, LowerError, NameError, ParseError, SortedNames, Span, TokenKind, TyDoc, TypeError,
};

// ---------------------------------------------------------------------------
// Golden-check infrastructure
// ---------------------------------------------------------------------------

fn goldens_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR points at the crate root during tests.
    let manifest = ipe_env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| String::from("."));
    PathBuf::from(manifest).join("tests").join("render_goldens")
}

fn update_mode() -> bool {
    ipe_env::var("UPDATE_GOLDENS").is_ok()
}

/// Render `d` against `source`, then compare to the golden file `name.txt`.
///
/// In update mode (`UPDATE_GOLDENS=1`) the file is written instead of checked.
/// Returns `Err` on an I/O failure so the test framework reports the cause
/// rather than a panic — the production no-panic rule applies here too.
fn check_golden(
    name: &str,
    d: &Diagnostic,
    file: &str,
    source: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Colour is off: nextest runs without a tty, so `color_enabled()` returns
    // false. This is structural, not a workaround.
    let actual = ipe_diagnostics::render(d, file, source);

    let path = goldens_dir().join(format!("{name}.txt"));

    if update_mode() {
        std::fs::write(&path, &actual)?;
        return Ok(());
    }

    let expected = std::fs::read_to_string(&path).map_err(|e| {
        format!(
            "golden {name}.txt missing or unreadable: {e}\n\
             Run with UPDATE_GOLDENS=1 to create it."
        )
    })?;

    assert!(
        actual == expected,
        "render golden mismatch for {name}.\n\
         --- expected ---\n{expected}\
         --- actual ---\n{actual}\
         ----------------\n\
         Re-run with UPDATE_GOLDENS=1 to accept the new output."
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers for constructing TyDoc values without boilerplate
// ---------------------------------------------------------------------------

fn ty_con(name: &str) -> TyDoc {
    TyDoc::Con {
        module: "".into(),
        name: name.into(),
        args: Box::new([]),
    }
}

fn ty_con1(name: &str, arg: TyDoc) -> TyDoc {
    TyDoc::Con {
        module: "".into(),
        name: name.into(),
        args: Box::new([arg]),
    }
}

// ---------------------------------------------------------------------------
// Parse family (IPE-P*)
// ---------------------------------------------------------------------------

#[test]
fn golden_parse_bare_wildcard_let_binding() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-P0064: `_` as the entire let binding pattern — binds nothing.
    let source = "module Main exposing (main)\n\nmain =\n    let _ = Io.println \"a\" in\n    Io.println \"b\"\n";
    let d = Diagnostic::Parse {
        span: Span::new(44, 45), // the bare `_` token.
        msg: ParseError::MalformedLet(ipe_diagnostics::LetDefect::BareWildcardBinding),
    };
    check_golden("parse_bare_wildcard_let_binding", &d, "test.ipe", source)
}

#[test]
fn golden_parse_unexpected_token() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-P0001: unexpected token — the parser found a number where an
    // identifier was expected.
    let source = "module Main exposing (main)\n\nmain =\n    42 True\n";
    let d = Diagnostic::Parse {
        span: Span::new(40, 42), // the `42` literal.
        msg: ParseError::UnexpectedToken {
            found: TokenKind::Int,
            expected: ExpectedSet(Box::new([Expected::Identifier])),
        },
    };
    check_golden("parse_unexpected_token", &d, "test.ipe", source)
}

#[test]
fn golden_parse_unterminated_string() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-P0014: string literal opened but never closed.
    let source = "module Main exposing (main)\n\nmain =\n    \"hello\n";
    let d = Diagnostic::Parse {
        span: Span::new(40, 46), // the unterminated `"hello` run.
        msg: ParseError::UnterminatedString,
    };
    check_golden("parse_unterminated_string", &d, "test.ipe", source)
}

#[test]
fn golden_parse_unexpected_eof() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-P0002: input ended while still inside a construct.
    let source = "module Main exposing (main)\n\nmain =\n    let x =\n";
    let d = Diagnostic::Parse {
        span: Span::new(46, 46),
        msg: ParseError::UnexpectedEof {
            construct: Construct::Let,
        },
    };
    check_golden("parse_unexpected_eof", &d, "test.ipe", source)
}

// ---------------------------------------------------------------------------
// Name family (IPE-N*)
// ---------------------------------------------------------------------------

#[test]
fn golden_name_value_not_found_single_suggestion() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-N0001: unknown value name with one close match — rendered as a
    // machine-applicable replacement suggestion.
    let source = "module Main exposing (main)\n\nmain =\n    lenght\n";
    // The primary span must cover the identifier `lenght` (bytes 40..46), not the
    // newline + indent before it — the single-suggestion `Suggest` reuses this
    // span to read the replaced text, so a slack span made it read `replace `\n
    //     l``. The resolver hands the identifier's own span here.
    let d = Diagnostic::Name {
        span: Span::new(40, 46),
        msg: NameError::ValueNotFound {
            name: "lenght".into(),
            suggestions: Candidates::at(
                EditTarget::whole(Span::new(40, 46), "lenght"),
                Box::new(["length".into()]),
            ),
        },
    };
    check_golden(
        "name_value_not_found_single_suggestion",
        &d,
        "test.ipe",
        source,
    )
}

#[test]
fn golden_name_module_not_found_multi_suggestion() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-N0020: module not found with several near-misses — collapsed into one
    // "did you mean one of:" block.
    let source = "module Main exposing (main)\nimport Httpp\n\nmain =\n    42\n";
    let d = Diagnostic::Name {
        span: Span::new(34, 39),
        msg: NameError::ModuleNotFound {
            name: "Httpp".into(),
            suggestions: Candidates::hints(Box::new(["Http".into(), "Https".into()])),
        },
    };
    check_golden(
        "name_module_not_found_multi_suggestion",
        &d,
        "test.ipe",
        source,
    )
}

#[test]
fn golden_name_duplicate_value() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-N0010: two top-level values share a name; the earlier span becomes a
    // secondary underline with the "first defined here" role.
    let source = "module Main exposing (x)\n\nx = 1\n\nx = 2\n";
    let d = Diagnostic::Name {
        span: Span::new(33, 34), // the second `x`.
        msg: NameError::DuplicateValue {
            name: "x".into(),
            first: Span::new(26, 27), // the first `x`.
        },
    };
    check_golden("name_duplicate_value", &d, "test.ipe", source)
}

#[test]
fn golden_name_rust_name_fold() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-N0048: two distinct Ipê definitions mangle to one generated Rust name.
    // The IR carries no source spans, so the message names BOTH Ipê definitions
    // and the shared Rust name and asks for a rename (DUMMY span → no snippet).
    let source = "";
    let d = Diagnostic::Name {
        span: Span::DUMMY,
        msg: NameError::RustNameFold {
            first: "firstName".into(),
            second: "first_name".into(),
            rust_name: "IpeHasFirstName".into(),
            kind: ipe_diagnostics::RustNameFoldKind::Value,
        },
    };
    check_golden("name_rust_name_fold", &d, "test.ipe", source)
}

#[test]
fn golden_name_import_cycle() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-N0021: circular import — no snippet (DUMMY span), just the cycle in
    // the label.
    let source = "";
    let d = Diagnostic::Name {
        span: Span::DUMMY,
        msg: NameError::ImportCycle {
            path: Box::new(["Main".into(), "Utils".into(), "Main".into()]),
        },
    };
    check_golden("name_import_cycle", &d, "<no file>", source)
}

#[test]
fn golden_name_kernel_alias_in_user_source() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-N0042: a user module tries to mint a kernel alias — FFI-adjacent name
    // diagnostic.
    let source = "module Main exposing (main)\n\nmain =\n    Kernel.kernel \"Http_get\"\n";
    let d = Diagnostic::Name {
        span: Span::new(40, 64), // the `Kernel.kernel "Http_get"` call.
        msg: NameError::KernelAliasInUserSource {
            alias: "Http_get".into(),
        },
    };
    check_golden("name_kernel_alias_in_user_source", &d, "test.ipe", source)
}

// ---------------------------------------------------------------------------
// Type family (IPE-T*)
// ---------------------------------------------------------------------------

#[test]
fn golden_type_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-T0001: the inferred type does not match the expected type.
    let source = "module Main exposing (main)\n\nmain : Int\nmain =\n    \"hello\"\n";
    let d = Diagnostic::Type {
        span: Span::new(51, 58), // the `"hello"` literal.
        msg: TypeError::TypeMismatch {
            expected: Box::new(ty_con("Int")),
            found: Box::new(ty_con("String")),
            definition: Some(Span::new(36, 39)), // the `Int` annotation.
            path: Box::new([]),
        },
    };
    check_golden("type_mismatch", &d, "test.ipe", source)
}

#[test]
fn golden_type_non_exhaustive_case() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-T0010: a case expression does not cover all constructors.
    let source = "module Main exposing (main)\n\ntype Color = Red | Green | Blue\n\nmain =\n    case Red of\n        Red -> 1\n";
    let d = Diagnostic::Type {
        span: Span::new(70, 78),
        msg: TypeError::NonExhaustiveCase {
            missing: SortedNames::new(["Green".into(), "Blue".into()]),
        },
    };
    check_golden("type_non_exhaustive_case", &d, "test.ipe", source)
}

#[test]
fn golden_type_infinite_type() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-T0002: occurs check failure — a type variable would have to equal a
    // type that contains itself.
    let source = "module Main exposing (main)\n\nmain =\n    let f x = f\n    in f\n";
    let d = Diagnostic::Type {
        span: Span::new(43, 44),
        msg: TypeError::InfiniteType {
            var: "a".into(),
            ty: Box::new(ty_con1("List", TyDoc::Var("a".into()))),
        },
    };
    check_golden("type_infinite_type", &d, "test.ipe", source)
}

#[test]
fn golden_type_redundant_branch_warning() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-T0011: a case branch is redundant — severity is Warning, not Error.
    let source = "module Main exposing (main)\n\ntype Color = Red | Green\n\nmain =\n    case Red of\n        Red -> 1\n        Red -> 2\n";
    // Underline the redundant second `Red` pattern (bytes 103..106), not the
    // tail of the first branch — the span names the branch that can never run.
    let d = Diagnostic::Type {
        span: Span::new(103, 106),
        msg: TypeError::RedundantCaseBranch {
            constructor: "Red".into(),
        },
    };
    check_golden("type_redundant_branch_warning", &d, "test.ipe", source)
}

#[test]
fn golden_type_mismatch_multiline_span() -> Result<(), Box<dyn std::error::Error>> {
    // A primary span that crosses lines: the offending expression spans an
    // application written over three lines. Every covered line is underlined,
    // and the label attaches to the last one.
    let source =
        "module Main exposing (main)\n\nmain : Int\nmain =\n    add\n        1\n        2\n";
    let d = Diagnostic::Type {
        span: Span::new(51, 74),
        msg: TypeError::TypeMismatch {
            expected: Box::new(ty_con("Int")),
            found: Box::new(ty_con("String")),
            definition: None,
            path: Box::new([]),
        },
    };
    check_golden("type_mismatch_multiline_span", &d, "test.ipe", source)
}

#[test]
fn golden_name_value_not_found_tab_indented() -> Result<(), Box<dyn std::error::Error>> {
    // The offending line is indented with a tab, not spaces. The caret must land
    // under the identifier once the tab is expanded to a fixed stop, so the
    // shown source line and the caret line agree on where the name begins.
    let source = "module Main exposing (main)\n\nmain =\n\tlenght\n";
    let d = Diagnostic::Name {
        span: Span::new(37, 43),
        msg: NameError::ValueNotFound {
            name: "lenght".into(),
            suggestions: Candidates::at(
                EditTarget::whole(Span::new(37, 43), "lenght"),
                Box::new(["length".into()]),
            ),
        },
    };
    check_golden("name_value_not_found_tab_indented", &d, "test.ipe", source)
}

#[test]
fn golden_name_value_not_found_wide_chars() -> Result<(), Box<dyn std::error::Error>> {
    // The line holds full-width (CJK) characters before the underlined name.
    // Each is two display cells, so the caret indent must count display width,
    // not `char`s, or it would under-shoot the identifier.
    let source = "module Main exposing (main)\n\nmain =\n    \"你好\" ++ x\n";
    let d = Diagnostic::Name {
        span: Span::new(48, 49),
        msg: NameError::ValueNotFound {
            name: "x".into(),
            suggestions: Candidates::default(),
        },
    };
    check_golden("name_value_not_found_wide_chars", &d, "test.ipe", source)
}

// ---------------------------------------------------------------------------
// Lower family (IPE-L*)
// ---------------------------------------------------------------------------

#[test]
fn golden_lower_unsupported_feature() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-L0101: an operator that the backend does not yet emit.
    let source = "module Main exposing (main)\n\nmain =\n    3 * 4\n";
    let d = Diagnostic::Lower {
        span: Span::new(38, 43),
        msg: LowerError::Unsupported(Feature::BinOps),
    };
    check_golden("lower_unsupported_feature", &d, "test.ipe", source)
}

#[test]
fn golden_lower_lawless_effect_discard() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-L0141: a Task value discarded with `let _ = …` in a non-Task context.
    let source = "module Main exposing (main)\n\nmain : Int\nmain =\n    let _ = Http.get \"https://example.com\"\n    in 42\n";
    let d = Diagnostic::Lower {
        span: Span::new(51, 89), // the `let _ = Http.get "…"` discard.
        msg: LowerError::LawlessEffectDiscard,
    };
    check_golden("lower_lawless_effect_discard", &d, "test.ipe", source)
}

#[test]
fn golden_lower_non_entry_main() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-L0136: `main` is a value, not the `Task Error ()` a runnable program
    // entry must be. The caret points at the `main` def name.
    let source = "module Main exposing (main)\n\nmain : Int\nmain = 42\n";
    let d = Diagnostic::Lower {
        span: Span::new(40, 44),
        msg: LowerError::NonEntryMain {
            found: ipe_diagnostics::MainRetName::Bare("Int"),
        },
    };
    check_golden("lower_non_entry_main", &d, "test.ipe", source)
}

#[test]
fn golden_lower_non_entry_main_non_task() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-L0136: `main` returns a type not in the bare-name list (catch-all
    // Phrase path). The rendered prose must not article-wrap the phrase and
    // must not produce nested or unbalanced backticks.
    let source = "module Main exposing (main)\n\nmain : Result String Int\nmain = Ok 1\n";
    let d = Diagnostic::Lower {
        span: Span::new(54, 58),
        msg: LowerError::NonEntryMain {
            found: ipe_diagnostics::MainRetName::Phrase("value that is not a `Task`"),
        },
    };
    check_golden("lower_non_entry_main_non_task", &d, "test.ipe", source)
}

#[test]
fn golden_lower_undeterminable_return_any() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-L0142: a wildcard `any` in return position that no parameter carries
    // and no body pins. The caret points at the signature.
    let source = "module Main exposing (main)\n\nfoo : Int -> List any\nfoo _ = []\n";
    let d = Diagnostic::Lower {
        span: Span::new(29, 50), // the `foo : Int -> List any` signature.
        msg: LowerError::UndeterminableReturnAny,
    };
    check_golden("lower_undeterminable_return_any", &d, "test.ipe", source)
}

// ---------------------------------------------------------------------------
// FFI family (IPE-F* / FFI-adjacent name diagnostics)
// ---------------------------------------------------------------------------

#[test]
fn golden_ffi_asserted_call_malformed() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-N0038: a `Rust.Ffi.call` binding is structurally malformed.
    // This is the FFI-adjacent name diagnostic reachable from user code.
    let source = "module Main exposing (main)\n\nmain = Rust.Ffi.call \"bad::shape\" 42\n";
    let d = Diagnostic::Name {
        span: Span::new(29, 65), // the whole `main = Rust.Ffi.call …` definition.
        msg: NameError::AssertedCallMalformed {
            detail: "the body must be exactly `Rust.Ffi.call \"<crate>::<fn>\"`".into(),
        },
    };
    check_golden("ffi_asserted_call_malformed", &d, "test.ipe", source)
}

// ---------------------------------------------------------------------------
// Internal / ICE family (IPE-I*)
// ---------------------------------------------------------------------------

#[test]
fn golden_internal_compiler_error_generic() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-I0001: a generic internal compiler error (DUMMY span, no snippet).
    let d = Diagnostic::CompilerBug {
        where_: "lower",
        detail: "no lowering for this IR node".into(),
    };
    check_golden("internal_compiler_error_generic", &d, "test.ipe", "")
}

#[test]
fn golden_internal_compiler_error_specific() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-I0010: a specific internal error with a recognised `where_` tag.
    let d = Diagnostic::CompilerBug {
        where_: "intern.resolve",
        detail: "symbol 42 has no entry".into(),
    };
    check_golden("internal_compiler_error_specific", &d, "test.ipe", "")
}

// ---------------------------------------------------------------------------
// Environment (IPE-E*)
// ---------------------------------------------------------------------------

#[test]
fn golden_registry_unreachable() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-E0001: crate registry unreachable — network/DNS failure at cargo fetch.
    let d = Diagnostic::RegistryUnreachable {
        detail: "cargo exited 101 while fetching crates for out/my-app:\nCould not resolve host: index.crates.io\nfailed to load source for dependency dlmalloc".into(),
    };
    check_golden("registry_unreachable", &d, "", "")
}

// ---------------------------------------------------------------------------
// Security-adjacent (IPE-N0032 alias expansion guard)
// ---------------------------------------------------------------------------

#[test]
fn golden_security_alias_expansion_too_deep() -> Result<(), Box<dyn std::error::Error>> {
    // IPE-N0032: alias expansion depth exceeded — a correctness guard on
    // pathological type alias chains (IPE-S0001 is produced outside this crate
    // by the consent layer; this covers the name-resolution guard that bounds
    // expansion depth as the security-adjacent representative).
    let source =
        "module Main exposing (main)\n\ntype alias A = B\ntype alias B = A\n\nmain : A\nmain = 0\n";
    let d = Diagnostic::Name {
        span: Span::new(29, 45), // the `type alias A = B` declaration.
        msg: NameError::TypeExpansionTooDeep {
            kind: AliasExpansionKind::Depth,
            limit: 256,
        },
    };
    check_golden("name_alias_expansion_too_deep", &d, "test.ipe", source)
}
