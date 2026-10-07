//! Every recursive shape `syn` parses fits its stack at the depth ceiling and is refused past it.
//!
//! For each shape, the control at the ceiling is the largest repetition count
//! whose measure stays within [`NestDepth::CEILING`]; it must parse, be judged
//! and be dropped on a [`CONTROL_STACK`] thread, and one repetition more must be
//! refused as [`ScanError::TooDeep`] before `syn` sees it. A shape whose
//! recursion the measure under-counts overflows the control's stack and kills
//! this test binary, so a red here is the measure being wrong, never a flake.
//!
//! The 4x stack margin is a claim about the release scanner the gate runs; the
//! release step of the `panic-scan` CI job runs this file with optimisations.

use std::path::{Path, PathBuf};

use panic_scan::{
    NestDepth, ParseStack, ScanError, SourceBytes, TestPathError, TokenCeiling, check_test_path,
    measure, read_source, scan_source, scan_source_on, test_only_item_lines,
};

/// A source holding `n` repetitions of one recursive shape.
type Shape = fn(usize) -> String;

/// A named shape.
type Case = (&'static str, Shape);

/// The deepest nest depth a scan accepts.
const CEILING: usize = NestDepth::CEILING.get();

/// The stack each control at the ceiling parses on.
///
/// Optimised, it is [`ParseStack::CALIBRATION`], a quarter of the production
/// stack, which proves the 4x margin. Unoptimised frames are larger, so a debug
/// run proves the shapes on the production stack itself, the stack every debug
/// build of the scanner (the `ipe` audit tests included) runs on.
const CONTROL_STACK: ParseStack = if cfg!(debug_assertions) {
    ParseStack::CEILING
} else {
    ParseStack::CALIBRATION
};

/// `e` as the initialiser of a `let` in a function body.
fn expr(e: &str) -> String {
    format!("fn f() {{\n    let _ = {e};\n}}\n")
}

/// `p` as the pattern of a `let` in a function body.
fn pat(p: &str) -> String {
    format!("fn f() {{\n    let {p} = a;\n}}\n")
}

/// `t` as the body of a type alias.
fn ty(t: &str) -> String {
    format!("type T = {t};\n")
}

/// `leaf` wrapped in `n` copies of `open` and `close`.
fn wrap(n: usize, open: &str, leaf: &str, close: &str) -> String {
    format!("{}{leaf}{}", open.repeat(n), close.repeat(n))
}

/// `seed` with `step` applied `n` times.
fn nest(n: usize, seed: &str, step: fn(&str) -> String) -> String {
    (0..n).fold(seed.to_owned(), |inner, _| step(&inner))
}

/// The nest depth of `shape` at `n` repetitions.
#[allow(clippy::expect_used)] // a shape that does not lex is a broken test, not a finding
fn depth_of(name: &str, shape: Shape, n: usize) -> usize {
    measure(&shape(n)).expect(name).depth
}

/// The largest repetition count of `shape` whose nest depth stays within the ceiling.
fn at_ceiling(name: &str, shape: Shape) -> usize {
    let mut over = CEILING.saturating_add(1);
    assert!(
        depth_of(name, shape, over) > CEILING,
        "{name}: each repetition must weigh at least one measure unit"
    );
    let mut fits = 0_usize;
    assert!(
        depth_of(name, shape, fits) <= CEILING,
        "{name}: the empty shape is over the ceiling"
    );
    while over.saturating_sub(fits) > 1 {
        let mid = fits.saturating_add(over.saturating_sub(fits) / 2);
        if depth_of(name, shape, mid) <= CEILING {
            fits = mid;
        } else {
            over = mid;
        }
    }
    fits
}

/// Pin every shape in `cases` at the ceiling and one repetition past it.
fn proves(cases: &[Case]) {
    for &(name, shape) in cases {
        let n = at_ceiling(name, shape);
        assert!(n > 0, "{name}: one repetition is already over the ceiling");
        let control = scan_source_on(CONTROL_STACK, &shape(n)).err();
        assert!(
            control.is_none(),
            "{name}: the control at the ceiling ({n} repetitions) is refused: {control:?}"
        );
        let over = scan_source(&shape(n.saturating_add(1))).err();
        assert!(
            matches!(over, Some(ScanError::TooDeep { .. })),
            "{name}: one repetition past the ceiling is not refused as too deep: {over:?}"
        );
    }
}

#[test]
fn expressions_fit_at_the_ceiling_and_are_refused_past_it() {
    let cases: &[Case] = &[
        ("unary not", |n| expr(&format!("{}a", "! ".repeat(n)))),
        ("unary negation", |n| expr(&format!("{}a", "- ".repeat(n)))),
        ("unary deref", |n| expr(&format!("{}a", "* ".repeat(n)))),
        ("unary reference", |n| expr(&format!("{}a", "& ".repeat(n)))),
        ("binary chain", |n| expr(&format!("a{}", " + a".repeat(n)))),
        ("assignment chain", |n| {
            expr(&format!("a{}", " = a".repeat(n)))
        }),
        ("cast chain", |n| expr(&format!("a{}", " as T".repeat(n)))),
        ("return chain", |n| {
            expr(&format!("{}a", "return ".repeat(n)))
        }),
        ("yield chain", |n| expr(&format!("{}a", "yield ".repeat(n)))),
        ("method chain", |n| expr(&format!("a{}", ".m()".repeat(n)))),
        ("field chain", |n| expr(&format!("a{}", ".f".repeat(n)))),
        ("tuple index chain", |n| {
            expr(&format!("a{}", ".0.1".repeat(n)))
        }),
        ("try chain", |n| expr(&format!("a{}", "?".repeat(n)))),
        ("parentheses", |n| expr(&wrap(n, "(", "a", ")"))),
        ("prefix against segment", |n| {
            expr(&nest(n, "x", |inner| format!("({inner})+a+a")))
        }),
        ("attributes in a chain", |n| {
            expr(&format!("a{}", " + #[x] a".repeat(n)))
        }),
        ("else-if chain", |n| {
            expr(&format!("{}{{}}", "if a {} else ".repeat(n)))
        }),
        ("let chain", |n| {
            expr(&format!("if a{} {{}}", " && let _ = a".repeat(n)))
        }),
        ("nested blocks", |n| expr(&wrap(n, "{ ", "a", " }"))),
        ("nested match", |n| {
            expr(&wrap(n, "match a { _ => ", "a", " }"))
        }),
    ];
    proves(cases);
}

#[test]
fn closures_fit_at_the_ceiling_and_are_refused_past_it() {
    let cases: &[Case] = &[
        ("closure chain", |n| expr(&format!("{}a", "|x| ".repeat(n)))),
        ("move closure chain", |n| {
            expr(&format!("{}a", "move |x| ".repeat(n)))
        }),
        ("two-parameter closure chain", |n| {
            expr(&format!("{}a", "|a, b| ".repeat(n)))
        }),
        ("closure behind a bit-or", |n| {
            expr(&format!("{}a", "x | |a, b| ".repeat(n)))
        }),
    ];
    proves(cases);
}

#[test]
fn patterns_fit_at_the_ceiling_and_are_refused_past_it() {
    let cases: &[Case] = &[
        ("nested tuple-struct pattern", |n| {
            pat(&wrap(n, "S(", "_", ")"))
        }),
        ("binding chain", |n| pat(&format!("{}_", "a @ ".repeat(n)))),
        ("match guard over bit-or", |n| {
            format!(
                "fn f() {{\n    match a {{\n        x if a{} => {{}}\n    }}\n}}\n",
                " | a".repeat(n)
            )
        }),
    ];
    proves(cases);
}

#[test]
fn types_fit_at_the_ceiling_and_are_refused_past_it() {
    let cases: &[Case] = &[
        ("generic arguments", |n| ty(&wrap(n, "A<", "u8", ">"))),
        ("reference chain", |n| ty(&format!("{}u8", "&".repeat(n)))),
        ("raw pointer chain", |n| {
            ty(&format!("{}u8", "*const ".repeat(n)))
        }),
        ("function pointer chain", |n| {
            ty(&format!("{}u8", "fn() -> ".repeat(n)))
        }),
        ("nested tuples", |n| {
            ty(&nest(n, "u8", |inner| format!("({inner},)")))
        }),
        ("nested arrays", |n| {
            ty(&nest(n, "u8", |inner| format!("[{inner}; 1]")))
        }),
    ];
    proves(cases);
}

#[test]
fn macro_bodies_fit_at_the_ceiling_and_are_refused_past_it() {
    let cases: &[Case] = &[
        ("nested macro groups", |n| {
            format!("fn f() {{\n    m!({});\n}}\n", wrap(n, "(", "a", ")"))
        }),
        ("gated item over a flat run", |n| {
            format!(
                "m! {{\n    #[cfg(test)]\n    fn g() {{\n        let _ = a{};\n    }}\n}}\n",
                " + a".repeat(n)
            )
        }),
        ("nested cfg_attr operand", |n| {
            format!(
                "#[{}]\nfn g() {{}}\n",
                wrap(n, "cfg_attr(unix, ", "doc = \"x\"", ")")
            )
        }),
        ("nested attribute in a macro body", |n| {
            format!(
                "m! {{\n    #[{}]\n    x\n}}\n",
                wrap(n, "cfg_attr(unix, ", "doc = \"x\"", ")")
            )
        }),
        ("stacked attributes", |n| {
            format!("{}fn g() {{}}\n", "#[a] ".repeat(n))
        }),
    ];
    proves(cases);
}

#[test]
fn use_trees_fit_at_the_ceiling_and_are_refused_past_it() {
    // `syn` parses a `use` tree, and the scan judges it, one recursion per `::`.
    let cases: &[Case] = &[
        ("use path chain", |n| format!("use a{};\n", "::a".repeat(n))),
        ("use path chain in a group", |n| {
            format!("use a::{{a{}}};\n", "::a".repeat(n))
        }),
        ("use path chain in a macro body", |n| {
            format!("m! {{\n    use a{};\n}}\n", "::a".repeat(n))
        }),
    ];
    proves(cases);
}

#[test]
fn blocks_and_literals_fit_at_the_ceiling_and_are_refused_past_it() {
    let cases: &[Case] = &[
        ("nested struct literals", |n| {
            expr(&nest(n, "a", |inner| format!("S {{ a: {inner} }}")))
        }),
        ("nested labeled blocks", |n| {
            expr(&wrap(n, "'a: { ", "a", " }"))
        }),
        ("nested async blocks", |n| {
            expr(&wrap(n, "async { ", "a", " }"))
        }),
        ("nested unsafe blocks", |n| {
            expr(&wrap(n, "unsafe { ", "a", " }"))
        }),
        ("nested arrays", |n| expr(&wrap(n, "[", "a", "]"))),
        ("nested tuples", |n| {
            expr(&nest(n, "a", |inner| format!("({inner},)")))
        }),
        ("nested ranges", |n| expr(&wrap(n, "..(", "a", ")"))),
        ("await chain", |n| expr(&format!("a{}", ".await".repeat(n)))),
        ("index chain", |n| expr(&format!("a{}", "[0]".repeat(n)))),
        ("call chain", |n| expr(&format!("a{}", "()".repeat(n)))),
        ("joint reference chain", |n| {
            expr(&format!("{}a", "&".repeat(n)))
        }),
        ("nested turbofish", |n| {
            expr(&format!("f::<{}>()", wrap(n, "A<", "u8", ">")))
        }),
    ];
    proves(cases);
}

#[test]
fn bounds_and_paths_fit_at_the_ceiling_and_are_refused_past_it() {
    let cases: &[Case] = &[
        ("nested qualified paths", |n| {
            ty(&nest(n, "T", |inner| format!("<{inner} as A>::B")))
        }),
        ("nested impl trait", |n| ty(&wrap(n, "impl A<", "u8", ">"))),
        ("nested dyn trait", |n| ty(&wrap(n, "&dyn A<", "u8", ">"))),
        ("nested fn trait sugar", |n| {
            ty(&nest(n, "u8", |inner| format!("dyn Fn({inner}) -> u8")))
        }),
        ("nested const generic blocks", |n| {
            ty(&nest(n, "u8", |inner| {
                format!("A<{{ let _: {inner} = a; 1 }}>")
            }))
        }),
        ("nested struct patterns", |n| {
            pat(&nest(n, "_", |inner| format!("S {{ a: {inner} }}")))
        }),
        ("nested slice patterns", |n| pat(&wrap(n, "[", "_", "]"))),
        ("reference pattern chain", |n| {
            pat(&format!("{}_", "&".repeat(n)))
        }),
    ];
    proves(cases);
}

#[test]
fn items_and_attributes_fit_at_the_ceiling_and_are_refused_past_it() {
    let cases: &[Case] = &[
        ("nested modules", |n| wrap(n, "mod a { ", "", "}")),
        ("nested functions", |n| wrap(n, "fn f() { ", "", "}")),
        ("nested impl blocks", |n| {
            wrap(n, "fn f() { impl S { fn g() { ", "", "} } }")
        }),
        ("nested use groups", |n| {
            format!("use {};\n", wrap(n, "a::{", "a", "}"))
        }),
        ("nested cfg all", |n| {
            format!("#[cfg({})]\nfn g() {{}}\n", wrap(n, "all(", "test", ")"))
        }),
        ("nested attribute lists", |n| {
            format!("#[{}]\nfn g() {{}}\n", wrap(n, "a(", "b", ")"))
        }),
    ];
    proves(cases);
}

#[test]
fn a_tuple_index_pair_weighs_as_two_fields() {
    // `a.0.1` is two nested fields behind one `.`: the float `0.1` is split.
    for n in [1_usize, 64, 1024] {
        let pairs = depth_of(
            "tuple index pairs",
            |k| expr(&format!("a{}", ".0.1".repeat(k))),
            n,
        );
        let fields = depth_of(
            "named fields",
            |k| expr(&format!("a{}", ".f".repeat(k))),
            n.saturating_mul(2),
        );
        assert!(
            pairs >= fields,
            "{n} tuple-index pairs measure {pairs}, under the {fields} of as many named fields"
        );
    }
}

#[test]
fn a_flat_or_pattern_of_real_length_is_scanned() {
    let src = format!(
        "fn f() {{\n    match a {{\n        A{} => {{}}\n        _ => {{}}\n    }}\n}}\n",
        " | A".repeat(1074)
    );
    let found = measure(&src);
    assert!(
        matches!(found, Ok(measured) if measured.depth <= CEILING),
        "{found:?}"
    );
    let scanned = scan_source(&src).err();
    assert!(scanned.is_none(), "{scanned:?}");
}

#[test]
fn a_source_one_byte_past_the_ceiling_is_too_large() {
    let head = "fn f() {}\n//";
    let at = format!(
        "{head}{}",
        "x".repeat(SourceBytes::CEILING.get().saturating_sub(head.len()))
    );
    assert_eq!(at.len(), SourceBytes::CEILING.get());
    let control = scan_source(&at).err();
    assert!(control.is_none(), "{control:?}");
    let over = scan_source(&format!("{at}x")).err();
    assert!(matches!(over, Some(ScanError::TooLarge { .. })), "{over:?}");
}

#[test]
fn a_source_one_token_past_the_ceiling_has_too_many_tokens() {
    // Ten tokens besides the run: `const A : & [u8] = & [..] ;`, `u8` and the
    // run's group; each `0,` adds two.
    let run = TokenCeiling::CEILING.get().saturating_sub(10) / 2;
    let at = format!("const A: &[u8] = &[{}];\n", "0,".repeat(run));
    let control = measure(&at);
    assert!(
        matches!(control, Ok(measured) if measured.tokens == TokenCeiling::CEILING.get()),
        "{control:?}"
    );
    let over = scan_source(&format!("const A: &[u8] = &[{}0];\n", "0,".repeat(run))).err();
    assert!(
        matches!(over, Some(ScanError::TooManyTokens { .. })),
        "{over:?}"
    );
}

#[test]
fn a_parse_error_reports_its_own_line() {
    let src = "fn a() {}\nfn b() {}\nfn c() {}\nfn d() {}\nlet x = 1;\n";
    let refused = scan_source(src).err();
    assert!(
        matches!(refused, Some(ScanError::Parse { line: 5, .. })),
        "{refused:?}"
    );
}

/// A fresh scratch directory under the test target directory.
#[allow(clippy::expect_used)] // a test that cannot build its tree has nothing to assert
fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("panic-scan-depth-ceiling")
        .join(name);
    // A leftover from an earlier run may be absent; the fresh contents written
    // afterwards are what the test relies on.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("tests")).expect("create scratch directory");
    dir
}

#[test]
#[allow(clippy::expect_used)] // a test that cannot build its tree has nothing to assert
fn a_too_deep_declaring_file_is_refused_not_overflowed() {
    let deep = format!(
        "#[cfg(test)]\nmod tests;\n{}",
        expr(&format!("{}a", "! ".repeat(CEILING.saturating_add(1))))
    );
    let root = scratch("deep-declaring-file");
    std::fs::write(root.join("lib.rs"), &deep).expect("write lib.rs");
    std::fs::write(root.join("tests").join("a.rs"), "").expect("write tests/a.rs");
    let judged = check_test_path(&root, Path::new("tests/a.rs"));
    assert!(
        matches!(
            judged,
            Err(TestPathError::Unparseable {
                error: ScanError::TooDeep { .. },
                ..
            })
        ),
        "{judged:?}"
    );
    let lines = test_only_item_lines(&deep);
    assert!(matches!(lines, Err(ScanError::TooDeep { .. })), "{lines:?}");
}

#[test]
#[allow(clippy::expect_used)] // the repository's own sources must be readable and lex
fn the_repository_maximum_sits_under_the_ceilings() {
    let root = e2e_support::manifest_dir!().join("..").join("..");
    for rel in [
        "src/compiler/backend/rust/src/emit_ui_plan.rs",
        "src/compiler/kernels/src/lib.rs",
        "src/compiler/lower/src/lower.rs",
    ] {
        let src = read_source(&root.join(rel)).expect(rel);
        let found = measure(&src).expect(rel);
        println!(
            "{rel}: nest depth {} (line {}), {} tokens",
            found.depth, found.line, found.tokens
        );
        assert!(
            found.depth < CEILING,
            "{rel}: nest depth {} is not under the ceiling of {CEILING}",
            found.depth
        );
        assert!(
            found.tokens.saturating_mul(4) <= TokenCeiling::CEILING.get(),
            "{rel}: {} tokens leave less than a 4x margin under the token ceiling",
            found.tokens
        );
    }
}

#[test]
#[allow(clippy::expect_used)] // the crate's own sources must be readable
fn only_the_bounded_entry_parses_a_whole_file() {
    let src = e2e_support::manifest_dir!().join("src");
    let mut parsers = Vec::new();
    for entry in std::fs::read_dir(&src).expect("read src") {
        let path = entry.expect("read a src entry").path();
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read a source file");
        if ["parse_file", "parse_str"]
            .iter()
            .any(|entry_point| text.contains(entry_point))
        {
            parsers.extend(
                path.file_name()
                    .map(|name| name.to_string_lossy().into_owned()),
            );
        }
    }
    assert_eq!(parsers, ["bounded.rs"]);
}
