#![forbid(unsafe_code)]
//! The type ceiling: every type former's deepest accepted chain builds, and
//! one level more is refused at the place that crossed the ceiling.
//!
//! Each case is a `let` chain in `main` whose bindings each wrap the one
//! before in one type former, so the chain's type grows one level per
//! binding. The deepest chain the checker accepts reaches exactly
//! [`TYPE_DEPTH_LIMIT`] levels in some type of the program, and under
//! `IPE_E2E=1` (the CI `e2e` job) its emitted crate is built with cargo. The
//! chain one binding longer is refused with IPE-T0022 at the exact span whose
//! type first passes the ceiling (the CI `test-run` job). A function applied to
//! the growing value has a type one arrow deeper than the value it returns, so
//! a former written as an application reaches the ceiling one binding earlier,
//! and a use whose callee takes the value reaches it one binding earlier again.
//!
//! Declared types are measured where they are written, used or not: a chain of
//! custom types each holding the one before is as deep as it is long, so the
//! one declaration past the ceiling is refused at the constructor that crosses
//! it, a top-level annotation past the ceiling at its name, and a custom type
//! that refers to itself with a growing parameter with IPE-T0024 at its name.
//! A custom type passing its parameters on permuted is as deep as every
//! arrangement its constructors reach, together, and is refused at the
//! constructor that permutes them. A parameter no field uses is accepted and
//! erased from the emitted enum, and a generic its erasure leaves no argument
//! to infer from is pinned at each call; a bounded generic only an erased
//! parameter names is refused with IPE-L0102 where its body reads it. A custom
//! type whose instantiations grow past the size ceiling is refused with
//! IPE-T0023 at the constructor applying the one that crosses it.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use ipe::CliError;
use ipe_diagnostics::nesting::{TYPE_DEPTH_LIMIT, TYPE_SIZE_LIMIT};
use ipe_diagnostics::{Diagnostic, IPE_L0102, IPE_T0022, IPE_T0023, IPE_T0024, Span, TypeError};

/// Where the chain one binding past the deepest is refused.
#[derive(Clone, Copy)]
enum RefusedAt {
    /// The last binding's whole body: the former's own value passes.
    Body,
    /// The head of the last binding's body, a function whose arrow passes.
    Head(&'static str),
    /// This callee in `main`'s body, whose arrow over the chain passes.
    Use(&'static str),
}

/// One type former and the chain built from it.
struct Former {
    name: &'static str,
    /// Import lines beyond `Ipe.Io`.
    imports: &'static str,
    /// Top-level declarations before `main`.
    decls: &'static str,
    /// A binding's body over the previous binding's name.
    wrap: fn(&str) -> String,
    /// `main`'s body over the last binding's name and the chain's length.
    body: fn(&str, usize) -> String,
    /// The type levels the chain's own value stops short of the ceiling.
    short_of_ceiling: usize,
    refused_at: RefusedAt,
}

/// `main`'s body comparing the last binding with itself, so the value is
/// compared and used twice.
fn compare(last: &str, _: usize) -> String {
    format!("Io.println (if {last} == {last} then \"same\" else \"differs\")")
}

/// Every former the checker measures, with the chain each builds.
fn formers() -> [Former; 11] {
    let plain = |name, wrap, refused_at| Former {
        name,
        imports: "",
        decls: "",
        wrap,
        body: compare,
        short_of_ceiling: 0,
        refused_at,
    };
    [
        plain("record", |x| format!("{{ a = {x} }}"), RefusedAt::Body),
        plain("tuple_last", |x| format!("( 0, {x} )"), RefusedAt::Body),
        plain("tuple_first", |x| format!("( {x}, 0 )"), RefusedAt::Body),
        plain("list", |x| format!("[ {x} ]"), RefusedAt::Body),
        // `Just : a -> Maybe a` is one arrow over the value it builds.
        Former {
            short_of_ceiling: 1,
            ..plain("maybe", |x| format!("Just {x}"), RefusedAt::Head("Just"))
        },
        Former {
            decls: "type Wrap a\n    = Wrap a\n\n\n",
            short_of_ceiling: 1,
            ..plain(
                "user_union",
                |x| format!("Wrap {x}"),
                RefusedAt::Head("Wrap"),
            )
        },
        // `ok : a -> Result String a` is one arrow over the value it builds.
        Former {
            decls: "ok : a -> Result String a\nok x =\n    Ok x\n\n\n",
            short_of_ceiling: 1,
            ..plain("result", |x| format!("ok {x}"), RefusedAt::Head("ok"))
        },
        // A decoder has no equality, so `main` runs it; `Decode.decodeJson`
        // takes the decoder after its input, two arrows over the decoder.
        Former {
            name: "decoder",
            imports: "import Ipe.Config as Decode\n",
            decls: "report : Result e a -> String\nreport result =\n    case result of\n        Ok _ ->\n            \"ok\"\n\n        Err _ ->\n            \"err\"\n\n\n",
            wrap: |x| format!("Decode.succeed {x}"),
            body: |last, _| format!("Io.println (report (Decode.decodeJson \"0\" {last}))"),
            short_of_ceiling: 2,
            refused_at: RefusedAt::Use("Decode.decodeJson"),
        },
        // `Dict.singleton : k -> v -> Dict k v` is two arrows over its value.
        Former {
            imports: "import Ipe.Dict as Dict\n",
            short_of_ceiling: 2,
            ..plain(
                "dict",
                |x| format!("Dict.singleton 0 {x}"),
                RefusedAt::Head("Dict.singleton"),
            )
        },
        // Applying the chain to all its arguments reads its own type, no deeper.
        Former {
            name: "lambda",
            imports: "import Ipe.String as String\n",
            decls: "",
            wrap: |x| format!("\\_ -> {x}"),
            body: |last, n| format!("Io.println (String.fromInt ({last}{}))", " 0".repeat(n)),
            short_of_ceiling: 0,
            refused_at: RefusedAt::Body,
        },
        // A task has no equality, so `main` runs it; `Task.andThen` takes the
        // task, its arrow two levels over the task's value.
        Former {
            name: "task",
            imports: "import Ipe.Task as Task\n",
            decls: "",
            wrap: |x| format!("Task.succeed {x}"),
            body: |last, _| format!("Task.andThen (\\_ -> Io.println \"done\") {last}"),
            short_of_ceiling: 2,
            refused_at: RefusedAt::Use("Task.andThen"),
        },
    ]
}

/// A chain's source and the span its refusal must carry.
struct Chain {
    src: String,
    refused_at: Span,
}

/// A byte offset as a span bound.
fn offset(at: usize) -> u32 {
    u32::try_from(at).unwrap_or(u32::MAX)
}

/// `former`'s chain of `n` bindings after `x0`.
fn chain(former: &Former, n: usize) -> Chain {
    let mut src = format!(
        "module Main exposing (main)\n\nimport Ipe.Io as Io\n{}\n\n{}main =\n    let\n        x0 = 0\n",
        former.imports, former.decls
    );
    let mut last_body = (0, String::new());
    for i in 1..=n {
        let body = (former.wrap)(&format!("x{}", i - 1));
        let _ = write!(src, "        x{i} = ");
        last_body = (src.len(), body.clone());
        src.push_str(&body);
        src.push('\n');
    }
    src.push_str("    in\n    ");
    let use_at = src.len();
    let use_body = (former.body)(&format!("x{n}"), n);
    src.push_str(&use_body);
    src.push('\n');
    let (lo, hi) = match former.refused_at {
        RefusedAt::Body => (last_body.0, last_body.0 + last_body.1.len()),
        RefusedAt::Head(head) => (last_body.0, last_body.0 + head.len()),
        RefusedAt::Use(callee) => {
            let at = use_at + use_body.find(callee).unwrap_or(use_body.len());
            (at, at + callee.len())
        }
    };
    Chain {
        src,
        refused_at: Span {
            lo: offset(lo),
            hi: offset(hi),
        },
    }
}

/// The deepest chain `former` builds that the checker accepts.
fn deepest(former: &Former) -> usize {
    usize::from(TYPE_DEPTH_LIMIT) - former.short_of_ceiling
}

/// Type-check, lower and emit `src` as a project's `Main` module, no cargo.
fn front_check(src: &str) -> Result<(), CliError> {
    ipe::front_check(ipe::RootFixture::main(src)?.root())
}

/// The pipeline diagnostic `result` was refused with, if it was.
fn refusal(result: &Result<(), CliError>) -> Option<&Diagnostic> {
    match result {
        Err(CliError::Pipeline { diag, .. }) => Some(diag),
        _ => None,
    }
}

/// Every former's deepest chain is accepted, and one binding more is refused
/// with IPE-T0022 at the span whose type first passes the ceiling.
#[test]
fn one_level_past_the_type_ceiling_is_refused_where_it_is_crossed() {
    for former in formers() {
        let name = former.name;
        let n = deepest(&former);
        let accepted = front_check(&chain(&former, n).src);
        assert!(
            accepted.is_ok(),
            "{name}: the chain of {n} must be accepted: {accepted:?}"
        );
        let past = chain(&former, n + 1);
        let refused = front_check(&past.src);
        let diag = refusal(&refused);
        assert_eq!(
            diag.map(Diagnostic::code),
            Some(IPE_T0022),
            "{name}: the chain of {} must be refused: {refused:?}",
            n + 1
        );
        assert_eq!(
            diag,
            Some(&Diagnostic::Type {
                span: past.refused_at,
                msg: TypeError::TypeTooDeep {
                    depth: TYPE_DEPTH_LIMIT + 1,
                    limit: TYPE_DEPTH_LIMIT,
                },
            }),
            "{name}: refused at {:?} ({:?})",
            past.refused_at,
            past.src
                .get(past.refused_at.lo as usize..past.refused_at.hi as usize)
        );
    }
}

/// Emit `src` into `out` and build the emitted crate with cargo as `bin`.
fn assert_builds_with_cargo(src: &str, out: &Path, runtime: &Path, bin: &str) {
    let emitted = ipe::RootFixture::main(src)
        .and_then(|fixture| ipe::build_fixture(&fixture, out, runtime).map(|_| ()));
    assert!(emitted.is_ok(), "{bin}: must emit: {emitted:?}");
    let built = e2e_support::build_rust_binary(bin, out);
    assert!(
        built.is_ok(),
        "{bin}: the emitted crate must build with cargo: {}",
        built.err().unwrap_or_default()
    );
}

/// Every former's deepest accepted chain builds with cargo. Gated on
/// `IPE_E2E=1` (the CI `e2e` job): the seal cargo-builds each emitted crate.
#[test]
fn deepest_accepted_chain_of_every_former_builds_with_cargo() {
    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let runtime = e2e_support::require_runtime().into_path_buf();
        let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("ipe_type_ceiling_{}", std::process::id()));
        for former in formers() {
            let src = chain(&former, deepest(&former)).src;
            let bin = format!("type_ceiling_{}", former.name);
            assert_builds_with_cargo(&src, &scratch.join(former.name), &runtime, &bin);
        }
        let _ = std::fs::remove_dir_all(&scratch);
    }
}

/// A module whose `main` prints a constant after `decls`.
fn with_decls(decls: &str) -> String {
    format!(
        "module Main exposing (main)\n\nimport Ipe.Io as Io\n\n\n{decls}main =\n    Io.println \"ok\"\n"
    )
}

/// The span of the first `needle` in `src` at or after byte `from`.
fn span_of(src: &str, needle: &str, from: usize) -> Span {
    let lo = src
        .get(from..)
        .and_then(|rest| rest.find(needle))
        .map_or(src.len(), |at| from + at);
    Span {
        lo: offset(lo),
        hi: offset(lo + needle.len()),
    }
}

/// `type U0 = U0` and `type U{k} = U{k} U{k-1}` through `U{n}`, `U{k}` declared
/// `k` levels deep, and the span of `U{n}`'s constructor.
fn union_chain(n: usize) -> Chain {
    let mut decls = String::from("type U0\n    = U0\n\n\n");
    for k in 1..=n {
        let _ = write!(decls, "type U{k}\n    = U{k} U{}\n\n\n", k - 1);
    }
    let src = with_decls(&decls);
    let ctor = format!("= U{n} ");
    let at = span_of(&src, &ctor, 0);
    Chain {
        refused_at: Span {
            lo: at.lo + 2,
            hi: at.hi - 1,
        },
        src,
    }
}

/// `deep : List (List … Int)` with `n` lists, unused, and the span of the name
/// its definition binds.
fn annotation_chain(n: usize) -> Chain {
    let src = with_decls(&format!(
        "deep : {}Int{}\ndeep =\n    []\n\n\n",
        "List (".repeat(n - 1) + "List ",
        ")".repeat(n - 1)
    ));
    let at = span_of(&src, "\ndeep =", 0);
    Chain {
        refused_at: Span {
            lo: at.lo + 1,
            hi: at.lo + 1 + offset("deep".len()),
        },
        src,
    }
}

/// `Nested` refers to itself at `inner`, given over its parameter `a`.
fn nested(inner: &str) -> String {
    with_decls(&format!(
        "type Nested a\n    = Leaf a\n    | Nest {inner}\n\n\n"
    ))
}

/// A refusal of `src` with IPE-T0022 at `span`, `depth` levels deep.
fn assert_too_deep(src: &str, span: Span, depth: u16) {
    let refused = front_check(src);
    assert_eq!(
        refusal(&refused),
        Some(&Diagnostic::Type {
            span,
            msg: TypeError::TypeTooDeep {
                depth,
                limit: TYPE_DEPTH_LIMIT,
            },
        }),
        "refused at {span:?} ({:?}): {refused:?}",
        src.get(span.lo as usize..span.hi as usize)
    );
}

/// The custom type chain as deep as the ceiling is accepted, and the one
/// declaration more is refused at its constructor, used or not.
#[test]
fn a_custom_type_chain_one_past_the_ceiling_is_refused_at_its_constructor() {
    let n = usize::from(TYPE_DEPTH_LIMIT);
    let accepted = front_check(&union_chain(n).src);
    assert!(
        accepted.is_ok(),
        "the chain of {n} must be accepted: {accepted:?}"
    );
    let past = union_chain(n + 1);
    assert_too_deep(&past.src, past.refused_at, TYPE_DEPTH_LIMIT + 1);
}

/// An annotation as deep as the ceiling is accepted, and one level more is
/// refused at the name it annotates, used or not.
#[test]
fn an_annotation_one_past_the_ceiling_is_refused_at_its_name() {
    let n = usize::from(TYPE_DEPTH_LIMIT);
    let accepted = front_check(&annotation_chain(n).src);
    assert!(
        accepted.is_ok(),
        "the annotation of {n} must be accepted: {accepted:?}"
    );
    let past = annotation_chain(n + 1);
    assert_too_deep(&past.src, past.refused_at, TYPE_DEPTH_LIMIT + 1);
}

/// A custom type that refers to itself with its parameter inside a larger type
/// is refused with IPE-T0024 at its name; the same type holding a list of
/// itself is accepted.
#[test]
fn a_custom_type_growing_at_each_self_reference_is_refused_at_its_name() {
    let accepted = front_check(&nested("(List (Nested a))"));
    assert!(
        accepted.is_ok(),
        "a list of itself must be accepted: {accepted:?}"
    );
    let src = nested("(Nested (List a))");
    let refused = front_check(&src);
    let diag = refusal(&refused);
    assert_eq!(diag.map(Diagnostic::code), Some(IPE_T0024), "{refused:?}");
    assert_eq!(
        diag,
        Some(&Diagnostic::Type {
            span: span_of(&src, "Nested", 0),
            msg: TypeError::ExpansiveRecursion {
                union: "Nested".into(),
                param: "a".into(),
            },
        }),
        "{refused:?}"
    );
}

/// The deepest accepted declarations build with cargo. Gated on `IPE_E2E=1`
/// (the CI `e2e` job).
#[test]
fn deepest_accepted_declarations_build_with_cargo() {
    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let runtime = e2e_support::require_runtime().into_path_buf();
        let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("ipe_type_ceiling_decls_{}", std::process::id()));
        let n = usize::from(TYPE_DEPTH_LIMIT);
        let cases = [
            ("union_chain", union_chain(n).src),
            ("annotation", annotation_chain(n).src),
            ("regular_nested", nested("(List (Nested a))")),
        ];
        for (name, src) in cases {
            let bin = format!("type_ceiling_{name}");
            assert_builds_with_cargo(&src, &scratch.join(name), &runtime, &bin);
        }
        let _ = std::fs::remove_dir_all(&scratch);
    }
}

/// `type R a1 … ak = Z | E a1 … ak | Rot (R a2 … ak a1)`, `k` nullary types
/// `K0 … K{k-1}`, a value `v : R K0 … K{k-1}` compared with itself, and the
/// span of `Rot`'s name.
///
/// `Rot` passes the parameters on rotated, so rustc builds all `k` rotations
/// of `R`, each one level over its payload: the declaration is `2 * k` deep.
fn rotation(k: usize) -> Chain {
    let params: Vec<String> = (1..=k).map(|n| format!("a{n}")).collect();
    let rotated: Vec<&str> = params
        .iter()
        .cycle()
        .skip(1)
        .take(k)
        .map(String::as_str)
        .collect();
    let mut decls = format!(
        "type R {params}\n    = Z\n    | E {params}\n    | Rot (R {rotated})\n\n\n",
        params = params.join(" "),
        rotated = rotated.join(" "),
    );
    for n in 0..k {
        let _ = write!(decls, "type K{n}\n    = K{n}\n\n\n");
    }
    let args: Vec<String> = (0..k).map(|n| format!("K{n}")).collect();
    let _ = write!(decls, "v : R {}\nv =\n    Z\n\n\n", args.join(" "));
    let src = format!(
        "module Main exposing (main)\n\nimport Ipe.Io as Io\n\n\n{decls}main =\n    {}\n",
        compare("v", 0)
    );
    let at = span_of(&src, "| Rot (", 0);
    Chain {
        refused_at: Span {
            lo: at.lo + 2,
            hi: at.lo + 2 + offset("Rot".len()),
        },
        src,
    }
}

/// A custom type passing its parameters on rotated is as deep as its rotations
/// together: the rotation reaching the ceiling is accepted, and the one
/// parameter more is refused at the constructor that rotates them.
#[test]
fn a_permuting_type_one_past_the_ceiling_is_refused_at_its_rotating_constructor() {
    let k = usize::from(TYPE_DEPTH_LIMIT) / 2;
    let accepted = front_check(&rotation(k).src);
    assert!(
        accepted.is_ok(),
        "the rotation of {k} must be accepted: {accepted:?}"
    );
    let past = rotation(k + 1);
    assert_too_deep(&past.src, past.refused_at, TYPE_DEPTH_LIMIT + 2);
}

/// The deepest accepted rotation builds with cargo: every rotation rustc
/// instantiates is charged, so none overflows its drop-check walk. Gated on
/// `IPE_E2E=1` (the CI `e2e` job).
#[test]
fn deepest_accepted_rotation_builds_with_cargo() {
    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let runtime = e2e_support::require_runtime().into_path_buf();
        let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("ipe_type_ceiling_rotation_{}", std::process::id()));
        let src = rotation(usize::from(TYPE_DEPTH_LIMIT) / 2).src;
        assert_builds_with_cargo(&src, &scratch, &runtime, "type_ceiling_rotation");
        let _ = std::fs::remove_dir_all(&scratch);
    }
}

/// `T a` whose parameter no constructor holds except through `T a` itself, and
/// a polymorphic function over it applied at two arguments.
const UNUSED_PARAMETER: &str = "module Main exposing (main)\n\nimport Ipe.Io as Io\n\n\ntype T a\n    = L\n    | N (T a)\n\n\nsize : T a -> Int\nsize t =\n    case t of\n        L ->\n            0\n\n        N inner ->\n            1 + size inner\n\n\nints : T Int\nints =\n    N (N L)\n\n\nstrings : T String\nstrings =\n    N L\n\n\nmain =\n    Io.println (if size ints == 2 then \"two\" else if size strings == 1 then \"one\" else \"other\")\n";

/// A custom type parameter no field uses is accepted and builds with cargo:
/// the emitted enum carries no parameter rustc would refuse as unused. The
/// acceptance runs in the CI `test-run` job, the build under `IPE_E2E=1` (the
/// CI `e2e` job).
#[test]
fn a_custom_type_parameter_no_field_uses_builds_with_cargo() {
    let accepted = front_check(UNUSED_PARAMETER);
    assert!(accepted.is_ok(), "must be accepted: {accepted:?}");
    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let runtime = e2e_support::require_runtime().into_path_buf();
        let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "ipe_type_ceiling_unused_param_{}",
            std::process::id()
        ));
        assert_builds_with_cargo(
            UNUSED_PARAMETER,
            &scratch,
            &runtime,
            "type_ceiling_unused_param",
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }
}

/// `Tag a` whose parameter no constructor holds, so its erasure removes the
/// only argument naming `empties`'s generic: a caller at `Tag Int`, a caller
/// generic over the erased parameter, and an unannotated caller.
const ERASED_INFERENCE_PIN: &str = "module Main exposing (main)\n\nimport Ipe.Io as Io\nimport Ipe.List as List\n\n\ntype Tag a\n    = Tag\n\n\nempties : Tag a -> List a\nempties _ =\n    []\n\n\ncount : Tag Int -> Int\ncount t =\n    List.length (empties t)\n\n\ncountAny : Tag b -> Int\ncountAny t =\n    List.length (empties t)\n\n\ncountUnannotated t =\n    List.length (empties t)\n\n\nmain =\n    Io.println (if count Tag + countAny Tag + countUnannotated Tag == 0 then \"zero\" else \"other\")\n";

/// Every emitted Rust source file under `dir`.
fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path);
            }
        }
    }
    found
}

/// Every emitted Rust line under `dir` that calls `callee` with a turbofish.
fn turbofish_calls(dir: &Path, callee: &str) -> Vec<String> {
    let needle = format!("{callee}::<");
    rust_sources(dir)
        .iter()
        .flat_map(|path| {
            let text = std::fs::read_to_string(path).unwrap_or_default();
            text.lines()
                .filter(|line| line.contains(&needle))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// A generic whose only naming argument a parameter erasure removed is pinned
/// at each call by its instantiation: `i64` at `Tag Int`, `()` where the
/// caller's own generic was erased too. The emitted calls are read in the CI
/// `test-run` job; the crate builds with cargo under `IPE_E2E=1` (the CI `e2e`
/// job).
#[test]
fn a_generic_named_only_by_an_erased_argument_is_pinned_at_each_call() {
    let runtime = e2e_support::require_runtime().into_path_buf();
    let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "ipe_type_ceiling_erased_pin_{}",
        std::process::id()
    ));
    let emitted = ipe::RootFixture::main(ERASED_INFERENCE_PIN)
        .and_then(|fixture| ipe::build_fixture(&fixture, &scratch, &runtime).map(|_| ()));
    assert!(emitted.is_ok(), "must emit: {emitted:?}");
    let calls = turbofish_calls(&scratch, "empties");
    assert!(
        calls.iter().any(|line| line.contains("empties::<i64>(")),
        "the `Tag Int` call must pin `i64`: {calls:?}"
    );
    assert!(
        calls
            .iter()
            .filter(|line| line.contains("empties::<()>("))
            .count()
            >= 2,
        "the calls over an erased caller generic must pin `()`: {calls:?}"
    );
    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let built = e2e_support::build_rust_binary("type_ceiling_erased_pin", &scratch);
        assert!(
            built.is_ok(),
            "the emitted crate must build with cargo: {}",
            built.err().unwrap_or_default()
        );
    }
    let _ = std::fs::remove_dir_all(&scratch);
}

/// `doubledCount` is generic over a `number` its body's `x + x` bounds, and
/// that only the erased parameter of `Tag` names, so its emitted signature
/// names no generic the body could read. The checker accepts it: the body adds
/// no literal to the annotated variable, and the one use pins it to `Int`
/// through `intTag`, since a use leaving a bounded generic unpinned is refused
/// with IPE-T0014.
const BOUNDED_ERASED_GENERIC: &str = "module Main exposing (main)\n\nimport Ipe.Io as Io\nimport Ipe.List as List\n\n\ntype Tag a\n    = Tag\n\n\nempties : Tag a -> List a\nempties _ =\n    []\n\n\nintTag : Tag Int\nintTag =\n    Tag\n\n\ndoubledCount : Tag number -> Int\ndoubledCount t =\n    case List.head (empties t) of\n        Just x ->\n            List.length [ x + x ]\n\n        Nothing ->\n            0\n\n\nmain =\n    Io.println (if doubledCount intTag == 0 then \"zero\" else \"other\")\n";

/// A bounded generic the emitted signature does not name has no reading in
/// its body: the build is refused with IPE-L0102 inside the body that reads
/// it, never a compiler bug, and no Rust is emitted. Read in the CI
/// `test-run` job.
#[test]
fn a_bounded_generic_only_an_erased_parameter_names_is_refused_where_it_is_read() {
    let runtime = e2e_support::require_runtime().into_path_buf();
    let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "ipe_type_ceiling_bounded_erased_{}",
        std::process::id()
    ));
    let built = ipe::RootFixture::main(BOUNDED_ERASED_GENERIC)
        .and_then(|fixture| ipe::build_fixture(&fixture, &scratch, &runtime).map(|_| ()));
    let diag = refusal(&built);
    assert_eq!(diag.map(Diagnostic::code), Some(IPE_L0102), "{built:?}");
    let src = BOUNDED_ERASED_GENERIC;
    let body = span_of(src, "doubledCount t =", 0);
    let main_at = span_of(src, "main =", offset_of(body));
    let span = diag.map(Diagnostic::primary_span);
    assert!(
        span.is_some_and(|s| s != Span::DUMMY
            && body.lo <= s.lo
            && s.lo < s.hi
            && s.hi <= main_at.lo),
        "refused at {span:?}, not inside doubledCount's body {}..{}: {built:?}",
        body.lo,
        main_at.lo
    );
    let emitted = rust_sources(&scratch);
    assert!(emitted.is_empty(), "no Rust may be emitted: {emitted:?}");
    let _ = std::fs::remove_dir_all(&scratch);
}

/// The byte offset `span` starts at.
fn offset_of(span: Span) -> usize {
    usize::try_from(span.lo).unwrap_or(usize::MAX)
}

/// `p0 = 0` and `pK = ( p{K-1}, p{K-1} )` through `p{n}`, compared with
/// itself, and the span of `p{n}`'s body.
fn doubling_chain(n: usize) -> Chain {
    let mut src = String::from(
        "module Main exposing (main)\n\nimport Ipe.Io as Io\n\n\nmain =\n    let\n        p0 = 0\n",
    );
    let mut last_body = (0, 0);
    for i in 1..=n {
        let _ = write!(src, "        p{i} = ");
        let lo = src.len();
        let _ = write!(src, "( p{0}, p{0} )", i - 1);
        last_body = (lo, src.len());
        src.push('\n');
    }
    let _ = write!(
        src,
        "    in\n    Io.println (if p{n} == p{n} then \"same\" else \"differs\")\n"
    );
    Chain {
        src,
        refused_at: Span {
            lo: offset(last_body.0),
            hi: offset(last_body.1),
        },
    }
}

/// A type that is shallow but unfolds to more than [`TYPE_SIZE_LIMIT`] nodes is
/// refused with IPE-T0023 at the binding that doubled past it; one doubling
/// less fits. `pK`'s type unfolds to `2^(K + 1) - 1` nodes.
#[test]
fn a_type_doubling_past_the_size_ceiling_is_refused() {
    let fits = front_check(&doubling_chain(15).src);
    assert!(
        fits.is_ok(),
        "a type of 2^16 - 1 nodes must be accepted: {fits:?}"
    );
    let past = doubling_chain(16);
    let refused = front_check(&past.src);
    let diag = refusal(&refused);
    assert_eq!(diag.map(Diagnostic::code), Some(IPE_T0023), "{refused:?}");
    assert_eq!(
        diag,
        Some(&Diagnostic::Type {
            span: past.refused_at,
            msg: TypeError::TypeTooLarge {
                limit: TYPE_SIZE_LIMIT,
            },
        })
    );
}

/// `type B p1 … pk = B p1 … pk` and `type T a b c d = Z | X (T Int (B a … a)
/// (B b … b) (B c … c))`, and the span of `X`'s name.
///
/// Each instantiation of `T` holds `B` over the previous one's arguments, so
/// the largest, `B (B (B Int …) …) …`, is `1 + k + k^2 + k^3` nodes: shallow,
/// but `k` times larger at each step.
fn widening(k: usize) -> Chain {
    let params: Vec<String> = (1..=k).map(|n| format!("p{n}")).collect();
    let over = |v: &str| format!("(B{})", format!(" {v}").repeat(k));
    let src = with_decls(&format!(
        "type B {params}\n    = B {params}\n\n\ntype T a b c d\n    = Z\n    | X (T Int {} {} {})\n\n\n",
        over("a"),
        over("b"),
        over("c"),
        params = params.join(" "),
    ));
    let at = span_of(&src, "| X (", 0);
    Chain {
        refused_at: Span {
            lo: at.lo + 2,
            hi: at.lo + 3,
        },
        src,
    }
}

/// A recursive type whose instantiations widen past [`TYPE_SIZE_LIMIT`] nodes
/// is refused with IPE-T0023 at the constructor that applies the widening
/// instantiation, before any of it is built; the widest that fits is accepted.
#[test]
fn a_type_whose_instantiations_widen_past_the_size_ceiling_is_refused() {
    let fits = front_check(&widening(39).src);
    assert!(fits.is_ok(), "a widening of 39 must be accepted: {fits:?}");
    for k in [40, 1500] {
        let past = widening(k);
        let refused = front_check(&past.src);
        assert_eq!(
            refusal(&refused),
            Some(&Diagnostic::Type {
                span: past.refused_at,
                msg: TypeError::TypeTooLarge {
                    limit: TYPE_SIZE_LIMIT,
                },
            }),
            "a widening of {k} must be refused: {refused:?}"
        );
    }
}

/// `main`'s body comparing the last binding with `0`, a type mismatch for
/// every chain whose value is not a number.
fn compare_with_zero(last: &str, _: usize) -> String {
    format!("Io.println (if {last} == 0 then \"zero\" else \"other\")")
}

/// The byte range of `src`'s last line, `main`'s body in every chain.
fn body_range(src: &str) -> (u32, u32) {
    let body = src.trim_end_matches('\n');
    let lo = body.rfind('\n').map_or(0, |at| at + 1);
    (offset(lo), offset(body.len()))
}

/// Assert `result` is refused with `code` at a span inside `main`'s body.
fn assert_refused_in_body(result: &Result<(), CliError>, src: &str, code: ipe_diagnostics::Code) {
    let diag = refusal(result);
    assert_eq!(diag.map(Diagnostic::code), Some(code), "{result:?}");
    let (lo, hi) = body_range(src);
    let span = match diag {
        Some(Diagnostic::Type { span, .. }) => Some(*span),
        _ => None,
    };
    assert!(
        span.is_some_and(|s| s != Span::DUMMY && lo <= s.lo && s.lo < s.hi && s.hi <= hi),
        "refused at {span:?}, not inside main's body {lo}..{hi}: {result:?}"
    );
}

/// A mismatch raised while solving, before every type is measured, over a
/// type past the depth ceiling is refused with IPE-T0022 at the mismatch; the
/// type is never read back or rendered for the mismatch's message.
#[test]
fn a_mismatch_over_a_type_past_the_depth_ceiling_is_refused_at_the_mismatch() {
    let former = Former {
        name: "record",
        imports: "",
        decls: "",
        wrap: |x| format!("{{ a = {x} }}"),
        body: compare_with_zero,
        short_of_ceiling: 0,
        refused_at: RefusedAt::Body,
    };
    let past = chain(&former, usize::from(TYPE_DEPTH_LIMIT) + 1);
    assert_refused_in_body(&front_check(&past.src), &past.src, IPE_T0022);
}

/// A mismatch raised while solving, before every type is measured, over a
/// type that unfolds past the size ceiling is refused with IPE-T0023 at the
/// mismatch, never at an unknown place.
#[test]
fn a_mismatch_over_a_type_past_the_size_ceiling_is_refused_at_the_mismatch() {
    let doubled = doubling_chain(16).src;
    let src = doubled.replace(
        "Io.println (if p16 == p16 then \"same\" else \"differs\")",
        &compare_with_zero("p16", 16),
    );
    assert_ne!(src, doubled, "the chain's body must be replaced");
    assert_refused_in_body(&front_check(&src), &src, IPE_T0023);
}
