//! Gate: a record `type alias` introduces a value-level
//! auto-constructor (IPE-N0001 fix). The `ipe` pipeline must emit a project
//! that builds and RUNS with the constructor binding fields **positionally in
//! declared order** — including the decisive same-typed order oracle, partial
//! application, a parametric record alias, and a bare reference reified into a
//! higher-order function.
//!
//! Behavioural oracle (hand-verified, documented against the design intent):
//! the program below prints, one per line:
//!
//! ```text
//! 7/hi     # Row { zebra = 7, apple = "hi" } — mixed-type, non-alphabetical
//! 1,2      # Pair { first = 1, second = 2 } — SAME-typed order oracle (not 2,1)
//! 4        # (mkPair 4).second, mkPair = Pair 3 — partial application keeps order
//! 99n      # Box { value = 99, tag = "n" } — parametric record alias
//! 60       # sum of Box values [10,20,30] — bare ctor reified into List.map
//! ok
//! ```
//!
//! The `1,2` line is load-bearing: both fields are `Int`, so a mis-ordered
//! constructor would still type-check but print `2,1`. Running the emitted
//! binary is therefore the only sound check of field-order correctness.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

const EXPECTED_STDOUT: &str = "7/hi\n1,2\n4\n99n\n60\nok\n";

#[test]
fn record_ctor_end_to_end_field_order() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("record_ctor")
        .join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m82_record_ctor_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("record_ctor", &out);
    assert_eq!(
        outcome.stdout, EXPECTED_STDOUT,
        "record-alias constructor must bind fields positionally in declared order"
    );
    assert_eq!(outcome.exit_code, Some(0), "clean exit");
}

/// A hand-written record literal and the alias's auto-constructor for the SAME
/// shape must resolve to ONE synthesised struct — the constructor introduces no
/// parallel representation. Emit-only (no `IPE_E2E` gate) so it runs in the
/// default suite. Both `viaLiteral` (record literal) and `viaCtor` (`Pt 1 2`)
/// return `Pt`, so their emitted return type is the same `Rec…` struct declared
/// exactly once.
#[test]
fn record_ctor_and_literal_share_one_struct() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("record_ctor_twin")
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m82_record_ctor_twin_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve: {:?}", runtime.err());
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let emitted = std::fs::read_to_string(out.join("src").join("main.rs"));
    assert!(emitted.is_ok(), "emitted main.rs must read");
    let Ok(src) = emitted else { return };

    // The `{ x, y }` shape resolves to `RecXY` (camel-cased field set). It must
    // be declared exactly once — the constructor reuses the literal's struct.
    let struct_defs = src.matches("pub struct RecXY ").count();
    assert_eq!(
        struct_defs, 1,
        "the record shape must have exactly one synthesised struct, got {struct_defs}"
    );
    // Both bindings return the same struct type.
    assert!(
        src.contains("fn main_via_literal() -> RecXY"),
        "literal-bearing binding returns RecXY"
    );
    assert!(
        src.contains("fn main_via_ctor() -> RecXY"),
        "ctor-bearing binding returns RecXY"
    );
    // The auto-constructor lowers to a plain record literal over its params —
    // the same construction a hand-written `{ x = …, y = … }` emits.
    assert!(
        src.contains("fn main_Pt(x: i64, y: i64) -> RecXY"),
        "the constructor `Pt` is a plain typed function `main_Pt`"
    );
    assert!(
        src.contains("RecXY { x: x, y: y }"),
        "the constructor body is an ordinary record literal"
    );
}

/// SEAL REGRESSION. A record `type alias` whose field embeds a function
/// NESTED inside a derive carrier (`List (Int -> Bool)`) must synthesise NO
/// constructor: the earlier head-only gate saw `Con "List"` (not `Lambda`) and
/// synthesised one, so the backend emitted a `#[derive(Clone, Debug, PartialEq)]`
/// struct over a `Box<dyn Fn>` field — ipe exit-0 then a cargo failure. This
/// emit-only check (default suite) confirms ipe succeeds AND that no struct for
/// the alias is emitted (no ctor). The companion `…_builds_and_runs` (`IPE_E2E`)
/// proves the emitted project actually cargo-builds — the decisive seal proof.
#[test]
fn seal_fn_field_alias_emits_no_struct() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("record_ctor_fn_field")
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m82_record_ctor_fn_field_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve: {:?}", runtime.err());
    let Ok(runtime) = runtime else { return };
    // ipe MUST succeed — a function-embedding alias that is merely NAMED
    // (declared, never constructed) is a valid program.
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipec must accept a merely-named function-embedding record alias: {:?}",
        built.err()
    );

    let emitted = std::fs::read_to_string(out.join("src").join("main.rs"));
    assert!(emitted.is_ok(), "emitted main.rs must read");
    let Ok(src) = emitted else { return };
    // No constructor was synthesised, so the field-set struct (`RecChecks`) and
    // the `main_Handlers` ctor function must be ABSENT — their presence would
    // mean a `Box<dyn Fn>`-field struct was emitted (the seal hole).
    assert!(
        !src.contains("RecChecks"),
        "no struct must be emitted for the un-constructed function-embedding alias"
    );
    assert!(
        !src.contains("main_Handlers"),
        "no constructor function must be emitted for the function-embedding alias"
    );
}

/// SEAL PROOF (`IPE_E2E`). The emitted project for the function-embedding
/// record alias must actually cargo-BUILD and run clean — ipe exit-0 AND cargo
/// exit-0. This is the exact class that regressed: ipe-success without a matching
/// cargo-success is the seal violation.
#[test]
fn seal_fn_field_alias_builds_and_runs() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("record_ctor_fn_field")
        .join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m82_record_ctor_fn_field_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "ipe build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("record_ctor_fn_field", &out);
    assert_eq!(
        outcome.stdout, "ok\n",
        "the function-embedding alias program must build and run clean"
    );
    assert_eq!(outcome.exit_code, Some(0), "clean exit (seal holds)");
}

/// ROUND-2 SEAL REGRESSION. A record `type alias` whose field is an OPAQUE
/// boxed-wrapper (`Decoder Int`) must synthesise NO constructor. Round-1's gate
/// EXEMPTED the opaque head (it mirrored the lowerer's function-embedding
/// payload-scan) and synthesised one, so the backend emitted a
/// `#[derive(Clone, Debug, PartialEq)]` + `impl IpeStringify` struct over the
/// non-derivable `Decoder` value — ipe exit-0 then cargo-101 (the seal hole).
/// This emit-only check (default suite) confirms ipe succeeds AND that no struct
/// for the alias is emitted (no ctor). The companion `…_builds_and_runs`
/// (`IPE_E2E`) proves the emitted project actually cargo-builds.
#[test]
fn seal_opaque_field_alias_emits_no_struct() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("record_ctor_opaque_field")
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m82_record_ctor_opaque_field_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve: {:?}", runtime.err());
    let Ok(runtime) = runtime else { return };
    // ipe MUST succeed — an opaque-wrapper-field alias that is merely NAMED
    // (declared, never constructed) is a valid program.
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipec must accept a merely-named opaque-wrapper-field record alias: {:?}",
        built.err()
    );

    let emitted = std::fs::read_to_string(out.join("src").join("main.rs"));
    assert!(emitted.is_ok(), "emitted main.rs must read");
    let Ok(src) = emitted else { return };
    // No constructor was synthesised, so the field-set struct (`RecDec`) and the
    // `main_D` ctor function must be ABSENT — their presence would mean a
    // `#[derive(…)]` struct over the non-derivable `Decoder` was emitted (the
    // seal hole).
    assert!(
        !src.contains("RecDec"),
        "no struct must be emitted for the un-constructed opaque-wrapper-field alias"
    );
    assert!(
        !src.contains("main_D("),
        "no constructor function must be emitted for the opaque-wrapper-field alias"
    );
}

/// ROUND-2 SEAL PROOF (`IPE_E2E`). The emitted project for the
/// opaque-wrapper-field record alias must actually cargo-BUILD and run clean —
/// ipe exit-0 AND cargo exit-0. Round-1 regressed exactly here: ipe-success
/// without a matching cargo-success (E0277/E0369/E0599 over `Decoder`).
#[test]
fn seal_opaque_field_alias_builds_and_runs() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("record_ctor_opaque_field")
        .join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m82_record_ctor_opaque_field_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "ipe build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("record_ctor_opaque_field", &out);
    assert_eq!(
        outcome.stdout, "ok\n",
        "the opaque-wrapper-field alias program must build and run clean"
    );
    assert_eq!(outcome.exit_code, Some(0), "clean exit (seal holds)");
}

/// ROUND-2 SEAL FAIL-CLOSED. The same opaque-wrapper-field alias, but the
/// alias name is USED as a value constructor (`D Decode.int`). Because synthesis
/// declined, no top-level value `D` exists, so this must fail CLOSED at ipe with
/// IPE-N0001 — NEVER ipe-0-then-cargo-fail. `ipe::build` must return `Err` and
/// emit nothing. This is the decisive contrast to the seal hole: the same source
/// shape that round-1 emitted-then-cargo-failed is now rejected at ipe.
#[test]
fn seal_opaque_field_used_as_ctor_fails_closed() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("record_ctor_opaque_ctor")
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m82_record_ctor_opaque_ctor_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve: {:?}", runtime.err());
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_err(),
        "using an opaque-wrapper-field alias as a ctor must fail CLOSED at ipec, \
         not ipe-0-then-cargo-fail"
    );
    // Fail-closed at the name-resolution stage: no `main.rs` was emitted.
    assert!(
        !out.join("src").join("main.rs").exists(),
        "a fail-closed ipe build must not emit a project"
    );
}

#[test]
fn record_ctor_cross_module_end_to_end() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let root = repo_root();
    let manifest = root
        .join("tests")
        .join("golden")
        .join("record_ctor_xmod")
        .join("package.ipe");
    let out = crate::support::scratch_root().join("ipec_m82_record_ctor_xmod_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };
    let built = ipe::build_project(&manifest, &out, &runtime);
    assert!(
        built.is_ok(),
        "cross-module build failed: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("record_ctor_xmod", &out);
    assert_eq!(
        outcome.stdout, "42:root\n",
        "a record alias's constructor exported from `State` must construct in `Main`"
    );
    assert_eq!(outcome.exit_code, Some(0), "clean exit");
}
