//! One record struct per class of unifiable occurrences of a field-name set.
//!
//! A value flows from one record type to another only when the two unify, so
//! the occurrences that unify share one struct, whose template is the least
//! general generalization of every member. A record literal can then never
//! resolve to a struct its destination does not accept.
//!
//! - `i3658_record_straddle_generic`: `f : { q : a }` takes `{ q = ( 1, 1 ) }`
//!   while `g : { q : ( a, a ) }` exists; one `RecQ<T1>` serves both.
//! - `i3658_record_straddle_concrete`: `{ q : ( a, Int ) }` and
//!   `{ q : ( Int, a ) }` both take an `( Int, Int )` literal; their
//!   generalization `RecQ<T1, T2>` serves both.
//! - `i3658_record_lgg_fn_sibling`: a sibling holds a function field, so the
//!   generalized field is a type parameter; show, measure and the row witness
//!   rest on the instantiation's bounds.
//! - `i3658_record_lgg_shared_fun`: a reused record of shared functions keyed on
//!   a type variable merges with a sibling; its clone and `'static` bound rest
//!   on the instantiation.
//! - `i3658_record_lgg_nested_record`: two `{q}` occurrences hold `{r}` records
//!   no member generalizes, and `{ r : ( String, String ) }` is a sibling `{r}`
//!   struct; the `{q}` template reaches its `{r}` record through a parameter.
//!
//! Each emits `main.rs` byte-identical to its golden with exactly one struct for
//! the name set, and behind `IPE_E2E=1` builds and prints its `expected.txt`.

use std::path::PathBuf;

use crate::support::repo_root;

/// The golden directory of the fixture `name`.
fn golden_dir(name: &str) -> PathBuf {
    repo_root().join("tests").join("golden").join(name)
}

/// Emit `name`, compare it with its golden, and return the emitted `main.rs`.
fn emit_matches_golden(name: &str) -> String {
    let dir = golden_dir(name);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_emit"));
    e2e_support::scratch::fresh(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&dir, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());
    crate::support::assert_emitted_project_matches_golden_dir(&out, &dir);
    std::fs::read_to_string(out.join("src").join("main.rs")).unwrap_or_default()
}

/// How many `pub struct <name>` declarations (any generic clause) `main_rs` holds.
fn struct_count(main_rs: &str, name: &str) -> usize {
    main_rs
        .lines()
        .filter(|line| {
            line.strip_prefix("pub struct ")
                .and_then(|rest| rest.strip_prefix(name))
                .is_some_and(|tail| tail.starts_with('<') || tail.starts_with(" {"))
        })
        .count()
}

/// Build and run the emitted `name` and compare its stdout with `expected.txt`.
fn end_to_end(name: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = golden_dir(name);
    let out = crate::support::scratch_root().join(format!("{name}_e2e"));
    e2e_support::scratch::fresh(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&dir, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());
    let outcome = crate::support::build_and_run_emitted(name, &out);
    crate::support::assert_self_regression(name, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0, matching the oracle");
}

const STRADDLE_GENERIC: &str = "i3658_record_straddle_generic";
const STRADDLE_CONCRETE: &str = "i3658_record_straddle_concrete";
const FN_SIBLING: &str = "i3658_record_lgg_fn_sibling";
const SHARED_FUN: &str = "i3658_record_lgg_shared_fun";

#[test]
fn straddle_generic_emits_one_struct() {
    let main_rs = emit_matches_golden(STRADDLE_GENERIC);
    assert_eq!(struct_count(&main_rs, "RecQ"), 1, "one struct for {{q}}");
    assert_eq!(
        struct_count(&main_rs, "RecQ2"),
        0,
        "no sibling struct for {{q}}"
    );
}

#[test]
fn straddle_generic_end_to_end() {
    end_to_end(STRADDLE_GENERIC);
}

#[test]
fn straddle_concrete_emits_one_two_parameter_struct() {
    let main_rs = emit_matches_golden(STRADDLE_CONCRETE);
    assert_eq!(struct_count(&main_rs, "RecQ"), 1, "one struct for {{q}}");
    assert_eq!(
        struct_count(&main_rs, "RecQ2"),
        0,
        "no sibling struct for {{q}}"
    );
    assert!(
        main_rs.contains("pub struct RecQ<T1, T2>"),
        "the generalization of `(a, Int)` and `(Int, a)` has two parameters"
    );
}

#[test]
fn straddle_concrete_end_to_end() {
    end_to_end(STRADDLE_CONCRETE);
}

#[test]
fn fn_sibling_moves_show_measure_and_witness_to_the_instantiation() {
    let main_rs = emit_matches_golden(FN_SIBLING);
    assert_eq!(
        struct_count(&main_rs, "RecFX"),
        1,
        "one struct for {{f, x}}"
    );
    assert_eq!(
        struct_count(&main_rs, "RecFX2"),
        0,
        "no sibling struct for {{f, x}}"
    );
    // The generalized function field shows through its parameter's bound, never
    // through a marker fixed by a sibling's function type.
    assert!(
        main_rs.contains("T1: IpeStringify") && main_rs.contains("IpeStringify::ipe_show(&self.f)"),
        "the generalized field shows under the instantiation's `IpeStringify` bound"
    );
    assert!(
        !main_rs.contains("\"<function>\""),
        "no function marker is fixed into the generalized struct"
    );
    // The measure is bounded per parameter, so a function instance has no measure.
    assert!(
        main_rs.contains("T1: RetainedBytes") && main_rs.contains(".plus(&self.f)"),
        "the generalized field is measured under the instantiation's `RetainedBytes` bound"
    );
}

#[test]
fn fn_sibling_end_to_end() {
    end_to_end(FN_SIBLING);
}

#[test]
fn shared_fun_emits_one_struct() {
    let main_rs = emit_matches_golden(SHARED_FUN);
    assert_eq!(
        struct_count(&main_rs, "RecCountFormat"),
        1,
        "one struct for {{count, format}}"
    );
    assert_eq!(
        struct_count(&main_rs, "RecCountFormat2"),
        0,
        "no sibling struct for {{count, format}}"
    );
}

#[test]
fn shared_fun_end_to_end() {
    end_to_end(SHARED_FUN);
}

const NESTED_RECORD: &str = "i3658_record_lgg_nested_record";

#[test]
fn nested_record_column_is_a_parameter() {
    let main_rs = emit_matches_golden(NESTED_RECORD);
    assert_eq!(struct_count(&main_rs, "RecQ"), 1, "one struct for {{q}}");
    // The `{q}` template reaches its inner `{r}` record through a parameter, so
    // each use site names the `{r}` struct its own record resolves to.
    assert!(
        main_rs.contains("pub struct RecQ<T1, T2> {\n    q: (T1, T2),"),
        "the nested record column is a type parameter"
    );
    assert!(
        main_rs.contains("RecQ<RecR<i64, T1>, i64>"),
        "`left` instantiates the parameter with its own `{{r}}` struct"
    );
    assert!(
        main_rs.contains("RecQ<RecR<T1, i64>, T2>"),
        "`right` instantiates the parameter with its own `{{r}}` struct"
    );
}

#[test]
fn nested_record_end_to_end() {
    end_to_end(NESTED_RECORD);
}
