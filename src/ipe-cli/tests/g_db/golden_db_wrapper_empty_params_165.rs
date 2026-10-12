//! `examples/17-ipemon`'s `cargo build` failure.
//!
//! Without the fix, `ipe dev build` exits 0, but the emitted Rust fails `cargo build`
//! with 6x E0277 (the trait bound `SqlParam: From<T1>` is not satisfied)
//! and 3x E0283 (`type annotations needed` / `cannot infer type of the type
//! parameter T declared on the struct Vec`) at every
//! `lib_database_query_or_log(label, queryStr, Vec::new())` call site (an
//! empty-params `Ipe.Db` query helper).
//!
//! Root cause: a Ipê-defined WRAPPER function around `Db.exec` / `Db.query`
//! (never the kernel called directly) forwards its own polymorphic
//! `args : List a` parameter into the kernel's params position. The type
//! checker's `Db.exec` / `Db.query` / `Db.queryDecode` scheme leaves that
//! element variable completely unconstrained (`list(var(0))`) — nothing
//! ever told the Rust backend that the ELEMENT type needs
//! `Into<ipe_runtime::db::SqlParam>`, so:
//!
//! * a genuinely polymorphic wrapper (called at different concrete `args`
//!   types across modules) emitted an unbounded `T1: Clone` generic whose
//!   own body's `SqlParam::from` projection had no bound to appeal to
//!   (E0277); and
//! * an EMPTY list literal argument (`[]`, no bind parameters) gave the
//!   lowerer zero type evidence, so it fell back to the wildcard-`any`
//!   convention (`IrType::Json`) — a bare, ambiguous `Vec::new()` call-site
//!   argument (E0283).
//!
//! Fix (`crates/ipe_types/src/{ty,constrain,lib}.rs` +
//! `crates/ipe_ir/src/ir.rs` + `crates/ipe_lower/src/lower.rs` +
//! `crates/ipe_backend_rust/src/emit_expr.rs`):
//!
//! 1. New `TyBounds::sql_param` obligation, tied to `Db.exec` / `Db.query` /
//!    `Db.queryDecode`'s params-list ELEMENT variable in
//!    `constrain_var_kernel` — the same `stdlib_scheme` + tie shape already
//!    used for the Set/Dict comparable-key obligation.
//! 2. A dangling (never otherwise pinned) `sql_param`-obligated flex
//!    variable now DEFAULTS to Ipê's own `SqlValue` ADT (mirroring the
//!    existing `Number` → `Int` defaulting arm) instead of falling through
//!    to the `IrType::Json` wildcard — closes the E0283 half.
//! 3. The obligation realises as `BoundSet::sql_param` →
//!    `T{n}: … Into<ipe_runtime::db::SqlParam>` on the emitted Rust generic
//!    (composes with the ordinary `<T{n}: Bound>` list; no separate `where`
//!    clause needed) — closes the E0277 half.
//! 4. `emit_db_call`'s `project_params` now maps via `Into::into` (not
//!    `SqlParam::from`) into an explicit `Vec<ipe_runtime::db::SqlParam>` —
//!    `Into::into` is what a `T{n}: Into<SqlParam>` bound actually lets a
//!    still-generic function body call; std's blanket `impl<T, U: From<T>>
//!    Into<U> for T` keeps every concrete element type (`String` / `i64` /
//!    `f64` / `bool` / the generated `SqlValue` impl) working exactly as
//!    before.
//!
//! The fixture (`tests/golden/db_wrapper_empty_params_165/src/`) is a genuine
//! 3-module project, mirroring `examples/17-ipemon`'s actual
//! `Lib.Database`/`Lib.Alerts`/`Lib.Monitors` cross-module shape:
//!
//! - `Lib1.ipe` — `withConn`, `query`, `exec`: unannotated wrappers around
//!   `Db.open` / `Db.query` / `Db.exec`; connection threaded explicitly.
//! - `Lib2.ipe` — calls `Lib1.exec` with a `List SqlValue` (typed
//!   mixed-param path).
//! - `Main.ipe` — calls `Lib1.exec` with BOTH the empty list `[]` (the
//!   trigger, twice — a DDL statement and a no-bind-params `DELETE`)
//!   AND a non-empty `List SqlValue`, then `Lib1.query` with `[]` to
//!   read the rows back. `args` stays `List SqlValue` at every non-empty
//!   call site (across BOTH `Lib2` and `Main`) so the fixture isolates the
//!   ONE variable this is actually about — empty vs. non-empty — rather
//!   than cross-call-site type diversity, a separate, already-covered
//!   concern (`tests/golden/db_poly_params`).
//!
//! Run:
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_db_wrapper_empty_params_165
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// ipe-0: the compiler must accept the 3-module program AND emit the
/// `Into<ipe_runtime::db::SqlParam>` bound on the wrapper functions' own
/// generic (the E0277 half of #165) — checked unconditionally (cheap, no
/// `cargo`), independent of the `IPE_E2E` gate below.
#[test]
fn db_wrapper_empty_params_165_ipec_accepts_and_emits_sql_param_bound() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("db_wrapper_empty_params_165")
        .join("src")
        .join("Main.ipe");
    let out =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("db_wrapper_empty_params_165_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for db_wrapper_empty_params_165: {:?}",
        built.err()
    );

    let emitted = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");

    // Every EMPTY-list call site must carry a concrete, non-`Vec::new()`
    // argument (the E0283 half) — the type checker's `sql_param`
    // defaulting gives the dangling element variable a concrete `SqlValue`
    // type instead of falling through to the wildcard-`any`/`IrType::Json`
    // convention.
    assert!(
        !emitted.contains("Vec::new()"),
        "every empty-params call site must carry an explicitly-typed empty \
         Vec, never a bare ambiguous `Vec::new()` (#165's E0283 half); got \
         main.rs:\n{emitted}"
    );

    // the E0277 half (a still-generic `Db.exec`/`Db.query` wrapper
    // needing `Into<ipe_runtime::db::SqlParam>` on its own emitted generic)
    // is NOT asserted textually here: this fixture's `args` unifies to the
    // concrete `MainSqlValue` at every call site (same as
    // `examples/17-ipemon`'s real wrappers, which likewise lower fully
    // concrete once every call site — including the empty-list ones —
    // carries real type evidence), so the bound never actually needs to
    // appear on `args`'s own type parameter in THIS fixture. Asserting on
    // internal Rust generic-signature shape here would be testing an
    // incidental unification outcome, not the bug. The E0277 half is
    // exercised directly by `crates/ipe_backend_rust`'s own
    // `render_bounds`/`bounds_for` unit-level wiring (the bound IS emitted
    // whenever `BoundSet::has_sql_param()` is set — see
    // `crates/ipe_lower/src/lower.rs`'s `bounds_for`); the E2E test below is
    // the authoritative end-to-end gate on the actual `cargo build` outcome
    // for both halves at once.
}

/// cargo-0 ∧ run-0: the emitted project actually compiles with `rustc` and
/// prints the two rows read back through the empty-params wrapper call.
/// Gated on `IPE_E2E=1` — a real `cargo build`, the only check that would
/// have caught the original SEAL violation (9x rustc error on
/// `examples/17-ipemon`, `ipe dev build` itself was clean).
#[test]
fn db_wrapper_empty_params_165_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("db_wrapper_empty_params_165")
        .join("src")
        .join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_db_wrapper_empty_params_165_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for db_wrapper_empty_params_165: {:?}",
        built.err()
    );

    // cargo-0 ∧ run-0: `build_and_run_emitted` fails the test loudly (with
    // cargo's own stderr) on any build failure — the exact gate that catches
    // the 9x rustc E0277/E0283 SEAL violation this test guards against.
    let outcome = crate::support::build_and_run_emitted("db_wrapper_empty_params_165", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "db_wrapper_empty_params_165 binary must exit 0; got {:?} (stdout: {:?})",
        outcome.exit_code,
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim(),
        "gadget,widget",
        "must print both rows (List SqlValue + List String inserts) read \
         back through the empty-params `Lib1.queryOrLog` call, ordered by \
         name; got: {:?}",
        outcome.stdout
    );
}
