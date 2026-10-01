//! Core-stdlib kernels are CALLABLE from user code.
//!
//! Without a kernel binding, a qualified `Result.andThen` / `Result.mapError` /
//! `String.containsIn` / `String.startsWithIn` / `String.endsWithIn` and the
//! Prelude `clamp` would be canon members with `id = None` — failing closed with
//! `error[IPE-L0108]: kernel function not available yet` at the first such call
//! (there is no `Ty::Var(u32::MAX)` fallback typing them as free variables).
//!
//! Each is wired as a kernel — `KernelFn` variant + `d(...)` decl + lower
//! arm + fail-closed `stdlib_scheme` entry + `FIRST_SCHEMED` membership:
//!
//! * `Result.andThen` / `Result.mapError` reuse the container-first runtime
//!   (`ipe_result_and_then(r, f)` / new `ipe_result_map_error(r, f)`); the
//!   emitter reverses the Ipê `(fn, result)` order per the row's `ArgOrder::ContainerFirst`
//!   (verified here — a wrong arg order would short-circuit the WRONG channel).
//! * `String.{containsIn,startsWithIn,endsWithIn}` are haystack-first
//!   companions; their new runtime wrappers take Ipê order directly (NO swap).
//! * `Basics.clamp` carries the same `Comparable a` (Ord) obligation as
//!   `Math.min`/`Math.max` — a bounded super-var tied across all three argument
//!   positions AND the result, so a non-comparable argument fails closed.
//!
//! `String.toChar` (no runtime fn, ambiguous Char-vs-Maybe-Char semantics) is
//! DELIBERATELY not wired — it stays a loud IPE-L0108 hole rather than risk a
//! miscompile.
//!
//! Gated on `IPE_E2E=1`. Run:
//! `IPE_E2E=1 cargo test -p ipe --test golden_core_stdlib`.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Compile `tests/golden/<name>/Main.ipe` into an emitted Rust project and
/// return its directory. Fails the test loudly on a compile error (so the
/// IPE-L0108 regression, were it to return, fails here rather than silently
/// skipping).
fn compile_golden(name: &str) -> PathBuf {
    let root = repo_root();
    let entry = golden_dir(&root, name).join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());
    out
}

/// The six newly-wired core-stdlib kernels compile and produce correct output.
#[test]
fn core_stdlib_wiring_runs_with_parity() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = compile_golden("m_core_stdlib");
    let out = crate::support::build_and_run_emitted("m_core_stdlib", &dir);
    assert_eq!(
        out.exit_code,
        Some(0),
        "expected a clean exit; got {:?}",
        out.exit_code
    );
    // andThen: Ok 5 → Ok 6 (=6); Err "e" short-circuits (withDefault → 0).
    // mapError: Err "boom" → Err (length "boom" = 4).
    // clamp: 150→100, -5→0, 42→42; sum = 142.
    // str: containsIn/startsWithIn/endsWithIn all True, last containsIn False.
    assert_eq!(
        out.stdout.trim(),
        "andThen 6 0 mapError 4 clamp 142 str TTTF"
    );
}
