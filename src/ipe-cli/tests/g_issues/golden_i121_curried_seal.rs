//! Seal — curried `FuncValue` arity-exact invariant.
//!
//! A named def with def-arity `k < N` referenced at a slot type that flattens
//! to `Fun([T0,…,T_{N-1}], R)` must not emit `Expr::FuncValue` with a
//! mismatched arity, which produces Rust that cargo rejects with E0593.  Companion
//! hole: a non-`Copy` local captured inside a lambda or partial application
//! would be moved into a `move` closure on first call, making the closure
//! `FnOnce` when the slot expects `Fn` (E0507 / E0525).
//!
//! Fixes:
//!
//! * **T3** — `lower_lambda` / `lower_let` thunk-body: classifies captured
//!   locals by [`CloneClass`]; replaces `CloneOk` reads with `CloneVar` (`.clone()`);
//!   emits `IPE-L0126` for `NonClone` captures outside callee position.
//! * **T4** — `eta_expand_partial`: classifies supplied `Var` args; rewrites
//!   `CloneOk` slots to `CloneVar` so the eta-lambda is `Fn`, not `FnOnce`.
//! * **T6** — `lower_expr` `FuncValue` reify site: when def-arity `k < N`,
//!   emits `eta_adapt_funcvalue` — a Lambda wrapper with N params whose body
//!   is `Apply(Call(callee, [eta_0..eta_{k-1}]), [eta_k..eta_{N-1}])`.
//!
//! Gated: green fixtures (F1-F5, F7-F10) require `IPE_E2E=1` for the cargo
//! build+run step; gate fixture (F6) runs the diagnostic check always.
//!
//! ```text
//! # green suite (cargo-0 required):
//! IPE_E2E=1 cargo test -p ipe --test golden_i121_curried_seal
//!
//! # gate checks only (no cargo, fast):
//! cargo test -p ipe --test golden_i121_curried_seal
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Concatenate every emitted `.rs` source directly under `out/src` (excluding
/// the `ipe_runtime` subtree) to let tests assert on generated program text.
fn emitted_program_source(out: &Path) -> String {
    let src = out.join("src");
    let mut acc = String::new();
    let Ok(entries) = std::fs::read_dir(&src) else {
        return acc;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path) {
            acc.push_str(&text);
            acc.push('\n');
        }
    }
    acc
}

// ── F1 — first-class curried fn + F11 shadow ─────────────────────────────────

/// `mk : String -> (String -> Page)`, def-arity 1, used at two first-class
/// reify sites (`let g = mk` and `apply2 mk`).  The closure body `\t -> Home s t`
/// captures `s : String` (`CloneOk`) — T3 rewrites to `.clone()`.
/// F11 shadow: `tag` rebinds `label` locally; the lambda must capture the
/// parameter, not the shadow (shadow reads stay bare).
#[test]
fn f1_firstclass_curried_and_shadow() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = root.join("tests").join("golden").join("firstclass_curried");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i121_firstclass_curried_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for firstclass_curried: {:?}",
        built.err()
    );

    // T6: eta-adapter must be emitted — FuncValue must use the adapter lambda.
    let program = emitted_program_source(&out);
    assert!(
        program.contains("eta_"),
        "T6 eta-adapter param must appear in emitted source"
    );

    let outcome = crate::support::build_and_run_emitted("firstclass_curried", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "must exit 0 (was E0593 + E0507)"
    );
    // let g = mk; g "first" "second" → Home "first" "second" → "first second"
    assert!(
        outcome.stdout.contains("first second"),
        "let-store reify must produce 'first second'; got:\n{}",
        outcome.stdout
    );
    // apply2 mk → Home "hello" "world" → "hello world"
    assert!(
        outcome.stdout.contains("hello world"),
        "HOF-arg reify must produce 'hello world'; got:\n{}",
        outcome.stdout
    );
    // F11 shadow: `tag "ipe-" ["a","b"]` → "ipe-a,ipe-b[2]"
    assert!(
        outcome.stdout.contains("ipe-a,ipe-b[2]"),
        "F11 shadow control must produce 'ipe-a,ipe-b[2]'; got:\n{}",
        outcome.stdout
    );
}

// ── F2 — nullary def with fn-typed value ─────────────────────────────────────

/// `handler : String -> Page`, def-arity 0 (`handler = mkPage "hello"`).
/// T6 adapter: `\eta_0 -> (main_handler())(eta_0)`.
#[test]
fn f2_firstclass_arity0() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = root.join("tests").join("golden").join("firstclass_arity0");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i121_firstclass_arity0_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for firstclass_arity0: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("firstclass_arity0", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "must exit 0 (was E0593 for arity-0 def)"
    );
    assert!(
        outcome.stdout.contains("hello world"),
        "arity-0 nullary handler must print 'hello world'; got:\n{}",
        outcome.stdout
    );
}

// ── F3 — partial application of non-Copy var ─────────────────────────────────

/// `let s = "hello" in let f = mk s in f "!"` — T4 rewrites `Var(s)` →
/// `CloneVar(s)` in the eta-lambda's captured arg; `f` called twice to
/// verify it is re-callable (`Fn`, not `FnOnce`).
#[test]
fn f3_partial_noncopy() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = root.join("tests").join("golden").join("partial_noncopy");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i121_partial_noncopy_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for partial_noncopy: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("partial_noncopy", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "must exit 0 (was E0525 on partial)"
    );
    // f called twice: f "!" → "hello!" and f "?" → "hello?"
    assert!(
        outcome.stdout.contains("hello!"),
        "first call of partial must produce 'hello!'; got:\n{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("hello?"),
        "second call of partial must produce 'hello?' (re-callable); got:\n{}",
        outcome.stdout
    );
}

// ── F4 — lambda capture of non-Copy local ────────────────────────────────────

/// `tag prefix items = List.map (\x -> String.append prefix x) items`
/// T3 rewrites captured `prefix : String` to `CloneVar(prefix)`.
/// F11 shadow: inner `let prefix = count in …` must not affect the lambda's
/// capture (lambda was already lowered with the parameter's `prefix`).
#[test]
fn f4_lambda_capture_noncopy_and_f11_shadow() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = root
        .join("tests")
        .join("golden")
        .join("lambda_capture_noncopy");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i121_lambda_capture_noncopy_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for lambda_capture_noncopy: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("lambda_capture_noncopy", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "must exit 0 (was E0525 on capture)"
    );
    // tag "ipe-" ["one","two"] → mapped = ["ipe-one","ipe-two"], shadow prefix = "2"
    // output: "ipe-one,ipe-two[2]"
    assert!(
        outcome.stdout.contains("ipe-one,ipe-two[2]"),
        "capture must use parameter prefix 'ipe-'; shadow '2' used as separator; \
         got:\n{}",
        outcome.stdout
    );
}

// ── F5 — control: fn-typed capture in callee position ────────────────────────

/// `let f = add 1 in List.map (\x -> f x) xs` — `f : Int -> Int` is
/// `NonClone` in CALLEE position.  T3 rule 3: bare `Var` (no clone, no `L0126`).
/// Must be GREEN before and after the fix — byte-stable.
#[test]
fn f5_capture_fn_called_control() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = root.join("tests").join("golden").join("capture_fn_called");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i121_capture_fn_called_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for capture_fn_called (control): {:?}",
        built.err()
    );

    // Verify NO CloneVar was emitted for the fn-typed capture (byte-stable gate).
    let program = emitted_program_source(&out);
    // The `f` binding should be called as `f(x)` not `f.clone()(x)`.
    assert!(
        !program.contains(".clone()"),
        "no .clone() must appear in the control fixture — fn-callee stays bare Var; \
         got emitted source containing .clone()"
    );

    let outcome = crate::support::build_and_run_emitted("capture_fn_called", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "control must exit 0 (was green before fix)"
    );
    assert!(
        outcome.stdout.contains("2, 3, 4"),
        "add-1 mapped over [1,2,3] must print '2, 3, 4'; got:\n{}",
        outcome.stdout
    );
}

// ── F6 — fn-typed capture forwarded (non-callee) → Arc-promoted, ACCEPTED ────

/// `compose f = \x -> applyTwice f x` — `f : Int -> Int` forwarded in a
/// non-callee position. Under the fn-value `Arc`-carrier promotion,
/// the param is shadow-rebound to the `Clone` `Arc<dyn Fn>` carrier
/// and the read re-dispatched through a fresh `Box` closure, so the program
/// compiles and runs (`compose (+1) 3` = `(+1)((+1) 3)` = `5`). A
/// IPE-L0125/6 gate is sound only while the sole carrier is a non-`Clone`
/// `Box<dyn Fn>` — the state it would reject is not invalid here, so keeping it
/// would be over-rejection, not soundness.
#[test]
fn f6_capture_fn_forwarded_promoted_accepts() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("capture_fn_forwarded")
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i121_capture_fn_forwarded_accept");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "forwarded fn-typed param must Arc-promote and build: {:?}",
        built.err()
    );

    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let outcome = crate::support::build_and_run_emitted("capture_fn_forwarded", &out);
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
    assert_eq!(outcome.stdout.trim(), "5", "applyTwice (+1) 3 = 5");
}

// ── F7 — curried fn in JsonDec.succeed pipeline ───────────────────────────────

/// `mkPair : String -> (Int -> String)`, def-arity 1, used in
/// `JsonDec.succeed mkPair |> Pipe.required … |> Pipe.required …`.
/// T6 eta-adapter inside `curry2`'s bound — E0593 without the arity-exact fix.
#[test]
fn f7_succeed_curried() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = root.join("tests").join("golden").join("succeed_curried");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i121_succeed_curried_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for succeed_curried: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("succeed_curried", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "must exit 0 (was E0593 in curry2 bound)"
    );
    assert!(
        outcome.stdout.contains("val:99"),
        "decoder pipeline must produce 'val:99'; got:\n{}",
        outcome.stdout
    );
}

// ── F8 — three-arrow curried fn ───────────────────────────────────────────────

/// `mk3 : String -> Int -> Bool -> String`, def-arity 1.  T6 emits ONE
/// `Apply` wrapping a `Call(mk3, [eta_0])`:
///   `\eta_0 eta_1 eta_2 -> (main_mk3(eta_0))(eta_1, eta_2)`
/// Both `let g = mk3` and `apply3 mk3` are tested.
#[test]
fn f8_curried_three_arrows() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = root
        .join("tests")
        .join("golden")
        .join("curried_three_arrows");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i121_curried_three_arrows_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for curried_three_arrows: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("curried_three_arrows", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "must exit 0 (was E0593 three-arrow)"
    );
    assert!(
        outcome.stdout.contains("ipe:7:F"),
        "let-store of mk3 must produce 'ipe:7:F'; got:\n{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("hello:42:T"),
        "HOF-arg apply3 mk3 must produce 'hello:42:T'; got:\n{}",
        outcome.stdout
    );
}

// ── F9 — decoder thunk capture (Fix-C boundary) ──────────────────────────────

/// `let field = "name" in let d = JsonDec.field field … in d used twice`.
/// T3 Fix-C rewrites captured `field : String` in the thunk body to
/// `CloneVar(field)` so the thunk is `Fn` and both decodes succeed.
#[test]
fn f9_decoder_thunk_capture() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = root
        .join("tests")
        .join("golden")
        .join("decoder_thunk_capture");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i121_decoder_thunk_capture_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for decoder_thunk_capture: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("decoder_thunk_capture", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "must exit 0 (was E0525 on thunk double-use)"
    );
    assert!(
        outcome.stdout.contains("alice,bob"),
        "two decoder uses must both succeed → 'alice,bob'; got:\n{}",
        outcome.stdout
    );
}

// ── F10 — bare-`Generic` curried capture is admitted (clones under its bound) ──

/// `pairWith : a -> b -> (a, b)`, def-arity 1. Lowering reaches the lambda body
/// `\y -> (x, y)`, where `x : a` is a bare `Generic` captured outside callee
/// position (inside a `Tuple`). A bare `Generic` capture clones under the emitted
/// `a : Clone` bound (`render_fn_generics`' unconditional `with_clone`, the same
/// bound `param_is_multiuse_clonable` relies on), so the capture-clone gate
/// yields and the crate builds and runs — a non-`Clone` instantiation is rejected
/// at the caller by the bound, never a silent cargo-fail. Prints `hello,42`.
#[test]
fn f10_generic_curried_capture_builds_and_runs() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("generic_curried")
        .join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i121_generic_curried_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a bare-`Generic` curried capture is admitted (clones under its `Clone` \
         bound): {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("generic_curried", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "must exit 0 (THE SEAL) — was IPE-L0126 before the bare-`Generic` capture \
         admission; stdout:\n{}",
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout, "hello,42\n",
        "the captured generic pairs with its argument"
    );
}

// ── F11 — curried fn in `JsonDecP.custom` pipeline step ─────

/// `mkPair : String -> (Int -> String)`, def-arity 1, same shape as F7 but the
/// pipeline's second step is `Pipe.custom` (not `Pipe.required`).  Reproduces
/// the independent-review-found gap: `is_pipeline_next_decoder_kernel`
/// (`crates/ipe_lower/src/lower.rs`) listed only five of the six
/// `Decoder<E, Box<dyn FnOnce(_) -> _>>`-shaped kernels, omitting
/// `KernelFn::JsonDecPCustom`.  Without the fix, `ipe build` exits 0 but the emitted
/// `decode_pipeline_custom` call site fails `cargo build` with 2×E0308
/// (`expected trait 'Fn', found trait 'FnOnce'`).
#[test]
fn f11_pipeline_custom_curried() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = root
        .join("tests")
        .join("golden")
        .join("pipeline_custom_curried");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i121_pipeline_custom_curried_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for pipeline_custom_curried: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("pipeline_custom_curried", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "must exit 0 (was E0308 x2 at decode_pipeline_custom call site)"
    );
    assert!(
        outcome.stdout.contains("val:99"),
        "custom-step decoder pipeline must produce 'val:99'; got:\n{}",
        outcome.stdout
    );
}
