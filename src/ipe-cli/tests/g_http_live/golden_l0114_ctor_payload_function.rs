//! IPE-L0114 ctor-payload-function — Stage 1 lift (function values in
//! `Maybe`/`Result`/user-union constructor payloads) + the T3 `andMap`
//! curried-payload gate + the T4 fn-value-reuse gate.
//!
//! See `docs/adr/0002-codegen-soundness-and-the-seal.md` (Stage 1
//! overview) and `docs/adr/0001-language-semantics-and-types.md` (the
//! two-tier T3 design implemented here).
//!
//! ## What's covered
//!
//! * T1/T2 — a function value DIRECTLY in `Ok`/`Just`/a user union's payload
//!   (declared or laundered through a type variable) is now ACCEPTED.
//! * T3 Tier 2 (primary) — `ipe_types::constrain::constrain_var_kernel` ties
//!   the callback-result scheme-var of EVERY pure higher-order kernel
//!   (`Maybe`/`Result` `map`, `map2..5`, `mapError`, `andMap`, and the
//!   collection HOFs — derived by `StdlibKernel::hof_result_vars`, checked by
//!   `hof_result_vars_match_scheme_shapes` in `ipe_types`) to a
//!   `TyBounds::hof_kernel_result()` obligation, checked at type-check time
//!   (`ipe_types::infer`) BEFORE lowering ever runs. The obligation covers the
//!   whole kernel set (a `Result.map` bypass otherwise slips through) and fails
//!   CLOSED on a bare `Ty::Var` (an annotated double forwarder's skolem
//!   otherwise escapes). Scoping it to `andMap` alone, or failing OPEN on a
//!   variable, reopens those bypasses.
//!   This is a TYPE-LEVEL check, so it survives arbitrary Ipê-level
//!   aliasing by construction. It
//!   surfaces as ONE of two diagnostics depending on HOW the obligated
//!   variable is used, mirroring the existing `Math.min` gate's documented
//!   split (`golden_m4c_math_gate.rs`): a DIRECT `andMap` call pins the
//!   obligated variable straight to a concrete `Fun` structure at the
//!   unifier's own head-pin check — the "eager pin" case — surfacing a plain
//!   `IPE-T0001` (`TypeMismatch`); an ANNOTATED GENERIC FORWARDER around
//!   `andMap` instead lifts the obligation onto its own skolem and defers to
//!   the `SchemeApp`/`check_scheme_applications` pass, re-verified at each of
//!   the forwarder's own external call sites — surfacing the friendlier,
//!   specifically-labelled `IPE-T0014` (`SuperTypeUnsatisfied`,
//!   "non-function callback result (higher-order kernel)").
//!   Both are clean Ipê diagnostics, never a cargo-fail;
//!   which one you see depends only on whether `andMap` was called directly
//!   or through a forwarder, confirmed empirically below (not merely
//!   predicted by the design doc, which anticipated IPE-T0014 as the sole
//!   Tier-2 code for every shape).
//! * T3 Tier 1 (backstop) — `reject_hof_callback_function_result`
//!   (`IPE-L0154`), inside `lower_callee` itself (the single funnel every
//!   kernel/top-level reference resolves through). It reads the kernel
//!   reference's solved type against `StdlibKernel::hof_result_vars`, so it
//!   holds independently of Tier 2's wiring; Tier 2 catches the hazard first.
//! * T4 — `reject_fn_value_reuse` (`IPE-L0127`), wired at all FIVE call sites
//!   a fn-carrying binding can originate from: typed/untyped Def params,
//!   let-bindings, match-arm bindings, AND lambda params (the lambda-param
//!   site was the exact gap that caused the first revert-incident, Bug 1).
//!
//! ## Aliasing-shape coverage (T3 fixture matrix)
//!
//! Every shape the incident history found (or the revised design's fixture
//! matrix names) gets its own red (still correctly rejected) fixture, each
//! going through `assert_hof_curried_rejected` (accepts IPE-T0001 /
//! IPE-T0014 / IPE-L0154 — see that helper's doc comment):
//!
//! | Shape | Fixture | Observed code |
//! |---|---|---|
//! | Direct call / pipe-desugared | `and_map_curried_stays_gated` | IPE-T0001 |
//! | `let`-bound partial application | `and_map_let_bound_alias_stays_gated` | IPE-T0001 |
//! | Bare, point-free top-level re-export | `and_map_bare_alias_stays_gated` | IPE-T0001 |
//! | Higher-order argument | `and_map_higher_order_arg_stays_gated` | IPE-T0001 |
//! | Record-field extraction | `and_map_record_field_stays_gated` | IPE-T0001 (Tier 2 fires before the pipeline reaches the unrelated IPE-L0107 record-field gate — see the test's own doc comment) |
//! | Annotated generic forwarder | `and_map_forwarder_curried_is_t0014` | IPE-T0014 (the friendly-message path) |
//! | **Annotated DOUBLE forwarder** | `and_map_annotated_double_forwarder_curried` | IPE-T0014 (fail-closed at the inner `am1` reference) |
//! | Annotated double forwarder, SAFE arity-1 payload | `and_map_annotated_double_forwarder_arity1` | IPE-T0014 (conservative reject; a documented precision loss matching `Math.min`'s conservatism on the identical shape) |
//! | Annotated TRIPLE forwarder | `and_map_triple_forwarder_curried` | IPE-T0014 (rejected at the first hop) |
//! | Eta-reduced annotated forwarder (`am2 = am1`) | `and_map_eta_reduced_forwarder_curried` | IPE-T0014 |
//! | Unannotated same-module double forwarder | `and_map_untyped_double_forwarder_curried` (+ green twin `…_arity1`) | IPE-T0014 (concrete found-type via `CLocal`; green twin ACCEPTED, runs, prints 42) |
//! | Cross-module UNANNOTATED double forwarder | `and_map_cross_module_untyped_forwarder_curried` | IPE-T0014 |
//! | **`Result.map` curried callback** | `map_curried_stays_gated` (Maybe variant) | IPE-T0001 (`map`/`map2..5`/`mapError` share the same FnOnce-vs-flattened hazard as `andMap`, otherwise reaching cargo as E0277) |
//! | `Maybe.map2` arity-3 callback | `map2_extra_arity_stays_gated` (+ exact-arity green twin) | IPE-T0001 |
//! | `Result.mapError` curried callback | `map_error_curried_stays_gated` (+ arity-1 green twin) | IPE-T0001 |
//! | Bare re-export of `Result.map` | `map_bare_alias_stays_gated` | IPE-T0001 |
//! | **User applicative `map2` via `Result.map`+`andMap`** | `user_map2_via_andmap_stays_gated` | IPE-T0001 (cargo-fails even at a SAFE arity-2 use without the generalized obligation) |
//! | Annotated `map` forwarder, curried | `map_annotated_forwarder_curried_is_t0014` (+ arity-1 green twin) | IPE-T0014 |
//! | `Result.andThen` returning `Ok fn` | `and_then_fn_payload_accepted` | n/a — accepted (`andThen` needs NO obligation, Con-headed callback result; a callback legitimately returning `Ok fn` stays ACCEPTED and computes 42) |
//! | Import alias | *(not constructible)* | n/a (`Result`/`Maybe` are compiler-kernel qualifiers in `ipe-lang`, not backed by an importable Ipe-source module — `crates/ipe_canon/src/resolve.rs`'s fixed kernel-qualifier list — so there is no module to `import … as …`) |
//! | Cross-module annotated wrapper, reused at 2 different arity-1 types | `and_map_cross_module_wrapper_accepted` | design doc's `T3.residual` row — must stay ACCEPTED (proves Tier 2 does not over-reject) | n/a — accepted |

use std::path::{Path, PathBuf};

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_entry(root: &Path, name: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(name)
        .join("Main.ipe")
}

fn fixture_src_entry(root: &Path, name: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(name)
        .join("src")
        .join("Main.ipe")
}

/// Build `name`'s `Main.ipe` and return the diagnostic code if the pipeline
/// rejected it, `None` if it was accepted (or failed for a non-pipeline
/// reason, which the caller's assertion will catch).
fn built_code(root: &Path, name: &str) -> (Result<(), CliError>, PathBuf) {
    let entry = fixture_entry(root, name);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_emit"));
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    (ipe::build(&entry, &out, &runtime), out)
}

// ── T1/T2: direct construction now ACCEPTED ─────────────────────────────────

/// `Ok f` holding a function must not trip IPE-L0114 unconditionally, which
/// would make `Result.andMap` unusable. Construction is sound (derive-demotion +
/// generic-bounded runtime `IpeResult` derives).
#[test]
fn result_and_map_fn_payload_accepted() {
    let root = repo_root();
    let (built, out) = built_code(&root, "result_and_map_fn_payload");
    assert!(
        built.is_ok(),
        "Ok f |> Result.andMap must be accepted: {built:?}"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome = crate::support::build_and_run_emitted("result_and_map_fn_payload", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "exit 0; stdout:\n{}",
            outcome.stdout
        );
        assert_eq!(outcome.stdout.trim(), "3");
    }
}

/// `Just f` holding a function must not trip IPE-L0114 unconditionally, which
/// would make `Maybe.andMap` unusable.
#[test]
fn maybe_and_map_fn_payload_accepted() {
    let root = repo_root();
    let (built, out) = built_code(&root, "maybe_and_map_fn_payload");
    assert!(
        built.is_ok(),
        "Just f |> Maybe.andMap must be accepted: {built:?}"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome = crate::support::build_and_run_emitted("maybe_and_map_fn_payload", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "exit 0; stdout:\n{}",
            outcome.stdout
        );
        assert_eq!(outcome.stdout.trim(), "42");
    }
}

/// Stage-1 RESIDUAL seal hole: a LET-BOUND constructor-wrapped closure
/// (`let f = Ok (\x -> x + 1)`) later passed to a `Box<dyn Fn>`-expecting
/// position would be a ipe-accept / cargo-reject E0308. The inline pipe form
/// (`Ok (\x…) |> Result.andMap (Ok 2)`) works because the kernel call site
/// supplies the `Box<dyn Fn>` coercion target; a bare `let` binding has none —
/// `Ok` routes to the runtime `IpeResult` enum whose generic arg is inferred
/// from the constructor arg, so `Box::new(closure)` would pin the CONCRETE
/// closure type and the later use against `Box<dyn Fn>` fail to unsize-coerce
/// across the `let` boundary. So the trait-object type is pinned at the lambda's
/// own emission site (`{ let __ipe_fn: Box<dyn Fn(..)->..> = Box::new(closure);
/// __ipe_fn }`), the same technique `emit_func_value` uses for a named fn value.
/// Passing the fn-carrier through a type-annotated function boundary
/// (`applyIt : Result Error (Int -> Int) -> Int`) is what makes the bug
/// reachable — Rust's whole-function inference cannot patch the closure type
/// from the far side of a `fn` call.
#[test]
fn let_bound_fn_payload_accepted() {
    let root = repo_root();
    let (built, out) = built_code(&root, "let_bound_fn_payload");
    assert!(
        built.is_ok(),
        "let f = Ok (\\x -> …) crossing a fn boundary must be accepted: {built:?}"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome = crate::support::build_and_run_emitted("let_bound_fn_payload", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "exit 0; stdout:\n{}",
            outcome.stdout
        );
        assert_eq!(outcome.stdout.trim(), "42");
    }
}

/// Let-bound seal hole — Maybe variant, exercising the same lambda
/// trait-object-pin through the runtime `IpeMaybe` enum
/// (`let f = Just (\x -> x * 2)`). Must build+run and print `42`.
#[test]
fn let_bound_maybe_fn_payload_accepted() {
    let root = repo_root();
    let (built, out) = built_code(&root, "let_bound_maybe_fn_payload");
    assert!(
        built.is_ok(),
        "let f = Just (\\x -> …) crossing a fn boundary must be accepted: {built:?}"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome = crate::support::build_and_run_emitted("let_bound_maybe_fn_payload", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "exit 0; stdout:\n{}",
            outcome.stdout
        );
        assert_eq!(outcome.stdout.trim(), "42");
    }
}

/// A DECLARED function-typed constructor payload (`RetryWhen (e -> Bool)`)
/// must not trip IPE-L0114 at the union declaration itself. The
/// derive-demotion fixpoint keeps the emitted enum sound.
#[test]
fn ctor_decl_fn_payload_accepted() {
    let root = repo_root();
    let (built, out) = built_code(&root, "ctor_decl_fn_payload");
    assert!(
        built.is_ok(),
        "declared fn-typed ctor payload must be accepted: {built:?}"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome = crate::support::build_and_run_emitted("ctor_decl_fn_payload", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "exit 0; stdout:\n{}",
            outcome.stdout
        );
        assert_eq!(outcome.stdout.trim(), "retry");
    }
}

/// T4 sound companion: calling an extracted function value MORE THAN ONCE
/// (callee position) is unlimited — a `Box<dyn Fn>` call borrows, never
/// moves. Must NOT trip the T4 reuse gate.
#[test]
fn fn_extracted_called_twice_accepted() {
    let root = repo_root();
    let (built, out) = built_code(&root, "fn_extracted_called_twice");
    assert!(
        built.is_ok(),
        "calling an extracted fn twice must be accepted: {built:?}"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome = crate::support::build_and_run_emitted("fn_extracted_called_twice", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "exit 0; stdout:\n{}",
            outcome.stdout
        );
        assert_eq!(outcome.stdout.trim(), "5");
    }
}

// ── T3: the andMap curried-payload gate — every aliasing shape ─────────────

/// Assert `name`'s `Main.ipe` is rejected with one of the three CLEAN outcomes
/// the two-tier design can produce — never silently accepted, never a
/// cargo-fail.
///
/// * `IPE-T0001` (ordinary `TypeMismatch`) — the "eager pin" case: every
///   fixture here calls `Maybe.andMap` / `Result.andMap` DIRECTLY (not
///   through a generic forwarder), so the curried payload's `b` unifies
///   HEAD-TO-HEAD against a concrete `Fun` structure during ordinary
///   solving. `unify.rs`'s `super_concrete_ok` head-pin-check rejects any
///   `Fun` meeting ANY bounded variable at the unification site itself,
///   before the deferred, nicely-labelled `SuperTypeUnsatisfied` pass ever
///   runs — EXACTLY the same "eager-pin sibling" behaviour already
///   documented for `Math.min`/`Math.max` called directly on two
///   non-comparable values (`crates/ipe/tests/golden_m4c_math_gate.rs`:
///   "Calling `Math.min` directly on two non-comparable values is the
///   eager-pin sibling and surfaces IPE-T0001 instead"). This is the
///   EXPECTED code for every fixture in this matrix, verified against the
///   actual behaviour of this pass, not merely predicted.
/// * `IPE-T0014` (`SuperTypeUnsatisfied`) — reached when the obligated
///   variable escapes into an ANNOTATED GENERIC FORWARDER (the
///   `check_scheme_applications` / `SchemeApp` path) rather than pinning
///   directly — see `and_map_curried_forwarder_is_ipe_t0014` below for the
///   fixture that exercises this path with the friendly "single-argument
///   function" message.
/// * `IPE-L0154` — the Tier-1 lowering backstop, the accepted
///   defense-in-depth outcome should Tier 2's wiring ever miss a shape.
fn assert_hof_curried_rejected(name: &str) {
    let root = repo_root();
    let (built, _out) = built_code(&root, name);
    let code = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert!(
        code == Some(ipe_diagnostics::IPE_T0001)
            || code == Some(ipe_diagnostics::IPE_T0014)
            || code == Some(ipe_diagnostics::IPE_L0154),
        "{name}: curried higher-order-kernel callback must be rejected with IPE-T0001 (Tier 2, \
         eager pin — the expected outcome for a DIRECT `andMap` call), IPE-T0014 \
         (Tier 2, deferred — reached only through a generic forwarder), or \
         IPE-L0154 (Tier 1 backstop), got: {built:?}"
    );
}

/// Direct call / pipe-desugared curried call — pre-existing shape, always
/// caught even by the first (buggy) T3 attempts.
#[test]
fn and_map_curried_direct_call_stays_gated() {
    assert_hof_curried_rejected("and_map_curried_stays_gated");
}

/// `let`-bound partial application — revert-incident Bug 2 (2nd revert):
/// `let g = Result.andMap (Ok 1) in g (Ok add3)` bypassed the first T3 fix,
/// which pattern-matched only the direct + pipe-desugared call shapes.
#[test]
fn and_map_curried_let_bound_alias_stays_gated() {
    assert_hof_curried_rejected("and_map_let_bound_alias_stays_gated");
}

/// Bare, point-free top-level re-export — revert-incident Bug 3 (3rd
/// revert): `myAndMap = Result.andMap` … `myAndMap (Ok 1) (Ok add3)` reaches
/// `Result.andMap`'s own reference through `lower_expr`'s bare-value arm,
/// never `lower_call_uniform`'s Call-node arm — the exact gap the revised
/// design closes by re-anchoring the Tier-1 check inside `lower_callee`
/// itself, and by making Tier 2 a genuine type-level obligation that does
/// not depend on lowering-time AST shape at all.
#[test]
fn and_map_curried_bare_alias_stays_gated() {
    assert_hof_curried_rejected("and_map_bare_alias_stays_gated");
}

/// Higher-order argument — `Result.andMap` passed bare as a call ARGUMENT
/// (not a callee), applied to a curried payload by the callee it was passed
/// to.
#[test]
fn and_map_curried_higher_order_arg_stays_gated() {
    assert_hof_curried_rejected("and_map_higher_order_arg_stays_gated");
}

/// Record-field extraction — `{ combiner = Result.andMap }`, later called
/// with a curried payload through the extracted field. Verified: this hits
/// the SAME Tier-2 eager-pin path (`IPE-T0001`) as every other direct-call
/// shape in this matrix — type-checking runs BEFORE lowering, so the T3
/// obligation on `Result.andMap`'s own occurrence (which does not care what
/// larger expression contains it — a record-field initializer is just
/// another position `constrain_var_kernel` sees the same way) fires and
/// rejects the program before the pipeline ever reaches the PRE-EXISTING,
/// unrelated `IPE-L0107` lowering-time gate (first-class function in a
/// record field) that would ALSO have rejected this shape had it gotten
/// that far. Confirmed empirically, not assumed — this is why the fixture
/// matrix table in the module doc comment says "closed by construction",
/// not "closed by IPE-L0107": the closing mechanism is Tier 2, same as
/// every other row.
#[test]
fn and_map_record_field_extraction_stays_gated() {
    assert_hof_curried_rejected("and_map_record_field_stays_gated");
}

/// design doc `T3.residual` fixture: an ANNOTATED wrapper around
/// `Result.andMap`, exported and reused CROSS-MODULE at two DIFFERENT
/// concrete payload types, both individually arity-1-safe. Must stay
/// ACCEPTED — proves the Tier-2 obligation does not over-reject legitimate
/// cross-module reuse (the one precision-loss case the design doc
/// acknowledges is the UNANNOTATED/untyped variant, §3.3 — not this one).
#[test]
fn and_map_cross_module_annotated_wrapper_accepted() {
    let root = repo_root();
    let entry = fixture_src_entry(&root, "and_map_cross_module_wrapper_accepted");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("l0114_and_map_cross_module_wrapper_accepted_emit");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "an annotated andMap wrapper reused cross-module at two arity-1-safe \
         concrete types must be accepted, got: {built:?}"
    );
}

/// The "forwarder" companion of `and_map_cross_module_annotated_wrapper_accepted`:
/// the SAME annotated `andMapAlias` wrapper, this time instantiated at a
/// CURRIED (arity >= 3) payload. Proves the FRIENDLY, deferred
/// `SuperTypeUnsatisfied` (`IPE-T0014`) diagnostic path genuinely fires
/// (not just the eager-pin `IPE-T0001` every direct-call fixture above hits)
/// — the obligation propagates onto the wrapper's own annotation skolem and
/// is re-verified at THIS external call site, exactly like `Math.min`'s
/// `pickMin` forwarder gate.
#[test]
fn and_map_forwarder_curried_is_ipe_t0014() {
    let root = repo_root();
    let entry = fixture_src_entry(&root, "and_map_forwarder_curried_is_t0014");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("l0114_and_map_forwarder_curried_is_t0014_emit");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build_loose_file(&entry, &out, &runtime);
    let code = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        code,
        Some(ipe_diagnostics::IPE_T0014),
        "a curried payload through an ANNOTATED andMap forwarder must surface \
         the friendly SuperTypeUnsatisfied diagnostic (IPE-T0014), got: {built:?}"
    );
}

// ── T4: fn-value reuse gate ─────────────────────────────────────────────────

/// A fn-carrying, non-Clone LAMBDA parameter used in two consuming positions
/// inside the lambda's own body. `lower_lambda` builds its own `ir_params`
/// independently of the other four `reject_fn_value_reuse` call sites and must
/// run them through the gate — otherwise this reaches `cargo build` as E0382
/// instead of a clean IPE-L0127. A `Maybe (Int -> Int)` payload is consumed by
/// the `andMap`/`map` kernels as an owned `FnOnce` (`Box`), so it stays on the
/// non-`Clone` `Box` carrier — reuse has no sound rewrite and stays fail-closed.
#[test]
fn lambda_param_reuse_gated() {
    let root = repo_root();
    let (built, _out) = built_code(&root, "lambda_param_reuse_gated");
    let code = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        code,
        Some(ipe_diagnostics::IPE_L0127),
        "a fn-carrying lambda param used twice (consuming positions) must be \
         rejected with IPE-L0127, got: {built:?}"
    );
}

/// Sound companion: calling the SAME lambda param twice (callee position) is
/// unlimited — proves the Bug 1 fix does not over-reject.
#[test]
fn lambda_param_call_twice_accepted() {
    let root = repo_root();
    let (built, out) = built_code(&root, "lambda_param_call_twice_accepted");
    assert!(
        built.is_ok(),
        "calling a lambda param twice must be accepted: {built:?}"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome =
            crate::support::build_and_run_emitted("lambda_param_call_twice_accepted", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "exit 0; stdout:\n{}",
            outcome.stdout
        );
        assert_eq!(outcome.stdout.trim(), "5");
    }
}

/// A fn-carrying, non-Clone `let`-binding used in two consuming (argument)
/// positions has no sound rewrite: a `Maybe (Int -> Int)` payload is consumed by
/// the `andMap`/`map` kernels as an owned `FnOnce` (`Box`), so it stays on the
/// non-`Clone` `Box` carrier — reuse must stay a clean IPE-L0127, never E0382 at
/// `cargo build`.
#[test]
fn fn_carrier_reuse_gated() {
    let root = repo_root();
    let (built, _out) = built_code(&root, "fn_carrier_reuse_gated");
    let code = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        code,
        Some(ipe_diagnostics::IPE_L0127),
        "a fn-carrying let-binding used twice (consuming positions) must be \
         rejected with IPE-L0127, got: {built:?}"
    );
}

// ── T3: forwarder-escape family ──

/// Assert `name` is rejected with IPE-T0014 specifically (the deferred
/// `check_scheme_applications` path — the fail-closed `Ty::Var` arm or a
/// concrete `Fun` found at a forwarder's own external call site).
fn assert_rejected_t0014(name: &str) {
    let root = repo_root();
    let (built, _out) = built_code(&root, name);
    let code = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        code,
        Some(ipe_diagnostics::IPE_T0014),
        "{name}: must be rejected with IPE-T0014 (fail-closed forwarder-escape \
         path), got: {built:?}"
    );
}

/// Build a green fixture, assert acceptance, and (under `IPE_E2E=1`) build the
/// emitted crate and assert its runtime stdout — the exact verification step
/// whose absence let attempts 1-4 ship exit-0-then-cargo-fail bugs.
fn assert_accepted_runs(name: &str, expected_stdout: &str) {
    let root = repo_root();
    let (built, out) = built_code(&root, name);
    assert!(built.is_ok(), "{name}: must be accepted, got: {built:?}");

    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{name}: emitted crate must build and exit 0; stdout:\n{}",
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim(),
        expected_stdout,
        "{name}: wrong runtime output"
    );
}

/// An ANNOTATED double forwarder (`am2 x f = am1 x f` over
/// `am1 x f = Result.andMap x f`, both with explicit signatures) applied to
/// an arity-2 payload. `am1`'s obligated `b` instantiates to `am2`'s own
/// annotation skolem; `check_scheme_applications` is one-shot (no bound
/// transfer), so a fail-OPEN `Ty::Var` arm would let the payload
/// flow unguarded to `main`'s call of `am2` — reaching `cargo build` as
/// E0308. The fail-closed arm rejects the inner `am1` reference, exactly as
/// `Math.min`'s `ord` obligation does on the identical shape.
#[test]
fn and_map_annotated_double_forwarder_curried_rejected() {
    assert_rejected_t0014("and_map_annotated_double_forwarder_curried");
}

/// Documented PRECISION LOSS companion: the same annotated double forwarder
/// at a SAFE arity-1 payload is conservatively rejected too (fail-closed on
/// the escaped skolem — cross-binding obligation propagation is not yet
/// supported for ANY bound; `Math.min` behaves identically). This test pins
/// the CLEAN diagnostic: the two sound outcomes are reject-both (this) or a
/// genuine bound-transfer accepting arity-1 and rejecting arity-2 at
/// `main`; accept-both is a seal violation. If this test
/// ever starts FAILING because the program is ACCEPTED, that is only
/// correct if cross-binding propagation is implemented — in that case the curried
/// sibling above MUST still be rejected AND this fixture's emitted crate
/// MUST build and print 42; anything else is this shape regressing.
#[test]
fn and_map_annotated_double_forwarder_arity1_conservatively_rejected() {
    assert_rejected_t0014("and_map_annotated_double_forwarder_arity1");
}

/// Triple forwarder — escape depth is irrelevant; rejected at the first hop.
#[test]
fn and_map_triple_forwarder_curried_rejected() {
    assert_rejected_t0014("and_map_triple_forwarder_curried");
}

/// Eta-reduced annotated forwarder (`am2 = am1`, bare reference) — the
/// `SchemeApp` records at the bare reference; same fail-closed rejection.
#[test]
fn and_map_eta_reduced_forwarder_curried_rejected() {
    assert_rejected_t0014("and_map_eta_reduced_forwarder_curried");
}

/// Unannotated same-module double forwarder, arity-2 — `CLocal` sharing
/// keeps the solved type CONCRETE at the check, so this rejects with the
/// precise found-type (no precision loss where the solver can see through).
#[test]
fn and_map_untyped_double_forwarder_curried_rejected() {
    assert_rejected_t0014("and_map_untyped_double_forwarder_curried");
}

/// GREEN twin: the same unannotated same-module double forwarder at an
/// arity-1 payload stays ACCEPTED and computes 42 — proves the fail-closed
/// `Ty::Var` arm did not over-reject the concretely-solvable path.
#[test]
fn and_map_untyped_double_forwarder_arity1_accepted() {
    assert_accepted_runs("and_map_untyped_double_forwarder_arity1", "42");
}

/// Cross-module UNANNOTATED double forwarder — the Boundary-Scheme-Promotion
/// escape (the quantified var is a bare `Ty::Var` at the check inside `Lib`);
/// fail-closed rejects it.
#[test]
fn and_map_cross_module_untyped_forwarder_curried_rejected() {
    let root = repo_root();
    let entry = fixture_src_entry(&root, "and_map_cross_module_untyped_forwarder_curried");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("l0114_and_map_cross_module_untyped_forwarder_curried_emit");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build_loose_file(&entry, &out, &runtime);
    let code = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        code,
        Some(ipe_diagnostics::IPE_T0014),
        "cross-module unannotated double forwarder at a curried payload must \
         be rejected with IPE-T0014, got: {built:?}"
    );
}

// ── T3: the map/map2..5/mapError family ──────

/// `Maybe.map` with a curried callback — the 13th-shape FAMILY: the 4th
/// attempt gated `andMap` only; `map` shares the identical
/// FnOnce-vs-IR-flattened-closure hazard and reached `cargo build` as E0277.
#[test]
fn map_curried_stays_gated() {
    assert_hof_curried_rejected("map_curried_stays_gated");
}

/// GREEN twin: `Result.map` with an exact-arity-1 callback stays accepted.
#[test]
fn map_fn_arity1_accepted() {
    assert_accepted_runs("map_fn_arity1_accepted", "42");
}

/// `Maybe.map2` with an arity-3 callback (one residual arrow) — rejected.
#[test]
fn map2_extra_arity_stays_gated() {
    assert_hof_curried_rejected("map2_extra_arity_stays_gated");
}

/// GREEN twin: `Maybe.map2` with an exact-arity-2 callback stays accepted —
/// the scheme's own intermediate `b -> v` arrow carries NO obligation, only
/// the final result var does.
#[test]
fn map2_exact_arity_accepted() {
    assert_accepted_runs("map2_exact_arity_accepted", "42");
}

/// `Result.mapError` with a curried callback — the hazard reaches the ERROR
/// channel too.
#[test]
fn map_error_curried_stays_gated() {
    assert_hof_curried_rejected("map_error_curried_stays_gated");
}

/// GREEN twin: `Result.mapError` with an arity-1 callback stays accepted.
#[test]
fn map_error_arity1_accepted() {
    assert_accepted_runs("map_error_arity1_accepted", "e:boom");
}

/// Bug-3 replay on the map family: bare point-free re-export of
/// `Result.map`, applied to a curried callback.
#[test]
fn map_bare_alias_stays_gated() {
    assert_hof_curried_rejected("map_bare_alias_stays_gated");
}

/// A user-written applicative `map2` over `Result.map` + `Result.andMap`.
/// Without the generalized obligation this cargo-fails as E0277 even at a SAFE
/// arity-2 use — `Result.map`'s callback result escapes into the annotation
/// skolem chain unchecked, and `myMap2` itself carries no obligation. The
/// generalized `Result.map` obligation rejects the definition's kernel
/// reference itself (conservative: the same fail-closed treatment as every
/// other forwarder-escape; the workaround is the built-in `Result.map2`).
#[test]
fn user_map2_via_andmap_stays_gated() {
    assert_hof_curried_rejected("user_map2_via_andmap_stays_gated");
}

/// Annotated generic forwarder around `Result.map` at a curried callback —
/// the deferred `SchemeApp` path, map-family mirror of
/// `and_map_forwarder_curried_is_ipe_t0014`.
#[test]
fn map_annotated_forwarder_curried_is_ipe_t0014() {
    assert_rejected_t0014("map_annotated_forwarder_curried_is_t0014");
}

/// GREEN twin: the same annotated map forwarder at an arity-1 callback stays
/// accepted — the obligation lifts onto the forwarder's own skolem and
/// re-verifies concretely (at `Int`) at the external call site.
#[test]
fn map_annotated_forwarder_arity1_accepted() {
    assert_accepted_runs("map_annotated_forwarder_arity1_accepted", "42");
}

/// Boundary pin: `Result.andThen` carries NO obligation — its callback
/// result is `Con`-headed in the scheme itself (a curried callback is a
/// plain type mismatch), and a callback legitimately returning `Ok fn`
/// (arity-1 inner lambda) is sound end-to-end: the extracted function
/// computes 42. Guards against a future over-eager extension of
/// `StdlibKernel::hof_result_vars` to structurally-protected kernels.
#[test]
fn and_then_fn_payload_accepted() {
    assert_accepted_runs("and_then_fn_payload_accepted", "42");
}

// ── collection-element carrier + element-capability gate ─────────────────────

/// A stored `List (Int -> Int)` of functions is `Clone` (each element on the
/// `Arc<dyn Fn>` carrier), so it can be built, forwarded to a helper, and folded
/// to apply every function — then reused a second time. Builds and prints `37`.
#[test]
fn list_fn_reuse_accepted() {
    assert_accepted_runs("list_fn_reuse", "37");
}

/// A `Dict String (Int -> Int)` dispatch table: the VALUE stores a function on
/// the `Arc` carrier (the KEY stays a comparable `String`), so a looked-up
/// function is projected out and applied. Builds and prints `42`.
#[test]
fn dict_fn_dispatch_accepted() {
    assert_accepted_runs("dict_fn_dispatch", "42");
}

/// Narrowing regression: a function-carrying `List` element is `Clone`
/// (storable), but not comparable — `List.member` needs `==` on the element, so
/// it must fail closed at `ipe` time, never emit Rust `cargo` rejects. The
/// kernel's equality obligation refuses the function element at type-check
/// (IPE-T0001), ahead of the element-capability gate (IPE-L0134). Proves the
/// storable-element carrier flip did NOT open an unsound equality path.
#[test]
fn list_fn_member_stays_gated() {
    let root = repo_root();
    let (built, _out) = built_code(&root, "list_fn_member_gated");
    let code = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        code,
        Some(ipe_diagnostics::IPE_T0001),
        "`List.member` over a function-carrying element must fail closed with \
         IPE-T0001 (a function is not equatable), got: {built:?}"
    );
}
