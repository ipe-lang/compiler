//! `Ipe.Dict` / `Ipe.Set` comparable-key gate.
//!
//! A `Set` element and a `Dict` key carry the Ipê `comparable`-key obligation
//! (the kernel's element / key variable is minted as a super-typed variable, the
//! same path `Math.min` / `Math.max` take for ordering). Three failure classes
//! must be caught at `ipe` — never left to emit Rust `cargo` rejects:
//!
//! * **Non-comparable element / key, direct call** (a record, a user ADT): fails
//!   closed at type-check as `IPE-T0001` (the eager-pin mismatch — the
//!   super-typed element variable meets a structure that does not support
//!   ordering). This is also stricter than Ipê's runtime, which keys a Set /
//!   Dict on a stringified value.
//! * **Non-comparable element / key, via a generic function** (a record or ADT
//!   passed to `singletonSet : a -> Set a` / `singletonDict : a -> v -> Dict a v`):
//!   fails closed at type-check as `IPE-T0014` (super-type unsatisfied — the
//!   generic's binding-bound variable is instantiated at a non-comparable type,
//!   the same path `Math.min` / `maxOf` take for ordering). Analogous to the
//!   `math_min_rec_gate` / `math_min_fn_gate` pair.
//! * **`Float` element / key** (`Set Float` / `Dict Float v`): `Float` IS Ipê
//!   `comparable`, so the type checker accepts it; but Rust's `f64` is neither
//!   `Ord` nor `Hash` / `Eq`, so `BTreeSet<f64>` / `HashMap<f64, _>` cannot
//!   exist. Fails closed at lowering as `IPE-L0117` (a dedicated diagnostic).
//!   Divergence from Ipê, rationale: Rust backend capability.
//!
//! Every fixture must stop the pipeline before codegen — no emitted crate.

use std::path::PathBuf;

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Build `tests/golden/<fixture>/Main.ipe`, assert it fails with `expected`, and
/// assert NO Rust was emitted (the pipeline stopped before codegen). Skips
/// silently when the runtime cannot be resolved.
fn assert_gate(fixture: &str, out_suffix: &str, expected: ipe_diagnostics::Code) {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join(fixture)
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(out_suffix);
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(expected),
        "fixture {fixture}: expected {expected:?}, got build result {built:?}"
    );

    let emitted = out.join("src").join("main.rs");
    assert!(
        !emitted.exists(),
        "fixture {fixture}: no Rust must be emitted on a rejection, but {} exists",
        emitted.display()
    );
}

// ── Non-comparable element / key → IPE-T0001 (eager-pin mismatch) ─────────────

/// `Set.insert { x = 1 } Set.empty` — a record is not orderable, so the Set
/// element variable cannot pin to it.
#[test]
fn set_record_element_is_ipe_t0001() {
    assert_gate(
        "set_record_gate",
        "m4d_set_record_gate_emit",
        ipe_diagnostics::IPE_T0001,
    );
}

/// `Dict.insert Red 1 Dict.empty` — a user ADT is not a comparable Dict key.
#[test]
fn dict_adt_key_is_ipe_t0001() {
    assert_gate(
        "dict_adt_gate",
        "m4d_dict_adt_gate_emit",
        ipe_diagnostics::IPE_T0001,
    );
}

// ── Float element / key → IPE-L0117 (Rust backend capability) ─────────────────

/// `Set Float` type-checks (Ipê `Float` is `comparable`) but has no sound Rust
/// backing (`f64` is not `Ord`), so lowering rejects it.
#[test]
fn set_float_element_is_ipe_l0117() {
    assert_gate(
        "set_float_gate",
        "m4d_set_float_gate_emit",
        ipe_diagnostics::IPE_L0117,
    );
}

/// `Dict Float v` type-checks but `HashMap<f64, _>` cannot exist (`f64` is not
/// `Hash` / `Eq`), so lowering rejects it.
#[test]
fn dict_float_key_is_ipe_l0117() {
    assert_gate(
        "dict_float_gate",
        "m4d_dict_float_gate_emit",
        ipe_diagnostics::IPE_L0117,
    );
}

// ── Float Set / Dict via INFERENCE (no annotation) → IPE-L0117 ───────────────
//
// The annotated fixtures above carry a `: Set Float` / `: Dict Float v`
// annotation, which drives the shape gate in `ir_type_from_ty`. A Set or Dict
// produced purely by inference never drives that conversion; their own call-site
// region type is the only place `Float` surfaces — these fixtures exercise that
// inference path.

/// Inline, unannotated `Set.fromList [1.5, 2.5]` — the producing call's region
/// type (`Set Float`) is the only carrier of the `Float` element.
#[test]
fn set_float_inline_is_ipe_l0117() {
    assert_gate(
        "set_float_inline_gate",
        "m4d_set_float_inline_gate_emit",
        ipe_diagnostics::IPE_L0117,
    );
}

/// `let s = Set.fromList [1.5, 2.5]` — a `let`-bound float Set with no
/// annotation on the binding.
#[test]
fn set_float_let_is_ipe_l0117() {
    assert_gate(
        "set_float_let_gate",
        "m4d_set_float_let_gate_emit",
        ipe_diagnostics::IPE_L0117,
    );
}

/// A Set built from a `List.map` result (`Set.fromList floats` where `floats`
/// is a mapped `List Float`) — the float-ness is map-derived, not a literal
/// float list.
#[test]
fn set_float_mapped_is_ipe_l0117() {
    assert_gate(
        "set_float_mapped_gate",
        "m4d_set_float_mapped_gate_emit",
        ipe_diagnostics::IPE_L0117,
    );
}

/// `Set.insert 1.5 Set.empty` — a float element introduced via `Set.insert`,
/// no annotation, type fixed entirely by inference.
#[test]
fn set_float_insert_is_ipe_l0117() {
    assert_gate(
        "set_float_insert_gate",
        "m4d_set_float_insert_gate_emit",
        ipe_diagnostics::IPE_L0117,
    );
}

/// Inline, unannotated `Dict.fromList [(1.0, "a")]` — the producing call's
/// region type (`Dict Float String`) is the only carrier of the `Float` key.
#[test]
fn dict_float_inline_is_ipe_l0117() {
    assert_gate(
        "dict_float_inline_gate",
        "m4d_dict_float_inline_gate_emit",
        ipe_diagnostics::IPE_L0117,
    );
}

/// `let d = Dict.fromList [(1.5, "cheap")]` — a `let`-bound float Dict with no
/// annotation on the binding.
#[test]
fn dict_float_let_is_ipe_l0117() {
    assert_gate(
        "dict_float_let_gate",
        "m4d_dict_float_let_gate_emit",
        ipe_diagnostics::IPE_L0117,
    );
}

/// `Dict.insert 1.5 "hello" Dict.empty` — a float key introduced via
/// `Dict.insert`, no annotation, type fixed entirely by inference.
#[test]
fn dict_float_insert_is_ipe_l0117() {
    assert_gate(
        "dict_float_insert_gate",
        "m4d_dict_float_insert_gate_emit",
        ipe_diagnostics::IPE_L0117,
    );
}

// ── Non-comparable element / key via generic function → IPE-T0014 ─────────────
//
// These four fixtures exercise the INDIRECT path: a user-written generic
// `singletonSet : a -> Set a` / `singletonDict : a -> v -> Dict a v` whose body
// uses `Set.fromList` / `Dict.fromList`.  The body's use of the kernel marks the
// binding-bound variable `a` with the comparable-key obligation, so instantiating
// the forwarder at a non-comparable type (record or user ADT) is rejected at
// type-check as `IPE-T0014` (super-type unsatisfied), exactly as `Math.min`
// does for ordering.  This is the direct Set / Dict analogue of
// `math_min_rec_gate` / `math_min_fn_gate`.

/// `singletonSet : a -> Set a` (body `Set.fromList [x]`) called at `{ x : Int }` —
/// a record is not comparable, so the generic is rejected at the call site with
/// `IPE-T0014`.
#[test]
fn set_rec_via_fn_is_ipe_t0014() {
    assert_gate(
        "set_rec_fn_gate",
        "m4d_set_rec_fn_gate_emit",
        ipe_diagnostics::IPE_T0014,
    );
}

/// `singletonSet : a -> Set a` (body `Set.fromList [x]`) called at a user ADT
/// `Color` — a user ADT is not comparable, so the generic is rejected with
/// `IPE-T0014`.
#[test]
fn set_adt_via_fn_is_ipe_t0014() {
    assert_gate(
        "set_adt_fn_gate",
        "m4d_set_adt_fn_gate_emit",
        ipe_diagnostics::IPE_T0014,
    );
}

/// `singletonDict : a -> v -> Dict a v` (body `Dict.fromList [(k, v)]`) called
/// with a `{ x : Int }` record key — a record is not comparable, so the generic
/// is rejected with `IPE-T0014`.
#[test]
fn dict_rec_via_fn_is_ipe_t0014() {
    assert_gate(
        "dict_rec_fn_gate",
        "m4d_dict_rec_fn_gate_emit",
        ipe_diagnostics::IPE_T0014,
    );
}

/// `singletonDict : a -> v -> Dict a v` (body `Dict.fromList [(k, v)]`) called
/// with a user ADT `Color` key — a user ADT is not comparable, so the generic is
/// rejected with `IPE-T0014`.
#[test]
fn dict_adt_via_fn_is_ipe_t0014() {
    assert_gate(
        "dict_adt_fn_gate",
        "m4d_dict_adt_fn_gate_emit",
        ipe_diagnostics::IPE_T0014,
    );
}
