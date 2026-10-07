//! `List.sortBy` key and `List.member` / `List.unique` element obligation gate.
//!
//! The runtime functions these kernels lower to bound a generic parameter by a
//! trait (`list_sort_by`'s `B: PartialOrd`, `list_member`'s `T0: PartialEq`,
//! `list_unique`'s `T: PartialEq`). The type checker ties the matching scheme
//! variable to the same obligation, so a type Rust cannot satisfy fails closed
//! at `ipe` — never left to emit Rust `cargo` rejects:
//!
//! * **Non-orderable key, direct call** (a record, a custom type, a function, a
//!   tuple): `IPE-T0001`, the eager-pin mismatch of the ordered key variable.
//! * **Through a generic forwarder** (`byKey : (a -> b) -> List a -> List a`):
//!   `IPE-T0014`, the forwarder's key variable inherits the obligation and its
//!   instantiation does not meet it. An ordering generic is emitted with a
//!   `Copy` bound, so a `String` key is refused here while the direct call
//!   accepts it.
//! * **Non-equatable element** (a record holding a function): `IPE-T0014`, the
//!   deep equality check over the pinned element.
//!
//! Every refusal must stop the pipeline before codegen — no emitted crate. The
//! accepted scalar keys are built and run under `IPE_E2E=1`.

use std::path::PathBuf;

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// The entry `tests/golden/<fixture>/Main.ipe`.
fn fixture_entry(fixture: &str) -> PathBuf {
    repo_root()
        .join("tests")
        .join("golden")
        .join(fixture)
        .join("Main.ipe")
}

/// Build `fixture`, assert it fails with `expected`, and assert NO Rust was
/// emitted (the pipeline stopped before codegen).
fn assert_gate(fixture: &str, out_suffix: &str, expected: ipe_diagnostics::Code) {
    let entry = fixture_entry(fixture);
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

// ── Non-orderable key, direct call → IPE-T0001 ────────────────────────────────

/// `List.sortBy (\d -> d.owner) docs` — a record key has no ordering.
#[test]
fn sort_by_record_key_is_ipe_t0001() {
    assert_gate(
        "sort_by_record_key_gate",
        "m4e_sort_by_record_key_gate_emit",
        ipe_diagnostics::IPE_T0001,
    );
}

/// `List.sortBy (\t -> t.shade) tiles` — a custom-type key has no ordering.
#[test]
fn sort_by_custom_type_key_is_ipe_t0001() {
    assert_gate(
        "sort_by_adt_key_gate",
        "m4e_sort_by_adt_key_gate_emit",
        ipe_diagnostics::IPE_T0001,
    );
}

/// `List.sortBy (\n -> \m -> n + m) offsets` — a function key has no ordering.
#[test]
fn sort_by_function_key_is_ipe_t0001() {
    assert_gate(
        "sort_by_fn_key_gate",
        "m4e_sort_by_fn_key_gate_emit",
        ipe_diagnostics::IPE_T0001,
    );
}

/// `List.sortBy (\p -> ( p.age, p.name )) people` — a tuple key is not an
/// orderable scalar.
#[test]
fn sort_by_tuple_key_is_ipe_t0001() {
    assert_gate(
        "sort_by_tuple_key_gate",
        "m4e_sort_by_tuple_key_gate_emit",
        ipe_diagnostics::IPE_T0001,
    );
}

// ── Through a generic forwarder → IPE-T0014 ───────────────────────────────────

/// `byKey (\d -> d.owner) docs` — the forwarder's key inherits the ordering
/// obligation, which a record does not meet.
#[test]
fn sort_by_forwarder_record_key_is_ipe_t0014() {
    assert_gate(
        "sort_by_wrapper_record_gate",
        "m4e_sort_by_wrapper_record_gate_emit",
        ipe_diagnostics::IPE_T0014,
    );
}

/// `byKey (\p -> p.name) people` — an ordering generic is emitted with a `Copy`
/// bound, which `String` does not meet.
#[test]
fn sort_by_forwarder_string_key_is_ipe_t0014() {
    assert_gate(
        "sort_by_wrapper_string_gate",
        "m4e_sort_by_wrapper_string_gate_emit",
        ipe_diagnostics::IPE_T0014,
    );
}

// ── Non-equatable element → IPE-T0014 ─────────────────────────────────────────

/// `List.member probe steps` — a record holding a function has no equality.
#[test]
fn member_function_record_is_ipe_t0014() {
    assert_gate(
        "member_fn_record_gate",
        "m4e_member_fn_record_gate_emit",
        ipe_diagnostics::IPE_T0014,
    );
}

/// `dedupe steps` over `dedupe xs = List.unique xs` — the forwarder's element
/// inherits the equality obligation, which a function-holding record does not
/// meet.
#[test]
fn unique_forwarder_function_record_is_ipe_t0014() {
    assert_gate(
        "unique_fn_record_gate",
        "m4e_unique_fn_record_gate_emit",
        ipe_diagnostics::IPE_T0014,
    );
}

// ── Accepted scalar keys, built and run ───────────────────────────────────────

/// `List.sortBy` over an `Int`, `String`, `Float`, `Bool` and `Char` key — each
/// is accepted, the emitted crate builds, and every sort orders its labels.
#[test]
fn sort_by_scalar_keys_build_and_order() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let name = "sort_by_scalar_keys";
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&fixture_entry(name), &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    let run = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(
        run.exit_code,
        Some(0),
        "must exit 0; got {:?}",
        run.exit_code
    );
    assert!(
        run.stdout.contains("yzx yzx xzy yxz zxy"),
        "each scalar key must order the labels; got: {:?}",
        run.stdout,
    );
}
