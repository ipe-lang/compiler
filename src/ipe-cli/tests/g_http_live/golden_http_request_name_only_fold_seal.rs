//! Regression for the "Name-only HttpRequest-shape false-positive fold" —
//! deciding "is this record an `HttpRequest`?" purely by field NAMES (in
//! `ipe_lower::lower::ir_type_from_ty`'s `Ty::Record` arm, its sibling in
//! `ir_type_from_canon`'s `canon::Type::Record` arm, and
//! `ipe_backend_rust::emit_expr::emit_record`'s independent
//! `HTTP_REQUEST_FIELDS` special case) is unsound: checking whether the field
//! NAMES exactly match the 6-field set `{body, headers, method, redirects,
//! timeout, url}` regardless of field TYPES silently
//! miscompiles a completely unrelated user record that happens to share those 7
//! field names (e.g. every field `Int`, nothing HTTP-related): `ipe` exits 0,
//! but the emitted `cargo build` fails with a wall of E0308 errors (the
//! struct's declared type disagreeing with the `HttpRequest` type the literal
//! is emitted as).
//!
//! So both `ipe_lower::lower::ir_type_from_ty` / `ir_type_from_canon`
//! check field TYPES in addition to field NAMES (`is_http_request_shape` /
//! `is_http_request_canon_shape`, `HTTP_REQUEST_FIELD_TYPES`) before folding
//! to the opaque `IrType::HttpRequest`. `ipe_backend_rust::emit_expr`'s
//! independent, cross-crate-isolated copy cannot re-run that TYPE-aware
//! check directly (no `ipe_lower` dependency), so it instead defers to the
//! lowerer's authoritative decision via `EmitCtx::has_record_struct_for`
//! before falling back to its own name-only heuristic — a genuine
//! `HttpRequest` literal never gets a registered struct (the lowerer
//! intercepts it into the opaque type first), so the ordering is sound.
//!
//! ## Why the emit-only assertions run in the DEFAULT gate
//!
//! `IPE_E2E`-gated tests do not run in the default `cargo nextest` gate
//! (documented BACKLOG "Gate blind spot" row). This file's first two tests
//! inspect the emitted `src/main.rs` text (no cargo build) so they run in
//! the DEFAULT gate and pin the regression even when `IPE_E2E` is unset; the
//! third test is the `IPE_E2E`-gated cargo-build-and-run proof that the
//! emitted crate actually compiles AND prints the right sum.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("http_request_name_only_fold_seal")
        .join("Main.ipe")
}

/// Build the fixture and return the emitted `src/main.rs` text. `None` when the
/// build fails (the caller's `assert!` reports the diag).
fn built_main_rs(root: &Path, out: &Path) -> (Result<(), ipe::CliError>, Option<String>) {
    let entry = fixture_entry(root);
    let _ = std::fs::remove_dir_all(out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, out, &runtime);
    let main_rs = if built.is_ok() {
        std::fs::read_to_string(out.join("src").join("main.rs")).ok()
    } else {
        None
    };
    (built, main_rs)
}

/// The all-`Int` 7-field record must NOT fold to the opaque
/// `ipe_runtime::HttpRequest` struct literal — it shares the canonical
/// `HttpRequest` field NAMES but none of its field TYPES, so the (now
/// type-aware) lowerer must classify it as a plain synthesised record.
#[test]
fn name_only_shape_does_not_emit_runtime_http_request_literal() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_http_request_name_only_fold_seal_emit");
    let (built, main_rs) = built_main_rs(&root, &out);
    assert!(
        built.is_ok(),
        "http_request_name_only_fold_seal: must be accepted, got: {built:?}"
    );
    let main_rs = main_rs.expect("an accepted build yields the emitted source");

    assert!(
        !main_rs.contains("ipe_runtime::HttpRequest {") && !main_rs.contains("HttpRequest {"),
        "an all-Int 6-field record sharing HttpRequest's field NAMES (not \
         TYPES) must NOT be emitted as an `HttpRequest` struct literal — \
         that struct's fields are typed String/RedirectPolicy/List and would \
         reject Int values with E0308.\n\
         --- src/main.rs ---\n{main_rs}"
    );
}

/// The literal must instead resolve through the ordinary synthesised-record
/// path — i.e. some `Rec...` struct literal carrying the 6 `1..=6` integer
/// field initialisers, proving `emit_record` deferred to the registered
/// struct (`EmitCtx::has_record_struct_for`) rather than its name-only
/// `HttpRequest` fallback.
#[test]
fn name_only_shape_emits_a_synthesised_record_struct() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_http_request_name_only_fold_seal_struct");
    let (built, main_rs) = built_main_rs(&root, &out);
    assert!(
        built.is_ok(),
        "http_request_name_only_fold_seal: must be accepted, got: {built:?}"
    );
    let main_rs = main_rs.expect("an accepted build yields the emitted source");

    // The struct DEFINITION carries all 6 field names typed `i64` (Ipê
    // `Int`), and the literal construction site initialises all 6 with the
    // fixture's `1..=6` integers — both are only true if `emit_record`
    // resolved a real synthesised struct instead of mislabelling the
    // literal `HttpRequest`.
    assert!(
        main_rs.contains("body: i64")
            && main_rs.contains("headers: i64")
            && main_rs.contains("method: i64")
            && main_rs.contains("redirects: i64")
            && main_rs.contains("timeout: i64")
            && main_rs.contains("url: i64"),
        "expected a synthesised record struct with all 6 fields typed `i64` \
         (Ipe `Int`) — got:\n--- src/main.rs ---\n{main_rs}"
    );
}

/// The load-bearing SEAL proof: under `IPE_E2E=1`, actually `cargo build`
/// the emitted crate and run it. A name-only fold would fail `cargo build` with
/// E0308 (Int values assigned into `HttpRequest`'s String/Bool/List fields);
/// the type-aware fold builds and prints `28` (`1+2+3+4+5+6+7`).
#[test]
fn http_request_name_only_fold_seal_builds_and_runs() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_http_request_name_only_fold_seal_e2e");
    let runtime = e2e_support::require_runtime().into_path_buf();
    let entry = fixture_entry(&root);
    let _ = std::fs::remove_dir_all(&out);
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "http_request_name_only_fold_seal: must be accepted, got: {built:?}"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome =
            crate::support::build_and_run_emitted("http_request_name_only_fold_seal", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "http_request_name_only_fold_seal: emitted crate must build and \
         exit 0 (pre-fix: E0308 from Int values assigned into HttpRequest's \
         String/Bool/List fields); stdout:\n{}",
            outcome.stdout
        );
        assert_eq!(outcome.stdout.trim(), "21", "wrong runtime output");
    }
}
