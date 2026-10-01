//! Seal — a GENERIC stdlib-style codec combinator that stores a function in its
//! representation and forwards it into a JSON kernel was `ipe`-accepted (exit 0)
//! but the emitted crate failed `cargo build` with two `E0277`s:
//!
//! 1. **Missing `Send` bound.** `decodeList : Codec a -> String -> Result Error
//!    (List a)` emits `fn <T1: Clone>` but its body builds a `Decoder (List a)`
//!    through `decode_list`, whose runtime element bound is `T: 'static + Send`.
//!    The `Decoder a` is hidden inside the `Codec a` ADT field, invisible to the
//!    signature-level obligation walk, so the `Send` bound was dropped.
//! 2. **No `SharedFun` → kernel-arg `Fn` coercion.** `encodeList` reads the codec's
//!    stored encoder (a `SharedFun` / `Arc<dyn Fn>`) and passes it into
//!    `json_enc_list`, whose element-encoder parameter is a bare `impl Fn` —
//!    `Arc<dyn Fn>` does not `impl Fn`.
//!
//! The fix propagates the runtime-required `Send + 'static` onto the generic and
//! eta-demotes the shared read onto the `Box<dyn Fn>` carrier the `impl Fn` slot
//! accepts (`move |eta_0| (read)(eta_0)`), the kernel-arg sibling of the
//! record-field read demotion.
//!
//! The fixture exercises the combinator at TWO element instantiations (`List Int`
//! and `List String`) to prove the propagated bound and the coercion hold across
//! monomorphisations, then round-trips both:
//! `[1,2,3] ints=3 ["a","b"] strs=3`.
//!
//! The load-bearing proof is the SEAL: under `IPE_E2E=1` the emitted crate must
//! `cargo build`, run, and exit 0.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "codec_generic_combinator";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Emit gate + byte-identity golden: the frontend must accept the generic
/// combinator program and re-emit the checked-in `main.rs` byte-for-byte (the
/// `Send + 'static` bound and the `move |eta_0| (…enc.clone())(eta_0)` demotion
/// are locked in the golden). The two `E0277`s this closed were `cargo`-time
/// failures invisible to an accept-only check, so this alone is not the SEAL
/// proof — see the E2E test.
#[test]
fn generic_combinator_emits_byte_identical() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("main.rs");
    let out = crate::support::scratch_root().join("ipec_i798_generic_combinator_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a generic codec combinator forwarding a stored `SharedFun` encoder into \
         `json_enc_list` and building a `decode_list` over a generic element must \
         be accepted + emitted (the `Send` bound is propagated, the `Arc<dyn Fn>` \
         read is demoted onto the `Box<dyn Fn>` carrier), got: {built:?}"
    );

    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` and run the emitted crate,
/// asserting the two-instantiation round-trip output. Before the fix this was
/// `ipe`-accept then `cargo` `E0277` (missing `Send` + `Arc<dyn Fn> !impl Fn`).
#[test]
fn generic_combinator_builds_and_runs() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_i798_generic_combinator_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome = crate::support::build_and_run_emitted(GOLDEN, &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "emitted crate must build and exit 0 — a generic combinator storing a \
         function and forwarding it into a JSON kernel must not be \
         `ipe`-accept-then-`cargo`-fail; stdout:\n{}",
            outcome.stdout
        );
        let dir = root.join("tests").join("golden").join(GOLDEN);
        crate::support::assert_go_parity(GOLDEN, &dir, &outcome.stdout);
    }
}
