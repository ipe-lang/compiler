//! SEAL — the `Ipe.Codec` composite combinator surface (`list`, `maybe`,
//! `dict`, `map`, and a multi-field record codec written as one `Codec` value)
//! must `ipe`-accept AND `cargo`-build AND run.
//!
//! Each combinator is pure Ipê composing the invariant `Codec` representation
//! (an encoder plus a `{} -> Decoder a` factory) over the existing
//! `Json.Encode`/`Json.Decode`/`Config` kernels — no new kernels. The stored
//! decoder factory and the shared-fn encoder carrier ride the record-of-functions
//! path; a generic `Codec a` forwarding those into the JSON kernels is exactly
//! the shape that was `ipe`-accept-then-`cargo`-fail before the carrier/bound
//! fixes, so the load-bearing proof is the E2E build-and-run, not accept alone.
//!
//! The fixture round-trips a representative value through every combinator
//! (encode → decode → re-encode stability) and asserts the fail-closed paths:
//! a malformed nested value is a typed `Err`, malformed JSON is an `Err`, and
//! `fromJsonSafe` rejects oversize input before decoding. Output:
//! `codec-combinators-ok`.
//!
//! ```text
//! cargo test -p ipe --test g_issues golden_i663_codec_combinators
//! IPE_E2E=1 cargo test -p ipe --test g_issues golden_i663_codec_combinators
//! ```

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "codec_combinators";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Accept + emit gate (always): the composite combinator program must be
/// accepted and lowered. A resolution/type/lower regression fails HERE, in the
/// fast path, never as a silent skip.
#[test]
fn codec_combinators_accepts_and_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_i663_codec_combinators_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // resolver unavailable — skip, matches the sibling goldens
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "the `Ipe.Codec` composite combinator surface must be accepted + emitted \
         (each combinator composes the `Codec` representation over the JSON \
         kernels), got: {built:?}"
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` and run the emitted
/// crate, asserting the round-trip + fail-closed output. `ipe`-accept must imply
/// `cargo`-build — a combinator that accepts then fails to build breaks the seal.
#[test]
fn codec_combinators_builds_and_runs() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_i663_codec_combinators_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let outcome = crate::support::build_and_run_emitted(GOLDEN, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "emitted crate must build and exit 0 — the composite codec combinators \
         must not be `ipe`-accept-then-`cargo`-fail; stdout:\n{}",
        outcome.stdout
    );
    let dir = root.join("tests").join("golden").join(GOLDEN);
    crate::support::assert_go_parity(GOLDEN, &dir, &outcome.stdout);
}
