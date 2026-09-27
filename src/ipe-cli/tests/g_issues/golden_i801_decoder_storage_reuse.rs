//! Seal — a GENERIC combinator that stores a BARE runtime `Decoder a` in its
//! representation, reads it back out, and forwards it into `Decode.list` was
//! `ipe`-accepted (exit 0) but the emitted crate failed `cargo build`: the stored
//! decoder read (`r.dec`) emits a `.clone()` (value semantics — a field read is a
//! copy), and the runtime `Decoder<E, T>` was a non-`Clone`, non-`Copy`
//! `Box<dyn Fn>`, so the clone (and the old reuse-factory closure that moved it)
//! could not compile. This is the decode-side mirror of the encode-side seal:
//! a stored function value rides a clonable `Arc` carrier, and now so does a
//! stored decoder.
//!
//! The fix flips the runtime `Decoder`'s carrier from `Box<dyn Fn + Send>` to
//! `Arc<dyn Fn + Send + Sync>`, making a `Decoder` `Clone` (a refcount bump) while
//! keeping it `Send` for the DB / Config async paths, and takes the list / dict
//! element decoder by value (borrowed across every element and document) instead
//! of through a reuse-factory closure that would have to move a non-`Copy`
//! decoder out of an `Fn`.
//!
//! The fixture stores a bare `Decoder a` at TWO element instantiations (`Int` and
//! `String`) and decodes each box TWICE — proving the stored decoder is reusable
//! across monomorphisations AND across repeated use:
//! `ints=3 ints=2 strs=3 strs=1`.
//!
//! The load-bearing proof is the SEAL: under `IPE_E2E=1` the emitted crate must
//! `cargo build`, run, and exit 0.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "decoder_storage_reuse";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Emit gate + byte-identity golden: the frontend must accept the stored-decoder
/// combinator and re-emit the checked-in `main.rs` byte-for-byte (the
/// `decode_list((r).dec.clone())` by-value forward is locked in the golden). The
/// `cargo`-time clone/move failure this closed was invisible to an accept-only
/// check, so this alone is not the SEAL proof — see the E2E test.
#[test]
fn decoder_storage_reuse_emits_byte_identical() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("main.rs");
    let out = crate::support::scratch_root().join("ipec_i801_decoder_storage_reuse_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // resolver unavailable — skip, matches the other goldens
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a generic combinator storing a bare `Decoder a` and forwarding it into \
         `Decode.list` must be accepted + emitted (the stored decoder rides the \
         clonable `Arc` carrier and is passed by value), got: {built:?}"
    );

    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` and run the emitted crate,
/// asserting the two-instantiation, twice-each round-trip output. Before the fix
/// this was `ipe`-accept then `cargo`-fail (the stored `Decoder` was not `Clone`).
#[test]
fn decoder_storage_reuse_builds_and_runs() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_i801_decoder_storage_reuse_e2e");
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
        "emitted crate must build and exit 0 — a generic combinator storing a bare \
         `Decoder` and reusing it must not be `ipe`-accept-then-`cargo`-fail; \
         stdout:\n{}",
        outcome.stdout
    );
    let dir = root.join("tests").join("golden").join(GOLDEN);
    crate::support::assert_go_parity(GOLDEN, &dir, &outcome.stdout);
}
