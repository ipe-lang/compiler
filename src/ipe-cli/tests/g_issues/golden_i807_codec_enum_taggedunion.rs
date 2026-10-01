//! SEAL — the `Ipe.Codec` sum-type combinators (`enum`, and `taggedUnion` with
//! `var0`/`var1`/`var2`/`var3`) must `ipe`-accept AND `cargo`-build AND run.
//!
//! Each combinator stores its driving data inside the decoder-factory closure —
//! an `enum`'s `Vec<(a, String)>` pairs, a `taggedUnion`'s `Vec<Variant a>` —
//! the tvar-inside-a-captured-collection shape. Before the Sync-through-composite
//! bound propagation (a tvar reached through a captured `Vec`/tuple/record that
//! flows into a `Send + Sync` closure stamps `Sync`) and the composite
//! clone-carrier fix (a bare `Generic` inside a captured composite is `CloneOk`,
//! so a `Codec`'s `enc` + `mkDec` reading the same data both clone it), the
//! emitted crate was `ipe`-accept-then-`cargo`-fail: E0277 (`T` not `Sync`) and
//! E0507/E0382 (the non-`Copy` collection moved out of an `Fn` closure). So the
//! load-bearing proof is the E2E build-and-run, not accept alone.
//!
//! The fixture round-trips every variant (encode → decode → re-encode stability),
//! nests the sum codecs under a `list` codec, and asserts the fail-closed paths:
//! an unknown enum tag and an unknown union tag are typed `Err`s, and
//! `fromJsonSafe` rejects oversize input before decoding. Output:
//! `codec-enum-tagged-ok`.
//!
//! ```text
//! cargo test -p ipe --test g_issues golden_i807_codec_enum_taggedunion
//! IPE_E2E=1 cargo test -p ipe --test g_issues golden_i807_codec_enum_taggedunion
//! ```

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "codec_enum_taggedunion";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Accept + emit gate (always): the sum-type combinator program must be accepted
/// and lowered. A resolution/type/lower regression fails HERE, in the fast path,
/// never as a silent skip.
#[test]
fn codec_enum_taggedunion_accepts_and_emits() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_i807_codec_enum_taggedunion_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "the `Ipe.Codec` sum-type combinator surface (`enum` / `taggedUnion` / \
         `varN`) must be accepted + emitted, got: {built:?}"
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` and run the emitted
/// crate, asserting the round-trip + fail-closed output. `ipe`-accept must imply
/// `cargo`-build — a combinator that accepts then fails to build (E0277/E0507)
/// breaks the seal.
#[test]
fn codec_enum_taggedunion_builds_and_runs() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_i807_codec_enum_taggedunion_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome = crate::support::build_and_run_emitted(GOLDEN, &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "emitted crate must build and exit 0 — the sum-type codec combinators \
         must not be `ipe`-accept-then-`cargo`-fail; stdout:\n{}",
            outcome.stdout
        );
        let dir = root.join("tests").join("golden").join(GOLDEN);
        crate::support::assert_go_parity(GOLDEN, &dir, &outcome.stdout);
    }
}
