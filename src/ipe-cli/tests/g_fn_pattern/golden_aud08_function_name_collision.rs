//! AUD-08 regression — two DISTINCT functions in DIFFERENT modules whose
//! `(home, name)` identity folds to the SAME Rust identifier under
//! `naming::module_value`'s `snake_case` fold must NOT silently emit two
//! functions sharing one Rust name (a `rustc` E0428 "duplicate definition",
//! or worse, whichever definition the emitter's map keeps last silently
//! winning). The injective name fold resolves this by disambiguating the
//! loser to a free Rust name, so BOTH definitions emit and the legal program
//! builds and runs; only a degenerate namespace with no free suffix fails
//! closed with `NameError::RustNameFold` (IPE-N0048), naming both Ipê paths
//! and the shared Rust name.
//!
//! `module_value`'s fold is not injective over the (home, name) split:
//! `["ZuiBorder"]/"rounded"` and `["Zui"]/"borderRounded"` both fold to
//! `zui_border_rounded` (verified against `to_snake_case`'s exact algorithm —
//! an interior uppercase char always emits a `_` boundary, so `ZuiBorder_rounded`
//! and `Zui_borderRounded` produce byte-identical output). `zui` is NOT a kernel
//! namespace, so no `user_` disambiguation prefix applies. The module
//! names are DELIBERATELY not `Ui`/`UiBorder`: `Ui` is a reserved Tier-C stdlib
//! qualifier (`Ipe.Ui`), so a bare `Ui.borderRounded` would raise IPE-N0034
//! (demanding `import Ipe.Ui`) and mask the fold-collision this test covers;
//! `Zui`/`ZuiBorder` are non-reserved names that fold identically. Mirrors the
//! sibling enum-name fold in `ipe_backend_rust`'s `emit`.
//!
//! ```text
//! cargo test -p ipe --test golden_aud08_function_name_collision
//! ```

use std::fs;
use std::path::PathBuf;

fn write_project(dir: &std::path::Path, files: &[(&str, &str)]) -> bool {
    let src = dir.join("src");
    let _ = fs::remove_dir_all(dir);
    if fs::create_dir_all(&src).is_err() {
        return false;
    }
    files
        .iter()
        .all(|(name, contents)| fs::write(src.join(name), contents).is_ok())
}

#[test]
fn distinct_functions_folding_to_the_same_rust_name_both_emit() {
    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // runtime unavailable in this environment — skip silently
    };

    let tmp = crate::support::scratch_root().join("ipec_aud08_function_name_collision");
    let wrote = write_project(
        &tmp,
        &[
            (
                "ZuiBorder.ipe",
                "module ZuiBorder exposing (rounded)\n\
                 rounded : Int -> Int\n\
                 rounded x = x\n",
            ),
            (
                "Zui.ipe",
                "module Zui exposing (borderRounded)\n\
                 borderRounded : Int -> Int\n\
                 borderRounded x = x + 1\n",
            ),
            (
                "Main.ipe",
                "module Main exposing (main)\n\
                 import Ipe.Io as Io\n\
                 import Ipe.String\n\
                 import ZuiBorder\n\
                 import Zui\n\n\
                 main = Io.println (String.fromInt (ZuiBorder.rounded 1 + Zui.borderRounded 1))\n",
            ),
        ],
    );
    assert!(wrote, "must write the fixture project to a temp dir");

    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("aud08_function_name_collision_out");
    let _ = fs::remove_dir_all(&out);

    // `ZuiBorder.rounded` and `Zui.borderRounded` both fold to
    // `zui_border_rounded`. The injective fold disambiguates the loser to a
    // free Rust name, so both definitions emit and the legal program builds —
    // it is NOT rejected. A leftover E0428 (two Rust fns sharing one name)
    // would surface as an emit/build error, so a clean `Ok` proves the fold
    // kept the two definitions distinct.
    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "two functions folding to `zui_border_rounded` must both emit under \
         disambiguated Rust names and build cleanly, got: {:?}",
        built.err()
    );
}

/// Positive control: two functions in different modules whose names do NOT
/// collide under the fold must build cleanly — the guard must not be
/// over-eager and reject legitimate distinct names.
#[test]
fn distinct_functions_with_distinct_rust_names_are_accepted() {
    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };

    let tmp = crate::support::scratch_root().join("ipec_aud08_function_name_collision_control");
    let wrote = write_project(
        &tmp,
        &[
            (
                "Lib.ipe",
                "module Lib exposing (helper)\n\
                 helper : Int -> Int\n\
                 helper x = x\n",
            ),
            (
                "Main.ipe",
                "module Main exposing (main)\n\
                 import Ipe.Io as Io\n\
                 import Lib\n\n\
import Ipe.String
                 main = Io.println (String.fromInt (Lib.helper 1))\n",
            ),
        ],
    );
    assert!(wrote, "must write the fixture project to a temp dir");

    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("aud08_function_name_collision_control_out");
    let _ = fs::remove_dir_all(&out);

    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "distinct, non-colliding function names must build cleanly: {:?}",
        built.err()
    );
}
