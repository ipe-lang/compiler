//! SEAL: a local a closure mentions only as a record-update base is captured, so its reuse is cloned first.
//!
//! A `move` closure captures every free local its body mentions, whatever the
//! emitted form at the mention. A lambda reading `card` only as the base of
//! `{ card | flavor = Just f }` therefore moves `card` into the closure; a
//! later use of `card` needs the pre-clone the capture walk grants, or the
//! emitted crate fails E0382 after `ipe` accepted the program.
//!
//! | Program | Shape | Outcome |
//! |---|---|---|
//! | `closure_capture_update_base` golden, `captureUpdateThenReuse` | Clone record, update base in a lambda, reused after | pre-cloned, builds, prints `ok` |
//! | same golden, `captureUpdateLastUse` | Clone record, update base in a lambda, dead after | no pre-clone |
//! | inline non-`Clone` record | `Task`-bearing record, update base in a continuation, reused after | fail-closed IPE-L0135 |

use std::path::{Path, PathBuf};

use ipe::CliError;

const GOLDEN: &str = "closure_capture_update_base";

/// The pre-clone that keeps `card` usable after the closure captures it.
const PRE_CLONE: &str = "let card = card.clone();";

const fn false_marker() -> bool {
    std::hint::black_box(false)
}

fn golden_dir(root: &Path) -> PathBuf {
    root.join("tests").join("golden").join(GOLDEN)
}

/// The emitted text of the function `name`, from its `fn` header to the next top-level `fn`.
fn fn_section<'a>(emitted: &'a str, name: &str) -> &'a str {
    let header = format!("fn {name}(");
    let start = emitted.find(&header);
    assert!(
        start.is_some(),
        "{GOLDEN}: emitted source must define `{name}`; got:\n{emitted}"
    );
    let rest = emitted.get(start.unwrap_or(0)..).unwrap_or_default();
    let body = rest.get(header.len()..).unwrap_or_default();
    let end = [body.find("\nfn "), body.find("\npub fn ")]
        .into_iter()
        .flatten()
        .min()
        .map_or(rest.len(), |at| at + header.len());
    rest.get(..end).unwrap_or(rest)
}

/// Emit gate: a reused update-base capture is pre-cloned; a last-use one is not.
#[test]
fn update_base_capture_pre_clones_only_a_reused_local() {
    let root = crate::support::repo_root();
    let entry = golden_dir(&root).join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{GOLDEN}_emit"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "{GOLDEN}: ipe must accept the program, got: {built:?}"
    );

    let emitted = crate::support::read_all_emitted_src(&out);
    for reused in [
        "main_capture_update_then_reuse",
        "main_capture_read_then_reuse",
    ] {
        assert!(
            fn_section(&emitted, reused).contains(PRE_CLONE),
            "{GOLDEN}: `card` is used after the closure in `{reused}`, so it must be \
             pre-cloned with `{PRE_CLONE}`; got:\n{emitted}"
        );
    }
    assert!(
        !fn_section(&emitted, "main_capture_update_last_use").contains(PRE_CLONE),
        "{GOLDEN}: `card` is dead after the closure in `main_capture_update_last_use`, \
         so it must move without `{PRE_CLONE}`; got:\n{emitted}"
    );
}

/// THE SEAL: under `IPE_E2E=1` the emitted crate must `cargo build` and print `ok`.
#[test]
fn update_base_capture_seal_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = crate::support::repo_root();
    let entry = golden_dir(&root).join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{GOLDEN}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "{GOLDEN}: ipe must accept the program, got: {built:?}"
    );

    let run = crate::support::build_and_run_emitted(GOLDEN, &out);
    assert_eq!(
        run.exit_code,
        Some(0),
        "{GOLDEN}: the emitted program must exit 0"
    );
    crate::support::assert_self_regression(GOLDEN, &golden_dir(&root), &run.stdout);
}

/// A non-`Clone` `Task`-bearing record `w` is mentioned by a closure only as an
/// update base, then read again by a later closure.
///
/// The first closure moves `w` into `first` before the second closure captures
/// it, so the second capture is a use after move; ipe must refuse it with
/// IPE-L0135 rather than emit a crate that fails E0382. The reuse follows the
/// capture in emitted order: a field read in a `Task.andThen` container runs
/// before its continuation moves `w`, which is a borrow then a move and builds.
const NONCLONE_UPDATE_BASE_CAPTURE_REUSE: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String
import Ipe.Task as Task


tagOf : { job : Task Error Int, tag : Int } -> Int
tagOf r =
    r.tag


bump : { job : Task Error Int, tag : Int } -> Task Error ()
bump w =
    let
        first =
            Task.andThen (\n -> Io.println (String.fromInt (tagOf { w | tag = n }))) (Task.succeed 1)
    in
    Task.andThen (\_ -> Io.println (String.fromInt w.tag)) first


main : Task Error ()
main =
    bump { job = Task.succeed 7, tag = 3 }
";

fn write_scratch(name: &str, source: &str) -> Option<PathBuf> {
    let dir = crate::support::scratch_root()
        .join("closure-capture-update-base")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    let src = dir.join("src");
    std::fs::create_dir_all(&src).ok()?;
    let entry = src.join("Main.ipe");
    std::fs::write(&entry, source).ok()?;
    Some(entry)
}

/// Refusal: a non-`Clone` update-base capture reused after the closure fails closed.
#[test]
fn nonclone_update_base_capture_reuse_fails_closed() {
    let name = "nonclone_update_base_capture_reuse";
    let entry = crate::support::expect_scratch_entry(
        name,
        write_scratch(name, NONCLONE_UPDATE_BASE_CAPTURE_REUSE),
    );
    let out = crate::support::scratch_root().join(format!("ipec_{name}"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    match ipe::build(&entry, &out, &runtime) {
        Err(CliError::Pipeline { diag, .. }) => assert_eq!(
            diag.code(),
            ipe_diagnostics::IPE_L0135,
            "{name}: expected fail-closed IPE-L0135, got a different diagnostic"
        ),
        Ok(()) => assert!(
            false_marker(),
            "{name}: ipe ACCEPTED a non-Clone record captured as an update base and \
             reused (exit 0); the emitted crate would fail cargo E0382, a SEAL break"
        ),
        Err(other) => assert!(
            false_marker(),
            "{name}: non-pipeline build error: {other:?}"
        ),
    }
}
