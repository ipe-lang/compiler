//! SEAL: a closure capturing an in-body local composite over a generic obliges `Sync` on it.
//!
//! `lens xs ns` builds `ys : List a` in its body and maps `ns` with a
//! `\n -> n + List.length ys` closure whose own type (`Int -> Int`) never
//! mentions `a`. The emitter boxes the closure as `Send + Sync`, moving `ys`
//! into it, so `lens`'s `T1` must carry `Send + Sync`; the obligation comes from
//! the closure's capture set, not from the shape of its signature or of the
//! enclosing parameters. Without it the emitted crate is ipe-accepted but fails
//! `cargo build` with E0277.
//!
//! The emit gate asserts the bound on `lens`'s emitted signature; under
//! `IPE_E2E=1` the program is built, run, and its stdout matched against
//! `expected.txt`.

use std::path::{Path, PathBuf};

const GOLDEN: &str = "capture_send_local_composite";

fn fixture_dir(root: &Path) -> PathBuf {
    root.join("tests").join("golden").join(GOLDEN)
}

/// The emitted signature line of the `Main` function spelled `ipe_name`.
///
/// Matches the emitted `main_<snake_case>` name with its underscores removed
/// against the lower-cased Ipê name, so the check does not re-derive the
/// backend's snake-casing.
fn signature_of<'a>(emitted: &'a str, ipe_name: &str) -> Option<&'a str> {
    let wanted = format!("main{}", ipe_name.to_lowercase());
    emitted.lines().find(|line| {
        line.split_once("fn ").is_some_and(|(_, rest)| {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .filter(|c| *c != '_')
                .collect();
            name == wanted
        })
    })
}

/// Emit gate: `lens`'s generic `T1` must be bounded by `Send + Sync`.
#[test]
fn capture_send_local_composite_bounds_emitted() {
    let root = crate::support::repo_root();
    let entry = fixture_dir(&root).join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{GOLDEN}_emit"));
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "{GOLDEN}: ipe build must accept the program, got: {built:?}"
    );

    let emitted = crate::support::read_all_emitted_src(&out);
    let signature = signature_of(&emitted, "lens");
    assert!(
        signature.is_some_and(|line| line.contains("T1: 'static + Send + Sync")),
        "{GOLDEN}: `lens`'s T1 must carry `Send + Sync` (a boxed closure captures \
         the local `ys : List a`), got signature: {signature:?}"
    );
}

/// THE SEAL: under `IPE_E2E=1` the emitted crate must build and print both mapped lists.
#[test]
fn capture_send_local_composite_runs() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = crate::support::repo_root();
    let dir = fixture_dir(&root);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{GOLDEN}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "{GOLDEN}: ipe build must accept the program, got: {built:?}"
    );

    let outcome = crate::support::build_and_run_emitted(GOLDEN, &out);
    crate::support::assert_go_parity(GOLDEN, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "{GOLDEN}: must exit 0");
}
