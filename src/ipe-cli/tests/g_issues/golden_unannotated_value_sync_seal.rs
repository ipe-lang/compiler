//! SEAL: an unannotated zero-parameter generic value carries the `Sync` obligations its body records.
//!
//! `Lib.emptyList = Decode.succeed []` and `Lib.checkboxOf = \toMsg checked ->
//! Input.checkbox …` generalize at the module boundary and are used from `Main`
//! at two instantiations each, so each lowers to a generic Rust function with
//! no parameters. `decode_succeed` and `input_checkbox_` bound their captured
//! value / message type `Sync`, so each generic must carry `Send + Sync` — the
//! zero-parameter value binding finalizes its generics through the same bound
//! folding every other definition shape uses.
//!
//! The emit gate asserts the bound on both generic parameter lists; under
//! `IPE_E2E=1` the emitted crate must `cargo build`.

use std::path::{Path, PathBuf};

const GOLDEN: &str = "unannotated_value_sync_seal";

/// The `Lib` values generic over a `Sync`-obliged type variable.
const VALUES: [&str; 2] = ["emptyList", "checkboxOf"];

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("src")
        .join("Main.ipe")
}

/// The generic parameter list of the emitted `Lib` function spelled `ipe_name`.
///
/// Matches the emitted `lib_<snake_case>` name with its underscores removed
/// against the lower-cased Ipê name, so the check does not re-derive the
/// backend's snake-casing. Returns the text between the name and the opening
/// parenthesis of the parameter list, so a `Sync` in the return type cannot
/// satisfy the check.
fn generics_of<'a>(emitted: &'a str, ipe_name: &str) -> Option<&'a str> {
    let wanted = format!("lib{}", ipe_name.to_lowercase());
    emitted.lines().find_map(|line| {
        let (_, rest) = line.split_once("fn ")?;
        let name_len = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        let (name, tail) = rest.split_at(name_len);
        let normalized: String = name.chars().filter(|c| *c != '_').collect();
        if normalized != wanted {
            return None;
        }
        Some(tail.split_once('(').map_or(tail, |(generics, _)| generics))
    })
}

/// Emit gate: each value's generic must be bounded by `Sync`.
#[test]
fn unannotated_value_sync_bounds_emitted() {
    let root = crate::support::repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join(format!("ipec_{GOLDEN}_emit"));
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "{GOLDEN}: ipe build must accept the program, got: {built:?}"
    );

    let emitted = crate::support::read_all_emitted_src(&out);
    for name in VALUES {
        let generics = generics_of(&emitted, name);
        assert!(
            generics.is_some_and(|g| g.contains("Send + Sync")),
            "{GOLDEN}: `Lib.{name}`'s generic must carry `Send + Sync` (its body \
             reaches a kernel that bounds it `Sync`), got generics: {generics:?}"
        );
    }
}

/// THE SEAL: under `IPE_E2E=1` the emitted crate must `cargo build`.
#[test]
fn unannotated_value_sync_seal_builds() {
    let root = crate::support::repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join(format!("ipec_{GOLDEN}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "{GOLDEN}: ipe build must accept the program, got: {built:?}"
    );

    crate::support::assert_seal_builds(GOLDEN, &out);
}
