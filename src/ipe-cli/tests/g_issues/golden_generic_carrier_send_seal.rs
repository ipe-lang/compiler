//! SEAL: a generic the body carries under a `Cmd` / `Sub` is bounded `Send + 'static`.
//!
//! `cmd_map` / `cmd_perform` / `sub_map` bound the type a command or
//! subscription carries `Send + 'static`. Each helper of the fixture carries
//! its generic `a` under a `Cmd` / `Sub` only inside its body — mapped,
//! performed, or bound by `let` and discarded — while its signature shows `a`
//! bare or under a function type, so no signature walk sees the carrier. The
//! obligation is read off each reference's solved type while the body lowers.
//!
//! The emit gate asserts the bound on every helper's `a` (its first generic,
//! `T1`); under `IPE_E2E=1` the emitted crate must `cargo build`.

use std::path::{Path, PathBuf};

const GOLDEN: &str = "generic_carrier_send_seal";

/// The helpers carrying their generic `a` under a `Cmd` / `Sub` in the body only.
const HELPERS: [&str; 4] = ["subMapped", "cmdMapped", "subDiscarded", "cmdDiscarded"];

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// The bounds of the first generic `T1` of the `Main` function spelled `ipe_name`.
///
/// Matches the emitted `main_<snake_case>` name with its underscores removed
/// against the lower-cased Ipê name, so the check does not re-derive the
/// backend's snake-casing, then returns the text of `T1`'s entry in the generic
/// parameter list (up to the next parameter or the list's end).
fn first_generic_of<'a>(main_rs: &'a str, ipe_name: &str) -> Option<&'a str> {
    let wanted = format!("main{}", ipe_name.to_lowercase());
    main_rs.lines().find_map(|line| {
        let (_, rest) = line.split_once("fn ")?;
        let name_len = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        let (name, tail) = rest.split_at(name_len);
        let normalized: String = name.chars().filter(|c| *c != '_').collect();
        if normalized != wanted {
            return None;
        }
        let generics = tail.split_once('(').map_or(tail, |(generics, _)| generics);
        let (_, first) = generics.split_once("T1")?;
        Some(first.split_once(", T").map_or(first, |(bounds, _)| bounds))
    })
}

/// Emit gate: every helper's `a` must be bounded `Send`.
#[test]
fn generic_carrier_send_bounds_emitted() {
    let root = crate::support::repo_root();
    let entry = fixture_entry(&root);
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
    for name in HELPERS {
        let bounds = first_generic_of(&emitted, name);
        assert!(
            bounds.is_some_and(|b| b.contains("Send") && b.contains("'static")),
            "{GOLDEN}: `{name}`'s `a` must carry `Send + 'static` (its body carries it \
             under a `Cmd` / `Sub`), got bounds: {bounds:?}"
        );
    }
}

/// THE SEAL: under `IPE_E2E=1` the emitted crate must `cargo build`.
#[test]
fn generic_carrier_send_seal_builds() {
    let root = crate::support::repo_root();
    let entry = fixture_entry(&root);
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

    crate::support::assert_seal_builds(GOLDEN, &out);
}
