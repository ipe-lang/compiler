//! The portable golden form of an emitted `Cargo.toml`.
//!
//! An emitted manifest carries two machine-specific values: the live
//! `ipe-runtime-rust` dependency path and the crate-identity hash suffix of the
//! `[package]` name. A committed golden stores a placeholder in place of each,
//! so the byte compare and the bless path read the same text on every host.

use crate::CRATE_IDENTITY_HEX_LEN;

/// The token a golden `Cargo.toml` stores in place of the `ipe-runtime-rust`
/// dependency path.
pub const RUNTIME_PATH_PLACEHOLDER: &str = "__IPE_RUNTIME_PATH__";

/// The token a golden `Cargo.toml` stores in place of the `[package] name`
/// crate-identity hash suffix.
pub const CRATE_IDENTITY_HASH_PLACEHOLDER: &str = "__IPE_CRATE_HASH__";

/// The golden form of an emitted `Cargo.toml`.
///
/// The `ipe-runtime-rust` dependency's `path = "…"` value becomes [`RUNTIME_PATH_PLACEHOLDER`] and the
/// `[package] name` hash suffix becomes [`CRATE_IDENTITY_HASH_PLACEHOLDER`];
/// every other byte is kept, so real manifest drift still shows as a diff.
#[must_use]
pub fn golden_cargo_toml(manifest: &str) -> String {
    let path_normalized = map_lines(manifest, |line| {
        if !line.contains("package = \"ipe-runtime-rust\"") {
            return line.to_owned();
        }
        let Some((head, rest)) = line.split_once("path = \"") else {
            return line.to_owned();
        };
        let Some((_, tail)) = rest.split_once('"') else {
            return line.to_owned();
        };
        format!("{head}path = \"{RUNTIME_PATH_PLACEHOLDER}\"{tail}")
    });
    normalize_crate_identity_hash(&path_normalized)
}

/// Replace the first `[package]` `name` value's `_<hex>` suffix, exactly
/// [`CRATE_IDENTITY_HEX_LEN`] lowercase-hex characters, with
/// [`CRATE_IDENTITY_HASH_PLACEHOLDER`]. An unsuffixed name and a `name` under
/// any other table pass through unchanged.
fn normalize_crate_identity_hash(manifest: &str) -> String {
    let mut in_package = false;
    let mut done = false;
    map_lines(manifest, |line| {
        let trimmed = line.trim_start();
        if trimmed.starts_with('[') {
            in_package = trimmed.starts_with("[package]");
            return line.to_owned();
        }
        if !in_package || done {
            return line.to_owned();
        }
        let Some((lhs, rhs)) = line.split_once('=') else {
            return line.to_owned();
        };
        if lhs.trim() != "name" {
            return line.to_owned();
        }
        done = true;
        let hashed = rhs
            .trim()
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .and_then(|inner| inner.rsplit_once('_'))
            .filter(|(_, hash)| {
                hash.len() == CRATE_IDENTITY_HEX_LEN
                    && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            });
        match hashed {
            Some((base, _)) => format!("{lhs}= \"{base}_{CRATE_IDENTITY_HASH_PLACEHOLDER}\""),
            None => line.to_owned(),
        }
    })
}

/// Rewrite `text` line by line, keeping its trailing newline if it has one.
fn map_lines(text: &str, mut f: impl FnMut(&str) -> String) -> String {
    let mut out = text.lines().map(&mut f).collect::<Vec<_>>().join("\n");
    if text.ends_with('\n') {
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_runtime_path_becomes_the_placeholder() {
        let manifest = "[dependencies]\nipe_runtime = { package = \"ipe-runtime-rust\", path = \"/home/x/runtime\", default-features = false }\n";
        assert_eq!(
            golden_cargo_toml(manifest),
            format!(
                "[dependencies]\nipe_runtime = {{ package = \"ipe-runtime-rust\", path = \"{RUNTIME_PATH_PLACEHOLDER}\", default-features = false }}\n"
            )
        );
    }

    #[test]
    fn a_path_on_another_dependency_is_kept() {
        let manifest = "[dependencies]\nother = { path = \"/home/x/other\" }\n";
        assert_eq!(golden_cargo_toml(manifest), manifest);
    }

    #[test]
    fn the_crate_identity_hash_becomes_the_placeholder() {
        let out =
            golden_cargo_toml("[package]\nname = \"mm-diamond_1a2b3c4d\"\nedition = \"2024\"\n");
        assert!(
            out.contains(&format!(
                "name = \"mm-diamond_{CRATE_IDENTITY_HASH_PLACEHOLDER}\""
            )),
            "{out}"
        );
        assert!(!out.contains("1a2b3c4d"), "no per-machine hash may survive");
    }

    #[test]
    fn distinct_hashes_share_one_golden_form() {
        assert_eq!(
            golden_cargo_toml("[package]\nname = \"app_00112233\"\n"),
            golden_cargo_toml("[package]\nname = \"app_deadbeef\"\n")
        );
    }

    /// A real crate identity normalizes, so the suffix width read here is the
    /// one `crate_identity` writes.
    #[test]
    fn a_real_crate_identity_normalizes() {
        let identity = crate::crate_identity("app", std::path::Path::new("/somewhere/app"));
        let manifest = format!("[package]\nname = \"{}\"\n", identity.as_str());
        assert_eq!(
            golden_cargo_toml(&manifest),
            format!("[package]\nname = \"app_{CRATE_IDENTITY_HASH_PLACEHOLDER}\"\n")
        );
    }

    #[test]
    fn unhashed_and_non_package_names_pass_through() {
        let single = "[package]\nname = \"ipe-app\"\nedition = \"2024\"\n";
        assert_eq!(golden_cargo_toml(single), single);
        let dep = "[package]\nname = \"app_00112233\"\n\n[[bin]]\nname = \"other_00112233\"\n";
        let out = golden_cargo_toml(dep);
        assert!(out.contains(&format!("name = \"app_{CRATE_IDENTITY_HASH_PLACEHOLDER}\"")));
        assert!(out.contains("name = \"other_00112233\""), "{out}");
    }

    #[test]
    fn a_wrong_width_or_uppercase_suffix_is_not_a_hash() {
        for manifest in [
            "[package]\nname = \"my_app\"\n",
            "[package]\nname = \"app_0011223\"\n",
            "[package]\nname = \"app_DEADBEEF\"\n",
        ] {
            assert_eq!(golden_cargo_toml(manifest), manifest);
        }
    }
}
