//! Shared test-target enumeration for the workspace-wide source scans
//! (`skip_scan`, `target_scan`).
//!
//! Each scan walks every `cargo metadata` target of kind `test`, plus every
//! module file it declares via `mod`/`#[path]`, so it reaches exactly the
//! source the test binaries actually compile — not every `.rs` file under
//! `tests/`, which would also catch fixtures the scans must not parse as
//! live source.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use syn::parse::Parser;

/// The workspace root, every test target's source files (relative to the
/// root), and the subset of those files reached only through an explicit
/// `#[path = "…"]` module attribute rather than the ordinary `mod name;`
/// file-naming convention.
///
/// The `#[path]` subset matters to a scan that must fail closed on what it
/// cannot read: a `#[path]` retarget (and its `cfg_attr(path = …)` form) can
/// point anywhere, so a scan that trusts the file it lands on is trusting a
/// redirection it did not itself verify is total.
#[allow(clippy::expect_used)] // an unreadable workspace manifest fails the scan: the designed outcome
pub fn test_target_files_with_path_attrs() -> (PathBuf, BTreeSet<PathBuf>, BTreeSet<PathBuf>) {
    let manifest = e2e_support::manifest_dir!().join("../../Cargo.toml");
    let out = std::process::Command::new(e2e_support::target::cargo_program())
        .args([
            "metadata",
            "--no-deps",
            "--offline",
            "--format-version",
            "1",
        ])
        .arg("--manifest-path")
        .arg(&manifest)
        .output()
        .expect("`cargo metadata` must run");
    assert!(
        out.status.success(),
        "`cargo metadata` failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("`cargo metadata` must print JSON");
    let root = PathBuf::from(
        meta.get("workspace_root")
            .and_then(serde_json::Value::as_str)
            .expect("metadata names the workspace root"),
    );
    let roots: Vec<PathBuf> = meta
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .expect("metadata lists the packages")
        .iter()
        .filter_map(|p| p.get("targets").and_then(serde_json::Value::as_array))
        .flatten()
        .filter(|t| {
            t.get("kind")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|k| k.iter().any(|k| k == "test"))
        })
        .map(|t| {
            t.get("src_path")
                .and_then(serde_json::Value::as_str)
                .map(PathBuf::from)
                .expect("every metadata target names its source path")
        })
        .collect();
    assert!(!roots.is_empty(), "the workspace must declare test targets");
    let mut walk = ModWalk::default();
    for target in roots {
        walk.visit(&target, true);
    }
    assert!(
        walk.unresolved.is_empty(),
        "unresolvable `mod` declarations in test targets:\n{}",
        walk.unresolved.join("\n")
    );
    let relativize = |set: &BTreeSet<PathBuf>| -> BTreeSet<PathBuf> {
        set.iter()
            .map(|f| {
                f.strip_prefix(&root)
                    .map_or_else(|_| f.clone(), Path::to_path_buf)
            })
            .collect()
    };
    let files = relativize(&walk.seen);
    let path_attr_files = relativize(&walk.path_attr_targets);
    (root, files, path_attr_files)
}

/// The workspace root and every test target's source files, relative to it.
pub fn test_target_files() -> (PathBuf, BTreeSet<PathBuf>) {
    let (root, files, _) = test_target_files_with_path_attrs();
    (root, files)
}

/// Follows every out-of-line `mod` declaration from the test-target roots.
#[derive(Default)]
struct ModWalk {
    seen: BTreeSet<PathBuf>,
    /// Files reached only through an explicit `#[path]` attribute.
    path_attr_targets: BTreeSet<PathBuf>,
    unresolved: Vec<String>,
}

impl ModWalk {
    /// Visit `file`; `mod_rs` when it is a crate root, a `mod.rs`, or a
    /// `#[path]` target, whose child modules live beside it.
    fn visit(&mut self, file: &Path, mod_rs: bool) {
        if !self.seen.insert(file.to_path_buf()) {
            return;
        }
        // An unreadable or unparsable file is refused by the per-file scan.
        let Some(parsed) = std::fs::read_to_string(file)
            .ok()
            .and_then(|text| syn::parse_file(&text).ok())
        else {
            return;
        };
        let dir = file.parent().map(Path::to_path_buf).unwrap_or_default();
        let base = if mod_rs {
            dir.clone()
        } else {
            file.file_stem()
                .map_or_else(|| dir.clone(), |stem| dir.join(stem))
        };
        self.items(file, &parsed.items, &dir, &base, false);
    }

    fn items(&mut self, file: &Path, items: &[syn::Item], dir: &Path, base: &Path, inline: bool) {
        for item in items {
            let syn::Item::Mod(m) = item else {
                continue;
            };
            let path_attr = path_attr(&m.attrs);
            if let Some((_, inner)) = &m.content {
                let nested =
                    path_attr.map_or_else(|| base.join(m.ident.to_string()), |p| base.join(p));
                self.items(file, inner, dir, &nested, true);
                continue;
            }
            let candidates = path_attr.as_deref().map_or_else(
                || {
                    let name = m.ident.to_string();
                    vec![
                        base.join(format!("{name}.rs")),
                        base.join(&name).join("mod.rs"),
                    ]
                },
                |p| vec![if inline { base.join(p) } else { dir.join(p) }],
            );
            if let Some(hit) = candidates.iter().find(|c| c.is_file()) {
                let mod_rs = path_attr.is_some() || hit.file_name().is_some_and(|n| n == "mod.rs");
                if path_attr.is_some() {
                    self.path_attr_targets.insert(hit.clone());
                }
                self.visit(hit, mod_rs);
                continue;
            }
            self.unresolved.push(format!(
                "{}: `mod {}` (tried {candidates:?})",
                file.display(),
                m.ident
            ));
        }
    }
}

/// The value of a `#[path = "…"]` attribute, looking inside any nesting depth
/// of `#[cfg_attr(predicate, path = "…")]` (and `cfg_attr` nested inside
/// `cfg_attr`) for the same `path = "…"` meta.
///
/// Exposed for a scan's own fixture test to prove it resolves the same
/// retarget the real test-target walk above does, over a fixture file pair
/// that the walk itself never reaches (fixtures sit outside every `cargo
/// metadata` test target).
pub fn path_attr(attrs: &[syn::Attribute]) -> Option<String> {
    attrs.iter().find_map(|attr| path_meta(&attr.meta))
}

/// The value of a `path = "…"` meta, looking through any `cfg_attr` nesting.
fn path_meta(meta: &syn::Meta) -> Option<String> {
    match meta {
        syn::Meta::NameValue(nv) if nv.path.is_ident("path") => match &nv.value {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(s),
                ..
            }) => Some(s.value()),
            _ => None,
        },
        syn::Meta::List(list) if list.path.is_ident("cfg_attr") => {
            let nested = syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
                .parse2(list.tokens.clone())
                .ok()?;
            // The first element is the cfg predicate; the rest are the
            // attributes applied when it holds.
            nested.iter().skip(1).find_map(path_meta)
        }
        _ => None,
    }
}
