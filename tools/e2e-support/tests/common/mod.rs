//! Shared test-target enumeration for the workspace-wide source scans of the
//! `suite` harness (`skip_scan`, `target_scan`, `test_binaries`).
//!
//! Each scan walks every `cargo metadata` target of kind `test`, plus every
//! module file it declares via `mod`/`#[path]`, so it reaches exactly the
//! source the test binaries actually compile — not every `.rs` file under
//! `tests/`, which would also catch fixtures the scans must not parse as
//! live source.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

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
pub fn test_target_files_with_path_attrs() -> (PathBuf, BTreeSet<PathBuf>, BTreeSet<PathBuf>) {
    let workspace = metadata();
    let roots: Vec<PathBuf> = workspace
        .packages
        .iter()
        .flat_map(|p| p.test_roots.iter().map(|(_, root)| root.clone()))
        .collect();
    let root = workspace.root;
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
        set.iter().map(|f| relative(&root, f)).collect()
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

/// One workspace package as `cargo metadata` reports it.
pub struct Package {
    pub name: String,
    /// The directory holding the package's `Cargo.toml`, absolute.
    pub manifest_dir: PathBuf,
    /// Every target of kind `test`: its name and its absolute root file.
    pub test_roots: Vec<(String, PathBuf)>,
}

/// The workspace as `cargo metadata` reports it.
pub struct Workspace {
    pub root: PathBuf,
    pub packages: Vec<Package>,
}

/// One test target and the source files its module graph reaches, both
/// relative to the workspace root.
pub struct TestTarget {
    pub package: String,
    pub name: String,
    pub root: PathBuf,
    pub files: BTreeSet<PathBuf>,
}

/// The workspace's packages and every test target with its own module graph.
///
/// Each target is walked on its own, so a file reached by two targets
/// appears in both graphs: the ratchet that bounds the set of test binaries
/// must tell a shared module from a file that belongs to one target.
pub fn test_targets() -> (Workspace, Vec<TestTarget>) {
    let workspace = metadata();
    let mut targets = Vec::new();
    let mut unresolved = Vec::new();
    for package in &workspace.packages {
        for (name, root) in &package.test_roots {
            let mut walk = ModWalk::default();
            walk.visit(root, true);
            unresolved.append(&mut walk.unresolved);
            targets.push(TestTarget {
                package: package.name.clone(),
                name: name.clone(),
                root: relative(&workspace.root, &normalize(root)),
                files: walk
                    .seen
                    .iter()
                    .map(|f| relative(&workspace.root, f))
                    .collect(),
            });
        }
    }
    assert!(
        unresolved.is_empty(),
        "unresolvable `mod` declarations in test targets:\n{}",
        unresolved.join("\n")
    );
    (workspace, targets)
}

/// `path` relative to `root`, or `path` itself when it lies outside it.
fn relative(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root)
        .map_or_else(|_| path.to_path_buf(), Path::to_path_buf)
}

/// A string field of a `cargo metadata` JSON object.
#[allow(clippy::expect_used)] // metadata missing a documented field fails the scan: the designed outcome
fn field<'a>(value: &'a serde_json::Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .expect("`cargo metadata` prints every documented field")
}

/// The test targets of one `cargo metadata` package object.
fn test_roots(package: &serde_json::Value) -> Vec<(String, PathBuf)> {
    package
        .get("targets")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|t| {
            t.get("kind")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|k| k.iter().any(|k| k == "test"))
        })
        .map(|t| {
            (
                field(t, "name").to_owned(),
                PathBuf::from(field(t, "src_path")),
            )
        })
        .collect()
}

/// The workspace root and its packages, from `cargo metadata`.
#[allow(clippy::expect_used)] // an unreadable workspace manifest fails the scan: the designed outcome
fn metadata() -> Workspace {
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
    let packages = meta
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .expect("metadata lists the packages")
        .iter()
        .map(|p| Package {
            name: field(p, "name").to_owned(),
            manifest_dir: Path::new(field(p, "manifest_path"))
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_default(),
            test_roots: test_roots(p),
        })
        .collect();
    Workspace {
        root: PathBuf::from(field(&meta, "workspace_root")),
        packages,
    }
}

/// `path` with every `.` dropped and every `..` folded into its parent, so a
/// file reached as `suite/../common/mod.rs` and as `common/mod.rs` is one
/// file.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push(part);
                }
            }
            other => out.push(other),
        }
    }
    out
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
        let file = &normalize(file);
        if !self.seen.insert(file.clone()) {
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
                    self.path_attr_targets.insert(normalize(hit));
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
