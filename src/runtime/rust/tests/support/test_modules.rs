//! Which walked files only `#[cfg(test)]` code loads, shared by the `syn`
//! source scans that prune test code (`like_prefix_single_renderer.rs`,
//! `secret_debug_scan.rs`).
//!
//! An out-of-line `mod name;` keeps its `#[cfg(test)]` on the declaring item,
//! not in the file it loads, so a scan that prunes inline test modules must
//! resolve the declaration to drop the file too. A file is dropped only when a
//! test-only declaration names it and no production declaration, `include!`,
//! or crate-root role can; every shape the resolver does not model keeps the
//! file scanned, so a gap turns a scan red, never vacuously green.

use std::collections::BTreeSet;

use syn::visit::{self, Visit};
use syn::{Attribute, Expr, Item, ItemMod, Lit, Macro, Meta};

use super::cfg_scan::{cfg_test_only, item_attrs};

/// One out-of-line `mod name;` declaration.
#[derive(Debug, PartialEq, Eq)]
pub struct ModDecl {
    /// The inline `mod … { }` blocks enclosing the declaration, outermost first.
    pub inline: Vec<String>,
    pub name: String,
    /// The `#[path = "…"]` value, if any.
    pub path: Option<String>,
    /// Whether the declaration is `#[cfg(test)]`-only.
    pub test: bool,
}

/// One file's out-of-line module declarations and `include!` operands.
#[derive(Default)]
pub struct FileDecls {
    /// Every out-of-line `mod` declaration outside test-only code, plus each
    /// out-of-line `#[cfg(test)] mod` (an out-of-line `mod` inside a test-only
    /// inline module is not recorded, so its file stays scanned).
    pub mods: Vec<ModDecl>,
    /// Every literal `include!` / `include_str!` operand outside test-only code.
    includes: Vec<String>,
    /// The inline modules enclosing the visitor's position, outermost first.
    mod_stack: Vec<String>,
    /// How many enclosing inline modules carry a `#[path]`, which moves their
    /// children somewhere the `inline` chain does not name.
    pathed: usize,
}

impl FileDecls {
    fn declare(&mut self, module: &ItemMod, test: bool) {
        // A `cfg_attr` can carry a `path` the declaration then loads, and a
        // pathed inline parent moves the child: neither is modelled, so the
        // declaration counts as production and its candidates stay scanned.
        let opaque = self.pathed > 0 || module.attrs.iter().any(|a| a.path().is_ident("cfg_attr"));
        let test = test && !opaque;
        let mut paths: Vec<Option<String>> = vec![path_attr(&module.attrs)];
        if !test {
            paths.extend(cfg_attr_paths(&module.attrs).into_iter().map(Some));
        }
        for path in paths {
            self.mods.push(ModDecl {
                inline: self.mod_stack.clone(),
                name: module.ident.to_string(),
                path,
                test,
            });
        }
    }
}

/// The string literal of a `name = "…"` meta, if it is one.
fn name_value_str(meta: &Meta, name: &str) -> Option<String> {
    if let Meta::NameValue(nv) = meta
        && nv.path.is_ident(name)
        && let Expr::Lit(lit) = &nv.value
        && let Lit::Str(value) = &lit.lit
    {
        Some(value.value())
    } else {
        None
    }
}

/// The `#[path = "…"]` value among `attrs`, if any.
fn path_attr(attrs: &[Attribute]) -> Option<String> {
    attrs
        .iter()
        .find_map(|attr| name_value_str(&attr.meta, "path"))
}

/// Every `path = "…"` a `#[cfg_attr(…)]` among `attrs` can apply.
fn cfg_attr_paths(attrs: &[Attribute]) -> Vec<String> {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident("cfg_attr"))
        .filter_map(|attr| {
            attr.parse_args_with(
                syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
            )
            .ok()
        })
        .flat_map(|metas| {
            metas
                .iter()
                .filter_map(|meta| name_value_str(meta, "path"))
                .collect::<Vec<_>>()
        })
        .collect()
}

impl<'ast> Visit<'ast> for FileDecls {
    fn visit_item(&mut self, item: &'ast Item) {
        if cfg_test_only(item_attrs(item)) {
            if let Item::Mod(module) = item
                && module.content.is_none()
            {
                self.declare(module, true);
            }
            return;
        }
        visit::visit_item(self, item);
    }

    fn visit_item_mod(&mut self, module: &'ast ItemMod) {
        if module.content.is_none() {
            self.declare(module, false);
            return;
        }
        let pathed = path_attr(&module.attrs).is_some();
        self.mod_stack.push(module.ident.to_string());
        self.pathed = self.pathed.saturating_add(usize::from(pathed));
        visit::visit_item_mod(self, module);
        self.pathed = self.pathed.saturating_sub(usize::from(pathed));
        self.mod_stack.pop();
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        let include = mac
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == "include" || s.ident == "include_str");
        if include && let Ok(lit) = mac.parse_body::<syn::LitStr>() {
            self.includes.push(lit.value());
        }
        visit::visit_macro(self, mac);
    }
}

/// The out-of-line module declarations and `include!` operands of `file`.
pub fn file_decls(file: &syn::File) -> FileDecls {
    let mut decls = FileDecls::default();
    decls.visit_file(file);
    decls
}

/// `rel` under `dir`, with `.` and `..` components resolved lexically; a `..`
/// that climbs above the walked root is kept, so the result names no walked
/// file rather than a wrong one.
pub fn join(dir: &str, rel: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in dir.split('/').chain(rel.split('/')) {
        match part {
            "" | "." => {}
            ".." if parts.last().is_some_and(|p| *p != "..") => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    parts.join("/")
}

/// The directory part of `file`.
fn dir_of(file: &str) -> &str {
    file.rsplit_once('/').map_or("", |(dir, _)| dir)
}

/// The files `decl`, declared in `parent`, may load.
///
/// A file named `mod.rs` / `lib.rs` / `main.rs` owns its directory; any other
/// file owns the directory named after its stem, unless it was itself loaded
/// through `#[path]` or is a crate root, when it owns its own directory. Which
/// applies is not known per file, so `broad` yields both readings (the
/// production side, where a wider set keeps more files scanned) and the narrow
/// reading takes the stem rule only (the test side, where a wider set would
/// drop more).
pub fn child_files(parent: &str, decl: &ModDecl, broad: bool) -> Vec<String> {
    let (dir, file) = parent.rsplit_once('/').unwrap_or(("", parent));
    let stem = file.strip_suffix(".rs").unwrap_or(file);
    let mut owned = Vec::new();
    if matches!(stem, "mod" | "lib" | "main") {
        owned.push(dir.to_owned());
    } else {
        owned.push(join(dir, stem));
        if broad {
            owned.push(dir.to_owned());
        }
    }
    let inline = decl.inline.join("/");
    match (&decl.path, decl.inline.is_empty()) {
        (Some(path), true) => vec![join(dir, path)],
        (Some(path), false) => owned
            .iter()
            .map(|base| join(&join(base, &inline), path))
            .collect(),
        (None, _) => owned
            .iter()
            .flat_map(|base| {
                let base = join(base, &inline);
                [
                    join(&base, &format!("{}.rs", decl.name)),
                    join(&base, &format!("{}/mod.rs", decl.name)),
                ]
            })
            .collect(),
    }
}

/// Whether `file` can be a crate root, which no `mod` declaration names: a
/// `lib.rs` / `main.rs` / `build.rs`, a file under a `bin` directory, or a
/// top-level `mod.rs` (the runtime crate's `[lib] path`).
fn crate_root(file: &str) -> bool {
    let name = file.rsplit_once('/').map_or(file, |(_, name)| name);
    matches!(name, "lib.rs" | "main.rs" | "build.rs")
        || file == "mod.rs"
        || file.split('/').any(|part| part == "bin")
}

/// The walked files only `#[cfg(test)]` code loads: each named by a test-only
/// declaration (or by any declaration of a file that is itself test-only) and
/// by no production declaration, `include!` or crate-root role.
///
/// # Panics
///
/// When a source does not parse: its declarations cannot be read, so the scan
/// fails rather than guess.
#[allow(clippy::expect_used)] // an unparsable source must fail the scan, never be skipped
pub fn test_only_files(sources: &[(String, String)]) -> BTreeSet<String> {
    let decls: Vec<(&str, FileDecls)> = sources
        .iter()
        .map(|(name, src)| {
            let file = syn::parse_file(src).expect("a scanned source parses");
            (name.as_str(), file_decls(&file))
        })
        .collect();
    // Each round only grows the set (a test-only parent turns its children's
    // declarations test-only), so it settles within one round per file; a
    // round cap that is never reached returns the smaller, scanned-more set.
    let mut test_only: BTreeSet<String> = BTreeSet::new();
    for _ in 0..=sources.len() {
        let mut production: BTreeSet<String> = BTreeSet::new();
        let mut tested: BTreeSet<String> = BTreeSet::new();
        for (name, file) in &decls {
            let parent_test = test_only.contains(*name);
            for decl in &file.mods {
                if decl.test || parent_test {
                    tested.extend(child_files(name, decl, false));
                } else {
                    production.extend(child_files(name, decl, true));
                }
            }
            if !parent_test {
                production.extend(file.includes.iter().map(|inc| join(dir_of(name), inc)));
            }
        }
        let next: BTreeSet<String> = sources
            .iter()
            .map(|(name, _)| name)
            .filter(|name| {
                tested.contains(*name) && !production.contains(*name) && !crate_root(name)
            })
            .cloned()
            .collect();
        if next == test_only {
            return test_only;
        }
        test_only = next;
    }
    test_only
}

/// `sources` without the files only `#[cfg(test)]` code loads.
pub fn production_sources(sources: Vec<(String, String)>) -> Vec<(String, String)> {
    let test_only = test_only_files(&sources);
    sources
        .into_iter()
        .filter(|(name, _)| !test_only.contains(name))
        .collect()
}
