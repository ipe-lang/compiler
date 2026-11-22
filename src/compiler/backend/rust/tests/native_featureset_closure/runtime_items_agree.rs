//! The runtime-item table agrees with the runtime source it names.
//!
//! [`RuntimeItem`] is the one place the backend spells a feature-gated
//! `ipe_runtime::web::<item>` path and the features that item compiles under.
//! Two checks keep that table honest:
//!
//! 1. every row's [`RuntimeItem::requires`] holds under exactly the feature
//!    sets the runtime's own `#[cfg(..)]` gates compile the item under, and
//!    every feature-gated `web` item a backend string names is a row;
//! 2. no backend string outside the table names a row's item, so an emit site
//!    cannot reach a gated item past the assembly-time check.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ipe_backend_rust::runtime_items::RuntimeItem;

use crate::cfg::{Cfg, CfgEnv, Truth, attrs_cfg, top_level_mods};
use crate::rust_lex::{Tok, lex, test_only_item_end};

/// The path prefix every row names.
const WEB_PREFIX: &str = "ipe_runtime::web::";

/// The features a row's predicate ranges over; every subset is evaluated.
const ITEM_FEATURES: [&str; 4] = ["web-core", "db", "redis_store", "web"];

/// The backend source file that owns the table.
const TABLE_FILE: &str = "runtime_items.rs";

/// The predicate the runtime compiles its `web` module under: the join of
/// every `mod web` declaration in the crate root.
#[allow(clippy::expect_used)] // test scaffolding: the crate sources always parse
fn web_module_gate(crate_root: &Path) -> Cfg {
    let src = std::fs::read_to_string(crate_root.join("src").join("mod.rs"))
        .expect("read runtime src/mod.rs");
    let file = syn::parse_file(&src).expect("runtime src/mod.rs parses");
    let decls: Vec<Cfg> = top_level_mods(&file)
        .expect("runtime src/mod.rs module gates read")
        .into_iter()
        .filter(|(m, _)| m.ident == "web")
        .map(|(_, cfg)| cfg)
        .collect();
    assert!(!decls.is_empty(), "runtime src/mod.rs declares no `web`");
    Cfg::Any(decls)
}

/// The runtime's `web/mod.rs`, parsed.
#[allow(clippy::expect_used)] // test scaffolding: the crate sources always parse
fn web_module(crate_root: &Path) -> syn::File {
    let src = std::fs::read_to_string(crate_root.join("src").join("web").join("mod.rs"))
        .expect("read runtime src/web/mod.rs");
    syn::parse_file(&src).expect("runtime src/web/mod.rs parses")
}

/// Whether `tree` brings `name` into scope by name (a glob does not count).
fn use_tree_names(tree: &syn::UseTree, name: &str) -> bool {
    match tree {
        syn::UseTree::Path(path) => use_tree_names(&path.tree, name),
        syn::UseTree::Name(leaf) => leaf.ident == name,
        syn::UseTree::Rename(rename) => rename.rename == name,
        syn::UseTree::Glob(_) => false,
        syn::UseTree::Group(group) => group.items.iter().any(|t| use_tree_names(t, name)),
    }
}

/// The first path segment of a `use` tree: the submodule it reaches into.
fn use_tree_root(tree: &syn::UseTree) -> Option<String> {
    match tree {
        syn::UseTree::Path(path) => Some(path.ident.to_string()),
        _ => None,
    }
}

/// The predicate one attribute list gates its node under; no gate holds.
#[allow(clippy::panic)] // test scaffolding: a runtime gate the grammar cannot read is a broken fixture
fn gate_of(attrs: &[syn::Attribute], what: &str) -> Cfg {
    attrs_cfg(attrs)
        .unwrap_or_else(|e| panic!("the gate of `{what}` does not read: {e}"))
        .unwrap_or(Cfg::All(Vec::new()))
}

/// The predicate `web/mod.rs` compiles `web::<name>` under, when it declares
/// it as a public function or a named public re-export.
///
/// A re-export is gated by its own attributes and by the submodule it reaches
/// into.
fn web_item_gate(web: &syn::File, name: &str) -> Option<Cfg> {
    let submodule_gate = |sub: &str| {
        web.items.iter().find_map(|item| match item {
            syn::Item::Mod(m) if m.ident == sub => Some(gate_of(&m.attrs, sub)),
            _ => None,
        })
    };
    let public = |vis: &syn::Visibility| matches!(vis, syn::Visibility::Public(_));
    let gates: Vec<Cfg> = web
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(f) if public(&f.vis) && f.sig.ident == name => {
                Some(gate_of(&f.attrs, name))
            }
            syn::Item::Use(u) if public(&u.vis) && use_tree_names(&u.tree, name) => {
                let own = gate_of(&u.attrs, name);
                let sub = use_tree_root(&u.tree).and_then(|s| submodule_gate(&s));
                Some(Cfg::All(sub.into_iter().chain([own]).collect()))
            }
            _ => None,
        })
        .collect();
    (!gates.is_empty()).then_some(Cfg::Any(gates))
}

/// Whether `gate` keeps its item out of some native build: it does not hold
/// with no feature on.
fn is_gated(gate: &Cfg) -> bool {
    let bare = CfgEnv {
        features: BTreeSet::new(),
        wasm: false,
    };
    bare.eval(gate) != Truth::Holds
}

/// Every subset of [`ITEM_FEATURES`], as the selection the backend would pass.
fn feature_subsets() -> impl Iterator<Item = Vec<&'static str>> {
    (0u32..(1 << ITEM_FEATURES.len())).map(|mask| {
        ITEM_FEATURES
            .iter()
            .enumerate()
            .filter(|(bit, _)| mask & (1 << bit) != 0)
            .map(|(_, f)| *f)
            .collect()
    })
}

/// Each row's predicate holds exactly where the runtime compiles its item.
#[test]
#[allow(clippy::panic)] // test scaffolding: a row the runtime does not declare is the red
fn every_row_requires_what_the_runtime_gates_it_under() {
    let crate_root = e2e_support::require_runtime_crate();
    let module = web_module_gate(&crate_root);
    let web = web_module(&crate_root);
    let table = crate::load_fixtures().table;
    for item in RuntimeItem::ALL {
        let Some(name) = item.path().strip_prefix(WEB_PREFIX) else {
            panic!("row `{}` is not a `{WEB_PREFIX}` path", item.path());
        };
        let Some(own) = web_item_gate(&web, name) else {
            panic!("runtime web/mod.rs declares no public `{name}`");
        };
        let gate = Cfg::All(vec![module.clone(), own]);
        for selected in feature_subsets() {
            let resolved = crate::resolve_features(&selected, &table);
            let env = CfgEnv {
                features: resolved.clone(),
                wasm: false,
            };
            let names: BTreeSet<&str> = resolved.iter().map(String::as_str).collect();
            let runtime = env.eval(&gate);
            let table_says = item.requires().holds(&names);
            assert!(
                runtime != Truth::Varies,
                "`{}` varies with the host under {selected:?}",
                item.path()
            );
            assert_eq!(
                runtime == Truth::Holds,
                table_says,
                "`{}` requires `{}` in the table, but the runtime compiles it \
                 {} under {selected:?}",
                item.path(),
                item.requires(),
                if runtime == Truth::Holds { "in" } else { "out" },
            );
        }
    }
}

/// Every backend source file, test files and the table's own file excluded.
fn backend_sources() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![e2e_support::manifest_dir!().join("src")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                if name != "tests" {
                    stack.push(path);
                }
            } else if path.extension().is_some_and(|ext| ext == "rs")
                && name != TABLE_FILE
                && name != "tests.rs"
                && !name.ends_with("_tests.rs")
            {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Every string literal a non-test build of `src` compiles, with its line.
fn production_strings(src: &str) -> Vec<(usize, String)> {
    let toks = lex(src);
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some((line, tok)) = toks.get(i) {
        if let Some(end) = test_only_item_end(&toks, i) {
            i = end + 1;
            continue;
        }
        if let Tok::Str(text) = tok {
            out.push((*line, text.clone()));
        }
        i += 1;
    }
    out
}

/// Whether `word` occurs in `text` delimited by non-identifier characters.
fn names_word(text: &str, word: &str) -> bool {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(word).any(|(at, _)| {
        let before = text.get(..at).and_then(|s| s.chars().next_back());
        let after = text.get(at + word.len()..).and_then(|s| s.chars().next());
        !before.is_some_and(ident) && !after.is_some_and(ident)
    })
}

/// The leaf items `text` names under `ipe_runtime::web::`: an identifier
/// followed by `::` is a submodule, not an item.
fn named_web_items(text: &str) -> Vec<String> {
    text.match_indices(WEB_PREFIX)
        .filter_map(|(at, _)| {
            let rest = text.get(at + WEB_PREFIX.len()..)?;
            let len = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            let ident = rest.get(..len)?;
            let leaf = !rest.get(len..).is_some_and(|tail| tail.starts_with("::"));
            (leaf && !ident.is_empty()).then(|| ident.to_owned())
        })
        .collect()
}

/// Every feature-gated `web` item a backend string names is a table row, so
/// the assembly-time check sees every gated reach.
#[test]
#[allow(clippy::expect_used)] // test scaffolding: the backend sources always read
fn every_gated_web_item_the_backend_names_is_a_row() {
    let crate_root = e2e_support::require_runtime_crate();
    let web = web_module(&crate_root);
    let rows: BTreeSet<&str> = RuntimeItem::ALL
        .iter()
        .filter_map(|item| item.path().strip_prefix(WEB_PREFIX))
        .collect();
    let mut missing = Vec::new();
    let mut reaches = 0usize;
    for path in backend_sources() {
        let src = std::fs::read_to_string(&path).expect("read backend source");
        for (line, text) in production_strings(&src) {
            reaches += text.matches(WEB_PREFIX).count();
            for name in named_web_items(&text) {
                let gated = web_item_gate(&web, &name).is_some_and(|gate| is_gated(&gate));
                if gated && !rows.contains(name.as_str()) {
                    missing.push(format!("{}:{line}: `{WEB_PREFIX}{name}`", path.display()));
                }
            }
        }
    }
    assert!(
        reaches > 0,
        "the scan read no `{WEB_PREFIX}` string: the source walk is broken"
    );
    assert!(
        missing.is_empty(),
        "feature-gated runtime items the backend names outside the \
         `RuntimeItem` table:\n{}",
        missing.join("\n")
    );
}

/// No backend string outside the table names a row's item; the one exempt
/// shape is a vendored runtime-source fragment that opens with its own
/// `#[cfg(..)]`, which the module-set closure checks as runtime source.
#[test]
#[allow(clippy::expect_used)] // test scaffolding: the backend sources always read
fn no_backend_string_names_a_row_past_the_table() {
    let names: Vec<&str> = RuntimeItem::ALL
        .iter()
        .filter_map(|item| item.path().strip_prefix(WEB_PREFIX))
        .collect();
    let mut leaks = Vec::new();
    for path in backend_sources() {
        let src = std::fs::read_to_string(&path).expect("read backend source");
        for (line, text) in production_strings(&src) {
            if text.trim_start().starts_with("#[cfg(") {
                continue;
            }
            for name in names.iter().filter(|name| names_word(&text, name)) {
                leaks.push(format!("{}:{line}: `{name}`", path.display()));
            }
        }
    }
    assert!(
        leaks.is_empty(),
        "backend strings name a runtime item past `RuntimeItem::path`:\n{}",
        leaks.join("\n")
    );
}
