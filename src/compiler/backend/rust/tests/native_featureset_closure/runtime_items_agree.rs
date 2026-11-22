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

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ipe_backend_rust::runtime_items::RuntimeItem;

use crate::cfg::{Cfg, CfgEnv, Truth, attrs_cfg, top_level_mods};
use crate::rust_lex::{Tok, lex, test_only_item_end};

/// The path prefix every row names.
const WEB_PREFIX: &str = "ipe_runtime::web::";

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

/// The runtime's `web` module source: `web/mod.rs` and every file-backed
/// submodule it declares, parsed.
struct WebSource {
    root: syn::File,
    /// `web/<sub>.rs` (or `web/<sub>/mod.rs`) by submodule name.
    subs: BTreeMap<String, syn::File>,
}

impl WebSource {
    #[allow(clippy::expect_used, clippy::panic)] // test scaffolding: the crate sources always parse
    fn load(crate_root: &Path) -> Self {
        let dir = crate_root.join("src").join("web");
        let src = std::fs::read_to_string(dir.join("mod.rs")).expect("read runtime src/web/mod.rs");
        let root = syn::parse_file(&src).expect("runtime src/web/mod.rs parses");
        let mut subs = BTreeMap::new();
        for item in &root.items {
            let syn::Item::Mod(m) = item else { continue };
            if m.content.is_some() {
                continue;
            }
            let name = m.ident.to_string();
            let flat = dir.join(format!("{name}.rs"));
            let nested = dir.join(&name).join("mod.rs");
            let Some(text) = std::fs::read_to_string(&flat)
                .ok()
                .or_else(|| std::fs::read_to_string(&nested).ok())
            else {
                continue;
            };
            let file = syn::parse_file(&text)
                .unwrap_or_else(|e| panic!("runtime src/web/{name} does not parse: {e}"));
            subs.insert(name, file);
        }
        Self { root, subs }
    }

    /// The gate of the `mod <sub>` declaration in `web/mod.rs`.
    fn submodule_gate(&self, sub: &str) -> Option<Cfg> {
        self.root.items.iter().find_map(|item| match item {
            syn::Item::Mod(m) if m.ident == sub => Some(gate_of(&m.attrs, sub)),
            _ => None,
        })
    }

    /// The predicate `web::<segments>` compiles under, when the runtime
    /// declares it: a public item of `web/mod.rs`, a named or glob re-export
    /// of a submodule's item (gated by the re-export, the submodule and the
    /// definition), or `<sub>::<item>` inside a submodule.
    fn gate(&self, segments: &[&str]) -> Option<Cfg> {
        let (&name, rest) = segments.split_first()?;
        let mut gates = Vec::new();
        for item in &self.root.items {
            match item {
                syn::Item::Mod(m) if m.ident == name => {
                    let own = gate_of(&m.attrs, name);
                    match rest.first() {
                        None => gates.push(own),
                        Some(&inner) => {
                            let def = self.subs.get(name).and_then(|f| public_item_gate(f, inner));
                            if let Some(def) = def {
                                gates.push(Cfg::All(vec![own, def]));
                            }
                        }
                    }
                }
                syn::Item::Use(u) if public(&u.vis) && rest.is_empty() => {
                    let Some(reach) = use_tree_reaches(&u.tree, name) else {
                        continue;
                    };
                    let own = gate_of(&u.attrs, name);
                    let root = use_tree_root(&u.tree);
                    match root.as_deref().and_then(|r| self.subs.get_key_value(r)) {
                        // A re-export of a local submodule's item: the use,
                        // the `mod` declaration and the definition all gate
                        // it. A submodule that does not declare the name
                        // leaves it unresolved, which fails closed.
                        Some((sub, file)) => {
                            let Some(def) = public_item_gate(file, name) else {
                                continue;
                            };
                            let mut all = vec![own];
                            all.extend(self.submodule_gate(sub));
                            all.push(def);
                            gates.push(Cfg::All(all));
                        }
                        // A named re-export of a crate path
                        // (`crate::widget_assets`): its own gate here; the
                        // crate-level module closure owns the definition's.
                        // A crate-path glob stays unresolved.
                        None => {
                            if matches!(reach, Reach::Named) {
                                gates.push(own);
                            }
                        }
                    }
                }
                _ if rest.is_empty() && public_item_named(item, name) => {
                    gates.push(gate_of(item_attrs(item), name));
                }
                _ => {}
            }
        }
        (!gates.is_empty()).then_some(Cfg::Any(gates))
    }
}

/// How a `use` tree brings a name into scope.
#[derive(Clone, Copy)]
enum Reach {
    /// By name (`use sub::{name}`, `use sub::name as name`).
    Named,
    /// Through a glob (`use sub::*`), when the submodule declares it.
    Glob,
}

/// Whether `tree` brings `name` into scope, and how.
fn use_tree_reaches(tree: &syn::UseTree, name: &str) -> Option<Reach> {
    match tree {
        syn::UseTree::Path(path) => use_tree_reaches(&path.tree, name),
        syn::UseTree::Name(leaf) => (leaf.ident == name).then_some(Reach::Named),
        syn::UseTree::Rename(rename) => (rename.rename == name).then_some(Reach::Named),
        syn::UseTree::Glob(_) => Some(Reach::Glob),
        syn::UseTree::Group(group) => {
            let reaches: Vec<Reach> = group
                .items
                .iter()
                .filter_map(|t| use_tree_reaches(t, name))
                .collect();
            reaches
                .iter()
                .find(|r| matches!(r, Reach::Named))
                .or_else(|| reaches.first())
                .copied()
        }
    }
}

/// The first path segment of a `use` tree: the submodule it reaches into.
fn use_tree_root(tree: &syn::UseTree) -> Option<String> {
    match tree {
        syn::UseTree::Path(path) => Some(path.ident.to_string()),
        _ => None,
    }
}

const fn public(vis: &syn::Visibility) -> bool {
    matches!(vis, syn::Visibility::Public(_))
}

/// Whether `item` is a public declaration named `name`.
fn public_item_named(item: &syn::Item, name: &str) -> bool {
    match item {
        syn::Item::Fn(f) => public(&f.vis) && f.sig.ident == name,
        syn::Item::Struct(i) => public(&i.vis) && i.ident == name,
        syn::Item::Enum(i) => public(&i.vis) && i.ident == name,
        syn::Item::Const(i) => public(&i.vis) && i.ident == name,
        syn::Item::Static(i) => public(&i.vis) && i.ident == name,
        syn::Item::Type(i) => public(&i.vis) && i.ident == name,
        syn::Item::Trait(i) => public(&i.vis) && i.ident == name,
        syn::Item::Mod(i) => public(&i.vis) && i.ident == name,
        syn::Item::Use(u) => {
            public(&u.vis) && matches!(use_tree_reaches(&u.tree, name), Some(Reach::Named))
        }
        _ => false,
    }
}

/// The attributes of a declaration [`public_item_named`] recognises.
fn item_attrs(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Fn(i) => &i.attrs,
        syn::Item::Struct(i) => &i.attrs,
        syn::Item::Enum(i) => &i.attrs,
        syn::Item::Const(i) => &i.attrs,
        syn::Item::Static(i) => &i.attrs,
        syn::Item::Type(i) => &i.attrs,
        syn::Item::Trait(i) => &i.attrs,
        syn::Item::Mod(i) => &i.attrs,
        syn::Item::Use(u) => &u.attrs,
        _ => &[],
    }
}

/// The predicate a submodule file compiles its public `name` under: the
/// file's inner `#![cfg(..)]` joined with the declaration's own gate.
fn public_item_gate(file: &syn::File, name: &str) -> Option<Cfg> {
    let gates: Vec<Cfg> = file
        .items
        .iter()
        .filter(|item| public_item_named(item, name))
        .map(|item| {
            Cfg::All(vec![
                gate_of(&file.attrs, name),
                gate_of(item_attrs(item), name),
            ])
        })
        .collect();
    (!gates.is_empty()).then_some(Cfg::Any(gates))
}

/// The predicate one attribute list gates its node under; no gate holds.
#[allow(clippy::panic)] // test scaffolding: a runtime gate the grammar cannot read is a broken fixture
fn gate_of(attrs: &[syn::Attribute], what: &str) -> Cfg {
    attrs_cfg(attrs)
        .unwrap_or_else(|e| panic!("the gate of `{what}` does not read: {e}"))
        .unwrap_or(Cfg::All(Vec::new()))
}

/// Whether `gate` keeps its item out of some build: it does not hold with no
/// feature on, natively or on wasm.
fn is_gated(gate: &Cfg) -> bool {
    [false, true].into_iter().any(|wasm| {
        let bare = CfgEnv {
            features: BTreeSet::new(),
            wasm,
        };
        bare.eval(gate) != Truth::Holds
    })
}

/// Every cargo feature `cfg` names.
fn cfg_features(cfg: &Cfg, out: &mut BTreeSet<String>) {
    match cfg {
        Cfg::Feature(name) => {
            out.insert(name.clone());
        }
        Cfg::All(members) | Cfg::Any(members) => {
            for member in members {
                cfg_features(member, out);
            }
        }
        Cfg::Not(inner) => cfg_features(inner, out),
        Cfg::Test | Cfg::Wasm | Cfg::Host => {}
    }
}

/// Every subset of `features`, as the selection the backend would pass.
fn feature_subsets(features: &[String]) -> impl Iterator<Item = Vec<&str>> {
    let width = u32::try_from(features.len()).unwrap_or(u32::MAX);
    assert!(
        width < 16,
        "a row's gate names {width} features: too many to sweep"
    );
    (0u32..(1 << width)).map(move |mask| {
        features
            .iter()
            .enumerate()
            .filter(|(bit, _)| mask & (1 << bit) != 0)
            .map(|(_, f)| f.as_str())
            .collect()
    })
}

/// A row's path below [`WEB_PREFIX`], split at `::`.
#[allow(clippy::panic)] // test scaffolding: a row outside `web` is the red
fn row_segments(item: RuntimeItem) -> Vec<&'static str> {
    let Some(tail) = item.path().strip_prefix(WEB_PREFIX) else {
        panic!("row `{}` is not a `{WEB_PREFIX}` path", item.path());
    };
    tail.split("::").collect()
}

/// Each row's predicate holds exactly where the runtime compiles its item,
/// on the native and the wasm target alike, over every subset of the
/// features either side names.
#[test]
#[allow(clippy::panic)] // test scaffolding: a row the runtime does not declare is the red
fn every_row_requires_what_the_runtime_gates_it_under() {
    let crate_root = e2e_support::require_runtime_crate();
    let module = web_module_gate(&crate_root);
    let web = WebSource::load(&crate_root);
    let table = crate::load_fixtures().table;
    for item in RuntimeItem::ALL {
        let segments = row_segments(item);
        let Some(own) = web.gate(&segments) else {
            panic!("runtime web/ declares no public `{}`", segments.join("::"));
        };
        let gate = Cfg::All(vec![module.clone(), own]);
        let mut universe: BTreeSet<String> = item
            .requires()
            .features()
            .into_iter()
            .map(|f| f.as_str().to_owned())
            .collect();
        cfg_features(&gate, &mut universe);
        let universe: Vec<String> = universe.into_iter().collect();
        for selected in feature_subsets(&universe) {
            let resolved = crate::resolve_features(&selected, &table);
            let names: BTreeSet<&str> = resolved.iter().map(String::as_str).collect();
            let table_says = item.requires().holds(&names);
            for wasm in [false, true] {
                let env = CfgEnv {
                    features: resolved.clone(),
                    wasm,
                };
                let runtime = env.eval(&gate);
                assert!(
                    runtime != Truth::Varies,
                    "`{}` varies with the host under {selected:?}",
                    item.path()
                );
                assert_eq!(
                    runtime == Truth::Holds,
                    table_says,
                    "`{}` requires `{}` in the table, but the runtime compiles it \
                     {} under {selected:?} (wasm: {wasm})",
                    item.path(),
                    item.requires(),
                    if runtime == Truth::Holds { "in" } else { "out" },
                );
            }
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
///
/// A line of a literal that opens with `//` is dropped: it is a comment of a
/// vendored source fragment, which names a path without reaching it.
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
            let code: Vec<&str> = text
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect();
            out.push((*line, code.join("\n")));
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

/// Whether `c` continues a Rust identifier.
const fn ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The paths `text` names under `ipe_runtime::web::`, each split into at most
/// two segments: an item of `web`, a submodule followed by the item it names,
/// or a submodule alone when no identifier follows it (`install::{..}`). A
/// turbofish (`::<`) ends the path. An empty path is kept, so the scan
/// refuses it rather than skipping it.
fn named_web_items(text: &str) -> Vec<Vec<String>> {
    text.match_indices(WEB_PREFIX)
        .map(|(at, _)| {
            let mut rest = text.get(at + WEB_PREFIX.len()..).unwrap_or("");
            let mut segments = Vec::new();
            while segments.len() < 2 {
                let len = rest.find(|c: char| !ident_char(c)).unwrap_or(rest.len());
                let ident = rest.get(..len).unwrap_or("");
                if ident.is_empty() {
                    break;
                }
                segments.push(ident.to_owned());
                match rest.get(len..).and_then(|tail| tail.strip_prefix("::")) {
                    Some(next) if next.starts_with(|c: char| ident_char(c)) => rest = next,
                    _ => break,
                }
            }
            segments
        })
        .collect()
}

/// Every feature-gated `web` path a backend string names is a table row, so
/// the assembly-time check sees every gated reach. A path the runtime source
/// does not resolve is refused too: an unread gate is never taken as no gate.
#[test]
#[allow(clippy::expect_used)] // test scaffolding: the backend sources always read
fn every_gated_web_item_the_backend_names_is_a_row() {
    let crate_root = e2e_support::require_runtime_crate();
    let web = WebSource::load(&crate_root);
    let rows: BTreeSet<Vec<&str>> = RuntimeItem::ALL.into_iter().map(row_segments).collect();
    let mut missing = Vec::new();
    let mut reaches = 0usize;
    for path in backend_sources() {
        let src = std::fs::read_to_string(&path).expect("read backend source");
        for (line, text) in production_strings(&src) {
            for segments in named_web_items(&text) {
                reaches += 1;
                let named: Vec<&str> = segments.iter().map(String::as_str).collect();
                let shown = format!(
                    "{}:{line}: `{WEB_PREFIX}{}`",
                    path.display(),
                    named.join("::")
                );
                match web.gate(&named) {
                    None => missing.push(format!("{shown} (the runtime declares no such item)")),
                    Some(gate) if is_gated(&gate) && !rows.contains(&named) => missing.push(shown),
                    Some(_) => {}
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
        "feature-gated or unresolved runtime items the backend names outside \
         the `RuntimeItem` table:\n{}",
        missing.join("\n")
    );
}

/// No backend string outside the table names a row's item; the one exempt
/// shape is a vendored runtime-source fragment that opens with its own
/// `#[cfg(..)]`, which the module-set closure checks as runtime source.
#[test]
#[allow(clippy::expect_used)] // test scaffolding: the backend sources always read
fn no_backend_string_names_a_row_past_the_table() {
    let names: Vec<String> = RuntimeItem::ALL
        .into_iter()
        .map(|item| row_segments(item).join("::"))
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

/// The scan splits a reach into the segments it resolves: a gated submodule
/// named alone or through a group is kept as the submodule, a turbofish ends
/// the path, and an empty path stays visible so the scan refuses it.
#[test]
fn the_scan_keeps_every_reach_it_cannot_skip() {
    let seg = |text: &str| named_web_items(text);
    assert_eq!(
        seg("ipe_runtime::web::install::register(&F)"),
        vec![vec!["install", "register"]]
    );
    assert_eq!(
        seg("use ipe_runtime::web::install::{InstallFacts};"),
        vec![vec!["install"]]
    );
    assert_eq!(
        seg("ipe_runtime::web::sub_every_hot::<Msg>(d)"),
        vec![vec!["sub_every_hot"]]
    );
    assert_eq!(seg("ipe_runtime::web::{a, b}"), vec![Vec::<String>::new()]);
    assert!(
        production_strings("const X: &str = \"\\n// ipe_runtime::web::install::register\\n\";")
            .iter()
            .all(|(_, text)| named_web_items(text).is_empty()),
        "a vendored comment line names no reach"
    );
    assert!(
        production_strings("const X: &str = \"\\nipe_runtime::web::install::register\\n\";")
            .iter()
            .any(|(_, text)| !named_web_items(text).is_empty()),
        "a vendored code line still names its reach"
    );
}

/// The resolver reads gates through a submodule path, a crate-path re-export
/// inside a submodule, and the definition; a name the runtime does not
/// declare resolves to nothing, which the scan refuses.
#[test]
#[allow(clippy::panic)] // test scaffolding: a missing fixture item is the red
fn the_resolver_reads_submodule_gates_and_refuses_unknown_names() {
    let web = WebSource::load(&e2e_support::require_runtime_crate());
    let gate = |path: &[&str]| {
        web.gate(path)
            .unwrap_or_else(|| panic!("runtime web/ declares no `{}`", path.join("::")))
    };
    assert!(
        is_gated(&gate(&["install", "register"])),
        "`web::install` is gated by `web`"
    );
    assert!(
        is_gated(&gate(&["install"])),
        "`web::install` is gated by `web`"
    );
    assert!(
        !is_gated(&gate(&["route", "Route"])),
        "`web::route` compiles in web-core"
    );
    assert!(
        !is_gated(&gate(&["route", "RenderRefusal"])),
        "a crate-path re-export inside a submodule resolves"
    );
    assert!(
        is_gated(&gate(&["apply_init_hot"])),
        "the hot readers are gated"
    );
    assert!(web.gate(&["install", "no_such_item"]).is_none());
    assert!(web.gate(&["no_such_item"]).is_none());
}
