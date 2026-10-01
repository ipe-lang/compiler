//! Every wasm32 test the runtime declares sits in a cell `test-claims.yml` claims.
//!
//! The scan walks the module tree of the library and of every integration
//! test target with a tri-state `cfg` evaluator, so a test a wasm32 build
//! would compile is found where it is declared. It enforces four rules:
//!
//! - (a) no plain `#[test]` is compiled only for wasm32 (it would run nowhere),
//!   and no plain `#[test]` enters a claimed wasm32 cell;
//! - (b) each claimed cell holds exactly its `expect_tests` count of
//!   `#[wasm_bindgen_test]` functions, and that count is above zero;
//! - (c) the wasm32 library test binary admits test-only code from
//!   `src/wasm/` alone, so it never needs a native-only dev-dependency;
//! - (d) every `#[wasm_bindgen_test]` a wasm32 build of any feature set could
//!   compile runs in some claimed cell of its target.
//!
//! An unknown `cfg` predicate, a `#[path]` module it cannot follow, a `mod`
//! with no file, an item `syn` cannot parse, and a module tree past its file or
//! depth limit are refusals. A macro invocation is refused when its literal
//! tokens name `wasm_bindgen_test` or hold a test-harness attribute; the scan
//! does not expand macros, so a test a macro assembles from other tokens is
//! seen only through a claimed cell's count, which the runner's executed count
//! must match.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::path::{Path, PathBuf};

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use syn::punctuated::Punctuated;
use syn::visit::Visit;
use syn::{Attribute, Expr, ExprLit, Item, Lit, Meta, Token};

/// The target triple every claimed cell must name.
const WASM_TRIPLE: &str = "wasm32-unknown-unknown";

/// The most module files one target's walk reads before it fails.
const MAX_MODULE_FILES: usize = 4096;

/// The deepest chain of module files (`mod` and `include!`) one walk follows.
const MAX_MODULE_DEPTH: usize = 64;

/// The claim table, relative to this crate's manifest directory.
const CLAIMS_PATH: &str = "../../../.github/ci/test-claims.yml";

/// The fixtures that drive the scan's refusals.
const FIXTURE_DIR: &str = "tests/fixtures/wasm_cell_scan";

/// A `cfg` predicate's value when some configuration facts are unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tri {
    True,
    False,
    Unknown,
}

impl Tri {
    /// The known value `value`.
    const fn of(value: bool) -> Self {
        if value { Self::True } else { Self::False }
    }

    /// Conjunction: false wins over unknown.
    const fn both(self, other: Self) -> Self {
        match (self, other) {
            (Self::False, _) | (_, Self::False) => Self::False,
            (Self::True, Self::True) => Self::True,
            _ => Self::Unknown,
        }
    }

    /// Disjunction: true wins over unknown.
    const fn either(self, other: Self) -> Self {
        match (self, other) {
            (Self::True, _) | (_, Self::True) => Self::True,
            (Self::False, Self::False) => Self::False,
            _ => Self::Unknown,
        }
    }

    /// Negation: unknown stays unknown.
    const fn negate(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }
}

/// The architecture a `cfg` predicate is evaluated for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arch {
    /// `wasm32-unknown-unknown`, whose target facts are all known.
    Wasm32,
    /// Any host triple, whose target facts other than "not wasm" are unknown.
    Native,
}

/// The configuration a `cfg` predicate is evaluated against.
#[derive(Clone, Copy, Debug)]
struct CfgEnv<'a> {
    arch: Arch,
    /// The enabled features, or `None` when any feature set is possible.
    features: Option<&'a BTreeSet<String>>,
    test: bool,
}

impl CfgEnv<'_> {
    /// The same configuration with `test` set to `test`.
    const fn with_test(self, test: bool) -> Self {
        Self { test, ..self }
    }
}

/// A fact the wasm32 triple fixes.
///
/// Exact on wasm32; on a native host false for the wasm value and unknown for
/// every other value.
const fn wasm_fact(arch: Arch, names_wasm: bool) -> Tri {
    match arch {
        Arch::Wasm32 => Tri::of(names_wasm),
        Arch::Native if names_wasm => Tri::False,
        Arch::Native => Tri::Unknown,
    }
}

/// `path` as written, `::`-joined.
fn path_text(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

/// The final segment of `path`.
fn last_segment(path: &syn::Path) -> String {
    path.segments
        .last()
        .map_or_else(String::new, |segment| segment.ident.to_string())
}

/// The string literal `expr` holds, if it is one.
fn string_value(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Lit(ExprLit {
            lit: Lit::Str(text),
            ..
        }) => Some(text.value()),
        _ => None,
    }
}

/// The members of a `cfg` list predicate such as `all(…)`.
fn cfg_members(list: &syn::MetaList) -> Result<Vec<Meta>, String> {
    list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
        .map(|members| members.into_iter().collect())
        .map_err(|error| {
            format!(
                "unparsable `{}(…)` arguments: {error}",
                path_text(&list.path)
            )
        })
}

/// The value of `predicate` under `env`, or why it cannot be evaluated.
fn eval(predicate: &Meta, env: CfgEnv<'_>) -> Result<Tri, String> {
    match predicate {
        Meta::Path(path) if path.is_ident("test") => Ok(Tri::of(env.test)),
        Meta::Path(path) if path.is_ident("unix") || path.is_ident("windows") => {
            Ok(wasm_fact(env.arch, false))
        }
        Meta::Path(path) => Err(format!("unknown cfg predicate `{}`", path_text(path))),
        Meta::List(list) => {
            let members = cfg_members(list)?;
            if list.path.is_ident("all") {
                members.iter().try_fold(Tri::True, |acc, member| {
                    eval(member, env).map(|v| acc.both(v))
                })
            } else if list.path.is_ident("any") {
                members.iter().try_fold(Tri::False, |acc, member| {
                    eval(member, env).map(|v| acc.either(v))
                })
            } else if list.path.is_ident("not") {
                match members.as_slice() {
                    [only] => eval(only, env).map(Tri::negate),
                    _ => Err("`not(…)` takes exactly one predicate".to_owned()),
                }
            } else {
                Err(format!(
                    "unknown cfg predicate `{}(…)`",
                    path_text(&list.path)
                ))
            }
        }
        Meta::NameValue(pair) => {
            let key = path_text(&pair.path);
            let value = string_value(&pair.value)
                .ok_or_else(|| format!("cfg `{key} = …` does not name a string"))?;
            match key.as_str() {
                "feature" => Ok(env
                    .features
                    .map_or(Tri::Unknown, |enabled| Tri::of(enabled.contains(&value)))),
                "target_arch" => Ok(wasm_fact(env.arch, value == "wasm32")),
                "target_family" => Ok(wasm_fact(env.arch, value == "wasm")),
                "target_os" => Ok(match env.arch {
                    Arch::Wasm32 => Tri::of(value == "unknown"),
                    Arch::Native => Tri::Unknown,
                }),
                _ => Err(format!("unknown cfg predicate `{key} = \"{value}\"`")),
            }
        }
    }
}

/// The value of the conjunction `chain` under `env`.
fn eval_chain(chain: &[Meta], env: CfgEnv<'_>) -> Result<Tri, String> {
    chain.iter().try_fold(Tri::True, |acc, predicate| {
        eval(predicate, env).map(|v| acc.both(v))
    })
}

/// The `#[cfg(…)]` predicates among `attrs`, inner and outer alike.
fn cfg_predicates(attrs: &[Attribute]) -> Result<Vec<Meta>, String> {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident("cfg"))
        .map(|attr| {
            attr.parse_args::<Meta>()
                .map_err(|error| format!("unparsable `#[cfg(…)]`: {error}"))
        })
        .collect()
}

/// The kind of test an attribute named `name` declares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestAttr {
    /// `#[wasm_bindgen_test]`: runs under `wasm-bindgen-test-runner`.
    WasmBindgen,
    /// `#[test]`, `#[tokio::test]`, or any other `…test…` harness attribute.
    Plain,
}

/// The test kind an attribute's final path segment `name` declares.
fn test_attr(name: &str) -> Option<TestAttr> {
    if name == "wasm_bindgen_test" {
        Some(TestAttr::WasmBindgen)
    } else if name.contains("test") {
        Some(TestAttr::Plain)
    } else {
        None
    }
}

/// Whether an attribute named `name` changes what the walk reads or counts.
fn walk_changing_attr(name: &str) -> bool {
    matches!(name, "path" | "cfg" | "cfg_attr" | "ignore") || test_attr(name).is_some()
}

/// Why a `#[cfg_attr(…)]` may not be admitted, if it may not.
///
/// A conditional attribute that adds a `cfg`, a `path`, an `ignore`, or a test
/// harness would change what the walk reads or counts in a way the walk does
/// not model, so it is refused.
fn cfg_attr_refusal(attr: &Attribute) -> Option<String> {
    let members = match &attr.meta {
        Meta::List(list) => match cfg_members(list) {
            Ok(members) => members,
            Err(why) => return Some(why),
        },
        _ => return Some("`cfg_attr` without arguments".to_owned()),
    };
    members
        .iter()
        .skip(1)
        .map(|added| last_segment(added.path()))
        .find(|name| walk_changing_attr(name))
        .map(|name| {
            format!("`#[cfg_attr(…, {name}…)]` conditionally adds an attribute the scan must see")
        })
}

/// Whether the leading path of an attribute's tokens names a test harness.
fn attr_tokens_declare_test(tokens: TokenStream) -> bool {
    let mut trees = tokens.into_iter();
    let mut name = String::new();
    let mut rest = TokenStream::new();
    for tree in trees.by_ref() {
        match tree {
            TokenTree::Ident(ident) => name = ident.to_string(),
            TokenTree::Punct(punct) if punct.as_char() == ':' => {}
            TokenTree::Group(group) => {
                rest = group.stream();
                break;
            }
            _ => break,
        }
    }
    if name == "cfg_attr" {
        let added: Vec<TokenTree> = rest
            .into_iter()
            .skip_while(|tree| !matches!(tree, TokenTree::Punct(p) if p.as_char() == ','))
            .collect();
        return added.iter().any(|tree| match tree {
            TokenTree::Ident(ident) => walk_changing_attr(&ident.to_string()),
            TokenTree::Group(group) => tokens_hold_test(group.stream()),
            _ => false,
        });
    }
    test_attr(&name).is_some()
}

/// Whether macro `tokens` could expand to a test.
///
/// True when they name `wasm_bindgen_test` anywhere or hold a `#[…]`
/// attribute whose path names a test harness.
fn tokens_hold_test(tokens: TokenStream) -> bool {
    let mut after_pound = false;
    for tree in tokens {
        match tree {
            TokenTree::Ident(ident) => {
                if ident == "wasm_bindgen_test" {
                    return true;
                }
                after_pound = false;
            }
            TokenTree::Punct(punct) => {
                after_pound = punct.as_char() == '#' || (after_pound && punct.as_char() == '!');
            }
            TokenTree::Group(group) => {
                if after_pound
                    && group.delimiter() == Delimiter::Bracket
                    && attr_tokens_declare_test(group.stream())
                {
                    return true;
                }
                if tokens_hold_test(group.stream()) {
                    return true;
                }
                after_pound = false;
            }
            TokenTree::Literal(_) => after_pound = false,
        }
    }
    false
}

/// Whether `mac` is `wasm_bindgen_test_configure!`, the one test-harness macro admitted.
fn is_configure(mac: &syn::Macro) -> bool {
    last_segment(&mac.path) == "wasm_bindgen_test_configure"
}

/// Collects every test declared where the module walk does not count it.
///
/// That is a test attribute nested inside a body or on a non-`fn` item, or a
/// macro that could expand to one.
#[derive(Default)]
struct HiddenTests {
    found: Vec<String>,
}

impl<'ast> Visit<'ast> for HiddenTests {
    fn visit_attribute(&mut self, attr: &'ast Attribute) {
        let name = last_segment(attr.path());
        if test_attr(&name).is_some() {
            self.found.push(format!(
                "`#[{name}]` nested where the walk does not count it"
            ));
        } else if name == "cfg_attr"
            && let Some(why) = cfg_attr_refusal(attr)
        {
            self.found.push(why);
        }
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if !is_configure(mac) && tokens_hold_test(mac.tokens.clone()) {
            self.found.push(format!(
                "`{}!` could expand to a test the walk does not count",
                path_text(&mac.path)
            ));
        }
    }
}

/// The attributes of `item`, or `None` for an item `syn` could not parse.
fn item_attrs(item: &Item) -> Option<&[Attribute]> {
    match item {
        Item::Const(i) => Some(&i.attrs),
        Item::Enum(i) => Some(&i.attrs),
        Item::ExternCrate(i) => Some(&i.attrs),
        Item::Fn(i) => Some(&i.attrs),
        Item::ForeignMod(i) => Some(&i.attrs),
        Item::Impl(i) => Some(&i.attrs),
        Item::Macro(i) => Some(&i.attrs),
        Item::Mod(i) => Some(&i.attrs),
        Item::Static(i) => Some(&i.attrs),
        Item::Struct(i) => Some(&i.attrs),
        Item::Trait(i) => Some(&i.attrs),
        Item::TraitAlias(i) => Some(&i.attrs),
        Item::Type(i) => Some(&i.attrs),
        Item::Union(i) => Some(&i.attrs),
        Item::Use(i) => Some(&i.attrs),
        _ => None,
    }
}

/// A short name for `item` in a refusal.
fn item_label(item: &Item) -> String {
    match item {
        Item::Fn(i) => format!("fn `{}`", i.sig.ident),
        Item::Mod(i) => format!("mod `{}`", i.ident),
        Item::Macro(i) => format!("macro `{}!`", path_text(&i.mac.path)),
        Item::Const(i) => format!("const `{}`", i.ident),
        Item::Static(i) => format!("static `{}`", i.ident),
        Item::Struct(i) => format!("struct `{}`", i.ident),
        Item::Enum(i) => format!("enum `{}`", i.ident),
        Item::Trait(i) => format!("trait `{}`", i.ident),
        Item::Type(i) => format!("type `{}`", i.ident),
        Item::Impl(_) => "impl block".to_owned(),
        Item::Use(_) => "use".to_owned(),
        _ => "item".to_owned(),
    }
}

/// Whether `path` is a regular file (a symbolic link is not).
fn plain_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file())
}

/// Which rules one walk enforces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Every target a wasm32 build could compile, under any feature set.
    Discover,
    /// One claimed cell, whose configuration is fully known.
    Cell {
        /// Whether the cell is the library's, where rule (c) applies.
        lib: bool,
    },
}

/// What one target's walk found.
#[derive(Debug, Default)]
struct Findings {
    /// `#[wasm_bindgen_test]` functions admitted: definitely in a cell,
    /// possibly in discovery.
    wasm_tests: usize,
    /// The identity of each admitted `#[wasm_bindgen_test]`: its declaring
    /// file and its item path, each segment tagged with its item ordinal.
    wasm_test_ids: BTreeSet<String>,
    refusals: Vec<String>,
}

/// Where a list of items is declared.
#[derive(Clone, Copy)]
struct Place<'p> {
    /// The declaring file, relative to the walk's base.
    rel: &'p str,
    /// The declaring file's directory, which `#[path]` and `include!` resolve against.
    file_dir: &'p Path,
    /// The directory the items' `mod name;` declarations resolve against.
    dir: &'p Path,
    /// Whether the items sit inside an inline `mod { … }`.
    inline: bool,
    /// The item path of the items' module, each segment tagged with its ordinal.
    module: &'p str,
}

/// The path an `include!` names, or why it names none.
fn literal_path(parsed: syn::Result<syn::LitStr>) -> Result<String, &'static str> {
    parsed
        .map(|literal| literal.value())
        .map_err(|_| "`include!` does not name a string literal")
}

/// One target's module walk.
struct Walk<'a> {
    mode: Mode,
    /// The wasm32 configuration the walk prunes by.
    wasm: CfgEnv<'a>,
    /// The native configuration rule (a) compares against in discovery.
    native: CfgEnv<'a>,
    /// Paths in refusals are shown relative to this directory.
    base: &'a Path,
    module_files: usize,
    /// How many module files deep the walk currently is.
    depth: usize,
    found: Findings,
}

impl<'a> Walk<'a> {
    /// A walk in `mode` under `wasm`, showing paths relative to `base`.
    fn new(mode: Mode, wasm: CfgEnv<'a>, base: &'a Path) -> Self {
        Self {
            mode,
            wasm,
            native: CfgEnv {
                arch: Arch::Native,
                features: None,
                test: true,
            },
            base,
            module_files: 0,
            depth: 0,
            found: Findings::default(),
        }
    }

    /// Record a refusal at `at`.
    fn refuse(&mut self, at: &str, why: impl Display) {
        self.found.refusals.push(format!("{at}: {why}"));
    }

    /// `path` relative to the walk's base, `/`-separated.
    fn relative(&self, path: &Path) -> String {
        path.strip_prefix(self.base)
            .unwrap_or(path)
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/")
    }

    /// `chain` extended by the `cfg`s of `attrs`, or `None` when the walk does
    /// not descend.
    ///
    /// The walk does not descend when wasm32 prunes the node, and records a
    /// refusal instead when the node breaks a rule.
    fn admit(
        &mut self,
        rel: &str,
        at: &str,
        chain: &[Meta],
        attrs: &[Attribute],
    ) -> Option<Vec<Meta>> {
        for attr in attrs.iter().filter(|attr| attr.path().is_ident("cfg_attr")) {
            if let Some(why) = cfg_attr_refusal(attr) {
                self.refuse(at, why);
            }
        }
        let own = match cfg_predicates(attrs) {
            Ok(own) => own,
            Err(why) => {
                self.refuse(at, why);
                return None;
            }
        };
        let mut next = chain.to_vec();
        next.extend(own);
        let reached = match eval_chain(&next, self.wasm) {
            Ok(Tri::False) => return None,
            Ok(Tri::Unknown) if matches!(self.mode, Mode::Cell { .. }) => {
                self.refuse(at, "`cfg` is undecided under the cell's configuration");
                return None;
            }
            Ok(_) => next,
            Err(why) => {
                self.refuse(at, why);
                return None;
            }
        };
        if matches!(self.mode, Mode::Cell { lib: true })
            && !rel.starts_with("src/wasm/")
            && matches!(
                eval_chain(&reached, self.wasm.with_test(false)),
                Ok(Tri::False)
            )
        {
            self.refuse(
                at,
                "test-only code outside `src/wasm/` enters the wasm32 library test binary; \
                 gate it `not(target_arch = \"wasm32\")`",
            );
            return None;
        }
        Some(reached)
    }

    /// Walk the module file `file`, whose child modules live in `dir`.
    ///
    /// `inline` is whether `file` is `include!`d inside an inline `mod { … }`,
    /// where a `#[path]` resolves by rules the walk does not model; `module` is
    /// the item path its items are declared at.
    fn walk_file(&mut self, file: &Path, dir: &Path, inline: bool, module: &str, chain: &[Meta]) {
        let rel = self.relative(file);
        self.module_files = self.module_files.saturating_add(1);
        if self.module_files > MAX_MODULE_FILES {
            self.refuse(&rel, format!("more than {MAX_MODULE_FILES} module files"));
            return;
        }
        if self.depth >= MAX_MODULE_DEPTH {
            self.refuse(
                &rel,
                format!("module files nested more than {MAX_MODULE_DEPTH} deep"),
            );
            return;
        }
        self.depth = self.depth.saturating_add(1);
        self.read_module_file(file, &rel, dir, inline, module, chain);
        self.depth = self.depth.saturating_sub(1);
    }

    /// Parse and walk the module file `file`, shown as `rel`.
    fn read_module_file(
        &mut self,
        file: &Path,
        rel: &str,
        dir: &Path,
        inline: bool,
        module: &str,
        chain: &[Meta],
    ) {
        let parsed = match std::fs::read_to_string(file) {
            Ok(source) => syn::parse_file(&source).map_err(|error| error.to_string()),
            Err(error) => Err(error.to_string()),
        };
        let parsed = match parsed {
            Ok(parsed) => parsed,
            Err(why) => {
                self.refuse(rel, format!("unreadable module: {why}"));
                return;
            }
        };
        let Some(chain) = self.admit(rel, rel, chain, &parsed.attrs) else {
            return;
        };
        let file_dir = file.parent().map_or_else(PathBuf::new, Path::to_path_buf);
        let place = Place {
            rel,
            file_dir: &file_dir,
            dir,
            inline,
            module,
        };
        self.walk_items(&place, &parsed.items, &chain);
    }

    /// Walk `items` declared at `place`.
    fn walk_items(&mut self, place: &Place<'_>, items: &[Item], chain: &[Meta]) {
        for (ordinal, item) in items.iter().enumerate() {
            let at = format!("{}: {}", place.rel, item_label(item));
            let Some(attrs) = item_attrs(item) else {
                self.refuse(&at, "an item `syn` could not parse");
                continue;
            };
            let Some(item_chain) = self.admit(place.rel, &at, chain, attrs) else {
                continue;
            };
            match item {
                Item::Mod(module) => {
                    let path = format!("{}::{}[{ordinal}]", place.module, module.ident);
                    self.walk_mod(place, &at, &path, module, &item_chain);
                }
                Item::Fn(function) => {
                    let id = format!(
                        "{}: {}::{}[{ordinal}]",
                        place.rel, place.module, function.sig.ident
                    );
                    self.check_fn(&at, id, function, &item_chain);
                }
                Item::Macro(mac) if mac.mac.path.is_ident("include") => {
                    match literal_path(mac.mac.parse_body::<syn::LitStr>()) {
                        Ok(path) => {
                            let file = place.file_dir.join(path);
                            let module = format!("{}::include[{ordinal}]", place.module);
                            if plain_file(&file) {
                                self.walk_file(
                                    &file,
                                    place.dir,
                                    place.inline,
                                    &module,
                                    &item_chain,
                                );
                            } else {
                                self.refuse(&at, "`include!` names no regular file");
                            }
                        }
                        Err(why) => self.refuse(&at, why),
                    }
                }
                other => {
                    let mut hidden = HiddenTests::default();
                    hidden.visit_item(other);
                    for why in hidden.found {
                        self.refuse(&at, why);
                    }
                }
            }
        }
    }

    /// Walk the reached module `module` declared at `place`, whose item path is `path`.
    ///
    /// A `#[path]` outside an inline module resolves against the declaring
    /// file's directory, and the file it names is a `mod.rs`-style module whose
    /// children live beside it.
    fn walk_mod(
        &mut self,
        place: &Place<'_>,
        at: &str,
        path: &str,
        module: &syn::ItemMod,
        chain: &[Meta],
    ) {
        let name = module.ident.to_string();
        let child_dir = place.dir.join(&name);
        let path_attrs: Vec<&Attribute> = module
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("path"))
            .collect();
        if let Some((_, items)) = &module.content {
            if !path_attrs.is_empty() {
                self.refuse(at, "a `#[path]` on an inline module is not modelled");
                return;
            }
            let inner = Place {
                dir: &child_dir,
                inline: true,
                module: path,
                ..*place
            };
            self.walk_items(&inner, items, chain);
            return;
        }
        match path_attrs.as_slice() {
            [] => {}
            [attr] => {
                if place.inline {
                    self.refuse(at, "a `#[path]` inside an inline module is not modelled");
                    return;
                }
                let value = match &attr.meta {
                    Meta::NameValue(pair) => string_value(&pair.value),
                    _ => None,
                };
                let Some(value) = value else {
                    self.refuse(at, "`#[path]` does not name a string");
                    return;
                };
                let file = place.file_dir.join(value);
                if plain_file(&file) {
                    let dir = file.parent().map_or_else(PathBuf::new, Path::to_path_buf);
                    self.walk_file(&file, &dir, false, path, chain);
                } else {
                    self.refuse(at, "`#[path]` names no regular file");
                }
                return;
            }
            _ => {
                self.refuse(at, "more than one `#[path]`");
                return;
            }
        }
        let flat = place.dir.join(format!("{name}.rs"));
        let nested = child_dir.join("mod.rs");
        match (plain_file(&flat), plain_file(&nested)) {
            (true, false) => self.walk_file(&flat, &child_dir, false, path, chain),
            (false, true) => self.walk_file(&nested, &child_dir, false, path, chain),
            (true, true) => self.refuse(at, format!("both `{name}.rs` and `{name}/mod.rs` exist")),
            (false, false) => self.refuse(at, format!("no regular file for `mod {name};`")),
        }
    }

    /// Classify the reached function `function` and count it, as `id`, if it is a wasm test.
    fn check_fn(&mut self, at: &str, id: String, function: &syn::ItemFn, chain: &[Meta]) {
        let mut wasm_tests = 0usize;
        for attr in &function.attrs {
            match test_attr(&last_segment(attr.path())) {
                Some(TestAttr::WasmBindgen) => {
                    wasm_tests = wasm_tests.saturating_add(1);
                    if !matches!(attr.meta, Meta::Path(_)) && matches!(self.mode, Mode::Cell { .. })
                    {
                        self.refuse(
                            at,
                            "`#[wasm_bindgen_test(…)]` arguments change where it runs",
                        );
                    }
                }
                Some(TestAttr::Plain) => self.check_plain_test(at, attr, chain),
                None => {}
            }
        }
        if wasm_tests > 1 {
            self.refuse(at, "`#[wasm_bindgen_test]` written more than once");
        }
        if wasm_tests > 0 {
            if matches!(self.mode, Mode::Cell { .. })
                && function.attrs.iter().any(|attr| {
                    attr.path().is_ident("ignore") || attr.path().is_ident("should_panic")
                })
            {
                self.refuse(
                    at,
                    "an `#[ignore]` or `#[should_panic]` wasm test does not run as counted",
                );
            }
            self.found.wasm_tests = self.found.wasm_tests.saturating_add(1);
            self.found.wasm_test_ids.insert(id);
        }
        let mut hidden = HiddenTests::default();
        hidden.visit_block(&function.block);
        for why in hidden.found {
            self.refuse(at, why);
        }
    }

    /// Rule (a) for a reached plain test attribute `attr`.
    fn check_plain_test(&mut self, at: &str, attr: &Attribute, chain: &[Meta]) {
        let name = path_text(attr.path());
        match self.mode {
            Mode::Cell { .. } => self.refuse(
                at,
                format!("`#[{name}]` in a wasm32 cell never runs under the wasm runner; write `#[wasm_bindgen_test]`"),
            ),
            Mode::Discover => match eval_chain(chain, self.native) {
                Ok(Tri::False) => self.refuse(
                    at,
                    format!("`#[{name}]` compiled only for wasm32 runs in no job; write `#[wasm_bindgen_test]`"),
                ),
                Ok(_) => {}
                Err(why) => self.refuse(at, why),
            },
        }
    }
}

/// Walk the target root `root` in `mode` under `wasm`.
fn scan_target(root: &Path, mode: Mode, wasm: CfgEnv<'_>, base: &Path) -> Findings {
    let mut walk = Walk::new(mode, wasm, base);
    let dir = root.parent().map_or_else(PathBuf::new, Path::to_path_buf);
    walk.walk_file(root, &dir, false, "crate", &[]);
    walk.found
}

/// Rule (d): why each `discovered` wasm test that no claimed cell runs is refused.
///
/// `run` is the union of what the target's claimed cells admit.
fn unrun_refusals(discovered: &BTreeSet<String>, run: &BTreeSet<String>) -> Vec<String> {
    discovered
        .difference(run)
        .map(|id| {
            format!(
                "`#[wasm_bindgen_test]` {id} runs in no claimed cell; \
                 claim a cell whose features compile it"
            )
        })
        .collect()
}

/// A test target of the runtime crate.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum TargetName {
    Lib,
    Test(String),
}

impl Display for TargetName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lib => f.write_str("lib"),
            Self::Test(name) => write!(f, "test `{name}`"),
        }
    }
}

/// One claimed cell of `test-claims.yml`.
#[derive(Debug, PartialEq, Eq)]
struct Cell {
    package: String,
    target: TargetName,
    platform: String,
    features: Vec<String>,
    owner: String,
    expect_tests: usize,
}

/// Whether `text` is a bare claim-table token: lowercase ASCII, digits, `-`, `_`.
fn bare_token(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// The bare token `value` of field `key`.
fn token_field(key: &str, value: &str) -> Result<String, String> {
    if bare_token(value) {
        Ok(value.to_owned())
    } else {
        Err(format!("`{key}: {value}` is not a bare token"))
    }
}

/// The `target:` value: `lib` or `{test: NAME}`.
fn target_field(value: &str) -> Result<TargetName, String> {
    if value == "lib" {
        return Ok(TargetName::Lib);
    }
    value
        .strip_prefix("{test: ")
        .and_then(|rest| rest.strip_suffix('}'))
        .filter(|name| bare_token(name) && !name.contains('-'))
        .map(|name| TargetName::Test(name.to_owned()))
        .ok_or_else(|| format!("`target: {value}` is neither `lib` nor `{{test: NAME}}`"))
}

/// The `features:` value: a flow list of bare tokens, `[]` when empty.
fn features_field(value: &str) -> Result<Vec<String>, String> {
    let inner = value
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .ok_or_else(|| format!("`features: {value}` is not a `[…]` list"))?;
    if inner.trim().is_empty() {
        return Ok(Vec::new());
    }
    inner
        .split(',')
        .map(str::trim)
        .map(|name| token_field("features", name))
        .collect()
}

/// The fields of one cell entry, keyed by field name.
type Fields = BTreeMap<String, String>;

/// One cell from its `fields`.
fn cell_from(fields: &Fields) -> Result<Cell, String> {
    let field = |key: &str| {
        fields
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| format!("cell is missing `{key}`"))
    };
    let known = [
        "package",
        "target",
        "platform",
        "features",
        "owner",
        "expect_tests",
    ];
    if let Some(unknown) = fields.keys().find(|key| !known.contains(&key.as_str())) {
        return Err(format!("unknown cell field `{unknown}`"));
    }
    let expect = field("expect_tests")?;
    Ok(Cell {
        package: token_field("package", field("package")?)?,
        target: target_field(field("target")?)?,
        platform: token_field("platform", field("platform")?)?,
        features: features_field(field("features")?)?,
        owner: token_field("owner", field("owner")?)?,
        expect_tests: expect
            .parse()
            .map_err(|_| format!("`expect_tests: {expect}` is not a count"))?,
    })
}

/// The cells of the claim table `text`.
///
/// The table is read in the one layout it is written in: a `cells:` line,
/// then per cell a `  - package: …` line and one `    key: value` line per
/// other field. Any other line is refused, so this reader and a YAML loader
/// cannot disagree on what the file says.
fn parse_claims(text: &str) -> Result<Vec<Cell>, String> {
    let mut lines = text
        .lines()
        .map(|line| {
            line.split_once(" #")
                .map_or(line, |(kept, _)| kept)
                .trim_end()
        })
        .filter(|line| !line.is_empty() && !line.trim_start().starts_with('#'));
    if lines.next() != Some("cells:") {
        return Err("the claim table must open with `cells:`".to_owned());
    }
    let mut entries: Vec<Fields> = Vec::new();
    for line in lines {
        let (field, opens_cell) = if let Some(rest) = line.strip_prefix("  - ") {
            (rest, true)
        } else if let Some(rest) = line.strip_prefix("    ") {
            (rest, false)
        } else {
            return Err(format!("`{line}` is outside the claim-table layout"));
        };
        let (key, value) = field
            .split_once(": ")
            .ok_or_else(|| format!("`{line}` is not `key: value`"))?;
        if opens_cell {
            if key != "package" {
                return Err(format!("a cell must open with `package:`, not `{key}:`"));
            }
            entries.push(Fields::new());
        }
        let entry = entries
            .last_mut()
            .ok_or_else(|| format!("`{line}` precedes every cell"))?;
        if entry
            .insert(key.to_owned(), value.trim().to_owned())
            .is_some()
        {
            return Err(format!("duplicate cell field `{key}`"));
        }
    }
    entries.iter().map(cell_from).collect()
}

/// The `[features]` table of the manifest `text`, feature to members.
fn feature_table(text: &str) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut table = BTreeMap::new();
    let mut in_features = false;
    let mut pending: Option<(String, String)> = None;
    for raw in text.lines() {
        let line = raw.split_once('#').map_or(raw, |(kept, _)| kept).trim();
        if pending.is_none() && raw.starts_with('[') {
            in_features = line == "[features]";
            continue;
        }
        if !in_features || line.is_empty() {
            continue;
        }
        let (name, body) = match pending.take() {
            Some((name, body)) => (name, format!("{body} {line}")),
            None => {
                let (name, rest) = line
                    .split_once('=')
                    .ok_or_else(|| format!("`{line}` in `[features]` is not `name = […]`"))?;
                (name.trim().to_owned(), rest.trim().to_owned())
            }
        };
        if body.ends_with(']') {
            let members = feature_members(&name, &body)?;
            if table.insert(name.clone(), members).is_some() {
                return Err(format!("feature `{name}` is defined twice"));
            }
        } else {
            pending = Some((name, body));
        }
    }
    if let Some((name, _)) = pending {
        return Err(format!("feature `{name}` has no closing `]`"));
    }
    Ok(table)
}

/// The quoted members of the feature list `body` (`[ "a", "b" ]`).
fn feature_members(name: &str, body: &str) -> Result<Vec<String>, String> {
    let inner = body
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .ok_or_else(|| format!("feature `{name}` is not a `[…]` list"))?;
    let pieces: Vec<&str> = inner.split('"').collect();
    if pieces.len().is_multiple_of(2) {
        return Err(format!("feature `{name}` has an unbalanced quote"));
    }
    let gaps: Vec<&str> = pieces.iter().step_by(2).map(|gap| gap.trim()).collect();
    let last = gaps.len().saturating_sub(1);
    let separators_only = gaps.iter().enumerate().all(|(at, gap)| match at {
        0 => gap.is_empty(),
        _ if at == last => gap.is_empty() || *gap == ",",
        _ => *gap == ",",
    });
    if !separators_only {
        return Err(format!(
            "feature `{name}` holds something other than quoted names"
        ));
    }
    Ok(pieces
        .iter()
        .skip(1)
        .step_by(2)
        .map(|member| (*member).to_owned())
        .collect())
}

/// Every feature `requested` turns on, `default` included.
///
/// `dep:x` enables no feature and `x?/y` enables `x` only when something else
/// does; `x/y` enables `x`. A requested name the table does not define is
/// refused.
fn feature_closure(
    table: &BTreeMap<String, Vec<String>>,
    requested: &[String],
) -> Result<BTreeSet<String>, String> {
    if let Some(unknown) = requested.iter().find(|name| !table.contains_key(*name)) {
        return Err(format!("feature `{unknown}` is not in `[features]`"));
    }
    let mut enabled = BTreeSet::new();
    let mut stack: Vec<String> = requested.to_vec();
    stack.push("default".to_owned());
    while let Some(member) = stack.pop() {
        if member.starts_with("dep:") || member.contains("?/") {
            continue;
        }
        let name = member.split('/').next().unwrap_or_default().to_owned();
        if enabled.insert(name.clone()) {
            stack.extend(table.get(&name).into_iter().flatten().cloned());
        }
    }
    Ok(enabled)
}

/// Why a cell's `found` count cannot stand for its claimed `expected`, if it cannot.
fn count_refusal(found: usize, expected: usize) -> Option<String> {
    if expected == 0 {
        Some("`expect_tests: 0` claims a cell that runs nothing".to_owned())
    } else if found == expected {
        None
    } else {
        Some(format!(
            "the tree declares {found} `#[wasm_bindgen_test]`, the claim table says {expected}"
        ))
    }
}

/// This crate's manifest directory.
fn crate_dir() -> PathBuf {
    e2e_support::manifest_dir!()
}

/// The claim table's text.
#[allow(clippy::expect_used)] // a missing claim table must fail the scan, never pass it
fn claims_text() -> String {
    std::fs::read_to_string(crate_dir().join(CLAIMS_PATH)).expect("read .github/ci/test-claims.yml")
}

/// Every test target of this crate: the library and each `tests/*.rs`.
#[allow(clippy::expect_used)] // an unreadable tests directory must fail the scan
fn test_targets() -> Vec<(TargetName, PathBuf)> {
    let dir = crate_dir().join("tests");
    let mut targets = vec![(TargetName::Lib, crate_dir().join("src/mod.rs"))];
    for entry in std::fs::read_dir(&dir).expect("read tests/") {
        let path = entry.expect("read a tests/ entry").path();
        assert!(
            !plain_file(&path.join("main.rs")),
            "{}: a `tests/*/main.rs` target is not scanned",
            path.display()
        );
        let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned());
        if let (Some(stem), true) = (stem, path.extension().is_some_and(|e| e == "rs")) {
            assert!(
                plain_file(&path),
                "{}: a test root must be a regular file",
                path.display()
            );
            targets.push((TargetName::Test(stem), path));
        }
    }
    targets.sort();
    targets
}

/// A discovery configuration: wasm32, any feature set, test harness on.
const fn discovery_env() -> CfgEnv<'static> {
    CfgEnv {
        arch: Arch::Wasm32,
        features: None,
        test: true,
    }
}

/// Discovery findings for the fixture `name`.
fn fixture(name: &str) -> Findings {
    let dir = crate_dir().join(FIXTURE_DIR);
    scan_target(&dir.join(name), Mode::Discover, discovery_env(), &dir)
}

/// Assert the fixture `name` is refused with a reason containing `reason`.
fn assert_fixture_refused(name: &str, reason: &str) {
    let found = fixture(name);
    assert!(
        found.refusals.iter().any(|why| why.contains(reason)),
        "{name} must be refused for {reason:?}; refusals: {:#?}",
        found.refusals
    );
}

/// Every claimed cell holds its claimed wasm tests, and every other rule holds.
#[test]
#[allow(clippy::expect_used)] // a malformed claim table or manifest must fail the scan
fn every_wasm_test_is_in_a_claimed_cell_with_its_claimed_count() {
    let cells = parse_claims(&claims_text()).expect("parse .github/ci/test-claims.yml");
    let manifest =
        std::fs::read_to_string(crate_dir().join("Cargo.toml")).expect("read Cargo.toml");
    let table = feature_table(&manifest).expect("parse [features]");
    let base = crate_dir();
    let targets = test_targets();
    let mut refusals: Vec<String> = Vec::new();

    let mut claimed: BTreeSet<TargetName> = BTreeSet::new();
    let mut run: BTreeMap<TargetName, BTreeSet<String>> = BTreeMap::new();
    for cell in cells
        .iter()
        .filter(|cell| cell.package == env!("CARGO_PKG_NAME"))
    {
        let at = format!("cell {} (owner `{}`)", cell.target, cell.owner);
        if cell.platform != WASM_TRIPLE {
            refusals.push(format!(
                "{at}: platform `{}` is not `{WASM_TRIPLE}`",
                cell.platform
            ));
            continue;
        }
        if !claimed.insert(cell.target.clone()) {
            refusals.push(format!("{at}: claimed more than once"));
        }
        let Some((_, root)) = targets.iter().find(|(name, _)| *name == cell.target) else {
            refusals.push(format!("{at}: no such test target"));
            continue;
        };
        let features = match feature_closure(&table, &cell.features) {
            Ok(features) => features,
            Err(why) => {
                refusals.push(format!("{at}: {why}"));
                continue;
            }
        };
        let env = CfgEnv {
            arch: Arch::Wasm32,
            features: Some(&features),
            test: true,
        };
        let mode = Mode::Cell {
            lib: cell.target == TargetName::Lib,
        };
        let found = scan_target(root, mode, env, &base);
        refusals.extend(found.refusals.into_iter().map(|why| format!("{at}: {why}")));
        refusals.extend(
            count_refusal(found.wasm_tests, cell.expect_tests).map(|why| format!("{at}: {why}")),
        );
        run.entry(cell.target.clone())
            .or_default()
            .extend(found.wasm_test_ids);
    }

    for (name, root) in &targets {
        let found = scan_target(root, Mode::Discover, discovery_env(), &base);
        refusals.extend(
            found
                .refusals
                .into_iter()
                .map(|why| format!("{name}: {why}")),
        );
        if found.wasm_tests > 0 && !claimed.contains(name) {
            refusals.push(format!(
                "{name}: can hold {} `#[wasm_bindgen_test]` but no cell in test-claims.yml claims it",
                found.wasm_tests
            ));
            continue;
        }
        let empty = BTreeSet::new();
        let ran = run.get(name).unwrap_or(&empty);
        refusals.extend(
            unrun_refusals(&found.wasm_test_ids, ran)
                .into_iter()
                .map(|why| format!("{name}: {why}")),
        );
    }

    assert!(
        refusals.is_empty(),
        "wasm test cells are unsound:\n{}",
        refusals.join("\n")
    );
}

#[test]
fn a_plain_test_compiled_only_for_wasm32_is_refused() {
    assert_fixture_refused("plain_test_in_wasm_mod.rs", "compiled only for wasm32");
}

#[test]
fn an_unknown_cfg_predicate_is_refused() {
    assert_fixture_refused("unknown_cfg.rs", "unknown cfg predicate");
}

#[test]
fn a_path_module_the_walk_cannot_follow_is_refused() {
    assert_fixture_refused("path_attr_missing.rs", "`#[path]` names no regular file");
    assert_fixture_refused("path_in_inline_mod.rs", "inside an inline module");
}

#[test]
fn a_path_module_and_an_include_are_followed() {
    for name in ["path_attr_ok.rs", "include_ok.rs"] {
        let found = fixture(name);
        assert!(found.refusals.is_empty(), "{name}: {:#?}", found.refusals);
        assert_eq!(found.wasm_tests, 1, "{name}");
    }
}

#[test]
fn an_include_the_walk_cannot_follow_is_refused() {
    assert_fixture_refused("include_missing.rs", "`include!` names no regular file");
    assert_fixture_refused("include_non_literal.rs", "does not name a string literal");
}

#[test]
fn a_module_with_no_file_is_refused() {
    assert_fixture_refused("missing_mod.rs", "no regular file for `mod absent;`");
}

#[test]
fn a_macro_that_can_expand_to_a_test_is_refused() {
    assert_fixture_refused("macro_hidden_test.rs", "could expand to a test");
}

#[test]
fn a_cfg_attr_adding_a_test_harness_is_refused() {
    assert_fixture_refused("cfg_attr_test.rs", "conditionally adds an attribute");
}

#[test]
fn a_wasm_bindgen_test_behind_known_cfgs_is_counted() {
    let found = fixture("ok_wasm_bindgen_test.rs");
    assert!(found.refusals.is_empty(), "refusals: {:#?}", found.refusals);
    assert_eq!(found.wasm_tests, 1);
}

#[test]
fn a_plain_test_inside_a_claimed_cell_is_refused() {
    let dir = crate_dir().join(FIXTURE_DIR);
    let features = BTreeSet::new();
    let env = CfgEnv {
        arch: Arch::Wasm32,
        features: Some(&features),
        test: true,
    };
    let found = scan_target(
        &dir.join("plain_test_in_cell.rs"),
        Mode::Cell { lib: false },
        env,
        &dir,
    );
    assert!(
        found
            .refusals
            .iter()
            .any(|why| why.contains("never runs under the wasm runner")),
        "refusals: {:#?}",
        found.refusals
    );
}

#[test]
fn a_test_only_item_outside_src_wasm_is_refused_in_the_lib_cell() {
    let dir = crate_dir().join(FIXTURE_DIR);
    let features = BTreeSet::new();
    let env = CfgEnv {
        arch: Arch::Wasm32,
        features: Some(&features),
        test: true,
    };
    let found = scan_target(
        &dir.join("test_only_helper.rs"),
        Mode::Cell { lib: true },
        env,
        &dir,
    );
    assert!(
        found
            .refusals
            .iter()
            .any(|why| why.contains("test-only code outside `src/wasm/`")),
        "refusals: {:#?}",
        found.refusals
    );
}

#[test]
fn a_cfg_undecided_in_a_cell_is_refused() {
    let dir = crate_dir().join(FIXTURE_DIR);
    let env = CfgEnv {
        arch: Arch::Wasm32,
        features: None,
        test: true,
    };
    let found = scan_target(
        &dir.join("ok_wasm_bindgen_test.rs"),
        Mode::Cell { lib: false },
        env,
        &dir,
    );
    assert!(
        found.refusals.iter().any(|why| why.contains("undecided")),
        "refusals: {:#?}",
        found.refusals
    );
}

/// Findings for the fixture `name` walked as a wasm32 cell of `features`.
fn cell_fixture(name: &str, features: &[&str]) -> Findings {
    let dir = crate_dir().join(FIXTURE_DIR);
    let features: BTreeSet<String> = features.iter().copied().map(str::to_owned).collect();
    let env = CfgEnv {
        arch: Arch::Wasm32,
        features: Some(&features),
        test: true,
    };
    scan_target(&dir.join(name), Mode::Cell { lib: false }, env, &dir)
}

/// Assert the cell walk of the fixture `name` is refused with a reason containing `reason`.
fn assert_cell_fixture_refused(name: &str, reason: &str) {
    let found = cell_fixture(name, &[]);
    assert!(
        found.refusals.iter().any(|why| why.contains(reason)),
        "{name} must be refused in a cell for {reason:?}; refusals: {:#?}",
        found.refusals
    );
}

#[test]
fn a_wasm_test_under_an_unclaimed_feature_is_refused() {
    let name = "feature_gated_wasm_test.rs";
    let discovered = fixture(name);
    assert!(
        discovered.refusals.is_empty(),
        "refusals: {:#?}",
        discovered.refusals
    );
    assert_eq!(discovered.wasm_test_ids.len(), 4);
    let claimed = cell_fixture(name, &[]);
    assert!(
        claimed.refusals.is_empty(),
        "refusals: {:#?}",
        claimed.refusals
    );
    assert_eq!(claimed.wasm_tests, 2);
    let unrun = unrun_refusals(&discovered.wasm_test_ids, &claimed.wasm_test_ids);
    assert_eq!(unrun.len(), 2, "unrun: {unrun:#?}");
    assert!(
        unrun.iter().any(|why| why.contains("::never_runs[")),
        "unrun: {unrun:#?}"
    );
    assert!(
        unrun.iter().any(|why| why.contains("::unclaimed_mod[")),
        "unrun: {unrun:#?}"
    );
    let every = cell_fixture(name, &["unclaimed"]);
    assert!(unrun_refusals(&discovered.wasm_test_ids, &every.wasm_test_ids).is_empty());
}

#[test]
fn an_ignored_or_should_panic_wasm_test_in_a_cell_is_refused() {
    assert_cell_fixture_refused("ignore_wasm_test.rs", "does not run as counted");
    assert_cell_fixture_refused("should_panic_wasm_test.rs", "does not run as counted");
}

#[test]
fn a_wasm_test_with_arguments_in_a_cell_is_refused() {
    assert_cell_fixture_refused("wasm_test_with_args.rs", "arguments change where it runs");
}

#[test]
fn a_duplicate_wasm_test_attribute_is_refused() {
    assert_fixture_refused("duplicate_wasm_attr.rs", "written more than once");
}

#[test]
fn a_module_with_both_files_is_refused() {
    assert_fixture_refused(
        "both_files.rs",
        "both `both_files_dup.rs` and `both_files_dup/mod.rs` exist",
    );
}

#[test]
fn a_module_tree_past_its_file_limit_is_refused() {
    assert_fixture_refused("fan_root.rs", "more than 4096 module files");
}

#[test]
fn a_module_tree_past_its_depth_limit_is_refused() {
    assert_fixture_refused("self_include.rs", "module files nested more than 64 deep");
}

#[test]
fn an_item_syn_cannot_parse_is_refused() {
    assert_fixture_refused("unparseable_item.rs", "an item `syn` could not parse");
}

#[test]
fn a_count_other_than_the_claim_is_refused() {
    assert!(count_refusal(3, 3).is_none());
    assert!(count_refusal(2, 3).is_some());
    assert!(count_refusal(4, 3).is_some());
    assert!(count_refusal(0, 0).is_some());
}

#[test]
fn the_claim_reader_refuses_every_shape_outside_its_layout() {
    let good = "cells:\n  - package: p\n    target: {test: t}\n    platform: x\n    features: []\n    owner: o\n    expect_tests: 1\n";
    assert!(parse_claims(good).is_ok());
    let refused = [
        good.replace("cells:", "claims:"),
        good.replace("    owner: o\n", ""),
        good.replace("    owner: o\n", "    owner: o\n    owner: o\n"),
        good.replace("    owner: o\n", "    owners: o\n"),
        good.replace("{test: t}", "{bench: t}"),
        good.replace("features: []", "features: wasm-client"),
        good.replace("expect_tests: 1", "expect_tests: many"),
        good.replace("  - package: p", "  - owner: p"),
        good.replace("    platform: x", "      platform: x"),
        good.replace("owner: o", "owner: \"o\""),
    ];
    for text in &refused {
        assert!(parse_claims(text).is_err(), "must be refused:\n{text}");
    }
}

#[test]
#[allow(clippy::expect_used)] // the fixture table is well-formed by construction
fn the_feature_closure_follows_members_and_refuses_unknown_names() {
    let table = feature_table(
        "[package]\nname = \"x\"\n\n[features]\ndefault = [\"base\"]\nbase = []\n# note\nwide = [\n    \"dep:serde\", # optional\n    \"tokio?/net\",\n    \"base\",\n]\nnet = [\"hyper/client\"]\n\n[dependencies]\n",
    )
    .expect("parse fixture [features]");
    let enabled = feature_closure(&table, &["wide".to_owned(), "net".to_owned()]).expect("close");
    let expected: BTreeSet<String> = ["base", "default", "hyper", "net", "wide"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert_eq!(enabled, expected);
    assert!(feature_closure(&table, &["absent".to_owned()]).is_err());
    assert!(feature_table("[features]\nbad = [\"a\" \"b\" x]\n").is_err());
    assert!(feature_table("[features]\nbad = [\"a\" \"b\"]\n").is_err());
    assert!(feature_table("[features]\ntwice = []\ntwice = []\n").is_err());
    assert!(feature_table("[features]\nopen = [\"a\",\n").is_err());
}

#[test]
fn the_cfg_evaluator_keeps_unknown_facts_unknown() {
    let tree = |text: &str| syn::parse_str::<Meta>(text).map_err(|error| error.to_string());
    let native = CfgEnv {
        arch: Arch::Native,
        features: None,
        test: true,
    };
    let cases = [
        ("target_arch = \"wasm32\"", Tri::False),
        ("target_arch = \"x86_64\"", Tri::Unknown),
        ("not(target_arch = \"wasm32\")", Tri::True),
        ("unix", Tri::Unknown),
        ("all(test, feature = \"x\")", Tri::Unknown),
        ("any(test, feature = \"x\")", Tri::True),
    ];
    for (text, expected) in cases {
        assert_eq!(
            tree(text).and_then(|meta| eval(&meta, native)),
            Ok(expected),
            "{text}"
        );
    }
    assert!(
        tree("target_vendor = \"apple\"")
            .and_then(|meta| eval(&meta, native))
            .is_err()
    );
    assert!(
        tree("not(test, unix)")
            .and_then(|meta| eval(&meta, native))
            .is_err()
    );
}
