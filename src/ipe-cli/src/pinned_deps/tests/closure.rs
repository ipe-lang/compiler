//! The emitter closure: every registry crate any emitted manifest can name,
//! under every feature the emitter can select, is held by the pinned set.
//!
//! The closure is derived, never listed: each `templates/Cargo*.toml`, each
//! production `const` of the backend source whose text opens `[package]`, and
//! the backend's crate-spec tables. A crate counts as held when the pinned set
//! locks a version its requirement matches AND some workspace member declares
//! that crate, at that version, with every feature (and the defaults) the
//! emitter can turn on — so no optional dependency the emitter can activate is
//! missing from the lock.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use semver::{Version, VersionReq};
use syn::visit::{self, Visit};

use super::super::{CrateName, PinnedSet, pinned_set};

/// The dependency tables a manifest (or one of its `[target.*]` tables) can carry.
const DEP_TABLES: &[&str] = &["dependencies", "dev-dependencies", "build-dependencies"];

/// `text` with every `__UPPER_CASE__` emitter placeholder removed.
///
/// A template is TOML only once the emitter fills its placeholders (the
/// runtime's feature list, say); an empty fill keeps every dependency it
/// declares.
fn without_placeholders(text: &str) -> String {
    let is_body = |body: &str| {
        !body.is_empty()
            && body
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    };
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find("__") {
        out.push_str(rest.get(..open).unwrap_or_default());
        let after = rest.get(open.saturating_add(2)..).unwrap_or_default();
        match after.find("__") {
            Some(close) if after.get(..close).is_some_and(is_body) => {
                rest = after.get(close.saturating_add(2)..).unwrap_or_default();
            }
            Some(_) | None => {
                out.push_str("__");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// One registry dependency a manifest declares.
#[derive(Debug, Clone)]
struct Declared {
    /// The crates.io package name (a `package = ...` rename resolved).
    package: String,
    /// Its version requirement.
    req: VersionReq,
    /// Every feature it, or a `[features]` edge of its manifest, can turn on.
    features: BTreeSet<String>,
    /// Whether its default features stay on.
    defaults: bool,
}

/// What the workspace members, together, turn on for one locked package.
#[derive(Debug, Default)]
struct Provided {
    features: BTreeSet<String>,
    defaults: bool,
}

/// The workspace's provision, keyed by package and the pinned version it resolves to.
type Provision = BTreeMap<(String, Version), Provided>;

/// The highest version `set` pins for `package` that `req` matches.
fn pin_for<'s>(set: &'s PinnedSet, package: &str, req: &VersionReq) -> Option<&'s Version> {
    let name = CrateName::parse(package)?;
    set.by_name
        .get(&name)?
        .iter()
        .map(|pin| &pin.version)
        .filter(|version| req.matches(version))
        .max()
}

/// The string array at `key` of `table`, empty when absent.
fn strings(table: &toml::Table, key: &str, at: &str) -> Result<Vec<String>, String> {
    match table.get(key) {
        None => Ok(Vec::new()),
        Some(toml::Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{at}: `{key}` holds a non-string"))
            })
            .collect(),
        Some(_) => Err(format!("{at}: `{key}` is not an array")),
    }
}

/// One dependency entry `key = value`, or `None` for a path or git dependency.
fn declared(key: &str, value: &toml::Value, at: &str) -> Result<Option<Declared>, String> {
    let at = format!("{at}: `{key}`");
    let parse_req =
        |req: &str| VersionReq::parse(req).map_err(|e| format!("{at}: requirement `{req}`: {e}"));
    match value {
        toml::Value::String(req) => Ok(Some(Declared {
            package: key.to_owned(),
            req: parse_req(req)?,
            features: BTreeSet::new(),
            defaults: true,
        })),
        toml::Value::Table(table) => {
            if table.contains_key("path") || table.contains_key("git") {
                return Ok(None);
            }
            if table.contains_key("workspace") {
                return Err(format!(
                    "{at}: inherits from a workspace table no manifest has"
                ));
            }
            let req = table
                .get("version")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| format!("{at}: names no version"))?;
            let package = match table.get("package") {
                None => key.to_owned(),
                Some(toml::Value::String(package)) => package.clone(),
                Some(_) => return Err(format!("{at}: `package` is not a string")),
            };
            let defaults = match table
                .get("default-features")
                .or_else(|| table.get("default_features"))
            {
                None => true,
                Some(toml::Value::Boolean(on)) => *on,
                Some(_) => return Err(format!("{at}: `default-features` is not a bool")),
            };
            Ok(Some(Declared {
                package,
                req: parse_req(req)?,
                features: strings(table, "features", &at)?.into_iter().collect(),
                defaults,
            }))
        }
        _ => Err(format!("{at}: is neither a requirement nor a table")),
    }
}

/// Every registry dependency `manifest` declares, each carrying the features
/// its `[features]` table can turn on through a `dep/feature` edge.
fn registry_deps(manifest: &toml::Table, at: &str) -> Result<Vec<Declared>, String> {
    let mut tables: Vec<&toml::Table> = DEP_TABLES
        .iter()
        .filter_map(|name| manifest.get(*name).and_then(toml::Value::as_table))
        .collect();
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        for target in targets.values().filter_map(toml::Value::as_table) {
            tables.extend(
                DEP_TABLES
                    .iter()
                    .filter_map(|name| target.get(*name).and_then(toml::Value::as_table)),
            );
        }
    }
    let mut by_key: Vec<(String, Declared)> = Vec::new();
    for table in tables {
        for (key, value) in table {
            if let Some(dep) = declared(key, value, at)? {
                by_key.push((key.clone(), dep));
            }
        }
    }
    if let Some(features) = manifest.get("features").and_then(toml::Value::as_table) {
        for feature in features.keys() {
            for edge in strings(features, feature, at)? {
                let Some((dep, enabled)) = edge.split_once('/') else {
                    continue;
                };
                let dep = dep.trim_end_matches('?');
                for (_, entry) in by_key.iter_mut().filter(|(key, _)| key == dep) {
                    entry.features.insert(enabled.to_owned());
                }
            }
        }
    }
    Ok(by_key.into_iter().map(|(_, dep)| dep).collect())
}

/// Parse `text` as a manifest named `at`.
fn manifest(text: &str, at: &str) -> Result<toml::Table, String> {
    text.parse::<toml::Table>()
        .map_err(|e| format!("{at}: not a manifest: {e}"))
}

/// Whether `cargo deny` judges the dependencies of the `[target.<key>]` table.
///
/// The deny graph (`deny.toml [graph]`, no target filter — `deny_graph_gaps`
/// refuses one) drops an edge whose `cfg` expression names no predicate and is
/// false — `cfg(any())` — so a pin spelled there is locked but never judged for
/// advisories, licences, bans or sources. Every predicate-free `cfg` is refused,
/// the true ones too (fail closed); `true` and `false` are literals, never
/// predicates. A pin that must never compile uses a contradiction such as
/// `cfg(all(unix, not(unix)))`, whose predicates keep the edge in the graph.
fn deny_judges_target(key: &str) -> bool {
    let Some(expr) = key
        .trim()
        .strip_prefix("cfg")
        .and_then(|rest| rest.trim_start().strip_prefix('('))
    else {
        return true;
    };
    expr.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(|word| !word.is_empty() && !matches!(word, "any" | "all" | "not" | "true" | "false"))
}

/// The `deny.toml [graph]` keys that leave every edge of a contradiction `cfg`
/// in the judged graph: the feature selection only. `targets` makes krates
/// evaluate each `cfg` per target (dropping the contradiction), and `exclude`,
/// `exclude-dev`, `exclude-unpublished` or any key cargo-deny adds later can
/// remove a pin's edge, so every other key is refused.
const DENY_GRAPH_KEYS: &[&str] = &["all-features", "no-default-features", "features"];

/// The top-level `deny.toml` keys that name the judged graph outside `[graph]`
/// (the pre-`[graph]` spelling of the target filter and the exclusions).
const DENY_LEGACY_GRAPH_KEYS: &[&str] = &["targets", "exclude", "exclude-dev"];

/// Each way the `deny.toml` `deny` (named `at`) would let cargo-deny drop the
/// edge of a pin `deny_judges_target` accepts.
fn deny_graph_gaps(deny: &toml::Table, at: &str) -> Vec<String> {
    let mut found: Vec<String> = DENY_LEGACY_GRAPH_KEYS
        .iter()
        .filter(|key| deny.contains_key(**key))
        .map(|key| format!("{at}: top-level `{key}` changes the judged graph's edges"))
        .collect();
    match deny.get("graph") {
        None => {}
        Some(toml::Value::Table(graph)) => found.extend(
            graph
                .keys()
                .filter(|key| !DENY_GRAPH_KEYS.contains(&key.as_str()))
                .map(|key| format!("{at}: `[graph] {key}` changes the judged graph's edges")),
        ),
        Some(_) => found.push(format!("{at}: `graph` is not a table")),
    }
    found
}

/// `manifest` without the `[target.*]` tables `cargo deny` never judges.
fn judged_only(mut manifest: toml::Table) -> toml::Table {
    if let Some(targets) = manifest
        .get_mut("target")
        .and_then(toml::Value::as_table_mut)
    {
        targets.retain(|key, _| deny_judges_target(key));
    }
    manifest
}

/// What the workspace members turn on, per package and the pinned version each declaration resolves to.
///
/// Only a declaration `cargo deny` judges provisions a crate: a pin the
/// supply-chain scan never sees is no pin of a crate that ships.
fn provision(set: &PinnedSet, members: &[(String, String)]) -> Result<Provision, String> {
    let mut provided = Provision::new();
    for (at, text) in members {
        for dep in registry_deps(&judged_only(manifest(text, at)?), at)? {
            let Some(version) = pin_for(set, &dep.package, &dep.req) else {
                continue;
            };
            let entry = provided
                .entry((dep.package.clone(), version.clone()))
                .or_default();
            entry.features.extend(dep.features);
            entry.defaults |= dep.defaults;
        }
    }
    Ok(provided)
}

/// Each way `wanted` (named by `at`) is not held by `set` and `provided`.
fn gaps(set: &PinnedSet, provided: &Provision, at: &str, wanted: &Declared) -> Vec<String> {
    let name = &wanted.package;
    let Some(version) = pin_for(set, name, &wanted.req) else {
        return vec![format!(
            "{at}: {name} {} matches no pinned version",
            wanted.req
        )];
    };
    let Some(have) = provided.get(&(name.clone(), version.clone())) else {
        return vec![format!(
            "{at}: no workspace member declares {name} {version}, so the lock misses its optional dependencies"
        )];
    };
    let mut found = Vec::new();
    let missing: Vec<&String> = wanted.features.difference(&have.features).collect();
    if !missing.is_empty() {
        found.push(format!(
            "{at}: no workspace member turns on {name} {version} features {missing:?}"
        ));
    }
    if wanted.defaults && !have.defaults {
        found.push(format!(
            "{at}: no workspace member keeps {name} {version}'s default features"
        ));
    }
    found
}

/// Every gap of every registry dependency the manifests `emitted` declare.
fn manifest_gaps(
    set: &PinnedSet,
    provided: &Provision,
    emitted: &[(String, String)],
) -> Result<Vec<String>, String> {
    let mut found = Vec::new();
    for (at, text) in emitted {
        let text = without_placeholders(text);
        for wanted in registry_deps(&manifest(&text, at)?, at)? {
            found.extend(gaps(set, provided, at, &wanted));
        }
    }
    Ok(found)
}

/// Every gap of the crates the backend's spec tables let a surgery emit.
fn spec_gaps(set: &PinnedSet, provided: &Provision) -> Result<Vec<String>, String> {
    use ipe_backend_rust::crate_specs as specs;
    let req = |spec: specs::CrateSpec| {
        VersionReq::parse(spec.version)
            .map_err(|e| format!("crate_specs: {} `{}`: {e}", spec.name, spec.version))
    };
    let mut wanted = Vec::new();
    for spec in specs::ALL {
        wanted.push(Declared {
            package: spec.name.to_owned(),
            req: req(*spec)?,
            features: BTreeSet::new(),
            defaults: false,
        });
    }
    for pinned in specs::ALL_PINNED {
        let drivers: &[&str] = if pinned.spec.name == specs::SQLX.spec.name {
            specs::SQLX_DRIVERS
        } else {
            &[]
        };
        wanted.push(Declared {
            package: pinned.spec.name.to_owned(),
            req: req(pinned.spec)?,
            features: pinned
                .features
                .iter()
                .chain(drivers)
                .map(|feature| (*feature).to_owned())
                .collect(),
            defaults: pinned.default_features,
        });
    }
    wanted.push(Declared {
        package: specs::TOKIO.name.to_owned(),
        req: req(specs::TOKIO)?,
        features: specs::TokioFeature::ALL
            .iter()
            .map(|feature| feature.as_str().to_owned())
            .collect(),
        defaults: true,
    });
    Ok(wanted
        .iter()
        .flat_map(|dep| gaps(set, provided, "crate_specs", dep))
        .collect())
}

/// The repository root.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Read `path` as text, the failure naming it.
fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Every workspace member's manifest, by member path.
fn member_manifests() -> Result<Vec<(String, String)>, String> {
    let root = repo_root();
    let workspace = manifest(&read(&root.join("Cargo.toml"))?, "Cargo.toml")?;
    let members = workspace
        .get("workspace")
        .and_then(toml::Value::as_table)
        .map(|table| strings(table, "members", "Cargo.toml [workspace]"))
        .ok_or("Cargo.toml declares no workspace")??;
    members
        .into_iter()
        .map(|member| {
            Ok((
                member.clone(),
                read(&root.join(&member).join("Cargo.toml"))?,
            ))
        })
        .collect()
}

/// The production `const` strings of one source file whose text opens `[package]`.
struct ManifestConsts {
    found: Vec<(String, String)>,
}

/// Whether `attrs` gate their item on `cfg(test)`.
fn test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr
                .meta
                .require_list()
                .is_ok_and(|list| list.tokens.to_string() == "test")
    })
}

impl<'ast> Visit<'ast> for ManifestConsts {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if !test_only(&item.attrs) {
            visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if !test_only(&item.attrs) {
            visit::visit_item_fn(self, item);
        }
    }

    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        if let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(text),
            ..
        }) = &*item.expr
            && !test_only(&item.attrs)
            && text.value().trim_start().starts_with("[package]")
        {
            self.found.push((item.ident.to_string(), text.value()));
        }
        visit::visit_item_const(self, item);
    }
}

/// Every `.rs` file beneath `dir`.
fn rust_files(dir: &Path, into: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| format!("{}: {e}", dir.display()))?.path();
        if path.is_dir() {
            rust_files(&path, into)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            into.push(path);
        }
    }
    Ok(())
}

/// Every manifest the emitter can write: each `templates/Cargo*.toml`, then
/// each production `const` string of the backend source that opens `[package]`.
fn emitted_manifests() -> Result<Vec<(String, String)>, String> {
    let backend = repo_root().join("src/compiler/backend/rust");
    let templates = backend.join("templates");
    let mut found = Vec::new();
    let entries =
        std::fs::read_dir(&templates).map_err(|e| format!("{}: {e}", templates.display()))?;
    for entry in entries {
        let path = entry
            .map_err(|e| format!("{}: {e}", templates.display()))?
            .path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        if name.starts_with("Cargo")
            && Path::new(&name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
        {
            found.push((format!("templates/{name}"), read(&path)?));
        }
    }
    let mut sources = Vec::new();
    rust_files(&backend.join("src"), &mut sources)?;
    for source in sources {
        let syntax =
            syn::parse_file(&read(&source)?).map_err(|e| format!("{}: {e}", source.display()))?;
        let mut consts = ManifestConsts { found: Vec::new() };
        consts.visit_file(&syntax);
        found.extend(consts.found);
    }
    Ok(found)
}

#[test]
fn the_embedded_set_holds_the_emitter_closure() {
    let set = pinned_set();
    assert!(set.is_ok(), "the workspace lock is a pinned set: {set:?}");
    let Ok(set) = set else { return };
    let deny = read(&repo_root().join("deny.toml")).and_then(|text| manifest(&text, "deny.toml"));
    assert!(deny.is_ok(), "{deny:?}");
    let Ok(deny) = deny else { return };
    let unjudged = deny_graph_gaps(&deny, "deny.toml");
    assert!(
        unjudged.is_empty(),
        "the emitter-closure pins are judged only while deny.toml's graph keeps every \
         contradiction-cfg edge:\n{}",
        unjudged.join("\n")
    );
    let members = member_manifests();
    assert!(members.is_ok(), "{members:?}");
    let emitted = emitted_manifests();
    assert!(emitted.is_ok(), "{emitted:?}");
    let (Ok(members), Ok(emitted)) = (members, emitted) else {
        return;
    };
    let names: Vec<&str> = emitted.iter().map(|(at, _)| at.as_str()).collect();
    for expected in [
        "templates/Cargo.toml",
        "templates/Cargo.dep.toml",
        "templates/Cargo.wasm-dep.toml",
        "WASM_CARGO_TOML",
    ] {
        assert!(
            names.contains(&expected),
            "the closure walk reaches {expected}: {names:?}"
        );
    }
    let provided = provision(set, &members);
    assert!(provided.is_ok(), "{provided:?}");
    let Ok(provided) = provided else { return };
    let mut found = Vec::new();
    for result in [
        manifest_gaps(set, &provided, &emitted),
        spec_gaps(set, &provided),
    ] {
        assert!(result.is_ok(), "{result:?}");
        found.extend(result.unwrap_or_default());
    }
    assert!(
        found.is_empty(),
        "every crate an emitted manifest can name must be pinned and provisioned by a \
         workspace member (template-only crates go under the \
         `cfg(all(unix, not(unix)))` table of src/compiler/backend/rust/Cargo.toml):\n{}",
        found.join("\n")
    );
}

/// The small pinned set of the parent tests: `serde_json` 1.0.140 and `itoa` 1.0.15.
fn small_set() -> Option<PinnedSet> {
    PinnedSet::from_seed(super::SET).ok()
}

/// The gaps of one emitted manifest `emitted` against one member manifest `member`.
fn gaps_of(member: &str, emitted: &str) -> Vec<String> {
    let Some(set) = small_set() else {
        return vec!["the small set does not parse".to_owned()];
    };
    let members = [("member".to_owned(), member.to_owned())];
    let emitted = [("emitted".to_owned(), emitted.to_owned())];
    provision(&set, &members)
        .and_then(|provided| manifest_gaps(&set, &provided, &emitted))
        .unwrap_or_else(|e| vec![e])
}

#[test]
fn a_provisioned_dependency_has_no_gap() {
    let member =
        "[dependencies]\nserde_json = { version = \"1\", features = [\"preserve_order\"] }\n";
    let emitted = "[dependencies]\nserde_json = { version = \"1\", features = [\"preserve_order\"] }\n\
                   [target.'cfg(unix)'.dependencies]\nitoa = { path = \"x\" }\n";
    assert_eq!(gaps_of(member, emitted), Vec::<String>::new());
}

#[test]
fn a_pin_under_a_predicate_free_cfg_provisions_nothing() {
    let emitted = "[dependencies]\nitoa = \"1\"\n";
    // `cfg(any())` is the edge the deny graph drops; the others it keeps
    // (`not(any())` is true) or cargo rejects, and are refused all the same.
    for predicate_free in [
        "cfg(any())",
        "cfg(not(any()))",
        "cfg ( all ( ) )",
        "cfg(false)",
        "cfg(true)",
        "cfg(all(true, not(false)))",
    ] {
        let member = format!("[target.'{predicate_free}'.dependencies]\nitoa = \"1\"\n");
        let found = gaps_of(&member, emitted);
        assert!(
            found.len() == 1
                && found
                    .iter()
                    .all(|gap| gap.contains("no workspace member declares itoa")),
            "{predicate_free}: {found:?}"
        );
    }
    for judged in [
        "cfg(all(unix, not(unix)))",
        "cfg(windows)",
        "x86_64-unknown-linux-gnu",
    ] {
        let member = format!("[target.'{judged}'.dependencies]\nitoa = \"1\"\n");
        assert_eq!(gaps_of(&member, emitted), Vec::<String>::new(), "{judged}");
    }
}

#[test]
fn a_deny_graph_that_can_drop_a_pin_edge_is_refused() {
    let gaps_in =
        |text: &str| manifest(text, "deny.toml").map(|deny| deny_graph_gaps(&deny, "deny.toml"));
    for kept in [
        "",
        "[graph]\n",
        "[graph]\nall-features = false\nno-default-features = false\nfeatures = [\"full\"]\n",
    ] {
        assert_eq!(gaps_in(kept), Ok(Vec::new()), "{kept:?}");
    }
    for (refused, key) in [
        (
            "[graph]\ntargets = [\"x86_64-unknown-linux-gnu\"]\n",
            "targets",
        ),
        ("[graph]\ntargets = []\n", "targets"),
        ("[graph]\nexclude-dev = true\n", "exclude-dev"),
        ("[graph]\nexclude = [\"dlmalloc\"]\n", "exclude"),
        (
            "[graph]\nexclude-unpublished = true\n",
            "exclude-unpublished",
        ),
        (
            "targets = [{ triple = \"x86_64-unknown-linux-gnu\" }]\n",
            "targets",
        ),
        ("graph = 1\n", "graph"),
    ] {
        let found = gaps_in(refused);
        assert!(
            found
                .as_ref()
                .is_ok_and(|found| found.len() == 1 && found.iter().all(|gap| gap.contains(key))),
            "{refused:?}: {found:?}"
        );
    }
}

#[test]
fn an_unpinned_template_dependency_is_a_gap() {
    let member = "[dependencies]\nserde_json = \"1\"\n";
    let emitted = "[dependencies]\ndlmalloc = { version = \"0.2\", optional = true }\n";
    let found = gaps_of(member, emitted);
    assert!(
        found.len() == 1 && found.iter().all(|gap| gap.contains("dlmalloc")),
        "{found:?}"
    );
}

#[test]
fn a_pinned_but_undeclared_dependency_is_a_gap() {
    let member = "[dependencies]\nserde_json = \"1\"\n";
    let emitted = "[target.'cfg(windows)'.dependencies]\nitoa = \"1\"\n";
    let found = gaps_of(member, emitted);
    assert!(
        found.len() == 1
            && found
                .iter()
                .all(|gap| gap.contains("no workspace member declares itoa")),
        "{found:?}"
    );
}

#[test]
fn a_feature_or_default_no_member_turns_on_is_a_gap() {
    let member = "[dependencies]\nserde_json = { version = \"1\", default-features = false }\n";
    let feature = "[dependencies]\nserde_json = { version = \"1\", default-features = false, features = [\"raw_value\"] }\n";
    let found = gaps_of(member, feature);
    assert!(
        found.len() == 1 && found.iter().all(|gap| gap.contains("raw_value")),
        "{found:?}"
    );
    let defaults = "[dependencies]\nserde_json = \"1\"\n";
    let found = gaps_of(member, defaults);
    assert!(
        found.len() == 1 && found.iter().all(|gap| gap.contains("default features")),
        "{found:?}"
    );
}

#[test]
fn a_feature_edge_of_the_emitted_manifest_is_wanted_and_of_a_member_provided() {
    let member = "[features]\nmore = [\"serde_json/raw_value\"]\n\
                  [dependencies]\nserde_json = \"1\"\n";
    let emitted = "[features]\nx = [\"json?/raw_value\"]\n\
                   [dependencies]\njson = { package = \"serde_json\", version = \"1\", optional = true }\n";
    assert_eq!(gaps_of(member, emitted), Vec::<String>::new());
    let bare = "[dependencies]\nserde_json = \"1\"\n";
    let found = gaps_of(bare, emitted);
    assert!(
        found.len() == 1 && found.iter().all(|gap| gap.contains("raw_value")),
        "{found:?}"
    );
}

#[test]
fn a_requirement_matching_only_another_major_is_a_gap() {
    let member = "[dependencies]\nserde_json = \"1\"\n";
    let emitted = "[dependencies]\nserde_json = \"2\"\n";
    let found = gaps_of(member, emitted);
    assert!(
        found.len() == 1
            && found
                .iter()
                .all(|gap| gap.contains("matches no pinned version")),
        "{found:?}"
    );
}

#[test]
fn a_manifest_const_is_found_and_a_test_const_is_not() {
    let sample = "pub const A: &str = \"[package]\\nname = \\\"a\\\"\\n\";\n\
                  const B: &str = \"not a manifest\";\n\
                  #[cfg(test)] const C: &str = \"[package]\\n\";\n\
                  #[cfg(test)] mod tests { const D: &str = \"[package]\\n\"; }";
    let syntax = syn::parse_file(sample).map_err(|e| e.to_string());
    assert!(syntax.is_ok(), "{:?}", syntax.as_ref().err());
    let Ok(syntax) = syntax else { return };
    let mut consts = ManifestConsts { found: Vec::new() };
    consts.visit_file(&syntax);
    let names: Vec<&str> = consts.found.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["A"]);
}

#[test]
fn only_an_upper_case_placeholder_is_removed() {
    assert_eq!(
        without_placeholders("f = [__A_B1__] }\nx__y__ = 1\n__ = 2"),
        "f = [] }\nx__y__ = 1\n__ = 2"
    );
    assert_eq!(without_placeholders("a ____ b"), "a ____ b");
}
