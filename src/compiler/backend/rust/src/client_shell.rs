//! The fixed native shell crate a `web client desktop` bundle is built from.
//!
//! The crate is a `main.rs` that never changes and a generated `site.rs`: the
//! table of every bundle asset, embedded with `include_bytes!` from the crate's
//! own `www/` tree, plus the window title, the storage key, the mount base and
//! the `Content-Security-Policy` value. The runtime's `webview::bundle_app`
//! re-parses that table at startup and serves it from memory, so the shell
//! holds no path and opens no file. Every literal in `site.rs` is printed by
//! the one Rust literal printer ([`ipe_intern::rust_str_lit`]); no author text
//! is spliced into Rust syntax any other way.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use ipe_backend::{EmittedProject, RelPath};
use ipe_diagnostics::DResult;
use ipe_intern::rust_str_lit;
use ipe_runtime_rust::encoding::{BundlePath, MountBase};

/// The runtime cargo feature the shell crate selects, and nothing else.
///
/// The runtime manifest declares it (`webview-shell`); the
/// `shell_feature_is_declared_by_the_runtime` test pins the two together.
pub const SHELL_RUNTIME_FEATURE: &str = "webview-shell";

/// The directory below the shell crate the bundle's files are written in.
pub const SHELL_WWW_DIR: &str = "www";

/// The page the bundle must hold; the runtime refuses a table without it.
const INDEX: &str = "index.html";

/// The fixed entry point of every shell crate.
///
/// Its `fn main() {` line is the one anchor the packer writes the capability
/// floor reference under, so it stays exactly that line.
const SHELL_MAIN_RS: &str = "\
//! The `client desktop` shell: one window over the embedded bundle.

mod site;

fn main() {
    if let Err(error) = ipe_runtime::webview::bundle_app(&site::SITE_CONFIG) {
        eprintln!(\"{error}\");
        std::process::exit(1);
    }
}
";

/// What a shell crate embeds, built from the collected client bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShellSite {
    title: String,
    storage_key: String,
    base: MountBase,
    csp: String,
    assets: BTreeMap<String, BundlePath>,
}

/// Why a [`ShellSite`] cannot be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShellSiteRefusal {
    /// Two assets have one path.
    Duplicate,
    /// No asset is the bundle's `index.html`.
    NoIndex,
}

impl std::fmt::Display for ShellSiteRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Duplicate => "two bundle assets share one path",
            Self::NoIndex => "the bundle has no index.html",
        })
    }
}

impl ShellSite {
    /// The table for a bundle of `assets` served at `base`.
    ///
    /// # Errors
    /// [`ShellSiteRefusal::Duplicate`] when two assets have one path;
    /// [`ShellSiteRefusal::NoIndex`] when none is `index.html`.
    pub fn new(
        title: &str,
        storage_key: &str,
        base: MountBase,
        csp: &str,
        assets: impl IntoIterator<Item = BundlePath>,
    ) -> Result<Self, ShellSiteRefusal> {
        let mut table = BTreeMap::new();
        for path in assets {
            if table.insert(path.rel().to_owned(), path).is_some() {
                return Err(ShellSiteRefusal::Duplicate);
            }
        }
        if !table.contains_key(INDEX) {
            return Err(ShellSiteRefusal::NoIndex);
        }
        Ok(Self {
            title: title.to_owned(),
            storage_key: storage_key.to_owned(),
            base,
            csp: csp.to_owned(),
            assets: table,
        })
    }

    /// The bundle paths the crate's `www/` tree must hold, in table order.
    pub fn asset_paths(&self) -> impl Iterator<Item = &BundlePath> {
        self.assets.values()
    }
}

/// Emit the shell crate for `site`: its manifest, `src/main.rs` and
/// `src/site.rs`.
///
/// The bundle's files are not part of the result: the caller writes them
/// below [`SHELL_WWW_DIR`] from the same read [`ShellSite`] was built from.
///
/// # Errors
/// [`ipe_diagnostics::Diagnostic::CompilerBug`] when the manifest template has drifted.
pub fn emit_client_shell(site: &ShellSite) -> DResult<EmittedProject> {
    let cargo_toml = crate::project::dep_manifest_selecting(
        &[SHELL_RUNTIME_FEATURE],
        "ipe_backend_rust::client_shell::emit_client_shell",
    )?;
    let mut files = BTreeMap::new();
    files.insert(RelPath::new("src/main.rs")?, SHELL_MAIN_RS.to_owned());
    files.insert(RelPath::new("src/site.rs")?, render_site(site));
    Ok(EmittedProject {
        files,
        cargo_toml,
        uses_webview: true,
        links_web_runtime: false,
        assets: BTreeMap::new(),
    })
}

/// The generated `site.rs` for `site`.
fn render_site(site: &ShellSite) -> String {
    let mut out = String::from(
        "//! The embedded bundle this shell serves, written by the packer.\n\n\
         use ipe_runtime::webview::bundle_site::{SiteAsset, SiteConfig};\n\n\
         static ASSETS: &[SiteAsset] = &[\n",
    );
    for path in site.assets.values() {
        let rel = path.rel();
        let file = format!("../{SHELL_WWW_DIR}/{rel}");
        let _ = writeln!(
            out,
            "    SiteAsset {{\n        path: {},\n        bytes: include_bytes!({}),\n    }},",
            rust_str_lit(rel),
            rust_str_lit(&file),
        );
    }
    let _ = write!(
        out,
        "];\n\n\
         pub static SITE_CONFIG: SiteConfig = SiteConfig {{\n    \
         title: {},\n    \
         storage_key: {},\n    \
         base: {},\n    \
         csp: {},\n    \
         assets: ASSETS,\n\
         }};\n",
        rust_str_lit(&site.title),
        rust_str_lit(&site.storage_key),
        rust_str_lit(site.base.prefix()),
        rust_str_lit(&site.csp),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Every asset path a `site.rs` embeds.
    fn embedded_paths(site_rs: &str) -> BTreeSet<String> {
        site_rs
            .lines()
            .filter_map(|line| line.trim().strip_prefix("path: "))
            .map(|lit| lit.trim_end_matches(',').trim_matches('"').to_owned())
            .collect()
    }

    fn path(text: &str) -> Option<BundlePath> {
        BundlePath::parse(text).ok()
    }

    fn site(title: &str, assets: &[&str]) -> Option<ShellSite> {
        let paths: Option<Vec<BundlePath>> = assets.iter().map(|p| path(p)).collect();
        ShellSite::new(
            title,
            "dev.ipe.example",
            MountBase::root(),
            "default-src 'none'",
            paths?,
        )
        .ok()
    }

    fn emitted(site: &ShellSite) -> Option<EmittedProject> {
        emit_client_shell(site).ok()
    }

    fn file<'p>(project: &'p EmittedProject, rel: &str) -> Option<&'p str> {
        project
            .files
            .iter()
            .find(|(key, _)| key.as_str() == rel)
            .map(|(_, text)| text.as_str())
    }

    /// The value of `SITE_CONFIG`'s string field `name`, read back through Rust's own grammar.
    fn config_field(site_rs: &str, name: &str) -> Option<String> {
        let file = syn::parse_file(site_rs).ok()?;
        let config = file.items.iter().find_map(|item| match item {
            syn::Item::Static(item) if item.ident == "SITE_CONFIG" => Some(item.expr.as_ref()),
            _ => None,
        })?;
        let syn::Expr::Struct(config) = config else {
            return None;
        };
        let field = config
            .fields
            .iter()
            .find(|field| matches!(&field.member, syn::Member::Named(id) if id == name))?;
        match &field.expr {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(lit),
                ..
            }) => Some(lit.value()),
            _ => None,
        }
    }

    /// How many items `site.rs` declares and how many fields `SITE_CONFIG` sets.
    fn config_shape(site_rs: &str) -> Option<(usize, usize)> {
        let file = syn::parse_file(site_rs).ok()?;
        let fields = file.items.iter().find_map(|item| match item {
            syn::Item::Static(item) if item.ident == "SITE_CONFIG" => match item.expr.as_ref() {
                syn::Expr::Struct(config) => Some(config.fields.len()),
                _ => None,
            },
            _ => None,
        })?;
        Some((file.items.len(), fields))
    }

    /// The `site.rs` the shell crate for `shell` holds.
    fn site_rs_of(shell: &ShellSite) -> Option<String> {
        let project = emitted(shell)?;
        file(&project, "src/site.rs").map(str::to_owned)
    }

    /// The shell manifest selects the runtime with its defaults off and exactly the shell feature on.
    ///
    /// Every other dependency is an optional allocator no default feature
    /// reaches, so the shell links no runtime surface beyond the webview shell.
    #[test]
    fn client_shell_cargo_toml_enables_only_webview_shell() {
        let Some(project) = site("App", &["index.html"]).as_ref().and_then(emitted) else {
            assert!(site("App", &["index.html"]).is_some());
            return;
        };
        let parsed = project.cargo_toml.parse::<toml::Table>();
        let Ok(manifest) = parsed else {
            assert!(parsed.is_ok(), "{parsed:?}");
            return;
        };
        let deps = manifest.get("dependencies").and_then(toml::Value::as_table);
        let runtime = deps
            .and_then(|deps| deps.get("ipe_runtime"))
            .and_then(toml::Value::as_table);
        let key = |name: &str| runtime.and_then(|runtime| runtime.get(name));
        assert_eq!(
            key("package").and_then(toml::Value::as_str),
            Some("ipe-runtime-rust")
        );
        assert_eq!(
            key("default-features").and_then(toml::Value::as_bool),
            Some(false)
        );
        let features: Option<Vec<&str>> = key("features")
            .and_then(toml::Value::as_array)
            .map(|list| list.iter().filter_map(toml::Value::as_str).collect());
        assert_eq!(features, Some(vec![SHELL_RUNTIME_FEATURE]));
        let required: Vec<&str> = deps
            .map(|deps| {
                deps.iter()
                    .filter(|(_, dep)| {
                        dep.get("optional").and_then(toml::Value::as_bool) != Some(true)
                    })
                    .map(|(name, _)| name.as_str())
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(required, ["ipe_runtime"]);
        assert_eq!(
            manifest
                .get("features")
                .and_then(|features| features.get("default"))
                .and_then(toml::Value::as_array)
                .map(Vec::len),
            Some(0)
        );
        assert_eq!(
            manifest
                .get("package")
                .and_then(|package| package.get("edition"))
                .and_then(toml::Value::as_str),
            Some("2024")
        );
        assert!(project.uses_webview);
        assert!(!project.links_web_runtime);
    }

    /// The shell manifest is the program manifest template with only its feature list set.
    ///
    /// The template bytes around the `__IPE_RUNTIME_FEATURES__` anchor render
    /// unchanged for every program feature, alone and together, so the shared
    /// renderer leaves each program manifest as it was; and no program feature
    /// is the shell's, so no program selects the shell.
    #[test]
    fn client_shell_emit_changes_no_existing_project_output() {
        const TEMPLATE: &str = include_str!("../templates/Cargo.dep.toml");
        const ANCHOR: &str = "__IPE_RUNTIME_FEATURES__";
        let Some((head, tail)) = TEMPLATE.split_once(ANCHOR) else {
            assert!(TEMPLATE.contains(ANCHOR));
            return;
        };
        assert!(!tail.contains(ANCHOR));
        let quoted = |names: &[&str]| {
            names
                .iter()
                .map(|name| format!("\"{name}\""))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let all: Vec<&str> = crate::runtime_features::RuntimeFeature::ALL
            .iter()
            .map(|feature| feature.as_str())
            .collect();
        assert!(!all.contains(&SHELL_RUNTIME_FEATURE), "{all:?}");
        let mut selections: Vec<Vec<&str>> = all.iter().map(|name| vec![*name]).collect();
        selections.push(all.clone());
        selections.push(Vec::new());
        for selection in selections {
            let rendered = crate::project::dep_manifest_selecting(&selection, "test");
            assert_eq!(
                rendered.ok(),
                Some(format!("{head}{}{tail}", quoted(&selection))),
                "{selection:?}"
            );
        }
        let Some(project) = site("App", &["index.html"]).as_ref().and_then(emitted) else {
            assert!(site("App", &["index.html"]).is_some());
            return;
        };
        assert_eq!(
            project.cargo_toml,
            format!("{head}{}{tail}", quoted(&[SHELL_RUNTIME_FEATURE]))
        );
    }

    /// The storage key reaches `site.rs` as one literal Rust reads back unchanged, never as syntax.
    #[test]
    fn client_shell_site_renders_storage_key_through_rust_string_literal() {
        for key in [
            "com.acme.notes",
            "a.b\", title: \"evil\", assets: &[] }; fn main() {} //\n\\",
        ] {
            let shell = ShellSite::new(
                "App",
                key,
                MountBase::root(),
                "default-src 'none'",
                path("index.html"),
            );
            let Some(site_rs) = shell.as_ref().ok().and_then(site_rs_of) else {
                assert!(shell.is_ok(), "{shell:?}");
                return;
            };
            assert_eq!(config_shape(&site_rs), Some((3, 5)), "{site_rs}");
            assert_eq!(config_field(&site_rs, "storage_key").as_deref(), Some(key));
            assert_eq!(config_field(&site_rs, "title").as_deref(), Some("App"));
            let line = format!("    storage_key: {},", rust_str_lit(key));
            assert_eq!(
                site_rs.lines().filter(|l| *l == line).count(),
                1,
                "{site_rs}"
            );
        }
    }

    /// Each adversarial title reads back from `site.rs` as exactly the title, in one literal.
    ///
    /// The expected value is what Rust's own lexer decodes from the
    /// `str::escape_default` rendering of the title, never a hand-written
    /// escape; `site.rs` keeps its three items and five config fields, so no
    /// title closes the literal and opens Rust syntax.
    #[test]
    fn rust_string_literal_round_trips_adversarial_titles() {
        for title in ["\"", "\\", "\"); panic!(\"", "a\nb", "a\u{2028}b", "a\0b"] {
            let oracle = syn::parse_str::<syn::LitStr>(&format!("\"{}\"", title.escape_default()))
                .map(|lit| lit.value());
            assert_eq!(oracle.as_deref().ok(), Some(title), "{title:?}");
            let Some(site_rs) = site(title, &["index.html"]).as_ref().and_then(site_rs_of) else {
                assert!(site(title, &["index.html"]).is_some(), "{title:?}");
                return;
            };
            assert_eq!(config_shape(&site_rs), Some((3, 5)), "{site_rs}");
            assert_eq!(config_field(&site_rs, "title"), oracle.ok(), "{site_rs}");
            assert!(!site_rs.contains('\u{2028}'), "{site_rs}");
            assert!(!site_rs.contains('\0'), "{site_rs}");
        }
    }

    /// The items `site.rs` declares, by kind and name, and `SITE_CONFIG`'s
    /// fields with their string values.
    ///
    /// Read through Rust's own grammar, so text inside a literal is never
    /// mistaken for syntax; a field whose value is not a string literal reads
    /// as `None`.
    fn site_structure(site_rs: &str) -> Option<SiteStructure> {
        let file = syn::parse_file(site_rs).ok()?;
        let items = file
            .items
            .iter()
            .map(|item| match item {
                syn::Item::Use(_) => "use".to_owned(),
                syn::Item::Static(item) => format!("static {}", item.ident),
                _ => "other".to_owned(),
            })
            .collect();
        let config = file.items.iter().find_map(|item| match item {
            syn::Item::Static(item) if item.ident == "SITE_CONFIG" => Some(item.expr.as_ref()),
            _ => None,
        })?;
        let syn::Expr::Struct(config) = config else {
            return None;
        };
        if config.rest.is_some() {
            return None;
        }
        let fields = config
            .fields
            .iter()
            .map(|field| {
                let name = match &field.member {
                    syn::Member::Named(id) => id.to_string(),
                    syn::Member::Unnamed(index) => index.index.to_string(),
                };
                let value = match &field.expr {
                    syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(lit),
                        ..
                    }) => Some(lit.value()),
                    _ => None,
                };
                (name, value)
            })
            .collect();
        Some(SiteStructure { items, fields })
    }

    /// What [`site_structure`] reads from a `site.rs`.
    #[derive(Debug, PartialEq, Eq)]
    struct SiteStructure {
        items: Vec<String>,
        fields: Vec<(String, Option<String>)>,
    }

    /// A hostile title stays inside the `title` literal: `site.rs` parses to
    /// its three items and `SITE_CONFIG` to its five fields, each once, with
    /// the title and storage key read back unchanged.
    #[test]
    fn client_shell_title_is_one_escaped_literal() {
        let hostile = "x\", storage_key: \"evil\" }; fn main() {} //\n\u{202e}\\";
        let Some(project) = site(hostile, &["index.html"]).as_ref().and_then(emitted) else {
            assert!(site(hostile, &["index.html"]).is_some());
            return;
        };
        let Some(site_rs) = file(&project, "src/site.rs") else {
            assert!(file(&project, "src/site.rs").is_some());
            return;
        };
        let field = |name: &str, value: Option<&str>| (name.to_owned(), value.map(str::to_owned));
        let expected = SiteStructure {
            items: vec![
                "use".to_owned(),
                "static ASSETS".to_owned(),
                "static SITE_CONFIG".to_owned(),
            ],
            fields: vec![
                field("title", Some(hostile)),
                field("storage_key", Some("dev.ipe.example")),
                field("base", Some(MountBase::root().prefix())),
                field("csp", Some("default-src 'none'")),
                field("assets", None),
            ],
        };
        assert_eq!(site_structure(site_rs), Some(expected), "{site_rs}");
        assert!(!site_rs.contains('\u{202e}'), "{site_rs}");
    }

    #[test]
    fn client_shell_table_embeds_every_asset_from_its_own_www() {
        let assets = ["index.html", "app.js", "pkg/app_bg.wasm"];
        let Some(shell) = site("App", &assets) else {
            assert!(site("App", &assets).is_some());
            return;
        };
        let Some(project) = emitted(&shell) else {
            assert!(emitted(&shell).is_some());
            return;
        };
        let site_rs = file(&project, "src/site.rs").unwrap_or_default();
        let expected: BTreeSet<String> = assets.iter().map(|p| (*p).to_owned()).collect();
        assert_eq!(embedded_paths(site_rs), expected);
        for asset in assets {
            let include = format!("include_bytes!(\"../www/{asset}\")");
            assert!(site_rs.contains(&include), "{include} in {site_rs}");
        }
        let listed: BTreeSet<String> = shell.asset_paths().map(|p| p.rel().to_owned()).collect();
        assert_eq!(listed, expected);
    }

    #[test]
    fn client_shell_main_is_fixed_and_calls_bundle_app() {
        let Some(project) = site("App", &["index.html"]).as_ref().and_then(emitted) else {
            assert!(site("App", &["index.html"]).is_some());
            return;
        };
        assert_eq!(file(&project, "src/main.rs"), Some(SHELL_MAIN_RS));
        assert!(SHELL_MAIN_RS.contains("ipe_runtime::webview::bundle_app(&site::SITE_CONFIG)"));
        assert_eq!(SHELL_MAIN_RS.matches("\nfn main() {\n").count(), 1);
        assert_eq!(project.files.len(), 2);
        assert!(project.assets.is_empty());
    }

    #[test]
    fn client_shell_site_refuses_duplicate_and_missing_index() {
        let twice = ["index.html", "a.js", "a.js"]
            .iter()
            .map(|p| path(p))
            .collect::<Option<Vec<_>>>()
            .unwrap_or_default();
        assert_eq!(
            ShellSite::new("App", "a.b", MountBase::root(), "", twice),
            Err(ShellSiteRefusal::Duplicate)
        );
        let no_index = path("app.js").into_iter();
        assert_eq!(
            ShellSite::new("App", "a.b", MountBase::root(), "", no_index),
            Err(ShellSiteRefusal::NoIndex)
        );
    }

    #[test]
    fn shell_feature_is_declared_by_the_runtime() {
        let manifest = include_str!("../../../../runtime/rust/Cargo.toml");
        let declared = manifest
            .lines()
            .any(|line| line.starts_with(&format!("{SHELL_RUNTIME_FEATURE} = [")));
        assert!(
            declared,
            "the runtime manifest declares `{SHELL_RUNTIME_FEATURE}`"
        );
    }
}
