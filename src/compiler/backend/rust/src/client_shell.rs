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
use ipe_diagnostics::{DResult, Diagnostic};
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
const SHELL_MAIN_RS: &str = "\
//! The `client desktop` shell: one window over the embedded bundle.

mod site;

fn main() -> std::process::ExitCode {
    match ipe_runtime::webview::bundle_app(&site::SITE_CONFIG) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(\"{error}\");
            std::process::ExitCode::FAILURE
        }
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
/// [`Diagnostic::CompilerBug`] when the manifest template has drifted.
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

    #[test]
    fn client_shell_manifest_selects_only_the_shell_feature() {
        let Some(project) = site("App", &["index.html"]).as_ref().and_then(emitted) else {
            assert!(site("App", &["index.html"]).is_some());
            return;
        };
        assert!(
            project
                .cargo_toml
                .contains("default-features = false, features = [\"webview-shell\"] }"),
            "{}",
            project.cargo_toml
        );
        assert!(project.cargo_toml.contains("edition = \"2024\""));
        assert!(project.uses_webview);
        assert!(!project.links_web_runtime);
    }

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
        let title_line = site_rs
            .lines()
            .find(|line| line.trim_start().starts_with("title: "))
            .unwrap_or_default();
        assert_eq!(
            title_line.trim(),
            format!("title: {},", rust_str_lit(hostile)),
            "{site_rs}"
        );
        assert_eq!(site_rs.matches("storage_key: ").count(), 1, "{site_rs}");
        assert!(!site_rs.contains('\u{202e}'), "{site_rs}");
        assert!(!site_rs.contains("fn main"), "{site_rs}");
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
