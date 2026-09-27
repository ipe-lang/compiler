//! Which Rust files are test code, and the on-disk proof behind that claim.
//!
//! [`is_test_path`] is the ONE path rule every tool uses to exempt a file from a
//! production-only check. It is component-based: a `tests` directory anywhere on
//! the path, or a file named `tests.rs`. A name that merely contains `tests`
//! (`contests.rs`, `tests_util.rs`, `unit_tests/`) is production.
//!
//! The rule rests on a premise the path alone cannot show: a `tests` directory
//! or `tests.rs` inside a crate's source tree is the body of an out-of-line
//! `#[cfg(test)] mod tests;`. A `pub mod tests;` would compile that body into
//! the production build while every path-based check skipped it.
//! [`check_test_path`] confirms the premise on disk and fails closed otherwise:
//!
//! * a `tests` directory or `tests.rs` under a `bin` directory is an
//!   automatically discovered production binary, never test code;
//! * every Rust file beside the test module (and the module file of the
//!   directory holding it) is free of production items that declare, name, or
//!   include test code;
//! * then either an integration-test directory sits beside a `Cargo.toml` whose
//!   explicit production targets ([`check_manifest`]) name no test code, or some
//!   file beside it declares `mod tests;` under a test-only `cfg`.

use std::fmt;
use std::path::{Component, Path, PathBuf};

use proc_macro2::{Ident, TokenStream, TokenTree};
use syn::ext::IdentExt;
use syn::visit::{self, Visit};
use syn::{Expr, ForeignItem, ImplItem, Item, Pat, TraitItem, Type, TypeParamBound};

use crate::manifest::{ManifestError, names_test_code, parse_manifest};
use crate::{item_test_only, scan_file};

/// Directory name of a crate's integration tests or an out-of-line test module.
const TEST_DIR: &str = "tests";

/// File name of an out-of-line test module's body.
const TEST_MODULE_FILE: &str = "tests.rs";

/// Directory name of the emitted-program Rust copied into generated binaries.
pub(crate) const TEMPLATE_DIR: &str = "templates";

/// File name of a crate manifest.
const MANIFEST_FILE: &str = "Cargo.toml";

/// Directory whose Rust files and subdirectories Cargo builds as binaries.
const AUTO_BIN_DIR: &str = "bin";

/// Whether `rel` names test code.
///
/// True for a path with a `tests` directory component or a final `tests.rs`
/// component. Pass a path relative to a source root: an absolute path whose
/// ancestor happens to be named `tests` would read as test code (and then
/// fail [`check_test_path`], which is the fail-closed outcome).
#[must_use]
pub fn is_test_path(rel: &Path) -> bool {
    test_marker(rel).is_some()
}

/// Whether `rel` lies under an emitted-program `templates` directory.
///
/// That Rust is copied verbatim into every generated binary and is covered by
/// the emitted-output package gate, not by the compiler-code scan.
#[must_use]
pub fn is_template_path(rel: &Path) -> bool {
    rel.parent()
        .is_some_and(|dir| dir.components().any(|c| c.as_os_str() == TEMPLATE_DIR))
}

/// Whether `rel` is test code AND its test-only premise holds under `root`.
///
/// The fail-closed form for report tools: a test path whose premise cannot be
/// confirmed is treated as production, so it stays in scope.
#[must_use]
pub fn is_verified_test_path(root: &Path, rel: &Path) -> bool {
    is_test_path(rel) && check_test_path(root, rel).is_ok()
}

/// Confirm that test path `rel` (relative to `root`) is compiled only for tests.
///
/// A path that is not a test path is trivially `Ok`. Otherwise the outermost
/// `tests` directory (or the `tests.rs` file) is judged by the directory `dir`
/// holding it: every non-test Rust file in `dir`, and `<dir>.rs`, must be free
/// of production items that declare, name, or include test code; then either
/// the `Cargo.toml` in `dir` names no test code as a production target, or some
/// of those files declares `mod tests;` under a test-only `cfg`.
///
/// # Errors
///
/// [`TestPathError`] when the marker sits in a `bin` directory, when no file
/// declares the test module, when a production item reaches it, when the
/// manifest names test code as a production target, or when a candidate file
/// or directory cannot be read or parsed.
pub fn check_test_path(root: &Path, rel: &Path) -> Result<(), TestPathError> {
    let Some(marker) = test_marker(rel) else {
        return Ok(());
    };
    let in_bin_dir = marker
        .declaring_dir
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case(AUTO_BIN_DIR));
    if in_bin_dir {
        return Err(TestPathError::AutoBinary {
            path: root.join(rel),
        });
    }
    let dir = root.join(&marker.declaring_dir);
    let mut declared = false;
    for file in declaring_candidates(&dir)? {
        let src = std::fs::read_to_string(&file).map_err(|error| TestPathError::Unreadable {
            file: file.clone(),
            error,
        })?;
        let parsed = syn::parse_file(&src).map_err(|error| TestPathError::Unparseable {
            file: file.clone(),
            error,
        })?;
        match tests_declaration(&parsed) {
            Declaration::Absent => {}
            Declaration::TestOnly => declared = true,
            Declaration::Ungated(by) => {
                return Err(TestPathError::Ungated {
                    declaring_file: file,
                    by,
                });
            }
        }
        if !scan_file(&parsed, &src).test_path_includes.is_empty() {
            return Err(TestPathError::Ungated {
                declaring_file: file,
                by: UngatedBy::IncludesTestCode,
            });
        }
    }
    let manifest = dir.join(MANIFEST_FILE);
    let has_manifest = marker.kind == MarkerKind::Directory && manifest.is_file();
    if has_manifest {
        check_manifest(&manifest)?;
    }
    if has_manifest || declared {
        Ok(())
    } else {
        Err(TestPathError::Undeclared {
            test_module: dir.join(marker.kind.name()),
        })
    }
}

/// Confirm that no explicit production target of `manifest` names test code.
///
/// A target names test code when its path, as written, has a `tests`
/// component or ends in `tests.rs`; such a file would be skipped by every
/// path-based check while compiling into the production build.
///
/// # Errors
///
/// [`TestPathError::Unreadable`] or [`TestPathError::ManifestUnparseable`] when
/// the manifest cannot be read, and [`TestPathError::TestTarget`] when a
/// production target names test code.
pub fn check_manifest(manifest: &Path) -> Result<(), TestPathError> {
    let src = std::fs::read_to_string(manifest).map_err(|error| TestPathError::Unreadable {
        file: manifest.to_path_buf(),
        error,
    })?;
    let targets = parse_manifest(&src).map_err(|error| TestPathError::ManifestUnparseable {
        manifest: manifest.to_path_buf(),
        error,
    })?;
    targets.first_test_path().map_or(Ok(()), |target| {
        Err(TestPathError::TestTarget {
            manifest: manifest.to_path_buf(),
            target: target.to_owned(),
        })
    })
}

/// Why a test path's test-only premise does not hold.
#[derive(Debug)]
pub enum TestPathError {
    /// No file beside the test module declares `mod tests;`.
    Undeclared { test_module: PathBuf },
    /// `declaring_file` reaches the test module from production code.
    Ungated {
        declaring_file: PathBuf,
        by: UngatedBy,
    },
    /// The test module sits in a `bin` directory, so Cargo builds it as a binary.
    AutoBinary { path: PathBuf },
    /// A candidate declaring file, its directory, or a manifest could not be read.
    Unreadable {
        file: PathBuf,
        error: std::io::Error,
    },
    /// A candidate declaring file does not parse as a Rust file.
    Unparseable { file: PathBuf, error: syn::Error },
    /// A manifest leaves the TOML subset the target reader accepts.
    ManifestUnparseable {
        manifest: PathBuf,
        error: ManifestError,
    },
    /// A manifest names test code as a production target.
    TestTarget { manifest: PathBuf, target: String },
}

/// The production item that reaches a test module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UngatedBy {
    /// A `mod tests;` without a test-only `cfg`.
    PlainMod,
    /// A production macro invocation or definition whose tokens name `tests`.
    MacroNamingTests,
    /// Any other production item whose tokens name `tests`.
    ItemNamingTests,
    /// A production `#[path]` or `include!` that names test code or cannot be judged.
    IncludesTestCode,
}

impl fmt::Display for UngatedBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PlainMod => "declares `mod tests;` without `#[cfg(test)]`",
            Self::MacroNamingTests => "invokes a production macro that names `tests`",
            Self::ItemNamingTests => "has a production item that names `tests`",
            Self::IncludesTestCode => {
                "has a production `#[path]` or `include!` that names test code or cannot be judged"
            }
        })
    }
}

impl fmt::Display for TestPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Undeclared { test_module } => write!(
                f,
                "{}: no sibling module file declares `#[cfg(test)] mod tests;` for this test module",
                test_module.display()
            ),
            Self::Ungated { declaring_file, by } => write!(
                f,
                "{}: {by}, so its test module may compile into production",
                declaring_file.display()
            ),
            Self::AutoBinary { path } => write!(
                f,
                "{}: a `bin` directory entry is a production binary, not test code",
                path.display()
            ),
            Self::Unreadable { file, error } => {
                write!(f, "{}: cannot read ({error})", file.display())
            }
            Self::Unparseable { file, error } => {
                write!(f, "{}: does not parse as Rust ({error})", file.display())
            }
            Self::ManifestUnparseable { manifest, error } => {
                write!(
                    f,
                    "{}: cannot read build targets ({error})",
                    manifest.display()
                )
            }
            Self::TestTarget { manifest, target } => write!(
                f,
                "{}: production target `{target}` lies in test code, which path-based checks skip",
                manifest.display()
            ),
        }
    }
}

impl std::error::Error for TestPathError {}

/// Whether the test marker is a `tests` directory or a `tests.rs` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarkerKind {
    Directory,
    ModuleFile,
}

impl MarkerKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Directory => TEST_DIR,
            Self::ModuleFile => TEST_MODULE_FILE,
        }
    }
}

/// The outermost test marker on a path and the directory that holds it.
#[derive(Debug, PartialEq, Eq)]
struct TestMarker {
    declaring_dir: PathBuf,
    kind: MarkerKind,
}

/// Locate the outermost `tests` directory or final `tests.rs` on `rel`.
fn test_marker(rel: &Path) -> Option<TestMarker> {
    let mut declaring_dir = PathBuf::new();
    let mut components = rel.components().peekable();
    while let Some(component) = components.next() {
        let is_last = components.peek().is_none();
        if let Component::Normal(name) = component {
            let kind = if is_last {
                (name == TEST_MODULE_FILE).then_some(MarkerKind::ModuleFile)
            } else {
                (name == TEST_DIR).then_some(MarkerKind::Directory)
            };
            if let Some(kind) = kind {
                return Some(TestMarker {
                    declaring_dir,
                    kind,
                });
            }
        }
        declaring_dir.push(component);
    }
    None
}

/// Files that may declare or reach a test module inside `dir`.
///
/// Every Rust file directly in `dir` except test code itself, plus `<dir>.rs`,
/// in path order. A missing `dir` has no candidates.
fn declaring_candidates(dir: &Path) -> Result<Vec<PathBuf>, TestPathError> {
    let unreadable = |error| TestPathError::Unreadable {
        file: dir.to_path_buf(),
        error,
    };
    let mut files = Vec::new();
    match std::fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries {
                let path = entry.map_err(unreadable)?.path();
                let rust = path.extension().is_some_and(|ext| ext == "rs");
                let test_code = path
                    .file_name()
                    .is_some_and(|name| names_test_code(Path::new(name)));
                if rust && !test_code && path.is_file() {
                    files.push(path);
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(unreadable(error)),
    }
    if dir.file_name().is_some() {
        let module_file = dir.with_extension("rs");
        if module_file.is_file() {
            files.push(module_file);
        }
    }
    files.sort();
    Ok(files)
}

/// How a module file reaches its `tests` child module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Declaration {
    /// No top-level item names `tests`.
    Absent,
    /// At least one `mod tests;` under a test-only `cfg`, and no production item names `tests`.
    TestOnly,
    /// A production item declares or names `tests`.
    Ungated(UngatedBy),
}

/// Classify every top-level item of `file` that reaches a `tests` module.
///
/// Every item counts, not only the first: one test-only `mod tests;` never
/// excuses a sibling production item that also declares or names `tests`.
/// Names compare case-insensitively, since a case-insensitive file system
/// resolves `mod Tests;` to a `tests` directory.
fn tests_declaration(file: &syn::File) -> Declaration {
    let mut file_names = NamesTests::default();
    for attr in &file.attrs {
        file_names.visit_attribute(attr);
    }
    if file_names.0 {
        return Declaration::Ungated(UngatedBy::ItemNamingTests);
    }
    let mut declared = false;
    for item in &file.items {
        let out_of_line_mod = match item {
            Item::Mod(m) if m.content.is_none() => Some(m.ident.unraw().to_string()),
            _ => None,
        };
        if item_test_only(item) {
            declared |= out_of_line_mod.as_deref() == Some(TEST_DIR);
            continue;
        }
        if out_of_line_mod.is_some_and(|name| name.eq_ignore_ascii_case(TEST_DIR)) {
            return Declaration::Ungated(UngatedBy::PlainMod);
        }
        let mut names = NamesTests::default();
        names.visit_item(item);
        if names.0 {
            return Declaration::Ungated(match item {
                Item::Macro(_) => UngatedBy::MacroNamingTests,
                _ => UngatedBy::ItemNamingTests,
            });
        }
    }
    if declared {
        Declaration::TestOnly
    } else {
        Declaration::Absent
    }
}

/// Whether an identifier names `tests`, ignoring case and a raw `r#` prefix.
fn ident_names_tests(ident: &Ident) -> bool {
    ident.unraw().to_string().eq_ignore_ascii_case(TEST_DIR)
}

/// Whether any token in `stream`, at any depth, is an identifier naming `tests`.
fn stream_names_tests(stream: &TokenStream) -> bool {
    stream.clone().into_iter().any(|tok| match tok {
        TokenTree::Ident(id) => ident_names_tests(&id),
        TokenTree::Group(g) => stream_names_tests(&g.stream()),
        TokenTree::Punct(_) | TokenTree::Literal(_) => false,
    })
}

/// Visitor recording whether any identifier or token names `tests`.
#[derive(Default)]
struct NamesTests(bool);

impl NamesTests {
    fn tokens(&mut self, stream: &TokenStream) {
        self.0 |= stream_names_tests(stream);
    }
}

impl<'ast> Visit<'ast> for NamesTests {
    fn visit_ident(&mut self, ident: &'ast Ident) {
        self.0 |= ident_names_tests(ident);
    }

    fn visit_token_stream(&mut self, stream: &'ast TokenStream) {
        self.tokens(stream);
    }

    fn visit_item(&mut self, item: &'ast Item) {
        match item {
            Item::Verbatim(ts) => self.tokens(ts),
            _ => visit::visit_item(self, item),
        }
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        match item {
            ImplItem::Verbatim(ts) => self.tokens(ts),
            _ => visit::visit_impl_item(self, item),
        }
    }

    fn visit_trait_item(&mut self, item: &'ast TraitItem) {
        match item {
            TraitItem::Verbatim(ts) => self.tokens(ts),
            _ => visit::visit_trait_item(self, item),
        }
    }

    fn visit_foreign_item(&mut self, item: &'ast ForeignItem) {
        match item {
            ForeignItem::Verbatim(ts) => self.tokens(ts),
            _ => visit::visit_foreign_item(self, item),
        }
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        match expr {
            Expr::Verbatim(ts) => self.tokens(ts),
            _ => visit::visit_expr(self, expr),
        }
    }

    fn visit_pat(&mut self, pat: &'ast Pat) {
        match pat {
            Pat::Verbatim(ts) => self.tokens(ts),
            _ => visit::visit_pat(self, pat),
        }
    }

    fn visit_type(&mut self, ty: &'ast Type) {
        match ty {
            Type::Verbatim(ts) => self.tokens(ts),
            _ => visit::visit_type(self, ty),
        }
    }

    fn visit_type_param_bound(&mut self, bound: &'ast TypeParamBound) {
        match bound {
            TypeParamBound::Verbatim(ts) => self.tokens(ts),
            _ => visit::visit_type_param_bound(self, bound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The declaration class of `src`, or `None` when it does not parse.
    fn declaration(src: &str) -> Option<Declaration> {
        syn::parse_file(src)
            .ok()
            .map(|file| tests_declaration(&file))
    }

    #[test]
    fn test_directories_and_module_files_are_test_paths() {
        for rel in [
            "tests/cli.rs",
            "src/ipe-cli/tests/cli.rs",
            "src/driver/tests/mod.rs",
            "src/driver/tests/nested/deep.rs",
            "src/tests.rs",
            "src/unit/tests.rs",
            "./tests/x.rs",
        ] {
            assert!(is_test_path(Path::new(rel)), "{rel} must be a test path");
        }
    }

    #[test]
    fn names_merely_containing_tests_are_production() {
        for rel in [
            "src/contests.rs",
            "src/tests_util.rs",
            "src/unit_tests/mod.rs",
            "src/testsuite/a.rs",
            "src/lib.rs",
            "tests",
            "src/tests.rs.bak",
            "src/Tests/a.rs",
            "",
        ] {
            assert!(!is_test_path(Path::new(rel)), "{rel} must be production");
        }
    }

    #[test]
    fn the_outermost_marker_names_the_declaring_directory() {
        let marker = test_marker(Path::new("crate/src/a/tests/b/tests/c.rs"));
        assert_eq!(
            marker,
            Some(TestMarker {
                declaring_dir: PathBuf::from("crate/src/a"),
                kind: MarkerKind::Directory,
            })
        );
        let marker = test_marker(Path::new("crate/src/a/tests.rs"));
        assert_eq!(
            marker,
            Some(TestMarker {
                declaring_dir: PathBuf::from("crate/src/a"),
                kind: MarkerKind::ModuleFile,
            })
        );
    }

    #[test]
    fn templates_directories_are_template_paths() {
        assert!(is_template_path(Path::new("src/ipe-cli/templates/main.rs")));
        assert!(!is_template_path(Path::new("src/templates.rs")));
        assert!(!is_template_path(Path::new("src/my_templates/a.rs")));
    }

    #[test]
    fn a_test_only_attribute_gates_the_declaration() {
        for src in [
            "#[cfg(test)]\nmod tests;",
            "#[cfg(test)]\npub(crate) mod tests;",
            "/// Unit tests.\n#[cfg(all(test, unix))]\nmod tests;",
            "#[cfg(test)]\n#[path = \"t/mod.rs\"]\nmod tests;",
            "mod a;\n#[cfg(test)]\nmod tests;\nmod b;",
            "#[cfg(test)]\nmod r#tests;",
            "#[cfg(test)]\nmod tests;\n#[cfg(test)]\nuse tests::helper;",
        ] {
            assert_eq!(declaration(src), Some(Declaration::TestOnly), "{src:?}");
        }
    }

    #[test]
    fn a_declaration_without_a_test_only_attribute_is_ungated() {
        for src in [
            "mod tests;",
            "pub mod tests;",
            "pub mod r#tests;",
            "pub mod Tests;",
            "#[cfg(any(test, feature = \"x\"))]\nmod tests;",
            "#[cfg(not(test))]\nmod tests;",
            "#[cfg(test)]\nuse x;\nmod tests;",
            "#[cfg(test)]\nfn helper() {}\nmod tests;",
            "#![cfg(test)]\nmod tests;",
            "#[test]\nmod tests;",
        ] {
            assert_eq!(
                declaration(src),
                Some(Declaration::Ungated(UngatedBy::PlainMod)),
                "{src:?}"
            );
        }
    }

    #[test]
    fn every_declaration_is_checked_not_only_the_first() {
        for src in [
            "#[cfg(test)]\nmod tests;\n#[cfg(not(test))]\npub mod tests;",
            "#[cfg(test)]\nmod tests;\nmod tests;",
            "#[cfg(test)]\nmod tests;\n#[cfg(feature = \"x\")]\npub mod tests;",
        ] {
            assert_eq!(
                declaration(src),
                Some(Declaration::Ungated(UngatedBy::PlainMod)),
                "{src:?}"
            );
        }
    }

    #[test]
    fn a_production_item_naming_tests_is_ungated() {
        for (src, by) in [
            (
                "#[cfg(test)]\nmod tests;\n#[cfg(not(test))]\ndecl!(tests);",
                UngatedBy::MacroNamingTests,
            ),
            ("decl! { tests }", UngatedBy::MacroNamingTests),
            (
                "macro_rules! m { () => { pub mod tests; } }",
                UngatedBy::MacroNamingTests,
            ),
            ("pub use tests::*;", UngatedBy::ItemNamingTests),
            ("mod tests {\n    mod inner;\n}", UngatedBy::ItemNamingTests),
            ("fn f() { mod tests; }", UngatedBy::ItemNamingTests),
            (
                "#[cfg_attr(not(test), path = \"x.rs\")]\nmod other { use super::tests; }",
                UngatedBy::ItemNamingTests,
            ),
            (
                "#![doc = \"x\"]\n#![cfg_attr(tests, x)]",
                UngatedBy::ItemNamingTests,
            ),
        ] {
            assert_eq!(declaration(src), Some(Declaration::Ungated(by)), "{src:?}");
        }
    }

    #[test]
    fn an_inline_or_missing_tests_module_is_no_declaration() {
        for src in [
            "fn f() {}",
            "#[cfg(test)]\nmod tests {\n    fn t() {}\n}",
            "mod contests;",
            "/// The tests live elsewhere.\nfn f() {}",
            "const S: &str = \"tests\";",
        ] {
            assert_eq!(declaration(src), Some(Declaration::Absent), "{src:?}");
        }
    }

    #[test]
    fn a_non_test_path_needs_no_premise() {
        assert!(check_test_path(Path::new("/nonexistent"), Path::new("src/lib.rs")).is_ok());
    }

    #[test]
    fn an_undeclared_test_module_fails_closed() {
        let result = check_test_path(Path::new("/nonexistent"), Path::new("src/tests/a.rs"));
        assert!(
            matches!(result, Err(TestPathError::Undeclared { .. })),
            "{result:?}"
        );
        assert!(!is_verified_test_path(
            Path::new("/nonexistent"),
            Path::new("src/tests/a.rs")
        ));
    }

    /// A fresh directory under the system temp dir holding `files`.
    fn scratch_crate(name: &str, files: &[(&str, &[u8])]) -> std::io::Result<PathBuf> {
        let root = std::env::temp_dir().join(format!(
            "panic-scan-test-path-{}-{name}",
            std::process::id()
        ));
        if root.exists() {
            std::fs::remove_dir_all(&root)?;
        }
        std::fs::create_dir_all(&root)?;
        for (rel, contents) in files {
            let path = root.join(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, contents)?;
        }
        Ok(root)
    }

    #[test]
    fn an_unreadable_declaring_file_fails_closed() -> std::io::Result<()> {
        let root = scratch_crate("unreadable", &[("lib.rs", b"\xff\xfe mod tests;")])?;
        let result = check_test_path(&root, Path::new("tests/a.rs"));
        assert!(
            matches!(result, Err(TestPathError::Unreadable { .. })),
            "{result:?}"
        );
        std::fs::remove_dir_all(root)
    }

    /// A directory whose listing is denied fails closed; the same crate with a
    /// readable directory passes, so the refusal is caused by the denial alone.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_declaring_directory_fails_closed() -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let root = scratch_crate(
            "unreadable-dir",
            &[
                ("src/lib.rs", b"#[cfg(test)]\nmod tests;\n"),
                ("src/tests/a.rs", b"fn t() {}\n"),
            ],
        )?;
        let rel = Path::new("src/tests/a.rs");
        let readable = check_test_path(&root, rel);
        assert!(readable.is_ok(), "{readable:?}");
        let src = root.join("src");
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o300))?;
        let listing_denied = std::fs::read_dir(&src).is_err();
        let result = check_test_path(&root, rel);
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o755))?;
        if listing_denied {
            assert!(
                matches!(result, Err(TestPathError::Unreadable { .. })),
                "{result:?}"
            );
        }
        std::fs::remove_dir_all(root)
    }

    #[test]
    fn an_unparseable_declaring_file_fails_closed() -> std::io::Result<()> {
        let root = scratch_crate(
            "unparseable",
            &[("lib.rs", b"#[cfg(test)]\nmod tests;\nfn f( {")],
        )?;
        let result = check_test_path(&root, Path::new("tests/a.rs"));
        assert!(
            matches!(result, Err(TestPathError::Unparseable { .. })),
            "{result:?}"
        );
        std::fs::remove_dir_all(root)
    }

    #[test]
    fn a_shadowing_second_declaration_fails_closed_on_disk() -> std::io::Result<()> {
        let root = scratch_crate(
            "shadowed",
            &[(
                "src/lib.rs",
                b"#[cfg(test)]\nmod tests;\n#[cfg(not(test))]\npub mod tests;\n",
            )],
        )?;
        let result = check_test_path(&root, Path::new("src/tests/mod.rs"));
        assert!(
            matches!(
                result,
                Err(TestPathError::Ungated {
                    by: UngatedBy::PlainMod,
                    ..
                })
            ),
            "{result:?}"
        );
        std::fs::remove_dir_all(root)
    }

    #[test]
    fn a_plain_crate_manifest_proves_its_integration_tests() -> std::io::Result<()> {
        let root = scratch_crate(
            "manifest-ok",
            &[
                (
                    "Cargo.toml",
                    b"[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
                ),
                ("src/lib.rs", b"pub fn f() {}\n"),
                ("build.rs", b"fn main() {}\n"),
            ],
        )?;
        let result = check_test_path(&root, Path::new("tests/cli.rs"));
        assert!(result.is_ok(), "{result:?}");
        std::fs::remove_dir_all(root)
    }

    #[test]
    fn a_manifest_target_under_tests_fails_closed() -> std::io::Result<()> {
        for (name, manifest) in [
            ("manifest-lib", &b"[lib]\npath = \"tests/lib.rs\"\n"[..]),
            (
                "manifest-bin",
                b"[[bin]]\nname = \"x\"\npath = \"tests/main.rs\"\n",
            ),
            (
                "manifest-build",
                b"[package]\nname = \"x\"\nbuild = \"tests/build.rs\"\n",
            ),
        ] {
            let root = scratch_crate(name, &[("Cargo.toml", manifest)])?;
            let result = check_test_path(&root, Path::new("tests/lib.rs"));
            assert!(
                matches!(result, Err(TestPathError::TestTarget { .. })),
                "{name}: {result:?}"
            );
            std::fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    fn an_unparseable_manifest_fails_closed() -> std::io::Result<()> {
        let root = scratch_crate("manifest-bad", &[("Cargo.toml", b"[lib\npath = 1\n")])?;
        let result = check_test_path(&root, Path::new("tests/a.rs"));
        assert!(
            matches!(result, Err(TestPathError::ManifestUnparseable { .. })),
            "{result:?}"
        );
        std::fs::remove_dir_all(root)
    }

    /// Every Rust file beside a manifest is a candidate, whatever its name.
    #[test]
    fn a_manifest_does_not_excuse_a_production_declaration() -> std::io::Result<()> {
        for (name, file) in [
            ("manifest-ungated-lib", "lib.rs"),
            ("manifest-ungated-build", "build.rs"),
            ("manifest-ungated-other", "helper.rs"),
        ] {
            let root = scratch_crate(
                name,
                &[
                    ("Cargo.toml", b"[package]\nname = \"x\"\n"),
                    (file, b"pub mod tests;\n"),
                ],
            )?;
            let result = check_test_path(&root, Path::new("tests/mod.rs"));
            assert!(
                matches!(
                    result,
                    Err(TestPathError::Ungated {
                        by: UngatedBy::PlainMod,
                        ..
                    })
                ),
                "{name}: {result:?}"
            );
            std::fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    fn a_production_include_of_test_code_is_ungated() -> std::io::Result<()> {
        let root = scratch_crate(
            "includes-tests",
            &[
                (
                    "src/lib.rs",
                    b"#[cfg(test)]\nmod tests;\n#[path = \"tests/x.rs\"]\nmod foo;\n",
                ),
                ("src/tests/x.rs", b"fn t() {}\n"),
            ],
        )?;
        let result = check_test_path(&root, Path::new("src/tests/x.rs"));
        assert!(
            matches!(
                result,
                Err(TestPathError::Ungated {
                    by: UngatedBy::IncludesTestCode,
                    ..
                })
            ),
            "{result:?}"
        );
        std::fs::remove_dir_all(root)
    }

    #[test]
    fn a_bin_directory_tests_entry_is_a_binary() {
        for rel in ["src/bin/tests.rs", "src/bin/tests/main.rs"] {
            let result = check_test_path(Path::new("/nonexistent"), Path::new(rel));
            assert!(
                matches!(result, Err(TestPathError::AutoBinary { .. })),
                "{rel}: {result:?}"
            );
        }
    }
}
