//! Production module and include sources, and the refusals they can earn.
//!
//! A production `#[path = "…"]` module or `include!("…")` compiles another file
//! into the build. Its literal is judged once, as written, into either a legal
//! source the caller resolves and scans, or a refusal: test code that
//! path-based checks skip, a value that is not a plain string literal, a
//! renamed `include`, or a literal that is absolute, ambiguous across
//! platforms, not Rust, or under an emitted-program `templates` directory. A
//! source that cannot be judged is refused, so an unreadable source never reads
//! as a safe one.

use std::fmt;
use std::path::{Component, Path};

use crate::manifest::names_test_code;
use crate::test_path::TEMPLATE_DIR;

/// A production source refused because it cannot be audited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestPathInclude {
    /// 1-based line of the source literal, macro, or declaration.
    pub line: usize,
    pub form: IncludeForm,
    pub target: IncludeTarget,
}

/// How a file names another source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncludeForm {
    /// `#[path = "…"]`, directly or inside a `cfg_attr`.
    PathAttr,
    /// `include!("…")`.
    IncludeMacro,
    /// `mod name;`, resolved by the compiler to `name.rs` or `name/mod.rs`.
    ModDecl,
}

/// Why a production source is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncludeTarget {
    /// A source naming test code.
    TestPath(String),
    /// A value that is not a plain string literal, so its target is unknown.
    Opaque(String),
    /// The `include` macro under another name, so its uses cannot be traced.
    Aliased(String),
    /// A plain string literal whose target cannot be audited.
    Refused { path: String, reason: PathRefusal },
}

/// Why a plain string-literal source cannot be audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRefusal {
    Absolute,
    Separator,
    TrailingDotOrSpace,
    NotRust,
    EscapesRoot,
    Template,
    Missing,
    InlineModule,
}

/// A legal production source the caller must resolve and scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncludedSource {
    /// 1-based line of the source literal or macro.
    pub line: usize,
    pub form: IncludeForm,
    /// The decoded literal, as written.
    pub literal: String,
    /// Names of the inline modules enclosing the source, outermost first.
    pub inline_mods: Vec<String>,
}

impl fmt::Display for IncludeForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PathAttr => "#[path]",
            Self::IncludeMacro => "include!",
            Self::ModDecl => "mod declaration",
        })
    }
}

impl fmt::Display for PathRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Absolute => "is absolute",
            Self::Separator => "holds a `\\` or `:` another platform reads as a separator",
            Self::TrailingDotOrSpace => "has a component ending in `.` or a space",
            Self::NotRust => "does not name a `.rs` file",
            Self::EscapesRoot => "escapes the scanned root",
            Self::Template => "lies under an emitted-program `templates` directory",
            Self::Missing => "names no existing file",
            Self::InlineModule => {
                "relocates an inline module, whose nested paths the scan does not resolve"
            }
        })
    }
}

impl fmt::Display for TestPathInclude {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.target {
            IncludeTarget::TestPath(path) => write!(
                f,
                "line {}: production {} names test code `{path}`, which path-based checks skip",
                self.line, self.form
            ),
            IncludeTarget::Opaque(value) => write!(
                f,
                "line {}: production {} source `{value}` is not a plain string literal, so its target is unknown",
                self.line, self.form
            ),
            IncludeTarget::Aliased(name) => write!(
                f,
                "line {}: production `{name}` is renamed or re-exported, so its includes cannot be traced",
                self.line
            ),
            IncludeTarget::Refused { path, reason } => write!(
                f,
                "line {}: production {} source `{path}` {reason}",
                self.line, self.form
            ),
        }
    }
}

/// Judge a decoded source literal as written, before any resolution.
///
/// # Errors
///
/// The refusal when the literal is absolute, holds a character another platform
/// reads as a separator, has a component Windows silently trims, does not name
/// a `.rs` file, names test code, or lies under a `templates` directory.
pub fn judge_literal(literal: &str) -> Result<(), IncludeTarget> {
    let refused = |reason| {
        Err(IncludeTarget::Refused {
            path: literal.to_owned(),
            reason,
        })
    };
    let path = Path::new(literal);
    if path.has_root() || path.is_absolute() {
        return refused(PathRefusal::Absolute);
    }
    if literal.contains(['\\', ':']) {
        return refused(PathRefusal::Separator);
    }
    let normal = || {
        path.components().filter_map(|c| match c {
            Component::Normal(name) => Some(name.to_string_lossy()),
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => None,
        })
    };
    if normal().any(|name| name.ends_with(['.', ' '])) {
        return refused(PathRefusal::TrailingDotOrSpace);
    }
    if path.extension().is_none_or(|ext| ext != "rs") {
        return refused(PathRefusal::NotRust);
    }
    if names_test_code(path) {
        return Err(IncludeTarget::TestPath(literal.to_owned()));
    }
    if normal().any(|name| name.eq_ignore_ascii_case(TEMPLATE_DIR)) {
        return refused(PathRefusal::Template);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan_source;

    fn includes(src: &str) -> Vec<TestPathInclude> {
        let scan = scan_source(src);
        assert!(scan.is_ok(), "{src:?} must parse: {scan:?}");
        scan.map(|s| s.test_path_includes).unwrap_or_default()
    }

    fn sources(src: &str) -> Vec<IncludedSource> {
        let scan = scan_source(src);
        assert!(scan.is_ok(), "{src:?} must parse: {scan:?}");
        scan.map(|s| s.included_sources).unwrap_or_default()
    }

    #[test]
    fn production_sources_naming_test_code_are_reported() {
        for (src, form) in [
            (
                "#[path = \"tests/prod.rs\"]\npub mod prod;",
                IncludeForm::PathAttr,
            ),
            (
                "#[path = r\"tests/prod.rs\"]\nmod prod;",
                IncludeForm::PathAttr,
            ),
            (
                "#[path = r#\"a/tests.rs\"#]\nmod prod;",
                IncludeForm::PathAttr,
            ),
            (
                "#[cfg_attr(unix, path = \"tests/prod.rs\")]\nmod prod;",
                IncludeForm::PathAttr,
            ),
            (
                "#[cfg_attr(not(test), path = \"tests/prod.rs\")]\nmod prod;",
                IncludeForm::PathAttr,
            ),
            (
                "#[cfg_attr(unix, cfg_attr(linux, path = \"tests/p.rs\"))]\nmod p;",
                IncludeForm::PathAttr,
            ),
            (
                "#[cfg(not(test))]\n#[path = \"tests/p.rs\"]\nmod p;",
                IncludeForm::PathAttr,
            ),
            (
                "#[path = \"t\\u{65}sts/p.rs\"]\nmod p;",
                IncludeForm::PathAttr,
            ),
            ("include!(\"tests/prod.rs\");", IncludeForm::IncludeMacro),
            ("include!(\"t\\x65sts/p.rs\");", IncludeForm::IncludeMacro),
            (
                "fn f() { include!(\"../tests/prod.rs\") }",
                IncludeForm::IncludeMacro,
            ),
            (
                "mod m { include!{\"tests.rs\"} }",
                IncludeForm::IncludeMacro,
            ),
            (
                "#[cfg(test)]\nuse x;\ninclude!(\"tests/p.rs\");",
                IncludeForm::IncludeMacro,
            ),
            (
                "fn f(x: u8) { match x { #[cfg(test)] 0 => {}, _ => { include!(\"tests/p.rs\"); } } }",
                IncludeForm::IncludeMacro,
            ),
            (
                "macro_rules! m { () => { include!(\"tests/p.rs\") }; }",
                IncludeForm::IncludeMacro,
            ),
            ("mod tests;", IncludeForm::ModDecl),
            ("pub mod Tests;", IncludeForm::ModDecl),
            (
                "#[test]\nfn t() { include!(\"tests/p.rs\"); }",
                IncludeForm::IncludeMacro,
            ),
        ] {
            let found = includes(src);
            assert!(
                matches!(found.as_slice(), [TestPathInclude { form: f, target: IncludeTarget::TestPath(_), .. }] if *f == form),
                "{src:?} -> {found:?}"
            );
        }
    }

    #[test]
    fn opaque_sources_are_reported() {
        for src in [
            "include!(concat!(\"tests/\", \"p.rs\"));",
            "#[path = SOME_CONST]\nmod p;",
            "#[path = \"p.rs\"suffix]\nmod p;",
        ] {
            let found = includes(src);
            assert!(
                matches!(
                    found.as_slice(),
                    [TestPathInclude {
                        target: IncludeTarget::Opaque(_),
                        ..
                    }]
                ),
                "{src:?} -> {found:?}"
            );
        }
    }

    #[test]
    fn renamed_include_is_refused() {
        for src in [
            "use core::include as grab;\nfn f() { grab!(\"tests/prod.rs\"); }",
            "pub use core::include;",
            "use core::{include as g};",
        ] {
            let found = includes(src);
            assert!(
                found
                    .iter()
                    .any(|i| matches!(&i.target, IncludeTarget::Aliased(_))),
                "{src:?} -> {found:?}"
            );
        }
    }

    #[test]
    fn illegal_literals_are_refused() {
        for (src, want) in [
            ("#[path = \"/etc/x.rs\"]\nmod p;", PathRefusal::Absolute),
            ("include!(\"a\\\\b.rs\");", PathRefusal::Separator),
            ("include!(\"c:x.rs\");", PathRefusal::Separator),
            ("include!(\"a./b.rs\");", PathRefusal::TrailingDotOrSpace),
            ("include!(\"a /b.rs\");", PathRefusal::TrailingDotOrSpace),
            ("include!(\"table.txt\");", PathRefusal::NotRust),
            ("include!(\"\");", PathRefusal::NotRust),
            ("include!(\"templates/x.rs\");", PathRefusal::Template),
            ("include!(\"a/Templates/x.rs\");", PathRefusal::Template),
            ("#[path = \"x.rs\"]\nmod m {}", PathRefusal::InlineModule),
        ] {
            let found = includes(src);
            assert!(
                matches!(
                    found.as_slice(),
                    [TestPathInclude { target: IncludeTarget::Refused { reason, .. }, .. }] if *reason == want
                ),
                "{src:?} -> {found:?}"
            );
        }
    }

    #[test]
    fn test_only_and_production_sources_are_not_reported() {
        for src in [
            "#[path = \"imp/unix.rs\"]\nmod imp;",
            "#[path = \"contests.rs\"]\nmod c;",
            "include!(\"generated/table.rs\");",
            "#[cfg(test)]\n#[path = \"tests/p.rs\"]\nmod p;",
            "#[path = \"tests/p.rs\"]\n#[cfg(test)]\nmod p;",
            "#[cfg(all(test, unix))]\ninclude!(\"tests/p.rs\");",
            "#[cfg_attr(test, path = \"tests/p.rs\")]\nmod p;",
            "#[cfg(test)]\nmod t {\n    include!(\"tests/p.rs\");\n}",
            "#[cfg(test)]\n#[test]\nfn t() { include!(\"tests/p.rs\"); }",
            "#[cfg(test)]\nmod tests;",
            "const S: &str = \"include!(\\\"tests/p.rs\\\")\";",
            "include_str!(\"tests/data.txt\");",
            "use core::include;",
        ] {
            let found = includes(src);
            assert!(found.is_empty(), "{src:?} -> {found:?}");
        }
    }

    #[test]
    fn legal_sources_are_handed_to_the_caller() {
        let found = sources(
            "mod outer {\n    include!(\"../gen/t.rs\");\n}\n#[path = \"imp/unix.rs\"]\nmod imp;",
        );
        assert!(
            matches!(
                found.as_slice(),
                [
                    IncludedSource { line: 2, form: IncludeForm::IncludeMacro, literal: a, inline_mods: m },
                    IncludedSource { line: 4, form: IncludeForm::PathAttr, literal: b, inline_mods: n },
                ] if a == "../gen/t.rs" && m == &["outer"] && b == "imp/unix.rs" && n.is_empty()
            ),
            "{found:?}"
        );
    }

    #[test]
    fn a_test_only_item_does_not_shield_its_production_sibling() {
        let found = includes("#[cfg(test)]\nmod t {}\n#[path = \"tests/p.rs\"]\nmod p;");
        assert_eq!(found.len(), 1, "{found:?}");
    }
}
