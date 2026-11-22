//! Program-name newtype: the name of one program a project builds, parsed once
//! at manifest decode.
//!
//! A program name reaches CLI lines, `--json` reports and the audit report that
//! judges untrusted registry packages. [`ProgramName`] holds only a name the
//! shared name grammar ([`crate::package_name::judge`]) accepts, so every sink
//! receives one portable token whatever its own escaping does. The two
//! constructors are [`ProgramName::parse`] and the lift from an already parsed
//! [`PackageName`]; no other code can build one from a `String`.

use crate::package_name::{NameRefusal, PackageName};

/// The name of one program a project builds, proven to match the name grammar.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProgramName(String);

impl ProgramName {
    /// Parse a raw program name through the grammar package names use.
    ///
    /// # Errors
    /// The [`NameRefusal`] of the first grammar rule `raw` breaks.
    pub fn parse(raw: &str) -> Result<Self, NameRefusal> {
        crate::package_name::judge(raw).map(|()| Self(raw.to_owned()))
    }

    /// The name as text.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Why a program name is refused, in the program name's wording.
    #[must_use]
    pub fn refusal_reason(why: NameRefusal) -> crate::text::Message {
        match why {
            NameRefusal::Empty => crate::text::msg::program_name_empty(),
            NameRefusal::TooLong => crate::text::msg::program_name_too_long(&NameRefusal::MAX_LEN),
            NameRefusal::BadStart => crate::text::msg::program_name_bad_start(),
            NameRefusal::BadChar => crate::text::msg::program_name_bad_char(),
            NameRefusal::DoubledDash => crate::text::msg::program_name_doubled_dash(),
            NameRefusal::TrailingDash => crate::text::msg::program_name_trailing_dash(),
        }
    }
}

impl From<&PackageName> for ProgramName {
    /// The default program's name: the package's own, already parsed through the
    /// same grammar.
    fn from(package: &PackageName) -> Self {
        Self(package.as_str().to_owned())
    }
}

impl std::fmt::Display for ProgramName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every case the grammar tests drive, accepted and refused alike.
    const CORPUS: &[&str] = &[
        "app",
        "storefront",
        "a1-b2",
        "9lives",
        "",
        "Admin",
        "aDmin",
        "admin_tool",
        "admin.v2",
        "a/b",
        "a\\b",
        "a b",
        "a\nb",
        "a\u{1b}[2J",
        "a`b",
        "c\u{e4}fe",
        "\u{430}dmin",
        "-a",
        "a-",
        "a--b",
        "..",
    ];

    #[test]
    fn accepts_the_longest_name() {
        let name = "a".repeat(NameRefusal::MAX_LEN);
        assert_eq!(ProgramName::parse(&name).map(|n| n.0), Ok(name));
    }

    #[test]
    fn refuses_one_past_the_length_bound() {
        let name = "a".repeat(NameRefusal::MAX_LEN + 1);
        assert_eq!(ProgramName::parse(&name), Err(NameRefusal::TooLong));
    }

    #[test]
    fn refuses_empty() {
        assert_eq!(ProgramName::parse(""), Err(NameRefusal::Empty));
    }

    #[test]
    fn refuses_an_uppercase_first_character() {
        assert_eq!(ProgramName::parse("Admin"), Err(NameRefusal::BadStart));
    }

    #[test]
    fn refuses_every_character_outside_the_grammar() {
        for raw in [
            "aDmin", "a_b", "a.b", "a/b", "a\\b", "a b", "a\nb", "a\u{1b}", "a`b", "c\u{e4}",
        ] {
            assert_eq!(
                ProgramName::parse(raw),
                Err(NameRefusal::BadChar),
                "{raw:?} must be refused for its character"
            );
        }
    }

    #[test]
    fn refuses_a_homoglyph_first_character() {
        assert_eq!(
            ProgramName::parse("\u{430}dmin"),
            Err(NameRefusal::BadStart),
            "a Cyrillic `а` is not the ASCII `a`"
        );
    }

    #[test]
    fn refuses_a_leading_dash() {
        assert_eq!(ProgramName::parse("-a"), Err(NameRefusal::BadStart));
    }

    #[test]
    fn refuses_a_trailing_dash() {
        assert_eq!(ProgramName::parse("a-"), Err(NameRefusal::TrailingDash));
    }

    #[test]
    fn refuses_a_doubled_dash() {
        assert_eq!(ProgramName::parse("a--b"), Err(NameRefusal::DoubledDash));
    }

    #[test]
    fn judge_is_shared() {
        let long = "a".repeat(NameRefusal::MAX_LEN + 1);
        for raw in CORPUS.iter().copied().chain([long.as_str()]) {
            assert_eq!(
                PackageName::parse(raw).is_ok(),
                ProgramName::parse(raw).is_ok(),
                "package and program names must share one grammar for {raw:?}"
            );
        }
    }

    #[test]
    fn the_default_program_takes_the_package_name() {
        let package = PackageName::parse("shop").expect("a package name");
        assert_eq!(ProgramName::from(&package).as_str(), "shop");
    }
}

#[cfg(test)]
mod constructor_scan {
    //! Pins that a program name is built only by its parser.
    //!
    //! `ProgramName` holds only a name the shared name grammar accepts. Its field
    //! is private, so outside `src/program_name.rs` the compiler already refuses
    //! the tuple constructor; this scan is the second, independent gate. It lexes
    //! every `.rs` file under `src/` and refuses the token pair `ProgramName (`
    //! anywhere but `src/program_name.rs`, so a value cannot be minted from an
    //! unparsed `String` even by code moved into that module's scope.

    use std::path::{Path, PathBuf};
    use std::str::FromStr as _;

    use proc_macro2::{Delimiter, TokenStream, TokenTree};

    /// The type whose tuple constructor is confined.
    const TYPE: &str = "ProgramName";

    /// The one file allowed to call the constructor, relative to `src/`.
    const OWNER: &str = "program_name.rs";

    /// The deepest directory level below `src/` the walk descends.
    const MAX_DEPTH: usize = 32;

    /// Every `.rs` file under `dir`, at most [`MAX_DEPTH`] levels below it.
    #[allow(clippy::expect_used)] // test helper: an unreadable source tree IS the failure
    fn rust_files(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
        assert!(depth <= MAX_DEPTH, "{} is nested too deep", dir.display());
        let entries = std::fs::read_dir(dir).expect("read a source directory");
        for entry in entries {
            let entry = entry.expect("read a directory entry");
            let path = entry.path();
            let kind = entry.file_type().expect("read an entry's type");
            if kind.is_dir() {
                rust_files(&path, depth + 1, out);
            } else if kind.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    /// How many times `tokens` holds `ProgramName` followed by a parenthesised group.
    fn constructor_calls(tokens: TokenStream) -> usize {
        let mut count = 0;
        let mut previous_is_type = false;
        for tree in tokens {
            if let TokenTree::Group(group) = &tree {
                if previous_is_type && group.delimiter() == Delimiter::Parenthesis {
                    count += 1;
                }
                count += constructor_calls(group.stream());
            }
            previous_is_type = matches!(&tree, TokenTree::Ident(ident) if ident == TYPE);
        }
        count
    }

    #[test]
    fn program_name_is_built_only_by_its_parser() {
        let src = e2e_support::manifest_dir!().join("src");
        let mut files = Vec::new();
        rust_files(&src, 0, &mut files);
        let owner = src.join(OWNER);
        assert!(files.contains(&owner), "{OWNER} defines the type");
        let mut offenders = Vec::new();
        for file in &files {
            let text = std::fs::read_to_string(file).expect("read a source file");
            let tokens = TokenStream::from_str(&text).expect("a source file lexes");
            let calls = constructor_calls(tokens);
            if file == &owner {
                assert!(calls > 0, "the scan sees the definition in {OWNER}");
            } else if calls > 0 {
                offenders.push(file.display().to_string());
            }
        }
        assert!(
            offenders.is_empty(),
            "`{TYPE}(` outside src/{OWNER}: {offenders:?}"
        );
    }

    #[test]
    fn the_scan_sees_a_constructor_call() {
        let built = TokenStream::from_str("fn f() -> ProgramName { ProgramName(String::new()) }")
            .expect("lexes");
        assert_eq!(constructor_calls(built), 1);
        let parsed = TokenStream::from_str("fn f() { ProgramName::parse(\"a\"); }").expect("lexes");
        assert_eq!(constructor_calls(parsed), 0);
    }
}
