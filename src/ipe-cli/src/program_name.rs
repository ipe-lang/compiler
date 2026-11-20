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
