//! The grammar of an `ipe doc` term and of a served site path.
//!
//! A positional term routes by its spelling alone, through one total
//! function over the closed [`TermShape`]: never by what exists on disk, so
//! one input gives one route in every directory. A request path reaches the
//! served site only as a [`ServedName`], whose grammar admits no traversal,
//! escape or separator spelling.

use crate::doc_bundle::is_qualified;

/// A reserved syntax token that names a language construct's page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyntaxToken {
    /// The token as a user types it.
    pub text: &'static str,
    /// The stem of the `docs/constructs/<stem>.md` page that owns it.
    pub construct: &'static str,
}

/// One [`SyntaxToken`] row, its construct page proven present at build time.
///
/// The `include_str!` of the page breaks the build the moment the named page
/// is renamed or removed, so the table cannot drift from the construct stems.
macro_rules! token {
    ($text:literal => $stem:literal) => {{
        const _: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/constructs/",
            $stem,
            ".md"
        ));
        SyntaxToken {
            text: $text,
            construct: $stem,
        }
    }};
}

/// Every reserved syntax token a term may be, with the construct page it opens.
pub const TOKENS: [SyntaxToken; 2] = [token!("->" => "lambda"), token!("\\" => "lambda")];

/// What an `ipe doc` positional term is, decided by its spelling alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TermShape {
    /// A binary operator's text (`//`, `|>`, `::`).
    Operator,
    /// A reserved syntax token (`->`, `\`).
    Token(SyntaxToken),
    /// A `kind:key` term whose kind is known.
    Qualified,
    /// A dotted module name (`Ipe.List`).
    Module,
    /// A module member (`List.map`).
    Member,
    /// Any other key: a bare name, a diagnostic code, a quoted phrase.
    Word,
    /// A host path: a separator or drive colon, or any word beside a
    /// generate-only flag.
    Path,
}

impl TermShape {
    /// The shape of the trimmed `term`; `generate_flags` is whether `--out` or
    /// `--write-format` appears in the same invocation.
    #[must_use]
    pub fn of(term: &str, generate_flags: bool) -> Self {
        if ipe_syntax::BinOp::from_text(term).is_some() {
            return Self::Operator;
        }
        if let Some(token) = TOKENS.iter().find(|token| token.text == term) {
            return Self::Token(*token);
        }
        if is_qualified(term) && !generate_flags {
            return Self::Qualified;
        }
        if has_host_path_syntax(term) {
            return Self::Path;
        }
        if is_module_name(term) {
            return Self::Module;
        }
        if is_member_key(term) {
            return Self::Member;
        }
        if generate_flags {
            return Self::Path;
        }
        Self::Word
    }

    /// Whether a term of this shape is a symbol that may begin with `-`, so a
    /// leading `-` does not make it a flag.
    #[must_use]
    pub const fn is_symbolic(self) -> bool {
        matches!(self, Self::Operator | Self::Token(_))
    }
}

/// Whether `s` is a member key: an uppercase-led module path, then `.` and a
/// lowercase-led member (`List.map`, `Ipe.Time.unixMillis`).
fn is_member_key(s: &str) -> bool {
    s.chars().next().is_some_and(|c| c.is_ascii_uppercase()) && is_symbol_key(s)
}

/// Whether the last `.` segment of `s` starts lowercase, as a module's value
/// does (`List.map`), unlike a module name (`Ipe.List`).
#[must_use]
pub fn is_symbol_key(s: &str) -> bool {
    s.rsplit_once('.')
        .and_then(|(_, member)| member.chars().next())
        .is_some_and(|c| c.is_ascii_lowercase())
}

/// Whether every dot-separated segment of `s` is a module-name segment: an
/// ASCII-uppercase letter, then ASCII alphanumerics or `_`.
///
/// No separator, drive colon or other punctuation is a grammar character, so
/// a host path never satisfies it on any platform.
#[must_use]
pub fn is_module_name(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').all(|segment| {
            let mut chars = segment.chars();
            chars.next().is_some_and(|c| c.is_ascii_uppercase())
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

/// Whether `s` carries a host-path character: a separator (`/`, `\`) or a
/// drive colon (`:`), none of which a module name or bare key holds.
fn has_host_path_syntax(s: &str) -> bool {
    s.contains(['/', '\\', ':'])
}

/// The site file a request path names, parsed once at the serve boundary.
///
/// The root (`/`, or an empty path) is `index.html`. Any other path is one or
/// more `/`-separated segments, each non-empty, never `.` or `..`, and spelled
/// only with ASCII alphanumerics and `-`, `.`, `_`, `~`. A percent escape, a
/// backslash, a NUL or any other byte has no representation, so no spelling of
/// a traversal reaches the site map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedName(String);

/// The file the site root serves.
const ROOT_FILE: &str = "index.html";

impl ServedName {
    /// The name `request_path` names, its `?query` and `#fragment` dropped, or
    /// `None` when the path is outside the grammar.
    #[must_use]
    pub fn parse(request_path: &str) -> Option<Self> {
        let path = request_path
            .split(['?', '#'])
            .next()
            .unwrap_or(request_path);
        if path.is_empty() || path == "/" {
            return Some(Self(ROOT_FILE.to_owned()));
        }
        let rest = path.strip_prefix('/')?;
        rest.split('/')
            .all(is_served_segment)
            .then(|| Self(rest.to_owned()))
    }

    /// The site-map key.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Whether `segment` is one admitted path segment of a [`ServedName`].
fn is_served_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arrow_is_a_term_not_a_flag() {
        assert!(matches!(
            TermShape::of("->", false),
            TermShape::Token(SyntaxToken {
                construct: "lambda",
                ..
            })
        ));
        assert!(TermShape::of("->", false).is_symbolic());
    }

    #[test]
    fn backslash_is_a_term_not_a_path() {
        assert!(matches!(
            TermShape::of("\\", false),
            TermShape::Token(SyntaxToken {
                construct: "lambda",
                ..
            })
        ));
        assert_eq!(TermShape::of("a\\b", false), TermShape::Path);
    }

    #[test]
    fn token_table_matches_construct_stems() {
        for token in TOKENS {
            assert!(
                crate::doc_bundle::EMBEDDED_CONSTRUCTS
                    .get_file(format!("{}.md", token.construct))
                    .is_some(),
                "`{}` names construct `{}`, which has no page",
                token.text,
                token.construct
            );
            assert!(
                ipe_syntax::BinOp::from_text(token.text).is_none(),
                "`{}` is an operator, so its token row is unreachable",
                token.text
            );
        }
    }

    #[test]
    fn each_shape_is_decided_by_spelling() {
        let cases = [
            ("//", false, TermShape::Operator),
            ("-", false, TermShape::Operator),
            ("construct:case", false, TermShape::Qualified),
            ("construct:case", true, TermShape::Path),
            ("nokind:x", false, TermShape::Path),
            ("src/x", false, TermShape::Path),
            ("D:\\pkg", false, TermShape::Path),
            ("D:\\my-pkg", false, TermShape::Path),
            ("Users/alice.pkg", false, TermShape::Path),
            ("Ipe.List", false, TermShape::Module),
            ("Ipe.List", true, TermShape::Module),
            ("List.map", false, TermShape::Member),
            ("IPE-E0001", false, TermShape::Word),
            ("readFile", false, TermShape::Word),
            ("read file", false, TermShape::Word),
            ("Read file", false, TermShape::Word),
            ("pkg", true, TermShape::Path),
        ];
        for (term, generate_flags, want) in cases {
            assert_eq!(
                TermShape::of(term, generate_flags),
                want,
                "{term:?} generate_flags={generate_flags}"
            );
        }
    }

    #[test]
    fn served_name_root_is_index() {
        for root in ["", "/", "/?v=1", "/#top"] {
            assert_eq!(
                ServedName::parse(root).as_ref().map(ServedName::as_str),
                Some("index.html"),
                "{root:?}"
            );
        }
    }

    #[test]
    fn served_name_admits_site_files() {
        for (path, name) in [
            ("/Ipe-List.html", "Ipe-List.html"),
            ("/style.css?v=1", "style.css"),
            ("/module/index.html", "module/index.html"),
            ("/diagnostic/IPE-E0001.html#x", "diagnostic/IPE-E0001.html"),
        ] {
            assert_eq!(
                ServedName::parse(path).as_ref().map(ServedName::as_str),
                Some(name),
                "{path:?}"
            );
        }
    }

    #[test]
    fn served_name_refuses_traversal() {
        for path in [
            "/../x",
            "/%2e%2e/x",
            "/a//b",
            "/a\\b",
            "/\0",
            "/a%00",
            "/./x",
            "/a/..",
            "//x",
            "/a/",
            "x.html",
            "/a b",
        ] {
            assert_eq!(ServedName::parse(path), None, "{path:?}");
        }
    }
}
