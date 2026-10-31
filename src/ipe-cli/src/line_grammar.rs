//! The closed line grammar every hand-read `key = value` file shares.
//!
//! A line is exactly one of: blank, a `#` comment free of display hazards, the
//! file's one table header, or `<key> = <value>` whose key is drawn from a closed
//! enum the file's writer also renders from. Anything else is a [`LineFault`],
//! never a skipped line. Only [`LINE_BLANKS`] are trimmed, so a Unicode
//! separator or format character around a header or key stays in the line and
//! is refused with it.

use ipe_diagnostics::terminal::DisplayHazard;

/// The blanks a line may carry around its content: space, tab, and the `\r` a
/// final CRLF-less line keeps.
pub const LINE_BLANKS: [char; 3] = [' ', '\t', '\r'];

/// The longest unknown key a refusal echoes, in characters.
pub const MAX_KEY_ECHO: usize = 64;

/// A 1-based line number in a read text file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextLine(usize);

impl TextLine {
    /// The line at 0-based `index` in the text.
    #[must_use]
    pub const fn at(index: usize) -> Self {
        Self(index.saturating_add(1))
    }

    /// The line numbered `number` (1-based), for tests naming a line.
    #[cfg(test)]
    #[must_use]
    pub const fn numbered(number: usize) -> Self {
        Self(number)
    }
}

impl std::fmt::Display for TextLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A closed key set: the keys one file's writer renders and its reader admits.
pub trait LineKey: Copy {
    /// The key spelled exactly `raw`, if any.
    fn parse(raw: &str) -> Option<Self>;
}

/// One line, classified by the closed grammar.
#[derive(Debug, PartialEq, Eq)]
pub enum LineShape<'a, K> {
    /// A blank line or a hazard-free `#` comment.
    Ignorable,
    /// The file's table header.
    Header,
    /// A `key = value` field; the value is trimmed of [`LINE_BLANKS`] only, its
    /// shape left to the key's own parser.
    Field(K, &'a str),
}

/// Why a line is outside the grammar.
#[derive(Debug, PartialEq, Eq)]
pub enum LineFault {
    /// Not blank, a comment, the header, or a `key = value` field.
    Unrecognised,
    /// A field whose key is outside the closed set; the key is cut to
    /// [`MAX_KEY_ECHO`] characters.
    UnknownKey(String),
    /// A comment holding a control, bidi, or invisible character: a viewer
    /// shows such a comment differently from what the reader ignores.
    HiddenCharacter(DisplayHazard),
}

/// Classify one raw line against the grammar whose table header is `header`.
///
/// # Errors
/// A [`LineFault`] for every shape the grammar does not admit.
pub fn classify<'a, K: LineKey>(raw: &'a str, header: &str) -> Result<LineShape<'a, K>, LineFault> {
    let text = raw.trim_matches(LINE_BLANKS);
    if text.is_empty() {
        return Ok(LineShape::Ignorable);
    }
    if text.starts_with('#') {
        return DisplayHazard::find(text).map_or(Ok(LineShape::Ignorable), |hazard| {
            Err(LineFault::HiddenCharacter(hazard))
        });
    }
    if text == header {
        return Ok(LineShape::Header);
    }
    if text.starts_with('[') {
        return Err(LineFault::Unrecognised);
    }
    let Some((raw_key, raw_value)) = text.split_once('=') else {
        return Err(LineFault::Unrecognised);
    };
    let raw_key = raw_key.trim_matches(LINE_BLANKS);
    let key = K::parse(raw_key)
        .ok_or_else(|| LineFault::UnknownKey(raw_key.chars().take(MAX_KEY_ECHO).collect()))?;
    Ok(LineShape::Field(key, raw_value.trim_matches(LINE_BLANKS)))
}

/// The inside of exactly one double-quoted string holding no other `"`, or
/// `None` for an unquoted value or one with text after its closing quote.
#[must_use]
pub fn quoted(value: &str) -> Option<&str> {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .filter(|v| !v.contains('"'))
}

#[cfg(test)]
mod tests {
    use super::{LineFault, LineKey, LineShape, TextLine, classify, quoted};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Only;

    impl LineKey for Only {
        fn parse(raw: &str) -> Option<Self> {
            (raw == "only").then_some(Self)
        }
    }

    #[test]
    fn every_admitted_shape_classifies() {
        assert_eq!(classify::<Only>("  ", "[[t]]"), Ok(LineShape::Ignorable));
        assert_eq!(
            classify::<Only>("# note", "[[t]]"),
            Ok(LineShape::Ignorable)
        );
        assert_eq!(classify::<Only>("[[t]]\r", "[[t]]"), Ok(LineShape::Header));
        assert_eq!(
            classify::<Only>("only = \"v\"", "[[t]]"),
            Ok(LineShape::Field(Only, "\"v\""))
        );
    }

    #[test]
    fn every_other_shape_is_refused() {
        assert_eq!(
            classify::<Only>("garbage", "[[t]]"),
            Err(LineFault::Unrecognised)
        );
        assert_eq!(
            classify::<Only>("[other]", "[[t]]"),
            Err(LineFault::Unrecognised)
        );
        assert_eq!(
            classify::<Only>("\u{2028}[[t]]", "[[t]]"),
            Err(LineFault::Unrecognised)
        );
        assert_eq!(
            classify::<Only>("other = \"v\"", "[[t]]"),
            Err(LineFault::UnknownKey("other".to_owned()))
        );
        assert!(matches!(
            classify::<Only>("# a\u{202e}b", "[[t]]"),
            Err(LineFault::HiddenCharacter(_))
        ));
    }

    #[test]
    fn quoted_admits_one_string_only() {
        assert_eq!(quoted("\"v\""), Some("v"));
        assert_eq!(quoted("v"), None);
        assert_eq!(quoted("\"v\" x"), None);
        assert_eq!(quoted("\"a\"b\""), None);
    }

    #[test]
    fn a_line_number_is_one_based() {
        assert_eq!(TextLine::at(0), TextLine::numbered(1));
        assert_eq!(TextLine::at(4).to_string(), "5");
    }
}
