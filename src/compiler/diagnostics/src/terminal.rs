//! Terminal-safe text: the one sanitiser every crate that prints untrusted text uses.
//!
//! It lives in this lowest shared crate so a compiler stage that carries a
//! foreign string into a user-facing refusal (a dependency name, a file label,
//! a child process's stderr) parses it into [`TerminalSafe`] where the value is
//! built, with the same rules the CLI applies to every message it prints.

use std::fmt;
use std::ops::RangeInclusive;

/// Characters that reorder, hide, or break the visible text without being control bytes.
///
/// Exactly the Unicode `Cf` (format) category plus the two `Zl`/`Zp` line and
/// paragraph separators: the bidirectional marks, embeddings, overrides, and
/// isolates; the zero-width space, joiners, and word joiner; the invisible
/// operators and deprecated format controls; the byte-order mark; the
/// prepended-number and annotation marks of Arabic, Syriac, Kaithi, Egyptian
/// hieroglyphs, shorthand, and musical notation; and the tag block, denied
/// whole so a tag assigned later is already covered.
///
/// A value carrying one could make the terminal show text in an order other
/// than the bytes', open a line the CLI never wrote, or hide characters that
/// change what a name means, so [`TerminalSafe`] drops each of them. No
/// CLI message relies on a zero-width joiner, so it is dropped too. A test
/// checks the table against the Unicode general-category data.
pub const DENIED_FORMAT_CHARS: &[RangeInclusive<char>] = &[
    '\u{00AD}'..='\u{00AD}',   // SOFT HYPHEN
    '\u{0600}'..='\u{0605}',   // ARABIC NUMBER SIGN .. NUMBER MARK ABOVE
    '\u{061C}'..='\u{061C}',   // ARABIC LETTER MARK
    '\u{06DD}'..='\u{06DD}',   // ARABIC END OF AYAH
    '\u{070F}'..='\u{070F}',   // SYRIAC ABBREVIATION MARK
    '\u{0890}'..='\u{0891}',   // ARABIC POUND / PIASTRE MARK ABOVE
    '\u{08E2}'..='\u{08E2}',   // ARABIC DISPUTED END OF AYAH
    '\u{180E}'..='\u{180E}',   // MONGOLIAN VOWEL SEPARATOR
    '\u{200B}'..='\u{200F}',   // ZERO WIDTH SPACE, NON-JOINER, JOINER, LRM, RLM
    '\u{2028}'..='\u{2029}',   // LINE / PARAGRAPH SEPARATOR
    '\u{202A}'..='\u{202E}',   // bidi EMBEDDINGs, POP, OVERRIDEs
    '\u{2060}'..='\u{2064}',   // WORD JOINER, invisible operators
    '\u{2066}'..='\u{206F}',   // bidi ISOLATEs, deprecated format controls
    '\u{FEFF}'..='\u{FEFF}',   // ZERO WIDTH NO-BREAK SPACE (BOM)
    '\u{FFF9}'..='\u{FFFB}',   // INTERLINEAR ANNOTATION controls
    '\u{110BD}'..='\u{110BD}', // KAITHI NUMBER SIGN
    '\u{110CD}'..='\u{110CD}', // KAITHI NUMBER SIGN ABOVE
    '\u{13430}'..='\u{1343F}', // EGYPTIAN HIEROGLYPH format controls
    '\u{1BCA0}'..='\u{1BCA3}', // SHORTHAND FORMAT controls
    '\u{1D173}'..='\u{1D17A}', // MUSICAL SYMBOL BEGIN/END controls
    '\u{E0000}'..='\u{E007F}', // TAG block
];

/// Whether `c` is one of the [`DENIED_FORMAT_CHARS`].
#[must_use]
pub fn is_denied_format_char(c: char) -> bool {
    DENIED_FORMAT_CHARS.iter().any(|range| range.contains(&c))
}

/// Whether `c` reorders, hides, or breaks visible text: `Cc ∪ Cf ∪ Zl ∪ Zp`.
///
/// Every control character (C0, `DEL`, C1) plus the [`DENIED_FORMAT_CHARS`].
/// The one predicate an identity-name constructor refuses and a print sink
/// escapes or drops.
#[must_use]
pub fn is_display_hazard(c: char) -> bool {
    c.is_control() || is_denied_format_char(c)
}

/// The first display hazard in a name: which code point, at which character.
///
/// Its [`fmt::Display`] is the one teaching hint every refusal of a hazardous
/// name renders, ASCII only so the hint itself carries no hazard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayHazard {
    ch: char,
    position: usize,
}

impl DisplayHazard {
    /// The first [`is_display_hazard`] character in `raw`, if any.
    #[must_use]
    pub fn find(raw: &str) -> Option<Self> {
        raw.chars()
            .enumerate()
            .find(|&(_, c)| is_display_hazard(c))
            .map(|(index, ch)| Self {
                ch,
                position: index.saturating_add(1),
            })
    }

    /// The hazardous code point.
    #[must_use]
    pub const fn ch(self) -> char {
        self.ch
    }

    /// The 1-based position of the hazard, counted in characters.
    #[must_use]
    pub const fn position(self) -> usize {
        self.position
    }
}

impl fmt::Display for DisplayHazard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "character {} is U+{:04X}, an invisible or text-reordering code point, so the name \
             would print differently from what is compared; retype it without that character",
            self.position,
            u32::from(self.ch)
        )
    }
}

/// Text that has been proven safe to write to a terminal.
///
/// No ANSI escape sequences, no C0/C1 control bytes, no `DEL`, no
/// [`DENIED_FORMAT_CHARS`], only printable characters plus the two layout
/// whitespaces (`\n`, `\t`) the gutter and terminal handle safely.
///
/// A crafted string laced with ANSI escapes or control bytes could move the
/// cursor, recolour or erase lines, or hide text, turning a diagnostic into a
/// spoofing/injection surface. `TerminalSafe` is the typed boundary: construct
/// it ONCE from the untrusted string, and every downstream renderer takes a
/// `TerminalSafe` rather than a bare `&str`, so the unsanitised form is
/// unrepresentable past it. Parse, don't validate.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TerminalSafe(String);

impl TerminalSafe {
    /// Sanitise `raw` into terminal-safe text.
    ///
    /// Drops every ANSI escape sequence (a lone `ESC`, a CSI `ESC [ … final`, or
    /// an OSC `ESC ] … BEL/ST`) whole, and every remaining control byte (C0,
    /// `DEL`, C1) and [`DENIED_FORMAT_CHARS`] entry, keeping only `\n` and `\t`.
    /// A sequence never spans a line: a `\n` inside an unterminated CSI or OSC
    /// ends it and is kept, so one hostile value cannot swallow the lines that
    /// follow it. Other printable text passes through untouched.
    #[must_use]
    pub fn sanitize(raw: &str) -> Self {
        let mut out = String::with_capacity(raw.len());
        let mut chars = raw.chars();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                match chars.clone().next() {
                    Some('[') => {
                        // CSI (`ESC [`) runs until a final byte in 0x40..=0x7e.
                        chars.next();
                        for seq in chars.by_ref() {
                            if seq == '\n' {
                                out.push('\n');
                                break;
                            }
                            if ('\u{40}'..='\u{7e}').contains(&seq) {
                                break;
                            }
                        }
                    }
                    Some(']') => {
                        // OSC (`ESC ]`) runs until BEL (0x07) or ST (`ESC \`).
                        chars.next();
                        while let Some(seq) = chars.next() {
                            if seq == '\n' {
                                out.push('\n');
                                break;
                            }
                            if seq == '\u{7}' {
                                break;
                            }
                            if seq == '\u{1b}' {
                                if chars.clone().next() == Some('\\') {
                                    chars.next();
                                }
                                break;
                            }
                        }
                    }
                    // A lone `ESC` before a line break drops only itself.
                    Some('\n') | None => {}
                    Some(_) => {
                        chars.next();
                    }
                }
                continue;
            }
            if c == '\n' || c == '\t' || !is_display_hazard(c) {
                out.push(c);
            }
        }
        Self(out)
    }

    /// The sanitised block text, newlines kept for a renderer that gutters each line.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Sanitise a borrowed string; see [`TerminalSafe::sanitize`].
impl From<&str> for TerminalSafe {
    fn from(raw: &str) -> Self {
        Self::sanitize(raw)
    }
}

/// Sanitise an owned string; see [`TerminalSafe::sanitize`].
impl From<String> for TerminalSafe {
    fn from(raw: String) -> Self {
        Self::sanitize(&raw)
    }
}

/// Text that has been proven safe to write as a single terminal line.
///
/// Built from [`TerminalSafe`] by also dropping `\n` and `\t`: the two
/// layout whitespaces `TerminalSafe` keeps for a block renderer would, on a
/// single line, either forge a second output line or misalign a fixed-width
/// column. A dependency name, an extracted library name, or a recorded trace
/// step is untrusted text placed into exactly one line, so it is parsed into
/// `TerminalLine` once at that boundary rather than hand-stripped per caller.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TerminalLine(String);

impl TerminalLine {
    /// Sanitise `raw` into one terminal-safe line: no ANSI, no control byte,
    /// no [`DENIED_FORMAT_CHARS`] entry, and no `\n` or `\t`.
    #[must_use]
    pub fn sanitize(raw: &str) -> Self {
        let safe = TerminalSafe::sanitize(raw);
        let line: String = safe
            .as_str()
            .chars()
            .filter(|&c| c != '\n' && c != '\t')
            .collect();
        Self(line)
    }

    /// The sanitised line text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the sanitised line holds no characters.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Sanitise a borrowed string; see [`TerminalLine::sanitize`].
impl From<&str> for TerminalLine {
    fn from(raw: &str) -> Self {
        Self::sanitize(raw)
    }
}

/// Sanitise an owned string; see [`TerminalLine::sanitize`].
impl From<String> for TerminalLine {
    fn from(raw: String) -> Self {
        Self::sanitize(&raw)
    }
}

impl fmt::Display for TerminalLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Indent that opens every continuation line of a [`TerminalSafe`] rendered inline.
///
/// Wider than the output gutter, so a continuation line never starts where a
/// real output line does.
pub const CONTINUATION_INDENT: &str = "    ";

/// The inline form: every line after the first is indented by [`CONTINUATION_INDENT`].
///
/// An inline placeholder renders untrusted text inside a line the caller owns.
/// A newline in that text cannot open a fresh, forged output line: it only
/// continues the owning line, visibly indented. Block renderers that gutter
/// each line themselves take [`TerminalSafe::as_str`] instead.
impl fmt::Display for TerminalSafe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut lines = self.0.split('\n');
        if let Some(first) = lines.next() {
            f.write_str(first)?;
        }
        for line in lines {
            f.write_str("\n")?;
            f.write_str(CONTINUATION_INDENT)?;
            f.write_str(line)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hostile message laced with ANSI escapes and control bytes is stripped
    /// to printable text plus layout whitespace.
    #[test]
    fn terminal_safe_strips_ansi_and_control_bytes() {
        let hostile = "\u{1b}[31mred\u{1b}[0m\u{1b}]0;title\u{7}\rmoved\u{8}\u{7f}done\ttab\nline";
        let safe = TerminalSafe::sanitize(hostile);
        let s = safe.as_str();
        assert!(!s.contains('\u{1b}'), "no ESC survives: {s:?}");
        assert!(!s.contains('\r'), "carriage return dropped: {s:?}");
        assert!(!s.contains('\u{7}'), "bell dropped: {s:?}");
        assert!(!s.contains('\u{8}'), "backspace dropped: {s:?}");
        assert!(!s.contains('\u{7f}'), "DEL dropped: {s:?}");
        assert_eq!(s, "redmoveddone\ttab\nline");
    }

    /// Rendered inline, untrusted text cannot open a forged output line.
    #[test]
    fn terminal_safe_inline_form_indents_continuation_lines() {
        let forged = TerminalSafe::sanitize("oops\n\u{2713} published\n\u{1b}[2Kdone");
        assert_eq!(
            forged.to_string(),
            format!("oops\n{CONTINUATION_INDENT}\u{2713} published\n{CONTINUATION_INDENT}done")
        );
        assert_eq!(TerminalSafe::sanitize("one line").to_string(), "one line");
    }

    /// An OSC closed by ST (`ESC \\`) is dropped whole, terminator included,
    /// and the text after it survives.
    #[test]
    fn terminal_safe_strips_st_terminated_osc() {
        let safe = TerminalSafe::sanitize("a\u{1b}]8;;https://evil\u{1b}\\b");
        assert_eq!(safe.as_str(), "ab");
    }

    /// An unterminated OSC or CSI ends at the next line break: the break and
    /// every later line survive, so one value cannot swallow what follows it.
    #[test]
    fn an_unterminated_sequence_stops_at_the_line_break() {
        let osc = TerminalSafe::sanitize("dep\u{1b}]8;;evil\nnext line\nlast");
        assert_eq!(osc.as_str(), "dep\nnext line\nlast");
        // `;` and digits are CSI parameter bytes, never a final byte, so only
        // the line break can end this sequence.
        let csi = TerminalSafe::sanitize("dep\u{1b}[1;2;3\n42 kept");
        assert_eq!(csi.as_str(), "dep\n42 kept");
        let lone = TerminalSafe::sanitize("a\u{1b}\nb");
        assert_eq!(lone.as_str(), "a\nb");
    }

    /// Every denied format character — both ends of each range — is dropped,
    /// so a value cannot reorder, hide, or break the visible text.
    #[test]
    fn terminal_safe_strips_every_denied_format_char() {
        for range in DENIED_FORMAT_CHARS {
            for denied in [*range.start(), *range.end()] {
                let safe = TerminalSafe::sanitize(&format!("a{denied}b"));
                assert_eq!(safe.as_str(), "ab", "{denied:?} survived");
            }
        }
        let spoof = TerminalSafe::sanitize("invoice\u{202E}fdp.exe");
        assert_eq!(spoof.as_str(), "invoicefdp.exe");
        let hidden = TerminalSafe::sanitize("req\u{200B}west\u{00AD}\u{FEFF}\u{E0041}\u{2060}");
        assert_eq!(hidden.as_str(), "reqwest");
    }

    /// The table denies every `Cf`, `Zl`, and `Zp` character and nothing a
    /// user could see: each denied character is one of those categories or
    /// still unassigned.
    #[test]
    fn denied_format_chars_match_the_unicode_format_category() {
        use unicode_general_category::{GeneralCategory, get_general_category};
        for c in char::MIN..=char::MAX {
            let category = get_general_category(c);
            let invisible = matches!(
                category,
                GeneralCategory::Format
                    | GeneralCategory::LineSeparator
                    | GeneralCategory::ParagraphSeparator
            );
            if invisible {
                assert!(
                    is_denied_format_char(c),
                    "{c:?} ({category:?}) is not denied"
                );
            }
            if is_denied_format_char(c) {
                assert!(
                    invisible || matches!(category, GeneralCategory::Unassigned),
                    "{c:?} ({category:?}) is denied but visible"
                );
            }
        }
    }

    /// Format characters outside the common bidi and zero-width set are dropped too.
    #[test]
    fn terminal_safe_strips_the_rarer_format_chars() {
        let hidden = "a\u{180E}\u{0600}\u{06DD}\u{070F}\u{08E2}\u{110BD}\u{110CD}\u{13430}\u{1BCA0}\u{1D173}b";
        assert_eq!(TerminalSafe::sanitize(hidden).as_str(), "ab");
    }

    /// Printable neighbours of the denied ranges pass through untouched.
    #[test]
    fn terminal_safe_keeps_printable_neighbours() {
        let kept = "\u{00AC}\u{00AE}\u{200A}\u{2010}\u{FEFC}\u{FFFC}\u{E0100}";
        assert_eq!(TerminalSafe::sanitize(kept).as_str(), kept);
    }

    /// A single line drops ANSI, control bytes, denied format chars, and the
    /// two layout whitespaces `TerminalSafe` would otherwise keep.
    #[test]
    fn terminal_line_drops_layout_whitespace_too() {
        let safe = TerminalLine::sanitize("a\nb\tc\x1b[31md\u{202e}");
        assert_eq!(safe.as_str(), "abcd");
        assert!(!safe.is_empty());
        assert!(TerminalLine::sanitize("\n\t").is_empty());
    }

    /// Every endpoint of the control and format ranges is a hazard, and each
    /// neighbour outside all of them is not.
    #[test]
    fn display_hazard_endpoints() {
        let control: [RangeInclusive<char>; 2] = ['\u{0}'..='\u{1F}', '\u{7F}'..='\u{9F}'];
        let ranges: Vec<&RangeInclusive<char>> =
            DENIED_FORMAT_CHARS.iter().chain(control.iter()).collect();
        let in_any = |c: char| ranges.iter().any(|range| range.contains(&c));
        for range in &ranges {
            let (lo, hi) = (u32::from(*range.start()), u32::from(*range.end()));
            assert!(is_display_hazard(*range.start()), "U+{lo:04X} is a hazard");
            assert!(is_display_hazard(*range.end()), "U+{hi:04X} is a hazard");
            let neighbours = [lo.checked_sub(1), hi.checked_add(1)];
            for c in neighbours.into_iter().flatten().filter_map(char::from_u32) {
                assert_eq!(
                    is_display_hazard(c),
                    in_any(c),
                    "neighbour U+{:04X}",
                    u32::from(c)
                );
            }
        }
        assert!(!is_display_hazard(' '));
        assert!(!is_display_hazard('\u{00AC}'));
        assert!(!is_display_hazard('\u{FFFC}'));
    }

    /// `find` reports the first hazard and its 1-based character position.
    #[test]
    fn display_hazard_find_reports_first_position() {
        let hit = DisplayHazard::find("ab\u{202E}c\u{200B}");
        assert_eq!(hit.map(DisplayHazard::ch), Some('\u{202E}'));
        assert_eq!(hit.map(DisplayHazard::position), Some(3));
        assert_eq!(DisplayHazard::find("plain name"), None);
        assert_eq!(DisplayHazard::find("Geo App"), None);
    }

    /// The rendered hint is ASCII and names the code point and its position.
    #[test]
    fn display_hazard_hint_is_ascii() {
        let hint = DisplayHazard::find("\u{E007F}x")
            .map(|hit| hit.to_string())
            .unwrap_or_default();
        assert!(hint.is_ascii(), "{hint:?}");
        assert!(hint.contains("U+E007F"), "{hint:?}");
        assert!(hint.contains("character 1"), "{hint:?}");
    }
}
