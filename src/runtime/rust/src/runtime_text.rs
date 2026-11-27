//! The text the runtime shows an end user: one row per [`TextId`], one catalog
//! per [`Locale`].
//!
//! A notice reaches its sink only by id: the browser client draws a row
//! through its one text sink, never a string written at the call. Every row
//! of every locale passes [`text_defect`] at build time, so an empty, an
//! over-long, a control-bearing or a reordering text does not compile.
//!
//! The bound is the one predicate every row passes:
//!
//! ```
//! use ipe_runtime_rust::runtime_text::admits;
//! const _: () = assert!(admits("Connection lost \u{2014} refresh to retry"));
//! ```
//!
//! An empty text is refused:
//!
//! ```compile_fail,E0080
//! use ipe_runtime_rust::runtime_text::admits;
//! const _: () = assert!(admits(""));
//! ```
//!
//! A text one byte past [`MAX_TEXT_BYTES`] is refused:
//!
//! ```compile_fail,E0080
//! use ipe_runtime_rust::runtime_text::admits;
//! const LONG: &str = match core::str::from_utf8(&[b'a'; 513]) {
//!     Ok(text) => text,
//!     Err(_) => "",
//! };
//! const _: () = assert!(admits(LONG));
//! ```
//!
//! A control character is refused:
//!
//! ```compile_fail,E0080
//! use ipe_runtime_rust::runtime_text::admits;
//! const _: () = assert!(admits("ring \u{7} the bell"));
//! ```
//!
//! A bidi override is refused:
//!
//! ```compile_fail,E0080
//! use ipe_runtime_rust::runtime_text::admits;
//! const _: () = assert!(admits("reload \u{202E}daolnwod"));
//! ```

/// The most bytes one row may hold.
pub const MAX_TEXT_BYTES: usize = 512;

/// Who reads a text.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Audience {
    /// The browser client draws it in the page.
    Client,
}

/// One user-visible runtime text. Its wire spelling is [`TextId::wire`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TextId {
    /// The page's boot data was refused.
    BootFailed,
    /// The document stopped applying updates.
    Stale,
    /// The live connection dropped and is being retried.
    Reconnecting,
    /// The live connection is lost for good.
    Offline,
    /// A dev rebuild cut over without a visible outage.
    SwapUpdated,
    /// The server closed a session that outgrew its ceiling.
    ClosedOverCeiling,
    /// The server closed a session whose sign-in was revoked.
    ClosedRevoked,
    /// The server closed a session that ended.
    ClosedEnded,
    /// The server closed a session for any other reason.
    ClosedOther,
    /// The server refused an event too large to send.
    RefusedTooLarge,
    /// The server refused an event.
    RefusedByServer,
    /// The server did not apply an event for any other reason.
    RefusedOther,
    /// A dev rebuild is in flight.
    DevRecompiling,
    /// A dev rebuild landed.
    DevUpdated,
    /// A dev rebuild failed; the compiler's error follows as its own text.
    DevRecompileFailed,
}

impl TextId {
    /// Every id, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::BootFailed,
        Self::Stale,
        Self::Reconnecting,
        Self::Offline,
        Self::SwapUpdated,
        Self::ClosedOverCeiling,
        Self::ClosedRevoked,
        Self::ClosedEnded,
        Self::ClosedOther,
        Self::RefusedTooLarge,
        Self::RefusedByServer,
        Self::RefusedOther,
        Self::DevRecompiling,
        Self::DevUpdated,
        Self::DevRecompileFailed,
    ];

    /// The id's one spelling outside Rust: the key of its row in the client
    /// catalog.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::BootFailed => "boot-failed",
            Self::Stale => "stale",
            Self::Reconnecting => "reconnecting",
            Self::Offline => "offline",
            Self::SwapUpdated => "swap-updated",
            Self::ClosedOverCeiling => "closed-over-ceiling",
            Self::ClosedRevoked => "closed-revoked",
            Self::ClosedEnded => "closed-ended",
            Self::ClosedOther => "closed-other",
            Self::RefusedTooLarge => "refused-too-large",
            Self::RefusedByServer => "refused-by-server",
            Self::RefusedOther => "refused-other",
            Self::DevRecompiling => "dev-recompiling",
            Self::DevUpdated => "dev-updated",
            Self::DevRecompileFailed => "dev-recompile-failed",
        }
    }

    /// Who reads the id's text.
    #[must_use]
    pub const fn audience(self) -> Audience {
        match self {
            Self::BootFailed
            | Self::Stale
            | Self::Reconnecting
            | Self::Offline
            | Self::SwapUpdated
            | Self::ClosedOverCeiling
            | Self::ClosedRevoked
            | Self::ClosedEnded
            | Self::ClosedOther
            | Self::RefusedTooLarge
            | Self::RefusedByServer
            | Self::RefusedOther
            | Self::DevRecompiling
            | Self::DevUpdated
            | Self::DevRecompileFailed => Audience::Client,
        }
    }

    /// The ids the browser client draws, in declaration order.
    pub fn client() -> impl Iterator<Item = Self> {
        Self::ALL
            .iter()
            .copied()
            .filter(|id| matches!(id.audience(), Audience::Client))
    }
}

/// A catalog the binary ships.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Locale {
    /// English.
    En,
}

impl Locale {
    /// Every shipped catalog.
    pub const ALL: &'static [Self] = &[Self::En];

    /// The catalog a request with no usable preference gets.
    pub const DEFAULT: Self = Self::En;

    /// The catalog's BCP-47 tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::En => "en",
        }
    }

    /// The catalog's text for `id`.
    #[must_use]
    pub const fn text(self, id: TextId) -> &'static str {
        match self {
            Self::En => english(id),
        }
    }
}

/// The English catalog.
const fn english(id: TextId) -> &'static str {
    match id {
        TextId::BootFailed => "Page failed to start \u{2014} reload to retry",
        TextId::Stale => "Page is out of date \u{2014} reload",
        TextId::Reconnecting => "Reconnecting\u{2026}",
        TextId::Offline => "Connection lost \u{2014} refresh to retry",
        TextId::SwapUpdated => "updated \u{2713}",
        TextId::ClosedOverCeiling => {
            "This page grew past its session limit and was closed \u{2014} reload to start over"
        }
        TextId::ClosedRevoked => "Your sign-in is no longer valid \u{2014} reload to sign in again",
        TextId::ClosedEnded => "This session has ended \u{2014} reload to start a new one",
        TextId::ClosedOther => "This session was closed \u{2014} reload to start a new one",
        TextId::RefusedTooLarge => {
            "This change is too large to send and was not saved \u{2014} shorten it and try again"
        }
        TextId::RefusedByServer => {
            "The server refused this action and did not apply it \u{2014} reload the page"
        }
        TextId::RefusedOther => "The server did not apply this action \u{2014} reload the page",
        TextId::DevRecompiling => "Recompiling app",
        TextId::DevUpdated => "Updated!",
        TextId::DevRecompileFailed => "Recompilation failed \u{b7} ",
    }
}

/// Why a text cannot be a row.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TextDefect {
    /// The text is empty.
    Empty,
    /// The text holds more than [`MAX_TEXT_BYTES`] bytes.
    TooLong,
    /// The text holds a C0 or C1 control, `DEL`, or a line or paragraph
    /// separator.
    Control,
    /// The text holds a bidi embedding, override or isolate.
    Bidi,
}

/// Why `text` cannot be a row, or `None` when it can.
#[must_use]
pub const fn text_defect(text: &str) -> Option<TextDefect> {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return Some(TextDefect::Empty);
    }
    if bytes.len() > MAX_TEXT_BYTES {
        return Some(TextDefect::TooLong);
    }
    // `text` is UTF-8, so each code point is matched by its whole encoding.
    let mut rest = bytes;
    while let [byte, tail @ ..] = rest {
        match (*byte, tail) {
            (0x00..=0x1F | 0x7F, _)
            | (0xC2, [0x80..=0x9F, ..])
            | (0xE2, [0x80, 0xA8 | 0xA9, ..]) => return Some(TextDefect::Control),
            (0xE2, [0x80, 0xAA..=0xAE, ..] | [0x81, 0xA6..=0xA9, ..]) => {
                return Some(TextDefect::Bidi);
            }
            _ => {}
        }
        rest = tail;
    }
    None
}

/// Whether `text` can be a row.
#[must_use]
pub const fn admits(text: &str) -> bool {
    text_defect(text).is_none()
}

/// Whether every row of every shipped catalog can be a row.
const fn every_row_admitted() -> bool {
    let mut locales = Locale::ALL;
    while let [locale, more_locales @ ..] = locales {
        let mut ids = TextId::ALL;
        while let [id, more_ids @ ..] = ids {
            if !admits(locale.text(*id)) {
                return false;
            }
            ids = more_ids;
        }
        locales = more_locales;
    }
    true
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a catalog row is empty, over-long, or holds a control or bidi character [ledger #boundary]
const _: () = assert!(every_row_admitted());

/// Whether `a` and `b` hold the same bytes.
const fn same(a: &str, b: &str) -> bool {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    loop {
        match (a, b) {
            ([], []) => return true,
            ([x, more_a @ ..], [y, more_b @ ..]) if *x == *y => {
                a = more_a;
                b = more_b;
            }
            _ => return false,
        }
    }
}

/// Whether [`TextId::ALL`] lists the ids in declaration order, each once, and
/// no two ids share a wire spelling.
const fn ids_well_formed() -> bool {
    let mut position = 0;
    let mut ids = TextId::ALL;
    while let [id, rest @ ..] = ids {
        if *id as usize != position {
            return false;
        }
        let mut others = rest;
        while let [other, more @ ..] = others {
            if same(id.wire(), other.wire()) {
                return false;
            }
            others = more;
        }
        position += 1;
        ids = rest;
    }
    true
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if `TextId::ALL` drifts from the declaration or two ids share a wire spelling [ledger #boundary]
const _: () = assert!(ids_well_formed());

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::{Audience, Locale, MAX_TEXT_BYTES, TextDefect, TextId, admits, text_defect};

    const CLIENT_JS: &str = include_str!("web/client.js");

    /// `client.js` with its comments dropped, each string literal written as
    /// `""` when empty and `"S"` otherwise, and each regex literal as `/R/`;
    /// plus every string literal's decoded value, in order.
    struct Lexed {
        code: String,
        literals: Vec<String>,
    }

    /// The value of the string literal opened by `quote` at `chars[start]`,
    /// and the index past its close; `None` when it never closes.
    fn string_literal(chars: &[char], start: usize, quote: char) -> Option<(String, usize)> {
        fn hex(chars: &[char], from: usize, len: usize) -> Option<u32> {
            let digits: String = chars.get(from..from + len)?.iter().collect();
            u32::from_str_radix(&digits, 16).ok()
        }
        fn push(code: u32, units: &mut Vec<u16>) {
            if let Ok(unit) = u16::try_from(code) {
                units.push(unit);
            } else if let Some(c) = char::from_u32(code) {
                let mut buf = [0u16; 2];
                units.extend_from_slice(c.encode_utf16(&mut buf));
            }
        }
        let mut units: Vec<u16> = Vec::new();
        let mut i = start + 1;
        loop {
            let c = *chars.get(i)?;
            if c == quote {
                return Some((String::from_utf16_lossy(&units), i + 1));
            }
            if c == '$' && quote == '`' && chars.get(i + 1) == Some(&'{') {
                return None;
            }
            if c != '\\' {
                push(u32::from(c), &mut units);
                i += 1;
                continue;
            }
            let e = *chars.get(i + 1)?;
            i += 2;
            let code = match e {
                'n' => 0x0A,
                't' => 0x09,
                'r' => 0x0D,
                'b' => 0x08,
                'f' => 0x0C,
                'v' => 0x0B,
                '0' => 0x00,
                '\n' => continue,
                'x' => {
                    let v = hex(chars, i, 2)?;
                    i += 2;
                    v
                }
                'u' if chars.get(i) == Some(&'{') => {
                    let close = (i..chars.len()).find(|&k| chars.get(k) == Some(&'}'))?;
                    let v = hex(chars, i + 1, close - i - 1)?;
                    i = close + 1;
                    v
                }
                'u' => {
                    let v = hex(chars, i, 4)?;
                    i += 4;
                    v
                }
                other => u32::from(other),
            };
            push(code, &mut units);
        }
    }

    /// The index past the regex literal opened at `chars[start]`.
    fn regex_literal(chars: &[char], start: usize) -> Option<usize> {
        let mut i = start + 1;
        let mut in_class = false;
        loop {
            match *chars.get(i)? {
                '\\' => i += 1,
                '[' => in_class = true,
                ']' => in_class = false,
                '/' if !in_class => break,
                '\n' => return None,
                _ => {}
            }
            i += 1;
        }
        i += 1;
        while chars.get(i).is_some_and(char::is_ascii_alphabetic) {
            i += 1;
        }
        Some(i)
    }

    /// Whether a `/` after `code` opens a regex literal rather than divides.
    fn regex_may_open(code: &str) -> bool {
        let head = code.trim_end();
        head.chars()
            .last()
            .is_none_or(|c| "(,=:[!&|?{};+-*%<>~^".contains(c))
            || head.ends_with("return")
            || head.ends_with("typeof")
    }

    fn lex(js: &str) -> Option<Lexed> {
        let chars: Vec<char> = js.chars().collect();
        let mut code = String::with_capacity(js.len());
        let mut literals = Vec::new();
        let mut i = 0;
        while let Some(&c) = chars.get(i) {
            let next = chars.get(i + 1).copied();
            match c {
                '/' if next == Some('/') => {
                    while chars.get(i).is_some_and(|&c| c != '\n') {
                        i += 1;
                    }
                }
                '/' if next == Some('*') => {
                    i += 2;
                    while !(chars.get(i) == Some(&'*') && chars.get(i + 1) == Some(&'/')) {
                        if *chars.get(i)? == '\n' {
                            code.push('\n');
                        }
                        i += 1;
                    }
                    code.push(' ');
                    i += 2;
                }
                '"' | '\'' | '`' => {
                    let (value, end) = string_literal(&chars, i, c)?;
                    code.push_str(if value.is_empty() { "\"\"" } else { "\"S\"" });
                    literals.push(value);
                    i = end;
                }
                '/' if regex_may_open(&code) => {
                    i = regex_literal(&chars, i)?;
                    code.push_str("/R/");
                }
                _ => {
                    code.push(c);
                    i += 1;
                }
            }
        }
        Some(Lexed { code, literals })
    }

    fn lexed() -> Lexed {
        let lexed = lex(CLIENT_JS);
        assert!(lexed.is_some(), "client.js lexes to its end");
        lexed.unwrap_or(Lexed {
            code: String::new(),
            literals: Vec::new(),
        })
    }

    fn collapse(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The top-level arguments of the call whose `(` ends at `open`.
    fn call_args(code: &str, open: usize) -> Vec<String> {
        let mut args = Vec::new();
        let mut depth = 0usize;
        let mut current = String::new();
        for c in code.get(open..).unwrap_or_default().chars() {
            match c {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        args.push(collapse(&current));
                        return args;
                    }
                }
                ',' if depth == 1 => {
                    args.push(collapse(&current));
                    current.clear();
                    continue;
                }
                _ => {}
            }
            if depth >= 1 && !(depth == 1 && c == '(') {
                current.push(c);
            }
        }
        args
    }

    /// The arguments of every call to `name`, each with the collapsed line it
    /// opens on.
    fn calls(code: &str, name: &str) -> Vec<(String, Vec<String>)> {
        let needle = format!("{name}(");
        code.match_indices(&needle)
            .filter(|(at, _)| {
                code.get(..*at)
                    .and_then(|head| head.chars().last())
                    .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'))
            })
            .map(|(at, _)| {
                let line_start = code
                    .get(..at)
                    .and_then(|h| h.rfind('\n'))
                    .map_or(0, |n| n + 1);
                let line_end = code
                    .get(at..)
                    .and_then(|t| t.find('\n'))
                    .map_or(code.len(), |n| at + n);
                let line = collapse(code.get(line_start..line_end).unwrap_or_default());
                (line, call_args(code, at + needle.len() - 1))
            })
            .collect()
    }

    fn is_literal(arg: &str) -> bool {
        arg.starts_with('"') || arg.starts_with("/R/")
    }

    fn upper_snake(wire: &str) -> String {
        wire.to_ascii_uppercase().replace('-', "_")
    }

    /// Every row of every catalog passes the bound the build asserts.
    #[test]
    fn every_row_is_admitted() {
        for locale in Locale::ALL {
            for id in TextId::ALL {
                assert_eq!(
                    text_defect(locale.text(*id)),
                    None,
                    "{}.{}",
                    locale.tag(),
                    id.wire()
                );
            }
        }
    }

    /// The bound refuses each defect and admits the text one step inside it.
    #[test]
    fn the_bound_refuses_each_defect() {
        let at_limit = "a".repeat(MAX_TEXT_BYTES);
        let past_limit = "a".repeat(MAX_TEXT_BYTES + 1);
        assert!(admits(&at_limit));
        for (text, defect) in [
            ("", TextDefect::Empty),
            (past_limit.as_str(), TextDefect::TooLong),
            ("a\u{0}b", TextDefect::Control),
            ("tab\there", TextDefect::Control),
            ("line\nbreak", TextDefect::Control),
            ("del\u{7f}", TextDefect::Control),
            ("c1\u{85}", TextDefect::Control),
            ("c1\u{9f}", TextDefect::Control),
            ("line\u{2028}sep", TextDefect::Control),
            ("para\u{2029}sep", TextDefect::Control),
            ("lre\u{202a}", TextDefect::Bidi),
            ("rlo\u{202e}", TextDefect::Bidi),
            ("lri\u{2066}", TextDefect::Bidi),
            ("pdi\u{2069}", TextDefect::Bidi),
        ] {
            assert_eq!(text_defect(text), Some(defect), "{text:?}");
        }
        for neighbour in [
            "nbsp\u{a0}",
            "dash\u{2014}",
            "ellipsis\u{2026}",
            "zwnj\u{200c}",
            "lrm\u{200e}",
            "fsi-neighbour\u{2065}",
            "pdi-neighbour\u{206a}",
            "ok \u{2713}",
        ] {
            assert!(admits(neighbour), "{neighbour:?}");
        }
    }

    /// Every id the client draws is a client id, and the ids' wire spellings
    /// are distinct.
    #[test]
    fn ids_are_closed_and_distinct() {
        let wires: std::collections::BTreeSet<&str> =
            TextId::ALL.iter().map(|id| id.wire()).collect();
        assert_eq!(wires.len(), TextId::ALL.len());
        assert!(
            TextId::client().all(|id| id.audience() == Audience::Client),
            "the client draws only client text"
        );
    }

    /// The client's id table is exactly the client ids, each named by its
    /// wire spelling in upper snake case, and its row bound is the table's.
    #[test]
    fn the_client_names_exactly_the_client_ids() {
        let lexed = lexed();
        let code = &lexed.code;
        let open = "var __IPE_TEXT = Object.freeze({";
        assert_eq!(code.matches(open).count(), 1, "one `{open}`");
        let start = code.find(open).map_or(0, |at| at + open.len());
        let body = code
            .get(start..)
            .and_then(|rest| rest.find("});").and_then(|end| rest.get(..end)))
            .unwrap_or_default();
        let names: Vec<String> = body
            .split(',')
            .filter_map(|entry| entry.split_once(':'))
            .map(|(name, _)| name.trim().to_owned())
            .collect();
        // The values are the literals that follow the opening, in order.
        let before = lex(code.get(..start).unwrap_or_default());
        let skip = before.map_or(0, |b| b.literals.len());
        let values: Vec<&String> = lexed.literals.iter().skip(skip).take(names.len()).collect();
        let wires: Vec<String> = TextId::client().map(|id| id.wire().to_owned()).collect();
        assert_eq!(
            values.iter().map(|v| (*v).clone()).collect::<Vec<_>>(),
            wires,
            "`__IPE_TEXT` holds the client ids in order"
        );
        let expected: Vec<String> = wires.iter().map(|w| upper_snake(w)).collect();
        assert_eq!(names, expected, "each id is named by its wire spelling");
        assert!(
            code.contains(&format!("var __IPE_TEXT_MAX = {MAX_TEXT_BYTES};")),
            "the client's row bound is `MAX_TEXT_BYTES`"
        );
        let known: std::collections::BTreeSet<&str> = expected.iter().map(String::as_str).collect();
        for (at, _) in code.match_indices("__IPE_TEXT.") {
            let name: String = code
                .get(at + "__IPE_TEXT.".len()..)
                .unwrap_or_default()
                .chars()
                .take_while(|c| c.is_ascii_uppercase() || *c == '_')
                .collect();
            assert!(
                known.contains(name.as_str()),
                "`__IPE_TEXT.{name}` names no id"
            );
        }
    }

    /// No runtime text is written in `client.js`: no string literal holds a
    /// row of any catalog.
    #[test]
    fn no_row_is_written_in_the_client() {
        let lexed = lexed();
        assert!(
            lexed.literals.len() > 100,
            "precondition: the lexer reads the client's literals"
        );
        for locale in Locale::ALL {
            for id in TextId::client() {
                let row = locale.text(id);
                let written: Vec<&String> =
                    lexed.literals.iter().filter(|l| l.contains(row)).collect();
                assert!(
                    written.is_empty(),
                    "{}.{} is written in client.js as {written:?}; draw it by id through `__ipeSay`",
                    locale.tag(),
                    id.wire()
                );
            }
        }
    }

    /// The client writes text and markup into the page only through its
    /// sinks: `__ipeSay` for runtime text, and the fixed sites that move
    /// server content. No sink takes a literal text.
    #[test]
    fn text_reaches_the_page_only_through_its_sinks() {
        let lexed = lexed();
        let code = &lexed.code;
        // Property writes into a node's text or markup.
        let mut writes = Vec::new();
        for line in code.lines() {
            for prop in [".textContent", ".innerText", ".innerHTML", ".outerHTML"] {
                for (at, _) in line.match_indices(prop) {
                    let after = line.get(at + prop.len()..).unwrap_or_default().trim_start();
                    let assigns = (after.starts_with('=') && !after.starts_with("=="))
                        || after.starts_with("+=");
                    if assigns {
                        writes.push(collapse(line));
                    }
                }
            }
        }
        assert_eq!(
            writes,
            [
                "holder.innerHTML = html;",
                "fresh.textContent = old.textContent;",
                "d.textContent = s == null ? \"\" : String(s);",
            ],
            "a node's text or markup is set through `__ipeSay` or `__ipeNode.setText`"
        );
        for sink in [
            "insertAdjacentHTML(",
            "insertAdjacentText(",
            ".write(",
            ".writeln(",
        ] {
            assert!(!code.contains(sink), "client.js calls `{sink}`");
        }
        assert_eq!(
            code.matches("textContent.call(").count(),
            1,
            "one captured setter"
        );
        let set_text: Vec<String> = calls(code, "setText")
            .into_iter()
            .map(|(line, _)| line)
            .collect();
        assert_eq!(
            set_text,
            [
                "__ipeNode.setText(el, p.text);",
                "__ipeNode.setText(el, typeof detail === \"S\" ? row + detail : row);",
            ],
            "`__ipeNode.setText` is called by `__ipeSay` and the server's text patch alone"
        );
        let say = calls(code, "__ipeSay");
        assert!(
            say.len() > 5,
            "precondition: the scan finds the sink's calls"
        );
        for (line, args) in &say {
            if line.starts_with("function __ipeSay(") {
                continue;
            }
            assert!(
                args.len() >= 2 && args.iter().skip(1).all(|a| !is_literal(a)),
                "`__ipeSay` takes an id, never a literal: {line}"
            );
        }
        let status = calls(code, "__ipeSetStatus");
        assert!(
            status.len() > 10,
            "precondition: the scan finds the banner's calls"
        );
        for (line, args) in &status {
            if line.starts_with("function __ipeSetStatus(") {
                continue;
            }
            assert!(
                args.iter().skip(1).all(|a| a == "\"\"" || !is_literal(a)),
                "`__ipeSetStatus` takes an id (or `\"\"`), never a literal text: {line}"
            );
        }
    }

    /// The scan's lexer reads comments, every literal form and regexes, and
    /// refuses an unterminated literal.
    #[test]
    fn the_lexer_reads_each_form() {
        let lexed = lex(concat!(
            "a = \"x\\u2014y\"; // \"Reconnecting\"\n",
            "b = 'it\\'s' /* \"no\" */ + `t`;\n",
            "c = /[\"/]+/g.test(\"\\x41\\u{1F600}\");\n",
            "d = e / f / g;\n",
        ));
        assert!(lexed.is_some());
        let Some(lexed) = lexed else { return };
        assert_eq!(lexed.literals, ["x\u{2014}y", "it's", "t", "A\u{1F600}"]);
        assert!(lexed.code.contains("c = /R/.test(\"S\");"));
        assert!(lexed.code.contains("d = e / f / g;"));
        assert!(!lexed.code.contains("Reconnecting"));
        assert!(lex("a = \"open;\n").is_none());
        assert!(lex("a = `x${y}`;").is_none());
        assert_eq!(
            calls("f(\"\", g(1, 2), [3, 4]);", "f")
                .first()
                .map(|(_, a)| a.clone()),
            Some(vec![
                "\"\"".to_owned(),
                "g(1, 2)".to_owned(),
                "[3, 4]".to_owned()
            ])
        );
    }
}
