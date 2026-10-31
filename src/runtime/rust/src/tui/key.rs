//! Ipe.Tui — raw-byte key decoder.
//!
//! Pure: decodes one keypress from a raw terminal byte buffer into a
//! `(TuiKey, consumed)` pair so a `Tui.Sub.onKey` handler sees typed `kind` / `value` strings.
//! No terminal I/O here — the `tui_app` loop reads raw stdin bytes and feeds
//! them in. Total: every access is bounds-checked (`.get`), never panics.

/// A decoded key. `kind` values: `enter` / `tab` / `space` / `backspace` /
/// `escape` / `up` / `down` / `left` / `right` / `home` / `end` / `delete` /
/// `pageup` / `pagedown` / `fn` (value = the F-key number, `1`-`12`) / `mouse` / `paste-start` /
/// `paste-end` / `ctrl` (value = letter) / `char` (value = the printable
/// character) / `other` (value = raw bytes lossily). The `shift` / `alt` /
/// `ctrl` flags are set only on a CSI-modified named key; `wire_key` decides
/// which of them reach a program.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct TuiKey {
    pub kind: String,
    pub value: String,
    pub shift: bool,
    pub alt: bool,
    pub ctrl: bool,
}

impl TuiKey {
    fn of(kind: &str) -> Self {
        TuiKey {
            kind: kind.to_string(),
            ..TuiKey::default()
        }
    }
    fn val(kind: &str, value: String) -> Self {
        TuiKey {
            kind: kind.to_string(),
            value,
            ..TuiKey::default()
        }
    }
}

#[allow(clippy::disallowed_methods)] // terminal input reaches Ipê as `String` text
fn lossy(buf: &[u8]) -> String {
    String::from_utf8_lossy(buf).into_owned()
}

/// Decode ONE keypress from `buf`. Returns the key + bytes consumed (0 only on
/// empty input). Mirrors `tuiDecodeKey`.
pub fn decode_key(buf: &[u8]) -> (TuiKey, usize) {
    let b = match buf.first() {
        Some(&b) => b,
        None => return (TuiKey::of("other"), 0),
    };
    match b {
        0x0d | 0x0a => (TuiKey::of("enter"), 1),
        0x09 => (TuiKey::of("tab"), 1),
        0x20 => (TuiKey::of("space"), 1),
        0x7f | 0x08 => (TuiKey::of("backspace"), 1),
        0x1b => decode_escape(buf),
        0x01..=0x1a => {
            // Ctrl-A..Ctrl-Z (Tab/LF/CR/ESC handled above).
            let letter = char::from(b'a' + (b - 1)).to_string();
            (TuiKey::val("ctrl", letter), 1)
        }
        _ => decode_char(buf),
    }
}

fn decode_escape(buf: &[u8]) -> (TuiKey, usize) {
    if buf.len() == 1 {
        return (TuiKey::of("escape"), 1);
    }
    match buf.get(1) {
        // CSI: ESC [
        Some(b'[') if buf.len() >= 3 => decode_csi(buf),
        // SS3: ESC O — F1..F4 on some terminals
        Some(b'O') if buf.len() >= 3 => match buf.get(2) {
            Some(b'P') => (TuiKey::val("fn", "1".into()), 3),
            Some(b'Q') => (TuiKey::val("fn", "2".into()), 3),
            Some(b'R') => (TuiKey::val("fn", "3".into()), 3),
            Some(b'S') => (TuiKey::val("fn", "4".into()), 3),
            _ => (TuiKey::val("other", lossy(buf.get(..3).unwrap_or(buf))), 3),
        },
        // Esc with stray bytes — treat as solo Esc, leave the rest.
        _ => (TuiKey::of("escape"), 1),
    }
}

fn decode_csi(buf: &[u8]) -> (TuiKey, usize) {
    match buf.get(2) {
        // SGR mouse: ESC [ < … M|m
        Some(b'<') => {
            let mut end = 3;
            while let Some(&c) = buf.get(end) {
                end += 1;
                if c == b'M' || c == b'm' {
                    let body = lossy(buf.get(3..end.saturating_sub(1)).unwrap_or(&[]));
                    let tag = if c == b'm' { "m" } else { "M" };
                    return (TuiKey::val("mouse", format!("{body}:{tag}")), end);
                }
            }
            (
                TuiKey::val("other", lossy(buf.get(..end).unwrap_or(buf))),
                end,
            )
        }
        // Linux console F1..F5: ESC [ [ A..E
        Some(b'[') => {
            let number = match buf.get(3) {
                Some(b'A') => "1",
                Some(b'B') => "2",
                Some(b'C') => "3",
                Some(b'D') => "4",
                Some(b'E') => "5",
                _ => return (TuiKey::val("other", lossy(buf.get(..3).unwrap_or(buf))), 3),
            };
            (TuiKey::val("fn", number.into()), 4)
        }
        // ESC [ <params> <final>: arrows, Home / End / Insert / Delete / Page,
        // F-keys, bracketed paste — modified or not. Consumed through the
        // final byte; a sequence naming no key is "other".
        _ => {
            let (key, end) = match csi_final(buf) {
                Some(at) => (
                    buf.get(2..at)
                        .and_then(csi_params)
                        .zip(buf.get(at).copied())
                        .and_then(|(params, final_byte)| csi_key(final_byte, params)),
                    at.saturating_add(1),
                ),
                None => (None, buf.len()),
            };
            let key =
                key.unwrap_or_else(|| TuiKey::val("other", lossy(buf.get(..end).unwrap_or(buf))));
            (key, end)
        }
    }
}

/// The index of the final byte (`0x40`..=`0x7e`) of the CSI sequence opening
/// `buf`, or `None` when `buf` ends first.
fn csi_final(buf: &[u8]) -> Option<usize> {
    buf.iter()
        .enumerate()
        .skip(2)
        .find_map(|(at, c)| (0x40..=0x7e).contains(c).then_some(at))
}

/// One numeric CSI parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CsiParam {
    /// Left empty: the terminal means the default.
    Omitted,
    Number(u16),
}

/// The `<code>` and `<modifier>` of `ESC [ <code> ; <modifier> <final>`;
/// `None` for any other parameter shape: a third parameter, a private marker,
/// a number past `u16`.
fn csi_params(params: &[u8]) -> Option<(CsiParam, CsiParam)> {
    let mut parts = params.split(|b| *b == b';');
    let code = csi_number(parts.next().unwrap_or(&[]))?;
    let modifier = match parts.next() {
        Some(part) => csi_number(part)?,
        None => CsiParam::Omitted,
    };
    if parts.next().is_some() {
        return None;
    }
    Some((code, modifier))
}

/// One CSI parameter; `None` unless it is empty or a decimal within `u16`.
fn csi_number(part: &[u8]) -> Option<CsiParam> {
    if part.is_empty() {
        return Some(CsiParam::Omitted);
    }
    if !part.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(part)
        .ok()?
        .parse::<u16>()
        .ok()
        .map(CsiParam::Number)
}

/// The key a complete CSI sequence names, or `None` when it names none.
fn csi_key(final_byte: u8, (code, modifier): (CsiParam, CsiParam)) -> Option<TuiKey> {
    let key = if final_byte == b'~' {
        let CsiParam::Number(code) = code else {
            return None;
        };
        match code {
            1 | 7 => TuiKey::of("home"),
            4 | 8 => TuiKey::of("end"),
            3 => TuiKey::of("delete"),
            5 => TuiKey::of("pageup"),
            6 => TuiKey::of("pagedown"),
            11 => TuiKey::val("fn", "1".into()),
            12 => TuiKey::val("fn", "2".into()),
            13 => TuiKey::val("fn", "3".into()),
            14 => TuiKey::val("fn", "4".into()),
            15 => TuiKey::val("fn", "5".into()),
            17 => TuiKey::val("fn", "6".into()),
            18 => TuiKey::val("fn", "7".into()),
            19 => TuiKey::val("fn", "8".into()),
            20 => TuiKey::val("fn", "9".into()),
            21 => TuiKey::val("fn", "10".into()),
            23 => TuiKey::val("fn", "11".into()),
            24 => TuiKey::val("fn", "12".into()),
            200 if modifier == CsiParam::Omitted => TuiKey::of("paste-start"),
            201 if modifier == CsiParam::Omitted => TuiKey::of("paste-end"),
            _ => return None,
        }
    } else {
        // A cursor or PC-style F-key final carries no code but the default `1`.
        if !matches!(code, CsiParam::Omitted | CsiParam::Number(1)) {
            return None;
        }
        match final_byte {
            b'A' => TuiKey::of("up"),
            b'B' => TuiKey::of("down"),
            b'C' => TuiKey::of("right"),
            b'D' => TuiKey::of("left"),
            b'H' => TuiKey::of("home"),
            b'F' => TuiKey::of("end"),
            // An unmodified PC-style F1..F4 arrives as SS3 (`ESC O P`); the
            // CSI spelling carries a modifier.
            b'P' if modifier != CsiParam::Omitted => TuiKey::val("fn", "1".into()),
            b'Q' if modifier != CsiParam::Omitted => TuiKey::val("fn", "2".into()),
            b'R' if modifier != CsiParam::Omitted => TuiKey::val("fn", "3".into()),
            b'S' if modifier != CsiParam::Omitted => TuiKey::val("fn", "4".into()),
            _ => return None,
        }
    };
    with_modifier(key, modifier)
}

/// `key` with the flags an xterm modifier parameter (`1` plus a mask of Shift
/// `1`, Alt `2`, Ctrl `4`, Meta `8`) sets; `None` for modifier `0`, which no
/// terminal sends.
fn with_modifier(mut key: TuiKey, modifier: CsiParam) -> Option<TuiKey> {
    let CsiParam::Number(modifier) = modifier else {
        return Some(key);
    };
    let bits = modifier.checked_sub(1)?;
    key.shift = bits & 1 != 0;
    key.alt = bits & 2 != 0;
    key.ctrl = bits & 4 != 0;
    Some(key)
}

/// The flat `(kind, value)` pair a decoded key reaches a program as.
///
/// The channel carries no modifier flags, so Ctrl on Left or Right is folded
/// into the kind (`ctrlleft` / `ctrlright`: a text field's word jumps and the
/// debugger's step keys); every other modifier is dropped. Every terminal
/// driver maps keys through this one function, so a program sees the same
/// kinds whichever driver and build features run it.
pub(crate) fn wire_key(key: TuiKey) -> (String, String) {
    let kind = if key.ctrl && matches!(key.kind.as_str(), "left" | "right") {
        format!("ctrl{}", key.kind)
    } else {
        key.kind
    };
    (kind, key.value)
}

fn decode_char(buf: &[u8]) -> (TuiKey, usize) {
    // Decode one UTF-8 scalar from the front of buf: try the maximal valid
    // prefix of at most 4 bytes (one scalar's longest encoding), down to 1
    // byte. Bounded to 4 bytes — never re-validates the whole read buffer to
    // find the first character. Falls to "other" (1 byte) if no prefix in
    // that window is valid, e.g. a lone continuation byte. A control
    // character no named kind owns (NUL from Ctrl-Space, `0x1c`..=`0x1f`, a
    // C1 control) is "other", never "char": "char" is printable text.
    for n in (1..=buf.len().min(4)).rev() {
        if let Some(s) = buf.get(..n).and_then(|b| std::str::from_utf8(b).ok())
            && let Some(c) = s.chars().next()
        {
            let kind = if c.is_control() { "other" } else { "char" };
            return (TuiKey::val(kind, c.to_string()), c.len_utf8());
        }
    }
    (TuiKey::val("other", lossy(buf.get(..1).unwrap_or(&[]))), 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_keys() {
        assert_eq!(decode_key(b"\r"), (TuiKey::of("enter"), 1));
        assert_eq!(decode_key(b"\t"), (TuiKey::of("tab"), 1));
        assert_eq!(decode_key(b" "), (TuiKey::of("space"), 1));
        assert_eq!(decode_key(b"\x7f"), (TuiKey::of("backspace"), 1));
        assert_eq!(decode_key(b"\x1b"), (TuiKey::of("escape"), 1));
    }

    #[test]
    fn ctrl_and_char() {
        assert_eq!(decode_key(&[0x03]), (TuiKey::val("ctrl", "c".into()), 1)); // Ctrl-C
        assert_eq!(decode_key(b"q"), (TuiKey::val("char", "q".into()), 1));
        let (k, n) = decode_key("é".as_bytes());
        assert_eq!((k.kind.as_str(), k.value.as_str(), n), ("char", "é", 2));
    }

    #[test]
    fn arrows_and_modifiers() {
        assert_eq!(decode_key(b"\x1b[A"), (TuiKey::of("up"), 3));
        assert_eq!(decode_key(b"\x1b[D"), (TuiKey::of("left"), 3));
        // Ctrl-Right: ESC [ 1 ; 5 C
        let (k, n) = decode_key(b"\x1b[1;5C");
        assert_eq!((k.kind.as_str(), k.ctrl, n), ("right", true, 6));
    }

    #[test]
    fn csi_tilde_and_empty() {
        assert_eq!(decode_key(b"\x1b[3~"), (TuiKey::of("delete"), 4));
        assert_eq!(decode_key(b"\x1b[5~"), (TuiKey::of("pageup"), 4));
        assert_eq!(decode_key(&[]), (TuiKey::of("other"), 0));
    }

    // Every spelling of a function key yields its F-number, whichever escape
    // form the terminal sends; a code no F-key owns stays `other`.
    #[test]
    fn function_keys_yield_their_f_number() {
        assert_eq!(decode_key(b"\x1bOP"), (TuiKey::val("fn", "1".into()), 3));
        assert_eq!(decode_key(b"\x1b[11~"), (TuiKey::val("fn", "1".into()), 5));
        assert_eq!(decode_key(b"\x1b[15~"), (TuiKey::val("fn", "5".into()), 5));
        assert_eq!(decode_key(b"\x1b[17~"), (TuiKey::val("fn", "6".into()), 5));
        assert_eq!(decode_key(b"\x1b[21~"), (TuiKey::val("fn", "10".into()), 5));
        assert_eq!(decode_key(b"\x1b[24~"), (TuiKey::val("fn", "12".into()), 5));
        let (k, n) = decode_key(b"\x1b[16~");
        assert_eq!((k.kind.as_str(), n), ("other", 5));
        assert_eq!(decode_key(b"\x1bOS"), (TuiKey::val("fn", "4".into()), 3));
        // Linux console F1..F5.
        assert_eq!(decode_key(b"\x1b[[A"), (TuiKey::val("fn", "1".into()), 4));
        assert_eq!(decode_key(b"\x1b[[E"), (TuiKey::val("fn", "5".into()), 4));
    }

    // A modifier parameter on a `~` key or a PC-style F1..F4 keeps the key and
    // sets its flags from the xterm bit mask.
    #[test]
    fn modified_keys_keep_their_kind() {
        let (k, n) = decode_key(b"\x1b[15;5~");
        assert_eq!(
            (k.kind.as_str(), k.value.as_str(), k.ctrl, n),
            ("fn", "5", true, 7)
        );
        let (k, n) = decode_key(b"\x1b[24;2~");
        assert_eq!(
            (k.kind.as_str(), k.value.as_str(), k.shift, n),
            ("fn", "12", true, 7)
        );
        let (k, n) = decode_key(b"\x1b[3;3~");
        assert_eq!((k.kind.as_str(), k.alt, n), ("delete", true, 6));
        let (k, n) = decode_key(b"\x1b[1;2P");
        assert_eq!(
            (k.kind.as_str(), k.value.as_str(), k.shift, n),
            ("fn", "1", true, 6)
        );
        let (k, n) = decode_key(b"\x1b[1;8A");
        assert_eq!(
            (k.kind.as_str(), k.shift, k.alt, k.ctrl, n),
            ("up", true, true, true, 6)
        );
    }

    // Refusals: a CSI sequence that names no key is "other", consumed through
    // its final byte (or to the end of an unterminated buffer).
    #[test]
    fn csi_naming_no_key_is_other() {
        for (seq, consumed) in [
            (&b"\x1b[P"[..], 3),       // PC-style F1 spelling needs a modifier
            (&b"\x1b[0~"[..], 4),      // no key owns code 0
            (&b"\x1b[15;0~"[..], 7),   // modifier 0 is no modifier spelling
            (&b"\x1b[15;5;1~"[..], 9), // a third parameter
            (&b"\x1b[99999~"[..], 8),  // past `u16`
            (&b"\x1b[?5~"[..], 5),     // a private marker
            (&b"\x1b[200;5~"[..], 8),  // a modified paste marker
            (&b"\x1b[2;5A"[..], 6),    // a cursor key with a code
            (&b"\x1b[15"[..], 4),      // unterminated
            (&b"\x1b[[Z"[..], 3),      // no linux-console F-key
        ] {
            let (k, n) = decode_key(seq);
            assert_eq!((k.kind.as_str(), n), ("other", consumed), "{seq:?}");
        }
        // Shift-Tab stays the raw `other` the focus driver matches.
        assert_eq!(
            decode_key(b"\x1b[Z"),
            (TuiKey::val("other", "\x1b[Z".into()), 3)
        );
    }

    // A control character no named kind owns is "other", never "char".
    #[test]
    fn unnamed_control_characters_are_other() {
        assert_eq!(decode_key(&[0x00]), (TuiKey::val("other", "\0".into()), 1));
        assert_eq!(
            decode_key(&[0x1c]),
            (TuiKey::val("other", "\x1c".into()), 1)
        );
        let (k, n) = decode_key("\u{85}".as_bytes());
        assert_eq!((k.kind.as_str(), n), ("other", 2));
    }

    // Every driver folds Ctrl on Left / Right into the kind and drops every
    // other modifier.
    #[test]
    fn wire_key_folds_only_ctrl_left_and_right() {
        let (k, _) = decode_key(b"\x1b[1;5C");
        assert_eq!(wire_key(k), ("ctrlright".to_owned(), String::new()));
        let (k, _) = decode_key(b"\x1b[1;5D");
        assert_eq!(wire_key(k), ("ctrlleft".to_owned(), String::new()));
        let (k, _) = decode_key(b"\x1b[1;2C");
        assert_eq!(wire_key(k), ("right".to_owned(), String::new()));
        let (k, _) = decode_key(b"\x1b[15;5~");
        assert_eq!(wire_key(k), ("fn".to_owned(), "5".to_owned()));
    }

    // `é` (2 bytes) followed by the lead byte of an unrelated, incomplete
    // 3-byte scalar: the bounded prefix decode must still find `é` as the
    // first character, consuming exactly its 2 bytes — pinning that the
    // 4-byte-window decode agrees with the old whole-buffer-first attempt.
    #[test]
    fn char_followed_by_split_multibyte_decodes_first() {
        let mut buf = "é".as_bytes().to_vec();
        buf.push(0xe2); // lead byte of a 3-byte sequence, no continuation bytes
        let (k, n) = decode_key(&buf);
        assert_eq!((k.kind.as_str(), k.value.as_str(), n), ("char", "é", 2));
    }

    // A lone continuation byte (no valid prefix at any window length) falls to
    // "other", consuming 1 byte — the unchanged fallback.
    #[test]
    fn lone_continuation_byte_is_other() {
        let (k, n) = decode_key(&[0x80]);
        assert_eq!(k.kind.as_str(), "other");
        assert_eq!(n, 1);
    }
}
