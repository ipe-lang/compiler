//! Ipe.Tui — raw-byte key decoder.
//!
//! Pure: decodes one keypress from a raw terminal byte buffer into a
//! `(TuiKey, consumed)` pair so a `Tui.Sub.onKey` handler sees typed `kind` / `value` strings.
//! No terminal I/O here — the `tui_app` loop reads raw stdin bytes and feeds
//! them in. Total: every access is bounds-checked (`.get`), never panics.

/// A decoded key. `kind` values: `enter` / `tab` / `space` / `backspace` /
/// `escape` / `up` / `down` / `left` / `right` / `home` / `end` / `delete` /
/// `pageup` / `pagedown` / `fn` (value = number) / `mouse` / `paste-start` /
/// `paste-end` / `ctrl` (value = letter) / `char` (value = the character) /
/// `other` (value = raw bytes lossily).
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
        // CSI 1;<mod><final> — modifier-prefixed arrows / Home / End / F-keys
        Some(b'1') if buf.len() >= 6 && buf.get(3) == Some(&b';') => {
            let modb = buf.get(4).copied().unwrap_or(0);
            let mut ev = match buf.get(5) {
                Some(b'A') => TuiKey::of("up"),
                Some(b'B') => TuiKey::of("down"),
                Some(b'C') => TuiKey::of("right"),
                Some(b'D') => TuiKey::of("left"),
                Some(b'H') => TuiKey::of("home"),
                Some(b'F') => TuiKey::of("end"),
                Some(b'P') => TuiKey::val("fn", "1".into()),
                Some(b'Q') => TuiKey::val("fn", "2".into()),
                Some(b'R') => TuiKey::val("fn", "3".into()),
                Some(b'S') => TuiKey::val("fn", "4".into()),
                _ => TuiKey::default(),
            };
            if !ev.kind.is_empty() {
                match modb {
                    b'2' => ev.shift = true,
                    b'3' => ev.alt = true,
                    b'4' => {
                        ev.shift = true;
                        ev.alt = true;
                    }
                    b'5' => ev.ctrl = true,
                    b'6' => {
                        ev.shift = true;
                        ev.ctrl = true;
                    }
                    b'7' => {
                        ev.alt = true;
                        ev.ctrl = true;
                    }
                    _ => {}
                }
                return (ev, 6);
            }
            (TuiKey::val("other", lossy(buf.get(..6).unwrap_or(buf))), 6)
        }
        // CSI <num> ~ — Home/End/Insert/Delete/Page/F-keys/bracketed-paste
        Some(&c) if c.is_ascii_digit() => {
            let mut end = 3;
            while let Some(&ch) = buf.get(end) {
                end += 1;
                if ch == b'~' {
                    let num = lossy(buf.get(2..end.saturating_sub(1)).unwrap_or(&[]));
                    let ev = match num.as_str() {
                        "1" | "7" => TuiKey::of("home"),
                        "4" | "8" => TuiKey::of("end"),
                        "3" => TuiKey::of("delete"),
                        "5" => TuiKey::of("pageup"),
                        "6" => TuiKey::of("pagedown"),
                        "11" | "12" | "13" | "14" | "15" | "17" | "18" | "19" | "20" | "21"
                        | "23" | "24" => TuiKey::val("fn", num.clone()),
                        "200" => TuiKey::of("paste-start"),
                        "201" => TuiKey::of("paste-end"),
                        _ => TuiKey::val("other", lossy(buf.get(..end).unwrap_or(buf))),
                    };
                    return (ev, end);
                }
                if (0x40..=0x7e).contains(&ch) {
                    break;
                }
            }
            (
                TuiKey::val("other", lossy(buf.get(..end).unwrap_or(buf))),
                end,
            )
        }
        // Plain CSI arrows / Home / End
        Some(b'A') => (TuiKey::of("up"), 3),
        Some(b'B') => (TuiKey::of("down"), 3),
        Some(b'C') => (TuiKey::of("right"), 3),
        Some(b'D') => (TuiKey::of("left"), 3),
        Some(b'H') => (TuiKey::of("home"), 3),
        Some(b'F') => (TuiKey::of("end"), 3),
        // Unrecognised CSI — consume to the final byte.
        _ => {
            let mut end = 2;
            while let Some(&c) = buf.get(end) {
                end += 1;
                if (0x40..=0x7e).contains(&c) {
                    break;
                }
            }
            (
                TuiKey::val("other", lossy(buf.get(..end).unwrap_or(buf))),
                end,
            )
        }
    }
}

fn decode_char(buf: &[u8]) -> (TuiKey, usize) {
    // Decode one UTF-8 scalar from the front of buf: try the maximal valid
    // prefix of at most 4 bytes (one scalar's longest encoding), down to 1
    // byte. Bounded to 4 bytes — never re-validates the whole read buffer to
    // find the first character. Falls to "other" (1 byte) if no prefix in
    // that window is valid, e.g. a lone continuation byte.
    for n in (1..=buf.len().min(4)).rev() {
        if let Some(s) = buf.get(..n).and_then(|b| std::str::from_utf8(b).ok())
            && let Some(c) = s.chars().next()
        {
            return (TuiKey::val("char", c.to_string()), c.len_utf8());
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
