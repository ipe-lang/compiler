//! The native-shell packager: turning a built Ipê app into an OS application
//! bundle.
//!
//! [`permissions`] derives a native shell's OS-permission declarations (iOS/macOS
//! `Info.plist` usage-description keys, Android `<uses-permission>`) from the
//! app's granted web capabilities, fail-closed in both directions. It is the
//! security boundary of the whole packager: the derivation is the single source
//! of truth for what a packaged app may do, so a package can neither
//! under-declare relative to consent nor smuggle an OS permission the app never
//! accepted.
//!
//! [`desktop`] turns a built `Ipe.WebView` app into a distributable per-OS
//! desktop bundle (a macOS `.app`, a Linux tarball, a Windows `.exe` + zip),
//! assembling the macOS `Info.plist` around [`permissions`]'s derivation — never
//! authoring a permission itself.
//!
//! [`mobile`] wraps the client-wasm `Web` SPA (the `web client` bundle) in a
//! thin iOS/Android system-webview shell that loads the bundle offline from app
//! assets, assembling the `Info.plist` / `AndroidManifest.xml` around
//! [`permissions`]'s derivation — never authoring a permission itself.

pub mod desktop;
pub mod mobile;
pub mod permissions;

/// Escape an author-supplied string for splicing into an XML/plist document —
/// the single source of truth for the packager's XML injection boundary.
///
/// Both the macOS/iOS `Info.plist` (text nodes) and the Android manifest
/// (attribute values) route their author-supplied identity strings through this
/// one function, so the injection surface cannot reopen in one packager while the
/// other is hardened. It escapes the five XML metacharacters (`& < > " '`) and,
/// fail-closed, drops the C0 control bytes that XML 1.0 forbids outright in a
/// document (everything below `0x20` except tab, LF, CR) — those cannot be
/// represented even as numeric character references, so a value carrying one can
/// never be rendered safely and the only sound outcome is to strip it.
pub(crate) fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(ch),
            // C0 controls XML 1.0 forbids in a document (no numeric ref can
            // represent them) — drop rather than emit an unrepresentable byte.
            c if (c as u32) < 0x20 => {}
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod xml_escape_tests {
    use super::xml_escape;

    #[test]
    fn each_xml_metacharacter_is_escaped() {
        assert_eq!(xml_escape("&"), "&amp;");
        assert_eq!(xml_escape("<"), "&lt;");
        assert_eq!(xml_escape(">"), "&gt;");
        assert_eq!(xml_escape("\""), "&quot;");
        assert_eq!(xml_escape("'"), "&apos;");
    }

    #[test]
    fn a_plist_injection_payload_cannot_break_out_of_its_node() {
        // A hostile identity string trying to close the <string> node and inject
        // a sibling key must come back fully neutralised — no raw `<`, `>`, `&`.
        let payload = "</string><key>injected</key><string>evil & co";
        let escaped = xml_escape(payload);
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
        assert_eq!(
            escaped,
            "&lt;/string&gt;&lt;key&gt;injected&lt;/key&gt;&lt;string&gt;evil &amp; co"
        );
    }

    #[test]
    fn a_forbidden_control_byte_is_dropped_not_emitted() {
        // NUL and other C0 controls XML 1.0 forbids are stripped, not passed
        // through, so no unrepresentable byte reaches the document.
        assert_eq!(xml_escape("a\u{0}b\u{1}c\u{1f}d\u{8}\u{b}\u{c}"), "abcd");
    }

    #[test]
    fn xml_legal_whitespace_survives() {
        assert_eq!(xml_escape("a\tb\nc\rd"), "a\tb\nc\rd");
    }
}
