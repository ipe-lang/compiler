//! The `.md` message catalog — the single source of the CLI's user-facing messages.
//!
//! `text/messages.md` holds every message as a `## <key>` section whose body is
//! the message; `{name}` marks a value filled in when it is shown. Rust never
//! spells a message: it calls the function declared for the key below, whose
//! parameters are exactly the message's placeholders, so a call site supplies
//! the values the text interpolates and nothing else. Each declaration resolves
//! its text at build time and asserts, in a `const`, that its section exists
//! once with exactly its placeholders, so a drifted catalog fails the build; the
//! catalog tests add that every section has a declaration. Edit the `.md`, never
//! a Rust string.
//!
//! A CLI error carries its text as a [`Message`], which only this module builds
//! (through the functions under [`msg`]), so an error spelled as a Rust literal
//! is a type error. A message with placeholders is returned only as a
//! [`Message`], never as a bare `String`, so every filled text a caller holds
//! has passed both the per-value and the whole-text sanitising. Every
//! placeholder value is sanitised on its own and written inline, so a line
//! break inside it is indented as a continuation and cannot open a line the
//! message never wrote; only a [`TerminalBlock`] places lines at column 0. A
//! placeholder whose value is untrusted — raw user input, fetched content, a
//! child process's output — is also declared `&TerminalSafe`, so the value is
//! sanitised where it is parsed.

use std::borrow::Cow;
use std::fmt::{self, Write as _};
use std::ops::Deref;

/// A user-facing message: a catalog text, or an already-rendered error relayed
/// verbatim.
///
/// Only this module constructs one, so a message cannot be spelled as a Rust
/// literal at a use site. Its text is terminal-safe by construction: a filled
/// or relayed text passes [`TerminalSafe::sanitize`], so no placeholder value
/// (trusted by declaration or not) can carry an escape sequence or a control
/// byte other than `\n` and `\t` into it.
///
/// [`TerminalSafe::sanitize`]: crate::style::TerminalSafe::sanitize
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message(Cow<'static, str>);

impl Message {
    /// A catalog text without placeholders.
    const fn fixed(text: &'static str) -> Self {
        Self(Cow::Borrowed(text))
    }

    /// A filled or relayed text, with escapes and stray control bytes stripped.
    ///
    /// [`fill`] already sanitised each value at its boundary; this whole-text
    /// pass is the second, independent gate.
    fn filled(text: &str) -> Self {
        Self(Cow::Owned(
            crate::style::TerminalSafe::sanitize(text)
                .as_str()
                .to_owned(),
        ))
    }

    /// Relay a typed refusal whose own `Display` is its user-facing text.
    ///
    /// Only a [`Relayable`] type qualifies: a closed set of typed refusals and
    /// diagnostics whose text is built from trusted parts, and whose untrusted
    /// parts (a dependency name, a file label) are [`TerminalSafe`] from the
    /// moment the refusal is built, so an arbitrary string (and the untrusted
    /// bytes it may carry) cannot become a message. The whole-text pass here
    /// is the second, independent gate.
    ///
    /// [`TerminalSafe`]: crate::style::TerminalSafe
    #[must_use]
    pub fn relay(rendered: &impl Relayable) -> Self {
        let mut text = String::new();
        // A `Display` that errs leaves what it wrote so far; relaying it is
        // better than aborting the error path.
        let _ = write!(text, "{rendered}");
        Self::filled(&text)
    }

    /// Join catalog messages into one, one message per line.
    #[must_use]
    pub fn lines(lines: impl IntoIterator<Item = Self>) -> Self {
        let mut joined = String::new();
        for (index, line) in lines.into_iter().enumerate() {
            if index > 0 {
                joined.push('\n');
            }
            joined.push_str(&line.0);
        }
        Self(Cow::Owned(joined))
    }

    /// The message text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Seals [`Relayable`] so only this module can extend its allowlist.
mod sealed {
    /// The sealing supertrait of [`super::Relayable`].
    pub trait Sealed {}
}

/// A typed refusal or diagnostic that [`Message::relay`] may carry verbatim.
///
/// Sealed: the allowlist below is closed, so relaying a raw string (and any
/// untrusted bytes in it) is a type error.
pub trait Relayable: fmt::Display + sealed::Sealed {}

/// Admit each listed type to [`Relayable`].
macro_rules! relayable {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl sealed::Sealed for $ty {}
            impl Relayable for $ty {}
        )+
    };
}

relayable!(
    crate::build_plan::Refusal,
    crate::delivery::DeliveryError,
    crate::pack::mobile::MobileRefusal,
    crate::pack::mobile::BundleError,
    crate::pack::desktop::DesktopRefusal,
    crate::ffi::WrapperRefusal,
    crate::ffi::BuildScriptsBanner,
    ipe_watch::ScopeError,
    ipe_docs::argv::NonUtf8Argument,
    ipe_lint::ConfigError,
    ipe_sandbox::run_jail::RunJailDefect,
    ipe_ffi::diag::Diagnostic,
    ipe_ffi::diag::WireDefect,
);

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Deref for Message {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for Message {
    fn eq(&self, other: &str) -> bool {
        *self.0 == *other
    }
}

impl PartialEq<&str> for Message {
    fn eq(&self, other: &&str) -> bool {
        *self.0 == **other
    }
}

impl PartialEq<String> for Message {
    fn eq(&self, other: &String) -> bool {
        *self.0 == **other
    }
}

impl From<Message> for String {
    fn from(message: Message) -> Self {
        message.0.into_owned()
    }
}

/// The message catalog.
pub const CATALOG: &str = include_str!("../text/messages.md");

/// One catalog section: its key and its body.
type Section = (&'static str, &'static str);

/// How many `## <key>` sections the catalog defines.
const SECTION_COUNT: usize = count_sections(CATALOG);

/// Every catalog section in catalog order, parsed once at build time.
static SECTIONS: [Section; SECTION_COUNT] = index_sections(CATALOG);

/// The text of the catalog's `## <key>` section, checked against its declaration.
///
/// The text is the section's body without its blank edge lines, running to the
/// next `#` or `##` heading. It is empty unless the declaration of `key` with
/// parameters `params` agrees with the catalog: the catalog defines `key`
/// exactly once, with a non-empty body whose placeholders are exactly `params`.
/// Every declared message resolves its text through this in a `const` and
/// asserts the text is non-empty, so the build refuses a renamed or deleted
/// section, a duplicated one, or a renamed placeholder.
#[must_use]
pub const fn checked_section(key: &str, params: &[&str]) -> &'static str {
    checked_section_in(&SECTIONS, key, params)
}

/// [`checked_section`] over the parsed sections `sections`.
const fn checked_section_in(sections: &[Section], key: &str, params: &[&str]) -> &'static str {
    let mut found: Option<&'static str> = None;
    let mut rest = sections;
    while let [(section_key, body), tail @ ..] = rest {
        if bytes_eq(section_key.as_bytes(), key.as_bytes()) {
            if found.is_some() {
                return "";
            }
            found = Some(*body);
        }
        rest = tail;
    }
    if let Some(body) = found
        && !body.is_empty()
        && every_placeholder_is_a_param(body.as_bytes(), params)
        && every_param_is_a_placeholder(body.as_bytes(), params)
    {
        return body;
    }
    ""
}

/// How many `## <key>` headings the catalog text `catalog` carries.
const fn count_sections(catalog: &str) -> usize {
    let mut count: usize = 0;
    let mut rest = catalog.as_bytes();
    while let [byte, tail @ ..] = rest {
        if *byte == b'\n' && strip_prefix(tail, b"## ").is_some() {
            count = count.saturating_add(1);
        }
        rest = tail;
    }
    count
}

/// The `N` sections of the catalog text `catalog`, in order.
///
/// `N` is [`count_sections`] of the same text; evaluated only in a `const`, so a
/// disagreement is a build error, never a runtime one.
#[allow(clippy::indexing_slicing)] // const-evaluated only: an index past `N` fails the build
const fn index_sections<const N: usize>(catalog: &'static str) -> [Section; N] {
    let mut sections: [Section; N] = [("", ""); N];
    let mut filled: usize = 0;
    let mut rest = catalog.as_bytes();
    while let [byte, tail @ ..] = rest {
        if *byte == b'\n'
            && let Some(heading) = strip_prefix(tail, b"## ")
        {
            sections[filled] = section_at(heading);
            filled = filled.saturating_add(1);
        }
        rest = tail;
    }
    sections
}

/// The key and body of the section whose heading text (past `## `) opens `heading`.
///
/// The key is the rest of the heading line; the body runs from the next line to
/// the next `#` or `##` heading, without its blank edge lines.
const fn section_at(heading: &'static [u8]) -> Section {
    let mut key_len: usize = 0;
    let mut rest = heading;
    while let [byte, tail @ ..] = rest {
        if *byte == b'\n' {
            break;
        }
        key_len = key_len.saturating_add(1);
        rest = tail;
    }
    let Some((key, after_key)) = heading.split_at_checked(key_len) else {
        return ("", "");
    };
    let body = trim_newlines(until_heading(after_key));
    match (core::str::from_utf8(key), core::str::from_utf8(body)) {
        (Ok(key), Ok(body)) => (key, body),
        _ => ("", ""),
    }
}

/// `hay` past `prefix`, or `None` when `hay` does not start with `prefix`.
const fn strip_prefix<'a>(mut hay: &'a [u8], mut prefix: &[u8]) -> Option<&'a [u8]> {
    loop {
        match (hay, prefix) {
            (_, []) => return Some(hay),
            ([h, hay_tail @ ..], [p, prefix_tail @ ..]) if *h == *p => {
                hay = hay_tail;
                prefix = prefix_tail;
            }
            _ => return None,
        }
    }
}

/// Whether `a` and `b` hold the same bytes.
pub(crate) const fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && strip_prefix(a, b).is_some()
}

/// `body` up to (not including) its first `\n# ` or `\n## ` heading line.
const fn until_heading(body: &[u8]) -> &[u8] {
    let mut len: usize = 0;
    let mut rest = body;
    while let [byte, tail @ ..] = rest {
        if *byte == b'\n'
            && (strip_prefix(tail, b"# ").is_some() || strip_prefix(tail, b"## ").is_some())
        {
            break;
        }
        len = len.saturating_add(1);
        rest = tail;
    }
    let Some((head, _)) = body.split_at_checked(len) else {
        return body;
    };
    head
}

/// `bytes` without its leading and trailing newlines.
const fn trim_newlines(mut bytes: &[u8]) -> &[u8] {
    while let [b'\n', tail @ ..] = bytes {
        bytes = tail;
    }
    while let [init @ .., b'\n'] = bytes {
        bytes = init;
    }
    bytes
}

/// The placeholder name opening `after_brace` (the bytes after a `{`).
///
/// A placeholder name is lowercase letters, digits, and `_`, starting with a
/// letter; empty when the text up to the next `}` is not one.
const fn placeholder_name(after_brace: &[u8]) -> &[u8] {
    let mut len: usize = 0;
    let mut rest = after_brace;
    while let [c, tail @ ..] = rest {
        if *c == b'}' {
            let Some((name, _)) = after_brace.split_at_checked(len) else {
                return b"";
            };
            return name;
        }
        let allowed = c.is_ascii_lowercase() || (len > 0 && (c.is_ascii_digit() || *c == b'_'));
        if !allowed {
            return b"";
        }
        len = len.saturating_add(1);
        rest = tail;
    }
    b""
}

/// Whether every placeholder `body` interpolates is one of `params`.
const fn every_placeholder_is_a_param(body: &[u8], params: &[&str]) -> bool {
    let mut rest = body;
    while let [c, tail @ ..] = rest {
        if *c == b'{' {
            let name = placeholder_name(tail);
            if !name.is_empty() && !names_contain(params, name) {
                return false;
            }
        }
        rest = tail;
    }
    true
}

/// Whether every one of `params` appears in `body` as a `{param}` placeholder.
const fn every_param_is_a_placeholder(body: &[u8], params: &[&str]) -> bool {
    let mut rest = params;
    while let [param, tail @ ..] = rest {
        if !has_placeholder(body, param.as_bytes()) {
            return false;
        }
        rest = tail;
    }
    true
}

/// Whether `names` holds `name`.
const fn names_contain(names: &[&str], name: &[u8]) -> bool {
    let mut rest = names;
    while let [candidate, tail @ ..] = rest {
        if bytes_eq(candidate.as_bytes(), name) {
            return true;
        }
        rest = tail;
    }
    false
}

/// Whether `body` contains `{name}`.
const fn has_placeholder(body: &[u8], name: &[u8]) -> bool {
    let mut rest = body;
    while let [_, tail @ ..] = rest {
        if let Some(after_open) = strip_prefix(rest, b"{")
            && let Some(after_name) = strip_prefix(after_open, name)
            && strip_prefix(after_name, b"}").is_some()
        {
            return true;
        }
        rest = tail;
    }
    false
}

/// A value a catalog placeholder takes, and the role that fixes how it is written.
///
/// Every value is inline except a [`TerminalBlock`]: it is sanitised on its
/// own and each line after its first is indented by the continuation indent,
/// so a line break inside it cannot open a line the message never wrote. Only
/// a [`TerminalBlock`] places lines at column 0, and only its constructor
/// decides where they break.
pub trait Placeholder {
    /// Append the value to `out` in its role's terminal-safe form.
    fn place(&self, out: &mut String);
}

/// Append `value` inline: sanitised, with continuation lines indented.
fn place_inline(value: &(impl fmt::Display + ?Sized), out: &mut String) {
    let mut shown = String::new();
    // A `Display` that errs leaves what it wrote so far; the message is
    // still filled rather than aborted.
    let _ = write!(shown, "{value}");
    let _ = write!(out, "{}", crate::style::TerminalSafe::sanitize(&shown));
}

impl Placeholder for &(dyn fmt::Display + '_) {
    fn place(&self, out: &mut String) {
        place_inline(*self, out);
    }
}

impl Placeholder for &crate::style::TerminalSafe {
    fn place(&self, out: &mut String) {
        place_inline(*self, out);
    }
}

impl Placeholder for &crate::package_name::PackageName {
    fn place(&self, out: &mut String) {
        place_inline(*self, out);
    }
}

impl Placeholder for &Message {
    fn place(&self, out: &mut String) {
        place_inline(*self, out);
    }
}

impl Placeholder for &TerminalBlock {
    fn place(&self, out: &mut String) {
        out.push_str(&self.0);
    }
}

/// Lines a message shows at column 0, such as a list of files.
///
/// Only [`TerminalBlock::lines`] builds one, and it alone puts a line break
/// between the lines it is given. Each line is sanitised and written inline,
/// so a line break carried inside a line's own value is indented as a
/// continuation and cannot start a line of its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalBlock(String);

impl TerminalBlock {
    /// One block line per item, each sanitised and kept to its own line.
    #[must_use]
    pub fn lines<I>(lines: I) -> Self
    where
        I: IntoIterator,
        I::Item: fmt::Display,
    {
        let mut out = String::new();
        let mut first = true;
        for line in lines {
            if !first {
                out.push('\n');
            }
            first = false;
            place_inline(&line, &mut out);
        }
        Self(out)
    }
}

/// Fill `template`'s `{name}` placeholders from `args`.
///
/// Each value is written by its [`Placeholder`] role: sanitised on its own,
/// so an escape sequence a value opens (an unterminated OSC, say) ends at the
/// value's boundary and cannot swallow the catalog text after it, and inline
/// unless it is a [`TerminalBlock`]. Brace text that names no argument is kept
/// as written.
#[must_use]
pub fn fill(template: &str, args: &[(&str, &dyn Placeholder)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(rest.get(..open).unwrap_or(""));
        let from_brace = rest.get(open..).unwrap_or("");
        let after = from_brace.get(1..).unwrap_or("");
        let filled = after.find('}').and_then(|close| {
            let name = after.get(..close)?;
            let (_, value) = args.iter().find(|(arg, _)| *arg == name)?;
            Some((close, *value))
        });
        let Some((close, value)) = filled else {
            out.push('{');
            rest = after;
            continue;
        };
        value.place(&mut out);
        rest = after.get(close.saturating_add(1)..).unwrap_or("");
    }
    out.push_str(rest);
    out
}

/// A message parameter as the `&dyn Placeholder` that [`fill`] takes.
const fn shown(value: &dyn Placeholder) -> &dyn Placeholder {
    value
}

/// The Rust type of a message parameter: `&dyn Display` unless declared.
macro_rules! param_ty {
    () => { &dyn ::std::fmt::Display };
    ($ty:ty) => { $ty };
}

/// Declare one catalog message as a function.
///
/// A message without placeholders is its `&'static str` text; one with
/// placeholders takes one value per placeholder and returns the filled text as
/// a [`Message`], so a filled text exists only in its sanitised form.
/// Either way the text is a `const` resolved by [`checked_section`] at build
/// time, and a `const` assertion that it is non-empty pins the declaration to
/// its section: the build fails when the section is missing, repeated, or
/// empty, or when its placeholders differ from the declared parameters. No
/// lookup runs when the message is shown.
macro_rules! message_fn {
    ($(#[$meta:meta])* $name:ident = $key:literal) => {
        $(#[$meta])*
        #[must_use]
        pub const fn $name() -> &'static str {
            const TEXT: &str = checked_section($key, &[]);
            // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if this declaration drifts from its `text/messages.md` section, the catalog SEAL [ledger #boundary]
            const _: () = assert!(
                !TEXT.is_empty(),
                concat!("message `", $key, "` disagrees with text/messages.md")
            );
            TEXT
        }
    };
    ($(#[$meta:meta])* $name:ident($($param:ident $(: $pty:ty)?),+) = $key:literal) => {
        $(#[$meta])*
        #[must_use]
        pub fn $name($($param: param_ty!($($pty)?)),+) -> Message {
            const TEXT: &str = checked_section($key, &[$(stringify!($param)),+]);
            // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if this declaration drifts from its `text/messages.md` section, the catalog SEAL [ledger #boundary]
            const _: () = assert!(
                !TEXT.is_empty(),
                concat!("message `", $key, "` disagrees with text/messages.md")
            );
            Message::filled(&fill(TEXT, &[$((stringify!($param), shown(&$param))),+]))
        }
    };
}

/// Declare one catalog message as a [`Message`] function beside its text function.
macro_rules! message_value_fn {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[must_use]
        pub const fn $name() -> Message {
            Message::fixed(super::$name())
        }
    };
    ($(#[$meta:meta])* $name:ident($($param:ident $(: $pty:ty)?),+)) => {
        $(#[$meta])*
        #[must_use]
        pub fn $name($($param: param_ty!($($pty)?)),+) -> Message {
            super::$name($($param),+)
        }
    };
}

/// Declare the catalog's messages.
///
/// Each gets a text function, its [`Message`] twin under [`msg`], and a
/// [`DECLARED`] entry.
macro_rules! messages {
    ($($(#[$meta:meta])* $name:ident $(($($param:ident $(: $pty:ty)?),+))? = $key:literal;)*) => {
        $(message_fn!($(#[$meta])* $name $(($($param $(: $pty)?),+))? = $key);)*

        /// Every catalog message as a [`Message`], the only way to build one.
        pub mod msg {
            use super::Message;

            $(message_value_fn!($(#[$meta])* $name $(($($param $(: $pty)?),+))?);)*
        }

        /// Every declared message: its catalog key and its placeholders.
        pub const DECLARED: &[(&str, &[&str])] = &[$(($key, &[$($(stringify!($param)),+)?])),*];
    };
}

messages! {
    /// A command's refusal, behind the `ipe <command>:` prefix.
    command_refusal(command, reason) = "command-refusal";
    /// A command was given a flag it does not recognise.
    unknown_flag(command, flag) = "unknown-flag";
    /// A parent command was given a subcommand it does not recognise.
    unknown_subcommand(command, sub, expected) = "unknown-subcommand";
    /// A command was given a positional it does not take.
    unexpected_argument(command, arg) = "unexpected-argument";
    /// A single-valued flag was given twice.
    flag_repeated(command, flag) = "flag-repeated";
    /// `--plain` and `--json` were both given.
    plain_json_exclusive(command) = "plain-json-exclusive";
    /// A value-taking flag ended the command line.
    flag_needs_value(command, flag) = "flag-needs-value";
    /// A `--target` value outside the vocabulary.
    unsupported_target(target, supported) = "unsupported-target";
    /// `--static` / `--allocator` with a wasm `--target`.
    static_flags_with_wasm(target) = "static-flags-with-wasm";
    /// `--cfree` with a wasm `--target`.
    cfree_with_wasm(target) = "cfree-with-wasm";
    /// `--emit-ir` with `--out`.
    emit_ir_with_out = "emit-ir-with-out";
    /// `--emit-ir` with `--static`.
    emit_ir_with_static = "emit-ir-with-static";
    /// `--emit-ir` with `--target`.
    emit_ir_with_target = "emit-ir-with-target";
    /// `--emit-ir` with `--allocator`.
    emit_ir_with_allocator = "emit-ir-with-allocator";
    /// `--emit-ir` with `--cfree`.
    emit_ir_with_cfree = "emit-ir-with-cfree";
    /// `ipe run --target wasm`, which has no native artifact.
    run_wasm_target = "run-wasm-target";
    /// `ipe run --target wasi` with a native-only flag.
    run_wasi_native_flags = "run-wasi-native-flags";
    /// `ipe eject` without `--out`.
    eject_out_required = "eject-out-required";
    /// `ipe release --target wasi`.
    release_no_wasi = "release-no-wasi";
    /// `ipe release --embed --bundle`.
    release_embed_bundle_exclusive = "release-embed-bundle-exclusive";
    /// `--port 0`.
    port_zero(command) = "port-zero";
    /// A non-numeric `--port`.
    port_invalid(command, value) = "port-invalid";
    /// `ipe fix` without its path.
    fix_usage = "fix-usage";
    /// `ipe lsp` given any arguments.
    lsp_takes_no_arguments = "lsp-takes-no-arguments";
    /// `ipe lint` given more than one path.
    lint_single_path = "lint-single-path";
    /// `ipe package audit --advisory-db` with `--no-advisory-db`.
    audit_advisory_db_exclusive = "audit-advisory-db-exclusive";
    /// `ipe package audit` given more than one path.
    audit_single_path = "audit-single-path";
    /// `ipe package audit` given a repeated output-format flag.
    audit_format_repeated = "audit-format-repeated";
    /// `ipe doc --type` with `--check-examples` or `--list`.
    doc_type_exclusive = "doc-type-exclusive";
    /// `ipe doc --type` given an unexpected positional.
    doc_type_unexpected_positional = "doc-type-unexpected-positional";
    /// `ipe doc serve --port` without a value.
    doc_serve_port_needs_number = "doc-serve-port-needs-number";
    /// `ipe doc <key>` given more than one key.
    doc_single_key = "doc-single-key";
    /// `ipe doc` given more than one path.
    doc_single_path = "doc-single-path";
    /// `ipe add`'s inspector binary is missing.
    ffi_inspector_not_found = "ffi-inspector-not-found";
    /// `ipe add` cannot make a safe scratch directory without an absolute `HOME`.
    ffi_add_home_not_absolute = "ffi-add-home-not-absolute";
    /// `ipe add` has no bubblewrap isolation available.
    ffi_no_bubblewrap = "ffi-no-bubblewrap";
    /// `ipe add`'s inspector payload was empty.
    ffi_add_no_payload = "ffi-add-no-payload";
    /// A confirmation prompt was declined.
    install_aborted = "install-aborted";
    /// A legacy `[[rust.define.*]]` TOML table is no longer supported.
    ffi_legacy_define_removed = "ffi-legacy-define-removed";
    /// Bare `ipe rust`.
    rust_usage = "rust-usage";
    /// `ipe rust add` misuse.
    rust_add_usage = "rust-add-usage";
    /// `ipe rust add`'s confirmation prompt was declined.
    rust_add_aborted = "rust-add-aborted";
    /// `ipe rust remove` misuse.
    rust_remove_usage = "rust-remove-usage";
    /// `ipe rust install` misuse.
    rust_install_usage = "rust-install-usage";
    /// `ipe rust install` found only a `package.ipe` manifest.
    rust_install_package_ipe_unsupported = "rust-install-package-ipe-unsupported";
    /// `ipe rust install` found no legacy manifest.
    rust_install_no_manifest = "rust-install-no-manifest";
    /// `ipe add`/`ipe remove` outside a package.
    pkg_no_manifest = "pkg-no-manifest";
    /// `ipe package publish` given more than one path.
    publish_single_path = "publish-single-path";
    /// `ipe watch`/`ipe build` given a directory with no manifest inside it.
    watch_dir_no_manifest = "watch-dir-no-manifest";
    /// `ipe diff` misuse.
    diff_usage = "diff-usage";
    /// `ipe init --shape` without its value.
    init_shape_needs_value = "init-shape-needs-value";
    /// A directory carries a legacy `ipe.toml` but no `package.ipe`.
    legacy_toml_hint = "legacy-toml-hint";
    /// A `package.ipe` above the entry file is foreign-owned or writable by another user.
    manifest_untrusted(path) = "manifest-untrusted";
    /// A `package.ipe` above the entry file is a symbolic link.
    manifest_symlink(path) = "manifest-symlink";
    /// A `package.ipe` above the entry file cannot be owner-checked on this platform.
    manifest_unverifiable(path) = "manifest-unverifiable";
    /// `build`/`run`/`watch` found no entry and none could be discovered.
    no_entry = "no-entry";
    /// The entry module was not found in the source map (an internal invariant).
    internal_entry_not_in_source_map = "internal-entry-not-in-source-map";
    /// A module in topo order was not found in the source map (an internal invariant).
    internal_module_not_in_source_map = "internal-module-not-in-source-map";
    /// A library package (only `exposedModules`) has no runnable entry.
    library_package_no_entry = "library-package-no-entry";
    /// A packager could not find a `package.ipe` from the given root.
    pkg_not_found_in_dir = "pkg-not-found-in-dir";
    /// Bare `ipe package`.
    package_usage = "package-usage";
    /// `ipe package validate-entry` without its entry-file path.
    package_validate_entry_usage = "package-validate-entry-usage";
    /// `ipe package audit-entry` given more than one path.
    package_audit_entry_single_path = "package-audit-entry-single-path";
    /// `ipe package audit-entry` without its entry-file path.
    package_audit_entry_usage = "package-audit-entry-usage";
    /// Capability inference found no package module to analyse.
    package_capability_inference_no_module = "package-capability-inference-no-module";
    /// `package.ipe` with no `name` field.
    package_manifest_name_required = "package-manifest-name-required";
    /// `package.ipe`'s source root does not exist.
    package_manifest_src_root_missing = "package-manifest-src-root-missing";
    /// `package.ipe` with no top-level `package` binding.
    package_manifest_no_package_binding = "package-manifest-no-package-binding";
    /// `ipe add`/`ipe remove` found no top-level `package` binding to edit.
    package_manifest_no_package_binding_edit = "package-manifest-no-package-binding-edit";
    /// `ipe add`/`ipe remove` found a non-record `package` value.
    package_manifest_package_not_record = "package-manifest-package-not-record";
    /// `ipe add`/`ipe remove` found a non-list `dependencies` field.
    package_manifest_deps_not_list = "package-manifest-deps-not-list";
    /// `ipe add` could not locate the `package` record's closing brace.
    package_manifest_deps_brace_not_found = "package-manifest-deps-brace-not-found";
    /// `ipe add` found the `package` record's closing brace out of range.
    package_manifest_deps_brace_out_of_range = "package-manifest-deps-brace-out-of-range";
    /// `ipe health --yes` with a data form.
    health_yes_with_format = "health-yes-with-format";
    /// `ipe fmt` with two paths.
    fmt_single_path = "fmt-single-path";
    /// `ipe fmt --stdin` with a path.
    fmt_stdin_and_path = "fmt-stdin-and-path";
    /// `ipe fmt --stdin` with a data form.
    fmt_format_with_stdin = "fmt-format-with-stdin";
    /// `ipe fmt` with a data form but no `--check`.
    fmt_format_needs_check = "fmt-format-needs-check";
    /// A bare delivery word that also names a path on disk.
    delivery_word_shadows_path(word) = "delivery-word-shadows-path";
    /// The label over a command group's verb list.
    verbs_label = "verbs-label";
    /// The heading of a help page's argument description.
    help_arguments_label = "help-arguments-label";
    /// The heading of a help page's option list.
    help_options_label = "help-options-label";
    /// The heading of a help page's output-location note.
    help_output_label = "help-output-label";
    /// An allocator name outside the closed set.
    unknown_allocator(allocator) = "unknown-allocator";
    /// A triple that is not a supported static target.
    unknown_static_target(target, supported) = "unknown-static-target";
    /// `--target` without `--static`.
    target_requires_static(target) = "target-requires-static";
    /// A non-default allocator for a dynamic build.
    allocator_requires_static(allocator) = "allocator-requires-static";
    /// The talc allocator, not yet wired.
    talc_requires_arena_design = "talc-requires-arena-design";
    /// A webview app asked to build static.
    webview_static = "webview-static";
    /// The rustup target is not installed.
    target_not_installed(triple) = "target-not-installed";
    /// No musl-capable C compiler for the triple.
    musl_c_compiler_missing(triple, triple_env) = "musl-c-compiler-missing";
    /// `mimalloc` with `--cfree`.
    mimalloc_requires_c(allocator) = "mimalloc-requires-c";
    /// The libc allocator with `--cfree`.
    libc_allocator_requires_c(allocator) = "libc-allocator-requires-c";
    /// `--cfree`, not yet wired.
    cfree_not_yet_wired = "cfree-not-yet-wired";
    /// A malformed boolean request value.
    invalid_bool(source, value) = "invalid-bool";
    /// The CLI positional shape disagrees with `main`'s own shape.
    delivery_shape_mismatch(stated, pinned) = "delivery-shape-mismatch";
    /// The literal token `served` was written.
    delivery_served_not_a_word = "delivery-served-not-a-word";
    /// A runtime word was given for a non-web shape.
    delivery_runtime_on_non_web(shape) = "delivery-runtime-on-non-web";
    /// A host word was given for a non-web shape.
    delivery_host_on_non_web(shape, host) = "delivery-host-on-non-web";
    /// A mobile host was given for the served runtime.
    delivery_served_host_not_mobile(host) = "delivery-served-host-not-mobile";
    /// `--static` was requested for `web desktop` (a webview host).
    delivery_static_not_allowed_webview = "delivery-static-not-allowed-webview";
    /// `--static` was requested for a delivery with no static form.
    delivery_static_not_allowed(delivery) = "delivery-static-not-allowed";
    /// An unknown token appeared where a runtime or host was expected.
    delivery_unknown_token(got) = "delivery-unknown-token";
    /// A runtime or host token was given more than once.
    delivery_duplicate_token(kind, got) = "delivery-duplicate-token";
    /// A `solo` delivery resolved to a native compile target.
    delivery_solo_requires_wasm_target = "delivery-solo-requires-wasm-target";
    /// A wasm compile target resolved without a `solo` delivery.
    delivery_wasm_target_requires_solo = "delivery-wasm-target-requires-solo";
    /// A WASM triple was requested for the native engine.
    delivery_native_engine_refuses_wasm_triple(triple) = "delivery-native-engine-refuses-wasm-triple";
    /// A `web solo` client asked for a non-browser triple.
    delivery_solo_requires_browser_triple(triple) = "delivery-solo-requires-browser-triple";
    /// A `web solo` client asked for the WASI triple.
    delivery_solo_refuses_wasi_triple = "delivery-solo-refuses-wasi-triple";
    /// A musl static triple was requested for a webview-native delivery.
    delivery_webview_has_no_static_triple(delivery) = "delivery-webview-has-no-static-triple";
    /// A co-located WASI build was asked to carry a `solo` delivery.
    delivery_wasi_refuses_solo_delivery = "delivery-wasi-refuses-solo-delivery";
    /// A co-located WASI build was asked for a non-`Direct` shape.
    delivery_wasi_requires_direct_shape(shape) = "delivery-wasi-requires-direct-shape";
    /// A co-located WASI engine was asked for a non-WASI triple.
    delivery_wasi_requires_wasi_triple(triple) = "delivery-wasi-requires-wasi-triple";
    /// A static-build request was refused.
    cli_static_refusal(refusal) = "cli-static-refusal";
    /// The Ipe runtime module tree could not be located.
    cli_runtime_not_found = "cli-runtime-not-found";
    /// Neither `$XDG_CACHE_HOME` nor `$HOME` names an absolute directory.
    cli_cache_home_unknown = "cli-cache-home-unknown";
    /// A directory environment variable is set to a relative path.
    cli_env_dir_not_absolute(var) = "cli-env-dir-not-absolute";
    /// `$IPE_RUNTIME_DIR` does not name a runtime crate root.
    cli_runtime_dir_invalid(path) = "cli-runtime-dir-invalid";
    /// The invalid runtime dir looks like the inner module directory.
    cli_runtime_dir_invalid_inner_hint = "cli-runtime-dir-invalid-inner-hint";
    /// No directory could be resolved to materialize the embedded runtime.
    cli_runtime_home_unknown = "cli-runtime-home-unknown";
    /// Writing the embedded runtime source failed.
    cli_runtime_materialize_failed(detail) = "cli-runtime-materialize-failed";
    /// The resolved runtime crate declares a different version than the compiler.
    cli_runtime_version_mismatch(path, found, expected) = "cli-runtime-version-mismatch";
    /// `cargo` failed because the runtime lacks a feature the emitted project needs.
    cli_emitted_build_feature_missing(what, feature) = "cli-emitted-build-feature-missing";
    /// The runtime root/version context appended to a feature-gap message.
    cli_emitted_build_feature_context(root, version) = "cli-emitted-build-feature-context";
    /// The stale-runtime remediation hint appended to a feature-gap message.
    cli_emitted_build_stale_runtime_hint = "cli-emitted-build-stale-runtime-hint";
    /// `cargo` could not reach the registry while fetching crates.
    cli_cargo_fetch_failed(code, what) = "cli-cargo-fetch-failed";
    /// `cargo` could not reach the registry while fetching crates, with detail.
    cli_cargo_fetch_failed_detail(code, what, trimmed) = "cli-cargo-fetch-failed-detail";
    /// `cargo` produced no output while failing to compile the emitted project.
    cli_cargo_compile_failed(code, what) = "cli-cargo-compile-failed";
    /// `cargo` failed to compile the emitted project, with detail.
    cli_cargo_compile_failed_detail(code, what, trimmed) = "cli-cargo-compile-failed-detail";
    /// The declared-vs-inferred capability mismatch headline.
    cli_capability_mismatch_header = "cli-capability-mismatch-header";
    /// The used-but-not-declared capability list line.
    cli_capability_mismatch_missing(list) = "cli-capability-mismatch-missing";
    /// The declared-but-not-used capability list line.
    cli_capability_mismatch_extra(list) = "cli-capability-mismatch-extra";
    /// A fetched package's content hash did not match the index's pinned hash.
    cli_hash_mismatch(package, expected, actual) = "cli-hash-mismatch";
    /// `ipe doc <query>` named no documentation entry.
    cli_doc_not_found(query) = "cli-doc-not-found";
    /// The header over a doc-not-found suggestion list.
    cli_doc_suggestions_header = "cli-doc-suggestions-header";
    /// One suggested documentation entry.
    cli_doc_suggestion_line(key, title, kind) = "cli-doc-suggestion-line";
    /// `ipe explain <CODE>` was given a string that is not a taxonomy code.
    cli_unknown_code(input) = "cli-unknown-code";
    /// The first suggested code for an unknown-code error.
    cli_unknown_code_did_you_mean(first) = "cli-unknown-code-did-you-mean";
    /// The verify mode found the proposed version does not clear the required floor.
    cli_semver_rejected(required, floor, proposed) = "cli-semver-rejected";
    /// `ipe package publish` declined to proceed.
    cli_publish_refused(refusal) = "cli-publish-refused";
    /// A package's version cannot enter the package index.
    cli_version_refused(package, refusal) = "cli-version-refused";
    /// A command group was followed by a token that is not one of its verbs.
    cli_unknown_group_verb(group, attempted) = "cli-unknown-group-verb";
    /// The near-miss suggestion offered for an unknown group verb.
    cli_unknown_group_suggestion(group, sugg) = "cli-unknown-group-suggestion";
    /// A stage of `ipe verify` failed.
    cli_verify_failed(stage) = "cli-verify-failed";
    /// The project's test runner exited non-zero.
    cli_test_failed_suffix(code) = "cli-test-failed-suffix";
    /// `ipe upgrade` could not find a prebuilt binary for the requested version.
    cli_upgrade_no_prebuilt(glyph, version, platform) = "cli-upgrade-no-prebuilt";
    /// `ipe health` found a critical prerequisite missing.
    cli_health_critical = "cli-health-critical";
    /// `ipe eject` was asked to eject a program it cannot make self-contained.
    cli_eject_unsupported(reason) = "cli-eject-unsupported";
    /// `ipe lint` found one or more findings at or above the gate severity.
    cli_lint_gate_failed = "cli-lint-gate-failed";
    /// A file exceeded the per-surface read ceiling.
    cli_file_too_large(path, max) = "cli-file-too-large";
    /// A remote transfer crossed its declared ingest budget.
    cli_remote_ingest_exceeded(source, limit) = "cli-remote-ingest-exceeded";
    /// A remote transfer ran past its wall-time ceiling.
    cli_remote_ingest_timed_out(source, limit) = "cli-remote-ingest-timed-out";
    /// A package source crossed a transfer or tree ceiling, naming the publisher's fix.
    cli_package_source_exceeded(source, limit) = "cli-package-source-exceeded";
    /// A remote transfer sent data it refuses by its shape.
    cli_remote_ingest_refused(source, shape) = "cli-remote-ingest-refused";
    /// A signal ended a remote transfer.
    cli_transfer_interrupted = "cli-transfer-interrupted";
    /// A local walk or git query crossed its ceiling.
    cli_local_limit_exceeded(source, limit) = "cli-local-limit-exceeded";
    /// A local git query ran past its wall-time ceiling.
    cli_local_timed_out(source, limit) = "cli-local-timed-out";
    /// A local walk met an entry it refuses by its shape.
    cli_local_tree_refused(source, shape) = "cli-local-tree-refused";
    /// A finished child's output pipe stayed open past the grace.
    cli_child_pipe_held(stream) = "cli-child-pipe-held";
    /// A source path named a FIFO, device, socket or other non-regular file.
    cli_source_not_regular_file(path) = "cli-source-not-regular-file";
    /// A source file or directory could not be opened for lack of permission.
    cli_source_access_denied(path) = "cli-source-access-denied";
    /// A module path was reached through a symlink the no-follow walk refuses.
    cli_source_symlink(path) = "cli-source-symlink";
    /// A manifest path escaped the project directory.
    cli_path_escape(raw, reason) = "cli-path-escape";
    /// A build-output location was refused.
    cli_output_refused(refusal) = "cli-output-refused";
    /// The module-discovery walk hit its depth ceiling or a symlink cycle.
    cli_discovery_limit_reached(detail) = "cli-discovery-limit-reached";
    /// A discovered source file names a Windows reserved device as a module segment.
    cli_device_named_module(path, segment) = "cli-device-named-module";
    /// A locked dependency falls within an advisory's affected range.
    cli_advisory_vulnerable(package, version, severity, id, description, fixed_in) =
        "cli-advisory-vulnerable";
    /// The fixed-in-version line appended to an advisory message.
    cli_advisory_fixed_in(v) = "cli-advisory-fixed-in";
    /// An advisory DB file could not be read.
    cli_advisory_db_unreachable(detail) = "cli-advisory-db-unreachable";
    /// An advisory DB file was present but malformed.
    cli_advisory_db_malformed(path, detail) = "cli-advisory-db-malformed";
    /// `ipe run --target wasi` on a binary built without the `wasi_run` feature.
    cli_wasi_run_feature_disabled = "cli-wasi-run-feature-disabled";
    /// The embedded wasmtime engine could not run the emitted WASI module.
    cli_wasi_run_failed(detail) = "cli-wasi-run-failed";
    /// The emitted WASI module ran to completion with a non-zero exit code.
    cli_wasi_run_exited(code) = "cli-wasi-run-exited";
    /// The "unknown command" line shown above the top-level help screen.
    cli_unknown_command_line(attempted) = "cli-unknown-command-line";
    /// The near-miss suggestion offered for an unknown command.
    cli_unknown_command_suggestion(sugg) = "cli-unknown-command-suggestion";
    /// A missing-file `Io` error.
    cli_io_not_found(path) = "cli-io-not-found";
    /// A non-missing-file `Io` error.
    cli_io_other(path, kind) = "cli-io-other";
    /// No private scratch directory could be created under the OS temp root.
    cli_scratch_unavailable(kind) = "cli-scratch-unavailable";
    /// The OS refused to start a thread the command needs.
    cli_thread_refused(role, kind) = "cli-thread-refused";
    /// The thread that runs an `ipe watch` session.
    thread_role_watch_session = "thread-role-watch-session";
    /// The thread that coalesces `ipe watch` file events.
    thread_role_watch_coalesce = "thread-role-watch-coalesce";
    /// The thread that relays filesystem events to `ipe watch`.
    thread_role_watch_fs_relay = "thread-role-watch-fs-relay";
    /// The thread that relays a stop request to `ipe watch`.
    thread_role_watch_stop_relay = "thread-role-watch-stop-relay";
    /// The thread that retries an `ipe watch` dependency resolve.
    thread_role_watch_resolve_retry = "thread-role-watch-resolve-retry";
    /// The thread that runs an `ipe watch` compile.
    thread_role_watch_compile = "thread-role-watch-compile";
    /// The thread that waits on an `ipe watch` cargo build.
    thread_role_watch_cargo_waiter = "thread-role-watch-cargo-waiter";
    /// The thread that enforces a WASI run's wall-clock ceiling.
    thread_role_wasi_wall_clock = "thread-role-wasi-wall-clock";
    /// `ipe watch` could not start its dependency-resolve retry thread.
    watch_thread_refused(detail) = "watch-thread-refused";
    /// Publish from a dirty working tree.
    publish_dirty_tree(source_root) = "publish-dirty-tree";
    /// Publish of an unpushed HEAD.
    publish_unpushed_head(rev) = "publish-unpushed-head";
    /// Publish of an already published version.
    publish_duplicate_version(name, version) = "publish-duplicate-version";
    /// Publish without a determinable source URL.
    publish_no_source = "publish-no-source";
    /// Publish without a commit-signing key.
    publish_unsigned_commit = "publish-unsigned-commit";
    /// Publish without a resolvable GitHub identity.
    publish_unresolvable_identity = "publish-unresolvable-identity";
    /// An `ipe.lock` `[[package]]` table lacks a required field.
    lock_missing_field(field) = "lock-missing-field";
    /// An `ipe.lock` package carries an unrecognised `kind`.
    lock_unknown_kind(package, kind) = "lock-unknown-kind";
    /// An `ipe.lock` index dependency records a `local` rev.
    lock_index_dep_local_rev(package) = "lock-index-dep-local-rev";
    /// A path dependency's `source` cannot be recorded in `ipe.lock`.
    lock_unrecordable_local_source(package, max, raw) = "lock-unrecordable-local-source";
    /// A path dependency's path is not valid UTF-8.
    lock_non_utf8_local_path(package, path) = "lock-non-utf8-local-path";
    /// A version string that is not valid semver.
    version_refused_malformed(raw, reason) = "version-refused-malformed";
    /// A version carrying build metadata.
    version_refused_build_metadata(version, build) = "version-refused-build-metadata";
    /// A version not above the greatest published one.
    version_refused_not_above(candidate, greatest) = "version-refused-not-above";
    /// The documentation site's skip-to-content link.
    site_skip_link = "site-skip-link";
    /// The accessible name of the site navigation.
    site_nav_label = "site-nav-label";
    /// The site title, full form.
    site_title_full = "site-title-full";
    /// The site title, short (mobile) form.
    site_title_short = "site-title-short";
    /// The accessible name of the mobile menu toggle.
    site_menu_label = "site-menu-label";
    /// The Guides section.
    site_guides = "site-guides";
    /// The Topics section.
    site_topics = "site-topics";
    /// The Idioms section.
    site_idioms = "site-idioms";
    /// The Constructs section.
    site_constructs = "site-constructs";
    /// The Reference section.
    site_reference = "site-reference";
    /// The Diagnostics section.
    site_diagnostics = "site-diagnostics";
    /// The CLI section.
    site_cli = "site-cli";
    /// The site landing page.
    site_documentation = "site-documentation";
    /// The search box placeholder.
    site_search_placeholder = "site-search-placeholder";
    /// The search box accessible name.
    site_search_label = "site-search-label";
    /// The search results accessible name.
    site_search_results_label = "site-search-results-label";
    /// The theme toggle accessible name.
    site_theme_toggle_label = "site-theme-toggle-label";
    /// The scroll-to-top button accessible name.
    site_scroll_top_label = "site-scroll-top-label";
    /// The module filter placeholder.
    site_filter_modules = "site-filter-modules";
    /// The module filter accessible name.
    site_filter_modules_label = "site-filter-modules-label";
    /// The project modules group.
    site_project_modules = "site-project-modules";
    /// The standard library group.
    site_standard_library = "site-standard-library";
    /// A module page's types heading.
    site_types = "site-types";
    /// A module page's values heading.
    site_values = "site-values";
    /// An entry with no body.
    site_no_documentation = "site-no-documentation";
    /// The landing page's pointer to the reference when no guide exists (HTML).
    site_reference_fallback = "site-reference-fallback";
    /// The diagnostics page's key to the code letters (HTML).
    site_code_families_intro = "site-code-families-intro";
    /// `ipe type-check` found no type errors.
    type_check_ok = "type-check-ok";
    /// `ipe upgrade` found the running version current.
    upgrade_up_to_date(version) = "upgrade-up-to-date";
    /// `ipe upgrade` could not reach the release feed.
    upgrade_feed_unreachable = "upgrade-feed-unreachable";
    /// `ipe upgrade` found a newer release.
    upgrade_available(current, latest) = "upgrade-available";
    /// `ipe upgrade`'s confirmation prompt.
    upgrade_confirm = "upgrade-confirm";
    /// `ipe release` wrote a single self-jailing binary.
    release_embedded(path) = "release-embedded";
    /// `ipe release --bundle` wrote a wrapper and app pair.
    release_bundled(path) = "release-bundled";
    /// One disclosure line under a consent refusal.
    consent_item(item) = "consent-item";
    /// The headline of the ungranted web-capability refusal.
    web_consent_header = "web-consent-header";
    /// An ungranted web axis and the modules that disclose it.
    web_consent_disclosure(wire, via) = "web-consent-disclosure";
    /// An ungranted web axis no scanned module could be attributed to.
    web_consent_disclosure_unattributed(wire) = "web-consent-disclosure-unattributed";
    /// The remedy closing the ungranted web-capability refusal.
    web_consent_remedy = "web-consent-remedy";
    /// The headline of the ungranted native-crossing refusal.
    native_ffi_consent_header = "native-ffi-consent-header";
    /// An ungranted native crossing and the modules that cross it.
    native_ffi_crossing(krate, via) = "native-ffi-crossing";
    /// An ungranted native crossing no scanned crate could be attributed to.
    native_ffi_crossing_unattributed = "native-ffi-crossing-unattributed";
    /// The remedy closing the ungranted native-crossing refusal.
    native_ffi_consent_remedy = "native-ffi-consent-remedy";
    /// A derived control model the declared `acceptsControl` set does not cover.
    control_model_consent_refusal(entry_module, model, ctor) = "control-model-consent-refusal";
    /// The headline of the unbacked OS-permission refusal.
    permission_consent_header(platform) = "permission-consent-header";
    /// The remedy closing the unbacked OS-permission refusal.
    permission_consent_remedy = "permission-consent-remedy";
    /// `ipe package audit` found no `package.ipe` in the directory.
    audit_no_manifest(path) = "audit-no-manifest";
    /// `ipe package audit` was given a path that is neither a project nor a manifest.
    audit_not_a_package(path) = "audit-not-a-package";
    /// An index entry file is not named `packages/<name>.toml`.
    index_entry_path_invalid(path) = "index-entry-path-invalid";
    /// An index entry exceeds the per-entry version ceiling.
    index_entry_too_many_versions(name: &crate::package_name::PackageName, count, max) = "index-entry-too-many-versions";
    /// An index entry rewrites a published version.
    index_entry_version_rewritten(name: &crate::package_name::PackageName, version) = "index-entry-version-rewritten";
    /// An index entry drops a published version.
    index_entry_version_dropped(name: &crate::package_name::PackageName, version) = "index-entry-version-dropped";
    /// A reserved package's audit-entry drops a published version without a blessed reset.
    index_entry_version_dropped_reset_refused(name: &crate::package_name::PackageName, version, refusal) =
        "index-entry-version-dropped-reset-refused";
    /// An index entry moves a package's source repository.
    index_entry_source_moved(name: &crate::package_name::PackageName, version, source, expected) = "index-entry-source-moved";
    /// `ipe clean` ran outside a project root.
    clean_no_manifest = "clean-no-manifest";
    /// `ipe diff` was given a version the package index would refuse.
    diff_invalid_version(refusal) = "diff-invalid-version";
    /// `ipe fmt` found no `.ipe` files.
    fmt_no_files(root) = "fmt-no-files";
    /// `ipe fmt --check` found unformatted files.
    fmt_unformatted_files(list: &crate::text::TerminalBlock) = "fmt-unformatted-files";
    /// `ipe fmt --stdin --check` found the input unformatted.
    fmt_stdin_unformatted = "fmt-stdin-unformatted";
    /// `ipe fmt` was given a missing path.
    fmt_no_such_path(root) = "fmt-no-such-path";
    /// `ipe health` could not locate the home directory.
    health_home_unknown = "health-home-unknown";
    /// An `ipe health` install command was empty (an internal invariant).
    health_install_command_empty = "health-install-command-empty";
    /// An `ipe health` install command could not be launched.
    health_install_launch_failed(program, detail) = "health-install-launch-failed";
    /// An `ipe health` install command exited non-zero.
    health_install_failed(program) = "health-install-failed";
    /// `ipe health` refused to overwrite a malformed config.
    health_config_not_toml(path, detail) = "health-config-not-toml";
    /// `ipe health`'s edited config did not re-parse.
    health_config_edit_unparsable(path) = "health-config-edit-unparsable";
    /// `ipe lint --fix` with a data form.
    lint_fix_with_format = "lint-fix-with-format";
    /// The language server failed.
    lsp_failed(detail) = "lsp-failed";
    /// `ipe watch` could not start its filesystem watcher.
    watch_start_failed(detail) = "watch-start-failed";
    /// `ipe watch` could not watch a path.
    watch_path_failed(path, detail) = "watch-path-failed";
    /// `ipe watch` could not bind its blue-green proxy's port.
    watch_proxy_bind_failed(port, detail) = "watch-proxy-bind-failed";
    /// A `ships` delivery is listed twice.
    ships_repeated(delivery) = "ships-repeated";
    /// A `ships` delivery does not fit the shape of `main`.
    ships_shape_mismatch(delivery, shape) = "ships-shape-mismatch";
    /// `ipe add` found the package already declared as an escape dependency.
    pkg_add_escape_dependency(name) = "pkg-add-escape-dependency";
    /// A `package.ipe` program entry has an empty path segment.
    manifest_entry_empty_segment(entry) = "manifest-entry-empty-segment";
    /// A `package.ipe` program entry has a `.` or `..` path segment.
    manifest_entry_dot_segment(entry) = "manifest-entry-dot-segment";
    /// A `package.ipe` program entry contains a backslash.
    manifest_entry_backslash(entry) = "manifest-entry-backslash";
    /// A `package.ipe` program entry opens with a drive prefix.
    manifest_entry_drive_prefix(entry) = "manifest-entry-drive-prefix";
    /// A `package.ipe` program entry does not end in `.ipe`.
    manifest_entry_extension(entry) = "manifest-entry-extension";
    /// A `package.ipe` program entry has an invalid module segment.
    manifest_entry_segment_invalid(entry, segment) = "manifest-entry-segment-invalid";
    /// A `package.ipe` program entry names no module.
    manifest_entry_no_module(entry) = "manifest-entry-no-module";
    /// A manifest path is not a `package.ipe`.
    manifest_not_package_ipe(path, hint) = "manifest-not-package-ipe";
    /// A package name is not a single path component for a bundle.
    bundle_name_not_a_component(name) = "bundle-name-not-a-component";
    /// The emitted wasm bundle has no top-level `index.html`.
    mobile_bundle_no_index(dir) = "mobile-bundle-no-index";
    /// An entry of the emitted wasm bundle a mobile shell cannot place.
    mobile_bundle_unplaceable(path, reason) = "mobile-bundle-unplaceable";
    /// The emitted wasm bundle nests directories past the walk's depth ceiling.
    mobile_bundle_too_deep(limit, path) = "mobile-bundle-too-deep";
    /// The emitted wasm bundle holds more entries than the walk's ceiling.
    mobile_bundle_too_many(limit) = "mobile-bundle-too-many";
    /// The emitted wasm bundle was replaced between its collection and its copy.
    mobile_bundle_replaced(path) = "mobile-bundle-replaced";
    /// A filesystem failure while walking the emitted wasm bundle.
    mobile_bundle_io(path, detail) = "mobile-bundle-io";
    /// A bundle entry's name is not UTF-8.
    mobile_asset_not_utf8 = "mobile-asset-not-utf8";
    /// A bundle entry's name is not one plain entry name.
    mobile_asset_bad_name = "mobile-asset-bad-name";
    /// A bundle entry is neither a regular file nor a directory.
    mobile_asset_kind(kind) = "mobile-asset-kind";
    /// A generate-only flag was given to an `ipe doc` subcommand.
    doc_generate_only_flag(sub, flag) = "doc-generate-only-flag";
    /// `--port` was given to an `ipe doc` subcommand other than `serve`.
    doc_port_serve_only(sub) = "doc-port-serve-only";
    /// A lookup-only flag was given to an `ipe doc` subcommand.
    doc_lookup_only_flag(sub, flag) = "doc-lookup-only-flag";
    /// An unknown `ipe doc --write-format` value.
    doc_unknown_write_format(format) = "doc-unknown-write-format";
    /// The standard-library documentation index could not be built.
    doc_stdlib_index_failed(detail) = "doc-stdlib-index-failed";
    /// The documentation bundle could not be built.
    doc_bundle_build_error(detail) = "doc-bundle-build-error";
    /// An `ipe doc <kind>:<key>` query named an unknown kind.
    doc_unknown_kind(prefix) = "doc-unknown-kind";
    /// An `ipe doc <kind>:<key>` query named no entry of that kind.
    doc_no_entry_for_key(kind, key, nearby: &crate::text::TerminalBlock) = "doc-no-entry-for-key";
    /// An `ipe doc <query>` short name matched more than one stdlib module.
    doc_ambiguous_module(query, candidates: &crate::text::TerminalBlock) = "doc-ambiguous-module";
    /// `ipe doc --type` matched no symbol.
    doc_type_no_match(query) = "doc-type-no-match";
    /// The kernel type table could not be read for `ipe doc`.
    doc_kernel_table_error(detail) = "doc-kernel-table-error";
    /// `ipe doc --type` was given a malformed type expression.
    doc_type_invalid_query(query, detail) = "doc-type-invalid-query";
    /// `ipe doc --type` matched no symbol, with a hint to broaden the query.
    doc_type_no_match_hint(query) = "doc-type-no-match-hint";
    /// An FFI cache entry is not owned by the user or another user can write it.
    ffi_cache_untrusted(path) = "ffi-cache-untrusted";
    /// The FFI cache's ownership cannot be verified on this platform.
    ffi_cache_unverifiable(path) = "ffi-cache-unverifiable";
    /// An FFI cache component or artifact is a symbolic link.
    ffi_cache_symlink(path) = "ffi-cache-symlink";
    /// An FFI cache artifact is not a regular file.
    ffi_cache_not_regular(path) = "ffi-cache-not-regular";
    /// An FFI cache directory lists more entries than the loader admits.
    ffi_cache_too_many_entries(path, max) = "ffi-cache-too-many-entries";
    /// A project module clashes with an installed FFI crate.
    ffi_module_clash(module, krate) = "ffi-module-clash";
    /// An FFI define type collides with an inspected opaque type.
    ffi_define_opaque_collision(krate, name) = "ffi-define-opaque-collision";
    /// Installed FFI crates bind one dependency name to two different sources.
    ffi_dependency_source_conflict(name, first, second) = "ffi-dependency-source-conflict";
    /// Installed FFI crates pin one dependency to two versions.
    ffi_dependency_pin_conflict(name, first, second) = "ffi-dependency-pin-conflict";
    /// Emitted FFI code names a dependency left out of the manifest.
    ffi_dropped_transitive(name, ident, site) = "ffi-dropped-transitive";
    /// Emitted FFI code does not lex, so its crate references are unknown.
    ffi_emit_unlexable(site) = "ffi-emit-unlexable";
    /// An FFI binding marks a type transparent without its shape.
    ffi_transparent_without_shape(krate, name, binding) = "ffi-transparent-without-shape";
    /// An FFI crate claims the reserved asserted-call module.
    ffi_reserved_module_claimed(krate, module) = "ffi-reserved-module-claimed";
    /// An FFI wrapper uses the reserved asserted-shim prefix.
    ffi_reserved_wrapper_prefix(krate, wrapper, prefix) = "ffi-reserved-wrapper-prefix";
    /// A project module takes the reserved asserted-call module name.
    ffi_reserved_module_exists(module) = "ffi-reserved-module-exists";
    /// Asserted calls were validated against an empty FFI catalog (an internal invariant).
    ffi_asserted_empty_catalog = "ffi-asserted-empty-catalog";
    /// `ipe add` could not prepare its scratch directory.
    ffi_add_scratch_dir(detail) = "ffi-add-scratch-dir";
    /// `ipe add` would bind a toolchain directory that exposes the cargo home.
    ffi_toolchain_bind_exposes_cargo_home(bind, cargo_home) = "ffi-toolchain-bind-exposes-cargo-home";
    /// `ipe add` found no cargo home to keep out of the jail.
    ffi_cargo_home_unresolved = "ffi-cargo-home-unresolved";
    /// `ipe add` refused a jail path that does not resolve or a home it cannot mask.
    ffi_jail_path_refused(detail) = "ffi-jail-path-refused";
    /// `ipe install` could not write the manifest.
    ffi_install_manifest_write_failed(detail) = "ffi-install-manifest-write-failed";
    /// `ipe install` could not write a manifest chunk.
    ffi_install_manifest_chunk_write_failed(detail) = "ffi-install-manifest-chunk-write-failed";
    /// FFI regeneration read malformed inspector JSON.
    ffi_regen_invalid_json(detail) = "ffi-regen-invalid-json";
    /// FFI regeneration read inspector output of an unexpected shape.
    ffi_regen_unexpected_shape(output) = "ffi-regen-unexpected-shape";
    /// FFI regeneration read an inspector item with no name.
    ffi_regen_item_unnamed(item) = "ffi-regen-item-unnamed";
    /// `ipe install` read malformed inspector JSON.
    ffi_install_invalid_json(detail) = "ffi-install-invalid-json";
    /// `ipe install` read inspector output of an unexpected shape.
    ffi_install_unexpected_shape(output) = "ffi-install-unexpected-shape";
    /// A legacy define table names no crate among several.
    ffi_define_crate_ambiguous(kind, name) = "ffi-define-crate-ambiguous";
    /// The inspection JSON is not an object, with the parse detail.
    ffi_inspection_not_object_detail(detail) = "ffi-inspection-not-object-detail";
    /// The inspection JSON is not an object.
    ffi_inspection_not_object = "ffi-inspection-not-object";
    /// The inspection's `functions` field is not an array.
    ffi_inspection_functions_not_array = "ffi-inspection-functions-not-array";
    /// A foreign `Opaque` names a type the crate does not report.
    ffi_opaque_unknown_type(name, rust_type, krate) = "ffi-opaque-unknown-type";
    /// A foreign `Opaque` names a type the inspector surfaced as a value.
    ffi_opaque_is_transparent(name, rust_type) = "ffi-opaque-is-transparent";
    /// A foreign `Opaque` names a type reported without a Rust path.
    ffi_opaque_without_path(name, rust_type) = "ffi-opaque-without-path";
    /// A foreign `Opaque` is declared twice over different types.
    ffi_opaque_declared_twice(name) = "ffi-opaque-declared-twice";
    /// A refusal at a source location.
    located_refusal(file, line, col, reason) = "located-refusal";
    /// `ipe init` was asked to reshape an existing project.
    init_shape_fixed(existing, stated) = "init-shape-fixed";
    /// `ipe init`'s shape positional and `--shape` disagree.
    init_shape_disagrees(positional, flag) = "init-shape-disagrees";
    /// `ipe init` was given a web runtime for a non-web shape.
    init_runtime_needs_web(runtime, shape) = "init-runtime-needs-web";
    /// `ipe init` was given an unknown shape word.
    init_unknown_shape(word) = "init-unknown-shape";
    /// `ipe init` was given an unknown runtime word.
    init_unknown_runtime(word) = "init-unknown-runtime";
    /// `ipe init`'s shape prompt was answered with an unknown choice.
    init_unknown_shape_choice(word) = "init-unknown-shape-choice";
    /// `ipe init`'s runtime prompt was answered with an unknown choice.
    init_unknown_runtime_choice(word) = "init-unknown-runtime-choice";
    /// `ipe init` could not derive a project name.
    init_no_project_name(target) = "init-no-project-name";
    /// GitHub returned a verification URL off `https://github.com`.
    login_verification_url_refused = "login-verification-url-refused";
    /// The device code expired before approval.
    login_code_expired_before_approval = "login-code-expired-before-approval";
    /// GitHub returned a malformed token.
    login_token_malformed = "login-token-malformed";
    /// The authorization was denied.
    login_denied = "login-denied";
    /// The device code expired.
    login_code_expired = "login-code-expired";
    /// GitHub reported an unrecognised status.
    login_github_reported(status: &crate::style::TerminalSafe) = "login-github-reported";
    /// GitHub's response carried neither a token nor a status.
    login_response_unrecognised = "login-response-unrecognised";
    /// `curl` could not be launched for the OAuth request.
    login_curl_unavailable(detail) = "login-curl-unavailable";
    /// The OAuth request failed while waiting for `curl`.
    login_curl_wait_failed(detail) = "login-curl-wait-failed";
    /// The OAuth request failed.
    login_request_failed(detail: &crate::style::TerminalSafe) = "login-request-failed";
    /// GitHub's response is not JSON.
    login_response_not_json(detail) = "login-response-not-json";
    /// GitHub's response lacks a field.
    login_response_missing(key) = "login-response-missing";
    /// No config directory could be determined for the token.
    login_config_dir_unknown = "login-config-dir-unknown";
    /// A directory or file could not be created for the token.
    login_create_failed(path, detail) = "login-create-failed";
    /// The token file could not be written.
    login_write_failed(path, detail) = "login-write-failed";
    /// The token file could not be moved into place.
    login_move_failed(path, detail) = "login-move-failed";
    /// The token file could not be removed.
    login_remove_failed(path, detail) = "login-remove-failed";
    /// The token cannot be stored owner-only on this platform.
    login_token_store_unsupported = "login-token-store-unsupported";
    /// A token file or its directory is not private to the invoking user.
    login_secret_not_owner_only(path) = "login-secret-not-owner-only";
    /// The token's directory is a symbolic link.
    login_secret_symlinked_dir(path) = "login-secret-symlinked-dir";
    /// A token file's name is held by something other than a regular file.
    login_secret_not_regular_file(path) = "login-secret-not-regular-file";
    /// The per-user cache salt's directory is a symbolic link.
    build_cache_dir_symlinked(path) = "build-cache-dir-symlinked";
    /// The per-user cache salt's directory, or an ancestor, is not private.
    build_cache_dir_untrusted(path) = "build-cache-dir-untrusted";
    /// `ipe login --status`: a well-formed token is stored.
    login_status_logged_in(path) = "login-status-logged-in";
    /// `ipe login --status`: the token file exists but does not parse.
    login_status_corrupt(path) = "login-status-corrupt";
    /// `ipe login --status`: the token file is not private to the invoking user.
    login_status_exposed(path) = "login-status-exposed";
    /// `ipe login --status`: the token's directory is a symbolic link.
    login_status_symlinked_dir(path) = "login-status-symlinked-dir";
    /// `ipe login --status`: the token's directory, or an ancestor, is not private.
    login_status_dir_untrusted(path) = "login-status-dir-untrusted";
    /// `ipe login --status`: no token is stored.
    login_status_not_logged_in = "login-status-not-logged-in";
    /// `ipe login` stored the token.
    login_stored(path) = "login-stored";
    /// `ipe login --logout` found no token to remove.
    login_logout_nothing = "login-logout-nothing";
    /// `ipe login --logout` removed the token.
    login_logout_removed(path) = "login-logout-removed";
    /// The device-flow prompt: what the grant is for, where to go, and the code.
    login_device_prompt(purpose, url, code: &crate::style::TerminalSafe) = "login-device-prompt";
    /// What the publish-token grant is for.
    login_grant_purpose_publish = "login-grant-purpose-publish";
    /// What the one-shot signing-key-registration grant is for.
    login_grant_purpose_signing_key(scope) = "login-grant-purpose-signing-key";
    /// `ipe login --status`: the signing key comes from the environment variable.
    signing_key_status_env(path: &crate::style::TerminalSafe, env) = "signing-key-status-env";
    /// `ipe login --status`: the environment variable names no usable key.
    signing_key_status_env_unusable(env) = "signing-key-status-env-unusable";
    /// `ipe login --status`: the signing key `ipe login` generated.
    signing_key_status_stored(path: &crate::style::TerminalSafe) = "signing-key-status-stored";
    /// `ipe login --status`: the stored signing key is not private to the invoking user.
    signing_key_status_stored_exposed(path: &crate::style::TerminalSafe, settings) = "signing-key-status-stored-exposed";
    /// `ipe login --status`: something other than a usable key file holds the stored key's name.
    signing_key_status_stored_unusable(path: &crate::style::TerminalSafe) = "signing-key-status-stored-unusable";
    /// `ipe login --status`: the stored key's directory is a symbolic link.
    signing_key_status_symlinked_dir(path: &crate::style::TerminalSafe) = "signing-key-status-symlinked-dir";
    /// `ipe login --status`: the stored key's directory, or an ancestor, is not private.
    signing_key_status_dir_untrusted(path: &crate::style::TerminalSafe, settings) = "signing-key-status-dir-untrusted";
    /// `ipe login --status`: no signing key is configured.
    signing_key_status_none = "signing-key-status-none";
    /// Signing-key setup found a usable key already configured.
    signing_key_already_configured(path: &crate::style::TerminalSafe) = "signing-key-already-configured";
    /// Signing-key setup found the environment variable set but unusable.
    signing_key_env_unusable(env) = "signing-key-env-unusable";
    /// The user declined signing-key setup.
    signing_key_declined(env) = "signing-key-declined";
    /// A signing key was generated, registered, and stored.
    signing_key_registered(path: &crate::style::TerminalSafe, settings) = "signing-key-registered";
    /// The consent question before generating and registering a signing key.
    signing_key_consent_question(path: &crate::style::TerminalSafe, scope, revoke_url) = "signing-key-consent-question";
    /// No signing key is configured and no terminal is available to set one up.
    signing_key_hint_no_terminal = "signing-key-hint-no-terminal";
    /// `ipe login --signing-key` without an interactive terminal.
    signing_key_needs_terminal = "signing-key-needs-terminal";
    /// No config directory could be determined for the signing key.
    signing_key_no_config_dir = "signing-key-no-config-dir";
    /// This host cannot keep the signing key's private half owner-only.
    signing_key_store_unsupported(env) = "signing-key-store-unsupported";
    /// A signing-key file or its directory is not private to the invoking user.
    signing_key_not_owner_only(path: &crate::style::TerminalSafe, env) = "signing-key-not-owner-only";
    /// The signing key's directory is a symbolic link.
    signing_key_symlinked_dir(path: &crate::style::TerminalSafe) = "signing-key-symlinked-dir";
    /// The stored key is already registered on GitHub but is not private to the
    /// invoking user; it must be revoked, never silently replaced.
    signing_key_stored_exposed(path: &crate::style::TerminalSafe, settings) = "signing-key-stored-exposed";
    /// A non-key entry occupies a signing-key file name.
    signing_key_occupied(path: &crate::style::TerminalSafe) = "signing-key-occupied";
    /// The config directory cannot hold the hard links key storage relies on.
    signing_key_link_unsupported(dir: &crate::style::TerminalSafe, detail: &crate::style::TerminalSafe, env) = "signing-key-link-unsupported";
    /// The OS random-number generator failed.
    signing_key_generation_failed = "signing-key-generation-failed";
    /// A filesystem step before registration failed.
    signing_key_write_failed(path: &crate::style::TerminalSafe, detail: &crate::style::TerminalSafe) = "signing-key-write-failed";
    /// Registration failed and the local key was removed.
    signing_key_registration_failed(reason: &crate::text::Message) = "signing-key-registration-failed";
    /// The key is registered on GitHub but could not be stored locally.
    signing_key_commit_failed(path: &crate::style::TerminalSafe, detail: &crate::style::TerminalSafe, title, settings) = "signing-key-commit-failed";
    /// The key-registration device-flow authorization failed.
    signing_key_authorization_failed(reason: &crate::style::TerminalSafe) = "signing-key-authorization-failed";
    /// GitHub refused the signing key.
    signing_key_refused(status, message: &crate::style::TerminalSafe) = "signing-key-refused";
    /// The key-registration request got no HTTP answer.
    signing_key_unreachable(reason: &crate::style::TerminalSafe) = "signing-key-unreachable";
    /// `ipe add` was given a malformed version requirement.
    pkg_invalid_requirement(requirement, detail) = "pkg-invalid-requirement";
    /// The usage line of `ipe add` / `ipe remove`.
    pkg_usage(command) = "pkg-usage";
    /// `ipe package publish` could not infer the fork owner.
    publish_fork_owner_unknown = "publish-fork-owner-unknown";
    /// `ipe package publish` found no `package.ipe` in the directory.
    publish_no_manifest(path) = "publish-no-manifest";
    /// `ipe package publish` was given a path that is neither a project nor a manifest.
    publish_not_a_package(path) = "publish-not-a-package";
    /// `ipe package publish` found no version in the manifest.
    publish_no_version(name) = "publish-no-version";
    /// `ipe package publish` refused the source URL.
    publish_source_refused(detail) = "publish-source-refused";
    /// `ipe package publish` refused the revision.
    publish_rev_refused(detail) = "publish-rev-refused";
    /// `ipe package publish`'s `--rev` resolved to a non-SHA.
    publish_rev_not_sha(detail) = "publish-rev-not-sha";
    /// `ipe package publish`'s `HEAD` did not resolve to a full SHA.
    publish_head_not_sha(detail) = "publish-head-not-sha";
    /// `ipe package publish --fresh` outside the reserved probe.
    publish_fresh_refused(name) = "publish-fresh-refused";
    /// The emitted `fn main` anchor is absent from the build.
    run_main_anchor_absent = "run-main-anchor-absent";
    /// A jail profile does not parse.
    run_profile_unparsable(code, detail) = "run-profile-unparsable";
    /// A binary carries no readable capability floor.
    run_floor_unreadable(code) = "run-floor-unreadable";
    /// A declared program entry outside `Main` is not yet buildable.
    build_entry_not_main(module) = "build-entry-not-main";
    /// `ipe pack` is retired.
    pack_retired = "pack-retired";
    /// `ipe build` found no binary after a successful `cargo build`.
    build_binary_missing(path) = "build-binary-missing";
    /// `ipe release` found no binary after a successful `cargo build`.
    release_binary_missing(path) = "release-binary-missing";
    /// `ipe release` found no app binary after a successful `cargo build`.
    release_app_binary_missing(path) = "release-app-binary-missing";
    /// `ipe release` could not locate the workspace root.
    release_workspace_root_unknown = "release-workspace-root-unknown";
    /// `wasm-bindgen` failed while bundling a `--target wasm` build.
    wasm_bindgen_failed(code, version) = "wasm-bindgen-failed";
    /// The `wasm32-wasip1` build reported no `.wasm` artifact.
    wasi_artifact_missing(dir) = "wasi-artifact-missing";
    /// `ipe run --record`/`--replay` on a program with no recordable session.
    session_no_recordable(flag, name) = "session-no-recordable";
    /// `ipe run --record`/`--replay` with `--target wasi`.
    session_native_only(flag) = "session-native-only";
    /// `ipe run --record`/`--replay` on a native-bearing program.
    session_jailed(flag) = "session-jailed";
    /// `ipe run --record` with `--replay`.
    session_flags_exclusive(first, second) = "session-flags-exclusive";
    /// `ipe run --replay` with no recorded log or trace in the output root.
    replay_no_default_log(typed, trace) = "replay-no-default-log";
    /// `ipe run --replay <log>` naming no regular file.
    replay_log_missing(path) = "replay-log-missing";
    /// A run program exited non-zero.
    program_exited(program, code) = "program-exited";
    /// `ipe exec` found no artifact directory.
    exec_no_artifact_dir(dir) = "exec-no-artifact-dir";
    /// `ipe exec` found no built binary.
    exec_no_binary(path) = "exec-no-binary";
    /// `ipe exec` found a floor-carrying binary without its jail profile.
    exec_profile_missing(path) = "exec-profile-missing";
    /// `cargo metadata` failed.
    cargo_metadata_failed(dir, detail) = "cargo-metadata-failed";
    /// `cargo metadata` emitted malformed JSON.
    cargo_metadata_unparsable(detail) = "cargo-metadata-unparsable";
    /// `cargo metadata` reported no target directory.
    cargo_metadata_no_target_dir = "cargo-metadata-no-target-dir";
    /// `ipe explain` moved to `ipe doc`.
    explain_moved = "explain-moved";
    /// No app binary after a successful `cargo build`.
    app_binary_missing(path) = "app-binary-missing";
    /// The `ipe` binary could not be located to build wasm.
    wasm_ipe_binary_unknown(detail) = "wasm-ipe-binary-unknown";
    /// The mobile shell's `--target wasm` build failed.
    mobile_wasm_build_failed(code) = "mobile-wasm-build-failed";
    /// `--emit-permissions` failed.
    emit_permissions_failed(verb, detail) = "emit-permissions-failed";
    /// `ipe package validate-entry` was given more than one path.
    package_validate_entry_single_path = "package-validate-entry-single-path";
    /// `ipe package audit-entry` found nothing new to audit.
    audit_entry_nothing_new(name) = "audit-entry-nothing-new";
    /// `ipe upgrade` on a platform without the installer.
    upgrade_unsupported_platform(command) = "upgrade-unsupported-platform";
    /// `ipe upgrade`'s installer could not be launched.
    upgrade_installer_launch_failed(detail) = "upgrade-installer-launch-failed";
    /// `ipe upgrade` could not download the installer.
    upgrade_installer_download_failed(detail) = "upgrade-installer-download-failed";
    /// `ipe upgrade`'s installer could not be waited on.
    upgrade_installer_wait_failed(detail) = "upgrade-installer-wait-failed";
    /// `ipe upgrade`'s installer exited non-zero.
    upgrade_installer_failed = "upgrade-installer-failed";
    /// An output path that is a symbolic link.
    output_symlink(path) = "output-symlink";
    /// An output path that exists and is not a directory.
    output_not_a_directory(path) = "output-not-a-directory";
    /// An output directory holding files but no ownership marker.
    output_not_ipe_owned(path, marker) = "output-not-ipe-owned";
    /// An output that is the project root.
    output_project_root(path) = "output-project-root";
    /// An output that encloses the project.
    output_contains_project(out, project) = "output-contains-project";
    /// An output inside the project's source root.
    output_inside_sources(out, sources) = "output-inside-sources";
    /// A project whose source root cannot be resolved.
    output_unresolved_sources(path) = "output-unresolved-sources";
    /// A user-bound output inside a tree ipe owns.
    output_inside_ipe_owned(out, owner) = "output-inside-ipe-owned";
    /// An output inside a `.git` directory.
    output_inside_vcs(out) = "output-inside-vcs";
    /// An output inside an ipe cache namespace.
    output_inside_cache_namespace(out, namespace) = "output-inside-cache-namespace";
    /// An output with a `..` that does not climb out of a plain existing directory.
    output_parent_traversal(path) = "output-parent-traversal";
    /// An output that names no single absolute place on every platform.
    output_unplaceable(path) = "output-unplaceable";
    /// An eject output that is not absent or empty.
    output_not_fresh(path) = "output-not-fresh";
    /// A product path with a component other than a plain name.
    output_unsafe_component(path) = "output-unsafe-component";
    /// A walked file that resolves outside the project.
    output_outside_project(path, root) = "output-outside-project";
    /// An owned directory whose path now names a different directory.
    output_replaced(path) = "output-replaced";
    /// A directory tree nested past the walk's depth ceiling.
    output_too_deep(path, limit) = "output-too-deep";
    /// A path on or under a Windows reparse point.
    output_reparse_point(path) = "output-reparse-point";
    /// An entry another program holds open, so ipe cannot remove or replace it.
    output_in_use(path) = "output-in-use";
    /// A GitHub login with nothing before its optional `[bot]` suffix.
    login_empty = "login-empty";
    /// A GitHub login past the length ceiling.
    login_too_long(max) = "login-too-long";
    /// A GitHub login holding a forbidden character.
    login_forbidden_byte = "login-forbidden-byte";
    /// A GitHub login starting or ending with a hyphen.
    login_edge_hyphen = "login-edge-hyphen";
    /// A GitHub login holding consecutive hyphens.
    login_double_hyphen = "login-double-hyphen";
    /// No proven publisher identity was presented.
    blessing_no_proven_identity = "blessing-no-proven-identity";
    /// The proven identity differs from the claimed publisher.
    blessing_identity_mismatch(proven, claimed) = "blessing-identity-mismatch";
    /// The proven identity is not the blessed first-party publisher.
    blessing_not_blessed(proven, blessed) = "blessing-not-blessed";
    /// `ipe package audit-entry --attested-actor` given a non-login.
    attested_actor_not_login(raw, refusal) = "attested-actor-not-login";
    /// `ipe package audit --publisher` given a non-login.
    audit_publisher_not_login(value, refusal) = "audit-publisher-not-login";
    /// `ipe package publish` from a source whose owner is not a login.
    publish_source_owner_not_login(refusal) = "publish-source-owner-not-login";
    /// `ipe package publish --fresh` without a proven blessed publisher.
    publish_fresh_needs_blessing(name, reason) = "publish-fresh-needs-blessing";
    /// A blessing proof that does not cover the claimed publisher.
    publish_fresh_claim_not_covered(claimed) = "publish-fresh-claim-not-covered";
    /// An index `source` that is not an accepted URL.
    index_source_url_invalid(pkg: &crate::package_name::PackageName, raw: &crate::style::TerminalSafe) = "index-source-url-invalid";
    /// An index `source` on the plaintext `git://` transport.
    index_source_url_plaintext(pkg: &crate::package_name::PackageName, raw: &crate::style::TerminalSafe) = "index-source-url-plaintext";
    /// An index `rev` shaped like an injection.
    index_rev_injection(pkg: &crate::package_name::PackageName, raw: &crate::style::TerminalSafe) = "index-rev-injection";
    /// A recorded `rev` that is not a full commit SHA.
    index_rev_not_immutable(pkg: &crate::package_name::PackageName, raw: &crate::style::TerminalSafe) = "index-rev-not-immutable";
    /// A requested rev that is hex-shaped but mixed-case.
    index_rev_mixed_case_hex(pkg: &crate::package_name::PackageName, raw: &crate::style::TerminalSafe) = "index-rev-mixed-case-hex";
    /// A full-SHA requested rev that disagrees with the commit git served.
    index_rev_served_mismatch(pkg: &crate::package_name::PackageName, requested, served) =
        "index-rev-served-mismatch";
    /// An index `sha256` that is not a content hash.
    index_sha256_invalid(pkg: &crate::package_name::PackageName, raw: &crate::style::TerminalSafe) = "index-sha256-invalid";
    /// An index entry that exists but cannot be read.
    index_entry_unreadable(name: &crate::package_name::PackageName, detail) = "index-entry-unreadable";
    /// `ipe add` of a package the index does not list.
    add_package_not_in_index(name: &crate::package_name::PackageName) = "add-package-not-in-index";
    /// `ipe add` could not read an index entry.
    add_index_entry_unreadable(name: &crate::package_name::PackageName, kind) = "add-index-entry-unreadable";
    /// No published version satisfies the requirement.
    index_no_version_satisfies(name: &crate::package_name::PackageName, req, available) = "index-no-version-satisfies";
    /// The available-versions list of an entry with none.
    index_no_version_available = "index-no-version-available";
    /// An index entry `publisher` that is not a login.
    index_publisher_not_login(name: &crate::package_name::PackageName, refusal) = "index-publisher-not-login";
    /// An index entry without `publisher`.
    index_entry_missing_publisher(name: &crate::package_name::PackageName) = "index-entry-missing-publisher";
    /// An index entry without `[[version]]`.
    index_entry_no_versions(name: &crate::package_name::PackageName) = "index-entry-no-versions";
    /// A malformed registry JSON mirror.
    registry_json_malformed(name: &crate::package_name::PackageName, detail: &crate::style::TerminalSafe) = "registry-json-malformed";
    /// An index entry capability that is not known.
    index_capability_unknown(name: &crate::package_name::PackageName, detail: &crate::style::TerminalSafe) =
        "index-capability-unknown";
    /// A `[[version]]` entry missing a field.
    index_version_missing_field(name: &crate::package_name::PackageName, field) = "index-version-missing-field";
    /// An index entry `capabilities` that is not an array.
    index_capabilities_not_array(name: &crate::package_name::PackageName, raw: &crate::style::TerminalSafe) =
        "index-capabilities-not-array";
    /// `ipe package publish --rev` naming no commit.
    publish_rev_unresolved(refspec: &crate::style::TerminalSafe, rev: &crate::style::TerminalSafe) =
        "publish-rev-unresolved";
    /// A scratch-filesystem failure during publish.
    publish_scratch_io(detail) = "publish-scratch-io";
    /// Cloning the author's index fork failed.
    publish_clone_failed(fork_url, git: &crate::style::TerminalSafe) = "publish-clone-failed";
    /// Pushing to the author's index fork failed.
    publish_push_failed(branch, fork_url, url, git: &crate::style::TerminalSafe) =
        "publish-push-failed";
    /// `ipe package publish` outside a git repository.
    publish_not_git_repo(path) = "publish-not-git-repo";
    /// `ipe package publish` could not run `git`.
    publish_git_unavailable(detail) = "publish-git-unavailable";
    /// A GitHub API call's `-w '%{http_code}'` text was empty.
    publish_http_status_empty(op) = "publish-http-status-empty";
    /// A GitHub API call's status text was not exactly 3 ASCII digits.
    publish_http_status_not_digits(op) = "publish-http-status-not-digits";
    /// A GitHub API call reported curl's "no response" status (`000`).
    publish_http_status_no_response(op) = "publish-http-status-no-response";
    /// A GitHub API call's 3-digit status fell outside 100..=599.
    publish_http_status_out_of_range(op, value) = "publish-http-status-out-of-range";
    /// `curl` exited nonzero before a GitHub API call got a response.
    publish_http_transport_failed(op, detail: &crate::style::TerminalSafe) =
        "publish-http-transport-failed";
    /// A GitHub API response body could not be read back from the scratch file.
    publish_http_body_io(op) = "publish-http-body-io";
    /// A registry trust identity field that is not a token.
    trust_token_invalid(label, raw: &crate::style::TerminalSafe) = "trust-token-invalid";
    /// A malformed signature bundle.
    signature_bundle_malformed(pkg, detail: &crate::style::TerminalSafe) =
        "signature-bundle-malformed";
    /// An unsigned version under a policy requiring signatures.
    signature_required_absent(pkg) = "signature-required-absent";
    /// A publisher signature that does not verify.
    signature_untrusted(pkg, detail: &crate::style::TerminalSafe) = "signature-untrusted";
    /// A malformed registry trust config.
    trust_config_malformed(detail: &crate::style::TerminalSafe) = "trust-config-malformed";
    /// A path dependency whose directory does not exist.
    resolve_path_dep_missing(name, path) = "resolve-path-dep-missing";
    /// An index dependency given to the escape resolver.
    resolve_index_dep_escape(name) = "resolve-index-dep-escape";
    /// Dependency resolution could not run `git`.
    resolve_git_unavailable(name, detail) = "resolve-git-unavailable";
    /// A `git` step of dependency resolution failed.
    resolve_git_failed(name, args: &crate::style::TerminalSafe, stderr: &crate::style::TerminalSafe) =
        "resolve-git-failed";
    /// A fetch that checked out a commit other than the one requested.
    resolve_fetched_commit_mismatch(pkg: &crate::package_name::PackageName, requested, served) =
        "resolve-fetched-commit-mismatch";
    /// An `ipe login` failure.
    login_error(message: &crate::text::Message) = "login-error";
    /// A package name that is not a safe path component.
    package_name_invalid(raw: &crate::style::TerminalSafe, why) = "package-name-invalid";
    /// Why a package name is invalid: it is empty.
    package_name_empty = "package-name-empty";
    /// Why a package name is invalid: it is too long.
    package_name_too_long(max) = "package-name-too-long";
    /// Why a package name is invalid: its first character.
    package_name_bad_start = "package-name-bad-start";
    /// Why a package name is invalid: a doubled `-`.
    package_name_doubled_dash = "package-name-doubled-dash";
    /// Why a package name is invalid: a disallowed character.
    package_name_bad_char = "package-name-bad-char";
    /// Why a package name is invalid: a trailing `-`.
    package_name_trailing_dash = "package-name-trailing-dash";
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Untrusted placeholders reach the rendered refusal with every escape
    /// sequence and control byte stripped, and the surrounding text pinned.
    #[test]
    #[allow(clippy::expect_used)] // the fixture name is a literal registry name
    fn untrusted_placeholders_render_terminal_safe() {
        let pkg = crate::package_name::PackageName::parse("pkg").expect("fixture name parses");
        let hostile =
            crate::style::TerminalSafe::sanitize("x\u{1b}[31my\u{7}z\u{9b}\u{1b}]0;t\u{7}");
        let table: [(Message, &str); 8] = [
            (
                index_rev_not_immutable(&pkg, &hostile),
                "package `pkg`: recorded `rev` is not an immutable commit SHA (expected 40 lowercase hex chars), got: xyz — re-run `ipe add` to record an immutable pin",
            ),
            (
                signature_bundle_malformed(&pkg, &hostile),
                "package `pkg`: signature bundle is malformed (xyz)",
            ),
            (
                trust_config_malformed(&hostile),
                "registry trust config is malformed (xyz)",
            ),
            (
                trust_token_invalid(&"publisher", &hostile),
                "registry trust: `publisher` must be a non-empty token with no whitespace or control characters, got: xyz",
            ),
            (
                add_package_not_in_index(&pkg),
                "add: package `pkg` is not in the index — check the name, or run `ipe rust add` for a Rust crate",
            ),
            (
                index_no_version_satisfies(&pkg, &"^1", &hostile),
                "package `pkg`: no published version satisfies `^1` (available: xyz)",
            ),
            (
                index_source_url_invalid(&pkg, &hostile),
                "package `pkg`: `source` must be an https://, ssh://, or file:// URL (or a bare absolute path), got: xyz",
            ),
            (
                registry_json_malformed(&pkg, &hostile),
                "package `pkg`: registry JSON is malformed (xyz)",
            ),
        ];
        for (rendered, expected) in &table {
            assert_eq!(rendered, expected);
            assert!(
                !rendered
                    .chars()
                    .any(|c| c.is_control() && c != '\n' && c != '\t'),
                "control byte survived in {rendered:?}"
            );
        }
    }

    /// A default-typed placeholder is sanitised too: a `Message` never carries
    /// an escape sequence or a stray control byte, whatever filled it.
    #[test]
    fn every_filled_message_is_terminal_safe() {
        let hostile = "a\u{1b}[2Jb\rc\u{7f}d\u{9b}e";
        let message = msg::publish_no_version(&hostile);
        assert_eq!(
            message,
            "ipe package publish: `abcde` declares no `version = \"…\"` — publish records the version being published, so the manifest must name one."
        );
        let joined = Message::lines([message, msg::publish_no_version(&"x\ny")]);
        assert!(
            !joined
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t'),
            "control byte survived in {joined:?}"
        );
    }

    /// An escape a value leaves open ends at the value: an unterminated OSC
    /// cannot swallow the trusted catalog text that follows it.
    #[test]
    fn an_unterminated_escape_in_a_value_keeps_the_catalog_tail() {
        let message = msg::publish_no_version(&"x\u{1b}]");
        assert_eq!(
            message,
            "ipe package publish: `x` declares no `version = \"…\"` — publish records the version being published, so the manifest must name one."
        );
        // The catalog text after `{why}` opens with a space and a dash, neither
        // a CSI final byte, so a whole-text-only pass would swallow them.
        let raw = crate::style::TerminalSafe::sanitize("raw");
        let csi = msg::package_name_invalid(&raw, &"y\u{1b}[");
        assert_eq!(
            csi,
            "`raw` is not a valid package name: y — a name is joined into a filesystem path, so it must be a single portable path component (matching `[a-z0-9]([a-z0-9]|-[a-z0-9])*`)"
        );
    }

    /// A relayed refusal is sanitised: its own `Display` cannot smuggle an
    /// escape sequence into the message.
    #[test]
    fn a_relayed_refusal_is_terminal_safe() {
        let relayed = Message::relay(&ipe_lint::ConfigError::Rejected(
            "bad\u{1b}]0;title\u{7}key\u{1b}[31m".to_owned(),
        ));
        assert!(
            !relayed
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t'),
            "control byte survived in {relayed:?}"
        );
        assert!(relayed.contains("badkey"), "{relayed:?}");
    }

    /// The catalog itself holds no control byte besides the line break.
    #[test]
    fn the_catalog_is_free_of_control_bytes() {
        assert!(!CATALOG.chars().any(|c| c.is_control() && c != '\n'));
    }

    /// The catalog's `.md` prose cannot call [`crate::style::REPO_URL`] — it is
    /// static text, not Rust — so the literal `cargo install --git …` example it
    /// carries is instead pinned against that SSOT constant here: a drift
    /// between the two fails this test rather than silently linking a stale repo.
    #[test]
    fn the_catalog_install_url_matches_the_repo_url_ssot() {
        assert!(
            CATALOG.contains(crate::style::REPO_URL),
            "messages.md must spell the `cargo install --git` example with {}",
            crate::style::REPO_URL
        );
    }

    /// Every `## <key>` the catalog defines.
    fn catalog_keys() -> Vec<&'static str> {
        CATALOG
            .lines()
            .filter_map(|line| line.trim_end().strip_prefix("## "))
            .collect()
    }

    #[test]
    fn every_declared_message_agrees_with_its_section() {
        for (key, params) in DECLARED {
            assert!(!checked_section(key, params).is_empty(), "`{key}` drifted");
        }
    }

    #[test]
    fn every_section_is_declared_exactly_once() {
        let keys = catalog_keys();
        assert!(!keys.is_empty(), "the catalog defines no section");
        for key in &keys {
            assert!(
                DECLARED.iter().any(|(declared, _)| declared == key),
                "`{key}` has no declaration"
            );
        }
        for (i, (key, _)) in DECLARED.iter().enumerate() {
            assert!(
                !DECLARED
                    .iter()
                    .skip(i.saturating_add(1))
                    .any(|(k, _)| k == key),
                "`{key}` is declared twice"
            );
        }
    }

    #[test]
    fn a_section_body_stops_at_the_next_heading() {
        assert_eq!(
            checked_section("emit-ir-with-out", &[]),
            "--emit-ir does not compose with --out"
        );
        assert_eq!(checked_section("verbs-label", &[]), "Verbs:");
        assert_eq!(emit_ir_with_out(), "--emit-ir does not compose with --out");
    }

    /// A small catalog for driving the agreement check's refusals.
    const FIXTURE: &str = "# fixture\n\n## plain\n\nNo values here.\n\n## one\n\nHello {name}, {name}.\n\n## twice\n\nA\n\n## twice\n\nB\n\n## blank\n\n\n# end\n";

    /// The sections of [`FIXTURE`].
    const FIXTURE_SECTIONS: [Section; count_sections(FIXTURE)] = index_sections(FIXTURE);

    #[test]
    fn the_agreement_check_resolves_a_matching_declaration() {
        assert_eq!(
            checked_section_in(&FIXTURE_SECTIONS, "plain", &[]),
            "No values here."
        );
        assert_eq!(
            checked_section_in(&FIXTURE_SECTIONS, "one", &["name"]),
            "Hello {name}, {name}."
        );
    }

    #[test]
    fn the_agreement_check_refuses_every_drift() {
        // A missing section.
        assert_eq!(checked_section_in(&FIXTURE_SECTIONS, "absent", &[]), "");
        assert_eq!(checked_section("no-such-message", &[]), "");
        // A key that is only a prefix of a section's key.
        assert_eq!(checked_section_in(&FIXTURE_SECTIONS, "on", &["name"]), "");
        // A section defined twice.
        assert_eq!(checked_section_in(&FIXTURE_SECTIONS, "twice", &[]), "");
        // A section with no text.
        assert_eq!(checked_section_in(&FIXTURE_SECTIONS, "blank", &[]), "");
        // A placeholder the declaration does not take.
        assert_eq!(checked_section_in(&FIXTURE_SECTIONS, "one", &[]), "");
        // A declared parameter the text never shows.
        assert_eq!(
            checked_section_in(&FIXTURE_SECTIONS, "one", &["name", "extra"]),
            ""
        );
        assert_eq!(
            checked_section_in(&FIXTURE_SECTIONS, "plain", &["name"]),
            ""
        );
        // A renamed placeholder.
        assert_eq!(checked_section_in(&FIXTURE_SECTIONS, "one", &["nom"]), "");
    }

    #[test]
    fn only_well_formed_names_are_placeholders() {
        assert_eq!(placeholder_name(b"a_2} rest"), b"a_2");
        assert_eq!(placeholder_name(b"Nope}"), b"");
        assert_eq!(placeholder_name(b"2a}"), b"");
        assert_eq!(placeholder_name(b"}"), b"");
        assert_eq!(placeholder_name(b"a b}"), b"");
        assert_eq!(placeholder_name(b"unclosed"), b"");
        assert!(every_placeholder_is_a_param(b"{Nope} {} {", &[]));
    }

    /// A line break inside an inline value is indented, never a line of its own.
    #[test]
    fn an_inline_value_cannot_open_an_output_line() {
        let forged = "x\nerror: forged\u{1b}[2K";
        let filled = command_refusal(&"build", &forged);
        assert_eq!(filled, "ipe build: x\n    error: forged");
        assert!(
            !filled.lines().any(|l| l.starts_with("error:")),
            "{filled:?}"
        );
        let safe = crate::style::TerminalSafe::sanitize(forged);
        let filled = trust_config_malformed(&safe);
        assert!(
            !filled.lines().any(|l| l.starts_with("error:")),
            "{filled:?}"
        );
        let message = msg::command_refusal(&"build", &forged);
        let relayed = command_refusal(&"run", &message);
        assert!(
            !relayed.lines().any(|l| l.starts_with("error:")),
            "{relayed:?}"
        );
    }

    /// A block places its own lines at column 0 and indents a break inside one.
    #[test]
    fn a_block_line_cannot_open_an_output_line() {
        let block = TerminalBlock::lines(["  a.ipe", "  b.ipe\nerror: forged\u{1b}]0;t\u{7}"]);
        let filled = fmt_unformatted_files(&block);
        assert!(
            filled.ends_with(":\n  a.ipe\n  b.ipe\n    error: forged"),
            "{filled:?}"
        );
        assert!(
            !filled.lines().any(|l| l.starts_with("error:")),
            "{filled:?}"
        );
        assert!(!filled.contains('\u{1b}'), "{filled:?}");
        let near = TerminalBlock::lines(["  fn:map", "  fn:x\rerror: forged"]);
        let filled = doc_no_entry_for_key(&"fn", &"mapp", &near);
        assert!(
            filled.ends_with("Nearby keys:\n  fn:map\n  fn:xerror: forged"),
            "{filled:?}"
        );
    }

    /// A text function with placeholders hands back a sanitised [`Message`], never a raw string.
    #[test]
    fn a_filled_text_function_returns_a_terminal_safe_message() {
        let hostile = "out\u{1b}]0;title\u{7}\n\u{1b}[2Kerror: forged\u{9b}31m";
        let message: Message = output_symlink(&hostile);
        assert!(!message.contains('\u{1b}'), "{message:?}");
        assert!(!message.contains('\u{7}'), "{message:?}");
        assert!(!message.contains('\u{9b}'), "{message:?}");
        assert!(
            !message.lines().any(|l| l.starts_with("error:")),
            "{message:?}"
        );
        assert_eq!(message, msg::output_symlink(&hostile));
    }

    #[test]
    fn fill_replaces_named_placeholders_and_keeps_other_braces() {
        let one: &dyn fmt::Display = &1;
        let two: &dyn fmt::Display = &"two";
        let args: [(&str, &dyn Placeholder); 2] = [("x", &one), ("y", &two)];
        assert_eq!(fill("a {x} b {y} {z} {", &args), "a 1 b two {z} {");
        assert_eq!(
            unknown_flag(&"build", &"--nope"),
            "ipe build: unknown flag `--nope`"
        );
    }

    /// Calls whose message argument must come from the catalog.
    const MESSAGE_SINKS: &[&str] = &[
        "CliError::Usage(",
        "Self::Usage(",
        "CliError::Resolve(",
        "Self::Resolve(",
        "Message::relay(",
        "usage(",
        "login_error(",
    ];

    /// Whether `byte` can continue a Rust identifier.
    const fn is_ident_byte(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || byte == b'_'
    }

    /// The end (exclusive) of the string literal whose opening `"` is at `open`.
    fn string_end(bytes: &[u8], open: usize) -> usize {
        let mut i = open.saturating_add(1);
        while let Some(&c) = bytes.get(i) {
            match c {
                b'\\' => i = i.saturating_add(2),
                b'"' => return i.saturating_add(1),
                _ => i = i.saturating_add(1),
            }
        }
        bytes.len()
    }

    /// The end (exclusive) of the raw string literal starting with the `r` at
    /// `at`, or `None` when no raw string starts there.
    fn raw_string_end(bytes: &[u8], at: usize) -> Option<usize> {
        let hashes = bytes
            .get(at.saturating_add(1)..)?
            .iter()
            .take_while(|&&c| c == b'#')
            .count();
        let open = at.saturating_add(1).saturating_add(hashes);
        if bytes.get(open) != Some(&b'"') {
            return None;
        }
        let mut closing = vec![b'"'];
        closing.extend(std::iter::repeat_n(b'#', hashes));
        let body = bytes.get(open.saturating_add(1)..)?;
        let end = body
            .windows(closing.len())
            .position(|w| w == closing.as_slice())
            .map_or(bytes.len(), |pos| {
                open.saturating_add(1)
                    .saturating_add(pos)
                    .saturating_add(closing.len())
            });
        Some(end)
    }

    /// The end (exclusive) of the character literal whose `'` is at `open`, or
    /// `None` when the `'` starts a lifetime.
    fn char_end(src: &str, open: usize) -> Option<usize> {
        let bytes = src.as_bytes();
        let after = open.saturating_add(1);
        if bytes.get(after) == Some(&b'\\') {
            let close = bytes
                .get(after.saturating_add(2)..)?
                .iter()
                .position(|&c| c == b'\'')?;
            return Some(after.saturating_add(3).saturating_add(close));
        }
        let width = src.get(after..)?.chars().next()?.len_utf8();
        let close = after.saturating_add(width);
        if bytes.get(close) == Some(&b'\'') {
            Some(close.saturating_add(1))
        } else {
            None
        }
    }

    /// `src` with comments blanked and literal contents blanked (delimiters
    /// kept), byte for byte, so offsets line up with `src`.
    fn mask(src: &str) -> Vec<u8> {
        let bytes = src.as_bytes();
        let mut out = bytes.to_vec();
        let mut blank = |from: usize, to: usize| {
            for byte in out.iter_mut().take(to).skip(from) {
                if *byte != b'\n' {
                    *byte = b' ';
                }
            }
        };
        let mut i = 0;
        while let Some(&c) = bytes.get(i) {
            let next = bytes.get(i.saturating_add(1)).copied();
            let prev_is_ident = i
                .checked_sub(1)
                .and_then(|p| bytes.get(p))
                .is_some_and(|&p| is_ident_byte(p));
            if c == b'/' && next == Some(b'/') {
                let end = bytes
                    .get(i..)
                    .and_then(|rest| rest.iter().position(|&b| b == b'\n'))
                    .map_or(bytes.len(), |pos| i.saturating_add(pos));
                blank(i, end);
                i = end;
            } else if c == b'/' && next == Some(b'*') {
                let end = bytes
                    .get(i.saturating_add(2)..)
                    .and_then(|rest| rest.windows(2).position(|w| w == b"*/"))
                    .map_or(bytes.len(), |pos| i.saturating_add(pos).saturating_add(4));
                blank(i, end);
                i = end;
            } else if c == b'"' {
                let end = string_end(bytes, i);
                blank(i.saturating_add(1), end.saturating_sub(1));
                i = end;
            } else if c == b'r'
                && !prev_is_ident
                && let Some(end) = raw_string_end(bytes, i)
            {
                blank(i.saturating_add(1), end);
                i = end;
            } else if c == b'\''
                && let Some(end) = char_end(src, i)
            {
                blank(i.saturating_add(1), end.saturating_sub(1));
                i = end;
            } else {
                i = i.saturating_add(1);
            }
        }
        out
    }

    /// The end (exclusive) of the item that starts at `from` in the masked
    /// source: the `;` or the closing `}` that ends it at bracket depth zero.
    fn item_end(masked: &[u8], from: usize) -> usize {
        let mut depth: usize = 0;
        let mut i = from;
        while let Some(&c) = masked.get(i) {
            i = i.saturating_add(1);
            match c {
                b'{' | b'(' | b'[' => depth = depth.saturating_add(1),
                b')' | b']' => depth = depth.saturating_sub(1),
                b'}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return i;
                    }
                }
                b';' if depth == 0 => return i,
                _ => {}
            }
        }
        masked.len()
    }

    /// `src` with every `#[cfg(test)]` item blanked: the production source.
    ///
    /// Only the attributed item goes; production code after it stays.
    fn production_source(src: &str) -> String {
        const TEST_ONLY: &[u8] = b"#[cfg(test)]";
        let masked = mask(src);
        let mut out = src.as_bytes().to_vec();
        let mut from = 0;
        while let Some(at) = masked
            .get(from..)
            .and_then(|rest| rest.windows(TEST_ONLY.len()).position(|w| w == TEST_ONLY))
            .map(|pos| from.saturating_add(pos))
        {
            let end = item_end(&masked, at.saturating_add(TEST_ONLY.len()));
            for byte in out.iter_mut().take(end).skip(at) {
                if *byte != b'\n' {
                    *byte = b' ';
                }
            }
            from = end.max(at.saturating_add(1));
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Whether the format string `content` (a literal's text) spells anything
    /// beyond `{…}` placeholders and whitespace.
    fn has_fixed_text(content: &str) -> bool {
        let mut chars = content.chars();
        while let Some(c) = chars.next() {
            match c {
                '{' => {
                    if chars.clone().next() == Some('{') {
                        return true;
                    }
                    for inner in chars.by_ref() {
                        if inner == '}' {
                            break;
                        }
                    }
                }
                '\\' => {
                    chars.next();
                }
                c if c.is_whitespace() => {}
                _ => return true,
            }
        }
        false
    }

    /// Whether the argument starting at `at` in `src` spells its message as a
    /// literal: a string literal (however converted), `String::from("…")`, or a
    /// `format!` whose format string carries fixed text.
    fn is_literal_message(src: &str, at: usize) -> bool {
        let rest = src.get(at..).unwrap_or("").trim_start();
        let rest = rest.strip_prefix('&').unwrap_or(rest).trim_start();
        if rest.starts_with('"') || rest.starts_with("r\"") || rest.starts_with("r#") {
            return true;
        }
        if let Some(inner) = rest.strip_prefix("String::from(") {
            return inner.trim_start().starts_with('"');
        }
        let Some(inner) = rest.strip_prefix("format!(") else {
            return false;
        };
        let inner = inner.trim_start();
        if inner.starts_with("r\"") || inner.starts_with("r#") {
            return true;
        }
        let Some(body) = inner.strip_prefix('"') else {
            return false;
        };
        let content_end = string_end(inner.as_bytes(), 0).saturating_sub(2);
        has_fixed_text(body.get(..content_end).unwrap_or(body))
    }

    /// Every sink call in `src` whose message is a literal, as byte offsets.
    fn literal_message_calls(src: &str) -> Vec<usize> {
        let production = production_source(src);
        let masked = mask(&production);
        let mut found = Vec::new();
        for sink in MESSAGE_SINKS {
            let mut from = 0;
            while let Some(at) = masked
                .get(from..)
                .and_then(|rest| rest.windows(sink.len()).position(|w| w == sink.as_bytes()))
                .map(|pos| from.saturating_add(pos))
            {
                let after = at.saturating_add(sink.len());
                let standalone = at
                    .checked_sub(1)
                    .and_then(|p| masked.get(p))
                    .is_none_or(|&p| !is_ident_byte(p));
                if standalone && is_literal_message(&production, after) {
                    found.push(at);
                }
                from = after;
            }
        }
        found.sort_unstable();
        found
    }

    /// Every `.rs` file under this crate's `src/`, skipping hidden directories
    /// and `target/`.
    fn rs_files_under(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_owned()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if !name.starts_with('.') && name != "target" {
                        stack.push(path);
                    }
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    out.push(path);
                }
            }
        }
        out
    }

    /// No production code spells a user-facing message as a Rust literal.
    ///
    /// Every message sink (`CliError::Usage`, `CliError::Resolve`, and the
    /// helpers that wrap them) takes its text from a `text::` function, so the
    /// rendered text and its catalog entry cannot drift. `#[cfg(test)]` items and
    /// confirmed out-of-line test modules ([`panic_scan::is_verified_test_path`])
    /// are exempt: a test fixture is not user-facing text.
    #[test]
    fn no_literal_cli_error_usage_outside_the_catalog() {
        let src_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let files = rs_files_under(&src_root);
        assert!(!files.is_empty(), "no sources under {}", src_root.display());
        let mut offenders = Vec::new();
        for path in files {
            let is_test_module = path
                .strip_prefix(&src_root)
                .is_ok_and(|rel| panic_scan::is_verified_test_path(&src_root, rel));
            if is_test_module {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("source is readable");
            for at in literal_message_calls(&src) {
                let line = src
                    .get(..at)
                    .map_or(0, |before| before.matches('\n').count())
                    .saturating_add(1);
                offenders.push(format!("{}:{line}", path.display()));
            }
        }
        assert!(
            offenders.is_empty(),
            "a message spelled as a literal — declare it in text/messages.md and \
             call its text:: fn instead: {offenders:#?}"
        );
    }

    #[test]
    fn the_detector_finds_every_literal_message_shape() {
        let offenders = [
            r#"Err(CliError::Usage("x"))"#,
            r#"Err(CliError::Usage(
                "split across lines"))"#,
            r#"CliError::Usage(format!("bad {x}"))"#,
            r#"CliError::Usage(format!("{}: {}", a, b))"#,
            r#"CliError::Usage(format!("{{literal braces}}"))"#,
            r#"CliError::Usage("x".to_owned())"#,
            r#"CliError::Usage(String::from("x"))"#,
            r#"CliError::Usage(format!(r"raw {x}"))"#,
            r#"Self::Usage("x".into())"#,
            r#"package_manifest::usage("x")"#,
            r#"Message::relay(&format!("no {x} here"))"#,
            r#"CliError::Resolve(format!("package `{name}`: {e}"))"#,
            r#"Self::Resolve("x".into())"#,
            r#"login_error(&format!("failed: {e}"))"#,
            "fn f() {}\n#[cfg(test)]\nfn t() {}\nfn g() { CliError::Usage(\"late\") }",
            "#[cfg(test)]\nuse x;\nfn g() { CliError::Usage(\"after a test-only use\") }",
        ];
        for src in offenders {
            assert_eq!(literal_message_calls(src).len(), 1, "missed: {src}");
        }
    }

    #[test]
    fn the_detector_passes_catalog_calls_comments_strings_and_tests() {
        let clean = [
            "CliError::Usage(text::msg::fix_usage())",
            r#"CliError::Usage(format!("{e}"))"#,
            r#"CliError::Usage(format!("{}\n{}", a, b))"#,
            "CliError::Usage(text::msg::command_refusal(&a, &b))",
            "CliError::Usage(crate::text::Message::relay(&err))",
            "CliError::Resolve(text::msg::index_entry_no_versions(&name))",
            "CliError::Resolve(crate::text::Message::relay(&banner))",
            "// CliError::Usage(\"in a comment\")",
            "/* CliError::Usage(\"in a block comment\") */",
            r#"let s = "CliError::Usage(\"in a string\")";"#,
            r##"let s = r#"CliError::Usage("in a raw string")"#;"##,
            "let c = '{'; let d = '\\''; fn f<'a>(x: &'a str) {}",
            "#[cfg(test)]\nmod tests { fn t() { CliError::Usage(\"fixture\"); } }",
            "fn cli_usage(x: &str) {} fn f() { cli_usage(\"x\") }",
            "fn usage(message: &'static str) -> CliError { CliError::Usage(message) }",
        ];
        for src in clean {
            assert!(literal_message_calls(src).is_empty(), "flagged: {src}");
        }
    }
}
