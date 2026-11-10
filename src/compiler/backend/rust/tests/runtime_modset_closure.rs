//! Fast static SEAL lint for the emitted runtime-module set.
//!
//! The backend trims `ipe_runtime/mod.rs` to a base module set and appends
//! feature-modules per `uses_*` flag. Every `crate::<dep>` path a compiled
//! module names MUST resolve to a module the same emitted `mod.rs` compiles —
//! otherwise `ipe` exits 0 and the emitted crate fails `cargo build`
//! (E0432/E0433/E0425/E0412), the module-set SEAL breach class.
//!
//! This test proves that closure WITHOUT invoking cargo. For a flag mask it
//! emits `ipe_runtime/mod.rs` and `Cargo.toml` through the real backend and
//! evaluates every `#[cfg(..)]` against the configuration the emitted crate
//! builds under: the features the manifest's `default` list enables, closed
//! under its `[features]` table, a native or wasm32 target, and never `test`.
//! A declaration counts only when its predicate holds. A module is scanned
//! whenever its declaration does not fail, and each `crate::` (or exact
//! `super::`-chain) path in it — `use` imports, path expressions, macro
//! invocations alike — is required when its enclosing predicates (item,
//! statement, expression, inner `#![cfg]`, child `mod` declaration) do not
//! fail. A predicate the build host decides (`unix`, `target_os`) varies, so a
//! reference under it is required; a predicate the evaluator cannot read is
//! refused. It is the fast counterpart to the ground-truth `ipe`-crate
//! `seal_modset` E2E gate (which does the actual `cargo build`).
//!
//! The same walk reads every `tokio::` path a compiled module names. Each
//! required path maps through a closed classification to the tokio features it
//! needs, and each must be enabled by the emitted `tokio` dependency line; a
//! path the classification does not know is refused.
//!
//! ## Why not an exhaustive `2^FLAG_COUNT` sweep
//!
//! Brute-forcing every flag mask is `O(2^FLAG_COUNT)` — infeasible as the
//! runtime feature count grows. The declared-module set is monotone in the mask
//! (the emitter only APPENDS feature modules), but a module's references are
//! not mask-independent: a flag that enables a Cargo feature turns on the
//! references gated by it, which may need a module only another flag declares.
//! So the proof checks every singleton and every PAIR of flags (each two-flag
//! interaction), plus the all-flags mask and a bounded, deterministic sample of
//! full masks as the backstop for wider interactions.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use ipe_backend::Backend;
use ipe_backend_rust::crate_specs::TokioFeature;
use ipe_backend_rust::{BuildIntent, RustBackend};
use ipe_intern::Interner;
use ipe_ir::{ModPath, Module, Program, Target};
use syn::visit::Visit;

#[path = "support/cfg.rs"]
mod cfg;

use cfg::{Cfg, CfgEnv, Truth, attrs_cfg, top_level_mods};

/// A `Module` with every module-set-relevant `uses_*` flag independently
/// settable, all else empty. The record fold is index-driven: bit `i` of `mask`
/// sets flag `i`.
///
/// `uses_ffi` is excluded: it appends `mod ffi;` to `main.rs` (not to
/// `ipe_runtime/mod.rs`) and requires FFI emission inputs the body-free emit
/// here cannot supply — it is orthogonal to the runtime-module closure.
///
/// The proof is per-flag + monotone + composed (see module docs), NOT a
/// `2^FLAG_COUNT` enumeration — it scales linearly.
const FLAG_COUNT: usize = 30;

/// How many random full masks the backstop [`sampled_full_masks_are_closed`]
/// checks, on top of the deterministic corners. Bounded so cost stays constant
/// as `FLAG_COUNT` grows.
const SAMPLE_MASKS: usize = 256;

/// A deterministic full-mask stream (fixed-seed splitmix64 — no entropy/`Date`,
/// so a failure reproduces). Masks are taken modulo the flag space.
fn sampled_masks(count: usize) -> Vec<u32> {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15; // fixed seed
    let mask_space: u64 = 1u64 << FLAG_COUNT;
    (0..count)
        .map(|_| {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            u32::try_from(z % mask_space).unwrap_or(0)
        })
        .collect()
}

#[allow(clippy::similar_names)] // `uses_ui` / `uses_tui` are intentionally alike
fn module_for_mask(name: ipe_intern::Symbol, mask: u32) -> Module {
    let f = |i: usize| mask & (1 << i) != 0;
    // `uses_ui` is forced true whenever `uses_tui` is true at the lowerer; mirror
    // that invariant here so the emitted set matches a real program (a Tui shape
    // always references Ui element kernels).
    let uses_tui = f(4);
    let uses_ui = f(2) || uses_tui;
    // Every gated surface below (db/tea/server/web/tui/webview/websocket/email/
    // http/config/compression/csv/crypto/jwt/auth/url) reaches a
    // reactor-requiring kernel, so a REAL program that sets any of them also
    // sets `uses_async_runtime` — which restores the tokio spine the per-surface
    // manifest augmenters (`tea_cargo_toml`, `server_cargo_toml`, …) anchor on.
    // Mirror that invariant here: any masked surface flag forces the async spine
    // on, so the SEAL emit sees the same manifest a real program would.
    // `uses_css` is the one whitelisted-pure surface (CssSafety kernels), so it
    // alone does NOT force it.
    let uses_async_runtime = f(0)
        || f(1)
        || f(3)
        || uses_tui
        || f(5)
        || f(7)
        || f(8)
        || f(9)
        || f(11)
        || f(12)
        || f(13)
        || f(14)
        || f(15)
        || f(16)
        || f(17);
    Module {
        name: ModPath(vec![name]),
        types: vec![],
        funcs: vec![],
        entry: None,
        records: vec![],
        uses_tea: f(0),
        uses_server: f(1),
        uses_ui,
        uses_web: f(3),
        uses_tui,
        // Fixed false: the Cli (`Cli.tea`) surface is outside this
        // flag-closure matrix (no dedicated mask bit); its manifest closure is
        // exercised by the Tui bit above.
        uses_console: false,
        uses_webview: f(5),
        uses_css: f(6),
        uses_auth: f(7),
        // Fixed false: the `principal` module carries no runtime dependency
        // edge, so it is outside this surface-flag closure matrix.
        uses_principal: false,
        uses_websocket: f(8),
        uses_email: f(9),
        // `uses_locale` is a pure surface (no reactor) — NOT in the async union.
        // Gates `locale.rs` + the `locale` Cargo feature. Standalone leaf.
        uses_locale: f(29),
        uses_time: false,
        uses_env_public: f(10),
        uses_http: f(11),
        uses_config: f(12),
        uses_compression: f(13),
        uses_csv: f(14),
        // `uses_cache` is a pure surface (no reactor) — like `csv` it is NOT in the
        // `uses_async_runtime` union above. A standalone leaf: gates the `cache`
        // module + the `cache_kernel` feature.
        uses_cache: f(28),
        // `uses_encoding` is a pure surface (no reactor) — like `crypto`/`csv` it
        // is NOT added to the `uses_async_runtime` union above.
        uses_encoding: f(18),
        // `uses_regex` / `uses_uuid` / `uses_random` / `uses_log` /
        // `uses_decimal` / `uses_char_category` are pure surfaces (no reactor) —
        // like `encoding`/`crypto`/`csv`, NOT in the async union. `uses_log` drives
        // `reaches_time_core` (chrono) alongside web / webview (bits 3 / 5);
        // `uses_decimal` (with the `db` surface, bit set elsewhere) drives
        // `reaches_decimal` (rust_decimal); `uses_char_category` is a standalone
        // leaf.
        uses_regex: f(19),
        uses_uuid: f(20),
        uses_random: f(21),
        uses_log: f(22),
        uses_decimal: f(23),
        uses_char_category: f(24),
        // `uses_crypto_core` / `uses_secret` are pure surfaces (no reactor) — like
        // `crypto`/`encoding`, NOT in the async union. `uses_crypto_core` drives
        // `reaches_crypto_core` (the crypto-floor feature); `uses_secret` gates
        // `secret.rs` and implies `crypto-core` (shared `subtle`).
        uses_crypto_core: f(25),
        uses_secret: f(26),
        // `uses_json` is a pure surface (no reactor) — NOT in the async union. It
        // gates the two prelude `Value`/`Decoder` aliases and the `json` feature
        // (demoted from the floor). A standalone leaf here; db/config/jwt fold into
        // `reaches_json` via their own bits.
        uses_json: f(27),
        uses_crypto: f(15),
        uses_jwt: f(16),
        uses_url: f(17),
        uses_debug: false,
        uses_ffi: false,
        uses_async_runtime,
    }
}

/// Extract the module name from one `mod.rs` line — handles both the
/// semicolon form (`pub mod foo;`) and the inline-block form
/// (`pub mod foo {`). Returns `None` for any other line.
fn module_name_from_line(line: &str) -> Option<String> {
    let t = line.trim();
    let rest = t
        .strip_prefix("pub mod ")
        .or_else(|| t.strip_prefix("mod "))?;
    // Semicolon form: `pub mod foo;`
    if let Some(name) = rest.strip_suffix(';')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Some(name.to_owned());
    }
    // Inline-block form: `pub mod foo {` (possibly with trailing whitespace
    // before the brace). Captures the name token before the `{`.
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if !name.is_empty() {
        let after = rest.get(name.len()..).unwrap_or("").trim_start();
        if after.starts_with('{') {
            return Some(name);
        }
    }
    None
}

/// Extract the set of top-level module names DECLARED by an emitted
/// `ipe_runtime/mod.rs` — every `pub mod X;` / `mod X;` line and every
/// `pub mod X { … }` inline-block declaration. Skips nested child declarations
/// (e.g. `pub mod route;` inside `pub mod web { … }`).
fn declared_modules(mod_rs: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut brace_depth: i32 = 0;
    for line in mod_rs.lines() {
        let t = line.trim();
        if brace_depth == 0
            && let Some(name) = module_name_from_line(line)
        {
            out.insert(name);
        }
        let opens = i32::try_from(t.matches('{').count()).unwrap_or(0);
        let closes = i32::try_from(t.matches('}').count()).unwrap_or(0);
        brace_depth = (brace_depth + opens - closes).max(0);
    }
    out
}

/// Every top-level module DECLARATION line in an emitted `ipe_runtime/mod.rs`,
/// as it literally appears — a `Vec`, NOT a set, so a module declared twice
/// shows up twice. Distinct from [`declared_modules`], whose `BTreeSet` silently
/// dedups and so cannot witness a double `pub mod`. Skips nested child
/// declarations inside inline blocks.
fn declared_module_lines(mod_rs: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut brace_depth: i32 = 0;
    for line in mod_rs.lines() {
        let t = line.trim();
        if brace_depth == 0
            && let Some(name) = module_name_from_line(line)
        {
            out.push(name);
        }
        let opens = i32::try_from(t.matches('{').count()).unwrap_or(0);
        let closes = i32::try_from(t.matches('}').count()).unwrap_or(0);
        brace_depth = (brace_depth + opens - closes).max(0);
    }
    out
}

/// The names a `mod.rs` declares more than once (each reported once).
fn duplicate_declarations(mod_rs: &str) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut dups = BTreeSet::new();
    for name in declared_module_lines(mod_rs) {
        if !seen.insert(name.clone()) {
            dups.insert(name);
        }
    }
    dups
}

/// The child modules whose `mod <child>;` declaration in `decl_src` carries a
/// `#[cfg(...)]` attribute.
///
/// A cfg on a `mod` declaration gates the child's whole file, so the child's
/// references are pulled in by that cfg, never by the parent's base append.
/// `#[cfg_attr(..)]` gates nothing and a top-level `#[cfg(not(..))]` holds in
/// the base build, so neither makes a child gated.
fn cfg_gated_child_modules(decl_src: &str) -> BTreeSet<String> {
    let mut gated = BTreeSet::new();
    let mut cfg_pending = false;
    for line in decl_src.lines() {
        let t = line.trim();
        if t.starts_with("#[cfg(") && !t.starts_with("#[cfg(not(") {
            cfg_pending = true;
            continue;
        }
        if t.starts_with("#[") || t.starts_with("//") || t.is_empty() {
            continue;
        }
        if cfg_pending && let Some(child) = mod_declaration_name(t) {
            gated.insert(child.to_owned());
        }
        cfg_pending = false;
    }
    gated
}

/// The module name of a file-backed `mod <name>;` declaration line.
fn mod_declaration_name(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("pub").map_or(line, |after_pub| {
        // `pub(crate) mod`, `pub(super) mod`, or plain `pub mod`.
        after_pub
            .split_once(')')
            .filter(|_| after_pub.starts_with('('))
            .map_or(after_pub, |(_, tail)| tail)
    });
    let name = rest
        .trim_start()
        .strip_prefix("mod ")?
        .strip_suffix(';')?
        .trim();
    (!name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .then_some(name)
}

/// The child-module declarations of the module whose files live in `dir`.
///
/// They are in `<dir>/mod.rs`, or else in the sibling `<dir>.rs` (`outer_file`).
fn dir_child_declarations(dir: &Path, outer_file: &Path) -> BTreeSet<String> {
    let mod_rs = dir.join("mod.rs");
    let decl = if mod_rs.is_file() {
        mod_rs.as_path()
    } else {
        outer_file
    };
    std::fs::read_to_string(decl)
        .map(|src| cfg_gated_child_modules(&src))
        .unwrap_or_default()
}

/// Blank the block comment whose `/` was just emitted, `at` being the `*`;
/// returns the index past its closing `*/`. Block comments nest.
fn blank_block_comment(chars: &[char], at: usize, out: &mut String) -> usize {
    out.push(' ');
    let mut i = at + 1;
    let mut depth = 1_usize;
    while depth > 0 {
        let Some(&x) = chars.get(i) else { break };
        let next = chars.get(i + 1).copied();
        if x == '/' && next == Some('*') {
            depth += 1;
            out.push_str("  ");
            i += 2;
        } else if x == '*' && next == Some('/') {
            depth -= 1;
            out.push_str("  ");
            i += 2;
        } else {
            out.push(if x == '\n' { '\n' } else { ' ' });
            i += 1;
        }
    }
    i
}

/// Blank the raw string whose `r` was just emitted, `at` being the index after
/// it; returns the index past its closing quote and hashes. Not a raw string
/// (`r#ident`) when no `"` follows the hashes: nothing more is consumed.
fn blank_raw_string(chars: &[char], at: usize, out: &mut String) -> usize {
    let mut open = at;
    while chars.get(open) == Some(&'#') {
        open += 1;
    }
    if chars.get(open) != Some(&'"') {
        return at;
    }
    let hashes = open - at;
    out.extend(std::iter::repeat_n('#', hashes));
    out.push('"');
    let mut i = open + 1;
    while let Some(&x) = chars.get(i) {
        if x == '"' && (1..=hashes).all(|h| chars.get(i + h) == Some(&'#')) {
            out.push('"');
            out.extend(std::iter::repeat_n('#', hashes));
            return i + 1 + hashes;
        }
        out.push(if x == '\n' { '\n' } else { ' ' });
        i += 1;
    }
    i
}

/// `src` with the inside of every string, raw string, char literal and block
/// comment blanked to spaces, newlines kept.
///
/// A literal may span lines (a raw string holding a fixture, a string with a
/// backslash continuation), so no per-line reader can tell code from literal
/// text: the whole file is blanked once, and every line scan reads code only.
/// Quotes are a char literal when they hold one character or an escape (`'r'`,
/// `'{'`, `'\n'`); `'a` is a lifetime. `r`, `br` and `cr` open a raw string
/// only at the start of an identifier. A `//` comment is left as written.
fn blank_literals(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let at = |k: usize| chars.get(k).copied();
    let is_ident = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
    let blank = |c: char| if c == '\n' { '\n' } else { ' ' };
    let mut out = String::with_capacity(src.len());
    let mut i = 0_usize;
    while let Some(c) = at(i) {
        let before = i.checked_sub(1).and_then(at);
        let before2 = i.checked_sub(2).and_then(at);
        let raw_prefix =
            !is_ident(before) || (matches!(before, Some('b' | 'c')) && !is_ident(before2));
        out.push(c);
        i += 1;
        match c {
            '/' if at(i) == Some('/') => {
                while let Some(x) = at(i).filter(|x| *x != '\n') {
                    out.push(x);
                    i += 1;
                }
            }
            '/' if at(i) == Some('*') => i = blank_block_comment(&chars, i, &mut out),
            'r' if raw_prefix && matches!(at(i), Some('#' | '"')) => {
                i = blank_raw_string(&chars, i, &mut out);
            }
            '"' => {
                while let Some(x) = at(i) {
                    i += 1;
                    if x == '\\' {
                        out.push(' ');
                        if let Some(escaped) = at(i) {
                            out.push(blank(escaped));
                            i += 1;
                        }
                    } else if x == '"' {
                        out.push('"');
                        break;
                    } else {
                        out.push(blank(x));
                    }
                }
            }
            '\'' => match (at(i), at(i + 1)) {
                (Some('\\'), _) => {
                    out.push_str("  ");
                    i += 2;
                    while let Some(x) = at(i) {
                        i += 1;
                        if x == '\'' {
                            out.push('\'');
                            break;
                        }
                        out.push(blank(x));
                    }
                }
                (Some(x), Some('\'')) => {
                    out.push(blank(x));
                    out.push('\'');
                    i += 2;
                }
                _ => {}
            },
            _ => {}
        }
    }
    out
}

/// The net brace depth change of one line of [`blank_literals`] output: `{`
/// adds one, `}` subtracts one, and a `//` comment ends the count.
fn unquoted_brace_delta(line: &str) -> i32 {
    let code = line.split_once("//").map_or(line, |(code, _)| code);
    code.chars().fold(0, |depth, c| match c {
        '{' => depth + 1,
        '}' => depth - 1,
        _ => depth,
    })
}

// ── emitted build configuration ──────────────────────────────────────────────

/// The `#[path = ".."]` of a file-backed `mod` declaration.
fn path_attr(attrs: &[syn::Attribute]) -> Option<String> {
    attrs.iter().find_map(|attr| match &attr.meta {
        syn::Meta::NameValue(pair) if pair.path.is_ident("path") => match &pair.value {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(value),
                ..
            }) => Some(value.value()),
            _ => None,
        },
        _ => None,
    })
}

/// No feature on, a native target.
const fn bare_env() -> CfgEnv {
    CfgEnv {
        features: BTreeSet::new(),
        wasm: false,
    }
}

/// The configuration of an emitted crate from its `Cargo.toml`.
fn manifest_env(cargo_toml: &str, wasm: bool) -> CfgEnv {
    CfgEnv {
        features: enabled_features(cargo_toml),
        wasm,
    }
}

/// The features an emitted `Cargo.toml` enables: its `[features]` `default`
/// list closed under the `[features]` table. An entry naming a dependency
/// feature (`x/y`) enables `x`; a `dep:x` or weak `x?/y` entry enables no
/// feature. A manifest with no `default` entry enables none.
fn enabled_features(cargo_toml: &str) -> BTreeSet<String> {
    let table = feature_table(cargo_toml);
    let seeds = table.get("default").cloned().unwrap_or_default();
    close_features(&table, seeds).0
}

/// The `[features]` table of `cargo_toml`: each feature and its raw entries.
fn feature_table(cargo_toml: &str) -> HashMap<String, Vec<String>> {
    let quoted = |value: &str| -> Vec<String> {
        value
            .split('"')
            .skip(1)
            .step_by(2)
            .map(str::to_owned)
            .collect()
    };
    let mut table: HashMap<String, Vec<String>> = HashMap::new();
    let mut in_features = false;
    let mut open: Option<(String, String)> = None;
    for line in cargo_toml.lines() {
        let code = line.split_once('#').map_or(line, |(code, _)| code).trim();
        if let Some((key, mut value)) = open.take() {
            value.push_str(code);
            if value.contains(']') {
                table.insert(key, quoted(&value));
            } else {
                open = Some((key, value));
            }
            continue;
        }
        if code.starts_with('[') && !code.contains('"') {
            in_features = code == "[features]";
            continue;
        }
        let Some((key, value)) = code.split_once('=').filter(|_| in_features) else {
            continue;
        };
        let key = key.trim().trim_matches('"').to_owned();
        if value.contains(']') {
            table.insert(key, quoted(value));
        } else {
            open = Some((key, value.to_owned()));
        }
    }
    table
}

/// The features `seeds` enable, closed under `table`, with the `tokio`
/// sub-features (`tokio/x`, weak `tokio?/x`) the closure's entries name.
fn close_features(
    table: &HashMap<String, Vec<String>>,
    seeds: Vec<String>,
) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut enabled = BTreeSet::new();
    let mut tokio = BTreeSet::new();
    let mut work = seeds;
    while let Some(entry) = work.pop() {
        if let Some(sub) = entry
            .strip_prefix("tokio/")
            .or_else(|| entry.strip_prefix("tokio?/"))
        {
            tokio.insert(sub.to_owned());
        }
        if entry.starts_with("dep:") || entry.contains("?/") {
            continue;
        }
        let name = entry.split_once('/').map_or(entry.as_str(), |(dep, _)| dep);
        if enabled.insert(name.to_owned())
            && let Some(implied) = table.get(name)
        {
            work.extend(implied.iter().cloned());
        }
    }
    (enabled, tokio)
}

// ── gated `crate::` reference scan ───────────────────────────────────────────

/// What a gated reference names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefKind {
    /// A crate-root module segment.
    Crate,
    /// A whole `tokio::` path, its segments joined by `::`.
    Tokio,
}

/// One crate-root or `tokio::` reference and the predicate it is compiled under.
#[derive(Clone, Debug)]
struct GatedRef {
    kind: RefKind,
    /// For [`RefKind::Crate`], the first segment after the crate root
    /// (`crate::<seg>`), or a `<no file ..>` marker for a `mod` declaration
    /// whose file is absent; for [`RefKind::Tokio`], the path.
    seg: String,
    cond: Cfg,
}

/// A child module file still to scan, with the position it is declared at.
struct PendingFile {
    path: PathBuf,
    /// The directory its own file-backed children live in.
    child_dir: PathBuf,
    /// The `super::` hops from it to the crate root.
    depth: usize,
    conds: Vec<Cfg>,
}

/// Walks the syntax of one runtime module, recording every crate-root
/// reference under the stack of predicates enclosing it: the item, statement,
/// arm, field and expression `#[cfg(..)]`s, the inner `#![cfg(..)]` of each
/// file, and the `#[cfg(..)]` of each child `mod` declaration. A child module
/// is followed to the file rustc reads for it (`#[path]` included); a file no
/// declaration names is never read. A `#[cfg(..)]` on a node the walk does
/// not scope is refused, so no gate is silently read as absent.
struct RefScanner<'r> {
    runtime_root: &'r Path,
    overlay: &'r Overlay,
    /// The address of every `#[cfg(..)]` attribute a scope consumed.
    consumed: BTreeSet<usize>,
    conds: Vec<Cfg>,
    depth: usize,
    child_dir: PathBuf,
    file_dir: PathBuf,
    file: PathBuf,
    refs: Vec<GatedRef>,
    pending: Vec<PendingFile>,
    errors: Vec<String>,
}

impl<'r> RefScanner<'r> {
    fn new(runtime_root: &'r Path, overlay: &'r Overlay, child_dir: PathBuf, depth: usize) -> Self {
        Self {
            runtime_root,
            overlay,
            consumed: BTreeSet::new(),
            conds: Vec::new(),
            depth,
            child_dir,
            file_dir: runtime_root.to_path_buf(),
            file: runtime_root.to_path_buf(),
            refs: Vec::new(),
            pending: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Run `walk` under the predicate `attrs` add.
    fn gated(&mut self, attrs: &[syn::Attribute], walk: impl FnOnce(&mut Self)) {
        self.consumed.extend(
            attrs
                .iter()
                .filter(|a| a.path().is_ident("cfg"))
                .map(|a| std::ptr::from_ref(a) as usize),
        );
        let pushed = match attrs_cfg(attrs) {
            Ok(Some(cfg)) => {
                self.conds.push(cfg);
                true
            }
            Ok(None) => false,
            Err(e) => {
                self.errors.push(format!("{}: {e}", self.file.display()));
                false
            }
        };
        walk(self);
        if pushed {
            self.conds.pop();
        }
    }

    fn push_ref(&mut self, seg: String) {
        self.push(RefKind::Crate, seg);
    }

    fn push(&mut self, kind: RefKind, seg: String) {
        let cond = Cfg::All(self.conds.clone());
        self.refs.push(GatedRef { kind, seg, cond });
    }

    /// Record `segs` when it is a `tokio::` path (`continues`: a glob follows
    /// it), and report whether it was one. A `self` segment names its parent.
    fn record_tokio(&mut self, segs: &[String], continues: bool) -> bool {
        if segs.first().map(String::as_str) != Some("tokio") || (segs.len() < 2 && !continues) {
            return false;
        }
        let mut path = segs
            .iter()
            .filter(|s| *s != "self")
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join("::");
        if continues {
            path.push_str("::*");
        }
        self.push(RefKind::Tokio, path);
        true
    }

    /// Record the path `segs` (`continues`: a glob follows it): a `tokio::`
    /// path whole, otherwise its crate-root segment. `crate::<seg>` and an exact `super::` chain back to the
    /// crate root both reach `<seg>`; a shorter `super::` chain names an
    /// intermediate module. A last segment is recorded only when it names a
    /// runtime module (`use crate::encoding;`): a bare root item is resolved by
    /// no module.
    fn record_path(&mut self, segs: &[String], continues: bool) {
        if self.record_tokio(segs, continues) {
            return;
        }
        let reach = match segs.first().map(String::as_str) {
            Some("crate") => 1,
            Some("super") => {
                let hops = segs.iter().take_while(|s| *s == "super").count();
                if hops != self.depth {
                    return;
                }
                hops
            }
            _ => return,
        };
        let Some(seg) = segs.get(reach) else {
            return;
        };
        let followed = continues || segs.len() > reach + 1;
        let is_module = self.exists(&self.runtime_root.join(format!("{seg}.rs")))
            || self.runtime_root.join(seg).is_dir();
        if followed || is_module {
            self.push_ref(seg.clone());
        }
    }

    /// Record a `use` leaf path. A leaf naming the `tokio` crate itself
    /// (`use tokio;`, `use tokio as t;`) is recorded as the bare crate path,
    /// which the tokio classification refuses: paths through the alias are not
    /// read.
    fn record_use_leaf(&mut self, segs: &[String]) {
        if let [only] = segs
            && only == "tokio"
        {
            self.push(RefKind::Tokio, only.clone());
            return;
        }
        self.record_path(segs, false);
    }

    fn use_tree(&mut self, tree: &syn::UseTree, prefix: &mut Vec<String>) {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                self.use_tree(&path.tree, prefix);
                prefix.pop();
            }
            syn::UseTree::Name(name) => {
                prefix.push(name.ident.to_string());
                self.record_use_leaf(prefix);
                prefix.pop();
            }
            syn::UseTree::Rename(rename) => {
                prefix.push(rename.ident.to_string());
                self.record_use_leaf(prefix);
                prefix.pop();
            }
            syn::UseTree::Glob(_) => self.record_path(prefix, true),
            syn::UseTree::Group(group) => {
                for item in &group.items {
                    self.use_tree(item, prefix);
                }
            }
        }
    }

    /// Record the paths inside a macro's unparsed tokens. A predicate inside
    /// them is not read, so each reference takes the macro's own predicate.
    fn macro_tokens(&mut self, stream: proc_macro2::TokenStream) {
        use proc_macro2::TokenTree;
        let toks: Vec<TokenTree> = stream.into_iter().collect();
        let is_colon =
            |k: usize| matches!(toks.get(k), Some(TokenTree::Punct(p)) if p.as_char() == ':');
        let mut i = 0_usize;
        while let Some(tok) = toks.get(i) {
            match tok {
                TokenTree::Group(group) => {
                    self.macro_tokens(group.stream());
                    i += 1;
                }
                TokenTree::Ident(ident) => {
                    let follows_segment =
                        i.checked_sub(3)
                            .and_then(|k| toks.get(k))
                            .is_some_and(|t| match t {
                                TokenTree::Ident(_) => true,
                                TokenTree::Punct(p) => p.as_char() == '>',
                                TokenTree::Group(_) | TokenTree::Literal(_) => false,
                            });
                    let mid_path = i >= 2 && is_colon(i - 1) && is_colon(i - 2) && follows_segment;
                    let mut segs = vec![ident.to_string()];
                    let mut next = i + 1;
                    let mut glob = false;
                    while is_colon(next) && is_colon(next + 1) {
                        match toks.get(next + 2) {
                            Some(TokenTree::Ident(seg)) => {
                                segs.push(seg.to_string());
                                next += 3;
                            }
                            Some(TokenTree::Punct(p)) if p.as_char() == '*' => {
                                glob = true;
                                next += 3;
                                break;
                            }
                            _ => break,
                        }
                    }
                    if !mid_path {
                        self.record_path(&segs, glob);
                    }
                    i = next;
                }
                TokenTree::Punct(_) | TokenTree::Literal(_) => i += 1,
            }
        }
    }

    /// A child `mod` declaration: an inline body is walked in place, a
    /// file-backed child is queued under the current predicates.
    fn module(&mut self, node: &syn::ItemMod) {
        let name = node.ident.to_string();
        if let Some((_, items)) = &node.content {
            let child_dir = self.child_dir.join(&name);
            let outer_dir = std::mem::replace(&mut self.child_dir, child_dir);
            self.depth += 1;
            for item in items {
                self.visit_item(item);
            }
            self.depth -= 1;
            self.child_dir = outer_dir;
            return;
        }
        let (path, child_dir) = if let Some(rel) = path_attr(&node.attrs) {
            let path = self.file_dir.join(rel);
            let dir = path.parent().map_or_else(PathBuf::new, Path::to_path_buf);
            (path, dir)
        } else {
            let flat = self.child_dir.join(format!("{name}.rs"));
            let nested = self.child_dir.join(&name).join("mod.rs");
            let path = if self.exists(&flat) { flat } else { nested };
            (path, self.child_dir.join(&name))
        };
        if self.exists(&path) {
            self.pending.push(PendingFile {
                path,
                child_dir,
                depth: self.depth + 1,
                conds: self.conds.clone(),
            });
        } else {
            self.push_ref(format!("<no file {} for `mod {name};`>", path.display()));
        }
    }

    /// Whether the emitted runtime carries the file `path`: an emitted file, or
    /// one of the runtime tree.
    fn exists(&self, path: &Path) -> bool {
        self.overlay.contains_key(path) || path.is_file()
    }

    /// The source of `path` in the emitted runtime: an emitted file overrides
    /// the runtime tree's.
    fn read(&self, path: &Path) -> Result<String, String> {
        self.overlay.get(path).map_or_else(
            || std::fs::read_to_string(path).map_err(|e| e.to_string()),
            |src| Ok(src.clone()),
        )
    }

    /// Scan every queued file, each once per predicate stack.
    fn drain(&mut self) {
        let mut seen: BTreeSet<(PathBuf, String)> = BTreeSet::new();
        while let Some(next) = self.pending.pop() {
            if !seen.insert((next.path.clone(), format!("{:?}", next.conds))) {
                continue;
            }
            let file = match self
                .read(&next.path)
                .and_then(|src| syn::parse_file(&src).map_err(|e| e.to_string()))
            {
                Ok(file) => file,
                Err(e) => {
                    self.errors
                        .push(format!("{} does not parse: {e}", next.path.display()));
                    continue;
                }
            };
            self.conds = next.conds;
            self.depth = next.depth;
            self.child_dir = next.child_dir;
            self.file_dir = next
                .path
                .parent()
                .map_or_else(PathBuf::new, Path::to_path_buf);
            self.file = next.path;
            self.gated(&file.attrs, |scanner| {
                for item in &file.items {
                    scanner.visit_item(item);
                }
            });
        }
    }
}

/// Override each `visit_<node>` of a node that carries attributes so its walk
/// runs under the predicate its `#[cfg(..)]`s add.
macro_rules! cfg_scoped {
    ($lt:lifetime; $($method:ident($ty:ident);)*) => {$(
        fn $method(&mut self, node: &$lt syn::$ty) {
            self.gated(&node.attrs, |scanner| syn::visit::$method(scanner, node));
        }
    )*};
}

impl<'ast> syn::visit::Visit<'ast> for RefScanner<'_> {
    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        if attr.path().is_ident("cfg") {
            if !self.consumed.contains(&(std::ptr::from_ref(attr) as usize)) {
                self.errors.push(format!(
                    "{}: a `#[cfg(..)]` on a node the scan does not scope",
                    self.file.display()
                ));
            }
        } else {
            let segs: Vec<String> = attr
                .path()
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            self.record_tokio(&segs, false);
        }
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let segs: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        self.record_path(&segs, false);
        syn::visit::visit_path(self, path);
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        self.gated(&node.attrs, |scanner| {
            scanner.use_tree(&node.tree, &mut Vec::new());
        });
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.visit_path(&mac.path);
        self.macro_tokens(mac.tokens.clone());
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        self.gated(&node.attrs, |scanner| scanner.module(node));
    }

    fn visit_item_extern_crate(&mut self, node: &'ast syn::ItemExternCrate) {
        self.gated(&node.attrs, |scanner| {
            if node.ident == "tokio" {
                scanner.push(RefKind::Tokio, "tokio".to_owned());
            }
            syn::visit::visit_item_extern_crate(scanner, node);
        });
    }

    cfg_scoped! {
        'ast;
        visit_item_const(ItemConst);
        visit_item_enum(ItemEnum);
        visit_item_fn(ItemFn);
        visit_item_foreign_mod(ItemForeignMod);
        visit_item_impl(ItemImpl);
        visit_item_macro(ItemMacro);
        visit_item_static(ItemStatic);
        visit_item_struct(ItemStruct);
        visit_item_trait(ItemTrait);
        visit_item_trait_alias(ItemTraitAlias);
        visit_item_type(ItemType);
        visit_item_union(ItemUnion);
        visit_impl_item_const(ImplItemConst);
        visit_impl_item_fn(ImplItemFn);
        visit_impl_item_macro(ImplItemMacro);
        visit_impl_item_type(ImplItemType);
        visit_trait_item_const(TraitItemConst);
        visit_trait_item_fn(TraitItemFn);
        visit_trait_item_macro(TraitItemMacro);
        visit_trait_item_type(TraitItemType);
        visit_foreign_item_fn(ForeignItemFn);
        visit_foreign_item_macro(ForeignItemMacro);
        visit_foreign_item_static(ForeignItemStatic);
        visit_foreign_item_type(ForeignItemType);
        visit_arm(Arm);
        visit_field(Field);
        visit_field_value(FieldValue);
        visit_field_pat(FieldPat);
        visit_variant(Variant);
        visit_type_param(TypeParam);
        visit_lifetime_param(LifetimeParam);
        visit_const_param(ConstParam);
        visit_pat_type(PatType);
        visit_receiver(Receiver);
        visit_local(Local);
        visit_stmt_macro(StmtMacro);
        visit_expr_array(ExprArray);
        visit_expr_assign(ExprAssign);
        visit_expr_async(ExprAsync);
        visit_expr_await(ExprAwait);
        visit_expr_binary(ExprBinary);
        visit_expr_block(ExprBlock);
        visit_expr_break(ExprBreak);
        visit_expr_call(ExprCall);
        visit_expr_cast(ExprCast);
        visit_expr_closure(ExprClosure);
        visit_expr_const(ExprConst);
        visit_expr_continue(ExprContinue);
        visit_expr_field(ExprField);
        visit_expr_for_loop(ExprForLoop);
        visit_expr_group(ExprGroup);
        visit_expr_if(ExprIf);
        visit_expr_index(ExprIndex);
        visit_expr_infer(ExprInfer);
        visit_expr_let(ExprLet);
        visit_expr_lit(ExprLit);
        visit_expr_loop(ExprLoop);
        visit_expr_macro(ExprMacro);
        visit_expr_match(ExprMatch);
        visit_expr_method_call(ExprMethodCall);
        visit_expr_paren(ExprParen);
        visit_expr_path(ExprPath);
        visit_expr_range(ExprRange);
        visit_expr_raw_addr(ExprRawAddr);
        visit_expr_reference(ExprReference);
        visit_expr_repeat(ExprRepeat);
        visit_expr_return(ExprReturn);
        visit_expr_struct(ExprStruct);
        visit_expr_try(ExprTry);
        visit_expr_try_block(ExprTryBlock);
        visit_expr_tuple(ExprTuple);
        visit_expr_unary(ExprUnary);
        visit_expr_unsafe(ExprUnsafe);
        visit_expr_while(ExprWhile);
        visit_expr_yield(ExprYield);
    }
}

/// One top-level module declaration of an emitted `ipe_runtime/mod.rs`.
#[derive(Clone)]
struct Decl<'f> {
    name: String,
    /// The predicate the declaration holds under.
    cond: Cfg,
    /// Its `#[path = ".."]`, relative to the runtime root.
    path: Option<String>,
    /// The body of an inline `pub mod <name> { .. }`.
    inline: Option<&'f [syn::Item]>,
}

/// An emitted `mod.rs`, parsed.
fn parse_mod_rs(mod_rs: &str) -> Result<syn::File, String> {
    syn::parse_file(mod_rs).map_err(|e| format!("emitted `mod.rs` does not parse: {e}"))
}

/// Every top-level module declaration of an emitted `mod.rs`, with the
/// predicate each holds under.
fn declarations(file: &syn::File) -> Result<Vec<Decl<'_>>, String> {
    Ok(top_level_mods(file)?
        .into_iter()
        .map(|(m, cond)| Decl {
            name: m.ident.to_string(),
            cond,
            path: path_attr(&m.attrs),
            inline: m.content.as_ref().map(|(_, items)| items.as_slice()),
        })
        .collect())
}

/// The file rustc reads for the file-backed declaration `decl`, and the
/// directory its own file-backed children live in.
fn decl_file(runtime_root: &Path, overlay: &Overlay, decl: &Decl) -> (PathBuf, PathBuf) {
    let child_dir = runtime_root.join(&decl.name);
    if let Some(rel) = &decl.path {
        let path = runtime_root.join(rel);
        let dir = path.parent().map_or_else(PathBuf::new, Path::to_path_buf);
        return (path, dir);
    }
    let flat = runtime_root.join(format!("{}.rs", decl.name));
    if overlay.contains_key(&flat) || flat.is_file() {
        (flat, child_dir)
    } else {
        (child_dir.join("mod.rs"), child_dir)
    }
}

/// The files an emitted project writes into its runtime tree, keyed by the
/// path they take under the runtime root. They override the tree's own.
type Overlay = HashMap<PathBuf, String>;

/// Every crate-root reference the declared module `decl` compiles, with the
/// predicate (within the module) it is compiled under. `errors` collects every
/// file that does not parse and every predicate the evaluator cannot read.
fn module_refs(
    runtime_root: &Path,
    overlay: &Overlay,
    decl: &Decl,
    errors: &mut Vec<String>,
) -> Vec<GatedRef> {
    let mut scanner = RefScanner::new(runtime_root, overlay, runtime_root.join(&decl.name), 1);
    if let Some(items) = decl.inline {
        for item in items {
            syn::visit::Visit::visit_item(&mut scanner, item);
        }
    } else {
        let (path, child_dir) = decl_file(runtime_root, overlay, decl);
        if scanner.exists(&path) {
            scanner.pending.push(PendingFile {
                path,
                child_dir,
                depth: 1,
                conds: Vec::new(),
            });
        } else {
            scanner.push_ref(format!(
                "<no file {} for `mod {};`>",
                path.display(),
                decl.name
            ));
        }
    }
    scanner.drain();
    errors.append(&mut scanner.errors);
    scanner.refs
}

/// The crate-root segments `decl`'s module requires in the build `env`: every
/// reference whose predicate (with the declaration's) does not fail.
fn required_segs(refs: &[GatedRef], decl_cond: &Cfg, env: &CfgEnv) -> BTreeSet<String> {
    required_of(RefKind::Crate, refs, decl_cond, env)
}

/// The references of `kind` among `refs` whose predicate (with the
/// declaration's) does not fail in `env`.
fn required_of(
    kind: RefKind,
    refs: &[GatedRef],
    decl_cond: &Cfg,
    env: &CfgEnv,
) -> BTreeSet<String> {
    let decl = env.eval(decl_cond);
    refs.iter()
        .filter(|r| r.kind == kind && decl.and(env.eval(&r.cond)) != Truth::Fails)
        .map(|r| r.seg.clone())
        .collect()
}

// ── `tokio::` path classification ────────────────────────────────────────────

/// The prefix of every tokio-feature violation, so a check can select them.
const TOKIO_BREACH: &str = "tokio feature breach:";

/// The tokio features the `tokio::` path `path` needs to compile.
///
/// The classification is closed: a path it does not name is an `Err`, never a
/// path that needs nothing.
fn tokio_need(path: &str) -> Result<&'static [TokioFeature], String> {
    use TokioFeature as F;
    const NO_FEATURE_IO: &[&str] = &[
        "AsyncRead",
        "AsyncWrite",
        "AsyncBufRead",
        "AsyncSeek",
        "ReadBuf",
        "Interest",
        "Ready",
        "Error",
        "ErrorKind",
        "Result",
    ];
    const IO_UTIL: &[&str] = &[
        "BufReader",
        "BufWriter",
        "BufStream",
        "duplex",
        "DuplexStream",
        "split",
        "ReadHalf",
        "WriteHalf",
        "empty",
        "repeat",
        "sink",
        "Lines",
        "Take",
        "Chain",
    ];
    let segs: Vec<&str> = path.split("::").skip(1).collect();
    match segs.as_slice() {
        [] => Err(format!(
            "`{path}` names the tokio crate whole, so its paths are not read; \
             name each tokio path from `tokio::`"
        )),
        ["io" | "time"] | ["io" | "time", "*"] => Err(format!(
            "`{path}` hides which of its items are used, and they need different \
             tokio features; import the items by name"
        )),
        ["sync", ..] => Ok(&[F::Sync]),
        ["net", ..] | ["io", "unix", ..] => Ok(&[F::Net]),
        ["signal", ..] => Ok(&[F::Signal]),
        ["process", ..] => Ok(&[F::Process]),
        ["fs", ..] => Ok(&[F::Fs]),
        ["time", "advance" | "pause" | "resume", ..] => Err(format!(
            "`{path}` needs tokio `test-util`, which no runtime feature enables"
        )),
        ["time", ..] => Ok(&[F::Time]),
        ["task", "block_in_place", ..] | ["runtime", "Builder", "new_multi_thread", ..] => {
            Ok(&[F::RtMultiThread])
        }
        ["spawn" | "task_local"] | ["task" | "runtime", ..] => Ok(&[F::Rt]),
        ["main"] => Ok(&[F::Macros, F::RtMultiThread]),
        ["select" | "join" | "try_join" | "test"] => Ok(&[F::Macros]),
        ["pin"] => Ok(&[]),
        ["io", item, ..] if NO_FEATURE_IO.contains(item) => Ok(&[]),
        ["io", item, ..]
            if IO_UTIL.contains(item)
                || item.starts_with("copy")
                || (item.starts_with("Async") && item.ends_with("Ext")) =>
        {
            Ok(&[F::IoUtil])
        }
        _ => Err(format!("`{path}` is an unclassified tokio path")),
    }
}

/// The tokio features the emitted `tokio = { .. }` dependency line of
/// `cargo_toml` enables, or `None` when it declares no `tokio` dependency.
fn tokio_line_features(cargo_toml: &str) -> Option<BTreeSet<TokioFeature>> {
    let line = cargo_toml
        .lines()
        .find(|l| l.trim_start().starts_with("tokio = {"))?;
    let list = line
        .split_once("features = [")
        .and_then(|(_, rest)| rest.split_once(']'))
        .map_or("", |(list, _)| list);
    Some(
        list.split('"')
            .skip(1)
            .step_by(2)
            .filter_map(TokioFeature::from_name)
            .collect(),
    )
}

/// Every required `tokio::` path of the module `decl_name` that the enabled
/// set `declared` (`None`: no `tokio` dependency) does not cover.
fn tokio_violations(
    decl_name: &str,
    required: &BTreeSet<String>,
    declared: Option<&BTreeSet<TokioFeature>>,
) -> Vec<String> {
    let mut out = Vec::new();
    for path in required {
        match (tokio_need(path), declared) {
            (Err(e), _) => out.push(format!("{TOKIO_BREACH} `{decl_name}`: {e}")),
            (Ok(_), None) => out.push(format!(
                "{TOKIO_BREACH} `{decl_name}` names `{path}`, but the emitted manifest \
                 declares no `tokio` dependency"
            )),
            (Ok(need), Some(enabled)) => {
                let missing: Vec<&str> = need
                    .iter()
                    .filter(|f| !enabled.contains(*f))
                    .map(|f| f.as_str())
                    .collect();
                if !missing.is_empty() {
                    out.push(format!(
                        "{TOKIO_BREACH} `{decl_name}` names `{path}`, which needs tokio \
                         {missing:?}, but the emitted `tokio` line enables only {:?}",
                        enabled.iter().map(|f| f.as_str()).collect::<Vec<_>>()
                    ));
                }
            }
        }
    }
    out
}

/// The crate-root segments the file-backed module `name` requires in `env`.
fn module_required(runtime_root: &Path, name: &str, env: &CfgEnv) -> BTreeSet<String> {
    let decl = Decl {
        name: name.to_owned(),
        cond: Cfg::All(Vec::new()),
        path: None,
        inline: None,
    };
    let mut errors = Vec::new();
    let refs = module_refs(runtime_root, &Overlay::new(), &decl, &mut errors);
    assert!(errors.is_empty(), "scan refused: {errors:?}");
    required_segs(&refs, &decl.cond, env)
}

/// The crate-root segments the source `src`, read as the top-level module
/// `probe` of an otherwise empty runtime, requires with no feature on.
#[allow(clippy::expect_used)] // test scaffolding: a fixture write cannot be skipped
fn source_required(src: &str) -> BTreeSet<String> {
    let dir = ipe_test_temp::temp_root().join(format!(
        "ipe_modset_closure_source_{}_{}",
        std::process::id(),
        SOURCE_PROBES.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create probe dir");
    let path = dir.join("probe.rs");
    std::fs::write(&path, src).expect("write probe source");
    let decl = Decl {
        name: "probe".to_owned(),
        cond: Cfg::All(Vec::new()),
        path: Some(path.to_string_lossy().into_owned()),
        inline: None,
    };
    let mut errors = Vec::new();
    let refs = module_refs(&dir, &Overlay::new(), &decl, &mut errors);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(errors.is_empty(), "scan refused: {errors:?}");
    required_segs(&refs, &decl.cond, &bare_env())
}

/// Distinguishes the probe files of concurrent [`source_required`] calls.
static SOURCE_PROBES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// What the first segment of a `crate::<seg>::…` reference names at the crate
/// root of one emitted `ipe_runtime/mod.rs`.
#[derive(Debug, PartialEq, Eq)]
enum RootRef {
    /// `<seg>` is a runtime module: the reference reaches into it.
    Module(String),
    /// `<seg>` is an item a root `pub use <provider>::…` re-exports
    /// (`crate::IoFailure::on_path` through `pub use error::*;`).
    Reexported { provider: String },
    /// `<seg>` is an item the emitted `mod.rs` itself defines, unconditionally.
    RootItem,
    /// Two or more root globs each define `<seg>`: rustc refuses the reference
    /// as ambiguous (E0659) whichever modules are declared.
    Ambiguous,
    /// No root name is `<seg>`: the emitted crate cannot resolve the reference.
    Unresolved,
}

impl RootRef {
    /// The module the emitted `mod.rs` must declare for the reference to build,
    /// `None` only for a root item. An ambiguous or unresolved `seg` stays its
    /// own dep — [`RootScope::resolve`] returns [`RootRef::Module`] for every
    /// declared name, so no declared set contains it and the closure check fires.
    fn dep(self, seg: &str) -> Option<String> {
        match self {
            Self::Module(m) | Self::Reexported { provider: m } => Some(m),
            Self::RootItem => None,
            Self::Ambiguous | Self::Unresolved => Some(seg.to_owned()),
        }
    }
}

/// Each module path's top-level definitions, memoised across masks.
type DefCache = HashMap<Vec<String>, BTreeSet<String>>;

/// One `pub use <path>::<item>;` (or `<item> as <alias>`) root re-export.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NamedReexport {
    /// The module path, segment by segment; `path[0]` is the providing module.
    path: Vec<String>,
    /// The item's name in `<path>` (before any `as`).
    item: String,
}

/// The root names one emitted `ipe_runtime/mod.rs` supplies: its declared
/// modules, its unconditional re-exports, and the items it defines itself.
struct RootScope<'a> {
    runtime_root: &'a Path,
    declared: BTreeSet<String>,
    /// `pub use <path>::*;` — each glob's module path, segment by segment.
    globs: Vec<Vec<String>>,
    /// `pub use <path>::{a, b as c};` / `pub use <path>::a;` — each exported
    /// name and the item it re-exports.
    named: HashMap<String, NamedReexport>,
    root_items: BTreeSet<String>,
}

impl<'a> RootScope<'a> {
    fn new(runtime_root: &'a Path, mod_rs: &str) -> Self {
        let mut globs = Vec::new();
        let mut named = HashMap::new();
        for stmt in unconditional_root_uses(mod_rs) {
            parse_root_use(&stmt, &mut globs, &mut named);
        }
        Self {
            runtime_root,
            declared: declared_modules(mod_rs),
            globs,
            named,
            root_items: top_level_definitions(&blank_literals(mod_rs)),
        }
    }

    /// Resolve the first segment of a `crate::<seg>::…` path: a runtime module
    /// (a `<seg>.rs` or `<seg>/` under the runtime root, or a module the
    /// `mod.rs` declares) first, then a root item, then a named re-export, then
    /// a glob re-export of a module defining `<seg>`.
    fn resolve(&self, seg: &str, defs: &mut DefCache) -> RootRef {
        let on_disk = self.runtime_root.join(format!("{seg}.rs")).is_file()
            || self.runtime_root.join(seg).is_dir();
        if on_disk || self.declared.contains(seg) {
            return RootRef::Module(seg.to_owned());
        }
        if self.root_items.contains(seg) {
            return RootRef::RootItem;
        }
        if let Some(named) = self.named.get(seg) {
            // A named re-export shadows every glob, so it alone decides `seg`:
            // an item `<path>` does not define makes the `pub use` itself E0432.
            let items = defs
                .entry(named.path.clone())
                .or_insert_with(|| module_definitions(self.runtime_root, &named.path));
            return match named.path.first() {
                Some(top) if items.contains(&named.item) => RootRef::Reexported {
                    provider: top.clone(),
                },
                _ => RootRef::Unresolved,
            };
        }
        let mut providers = BTreeSet::new();
        for path in &self.globs {
            let items = defs
                .entry(path.clone())
                .or_insert_with(|| module_definitions(self.runtime_root, path));
            if items.contains(seg) {
                providers.insert(path.clone());
            }
        }
        let mut providers = providers.into_iter();
        match (providers.next(), providers.next()) {
            (Some(path), None) => {
                path.first()
                    .map_or(RootRef::Unresolved, |top| RootRef::Reexported {
                        provider: top.clone(),
                    })
            }
            (Some(_), Some(_)) => RootRef::Ambiguous,
            (None, _) => RootRef::Unresolved,
        }
    }

    /// The module each raw `crate::<seg>` reference needs declared, paired
    /// with the segment that needs it.
    fn deps_of(&self, raw: &BTreeSet<String>, defs: &mut DefCache) -> Vec<(String, String)> {
        raw.iter()
            .filter_map(|seg| {
                self.resolve(seg, defs)
                    .dep(seg)
                    .map(|dep| (seg.clone(), dep))
            })
            .collect()
    }
}

/// Every depth-0 `pub use …;` statement of a `mod.rs`, joined onto one line,
/// that no `#[cfg(..)]` attribute gates. A gated re-export does not hold in
/// every build, so it supplies no name unconditionally — `#[cfg(not(..))]`
/// included: it drops the re-export whenever its predicate's feature or target
/// is on (a wasm32 build, a feature-on mask). A multi-line attribute is
/// consumed whole, and a trailing `//` comment is not part of the statement.
fn unconditional_root_uses(mod_rs: &str) -> Vec<String> {
    let src = blank_literals(mod_rs);
    let mut out = Vec::new();
    let mut depth: i32 = 0;
    let mut cfg_pending = false;
    // Bracket balance of a multi-line attribute still open.
    let mut attr_open: i32 = 0;
    let mut open: Option<(String, bool)> = None;
    for line in src.lines() {
        let t = line.split_once("//").map_or(line, |(code, _)| code).trim();
        if let Some((mut stmt, gated)) = open.take() {
            stmt.push(' ');
            stmt.push_str(t);
            if !t.ends_with(';') {
                open = Some((stmt, gated));
            } else if !gated {
                out.push(stmt);
            }
            continue;
        }
        if depth == 0 {
            if attr_open > 0 {
                attr_open = (attr_open + bracket_delta(t)).max(0);
                continue;
            }
            if t.starts_with("#[") {
                if t.starts_with("#[cfg(") {
                    cfg_pending = true;
                }
                attr_open = bracket_delta(t).max(0);
                continue;
            }
            if t.is_empty() {
                continue;
            }
            let gated = std::mem::take(&mut cfg_pending);
            if t.starts_with("pub use ") {
                if !t.ends_with(';') {
                    open = Some((t.to_owned(), gated));
                } else if !gated {
                    out.push(t.to_owned());
                }
                continue;
            }
        }
        depth = (depth + unquoted_brace_delta(t)).max(0);
    }
    out
}

/// The net `[` minus `]` count of one [`blank_literals`] line.
fn bracket_delta(s: &str) -> i32 {
    s.chars().fold(0, |n, c| match c {
        '[' => n + 1,
        ']' => n - 1,
        _ => n,
    })
}

/// Record one `pub use <path>::…;` statement as a glob or as named exports.
/// A path of one segment (`pub use foo;`) names no runtime module and is
/// skipped.
fn parse_root_use(
    stmt: &str,
    globs: &mut Vec<Vec<String>>,
    named: &mut HashMap<String, NamedReexport>,
) {
    let Some(body) = stmt
        .strip_prefix("pub use ")
        .and_then(|s| s.trim().strip_suffix(';'))
    else {
        return;
    };
    let body = body.split_whitespace().collect::<Vec<_>>().join(" ");
    let segs_of = |path: &str| -> Vec<String> {
        path.split("::")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    };
    if let Some(path) = body.strip_suffix("::*") {
        globs.push(segs_of(path));
        return;
    }
    let (path, entries): (&str, Vec<&str>) = match body.split_once("::{") {
        Some((path, list)) => (path, list.trim_end_matches('}').split(',').collect()),
        None => match body.rsplit_once("::") {
            Some((path, name)) => (path, vec![name]),
            None => return,
        },
    };
    let path = segs_of(path);
    if path.is_empty() {
        return;
    }
    for entry in entries {
        let words: Vec<&str> = entry.split_whitespace().collect();
        let (item, exported) = match words.as_slice() {
            [item, "as", alias] => (*item, *alias),
            [item] => (*item, *item),
            _ => continue,
        };
        // `a::B` inside a brace list nests a path: its item lives one module
        // further down.
        let mut item_path = path.clone();
        let mut item_segs = segs_of(item);
        let Some(item) = item_segs.pop() else {
            continue;
        };
        item_path.extend(item_segs);
        let exported = exported.rsplit("::").next().unwrap_or(exported);
        named.insert(
            exported.to_owned(),
            NamedReexport {
                path: item_path,
                item,
            },
        );
    }
}

/// The top-level definitions of the runtime module at `path` (segments under
/// the runtime root), read from `<path>.rs` and `<path>/mod.rs`. A nested
/// module whose `mod` declaration in its parent is cfg-gated supplies none.
fn module_definitions(runtime_root: &Path, path: &[String]) -> BTreeSet<String> {
    let mut parent = runtime_root.to_path_buf();
    for seg in path {
        if parent != runtime_root
            && dir_child_declarations(&parent, &parent.with_extension("rs")).contains(seg)
        {
            return BTreeSet::new();
        }
        parent.push(seg);
    }
    let rel: std::path::PathBuf = path.iter().collect();
    let flat = runtime_root.join(&rel).with_extension("rs");
    let dir_mod = runtime_root.join(&rel).join("mod.rs");
    [flat, dir_mod]
        .iter()
        .filter_map(|file| std::fs::read_to_string(file).ok())
        .flat_map(|src| top_level_definitions(&blank_literals(&src)))
        .collect()
}

/// The names of the `pub`/`pub(crate)` items defined at brace depth 0 of a
/// [`blank_literals`] source that no `#[cfg(..)]` attribute gates —
/// `#[cfg(not(..))]` included, as it drops the item under a wasm32 build or a
/// feature-on mask: `struct`, `enum`, `union`,
/// `fn` (`const`/`async`/`extern` too), `type`, `trait`, `const`, `static`,
/// `mod`. A nested `pub use` or a `macro_rules!` supplies no name here, so a
/// reference only they could satisfy stays unresolved — the check fails
/// closed on what it cannot prove.
fn top_level_definitions(src: &str) -> BTreeSet<String> {
    const KINDS: &[&str] = &[
        "struct", "enum", "union", "fn", "type", "trait", "const", "static", "mod",
    ];
    const QUALIFIERS: &[&str] = &["pub", "crate", "async", "unsafe", "extern"];
    let mut out = BTreeSet::new();
    let mut depth: i32 = 0;
    let mut cfg_pending = false;
    // Bracket balance of a multi-line attribute still open.
    let mut attr_open: i32 = 0;
    for line in src.lines() {
        let t = line.trim();
        let at_root = depth == 0;
        depth = (depth + unquoted_brace_delta(t)).max(0);
        if !at_root || t.starts_with("//") || t.is_empty() {
            continue;
        }
        if attr_open > 0 {
            attr_open = (attr_open + bracket_delta(t)).max(0);
            continue;
        }
        if t.starts_with("#[") {
            if t.starts_with("#[cfg(") {
                cfg_pending = true;
            }
            attr_open = bracket_delta(t).max(0);
            continue;
        }
        let gated = std::mem::take(&mut cfg_pending);
        if gated || !(t.starts_with("pub ") || t.starts_with("pub(crate)")) {
            continue;
        }
        let mut words = t
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|w| !w.is_empty())
            .skip_while(|w| QUALIFIERS.contains(w));
        let Some(mut kind) = words.next() else {
            continue;
        };
        let mut name = words.next();
        if kind == "const" && matches!(name, Some("fn" | "async" | "unsafe" | "extern")) {
            kind = "fn";
            name = words.find(|w| !matches!(*w, "fn" | "async" | "unsafe" | "extern"));
        }
        if KINDS.contains(&kind)
            && let Some(name) = name
        {
            out.insert(name.to_owned());
        }
    }
    out
}

/// The set of top-level modules the emitted `ipe_runtime/mod.rs` DECLARES for
/// one flag mask.
#[allow(clippy::expect_used)] // test scaffolding: a body-free emit cannot fail
fn declared_for_mask(interner: &Interner, main: ipe_intern::Symbol, mask: u32) -> BTreeSet<String> {
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![module_for_mask(main, mask)],
    };
    let emitted = RustBackend::new(interner)
        .emit(&prog)
        .expect("emit must succeed for a body-free program");
    let mod_rs = emitted
        .files
        .get("src/ipe_runtime/mod.rs")
        .expect("emitted project must contain ipe_runtime/mod.rs");
    declared_modules(mod_rs)
}

/// The raw text of the emitted `ipe_runtime/mod.rs` for one flag mask — the
/// literal file, before any dedup, so a doubled `pub mod` line is observable.
#[allow(clippy::expect_used)] // test scaffolding: a body-free emit cannot fail
fn mod_rs_for_mask(interner: &Interner, main: ipe_intern::Symbol, mask: u32) -> String {
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![module_for_mask(main, mask)],
    };
    let emitted = RustBackend::new(interner)
        .emit(&prog)
        .expect("emit must succeed for a body-free program");
    emitted
        .files
        .get("src/ipe_runtime/mod.rs")
        .expect("emitted project must contain ipe_runtime/mod.rs")
        .clone()
}

/// Every way one emitted `mod.rs` fails to build in the configuration `env`:
/// a module it compiles reaches `crate::<seg>` under a predicate that does not
/// fail, and the module supplying `<seg>` is not declared under a predicate
/// that holds (or under the referencing module's own predicate); or it names a
/// `tokio::` path under such a predicate that the emitted `tokio` line (none on
/// wasm) does not enable. A source the scan cannot parse, a predicate it cannot
/// read and an unclassified `tokio::` path are violations too.
fn closure_violations(
    runtime_root: &Path,
    emit: &Emit,
    env: &CfgEnv,
    cache: &mut ScanCache,
) -> Vec<String> {
    let file = match parse_mod_rs(&emit.mod_rs) {
        Ok(file) => file,
        Err(e) => return vec![e],
    };
    let decls = match declarations(&file) {
        Ok(decls) => decls,
        Err(e) => return vec![e],
    };
    let overlay: Overlay = emit
        .runtime_files
        .iter()
        .map(|(rel, src)| (runtime_root.join(rel), src.clone()))
        .collect();
    let conds: HashMap<&str, &Cfg> = decls.iter().map(|d| (d.name.as_str(), &d.cond)).collect();
    let scope = RootScope::new(runtime_root, &emit.mod_rs);
    let tokio = if env.wasm {
        None
    } else {
        tokio_line_features(&emit.cargo_toml)
    };
    let mut out = Vec::new();
    for decl in &decls {
        if env.eval(&decl.cond) == Truth::Fails {
            continue;
        }
        let emitted_file = decl.inline.is_some()
            || overlay.contains_key(&decl_file(runtime_root, &overlay, decl).0);
        let mut own_errors = Vec::new();
        let (refs, errors) = if emitted_file {
            let refs = module_refs(runtime_root, &overlay, decl, &mut own_errors);
            (std::borrow::Cow::Owned(refs), own_errors.as_slice())
        } else {
            let (refs, errors) = cache
                .refs
                .entry((decl.name.clone(), decl.path.clone()))
                .or_insert_with(|| {
                    let mut errors = Vec::new();
                    let refs = module_refs(runtime_root, &overlay, decl, &mut errors);
                    (refs, errors)
                });
            (
                std::borrow::Cow::Borrowed(refs.as_slice()),
                errors.as_slice(),
            )
        };
        out.extend(errors.iter().map(|e| format!("`{}`: {e}", decl.name)));
        out.extend(tokio_violations(
            &decl.name,
            &required_of(RefKind::Tokio, &refs, &decl.cond, env),
            tokio.as_ref(),
        ));
        let required = required_segs(&refs, &decl.cond, env);
        for (seg, dep) in scope.deps_of(&required, &mut cache.defs) {
            let declared = conds
                .get(dep.as_str())
                .is_some_and(|c| env.eval(c) == Truth::Holds || **c == decl.cond);
            if !declared {
                out.push(format!(
                    "`{}` reaches `crate::{seg}` (supplied by `{dep}`), but `{dep}` is not \
                     declared under a predicate that holds",
                    decl.name
                ));
            }
        }
    }
    out
}

/// The build intents every flag mask is checked under: a release emit and a
/// development emit (`dev-posture`). The vendored runtime refuses a
/// `--debugger` emit, so the `debugger` feature never reaches it.
const EMIT_INTENTS: [BuildIntent; 2] = [BuildIntent::Release, BuildIntent::Development];

/// The parts of one emitted project the closure check reads.
struct Emit {
    mod_rs: String,
    cargo_toml: String,
    /// Every other file the project writes under `src/ipe_runtime/`, keyed by
    /// its path under the runtime root.
    runtime_files: BTreeMap<String, String>,
}

impl Emit {
    /// A fixture project: `mod_rs` and no other emitted runtime file.
    fn of_mod_rs(mod_rs: &str) -> Self {
        Self {
            mod_rs: mod_rs.to_owned(),
            cargo_toml: String::new(),
            runtime_files: BTreeMap::new(),
        }
    }
}

/// The emitted project of one flag mask.
#[allow(clippy::expect_used)] // test scaffolding: a body-free emit cannot fail
fn emit_mask(
    interner: &Interner,
    main: ipe_intern::Symbol,
    mask: u32,
    target: Target,
    intent: BuildIntent,
) -> Emit {
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![module_for_mask(main, mask)],
    };
    let emitted = RustBackend::new(interner)
        .with_target(target)
        .with_build_intent(intent)
        .emit(&prog)
        .expect("emit must succeed for a body-free program");
    let mut runtime_files = BTreeMap::new();
    let mut mod_rs = None;
    for (path, src) in emitted.files {
        match path.as_str().strip_prefix("src/ipe_runtime/") {
            Some("mod.rs") => mod_rs = Some(src),
            Some(rel) => {
                runtime_files.insert(rel.to_owned(), src);
            }
            None => {}
        }
    }
    Emit {
        mod_rs: mod_rs.expect("emitted project must contain ipe_runtime/mod.rs"),
        cargo_toml: emitted.cargo_toml,
        runtime_files,
    }
}

/// The per-mask closure obligation, under every [`EMIT_INTENTS`] entry: in the
/// configuration the emitted `Cargo.toml` builds under, every module the
/// emitted `mod.rs` compiles reaches only modules it declares as compiled.
/// Shared by the per-flag, pairwise, composed, and sampled proofs so they run
/// an identical check.
fn assert_mask_closed(
    runtime_root: &Path,
    interner: &Interner,
    main: ipe_intern::Symbol,
    mask: u32,
    cache: &mut ScanCache,
) {
    for intent in EMIT_INTENTS {
        let emit = emit_mask(interner, main, mask, Target::Native, intent);
        let env = manifest_env(&emit.cargo_toml, false);
        let violations = closure_violations(runtime_root, &emit, &env, cache);
        assert!(
            violations.is_empty(),
            "module-set SEAL breach — flag mask {mask:#019b}, {intent:?} emit, features {:?}. \
             The emitted crate would fail `cargo build` though `ipe` exits 0:\n{}",
            env.features,
            violations.join("\n")
        );
    }
}

/// A file-backed declaration: its name and its `#[path]`.
type DeclKey = (String, Option<String>);

/// One module's gated `crate::` references and its scan errors.
type ScannedRefs = (Vec<GatedRef>, Vec<String>);

/// Memoised source scans: each file-backed module's gated `crate::` references
/// with its scan errors, and each module path's top-level definitions. Both are
/// mask-independent.
#[derive(Default)]
struct ScanCache {
    refs: HashMap<DeclKey, ScannedRefs>,
    defs: DefCache,
}

// ── (1) per-flag closure — O(FLAG_COUNT) ────────────────────────────────────

/// Every single `uses_*` flag on its own (and the featureless base, mask 0)
/// emits a `mod.rs` whose declared set is closed under its unconditional deps.
/// The base case of the composition argument (module docs).
#[test]
fn each_flag_declares_a_closed_modset() {
    let runtime_root = e2e_support::require_runtime().into_path_buf();
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    let mut dep_cache = ScanCache::default();
    assert_mask_closed(&runtime_root, &interner, main, 0, &mut dep_cache);
    for bit in 0..FLAG_COUNT {
        assert_mask_closed(&runtime_root, &interner, main, 1u32 << bit, &mut dep_cache);
    }
}

// ── (2) monotonicity — the compose glue ─────────────────────────────────────

/// The declared module set distributes over union of flags:
/// `declared(a | b) = declared(a) ∪ declared(b)`. The emitter only APPENDS
/// feature modules, so enabling a flag can only add declarations, never drop
/// one — which lets per-flag closure compose to every combination. Verified on
/// the deterministic mask sample crossed with the singletons.
#[test]
fn declared_modset_is_monotone() {
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    for a in sampled_masks(SAMPLE_MASKS) {
        for bit in 0..FLAG_COUNT {
            let b = 1u32 << bit;
            let mut composed = declared_for_mask(&interner, main, a);
            composed.extend(declared_for_mask(&interner, main, b));
            let union_declared = declared_for_mask(&interner, main, a | b);
            assert_eq!(
                union_declared, composed,
                "monotonicity broken: declared(a | b) != declared(a) ∪ \
                 declared(b) — a={a:#019b} b={b:#019b}. Enabling a flag REMOVED a \
                 module declaration; per-flag closure no longer composes and a \
                 targeted combination check is needed for this interaction."
            );
        }
    }
}

// ── (3) composition — per-flag + monotone ⇒ every mask closed ───────────────

/// The composition made explicit: the all-flags declared set equals the UNION
/// of the per-flag declared sets, and that union is closed under its deps. Given
/// [`each_flag_declares_a_closed_modset`] and [`declared_modset_is_monotone`],
/// this stands in for the whole `2^FLAG_COUNT` sweep — any mask's declaration is
/// the union of its set-bit declarations, and every dep-target sits in the flag
/// that introduced the depending module (per-flag closure), so no union can drop
/// a needed module.
#[test]
fn composed_full_modset_is_closed() {
    let runtime_root = e2e_support::require_runtime().into_path_buf();
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    let all: u32 = (1u32 << FLAG_COUNT) - 1;

    let mut composed: BTreeSet<String> = BTreeSet::new();
    for bit in 0..FLAG_COUNT {
        composed.extend(declared_for_mask(&interner, main, 1u32 << bit));
    }
    let full = declared_for_mask(&interner, main, all);
    assert_eq!(
        full, composed,
        "composition invalid: declared(all) != ⋃ declared(singleton) — the \
         module set is not a pure per-flag union, so per-flag closure does not \
         compose"
    );

    let mut dep_cache = ScanCache::default();
    assert_mask_closed(&runtime_root, &interner, main, all, &mut dep_cache);
}

// ── the sampled full-mask backstop (redundancy, not the proof) ──────────────

/// A bounded, deterministic sample of full masks run through the whole per-mask
/// closure check, plus the corners (all-off, all-on, every singleton). A
/// redundancy net, not the primary guarantee; fixed seed ⇒ reproducible;
/// constant cost as `FLAG_COUNT` grows.
#[test]
fn sampled_full_masks_are_closed() {
    let runtime_root = e2e_support::require_runtime().into_path_buf();
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    let all: u32 = (1u32 << FLAG_COUNT) - 1;
    let mut dep_cache = ScanCache::default();

    let mut masks: BTreeSet<u32> = sampled_masks(SAMPLE_MASKS).into_iter().collect();
    masks.insert(0);
    masks.insert(all);
    for bit in 0..FLAG_COUNT {
        masks.insert(1u32 << bit);
    }
    for mask in masks {
        assert_mask_closed(&runtime_root, &interner, main, mask, &mut dep_cache);
    }
}

// ── no duplicate `pub mod` declaration in the emitted mod.rs ─────────────────

/// No emitted `ipe_runtime/mod.rs` may declare the same top-level module twice.
/// The emitter builds the file from a base list plus per-flag appends; if a
/// module sits in BOTH the base and a gated append, enabling that flag emits
/// `pub mod X;` twice and the emitted crate fails `cargo build` with
/// `error[E0428]: the name X is defined multiple times` — while `ipe` itself
/// exits 0. That is a SEAL breach: the ground-truth failure is a downstream
/// cargo error, so this proves the same property statically, without cargo.
///
/// Checked over the featureless base, every singleton flag, the all-flags
/// union, and the deterministic full-mask sample. The declaration set is a
/// per-flag union of appends (monotone; see module docs), so a duplicate can
/// only arise from a base/append or append/append overlap — both of which a
/// singleton or the union exercises. `declared_modules`' `BTreeSet` dedups
/// silently, so this test parses the raw text via `duplicate_declarations`.
#[test]
fn emitted_mod_rs_declares_no_module_twice() {
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    let all: u32 = (1u32 << FLAG_COUNT) - 1;

    let mut masks: BTreeSet<u32> = sampled_masks(SAMPLE_MASKS).into_iter().collect();
    masks.insert(0);
    masks.insert(all);
    for bit in 0..FLAG_COUNT {
        masks.insert(1u32 << bit);
    }
    for mask in masks {
        let mod_rs = mod_rs_for_mask(&interner, main, mask);
        let dups = duplicate_declarations(&mod_rs);
        assert!(
            dups.is_empty(),
            "duplicate-declaration SEAL breach: emitted `mod.rs` declares \
             {dups:?} more than once — flag mask {mask:#019b}. A module in both \
             the base list and a gated append emits `pub mod` twice; the \
             emitted crate fails `cargo build` (E0428) though `ipe` exits 0. \
             Declare it SOLELY via its gated append, or SOLELY in the base."
        );
    }
}

/// The always-on-core rule: a runtime module in the always-compiled BASE floor
/// (the module set emitted for a program that uses no `uses_*` feature — mask 0)
/// must reach only base modules in the base configuration. A base→gated edge
/// would force the gated module always-on (re-coupling the two), defeating the
/// point of gating and pulling the gated module's crates into every program.
///
/// The base floor is derived, not hardcoded: it is exactly the module set the
/// backend emits for the featureless program, read under the features its
/// `Cargo.toml` enables, so it tracks the template automatically.
#[test]
fn base_modules_do_not_reach_gated_modules() {
    let runtime_root = e2e_support::require_runtime().into_path_buf();
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    let emit = emit_mask(&interner, main, 0, Target::Native, BuildIntent::Release);
    let env = manifest_env(&emit.cargo_toml, false);
    let violations = closure_violations(&runtime_root, &emit, &env, &mut ScanCache::default());
    assert!(
        violations.is_empty(),
        "always-on-core rule violation: a base module reaches a module the \
         featureless base does not compile. Move the reach behind the gated \
         module's own cfg, or promote the module to the base floor:\n{}",
        violations.join("\n")
    );
}

/// Guard the `ct_eq` closure edge: `crypto_core` and `secret` both
/// `use crate::ct_eq::…` unconditionally, so every emitted `mod.rs` that
/// declares either of those modules MUST also declare `ct_eq`. Both modules
/// live in the base floor (mask 0), so this is a base-floor edge rather than a
/// per-flag edge — the base-floor test [`base_modules_do_not_reach_gated_modules`]
/// already covers it structurally, but this named witness makes the exact defect
/// class (SEAL: missing `ct_eq` in the emitted module set) fail loudly.
#[test]
fn base_declares_ct_eq_with_crypto_core_and_secret() {
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    // The featureless base (mask 0) emits `crypto_core` and `secret` from the
    // base template; `ct_eq` must accompany both.
    let declared = declared_for_mask(&interner, main, 0);
    assert!(
        declared.contains("ct_eq"),
        "base floor must declare `ct_eq` — `crypto_core` and `secret` use \
         `crate::ct_eq::…` unconditionally; without `ct_eq` the emitted crate \
         fails `cargo build` (E0433). Declared: {declared:?}"
    );
    assert!(
        declared.contains("crypto_core"),
        "base floor must declare `crypto_core`; got {declared:?}"
    );
    assert!(
        declared.contains("secret"),
        "base floor must declare `secret`; got {declared:?}"
    );
}

/// Guard the specific witnesses of the previously-live breaches at the flag
/// level: a `uses_web` shape must declare `tea` (web/pubsub `use crate::tea`),
/// and a `uses_server` shape must declare `tea` (`http_stream.rs` `use super::*`
/// → `IpeSub`). `http_stream` is declared only when `reaches_http_client` is
/// true (an HTTP kernel or email), so a server-only shape omits it — keeping
/// reqwest out of server/web apps with no outbound HTTP calls.
#[test]
fn web_shape_declares_tea() {
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    // uses_web only (bit 3).
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![module_for_mask(main, 1 << 3)],
    };
    let emitted = RustBackend::new(&interner).emit(&prog).expect("emit");
    let mod_rs = emitted.files.get("src/ipe_runtime/mod.rs").expect("mod.rs");
    let declared = declared_modules(mod_rs);
    assert!(
        declared.contains("tea") && declared.contains("web"),
        "uses_web must declare both `web` and `tea`; got {declared:?}"
    );
}

#[test]
fn server_shape_declares_tea_without_http_stream() {
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    // uses_server only (bit 1) — no HTTP kernel, no email.
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![module_for_mask(main, 1 << 1)],
    };
    let emitted = RustBackend::new(&interner).emit(&prog).expect("emit");
    let mod_rs = emitted.files.get("src/ipe_runtime/mod.rs").expect("mod.rs");
    let declared = declared_modules(mod_rs);
    assert!(
        declared.contains("tea") && declared.contains("server"),
        "uses_server must declare `server` and `tea`; got {declared:?}"
    );
    assert!(
        !declared.contains("http_stream"),
        "uses_server without an HTTP kernel must NOT declare `http_stream` \
         (reqwest must stay absent from a plain server app); got {declared:?}"
    );
}

#[test]
fn http_kernel_shape_declares_http_stream() {
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    // uses_http (bit 11) — the outbound HTTP client kernel.
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![module_for_mask(main, 1 << 11)],
    };
    let emitted = RustBackend::new(&interner).emit(&prog).expect("emit");
    let mod_rs = emitted.files.get("src/ipe_runtime/mod.rs").expect("mod.rs");
    let declared = declared_modules(mod_rs);
    assert!(
        declared.contains("http_client") && declared.contains("http_stream"),
        "uses_http must declare both `http_client` and `http_stream`; got {declared:?}"
    );
}

// ── wasm vendored module-set closure ─────────────────────────────────────────

/// The wasm vendored `WASM_RUNTIME_MOD_RS` module set is closed in the wasm32
/// configuration its `Cargo.toml` builds under: every module it compiles
/// reaches only modules it compiles.
///
/// The vendored path emits `src/ipe_runtime/mod.rs` from a STATIC constant
/// (`WASM_RUNTIME_MOD_RS`) rather than a per-flag append list, so a module that
/// calls `crate::<dep>::…` in a wasm32 build can only compile if `<dep>` is
/// also declared in that constant. The breach class: `ipe` exits 0; the
/// emitted wasm crate fails `cargo check` (E0433). The native closure tests do
/// not reach this set: they emit through the native template and its appends.
///
/// An inline module (`pub mod web { pub mod route; }`) compiles only the
/// children it declares, never the rest of its directory, and a required
/// `tokio::` path is refused: tokio is native-only.
#[test]
fn wasm_vendored_modset_is_closed() {
    let runtime_root = e2e_support::require_runtime().into_path_buf();
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    let mut cache = ScanCache::default();
    for intent in EMIT_INTENTS {
        let emit = emit_mask(&interner, main, 0, Target::WasmClient, intent);
        let env = manifest_env(&emit.cargo_toml, true);
        let violations = closure_violations(&runtime_root, &emit, &env, &mut cache);
        assert!(
            violations.is_empty(),
            "wasm vendored module-set SEAL breach — {intent:?} emit, features {:?}. \
             The emitted wasm crate fails `cargo check --target \
             wasm32-unknown-unknown` (E0433) though `ipe` exits 0; declare the \
             missing module in `WASM_RUNTIME_MOD_RS` \
             (`src/compiler/backend/rust/src/project.rs`):\n{}",
            env.features,
            violations.join("\n")
        );
    }
}

/// The wasm vendored module set must declare `app_config` — `log.rs` calls
/// `crate::app_config::resolve_log_level_override()` unconditionally, so the
/// absence of `app_config` from `WASM_RUNTIME_MOD_RS` breaks `cargo check
/// --target wasm32-unknown-unknown` with E0433.
///
/// A named witness alongside the structural test above: the structural test
/// catches any future drift; this named test makes the specific regression
/// fail loudly with a diagnostic that names the original defect.
#[test]
fn wasm_vendored_modset_declares_app_config() {
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![module_for_mask(main, 0)],
    };
    let emitted = RustBackend::new(&interner)
        .with_target(Target::WasmClient)
        .emit(&prog)
        .expect("wasm vendored emit must succeed");
    let mod_rs = emitted
        .files
        .get("src/ipe_runtime/mod.rs")
        .expect("wasm vendored emit must include src/ipe_runtime/mod.rs");
    let declared = declared_modules(mod_rs);
    assert!(
        declared.contains("app_config"),
        "`WASM_RUNTIME_MOD_RS` must declare `app_config` — `log.rs` calls \
         `crate::app_config::resolve_log_level_override()` unconditionally, so \
         its absence is E0433 in `cargo check --target wasm32-unknown-unknown`. \
         Declared: {declared:?}"
    );
    assert!(
        declared.contains("log"),
        "`WASM_RUNTIME_MOD_RS` must declare `log` (precondition for the \
         `app_config` edge); got {declared:?}"
    );
}

/// The wasm vendored module set must declare `seal_codec` — `ui/widget.rs`
/// imports `crate::seal_codec::{SealLimits, seal_decode_serde}` under
/// `#[cfg(feature = "json")]`, and the wasm module set always carries `json`
/// (`pub mod json;` is unconditional in `WASM_RUNTIME_MOD_RS`). So on wasm the
/// edge is effectively unconditional; without `seal_codec` the emitted wasm
/// crate fails `cargo check --target wasm32-unknown-unknown` with E0432.
///
/// The structural `wasm_vendored_modset_is_closed` scanner excludes the
/// `#[cfg(...)]`-gated import line, so a named witness pins the specific edge
/// that the `CustomElement.node` up-decode path relies on.
#[test]
fn wasm_vendored_modset_declares_seal_codec() {
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![module_for_mask(main, 0)],
    };
    let emitted = RustBackend::new(&interner)
        .with_target(Target::WasmClient)
        .emit(&prog)
        .expect("wasm vendored emit must succeed");
    let mod_rs = emitted
        .files
        .get("src/ipe_runtime/mod.rs")
        .expect("wasm vendored emit must include src/ipe_runtime/mod.rs");
    let declared = declared_modules(mod_rs);
    assert!(
        declared.contains("seal_codec"),
        "`WASM_RUNTIME_MOD_RS` must declare `seal_codec` — `ui/widget.rs` \
         imports `crate::seal_codec::{{SealLimits, seal_decode_serde}}` and the \
         wasm module set always carries `json`, so its absence is E0432 in \
         `cargo check --target wasm32-unknown-unknown`. Declared: {declared:?}"
    );
    assert!(
        declared.contains("json") && declared.contains("ui"),
        "`WASM_RUNTIME_MOD_RS` must declare `json` and `ui` (preconditions for \
         the `seal_codec` edge); got {declared:?}"
    );
}

/// Every emitted module set declares `narrow`, the narrowing helpers any kernel
/// module may call under any `cfg`.
///
/// The callers of `narrow` sit inside target-gated items
/// (`time::time_now`'s two target arms, `tea::EveryInterval::browser_delay_ms`),
/// so a set missing it fails the emitted `cargo build` (E0433) on the target
/// that compiles them. The featureless native
/// base set is the floor every flag mask extends
/// (`declared_modset_is_monotone`), so the base and the wasm set together
/// cover every emitted set.
#[test]
fn every_emitted_modset_declares_narrow() {
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    let base = declared_for_mask(&interner, main, 0);
    assert!(
        base.contains("narrow"),
        "the native base module set (`templates/ipe_runtime/mod.rs`) must declare \
         `narrow`; declared: {base:?}"
    );
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![module_for_mask(main, 0)],
    };
    let emitted = RustBackend::new(&interner)
        .with_target(Target::WasmClient)
        .emit(&prog)
        .expect("wasm vendored emit must succeed");
    let mod_rs = emitted
        .files
        .get("src/ipe_runtime/mod.rs")
        .expect("wasm vendored emit must include src/ipe_runtime/mod.rs");
    let wasm = declared_modules(mod_rs);
    assert!(
        wasm.contains("narrow"),
        "`WASM_RUNTIME_MOD_RS` must declare `narrow`; declared: {wasm:?}"
    );
}

// ── scanner unit tests: inline-path and cfg(test) regression ─────────────────

/// The scan detects `crate::<seg>::` occurrences that are NOT `use`
/// statements — path expressions and macro calls. This is the false-negative
/// class that let the `wasm app_config` and `revocation` E0433 SEAL breaches
/// reach main undetected.
#[test]
fn scanner_detects_inline_crate_path_expressions() {
    let deps = source_required(
        "fn f() {\n    if let Some(tag) = crate::app_config::resolve_log_level_override() {}\n}\n",
    );
    assert!(
        deps.contains("app_config"),
        "the scan must detect `crate::app_config::` in an inline path expression; got {deps:?}"
    );
    let deps = source_required("crate::ct_eq::impl_ct_eq!(Key);\n");
    assert!(
        deps.contains("ct_eq"),
        "the scan must detect `crate::ct_eq::` in a macro invocation; got {deps:?}"
    );
    let deps = source_required(
        "fn f() { if secret.len() < crate::jwt::HS256_MIN_SECRET_BYTES { crate::jwt::msg() } }\n",
    );
    assert!(
        deps.contains("jwt"),
        "the scan must detect repeated `crate::jwt::` refs; got {deps:?}"
    );
    let deps = source_required("fn f() { format!(\"{}\", crate::locale::tag()); }\n");
    assert!(
        deps.contains("locale"),
        "the scan must detect a `crate::` path inside a macro's arguments; got {deps:?}"
    );
}

/// A `crate::Foo` reference with NO trailing `::` that names no runtime module
/// is a re-exported item, not a module dependency — the scan must NOT register
/// it as a dep.
#[test]
fn scanner_ignores_bare_crate_item_without_module_path() {
    let deps = source_required("use crate::IpeMaybe;\n");
    assert!(
        deps.is_empty(),
        "bare `crate::Item` (no trailing `::`) must NOT register as a module dep; got {deps:?}"
    );
}

/// A runtime-root fixture for the [`RootScope`] resolver tests: `error.rs`
/// defines `IoFailure` unconditionally and `Gated` only under a cfg, and
/// `csv.rs` and `retained.rs` exist. Returns the root; the caller removes it.
#[allow(clippy::expect_used)] // test scaffolding: a temp fixture write cannot be skipped
fn root_scope_fixture(tag: &str) -> std::path::PathBuf {
    let root = ipe_test_temp::temp_root().join(format!(
        "ipe_modset_closure_root_scope_{tag}_{}",
        std::process::id()
    ));
    std::fs::create_dir_all(root.join("outer")).expect("create fixture root");
    let files = [
        (
            "error.rs",
            "/// A host failure.\n#[derive(Debug)]\npub struct IoFailure {\n    kind: u8,\n}\n\
             #[cfg(feature = \"x\")]\npub struct Gated;\n\
             #[cfg(not(target_arch = \"wasm32\"))]\npub struct NativeOnly;\n\
             mod inner {\n    pub struct Nested;\n}\n",
        ),
        ("io.rs", "pub struct IoFailure;\n"),
        (
            "outer/mod.rs",
            "#[cfg(feature = \"x\")]\npub mod inner;\npub mod open;\n",
        ),
        ("outer/inner.rs", "pub struct Deep;\n"),
        ("outer/open.rs", "pub struct Shallow;\n"),
        ("csv.rs", "pub fn read() {}\n"),
        (
            "retained.rs",
            "pub struct Bytes;\npub struct RetainedBytes;\n",
        ),
    ];
    for (name, src) in files {
        std::fs::write(root.join(name), src).expect("write fixture file");
    }
    root
}

/// Every root name rustc would refuse stays unresolved, never a passing dep:
/// an item only a `#[cfg(not(..))]` defines (absent from a wasm32 build), a
/// name two globs both define (E0659), a re-export behind a multi-line cfg
/// attribute, a named re-export of an item its module lacks (E0432), and a
/// glob over a nested module its parent declares under a cfg.
#[test]
fn root_scope_refuses_names_rustc_cannot_resolve() {
    let root = root_scope_fixture("unsound");
    let mut defs = DefCache::new();
    let cfg_not = RootScope::new(&root, "pub mod error;\npub use error::*;\n")
        .resolve("NativeOnly", &mut defs);
    let ambiguous = RootScope::new(
        &root,
        "pub mod error;\npub mod io;\npub use error::*;\npub use io::*;\n",
    )
    .resolve("IoFailure", &mut defs);
    let multi_line_cfg = RootScope::new(
        &root,
        "pub mod error;\n#[cfg(any(\n    feature = \"x\",\n    feature = \"y\",\n))]\n\
         pub use error::*;\n",
    )
    .resolve("IoFailure", &mut defs);
    let missing_item = RootScope::new(
        &root,
        "pub mod retained;\npub use retained::{Bytes, Gone as Held};\n",
    )
    .resolve("Held", &mut defs);
    let gated_nested = RootScope::new(&root, "pub mod outer;\npub use outer::inner::*;\n")
        .resolve("Deep", &mut defs);
    let open_nested = RootScope::new(&root, "pub mod outer;\npub use outer::open::*;\n")
        .resolve("Shallow", &mut defs);
    let commented = RootScope::new(
        &root,
        "pub mod error;\npub use error::*; // the error kinds\n",
    )
    .resolve("IoFailure", &mut defs);
    let _ = std::fs::remove_dir_all(&root);

    assert_eq!(
        cfg_not,
        RootRef::Unresolved,
        "a `#[cfg(not(..))]` item is absent under its predicate, so it is not unconditional"
    );
    assert_eq!(
        ambiguous,
        RootRef::Ambiguous,
        "two globs defining one name make `crate::<name>` E0659"
    );
    assert_eq!(
        multi_line_cfg,
        RootRef::Unresolved,
        "a re-export behind a multi-line cfg attribute is gated"
    );
    assert_eq!(
        missing_item,
        RootRef::Unresolved,
        "a named re-export of an item its module does not define supplies nothing"
    );
    assert_eq!(
        gated_nested,
        RootRef::Unresolved,
        "a glob over a cfg-declared nested module supplies nothing unconditionally"
    );
    let outer = RootRef::Reexported {
        provider: "outer".to_owned(),
    };
    assert_eq!(
        open_nested, outer,
        "an ungated nested module still supplies"
    );
    assert_eq!(
        commented,
        RootRef::Reexported {
            provider: "error".to_owned()
        },
        "a trailing comment does not hide the re-export"
    );
    for refused in [
        cfg_not,
        ambiguous,
        multi_line_cfg,
        missing_item,
        gated_nested,
    ] {
        assert_eq!(
            refused.dep("Probe").as_deref(),
            Some("Probe"),
            "a refused name stays its own (never declared) dep"
        );
    }
}

/// A `crate::<Type>::…` path resolves to the module whose root re-export
/// supplies the type, a `crate::<module>::…` path to the module itself, and a
/// segment no root name supplies stays an unresolved dep the closure check
/// fires on.
#[test]
fn root_scope_resolves_a_crate_item_path_to_its_providing_module() {
    let root = root_scope_fixture("resolve");
    let mod_rs = "pub mod error;\npub mod csv;\npub mod retained;\npub use error::*;\n\
                  pub use csv::*;\npub use retained::{Bytes, RetainedBytes as Held};\n\
                  pub fn root_helper() {}\n";
    let scope = RootScope::new(&root, mod_rs);
    let mut defs = DefCache::new();

    let raw = source_required(
        "fn f() {\n    crate::IoFailure::on_path(\"read CSV file\", path, io);\n    \
         crate::csv::read();\n    crate::NoSuchItem::x();\n    crate::Held::new();\n    \
         crate::Bytes::new();\n    crate::root_helper::x();\n    crate::Gated::x();\n    \
         crate::Nested::x();\n}\n",
    );
    let pairs = scope.deps_of(&raw, &mut defs);
    let resolved: HashMap<&str, &str> = pairs
        .iter()
        .map(|(seg, dep)| (seg.as_str(), dep.as_str()))
        .collect();
    let _ = std::fs::remove_dir_all(&root);

    assert_eq!(
        resolved.get("IoFailure"),
        Some(&"error"),
        "a glob-re-exported type resolves to its defining module"
    );
    assert_eq!(
        resolved.get("csv"),
        Some(&"csv"),
        "a module path stays the module"
    );
    assert_eq!(
        resolved.get("Held"),
        Some(&"retained"),
        "an aliased named re-export"
    );
    assert_eq!(
        resolved.get("Bytes"),
        Some(&"retained"),
        "a named re-export"
    );
    assert!(
        !resolved.contains_key("root_helper"),
        "an unconditional item the `mod.rs` defines itself needs no module"
    );
    for unresolved in ["NoSuchItem", "Gated", "Nested"] {
        assert_eq!(
            resolved.get(unresolved),
            Some(&unresolved),
            "`crate::{unresolved}` has no unconditional root name, so it stays its own dep"
        );
        assert!(
            !scope.declared.contains(unresolved),
            "an unresolved dep is never a declared module, so the closure check fires"
        );
    }
}

/// A re-export the `mod.rs` emits without declaring its module, or emits only
/// under a cfg, does not satisfy the reference: the first yields a dep the
/// declared set lacks, the second leaves the segment unresolved.
#[test]
fn root_scope_refuses_an_undeclared_or_gated_provider() {
    let root = root_scope_fixture("refuse");
    let undeclared = RootScope::new(&root, "pub mod csv;\npub use error::*;\n");
    let gated = RootScope::new(
        &root,
        "pub mod error;\npub mod csv;\n#[cfg(feature = \"x\")]\npub use error::*;\n",
    );
    let mut defs = DefCache::new();
    let undeclared_ref = undeclared.resolve("IoFailure", &mut defs);
    let gated_ref = gated.resolve("IoFailure", &mut defs);
    let _ = std::fs::remove_dir_all(&root);

    assert_eq!(
        undeclared_ref,
        RootRef::Reexported {
            provider: "error".to_owned()
        }
    );
    assert!(
        !undeclared.declared.contains("error"),
        "the provider `error` is not declared, so the closure check fires on `csv`"
    );
    assert_eq!(
        gated_ref,
        RootRef::Unresolved,
        "a cfg-gated re-export supplies no name unconditionally"
    );
}

/// References inside a `#[cfg(test)] mod tests` block never compile in an
/// emitted build, so they are not deps.
#[test]
fn scanner_excludes_crate_refs_inside_cfg_test_mod() {
    let deps = source_required(
        r"
pub fn prod() -> i32 { 42 }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonexistent_module::helper;
    fn check() { crate::nonexistent_module::run(); }
}
",
    );
    assert!(
        deps.is_empty(),
        "no compiled crate-root deps in this fixture; got {deps:?}"
    );
}

/// Blanking empties every literal and block comment, whatever its shape or the
/// lines it spans, and leaves the code and the lifetimes around it.
#[test]
fn blank_literals_empties_every_literal_and_keeps_code() {
    let depth = |src: &str| unquoted_brace_delta(&blank_literals(src));
    assert_eq!(depth("('r', Some('#' | '\"')) if x => {"), 1);
    assert_eq!(depth("fn f() { let b = br#\"x\"y\"#; g(async {}); }"), 0);
    assert_eq!(depth("fn f() { let c = cr#\"x\"y\"#; }"), 0);
    assert_eq!(depth("let s = r\"{\"; let t = r##\"}\"#\"##; {"), 1);
    assert_eq!(depth("let c = '\\u{7b}'; let d = '\\''; {"), 1);
    assert_eq!(depth("'a: loop { f::<'a>(); }"), 0);
    assert_eq!(depth("let xr = 1; { let s = \"}\"; }"), 0);
    assert_eq!(depth("let s = \"a{ \\\n }\"; {"), 1);
    assert_eq!(depth("let s = r##\"{\n}\n{\"##; /* { /* } */ { */ }"), -1);
    assert_eq!(depth("fn f() { // {{"), 1);
    assert_eq!(
        blank_literals("let a = 'x'; // 'q \" z"),
        "let a = ' '; // 'q \" z"
    );
}

/// A test module whose fixtures hold letter char literals, raw byte strings and
/// multi-line strings with unbalanced braces keeps its `crate::` references out
/// of the deps, and a production reference after it is still found.
#[test]
fn scanner_excludes_a_test_mod_with_literal_fixtures() {
    let deps = source_required(
        r###"
pub fn prod() -> i32 { 42 }

#[cfg(all(test, not(target_arch = "wasm32")))]
mod fixtures {
    fn code_only(c: char) -> bool {
        match (c, Some('x')) {
            ('r', Some('#' | '"')) if c == 'r' => {
                let b = br#"x"y"#;
                true
            }
            _ => false,
        }
    }
    fn multi() {
        let bare = "pub fn sub_fake() { IpeSub::Source(Box::new(move |emit| { \
                    work::start(async move {}); SourceTask::Idle })) }";
        let quoted = r##"pub fn sub_quoted() {
    let s = "work::start(";
}
#[cfg(test)]
mod tests {
    fn t() { work::start(async {}); }
"##;
    }
    const GUARD: fn() = crate::root_item::run;
}

pub fn after() { crate::real_dep::run(); }
"###,
    );
    assert_eq!(
        deps,
        BTreeSet::from(["real_dep".to_owned()]),
        "only the production reference counts, and the one after a fixture-laden test module is found"
    );
}

/// A child module whose `mod` declaration is cfg-gated is gated whole: its
/// file's `crate::` references hold only under that cfg, even on lines carrying
/// no cfg of their own. An ungated sibling's hold always, a
/// `#[cfg(not(..))]` child's hold while its feature is off, and a
/// `#[cfg_attr(..)]` gates nothing.
#[test]
#[allow(clippy::expect_used)] // test scaffolding: a fixture write cannot be skipped
fn scanner_scopes_a_cfg_gated_mod_declaration_to_the_child_file() {
    let root = ipe_test_temp::temp_root().join(format!(
        "ipe_modset_closure_gated_child_{}",
        std::process::id()
    ));
    let web = root.join("web");
    let nested = web.join("hub");
    std::fs::create_dir_all(&nested).expect("create fixture dirs");
    let files = [
        (
            web.join("mod.rs"),
            "/// Server-only.\n#[cfg(feature = \"server\")]\n#[allow(dead_code)]\npub mod csrf;\n\
             #[cfg(feature = \"db\")]\npub(crate) mod hub;\npub mod plain;\n\
             #[cfg_attr(test, allow(dead_code))]\npub mod attr;\n\
             #[cfg(not(feature = \"db\"))]\nmod fallback;\n\
             #[cfg(feature = \"server\")]\nfn gated() {\n    crate::session::x();\n}\n",
        ),
        (
            web.join("csrf.rs"),
            "pub fn set() -> crate::server::SetCookie {\n    use crate::server::{CookieName};\n}\n",
        ),
        (web.join("plain.rs"), "use crate::tea::Model;\n"),
        (web.join("attr.rs"), "use crate::alpha::A;\n"),
        (web.join("fallback.rs"), "use crate::beta::B;\n"),
        (nested.join("mod.rs"), "use crate::db::Pool;\n"),
    ];
    for (path, src) in &files {
        std::fs::write(path, src).expect("write fixture file");
    }
    let bare = module_required(&root, "web", &bare_env());
    let with = |features: &[&str]| CfgEnv {
        features: features.iter().map(|f| (*f).to_owned()).collect(),
        wasm: false,
    };
    let server = module_required(&root, "web", &with(&["server"]));
    let db = module_required(&root, "web", &with(&["db"]));
    let _ = std::fs::remove_dir_all(&root);
    let set =
        |names: &[&str]| -> BTreeSet<String> { names.iter().map(|n| (*n).to_owned()).collect() };
    assert_eq!(
        bare,
        set(&["alpha", "beta", "tea"]),
        "with no feature on only the ungated children and the `not(db)` child compile"
    );
    assert_eq!(
        server,
        set(&["alpha", "beta", "server", "session", "tea"]),
        "the `server` feature compiles the `server`-gated child and item"
    );
    assert_eq!(
        db,
        set(&["alpha", "db", "tea"]),
        "the `db` feature compiles `hub` and drops the `not(db)` child"
    );
}

/// `log.rs`'s inline `crate::app_config::` and `crate::system::` calls are
/// deps of `log` in every configuration, so a module set declaring `log`
/// without `app_config` is refused by name.
#[test]
fn scanner_detects_log_rs_dep_on_app_config() {
    let runtime_root = e2e_support::require_runtime().into_path_buf();
    let deps = module_required(&runtime_root, "log", &bare_env());
    assert!(
        deps.contains("app_config"),
        "`log.rs` must register `app_config` as a dep \
         (via `crate::app_config::resolve_log_level_override()`); got {deps:?}"
    );
    assert!(
        deps.contains("system"),
        "`log.rs` must register `system` as a dep \
         (via `crate::system::read_env_var()`); got {deps:?}"
    );
}

// ── pairwise closure — the feature interactions composition cannot see ─────

/// Every PAIR of `uses_*` flags emits a closed module set. A module's
/// references depend on the features the manifest enables (a `web`-gated item
/// in `web/mod.rs` reaching `crate::bundle_route`), so a reference one flag's
/// feature turns on may need a module only another flag declares: closure of
/// each singleton does not compose to their union. Every two-flag interaction
/// is checked here; wider ones are covered by the sampled and all-flags masks.
#[test]
fn flag_pairs_declare_a_closed_modset() {
    let runtime_root = e2e_support::require_runtime().into_path_buf();
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    let mut cache = ScanCache::default();
    for a in 0..FLAG_COUNT {
        for b in (a + 1)..FLAG_COUNT {
            let mask = (1u32 << a) | (1u32 << b);
            assert_mask_closed(&runtime_root, &interner, main, mask, &mut cache);
        }
    }
}

/// A `uses_web` shape compiles `bundle_route`: the served `web` surface's
/// static-asset media types (`web::static_noise_mime`, `web`-gated) name
/// `crate::bundle_route::MediaType`. A named witness of the edge the closure
/// proofs check structurally.
#[test]
fn web_shape_declares_bundle_route() {
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    for intent in EMIT_INTENTS {
        let emit = emit_mask(&interner, main, 1 << 3, Target::Native, intent);
        let env = manifest_env(&emit.cargo_toml, false);
        let file = parse_mod_rs(&emit.mod_rs).expect("the emitted `mod.rs` parses");
        let decls = declarations(&file).expect("the emitted `mod.rs` predicates read");
        let compiled = |name: &str| {
            decls
                .iter()
                .any(|d| d.name == name && env.eval(&d.cond) == Truth::Holds)
        };
        assert!(
            compiled("web") && compiled("bundle_route"),
            "uses_web must compile both `web` and `bundle_route` — {intent:?} emit, \
             features {:?}",
            env.features
        );
    }
}

/// A runtime fixture for the closure-check refusal tests: `files` written
/// under a fresh root. The caller removes it.
#[allow(clippy::expect_used)] // test scaffolding: a temp fixture write cannot be skipped
fn closure_fixture(tag: &str, files: &[(&str, &str)]) -> PathBuf {
    let root = ipe_test_temp::temp_root().join(format!(
        "ipe_modset_closure_cfg_{tag}_{}",
        std::process::id()
    ));
    for (rel, src) in files {
        let path = root.join(rel);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).expect("create fixture dir");
        }
        std::fs::write(&path, src).expect("write fixture file");
    }
    root
}

/// The violations of the fixture `mod_rs` with exactly `features` on.
fn fixture_violations(root: &Path, mod_rs: &str, features: &[&str]) -> Vec<String> {
    tokio_fixture_violations(root, mod_rs, features, None)
}

/// The violations of the fixture `mod_rs` with exactly `features` on and the
/// emitted `tokio` line enabling `tokio` (`None`: no `tokio` dependency).
fn tokio_fixture_violations(
    root: &Path,
    mod_rs: &str,
    features: &[&str],
    tokio: Option<&[&str]>,
) -> Vec<String> {
    let env = CfgEnv {
        features: features.iter().map(|f| (*f).to_owned()).collect(),
        wasm: false,
    };
    let mut emit = Emit::of_mod_rs(mod_rs);
    emit.cargo_toml = tokio.map_or_else(String::new, tokio_line);
    closure_violations(root, &emit, &env, &mut ScanCache::default())
}

/// A `tokio = { .. }` dependency line enabling exactly `features`.
fn tokio_line(features: &[&str]) -> String {
    let quoted: Vec<String> = features.iter().map(|f| format!("\"{f}\"")).collect();
    format!(
        "[dependencies]\ntokio = {{ version = \"1\", features = [{}] }}\n",
        quoted.join(", ")
    )
}

/// The shape of the served-asset breach: a module whose feature-gated item
/// reaches a module declared under a feature the manifest leaves off is
/// refused; with that feature on, or the item's feature off, it builds.
#[test]
fn a_feature_gated_reference_needs_its_module_compiled() {
    let root = closure_fixture(
        "feature",
        &[
            (
                "web.rs",
                "#[cfg(feature = \"web\")]\nfn mime() -> u8 { crate::bundle_route::of() }\n",
            ),
            ("bundle_route.rs", "pub fn of() -> u8 { 0 }\n"),
        ],
    );
    let mod_rs = "pub mod web;\n#[cfg(feature = \"encoding\")]\npub mod bundle_route;\n";
    let breach = fixture_violations(&root, mod_rs, &["web"]);
    let encoded = fixture_violations(&root, mod_rs, &["web", "encoding"]);
    let unserved = fixture_violations(&root, mod_rs, &[]);
    let ungated = fixture_violations(&root, "pub mod web;\npub mod bundle_route;\n", &["web"]);
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        breach.iter().any(|v| v.contains("`bundle_route`")),
        "`web` reaches `bundle_route` under `web`, which is on, and `bundle_route` \
         is declared under `encoding`, which is off: refused; got {breach:?}"
    );
    assert!(encoded.is_empty(), "both features on: {encoded:?}");
    assert!(
        unserved.is_empty(),
        "the referencing item compiles out: {unserved:?}"
    );
    assert!(ungated.is_empty(), "an ungated declaration: {ungated:?}");
}

/// A reference under a predicate the build host decides (`#[cfg(unix)]`) is
/// required, since some host compiles it; a module declared under the same
/// predicate as its referrer satisfies it, one under another does not.
#[test]
fn a_host_gated_reference_is_required() {
    let root = closure_fixture(
        "host",
        &[
            ("a.rs", "#[cfg(unix)]\npub fn f() { crate::b::g(); }\n"),
            ("b.rs", "pub fn g() {}\n"),
        ],
    );
    let undeclared = fixture_violations(&root, "pub mod a;\n", &[]);
    let same_gate = fixture_violations(
        &root,
        "#[cfg(unix)]\npub mod a;\n#[cfg(unix)]\npub mod b;\n",
        &[],
    );
    let other_gate = fixture_violations(&root, "pub mod a;\n#[cfg(windows)]\npub mod b;\n", &[]);
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        undeclared.iter().any(|v| v.contains("`b`")),
        "a `cfg(unix)` reference to an undeclared module: {undeclared:?}"
    );
    assert!(
        same_gate.is_empty(),
        "both under `cfg(unix)`: {same_gate:?}"
    );
    assert!(
        other_gate.iter().any(|v| v.contains("`b`")),
        "`b` under `cfg(windows)` does not hold where `a` reaches it: {other_gate:?}"
    );
}

/// A predicate the evaluator cannot read is refused, never read as either
/// truth.
#[test]
fn an_unreadable_cfg_predicate_is_refused() {
    let root = closure_fixture(
        "unreadable",
        &[("a.rs", "#[cfg(frobnicate)]\npub fn f() {}\n")],
    );
    let in_source = fixture_violations(&root, "pub mod a;\n", &[]);
    let in_mod_rs = fixture_violations(&root, "#[cfg(target_banana = \"x\")]\npub mod a;\n", &[]);
    let not_pair = fixture_violations(&root, "#[cfg(not(test, unix))]\npub mod a;\n", &[]);
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        in_source.iter().any(|v| v.contains("frobnicate")),
        "an unknown cfg flag in a module source: {in_source:?}"
    );
    assert!(
        in_mod_rs.iter().any(|v| v.contains("target_banana")),
        "an unknown cfg atom on a declaration: {in_mod_rs:?}"
    );
    assert!(
        not_pair.iter().any(|v| v.contains("not(..)")),
        "`not` over two predicates: {not_pair:?}"
    );
}

/// A file's inner `#![cfg(..)]` gates every reference in it, a `#[test]`
/// function never compiles, a `#[path]` child is read at the path it names, a
/// child declared without a file is refused, and an exact `super::` chain
/// reaches the crate root.
#[test]
fn file_gates_and_child_paths_are_followed() {
    let root = closure_fixture(
        "files",
        &[
            (
                "inner.rs",
                "#![cfg(feature = \"f\")]\npub fn f() { crate::b::g(); }\n",
            ),
            ("tested.rs", "#[test]\nfn t() { crate::b::g(); }\n"),
            (
                "pathed.rs",
                "#[path = \"elsewhere/impl_file.rs\"]\nmod child;\n",
            ),
            ("elsewhere/impl_file.rs", "pub fn f() { crate::b::g(); }\n"),
            ("ghost.rs", "mod missing;\n"),
            ("chain/mod.rs", "mod leaf;\n"),
            ("chain/leaf.rs", "pub fn f() { super::super::b::g(); }\n"),
        ],
    );
    let inner_off = fixture_violations(&root, "pub mod inner;\n", &[]);
    let inner_on = fixture_violations(&root, "pub mod inner;\n", &["f"]);
    let tested = fixture_violations(&root, "pub mod tested;\n", &[]);
    let pathed = fixture_violations(&root, "pub mod pathed;\n", &[]);
    let ghost = fixture_violations(&root, "pub mod ghost;\n", &[]);
    let chain = fixture_violations(&root, "pub mod chain;\n", &[]);
    let _ = std::fs::remove_dir_all(&root);
    assert!(inner_off.is_empty(), "the file compiles out: {inner_off:?}");
    assert!(
        inner_on.iter().any(|v| v.contains("`b`")),
        "the file compiles with `f` on: {inner_on:?}"
    );
    assert!(tested.is_empty(), "a `#[test]` fn: {tested:?}");
    assert!(
        pathed.iter().any(|v| v.contains("`b`")),
        "the `#[path]` child's reference: {pathed:?}"
    );
    assert!(
        ghost.iter().any(|v| v.contains("no file")),
        "a `mod` with no file: {ghost:?}"
    );
    assert!(
        chain.iter().any(|v| v.contains("`b`")),
        "`super::super::` from depth 2 reaches the crate root: {chain:?}"
    );
}

/// The features a manifest enables are its `default` list closed under the
/// `[features]` table, dependency features naming their feature and `dep:`
/// entries none.
#[test]
fn enabled_features_close_the_default_list() {
    let manifest = "[package]\nname = \"x\"\n\n[features]\n\
                    default = [\"json\", \"web\"] # served\n\
                    web = [\n    \"web-core\",\n    \"widget-assets\",\n    \"dep:axum\",\n]\n\
                    web-core = [\"tokio/rt\"]\nwidget-assets = []\nencoding = []\n\
                    json = [\"serde?/std\"]\n\n[dependencies]\ntokio = { version = \"1\" }\n";
    let enabled = enabled_features(manifest);
    let expected: BTreeSet<String> = ["json", "tokio", "web", "web-core", "widget-assets"]
        .iter()
        .map(|f| (*f).to_owned())
        .collect();
    assert_eq!(enabled, expected);
    assert!(
        enabled_features("[package]\nname = \"x\"\n").is_empty(),
        "no `default` entry enables nothing"
    );
}

// ── `tokio::` paths: the runtime crate and the classification ───────────────

/// Every required `tokio::` path in the runtime crate is enabled by the tokio
/// features its own manifest resolves for the selection.
///
/// For the empty selection, each runtime feature alone, and every native
/// feature at once, the runtime's own `mod.rs` is scanned under the features
/// the runtime `[features]` table closes the selection to, against the base
/// `tokio` line plus every `tokio/x` and `tokio?/x` entry of that closure. The
/// table is read from the runtime `Cargo.toml`, independent of the backend's
/// projection.
#[test]
#[allow(clippy::expect_used)] // test scaffolding: the runtime sources are part of the checkout
fn runtime_crate_tokio_references_are_declared() {
    let runtime_root = e2e_support::require_runtime().into_path_buf();
    let crate_root = e2e_support::require_runtime_crate();
    let manifest =
        std::fs::read_to_string(crate_root.join("Cargo.toml")).expect("read runtime Cargo.toml");
    let mod_rs = std::fs::read_to_string(runtime_root.join("mod.rs")).expect("read runtime mod.rs");
    let base = tokio_line_features(&manifest).expect("the runtime declares a tokio dependency");
    let table = feature_table(&manifest);
    let names: Vec<&str> = ipe_backend_rust::tokio_projection_table()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    let native: Vec<String> = names
        .iter()
        .filter(|n| **n != "wasm-client")
        .map(|n| (*n).to_owned())
        .collect();
    let selections = std::iter::once(Vec::new())
        .chain(names.iter().map(|n| vec![(*n).to_owned()]))
        .chain(std::iter::once(native));
    let mut cache = ScanCache::default();
    let mut breaches = Vec::new();
    for selection in selections {
        let (features, subs) = close_features(&table, selection.clone());
        let mut enabled: Vec<&str> = base.iter().map(|f| f.as_str()).collect();
        enabled.extend(subs.iter().map(String::as_str));
        let emit = Emit {
            mod_rs: mod_rs.clone(),
            cargo_toml: if features.contains("tokio") {
                tokio_line(&enabled)
            } else {
                String::new()
            },
            runtime_files: BTreeMap::new(),
        };
        let env = CfgEnv {
            features,
            wasm: false,
        };
        breaches.extend(
            closure_violations(&runtime_root, &emit, &env, &mut cache)
                .into_iter()
                .filter(|v| v.starts_with(TOKIO_BREACH))
                .map(|v| format!("selection {selection:?}: {v}")),
        );
    }
    assert!(
        breaches.is_empty(),
        "the runtime crate names a tokio API its manifest does not enable for the \
         selection; add the `tokio/x` entry to the runtime `[features]` row and the \
         `RuntimeFeature::tokio_projection` arm:\n{}",
        breaches.join("\n")
    );
}

/// A `tokio::` path under a predicate that holds needs its feature in the
/// emitted `tokio` line.
#[test]
fn a_tokio_path_under_a_holding_cfg_needs_its_feature() {
    let root = closure_fixture(
        "tokio_holding",
        &[(
            "a.rs",
            "#[cfg(feature = \"tokio\")]\nmod m { use tokio::sync::mpsc; }\n",
        )],
    );
    let lacking = tokio_fixture_violations(&root, "pub mod a;\n", &["tokio"], Some(&["rt"]));
    let declared =
        tokio_fixture_violations(&root, "pub mod a;\n", &["tokio"], Some(&["rt", "sync"]));
    let absent = tokio_fixture_violations(&root, "pub mod a;\n", &["tokio"], None);
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        lacking
            .iter()
            .any(|v| v.starts_with(TOKIO_BREACH) && v.contains("tokio::sync::mpsc")),
        "`tokio::sync` with a line lacking `sync`: {lacking:?}"
    );
    assert!(declared.is_empty(), "`sync` declared: {declared:?}");
    assert!(
        absent
            .iter()
            .any(|v| v.contains("declares no `tokio` dependency")),
        "no tokio line at all: {absent:?}"
    );
}

/// A `tokio::` path under a predicate that fails is not required.
#[test]
fn a_tokio_path_under_a_failing_cfg_is_not_required() {
    let root = closure_fixture(
        "tokio_failing",
        &[(
            "a.rs",
            "#[cfg(feature = \"web\")]\npub fn f() { let _ = tokio::process::Command::new(\"x\"); }\n\
             #[cfg(test)]\nmod t { use tokio::time::advance; }\n",
        )],
    );
    let off = tokio_fixture_violations(&root, "pub mod a;\n", &[], Some(&["rt"]));
    let on = tokio_fixture_violations(&root, "pub mod a;\n", &["web"], Some(&["rt"]));
    let _ = std::fs::remove_dir_all(&root);
    assert!(off.is_empty(), "both paths compile out: {off:?}");
    assert!(
        on.iter()
            .any(|v| v.contains("tokio::process::Command::new")),
        "the scan reads the `web`-gated path once `web` is on: {on:?}"
    );
    assert!(
        !on.iter().any(|v| v.contains("advance")),
        "a `cfg(test)` path is never required: {on:?}"
    );
}

/// A `tokio::` path under a predicate the build host decides is required.
#[test]
fn a_host_gated_tokio_path_is_required() {
    let root = closure_fixture(
        "tokio_host",
        &[(
            "a.rs",
            "#[cfg(unix)]\npub fn f() { let _ = tokio::signal::unix::SignalKind::terminate(); }\n",
        )],
    );
    let lacking = tokio_fixture_violations(&root, "pub mod a;\n", &[], Some(&["rt"]));
    let declared = tokio_fixture_violations(&root, "pub mod a;\n", &[], Some(&["rt", "signal"]));
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        lacking.iter().any(|v| v.contains("tokio::signal::unix")),
        "a `cfg(unix)` signal path with a line lacking `signal`: {lacking:?}"
    );
    assert!(declared.is_empty(), "`signal` declared: {declared:?}");
}

/// A `tokio::` path the classification does not name is refused, whatever the
/// emitted line enables.
#[test]
fn an_unclassified_tokio_path_is_refused() {
    let root = closure_fixture(
        "tokio_unclassified",
        &[
            ("a.rs", "pub fn f() { let _ = tokio::io::stdin(); }\n"),
            ("b.rs", "use tokio::*;\n"),
        ],
    );
    let every: Vec<&str> = TokioFeature::ALL.iter().map(|f| f.as_str()).collect();
    let refused = tokio_fixture_violations(&root, "pub mod a;\npub mod b;\n", &[], Some(&every));
    let _ = std::fs::remove_dir_all(&root);
    for path in ["tokio::io::stdin", "tokio::*"] {
        assert!(
            refused
                .iter()
                .any(|v| v.contains(&format!("`{path}` is an unclassified tokio path"))),
            "`{path}` must be refused: {refused:?}"
        );
    }
}

/// An import that hides which tokio items it reaches is refused even with every
/// tokio feature declared: the crate imported whole or renamed, and a module
/// (`io`, `time`) imported bare, renamed, through `self` or by glob, whose items
/// need different features.
#[test]
fn tokio_imports_hiding_their_items_are_refused() {
    let root = closure_fixture(
        "tokio_hiding",
        &[
            (
                "a.rs",
                "use tokio::io;\npub fn f() { let _ = io::sink(); }\n",
            ),
            ("b.rs", "use tokio::{io::{self as tio}, time::*};\n"),
            ("c.rs", "use tokio as t;\n"),
            ("d.rs", "extern crate tokio as tk;\n"),
            ("e.rs", "use ::tokio;\n"),
        ],
    );
    let every: Vec<&str> = TokioFeature::ALL.iter().map(|f| f.as_str()).collect();
    let refused = tokio_fixture_violations(
        &root,
        "pub mod a;\npub mod b;\npub mod c;\npub mod d;\npub mod e;\n",
        &[],
        Some(&every),
    );
    let _ = std::fs::remove_dir_all(&root);
    let hiding = |path: &str| {
        refused
            .iter()
            .any(|v| v.contains(&format!("`{path}` hides which of its items are used")))
    };
    assert!(hiding("tokio::io"), "a bare `io` import: {refused:?}");
    assert!(hiding("tokio::time::*"), "a `time` glob: {refused:?}");
    let whole = refused
        .iter()
        .filter(|v| v.contains("`tokio` names the tokio crate whole"))
        .count();
    assert_eq!(
        whole, 3,
        "renamed, `extern crate` and bare crate imports: {refused:?}"
    );
    let io_imports = refused
        .iter()
        .filter(|v| v.contains("`tokio::io` hides"))
        .count();
    assert_eq!(
        io_imports, 2,
        "`io` bare and through `self as`: {refused:?}"
    );
}

/// Grouped and renamed imports, macro paths, a leading-colon path inside macro
/// tokens and an attribute path are each read as `tokio::` paths.
#[test]
fn grouped_renamed_macro_and_attribute_tokio_paths_are_read() {
    let root = closure_fixture(
        "tokio_forms",
        &[(
            "a.rs",
            "use tokio::{net::TcpListener, sync as s};\n\
             pub fn f() { tokio::select! { _ = async {} => {} } }\n\
             pub fn g() { let _ = vec![::tokio::time::Instant::now()]; }\n\
             #[tokio::main]\npub async fn h() {}\n",
        )],
    );
    let bare = tokio_fixture_violations(&root, "pub mod a;\n", &[], Some(&[]));
    let full = tokio_fixture_violations(
        &root,
        "pub mod a;\n",
        &[],
        Some(&["rt", "rt-multi-thread", "macros", "time", "sync", "net"]),
    );
    let _ = std::fs::remove_dir_all(&root);
    for path in [
        "`tokio::net::TcpListener`",
        "`tokio::sync`",
        "`tokio::select`",
        "`tokio::time::Instant::now`",
        "`tokio::main`",
    ] {
        assert!(
            bare.iter().any(|v| v.contains(path)),
            "{path} must be read: {bare:?}"
        );
    }
    assert!(full.is_empty(), "every feature declared: {full:?}");
}
