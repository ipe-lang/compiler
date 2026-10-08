//! Fast static SEAL lint for the emitted runtime-module set.
//!
//! The backend trims `ipe_runtime/mod.rs` to a base module set and appends
//! feature-modules per `uses_*` flag. Each appended module carries a
//! `use crate::<dep>` closure that MUST itself be declared in the same emitted
//! `mod.rs` — otherwise `ipe` exits 0 and the emitted crate fails `cargo build`
//! (E0432/E0425/E0412), the module-set SEAL breach class.
//!
//! This test proves that closure WITHOUT invoking cargo: for every reachable
//! combination of the `Module` `uses_*` flags it emits the `ipe_runtime/mod.rs`
//! via the real backend, then checks that every top-level module the emitted
//! `mod.rs` declares has all of its UNCONDITIONAL `use crate::<dep>::`
//! references also declared. It is the fast counterpart to the ground-truth
//! `ipe`-crate `seal_modset` E2E gate (which does the actual `cargo build`).
//!
//! "Unconditional" means: any `crate::<dep>::` or matching-length `super::`-chain
//! reference in the production body — `use` imports, inline path expressions, and
//! macro invocations (`crate::ct_eq::impl_ct_eq!(…)`) alike. Lines immediately
//! preceded by a `#[cfg(...)]` attribute, or living inside a `#[cfg(test)]`
//! module, are excluded (their target is pulled in by the same cfg, not the base
//! append — matches the runtime's db-gated telemetry refs, which are correctly
//! NOT a SEAL requirement).
//!
//! ## Why not an exhaustive `2^FLAG_COUNT` sweep
//!
//! Brute-forcing every flag mask is `O(2^FLAG_COUNT)` — infeasible as the
//! runtime feature count grows. This SEAL proves the SAME closure in linear
//! time by per-flag closure + monotonicity + composition (the featureset SEAL
//! carries the full argument). The declared-module set is monotone in the mask
//! — the emitter only APPENDS feature modules — so a superset of flags declares
//! a superset of modules. Each module's unconditional `use crate::<dep>` closure
//! is source-only (mask-independent). Therefore: if every singleton flag's
//! declared set is closed under its deps, and the declared set is monotone, then
//! every union is closed (the composed all-flags declaration is exactly the
//! union of the per-flag declarations, and each dep-target it needs is present
//! in the flag that introduced its module). A bounded, deterministic sampled
//! sweep is retained as a backstop.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use ipe_backend::Backend;
use ipe_backend_rust::RustBackend;
use ipe_intern::Interner;
use ipe_ir::{ModPath, Module, Program, Target};

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

/// For one runtime module `name`, read its source (`<name>.rs` or
/// `<name>/mod.rs`) and return the set of top-level modules it references via an
/// UNCONDITIONAL `use crate::<dep>` (dep = first path segment after `crate::`).
/// cfg-/test-gated `use`s are excluded (their target is pulled in by the same
/// cfg, not the base append), and so is every file of a child module whose
/// `mod` declaration is cfg-gated.
fn unconditional_crate_deps(runtime_root: &Path, name: &str) -> BTreeSet<String> {
    let mut deps = BTreeSet::new();
    let flat = runtime_root.join(format!("{name}.rs"));
    let dir = runtime_root.join(name);
    if flat.is_file() {
        // `<name>.rs` is a top-level module — its module path is `crate::<name>`,
        // so `super` reaches the crate root (1 hop).
        scan_file_deps(&flat, 1, &mut deps);
    }
    if dir.is_dir() {
        // Files under `<name>/`: `<name>/mod.rs` is `crate::<name>` (1 super to
        // root); `<name>/foo.rs` is `crate::<name>::foo` (2); each nested dir +1.
        collect_dir_deps(&dir, &flat, 1, &mut deps);
    }
    deps
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

/// Recurse a module's directory, scanning each `.rs` file for crate-root deps.
/// `mod_depth` is the module-path depth of `<dir>/mod.rs` (= supers to root);
/// `outer_file` is the `<dir>.rs` that declares the children when there is no
/// `<dir>/mod.rs`. A child whose `mod` declaration is cfg-gated is skipped
/// whole, file and directory alike.
fn collect_dir_deps(dir: &Path, outer_file: &Path, mod_depth: usize, deps: &mut BTreeSet<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let gated = dir_child_declarations(dir, outer_file);
    for entry in entries.flatten() {
        let path = entry.path();
        let stem = path
            .file_stem()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        if gated.contains(&stem) {
            continue;
        }
        if path.is_dir() {
            let child_outer = dir.join(format!("{stem}.rs"));
            collect_dir_deps(&path, &child_outer, mod_depth + 1, deps);
        } else if path.extension().is_some_and(|e| e == "rs") {
            // `mod.rs` sits at `mod_depth`; any other `<file>.rs` is one module
            // level deeper (`crate::…::<dir>::<file>`).
            let is_mod_rs = path.file_name().is_some_and(|n| n == "mod.rs");
            let supers = if is_mod_rs { mod_depth } else { mod_depth + 1 };
            scan_file_deps(&path, supers, deps);
        }
    }
}

/// Extract every UNCONDITIONAL crate-root module dep from one file whose module
/// reaches the crate root in `supers_to_root` `super::` hops. Both
/// `use crate::<dep>` / `crate::<dep>::path()` and a matching-length
/// `super`-chain name a top-level module. cfg-/test-gated lines are excluded.
fn scan_file_deps(path: &Path, supers_to_root: usize, deps: &mut BTreeSet<String>) {
    let src = std::fs::read_to_string(path).unwrap_or_default();

    // Three skip-regions, checked in priority order:
    // 1. `in_cfg_test_mod` — `#[cfg(test)] mod tests { … }`: skip entire block.
    // 2. `cfg_gated_depth` — inside a `#[cfg(…)]`-gated brace block: skip until
    //    depth returns to 0.
    // 3. `cfg_item_pending` — a `#[cfg(…)]` was seen; skip the annotated item
    //    (including its stacked attributes, doc-comments, and multi-line signature)
    //    until we have consumed at least one opening brace and the depth closes.
    let mut in_cfg_test_mod = false;
    let mut cfg_test_brace_depth: i32 = 0;
    // `cfg_test_opened`: true once the `#[cfg(test)]` block's first `{` has been
    // seen. Until then, stacked attributes (`#[cfg(any(feature = …))]`) and
    // doc-comments before the `mod tests {` header keep the depth at 0 — the
    // block must NOT be considered closed during that pre-brace window.
    let mut cfg_test_opened = false;
    let mut cfg_gated_depth: i32 = 0;
    // `cfg_item_pending`: true after a `#[cfg(…)]` attr and until the cfg-gated
    // item's block closes (or a `;`-terminated single-line item is consumed).
    let mut cfg_item_pending = false;
    // `cfg_item_opened`: true once the first `{` of the cfg-gated item has been
    // seen; until then, more lines (signature / where-clause) are still gated.
    let mut cfg_item_opened = false;
    for line in src.lines() {
        let t = line.trim();

        // ── region 1: inside a `#[cfg(test)]` block ──────────────────────────
        if in_cfg_test_mod {
            cfg_test_brace_depth += unquoted_brace_delta(t);
            if cfg_test_brace_depth > 0 {
                // The `mod tests {` header (possibly after stacked attributes)
                // has been reached; the block is now genuinely open.
                cfg_test_opened = true;
            }
            // Only leave the test region once the block has actually opened AND
            // its braces have balanced back to 0 — never during the pre-brace
            // window where stacked attributes leave the depth at 0.
            if cfg_test_opened && cfg_test_brace_depth <= 0 {
                in_cfg_test_mod = false;
            }
            cfg_item_pending = false;
            cfg_item_opened = false;
            continue;
        }
        // `#[cfg(test)]` opens the test region on the NEXT non-attr line.
        if t.starts_with("#[cfg(test)]") {
            in_cfg_test_mod = true;
            cfg_test_brace_depth = 0;
            cfg_test_opened = false;
            cfg_item_pending = false;
            cfg_item_opened = false;
            continue;
        }

        // ── region 2: inside a `#[cfg(…)]`-gated brace block ────────────────
        if cfg_gated_depth > 0 {
            cfg_gated_depth += unquoted_brace_delta(t);
            if cfg_gated_depth <= 0 {
                cfg_gated_depth = 0;
                cfg_item_pending = false;
                cfg_item_opened = false;
            }
            continue;
        }

        // ── region 3: cfg-item pending (pre- or mid-signature) ───────────────
        if cfg_item_pending {
            // Stacked attributes and doc-comments before the actual item header.
            if t.starts_with("#[") || t.starts_with("//") {
                continue; // remain in cfg_item_pending
            }
            let delta = unquoted_brace_delta(t);
            if !cfg_item_opened {
                // Still scanning the item header (could be multi-line `fn`/`impl`
                // signature before the `{`). If this line has a net opening brace,
                // the block has started; otherwise keep skipping signature lines.
                if delta > 0 {
                    cfg_item_opened = true;
                    cfg_gated_depth = delta;
                    if cfg_gated_depth <= 0 {
                        // e.g. a one-liner `fn foo() {}` — item done.
                        cfg_item_pending = false;
                        cfg_item_opened = false;
                    }
                }
                // else: no brace yet (still in `fn` / `where` / type params line)
            }
            // single-line item with semicolon and no braces: `use …;` / `type …;`
            if delta == 0 && t.ends_with(';') {
                cfg_item_pending = false;
                cfg_item_opened = false;
            }
            continue;
        }

        // ── normal scanning ───────────────────────────────────────────────────

        // Skip comment lines — `//` and `///` doc-comments may name `crate::X`
        // in backtick links or prose; they carry no compile-time dependency.
        if t.starts_with("//") {
            continue;
        }

        let is_cfg_attr = t.starts_with("#[cfg(") || t.starts_with("#[cfg_attr(");
        if is_cfg_attr {
            cfg_item_pending = true;
            cfg_item_opened = false;
            continue;
        }

        crate_refs_in_line(t, supers_to_root, deps);
    }
}

/// Count the net unquoted brace depth change for one source line: `{` outside a
/// string literal or character literal adds +1; `}` subtracts 1. String literals
/// (including raw strings `r#"…"#` and `r"…"`) and char literals are skipped so
/// that format-string braces (`"{value:?}"`) or pattern-match bodies with literal
/// `'}'` do not skew the depth.
///
/// This is deliberately conservative and single-line: multi-line string literals
/// are vanishingly rare in the runtime source, and any mismatch on a single line
/// still averages out across the file because both `{` and `}` in strings are
/// equally likely to appear.  The one case that matters — format strings like
/// `"expected {val:?}"` — perfectly balance (one `{`, one `}`) and net to 0.
fn unquoted_brace_delta(line: &str) -> i32 {
    let mut delta: i32 = 0;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            // Regular string literal: skip to closing `"` (handle `\"` escapes).
            '"' => {
                while let Some(sc) = chars.next() {
                    if sc == '\\' {
                        chars.next(); // consume escaped character
                    } else if sc == '"' {
                        break;
                    }
                }
            }
            // Char literal: skip to closing `'` (handle `\'` escapes).
            '\'' => {
                // Disambiguate lifetime from char: lifetimes are `'name` with an
                // identifier character following. We do a simple lookahead:
                // if the character after `'` is alphanumeric or `_`, treat as
                // lifetime and don't try to consume a closing `'`.
                if let Some(&nc) = chars.peek() {
                    if nc.is_ascii_alphanumeric() || nc == '_' {
                        // lifetime annotation — skip
                    } else {
                        // char literal
                        while let Some(sc) = chars.next() {
                            if sc == '\\' {
                                chars.next();
                            } else if sc == '\'' {
                                break;
                            }
                        }
                    }
                }
            }
            // Line comment: stop counting — everything after `//` is comment.
            '/' if chars.peek() == Some(&'/') => break,
            '{' => delta += 1,
            '}' => delta -= 1,
            _ => {}
        }
    }
    delta
}

/// Scan one source line for ALL occurrences of crate-root module references —
/// `use crate::<seg>::`, inline path expressions `crate::<seg>::fn()`, and macro
/// invocations `crate::<seg>::mac!(…)`, plus the equivalent `super::`-chain forms
/// — and insert every resolved first segment into `deps`.
///
/// A module DEPENDENCY reaches INTO a module (`crate::tea::{…}`,
/// `crate::app_config::resolve()`, `crate::ct_eq::impl_ct_eq!(...)`); a bare
/// `crate::Foo` with no trailing `::` imports an item re-exported at the crate
/// root via the `mod.rs` glob and needs no separate `pub mod` declaration.
///
/// The `super::`-chain form is recognised only for an EXACT chain of
/// `supers_to_root` hops, which resolves to the crate root from this file's
/// module depth; shorter or longer chains refer to intermediate modules, not the
/// crate root, and are ignored.
fn crate_refs_in_line(line: &str, supers_to_root: usize, deps: &mut BTreeSet<String>) {
    // Build the exact `super::` prefix we accept (e.g. `super::super::` for depth 2).
    let super_prefix: String = "super::".repeat(supers_to_root);

    let mut rest = line;
    while !rest.is_empty() {
        // Try to match `crate::` at the current position.
        if let Some(after_crate) = rest.strip_prefix("crate::") {
            if let Some(seg) = extract_seg_with_trailing_colons(after_crate) {
                deps.insert(seg);
            }
            // Advance past `crate::` to continue scanning the remainder.
            rest = after_crate;
            continue;
        }
        // Try to match the exact `super::…` chain reaching the crate root.
        if !super_prefix.is_empty()
            && let Some(after_supers) = rest.strip_prefix(super_prefix.as_str())
        {
            // Must not start with another `super::` — that would be a deeper chain
            // pointing above the crate root (impossible in Rust, but guard it).
            if !after_supers.starts_with("super::")
                && let Some(seg) = extract_seg_with_trailing_colons(after_supers)
            {
                deps.insert(seg);
            }
            rest = after_supers;
            continue;
        }
        // Advance by one character and keep scanning.
        let mut chars = rest.chars();
        chars.next();
        rest = chars.as_str();
    }
}

/// Extract the first identifier segment from `s` and return it if it is
/// immediately followed by `::` (i.e. the path reaches INTO that module).
/// Returns `None` for a bare item name (`IpeMaybe`) with no `::` suffix.
fn extract_seg_with_trailing_colons(s: &str) -> Option<String> {
    let seg: String = s
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if seg.is_empty() {
        return None;
    }
    match s.get(seg.len()..) {
        Some(tail) if tail.starts_with("::") => Some(seg),
        _ => None,
    }
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

/// The per-mask closure obligation: the declared module set is CLOSED under
/// every declared module's unconditional `use crate::<dep>` references. Shared
/// by the per-flag, composed, and sampled proofs so they run an identical check.
/// `dep_cache` memoises the source-only, mask-independent per-module dep scan.
fn assert_mask_closed(
    runtime_root: &Path,
    interner: &Interner,
    main: ipe_intern::Symbol,
    mask: u32,
    dep_cache: &mut HashMap<String, BTreeSet<String>>,
) {
    let declared = declared_for_mask(interner, main, mask);
    for m in &declared {
        let deps = dep_cache
            .entry(m.clone())
            .or_insert_with(|| unconditional_crate_deps(runtime_root, m));
        for dep in deps.iter() {
            assert!(
                declared.contains(dep),
                "module-set SEAL breach: emitted `mod.rs` declares `{m}` \
                 (which does `use crate::{dep}`) but does NOT declare `{dep}` \
                 — flag mask {mask:#019b}. The emitted crate would fail `cargo build`. \
                 Declared modules: {declared:?}"
            );
        }
    }
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
    let mut dep_cache: HashMap<String, BTreeSet<String>> = HashMap::new();
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

    let mut dep_cache: HashMap<String, BTreeSet<String>> = HashMap::new();
    assert_mask_closed(&runtime_root, &interner, main, all, &mut dep_cache);
}

/// A vendored `revocation` module publishes on `tokio::sync::watch` whenever the
/// `tokio` feature is on, so every emitted manifest that declares the module and
/// enables `tokio` must extend the `tokio` dependency with `"sync"`. Checked on
/// the featureless base, every singleton, and the all-on mask.
#[test]
fn declared_revocation_module_implies_tokio_sync() {
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    let all: u32 = (1u32 << FLAG_COUNT) - 1;
    let masks = std::iter::once(0u32)
        .chain((0..FLAG_COUNT).map(|bit| 1u32 << bit))
        .chain(std::iter::once(all));
    let mut revocation_cases = 0usize;
    for mask in masks {
        let prog = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![module_for_mask(main, mask)],
        };
        let emitted = RustBackend::new(&interner)
            .emit(&prog)
            .expect("emit must succeed for a body-free program");
        let mod_rs = emitted.files.get("src/ipe_runtime/mod.rs").expect("mod.rs");
        let cargo = &emitted.cargo_toml;
        let tokio_on = cargo
            .lines()
            .any(|l| l.starts_with("default = [") && l.contains("\"tokio\""));
        if !declared_modules(mod_rs).contains("revocation") || !tokio_on {
            continue;
        }
        revocation_cases += 1;
        let tokio_dep = cargo
            .lines()
            .find(|l| l.starts_with("tokio = {"))
            .expect("a manifest with the tokio feature on must declare the tokio dependency");
        assert!(
            tokio_dep.contains("\"sync\""),
            "SEAL breach: `revocation` is declared with the tokio feature on, but the \
             tokio dependency lacks `sync` (`tokio::sync::watch` would not compile) \
             - flag mask {mask:#019b}: {tokio_dep}"
        );
    }
    assert!(
        revocation_cases > 0,
        "no sampled mask declared `revocation` on a tokio runtime - the check proved nothing"
    );
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
    let mut dep_cache: HashMap<String, BTreeSet<String>> = HashMap::new();

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
/// must NOT unconditionally `use crate::<gated_module>`. A base→gated
/// unconditional edge would force the gated module always-on (re-coupling the
/// two), defeating the point of gating and pulling the gated module's crates
/// into every program. The base floor must be closed under its OWN unconditional
/// deps: every such dep is itself a base module.
///
/// This is the STRUCTURAL guard that keeps a future module on the correct side
/// of the base/gated boundary — a PR that adds a base→gated edge (e.g. an
/// base-floor module reaching into a gated `crypto`/`jwt`/`compression`
/// surface) fails HERE, statically, instead of silently re-coupling the deps or
/// breaking the emitted `cargo build` only under a specific feature combo.
///
/// The base floor is derived, not hardcoded: it is exactly the module set the
/// backend emits for the featureless program, so it tracks the template
/// automatically.
#[test]
fn base_modules_do_not_reach_gated_modules() {
    let runtime_root = e2e_support::require_runtime().into_path_buf();

    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");

    // The always-compiled BASE floor: the module set emitted with every `uses_*`
    // flag off.
    let base_prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![module_for_mask(main, 0)],
    };
    let emitted = RustBackend::new(&interner)
        .emit(&base_prog)
        .expect("emit must succeed for the featureless base program");
    let base_mod_rs = emitted
        .files
        .get("src/ipe_runtime/mod.rs")
        .expect("emitted project must contain ipe_runtime/mod.rs");
    let base = declared_modules(base_mod_rs);

    for m in &base {
        for dep in unconditional_crate_deps(&runtime_root, m) {
            assert!(
                base.contains(&dep),
                "always-on-core rule violation: base module `{m}` does \
                 `use crate::{dep}` unconditionally, but `{dep}` is NOT in the \
                 always-compiled base floor — it is a gated feature module. A \
                 base module must reach only other base modules (outside \
                 `#[cfg(...)]` / `#[cfg(test)]`); move the reach behind a cfg, or \
                 promote `{dep}` to the base floor. Base floor: {base:?}"
            );
        }
    }
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

/// The unconditional crate-root deps of a top-level module in the WASM
/// vendored module set. Differs from [`unconditional_crate_deps`] in how it
/// handles inline module declarations such as `pub mod web { pub mod route; }`:
/// an inline block compiles ONLY its explicitly-declared children (here just
/// `web/route.rs`), not the whole `web/` directory (which includes
/// `web/mod.rs` with server-only deps). For a regular `pub mod foo;` module
/// the two functions are equivalent.
///
/// `inline_children`: a pre-parsed map from module name → its explicitly-listed
/// children (populated from `pub mod X { pub mod Y; … }` blocks in
/// `WASM_RUNTIME_MOD_RS`).
fn wasm_unconditional_crate_deps(
    runtime_root: &Path,
    name: &str,
    inline_children: &HashMap<String, Vec<String>>,
) -> BTreeSet<String> {
    let mut deps = BTreeSet::new();
    if let Some(children) = inline_children.get(name) {
        // Inline block: only the declared child files are compiled.
        for child in children {
            let child_file = runtime_root.join(name).join(format!("{child}.rs"));
            if child_file.is_file() {
                // Child is 1 level inside `crate::<name>`, so 2 supers to root.
                scan_file_deps(&child_file, 2, &mut deps);
            }
        }
    } else {
        // Regular `pub mod name;`: use the shared scanner.
        let flat = runtime_root.join(format!("{name}.rs"));
        let dir = runtime_root.join(name);
        if flat.is_file() {
            scan_file_deps(&flat, 1, &mut deps);
        }
        if dir.is_dir() {
            collect_dir_deps(&dir, &flat, 1, &mut deps);
        }
    }
    deps
}

/// Parse the inline-block children from a `WASM_RUNTIME_MOD_RS`-style string.
/// Returns a map from top-level inline module name → list of declared children.
/// Example: `pub mod web { pub mod route; }` → `{"web": ["route"]}`.
fn parse_inline_modules(mod_rs: &str) -> HashMap<String, Vec<String>> {
    let mut result: HashMap<String, Vec<String>> = HashMap::new();
    let mut in_block: Option<String> = None;
    let mut brace_depth: i32 = 0;
    for line in mod_rs.lines() {
        let t = line.trim();
        if let Some(ref parent) = in_block.clone() {
            let opens = i32::try_from(t.matches('{').count()).unwrap_or(0);
            let closes = i32::try_from(t.matches('}').count()).unwrap_or(0);
            brace_depth += opens - closes;
            if brace_depth <= 0 {
                in_block = None;
                brace_depth = 0;
            } else {
                // Parse `pub mod child;` inside the block.
                let rest = t
                    .strip_prefix("pub mod ")
                    .or_else(|| t.strip_prefix("mod "));
                if let Some(rest) = rest
                    && let Some(child) = rest.strip_suffix(';')
                    && child.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    result
                        .entry(parent.clone())
                        .or_default()
                        .push(child.to_owned());
                }
            }
            continue;
        }
        // Check for an inline-block opener: `pub mod name {`.
        let rest = t
            .strip_prefix("pub mod ")
            .or_else(|| t.strip_prefix("mod "));
        if let Some(rest) = rest {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                let after = rest.get(name.len()..).unwrap_or("").trim_start();
                if after.starts_with('{') {
                    in_block = Some(name.clone());
                    brace_depth = 1;
                    result.entry(name).or_default();
                }
            }
        }
    }
    result
}

/// The wasm vendored `WASM_RUNTIME_MOD_RS` module set is closed under the
/// unconditional `use crate::<dep>` references of every module it declares.
///
/// The vendored path emits `src/ipe_runtime/mod.rs` from a STATIC constant
/// (`WASM_RUNTIME_MOD_RS`) rather than a per-flag append list, so a module that
/// calls `crate::<dep>::…` without a `#[cfg(...)]` guard can only compile if
/// `<dep>` is also declared in that constant. This test proves closure WITHOUT
/// invoking cargo — the same obligation the per-flag native tests above prove for
/// the native module set, applied to the wasm vendored constant.
///
/// The breach class is: a module `M` in `WASM_RUNTIME_MOD_RS` calls
/// `crate::<dep>::fn()` unconditionally, but `<dep>` is absent from the
/// constant. `ipe` exits 0; the emitted wasm crate fails `cargo check` (E0433).
/// A regression in the native modset closure tests would not catch this because
/// those tests emit via `RustBackend::new(interner)` (the NATIVE path, which
/// uses the native template + per-flag appends — not `WASM_RUNTIME_MOD_RS`).
///
/// Inline modules (e.g. `pub mod web { pub mod route; }`) are handled correctly:
/// only the explicitly-listed child files are scanned, not the whole directory.
#[test]
fn wasm_vendored_modset_is_closed() {
    let runtime_root = e2e_support::require_runtime().into_path_buf();
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");

    // Emit the wasm VENDORED mod.rs (no `with_runtime_dep`) — this path writes
    // `WASM_RUNTIME_MOD_RS` into `src/ipe_runtime/mod.rs`.
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![module_for_mask(main, 0)],
    };
    let emitted = RustBackend::new(&interner)
        .with_target(Target::WasmClient)
        .emit(&prog)
        .expect("wasm vendored emit must succeed for a body-free program");
    let mod_rs = emitted
        .files
        .get("src/ipe_runtime/mod.rs")
        .expect("wasm vendored emit must include src/ipe_runtime/mod.rs");
    let declared = declared_modules(mod_rs);
    let inline_children = parse_inline_modules(mod_rs);

    let mut dep_cache: HashMap<String, BTreeSet<String>> = HashMap::new();
    for m in &declared {
        let deps = dep_cache
            .entry(m.clone())
            .or_insert_with(|| wasm_unconditional_crate_deps(&runtime_root, m, &inline_children));
        for dep in deps.iter() {
            assert!(
                declared.contains(dep),
                "wasm vendored module-set SEAL breach: `WASM_RUNTIME_MOD_RS` declares \
                 `{m}` (which does `use crate::{dep}` unconditionally) but does NOT \
                 declare `{dep}`. The emitted wasm crate fails `cargo check \
                 --target wasm32-unknown-unknown` (E0433) though `ipe` exits 0. \
                 Add `pub mod {dep};` to `WASM_RUNTIME_MOD_RS` in \
                 `src/compiler/backend/rust/src/project.rs`. \
                 Declared wasm modules: {declared:?}"
            );
        }
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

// ── scanner unit tests: inline-path and cfg(test) regression ─────────────────

/// The `crate_refs_in_line` scanner must detect `crate::<seg>::` occurrences
/// that are NOT `use` statements — path expressions and macro calls. This is the
/// exact false-negative class that let the `wasm app_config` and `revocation`
/// E0433 SEAL breaches reach main undetected.
#[test]
fn scanner_detects_inline_crate_path_expressions() {
    let mut deps = BTreeSet::new();
    // Inline function call — matches `crate::app_config::resolve_log_level_override()`.
    crate_refs_in_line(
        "    if let Some(tag) = crate::app_config::resolve_log_level_override() {",
        1,
        &mut deps,
    );
    assert!(
        deps.contains("app_config"),
        "scanner must detect `crate::app_config::` in an inline path expression; got {deps:?}"
    );

    let mut deps2 = BTreeSet::new();
    // Macro invocation — matches `crate::ct_eq::impl_ct_eq!(Key)`.
    crate_refs_in_line("crate::ct_eq::impl_ct_eq!(Key);", 1, &mut deps2);
    assert!(
        deps2.contains("ct_eq"),
        "scanner must detect `crate::ct_eq::` in a macro invocation; got {deps2:?}"
    );

    let mut deps3 = BTreeSet::new();
    // Multiple refs on one line — `crate::jwt::…` appears twice.
    crate_refs_in_line(
        "    if secret.len() < crate::jwt::HS256_MIN_SECRET_BYTES { crate::jwt::hs256_short_secret_msg() }",
        1,
        &mut deps3,
    );
    assert!(
        deps3.contains("jwt"),
        "scanner must detect repeated `crate::jwt::` refs on one line; got {deps3:?}"
    );
}

/// A `crate::Foo` reference with NO trailing `::` is a re-exported item, not a
/// module dependency — the scanner must NOT register it as a dep.
#[test]
fn scanner_ignores_bare_crate_item_without_module_path() {
    let mut deps = BTreeSet::new();
    // `crate::IpeMaybe` — a re-export from the crate root, no `::` suffix.
    crate_refs_in_line("use crate::IpeMaybe;", 1, &mut deps);
    assert!(
        deps.is_empty(),
        "bare `crate::Item` (no trailing `::`) must NOT register as a module dep; got {deps:?}"
    );
}

/// References inside a `#[cfg(test)] mod tests` block must NOT register as
/// production deps. This is the false-positive class (`ui → helpers`) the
/// cfg(test)-exclusion logic prevents.
#[test]
fn scanner_excludes_crate_refs_inside_cfg_test_mod() {
    use std::path::PathBuf;
    // Synthesise a file that has an inline `crate::nonexistent_module::fn()` ONLY
    // inside a `#[cfg(test)] mod tests` block — not in production code.
    let src = r"
// production function — no crate:: dep
pub fn prod() -> i32 { 42 }

#[cfg(test)]
mod tests {
    use super::*;
    // This would be a false breach if not excluded:
    use crate::nonexistent_module::helper;
    fn check() { crate::nonexistent_module::run(); }
}
";
    // Write to a temp file and scan it.
    let dir = ipe_test_temp::temp_root();
    let path: PathBuf = dir.join("ipe_modset_closure_cfg_test_regression.rs");
    std::fs::write(&path, src).expect("write temp file");
    let mut deps = BTreeSet::new();
    scan_file_deps(&path, 1, &mut deps);
    let _ = std::fs::remove_file(&path);
    assert!(
        !deps.contains("nonexistent_module"),
        "scanner must NOT register `crate::nonexistent_module` from inside \
         `#[cfg(test)] mod tests`; got {deps:?}"
    );
    assert!(
        deps.is_empty(),
        "no production crate-root deps in this fixture; got {deps:?}"
    );
}

/// A child module whose `mod` declaration is cfg-gated is gated whole: its
/// file's `crate::` references are not unconditional deps of the parent, even
/// on lines carrying no cfg of their own. An ungated sibling's still are.
#[test]
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
    let deps = unconditional_crate_deps(&root, "web");
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(
        deps,
        BTreeSet::from(["alpha".to_owned(), "beta".to_owned(), "tea".to_owned()]),
        "only the children whose `mod` declaration is not cfg-gated are dep sources"
    );
}

/// Prove the fix direction: if `app_config` were removed from the wasm constant,
/// the structural `wasm_vendored_modset_is_closed` test would catch it (via
/// `log.rs`'s inline `crate::app_config::` call). This named test asserts the
/// SAME closure edge via the scanner directly, so a regression is identified by
/// name and not just by the structural test's catch-all message.
#[test]
fn scanner_detects_log_rs_dep_on_app_config() {
    let runtime_root = e2e_support::require_runtime().into_path_buf();
    // `log.rs` uses `crate::app_config::resolve_log_level_override()` and
    // `crate::system::read_env_var()` unconditionally — both are inline paths,
    // not `use` statements. The reworked scanner must catch them.
    let deps = unconditional_crate_deps(&runtime_root, "log");
    assert!(
        deps.contains("app_config"),
        "`log.rs` must register `app_config` as an unconditional dep \
         (via `crate::app_config::resolve_log_level_override()`); got {deps:?}"
    );
    assert!(
        deps.contains("system"),
        "`log.rs` must register `system` as an unconditional dep \
         (via `crate::system::read_env_var()`); got {deps:?}"
    );
}
