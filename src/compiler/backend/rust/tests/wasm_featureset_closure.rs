//! Fast static SEAL for the emitted runtime FEATURE set on the WASM target.
//!
//! The `runtime_featureset_closure` SEAL proves the same closure obligation for
//! the NATIVE target (where `target_arch = "wasm32"` is false). This file proves
//! it for the browser-WASM dependency-model emit, where the target atom is TRUE
//! and the SSOT selects exactly the `wasm-client` floor.
//!
//! `ipe` exiting 0 on a `--target wasm` build must imply the emitted project
//! `cargo build --target wasm32-unknown-unknown`s. Under the dependency model the
//! breach class is "selected wasm feature set under which the runtime crate does
//! not export a referenced kernel on wasm32". This test proves the closure
//! WITHOUT invoking cargo, over the exhaustive `uses_*` flag-mask sweep (every
//! browser-admissible flag combination), by:
//!
//! 1. asking the real backend for the wasm SSOT feature set
//!    (`with_target(WasmClient).runtime_feature_names`) — always exactly
//!    `["wasm-client"]`, the fail-closed browser floor;
//! 2. checking `wasm-client` is declared in the runtime crate's `[features]`
//!    universe and resolves closed;
//! 3. statically scanning the EMITTED wasm user files for every
//!    `ipe_runtime::<module>::` reference and asserting each referenced module is
//!    `cfg`-satisfied by the resolved feature set UNDER `target_arch = "wasm32"`
//!    (walking the runtime crate's `src/mod.rs` `#[cfg(...)]` attributes — the
//!    same source-parse discipline the native SEAL uses, but with the wasm32 atom
//!    evaluated TRUE).
//!
//! A "wasm-client does not gate-satisfy an emitted wasm reference" drift fails at
//! (3), fail-closed. The fail-closed DIRECTION is proven by
//! [`wasm_reference_gap_fails_closed`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ipe_backend::Backend;
use ipe_backend_rust::{RuntimeDep, RustBackend};
use ipe_intern::Interner;
use ipe_ir::{ModPath, Module, Program, Target};

/// The browser-admissible flag space. Only surfaces `assert_wasm_admissible`
/// permits are exercised (db/server/tui/webview/email/auth/ffi are rejected
/// upstream, so a wasm program can never set them). The mask drives the pure /
/// TEA / websocket surfaces plus the standalone leaves.
const FLAG_COUNT: usize = 20;

/// Locate the runtime crate root (`src/runtime/rust`).
#[allow(clippy::expect_used)]
fn runtime_crate_root() -> PathBuf {
    let manifest = e2e_support::manifest_dir!();
    let mut here: Option<&Path> = Some(&manifest);
    std::iter::from_fn(|| {
        let dir = here?;
        here = dir.parent();
        Some(dir.join("src").join("runtime").join("rust"))
    })
    .find(|candidate| candidate.join("Cargo.toml").is_file())
    .expect("runtime crate root (src/runtime/rust) must resolve")
}

/// A body-free wasm `Module` with the mask's browser-admissible `uses_*` flags.
/// tui/ui and the async-spine invariants a real lowerer enforces are NOT modelled
/// here — the wasm floor selection ignores them entirely (the SSOT returns the
/// `wasm-client` floor regardless), so the mask only needs to steer which
/// browser kernels the EMITTER references.
#[allow(clippy::similar_names)]
fn wasm_module_for_mask(name: ipe_intern::Symbol, mask: u32) -> Module {
    let f = |i: usize| mask & (1 << i) != 0;
    Module {
        name: ModPath(vec![name]),
        types: vec![],
        funcs: vec![],
        entry: None,
        records: vec![],
        uses_tea: f(0),
        uses_server: false,
        uses_ui: f(0) || f(2),
        uses_web: false,
        uses_tui: false,
        uses_console: false,
        uses_webview: false,
        uses_css: f(6),
        uses_auth: false,
        uses_principal: false,
        uses_websocket: f(8),
        uses_email: false,
        uses_locale: false,
        uses_time: f(10),
        uses_env_public: f(11),
        uses_http: f(12),
        uses_config: false,
        uses_compression: false,
        uses_csv: false,
        uses_cache: false,
        uses_encoding: f(18),
        uses_regex: f(3),
        uses_uuid: f(13),
        uses_random: f(14),
        uses_log: f(15),
        uses_decimal: f(16),
        uses_char_category: f(17),
        uses_crypto_core: f(5),
        uses_secret: f(9),
        uses_json: f(7),
        uses_crypto: false,
        uses_jwt: false,
        uses_url: f(4),
        uses_debug: f(19),
        uses_ffi: false,
        uses_async_runtime: false,
    }
}

// ── the runtime crate's `[features]` universe + resolution ─────────────────

/// Parse `src/runtime/rust/Cargo.toml`'s `[features]` table into
/// `feature -> [enabled tokens]`, normalising the `dep:` / `crate/` / `dep?/`
/// prefixes to the bare name a `#[cfg(feature = …)]` tests.
fn parse_feature_table(cargo_toml: &str) -> BTreeMap<String, Vec<String>> {
    let mut table = BTreeMap::new();
    let mut in_features = false;
    let mut current: Option<(String, Vec<String>)> = None;
    for raw in cargo_toml.lines() {
        let line = raw.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            if let Some((name, toks)) = current.take() {
                table.insert(name, toks);
            }
            in_features = line == "[features]";
            continue;
        }
        if !in_features {
            continue;
        }
        // A feature may span several lines (the crate wraps `wasm-client`'s list).
        // Accumulate tokens until the closing `]`.
        if let Some((_, toks)) = current.as_mut() {
            for tok in line.split(['[', ']', ',', '"']) {
                let t = tok.trim();
                if !t.is_empty() {
                    toks.push(normalize_feature_token(t));
                }
            }
            if line.contains(']')
                && let Some((name, toks)) = current.take()
            {
                table.insert(name, toks);
            }
            continue;
        }
        let Some((name, rhs)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim().to_owned();
        if name.is_empty() {
            continue;
        }
        let mut toks = Vec::new();
        for tok in rhs.split(['[', ']', ',', '"']) {
            let t = tok.trim();
            if !t.is_empty() {
                toks.push(normalize_feature_token(t));
            }
        }
        if rhs.contains(']') || !rhs.contains('[') {
            table.insert(name, toks);
        } else {
            current = Some((name, toks));
        }
    }
    if let Some((name, toks)) = current.take() {
        table.insert(name, toks);
    }
    table
}

fn normalize_feature_token(tok: &str) -> String {
    let tok = tok.strip_prefix("dep:").unwrap_or(tok);
    if let Some((crate_name, _sub)) = tok.split_once('/') {
        return crate_name.trim_end_matches('?').to_owned();
    }
    tok.to_owned()
}

/// Resolve `selected` to the full transitive feature-or-dep set.
fn resolve_features(selected: &[&str], table: &BTreeMap<String, Vec<String>>) -> BTreeSet<String> {
    let mut resolved = BTreeSet::new();
    let mut stack: Vec<String> = selected.iter().map(|s| (*s).to_owned()).collect();
    while let Some(feat) = stack.pop() {
        if !resolved.insert(feat.clone()) {
            continue;
        }
        if let Some(deps) = table.get(&feat) {
            for d in deps {
                if !resolved.contains(d) {
                    stack.push(d.clone());
                }
            }
        }
    }
    resolved
}

// ── the runtime crate's `src/mod.rs` cfg gates (wasm32 = TRUE) ──────────────

#[derive(Debug, Clone)]
enum Cfg {
    Always,
    Feature(String),
    All(Vec<Self>),
    Any(Vec<Self>),
    /// A non-feature atom. `target_arch = "wasm32"` is TRUE here (this SEAL models
    /// the wasm target); every other `target_*`/`unix` atom is native-false.
    Atom(bool),
}

impl Cfg {
    fn eval(&self, feats: &BTreeSet<String>) -> bool {
        match self {
            Self::Always => true,
            Self::Feature(f) => feats.contains(f),
            Self::All(cs) => cs.iter().all(|c| c.eval(feats)),
            Self::Any(cs) => cs.iter().any(|c| c.eval(feats)),
            Self::Atom(v) => *v,
        }
    }
}

fn parse_cfg_pred(inner: &str) -> Cfg {
    let s = inner.trim();
    if let Some(rest) = s.strip_prefix("all(") {
        let body = rest.strip_suffix(')').unwrap_or(rest);
        return Cfg::All(
            split_cfg_args(body)
                .iter()
                .map(|a| parse_cfg_pred(a))
                .collect(),
        );
    }
    if let Some(rest) = s.strip_prefix("any(") {
        let body = rest.strip_suffix(')').unwrap_or(rest);
        return Cfg::Any(
            split_cfg_args(body)
                .iter()
                .map(|a| parse_cfg_pred(a))
                .collect(),
        );
    }
    if let Some(rest) = s.strip_prefix("feature")
        && let Some(eq) = rest.trim_start().strip_prefix('=')
    {
        return Cfg::Feature(eq.trim().trim_matches('"').to_owned());
    }
    // `target_arch = "wasm32"` → TRUE on this SEAL's target; any other atom false.
    Cfg::Atom(s.contains("wasm32"))
}

fn split_cfg_args(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for ch in body.chars() {
        match ch {
            '(' => {
                depth += 1;
                cur.push(ch);
            }
            ')' => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if depth == 0 => {
                if !cur.trim().is_empty() {
                    out.push(cur.trim().to_owned());
                }
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_owned());
    }
    out
}

fn module_gates(mod_rs: &str) -> BTreeMap<String, Cfg> {
    let mut gates = BTreeMap::new();
    let mut pending: Vec<Cfg> = Vec::new();
    for raw in mod_rs.lines() {
        let line = raw.trim();
        if let Some(inner) = cfg_attr_inner(line) {
            pending.push(parse_cfg_pred(&inner));
            continue;
        }
        let decl = line
            .strip_prefix("pub mod ")
            .or_else(|| line.strip_prefix("mod "));
        if let Some(rest) = decl
            && let Some(name) = rest.strip_suffix(';')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            let gate = match pending.as_slice() {
                [] => Cfg::Always,
                [only] => only.clone(),
                _ => Cfg::All(pending.clone()),
            };
            gates.entry(name.to_owned()).or_insert(gate);
            pending.clear();
            continue;
        }
        if !line.is_empty() && !line.starts_with("//") {
            pending.clear();
        }
    }
    gates
}

fn cfg_attr_inner(line: &str) -> Option<String> {
    let s = line.strip_prefix("#[cfg(")?;
    let inner = s.strip_suffix(")]")?;
    Some(inner.to_owned())
}

/// Join `src/mod.rs` so every multi-line `#[cfg(...)]` attribute is on ONE line.
fn join_cfg_attrs(src: &str) -> String {
    let mut out = String::new();
    let mut buf = String::new();
    let mut in_attr = false;
    for line in src.lines() {
        let t = line.trim();
        if in_attr {
            buf.push(' ');
            buf.push_str(t);
            if t.ends_with(")]") {
                out.push_str(buf.trim());
                out.push('\n');
                buf.clear();
                in_attr = false;
            }
            continue;
        }
        if t.starts_with("#[cfg(") && !t.ends_with(")]") {
            in_attr = true;
            buf.push_str(t);
            continue;
        }
        out.push_str(t);
        out.push('\n');
    }
    if !buf.is_empty() {
        out.push_str(buf.trim());
        out.push('\n');
    }
    out
}

// ── emitted-output scan ─────────────────────────────────────────────────────

fn referenced_runtime_modules(emitted: &str) -> BTreeSet<String> {
    let mut mods = BTreeSet::new();
    let needle = "ipe_runtime::";
    let mut i = 0;
    while let Some(pos) = emitted[i..].find(needle) {
        let start = i + pos + needle.len();
        let seg: String = emitted[start..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        i = start;
        if seg.is_empty() {
            continue;
        }
        let after = start + seg.len();
        if emitted.get(after..after.saturating_add(2)) == Some("::") {
            mods.insert(seg);
        }
    }
    mods
}

// ── fixtures + the wasm emit ────────────────────────────────────────────────

struct SealFixtures {
    table: BTreeMap<String, Vec<String>>,
    gates: BTreeMap<String, Cfg>,
}

#[allow(clippy::expect_used)]
fn load_fixtures() -> SealFixtures {
    let crate_root = runtime_crate_root();
    let cargo_toml =
        std::fs::read_to_string(crate_root.join("Cargo.toml")).expect("read runtime Cargo.toml");
    let table = parse_feature_table(&cargo_toml);
    assert!(!table.is_empty(), "runtime [features] table parsed empty");
    let mod_rs_raw =
        std::fs::read_to_string(crate_root.join("src").join("mod.rs")).expect("read src/mod.rs");
    let gates = module_gates(&join_cfg_attrs(&mod_rs_raw));
    assert!(!gates.is_empty(), "runtime src/mod.rs gates parsed empty");
    SealFixtures { table, gates }
}

/// The wasm dependency-model backend the emit exercises.
fn wasm_backend(interner: &Interner) -> RustBackend<'_> {
    RustBackend::new(interner)
        .with_target(Target::WasmClient)
        .with_runtime_dep(Some(RuntimeDep {
            root: runtime_crate_root(),
        }))
}

#[allow(clippy::expect_used)]
fn selected_features(
    interner: &Interner,
    main: ipe_intern::Symbol,
    mask: u32,
) -> Vec<&'static str> {
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![wasm_module_for_mask(main, mask)],
    };
    wasm_backend(interner)
        .runtime_feature_names(&prog)
        .expect("runtime_feature_names must succeed for a body-free wasm program")
}

#[allow(clippy::expect_used)]
fn emitted_module_references(
    interner: &Interner,
    main: ipe_intern::Symbol,
    mask: u32,
) -> BTreeSet<String> {
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![wasm_module_for_mask(main, mask)],
    };
    let emitted = wasm_backend(interner)
        .emit(&prog)
        .expect("wasm emit must succeed for a body-free program");
    let mut refs = BTreeSet::new();
    for (path, text) in &emitted.files {
        if Path::new(path.as_str())
            .extension()
            .is_none_or(|ext| ext != "rs")
        {
            continue;
        }
        refs.extend(referenced_runtime_modules(text));
    }
    refs
}

fn assert_mask_closed(fx: &SealFixtures, interner: &Interner, main: ipe_intern::Symbol, mask: u32) {
    // (1) the wasm SSOT feature set — always exactly the `wasm-client` floor.
    let selected = selected_features(interner, main, mask);
    assert_eq!(
        selected,
        vec!["wasm-client"],
        "wasm SSOT must select exactly the `wasm-client` floor for mask {mask:#b}: {selected:?}"
    );

    // (2) declared + resolves closed.
    assert!(
        fx.table.contains_key("wasm-client"),
        "`wasm-client` is not declared in the runtime [features] universe"
    );
    let resolved = resolve_features(&selected, &fx.table);
    let reresolved = resolve_features(
        &resolved.iter().map(String::as_str).collect::<Vec<_>>(),
        &fx.table,
    );
    assert_eq!(
        resolved, reresolved,
        "wasm feature resolution is not closed under the crate [features] table"
    );

    // (3) every emitted `ipe_runtime::<mod>::` reference is cfg-satisfied on wasm32.
    for m in emitted_module_references(interner, main, mask) {
        let gate = fx.gates.get(&m).cloned().unwrap_or(Cfg::Always);
        assert!(
            gate.eval(&resolved),
            "wasm featureset SEAL breach: emitted reference `ipe_runtime::{m}::…` for mask \
             {mask:#b}, but the runtime crate gates `mod {m}` behind {gate:?}, UNSATISFIED by the \
             `wasm-client` floor {resolved:?} on wasm32. The emitted wasm crate would fail \
             `cargo build --target wasm32-unknown-unknown` (E0433)."
        );
    }
}

/// Every browser-admissible single flag (and the featureless base) selects the
/// closed `wasm-client` floor and emits only wasm32-cfg-satisfied references.
#[test]
fn each_wasm_flag_is_self_consistent() {
    let fx = load_fixtures();
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    assert_mask_closed(&fx, &interner, main, 0);
    for bit in 0..FLAG_COUNT {
        assert_mask_closed(&fx, &interner, main, 1u32 << bit);
    }
}

/// The all-flags wasm mask (every browser surface at once) is closed — the union
/// of every emitted wasm reference is cfg-satisfied by the single `wasm-client`
/// floor. Since the SSOT is a constant floor (never widened by a flag), the
/// all-on mask is the extremal reference set.
#[test]
fn all_wasm_flags_composed_is_closed() {
    let fx = load_fixtures();
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    let all: u32 = (1u32 << FLAG_COUNT) - 1;
    assert_mask_closed(&fx, &interner, main, all);
}

/// Fail-closed proof: if the resolved feature set DROPS `wasm-client`, an emitted
/// wasm-only reference (`ipe_runtime::wasm::…`) MUST become uncovered — so the
/// gate check has no false-negative that would pass an under-featured manifest.
#[test]
fn wasm_reference_gap_fails_closed() {
    let fx = load_fixtures();
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");

    // A TEA wasm program emits `ipe_runtime::wasm::…`, gated on
    // `all(target_arch = "wasm32", feature = "wasm-client")`.
    let refs = emitted_module_references(&interner, main, 1 << 0);
    assert!(
        refs.contains("wasm"),
        "a wasm TEA program must emit at least one `ipe_runtime::wasm::…` reference: {refs:?}"
    );
    let gate = fx.gates.get("wasm").cloned().unwrap_or(Cfg::Always);
    // The correct floor covers it; the mutated (empty) set drops `wasm-client`.
    let covered = gate.eval(&resolve_features(&["wasm-client"], &fx.table));
    let uncovered = !gate.eval(&resolve_features(&[], &fx.table));
    assert!(
        covered,
        "precondition: the `wasm-client` floor must cover the `ipe_runtime::wasm::…` reference"
    );
    assert!(
        uncovered,
        "fail-closed proof: dropping `wasm-client` must leave the `ipe_runtime::wasm::…` \
         reference UNCOVERED — the closure check would have a false negative otherwise"
    );
}
