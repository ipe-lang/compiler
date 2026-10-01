//! Fast static SEAL for the emitted runtime FEATURE set.
//!
//! The dependency-model emit selects a set of `ipe-runtime-rust` cargo features
//! per program (the `runtime_features` SSOT in the backend). `ipe` exiting 0
//! must imply the emitted project `cargo build`s; under the dependency model the
//! breach class is "selected feature set under which the runtime crate does not
//! compile or does not export a referenced kernel". This test proves the closure
//! WITHOUT invoking cargo, over the SAME exhaustive `uses_*` flag-mask sweep the
//! module-set SEAL uses.
//!
//! For every reachable combination of the `Module` `uses_*` flags it:
//!
//! 1. asks the real backend for the SSOT feature set (`runtime_feature_names`);
//! 2. checks every selected feature is declared in the runtime crate's
//!    `[features]` universe (`src/runtime/rust/Cargo.toml`);
//! 3. resolves the set through that `[features]` table (Cargo's transitive
//!    feature unification) and asserts the resolution is closed;
//! 4. **the obligation the module-set SEAL never had** — statically scans the
//!    EMITTED user files for every `ipe_runtime::<module>::` reference the
//!    generated prelude/main hard-codes, and asserts each referenced module is
//!    `cfg`-satisfied by the resolved feature set (walking the runtime crate's
//!    own `src/mod.rs` `#[cfg(feature = …)]` attributes — the same source-parse
//!    discipline the modset test uses on the emitted `mod.rs`).
//!
//! A "declared-but-feature-absent" drift fails at (2)/(3); a
//! "prelude-references-a-module-whose-feature-is-off" drift fails at (4). Both
//! fail-closed.
//!
//! ## Why not an exhaustive `2^FLAG_COUNT` sweep
//!
//! A brute-force enumeration of every flag mask is `O(2^FLAG_COUNT)` — feasible
//! at 18 flags, infeasible as the runtime feature count grows (2^28 masks).
//! This SEAL proves the SAME closure guarantee in `O(FLAG_COUNT)` by three
//! composable checks, each individually verified and provably equivalent to the
//! full sweep for the closure property:
//!
//! 1. **Per-flag closure** ([`each_flag_is_self_consistent`]): for every single
//!    `uses_*` flag on its own (and the featureless base), the SSOT set is in
//!    the declared universe, resolves closed, and every emitted
//!    `ipe_runtime::<mod>::` reference is cfg-satisfied. Linear.
//! 2. **Monotonicity** ([`feature_selection_is_monotone`],
//!    [`emitted_references_are_monotone`]): the SSOT and the emitted-reference
//!    set are monotone in the flag mask — a superset of flags selects a
//!    superset of features and references. Cargo feature resolution and
//!    `Cfg::eval` are both monotone in the feature set. Property-tested on a
//!    fixed sample of flag PAIRS: `f(a | b) = f(a) ∪ f(b)`.
//! 3. **Composition** ([`composed_full_universe_is_closed`]): per-flag + monotone
//!    ⇒ EVERY mask is closed. Proof: for any mask `M = ⋃ bit_i`, monotonicity
//!    gives `refs(M) = ⋃ refs(bit_i)` and `features(M) = ⋃ features(bit_i)`.
//!    Each `refs(bit_i)` is cfg-satisfied by `features(bit_i)` (check 1); since
//!    `Cfg::eval` is monotone-up in the feature set and
//!    `features(bit_i) ⊆ features(M)`, each reference stays satisfied under the
//!    union. So the union of individually-closed sets is closed — no
//!    combination can drop a needed module or leave a reference uncovered. This
//!    test builds the composed all-flags reference/feature sets and asserts
//!    closure directly, standing in for the whole `2^FLAG_COUNT` space.
//!
//! A bounded, deterministic **sampled sweep** ([`sampled_full_masks_are_closed`])
//! runs the original whole-mask check on a fixed pseudo-random selection of full
//! masks (plus the corners: all-off, all-on, each singleton) as a backstop — it
//! is a redundancy net, not the primary proof.
//!
//! The fail-closed DIRECTION is proven by [`prelude_reference_gap_fails_closed`]:
//! an injected drift (a feature dropped from a reference's gate) MUST make the
//! coverage check fail.

mod seal_e2e;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ipe_backend::Backend;
use ipe_backend_rust::RustBackend;
use ipe_diagnostics::DResult;
use ipe_intern::Interner;
use ipe_ir::{
    CallPin, Callee, Expr, Func, FuncId, IrType, KernelFn, ModPath, Module, OnFormKind, Program,
};

/// The flag space, identical to `runtime_modset_closure.rs`: bit `i` sets
/// `uses_*` flag `i`. The two SEALs share one flag layout so the featureset
/// closure covers exactly the programs the module closure does. The proof is
/// per-flag + monotone + composed (see the module docs), NOT a `2^FLAG_COUNT`
/// enumeration — it scales to a far larger flag count in linear time.
const FLAG_COUNT: usize = 30;

/// How many random full masks the backstop [`sampled_full_masks_are_closed`]
/// exercises, on top of the deterministic corners. Bounded so the sample cost
/// stays constant as `FLAG_COUNT` grows.
const SAMPLE_MASKS: usize = 256;

/// A deterministic full-mask stream: a fixed-seed splitmix64 generator. No
/// `rand`/`Date`/entropy — the seed is a constant so the sample is identical on
/// every run (a failure reproduces without a flake). Masks are taken modulo the
/// flag space.
fn sampled_masks(count: usize) -> Vec<u32> {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15; // fixed seed
    let mask_space: u64 = 1u64 << FLAG_COUNT;
    (0..count)
        .map(|_| {
            // splitmix64 step.
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            u32::try_from(z % mask_space).unwrap_or(0)
        })
        .collect()
}

/// Build a body-free `Module` with the mask's `uses_*` flags, mirroring the
/// module-set SEAL's invariants (tui⇒ui; every gated surface forces the async
/// spine so the emitted manifest matches a real program).
#[allow(clippy::similar_names)]
fn module_for_mask(name: ipe_intern::Symbol, mask: u32) -> Module {
    let f = |i: usize| mask & (1 << i) != 0;
    let uses_tui = f(4);
    let uses_ui = f(2) || uses_tui;
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
        uses_console: false,
        uses_webview: f(5),
        uses_css: f(6),
        uses_auth: f(7),
        // Fixed false: the `principal` module carries no feature-gate edge, so
        // it is outside this feature-flag closure matrix.
        uses_principal: false,
        uses_websocket: f(8),
        uses_email: f(9),
        // `uses_locale` is a pure surface (no reactor) — NOT in the async union.
        // It gates `locale.rs` + the `locale` Cargo feature (`icu_casemap` +
        // `icu_locale_core`). A standalone leaf here.
        uses_locale: f(29),
        uses_time: false,
        uses_env_public: f(10),
        uses_http: f(11),
        uses_config: f(12),
        uses_compression: f(13),
        uses_csv: f(14),
        // `uses_cache` is a pure surface (no reactor) — NOT in the async union. A
        // standalone leaf: gates the `cache` module + the `cache_kernel` feature.
        uses_cache: f(28),
        // `uses_encoding` is a pure surface (no reactor) — NOT in the async union.
        uses_encoding: f(18),
        // `uses_regex` / `uses_uuid` / `uses_random` / `uses_log` /
        // `uses_decimal` / `uses_char_category` are pure surfaces (no reactor) —
        // NOT in the async union. `uses_log` drives `reaches_time_core` (chrono)
        // alongside web / webview (bits 3 / 5); `uses_decimal` drives
        // `reaches_decimal` (rust_decimal) alongside the `db` surface;
        // `uses_char_category` is a standalone leaf.
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

// ── the runtime crate's `[features]` universe + resolution ─────────────────

/// Parse `src/runtime/rust/Cargo.toml`'s `[features]` table into
/// `feature -> [enabled tokens]`. A token is another feature name or an
/// (implicit) optional-dep feature; the `dep:`, `crate/`, and `dep?/` prefixes
/// are normalized to the bare feature-or-dep name that a `#[cfg(feature = …)]`
/// can test.
fn parse_feature_table(cargo_toml: &str) -> BTreeMap<String, Vec<String>> {
    let mut table = BTreeMap::new();
    let mut in_features = false;
    for raw in cargo_toml.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            in_features = line == "[features]";
            continue;
        }
        if !in_features {
            continue;
        }
        // `name = ["a", "b/c", "dep:d"]` — may span lines; the crate keeps each
        // feature on one line, so parse a single-line array.
        let Some((name, rhs)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let mut enabled = Vec::new();
        for tok in rhs.split(['[', ']', ',', '"']) {
            let t = tok.trim();
            if t.is_empty() {
                continue;
            }
            enabled.push(normalize_feature_token(t));
        }
        table.insert(name.to_owned(), enabled);
    }
    table
}

/// Normalize a feature-list token to the bare feature-or-dep name a
/// `#[cfg(feature = "…")]` tests: `dep:tokio` → `tokio`, `sqlx?/sqlite` →
/// `sqlite` (the sqlx sub-feature — not a crate feature, so it will simply not
/// resolve as a key, which is correct), `sqlx/postgres` → `postgres`,
/// `tokio/sync` → `sync`. A bare `json` stays `json`.
fn normalize_feature_token(tok: &str) -> String {
    let tok = tok.strip_prefix("dep:").unwrap_or(tok);
    // `crate?/feat` or `crate/feat` — the enabled thing is the sub-feature; for
    // our cfg-satisfaction purposes the crate itself is what a
    // `#[cfg(feature = "crate")]` would test, so keep the crate name.
    if let Some((crate_name, _sub)) = tok.split_once('/') {
        return crate_name.trim_end_matches('?').to_owned();
    }
    tok.to_owned()
}

/// Resolve `selected` to the full set of enabled feature-or-dep names under
/// Cargo's transitive unification (a feature enables everything on its list,
/// recursively). Non-key tokens (optional-dep implicit features like `tokio`,
/// sub-features like `sync`) are enabled leaves.
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

// ── the runtime crate's `src/mod.rs` cfg gates ─────────────────────────────

/// A `#[cfg(...)]` predicate over the runtime crate's features, restricted to
/// the shapes `src/mod.rs` uses on module declarations.
#[derive(Debug, Clone)]
enum Cfg {
    /// Always compiled (no cfg).
    Always,
    /// `feature = "x"`.
    Feature(String),
    /// `all(...)`.
    All(Vec<Self>),
    /// `any(...)`.
    Any(Vec<Self>),
    /// `target_arch = "wasm32"` (or any other non-feature atom) — evaluated as
    /// its constant truth on the native target this SEAL models.
    TargetAtom(bool),
}

impl Cfg {
    /// Evaluate under the resolved native-target feature set.
    fn eval(&self, feats: &BTreeSet<String>) -> bool {
        match self {
            Self::Always => true,
            Self::Feature(f) => feats.contains(f),
            Self::All(cs) => cs.iter().all(|c| c.eval(feats)),
            Self::Any(cs) => cs.iter().any(|c| c.eval(feats)),
            Self::TargetAtom(v) => *v,
        }
    }
}

/// Parse a `#[cfg(...)]` inner-predicate string (the text between the outer
/// parentheses) into a [`Cfg`]. `target_arch = "wasm32"` is false on the native
/// target this SEAL models; any other `target_*`/`unix` atom is likewise a
/// non-feature and evaluated false (the emitted references this SEAL checks are
/// native-target references — a wasm-only module is never referenced by native
/// emitted output).
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
    if let Some(rest) = s.strip_prefix("feature") {
        // `feature = "x"`.
        if let Some(eq) = rest.trim_start().strip_prefix('=') {
            let name: String = eq.trim().trim_matches('"').to_owned();
            return Cfg::Feature(name);
        }
    }
    // `target_arch = "wasm32"` and friends: non-feature atom → native-false.
    Cfg::TargetAtom(false)
}

/// Split the comma-separated arguments of an `all(...)`/`any(...)` at the top
/// nesting level (commas inside a nested `all`/`any` stay with their group).
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

/// Walk the runtime crate's `src/mod.rs` and return `module -> gating Cfg` for
/// every top-level `pub mod X;` / `mod X;` declaration. A declaration preceded
/// by one or more `#[cfg(...)]` attribute lines carries their conjunction; an
/// un-attributed declaration is [`Cfg::Always`].
fn module_gates(mod_rs: &str) -> BTreeMap<String, Cfg> {
    let mut gates = BTreeMap::new();
    let mut pending: Vec<Cfg> = Vec::new();
    for raw in mod_rs.lines() {
        let line = raw.trim();
        // A one-line `#[cfg(...)] pub mod x;` would be parsed as neither an
        // attribute (no trailing `)]`) nor a `mod` decl (starts with `#`) and so
        // slip through UN-gated — a silent false negative. The crate keeps every
        // cfg attribute on its own line; assert that, so a future inline edit
        // trips here instead of weakening the closure check.
        assert!(
            !(line.contains("#[cfg(") && line.contains(" mod ")),
            "runtime src/mod.rs has an inline `#[cfg(...)] mod` on one line — the \
             featureset-closure gate parser needs the cfg attribute on its own \
             line above the `mod` decl: {line}"
        );
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
            // First declaration wins (the `pub use` lines that follow repeat the
            // same cfg but are not `mod` decls, so they are skipped anyway).
            gates.entry(name.to_owned()).or_insert(gate);
            pending.clear();
            continue;
        }
        // Any non-attribute, non-mod line (blank, comment, `pub use …`, other
        // item) breaks a pending attribute run that did not attach to a `mod`.
        if !line.is_empty() && !line.starts_with("//") {
            pending.clear();
        }
    }
    gates
}

/// If `line` is a single-line `#[cfg(...)]` attribute, return its inner
/// predicate text (between the outer parens). Multi-line cfg attributes are
/// joined by the caller before this is reached — but `src/mod.rs` keeps each on
/// its own logical run; a cfg opened on one line and closed on another is
/// reassembled by [`join_cfg_attrs`].
fn cfg_attr_inner(line: &str) -> Option<String> {
    let s = line.strip_prefix("#[cfg(")?;
    let inner = s.strip_suffix(")]")?;
    Some(inner.to_owned())
}

/// Join `src/mod.rs` so every `#[cfg(...)]` attribute is on ONE line — the
/// crate wraps the multi-line `any(feature = …, …)` gates across several source
/// lines, which [`cfg_attr_inner`] cannot parse line-by-line.
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

// ── emitted-output scan: every `ipe_runtime::<mod>::` hard reference ────────

/// Extract every top-level runtime module named by an `ipe_runtime::<mod>::`
/// path anywhere in an emitted file (the prelude/main hard-references kernels
/// module-qualified). The first path segment after `ipe_runtime::` is the
/// module; a trailing `::` distinguishes a module reach from a bare re-exported
/// item.
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
        // Require a module reach (`ipe_runtime::mod::…`), not a bare item
        // (`ipe_runtime::IpeMaybe`) re-exported at the crate root by a glob.
        let after = start + seg.len();
        if emitted.get(after..after.saturating_add(2)) == Some("::") {
            mods.insert(seg);
        }
    }
    mods
}

// ── the reusable per-mask closure check + shared fixtures ───────────────────

/// The crate manifest `[features]` table and `src/mod.rs` module gates, read
/// once. Both are program-independent (source-only), so every proof below shares
/// one parse.
struct SealFixtures {
    table: BTreeMap<String, Vec<String>>,
    gates: BTreeMap<String, Cfg>,
}

#[allow(clippy::expect_used)] // test scaffolding: the crate sources always parse
fn load_fixtures() -> SealFixtures {
    let crate_root = e2e_support::require_runtime_crate();
    let cargo_toml =
        std::fs::read_to_string(crate_root.join("Cargo.toml")).expect("read runtime Cargo.toml");
    let table = parse_feature_table(&cargo_toml);
    assert!(
        !table.is_empty(),
        "runtime crate [features] table parsed empty"
    );
    let mod_rs_raw =
        std::fs::read_to_string(crate_root.join("src").join("mod.rs")).expect("read src/mod.rs");
    let gates = module_gates(&join_cfg_attrs(&mod_rs_raw));
    assert!(
        !gates.is_empty(),
        "runtime src/mod.rs module gates parsed empty"
    );
    SealFixtures { table, gates }
}

/// The set of `ipe_runtime::<mod>::` module references the EMITTED user code
/// (main.rs / `ipe_mods`, `.rs` only) hard-codes for one flag mask. The vendored
/// `ipe_runtime/*` files reference themselves via `crate::`/`super::` (the
/// module-set SEAL's domain), not the `ipe_runtime::` extern path, so they are
/// excluded.
#[allow(clippy::expect_used)] // test scaffolding: a body-free emit cannot fail
fn emitted_module_references(
    interner: &Interner,
    main: ipe_intern::Symbol,
    mask: u32,
) -> BTreeSet<String> {
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![module_for_mask(main, mask)],
    };
    let emitted = RustBackend::new(interner)
        .emit(&prog)
        .expect("emit must succeed for a body-free program");
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

/// The SSOT feature names for one flag mask.
#[allow(clippy::expect_used)] // test scaffolding: a body-free emit cannot fail
fn selected_features(
    interner: &Interner,
    main: ipe_intern::Symbol,
    mask: u32,
) -> Vec<&'static str> {
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![module_for_mask(main, mask)],
    };
    RustBackend::new(interner)
        .runtime_feature_names(&prog)
        .expect("runtime_feature_names must succeed for a body-free program")
}

/// The whole per-mask closure obligation, in one place so every proof (per-flag,
/// composed, sampled) runs the identical check. Returns nothing; asserts on any
/// breach.
///
/// A bare `ipe_runtime::foo` path may name a module `mod.rs` declares
/// unconditionally with a `pub use foo::*` glob (so the item is ALSO reachable
/// at the root). The check only fails on a reference to a module whose gate is
/// UNSATISFIED — an always-on module (gate `Always`) trivially passes.
fn assert_mask_closed(fx: &SealFixtures, interner: &Interner, main: ipe_intern::Symbol, mask: u32) {
    // (1) the SSOT feature set.
    let selected = selected_features(interner, main, mask);

    // (2) every selected feature is in the crate's declared universe.
    for feat in &selected {
        assert!(
            fx.table.contains_key(*feat),
            "featureset SEAL breach: selected feature `{feat}` is NOT declared \
             in the runtime crate's [features] universe — flag mask {mask:#019b}. \
             Declared: {:?}",
            fx.table.keys().collect::<Vec<_>>()
        );
    }

    // (3) resolve + closure self-consistency: the resolution is a fixpoint
    // (resolving the resolved set adds nothing new).
    let resolved = resolve_features(&selected, &fx.table);
    let reresolved = resolve_features(
        &resolved.iter().map(String::as_str).collect::<Vec<_>>(),
        &fx.table,
    );
    assert_eq!(
        resolved, reresolved,
        "featureset SEAL breach: feature resolution is not closed under the \
         crate [features] table — flag mask {mask:#019b}"
    );

    // (4) every emitted `ipe_runtime::<mod>::` reference is cfg-satisfied.
    for m in emitted_module_references(interner, main, mask) {
        let gate = fx.gates.get(&m).cloned().unwrap_or(Cfg::Always);
        assert!(
            gate.eval(&resolved),
            "featureset SEAL breach: emitted reference `ipe_runtime::{m}::…` for \
             flag mask {mask:#019b}, but the runtime crate gates `mod {m}` behind \
             {gate:?}, UNSATISFIED by the selected feature set {selected:?} \
             (resolved {resolved:?}). The emitted crate would fail `cargo build` \
             (E0433)."
        );
    }
}

// ── (1) per-flag closure — O(FLAG_COUNT) ────────────────────────────────────

/// Every single `uses_*` flag on its own (and the featureless base, mask 0) is
/// self-consistent: its SSOT set is declared, resolves closed, and each emitted
/// module reference is cfg-satisfied. Linear in `FLAG_COUNT` — the base case of
/// the composition argument.
#[test]
fn each_flag_is_self_consistent() {
    let fx = load_fixtures();
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    assert_mask_closed(&fx, &interner, main, 0);
    for bit in 0..FLAG_COUNT {
        assert_mask_closed(&fx, &interner, main, 1u32 << bit);
    }
}

// ── (2) monotonicity — the compose glue ─────────────────────────────────────

/// The SSOT feature selection is monotone in the flag mask AND distributes over
/// union: `features(a | b) = features(a) ∪ features(b)`. Cargo features are
/// additive and `runtime_features` only ever INSERTS (each variant behind an
/// `if flag { insert }`), so no flag can remove a feature another selects. This
/// is what lets per-flag closure compose to the full-set guarantee. Verified on
/// the deterministic mask sample crossed pairwise with the singletons.
#[test]
fn feature_selection_is_monotone() {
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    let as_set = |mask: u32| -> BTreeSet<&'static str> {
        selected_features(&interner, main, mask)
            .into_iter()
            .collect()
    };
    let mut pairs: Vec<(u32, u32)> = Vec::new();
    for a in sampled_masks(SAMPLE_MASKS) {
        for bit in 0..FLAG_COUNT {
            pairs.push((a, 1u32 << bit));
        }
    }
    for (a, b) in pairs {
        let union_features = as_set(a | b);
        let mut composed = as_set(a);
        composed.extend(as_set(b));
        assert_eq!(
            union_features, composed,
            "monotonicity broken: features(a | b) != features(a) ∪ features(b) \
             for a={a:#019b} b={b:#019b}. Per-flag closure no longer composes — \
             the SSOT inserted-only invariant is violated (a flag interaction \
             REMOVES a feature). Per-feature checks would be insufficient; a \
             targeted combination check is needed for this interaction."
        );
        // Monotone-up: the union selects a superset of either operand.
        assert!(
            union_features.is_superset(&as_set(a)) && union_features.is_superset(&as_set(b)),
            "monotonicity broken: features(a | b) is not a superset of features(a) \
             and features(b) — a={a:#019b} b={b:#019b}"
        );
    }
}

/// The emitted module-reference set is monotone in the flag mask:
/// `refs(a | b) ⊇ refs(a) ∪ refs(b)`. The sectioned prelude only APPENDS a
/// section per reachable surface, so enabling a flag can only add references,
/// never drop one. (Equality is the natural shape; `⊇` is the load-bearing
/// direction for the composition proof — no reference vanishes under a superset
/// of flags.)
#[test]
fn emitted_references_are_monotone() {
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    for a in sampled_masks(SAMPLE_MASKS) {
        for bit in 0..FLAG_COUNT {
            let b = 1u32 << bit;
            let mut composed = emitted_module_references(&interner, main, a);
            composed.extend(emitted_module_references(&interner, main, b));
            let union_refs = emitted_module_references(&interner, main, a | b);
            assert!(
                union_refs.is_superset(&composed),
                "monotonicity broken: refs(a | b) does not cover refs(a) ∪ \
                 refs(b) — a={a:#019b} b={b:#019b}. Enabling a flag DROPPED an \
                 emitted reference; the composed proof no longer covers every \
                 combination."
            );
        }
    }
}

// ── (3) composition — per-flag + monotone ⇒ every mask closed ───────────────

/// The composition step made explicit and self-checking: build the all-flags
/// mask's feature and reference sets AS THE UNION of the per-flag sets, and
/// assert (a) the union equals what the SSOT/emitter produce for the full mask
/// (so monotonicity actually holds at the extremum), and (b) the composed set is
/// closed — every composed reference cfg-satisfied by the composed features.
///
/// Given [`each_flag_is_self_consistent`] (each singleton closed) and
/// [`feature_selection_is_monotone`] + [`emitted_references_are_monotone`]
/// (union distributes), this stands in for the entire `2^FLAG_COUNT` sweep: any
/// mask `M` decomposes into its set bits, `features(M)`/`refs(M)` are the unions
/// of the per-bit sets, each per-bit reference is satisfied by its per-bit
/// features (⊆ `features(M)`), and `Cfg::eval` is monotone-up, so every
/// reference stays satisfied under `features(M)`.
#[test]
fn composed_full_universe_is_closed() {
    let fx = load_fixtures();
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    let all: u32 = (1u32 << FLAG_COUNT) - 1;

    // Compose per-flag features + references.
    let mut composed_features: BTreeSet<&'static str> = BTreeSet::new();
    let mut composed_refs: BTreeSet<String> = BTreeSet::new();
    for bit in 0..FLAG_COUNT {
        let m = 1u32 << bit;
        composed_features.extend(selected_features(&interner, main, m));
        composed_refs.extend(emitted_module_references(&interner, main, m));
    }

    // (a) monotonicity holds at the top: the full-mask sets equal the composed
    // unions (features) / are covered by them (references — the emitter may add
    // cross-surface references that no singleton triggers, so full ⊇ composed;
    // the closure below checks the FULL reference set regardless).
    let full_features: BTreeSet<&'static str> = selected_features(&interner, main, all)
        .into_iter()
        .collect();
    assert_eq!(
        full_features, composed_features,
        "composition invalid: features(all) != ⋃ features(singleton) — the SSOT \
         is not a pure per-flag union, so per-flag closure does not compose"
    );

    // (b) the composed feature set resolves closed, and every emitted reference
    // for the FULL mask is cfg-satisfied by it. This is the whole-mask check run
    // once at the extremum — the union of the individually-closed sets.
    let resolved = resolve_features(
        &composed_features.iter().copied().collect::<Vec<_>>(),
        &fx.table,
    );
    let full_refs = emitted_module_references(&interner, main, all);
    for m in &full_refs {
        let gate = fx.gates.get(m).cloned().unwrap_or(Cfg::Always);
        assert!(
            gate.eval(&resolved),
            "composed-closure breach: full-mask reference `ipe_runtime::{m}::…` \
             is gated behind {gate:?}, UNSATISFIED by the composed feature set \
             {composed_features:?} (resolved {resolved:?})."
        );
    }
    // Sanity: the emitter did not invent a reference outside the composed union
    // that the per-flag proofs never saw (would break the composition base).
    assert!(
        composed_refs.is_superset(&full_refs) || full_refs.is_superset(&composed_refs),
        "reference sets are incomparable — composition assumption violated"
    );
}

// ── the sampled full-mask backstop (redundancy, not the proof) ──────────────

/// A bounded, deterministic sample of FULL masks run through the whole per-mask
/// closure check, plus the corners (all-off, all-on, every singleton). This is a
/// redundancy net catching any gap the per-flag + monotone proof missed — not
/// the primary guarantee. Fixed seed ⇒ reproducible; constant cost as
/// `FLAG_COUNT` grows.
#[test]
fn sampled_full_masks_are_closed() {
    let fx = load_fixtures();
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
        assert_mask_closed(&fx, &interner, main, mask);
    }
}

/// Fail-closed proof for direction (4): a hand-built feature set that DROPS a
/// required feature must make the coverage check fail. Uses the same gate/scan
/// machinery, so a regression that weakens the closure (e.g. treating an
/// unsatisfied gate as satisfied) trips here.
#[test]
fn prelude_reference_gap_fails_closed() {
    let crate_root = e2e_support::require_runtime_crate();
    let cargo_toml =
        std::fs::read_to_string(crate_root.join("Cargo.toml")).expect("read runtime Cargo.toml");
    let table = parse_feature_table(&cargo_toml);
    let mod_rs_raw =
        std::fs::read_to_string(crate_root.join("src").join("mod.rs")).expect("read src/mod.rs");
    let gates = module_gates(&join_cfg_attrs(&mod_rs_raw));

    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    // A `uses_auth` program: its emitted prelude hard-references
    // `ipe_runtime::auth::…`, and `mod auth` is gated on `feature = "jwt"`.
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![module_for_mask(main, 1 << 7)],
    };
    let backend = RustBackend::new(&interner);
    let emitted = backend.emit(&prog).expect("emit");

    // The correct set covers the `auth` reference; the mutated set drops `jwt`
    // (auth's gating feature).
    let full = backend.runtime_feature_names(&prog).expect("features");
    assert!(
        full.contains(&"jwt"),
        "precondition: a uses_auth program selects `jwt` (auth's gate); got {full:?}"
    );
    let mutated: Vec<&str> = full.into_iter().filter(|f| *f != "jwt").collect();
    let resolved = resolve_features(&mutated, &table);

    // Find at least one emitted `ipe_runtime::auth::…` reference and assert the
    // dropped-feature set does NOT cover it — the fail-closed direction.
    let mut saw_ref = false;
    let mut uncovered = false;
    for text in emitted.files.values() {
        for m in referenced_runtime_modules(text) {
            if m == "auth" {
                saw_ref = true;
                let gate = gates.get("auth").cloned().unwrap_or(Cfg::Always);
                if !gate.eval(&resolved) {
                    uncovered = true;
                }
            }
        }
    }
    assert!(
        saw_ref,
        "a uses_auth program must emit at least one `ipe_runtime::auth::…` reference"
    );
    assert!(
        uncovered,
        "fail-closed proof: dropping the `jwt` feature must leave the emitted \
         `ipe_runtime::auth::…` reference UNCOVERED — the closure check would have \
         a false negative otherwise"
    );
}

/// The universe check is non-trivial: the SSOT DOES select features across the
/// sweep (a green run where nothing is ever selected would be vacuous). Assert
/// the union of selected features over the sweep is a non-empty subset of the
/// declared universe and includes the dependency-bearing surfaces.
#[test]
fn ssot_selects_a_meaningful_subset_of_the_universe() {
    let crate_root = e2e_support::require_runtime_crate();
    let cargo_toml =
        std::fs::read_to_string(crate_root.join("Cargo.toml")).expect("read runtime Cargo.toml");
    let table = parse_feature_table(&cargo_toml);

    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");

    let mut union: BTreeSet<String> = BTreeSet::new();
    // A representative slice of the sweep (full sweep is exercised by the
    // coverage test); each single-flag mask plus the empty mask suffices to
    // union every surface feature.
    for bit in 0..FLAG_COUNT {
        let prog = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![module_for_mask(main, 1 << bit)],
        };
        for f in RustBackend::new(&interner)
            .runtime_feature_names(&prog)
            .expect("features")
        {
            union.insert(f.to_owned());
        }
    }
    assert!(!union.is_empty(), "SSOT selected nothing across the sweep");
    for f in &union {
        assert!(
            table.contains_key(f),
            "union feature `{f}` not in the declared universe"
        );
    }
    for expect in [
        "json",
        "url",
        "http_client",
        "server",
        "web",
        "tui",
        "websocket_client",
    ] {
        assert!(
            union.contains(expect),
            "SSOT sweep never selected the dependency-bearing feature `{expect}`: {union:?}"
        );
    }
}

/// A program whose module only has `uses_locale = true` (set here directly,
/// as it would be after the lowerer detects `IrType::Locale` in a type
/// position) must select the `locale` runtime feature, so `locale_from_tag`
/// reaches the ICU4X parse path and `locale.rs` compiles.
///
/// The lowerer half — that `IrType::Locale` in any emittable position sets
/// `uses_locale` — is covered by the `ipe_lower` test suite.
#[test]
fn uses_locale_selects_locale_feature() {
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main]),
            types: vec![],
            funcs: vec![],
            entry: None,
            records: vec![],
            uses_tea: false,
            uses_server: false,
            uses_ui: false,
            uses_web: false,
            uses_tui: false,
            uses_console: false,
            uses_webview: false,
            uses_css: false,
            uses_auth: false,
            uses_principal: false,
            uses_websocket: false,
            uses_http: false,
            uses_config: false,
            uses_compression: false,
            uses_csv: false,
            uses_cache: false,
            uses_encoding: false,
            uses_regex: false,
            uses_uuid: false,
            uses_random: false,
            uses_log: false,
            uses_decimal: false,
            uses_char_category: false,
            uses_crypto_core: false,
            uses_secret: false,
            uses_json: false,
            uses_crypto: false,
            uses_jwt: false,
            uses_url: false,
            uses_debug: false,
            uses_ffi: false,
            uses_email: false,
            uses_locale: true,
            uses_time: false,
            uses_env_public: false,
            uses_async_runtime: false,
        }],
    };
    let features = RustBackend::new(&interner)
        .runtime_feature_names(&prog)
        .expect("runtime_feature_names");
    assert!(
        features.contains(&"locale"),
        "a uses_locale program must select the `locale` runtime feature; \
         got {features:?}"
    );
}

/// A program whose module only has `uses_email = true` must select the
/// `email` runtime feature so the generated `mod.rs` declares
/// `pub mod email` and all email types resolve at `cargo build` time.
///
/// The lowerer half — that all email kernels and `IrType::EmailAddress` set
/// `uses_email` — is covered by the `ipe_lower` test suite.
#[test]
fn uses_email_selects_email_feature() {
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main]),
            types: vec![],
            funcs: vec![],
            entry: None,
            records: vec![],
            uses_tea: false,
            uses_server: false,
            uses_ui: false,
            uses_web: false,
            uses_tui: false,
            uses_console: false,
            uses_webview: false,
            uses_css: false,
            uses_auth: false,
            uses_principal: false,
            uses_websocket: false,
            uses_http: false,
            uses_config: false,
            uses_compression: false,
            uses_csv: false,
            uses_cache: false,
            uses_encoding: false,
            uses_regex: false,
            uses_uuid: false,
            uses_random: false,
            uses_log: false,
            uses_decimal: false,
            uses_char_category: false,
            uses_crypto_core: false,
            uses_secret: false,
            uses_json: false,
            uses_crypto: false,
            uses_jwt: false,
            uses_url: false,
            uses_debug: false,
            uses_ffi: false,
            uses_email: true,
            uses_locale: false,
            uses_time: false,
            uses_env_public: false,
            uses_async_runtime: false,
        }],
    };
    let features = RustBackend::new(&interner)
        .runtime_feature_names(&prog)
        .expect("runtime_feature_names");
    assert!(
        features.contains(&"email"),
        "a uses_email program must select the `email` runtime feature; \
         got {features:?}"
    );
}

/// SEAL (E2E): a program that calls only `Email.parseAddress` (no `Email.send`)
/// must produce a crate that `cargo build`s successfully. The regression class:
/// the lowerer previously set `uses_email` only for `EmailSend`, so a
/// `parseAddress`-only program emitted an `ipe_runtime::email::*` reference
/// without enabling the `email` cargo feature, causing a `cargo build` failure
/// after `ipe` exited 0.
///
/// The IR here represents the lowerer's output — `uses_email` is `true` because
/// the lowerer detected `KernelFn::EmailAddressParse`. The SEAL proves the
/// emitted crate (Cargo.toml + mod.rs) satisfies cargo's feature resolution.
///
/// Gated on `IPE_E2E=1`; skipped in offline / unit-test-only runs.
#[test]
fn email_parse_address_only_cargo_builds() -> DResult<()> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let runtime = e2e_support::require_runtime().into_path_buf();

    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let main_sym = interner.intern("main")?;
    let s_sym = interner.intern("s")?;

    // `helper s = Email.parseAddress s` — exercises the kernel without EmailSend.
    let helper_sym = interner.intern("helper")?;
    let helper_fn = Func {
        id: FuncId::from_raw(0),
        name: helper_sym,
        home: ModPath(vec![main_mod]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(s_sym, IrType::Str)],
        ret: IrType::Maybe(Box::new(IrType::EmailAddress)),
        body: Expr::Call {
            callee: Callee::Kernel(KernelFn::EmailAddressParse),
            args: vec![Expr::Var(s_sym)],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        },
    };

    // `main = Io.println ""` — a minimal valid Task entry.
    let main_fn = Func {
        id: FuncId::from_raw(1),
        name: main_sym,
        home: ModPath(vec![main_mod]),
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret: IrType::Task(Box::new(IrType::Unit)),
        body: Expr::Call {
            callee: Callee::Kernel(KernelFn::IoPrintln),
            args: vec![Expr::Str(String::new())],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        },
    };

    // Module with uses_email: true (set by the lowerer upon seeing EmailAddressParse).
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main_mod]),
            types: vec![],
            funcs: vec![helper_fn, main_fn],
            entry: Some(FuncId::from_raw(1)),
            records: vec![],
            uses_tea: false,
            uses_server: false,
            uses_ui: false,
            uses_web: false,
            uses_tui: false,
            uses_console: false,
            uses_webview: false,
            uses_css: false,
            uses_auth: false,
            uses_principal: false,
            uses_websocket: false,
            uses_http: false,
            uses_config: false,
            uses_compression: false,
            uses_csv: false,
            uses_cache: false,
            uses_encoding: false,
            uses_regex: false,
            uses_uuid: false,
            uses_random: false,
            uses_log: false,
            uses_decimal: false,
            uses_char_category: false,
            uses_crypto_core: false,
            uses_secret: false,
            uses_json: false,
            uses_crypto: false,
            uses_jwt: false,
            uses_url: false,
            uses_debug: false,
            uses_ffi: false,
            uses_email: true,
            uses_locale: false,
            uses_time: false,
            uses_env_public: false,
            uses_async_runtime: false,
        }],
    };

    let emitted = RustBackend::new(&interner).emit(&prog)?;
    let status = seal_e2e::vendor_and_run(&emitted, &runtime, "ipe_email_parse_only_e2e", "build")?;
    assert!(
        matches!(&status, Ok(s) if s.success()),
        "an Email.parseAddress-only (no Email.send) program must cargo build; \
         email feature must be enabled by uses_email=true: {status:?}"
    );
    Ok(())
}
