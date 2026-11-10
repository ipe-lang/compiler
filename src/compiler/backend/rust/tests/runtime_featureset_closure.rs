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
//!    superset of features and references. Cargo feature resolution is
//!    monotone in the feature set. Property-tested on a fixed sample of flag
//!    PAIRS: `f(a | b) = f(a) ∪ f(b)`.
//! 3. **Composition** ([`composed_full_universe_is_closed`]): per-flag + monotone
//!    ⇒ EVERY mask is closed. Proof: for any mask `M = ⋃ bit_i`, monotonicity
//!    gives `refs(M) = ⋃ refs(bit_i)` and `features(M) = ⋃ features(bit_i)`.
//!    Each `refs(bit_i)` is cfg-satisfied by `features(bit_i)` (check 1), and
//!    `features(bit_i) ⊆ features(M)`; a reference stays satisfied under the
//!    union only while its module gate is monotone in the feature set. A gate
//!    under `not(feature = ..)` is not, so this test also checks the composed
//!    all-flags reference/feature sets directly rather than relying on the
//!    union argument alone.
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

#[path = "support/cfg.rs"]
mod cfg;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ipe_backend::Backend;
use ipe_backend_rust::{RuntimeDep, RustBackend};
use ipe_diagnostics::DResult;
use ipe_intern::Interner;
use ipe_ir::{
    CallPin, Callee, Expr, Func, FuncId, IrType, KernelFn, ModPath, Module, OnFormKind, Program,
    Target,
};

use cfg::{CfgEnv, ModuleGates};

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
    raw_feature_table(cargo_toml)
        .into_iter()
        .map(|(name, tokens)| {
            let enabled = tokens.iter().map(|t| normalize_feature_token(t)).collect();
            (name, enabled)
        })
        .collect()
}

/// Parse a manifest's `[features]` table into verbatim token lists.
///
/// A list may span lines and carry `#` comments; each token is kept as written
/// (`dep:x`, `x/y`, `x`) so liveness can tell a dependency activation from a
/// feature edge.
fn raw_feature_table(cargo_toml: &str) -> BTreeMap<String, Vec<String>> {
    let mut table: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut in_features = false;
    // The feature whose `[ … ]` list is still open across lines.
    let mut open: Option<String> = None;
    for raw in cargo_toml.lines() {
        let line = raw.split_once('#').map_or(raw, |(code, _)| code).trim();
        if line.is_empty() {
            continue;
        }
        let (name, rhs) = if let Some(name) = open.take() {
            (name, line)
        } else if line.starts_with('[') {
            in_features = line == "[features]";
            continue;
        } else if !in_features {
            continue;
        } else if let Some((name, rhs)) = line.split_once('=') {
            (name.trim().to_owned(), rhs)
        } else {
            continue;
        };
        table
            .entry(name.clone())
            .or_default()
            .extend(rhs.split('"').skip(1).step_by(2).map(str::to_owned));
        if !rhs.contains(']') {
            open = Some(name);
        }
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

// ── the runtime crate's `src/mod.rs` module gates ───────────────────────────

/// The runtime crate's native build under the resolved feature set.
fn native_env(resolved: &BTreeSet<String>) -> CfgEnv {
    CfgEnv {
        features: resolved.clone(),
        wasm: false,
    }
}

/// The runtime crate's `src/mod.rs` module gates, parsed through the shared
/// cfg grammar; an unreadable predicate fails the read.
#[allow(clippy::expect_used)] // test scaffolding: the crate sources always parse
fn runtime_module_gates(crate_root: &Path) -> ModuleGates {
    let mod_rs =
        std::fs::read_to_string(crate_root.join("src").join("mod.rs")).expect("read src/mod.rs");
    ModuleGates::parse(&mod_rs).expect("runtime src/mod.rs module gates must parse")
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

// ── liveness: every declared feature and optional dependency is used ────────

/// Optional dependencies no runtime code names, on purpose.
///
/// `tinyvec` is declared only to force its `std` feature on through Cargo's
/// feature unification (a transitive dependency of `url`).
const FEATURE_UNIFICATION_PINS: &[&str] = &["tinyvec"];

/// Whether `text` balances its opening and closing brackets and braces.
fn balanced(text: &str) -> bool {
    text.matches(['{', '[']).count() == text.matches(['}', ']']).count()
}

/// The optional dependencies a manifest's build `[dependencies]` tables
/// declare, target-specific tables included and dev-dependencies excluded.
fn optional_deps(cargo_toml: &str) -> BTreeSet<String> {
    let mut deps = BTreeSet::new();
    let mut in_deps = false;
    // The dependency whose inline table or array is still open across lines.
    let mut open: Option<(String, String)> = None;
    for raw in cargo_toml.lines() {
        let line = raw.split_once('#').map_or(raw, |(code, _)| code);
        let (name, text) = if let Some((name, mut text)) = open.take() {
            text.push_str(line);
            (name, text)
        } else {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                in_deps = trimmed == "[dependencies]"
                    || (trimmed.starts_with("[target.") && trimmed.ends_with(".dependencies]"));
                continue;
            }
            if !in_deps || line.starts_with(char::is_whitespace) {
                continue;
            }
            let Some((name, rhs)) = trimmed.split_once('=') else {
                continue;
            };
            (name.trim().to_owned(), rhs.to_owned())
        };
        if balanced(&text) {
            if text.contains("optional = true") {
                deps.insert(name);
            }
        } else {
            open = Some((name, text));
        }
    }
    deps
}

/// The runtime crate's reachable Rust code, comment lines dropped.
///
/// It reads `src/**/*.rs` and `build.rs`; dropping comments keeps prose naming
/// a feature or crate from reading as use.
#[allow(clippy::expect_used)] // test scaffolding: the runtime sources are readable
fn runtime_code(crate_root: &Path) -> String {
    let mut files = vec![crate_root.join("build.rs")];
    let mut dirs = vec![crate_root.join("src")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("read runtime source dir") {
            let path = entry.expect("read runtime source entry").path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    let mut code = String::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("read runtime source file");
        for line in text.lines() {
            if !line.trim_start().starts_with("//") {
                code.push_str(line);
                code.push('\n');
            }
        }
    }
    code
}

/// Whether `code` gates anything on the cargo feature `feature`.
fn reads_feature(code: &str, feature: &str) -> bool {
    code.contains(&format!("feature = \"{feature}\""))
        || code.contains(&format!("feature=\"{feature}\""))
}

/// Whether `code` names the crate `dep` as a path root (`dep::…`).
///
/// The crate is looked up under its `-`→`_` library name and its `-`-dropped
/// one (`md-5` is `md5`).
fn names_crate_path(code: &str, dep: &str) -> bool {
    [dep.replace('-', "_"), dep.replace('-', "")]
        .iter()
        .any(|ident| {
            let needle = format!("{ident}::");
            code.match_indices(&needle).any(|(at, _)| {
                code.get(..at)
                    .and_then(|before| before.chars().next_back())
                    .is_none_or(|c| c != '_' && !c.is_ascii_alphanumeric())
            })
        })
}

/// Whether one `[features]` token turns on something code uses.
///
/// It does when it is a `dep:x` activation of a crate the code names, a `x/y` sub-feature setting, or a
/// bare optional dependency the code names. A bare edge to another feature
/// adds nothing on its own; that feature answers for its own liveness.
fn token_contributes(
    token: &str,
    table: &BTreeMap<String, Vec<String>>,
    optional: &BTreeSet<String>,
    code: &str,
) -> bool {
    if let Some(dep) = token.strip_prefix("dep:") {
        return names_crate_path(code, dep);
    }
    token.contains('/')
        || (!table.contains_key(token) && optional.contains(token) && names_crate_path(code, token))
}

/// The declared features that change nothing the build compiles.
///
/// Such a feature is read by no `cfg`, and none of its tokens turns on a used
/// crate or sub-feature. `default` is exempt, as the crate's empty baseline.
fn dead_features(cargo_toml: &str, code: &str) -> Vec<String> {
    let table = raw_feature_table(cargo_toml);
    let optional = optional_deps(cargo_toml);
    table
        .iter()
        .filter(|(name, tokens)| {
            name.as_str() != "default"
                && !reads_feature(code, name)
                && !tokens
                    .iter()
                    .any(|t| token_contributes(t, &table, &optional, code))
        })
        .map(|(name, _)| name.clone())
        .collect()
}

/// The optional dependencies the code never names as a path root.
fn unused_optional_deps(cargo_toml: &str, code: &str) -> Vec<String> {
    optional_deps(cargo_toml)
        .into_iter()
        .filter(|dep| !names_crate_path(code, dep))
        .collect()
}

// ── the reusable per-mask closure check + shared fixtures ───────────────────

/// The crate manifest `[features]` table and `src/mod.rs` module gates, read
/// once. Both are program-independent (source-only), so every proof below shares
/// one parse.
struct SealFixtures {
    table: BTreeMap<String, Vec<String>>,
    gates: ModuleGates,
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
    let gates = runtime_module_gates(&crate_root);
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
    let refs = emitted_module_references(interner, main, mask);
    let unsatisfied = fx.gates.unsatisfied(&refs, &native_env(&resolved));
    assert!(
        unsatisfied.is_empty(),
        "featureset SEAL breach for flag mask {mask:#019b}, selected feature set \
         {selected:?} (resolved {resolved:?}); the emitted crate would fail \
         `cargo build` (E0433):\n{}",
        unsatisfied.join("\n")
    );
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
/// features (⊆ `features(M)`), and a module gate monotone in the feature set
/// keeps every reference satisfied under `features(M)`; a `not(feature = ..)`
/// gate is not monotone, which the direct check below still evaluates.
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
    let unsatisfied = fx.gates.unsatisfied(&full_refs, &native_env(&resolved));
    assert!(
        unsatisfied.is_empty(),
        "composed-closure breach under the composed feature set \
         {composed_features:?} (resolved {resolved:?}):\n{}",
        unsatisfied.join("\n")
    );
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
    let gates = runtime_module_gates(&crate_root);

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
    let covered = resolve_features(&full, &table);
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
                let refs = BTreeSet::from([m]);
                assert!(
                    gates.unsatisfied(&refs, &native_env(&covered)).is_empty(),
                    "the full feature set of a uses_auth program must cover `ipe_runtime::auth::…`"
                );
                if !gates.unsatisfied(&refs, &native_env(&resolved)).is_empty() {
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
        params: vec![ipe_ir::Param::owned(s_sym, IrType::Str)],
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
    let built = seal_e2e::build_emitted(&emitted, &runtime, "ipe_email_parse_only_e2e")?;
    assert!(
        built.is_ok(),
        "an Email.parseAddress-only (no Email.send) program must cargo build; \
         email feature must be enabled by uses_email=true: {:?}",
        built.err()
    );
    Ok(())
}

// ── the shared cfg grammar's refusals ───────────────────────────────────────

/// A runtime crate root holding a declaration under `not(feature = "x")`.
const NOT_GATED_ROOT: &str = r#"
#[cfg(not(feature = "x"))]
pub mod gated;
"#;

fn env_with(features: &[&str]) -> CfgEnv {
    native_env(&features.iter().map(|f| (*f).to_owned()).collect())
}

/// A reference to a module declared under `not(feature = "x")` is refused once
/// `x` is on: the negation is evaluated, never read as compiled.
#[test]
#[allow(clippy::expect_used)] // test scaffolding: the fixture root parses
fn not_feature_gate_refuses_reference_when_feature_on() {
    let gates = ModuleGates::parse(NOT_GATED_ROOT).expect("fixture root parses");
    let refs = BTreeSet::from(["gated".to_owned()]);
    assert_eq!(
        gates.unsatisfied(&refs, &env_with(&["x"])),
        vec![
            "`ipe_runtime::gated::` needs `mod gated`, which is not compiled \
             (declared under [All([Not(Feature(\"x\"))])])"
                .to_owned()
        ],
    );
    assert!(gates.unsatisfied(&refs, &env_with(&[])).is_empty());
}

/// A reference to a module the crate root never declares is refused.
#[test]
#[allow(clippy::expect_used)] // test scaffolding: the fixture root parses
fn undeclared_module_reference_is_refused() {
    let gates = ModuleGates::parse(NOT_GATED_ROOT).expect("fixture root parses");
    let refs = BTreeSet::from(["absent".to_owned()]);
    assert_eq!(
        gates.unsatisfied(&refs, &env_with(&["x"])),
        vec![
            "`ipe_runtime::absent::` needs `mod absent`, which is not declared (declared under [])"
                .to_owned()
        ],
    );
}

/// A module the build host decides is refused: it is absent on some host.
#[test]
#[allow(clippy::expect_used)] // test scaffolding: the fixture root parses
fn host_gated_module_reference_is_refused() {
    let gates = ModuleGates::parse("#[cfg(unix)]\npub mod host;\n").expect("fixture root parses");
    let refs = BTreeSet::from(["host".to_owned()]);
    assert_eq!(
        gates.unsatisfied(&refs, &env_with(&[])),
        vec![
            "`ipe_runtime::host::` needs `mod host`, which is compiled only on some \
             build hosts (declared under [All([Host])])"
                .to_owned()
        ],
    );
}

/// A module declared once per side of a feature is compiled either way.
#[test]
#[allow(clippy::expect_used)] // test scaffolding: the fixture root parses
fn module_declared_on_both_sides_of_a_feature_holds() {
    let gates = ModuleGates::parse(
        "#[cfg(not(feature = \"pg\"))]\npub mod config;\n\
         #[cfg(feature = \"pg\")]\n#[path = \"config_pg.rs\"]\npub mod config;\n",
    )
    .expect("fixture root parses");
    let refs = BTreeSet::from(["config".to_owned()]);
    assert!(gates.unsatisfied(&refs, &env_with(&[])).is_empty());
    assert!(gates.unsatisfied(&refs, &env_with(&["pg"])).is_empty());
}

/// An atom the grammar does not know is refused, never read as false.
#[test]
fn unknown_cfg_atom_is_refused() {
    let flag = ModuleGates::parse("#[cfg(madeup)]\npub mod m;\n").map(|g| g.is_empty());
    assert_eq!(flag, Err("unknown cfg flag `madeup`".to_owned()));
    let atom = ModuleGates::parse("#[cfg(madeup = \"v\")]\npub mod m;\n").map(|g| g.is_empty());
    assert_eq!(atom, Err("unknown cfg atom `madeup = \"v\"`".to_owned()));
    let nested = ModuleGates::parse("#[cfg(not(madeup))]\npub mod m;\n").map(|g| g.is_empty());
    assert_eq!(nested, Err("unknown cfg flag `madeup`".to_owned()));
    let combinator = ModuleGates::parse("#[cfg(either(test))]\npub mod m;\n").map(|g| g.is_empty());
    assert_eq!(
        combinator,
        Err("unknown cfg combinator `either(..)`".to_owned())
    );
}

// ── liveness: no dead feature, no unused dependency, no `chrono-tz` ──────────

/// The runtime manifest and the code it builds.
#[allow(clippy::expect_used)] // test scaffolding: the runtime crate is readable
fn runtime_manifest_and_code() -> (String, String) {
    let crate_root = e2e_support::require_runtime_crate();
    let cargo_toml =
        std::fs::read_to_string(crate_root.join("Cargo.toml")).expect("read runtime Cargo.toml");
    (cargo_toml, runtime_code(&crate_root))
}

/// Every declared runtime feature is read by a `cfg` or turns on a used crate.
///
/// An emitted manifest selecting a feature then always pays for real code.
#[test]
fn no_declared_runtime_feature_is_dead() {
    let (cargo_toml, code) = runtime_manifest_and_code();
    let table = raw_feature_table(&cargo_toml);
    assert!(
        table
            .get("wasm-client")
            .is_some_and(|tokens| tokens.iter().any(|t| t == "time-core")),
        "precondition: the multi-line `wasm-client` list parses whole: {:?}",
        table.get("wasm-client")
    );
    let dead = dead_features(&cargo_toml, &code);
    assert!(
        dead.is_empty(),
        "runtime features no `cfg` reads and that turn on no used crate: {dead:?}"
    );
}

/// Every optional runtime dependency is named by runtime code.
///
/// The declared feature-unification pins are the only exemption.
#[test]
fn no_optional_runtime_dependency_is_unused() {
    let (cargo_toml, code) = runtime_manifest_and_code();
    assert!(
        optional_deps(&cargo_toml).contains("chrono"),
        "precondition: the optional dependency scan sees `chrono`"
    );
    let unused: Vec<String> = unused_optional_deps(&cargo_toml, &code)
        .into_iter()
        .filter(|dep| !FEATURE_UNIFICATION_PINS.contains(&dep.as_str()))
        .collect();
    assert!(
        unused.is_empty(),
        "optional runtime dependencies no runtime code names: {unused:?}"
    );
}

/// A feature that only adds an unused crate to a live feature is refused.
///
/// Either a `cfg` read or a use of the crate revives it.
#[test]
fn dead_feature_and_unused_dependency_are_refused() {
    const MANIFEST: &str = r#"
[dependencies]
chrono = { version = "0.4", optional = true }
chrono-tz = { version = "0.10", optional = true }

[features]
default = []
time-core = ["dep:chrono"]
time = [
    "dep:chrono-tz",
    "time-core",
]
"#;
    const CODE: &str = "#[cfg(feature = \"time-core\")]\npub mod time;\n\
                        fn now() { let _ = chrono::Utc::now(); }\n";
    assert_eq!(dead_features(MANIFEST, CODE), vec!["time".to_owned()]);
    assert_eq!(
        unused_optional_deps(MANIFEST, CODE),
        vec!["chrono-tz".to_owned()]
    );
    let read = format!("{CODE}#[cfg(feature = \"time\")]\nmod zones;\n");
    assert!(dead_features(MANIFEST, &read).is_empty());
    let used = format!("{CODE}fn zone() {{ let _ = chrono_tz::UTC; }}\n");
    assert!(dead_features(MANIFEST, &used).is_empty());
    assert!(unused_optional_deps(MANIFEST, &used).is_empty());
}

/// The emitted manifest of a `uses_time` program on one target and model.
#[allow(clippy::expect_used)] // test scaffolding: a body-free emit cannot fail
fn time_program_cargo_toml(
    interner: &Interner,
    prog: &Program,
    target: Target,
    dep: bool,
) -> String {
    let backend = RustBackend::new(interner).with_target(target);
    let backend = if dep {
        backend.with_runtime_dep(Some(RuntimeDep {
            root: e2e_support::require_runtime_crate(),
        }))
    } else {
        backend
    };
    backend
        .emit(prog)
        .expect("emit must succeed for a body-free program")
        .cargo_toml
}

/// No emitted manifest names `chrono-tz` or selects a dead runtime feature.
///
/// A `uses_time` program, alone and beside each other surface, on both targets
/// and both runtime models, enables `time-core` (selected, or implied by a
/// selected feature such as `wasm-client`) and selects nothing unread.
#[test]
#[allow(clippy::expect_used)] // test scaffolding: a body-free emit cannot fail
fn time_programs_emit_no_dead_feature_or_chrono_tz() {
    let (cargo_toml, code) = runtime_manifest_and_code();
    let dead = dead_features(&cargo_toml, &code);
    let table = parse_feature_table(&cargo_toml);
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    let native = (0..FLAG_COUNT).map(|bit| (Target::Native, 1u32 << bit));
    let cases = std::iter::once((Target::Native, 0))
        .chain(native)
        .chain(std::iter::once((Target::WasmClient, 0)));
    for (target, mask) in cases {
        let prog = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                uses_time: true,
                ..module_for_mask(main, mask)
            }],
        };
        let selected = RustBackend::new(&interner)
            .with_target(target)
            .runtime_feature_names(&prog)
            .expect("runtime_feature_names must succeed for a body-free program");
        assert!(
            resolve_features(&selected, &table).contains("time-core"),
            "a uses_time program ({target:?}, mask {mask:#b}) must enable `time-core`: {selected:?}"
        );
        for feature in &selected {
            assert!(
                *feature != "time" && !dead.iter().any(|d| d.as_str() == *feature),
                "a uses_time program ({target:?}, mask {mask:#b}) selects the dead \
                 feature `{feature}`: {selected:?}"
            );
        }
        for dep in [false, true] {
            let toml = time_program_cargo_toml(&interner, &prog, target, dep);
            let code_lines = toml
                .lines()
                .filter(|l| !l.trim_start().starts_with('#'))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                !code_lines.contains("chrono-tz") && !code_lines.contains("chrono_tz"),
                "a uses_time manifest ({target:?}, mask {mask:#b}, dependency model {dep}) \
                 names `chrono-tz`:\n{toml}"
            );
            assert!(
                !code_lines
                    .lines()
                    .any(|l| l.trim_start().starts_with("time = ")),
                "a uses_time manifest ({target:?}, mask {mask:#b}, dependency model {dep}) \
                 declares a `time` feature:\n{toml}"
            );
        }
    }
}
