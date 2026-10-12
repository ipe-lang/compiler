//! The one descriptor table the runtime-feature-set walks read.
//!
//! Which `ipe-runtime-rust` cargo features a program selects used to be spelled
//! out as parallel `if <flag> { set.insert(<feature>) }` sequences — once for a
//! native target, once for the `wasm32-wasip1` sealed-floor subset. Two hand-
//! synced walks over the SAME predicate→feature mapping: a feature wired into
//! one but forgotten in the other is an ipe-accepts-then-cargo-fails gap.
//!
//! [`CAPABILITIES`] states that mapping ONCE. Each row pairs a gate (a
//! [`EmitCtx`] `reaches_*` / `uses_*` predicate) with the [`RuntimeFeature`] it
//! selects and whether that feature is legal on the wasip1 sealed floor. Both
//! builders in [`crate::runtime_features`] iterate this single table, so the
//! native set and the wasip1 subset can never disagree about which predicate
//! selects a feature.
//!
//! Coverage is fail-closed by construction: a build-time `const` assertion (at
//! the foot of this file) proves every [`RuntimeFeature`] variant appears in some
//! row's [`RuntimeCapability::covers`], so a new feature added without a row
//! breaks the BUILD — the SEAL "a table drifted from its callee table" clause —
//! rather than silently dropping from a feature set two steps downstream at cargo
//! time.

use crate::EmitCtx;
use crate::runtime_features::RuntimeFeature;

/// One runtime-crate capability: the gate that decides whether a program selects
/// it, the concrete [`RuntimeFeature`] it selects, and whether that feature is
/// legal on the `wasm32-wasip1` sealed floor.
///
/// `select` is a closure — not a bare feature value — so a capability whose
/// concrete feature depends on the [`EmitCtx`] (the `Db` row, resolving to the
/// sqlite or postgres driver alias) stays a single row. It is only ever consulted
/// when `gate` returns `true`. `covers` names every feature `select` can return,
/// so the drift assert can prove coverage without evaluating the (ctx-reading)
/// closure in a `const` context.
pub struct RuntimeCapability {
    /// Whether the program reaches this capability. The same `reaches_*` /
    /// `uses_*` union the hand-written walks keyed on, so the derivation is
    /// byte-identical to the pre-table sequences.
    pub gate: fn(&EmitCtx) -> bool,
    /// The concrete feature this capability selects when `gate` holds. A closure
    /// rather than a value so the `Db` driver split (sqlite vs postgres) lives in
    /// one row instead of forking the table.
    pub select: fn(&EmitCtx) -> RuntimeFeature,
    /// Every feature `select` can return — one element for a fixed row, both
    /// driver aliases for the `Db` row. The drift assert folds this over the whole
    /// table and checks it equals [`RuntimeFeature::ALL`].
    pub covers: &'static [RuntimeFeature],
    /// `true` when the feature is part of the `wasm32-wasip1` sealed-floor
    /// closure — the pure families plus the always-on effect floor. The tokio/
    /// axum/reqwest/sqlx stacks do NOT build on wasip1, so their rows are
    /// `false`: the wasip1 builder filters on this flag, giving the positive,
    /// closed legal subset as defense in depth even if an upstream gate mis-set a
    /// flag (see [`crate::runtime_features::runtime_features`]).
    pub wasip1_legal: bool,
}

/// Every runtime capability, one row per capability the feature-set walks select.
/// The `Async`, `Debugger`, `DevPosture`, and `WasmClient` features are
/// build-mode / target selections rather than reachability, so their rows carry
/// the exact gates the native/wasm builders apply.
///
/// Row order is irrelevant to correctness: the feature set is a sorted
/// [`std::collections::BTreeSet`], so the emitted `features = [...]` list is
/// canonical regardless of iteration order.
pub const CAPABILITIES: &[RuntimeCapability] = &[
    RuntimeCapability {
        gate: |ctx| ctx.reaches_json(),
        select: |_| RuntimeFeature::Json,
        covers: &[RuntimeFeature::Json],
        wasip1_legal: true,
    },
    RuntimeCapability {
        gate: |ctx| ctx.uses_async_runtime,
        select: |_| RuntimeFeature::Async,
        covers: &[RuntimeFeature::Async],
        wasip1_legal: false,
    },
    RuntimeCapability {
        gate: |ctx| ctx.uses_db,
        select: |ctx| match ctx.db_driver {
            crate::DbDriver::Sqlite => RuntimeFeature::DbSqlite,
            crate::DbDriver::Postgres => RuntimeFeature::DbPostgres,
        },
        covers: &[RuntimeFeature::DbSqlite, RuntimeFeature::DbPostgres],
        wasip1_legal: false,
    },
    RuntimeCapability {
        gate: |ctx| ctx.uses_server || ctx.uses_web,
        select: |_| RuntimeFeature::Server,
        covers: &[RuntimeFeature::Server],
        wasip1_legal: false,
    },
    RuntimeCapability {
        gate: |ctx| ctx.uses_web,
        select: |_| RuntimeFeature::Web,
        covers: &[RuntimeFeature::Web],
        wasip1_legal: false,
    },
    RuntimeCapability {
        gate: |ctx| ctx.uses_tui || ctx.uses_console,
        select: |_| RuntimeFeature::Tui,
        covers: &[RuntimeFeature::Tui],
        wasip1_legal: false,
    },
    RuntimeCapability {
        gate: |ctx| ctx.uses_webview,
        select: |_| RuntimeFeature::Webview,
        covers: &[RuntimeFeature::Webview],
        wasip1_legal: false,
    },
    RuntimeCapability {
        gate: |ctx| ctx.uses_websocket,
        select: |_| RuntimeFeature::WebsocketClient,
        covers: &[RuntimeFeature::WebsocketClient],
        wasip1_legal: false,
    },
    RuntimeCapability {
        gate: |ctx| ctx.uses_email,
        select: |_| RuntimeFeature::Email,
        covers: &[RuntimeFeature::Email],
        wasip1_legal: false,
    },
    RuntimeCapability {
        gate: |ctx| ctx.uses_locale,
        select: |_| RuntimeFeature::Locale,
        covers: &[RuntimeFeature::Locale],
        wasip1_legal: false,
    },
    RuntimeCapability {
        gate: |ctx| ctx.reaches_http_client(),
        select: |_| RuntimeFeature::HttpClient,
        covers: &[RuntimeFeature::HttpClient],
        wasip1_legal: false,
    },
    RuntimeCapability {
        gate: |ctx| ctx.reaches_url(),
        select: |_| RuntimeFeature::Url,
        covers: &[RuntimeFeature::Url],
        wasip1_legal: false,
    },
    RuntimeCapability {
        gate: |ctx| ctx.uses_config,
        select: |_| RuntimeFeature::Config,
        covers: &[RuntimeFeature::Config],
        wasip1_legal: false,
    },
    RuntimeCapability {
        gate: |ctx| ctx.uses_compression,
        select: |_| RuntimeFeature::Compression,
        covers: &[RuntimeFeature::Compression],
        wasip1_legal: false,
    },
    RuntimeCapability {
        gate: |ctx| ctx.uses_csv,
        select: |_| RuntimeFeature::CsvKernel,
        covers: &[RuntimeFeature::CsvKernel],
        wasip1_legal: false,
    },
    RuntimeCapability {
        gate: |ctx| ctx.uses_cache,
        select: |_| RuntimeFeature::CacheKernel,
        covers: &[RuntimeFeature::CacheKernel],
        wasip1_legal: false,
    },
    RuntimeCapability {
        gate: |ctx| ctx.uses_time,
        select: |_| RuntimeFeature::Time,
        covers: &[RuntimeFeature::Time],
        wasip1_legal: true,
    },
    RuntimeCapability {
        gate: |ctx| ctx.reaches_encoding(),
        select: |_| RuntimeFeature::Encoding,
        covers: &[RuntimeFeature::Encoding],
        wasip1_legal: true,
    },
    RuntimeCapability {
        gate: |ctx| ctx.uses_regex,
        select: |_| RuntimeFeature::Regex,
        covers: &[RuntimeFeature::Regex],
        wasip1_legal: true,
    },
    RuntimeCapability {
        gate: |ctx| ctx.reaches_uuid(),
        select: |_| RuntimeFeature::Uuid,
        covers: &[RuntimeFeature::Uuid],
        wasip1_legal: true,
    },
    RuntimeCapability {
        gate: |ctx| ctx.reaches_random(),
        select: |_| RuntimeFeature::Random,
        covers: &[RuntimeFeature::Random],
        wasip1_legal: true,
    },
    RuntimeCapability {
        gate: |ctx| ctx.reaches_log(),
        select: |_| RuntimeFeature::Log,
        covers: &[RuntimeFeature::Log],
        wasip1_legal: true,
    },
    RuntimeCapability {
        gate: |ctx| ctx.reaches_time_core(),
        select: |_| RuntimeFeature::TimeCore,
        covers: &[RuntimeFeature::TimeCore],
        wasip1_legal: true,
    },
    RuntimeCapability {
        gate: |ctx| ctx.reaches_decimal(),
        select: |_| RuntimeFeature::Decimal,
        covers: &[RuntimeFeature::Decimal],
        wasip1_legal: true,
    },
    RuntimeCapability {
        gate: |ctx| ctx.reaches_char_category(),
        select: |_| RuntimeFeature::CharCategory,
        covers: &[RuntimeFeature::CharCategory],
        wasip1_legal: true,
    },
    RuntimeCapability {
        gate: |ctx| ctx.uses_crypto,
        select: |_| RuntimeFeature::Crypto,
        covers: &[RuntimeFeature::Crypto],
        wasip1_legal: false,
    },
    RuntimeCapability {
        gate: |ctx| ctx.reaches_crypto_core(),
        select: |_| RuntimeFeature::CryptoCore,
        covers: &[RuntimeFeature::CryptoCore],
        wasip1_legal: true,
    },
    RuntimeCapability {
        gate: |ctx| ctx.reaches_secret(),
        select: |_| RuntimeFeature::Secret,
        covers: &[RuntimeFeature::Secret],
        wasip1_legal: true,
    },
    RuntimeCapability {
        gate: |ctx| ctx.reaches_jwt(),
        select: |_| RuntimeFeature::Jwt,
        covers: &[RuntimeFeature::Jwt],
        wasip1_legal: false,
    },
    RuntimeCapability {
        gate: |ctx| ctx.debugger,
        select: |_| RuntimeFeature::Debugger,
        covers: &[RuntimeFeature::Debugger],
        wasip1_legal: false,
    },
    // The loopback dev-loop control channel for a repaintable TERMINAL shape. A
    // `Tui.tea` app has no HTTP control port, so its appearance hot-swap rides the
    // `control-wire` loopback socket instead. Selected ONLY for an `ipe dev watch`
    // build of a tui view: `hot_appearance` AND `uses_tui`. A plain `ipe dev build` /
    // `ipe release` arms no dev-loop flag, so a production terminal artifact
    // selects it not — the control server is absent from production by
    // construction (dev == prod by absence).
    //
    // A cli (`uses_console`) is excluded: it has no repaintable appearance
    // surface to hot-swap, and its dev-loop debugger records to the
    // `IPE_DEBUGGER_RECORD` dump at loop exit rather than driving the control
    // socket accept-loop. The `debugger` flag is likewise NOT a disjunct here:
    // the `debugger` Cargo feature already implies `control-wire` in the crate
    // graph (`debugger = ["control-wire", …]`), so a `--debugger` build pulls the
    // control codec transitively without this row — this row is the pure-
    // `hot_appearance` tui selector, never double-counting (the feature set is a
    // set). The web shape reaches the control module through its `server` feature.
    RuntimeCapability {
        gate: |ctx| ctx.hot_appearance && ctx.uses_tui,
        select: |_| RuntimeFeature::ControlWire,
        covers: &[RuntimeFeature::ControlWire],
        wasip1_legal: false,
    },
    // The dev-loop build intent: the one input that lets the runtime console
    // default open (and only on a loopback bind). A release emit selects it not,
    // so a shipped binary has no development console default.
    RuntimeCapability {
        gate: |ctx| ctx.build_intent == crate::BuildIntent::Development,
        select: |_| RuntimeFeature::DevPosture,
        covers: &[RuntimeFeature::DevPosture],
        wasip1_legal: true,
    },
    RuntimeCapability {
        gate: |ctx| ctx.target == ipe_ir::Target::WasmClient,
        select: |_| RuntimeFeature::WasmClient,
        covers: &[RuntimeFeature::WasmClient],
        wasip1_legal: false,
    },
];

/// `true` when `feature` appears in some [`CAPABILITIES`] row's `covers`.
const fn feature_has_a_row(feature: RuntimeFeature) -> bool {
    let mut rows = CAPABILITIES;
    while let [row, rest @ ..] = rows {
        let mut covers = row.covers;
        while let [covered, tail @ ..] = covers {
            if covered.const_eq(feature) {
                return true;
            }
            covers = tail;
        }
        rows = rest;
    }
    false
}

/// `true` when every [`RuntimeFeature`] variant has a [`CAPABILITIES`] row.
const fn every_feature_has_a_row() -> bool {
    let mut rest = RuntimeFeature::ALL;
    while let [first, tail @ ..] = rest {
        if !feature_has_a_row(*first) {
            return false;
        }
        rest = tail;
    }
    true
}

/// `true` when some [`RuntimeFeature::ALL`] entry has the given `index`.
const fn all_contains_index(index: usize) -> bool {
    let mut rest = RuntimeFeature::ALL;
    while let [first, tail @ ..] = rest {
        if first.index() == index {
            return true;
        }
        rest = tail;
    }
    false
}

/// `true` when [`RuntimeFeature::ALL`] covers every index in the
/// [`RuntimeFeature::index`] domain.
///
/// The domain size comes from the exhaustive `index` match
/// ([`RuntimeFeature::index_domain_size`]), never from `ALL.len()`: a variant
/// present in `index` but missing from `ALL` leaves its index uncovered here, so
/// the build breaks. This is what forces a newly added variant — already forced
/// into the exhaustive `index` match — into `ALL` as well, keeping the drift
/// assert above non-vacuous.
const fn all_covers_index_domain() -> bool {
    let mut index = 0;
    while index < RuntimeFeature::index_domain_size() {
        if !all_contains_index(index) {
            return false;
        }
        index += 1;
    }
    true
}

// IPE-RUST-AUDIT:ACCEPTED — build-time drift tripwire, not a runtime panic. Both
// conjuncts are evaluated in a `const` context, so they fire at COMPILE time.
// `every_feature_has_a_row`: a `RuntimeFeature` variant lacking a capability row
// breaks the build (a row with no feature would otherwise silently drop from
// every runtime feature set — SEAL: table drifted from its callee table).
// `all_covers_index_domain`: `ALL` must cover the whole `index` domain, so a
// variant added to the exhaustive `index` match but forgotten in `ALL` breaks
// the build instead of leaving the drift assert vacuously true over a short
// `ALL`.
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    every_feature_has_a_row() && all_covers_index_domain(),
    "every RuntimeFeature variant must have a CAPABILITIES row, and \
     RuntimeFeature::ALL must cover the whole RuntimeFeature::index domain"
);
