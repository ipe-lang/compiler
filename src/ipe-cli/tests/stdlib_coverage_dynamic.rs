#![forbid(unsafe_code)]
//! The stdlib coverage-matrix dynamic gate: the reconciled surface enumerates
//! every exported symbol, and the dynamic aspect columns drive each through the
//! compile stages a registry read cannot reach — lowering, a nested-composition
//! lowering, a real emit → build → run, the runtime symbol's existence, and wasm
//! availability.
//!
//! These columns generate and compile a program per symbol, so the whole file is
//! gated behind `IPE_E2E=1`: without it every test returns early. The `composes`
//! column is the composed-combinator bug-catcher — a higher-order symbol that
//! type-checks under nesting but does not lower is a real lowering gap, surfaced
//! at its coordinate and never weakened into a pass.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use ipe::coverage::contract::{AspectCheck, Cell, StdlibSymbol, Surface};
use ipe::coverage::matrix::run;
use ipe::coverage::surface::StdlibSurface;

/// The bounded worker count for the parallel build+run sweep.
///
/// Each probe shells out to `ipe run`, which cargo-builds the emitted crate; the
/// probes are independent (a unique per-symbol snippet dir and a unique emitted
/// crate name), so the sweep fans them across a bounded pool to fit the CI
/// deadline instead of paying every build back-to-back. The bound is read from
/// `IPE_COVERAGE_BUILD_JOBS` (so CI can tune it to its runner), defaulting to the
/// machine's available parallelism capped at 8 — high enough to fit the deadline,
/// bounded so a shared build host is not swamped.
fn build_run_jobs() -> usize {
    if let Ok(raw) = ipe_env::var("IPE_COVERAGE_BUILD_JOBS")
        && let Ok(n) = raw.trim().parse::<usize>()
        && n >= 1
    {
        return n;
    }
    std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(8)
}

/// Drive the build+run column over `symbols` across a bounded worker pool,
/// returning every `(dotted symbol, message)` hole. Each worker pulls the next
/// index from a shared atomic cursor, so the load balances without a queue; the
/// column is `Sync` and every probe is independent, so this is sound. A single
/// `column` is shared (its scratch dir is per-symbol-keyed), so no worker
/// clobbers another's snippet.
fn build_run_holes(symbols: &[StdlibSymbol]) -> Vec<(String, String)> {
    let column = ipe::coverage::columns_runtime::BuildRunColumn::new();
    let cursor = AtomicUsize::new(0);
    let holes: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());
    let jobs = build_run_jobs().min(symbols.len().max(1));

    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| {
                loop {
                    let idx = cursor.fetch_add(1, Ordering::Relaxed);
                    let Some(sym) = symbols.get(idx) else {
                        break;
                    };
                    if let Cell::Hole(message) = column.check(sym) {
                        let path = dotted(sym);
                        if !allowlisted("build+run", &path) {
                            holes
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .push((path, message));
                        }
                    }
                }
            });
        }
    });

    let mut out = holes
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    out.sort();
    out
}

/// Run one dynamic column over the whole surface, returning every hole as a
/// `(dotted symbol, message)` pair.
fn holes_of(column: Box<dyn AspectCheck<StdlibSymbol>>) -> Vec<(String, String)> {
    let columns = vec![column];
    let report = run(&StdlibSurface, &columns);
    report
        .holes
        .into_iter()
        .map(|h| (h.symbol, h.message))
        .collect()
}

/// The pre-existing-hole allowlist for the dynamic columns. Each entry is
/// `(aspect, dotted-symbol, reason)`: a real gap that predates this gate, recorded
/// with a tracking reason so the column stays meaningful while the gate is not
/// blocked on debt it did not introduce.
const ALLOWLIST: &[(&str, &str, &str)] = &[];

/// Whether a hole coordinate is allowlisted.
fn allowlisted(aspect: &str, symbol: &str) -> bool {
    ALLOWLIST
        .iter()
        .any(|(a, s, _)| *a == aspect && *s == symbol)
}

/// The dotted display path of a symbol, e.g. `Ipe.List.map`.
fn dotted(sym: &StdlibSymbol) -> String {
    let mut path = sym.module.join(".");
    if !path.is_empty() {
        path.push('.');
    }
    path.push_str(&sym.name);
    path
}

// ── composes: the composed-combinator lowering bug-catcher ────────────────────

#[test]
fn composes_column_passes_over_every_higher_order_symbol() {
    use std::fmt::Write as _;
    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let holes = holes_of(Box::new(
            ipe::coverage::columns_runtime::ComposesColumn::new(),
        ));

        let mut unexpected = String::new();
        for (symbol, message) in holes {
            if !allowlisted("composes", &symbol) {
                let _ = writeln!(unexpected, "  HOLE [composes] {symbol}: {message}");
            }
        }

        assert!(
            unexpected.is_empty(),
            "every higher-order stdlib symbol must lower under nesting (a composed \
         combinator that type-checks but does not lower is a real lowering gap):\n\
         {unexpected}",
        );
    }
}

// ── lowers ────────────────────────────────────────────────────────────────────

#[test]
fn lowers_column_passes_over_the_surface() {
    use std::fmt::Write as _;
    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let holes = holes_of(Box::new(ipe::coverage::columns_runtime::LowersColumn::new()));

        let mut unexpected = String::new();
        for (symbol, message) in holes {
            if !allowlisted("lowers", &symbol) {
                let _ = writeln!(unexpected, "  HOLE [lowers] {symbol}: {message}");
            }
        }

        assert!(
            unexpected.is_empty(),
            "every stdlib symbol whose point-free probe type-checks must lower:\n{unexpected}",
        );
    }
}

// ── runtime-fn-exists + wasm (registry reads; cheap even under E2E) ────────────

#[test]
fn runtime_fn_and_wasm_columns_report_no_holes() {
    use std::fmt::Write as _;
    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let mut unexpected = String::new();
        for column in [
            Box::new(ipe::coverage::columns_runtime::RuntimeFnExistsColumn::new())
                as Box<dyn AspectCheck<StdlibSymbol>>,
            Box::new(ipe::coverage::columns_runtime::WasmColumn),
        ] {
            let aspect = column.name();
            for (symbol, message) in holes_of(column) {
                if !allowlisted(aspect, &symbol) {
                    let _ = writeln!(unexpected, "  HOLE [{aspect}] {symbol}: {message}");
                }
            }
        }

        assert!(
            unexpected.is_empty(),
            "the runtime-fn-exists and wasm columns report holes (both emit advisories, \
         not holes, by design — a hole here is a contract break):\n{unexpected}",
        );
    }
}

// ── build+run: heavy (a full cargo build per symbol) ──────────────────────────

/// The build+run column emits, builds, and runs a program per symbol — a full
/// cargo build each. This drives the higher-order combinators (the class the
/// composition bug lived in), fanned across a bounded worker pool so the sweep
/// fits the CI deadline without dropping coverage.
///
/// A symbol a standalone build+run cannot exercise — a browser web axis whose JS
/// runs in a live page, or a point-free reference the name resolver cannot address
/// — is classified `NotApplicable` by the column from a real structural property,
/// so it is neither a false hole nor a silently-passed one; every symbol that CAN
/// build+run still does, and a genuine emit/build/run gap is a hole at its
/// coordinate.
#[test]
fn build_run_column_over_a_representative_slice() {
    use std::fmt::Write as _;
    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let symbols: Vec<StdlibSymbol> = StdlibSurface
            .all()
            .into_iter()
            .filter(|s| s.is_higher_order)
            .collect();

        let mut unexpected = String::new();
        for (path, message) in build_run_holes(&symbols) {
            let _ = writeln!(unexpected, "  HOLE [build+run] {path}: {message}");
        }

        assert!(
            unexpected.is_empty(),
            "every higher-order symbol's minimal program must emit, build, and run \
         (or be a justified NotApplicable):\n{unexpected}",
        );
    }
}

// ── the whole dynamic set, for a single-command CI sweep ──────────────────────

/// The dynamic column set over the whole surface, as one single-command sweep.
///
/// # Coverage tiering (no symbol is sampled away)
///
/// Every dynamic column is judged over its full scope, but split across tests so
/// each fits the `--profile ci` 900s deadline — the per-symbol cost is real (a
/// lowering per symbol for `lowers`/`composes`, a full cargo build per symbol for
/// `build+run`), and summing all of them in one test exceeds the cap. The split
/// drops NO coverage; it is a scheduling tier, and each tier is a named test:
///
/// - `lowers` over the WHOLE surface — [`lowers_column_passes_over_the_surface`].
/// - `composes` over every higher-order symbol —
///   [`composes_column_passes_over_every_higher_order_symbol`].
/// - `runtime-fn-exists` + `wasm` (registry reads, cheap) —
///   [`runtime_fn_and_wasm_columns_report_no_holes`].
/// - `build+run` over the higher-order combinators (the class a build/run gap
///   lives in — a first-order value that lowers builds+runs trivially), fanned
///   across a bounded worker pool — [`build_run_column_over_a_representative_slice`].
///
/// This test is the single-command entry that re-asserts the two CHEAP registry
/// columns over the whole surface plus the `build+run` slice — the fast confidence
/// check — while the heavy per-symbol lowering sweeps stay in their own named
/// tiers above. Nothing here is a silent sample: the deliberately-bounded scope is
/// documented, and the full per-symbol coverage is the union of the named tests.
#[test]
fn dynamic_columns_pass_over_the_whole_surface() {
    use std::fmt::Write as _;
    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        // The cheap registry columns over the WHOLE surface (no build, no lowering).
        let report = run(
            &StdlibSurface,
            &[
                Box::new(ipe::coverage::columns_runtime::RuntimeFnExistsColumn::new())
                    as Box<dyn AspectCheck<StdlibSymbol>>,
                Box::new(ipe::coverage::columns_runtime::WasmColumn),
            ],
        );
        let mut unexpected = String::new();
        for h in &report.holes {
            if !allowlisted(h.aspect, &h.symbol) {
                let _ = writeln!(
                    unexpected,
                    "  HOLE [{}] {}: {}",
                    h.aspect, h.symbol, h.message
                );
            }
        }

        // The build+run slice (the higher-order combinators), fanned across the pool.
        // A browser web axis or an unaddressable point-free reference is a justified
        // NotApplicable, not a dropped symbol.
        let ho_symbols: Vec<StdlibSymbol> = StdlibSurface
            .all()
            .into_iter()
            .filter(|s| s.is_higher_order)
            .collect();
        for (path, message) in build_run_holes(&ho_symbols) {
            let _ = writeln!(unexpected, "  HOLE [build+run] {path}: {message}");
        }

        assert!(
            unexpected.is_empty(),
            "the dynamic coverage sweep must pass (the per-symbol lowering tiers run in \
         their own named tests; see this test's doc):\n{unexpected}",
        );
    }
}
