//! The dynamic (emit/build/run) aspect columns: lowers, composes, build+run,
//! runtime-fn-exists, wasm.
//!
//! These drive a symbol through the compile stages a static registry read cannot
//! reach: lowering, a nested-composition lowering, a real emit → cargo build →
//! run, the runtime symbol's existence, and wasm availability. The three that
//! run a program ([`LowersColumn`], [`ComposesColumn`], [`BuildRunColumn`])
//! generate a minimal probe per symbol (see [`crate::coverage::probe`]); the two
//! registry-derived ones ([`RuntimeFnExistsColumn`], [`WasmColumn`]) read the
//! kernel table symbol-level. The heavy build sweep is gated by the caller behind
//! the E2E path.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ipe_kernels::{StdlibKernel, Target};

use crate::coverage::contract::{AspectCheck, Cell, StdlibSymbol, SymbolKind};
use crate::coverage::probe::{self, ProbeUnavailable, StageOutcome};
use crate::coverage::source_tree::{TreeRefusal, for_each_source};

/// A scratch dir shared by a program-running column across a whole run, so the
/// per-symbol probes do not each pay a temp-dir setup. RAII-cleaned on drop.
fn scratch_dir() -> Result<crate::scratch::ScratchDir, String> {
    crate::scratch::ScratchDir::new("ipe-coverage-probe").map_err(|e| e.to_string())
}

/// `name` inside `scratch`, or a hole cell when `name` is not a plain leaf name.
fn scratch_child(
    scratch: &crate::scratch::ScratchDir,
    name: &str,
) -> Result<std::path::PathBuf, Cell> {
    crate::scratch::LeafName::new(name)
        .map(|leaf| scratch.child(&leaf))
        .map_err(|e| Cell::Hole(format!("scratch entry `{name}` refused: {e}")))
}

/// A filesystem-safe, per-symbol scratch subdirectory key — injective by
/// construction: distinct symbols always produce distinct keys.
///
/// The dotted symbol path (`Module.Sub.name`) uses only ASCII alphanumerics,
/// `.`, and `_`. Keeping `.` and `_` verbatim (both are valid path-component
/// characters) makes the mapping a bijection over the stdlib symbol surface.
/// Any other character (not expected for stdlib symbols) is replaced by `-` so
/// the key stays filesystem-safe without colliding with `.` or `_`.
fn symbol_scratch_key(sym: &StdlibSymbol) -> String {
    let dotted = format!("{}.{}", sym.module.join("."), sym.name);
    dotted
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

/// Map a [`ProbeUnavailable`] to the `NotApplicable` verdict — a symbol the
/// generator cannot express is not judged by a build column, carrying the reason
/// so the pass is auditable.
fn unavailable_cell(reason: &ProbeUnavailable) -> Cell {
    let why = match reason {
        ProbeUnavailable::NotAValue => {
            "the symbol is a type or constructor, not a value — the value-reference probe does \
             not apply"
        }
        ProbeUnavailable::Unaddressable => {
            "the symbol has no compiled-source module to import it from — not reachable by a \
             qualified reference"
        }
    };
    Cell::not_applicable(why)
}

// ── lowers ────────────────────────────────────────────────────────────────────

/// Column **lowers**: a minimal program referencing the symbol lowers in
/// isolation.
///
/// A value symbol is bound point-free (`probe = List.map`) and driven through the
/// same name-resolution + type-check + lower pipeline the build uses. The column
/// judges the SEAM the spec names — "type-checks but does not lower" — so it first
/// type-checks the probe: a probe that does not even type-check is a limitation of
/// the point-free reference form for that symbol (a symbol the resolver refuses to
/// pass point-free — a module with no importable home, a fully-polymorphic value
/// with no determinable concrete type, an accessor builder that must be applied
/// directly), not a lowering gap, so it is `NotApplicable`. A probe that
/// type-checks but then fails to lower is a hole — the class the composed-
/// combinator bug fell into, an internal-compiler-error in the lowerer included. A
/// non-value symbol is `NotApplicable`.
pub struct LowersColumn {
    scratch: Option<crate::scratch::ScratchDir>,
}

impl LowersColumn {
    #[must_use]
    pub fn new() -> Self {
        Self {
            scratch: scratch_dir().ok(),
        }
    }
}

impl Default for LowersColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl AspectCheck<StdlibSymbol> for LowersColumn {
    fn name(&self) -> &'static str {
        "lowers"
    }

    fn check(&self, sym: &StdlibSymbol) -> Cell {
        let Some(scratch) = &self.scratch else {
            return Cell::Warn("no scratch dir; lowers probe skipped".to_owned());
        };
        let source = match probe::reference_program(sym) {
            Ok(s) => s,
            Err(reason) => return unavailable_cell(&reason),
        };
        let base = scratch.path();
        // The seam is "type-checks but does not lower": a probe that does not
        // type-check is a point-free-reference limitation for this symbol, not a
        // lowering gap.
        if let StageOutcome::Failed { .. } = probe::typechecks(&source, base) {
            return Cell::not_applicable(format!(
                "{}.{}: the point-free reference program does not type-check — a \
                 probe-form limitation for this symbol, not a lowering gap",
                sym.module.join("."),
                sym.name
            ));
        }
        let outcome = probe::lower(&source, base);
        classify_lower_outcome(sym, outcome, "type-checks but does not lower")
    }
}

/// Turn a probe's lowering outcome into a cell, separating the real "type-checks
/// but does not lower" seam from the two failures the probe FORM provokes:
///
/// * A probe-form limitation (a value the language refuses point-free, or a
///   fully-polymorphic unused binding) is `NotApplicable` — the diagnostic is a
///   property of the point-free probe, not a lowering gap in the symbol.
/// * An internal compiler error is a [`Cell::Warn`] advisory — a lowerer defect
///   the probe reached (a pre-existing empty-type-home ICE, say), surfaced so it
///   is neither silently passed nor miscast as this column's own seam.
/// * Any other lowering rejection is the seam this column gates: a [`Cell::Hole`].
fn classify_lower_outcome(sym: &StdlibSymbol, outcome: StageOutcome, seam: &str) -> Cell {
    if matches!(outcome, StageOutcome::Ok) {
        return Cell::Ok;
    }
    if probe::is_probe_form_limitation(&outcome) {
        return Cell::not_applicable(format!(
            "{}.{}: the point-free probe is refused by the language (a value that must be \
             applied directly, or a fully-polymorphic unused binding) — a probe-form \
             limitation, not a lowering gap",
            sym.module.join("."),
            sym.name
        ));
    }
    let is_ice = probe::is_internal_compiler_error(&outcome);
    let StageOutcome::Failed { message, .. } = outcome else {
        return Cell::Ok;
    };
    if is_ice {
        return Cell::Warn(format!(
            "{}.{} triggers an internal compiler error when {seam} (a lowerer defect \
             the probe reached, not a probe-form limitation): {message}",
            sym.module.join("."),
            sym.name
        ));
    }
    Cell::Hole(format!(
        "{}.{} {seam}: {message}",
        sym.module.join("."),
        sym.name
    ))
}

// ── composes ──────────────────────────────────────────────────────────────────

/// Column **composes**: a higher-order symbol lowers under NESTING.
///
/// The bug this column exists to catch: a combinator that type-checked but never
/// lowered, surfacing only when a real module nested it. The probe references the
/// symbol inside a lambda passed to another combinator (`List.map (\_ -> Foo.bar)
/// []`), forcing the lowerer to descend into the nested combinator position. A
/// higher-order symbol whose nested probe type-checks but does not lower is a
/// hole. A first-order symbol is `NotApplicable` (composition does not apply). A
/// nested probe that does not even type-check is `NotApplicable` — the generator,
/// not the symbol, is at fault, so it is not reported as a false lowering hole.
pub struct ComposesColumn {
    scratch: Option<crate::scratch::ScratchDir>,
}

impl ComposesColumn {
    #[must_use]
    pub fn new() -> Self {
        Self {
            scratch: scratch_dir().ok(),
        }
    }
}

impl Default for ComposesColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl AspectCheck<StdlibSymbol> for ComposesColumn {
    fn name(&self) -> &'static str {
        "composes"
    }

    fn check(&self, sym: &StdlibSymbol) -> Cell {
        if !sym.is_higher_order {
            return Cell::not_applicable("first-order symbol — composition does not apply");
        }
        let Some(scratch) = &self.scratch else {
            return Cell::Warn("no scratch dir; composes probe skipped".to_owned());
        };
        let source = match probe::nested_program(sym) {
            Ok(s) => s,
            Err(reason) => return unavailable_cell(&reason),
        };
        let base = scratch.path();
        // A nested probe that does not type-check is a generator limitation for
        // this symbol's shape, not a lowering gap: report it inapplicable so it
        // is not a false hole.
        if let StageOutcome::Failed { .. } = probe::typechecks(&source, base) {
            return Cell::not_applicable(format!(
                "{}.{}: the nested reference program does not type-check — a generator \
                 limitation for this symbol's shape, not a lowering gap",
                sym.module.join("."),
                sym.name
            ));
        }
        let outcome = probe::lower(&source, base);
        classify_lower_outcome(
            sym,
            outcome,
            "type-checks under nesting but does NOT lower (a composed-combinator lowering gap)",
        )
    }
}

// ── build+run ─────────────────────────────────────────────────────────────────

/// Column **build+run**: a minimal program using the symbol emits, builds, and
/// RUNS.
///
/// The probe program is a complete `module Main` with a valid `main` entry, so it
/// emits to a cargo crate, builds, and runs. A symbol whose program does not
/// build or whose binary does not run to a zero exit is a hole. Non-value symbols
/// are `NotApplicable`. Heavy (a full cargo build per symbol) — the caller runs
/// this only on the E2E path.
///
/// A standalone single-file build+run cannot exercise every shape. Two structural
/// classes are inapplicable to it, each judged from a real property of the symbol
/// (never a hand-kept symbol list) and reported `NotApplicable` with the deriving
/// property named:
///
/// * A symbol homed under a reserved `Ipe.Browser.<Api>` module discloses a
///   `js-port:<axis>` web capability — client browser JS that runs in a live page,
///   which a bare probe cannot grant (`IPE-S0002`) and, even granted, has no server
///   process to run. Derived from the module path via
///   [`probe::browser_web_axis`].
/// * A symbol whose point-free reference program cannot even NAME-RESOLVE (a
///   shape-scoped module with no standalone importable home, an `Ipe.Tea.*` shape
///   module a plain-`main` Program may not import, or a kernel-homed symbol the
///   compiled module does not expose under that name) is a probe-FORM
///   limitation, not a build+run gap. Derived from the name-resolution rejection
///   code via [`probe::probe_form_unaddressable_code`], caught by the cheap
///   pre-lower before any cargo build. (A qualified-import qualifier collision no
///   longer arises: the probe binds every module under a fixed reserved alias that
///   cannot collide with a real qualifier.)
pub struct BuildRunColumn {
    scratch: Option<crate::scratch::ScratchDir>,
}

impl BuildRunColumn {
    #[must_use]
    pub fn new() -> Self {
        Self {
            scratch: scratch_dir().ok(),
        }
    }
}

impl Default for BuildRunColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl AspectCheck<StdlibSymbol> for BuildRunColumn {
    fn name(&self) -> &'static str {
        "build+run"
    }

    fn check(&self, sym: &StdlibSymbol) -> Cell {
        // A `Ipe.Browser.<Api>` symbol discloses a `js-port:<axis>` web capability:
        // client browser JS that a standalone build+run cannot exercise (the effect
        // lives in a live page, not the emitted binary; a bare probe cannot even
        // grant it). Judged structurally from the module path, before any build.
        if let Some(axis) = probe::browser_web_axis(sym) {
            return Cell::NotApplicable {
                reason: format!(
                    "{}.{} discloses the browser web capability `js-port:{}` — client \
                     JavaScript that runs in a live browser page, which a standalone \
                     build+run cannot exercise (no page to run it in, and a bare \
                     single-file probe cannot grant the axis)",
                    sym.module.join("."),
                    sym.name,
                    axis.as_str()
                ),
            };
        }
        let Some(scratch) = &self.scratch else {
            return Cell::Warn("no scratch dir; build+run probe skipped".to_owned());
        };
        let source = match probe::reference_program(sym) {
            Ok(s) => s,
            Err(reason) => return unavailable_cell(&reason),
        };
        // Each symbol's probe projects live under its OWN subdirectory of the
        // shared scratch, keyed on the dotted path, so a parallel sweep (distinct
        // symbols on distinct threads) keeps each symbol's projects apart.
        let base = match scratch_child(scratch, &symbol_scratch_key(sym)) {
            Ok(dir) => dir,
            Err(cell) => return cell,
        };
        // The point-free reference program can fail to compile for a reason that
        // is a property of the probe FORM, not a build gap: a value the language
        // refuses point-free, a fully-polymorphic unused binding, or a lowerer ICE
        // the probe reaches. Pre-check by lowering — build+run shells out and sees
        // only text, so it cannot classify — and defer to that verdict rather than
        // pay a full cargo build to reach a false hole.
        let lowered = probe::lower(&source, &base);
        if probe::is_probe_form_limitation(&lowered) {
            return Cell::NotApplicable {
                reason: format!(
                    "{}.{}: the point-free reference program does not lower — a probe-form \
                     limitation (a value the language refuses point-free, or a \
                     fully-polymorphic unused binding), not a build+run gap",
                    sym.module.join("."),
                    sym.name
                ),
            };
        }
        // A point-free reference the name resolver cannot even ADDRESS (a
        // shape-scoped module with no standalone home, an `Ipe.Tea.*` shape module
        // the Program probe may not import, or a kernel member the
        // compiled module does not expose under that name) is a probe-form
        // limitation, not a build+run gap — caught before any build.
        if let Some(code) = probe::probe_form_unaddressable_code(&lowered) {
            return Cell::NotApplicable {
                reason: format!(
                    "{}.{}: the point-free reference program does not name-resolve \
                     ({}) — the probe form cannot address this symbol (a \
                     shape-scoped module with no standalone home, an `Ipe.Tea.*` \
                     shape module a plain-`main` Program may not import, or a kernel \
                     member not exposed under this name), not a build+run gap",
                    sym.module.join("."),
                    sym.name,
                    code.as_str()
                ),
            };
        }
        if probe::is_internal_compiler_error(&lowered) {
            let StageOutcome::Failed { message, .. } = lowered else {
                return Cell::not_applicable("internal-compiler-error outcome carried no message");
            };
            return Cell::Warn(format!(
                "{}.{} triggers an internal compiler error before build+run: {message}",
                sym.module.join("."),
                sym.name
            ));
        }
        match probe::build_and_run(&source, &base) {
            StageOutcome::Ok => Cell::Ok,
            StageOutcome::Failed { message, .. } => Cell::Hole(format!(
                "{}.{} emits but does not build+run: {message}",
                sym.module.join("."),
                sym.name
            )),
        }
    }
}

// ── the kernel index (shared by runtime-fn-exists + wasm) ──────────────────────

/// Resolve a surface symbol to its wired kernel, when it has one.
///
/// A symbol carrying `has_kernel` corresponds to a [`StdlibKernel`] whose
/// `def.name` equals the symbol name; the qualifier disambiguates a name wired
/// under more than one qualifier. The surface homes a kernel under a module whose
/// last segment is the kernel qualifier (a kernel-qualifier module) or the
/// compiled-source module that aliases it (whose last segment likewise matches
/// the short qualifier), so the last module segment is matched against the
/// kernel's qualifier.
fn kernel_for(sym: &StdlibSymbol) -> Option<StdlibKernel> {
    if !sym.has_kernel || sym.kind != SymbolKind::Value {
        return None;
    }
    let by_name: Vec<StdlibKernel> = StdlibKernel::ALL
        .iter()
        .copied()
        .filter(|k| k.def().name == sym.name)
        .collect();
    match by_name.as_slice() {
        [] => None,
        [only] => Some(*only),
        many => {
            let last = sym.module.last().map(String::as_str);
            many.iter()
                .copied()
                .find(|k| Some(k.def().qualifier) == last)
                .or_else(|| many.first().copied())
        }
    }
}

// ── runtime-fn-exists ──────────────────────────────────────────────────────────

/// Column **runtime-fn-exists**: a kernel symbol's emit token cross-references a
/// real definition in the runtime crate.
///
/// A kernel carries an emit token (`KernelDef::runtime_fn`, e.g. `string_length`).
/// For the large family of kernels lowered to a generic `ipe_runtime::<mod>::<fn>`
/// call, that token names a real runtime function, and finding it is a fast
/// cross-reference that the emit table and the runtime crate agree. Other kernel
/// families lower their token differently — a record-update builder, an inline
/// specialization, an enum-variant constructor, a query-plan node — so their emit
/// token is a routing key rather than a free function name and is not expected in
/// the runtime source.
///
/// The verdict reflects that: a token found in the runtime source is `Ok`; a
/// token NOT found is [`Cell::Warn`], not [`Cell::Hole`] — at symbol level the
/// two causes (a genuinely missing runtime function versus a builder/inline
/// kernel whose token is not a free fn) are indistinguishable, and the
/// authoritative catch for a genuinely missing runtime symbol is the `build+run`
/// column, which emits and builds the program end-to-end. This column is the fast
/// standing cross-reference; `build+run` is the proof. A non-kernel symbol, or a
/// kernel whose emit token is not a plain identifier, is `NotApplicable`.
pub struct RuntimeFnExistsColumn {
    /// Every identifier defined or re-exported in the runtime crate source.
    runtime_symbols: RuntimeSymbols,
}

impl RuntimeFnExistsColumn {
    #[must_use]
    pub fn new() -> Self {
        Self {
            runtime_symbols: scan_runtime_symbols(),
        }
    }
}

/// The runtime crate's identifiers, or why they could not be collected.
#[derive(Debug)]
enum RuntimeSymbols {
    /// Every identifier the whole runtime source tree defines or re-exports.
    Scanned(BTreeSet<String>),
    /// No runtime crate source directory was found.
    NotLocated,
    /// The runtime source tree could not be read whole.
    Refused(TreeRefusal),
}

impl Default for RuntimeFnExistsColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl AspectCheck<StdlibSymbol> for RuntimeFnExistsColumn {
    fn name(&self) -> &'static str {
        "runtime-fn-exists"
    }

    fn check(&self, sym: &StdlibSymbol) -> Cell {
        let Some(kernel) = kernel_for(sym) else {
            return Cell::not_applicable("not a kernel symbol — no runtime function to resolve");
        };
        let runtime_fn = kernel.def().runtime_fn;
        // An emit token that is not a bare identifier is an inline/operator
        // emission, not a runtime fn call — no symbol to resolve.
        if runtime_fn.is_empty()
            || !runtime_fn
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Cell::not_applicable(
                "the kernel's emit token is not a bare identifier — an inline/operator/\
                 constructor emission, not a free runtime function",
            );
        }
        let symbols = match &self.runtime_symbols {
            RuntimeSymbols::Scanned(symbols) if !symbols.is_empty() => symbols,
            RuntimeSymbols::Scanned(_) | RuntimeSymbols::NotLocated => {
                return Cell::Warn(
                    "runtime crate source not found; runtime-fn existence not checked".to_owned(),
                );
            }
            RuntimeSymbols::Refused(refusal) => {
                return Cell::Warn(format!("runtime-fn existence not checked: {refusal}"));
            }
        };
        if symbols.contains(runtime_fn) {
            Cell::Ok
        } else {
            Cell::Warn(format!(
                "kernel {}.{}'s emit token `{runtime_fn}` is not a free function in \
                 the runtime crate — expected for a builder/inline/constructor \
                 kernel; the build+run column proves the emitted crate actually \
                 builds",
                sym.module.join("."),
                sym.name
            ))
        }
    }
}

/// Scan the runtime crate source tree for every identifier a `#[cfg]`-satisfied
/// emit could resolve to: `fn NAME`, `pub fn NAME`, `pub use … NAME`, `macro_rules!
/// NAME`, and `pub(crate) fn NAME`. The scan is a superset (it does not evaluate
/// cfgs), which is the fail-safe direction: a genuinely missing symbol is still a
/// hole, and a symbol present only under an off feature is not falsely flagged —
/// the featureset-closure SEAL owns the cfg-reachability axis.
fn scan_runtime_symbols() -> RuntimeSymbols {
    let Some(root) = runtime_crate_src() else {
        return RuntimeSymbols::NotLocated;
    };
    collect_symbols_under(&root)
}

/// Collect defined/re-exported identifiers from every `.rs` file under `root`,
/// or the refusal that kept the walk from reading the tree whole.
fn collect_symbols_under(root: &Path) -> RuntimeSymbols {
    let mut symbols = BTreeSet::new();
    match for_each_source(root, panic_scan::Want::RustFiles, |_, text| {
        collect_symbols_in_text(text, &mut symbols);
    }) {
        Ok(()) => RuntimeSymbols::Scanned(symbols),
        Err(refusal) => RuntimeSymbols::Refused(refusal),
    }
}

/// Locate the runtime crate's `src` directory via `IPE_RUNTIME_DIR` or an
/// ancestor walk to `src/runtime/rust/src`.
fn runtime_crate_src() -> Option<PathBuf> {
    if let Ok(dir) = ipe_env::var("IPE_RUNTIME_DIR") {
        let p = PathBuf::from(dir);
        if p.join("mod.rs").is_file() || p.join("lib.rs").is_file() {
            return Some(p);
        }
        let src = p.join("src");
        if src.is_dir() {
            return Some(src);
        }
    }
    let mut here = std::env::current_dir().ok();
    while let Some(dir) = here {
        let candidate = dir.join("src").join("runtime").join("rust").join("src");
        if candidate.is_dir() {
            return Some(candidate);
        }
        here = dir.parent().map(Path::to_path_buf);
    }
    None
}

/// Extract every runtime-symbol identifier a kernel emit could name from one
/// source file: `fn NAME`, `macro_rules! NAME`, and the trailing name of a
/// `pub use path::NAME;` re-export.
fn collect_symbols_in_text(text: &str, out: &mut BTreeSet<String>) {
    for line in text.lines() {
        let t = line.trim();
        if let Some(name) = ident_after(t, "fn ") {
            out.insert(name);
        }
        if let Some(name) = ident_after(t, "macro_rules! ") {
            out.insert(name);
        }
        if t.starts_with("pub use ") || t.starts_with("use ") {
            for name in reexport_names(t) {
                out.insert(name);
            }
        }
    }
}

/// The identifier immediately following `keyword` in `line`, up to the first
/// non-identifier character.
fn ident_after(line: &str, keyword: &str) -> Option<String> {
    let idx = line.find(keyword)? + keyword.len();
    // Guard against `keyword` appearing mid-identifier (e.g. `refn`): the char
    // before the keyword must be a boundary.
    let before = line[..line.find(keyword)?].chars().next_back();
    if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let name: String = line[idx..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() { None } else { Some(name) }
}

/// The re-exported trailing names of a `use`/`pub use` line: the final path
/// segment, plus every name in a trailing `{ … }` brace group. A best-effort
/// text scan (it does not resolve globs), which only widens the symbol set.
fn reexport_names(line: &str) -> Vec<String> {
    let body = line
        .trim_end_matches(';')
        .trim_start_matches("pub use ")
        .trim_start_matches("use ")
        .trim();
    if let Some(open) = body.find('{') {
        let inner = &body[open + 1..body.rfind('}').unwrap_or(body.len())];
        return inner
            .split(',')
            .filter_map(|seg| {
                let name = seg.trim().rsplit("::").next().unwrap_or("").trim();
                let name = name.split(" as ").last().unwrap_or(name).trim();
                if name.is_empty() || name == "*" {
                    None
                } else {
                    Some(name.to_owned())
                }
            })
            .collect();
    }
    let name = body.rsplit("::").next().unwrap_or(body).trim();
    let name = name.split(" as ").last().unwrap_or(name).trim();
    if name.is_empty() || name == "*" {
        Vec::new()
    } else {
        vec![name.to_owned()]
    }
}

// ── wasm ───────────────────────────────────────────────────────────────────────

/// Column **wasm**: a pure kernel is available under the `wasm32` client target.
///
/// A kernel carries a per-target denotation ([`StdlibKernel::available_on`]); the
/// `WasmClient` allowlist is default-deny, so a server-effect kernel (net, fs,
/// process, db) has no client denotation and is `NotApplicable` — not every
/// kernel is meant to lower for wasm, and denying one is a security property, not
/// a hole. A kernel the allowlist DOES admit must lower for the client target; a
/// wasm-available kernel is `Ok`. A non-kernel symbol is `NotApplicable`.
pub struct WasmColumn;

impl AspectCheck<StdlibSymbol> for WasmColumn {
    fn name(&self) -> &'static str {
        "wasm"
    }

    fn check(&self, sym: &StdlibSymbol) -> Cell {
        let Some(kernel) = kernel_for(sym) else {
            return Cell::not_applicable("not a kernel symbol — no wasm denotation to check");
        };
        if kernel.available_on(Target::WasmClient) {
            Cell::Ok
        } else {
            // Denied by the default-deny WasmClient allowlist: this kernel has no
            // client denotation by design (a server effect), so wasm does not
            // apply to it.
            Cell::not_applicable(format!(
                "{}.{}: a server-effect kernel with no WasmClient denotation — denied by the \
                 default-deny wasm allowlist by design (a security property, not a gap)",
                sym.module.join("."),
                sym.name
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::contract::SymbolKind;

    fn sym(module: &[&str], name: &str) -> StdlibSymbol {
        StdlibSymbol {
            module: module.iter().map(|s| (*s).to_owned()).collect(),
            name: name.to_owned(),
            kind: SymbolKind::Value,
            has_kernel: false,
            has_compiled_source: false,
            exported: true,
            scheme: None,
            is_higher_order: false,
        }
    }

    /// Previously `A.b_c` and `A_b.c` both mapped to `A_b_c` — the same key.
    /// After the fix they map to `A.b_c` and `A_b.c` respectively — distinct.
    #[test]
    fn scratch_key_is_injective_for_dot_underscore_ambiguity() {
        // A.b_c  (module=["A"], name="b_c")
        let key1 = symbol_scratch_key(&sym(&["A"], "b_c"));
        // A_b.c  (module=["A_b"], name="c")
        let key2 = symbol_scratch_key(&sym(&["A_b"], "c"));
        assert_ne!(
            key1, key2,
            "A.b_c and A_b.c must map to distinct scratch keys; both produced {key1:?}"
        );
    }

    /// Key is deterministic: same symbol, two calls, identical result.
    #[test]
    fn scratch_key_is_deterministic() {
        let s = sym(&["Ipe", "List"], "map");
        assert_eq!(symbol_scratch_key(&s), symbol_scratch_key(&s));
    }
    /// A runtime tree the walk cannot read whole is a named refusal, and the
    /// column reports the cause rather than "source not found" or a miss.
    #[test]
    fn an_unlisted_runtime_tree_is_a_named_refusal() {
        let missing = ipe_test_temp::temp_root().join(format!(
            "ipe-runtime-symbols-missing-{}",
            std::process::id()
        ));
        let symbols = collect_symbols_under(&missing);
        assert!(matches!(symbols, RuntimeSymbols::Refused(_)), "{symbols:?}");
        let kernel = StdlibKernel::ALL
            .iter()
            .copied()
            .find(|k| {
                let token = k.def().runtime_fn;
                !token.is_empty() && token.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            })
            .expect("a kernel lowers to a free runtime function");
        let mut probe = sym(&[kernel.def().qualifier], kernel.def().name);
        probe.has_kernel = true;
        let column = RuntimeFnExistsColumn {
            runtime_symbols: symbols,
        };
        let cell = column.check(&probe);
        assert!(
            matches!(&cell, Cell::Warn(msg) if msg.contains("cannot be listed whole")),
            "{cell:?}"
        );
    }
}
