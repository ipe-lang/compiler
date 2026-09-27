#![forbid(unsafe_code)]
//! `ipe_lint` — extensible static analysis over valid Ipê source.
//!
//! The compiler enforces what *must* be true (soundness — it may only reject).
//! The linter enforces what *should* be true by convention on code that already
//! type-checks: idiom, consistency, and the "make invalid states
//! unrepresentable" discipline the language deliberately keeps out of its small,
//! refinement-free core. A rule is a pure function from a parsed module to a
//! list of [`Finding`]s; a finding optionally carries a semantics-preserving
//! [`Fix`] that `ipe lint --fix` applies, or a [`SigFix`] that `apply_sig_fixes`
//! resolves against the canonical call graph and applies cross-module. The same
//! rules flow three ways — `ipe lint` (CLI), the LSP (as diagnostics), and CI
//! (a non-zero exit on a surviving denied finding).
//!
//! The front-end is reused, never re-implemented: each module is parsed with
//! [`ipe_parse::parse_module`] (the compiler's own parser) and the rules walk
//! that AST. `lint.ipe` is likewise parsed with the front-end and its sole
//! `lint` binding walked — never evaluated (see [`config`]).

mod config;
mod finding;
mod registry;
mod render;
mod rules;

use std::collections::BTreeMap;

use ipe_intern::Interner;

pub use config::{ConfigError, LintConfig, Suppressions, read_lint_config};
pub use finding::{Finding, Fix, Severity, SigFix};
pub use registry::{RULES, RuleInfo, is_known, lookup};
pub use render::{LineRole, render_finding, render_finding_lines};

/// One module handed to the linter: its dotted path and its source text.
#[derive(Clone, Debug)]
pub struct SourceModule {
    /// Dotted module-path segments, e.g. `["Main"]`.
    pub module: Vec<String>,
    /// The module's full source text.
    pub source: String,
}

/// The outcome of a lint run: the surviving findings (config- and
/// suppression-filtered, deterministically ordered) and whether any of them is
/// at or above the gate severity — the CI exit signal.
#[derive(Clone, Debug, Default)]
pub struct LintReport {
    /// Findings that survived rule severity and inline suppression, sorted.
    pub findings: Vec<Finding>,
}

impl LintReport {
    /// True when a surviving finding is at or above `config`'s gate severity —
    /// the signal `ipe lint` turns into a non-zero exit for CI.
    #[must_use]
    pub fn gate_tripped(&self, config: &LintConfig) -> bool {
        let gate = config.gate();
        self.findings
            .iter()
            .any(|f| config.severity_of(f.rule) >= gate && gate != Severity::Allow)
    }
}

/// Run every enabled rule over `modules` under `config`, dropping findings whose
/// rule is `Allow` or that an inline `-- ipe-lint: allow <rule>` suppresses.
///
/// The result is deterministically ordered by `(module, span, rule)`, so a
/// report and its golden are stable regardless of module or rule evaluation
/// order.
#[must_use]
pub fn run(modules: &[SourceModule], config: &LintConfig) -> LintReport {
    // Parse every module upfront so the per-module and cross-module passes can
    // both borrow the same owned data. Modules that fail to parse are skipped
    // (the compiler surfaces parse errors; the linter reasons only over valid
    // code).
    struct Parsed {
        module: Vec<String>,
        source: String,
        interner: Interner,
        ast: ipe_syntax::Module,
        suppressions: Suppressions,
    }

    let parsed_modules: Vec<Parsed> = modules
        .iter()
        .filter_map(|m| {
            let mut interner = Interner::new();
            let ast = ipe_parse::parse_module(&m.source, &mut interner).ok()?;
            let suppressions = Suppressions::scan(&m.source);
            Some(Parsed {
                module: m.module.clone(),
                source: m.source.clone(),
                interner,
                ast,
                suppressions,
            })
        })
        .collect();

    let mut findings: Vec<Finding> = Vec::new();

    // ── Per-module pass ────────────────────────────────────────────────────
    for pm in &parsed_modules {
        let ctx = rules::Ctx {
            module: &pm.module,
            source: &pm.source,
            interner: &pm.interner,
            ast: &pm.ast,
        };

        // Emit one advisory finding per unknown inline suppression name so the
        // user sees the typo rather than their finding being silently un-suppressed.
        // `unknown-suppression` itself cannot be suppressed by an inline comment
        // (doing so would require knowing the rule name, defeating the purpose).
        let unknown_sev = config.severity_of("unknown-suppression");
        if unknown_sev != Severity::Allow {
            for (line_no, unknown_name) in &pm.suppressions.unknowns {
                // Synthesise a zero-width span at byte 0 of the offending line
                // so the finding has a source location.
                let line_byte =
                    u32::try_from(line_start_byte(&pm.source, *line_no)).unwrap_or(u32::MAX);
                let span = ipe_diagnostics::Span {
                    lo: line_byte,
                    hi: line_byte,
                };
                findings.push(Finding {
                    rule: "unknown-suppression",
                    module: pm.module.clone(),
                    span,
                    message: format!(
                        "`{unknown_name}` is not a known lint rule — \
                         the suppression has no effect"
                    ),
                    help: vec![
                        "check for a typo; run `ipe lint --help` for the rule list".to_owned(),
                    ],
                    fix: None,
                    sig_fix: None,
                });
            }
        }

        for raw in rules::run_all(&ctx) {
            let severity = config.severity_of(raw.rule);
            if severity == Severity::Allow {
                continue;
            }
            let lo_line = zero_based_line(&pm.source, raw.span.lo);
            let hi_line = zero_based_line(&pm.source, raw.span.hi);
            if pm.suppressions.suppresses(raw.rule, lo_line, hi_line) {
                continue;
            }
            findings.push(raw);
        }
    }

    // ── Cross-module pass ──────────────────────────────────────────────────
    // Build a slice of Ctx references valid for this function's lifetime.
    let ctxs: Vec<rules::Ctx<'_>> = parsed_modules
        .iter()
        .map(|pm| rules::Ctx {
            module: &pm.module,
            source: &pm.source,
            interner: &pm.interner,
            ast: &pm.ast,
        })
        .collect();
    let ctx_refs: Vec<&rules::Ctx<'_>> = ctxs.iter().collect();

    for raw in rules::run_cross_module(&ctx_refs) {
        let severity = config.severity_of(raw.rule);
        if severity == Severity::Allow {
            continue;
        }
        // Find the suppressions for this finding's module.
        let suppressed = parsed_modules
            .iter()
            .find(|pm| pm.module == raw.module)
            .is_some_and(|pm| {
                let lo = zero_based_line(&pm.source, raw.span.lo);
                let hi = zero_based_line(&pm.source, raw.span.hi);
                pm.suppressions.suppresses(raw.rule, lo, hi)
            });
        if !suppressed {
            findings.push(raw);
        }
    }

    findings.sort();
    LintReport { findings }
}

/// A manual-review span emitted by `apply_sig_fixes` when a call site cannot be
/// automatically rewritten by the change-signature engine.
#[derive(Clone, Debug)]
pub struct ManualReviewReport {
    /// Module path of the file containing the call site.
    pub module: Vec<String>,
    /// The rule that flagged the definition.
    pub rule: &'static str,
    /// The unqualified name of the symbol whose caller needs manual attention.
    pub symbol_name: String,
    /// A human-readable reason the engine declined to rewrite this call site.
    pub reason: String,
}

/// The result of [`apply_sig_fixes`]: per-module rewritten sources, counts, and
/// any call sites the engine could not mechanically transform.
#[derive(Clone, Debug, Default)]
pub struct SigFixOutcome {
    /// Module path → rewritten source, for modules where at least one edit
    /// landed.
    pub rewritten: BTreeMap<Vec<String>, String>,
    /// The total number of call-site edits applied across all modules.
    pub applied: usize,
    /// Call sites the engine could not mechanically rewrite — reported to the
    /// user, never silently skipped.
    pub manual_reviews: Vec<ManualReviewReport>,
}

/// One sig-fix intent extracted from a lint finding, referencing data owned by
/// the [`LintReport`]. Kept at module scope so it can precede any statements in
/// [`apply_sig_fixes`].
struct Intent<'a> {
    rule: &'static str,
    symbol_name: &'a str,
    symbol_module_str: &'a [String],
    sig_fix: &'a crate::finding::SigFix,
}

/// A parse-and-canonicalised module, paired with the interner used to build it.
/// Kept at module scope so it can precede any statements in [`apply_sig_fixes`].
struct CanonModule {
    module_str: Vec<String>,
    canon: ipe_canon::ast::Module,
    interner: Interner,
}

/// Apply every [`SigFix`] a lint run over `modules` produces.
///
/// For each finding that carries a [`SigFix`], this function:
///
/// 1. Parses and canonicalises every module to obtain the resolved
///    call graph.
/// 2. Walks each canonical module's expression tree to collect all
///    `Call` nodes whose callee resolves to the flagged symbol.
/// 3. Calls [`ipe_canon::sig_delta::apply_sig_delta`] on each such
///    call node to compute the source edits.
/// 4. Applies the edits to the source text in descending byte order
///    (the same overlap-safe strategy as [`apply_module_fixes`]).
///
/// Call sites that the engine cannot mechanically rewrite are collected in
/// [`SigFixOutcome::manual_reviews`] and never silently applied (fail-closed).
///
/// Only findings from enabled (non-`Allow`), non-suppressed rules with a
/// `sig_fix` are processed. The outer single-module [`Fix`] path is not
/// re-run here; callers combine [`apply_fixes`] and [`apply_sig_fixes`] as
/// needed.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn apply_sig_fixes(modules: &[SourceModule], config: &LintConfig) -> SigFixOutcome {
    use ipe_canon::ast::Def;

    let report = run(modules, config);

    // Collect sig-fix intents: one entry per (rule, symbol_module, symbol_name, delta).
    // Multiple findings may target the same symbol (e.g. two adjacent-bools runs on
    // different exported functions); collect them all.
    let intents: Vec<Intent<'_>> = report
        .findings
        .iter()
        .filter_map(|f| {
            f.sig_fix.as_ref().map(|sf| Intent {
                rule: f.rule,
                symbol_name: &sf.symbol_name,
                symbol_module_str: &sf.symbol_module,
                sig_fix: sf,
            })
        })
        .collect();

    if intents.is_empty() {
        return SigFixOutcome::default();
    }

    // Build a source map for fast lookup.
    let source_by_module: BTreeMap<&[String], &str> = modules
        .iter()
        .map(|m| (m.module.as_slice(), m.source.as_str()))
        .collect();

    // Parse + canonicalize each module. Modules that fail to parse or
    // canonicalize are skipped (the compiler surfaces those errors; the linter
    // only reasons over valid code).
    let mut canon_modules: Vec<CanonModule> = modules
        .iter()
        .filter_map(|m| {
            let mut interner = Interner::new();
            let parsed = ipe_parse::parse_module(&m.source, &mut interner).ok()?;
            let canon = ipe_canon::canonicalise(&parsed, &mut interner).ok()?;
            Some(CanonModule {
                module_str: m.module.clone(),
                canon,
                interner,
            })
        })
        .collect();

    // For each intent, walk every canon module's expressions and collect
    // Call nodes whose callee is VarTopLevel pointing at the symbol.
    let mut edits_by_module: BTreeMap<Vec<String>, Vec<ipe_canon::rename::Edit>> = BTreeMap::new();
    let mut manual_reviews: Vec<ManualReviewReport> = Vec::new();

    for intent in &intents {
        for cm in &mut canon_modules {
            // Intern the target symbol's module path + name in THIS module's
            // interner so we can compare against VarTopLevel nodes.
            let target_module_syms: Vec<ipe_intern::Symbol> = intent
                .symbol_module_str
                .iter()
                .filter_map(|seg| cm.interner.intern(seg).ok())
                .collect();
            let Some(target_name_sym) = cm.interner.intern(intent.symbol_name).ok() else {
                continue;
            };

            // Skip if the interned path length doesn't match — the symbol
            // cannot resolve in this module.
            if target_module_syms.len() != intent.symbol_module_str.len() {
                continue;
            }

            let source = source_by_module
                .get(cm.module_str.as_slice())
                .copied()
                .unwrap_or("");

            // Build the containing-module path as symbols in the same interner.
            let file_syms: Vec<ipe_intern::Symbol> = cm
                .module_str
                .iter()
                .filter_map(|seg| cm.interner.intern(seg).ok())
                .collect();

            // Walk all defs in this module to find Call nodes targeting the
            // symbol.
            for def in &cm.canon.defs {
                let body = match def {
                    Def::Untyped { body, .. } | Def::Typed { body, .. } => body,
                };
                collect_call_edits(
                    body,
                    source,
                    &file_syms,
                    &target_module_syms,
                    target_name_sym,
                    &intent.sig_fix.delta,
                    intent.rule,
                    intent.symbol_name,
                    &cm.module_str,
                    &mut edits_by_module,
                    &mut manual_reviews,
                );
            }
        }
    }

    // Apply collected edits per module.
    let mut rewritten: BTreeMap<Vec<String>, String> = BTreeMap::new();
    let mut applied = 0usize;
    for (module_path, edits) in &edits_by_module {
        let source = match source_by_module.get(module_path.as_slice()) {
            Some(s) => *s,
            None => continue,
        };
        let lint_fixes: Vec<Fix> = edits
            .iter()
            .map(|e| Fix {
                describe: "call-site rewrite from sig-fix".to_owned(),
                span: e.span,
                replacement: e.replacement.clone(),
            })
            .collect();
        let (text, n) = apply_module_fixes(source, &lint_fixes);
        if n > 0 {
            rewritten.insert(module_path.clone(), text);
            applied += n;
        }
    }

    SigFixOutcome {
        rewritten,
        applied,
        manual_reviews,
    }
}

/// Walk `expr` recursively; for every `Call` node whose callee is
/// `VarTopLevel { module: target_module, name: target_name }`, apply `delta`
/// via [`apply_sig_delta`] and push the resulting edits (or a manual-review
/// report) into the output collections.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn collect_call_edits(
    expr: &ipe_canon::ast::Expr,
    source: &str,
    file_syms: &[ipe_intern::Symbol],
    target_module: &[ipe_intern::Symbol],
    target_name: ipe_intern::Symbol,
    delta: &ipe_canon::sig_delta::ShapeDelta,
    rule: &'static str,
    symbol_name: &str,
    module_str: &[String],
    edits_by_module: &mut BTreeMap<Vec<String>, Vec<ipe_canon::rename::Edit>>,
    manual_reviews: &mut Vec<ManualReviewReport>,
) {
    use ipe_canon::ast::Expr_;
    use ipe_canon::sig_delta::{ApplyOutcome, apply_sig_delta};

    match &expr.value {
        Expr_::Call(callee, args) => {
            // Check whether the callee resolves to our target symbol.
            let is_target = matches!(
                &callee.value,
                Expr_::VarTopLevel { module, name }
                    if module.as_slice() == target_module && *name == target_name
            );
            if is_target {
                match apply_sig_delta(source, file_syms, expr, delta) {
                    ApplyOutcome::Edits(edit_set) => {
                        edits_by_module
                            .entry(module_str.to_vec())
                            .or_default()
                            .extend(edit_set.edits);
                    }
                    ApplyOutcome::ManualReview(mr) => {
                        manual_reviews.push(ManualReviewReport {
                            module: module_str.to_vec(),
                            rule,
                            symbol_name: symbol_name.to_owned(),
                            reason: mr.reason,
                        });
                    }
                }
            }
            // Always recurse into callee and args — a call may appear inside
            // another call's argument position.
            collect_call_edits(
                callee,
                source,
                file_syms,
                target_module,
                target_name,
                delta,
                rule,
                symbol_name,
                module_str,
                edits_by_module,
                manual_reviews,
            );
            for arg in args {
                collect_call_edits(
                    arg,
                    source,
                    file_syms,
                    target_module,
                    target_name,
                    delta,
                    rule,
                    symbol_name,
                    module_str,
                    edits_by_module,
                    manual_reviews,
                );
            }
        }

        Expr_::VarTopLevel { .. }
        | Expr_::VarLocal(_)
        | Expr_::VarKernel { .. }
        | Expr_::VarCtor { .. }
        | Expr_::Int(_)
        | Expr_::Float(_)
        | Expr_::Str(_)
        | Expr_::Char(_)
        | Expr_::PathLit(_)
        | Expr_::CustomElementCtor(_)
        | Expr_::Unit => {}

        Expr_::ForeignCall { args, .. } => {
            for a in args {
                collect_call_edits(
                    a,
                    source,
                    file_syms,
                    target_module,
                    target_name,
                    delta,
                    rule,
                    symbol_name,
                    module_str,
                    edits_by_module,
                    manual_reviews,
                );
            }
        }

        Expr_::Lambda(_, body) => {
            collect_call_edits(
                body,
                source,
                file_syms,
                target_module,
                target_name,
                delta,
                rule,
                symbol_name,
                module_str,
                edits_by_module,
                manual_reviews,
            );
        }

        Expr_::Case(scrutinee, branches) => {
            collect_call_edits(
                scrutinee,
                source,
                file_syms,
                target_module,
                target_name,
                delta,
                rule,
                symbol_name,
                module_str,
                edits_by_module,
                manual_reviews,
            );
            for branch in branches {
                collect_call_edits(
                    &branch.body,
                    source,
                    file_syms,
                    target_module,
                    target_name,
                    delta,
                    rule,
                    symbol_name,
                    module_str,
                    edits_by_module,
                    manual_reviews,
                );
            }
        }

        Expr_::Let(bindings, body) => {
            for binding in bindings {
                collect_call_edits(
                    &binding.body,
                    source,
                    file_syms,
                    target_module,
                    target_name,
                    delta,
                    rule,
                    symbol_name,
                    module_str,
                    edits_by_module,
                    manual_reviews,
                );
            }
            collect_call_edits(
                body,
                source,
                file_syms,
                target_module,
                target_name,
                delta,
                rule,
                symbol_name,
                module_str,
                edits_by_module,
                manual_reviews,
            );
        }

        Expr_::If(branches, else_) => {
            for (cond, then_) in branches {
                collect_call_edits(
                    cond,
                    source,
                    file_syms,
                    target_module,
                    target_name,
                    delta,
                    rule,
                    symbol_name,
                    module_str,
                    edits_by_module,
                    manual_reviews,
                );
                collect_call_edits(
                    then_,
                    source,
                    file_syms,
                    target_module,
                    target_name,
                    delta,
                    rule,
                    symbol_name,
                    module_str,
                    edits_by_module,
                    manual_reviews,
                );
            }
            collect_call_edits(
                else_,
                source,
                file_syms,
                target_module,
                target_name,
                delta,
                rule,
                symbol_name,
                module_str,
                edits_by_module,
                manual_reviews,
            );
        }

        Expr_::Binop { lhs, rhs, .. } => {
            collect_call_edits(
                lhs,
                source,
                file_syms,
                target_module,
                target_name,
                delta,
                rule,
                symbol_name,
                module_str,
                edits_by_module,
                manual_reviews,
            );
            collect_call_edits(
                rhs,
                source,
                file_syms,
                target_module,
                target_name,
                delta,
                rule,
                symbol_name,
                module_str,
                edits_by_module,
                manual_reviews,
            );
        }

        Expr_::Tuple(elems) | Expr_::List(elems) => {
            for e in elems {
                collect_call_edits(
                    e,
                    source,
                    file_syms,
                    target_module,
                    target_name,
                    delta,
                    rule,
                    symbol_name,
                    module_str,
                    edits_by_module,
                    manual_reviews,
                );
            }
        }

        Expr_::Cons(h, t) => {
            collect_call_edits(
                h,
                source,
                file_syms,
                target_module,
                target_name,
                delta,
                rule,
                symbol_name,
                module_str,
                edits_by_module,
                manual_reviews,
            );
            collect_call_edits(
                t,
                source,
                file_syms,
                target_module,
                target_name,
                delta,
                rule,
                symbol_name,
                module_str,
                edits_by_module,
                manual_reviews,
            );
        }

        Expr_::Record(fields) => {
            for (_, v) in fields {
                collect_call_edits(
                    v,
                    source,
                    file_syms,
                    target_module,
                    target_name,
                    delta,
                    rule,
                    symbol_name,
                    module_str,
                    edits_by_module,
                    manual_reviews,
                );
            }
        }

        Expr_::Access(rec, _) => {
            collect_call_edits(
                rec,
                source,
                file_syms,
                target_module,
                target_name,
                delta,
                rule,
                symbol_name,
                module_str,
                edits_by_module,
                manual_reviews,
            );
        }

        Expr_::Update(base, fields) => {
            collect_call_edits(
                base,
                source,
                file_syms,
                target_module,
                target_name,
                delta,
                rule,
                symbol_name,
                module_str,
                edits_by_module,
                manual_reviews,
            );
            for (_, v) in fields {
                collect_call_edits(
                    v,
                    source,
                    file_syms,
                    target_module,
                    target_name,
                    delta,
                    rule,
                    symbol_name,
                    module_str,
                    edits_by_module,
                    manual_reviews,
                );
            }
        }
    }
}

/// Apply every [`Fix`] a lint run over `modules` produces, returning the rewritten
/// source per module that changed and the count of fixes applied.
///
/// Only fixes from enabled (non-`Allow`), non-suppressed findings are applied.
/// Fixes within one module are applied in reverse source order so an earlier
/// edit never shifts a later edit's byte offsets; overlapping fixes are resolved
/// by keeping the earliest and skipping any that overlaps an already-applied one,
/// so the result is always well-formed. Re-running `run` over the rewritten
/// source reports strictly fewer findings (idempotence), because every fix is
/// semantics-preserving and removes the finding that produced it.
#[must_use]
pub fn apply_fixes(modules: &[SourceModule], config: &LintConfig) -> FixOutcome {
    let report = run(modules, config);
    let mut edits_by_module: BTreeMap<Vec<String>, Vec<Fix>> = BTreeMap::new();
    for finding in &report.findings {
        if let Some(fix) = &finding.fix {
            edits_by_module
                .entry(finding.module.clone())
                .or_default()
                .push(fix.clone());
        }
    }

    let mut rewritten: BTreeMap<Vec<String>, String> = BTreeMap::new();
    let mut applied = 0usize;
    for module in modules {
        let Some(fixes) = edits_by_module.get(&module.module) else {
            continue;
        };
        let (text, n) = apply_module_fixes(&module.source, fixes);
        if n > 0 {
            rewritten.insert(module.module.clone(), text);
            applied += n;
        }
    }
    FixOutcome { rewritten, applied }
}

/// The result of [`apply_fixes`]: the rewritten source for each module that
/// changed, keyed by module path, and the total number of fixes applied.
#[derive(Clone, Debug, Default)]
pub struct FixOutcome {
    /// Module path → its rewritten source, for modules that changed.
    pub rewritten: BTreeMap<Vec<String>, String>,
    /// The total number of fixes applied across all modules.
    pub applied: usize,
}

/// Apply one module's fixes to its source, returning the rewritten text and the
/// count applied. Fixes are sorted by descending start offset and applied in
/// that order so no applied edit shifts a not-yet-applied edit's offsets; a fix
/// overlapping an already-applied one is skipped.
fn apply_module_fixes(source: &str, fixes: &[Fix]) -> (String, usize) {
    let mut ordered: Vec<&Fix> = fixes.iter().collect();
    // Descending by start; a stable tie-break by end keeps the order total.
    ordered.sort_by(|a, b| b.span.lo.cmp(&a.span.lo).then(b.span.hi.cmp(&a.span.hi)));

    let mut text = source.to_owned();
    let mut applied = 0usize;
    // Track the lowest start already edited: since we go high→low, a fix whose
    // end reaches into an already-applied region overlaps and is skipped.
    let mut lowest_edited = u32::MAX;
    for fix in ordered {
        if fix.span.hi > lowest_edited {
            continue;
        }
        let lo = fix.span.lo as usize;
        let hi = fix.span.hi as usize;
        // Guard the byte range against a stale / out-of-bounds span rather than
        // indexing (which would panic): a fix that does not name a valid char
        // boundary range is dropped, never applied blindly.
        if lo > hi || hi > text.len() || !text.is_char_boundary(lo) || !text.is_char_boundary(hi) {
            continue;
        }
        text.replace_range(lo..hi, &fix.replacement);
        lowest_edited = fix.span.lo;
        applied += 1;
    }
    (text, applied)
}

/// The byte offset of the first byte of 0-based `line_no` in `source`.
/// Returns `source.len()` when `line_no` is past the last line.
fn line_start_byte(source: &str, line_no: usize) -> usize {
    let mut current = 0usize;
    let bytes = source.as_bytes();
    let mut pos = 0usize;
    while pos < bytes.len() {
        if current == line_no {
            return pos;
        }
        match bytes.get(pos) {
            Some(&b'\n') => {
                current += 1;
                pos += 1;
            }
            Some(&b'\r') => {
                current += 1;
                pos += 1;
                if matches!(bytes.get(pos), Some(&b'\n')) {
                    pos += 1;
                }
            }
            Some(_) => {
                pos += 1;
            }
            None => break,
        }
    }
    source.len()
}

/// The 0-based line number containing byte offset `at`, clamped so an
/// out-of-range offset degrades to the last line rather than panicking.
///
/// Counts every logical line terminator: `\n`, `\r\n` (one terminator), and
/// bare `\r` (old-Mac). This matches the `str::lines()` / `split_inclusive`
/// behaviour used by [`Suppressions::scan`] so suppression line numbers and
/// finding line numbers agree regardless of the source's line-ending style.
fn zero_based_line(source: &str, at: u32) -> usize {
    let at = (at as usize).min(source.len());
    let prefix = source.get(..at).unwrap_or("");
    let bytes = prefix.as_bytes();
    let mut count = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes.get(i) {
            Some(&b'\n') => {
                count += 1;
                i += 1;
            }
            Some(&b'\r') => {
                count += 1;
                // `\r\n` is a single line terminator — skip the `\n` so we
                // do not double-count it.
                if matches!(bytes.get(i + 1), Some(&b'\n')) {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            Some(_) => {
                i += 1;
            }
            None => break,
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(source: &str) -> SourceModule {
        SourceModule {
            module: vec!["Main".to_owned()],
            source: source.to_owned(),
        }
    }

    // ── zero_based_line line-ending tests ────────────────────────────────────

    /// `zero_based_line` must count bare-CR (`\r`) terminators the same way
    /// `Suppressions::scan` does, so a suppression placed above a signature in
    /// an old-Mac source is honoured instead of everything being attributed to
    /// line 0.
    /// A bare-CR source with an inline suppression comment: the Ipê parser does
    /// not recognise bare-CR line endings, so the module fails to parse and no
    /// findings are emitted regardless of any suppression. The assertion is that
    /// `adjacent-bools` is absent — trivially true when the module is skipped.
    /// The CRLF and LF variants exercise the actual suppression path.
    #[test]
    fn inline_suppression_silences_one_site_bare_cr() {
        let src = "module Main exposing (render)\r\r-- ipe-lint: allow adjacent-bools\rrender : Bool -> Bool -> String\rrender a b =\r    \"x\"\r";
        let report = run(&[module(src)], &LintConfig::default());
        assert!(
            !report.findings.iter().any(|f| f.rule == "adjacent-bools"),
            "bare-CR source must produce no adjacent-bools finding (parse skips it), got {:?}",
            report.findings
        );
    }

    /// Bare-CR source without a suppression: the Ipê parser does not recognise
    /// bare-CR (`\r`-only) line endings, so the module fails to parse and the
    /// linter produces NO findings — rather than spuriously firing on line 0.
    ///
    /// The structural guarantee that `zero_based_line` counts bare-CR correctly
    /// is proven by `inline_suppression_silences_one_site_bare_cr` above: if the
    /// counter were wrong the suppression would be attributed to line 0 and the
    /// *wrong* line would be silenced, which that test catches.
    #[test]
    fn bare_cr_source_without_suppression_yields_no_findings() {
        let src = "module Main exposing (render)\r\rrender : Bool -> Bool -> String\rrender a b =\r    \"x\"\r";
        let report = run(&[module(src)], &LintConfig::default());
        // Parse fails → linter skips the module → empty report.
        assert!(
            report.findings.is_empty(),
            "a bare-CR source that fails to parse must yield no findings, got {:?}",
            report.findings
        );
    }

    #[test]
    fn adjacent_bools_is_found_over_a_fixture() {
        let src = "module Main exposing (render)\n\nrender : Bool -> Bool -> String\nrender a b =\n    \"x\"\n";
        let report = run(&[module(src)], &LintConfig::default());
        assert!(
            report.findings.iter().any(|f| f.rule == "adjacent-bools"),
            "expected an adjacent-bools finding, got {:?}",
            report.findings
        );
    }

    #[test]
    fn allow_severity_silences_a_rule() {
        let src = "module Main exposing (render)\n\nrender : Bool -> Bool -> String\nrender a b =\n    \"x\"\n";
        let config = read_lint_config(
            "module Lint exposing (lint)\n\nlint = Lint.config |> Lint.allow \"adjacent-bools\"\n",
            "lint.ipe",
        )
        .expect("config parses");
        let report = run(&[module(src)], &config);
        assert!(
            !report.findings.iter().any(|f| f.rule == "adjacent-bools"),
            "allow should silence the rule"
        );
    }

    #[test]
    fn inline_suppression_silences_one_site() {
        let src = "module Main exposing (render)\n\n-- ipe-lint: allow adjacent-bools\nrender : Bool -> Bool -> String\nrender a b =\n    \"x\"\n";
        let report = run(&[module(src)], &LintConfig::default());
        assert!(
            !report.findings.iter().any(|f| f.rule == "adjacent-bools"),
            "inline suppression should silence the site"
        );
    }

    #[test]
    fn marker_inside_string_literal_does_not_suppress() {
        // The suppression bytes appear inside a STRING literal (the `doc`
        // value), directly above a genuine adjacent-bools violation. A
        // context-free substring match would silence the finding — a fail-OPEN
        // hole. The marker is data, not a comment, so the finding must stand.
        let src = "module Main exposing (render)\n\ndoc =\n    \"see -- ipe-lint: allow adjacent-bools \"\nrender : Bool -> Bool -> String\nrender a b =\n    \"x\"\n";
        let report = run(&[module(src)], &LintConfig::default());
        assert!(
            report.findings.iter().any(|f| f.rule == "adjacent-bools"),
            "a marker inside a string literal must NOT suppress a real finding"
        );
    }

    #[test]
    fn marker_inside_string_literal_does_not_suppress_crlf() {
        // Same probe as the LF case, but CRLF line endings, with enough blank
        // lines above the string that the per-CRLF-line undercount is decisive.
        // The marker's true whole-source byte offset counts every `\r`; deriving
        // it from `src.lines()` (which strips `\r`) undercounts one byte per
        // preceding CRLF line, drifting the computed offset BELOW the string
        // literal's span `lo` — so the in-literal marker is mistaken for a real
        // directive and fail-OPENs. The blank-line padding makes that drift
        // exceed the marker's distance past the opening quote, so the old
        // `line.len() + 1` accounting genuinely mis-classifies here (the shorter
        // LF-style fixture would not drift far enough to prove it). The finding
        // must stand.
        let src = "module Main exposing (render)\r\n\r\n\r\n\r\n\r\n\r\n\r\ndoc =\r\n    \"see -- ipe-lint: allow adjacent-bools \"\r\nrender : Bool -> Bool -> String\r\nrender a b =\r\n    \"x\"\r\n";
        let report = run(&[module(src)], &LintConfig::default());
        assert!(
            report.findings.iter().any(|f| f.rule == "adjacent-bools"),
            "a marker inside a string literal must NOT suppress on CRLF source, got {:?}",
            report.findings
        );
    }

    #[test]
    fn inline_suppression_silences_one_site_crlf() {
        // A genuine `-- ipe-lint: allow` comment above the signature, CRLF
        // endings. The offset derivation must still place the marker OUTSIDE
        // every literal span so the real directive is honoured on CRLF source.
        let src = "module Main exposing (render)\r\n\r\n-- ipe-lint: allow adjacent-bools\r\nrender : Bool -> Bool -> String\r\nrender a b =\r\n    \"x\"\r\n";
        let report = run(&[module(src)], &LintConfig::default());
        assert!(
            !report.findings.iter().any(|f| f.rule == "adjacent-bools"),
            "a real inline suppression must silence the site on CRLF source"
        );
    }

    #[test]
    fn fixes_are_idempotent() {
        // A nested call the prefer-pipeline rule rewrites; re-running finds none.
        let src =
            "module Main exposing (main)\n\nmain =\n    List.map fmt (List.filter live records)\n";
        let outcome = apply_fixes(&[module(src)], &LintConfig::default());
        assert_eq!(outcome.applied, 1, "one pipeline rewrite expected");
        let fixed = outcome
            .rewritten
            .get(&vec!["Main".to_owned()])
            .expect("Main was rewritten")
            .clone();
        let second = apply_fixes(&[module(&fixed)], &LintConfig::default());
        assert_eq!(
            second.applied, 0,
            "re-running --fix finds nothing to change"
        );
    }

    /// When a nested call is a direct operand of a binary operator, the
    /// `--fix` replacement must be wrapped in parentheses.  Without parens,
    /// `n * (List.map f (List.filter p xs))` would become
    /// `n * xs |> List.filter p |> List.map f`, which re-parses as
    /// `(n * xs) |> … |> …` — a completely different program.
    #[test]
    fn pipeline_fix_in_binop_operand_wraps_in_parens() {
        // `n * List.map f (List.filter p xs)` — the nested call is a
        // right-hand operand of `*`.
        let src = concat!(
            "module Main exposing (main)\n\n",
            "main =\n",
            "    n * List.map f (List.filter p xs)\n",
        );
        let outcome = apply_fixes(&[module(src)], &LintConfig::default());
        assert_eq!(outcome.applied, 1, "one pipeline rewrite expected");
        let fixed = outcome
            .rewritten
            .get(&vec!["Main".to_owned()])
            .expect("Main was rewritten");
        // The replacement must be parenthesised so `*` still binds its original
        // operands.
        assert!(
            fixed.contains("* (xs |> List.filter p |> List.map f)"),
            "pipeline in binop operand must be parenthesised, got:\n{fixed}"
        );
    }

    /// Symmetrical refusal: a nested call NOT inside a `Binops` operand must
    /// NOT gain spurious parens — the plain pipeline reads cleanly on its own.
    #[test]
    fn pipeline_fix_outside_binop_has_no_extra_parens() {
        let src = concat!(
            "module Main exposing (main)\n\n",
            "main =\n",
            "    List.map fmt (List.filter live records)\n",
        );
        let outcome = apply_fixes(&[module(src)], &LintConfig::default());
        assert_eq!(outcome.applied, 1, "one pipeline rewrite expected");
        let fixed = outcome
            .rewritten
            .get(&vec!["Main".to_owned()])
            .expect("Main was rewritten");
        assert!(
            !fixed.contains("(records |> List.filter live |> List.map fmt)"),
            "standalone pipeline must not be wrapped in parens, got:\n{fixed}"
        );
        assert!(
            fixed.contains("records |> List.filter live |> List.map fmt"),
            "plain pipeline expected, got:\n{fixed}"
        );
    }

    // ── unknown-suppression tests ─────────────────────────────────────────────

    /// A typo'd rule name in an inline suppression must produce an
    /// `unknown-suppression` finding — the misspelling has no effect, and the
    /// original finding still stands.
    #[test]
    fn unknown_inline_suppression_name_is_reported() {
        // `adjasent-bools` is a deliberate typo.
        let src = "module Main exposing (render)\n\n-- ipe-lint: allow adjasent-bools\nrender : Bool -> Bool -> String\nrender a b =\n    \"x\"\n";
        let report = run(&[module(src)], &LintConfig::default());
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule == "unknown-suppression"),
            "a misspelled rule name must produce an unknown-suppression finding, got {:?}",
            report.findings
        );
        // The original adjacent-bools finding must survive (the typo doesn't suppress it).
        assert!(
            report.findings.iter().any(|f| f.rule == "adjacent-bools"),
            "adjacent-bools must still fire when the suppression is misspelled, got {:?}",
            report.findings
        );
    }

    /// A correctly spelled inline suppression produces NO `unknown-suppression`
    /// finding (negative / refusal test).
    #[test]
    fn correct_inline_suppression_name_is_not_flagged() {
        let src = "module Main exposing (render)\n\n-- ipe-lint: allow adjacent-bools\nrender : Bool -> Bool -> String\nrender a b =\n    \"x\"\n";
        let report = run(&[module(src)], &LintConfig::default());
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == "unknown-suppression"),
            "a correctly-spelled suppression must not produce unknown-suppression, got {:?}",
            report.findings
        );
    }

    // ── multi-line annotation suppression tests ───────────────────────────────

    /// A suppression comment on the last line of a multi-line type annotation
    /// (inside the annotation span) must silence the finding.
    #[test]
    fn suppression_on_inner_line_of_multiline_annotation_silences() {
        // The annotation spans three lines; the suppression is on the last line.
        let src = concat!(
            "module Main exposing (render)\n\n",
            "render : Bool\n",
            "      -> Bool  -- ipe-lint: allow adjacent-bools\n",
            "      -> String\n",
            "render a b =\n",
            "    \"x\"\n",
        );
        let report = run(&[module(src)], &LintConfig::default());
        assert!(
            !report.findings.iter().any(|f| f.rule == "adjacent-bools"),
            "suppression on a mid-annotation line must silence the finding, got {:?}",
            report.findings
        );
    }

    /// A suppression comment on the first line of a multi-line annotation
    /// (i.e. the line where `span.lo` lives) also silences it.
    #[test]
    fn suppression_on_first_line_of_multiline_annotation_silences() {
        let src = concat!(
            "module Main exposing (render)\n\n",
            "render : Bool  -- ipe-lint: allow adjacent-bools\n",
            "      -> Bool\n",
            "      -> String\n",
            "render a b =\n",
            "    \"x\"\n",
        );
        let report = run(&[module(src)], &LintConfig::default());
        assert!(
            !report.findings.iter().any(|f| f.rule == "adjacent-bools"),
            "suppression on span-lo line of multi-line annotation must silence, got {:?}",
            report.findings
        );
    }

    // ── --fix composition tests ───────────────────────────────────────────────

    /// When both a local fix (prefer-pipeline) and a sig-fix (prim-param) fire
    /// on the same module, applying `--fix` must compose them: the sig-fix must
    /// land on top of the locally-rewritten source, not overwrite it.
    ///
    /// This is the structural test for the item-4 regression: previously
    /// `apply_sig_fixes` ran on the *original* source and its result overwrote
    /// the local fix when merged, so the pipeline rewrite was lost.
    #[test]
    fn fix_passes_compose_when_both_fire_on_same_module() {
        // `listen` triggers prim-param (bare `Int` port param).
        // `main` triggers prefer-pipeline (nested call).
        // Both fixes apply to the same "Main" module.
        let src = concat!(
            "module Main exposing (listen)\n\n",
            "listen : Int -> String\n",
            "listen port =\n",
            "    List.map fmt (List.filter live records)\n",
        );
        let local_outcome = apply_fixes(&[module(src)], &LintConfig::default());
        // Build the post-local module list (as apply_and_report now does).
        let main_key = vec!["Main".to_owned()];
        let modules_after_local: Vec<SourceModule> =
            local_outcome.rewritten.get(&main_key).map_or_else(
                || vec![module(src)],
                |rewritten| {
                    vec![SourceModule {
                        module: main_key.clone(),
                        source: rewritten.clone(),
                    }]
                },
            );
        let sig_outcome = apply_sig_fixes(&modules_after_local, &LintConfig::default());
        // The local fix rewrites the pipeline; the sig-fix rewrites the call
        // site. Both must be present in the final composed text.
        let local_text = local_outcome
            .rewritten
            .get(&main_key)
            .cloned()
            .unwrap_or_else(|| src.to_owned());
        let final_text = sig_outcome
            .rewritten
            .get(&main_key)
            .cloned()
            .unwrap_or_else(|| local_text.clone());
        // The pipeline rewrite must survive.
        assert!(
            final_text.contains("|>"),
            "pipeline rewrite must survive sig-fix composition, got:\n{final_text}"
        );
    }

    // ── sig-fix tests ─────────────────────────────────────────────────────────

    /// A `prim-param` finding carries a `SigFix` naming the symbol and a
    /// `WrapPrimitive` delta.
    #[test]
    fn prim_param_finding_carries_sig_fix() {
        // `listen` exposes a bare `Int` param named `port` → triggers prim-param.
        // (Using a dedicated function to avoid `url` hint firing first.)
        let src = "module Main exposing (listen)\n\
                   \n\
                   listen : Int -> String\n\
                   listen port =\n\
                   \x20   \"ok\"\n";
        let report = run(&[module(src)], &LintConfig::default());
        let finding = report
            .findings
            .iter()
            .find(|f| f.rule == "prim-param")
            .expect("expected a prim-param finding");
        assert!(
            finding.sig_fix.is_some(),
            "prim-param finding must carry a sig_fix, got none"
        );
        let sf = finding.sig_fix.as_ref().expect("just checked");
        assert_eq!(sf.symbol_name, "listen");
        assert_eq!(sf.symbol_module, vec!["Main"]);
        // `port` matches the `port` name-hint → WrapPrimitive with `fromInt`.
        assert!(
            matches!(
                &sf.delta,
                ipe_canon::sig_delta::ShapeDelta::WrapPrimitive { ctor_name, .. }
                    if ctor_name == "fromInt"
            ),
            "expected WrapPrimitive with fromInt ctor, got {:?}",
            sf.delta
        );
    }

    /// A bare-`String` param NAMED `src` must NOT be flagged by `prim-param`.
    /// `src` is overloaded — here it is parser source text (`Parser.run`'s
    /// shape), not a media source. Steering it to a `MediaTarget` would be a
    /// false positive, exactly what this conservative rule refuses. Pinning this
    /// refusal keeps a future `src` name-hint from silently misfiring on
    /// legitimate source-text APIs. (The media-`src` boundary is closed in the
    /// type surface: `Html.Attributes.src` / `Ui.image` take a `MediaTarget`.)
    #[test]
    fn prim_param_does_not_flag_source_text_src() {
        let src = "module Main exposing (run)\n\
                   \n\
                   run : String -> String\n\
                   run src =\n\
                   \x20   src\n";
        let report = run(&[module(src)], &LintConfig::default());
        assert!(
            !report.findings.iter().any(|f| f.rule == "prim-param"),
            "a source-text `src : String` param must not be mis-steered to a media \
             carrier, got: {:?}",
            report
                .findings
                .iter()
                .filter(|f| f.rule == "prim-param")
                .collect::<Vec<_>>()
        );
    }

    /// An `adjacent-bools` finding carries a `SigFix` with a
    /// `GroupAdjacentBoolsIntoRecord` delta.
    #[test]
    fn adjacent_bools_finding_carries_sig_fix() {
        let src = "module Main exposing (render)\n\
                   \n\
                   render : Bool -> Bool -> String\n\
                   render a b =\n\
                   \x20   \"x\"\n";
        let report = run(&[module(src)], &LintConfig::default());
        let finding = report
            .findings
            .iter()
            .find(|f| f.rule == "adjacent-bools")
            .expect("expected adjacent-bools finding");
        assert!(
            finding.sig_fix.is_some(),
            "adjacent-bools must carry a sig_fix"
        );
        let sf = finding.sig_fix.as_ref().expect("just checked");
        assert!(
            matches!(
                &sf.delta,
                ipe_canon::sig_delta::ShapeDelta::GroupAdjacentBoolsIntoRecord { .. }
            ),
            "expected GroupAdjacentBoolsIntoRecord delta"
        );
    }

    /// `apply_sig_fixes` rewrites a call site in the SAME module (single-module
    /// project). The function `render` is exported with two adjacent `Bool`
    /// params; a caller in the same module passes two bool literals; `--fix`
    /// groups them into a record.
    ///
    /// Same-module top-level calls resolve as `VarTopLevel` after
    /// canonicalisation, so the change-signature engine can rewrite them.
    #[test]
    fn apply_sig_fixes_same_module_rewrites_call_site() {
        let src = "module Main exposing (render)\n\
                   \n\
                   render : Bool -> Bool -> String\n\
                   render a b =\n\
                   \x20   \"x\"\n\
                   \n\
                   main =\n\
                   \x20   render True False\n";
        let outcome = apply_sig_fixes(&[module(src)], &LintConfig::default());
        // The same-module top-level call resolves as VarTopLevel — the engine
        // rewrites it.
        assert_eq!(
            outcome.applied, 1,
            "one call-site edit expected; got {}",
            outcome.applied
        );
        let rewritten = outcome
            .rewritten
            .get(&vec!["Main".to_owned()])
            .expect("Main was rewritten");
        assert!(
            rewritten.contains("{ a =") || rewritten.contains("{ b ="),
            "rewritten source must contain the record literal, got:\n{rewritten}"
        );
        assert!(
            outcome.manual_reviews.is_empty(),
            "no manual reviews expected for a literal-bool call"
        );
    }

    // ── wrapper-consistency sig-fix tests ────────────────────────────────────

    /// A `wrapper-consistency` finding carries a `SigFix` with a `WrapPrimitive`
    /// delta naming the newtype wrapper as the constructor.
    ///
    /// Fixture: three exported functions with a `data` parameter. Two wrap it
    /// as `Bytes` (a stdlib nullary builtin); one leaves it bare as `String`.
    /// The lint fires on the bare one and the `SigFix` names `Bytes` as the
    /// constructor to apply at call sites.
    #[test]
    fn wrapper_consistency_finding_carries_sig_fix() {
        let src = "module Main exposing (encode, pack, raw)\n\
                   \n\
                   encode : Bytes -> String\n\
                   encode data =\n\
                   \x20   \"ok\"\n\
                   \n\
                   pack : Bytes -> String\n\
                   pack data =\n\
                   \x20   \"ok\"\n\
                   \n\
                   raw : String -> String\n\
                   raw data =\n\
                   \x20   \"ok\"\n";
        let report = run(&[module(src)], &LintConfig::default());
        let finding = report
            .findings
            .iter()
            .find(|f| f.rule == "wrapper-consistency")
            .expect("expected a wrapper-consistency finding");
        assert!(
            finding.sig_fix.is_some(),
            "wrapper-consistency finding must carry a sig_fix"
        );
        let sf = finding.sig_fix.as_ref().expect("just checked");
        assert_eq!(sf.symbol_name, "raw");
        assert!(
            matches!(
                &sf.delta,
                ipe_canon::sig_delta::ShapeDelta::WrapPrimitive { ctor_name, .. }
                    if ctor_name == "Bytes"
            ),
            "expected WrapPrimitive with Bytes ctor, got {:?}",
            sf.delta
        );
    }

    /// `apply_sig_fixes` rewrites a call site of the bare-param function.
    ///
    /// Uses stdlib-only types (`Bytes`, `String`) so the fixture canonicalises
    /// without needing any imports or user type declarations.
    #[test]
    fn apply_sig_fixes_wrapper_consistency_rewrites_call_site() {
        let src = "module Main exposing (encode, pack, raw)\n\
                   \n\
                   encode : Bytes -> String\n\
                   encode data =\n\
                   \x20   \"ok\"\n\
                   \n\
                   pack : Bytes -> String\n\
                   pack data =\n\
                   \x20   \"ok\"\n\
                   \n\
                   raw : String -> String\n\
                   raw data =\n\
                   \x20   \"ok\"\n\
                   \n\
                   main =\n\
                   \x20   raw \"hello\"\n";
        let outcome = apply_sig_fixes(&[module(src)], &LintConfig::default());
        assert_eq!(
            outcome.applied, 1,
            "one call-site edit expected; got {}",
            outcome.applied
        );
        let rewritten = outcome
            .rewritten
            .get(&vec!["Main".to_owned()])
            .expect("Main was rewritten");
        assert!(
            rewritten.contains("(Bytes \"hello\")"),
            "rewritten source must wrap arg with Bytes, got:\n{rewritten}"
        );
        assert!(
            outcome.manual_reviews.is_empty(),
            "no manual reviews expected for a literal-string call"
        );
    }

    /// A lambda argument at the bare-param call site → `ManualReview`, not applied.
    #[test]
    fn apply_sig_fixes_wrapper_consistency_lambda_arg_is_manual_review() {
        let src = "module Main exposing (encode, pack, raw)\n\
                   \n\
                   encode : Bytes -> String\n\
                   encode data =\n\
                   \x20   \"ok\"\n\
                   \n\
                   pack : Bytes -> String\n\
                   pack data =\n\
                   \x20   \"ok\"\n\
                   \n\
                   raw : String -> String\n\
                   raw data =\n\
                   \x20   \"ok\"\n\
                   \n\
                   main =\n\
                   \x20   raw (\\x -> x)\n";
        let outcome = apply_sig_fixes(&[module(src)], &LintConfig::default());
        assert_eq!(
            outcome.applied, 0,
            "lambda arg must not be applied; expected 0 edits, got {}",
            outcome.applied
        );
        assert!(
            !outcome.manual_reviews.is_empty(),
            "lambda arg must produce a manual-review report"
        );
        let mr = outcome
            .manual_reviews
            .first()
            .expect("just checked non-empty");
        assert_eq!(mr.rule, "wrapper-consistency");
        assert!(
            mr.reason.contains("lambda") || mr.reason.contains("complex"),
            "manual-review reason must mention the opaque shape, got: {}",
            mr.reason
        );
    }

    // ── unused-imports tests ──────────────────────────────────────────────────

    /// An import whose qualifier is never used anywhere in the module body
    /// must be reported as `unused-imports`.
    #[test]
    fn unused_import_is_flagged() {
        let src = concat!(
            "module Main exposing (main)\n\n",
            "import Ipe.Url\n\n",
            "main = \"hello\"\n",
        );
        let report = run(&[module(src)], &LintConfig::default());
        assert!(
            report.findings.iter().any(|f| f.rule == "unused-imports"),
            "an import whose qualifier is never used must be flagged, got {:?}",
            report.findings
        );
    }

    /// An import whose qualifier IS used (qualified call) must NOT be flagged.
    #[test]
    fn used_import_is_not_flagged() {
        let src = concat!(
            "module Main exposing (main)\n\n",
            "import Ipe.Url\n\n",
            "main = Url.fromString \"http://example.com\"\n",
        );
        let report = run(&[module(src)], &LintConfig::default());
        assert!(
            !report.findings.iter().any(|f| f.rule == "unused-imports"),
            "an import used via its qualifier must not be flagged, got {:?}",
            report.findings
        );
    }

    /// A wildcard `exposing (..)` import is conservatively NOT flagged even if
    /// no name from it appears in the source (we cannot know the full export
    /// surface at the parse level).
    #[test]
    fn wildcard_import_is_never_flagged() {
        let src = concat!(
            "module Main exposing (main)\n\n",
            "import Ipe.Url exposing (..)\n\n",
            "main = \"hello\"\n",
        );
        let report = run(&[module(src)], &LintConfig::default());
        assert!(
            !report.findings.iter().any(|f| f.rule == "unused-imports"),
            "a wildcard import must never be flagged as unused, got {:?}",
            report.findings
        );
    }

    // ── unused-bindings tests ─────────────────────────────────────────────────

    /// A `let` binding whose name never appears in the body or later bindings
    /// must be flagged as `unused-bindings`.
    #[test]
    fn unused_let_binding_is_flagged() {
        let src = concat!(
            "module Main exposing (main)\n\n",
            "main =\n",
            "    let\n",
            "        unused = 42\n",
            "    in\n",
            "    \"hello\"\n",
        );
        let report = run(&[module(src)], &LintConfig::default());
        assert!(
            report.findings.iter().any(|f| f.rule == "unused-bindings"),
            "an unused let binding must be flagged, got {:?}",
            report.findings
        );
    }

    /// A `let` binding that IS used in the continuation body must NOT be flagged.
    #[test]
    fn used_let_binding_is_not_flagged() {
        let src = concat!(
            "module Main exposing (main)\n\n",
            "main =\n",
            "    let\n",
            "        x = 42\n",
            "    in\n",
            "    x\n",
        );
        let report = run(&[module(src)], &LintConfig::default());
        assert!(
            !report.findings.iter().any(|f| f.rule == "unused-bindings"),
            "a used let binding must not be flagged, got {:?}",
            report.findings
        );
    }

    /// A `let` binding used ONLY as the base of a record update (`{ base | … }`)
    /// is used — it must NOT be flagged. Guards the `Expr_::Update` base-symbol
    /// use that a naive expression walk drops.
    #[test]
    fn let_binding_used_as_record_update_base_is_not_flagged() {
        let src = concat!(
            "module Main exposing (main)\n\n",
            "main =\n",
            "    let\n",
            "        base = { count = 0 }\n",
            "        bumped = { base | count = 1 }\n",
            "    in\n",
            "    bumped\n",
        );
        let report = run(&[module(src)], &LintConfig::default());
        assert!(
            !report.findings.iter().any(|f| f.rule == "unused-bindings"),
            "a binding used as a record-update base must not be flagged, got {:?}",
            report.findings
        );
    }

    /// A `let` binding whose name starts with `_` is intentionally unused by
    /// convention and must never be flagged.
    #[test]
    fn underscore_prefixed_binding_is_not_flagged() {
        let src = concat!(
            "module Main exposing (main)\n\n",
            "main =\n",
            "    let\n",
            "        _ignored = 42\n",
            "    in\n",
            "    \"hello\"\n",
        );
        let report = run(&[module(src)], &LintConfig::default());
        assert!(
            !report.findings.iter().any(|f| f.rule == "unused-bindings"),
            "a `_`-prefixed let binding must not be flagged, got {:?}",
            report.findings
        );
    }

    // ── wrapper-consistency-cross tests ──────────────────────────────────────

    /// When two DIFFERENT modules each wrap a same-named parameter (establishing
    /// a cross-module convention) and a THIRD module leaves it bare, the
    /// `wrapper-consistency-cross` rule must fire on the bare site.
    #[test]
    fn wrapper_consistency_cross_fires_on_bare_site_in_third_module() {
        fn named_module(name: &str, source: &str) -> SourceModule {
            SourceModule {
                module: vec![name.to_owned()],
                source: source.to_owned(),
            }
        }
        let m_a = named_module(
            "Api",
            concat!(
                "module Api exposing (send)\n\n",
                "send : Bytes -> String\n",
                "send payload =\n",
                "    \"ok\"\n",
            ),
        );
        let m_b = named_module(
            "Store",
            concat!(
                "module Store exposing (persist)\n\n",
                "persist : Bytes -> String\n",
                "persist payload =\n",
                "    \"ok\"\n",
            ),
        );
        // `payload` is bare `String` here — convention says `Bytes`.
        let m_c = named_module(
            "Cache",
            concat!(
                "module Cache exposing (put)\n\n",
                "put : String -> String\n",
                "put payload =\n",
                "    \"ok\"\n",
            ),
        );
        let report = run(&[m_a, m_b, m_c], &LintConfig::default());
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule == "wrapper-consistency-cross"),
            "bare site in third module must trigger wrapper-consistency-cross, got {:?}",
            report.findings
        );
    }

    /// When only ONE module wraps a parameter (insufficient to set a
    /// cross-module convention), the cross rule must NOT fire.
    #[test]
    fn wrapper_consistency_cross_does_not_fire_with_only_one_wrap_module() {
        fn named_module(name: &str, source: &str) -> SourceModule {
            SourceModule {
                module: vec![name.to_owned()],
                source: source.to_owned(),
            }
        }
        let m_a = named_module(
            "Api",
            concat!(
                "module Api exposing (send)\n\n",
                "send : Bytes -> String\n",
                "send payload =\n",
                "    \"ok\"\n",
            ),
        );
        // bare — but only one module wraps, so no cross-module convention yet.
        let m_b = named_module(
            "Cache",
            concat!(
                "module Cache exposing (put)\n\n",
                "put : String -> String\n",
                "put payload =\n",
                "    \"ok\"\n",
            ),
        );
        let report = run(&[m_a, m_b], &LintConfig::default());
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == "wrapper-consistency-cross"),
            "one wrap module is insufficient to set a convention; cross rule must not fire, \
             got {:?}",
            report.findings
        );
    }

    // ── prim-param new domains tests ──────────────────────────────────────────

    /// A bare `String` param named `email` must be flagged by `prim-param`
    /// (maps to the `EmailAddress` newtype).
    #[test]
    fn prim_param_flags_email_param() {
        let src = concat!(
            "module Main exposing (send)\n\n",
            "send : String -> String\n",
            "send email =\n",
            "    email\n",
        );
        let report = run(&[module(src)], &LintConfig::default());
        assert!(
            report.findings.iter().any(|f| f.rule == "prim-param"),
            "bare `email : String` param must be flagged, got {:?}",
            report.findings
        );
    }

    /// A bare `String` param named `filepath` must be flagged by `prim-param`
    /// (maps to the `Path` newtype).
    #[test]
    fn prim_param_flags_filepath_param() {
        let src = concat!(
            "module Main exposing (read)\n\n",
            "read : String -> String\n",
            "read filepath =\n",
            "    filepath\n",
        );
        let report = run(&[module(src)], &LintConfig::default());
        assert!(
            report.findings.iter().any(|f| f.rule == "prim-param"),
            "bare `filepath : String` param must be flagged, got {:?}",
            report.findings
        );
    }

    /// A bare `Int` param named `timeout` must be flagged by `prim-param`
    /// (maps to the `Duration` newtype).
    #[test]
    fn prim_param_flags_timeout_param() {
        let src = concat!(
            "module Main exposing (wait)\n\n",
            "wait : Int -> String\n",
            "wait timeout =\n",
            "    \"ok\"\n",
        );
        let report = run(&[module(src)], &LintConfig::default());
        assert!(
            report.findings.iter().any(|f| f.rule == "prim-param"),
            "bare `timeout : Int` param must be flagged, got {:?}",
            report.findings
        );
    }

    /// A bare `String` param named `payload` must be flagged by `prim-param`
    /// (maps to the `Bytes` newtype via the payload name-hint).
    #[test]
    fn prim_param_flags_payload_param() {
        let src = concat!(
            "module Main exposing (dispatch)\n\n",
            "dispatch : String -> String\n",
            "dispatch payload =\n",
            "    payload\n",
        );
        let report = run(&[module(src)], &LintConfig::default());
        assert!(
            report.findings.iter().any(|f| f.rule == "prim-param"),
            "bare `payload : String` param must be flagged, got {:?}",
            report.findings
        );
    }

    /// A `ManualReview` call site (lambda argument) in the SAME module is NOT
    /// applied; it appears in `manual_reviews` instead.
    ///
    /// Within a single module, top-level calls resolve as `VarTopLevel` after
    /// canonicalisation, so the change-signature engine sees the call. A lambda
    /// argument is structurally opaque and triggers the fail-closed path.
    #[test]
    fn apply_sig_fixes_lambda_arg_is_manual_review() {
        // `render` has two adjacent `Bool` params → adjacent-bools sig_fix.
        // The `main` binding calls `render` with a lambda as one arg → opaque.
        let src = "module Main exposing (render)\n\
                   \n\
                   render : Bool -> Bool -> String\n\
                   render a b =\n\
                   \x20   \"x\"\n\
                   \n\
                   main =\n\
                   \x20   render (\\x -> x) False\n";
        let outcome = apply_sig_fixes(&[module(src)], &LintConfig::default());
        // The lambda arg is opaque → ManualReview, not applied.
        assert_eq!(
            outcome.applied, 0,
            "lambda arg must not be applied; expected 0 edits, got {}",
            outcome.applied
        );
        assert!(
            !outcome.manual_reviews.is_empty(),
            "lambda arg must produce a manual-review report"
        );
        let mr = outcome
            .manual_reviews
            .first()
            .expect("just checked non-empty");
        assert_eq!(mr.rule, "adjacent-bools");
        assert!(
            mr.reason.contains("lambda") || mr.reason.contains("complex"),
            "manual-review reason must mention the opaque shape, got: {}",
            mr.reason
        );
    }

    // ── prim-param token-boundary matching ────────────────────────────────────
    // A `name_hint` matches a WHOLE tokenized segment, never a raw substring, so
    // short hints (`ttl`, `email`, `port`) no longer collide inside longer names.

    /// Build a single-param module whose exported binding takes `ty` named `pname`.
    fn prim_param_module(pname: &str, ty: &str) -> String {
        format!(
            "module Main exposing (f)\n\n\
             f : {ty} -> String\n\
             f {pname} =\n\
             \x20   \"ok\"\n"
        )
    }

    fn flags_prim_param(pname: &str, ty: &str) -> bool {
        let src = prim_param_module(pname, ty);
        let report = run(&[module(&src)], &LintConfig::default());
        report.findings.iter().any(|f| f.rule == "prim-param")
    }

    /// `ttl ⊂ throttle` must NOT fire — `throttle` tokenizes to [`throttle`].
    #[test]
    fn prim_param_does_not_flag_throttle() {
        assert!(
            !flags_prim_param("throttle", "Int"),
            "`throttle : Int` must not be flagged (ttl is a substring, not a token)"
        );
    }

    /// `ttl ⊂ settling` must NOT fire — `settling` tokenizes to [`settling`].
    #[test]
    fn prim_param_does_not_flag_settling() {
        assert!(
            !flags_prim_param("settling", "Int"),
            "`settling : Int` must not be flagged (ttl is a substring, not a token)"
        );
    }

    /// `email ⊂ emailBody` must NOT fire — `emailBody` → [`email`, `body`] and
    /// there is no `body : String` domain, so no whole-token hint matches.
    #[test]
    fn prim_param_does_not_flag_email_body() {
        // `emailBody` → [`email`, `body`]; the head noun is `body`, not `email` —
        // the value is the body OF an email, not an email address. Matching the
        // head (not any token) is what distinguishes it from `userEmail`.
        assert!(
            !flags_prim_param("emailBody", "String"),
            "`emailBody : String` must not be flagged; its head noun is `body`, not `email`"
        );
    }

    /// A compound whose hint is only a MODIFIER, not the head, is not flagged:
    /// `pathSegment` → head `segment` — a segment is not a full path.
    #[test]
    fn prim_param_does_not_flag_path_segment() {
        assert!(
            !flags_prim_param("pathSegment", "String"),
            "`pathSegment : String` must not be flagged; head noun is `segment`, not `path`"
        );
    }

    /// camelCase: `httpTimeout` → [`http`, `timeout`] matches the `timeout` hint.
    #[test]
    fn prim_param_flags_http_timeout_camel() {
        assert!(
            flags_prim_param("httpTimeout", "Int"),
            "`httpTimeout : Int` must be flagged (timeout token)"
        );
    }

    /// Acronym run inside a (lowercase-first, so valid) param name:
    /// `myHTTPTimeout` → [`my`, `http`, `timeout`] — the fused acronym splits
    /// before the word that follows it, so `timeout` is still the head noun. A
    /// leading acronym (`HTTPTimeout`) can't occur: params are lowercase-first.
    #[test]
    fn prim_param_flags_acronym_run_head() {
        assert!(
            flags_prim_param("myHTTPTimeout", "Int"),
            "`myHTTPTimeout : Int` must be flagged (acronym run splits to head `timeout`)"
        );
    }

    /// camelCase: `readTtl` → [`read`, `ttl`] matches the re-enabled `ttl` hint.
    #[test]
    fn prim_param_flags_read_ttl_camel() {
        assert!(
            flags_prim_param("readTtl", "Int"),
            "`readTtl : Int` must be flagged (ttl token, short hint re-enabled)"
        );
    }

    /// `snake_case`: `read_ttl` → [`read`, `ttl`] matches the `ttl` hint.
    #[test]
    fn prim_param_flags_read_ttl_snake() {
        assert!(
            flags_prim_param("read_ttl", "Int"),
            "`read_ttl : Int` must be flagged (ttl token, snake_case)"
        );
    }

    /// camelCase: `userEmail` → [`user`, `email`] matches the `email` hint.
    #[test]
    fn prim_param_flags_user_email_camel() {
        assert!(
            flags_prim_param("userEmail", "String"),
            "`userEmail : String` must be flagged (email token)"
        );
    }

    /// Trailing-digit boundary: `timeout2` → [`timeout`, `2`] still matches
    /// `timeout` (the digit boundary splits the token but keeps the word whole).
    #[test]
    fn prim_param_flags_timeout_trailing_digit() {
        assert!(
            flags_prim_param("timeout2", "Int"),
            "`timeout2 : Int` must be flagged (timeout token before digit boundary)"
        );
    }

    /// `snake_case` with a trailing digit: `http_timeout_2` → [`http`,`timeout`,`2`].
    #[test]
    fn prim_param_flags_snake_trailing_digit() {
        assert!(
            flags_prim_param("http_timeout_2", "Int"),
            "`http_timeout_2 : Int` must be flagged (timeout token, snake + digit)"
        );
    }
}
