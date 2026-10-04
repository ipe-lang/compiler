//! Whole-project diagnostics collection over the `ipe_db` query graph.
//!
//! [`collect`] demands the same memoized queries the batch driver runs —
//! `parse` → `canonicalize` (dep-first) → `typecheck` → `lower_program` —
//! and returns every resulting compiler [`Diagnostic`] attributed to the
//! module that owns it. The attribution rules mirror the driver's blame
//! logic exactly:
//!
//! - parse/canonicalize diagnostics belong to the module that produced them;
//!   an importer of a red dependency inherits the dep's failure *silently*
//!   (the dep already reported it at its own file);
//! - a `typecheck` error names its owning module by construction
//!   (`ipe_types::InferError`) — an exact lookup, never a guess; a home naming
//!   no project module is refused as a compiler bug on the entry, and a
//!   whole-program error belongs to the entry;
//! - only a link or lowering error with no home falls back to the span
//!   heuristic over the linked program's defs — the same closest-`lo` rule the
//!   CLI driver renders with.
//!
//! Every module in the project appears in the result (with an empty list
//! when clean), so a consumer can clear stale diagnostics for files that
//! healed.

use std::collections::{BTreeMap, BTreeSet};

use ipe_db::{Db as _, ImportResolution, IpeDatabase, SourceRoot};
use ipe_diagnostics::{Diagnostic, Severity, Span};
use ipe_intern::Symbol;
use lsp_types::{DiagnosticSeverity, NumberOrString};

use crate::offset::{PositionEncoding, span_to_range};

/// Every diagnostic owned by one module, keyed by its module path.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ModuleDiagnostics {
    /// The owning module's path segments (e.g. `["Main"]`).
    pub module: Vec<String>,
    /// The module's diagnostics, in pipeline order. Empty when clean.
    pub diagnostics: Vec<Diagnostic>,
}

/// Collect every current diagnostic for the project rooted at `root` with
/// entry module `entry`, one entry per module (empty when clean).
#[must_use]
pub fn collect(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: ipe_db::SourceFile,
) -> Vec<ModuleDiagnostics> {
    let files = root.files(db).clone();
    let entry_module: Vec<String> = entry.module_path(db).clone();
    let mut by_module: BTreeMap<Vec<String>, Vec<Diagnostic>> = files
        .keys()
        .map(|path| (path.clone(), Vec::new()))
        .collect();

    // Parse every module; a red parse taints the module for later stages.
    let mut failed: BTreeSet<Vec<String>> = BTreeSet::new();
    for (path, file) in &files {
        if let Err(diag) = ipe_db::parse(db, *file) {
            push(&mut by_module, path, diag.clone());
            failed.insert(path.clone());
        }
    }

    // Dependency-first order; a cycle is one project-level diagnostic.
    let order = match ipe_db::topo_order(db, root, entry) {
        Ok(order) => order,
        Err(diag) => {
            push(&mut by_module, &entry_module, diag.clone());
            return flatten(by_module);
        }
    };

    // Canonicalise dep-first. A module whose (transitive) dep already failed
    // is skipped: its `canonicalize` error would be the dep's own diagnostic
    // replayed, and attributing that to the importer would be a mis-blame.
    for path in order.iter() {
        if failed.contains(path) {
            continue;
        }
        let Some(file) = files.get(path) else {
            continue;
        };
        let dep_tainted =
            ipe_db::resolve_imports(db, root, *file)
                .as_ref()
                .map_or(true, |resolutions| {
                    resolutions.iter().any(|(dep_path, resolution)| {
                        matches!(resolution, ImportResolution::Resolved(_))
                            && failed.contains(dep_path)
                    })
                });
        if dep_tainted {
            failed.insert(path.clone());
            continue;
        }
        if let Err(diag) = ipe_db::canonicalize(db, root, *file) {
            push(&mut by_module, path, diag.clone());
            failed.insert(path.clone());
        }
    }

    if !failed.is_empty() {
        // The whole-program stages need every module canonicalised; their
        // demand now would only replay a diagnostic already attributed above.
        return flatten(by_module);
    }

    match ipe_db::typecheck(db, root, entry) {
        Err(ipe_db::TypecheckError::Link(diag)) => {
            push(&mut by_module, &entry_module, diag.clone());
        }
        Err(ipe_db::TypecheckError::Infer(err)) => {
            let (owner, diag) = attribute_infer(db, &by_module, err, &entry_module);
            push(&mut by_module, &owner, diag);
        }
        Ok(solved) => {
            for warning in &solved.warnings {
                let diag = warning.diagnostic();
                let owner = attribute(
                    db,
                    root,
                    entry,
                    warning.home(),
                    diag.primary_span(),
                    &entry_module,
                );
                push(&mut by_module, &owner, diag.clone());
            }
            match ipe_db::lower_program(db, root, entry) {
                Ok(_) => {}
                Err(ipe_db::PipelineError::Infer(err)) => {
                    let (owner, diag) = attribute_infer(db, &by_module, err, &entry_module);
                    push(&mut by_module, &owner, diag);
                }
                Err(ipe_db::PipelineError::Lower(diag, home)) => {
                    let owner =
                        attribute(db, root, entry, home, diag.primary_span(), &entry_module);
                    push(&mut by_module, &owner, diag.clone());
                }
            }
        }
    }

    flatten(by_module)
}

fn push(by_module: &mut BTreeMap<Vec<String>, Vec<Diagnostic>>, path: &[String], diag: Diagnostic) {
    if let Some(list) = by_module.get_mut(path) {
        list.push(diag);
    } else {
        by_module.insert(path.to_vec(), vec![diag]);
    }
}

fn flatten(by_module: BTreeMap<Vec<String>, Vec<Diagnostic>>) -> Vec<ModuleDiagnostics> {
    by_module
        .into_iter()
        .map(|(module, diagnostics)| ModuleDiagnostics {
            module,
            diagnostics,
        })
        .collect()
}

/// Resolve a type-checker error's owning module from its typed home.
///
/// A sited error belongs to the project module its home names. A home naming
/// no project module is refused as [`Diagnostic::CompilerBug`] on the entry,
/// never handed to the span heuristic. A whole-program error belongs to the
/// entry.
fn attribute_infer(
    db: &IpeDatabase,
    by_module: &BTreeMap<Vec<String>, Vec<Diagnostic>>,
    err: &ipe_types::InferError,
    entry_module: &[String],
) -> (Vec<String>, Diagnostic) {
    let Some(home) = err.home() else {
        return (entry_module.to_vec(), err.diagnostic().clone());
    };
    resolve_module_path(db, home.path())
        .filter(|path| by_module.contains_key(path))
        .map_or_else(
            || {
                (
                    entry_module.to_vec(),
                    Diagnostic::CompilerBug {
                        where_: "lsp.attribute_infer",
                        detail: "a type-checker error names a module with no source file"
                            .to_owned(),
                    },
                )
            },
            |path| (path, err.diagnostic().clone()),
        )
}

/// Resolve a link or lowering diagnostic's owning module: an exact `home`
/// lookup when the lowerer attributed one, else the span heuristic over the
/// linked program, else the entry module.
fn attribute(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: ipe_db::SourceFile,
    home: &[Symbol],
    span: Span,
    entry_module: &[String],
) -> Vec<String> {
    let home_syms: Option<Vec<Symbol>> = if home.is_empty() {
        ipe_db::linked_program(db, root, entry)
            .clone()
            .ok()
            .and_then(|linked| home_for_span(&linked.module, span))
    } else {
        Some(home.to_vec())
    };
    home_syms
        .and_then(|syms| resolve_module_path(db, &syms))
        .unwrap_or_else(|| entry_module.to_vec())
}

/// Resolve an interned module path back to its string segments.
fn resolve_module_path(db: &IpeDatabase, home: &[Symbol]) -> Option<Vec<String>> {
    let interner = db.interner().lock();
    home.iter()
        .map(|&sym| interner.resolve(sym).map(str::to_owned))
        .collect()
}

/// The module whose def (or union constructor) most tightly encloses `span`
/// in the linked whole-program module — the driver's closest-`lo` blame rule.
///
/// After link, every def keeps its original `home`, and every span in a
/// def's body is a byte offset into that home module's own source, so the
/// def that *starts nearest* the failing span (narrower body as tiebreaker)
/// names the owning module.
fn home_for_span(linked: &ipe_canon::ast::Module, span: Span) -> Option<Vec<Symbol>> {
    if span == Span::DUMMY {
        return None;
    }
    // (lo_dist, width, home)
    let mut best: Option<(u32, u32, &[Symbol])> = None;
    for def in &linked.defs {
        let body_span = match def {
            ipe_canon::ast::Def::Untyped { body, .. } | ipe_canon::ast::Def::Typed { body, .. } => {
                body.span
            }
        };
        if body_span.lo <= span.lo && span.hi <= body_span.hi {
            let lo_dist = span.lo.saturating_sub(body_span.lo);
            let width = body_span.hi.saturating_sub(body_span.lo);
            if best.is_none_or(|(prev_dist, prev_width, _)| {
                lo_dist < prev_dist || (lo_dist == prev_dist && width < prev_width)
            }) {
                best = Some((lo_dist, width, def.home()));
            }
        }
    }
    for union in &linked.unions {
        for ctor in &union.ctors {
            if ctor.span.lo <= span.lo && span.hi <= ctor.span.hi {
                let lo_dist = span.lo.saturating_sub(ctor.span.lo);
                let width = ctor.span.hi.saturating_sub(ctor.span.lo);
                if best.is_none_or(|(prev_dist, prev_width, _)| {
                    lo_dist < prev_dist || (lo_dist == prev_dist && width < prev_width)
                }) {
                    best = Some((lo_dist, width, union.home.as_slice()));
                }
            }
        }
    }
    best.map(|(_, _, home)| home.to_vec())
}

/// Map one compiler diagnostic to its LSP form.
///
/// `text` is the owning module's source. The message is the compiler's own
/// snippet-free rendering ([`ipe_diagnostics::plain_message`]) — the wording
/// cannot drift from `ipe dev build`'s.
#[must_use]
pub fn to_lsp(diag: &Diagnostic, text: &str, encoding: PositionEncoding) -> lsp_types::Diagnostic {
    let span = diag.primary_span();
    let range = if span == Span::DUMMY {
        lsp_types::Range::default()
    } else {
        span_to_range(text, span, encoding)
    };
    let severity = match diag.severity() {
        Severity::Error | Severity::Bug => DiagnosticSeverity::ERROR,
        Severity::Warning => DiagnosticSeverity::WARNING,
    };
    lsp_types::Diagnostic {
        range,
        severity: Some(severity),
        code: Some(NumberOrString::String(diag.code().as_str().to_owned())),
        code_description: None,
        source: Some("ipe".to_owned()),
        message: ipe_diagnostics::plain_message(diag, text),
        related_information: None,
        tags: None,
        data: None,
    }
}

/// Run the linter over the project's user modules and return each finding as an
/// LSP diagnostic, keyed by owning module.
///
/// This is the transport that surfaces lint findings live in the editor
/// alongside the compiler's own diagnostics (the way clippy flows through
/// rust-analyzer).
///
/// `user_texts` is the source of each module the editor owns a file for
/// (injected stdlib is excluded — the linter reasons over the user's code).
/// `config` is the resolved `lint.ipe` (or defaults). The message reuses the
/// finding's own prose; the help lines are appended so the editor shows the same
/// teaching the CLI does.
#[must_use]
pub fn collect_lint(
    user_texts: &BTreeMap<Vec<String>, String>,
    config: &ipe_lint::LintConfig,
    encoding: PositionEncoding,
) -> Vec<(Vec<String>, Vec<lsp_types::Diagnostic>)> {
    let modules: Vec<ipe_lint::SourceModule> = user_texts
        .iter()
        .map(|(module, source)| ipe_lint::SourceModule {
            module: module.clone(),
            source: source.clone(),
        })
        .collect();
    let report = ipe_lint::run(&modules, config);

    let mut per_module: BTreeMap<Vec<String>, Vec<lsp_types::Diagnostic>> = BTreeMap::new();
    for finding in &report.findings {
        let Some(text) = user_texts.get(&finding.module) else {
            continue;
        };
        let severity = match config.severity_of(finding.rule) {
            ipe_lint::Severity::Deny => DiagnosticSeverity::ERROR,
            // A warn-level (or allow, though allow never reaches here) lint is a
            // hint in the editor — advisory, never a build blocker.
            ipe_lint::Severity::Warn | ipe_lint::Severity::Allow => DiagnosticSeverity::WARNING,
        };
        let range = span_to_range(text, finding.span, encoding);
        let message = if finding.help.is_empty() {
            finding.message.clone()
        } else {
            format!("{}\n{}", finding.message, finding.help.join("\n"))
        };
        // The fix rides in `data` (raw JSON, `lsp_types::Diagnostic`'s only
        // extension point) so the generic code-action provider can build an
        // edit from any rule's finding without re-running the linter or
        // re-parsing the module. Only a local, single-module `Fix` travels
        // this way — a cross-module `SigFix` has no per-finding LSP action.
        let data = finding.fix.as_ref().map(|fix| {
            serde_json::json!({
                "fix": {
                    "describe": fix.describe.clone(),
                    "lo": fix.span.lo,
                    "hi": fix.span.hi,
                    "replacement": fix.replacement.clone(),
                }
            })
        });
        per_module
            .entry(finding.module.clone())
            .or_default()
            .push(lsp_types::Diagnostic {
                range,
                severity: Some(severity),
                code: Some(NumberOrString::String(format!("lint/{}", finding.rule))),
                code_description: None,
                source: Some("ipe-lint".to_owned()),
                message,
                related_information: None,
                tags: None,
                data,
            });
    }
    per_module.into_iter().collect()
}
