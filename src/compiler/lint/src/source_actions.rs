//! Whole-file source actions: `organize_imports` and `fix_all`.
//!
//! Both compose what the rest of the crate already produces — the
//! `unused-imports` [`crate::Finding`] and the registered [`crate::Fix`] values
//! from [`crate::apply_fixes`] — and never re-derive usage or fixability
//! themselves. Every edit is proven before it is offered: the output is
//! re-parsed and checked against the input, and any doubt (a parse failure, an
//! unresolvable name, trivia inside the import block, a missing module) yields
//! no edit at all.

use std::collections::{BTreeMap, BTreeSet};

use ipe_intern::{Interner, Symbol};
use ipe_syntax::{Exposed, Exposing, Import, Module, Privacy as AstPrivacy};

use crate::rules::unused_imports::{
    RULE as UNUSED_IMPORTS, any_referenced, import_qualifier_texts, removal_range,
};
use crate::{LintConfig, SourceModule, apply_fixes, run};

/// The round ceiling for [`fix_all`].
///
/// A fix can only unlock a further fix on the *next* re-lint (e.g.
/// `prefer-pipeline` flattens one nesting level per round), so full
/// convergence on deeply-shaped input can take several rounds. This is the
/// soundness floor against input shaped to defeat convergence (arbitrarily
/// deep nesting), not a tuning knob.
pub const FIX_ALL_MAX_ROUNDS: usize = 8;

/// A minimal edit to one module: replace bytes `lo..hi` with `replacement`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlockEdit {
    /// Start byte of the replaced range.
    pub lo: usize,
    /// End byte (exclusive) of the replaced range.
    pub hi: usize,
    /// The text that supplants `lo..hi`.
    pub replacement: String,
}

impl BlockEdit {
    /// The module text with this edit applied, or `None` when the range does
    /// not lie on char boundaries of `source`.
    #[must_use]
    pub fn apply(&self, source: &str) -> Option<String> {
        let head = source.get(..self.lo)?;
        let tail = source.get(self.hi..)?;
        Some(format!("{head}{}{tail}", self.replacement))
    }
}

/// Sort, merge, and prune the `import` block of one module.
///
/// An import flagged `unused-imports` — matched back to its AST node by the
/// finding's identity key, the `import_kw` span — is dropped wholesale; this
/// is the only signal that *decides* a drop. Surviving imports of the same dotted
/// module path and `as` alias are merged into one declaration, their
/// `exposing` lists unioned (privacy only ever widens: `Public` beats
/// `PublicCtors` beats `Private`) and sorted by name; the merged declarations
/// are sorted by module path, then alias. An empty merged `exposing` list is
/// rendered as a bare `import Foo`, which keeps a second run a no-op.
///
/// The edit covers exactly the import block, located from the parser-recorded
/// declaration spans. It is refused (`None`) when the module does not parse,
/// when any declaration shares a line with other code, when a kept
/// declaration holds a comment (its replacement is re-serialized from the
/// AST, which cannot reproduce it), when anything but whitespace lies between
/// declarations, when a name does not resolve, when the rewritten module
/// fails to re-parse to the same declarations and the kept imports' bound
/// names, or when a re-derivation
/// on the output cannot prove that the drop removed only what the dropped
/// imports bound and that none of it is still referenced. That proof is
/// independent of the drop *decision* but reuses the `unused-imports` usage
/// walk, so a reference the walk cannot see escapes both alike. `None` also
/// means there is nothing to change. Line endings follow the block's own
/// (`\r\n` or `\n`).
#[must_use]
pub fn organize_imports(module: &SourceModule, config: &LintConfig) -> Option<BlockEdit> {
    let report = std::cell::OnceCell::new();
    organize_imports_dropping(module, |imp| {
        report
            .get_or_init(|| {
                let Ok(report) = run(std::slice::from_ref(module), config, &crate::NeverCancel);
                report
            })
            .findings
            .iter()
            .any(|f| {
                f.rule == UNUSED_IMPORTS
                    && f.module == module.module
                    && f.span.lo == imp.import_kw.lo
            })
    })
}

/// [`organize_imports`] with the drop decision supplied by `is_dropped`.
///
/// Production passes the `unused-imports` report; a test passes a
/// deliberately wrong decision to prove the output-side re-derivation
/// refuses it through the same code path.
fn organize_imports_dropping(
    module: &SourceModule,
    is_dropped: impl Fn(&Import) -> bool,
) -> Option<BlockEdit> {
    let source = module.source.as_str();
    let mut interner = Interner::new();
    let ast = ipe_parse::parse_module(source, &mut interner).ok()?;

    let mut extents = ast
        .imports
        .iter()
        .map(|imp| removal_range(source, imp))
        .collect::<Option<Vec<_>>>()?;
    extents.sort_unstable();
    let (lo, _) = *extents.first()?;
    let mut hi = lo;
    for (start, end) in &extents {
        let gap = source.get(hi..*start)?;
        if *start < hi || !gap.chars().all(char::is_whitespace) {
            return None;
        }
        hi = *end;
    }
    let original = source.get(lo..hi)?;

    let (dropped, kept): (Vec<&Import>, Vec<&Import>) =
        ast.imports.iter().partition(|imp| is_dropped(imp));

    // A kept import is re-serialized from its AST (module path, alias,
    // exposing list) by `render_import_block`, never copied from source, so a
    // comment nested inside its declaration would be silently lost. A dropped
    // import's declaration is never re-serialized (its whole span vanishes
    // with the rest of the block), so a comment inside it is harmless here.
    if kept.iter().any(|imp| declaration_has_comment(source, imp)) {
        return None;
    }

    let newline = if original.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut replacement = render_import_block(&kept, &interner, newline)?;
    if !original.ends_with('\n') {
        let trimmed = replacement.trim_end_matches(['\r', '\n']).len();
        replacement.truncate(trimmed);
    }
    if replacement == original {
        return None;
    }

    let edit = BlockEdit {
        lo,
        hi,
        replacement,
    };
    let output = edit.apply(source)?;
    let mut out_interner = Interner::new();
    let out_ast = ipe_parse::parse_module(&output, &mut out_interner).ok()?;
    let same_decls = decl_names(&ast, &interner)? == decl_names(&out_ast, &out_interner)?;
    let out_imports: Vec<&Import> = out_ast.imports.iter().collect();
    let faithful = bindings(&kept, &interner)? == bindings(&out_imports, &out_interner)?;
    let proven = drop_is_proven(&ast, &interner, &dropped, &out_ast, &out_interner);
    (same_decls && faithful && proven).then_some(edit)
}

/// Whether `output` provably differs from `original` only by `dropped`, none
/// of whose names `output` still references.
///
/// Re-derived from the two parse trees, independently of whatever decided
/// the drop — but the reference check below runs the same `unused-imports`
/// usage walk the production decision does, and the output body is the
/// input body, so a use the walk misses is missed by both (common mode):
/// - no binding is gained: the output's import bindings are a subset of the
///   original's;
/// - every binding lost is one a dropped import supplied (a binding also
///   supplied by a kept import survives in the output, so it is not lost);
/// - the `unused-imports` usage walk, re-run on `output`, finds no reference
///   to any qualifier, alias, or exposed name of `dropped`.
///
/// Fail-closed: an unresolvable name or an opaque output is a refusal.
fn drop_is_proven(
    original: &Module,
    interner: &Interner,
    dropped: &[&Import],
    output: &Module,
    out_interner: &Interner,
) -> bool {
    let original_imports: Vec<&Import> = original.imports.iter().collect();
    let output_imports: Vec<&Import> = output.imports.iter().collect();
    let (Some(before), Some(gone), Some(after)) = (
        bindings(&original_imports, interner),
        bindings(dropped, interner),
        bindings(&output_imports, out_interner),
    ) else {
        return false;
    };
    after.is_subset(&before)
        && before.difference(&after).all(|b| gone.contains(b))
        && !any_referenced(output, out_interner, dropped, interner)
}

/// The smallest whole-line edit turning `before` into `after`.
///
/// The common prefix and suffix are left untouched; the changed middle is
/// widened to whole lines, so the range never splits a character or a `\r\n`
/// pair. `None` when the texts are equal.
#[must_use]
pub fn minimal_edit(before: &str, after: &str) -> Option<BlockEdit> {
    if before == after {
        return None;
    }
    let prefix = before
        .bytes()
        .zip(after.bytes())
        .take_while(|(a, b)| a == b)
        .count();
    let room = before.len().min(after.len()).saturating_sub(prefix);
    let suffix = before
        .bytes()
        .rev()
        .zip(after.bytes().rev())
        .take(room)
        .take_while(|(a, b)| a == b)
        .count();
    let lo = crate::rules::unused_imports::line_start(before, prefix);
    let mut hi = before.len().saturating_sub(suffix);
    if hi > 0 && before.as_bytes().get(hi.saturating_sub(1)) != Some(&b'\n') {
        hi = crate::rules::unused_imports::line_end(before, hi);
    }
    let kept_tail = before.len().saturating_sub(hi);
    let after_hi = after.len().checked_sub(kept_tail)?;
    Some(BlockEdit {
        lo,
        hi,
        replacement: after.get(lo..after_hi)?.to_owned(),
    })
}

/// Apply every machine-applicable fix across `modules`, up to
/// [`FIX_ALL_MAX_ROUNDS`] re-lint rounds, and return `target`'s final text.
///
/// `None` when `target` is not among `modules` or nothing changed.
#[must_use]
pub fn fix_all(modules: &[SourceModule], target: &[String], config: &LintConfig) -> Option<String> {
    fix_all_bounded(modules, target, config, FIX_ALL_MAX_ROUNDS)
}

/// [`fix_all`] with an explicit round ceiling.
///
/// Production always pins [`FIX_ALL_MAX_ROUNDS`] via [`fix_all`]; a test
/// proving the bound passes a small one, so the refusal runs through the same
/// code path.
///
/// Each round is [`crate::apply_fixes`] itself, so an unfixable finding is
/// never touched. A round is kept only when every module it rewrote still
/// parses, no rule reports more findings than before, and the resulting text
/// is one no earlier round produced; otherwise the loop stops at the last good
/// text. `None` when `target` is not among `modules` or nothing changed.
#[must_use]
pub fn fix_all_bounded(
    modules: &[SourceModule],
    target: &[String],
    config: &LintConfig,
    max_rounds: usize,
) -> Option<String> {
    let original = modules.iter().find(|m| m.module == target)?;
    let mut current: Vec<SourceModule> = modules.to_vec();
    let mut counts = rule_counts(&current, config);
    let mut seen: BTreeSet<Vec<String>> = BTreeSet::new();
    seen.insert(current.iter().map(|m| m.source.clone()).collect());
    for _ in 0..max_rounds {
        let outcome = apply_fixes(&current, config);
        if outcome.applied == 0 {
            break;
        }
        let mut next = current.clone();
        for m in &mut next {
            if let Some(text) = outcome.rewritten.get(&m.module) {
                m.source.clone_from(text);
            }
        }
        let all_parse = next
            .iter()
            .filter(|m| outcome.rewritten.contains_key(&m.module))
            .all(|m| ipe_parse::parse_module(&m.source, &mut Interner::new()).is_ok());
        if !all_parse {
            break;
        }
        let next_counts = rule_counts(&next, config);
        let regressed = next_counts
            .iter()
            .any(|(rule, n)| counts.get(rule).is_none_or(|before| n > before));
        if regressed || !seen.insert(next.iter().map(|m| m.source.clone()).collect()) {
            break;
        }
        current = next;
        counts = next_counts;
    }
    current
        .into_iter()
        .find(|m| m.module == target)
        .map(|m| m.source)
        .filter(|text| *text != original.source)
}

/// Findings per rule across `modules`.
fn rule_counts(modules: &[SourceModule], config: &LintConfig) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::new();
    let Ok(report) = run(modules, config, &crate::NeverCancel);
    for finding in report.findings {
        *counts.entry(finding.rule).or_insert(0usize) += 1;
    }
    counts
}

/// The names of every non-import declaration, per kind, in source order.
type DeclNames = [Vec<String>; 4];

/// [`DeclNames`] of `ast`, or `None` when a name does not resolve.
fn decl_names(ast: &Module, interner: &Interner) -> Option<DeclNames> {
    let names = |syms: Vec<Symbol>| -> Option<Vec<String>> {
        syms.into_iter().map(|s| resolve(interner, s)).collect()
    };
    Some([
        names(ast.values.iter().map(|v| v.value.name.value).collect())?,
        names(ast.unions.iter().map(|u| u.value.name.value).collect())?,
        names(ast.aliases.iter().map(|a| a.value.name.value).collect())?,
        names(ast.foreigns.iter().map(|f| f.value.name.value).collect())?,
    ])
}

/// A (dotted module path, `as` alias) import key.
type ImportKey = (String, Option<String>);

/// One name an import set binds.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Binding {
    /// A module qualifier spelling.
    Qualifier(String),
    /// `exposing (..)`: every export of the module.
    Wildcard(ImportKey),
    /// An exposed value.
    Value(ImportKey, String),
    /// An exposed type name.
    Type(ImportKey, String),
    /// `Type(..)`: every constructor of the type.
    AllCtors(ImportKey, String),
    /// One listed constructor.
    Ctor(ImportKey, String, String),
}

/// The normalized binding set of `imports`.
///
/// A wildcard absorbs every other exposed entry of its key and `Type(..)`
/// absorbs its listed constructors, so two import sets binding the same names
/// compare equal however they are spelled. `None` when a name does not
/// resolve.
fn bindings(imports: &[&Import], interner: &Interner) -> Option<BTreeSet<Binding>> {
    let mut set = BTreeSet::new();
    for imp in imports {
        for text in import_qualifier_texts(interner, imp)? {
            set.insert(Binding::Qualifier(text));
        }
        let key = import_key(imp, interner)?;
        let Exposing::List(items) = &imp.exposing.value else {
            set.insert(Binding::Wildcard(key));
            continue;
        };
        for item in items {
            match &item.value {
                Exposed::Value(s) => {
                    set.insert(Binding::Value(key.clone(), resolve(interner, *s)?));
                }
                Exposed::Type(s, privacy) => {
                    let ty = resolve(interner, *s)?;
                    match privacy {
                        AstPrivacy::Private => {}
                        AstPrivacy::Public => {
                            set.insert(Binding::AllCtors(key.clone(), ty.clone()));
                        }
                        AstPrivacy::PublicCtors(ctors) => {
                            for c in ctors {
                                let ctor = resolve(interner, *c)?;
                                set.insert(Binding::Ctor(key.clone(), ty.clone(), ctor));
                            }
                        }
                    }
                    set.insert(Binding::Type(key.clone(), ty));
                }
            }
        }
    }
    let wildcards: BTreeSet<ImportKey> = set
        .iter()
        .filter_map(|b| match b {
            Binding::Wildcard(k) => Some(k.clone()),
            _ => None,
        })
        .collect();
    let all_ctors: BTreeSet<(ImportKey, String)> = set
        .iter()
        .filter_map(|b| match b {
            Binding::AllCtors(k, ty) => Some((k.clone(), ty.clone())),
            _ => None,
        })
        .collect();
    set.retain(|b| match b {
        Binding::Qualifier(_) | Binding::Wildcard(_) => true,
        Binding::Value(k, _) | Binding::Type(k, _) | Binding::AllCtors(k, _) => {
            !wildcards.contains(k)
        }
        Binding::Ctor(k, ty, _) => {
            !wildcards.contains(k) && !all_ctors.contains(&(k.clone(), ty.clone()))
        }
    });
    Some(set)
}

/// The [`ImportKey`] of `imp`, or `None` when a name does not resolve.
fn import_key(imp: &Import, interner: &Interner) -> Option<ImportKey> {
    let path = imp
        .name
        .value
        .iter()
        .map(|s| resolve(interner, *s))
        .collect::<Option<Vec<_>>>()?
        .join(".");
    let alias = match imp.alias {
        Some(a) => Some(resolve(interner, a)?),
        None => None,
    };
    Some((path, alias))
}

/// A ctor-name set, or a value/opaque-type marker, widened by a merge.
#[derive(Clone, PartialEq, Eq)]
enum MergedPrivacy {
    Public,
    PrivateOpaque,
    Ctors(BTreeSet<String>),
}

/// One merged `exposing` entry: a plain value name, or a type name with its
/// merged constructor privacy.
enum ExposedKind {
    Value,
    Type(MergedPrivacy),
}

/// The name-and-kind key of a merged `exposing` entry; `true` marks a type.
type ExposedKey = (String, bool);

/// A merged `exposing` clause.
///
/// `exposing (..)` absorbs everything; otherwise the deduplicated item set,
/// ordered by name.
enum MergedExposing {
    All,
    List(BTreeMap<ExposedKey, ExposedKind>),
}

/// The text of `sym`, or `None` when the interner does not hold it.
fn resolve(interner: &Interner, sym: Symbol) -> Option<String> {
    interner.resolve(sym).map(str::to_owned)
}

fn merged_privacy(privacy: &AstPrivacy, interner: &Interner) -> Option<MergedPrivacy> {
    Some(match privacy {
        AstPrivacy::Public => MergedPrivacy::Public,
        AstPrivacy::Private => MergedPrivacy::PrivateOpaque,
        AstPrivacy::PublicCtors(ctors) => MergedPrivacy::Ctors(
            ctors
                .iter()
                .map(|s| resolve(interner, *s))
                .collect::<Option<_>>()?,
        ),
    })
}

fn widen_privacy(a: MergedPrivacy, b: MergedPrivacy) -> MergedPrivacy {
    match (a, b) {
        (MergedPrivacy::Public, _) | (_, MergedPrivacy::Public) => MergedPrivacy::Public,
        (MergedPrivacy::Ctors(mut x), MergedPrivacy::Ctors(y)) => {
            x.extend(y);
            MergedPrivacy::Ctors(x)
        }
        (MergedPrivacy::Ctors(x), MergedPrivacy::PrivateOpaque)
        | (MergedPrivacy::PrivateOpaque, MergedPrivacy::Ctors(x)) => MergedPrivacy::Ctors(x),
        (MergedPrivacy::PrivateOpaque, MergedPrivacy::PrivateOpaque) => {
            MergedPrivacy::PrivateOpaque
        }
    }
}

fn merge_exposing(
    entry: &mut MergedExposing,
    exposing: &Exposing,
    interner: &Interner,
) -> Option<()> {
    let Exposing::List(items) = exposing else {
        *entry = MergedExposing::All;
        return Some(());
    };
    let MergedExposing::List(map) = entry else {
        return Some(());
    };
    for item in items {
        match &item.value {
            Exposed::Value(sym) => {
                map.entry((resolve(interner, *sym)?, false))
                    .or_insert(ExposedKind::Value);
            }
            Exposed::Type(sym, privacy) => {
                let rendered = merged_privacy(privacy, interner)?;
                match map.entry((resolve(interner, *sym)?, true)) {
                    std::collections::btree_map::Entry::Vacant(v) => {
                        v.insert(ExposedKind::Type(rendered));
                    }
                    std::collections::btree_map::Entry::Occupied(mut o) => {
                        if let ExposedKind::Type(existing) = o.get_mut() {
                            let taken = std::mem::replace(existing, MergedPrivacy::PrivateOpaque);
                            *existing = widen_privacy(taken, rendered);
                        }
                    }
                }
            }
        }
    }
    Some(())
}

fn render_exposed(key: &ExposedKey, kind: &ExposedKind) -> String {
    let (name, _) = key;
    match kind {
        ExposedKind::Value | ExposedKind::Type(MergedPrivacy::PrivateOpaque) => name.clone(),
        ExposedKind::Type(MergedPrivacy::Public) => format!("{name}(..)"),
        ExposedKind::Type(MergedPrivacy::Ctors(ctors)) => {
            let names: Vec<&str> = ctors.iter().map(String::as_str).collect();
            format!("{name}({})", names.join(", "))
        }
    }
}

fn render_import_line(key: &ImportKey, exposing: &MergedExposing, newline: &str) -> String {
    let (path, alias) = key;
    let mut line = format!("import {path}");
    if let Some(a) = alias {
        line.push_str(" as ");
        line.push_str(a);
    }
    match exposing {
        MergedExposing::All => line.push_str(" exposing (..)"),
        MergedExposing::List(map) if map.is_empty() => {}
        MergedExposing::List(map) => {
            let items: Vec<String> = map.iter().map(|(k, v)| render_exposed(k, v)).collect();
            line.push_str(" exposing (");
            line.push_str(&items.join(", "));
            line.push(')');
        }
    }
    line.push_str(newline);
    line
}

/// Render surviving imports as sorted, merged source text: one line per
/// distinct [`ImportKey`], in key order. `None` when a name does not resolve.
/// Whether `import`'s declaration span holds a `--` or `{-` comment opener.
///
/// A kept import's rendered replacement comes only from its AST fields
/// (`render_import_block` never copies source text), so any comment in its
/// span cannot survive reorganization; this is what the caller refuses on.
/// Fail-closed: an out-of-range or off-boundary span reads as holding one.
fn declaration_has_comment(text: &str, import: &Import) -> bool {
    let lo = import.span.lo as usize;
    let hi = import.span.hi as usize;
    text.get(lo..hi)
        .is_none_or(|body| body.contains("--") || body.contains("{-"))
}

fn render_import_block(imports: &[&Import], interner: &Interner, newline: &str) -> Option<String> {
    let mut groups: BTreeMap<ImportKey, MergedExposing> = BTreeMap::new();
    for imp in imports {
        let entry = groups
            .entry(import_key(imp, interner)?)
            .or_insert_with(|| MergedExposing::List(BTreeMap::new()));
        merge_exposing(entry, &imp.exposing.value, interner)?;
    }
    Some(
        groups
            .iter()
            .map(|(key, exposing)| render_import_line(key, exposing, newline))
            .collect(),
    )
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

    fn target() -> Vec<String> {
        vec!["Main".to_owned()]
    }

    /// The organized module text, or the input when no edit is offered.
    fn organized(src: &str) -> String {
        organize_imports(&module(src), &LintConfig::default())
            .and_then(|edit| edit.apply(src))
            .unwrap_or_else(|| src.to_owned())
    }

    /// The fixed module text, or the input when nothing changed.
    fn fixed(src: &str, rounds: usize) -> String {
        fix_all_bounded(&[module(src)], &target(), &LintConfig::default(), rounds)
            .unwrap_or_else(|| src.to_owned())
    }

    /// The byte offset of the `import` keyword of `imp`.
    fn kw_at(imp: &Import) -> Option<usize> {
        usize::try_from(imp.import_kw.lo).ok()
    }

    #[test]
    fn a_drop_decision_that_misses_a_qualified_use_is_refused() {
        let src = "module Main exposing (main)\n\nimport Zeta\nimport Alpha\n\nmain =\n    (Zeta.a, Alpha.b)\n";
        assert_eq!(organize_imports_dropping(&module(src), |_| true), None);
        let alpha = src.find("import Alpha");
        assert_eq!(
            organize_imports_dropping(&module(src), |imp| kw_at(imp) == alpha),
            None,
            "dropping one qualified-used import is refused too"
        );
    }

    #[test]
    fn a_drop_decision_that_misses_an_exposed_use_is_refused() {
        let src = "module Main exposing (main)\n\nimport Data exposing (a)\nimport Unused\n\nmain =\n    a\n";
        let data = src.find("import Data");
        assert_eq!(
            organize_imports_dropping(&module(src), |imp| kw_at(imp) == data),
            None
        );
        // Positive control: the same seam with the correct decision edits, so
        // the refusal above is the proof firing, not the seam being inert.
        let unused = src.find("import Unused");
        assert!(organize_imports_dropping(&module(src), |imp| kw_at(imp) == unused).is_some());
    }

    #[test]
    fn a_drop_decision_that_misses_a_constructor_use_is_refused() {
        let src = "module Main exposing (main)\n\nimport Shape exposing (Shape(Circle))\n\nmain =\n    Circle\n";
        assert_eq!(organize_imports_dropping(&module(src), |_| true), None);
    }

    #[test]
    fn a_drop_decision_on_an_opaque_module_is_refused() {
        let src = "module Main exposing (main)\n\nimport Zeta\nimport Alpha\n\nmain =\n    \"\"\"{{ Zeta.a }}\"\"\"\n";
        let zeta = src.find("import Zeta");
        assert_eq!(
            organize_imports_dropping(&module(src), |imp| kw_at(imp) == zeta),
            None
        );
        // Positive control: the module parses and a drop-free sort is offered.
        assert!(organize_imports_dropping(&module(src), |_| false).is_some());
    }

    /// [`drop_is_proven`] for `original` with the imports at `drop` (by
    /// position) dropped, against `output`. `None` when either fails to parse.
    fn proven(original: &str, drop: &[usize], output: &str) -> Option<bool> {
        let mut interner = Interner::new();
        let ast = ipe_parse::parse_module(original, &mut interner).ok()?;
        let mut out_interner = Interner::new();
        let out_ast = ipe_parse::parse_module(output, &mut out_interner).ok()?;
        let dropped: Vec<&Import> = ast
            .imports
            .iter()
            .enumerate()
            .filter(|(i, _)| drop.contains(i))
            .map(|(_, imp)| imp)
            .collect();
        Some(drop_is_proven(
            &ast,
            &interner,
            &dropped,
            &out_ast,
            &out_interner,
        ))
    }

    const HEAD: &str = "module Main exposing (main)\n\n";

    #[test]
    fn the_drop_proof_accepts_a_faithful_drop() {
        let original = format!("{HEAD}import Alpha\nimport Beta\n\nmain =\n    Alpha.a\n");
        let output = format!("{HEAD}import Alpha\n\nmain =\n    Alpha.a\n");
        assert_eq!(proven(&original, &[1], &output), Some(true));
    }

    #[test]
    fn the_drop_proof_refuses_losing_a_kept_import() {
        let original = format!("{HEAD}import Alpha\nimport Beta\n\nmain =\n    1\n");
        let output = format!("{HEAD}import Alpha\n\nmain =\n    1\n");
        assert_eq!(proven(&original, &[], &output), Some(false));
    }

    #[test]
    fn the_drop_proof_refuses_gaining_a_binding() {
        let original = format!("{HEAD}import Alpha\n\nmain =\n    1\n");
        let output = format!("{HEAD}import Alpha\nimport Gamma\n\nmain =\n    1\n");
        assert_eq!(proven(&original, &[], &output), Some(false));
    }

    #[test]
    fn the_drop_proof_refuses_a_dropped_import_still_referenced() {
        // The binding sets agree (Beta was dropped and is gone); only the
        // re-run usage walk on the output catches the live `Beta.b`.
        let original = format!("{HEAD}import Alpha\nimport Beta\n\nmain =\n    Beta.b\n");
        let output = format!("{HEAD}import Alpha\n\nmain =\n    Beta.b\n");
        assert_eq!(proven(&original, &[1], &output), Some(false));
    }

    #[test]
    fn a_qualifier_shared_with_a_kept_import_is_not_a_false_refusal() {
        let src = "module Main exposing (main)\n\nimport Data exposing (a)\nimport Data\n\nmain =\n    a\n";
        let out = organized(src);
        assert_eq!(out.matches("import Data").count(), 1, "got:\n{out}");
        assert!(out.contains("import Data exposing (a)\n"), "got:\n{out}");
    }

    #[test]
    fn organize_imports_sorts_by_module_path() {
        let src = "module Main exposing (main)\n\nimport Zeta\nimport Alpha\n\nmain =\n    (Zeta.a, Alpha.b)\n";
        let out = organized(src);
        let alpha_at = out.find("import Alpha");
        let zeta_at = out.find("import Zeta");
        assert!(
            matches!((alpha_at, zeta_at), (Some(a), Some(z)) if a < z),
            "sorted output, got:\n{out}"
        );
    }

    #[test]
    fn organize_imports_edits_only_the_import_block() {
        let src = "module Main exposing (main)\n\nimport Zeta\nimport Alpha\n\nmain =\n    (Zeta.a, Alpha.b)\n";
        let edit = organize_imports(&module(src), &LintConfig::default());
        assert!(
            matches!(&edit, Some(e) if src.get(e.lo..e.hi) == Some("import Zeta\nimport Alpha\n")
                && e.replacement == "import Alpha\nimport Zeta\n"),
            "{edit:?}"
        );
    }

    #[test]
    fn organize_imports_merges_duplicate_imports_and_sorts_exposing() {
        let src = "module Main exposing (main)\n\nimport Data exposing (b)\nimport Data exposing (a)\n\nmain =\n    (a, b)\n";
        let out = organized(src);
        assert_eq!(
            out.matches("import Data").count(),
            1,
            "duplicate imports merge into one, got:\n{out}"
        );
        assert!(
            out.contains("import Data exposing (a, b)"),
            "exposing lists union and sort, got:\n{out}"
        );
    }

    #[test]
    fn organize_imports_removes_a_wholly_unused_import() {
        let src = "module Main exposing (main)\n\nimport Data exposing (a)\nimport Unused\n\nmain =\n    a\n";
        let out = organized(src);
        assert!(
            !out.contains("Unused"),
            "unused import dropped, got:\n{out}"
        );
        assert!(
            out.contains("import Data exposing (a)"),
            "used import kept, got:\n{out}"
        );
    }

    #[test]
    fn organize_imports_keeps_as_alias() {
        let src = "module Main exposing (main)\n\nimport Zeta\nimport Data as D exposing (a)\n\nmain =\n    (D.x, a, Zeta.z)\n";
        let out = organized(src);
        assert!(
            out.contains("import Data as D exposing (a)\nimport Zeta\n"),
            "alias survives the rewrite, got:\n{out}"
        );
    }

    #[test]
    fn organize_imports_is_idempotent() {
        let src = "module Main exposing (main)\n\nimport Zeta\nimport Data exposing (b)\nimport Data exposing (a)\nimport Unused\n\nmain =\n    (Zeta.z, a, b)\n";
        let first = organized(src);
        assert_ne!(first, src, "the first pass rewrites");
        let second = organize_imports(&module(&first), &LintConfig::default());
        assert!(second.is_none(), "a second pass offers nothing: {second:?}");
    }

    #[test]
    fn organize_imports_keeps_an_import_used_only_in_a_type_annotation() {
        let src = "module Main exposing (main)\n\nimport Zeta\nimport Types exposing (Config)\n\nmain : Config -> Config\nmain x =\n    Zeta.id x\n";
        let out = organized(src);
        assert!(
            out.contains("import Types exposing (Config)"),
            "a type-annotation-only reference counts as used, got:\n{out}"
        );
    }

    #[test]
    fn organize_imports_preserves_crlf() {
        let src = "module Main exposing (main)\r\n\r\nimport Zeta\r\nimport Alpha\r\n\r\nmain =\r\n    (Zeta.a, Alpha.b)\r\n";
        let out = organized(src);
        assert!(
            out.contains("import Alpha\r\nimport Zeta\r\n"),
            "CRLF line endings kept, got:\n{out:?}"
        );
    }

    #[test]
    fn organize_imports_refuses_a_comment_in_the_block() {
        let src = "module Main exposing (main)\n\nimport Zeta\n-- keep this note\nimport Alpha\n\nmain =\n    (Zeta.a, Alpha.b)\n";
        let edit = organize_imports(&module(src), &LintConfig::default());
        assert!(edit.is_none(), "{edit:?}");
    }

    #[test]
    fn organize_imports_refuses_a_comment_inside_a_declaration() {
        let src = "module Main exposing (main)\n\nimport Zeta\nimport Alpha {- why -} exposing (b)\n\nmain =\n    (Zeta.a, b)\n";
        let edit = organize_imports(&module(src), &LintConfig::default());
        assert!(edit.is_none(), "{edit:?}");
    }

    #[test]
    fn organize_imports_is_a_no_op_on_a_parse_failure() {
        let src = "module Main exposing (main)\n\nimport Zeta\nimport Alpha\n\nmain = (\n";
        let edit = organize_imports(&module(src), &LintConfig::default());
        assert!(edit.is_none(), "{edit:?}");
    }

    #[test]
    fn organize_imports_refuses_a_declaration_sharing_a_line() {
        let src =
            "module Main exposing (main)\n\nimport Zeta\nimport Alpha main = (Zeta.a, Alpha.b)\n";
        let edit = organize_imports(&module(src), &LintConfig::default());
        assert!(edit.is_none(), "{edit:?}");
    }

    #[test]
    fn organize_imports_refuses_a_header_sharing_a_line() {
        let src = "module Main exposing (main) import Zeta\nimport Alpha\n\nmain =\n    (Zeta.a, Alpha.b)\n";
        let edit = organize_imports(&module(src), &LintConfig::default());
        assert!(edit.is_none(), "{edit:?}");
    }

    #[test]
    fn organize_imports_keeps_a_dotted_qualifier_import() {
        let src = "module Main exposing (main)\n\nimport Zeta\nimport App.Utils\n\nmain =\n    (Zeta.a, App.Utils.f)\n";
        let out = organized(src);
        assert!(out.contains("import App.Utils\n"), "got:\n{out}");
    }

    #[test]
    fn organize_imports_keeps_a_ctor_only_import() {
        let src = "module Main exposing (area)\n\nimport Zeta\nimport Geo exposing (Shape(Circle))\n\narea s =\n    case s of\n        Circle r ->\n            Zeta.f r\n";
        let out = organized(src);
        assert!(
            out.contains("import Geo exposing (Shape(Circle))\n"),
            "got:\n{out}"
        );
    }

    #[test]
    fn fix_all_applies_several_findings_in_one_file() {
        // `prefer-pipeline` fires only once the rewrite removes at least two
        // paren levels (`MIN_PAREN_LEVELS`); a one-level nest such as
        // `List.map fmt (List.filter live records)` is left alone, so this
        // fixture needs a third level (`String.concat (…)`) to qualify.
        let src = "module Main exposing (main)\n\nimport Unused\n\nmain =\n    String.concat (List.map fmt (List.filter live records))\n";
        let out = fixed(src, FIX_ALL_MAX_ROUNDS);
        assert!(!out.contains("Unused"), "unused import fixed, got:\n{out}");
        assert!(
            out.contains("|>"),
            "nested call flattened to a pipeline, got:\n{out}"
        );
    }

    #[test]
    fn fix_all_bounded_stops_at_the_round_bound() {
        // `Chain::of` walks an entire run of nested calls threaded through
        // trailing arguments in one pass, so a single finding already
        // flattens an arbitrarily deep pure `List.map (List.map (…))` nest —
        // that shape never needs a second round. A second round IS needed
        // when two findings' fix spans overlap: `apply_module_fixes` applies
        // the later (rightmost) one and skips the other for this round. Here
        // the outer `max 0 (min a (…))` chain's fix span covers the whole
        // expression, including the binop-operand chain nested inside it
        // (`String.concat (List.map fmt (List.filter live records))`, itself
        // qualifying at three levels); round 1 applies only the inner,
        // non-overlapping rewrite and leaves the outer chain — still
        // findable on the rewritten text — for round 2.
        let src = "module Main exposing (main)\n\nmain =\n    max 0 (min a (n + String.concat (List.map fmt (List.filter live records))))\n";

        let partial = fixed(src, 1);
        let Ok(residual) = run(
            &[module(&partial)],
            &LintConfig::default(),
            &crate::NeverCancel,
        );
        assert!(
            residual
                .findings
                .iter()
                .any(|f| f.rule == "prefer-pipeline"),
            "one round only partially flattens a 4-deep nest, got:\n{partial}"
        );

        let full = fixed(src, FIX_ALL_MAX_ROUNDS);
        let Ok(converged) = run(
            &[module(&full)],
            &LintConfig::default(),
            &crate::NeverCancel,
        );
        assert!(
            !converged
                .findings
                .iter()
                .any(|f| f.rule == "prefer-pipeline"),
            "enough rounds fully converge, got:\n{full}"
        );
    }

    #[test]
    fn fix_all_leaves_an_unfixable_finding_unapplied() {
        let src = "module Main exposing (main)\n\nmain =\n    unsafeDoIt\n";
        let out = fix_all(&[module(src)], &target(), &LintConfig::default());
        assert!(
            out.is_none(),
            "unsafe-convention carries no fix, nothing changes: {out:?}"
        );
        let Ok(report) = run(&[module(src)], &LintConfig::default(), &crate::NeverCancel);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule == "unsafe-convention"),
            "the unfixable finding still stands, got {:?}",
            report.findings
        );
    }

    #[test]
    fn fix_all_is_none_for_a_missing_module() {
        let src = "module Main exposing (main)\n\nimport Unused\n\nmain =\n    1\n";
        let out = fix_all(
            &[module(src)],
            &["Other".to_owned()],
            &LintConfig::default(),
        );
        assert!(out.is_none(), "{out:?}");
    }

    #[test]
    fn minimal_edit_is_whole_changed_lines() {
        let before = "a\nbb\ncc\nd\n";
        let after = "a\nbX\ncc\nd\n";
        let edit = minimal_edit(before, after);
        assert!(
            matches!(&edit, Some(e) if before.get(e.lo..e.hi) == Some("bb\n") && e.replacement == "bX\n"),
            "{edit:?}"
        );
        assert_eq!(edit.and_then(|e| e.apply(before)).as_deref(), Some(after));
    }

    #[test]
    fn minimal_edit_never_splits_crlf_or_a_char() {
        let before = "a\r\n\u{e9}\r\nz\r\n";
        let after = "a\r\n\u{e8}\r\nz\r\n";
        let edit = minimal_edit(before, after);
        assert!(
            matches!(&edit, Some(e) if before.get(e.lo..e.hi) == Some("\u{e9}\r\n")),
            "{edit:?}"
        );
        assert_eq!(edit.and_then(|e| e.apply(before)).as_deref(), Some(after));
    }

    #[test]
    fn minimal_edit_handles_pure_insertion_and_deletion() {
        for (before, after) in [
            ("a\nb\n", "a\nx\nb\n"),
            ("a\nx\nb\n", "a\nb\n"),
            ("a", "ab"),
        ] {
            let edit = minimal_edit(before, after);
            assert_eq!(
                edit.and_then(|e| e.apply(before)).as_deref(),
                Some(after),
                "{before:?} -> {after:?}"
            );
        }
        assert!(minimal_edit("same\n", "same\n").is_none());
    }

    #[test]
    fn fix_all_is_a_no_op_on_a_parse_failure() {
        let src = "module Main exposing (main)\n\nimport Unused\n\nmain = (\n";
        let out = fix_all(&[module(src)], &target(), &LintConfig::default());
        assert!(out.is_none(), "{out:?}");
    }
}
