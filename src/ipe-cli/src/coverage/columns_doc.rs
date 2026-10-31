//! The documentation aspect columns: documented, doc-example-checks.
//!
//! These read the stdlib source doc-comments — the `{-| … -}` block form and the
//! `-- |` line form, both recovered by [`ipe_docs::stdlib_docs`] — and the fenced
//! ` ```ipe ` examples inside them. The documented column reads source only; the
//! doc-example column type-checks each fenced example through the same
//! source-graph pipeline the build path uses, so it belongs to the E2E-adjacent
//! set but stays cheap (type-check, no cargo build).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::coverage::contract::{AspectCheck, Cell, StdlibSymbol, SymbolKind};

/// The short module name of a symbol — the dotted module with a leading `Ipe.`
/// stripped, matching [`ipe_docs::stdlib_docs::ModuleDoc::short`].
fn short_module(sym: &StdlibSymbol) -> String {
    let dotted = sym.module.join(".");
    dotted.strip_prefix("Ipe.").unwrap_or(&dotted).to_owned()
}

// ── documented ────────────────────────────────────────────────────────────────

/// Column **documented**: every exported value or type carries a doc-string.
///
/// [`ipe_docs::stdlib_docs`] recovers both doc-comment conventions the stdlib
/// uses (`{-| … -}` blocks and `-- |` line blocks) keyed by declaration name, so
/// this universalizes the per-module veneer doc-string check onto the whole
/// surface: an exported symbol whose declaration has no doc body is flagged. The
/// verdict is [`Cell::Warn`], not [`Cell::Hole`]: a missing doc-string is
/// documentation debt, not a correctness gap, so the column surfaces every
/// undocumented symbol without failing the gate — the severity split the contract
/// draws between a forgotten binding and an advisory. A non-exported symbol (a
/// kernel homed under a kernel qualifier, not reached through a compiled-source
/// `exposing`) is `NotApplicable` — the doc extractor reads compiled-source
/// declarations, and there is no source declaration to document. A constructor is
/// documented through its union type, so it is `NotApplicable` here (the type row
/// carries the doc).
pub struct DocumentedColumn {
    /// `(short module, symbol name)` → whether the declaration has a doc body.
    documented: BTreeMap<(String, String), bool>,
}

impl DocumentedColumn {
    #[must_use]
    pub fn new() -> Self {
        let mut documented = BTreeMap::new();
        for module in ipe_docs::stdlib_docs::all_module_docs() {
            for export in &module.exports {
                documented.insert(
                    (module.short.clone(), export.name.clone()),
                    export.doc.is_some(),
                );
            }
        }
        Self { documented }
    }
}

impl Default for DocumentedColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl AspectCheck<StdlibSymbol> for DocumentedColumn {
    fn name(&self) -> &'static str {
        "documented"
    }

    fn check(&self, sym: &StdlibSymbol) -> Cell {
        if !sym.exported || sym.kind == SymbolKind::Ctor {
            return Cell::not_applicable(
                "not an exported value or type — a doc-string is judged on exported \
                 values/types, not on unexported symbols or constructors",
            );
        }
        match self.documented.get(&(short_module(sym), sym.name.clone())) {
            Some(true) => Cell::Ok,
            Some(false) => Cell::Warn(format!(
                "exported {} {}.{} has no doc-string ({{-| … -}} or -- |)",
                kind_word(sym.kind),
                sym.module.join("."),
                sym.name
            )),
            // The doc extractor reads compiled-source declarations; an exported
            // symbol with no source declaration (a kernel-alias whose scheme
            // lives in the kernel table, addressed only through `exposing`) is not
            // a documentation hole here — its home module owns its surface.
            None => Cell::not_applicable(
                "no compiled-source declaration (a kernel-alias addressed only through \
                 `exposing`) — its home module owns its documentation surface",
            ),
        }
    }
}

/// A human word for a symbol kind, for a hole message.
const fn kind_word(kind: SymbolKind) -> &'static str {
    match kind {
        SymbolKind::Value => "value",
        SymbolKind::Type => "type",
        SymbolKind::Ctor => "constructor",
    }
}

// ── doc-example-checks ────────────────────────────────────────────────────────

/// Column **doc-example-checks**: every fenced ` ```ipe ` example in a symbol's
/// doc-string type-checks.
///
/// The doc body of each exported declaration may carry fenced ` ```ipe ` examples
/// (a ` ```ipe ipe:skip ` fence marks a documentation-only snippet, exempt). Each
/// example is wrapped in a synthetic `module Main` that imports the documenting
/// module `exposing (..)`, then type-checked through the same source-graph
/// pipeline the build uses. A symbol whose examples all type-check is `Ok`; one
/// whose example does not is a hole naming the failing example. A symbol with no
/// fenced example, a non-exported symbol, or a constructor is `NotApplicable`.
pub struct DocExampleColumn {
    /// `(short module, symbol name)` → the doc body, when the declaration has one.
    docs: BTreeMap<(String, String), String>,
    /// `short module` → dotted module name, for the synthetic import header.
    dotted_of_short: BTreeMap<String, String>,
    /// `dotted module` → its own `import …` lines, injected into the synthetic
    /// example module so a qualified name the documenting module imports (an alias
    /// included) resolves in the example exactly as it does inside that module.
    module_imports: BTreeMap<String, Vec<String>>,
}

impl DocExampleColumn {
    #[must_use]
    pub fn new() -> Self {
        let mut docs = BTreeMap::new();
        let mut dotted_of_short = BTreeMap::new();
        for module in ipe_docs::stdlib_docs::all_module_docs() {
            dotted_of_short.insert(module.short.clone(), module.dotted.clone());
            for export in &module.exports {
                if let Some(doc) = &export.doc {
                    docs.insert((module.short.clone(), export.name.clone()), doc.clone());
                }
            }
        }
        Self {
            docs,
            dotted_of_short,
            module_imports: stdlib_module_imports(),
        }
    }
}

/// Every stdlib module's own top-level `import …` lines, keyed by dotted module
/// name, gathered from the embedded sources.
fn stdlib_module_imports() -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for m in ipe_stdlib::MODULES {
        out.entry(m.name.to_owned())
            .or_insert_with(|| import_lines(m.source));
    }
    for m in ipe_stdlib::COMPILED_STD_MODULES {
        out.entry(m.dotted.to_owned())
            .or_insert_with(|| import_lines(m.source));
    }
    out
}

/// The verbatim top-level `import …` lines of a module source.
fn import_lines(source: &str) -> Vec<String> {
    source
        .lines()
        .filter(|line| line.starts_with("import "))
        .map(str::to_owned)
        .collect()
}

impl Default for DocExampleColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl AspectCheck<StdlibSymbol> for DocExampleColumn {
    fn name(&self) -> &'static str {
        "doc-example-checks"
    }

    fn check(&self, sym: &StdlibSymbol) -> Cell {
        if !sym.exported || sym.kind == SymbolKind::Ctor {
            return Cell::not_applicable(
                "not an exported value or type — doc-example checking applies to exported \
                 values/types only",
            );
        }
        let short = short_module(sym);
        let Some(doc) = self.docs.get(&(short.clone(), sym.name.clone())) else {
            return Cell::not_applicable(
                "no compiled-source doc-string for this symbol — nothing to extract an \
                 example from",
            );
        };
        let examples = fenced_ipe_examples(doc);
        if examples.is_empty() {
            return Cell::not_applicable(
                "the doc-string carries no fenced ```ipe example — nothing to type-check",
            );
        }
        let dotted = self
            .dotted_of_short
            .get(&short)
            .cloned()
            .unwrap_or_else(|| sym.module.join("."));
        let empty = Vec::new();
        let module_imports = self.module_imports.get(&dotted).unwrap_or(&empty);

        // Each example is the `Main` module of its own scratch project, so no
        // file outside it is a module of the check; RAII-cleaned on drop.
        for (index, body) in examples.iter().enumerate() {
            let module_src = synthesize_example_module(body, &dotted, module_imports);
            let scratch = match crate::project_root::ProjectRoot::scratch(&module_src) {
                Ok(scratch) => scratch,
                Err(e) => {
                    return Cell::Hole(format!(
                        "could not write {}.{}'s example {} to type-check it: {e}",
                        sym.module.join("."),
                        sym.name,
                        index + 1
                    ));
                }
            };
            if let Err(err) = crate::driver::typecheck_stage_target(
                &crate::project_root::AnalysisTarget::Project(scratch.root()),
            ) {
                return Cell::Hole(format!(
                    "{}.{} doc-string example {} does not type-check: {err}",
                    sym.module.join("."),
                    sym.name,
                    index + 1
                ));
            }
        }
        Cell::Ok
    }
}

/// Extract the body of every fenced ` ```ipe ` block in a doc body, dropping any
/// fence carrying a `skip` info-string (a documentation-only snippet the gate is
/// asked to exempt, e.g. one needing a cross-module context this synthetic module
/// cannot supply).
fn fenced_ipe_examples(doc: &str) -> Vec<String> {
    const FENCE_OPEN: &str = "```ipe";
    const FENCE_CLOSE: &str = "```";

    let mut examples = Vec::new();
    let mut search = 0usize;
    while let Some(open_rel) = doc[search..].find(FENCE_OPEN) {
        let after_open = search + open_rel + FENCE_OPEN.len();
        // The rest of the opening fence line is the info string.
        let content_start = doc[after_open..]
            .find('\n')
            .map_or(doc.len(), |nl| after_open + nl + 1);
        let info = doc[after_open..content_start].trim();
        let Some(close_rel) = doc[content_start..].find(FENCE_CLOSE) else {
            break;
        };
        let content_end = content_start + close_rel;
        if !info.contains("skip") {
            let body = doc[content_start..content_end].trim_end_matches('\n');
            examples.push(body.to_owned());
        }
        search = content_end + FENCE_CLOSE.len();
    }
    examples
}

/// The dotted module an `import …` line names, e.g. `Ipe.Duration` from
/// `import Ipe.Duration as Duration exposing (Duration)`.
fn import_line_module(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("import ")?;
    Some(rest.split_whitespace().next().unwrap_or(rest))
}

/// Wrap an example body in a synthetic `module Main` that imports the documenting
/// module `exposing (..)` (its unqualified names in scope), injects that module's
/// own imports (so a qualified alias it uses resolves), and adds a fixed fallback
/// import for a common qualified prefix the example reaches that the documenting
/// module does not itself import. An example already starting with `module ` is
/// returned verbatim; it is checked as its project's `Main` module, so its
/// header must name `Main`.
///
/// A line carrying `-->` is an expression/result annotation: the expression
/// before the arrow becomes a fresh top-level binding (`docCheckN = <expr>`) so
/// the type-checker reaches it without needing a `main` entry, mirroring the
/// stdlib doc-example gate's scoping exactly.
fn synthesize_example_module(body: &str, source_module: &str, module_imports: &[String]) -> String {
    if body.trim_start().starts_with("module ") {
        return body.to_owned();
    }

    let mut out = String::from("module Main exposing (..)\n");
    let mut imported: Vec<&str> = Vec::new();

    if !source_module.is_empty() {
        let short = source_module
            .split('.')
            .next_back()
            .unwrap_or(source_module);
        let _ = writeln!(out, "\nimport {source_module} as {short} exposing (..)");
        imported.push(source_module);
    }

    for import in module_imports {
        if let Some(module) = import_line_module(import)
            && !imported.contains(&module)
        {
            out.push('\n');
            out.push_str(import);
            imported.push(module);
        }
    }

    // A fixed fallback for a common qualified prefix the example uses that the
    // documenting module does not itself import (e.g. a `Ipe.Result` example
    // reaching for `String.fromInt`).
    for (prefix, import) in FALLBACK_IMPORTS {
        let Some(module) = import_line_module(import) else {
            continue;
        };
        if body.contains(prefix) && !imported.contains(&module) {
            out.push('\n');
            out.push_str(import);
            imported.push(module);
        }
    }
    out.push('\n');

    emit_example_bindings(&mut out, body);
    out
}

/// Emit each example item as source the type-checker reaches.
///
/// An item is a run of expression lines, assembled into one `docCheckN = …`
/// binding so a multi-line expression (a pipeline, a bracketed call) is one
/// binding rather than each line orphaned at top level. The run ends at a
/// boundary: an inline `-->` result annotation (its expression before the arrow
/// closes the run), a standalone result annotation, a `--` comment line (a
/// `-- == …` expected-result note), a blank line, a top-level declaration, or an
/// import. A declaration and an import are emitted verbatim, so a standalone
/// helper decl stays a decl; annotations and blank lines only close the run.
fn emit_example_bindings(out: &mut String, body: &str) {
    let mut check_idx = 0usize;
    let mut pending: Vec<&str> = Vec::new();

    let flush_binding = |out: &mut String, check_idx: &mut usize, pending: &mut Vec<&str>| {
        let expr = pending.join("\n");
        pending.clear();
        if expr.trim().is_empty() {
            return;
        }
        *check_idx += 1;
        let _ = writeln!(out, "docCheck{check_idx} =");
        for expr_line in expr.lines() {
            let _ = writeln!(out, "    {expr_line}");
        }
    };

    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(arrow) = line.find("-->") {
            let head = line[..arrow].trim_end();
            if !head.trim().is_empty() {
                pending.push(head);
            }
            flush_binding(out, &mut check_idx, &mut pending);
        } else if trimmed.is_empty() || trimmed.starts_with("--") {
            // A blank line or a comment (a `-- == …` expected-result note) closes
            // the current expression; it never extends it.
            flush_binding(out, &mut check_idx, &mut pending);
        } else if is_top_level_decl(line) || line.starts_with("import ") {
            flush_binding(out, &mut check_idx, &mut pending);
            out.push_str(line);
            out.push('\n');
        } else {
            pending.push(line);
        }
    }
    flush_binding(out, &mut check_idx, &mut pending);
}

/// Whether a line opens a top-level declaration — a bare name at column zero
/// followed by a `=` or a `:` type signature — as opposed to a continuation line
/// of a multi-line expression.
fn is_top_level_decl(line: &str) -> bool {
    let Some(first) = line.chars().next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    let Some((head, _)) = line.split_once(['=', ':']) else {
        return false;
    };
    head.split_whitespace().count() == 1
}

/// The fixed fallback imports for a qualified prefix a doc example commonly
/// reaches for, mirroring the stdlib doc-example gate's fallback set.
const FALLBACK_IMPORTS: &[(&str, &str)] = &[
    ("Maybe.", "import Ipe.Maybe as Maybe exposing (Maybe(..))"),
    ("List.", "import Ipe.List as List"),
    ("String.", "import Ipe.String as String"),
    ("Dict.", "import Ipe.Dict as Dict"),
    ("Set.", "import Ipe.Set as Set"),
    (
        "Result.",
        "import Ipe.Result as Result exposing (Result(..))",
    ),
    ("Task.", "import Ipe.Task as Task"),
    ("Io.", "import Ipe.Io as Io"),
    ("Debug.", "import Ipe.Debug as Debug"),
    ("Char.", "import Ipe.Char as Char"),
    ("Tuple.", "import Ipe.Tuple as Tuple"),
];
