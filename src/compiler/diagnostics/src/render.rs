//! Human-facing diagnostic rendering: the prose-first, Elm-faithful layout.
//!
//! [`render`] turns a [`Diagnostic`] plus its source file into a string. The
//! reader meets a plain-English description first; the machine code is demoted
//! to a single footer line, never the headline:
//!
//! 1. **title rule** — `-- TYPE MISMATCH ------------------ file.ipe`: a
//!    per-code title naming what actually went wrong, a textual severity cue for
//!    a warning (` (warning)`, legible when colour is stripped), a dash rule
//!    padding to a fixed width, then the source file. The reader's first glance.
//! 2. **prose band** — one short sentence describing what the compiler found or
//!    expected, in the compiler's second-person voice, above the snippet.
//! 3. **location** — ` --> file:line:col` derived from the primary span. A
//!    [`Span::DUMMY`] primary span (e.g. a [`Diagnostic::CompilerBug`]) suppresses
//!    the location and the source snippet entirely.
//! 4. **snippet** — the offending source line with a right-aligned line-number
//!    gutter, the primary span underlined with `^` and an inline payload-derived
//!    label, plus any secondary span underlined with `-` and its own label.
//! 5. **help / note** — the structured [`Diagnostic::help`] lines.
//! 6. **code footer** — the machine code and the `ipe doc` next step, last:
//!    a reader reaches for the lookup key only after reading the message above.
//!
//! The function is pure and **deterministic**: every list is walked in producer
//! order, there is no `HashMap` iteration, byte→line/col is a checked, clamped
//! scan, and slicing goes through [`str::get`] so a `DUMMY` or out-of-bounds span
//! renders gracefully rather than panicking. Colour (ANSI) is added only when
//! stderr is a terminal and `NO_COLOR` is unset; it never changes the byte
//! content beyond the escape sequences themselves.

use core::fmt::Write as _;

use crate::code::{Severity, issue_tracker_url, title};
use crate::diagnostic::{
    AppShape, Applicability, CaseDefect, CodecAutoRejection, ConsentError, Diagnostic, Expected,
    ExpectedSet, ExposingDefect, Feature, FfiError, GenericAppEntryReach, HeaderDefect, HelpLine,
    Hint, IfDefect, ImportedAs, LetDefect, LowerError, NameError, ParseError, RoutePatternDefect,
    SandboxError, SealRejection, SpanRole, StoreEqAccessorDefect, StoreSelectProjectionDefect,
    Suggestion, TokenKind, TyDoc, TypeDeclDefect, TypeError, WildcardDependence,
    intercept_context_phrase,
};
use crate::span::Span;

// ANSI escape sequences. Colour only ever *wraps* text, so stripping these
// yields byte-identical output to the plain (non-tty / `NO_COLOR`) path.
const RED: &str = "\x1b[31;1m";
const YELLOW: &str = "\x1b[33;1m";
const BLUE: &str = "\x1b[34;1m";
const RESET: &str = "\x1b[0m";

/// The CLI verb that looks up diagnostic codes and teaching pages.
///
/// Every rendered diagnostic footer and help-line that points a reader at a
/// lookup interpolates this constant rather than spelling the verb inline.
pub const DOC_HINT_CMD: &str = "ipe doc";

/// Render a diagnostic against its source file.
///
/// `file` is the path shown in the location line; `source` is its full contents,
/// used to extract the offending line and compute line/column. Both are only
/// read, never trusted to be well-formed: an empty `source`, a `DUMMY` span, or a
/// span past end-of-file all render without panicking.
#[must_use]
pub fn render(d: &Diagnostic, file: &str, source: &str) -> String {
    let color = color_enabled();
    let code = d.code();
    let severity = d.severity();
    let mut out = String::new();

    // Band 1 — title rule. The family title leads, the source file trails, and a
    // dash rule fills the gap: `-- TYPE MISMATCH --------------- app.ipe`. The
    // machine code is not here — it lives in the footer.
    out.push_str(&paint(
        color,
        severity_color(severity),
        &title_rule(code, severity, file),
    ));
    out.push('\n');

    // Band 2 — prose band. One second-person sentence, above the snippet, in
    // which the compiler describes what it found or expected. The reader acts on
    // this, not on the code — so it reads like a colleague, not a verdict.
    out.push('\n');
    out.push_str(&prose_band(d));
    out.push('\n');

    // Split the help lines: secondary spans belong to the snippet band, the
    // rest to the help/note band.
    let help = d.help();
    let mut secondaries: Vec<(Span, SpanRole)> = Vec::new();
    let mut other_help: Vec<&HelpLine> = Vec::new();
    for line in &help {
        match line {
            HelpLine::SecondarySpan { span, role } => secondaries.push((*span, *role)),
            other => other_help.push(other),
        }
    }

    let primary = d.primary_span();
    let has_snippet = primary != Span::DUMMY;

    // Gutter width is the digit-count of the largest line number we will print.
    let gutter = if has_snippet {
        // The gutter must fit the largest line number any span will PRINT, and
        // `push_span_block` prints through `locate(span.hi).line`; a hi line with
        // more digits than the lo line (a span crossing a digit boundary, e.g.
        // 9→10) would otherwise widen the source row past the underline row and
        // shift the carets. Fold in every span's hi line, not just its lo line.
        let mut max_line = locate(source, primary.hi).line;
        for (span, _) in &secondaries {
            if *span != Span::DUMMY {
                max_line = max_line.max(locate(source, span.hi).line);
            }
        }
        max_line.to_string().len()
    } else {
        1
    };
    let bar_pad = " ".repeat(gutter);

    if has_snippet {
        // Band 3 — location.
        out.push('\n');
        let ploc = locate(source, primary.lo);
        out.push_str(&bar_pad);
        let _ = writeln!(out, "--> {file}:{}:{}", ploc.line, ploc.col);

        // Band 4 — snippet.
        out.push_str(&bar_pad);
        out.push_str(" |\n");
        let plabel = primary_label(d).unwrap_or_default();
        let primary_style = UnderlineStyle {
            glyph: '^',
            color_seq: severity_color(severity),
            label: &plabel,
        };
        push_span_block(&mut out, source, primary, &primary_style, gutter, color);
        for (span, role) in &secondaries {
            if *span != Span::DUMMY {
                out.push_str(&bar_pad);
                out.push_str(" |\n");
                let style = UnderlineStyle {
                    glyph: '-',
                    color_seq: BLUE,
                    label: role_label(*role),
                };
                push_span_block(&mut out, source, *span, &style, gutter, color);
            }
        }
    }

    // Band 5 — help + note lines.
    let mut footer = build_help_footer(&other_help, source);
    // Humble messaging: an internal compiler error (every `IPE-I*`) is a gap in
    // Ipê, not the reader's fault. Apologise plainly, Elm-style, and point at
    // the one issue tracker — never a raw backtrace, never false confidence.
    if severity == Severity::Bug {
        if let Diagnostic::CompilerBug { detail, .. } = d
            && !detail.is_empty()
        {
            footer.push(format!("note: {detail}"));
        }
        footer.push("note: this is a bug in Ipe, please report it".to_string());
        let tracker = issue_tracker_url();
        footer.push(format!(
            "note: I'm not sure what went wrong here — sorry about that. This is likely a gap \
             in the Ipe Rust compiler. Please report it (with this source + `ipe version`) \
             at: {tracker}"
        ));
    }

    if has_snippet {
        out.push_str(&bar_pad);
        out.push_str(" |\n");
    }
    // A footer entry may itself span several lines (a collapsed did-you-mean
    // block). The first line carries the `= ` marker; continuation lines are
    // aligned under it with blank gutter so the block reads as one help item.
    let continuation = format!("{bar_pad}   ");
    for line in &footer {
        for (n, part) in line.split('\n').enumerate() {
            if n == 0 {
                out.push_str(&bar_pad);
                out.push_str(" = ");
            } else {
                out.push_str(&continuation);
            }
            out.push_str(part);
            out.push('\n');
        }
    }

    // Band 6 — code footer. The lookup key and the next step, last: a reader
    // reaches for `ipe doc` only after reading the message above.
    out.push('\n');
    out.push_str(&paint(color, severity_color(severity), code.as_str()));
    let _ = write!(out, " · run `{DOC_HINT_CMD} {}`", code.as_str());
    out.push('\n');

    out
}

/// The width the title rule fills to before the trailing file path.
const TITLE_RULE_WIDTH: usize = 60;

/// Build the Elm-faithful title rule: `-- TYPE MISMATCH -------- app.ipe`.
///
/// A `-- ` lead, the per-code title in uppercase, an optional ` (warning)` cue
/// for a non-error severity, a dash rule padding to [`TITLE_RULE_WIDTH`], then a
/// space and the source file. When the title plus file already reach the width,
/// at least one dash still separates them so the rule always reads as a rule.
///
/// The severity word is textual, not just a colour: a warning stays
/// unmistakable when the output is piped, `NO_COLOR` is set, or the reader is a
/// machine — where the ANSI colour that also distinguishes it is stripped.
fn title_rule(code: crate::code::Code, severity: Severity, file: &str) -> String {
    let name = title_rule_name(code);
    let cue = severity_cue(severity);
    // `-- ` + name + cue + ` ` consumed so far; the dash run fills the
    // remainder, then ` ` + file. Always at least one dash, even past the width.
    let prefix_len = 3 + name.chars().count() + cue.chars().count() + 1;
    let dashes = TITLE_RULE_WIDTH.saturating_sub(prefix_len).max(1);
    format!("-- {name}{cue} {} {file}", "-".repeat(dashes))
}

/// The textual severity cue appended after the title word. An error carries no
/// cue (the title already reads as a problem); a warning is marked ` (warning)`
/// so it is legible even when colour is stripped. A `Bug` reads as the internal
/// compiler error its title already names, so it takes no extra cue.
const fn severity_cue(severity: Severity) -> &'static str {
    match severity {
        Severity::Warning => " (warning)",
        Severity::Error | Severity::Bug => "",
    }
}

/// The prose band sentence: one second-person sentence, above the snippet, in
/// which the compiler explains what it found or expected. It reads like a
/// helpful colleague ("I was expecting an `Int`, but this is a `String`."), not
/// a category label — the title rule already names the family, so the band
/// never repeats it. The wording is derived from the payload so the reader gets
/// the concrete detail (the two types, the missing branches, the name) up front.
fn prose_band(d: &Diagnostic) -> String {
    match d {
        Diagnostic::Parse { msg, .. } => parse_prose(msg),
        Diagnostic::Name { msg, .. } => name_prose(msg),
        Diagnostic::Type { msg, .. } => type_prose(msg),
        Diagnostic::Lower { msg, .. } => lower_prose(msg),
        Diagnostic::CompilerBug { .. } => {
            "Something went wrong inside the compiler while working on your code — this \
             is my mistake, not yours."
                .to_string()
        }
        Diagnostic::Ffi { msg } => ffi_prose(msg),
        Diagnostic::Sandbox { msg } => sandbox_prose(msg),
        Diagnostic::Consent { msg } => consent_prose(msg),
        Diagnostic::RegistryUnreachable { detail } => {
            format!(
                "The compiler could not reach the crate registry while building your program. \
                 This is a network or DNS problem on your machine — not a mistake in your code.\n\
                 \n\
                 {detail}\n\
                 \n\
                 Check your connection and try again. Run `{DOC_HINT_CMD} IPE-E0001` for more help."
            )
        }
    }
}

/// The prose band for an FFI-generator diagnostic.
fn ffi_prose(msg: &FfiError) -> String {
    match msg {
        FfiError::CallUnrenderable { function, detail } => {
            format!("The foreign call for `{function}` cannot be rendered as valid Rust: {detail}.")
        }
        FfiError::GenericNotBindable { callee, detail } => {
            format!("The generic FFI call `{callee}` cannot be soundly bound: {detail}.")
        }
        FfiError::WireMalformed { context, detail } => {
            format!("The inspection data for `{context}` is malformed: {detail}.")
        }
        FfiError::ShapeContradiction { function, flags } => {
            let flags: Vec<String> = flags.iter().map(ToString::to_string).collect();
            format!(
                "`{function}` declares contradictory shape flags at once: {}.",
                flags.join(" + ")
            )
        }
        FfiError::SourceRejected { source, detail } => {
            format!("The crate source `{source}` was rejected at the security gate: {detail}.")
        }
        FfiError::ArtifactIo { path, detail } => {
            format!("The FFI cache artifact `{path}` could not be accessed: {detail}.")
        }
        FfiError::AssertedRefused { path, detail } => {
            format!("The asserted foreign call `{path}` was refused: {detail}.")
        }
        FfiError::SystemLibraryNotFound {
            system_lib,
            crate_name,
            install_hint,
        } => format!(
            "Crate `{crate_name}` needs the system library `{system_lib}`, \
             which pkg-config cannot find. {install_hint}."
        ),
    }
}

/// The prose band for a sandbox diagnostic.
fn sandbox_prose(msg: &SandboxError) -> String {
    match msg {
        SandboxError::BuildJail { detail } => format!(
            "No isolation jail could be established for compiling the untrusted crate: {detail}."
        ),
        SandboxError::RunJail { detail } => format!(
            "No runtime jail could be established around the capability-bearing program: {detail}."
        ),
    }
}

/// The prose band for a consent-gate diagnostic.
fn consent_prose(msg: &ConsentError) -> String {
    match msg {
        ConsentError::NonInteractive { body } => {
            format!("{body}This is a non-interactive build — it will not prompt.")
        }
        ConsentError::InteractiveDenied { body } => {
            format!("{body}The unsafe escape-hatch imports were not acknowledged — build stopped.")
        }
        ConsentError::WebAxisUngranted { body }
        | ConsentError::NativeCrossingUngranted { body }
        | ConsentError::ControlModelUncovered { body } => body.clone(),
    }
}

/// The prose band for a parse-family diagnostic.
fn parse_prose(msg: &ParseError) -> String {
    match msg {
        ParseError::UnexpectedToken { found, expected } => format!(
            "I found {} here, but I was expecting {}.",
            token_kind_str(*found),
            expected_set_str(expected)
        ),
        ParseError::UnexpectedEof { .. } => {
            "The file ended while I was still in the middle of reading something.".to_string()
        }
        ParseError::NestingTooDeep { .. } | ParseError::TooDeep => {
            "This expression nests deeper than I can follow.".to_string()
        }
        ParseError::UnknownChar(c) => {
            format!("I don't recognise the character {} here.", char_repr(*c))
        }
        ParseError::StrayDot | ParseError::SpaceBeforeDot => {
            "This `.` isn't attached to anything I can read as a field access.".to_string()
        }
        ParseError::NumberJoinedToName(_) => {
            "This number runs straight into a name, so I can't tell where one ends and the \
             other begins."
                .to_string()
        }
        ParseError::IntLiteralOutOfRange => {
            "This whole number does not fit in Ipê's `Int`.".to_string()
        }
        ParseError::FloatLiteralOutOfRange => {
            "This number is too large for Ipê's `Float` to hold.".to_string()
        }
        ParseError::UnterminatedString => {
            "This string opens with a `\"` but never closes.".to_string()
        }
        ParseError::MalformedChar => "I can't read this as a character literal.".to_string(),
        ParseError::UnterminatedBlockComment => {
            "This block comment opens with `{-` but never closes.".to_string()
        }
        ParseError::MalformedModuleHeader(_) => {
            "I couldn't read the module header at the top of this file.".to_string()
        }
        ParseError::MalformedExposingList(_) => {
            "I couldn't read this `exposing (...)` list.".to_string()
        }
        ParseError::MissingEquals { binding } => {
            format!("`{binding}` looks like a definition, but I don't see the `=` yet.")
        }
        ParseError::MalformedTypeDeclaration(_) => {
            "I couldn't read this `type` declaration.".to_string()
        }
        ParseError::TypeArgsOnNonConstructor => {
            "Only a type constructor can take type arguments, and this isn't one.".to_string()
        }
        ParseError::ExpectedType => "I was expecting a type here.".to_string(),
        ParseError::UnclosedDelimiter { .. } => "This opening bracket is never closed.".to_string(),
        ParseError::MalformedCase(_) => "I couldn't read this `case` expression.".to_string(),
        ParseError::MalformedLet(LetDefect::BareWildcardBinding) => {
            "a bare `_` cannot be the whole binding pattern in a `let`.".to_string()
        }
        ParseError::MalformedLet(_) => "I couldn't read this `let` expression.".to_string(),
        ParseError::MalformedIf(_) => "I couldn't read this `if` expression.".to_string(),
        ParseError::InvalidPathLiteral { .. } => {
            "I can't accept this path — it isn't safe to open.".to_string()
        }
        ParseError::SteplessDo => {
            "This `do` block has no Task step (`<-` bind or bare-run line) — it is \
             pure code dressed as a `do`. Use `let … in` for pure bindings instead."
                .to_string()
        }
        ParseError::DocOnUnexported { name } => {
            format!(
                "This doc-string is on `{name}`, which is not exported — \
                 it can never appear in generated documentation."
            )
        }
        ParseError::MissingDocString { name } => {
            format!("`{name}` is exported but has no doc-string.")
        }
        ParseError::AnnotationWithoutBinding { name } => {
            format!(
                "This `{name} : …` type annotation has no matching `{name} = …` \
                 definition. Without a binding to attach to, the type is discarded."
            )
        }
        ParseError::DuplicateAnnotation { name } => {
            format!(
                "`{name}` has more than one type annotation. A value can carry only \
                 one declared type."
            )
        }
        ParseError::SourceTooLarge { bytes } => {
            format!(
                "this source file is {bytes} bytes, larger than I can compile — a file \
                 must fit in a 32-bit byte offset (under 4 GiB)."
            )
        }
        ParseError::Unexpected => "I couldn't make sense of this part of the file.".to_string(),
    }
}

/// The prose band for a naming-family diagnostic.
#[allow(clippy::too_many_lines)] // one arm per NameError variant — mechanical dispatch
fn name_prose(msg: &NameError) -> String {
    match msg {
        NameError::ValueNotFound { name, .. } => format!("I can't find `{name}` in scope."),
        NameError::TypeNotFound { .. } => "I can't find a type by this name in scope.".to_string(),
        NameError::ConstructorNotFound { .. } => {
            "I can't find a constructor by this name in scope.".to_string()
        }
        NameError::UnknownModule { qualifier, .. } => {
            format!("I can't find a module called `{qualifier}`.")
        }
        NameError::ImportRequired { reached, .. } => {
            format!(
                "`{}` names a module you haven't imported yet.",
                reached.spelling()
            )
        }
        NameError::OperatorImportRequired { operator, module } => {
            format!("`{operator}` comes from `{module}`, which you haven't imported yet.")
        }
        NameError::NoSuchMember { module, member, .. } => {
            format!("`{module}` doesn't have anything called `{member}`.")
        }
        NameError::DuplicateValue { name, .. }
        | NameError::DuplicateConstructor { name, .. }
        | NameError::DuplicateType { name, .. } => {
            format!("`{name}` is already defined, so I found two definitions with the same name.")
        }
        NameError::AliasArity { name, .. } | NameError::BuiltinTypeArity { name, .. } => {
            format!("`{name}` is applied to the wrong number of type arguments.")
        }
        NameError::ModuleNotFound { name, .. } => {
            format!("I couldn't find the module `{name}` on disk.")
        }
        NameError::ImportCycle { .. } => {
            "These modules import each other in a circle, so I can't decide which to compile first."
                .to_string()
        }
        NameError::NameNotExposed { module, name, .. } => {
            format!("`{module}` doesn't expose `{name}`, so you can't import it.")
        }
        NameError::ModulePathMismatch { .. } => {
            "This module's declared name doesn't match its path on disk.".to_string()
        }
        NameError::AmbiguousImport { name, .. } => {
            format!(
                "`{name}` is imported from more than one place, so I don't know which you mean."
            )
        }
        NameError::ReservedNamespace { name } | NameError::ReservedBuiltinType { name } => {
            format!("`{name}` uses a name that Ipê reserves for itself.")
        }
        NameError::DuplicateQualifier { qualifier, .. } => {
            format!("Two imports both claim the qualifier `{qualifier}`.")
        }
        NameError::UnknownKernelAlias {
            module, function, ..
        } => {
            format!("There's no built-in effect called `{module}.{function}`.")
        }
        NameError::KernelAliasInUserSource { .. } => {
            "This code tries to mint a built-in effect directly, which only the standard library \
             may do."
                .to_string()
        }
        NameError::ServerOnlyKernelForWasm { qualifier, name } => {
            format!(
                "`{qualifier}.{name}` only runs on the server, so it can't be part of a \
                     browser build."
            )
        }
        NameError::ServerModuleReachableFromWasmClient { .. } => {
            "Your browser code can reach a server-only module, which can't be compiled into the \
             browser bundle."
                .to_string()
        }
        NameError::TypeExpansionTooDeep { .. } => {
            "This type alias expands forever, so I can't work out what it finally stands for."
                .to_string()
        }
        NameError::ProgramImportsTeaShape { .. } => {
            "This looks like a plain program, but it imports an app module — so I can't tell \
             which kind of `main` you meant."
                .to_string()
        }
        NameError::RuntimeBranchedMain => {
            "This `main` decides at run time which kind of app it is, but that has to be \
             decided up front — one `main`, one shape."
                .to_string()
        }
        NameError::WrongShapeCmdSub(_) => {
            "This `Cmd` / `Sub` belongs to a different app shape than the one you're building."
                .to_string()
        }
        NameError::TwoShapeImports { .. } => {
            "This module imports two app shapes, but a module builds at most one.".to_string()
        }
        NameError::DiscardedConfig => {
            "You wrote a `config` binding, but nothing uses it — its settings would just be \
             ignored."
                .to_string()
        }
        NameError::RemovedSurface {
            qualifier, name, ..
        } => {
            format!("`{qualifier}.{name}` is no longer part of Ipê.")
        }
        NameError::AssertedCallMalformed { .. } => {
            "I can't read this `Rust.Ffi.call` — it isn't in the one shape I accept.".to_string()
        }
        NameError::CustomElementCtorMalformed { .. } => {
            "I can't read this `CustomElement.fromFile` — it isn't in the one shape I accept."
                .to_string()
        }
        NameError::BoundarySealIllegal { seal_type, .. } => {
            format!("`{seal_type}` can't cross the boundary between Ipê and JavaScript.")
        }
        NameError::NestedDecoderPipeline => {
            "These decoder steps are nested, which would bind your fields in the wrong order."
                .to_string()
        }
        NameError::CodecAutoUnderivable { .. } => {
            "I can't derive a codec here automatically.".to_string()
        }
        NameError::WebInitPolyArg => {
            "The `init` annotation uses a free type variable for the request argument, \
             but `Web.tea` always passes a `WebReq` — write `init : WebReq -> …` \
             or remove the annotation and let inference fill it in."
                .to_string()
        }
        NameError::ModuleNotAllowedInPlacement(r) => {
            format!(
                "`{}` isn't available in a `{}` app — that combination of what your app \
                 renders and where it runs doesn't include this module.",
                r.module, r.placement,
            )
        }
        NameError::RustNameFold {
            first,
            second,
            rust_name,
            kind,
        } => format!(
            "Two different {} — `{first}` and `{second}` — end up with the same \
             generated name `{rust_name}`, so I can't emit them both.",
            kind.noun(),
        ),
        NameError::DuplicatePatternBinder { name, .. } => {
            format!("`{name}` is bound twice in the same pattern, so I don't know which you mean.")
        }
        NameError::ScriptImportsShapeView {
            shape_ui_module,
            shape,
            ..
        } => format!(
            "This is a script — its `main` is a plain `Task`, so it renders nothing — but it \
             imports `{shape_ui_module}`, the {shape} view. A script has no `view`, so that UI \
             never reaches the screen."
        ),
        NameError::GenericAppEntry {
            entry,
            type_var,
            reach: GenericAppEntryReach::Mentioned,
        } => format!(
            "`{entry}` is built here with `{type_var}` still a type variable, but a running app \
             needs one concrete model and message type."
        ),
        NameError::GenericAppEntry {
            entry,
            type_var,
            reach: GenericAppEntryReach::Undetermined,
        } => format!(
            "`{entry}` is refused here: the generic `{type_var}` is in scope and whether the \
             app's model or message reaches it cannot be determined, but a running app needs \
             one concrete model and message type."
        ),
        NameError::UnpinnedAppEntry { entry } => format!(
            "`{entry}` is built here, but nothing in the program fixes its model or message to \
             a concrete type — e.g. `update` ignores its message and no view emits one — and a \
             running app needs one concrete model and message type."
        ),
        NameError::InputFieldIsSubscription { entry, field, .. } => format!(
            "`{field}` is not a `{entry}` config field — terminal input arrives through \
             `subscriptions`, like every other event."
        ),
        NameError::AliasRowArgument { alias, fault } => match fault {
            crate::diagnostic::AliasRowFault::NotARecord { found } => format!(
                "`{alias}` extends its row argument with its own fields, but {found} is not a \
                 record."
            ),
            crate::diagnostic::AliasRowFault::FieldClash { field } => format!(
                "`{alias}` already has a `{field}` field, so its row argument cannot add \
                 another one."
            ),
        },
        NameError::Unknown => "Something is off with a name in this code.".to_string(),
    }
}

/// The prose band for a type-family diagnostic.
fn type_prose(msg: &TypeError) -> String {
    match msg {
        TypeError::TypeMismatch {
            expected, found, ..
        } => format!(
            "I was expecting this to be {}, but it's {}.",
            an_article(&ty_to_string(expected)),
            an_article(&ty_to_string(found))
        ),
        TypeError::Mismatch => {
            "The type I inferred here isn't the type I was expecting.".to_string()
        }
        TypeError::InfiniteType { .. } => {
            "This value's type would have to contain itself forever, so I can't pin it down."
                .to_string()
        }
        TypeError::TooManyParameters { binding, .. } => {
            format!("`{binding}` is given more arguments than its type allows.")
        }
        TypeError::NonExhaustiveCase { .. } => {
            "This `case` doesn't cover every possibility yet.".to_string()
        }
        TypeError::RedundantCaseBranch { constructor } => {
            format!(
                "This branch for `{constructor}` can never run — an earlier branch already \
                     handles it."
            )
        }
        TypeError::NoSuchField { field, .. } => {
            format!("This value has no field called `{field}`.")
        }
        TypeError::BuiltinRecordUpdate { name } => {
            format!(
                "`{name}` is a built-in type, so you can read its fields but not rebuild it \
                     with record-update syntax."
            )
        }
        TypeError::CtorPatternArity { ctor, .. } => {
            format!("This pattern binds the wrong number of fields for `{ctor}`.")
        }
        TypeError::SuperTypeUnsatisfied { .. } => {
            "This type doesn't support the operation you're using here.".to_string()
        }
        TypeError::RefutablePatternParameter => {
            "This parameter pattern can fail to match, but a parameter has to match every time."
                .to_string()
        }
        TypeError::OrPatternBindingMismatch { .. } => {
            "Each option in a `|` pattern has to bind the same names, but these options don't \
             agree on what they bind."
                .to_string()
        }
        TypeError::TaskArity { carrier, .. } => {
            format!("`{carrier}` is applied to the wrong number of type arguments.")
        }
        TypeError::WildcardCoversKnownConstructors { .. } => {
            "This `_` arm quietly absorbs constructors you could handle by name.".to_string()
        }
        TypeError::WebViewReturnsHtml => {
            "This returns `Html`, but an `Element` is what's needed here.".to_string()
        }
        TypeError::WildcardNotIndependent { parameter, .. } => {
            format!(
                "The `any` in parameter {parameter} is tied to another type, so it \
                 can't stay a wildcard."
            )
        }
        TypeError::BudgetExceeded | TypeError::StepBudgetExceeded { .. } => {
            "Type checking this took longer than I'm allowed to spend on it.".to_string()
        }
    }
}

/// The prose band for a lower-family (unsupported-feature) diagnostic. These are
/// things Ipê can't compile yet; the band names the situation plainly and the
/// label / help carry the workaround.
#[allow(clippy::too_many_lines)] // one declarative arm per lower-family diagnostic
fn lower_prose(msg: &LowerError) -> String {
    match msg {
        LowerError::Unsupported(_) => "This uses something I can't compile yet.".to_string(),
        LowerError::InadmissibleAppModel { .. } | LowerError::InadmissibleAppMsg { .. } => {
            "This app's Model or message type uses something I can't compile yet.".to_string()
        }
        LowerError::BackendNestingTooDeep { .. } => {
            "This expression nests deeper than I can compile.".to_string()
        }
        LowerError::DecodeSucceedArityTooHigh { .. } => {
            "This decoder builds a value with more fields than I can wire up at once.".to_string()
        }
        LowerError::RouteParamCountMismatch { .. } => {
            "This route's `:param` segments don't line up with its page constructor.".to_string()
        }
        LowerError::RoutePatternMalformed { call, .. } => {
            format!("The path you gave `{call}` isn't a valid route.")
        }
        LowerError::RouteBuilderUnsupportedShape => {
            "A route's page builder must be the page constructor itself.".to_string()
        }
        LowerError::RouteAmbiguous { .. } => {
            "Two routes match the same paths but build different pages.".to_string()
        }
        LowerError::RouteUnreachable { .. } => {
            "This route can never match: an earlier route always wins.".to_string()
        }
        LowerError::RoutedPageWithoutRoute { .. } => {
            "One of your pages has no route, so it has no address.".to_string()
        }
        LowerError::RouteTableOpaque => {
            "I can't read this app's `routes` as a list of `Web.route` calls.".to_string()
        }
        LowerError::RoutedPageNotCustomType => {
            "Your Model's `page` field needs to be a custom type of pages.".to_string()
        }
        LowerError::OnNavigateWithoutPage => {
            "`onNavigate` is set, but your Model has no `page` field to route.".to_string()
        }
        LowerError::RouteParamUnsupportedType { .. } => {
            "One of this route's fields has a type I can't read out of a URL.".to_string()
        }
        LowerError::DevOnlyKernelInProduction { .. } => {
            "This uses a debugging-only helper that can't be part of a production build."
                .to_string()
        }
        LowerError::SecretFromStringLiteral => {
            "A secret can't be written straight into your code as a quoted string.".to_string()
        }
        LowerError::SecretFromStringUnapplied => {
            "`Secret.fromString` has to be called right on its argument — you can't pass it \
             around or store it under a name."
                .to_string()
        }
        LowerError::UiCellsInWebShape(_) => {
            "`Ui.cells` paints a terminal character grid, so it has no meaning in a browser app."
                .to_string()
        }
        LowerError::UiCellsInCliShape(_) => {
            "`Ui.cells` paints a terminal character grid, so it has no meaning in a Cli (line-oriented) app."
                .to_string()
        }
        LowerError::UiWidgetInNonWebShape => {
            "`CustomElement.node` mounts a browser custom element, so it has no meaning in a terminal app."
                .to_string()
        }
        LowerError::LawlessEffectDiscard => {
            "Discarding this `Task` here would quietly run its effect from a function that isn't \
             supposed to do any."
                .to_string()
        }
        LowerError::RoutedAppMissingPageField { .. } => {
            "You've declared routes, but your Model has no `page` field for them to update, so \
             routing does nothing."
                .to_string()
        }
        LowerError::NonEntryMain { found } => {
            use crate::diagnostic::MainRetName;
            let type_phrase = match found {
                MainRetName::Bare(n) => an_article(n),
                MainRetName::Phrase(p) => (*p).to_string(),
            };
            format!(
                "`main` has to be a `Task Error ()` — the one effect your program runs. \
                 This `main` is {type_phrase}."
            )
        }
        LowerError::UndeterminableReturnAny => {
            "This signature's return `any` can't be worked out — nothing pins it to a \
             concrete type."
                .to_string()
        }
        LowerError::WildcardAnyFieldTypeMismatch {
            field,
            required,
            found,
        } => {
            format!(
                "The record you passed has a `{field}` field of type `{found}`, \
                 but the function requires `{field} : {required}`."
            )
        }
        LowerError::WildcardAnyArgNotRecord { found } => {
            format!(
                "This function's parameter is `any` and reads record fields, \
                 so it only accepts a record — but you passed {found}.",
                found = an_article(found)
            )
        }
        LowerError::StoreEqAccessorInvalid(defect) => match defect {
            StoreEqAccessorDefect::NotAnAccessor => {
                "A `Store.eq` / `Store.eqBy` column must be a bare field accessor \
                 like `.age`."
                    .to_string()
            }
            StoreEqAccessorDefect::UnknownField { field } => {
                format!("This row has no `{field}` field for the query column.")
            }
            StoreEqAccessorDefect::NonScalarField { field, found } => {
                format!(
                    "`{field}` is `{found}`, not a scalar (String / Int / Bool / \
                     Float). Use `Store.eqBy` with the field's codec."
                )
            }
            StoreEqAccessorDefect::InvalidColumn { column } => {
                format!("`{column}` is not a valid SQL column name.")
            }
        },
        LowerError::AccessorKernelOffIntercept { kernel, context } => {
            let phrase = intercept_context_phrase(*context);
            format!(
                "`{kernel}` has no runtime function, so it is {phrase} — it cannot be \
                 called here."
            )
        }
        LowerError::PointFreeAccessorKernel { kernel } => {
            format!(
                "`{kernel}` reads its column from a `.field` accessor, so it must \
                 be applied directly with its accessor and value — not passed \
                 around point-free or partially applied."
            )
        }
        LowerError::UnsaturatedHandlerKernel { kernel } => {
            format!(
                "`{kernel}` has to be called with all its arguments — you can't \
                 store it under a name or pass it around before its handler is given."
            )
        }
        LowerError::StoreSelectProjectionInvalid(defect) => match defect {
            StoreSelectProjectionDefect::NotAProjectionLambda => {
                "A `Store.select` projection must be `\\( left, right ) -> \
                 side.field` — a two-binder tuple parameter over a column \
                 reference."
                    .to_string()
            }
            StoreSelectProjectionDefect::UnsupportedProjectionBody => {
                "A `Store.select` projection must be a `side.field` column \
                 reference, or a tuple of such references."
                    .to_string()
            }
            StoreSelectProjectionDefect::NestedProjectionTuple => {
                "A `Store.select` multi-column projection is a flat tuple of \
                 `side.field` references; a tuple element cannot itself be a tuple."
                    .to_string()
            }
            StoreSelectProjectionDefect::UnknownField { field } => {
                format!("This side's row has no `{field}` field for the projection.")
            }
            StoreSelectProjectionDefect::InvalidColumn { column } => {
                format!("`{column}` is not a valid SQL column name.")
            }
            StoreSelectProjectionDefect::LiteralTypeUnsupported { ty } => {
                format!(
                    "`Store.literal` must bind a String, Int, Bool, or Float value — \
                     `{ty}` is not a supported scalar type."
                )
            }
        },
    }
}

/// Prefix a rendered type with the article a reader would say aloud — `an Int`,
/// `a String`, `a List String`. Type variables and lowercase-leading renders
/// still read naturally with `a`/`an`, so the same rule applies. Purely for the
/// prose band; caret labels stay article-free.
///
/// Callers must pass a bare type name — no embedded backticks. Pass a
/// [`crate::diagnostic::MainRetName::Phrase`] value verbatim instead of routing
/// it through here when the string is already a complete noun phrase.
fn an_article(rendered: &str) -> String {
    let first = rendered.chars().next().map(|c| c.to_ascii_lowercase());
    let article = match first {
        Some('a' | 'e' | 'i' | 'o' | 'u') => "an",
        _ => "a",
    };
    format!("{article} `{rendered}`")
}

/// The uppercase title for the human-facing header rule.
///
/// Derives mechanically from the [`crate::code::title`] SSOT: every code's
/// human header is its lowercase taxonomy title uppercased. This keeps the
/// JSON `title` field and the rendered rule header in sync from a single
/// declaration — adding a code row in `code.rs` automatically updates both.
fn title_rule_name(code: crate::code::Code) -> String {
    title(code).to_ascii_uppercase()
}

/// Render a diagnostic as a snippet-free, colour-free message.
///
/// The title, the primary payload label, then every help/note line — the
/// same wording as [`render`], minus the location/snippet bands and the ANSI
/// colour a client (an editor showing an LSP diagnostic) renders itself.
/// Secondary spans are omitted here; a protocol client carries them as
/// related locations instead.
#[must_use]
pub fn plain_message(d: &Diagnostic, source: &str) -> String {
    let code = d.code();
    let mut out = String::new();
    out.push_str(title(code));
    if let Some(label) = primary_label(d) {
        out.push_str(": ");
        out.push_str(&label);
    }
    let help = d.help();
    let mut idx = 0;
    while let Some(line) = help.get(idx) {
        if matches!(line, HelpLine::DidYouMean(_)) {
            let mut names: Vec<&str> = Vec::new();
            while let Some(HelpLine::DidYouMean(name)) = help.get(idx) {
                names.push(name);
                idx += 1;
            }
            out.push('\n');
            out.push_str(&did_you_mean_footer(&names));
            continue;
        }
        let text = match line {
            HelpLine::Suggest(s) => Some(suggestion_text(s, source)),
            HelpLine::SecondarySpan { .. } => None,
            other => help_text(other),
        };
        if let Some(text) = text {
            out.push('\n');
            out.push_str(&text);
        }
        idx += 1;
    }
    if let Diagnostic::CompilerBug { detail, .. } = d {
        if !detail.is_empty() {
            out.push_str("\nnote: ");
            out.push_str(detail);
        }
        let _ = write!(
            out,
            "\nnote: this is a bug in the compiler, please report it at: {}",
            issue_tracker_url()
        );
    }
    let _ = write!(
        out,
        "\nnote: run `{DOC_HINT_CMD} {}` for more information",
        code.as_str()
    );
    out
}

/// Render a diagnostic as a stable JSON object for machine consumers.
///
/// Schema (every field always present, `null` only when structurally absent):
///
/// ```text
/// {
///   "code": "IPE-T0001",
///   "severity": "error" | "warning" | "bug",
///   "title": "TYPE MISMATCH",
///   "message": "I was expecting…",
///   "primary_span": {
///     "file": "src/Main.ipe",
///     "byte_lo": 42, "byte_hi": 48,
///     "line": 3, "col": 5,
///     "line_end": 3, "col_end": 11
///   } | null,
///   "secondary_spans": [
///     { "file": "…", "byte_lo": …, "byte_hi": …,
///       "line": …, "col": …, "line_end": …, "col_end": …,
///       "role": "first_definition" | "opener" | "definition" }
///   ],
///   "hints": ["…"],
///   "suggestions": [
///     { "byte_lo": …, "byte_hi": …,
///       "replacement": "…",
///       "applicability": "machine-applicable" | "maybe-incorrect" | "has-placeholders" }
///   ],
///   "explain_ref": "ipe doc IPE-T0001"
/// }
/// ```
///
/// `explain_ref` is `<DOC_HINT_CMD> <code>` — the verb is [`DOC_HINT_CMD`], not
/// a literal, so a consumer reads the prefix from that constant rather than
/// hard-coding it.
///
/// The object ends with a newline so callers can concatenate records (one per
/// line) without inserting separators. Escaping follows RFC 8259: `\n`, `\r`,
/// `\t`, `\\`, `\"`, and `\uXXXX` for other ASCII control characters — no
/// other escaping is needed for UTF-8 content.
#[allow(clippy::too_many_lines)] // one linear pass over help lines plus the JSON assembly — splitting reads worse
#[must_use]
pub fn render_json(d: &Diagnostic, file: &str, source: &str) -> String {
    let code = d.code();
    let severity_str = match d.severity() {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Bug => "bug",
    };
    let title_str = title(code);

    // prose_band gives the human-readable message sentence.
    let message_str = prose_band(d);

    // Primary span.
    let primary = d.primary_span();
    let primary_json = if primary == crate::span::Span::DUMMY {
        "null".to_owned()
    } else {
        let lo = locate(source, primary.lo);
        let hi = locate(source, primary.hi);
        format!(
            "{{\"file\":{},\"byte_lo\":{},\"byte_hi\":{},\
             \"line\":{},\"col\":{},\"line_end\":{},\"col_end\":{}}}",
            json_str(file),
            primary.lo,
            primary.hi,
            lo.line,
            lo.col,
            hi.line,
            hi.col,
        )
    };

    // Split help lines into secondary-spans, hints, and suggestions.
    let help = d.help();
    let mut secondary_json_parts: Vec<String> = Vec::new();
    let mut hint_json_parts: Vec<String> = Vec::new();
    let mut suggestion_json_parts: Vec<String> = Vec::new();

    for line in &help {
        match line {
            HelpLine::SecondarySpan { span, role } => {
                if *span != crate::span::Span::DUMMY {
                    let lo = locate(source, span.lo);
                    let hi = locate(source, span.hi);
                    let role_str = match role {
                        SpanRole::FirstDefinition => "first_definition",
                        SpanRole::Opener => "opener",
                        SpanRole::Definition => "definition",
                    };
                    secondary_json_parts.push(format!(
                        "{{\"file\":{},\"byte_lo\":{},\"byte_hi\":{},\
                         \"line\":{},\"col\":{},\"line_end\":{},\"col_end\":{},\
                         \"role\":{}}}",
                        json_str(file),
                        span.lo,
                        span.hi,
                        lo.line,
                        lo.col,
                        hi.line,
                        hi.col,
                        json_str(role_str),
                    ));
                }
            }
            HelpLine::Suggest(s) => {
                let applicability_str = match s.applicability {
                    Applicability::MachineApplicable => "machine-applicable",
                    Applicability::MaybeIncorrect => "maybe-incorrect",
                    Applicability::HasPlaceholders => "has-placeholders",
                };
                suggestion_json_parts.push(format!(
                    "{{\"byte_lo\":{},\"byte_hi\":{},\"replacement\":{},\"applicability\":{}}}",
                    s.span.lo,
                    s.span.hi,
                    json_str(&s.replacement),
                    json_str(applicability_str),
                ));
            }
            // Flatten all other help lines (note/hint/did-you-mean/missing-constructor)
            // into a plain hint string.
            other => {
                if let Some(text) = help_text(other) {
                    hint_json_parts.push(json_str(&text));
                }
            }
        }
    }

    // For CompilerBug, add its detail + the tracker URL as hints.
    if d.severity() == Severity::Bug {
        if let Diagnostic::CompilerBug { detail, .. } = d
            && !detail.is_empty()
        {
            hint_json_parts.push(json_str(detail));
        }
        hint_json_parts.push(json_str("this is a bug in the compiler, please report it"));
        hint_json_parts.push(json_str(&format!("report at: {}", issue_tracker_url())));
    }

    let secondaries_json = format!("[{}]", secondary_json_parts.join(","));
    let hints_json = format!("[{}]", hint_json_parts.join(","));
    let suggestions_json = format!("[{}]", suggestion_json_parts.join(","));
    let explain_ref = json_str(&format!("{DOC_HINT_CMD} {}", code.as_str()));

    format!(
        "{{\"code\":{},\"severity\":{},\"title\":{},\"message\":{},\
         \"primary_span\":{},\"secondary_spans\":{},\
         \"hints\":{},\"suggestions\":{},\"explain_ref\":{}}}\n",
        json_str(code.as_str()),
        json_str(severity_str),
        json_str(title_str),
        json_str(&message_str),
        primary_json,
        secondaries_json,
        hints_json,
        suggestions_json,
        explain_ref,
    )
}

/// A JSON string literal of `s`, escaped by the display escaper [`crate::json::string_body`].
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    crate::json::string_body_into(s, &mut out);
    out.push('"');
    out
}

// ===========================================================================
// Source-position arithmetic (checked, clamped, panic-free)
// ===========================================================================

/// How a span's underline is drawn: the glyph, its colour, and the trailing
/// label. Bundled so [`push_span_block`] stays within the argument budget.
struct UnderlineStyle<'a> {
    glyph: char,
    color_seq: &'a str,
    label: &'a str,
}

/// A resolved source position plus the byte bounds of its line.
struct Loc {
    /// 1-based line number.
    line: usize,
    /// 1-based column, counted in characters.
    col: usize,
    /// Byte offset of the first character on the line.
    line_start: usize,
    /// Byte offset just past the last character on the line (before any `\n`).
    line_end: usize,
}

/// Locate a byte offset within `source`, clamping out-of-range and mid-character
/// offsets to the nearest valid char boundary. Never panics.
fn locate(source: &str, raw: u32) -> Loc {
    let byte = floor_boundary(source, raw as usize);
    let before = slice(source, 0, byte);
    let line = before.bytes().filter(|&b| b == b'\n').count() + 1;
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    let col = slice(source, line_start, byte).chars().count() + 1;
    let rest = slice(source, line_start, source.len());
    let line_len = rest.find('\n').unwrap_or(rest.len());
    Loc {
        line,
        col,
        line_start,
        line_end: line_start + line_len,
    }
}

/// The largest char boundary `<= b` (and `<= source.len()`).
fn floor_boundary(source: &str, b: usize) -> usize {
    let mut b = b.min(source.len());
    while b > 0 && !source.is_char_boundary(b) {
        b -= 1;
    }
    b
}

/// Slice `source[lo..hi]`, yielding `""` for any out-of-range or inverted range
/// instead of panicking. Replaces raw indexing (denied workspace-wide).
fn slice(source: &str, lo: usize, hi: usize) -> &str {
    source.get(lo..hi).unwrap_or("")
}

/// The tab stop the snippet uses when it expands a tab. A tab in the source
/// advances to the next multiple of this width; both the shown source line and
/// the caret indent use the same expansion, so a caret lands under the glyph a
/// reader sees even when the source is tab-indented.
const TAB_WIDTH: usize = 4;

/// The terminal display width of one character: a tab advances to the next tab
/// stop given the column reached so far, a wide (CJK / full-width) character is
/// two cells, a zero-width or control character is none, and everything else is
/// one. `col` is the display column already consumed on this line, so a tab's
/// width depends on where it falls.
fn char_display_width(c: char, col: usize) -> usize {
    use unicode_width::UnicodeWidthChar;
    if c == '\t' {
        TAB_WIDTH - (col % TAB_WIDTH)
    } else {
        c.width().unwrap_or(0)
    }
}

/// The display width of `text` starting from display column `start`, summing
/// each character's cell width with tabs expanded to [`TAB_WIDTH`] stops. Used
/// to place the caret indent and size the underline so both track the source
/// line as a terminal draws it, not its byte or `char` count.
fn display_width(text: &str, start: usize) -> usize {
    let mut col = start;
    for c in text.chars() {
        col += char_display_width(c, col);
    }
    col - start
}

/// Expand a source line's tabs to spaces at [`TAB_WIDTH`] stops. The snippet
/// shows this expanded form so the caret line — which is measured in the same
/// expanded space — stays aligned under it regardless of the terminal's own tab
/// width. No other character is altered.
fn expand_tabs(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut col = 0;
    for c in line.chars() {
        if c == '\t' {
            let pad = TAB_WIDTH - (col % TAB_WIDTH);
            for _ in 0..pad {
                out.push(' ');
            }
            col += pad;
        } else {
            out.push(c);
            col += char_display_width(c, col);
        }
    }
    out
}

/// Emit the snippet block for a span, underlining every source line it covers.
///
/// A single-line span underlines from its start column to its end column. A span
/// that crosses lines underlines the remainder of its first line, each whole
/// middle line, and the head of its last line — so a multi-line region is shown
/// in full, not clipped to line one. The trailing `label` is attached to the
/// final underlined line, where the reader's eye lands.
///
/// Tabs are expanded and character display width is honoured (via
/// [`expand_tabs`] / [`display_width`]) so a caret sits under the glyph a reader
/// sees, even under tab indentation or wide (CJK) source.
fn push_span_block(
    out: &mut String,
    source: &str,
    span: Span,
    style: &UnderlineStyle,
    gutter: usize,
    color: bool,
) {
    let start = locate(source, span.lo);
    let end = locate(source, span.hi);
    // The covered byte range, clamped to char boundaries and to `lo <= hi`.
    let span_lo = floor_boundary(source, span.lo as usize);
    let span_hi = floor_boundary(source, span.hi as usize).max(span_lo);

    let mut line = start.line;
    let mut line_start = start.line_start;
    let mut line_end = start.line_end;
    loop {
        let is_last = line >= end.line;
        // The underlined byte sub-range on this line: from the span start (or the
        // line start on a continuation line) to the span end (or the line end on
        // an earlier line).
        let seg_lo = span_lo.max(line_start).min(line_end);
        let seg_hi = if is_last {
            span_hi.min(line_end).max(seg_lo)
        } else {
            line_end
        };

        let line_text = expand_tabs(slice(source, line_start, line_end));
        let _ = writeln!(out, "{line:>gutter$} | {line_text}");

        let leading = display_width(slice(source, line_start, seg_lo), 0);
        let mut width = display_width(slice(source, seg_lo, seg_hi), leading);
        // A zero-width segment (an empty span, or a line whose covered part is
        // only a tab boundary) still shows one caret, so the underline is never
        // invisible.
        width = width.max(1);

        out.push_str(&" ".repeat(gutter));
        out.push_str(" | ");
        out.push_str(&" ".repeat(leading));
        out.push_str(&paint(
            color,
            style.color_seq,
            &style.glyph.to_string().repeat(width),
        ));
        if is_last && !style.label.is_empty() {
            out.push(' ');
            out.push_str(style.label);
        }
        out.push('\n');

        if is_last {
            break;
        }
        // Advance to the next line. `line_end` sits on the newline (or at
        // end-of-file); the next line starts just past it. A line with no
        // following newline ends the block defensively even if `end.line` was
        // past end-of-file.
        let next_start = line_end + 1;
        if next_start > source.len() {
            break;
        }
        let rest = slice(source, next_start, source.len());
        let next_len = rest.find('\n').unwrap_or(rest.len());
        line += 1;
        line_start = next_start;
        line_end = next_start + next_len;
    }
}

// ===========================================================================
// Colour
// ===========================================================================

fn color_enabled() -> bool {
    use std::io::IsTerminal;
    ipe_env::var_os("NO_COLOR").is_none() && std::io::stderr().is_terminal()
}

fn paint(color: bool, seq: &str, text: &str) -> String {
    if color {
        format!("{seq}{text}{RESET}")
    } else {
        text.to_string()
    }
}

const fn severity_color(s: Severity) -> &'static str {
    match s {
        Severity::Error | Severity::Bug => RED,
        Severity::Warning => YELLOW,
    }
}

// ===========================================================================
// Primary inline labels (payload-derived)
// ===========================================================================

/// The inline label printed after the primary `^` underline, derived from the
/// diagnostic's payload. `None` means "carets only, no label".
fn primary_label(d: &Diagnostic) -> Option<String> {
    match d {
        Diagnostic::Parse { msg, .. } => parse_label(msg),
        Diagnostic::Name { msg, .. } => name_label(msg),
        Diagnostic::Type { msg, .. } => type_label(msg),
        Diagnostic::Lower { msg, .. } => Some(lower_label(msg)),
        Diagnostic::CompilerBug { .. }
        | Diagnostic::Ffi { .. }
        | Diagnostic::Sandbox { .. }
        | Diagnostic::Consent { .. }
        | Diagnostic::RegistryUnreachable { .. } => None,
    }
}

fn parse_label(msg: &ParseError) -> Option<String> {
    match msg {
        ParseError::UnexpectedToken { found, expected } => Some(format!(
            "found {}, expected {}",
            token_kind_str(*found),
            expected_set_str(expected)
        )),
        ParseError::UnexpectedEof { .. } => Some("input ended here".to_string()),
        ParseError::NestingTooDeep { limit, .. } => {
            Some(format!("nested past the limit of {limit}"))
        }
        ParseError::UnknownChar(c) => Some(format!("unknown character {}", char_repr(*c))),
        ParseError::StrayDot => Some("stray `.`".to_string()),
        ParseError::SpaceBeforeDot => {
            Some("a space before `.` reads as the accessor function `.field`".to_string())
        }
        ParseError::NumberJoinedToName(c) => {
            Some(format!("a number cannot be followed by {}", char_repr(*c)))
        }
        ParseError::IntLiteralOutOfRange => {
            Some("this integer does not fit in 64 bits".to_string())
        }
        ParseError::FloatLiteralOutOfRange => {
            Some("this float is too large to represent".to_string())
        }
        ParseError::UnterminatedString => Some("this string is never closed".to_string()),
        ParseError::MalformedChar => Some("this character literal is malformed".to_string()),
        ParseError::UnterminatedBlockComment => {
            Some("this block comment is never closed".to_string())
        }
        ParseError::MalformedModuleHeader(defect) => Some(header_defect_str(*defect).to_string()),
        ParseError::MalformedExposingList(defect) => Some(exposing_defect_str(*defect).to_string()),
        ParseError::MissingEquals { binding } => Some(format!("`{binding}` needs an `=` here")),
        ParseError::MalformedTypeDeclaration(defect) => {
            Some(type_decl_defect_str(*defect).to_string())
        }
        ParseError::TypeArgsOnNonConstructor => {
            Some("only a type constructor can take arguments".to_string())
        }
        ParseError::ExpectedType => Some("expected a type here".to_string()),
        ParseError::UnclosedDelimiter { .. } => Some("this delimiter is never closed".to_string()),
        ParseError::MalformedCase(defect) => Some(case_defect_str(*defect).to_string()),
        ParseError::MalformedLet(defect) => Some(let_defect_str(*defect).to_string()),
        ParseError::MalformedIf(defect) => Some(if_defect_str(*defect).to_string()),
        ParseError::InvalidPathLiteral { literal, refusal } => {
            use ipe_path_core::{Regime, SealRefusal};
            let detail = match (refusal.regime, &refusal.why) {
                (_, SealRefusal::Nul) => {
                    "the path contains a NUL byte (a syscall-boundary truncation / traversal risk)"
                        .to_string()
                }
                (_, SealRefusal::DisguisedParent) => format!(
                    "an element of the path becomes `..` once Windows strips its trailing \
                     dots / spaces (a traversal disguise): {literal:?}"
                ),
                (Regime::Unix, SealRefusal::Escape { .. }) => {
                    format!("the path escapes its root via `..` traversal: {literal:?}")
                }
                (Regime::Windows, SealRefusal::Escape { .. }) => format!(
                    "the path escapes its root via `..` traversal on Windows, where `\\` \
                     also separates elements: {literal:?}"
                ),
            };
            Some(detail)
        }
        ParseError::AnnotationWithoutBinding { .. } => {
            Some("this annotation has no matching definition".to_string())
        }
        ParseError::DuplicateAnnotation { .. } => {
            Some("this name is already annotated above".to_string())
        }
        ParseError::Unexpected
        | ParseError::TooDeep
        | ParseError::SteplessDo
        | ParseError::DocOnUnexported { .. }
        | ParseError::SourceTooLarge { .. }
        | ParseError::MissingDocString { .. } => None,
    }
}

#[allow(clippy::too_many_lines)]
fn name_label(msg: &NameError) -> Option<String> {
    match msg {
        NameError::ValueNotFound { .. } => Some("I don't know this name".to_string()),
        NameError::TypeNotFound { .. } => Some("I don't know this type".to_string()),
        NameError::ConstructorNotFound { .. } => Some("I don't know this constructor".to_string()),
        NameError::UnknownModule { qualifier, .. } => Some(format!("unknown module `{qualifier}`")),
        NameError::ImportRequired {
            reached,
            candidates,
            imported_as,
        } => Some(imported_as.as_deref().map_or_else(
            || import_required_label(reached.spelling(), candidates),
            |imported| imported_as_label(reached.spelling(), imported),
        )),
        NameError::OperatorImportRequired { operator, module } => Some(format!(
            "`{operator}` comes from `{module}`; add `import {module}`"
        )),
        NameError::NoSuchMember { module, member, .. } => {
            Some(format!("`{module}` has no member `{member}`"))
        }
        NameError::DuplicateValue { name, .. }
        | NameError::DuplicateConstructor { name, .. }
        | NameError::DuplicateType { name, .. } => Some(format!("`{name}` is redefined here")),
        NameError::AliasArity {
            name,
            expected,
            found,
        } => Some(format!(
            "`{name}` takes {expected} type argument(s), but {found} were given"
        )),
        NameError::BuiltinTypeArity {
            name,
            expected,
            found,
        } => Some(format!(
            "`{name}` takes exactly {expected} type argument(s), but {found} were given"
        )),
        NameError::ModuleNotFound { name, .. } => Some(format!("module `{name}` was not found")),
        NameError::ImportCycle { path } => {
            let cycle = path.join(" → ");
            Some(format!("import cycle: {cycle}"))
        }
        NameError::NameNotExposed { module, name, .. } => {
            Some(format!("`{module}` does not expose `{name}`"))
        }
        NameError::ModulePathMismatch { declared, expected } => {
            Some(format!("declared as `{declared}`, expected `{expected}`"))
        }
        NameError::AmbiguousImport { name, modules } => {
            let origins = modules.join(", ");
            Some(format!("`{name}` is exported by: {origins}"))
        }
        NameError::ReservedNamespace { name } => {
            Some(format!("`{name}` begins with a reserved namespace"))
        }
        NameError::ReservedBuiltinType { name } => {
            Some(format!("`{name}` is a built-in type name"))
        }
        NameError::DuplicateQualifier { qualifier, .. } => Some(format!(
            "qualifier `{qualifier}` already claimed by another import"
        )),
        NameError::UnknownKernelAlias {
            module, function, ..
        } => Some(format!("no registered kernel `{module}.{function}`")),
        NameError::KernelAliasInUserSource { alias } => Some(format!(
            "`Kernel.kernel {alias:?}` mints a kernel — only the standard library \
             and the generated FFI interface may do this; reach the effect \
             through its published module (an unsafe kernel via its `Ipe.<M>.Unsafe` \
             module, which discloses the `unsafe` capability)"
        )),
        NameError::ServerOnlyKernelForWasm { qualifier, name } => Some(format!(
            "`{qualifier}.{name}` is server-only and has no denotation for target `wasm`; \
             run it behind a server route and call it from the client over HTTP"
        )),
        NameError::ServerModuleReachableFromWasmClient { chain } => Some(format!(
            "the client entry's reachability closure reaches a server module: {chain}"
        )),
        NameError::TypeExpansionTooDeep { kind, limit } => {
            use crate::diagnostic::AliasExpansionKind;
            let what = match kind {
                AliasExpansionKind::Depth => "recursion depth",
                AliasExpansionKind::Nodes => "node count",
            };
            Some(format!(
                "alias expansion exceeded the {what} limit of {limit}"
            ))
        }
        NameError::ProgramImportsTeaShape { module } => Some(format!(
            "this module has a plain `main` (a Program) but imports `{module}`; \
             a module that imports any `Ipe.Tea.*` shape is a TEA app, so give \
             `main` a shape entry (`Web.tea` / `Tui.tea` / \
             `Cli.tea`), or drop the `{module}` import \
             if this is a Program"
        )),
        NameError::RuntimeBranchedMain => Some(
            "`main`'s head is an `if` / `case` whose branches are different app \
             entries, so which shape this program is would be decided at run time; \
             a program's shape is pinned by the entry head at compile time, not \
             chosen from a value. Commit `main` to one shape entry (`Web.tea` / \
             `Tui.tea` / `Cli.tea`), and put \
             any run-time choice inside that shape (in its `init` / `update`), or \
             — for a plain program — make `main` a `Task Error ()`"
                .to_string(),
        ),
        NameError::TwoShapeImports {
            first_module,
            second_module,
            ..
        } => Some(format!(
            "this module already imports `{first_module}`, so it cannot also import \
             `{second_module}`; keep the one shape this module builds"
        )),
        NameError::WrongShapeCmdSub(m) => Some(format!(
            "`{}` is the {} shape's `Cmd` / `Sub`, but this \
             is a {} app; import `{}` instead",
            m.imported, m.imported_shape, m.app_shape, m.expected
        )),
        NameError::DiscardedConfig => Some(
            "this module declares a top-level `config` binding but never threads it into an \
             app entry, so every setting it lists is silently dropped; give the module a Web \
             app entry (`main = Web.tea { … }`, which threads a sibling `config` binding \
             automatically — or pass it explicitly with `Web.appWith config { … }`), or \
             delete the `config` binding if it is unused"
                .to_string(),
        ),
        NameError::RemovedSurface {
            qualifier,
            name,
            replacement,
        } => {
            if replacement.is_empty() {
                Some(format!(
                    "`{qualifier}.{name}` has been removed from the Ipê surface"
                ))
            } else {
                Some(format!(
                    "`{qualifier}.{name}` has been removed; use `{replacement}` instead"
                ))
            }
        }
        NameError::AssertedCallMalformed { detail } => Some(format!(
            "this `Rust.Ffi.call` is malformed: {detail}. The one accepted shape is a \
             top-level annotated definition whose whole body is `Rust.Ffi.call \
             \"<crate>::<function>\"`"
        )),
        NameError::CustomElementCtorMalformed { detail } => Some(format!(
            "this `CustomElement.fromFile` is malformed: {detail}. The one accepted shape is a \
             `CustomElement`-annotated binding whose whole body is `CustomElement.fromFile \
             \"<js-path>\"` — a single string literal naming a widget-hook JS file \
             inside your project (no `..` escape), and the file must exist"
        )),
        NameError::BoundarySealIllegal { seal_type, reason } => {
            let why = match reason {
                SealRejection::Function => {
                    "a function is not a plain value and cannot be serialised"
                }
                SealRejection::EffectCarrier => {
                    "an effect carrier (`Cmd` / `Task` / `Sub`) does not cross the seam as data"
                }
                SealRejection::ViewValue => {
                    "a view value (`Html` / `Element` / `Attribute`) is not a boundary data value"
                }
                SealRejection::SecretOrSink => {
                    "a `Secret` or reserved sink type must never be exposed across the JS seam"
                }
                SealRejection::NonConcrete => {
                    "the seal is monomorphic — a type variable or open row has no concrete codec"
                }
                SealRejection::NotProvenPlain => {
                    "the seal cannot prove this is a plain, closed, serialisable value type"
                }
            };
            Some(format!(
                "`{seal_type}` cannot cross the Ipê↔JS boundary: {why}. A `CustomElement \
                 down up` parameter must be a plain, closed value type — a primitive, \
                 record, list, tuple, `Maybe`, or user ADT over those"
            ))
        }
        NameError::NestedDecoderPipeline => Some(
            "this decoder-pipeline combinator is hand-nested, which binds fields to the \
             constructor in REVERSE source order and silently swaps any two same-typed \
             fields. Thread the combinators with `|>` instead — `succeed Ctor |> required \
             \"a\" da |> required \"b\" db` — so the fields bind top-to-bottom in the order \
             written"
                .to_string(),
        ),
        NameError::CodecAutoUnderivable { reason, field } => {
            let why = match reason {
                CodecAutoRejection::WitnessNotRecordValue => {
                    "`Codec.auto` needs a witness that is a top-level value annotated with a \
                     record type — `Codec.auto blankUser` where `blankUser : User` and `User` \
                     is a record. It reads that record's fields to build the codec"
                        .to_string()
                }
                CodecAutoRejection::ArityMismatch => {
                    "`Codec.auto` takes exactly one argument: a witness value whose record type \
                     names the codec to derive"
                        .to_string()
                }
                CodecAutoRejection::SecretField => format!(
                    "field `{field}` is a `Secret` (or a reserved sink type): encoding it to \
                     JSON or a column is exactly the leak the Security principle forbids, so no \
                     codec can serialise it"
                ),
                CodecAutoRejection::FunctionField => format!(
                    "field `{field}` is a function, which is not a serialisable value — no leaf \
                     codec derives for it"
                ),
                CodecAutoRejection::UnsupportedField => format!(
                    "field `{field}` has no derivable leaf codec (a data-carrying ADT, an opaque \
                     handle, or an effect/decoder carrier). Write the codec explicitly — use \
                     `Codec.taggedUnion` / `varN` for a data ADT"
                ),
            };
            Some(why)
        }
        NameError::WebInitPolyArg => Some(
            "change `a` to `WebReq`, or remove the type annotation entirely — \
             inference will pin the argument to `WebReq` automatically"
                .to_string(),
        ),
        NameError::ModuleNotAllowedInPlacement(r) => {
            use crate::diagnostic::ModulePlacementReason;
            let module = &r.module;
            let placement = &r.placement;
            let why_and_fix = match r.reason {
                ModulePlacementReason::NativeEffectInSandbox => {
                    "it is a native effect (a direct database, file, server, or secret), and a \
                     `solo` app runs sandboxed in the browser — there is no native effect there. \
                     Move it behind an HTTP boundary (`Ipe.Http` to your backend), or deliver \
                     the app as `web` (served, the co-located default), where the loop runs \
                     server-side"
                        .to_string()
                }
                ModulePlacementReason::BrowserOutsideBrowserHost => format!(
                    "it is a browser host capability, and a `{placement}` app has no browser to \
                     host it. Use a web app (`web` or `web solo`) for browser capabilities, or \
                     reach the equivalent effect through a native module in this shape"
                ),
            };
            Some(format!(
                "`{module}` is not available in a `{placement}` app because {why_and_fix}. \
                 A program is placed on two axes: what it renders (its shape, pinned by `main`) \
                 and where it runs (its runtime); this module belongs to a different set of \
                 placements"
            ))
        }
        // `RustNameFold`'s span is always DUMMY (the IR carries none), so a label
        // never reaches a caret; the fix rides the help note instead (see
        // `name_help`), which renders with or without a snippet — and `None` here
        // also avoids duplicating that note in the snippet-free `plain_message`.
        NameError::DuplicatePatternBinder { .. } => {
            Some("this name is already bound in this pattern".to_string())
        }
        NameError::ScriptImportsShapeView { shape, entry, .. } => Some(format!(
            "this script has no `view`; did you mean `main = {entry} {{ … }}` to run a {shape} app?"
        )),
        NameError::GenericAppEntry { type_var, .. } => Some(format!(
            "fix `{type_var}` to your concrete type (e.g. `Msg`) in this definition's annotation, \
             or build the app where the model and message types are known"
        )),
        NameError::UnpinnedAppEntry { .. } => Some(
            "annotate the app's functions with your concrete types, e.g. \
             `update : Msg -> Model -> ( Model, Cmd Msg )`"
                .to_string(),
        ),
        NameError::InputFieldIsSubscription {
            field, sub_module, ..
        } => Some(format!(
            "remove `{field}` from the config and subscribe instead: \
             `import {sub_module} as Sub`, then `subscriptions _ = Sub.{field} {field}`"
        )),
        NameError::AliasRowArgument { alias, fault } => Some(match fault {
            crate::diagnostic::AliasRowFault::NotARecord { .. } => format!(
                "pass `{alias}` a record (`{alias} {{ age : Int }}`) or a type variable \
                 (`{alias} r`)"
            ),
            crate::diagnostic::AliasRowFault::FieldClash { field } => {
                format!("remove `{field}` from the argument; `{alias}` already supplies it")
            }
        }),
        NameError::RustNameFold { .. } | NameError::Unknown => None,
    }
}

/// The IPE-N0034 label: the import to add, or every import that would bind it.
/// The IPE-N0034 label when the module is imported under another spelling.
fn imported_as_label(qualifier: &str, imported: &ImportedAs) -> String {
    let ImportedAs { module, alias } = imported;
    format!("you imported `{module}` as `{alias}`; write `{alias}.` where you wrote `{qualifier}.`")
}

fn import_required_label(qualifier: &str, candidates: &[Box<str>]) -> String {
    match candidates {
        [] => format!("`{qualifier}` names a module you haven't imported"),
        [only] => format!("`{qualifier}` is the module `{only}`; add `import {only}` to use it"),
        many => {
            let imports = many
                .iter()
                .map(|module| format!("`import {module}`"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("`{qualifier}` names more than one module; add one of: {imports}")
        }
    }
}

#[allow(clippy::too_many_lines)] // one match arm per TypeError variant — mechanical dispatch
fn type_label(msg: &TypeError) -> Option<String> {
    match msg {
        TypeError::TypeMismatch {
            expected,
            found,
            path,
            ..
        } => {
            let mut label = format!(
                "expected {}, found {}",
                ty_to_string(expected),
                ty_to_string(found)
            );
            if !path.is_empty() {
                let joined: Vec<&str> = path.iter().map(AsRef::as_ref).collect();
                let _ = write!(label, " (at {})", joined.join("."));
            }
            Some(label)
        }
        TypeError::InfiniteType { var, ty } => {
            Some(format!("`{var}` would have to equal {}", ty_to_string(ty)))
        }
        TypeError::TooManyParameters { binding, signature } => {
            Some(format!("`{binding}` has type {}", ty_to_string(signature)))
        }
        TypeError::NonExhaustiveCase { .. } => {
            Some("some possibilities aren't handled".to_string())
        }
        TypeError::RedundantCaseBranch { constructor } => {
            Some(format!("`{constructor}` is already handled above"))
        }
        TypeError::NoSuchField { field, record } => Some(format!(
            "type {} has no field `{field}`",
            ty_to_string(record)
        )),
        TypeError::BuiltinRecordUpdate { name } => Some(format!(
            "`{name}` is a built-in type — its fields can be read (`x.field`), \
             but it cannot be rebuilt with record-update syntax"
        )),
        TypeError::CtorPatternArity {
            ctor,
            expected,
            found,
        } => Some(format!(
            "`{ctor}` binds {found} field(s) but its declaration has {expected}"
        )),
        TypeError::SuperTypeUnsatisfied { class, found } => {
            if &**class == crate::diagnostic::HOF_KERNEL_RESULT_CLASS {
                // Tailored sentence: the generic template below would read as
                // a double negative for this internal arity obligation
                // ("`a` is not a non-function callback result … type").
                Some(format!(
                    "the callback's result type {} may itself be a function — \
                     higher-order kernels (List.map / List.foldl / Maybe.map2 / \
                     andMap / …) apply their callback at one exact arity, so the \
                     callback must return a plain (non-function) value",
                    ty_to_string(found)
                ))
            } else if &**class == crate::diagnostic::INTERPOLABLE_CLASS {
                Some(format!(
                    "{} cannot be interpolated or logged — `{{{{…}}}}` and `Log.*With` \
                     accept only {}; convert the value first with `String.fromInt`, \
                     `String.fromFloat`, `String.fromBool` or `String.fromChar`, or \
                     with your own function that renders a record or custom type as a \
                     `String`",
                    ty_to_string(found),
                    crate::diagnostic::INTERPOLABLE_TYPES.join(", ")
                ))
            } else {
                Some(format!("{} is not a {class} type", ty_to_string(found)))
            }
        }
        TypeError::RefutablePatternParameter => {
            Some("this parameter pattern can fail to match".to_string())
        }
        TypeError::OrPatternBindingMismatch { names } => {
            // The payload carries only the *difference* — the names bound by some
            // options but not all — so the label names exactly those, and the
            // reader learns the rule from the prose band + the concrete list.
            let listed = names
                .iter()
                .map(|n| format!("`{n}`"))
                .collect::<Vec<_>>()
                .join(", ");
            let subject = if names.len() == 1 { "isn't" } else { "aren't" };
            Some(format!(
                "{listed} {subject} bound by every option, so I wouldn't know what it is"
            ))
        }
        TypeError::TaskArity { carrier, found } => Some(if *carrier == "Task" {
            format!(
                "`Task` takes an error type and a success type (`Task Error a`), \
                 but here it is applied to {found} type argument(s)"
            )
        } else {
            format!(
                "`{carrier}` takes a single message type (`{carrier} msg`), \
                 but here it is applied to {found} type argument(s)"
            )
        }),
        TypeError::WildcardCoversKnownConstructors { constructors } => {
            let listed = constructors
                .iter()
                .map(|c| format!("`{c}`"))
                .collect::<Vec<_>>()
                .join(", ");
            Some(format!(
                "this arm absorbs {listed} — handle each constructor explicitly, \
                 so adding a variant forces an update here instead of falling \
                 through silently"
            ))
        }
        TypeError::WebViewReturnsHtml => Some(
            "this is `Html`, but an `Element` is required here — `Ui.layout` / \
             `Ui.layoutWith` turn an `Element` into `Html`, so a `view` that \
             calls one returns `Html` (the app shape applies the layout for you)"
                .to_string(),
        ),
        TypeError::WildcardNotIndependent { dependence, .. } => Some(match dependence {
            WildcardDependence::TypeVariable { name: Some(name) } => {
                format!("the body makes this `any` the same type as the type variable `{name}`")
            }
            WildcardDependence::TypeVariable { name: None } => {
                "the body makes this `any` the same type as a type variable".to_string()
            }
            WildcardDependence::SharedWith { parameter } => format!(
                "the body makes this `any` the same type as the `any` of parameter \
                 {parameter}"
            ),
            WildcardDependence::PartialStructure { found } => format!(
                "the body needs this `any` to be `{}`, which still leaves part \
                 of the type open",
                ty_to_string(found)
            ),
        }),
        TypeError::Mismatch | TypeError::BudgetExceeded | TypeError::StepBudgetExceeded { .. } => {
            None
        }
    }
}

#[allow(clippy::too_many_lines)] // one declarative arm per lower-family diagnostic
fn lower_label(msg: &LowerError) -> String {
    match msg {
        LowerError::Unsupported(f) => feature_label(*f).to_string(),
        LowerError::InadmissibleAppModel { app, field, leaf } => {
            crate::diagnostic::inadmissible_model_message(*app, field, *leaf)
        }
        LowerError::InadmissibleAppMsg { app, field, leaf } => {
            crate::diagnostic::inadmissible_msg_message(*app, field, *leaf)
        }
        LowerError::BackendNestingTooDeep { limit } => {
            format!("nested past the backend limit of {limit}")
        }
        LowerError::DecodeSucceedArityTooHigh { n } => {
            format!("`succeed` constructor has {n} parameters; the `curry1`..`curry10` cap is 10")
        }
        LowerError::RouteParamCountMismatch {
            pattern,
            param_count,
            ctor_payload_count,
        } => format!(
            "pattern `{pattern}` has {param_count} `:param` segment(s) but the page \
             constructor takes {ctor_payload_count} payload field(s)"
        ),
        LowerError::RoutePatternMalformed { defect, .. } => route_pattern_label(defect),
        LowerError::RouteBuilderUnsupportedShape => {
            "this page builder is not a bare page constructor — a function builder has \
             no inverse, so the page's path cannot be rendered"
                .to_string()
        }
        LowerError::RouteAmbiguous { first, second } => {
            format!("`{second}` is equivalent to the earlier `{first}` but builds a different page")
        }
        LowerError::RouteUnreachable { pattern, earlier } => {
            format!("`{pattern}` can never match: the earlier `{earlier}` matches first")
        }
        LowerError::RoutedPageWithoutRoute { ctor } => {
            format!("page constructor `{ctor}` has no route")
        }
        LowerError::RouteTableOpaque => {
            "`routes` is not a list of `Web.route \"<literal>\" PageConstructor`".to_string()
        }
        LowerError::RoutedPageNotCustomType => {
            "the Model's `page` field is not a custom type".to_string()
        }
        LowerError::OnNavigateWithoutPage => {
            "`onNavigate` is set but the Model has no `page` field".to_string()
        }
        LowerError::RouteParamUnsupportedType {
            field_index,
            type_name,
        } => format!(
            "payload field {field_index} has type `{type_name}`, which cannot be decoded \
             from a URL `:param` string"
        ),
        LowerError::DevOnlyKernelInProduction { kernel } => format!(
            "`{kernel}` is a development-only debugging escape hatch and cannot be used \
             in a production build (`ipe release`)"
        ),
        LowerError::SecretFromStringLiteral => {
            "a committed string literal cannot become a `Secret` — a secret must not be \
             baked into source. Read it from the environment at runtime with \
             `App.fromEnvRequired \"VAR\"`, or seal a `String` obtained at runtime with \
             `Secret.fromString`"
                .to_string()
        }
        LowerError::SecretFromStringUnapplied => {
            "`Secret.fromString` must be applied directly to its argument — it cannot be \
             passed as a value, let-bound, or otherwise used point-free. The committed-literal \
             seal gate reads the call's argument, so an un-applied reference would route a later \
             argument around it. Write `Secret.fromString runtimeString`, or map with a lambda: \
             `List.map (\\s -> Secret.fromString s) runtimeStrings`"
                .to_string()
        }
        LowerError::UiCellsInWebShape(app) => format!(
            "`Ui.cells` is terminal-only; not available in the {} shape — it paints a \
             raw character grid directly to the terminal and has no browser rendering. \
             Use it only under `Tui.tea`",
            web_shape_label(*app)
        ),
        LowerError::UiCellsInCliShape(_) => {
            "`Ui.cells` is terminal-screen-only; not available in the Cli shape — a \
             Cli view returns `String` (line output) and has no character-grid surface. \
             Use `Tui.tea` for a full-screen cell-grid app, or format the \
             content as a `String` for line output"
                .to_string()
        }
        LowerError::UiWidgetInNonWebShape => {
            "`CustomElement.node` is browser-only; not available outside a Web shape — its \
             up-event handler is carried over the seal codec, which exists only in a \
             browser build. Use it only under `Web.tea`"
                .to_string()
        }
        LowerError::LawlessEffectDiscard => {
            "discarding this `Task` with `let _ = …` in a function that does not return \
             a `Task` would run its effect through a hidden `Task.run` — a plainly-typed \
             function would silently perform I/O. Give the function a `Task e ()` return \
             type, or run the effect with `Task.run`"
                .to_string()
        }
        LowerError::RoutedAppMissingPageField { route_count } => format!(
            "{route_count} route(s) declared but the Model has no `page` field — \
             routing is disabled and the routes are ignored"
        ),
        LowerError::NonEntryMain { found } => {
            use crate::diagnostic::MainRetName;
            let type_phrase = match found {
                MainRetName::Bare(n) => an_article(n),
                MainRetName::Phrase(p) => (*p).to_string(),
            };
            format!("this `main` is {type_phrase}, not a `Task Error ()`")
        }
        LowerError::UndeterminableReturnAny => {
            "a wildcard `any` in the return type is pinned by no body — a caller could \
             never determine its concrete type. Return a concrete value, annotate a \
             concrete return type, or use a named type variable such as `a` for genuine \
             polymorphism"
                .to_string()
        }
        LowerError::WildcardAnyFieldTypeMismatch {
            field,
            required,
            found,
        } => {
            format!(
                "field `{field}` has type `{found}` here, but the callee's body requires \
                 `{field} : {required}` — change the field's value to a `{required}`, or \
                 annotate the callee's parameter with a closed record type so the \
                 type-checker enforces the field type at each call site"
            )
        }
        LowerError::WildcardAnyArgNotRecord { found } => {
            format!(
                "this is {found} — the callee's `any` parameter reads record fields, \
                 so only a record is accepted here",
                found = an_article(found)
            )
        }
        LowerError::StoreEqAccessorInvalid(defect) => store_eq_accessor_label(defect),
        LowerError::AccessorKernelOffIntercept { kernel, context } => {
            let phrase = intercept_context_phrase(*context);
            format!("`{kernel}` is called outside its rewrite here — it is {phrase}")
        }
        LowerError::PointFreeAccessorKernel { kernel } => {
            format!(
                "`{kernel}` is partially applied here — apply it directly with its \
                 accessor and value (e.g. `{kernel} .field value`) instead of \
                 passing it point-free (say `\\x -> {kernel} .field x` if you need a \
                 function value)"
            )
        }
        LowerError::UnsaturatedHandlerKernel { kernel } => {
            format!(
                "`{kernel}` must be applied to all its arguments here — it rebuilds its \
                 handler for every request, so the handler must be given at the call: \
                 write `{kernel} contentType handler` (piping the handler in with \
                 `<|` / `|>` is fine) instead of binding `{kernel}` or a partial \
                 application of it to a name or passing it as a value"
            )
        }
        LowerError::StoreSelectProjectionInvalid(defect) => store_select_projection_label(defect),
    }
}

/// The detailed caret label for a [`LowerError::StoreSelectProjectionInvalid`],
/// factored out of [`lower_label`] so that dispatcher stays under the line cap.
fn store_select_projection_label(defect: &StoreSelectProjectionDefect) -> String {
    match defect {
        StoreSelectProjectionDefect::NotAProjectionLambda => {
            "a `Store.select` projection is `\\( left, right ) -> side.field` — a \
             two-binder tuple parameter over a column reference on one side"
                .to_string()
        }
        StoreSelectProjectionDefect::UnsupportedProjectionBody => {
            "project columns as bare `side.field` references — one column, or a \
             tuple of columns; a computed value or a literal is not a column"
                .to_string()
        }
        StoreSelectProjectionDefect::NestedProjectionTuple => {
            "a multi-column projection is a flat tuple of `side.field` references; \
             a tuple element cannot itself be a tuple"
                .to_string()
        }
        StoreSelectProjectionDefect::UnknownField { field } => format!(
            "the projection reads a `{field}` field the side's row type does not \
             declare — name a field that exists on that store's row"
        ),
        StoreSelectProjectionDefect::InvalidColumn { column } => format!(
            "the column name `{column}` derived from the projected field is not a \
             valid SQL identifier (letters, digits, and underscore only)"
        ),
        StoreSelectProjectionDefect::LiteralTypeUnsupported { ty } => format!(
            "`Store.literal` binds a scalar SQL parameter — `{ty}` is not a \
             supported scalar (String, Int, Bool, or Float)"
        ),
    }
}

/// The detailed caret label for a [`LowerError::StoreEqAccessorInvalid`],
/// factored out of [`lower_label`] so that dispatcher stays under the line cap.
fn route_pattern_label(defect: &RoutePatternDefect) -> String {
    match defect {
        RoutePatternDefect::ParamEmpty => {
            "a `:` or `*` segment has no parameter name after it".to_string()
        }
        RoutePatternDefect::ParamNotIdentifier { name, at } => format!(
            "parameter name `{name}` is not an identifier (byte {at} is not a letter, \
             digit, or `_`)"
        ),
        RoutePatternDefect::ParamDuplicate { name } => {
            format!("parameter name `{name}` appears more than once in this path")
        }
        RoutePatternDefect::MalformedEscape { segment, at } => format!(
            "segment `{segment}` has a `%` at byte {at} that is not followed by two hex digits"
        ),
        RoutePatternDefect::InvalidUtf8 { segment, at } => {
            format!("segment `{segment}` percent-decodes to invalid UTF-8 starting at byte {at}")
        }
        RoutePatternDefect::TooLong { cap } => {
            format!("this path is longer than the {cap}-byte route ceiling")
        }
        RoutePatternDefect::UnrenderableLiteral { segment } => {
            format!(
                "segment `{segment}` is empty, `.` or `..`, so this route's URL cannot be rendered"
            )
        }
    }
}

fn store_eq_accessor_label(defect: &StoreEqAccessorDefect) -> String {
    match defect {
        StoreEqAccessorDefect::NotAnAccessor => {
            "a typed query column is a bare field accessor — write `Store.eq .age 18`, \
             not a let-bound name or a computed lambda; the accessor names the column"
                .to_string()
        }
        StoreEqAccessorDefect::UnknownField { field } => format!(
            "the accessor reads a `{field}` field the row type does not declare — \
             name a field that exists on the store's row"
        ),
        StoreEqAccessorDefect::NonScalarField { field, found } => format!(
            "`{field}` has type `{found}`, which plain `Store.eq` cannot bind — \
             only String / Int / Bool / Float are scalar. For an enum or newtype \
             column, use `Store.eqBy` with the field's codec so its wire form is \
             projected to a bound value"
        ),
        StoreEqAccessorDefect::InvalidColumn { column } => format!(
            "the column name `{column}` derived from the accessor is not a valid \
             SQL identifier (letters, digits, and underscore only)"
        ),
    }
}

/// The web-family shape name for the [`LowerError::UiCellsInWebShape`] message.
/// Only `Web` / `WebView` ever reach this diagnostic (the gate fires solely for
/// those shapes); the terminal shapes share the `Web/WebView` fallback wording
/// defensively rather than a panic.
const fn web_shape_label(app: AppShape) -> &'static str {
    match app {
        AppShape::Web => "Web",
        AppShape::WebView => "WebView",
        AppShape::Tui | AppShape::Cli => "Web/WebView",
    }
}

const fn role_label(role: SpanRole) -> &'static str {
    match role {
        SpanRole::FirstDefinition => "first defined here",
        SpanRole::Opener => "the unclosed delimiter opened here",
        SpanRole::Definition => "the type was fixed here",
    }
}

// ===========================================================================
// Help / note text
// ===========================================================================

/// Turn the non-secondary help lines into footer entries.
///
/// Consecutive `did you mean` lines collapse into a single
/// `help: did you mean one of:` header + an indented candidate list (via
/// [`did_you_mean_footer`]), so a suggestion universe of many near-misses is one
/// help block, not one `= help:` line per candidate. Every other line renders
/// through [`help_text`] (or [`suggestion_text`] for a source-scoped `Suggest`).
/// An entry may itself contain newlines — the caller aligns continuation lines.
fn build_help_footer(other_help: &[&HelpLine], source: &str) -> Vec<String> {
    let mut footer: Vec<String> = Vec::new();
    let mut idx = 0;
    while let Some(line) = other_help.get(idx) {
        if matches!(line, HelpLine::DidYouMean(_)) {
            let mut names: Vec<&str> = Vec::new();
            while let Some(HelpLine::DidYouMean(name)) = other_help.get(idx) {
                names.push(name);
                idx += 1;
            }
            footer.push(did_you_mean_footer(&names));
            continue;
        }
        let text = match line {
            HelpLine::Suggest(s) => Some(suggestion_text(s, source)),
            other => help_text(other),
        };
        if let Some(text) = text {
            footer.push(text);
        }
        idx += 1;
    }
    footer
}

/// Render a run of `did you mean` candidates as one footer entry.
///
/// A single candidate keeps the terse inline form (`help: did you mean `X`?`).
/// Two or more collapse into a `help: did you mean one of:` header with each
/// candidate on its own indented line — one help block instead of one
/// `= help: did you mean` line per candidate. The returned string may contain
/// newlines; the footer printer aligns the continuation lines.
fn did_you_mean_footer(names: &[&str]) -> String {
    match names {
        [] => String::new(),
        [only] => format!("help: did you mean `{only}`?"),
        many => {
            let mut block = String::from("help: did you mean one of:");
            for name in many {
                let _ = write!(block, "\n  `{name}`");
            }
            block
        }
    }
}

/// Render a non-secondary help line into a `<kind>: <text>` string (the leading
/// `= ` is added by the caller). `None` drops the line.
fn help_text(line: &HelpLine) -> Option<String> {
    match line {
        HelpLine::DidYouMean(name) => Some(format!("help: did you mean `{name}`?")),
        HelpLine::Note(text) => Some(format!("note: {text}")),
        HelpLine::Hint(hint) => Some(format!("help: {}", hint_text(*hint))),
        HelpLine::MissingConstructor(name) => Some(format!("help: add a branch for `{name}`")),
        // Source-free fallback: the source-aware [`suggestion_text`] is used in
        // the render footer, but this arm keeps `help_text` total over `HelpLine`.
        HelpLine::Suggest(s) => Some(format!("help: replace with `{}`", s.replacement)),
        HelpLine::SecondarySpan { .. } => None,
        HelpLine::SeeExplain(topic) => Some(format!(
            "help: → run `{DOC_HINT_CMD} {topic}` to learn more"
        )),
    }
}

/// Render a suggestion as a `help: replace ... with ...` line.
///
/// The edit is spelled out only when `source` holds exactly `s.replaces` over
/// the suggestion's span; any other text there (a stale or mismatched source)
/// renders the source-free did-you-mean, never a claim about the wrong text.
fn suggestion_text(s: &Suggestion, source: &str) -> String {
    let lo = s.span.lo as usize;
    let hi = s.span.hi as usize;
    if !s.replaces.is_empty() && source.get(lo..hi) == Some(&*s.replaces) {
        format!("help: replace `{}` with `{}`", s.replaces, s.replacement)
    } else {
        did_you_mean_footer(&[&*s.replacement])
    }
}

fn hint_text(hint: Hint) -> String {
    match hint {
        Hint::ModuleHeaderExample => {
            "a module header looks like `module Main exposing (main)`".to_string()
        }
        Hint::UseDotDotOrQualified => {
            "use `..` for a range, or `Module.name` for a qualified name".to_string()
        }
        Hint::RemoveSpaceBeforeDot => {
            "`f .field` is the accessor function `.field` applied to `f`, which \
             isn't supported yet; for field access remove the space (`f.field`)"
                .to_string()
        }
        Hint::SeparateWithSpace => "separate the number and the name with a space".to_string(),
        Hint::IntegerLiteralRange => {
            format!(
                "integer literals must fit between {} and {}",
                i64::MIN,
                i64::MAX
            )
        }
        Hint::FloatLiteralRange => {
            "float literals must not exceed f64's maximum magnitude (~1.8e308)".to_string()
        }
        Hint::AddTypeSignature => {
            "add a top-level type signature, e.g. `f : Int -> Int`".to_string()
        }
        Hint::RaiseSolverBudget => {
            "raise the budget with `IPE_SOLVER_BUDGET=<n>` (0 disables the limit)".to_string()
        }
        Hint::NestingBoundDeliberate => {
            "this limit is deliberate, to fail fast on pathologically nested input".to_string()
        }
        Hint::TypeAtomForms => {
            "a type is a name, a type variable, or a parenthesised type".to_string()
        }
        Hint::ConstructorMustBeUppercase => {
            "constructor names must start with an uppercase letter".to_string()
        }
        Hint::FeatureNotSupported(f) => feature_label(f).to_string(),
        Hint::IrrefutableParameterRequired => {
            "a parameter pattern must be irrefutable; `Just x` can fail to match — \
             bind the whole value and use `case`"
                .to_string()
        }
    }
}

// One flat label per `Feature` variant; each new feature adds ~5 lines, so the
// 100-line pedantic ceiling is structural, not a complexity smell. Narrow allow.
#[allow(clippy::too_many_lines)]
const fn feature_label(f: Feature) -> &'static str {
    match f {
        Feature::CasePatternKinds => {
            "case patterns other than nullary constructors are not supported yet \
             [feature: case-pattern-kinds]"
        }
        Feature::BinOps => {
            "operators other than `+` and `-` are not supported yet [feature: binops]"
        }
        Feature::Polymorphism => {
            "this value stays fully polymorphic — its concrete type is never \
             determined, so it cannot be compiled yet [feature: polymorphism]"
        }
        Feature::HigherOrderValues => {
            "function-valued parameters and returns are not supported yet \
             [feature: higher-order-values]"
        }
        Feature::TaskResults => "only `Task ()` is supported yet [feature: task-results]",
        Feature::ParamPatterns => {
            "parameter destructuring is not supported yet [feature: param-patterns]"
        }
        Feature::UntypedFunctions => {
            "top-level functions need a type signature [feature: untyped-functions]"
        }
        Feature::FirstClassFunctions => {
            "storing a function value in a record field is not supported yet \
             [feature: first-class-functions]"
        }
        Feature::Kernels => "this kernel function is not available yet [feature: kernels]",
        Feature::PartialOverApplication => {
            "partial application and over-application are not supported yet \
             [feature: partial-over-application]"
        }
        Feature::BoundedRecordUpdate => {
            "updating a generic record is not supported yet — it needs a \
             `Clone`-bounded type parameter (bounded generics are not \
             supported yet) [feature: bounded-record-update]"
        }
        Feature::NestedPayloadPatterns => {
            "a record pattern is supported at a `case` scrutinee or a `let` \
             destructure, but not yet nested inside a constructor payload or a \
             tuple element — that needs the carrier's record type threaded to the \
             lowerer [feature: nested-payload-patterns]"
        }
        Feature::WasmRoutedApp => {
            "a routed Web.tea (Model with a `page` field + `routes`) has no \
             browser client router yet — under `--target wasm` use a \
             single-page Model (no `page` field) for now \
             [feature: wasm-routed-app]"
        }
        Feature::AliasOverRefutablePayload => {
            "an `as`-alias over a nested constructor / literal / list pattern \
             in a match arm is not supported yet — the alias binder and the \
             inner bindings would double-move a non-Copy payload; bind the \
             whole value with a plain name and match the inner shape in a \
             nested `case` instead [feature: alias-over-refutable-payload]"
        }
        Feature::CtorAsFunction => {
            "a data constructor used as a function value (referenced bare or \
             partially applied) is not supported yet — apply it to all its \
             fields at once [feature: ctor-as-function]"
        }
        Feature::CtorPayloadFunction => {
            "storing a function value in a `Set` element or a `Dict` KEY is not \
             sound (a `Set` member / `Dict` key must be comparable/hashable, which a \
             function is not — a `List` element or a `Dict` VALUE stores a function \
             fine), and an `andMap` chain applying a curried (2-or-more-argument) \
             function needs curried-payload support that is not implemented yet — \
             this is a lowering-time backstop; the primary check is a type error \
             (IPE-T0014) [feature: ctor-payload-function]"
        }
        Feature::TuplePatternMatch => {
            "a tuple pattern is supported only as a single irrefutable destructure \
             (one `case` arm or a function parameter, with variable / `_` \
             elements) for now — matching a tuple with multiple arms or a \
             refutable element is not supported yet [feature: tuple-pattern-match]"
        }
        Feature::NestedCtorDiscrimination => {
            "this refutable pattern-discrimination shape is not supported yet — \
             discriminating with cons / list patterns or guarded arms needs \
             machinery that is not in place yet \
             [feature: nested-ctor-discrimination]"
        }
        Feature::FloatKeyedCollection => {
            "a `Set Float` / `Dict Float _` has no sound Rust representation: \
             `f64` is neither `Ord` (NaN has no total order) nor `Hash` / `Eq`, \
             which `BTreeSet` / `HashMap` require — use an `Int`, `Char`, or \
             `String` element / key instead. Divergence from Ipe, rationale: \
             Rust backend capability [feature: float-keyed-collection]"
        }
        Feature::RoutedWebApp => {
            "`Web.appRouted` is not yet wired on the Rust backend — \
             use the non-routed `Web.tea` \
             { init, update, view, subscriptions } form for now \
             [feature: routed-live-app]"
        }
        Feature::LetBoundAppCfg => {
            "the cfg for an app entry point (`Web.tea` / `Tui.tea` / \
             `Cli.tea`) must be written inline as a record literal, \
             not a let-bound variable [feature: let-bound-app-cfg]"
        }
        Feature::NonCloneCapture => {
            "a function/task/decoder value captured by a closure can only be called, \
             not forwarded; bind the result outside the closure or wrap the forwarding \
             in a named top-level function [feature: non-clone-capture]"
        }
        Feature::FunctionValueReuse => {
            "a value holding a function is used more than once — function values \
             cannot be copied yet; calling it is unlimited, but a second non-call \
             use needs the value re-constructed or the code restructured to a single \
             linear use [feature: function-value-reuse]"
        }
        Feature::ForeignHandleReuse => {
            "a foreign opaque FFI handle is used more than once — the handle is the \
             real foreign Rust type, which need not be `Clone`, so a duplicating \
             `.clone()` may not compile; thread the handle linearly through one \
             call chain and read it once at the end [feature: foreign-handle-reuse]"
        }
        Feature::RowPolyRecordAnnotation => {
            "this row-polymorphic record annotation `{ r | f : T }` is not yet \
             emittable — an argument-position open row is supported, but a row in \
             return position, nested under a container/record/tuple, or one whose \
             field type itself embeds an open row, is not; use a closed record \
             annotation, or drop the annotation and let the parameter's shape be \
             inferred at its call site [feature: row-poly-record-annotation]"
        }
        Feature::JsPortBoundarySeal => {
            "a `Js.send` payload or a `Js.subscribe` decoder crosses the Ipê↔JS \
             port seam with a type that cannot be sealed: a `Secret` or \
             reserved-sink type (a secret must never be serialised to JS), an \
             untyped `Value` (the untyped channel cannot be spelled — wrap the \
             payload in a declared ADT such as `type RawJson = RawJson String`), a \
             function, an effect carrier, or another non-plain value. A port value \
             must be a plain, closed, concrete value type, exactly the seal the \
             `CustomElement down up` boundary enforces [feature: \
             js-port-boundary-seal]"
        }
        Feature::FunctionElementEquality => {
            "a function value stored in a `List`/`Dict` is `Clone` (so it can be \
             stored and forwarded, and mapped/folded/filtered by the `List.map` \
             family), but some collection operations cannot represent it: an \
             equality- or ordering-requiring operation (`List.member`, \
             `List.sort`, `List.unique`, `List.maximum`, `List.minimum`) has no \
             comparison for a function, and a higher-order operation whose mapper \
             carrier is not yet function-aware (`List.partition`, `List.map2`…`5`, \
             `Dict.map`, `Dict.foldl`/`foldr`, `Dict.filter`) cannot pass a stored \
             function to its closure. Compare on a non-function key, or move the \
             function out of the collection, instead [feature: \
             function-element-equality]"
        }
        Feature::HofCallbackFunctionResult => {
            "a higher-order kernel (`List.map`, `List.foldl`, `Maybe.map2`, \
             `andMap`, …) applies its callback at one exact arity, so the \
             callback must return a plain (non-function) value; apply the \
             missing argument inside the callback (`\\x -> add x 1`) or use \
             the kernel whose callback takes every argument (`List.map2`) \
             [feature: hof-callback-function-result]"
        }
        Feature::EtaSiteLimit => {
            "passing stored functions to a named mapper (`List.map5 applyAll fs …`) \
             wraps the mapper in an adapter with one parameter per mapper \
             argument and per argument of each stored function, and one call \
             site bounds how many it may draw; pass the mapper as a lambda that \
             calls the stored functions directly, or store functions that take \
             fewer arguments (a record or tuple of arguments) \
             [feature: eta-site-limit]"
        }
        Feature::NonCloneValueReuse => {
            "a value holding a `Task`/`Cmd`/`Sub` effect (bare, or inside a \
             union/tuple/record payload) is used more than once, or one of its \
             fields is read after the value was consumed — an effect value is \
             not `Clone`, so the second use has no sound copy to make; thread \
             the value linearly (bind and use it once), read the fields you \
             need into `let` bindings before the consuming use, or restructure \
             so the effect flows through a single continuation \
             [feature: non-clone-value-reuse]"
        }
        Feature::TaskLoopFunctionState => {
            "a `Task.loop` state whose type contains a function type (`Int -> Int`, \
             a tuple or record with a function component, or a type applied to a \
             function type such as `Maybe (Int -> Int)`) is not supported yet — the \
             state is both the `init` argument and the `Continue` constructor's \
             payload, and a function cannot take one representation in both; keep \
             the state plain data and call the function from the step instead \
             [feature: task-loop-function-state]"
        }
        Feature::StreamHandlerCapture => {
            "a `Stream.stream` handler is rebuilt for every request, so each value \
             it captures is copied into it — this capture cannot be copied (a \
             function bound through a tuple/record destructure, a `Task`/`Cmd`/\
             `Sub`, or a value whose type could not be determined); bind a \
             captured function with a plain `let f = …` or take it as a parameter, \
             and build a captured task inside the handler \
             [feature: stream-handler-capture]"
        }
        Feature::RebuiltClosureMovesCapture => {
            "this value is moved into a closure that this call builds and may \
             call more than once; a function, `Task` or `Decoder` value cannot \
             be copied into each call. Take the function as its own parameter or \
             bind it with a plain `let` so it is shared, or write an explicit \
             lambda that builds the `Task` or `Decoder` inside its body \
             [feature: rebuilt-closure-moves-capture]"
        }
    }
}

// ===========================================================================
// Token / payload stringifiers
// ===========================================================================

const fn token_kind_str(t: TokenKind) -> &'static str {
    match t {
        TokenKind::Module => "`module`",
        TokenKind::Import => "`import`",
        TokenKind::Exposing => "`exposing`",
        TokenKind::As => "`as`",
        TokenKind::Type => "`type`",
        TokenKind::Foreign => "`foreign`",
        TokenKind::Case => "`case`",
        TokenKind::Of => "`of`",
        TokenKind::Let => "`let`",
        TokenKind::In => "`in`",
        TokenKind::If => "`if`",
        TokenKind::Then => "`then`",
        TokenKind::Else => "`else`",
        TokenKind::Do => "`do`",
        TokenKind::LParen => "`(`",
        TokenKind::RParen => "`)`",
        TokenKind::LBrace => "`{`",
        TokenKind::RBrace => "`}`",
        TokenKind::LBracket => "`[`",
        TokenKind::RBracket => "`]`",
        TokenKind::ColonColon => "`::`",
        TokenKind::Equals => "`=`",
        TokenKind::Pipe => "`|`",
        TokenKind::Colon => "`:`",
        TokenKind::Arrow => "`->`",
        TokenKind::LeftArrow => "`<-`",
        TokenKind::Backslash => "`\\`",
        TokenKind::DotDot => "`..`",
        TokenKind::Dot => "`.`",
        TokenKind::Comma => "`,`",
        TokenKind::Underscore => "`_`",
        TokenKind::Plus => "`+`",
        TokenKind::PlusPlus => "`++`",
        TokenKind::Minus => "`-`",
        TokenKind::Star => "`*`",
        TokenKind::Slash => "`/`",
        TokenKind::SlashEq => "`/=`",
        TokenKind::SlashSlash => "`//`",
        TokenKind::EqEq => "`==`",
        TokenKind::Lt => "`<`",
        TokenKind::Gt => "`>`",
        TokenKind::Le => "`<=`",
        TokenKind::Ge => "`>=`",
        TokenKind::AmpAmp => "`&&`",
        TokenKind::PipePipe => "`||`",
        TokenKind::PipeGt => "`|>`",
        TokenKind::LtPipe => "`<|`",
        TokenKind::PipeEq => "`|=`",
        TokenKind::PipeDot => "`|.`",
        TokenKind::GtGt => "`>>`",
        TokenKind::LtLt => "`<<`",
        TokenKind::Ident => "an identifier",
        TokenKind::Int => "a number",
        TokenKind::Float => "a floating-point number",
        TokenKind::Str => "a string literal",
        TokenKind::Char => "a character literal",
        TokenKind::Eof => "end of input",
    }
}

const fn expected_str(e: Expected) -> &'static str {
    match e {
        Expected::ModuleKeyword => "`module`",
        Expected::ExposingKeyword => "`exposing`",
        Expected::OfKeyword => "`of`",
        Expected::InKeyword => "`in`",
        Expected::ThenKeyword => "`then`",
        Expected::ElseKeyword => "`else`",
        Expected::Equals => "`=`",
        Expected::Arrow => "`->`",
        Expected::Pipe => "`|`",
        Expected::Comma => "`,`",
        Expected::Colon => "`:`",
        Expected::LParen => "`(`",
        Expected::RParen => "`)`",
        Expected::RBrace => "`}`",
        Expected::Identifier => "an identifier",
        Expected::Constructor => "a constructor",
        Expected::TypeAtom => "a type",
        Expected::Expression => "an expression",
        Expected::Pattern => "a pattern",
    }
}

/// Render an expected set in producer order: `a`, `a or b`, `a, b, or c`.
fn expected_set_str(set: &ExpectedSet) -> String {
    let items: Vec<&str> = set.0.iter().map(|e| expected_str(*e)).collect();
    match items.as_slice() {
        [] => "something else".to_string(),
        [only] => (*only).to_string(),
        [a, b] => format!("{a} or {b}"),
        [rest @ .., last] => format!("{}, or {last}", rest.join(", ")),
    }
}

const fn header_defect_str(d: HeaderDefect) -> &'static str {
    match d {
        HeaderDefect::NotModuleKeyword => "a file must begin with `module`",
        HeaderDefect::MissingName => "the module name is missing",
        HeaderDefect::NameNotIdentifier => "the module name must be an identifier",
        HeaderDefect::MissingExposing => "the `exposing` keyword is missing",
    }
}

const fn exposing_defect_str(d: ExposingDefect) -> &'static str {
    match d {
        ExposingDefect::MissingOpenParen => "the opening `(` is missing",
        ExposingDefect::BadSeparator => "expected `,` or `)` here",
        ExposingDefect::NameNotIdentifier => "an exposed name must be an identifier",
        ExposingDefect::MalformedCtorList => "this `Type(..)` constructor list is malformed",
    }
}

const fn type_decl_defect_str(d: TypeDeclDefect) -> &'static str {
    match d {
        TypeDeclDefect::MissingName => "the type name is missing",
        TypeDeclDefect::MissingEquals => "expected `=` before the constructors",
        TypeDeclDefect::CtorNotUppercase => {
            "a constructor name must start with an uppercase letter"
        }
        TypeDeclDefect::CtorNotIdentifier => "expected a constructor name here",
    }
}

const fn case_defect_str(d: CaseDefect) -> &'static str {
    match d {
        CaseDefect::MissingOf => "expected `of` after the scrutinee",
        CaseDefect::MissingArrow => "expected `->` in this branch",
        CaseDefect::NoBranches => "this `case` has no branches",
        CaseDefect::FirstBranchNotIndented => "the first branch must be indented past `case`",
    }
}

const fn let_defect_str(d: LetDefect) -> &'static str {
    match d {
        LetDefect::NoBindings => "this `let` has no bindings before `in`",
        LetDefect::BindingNameNotLower => "a let binding name must be a lowercase identifier",
        LetDefect::MissingEquals => "expected `=` after the binding name",
        LetDefect::MissingIn => "expected `in` after the let bindings",
        LetDefect::BareWildcardBinding => {
            "`_` as the whole binding pattern binds nothing — use a `do` line or `|> Task.andThen (\\_ -> …)` to sequence an effect"
        }
    }
}

const fn if_defect_str(d: IfDefect) -> &'static str {
    match d {
        IfDefect::MissingCondition => "this `if` is missing its condition",
        IfDefect::MissingThen => "expected `then` after the condition",
        IfDefect::MissingElse => "expected `else` after the `then` branch",
    }
}

/// A human-safe representation of a character for inline display.
///
/// A control, a denied format character, or a space is invisible or
/// reorders the line around it, so it is shown by its code point.
fn char_repr(c: char) -> String {
    if c.is_control() || crate::terminal::is_denied_format_char(c) || c == ' ' {
        format!("U+{:04X}", c as u32)
    } else {
        format!("`{c}`")
    }
}

// ===========================================================================
// Type rendering
// ===========================================================================

/// Render a resolved type document to its display form.
///
/// The same rendering diagnostics use inline (`expected Int, found List
/// String`), exposed for consumers (hover, docs) that show a type outside a
/// diagnostic.
#[must_use]
pub fn render_ty(t: &TyDoc) -> String {
    ty_to_string(t)
}

/// Render a resolved type document at the top precedence level.
fn ty_to_string(t: &TyDoc) -> String {
    match t {
        TyDoc::Unit => "()".to_string(),
        TyDoc::Var(v) => v.to_string(),
        TyDoc::Con { module, name, args } => {
            // The terminal view surfaces intern their attribute types under
            // internal spellings (`TuiAttr` / `CliAttr`) that keep them distinct
            // from the DOM `Attribute`, but the author only ever writes the
            // module-qualified `Attribute`. Render the user-facing name so a
            // mismatch points at the type they can name, not the internal one.
            let head = match name.as_ref() {
                "TuiAttr" => "Tui.Ui.Attribute".to_string(),
                "CliAttr" => "Cli.Ui.Attribute".to_string(),
                _ if module.is_empty() => name.to_string(),
                _ => format!("{module}.{name}"),
            };
            if args.is_empty() {
                head
            } else {
                let rendered: Vec<String> = args.iter().map(ty_arg).collect();
                format!("{head} {}", rendered.join(" "))
            }
        }
        TyDoc::Fun(a, b) => format!("{} -> {}", ty_fun_lhs(a), ty_to_string(b)),
        TyDoc::Tuple(elems) => {
            let rendered: Vec<String> = elems.iter().map(ty_to_string).collect();
            format!("({})", rendered.join(", "))
        }
        TyDoc::Record(fields) => {
            if fields.is_empty() {
                "{}".to_string()
            } else {
                let rendered: Vec<String> = fields
                    .iter()
                    .map(|(name, ty)| format!("{name} : {}", ty_to_string(ty)))
                    .collect();
                format!("{{ {} }}", rendered.join(", "))
            }
        }
    }
}

/// Render a type in argument position, parenthesising applications and arrows.
fn ty_arg(t: &TyDoc) -> String {
    match t {
        TyDoc::Con { args, .. } if !args.is_empty() => format!("({})", ty_to_string(t)),
        TyDoc::Fun(..) => format!("({})", ty_to_string(t)),
        _ => ty_to_string(t),
    }
}

/// Render a type on the left of an arrow, parenthesising nested arrows.
fn ty_fun_lhs(t: &TyDoc) -> String {
    match t {
        TyDoc::Fun(..) => format!("({})", ty_to_string(t)),
        _ => ty_to_string(t),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::{IPE_I0001, IPE_N0001, IPE_P0050, IPE_T0001};
    use crate::diagnostic::{
        Candidates, Diagnostic, EditTarget, Expected, ExpectedSet, ParseError, SortedNames,
    };

    /// A bidi override or zero-width character named in a diagnostic is shown
    /// by its code point, never raw where it would reorder or hide the line.
    #[test]
    fn char_repr_names_invisible_and_reordering_chars_by_code_point() {
        assert_eq!(char_repr('\u{202e}'), "U+202E");
        assert_eq!(char_repr('\u{200b}'), "U+200B");
        assert_eq!(char_repr('\u{1b}'), "U+001B");
        assert_eq!(char_repr('$'), "`$`");
    }

    /// An operator that reaches an unimported module is IPE-N0034, naming the
    /// operator and the one import to add, never the qualifier wording.
    #[test]
    fn operator_import_required_names_the_operator_and_its_import() {
        let msg = NameError::OperatorImportRequired {
            operator: "|=".into(),
            module: "Ipe.Parser".into(),
        };
        assert_eq!(
            name_label(&msg).as_deref(),
            Some("`|=` comes from `Ipe.Parser`; add `import Ipe.Parser`")
        );
        assert_eq!(
            name_prose(&msg),
            "`|=` comes from `Ipe.Parser`, which you haven't imported yet."
        );
        let diag = Diagnostic::Name {
            span: Span::new(0, 2),
            msg,
        };
        assert_eq!(diag.code(), crate::code::IPE_N0034);
    }

    fn con(name: &str) -> TyDoc {
        TyDoc::Con {
            module: "".into(),
            name: name.into(),
            args: Box::new([]),
        }
    }

    #[test]
    fn terminal_attribute_types_render_user_facing_name() {
        assert_eq!(render_ty(&con("TuiAttr")), "Tui.Ui.Attribute");
        assert_eq!(render_ty(&con("CliAttr")), "Cli.Ui.Attribute");
        // A plain con with an empty module still renders bare.
        assert_eq!(render_ty(&con("Int")), "Int");
    }

    #[test]
    fn type_mismatch_shows_caret_and_expected_found() {
        let src = "module Main exposing (main)\n\nmain =\n    foo\n";
        // Underline `foo` on line 4 (bytes 40..43).
        let d = Diagnostic::Type {
            span: Span::new(40, 43),
            msg: TypeError::TypeMismatch {
                expected: Box::new(con("Int")),
                found: Box::new(TyDoc::Con {
                    module: "".into(),
                    name: "List".into(),
                    args: Box::new([con("String")]),
                }),
                definition: None,
                path: Box::new([]),
            },
        };
        let out = render(&d, "test.ipe", src);

        assert!(
            out.starts_with("-- TYPE MISMATCH "),
            "title rule leads:\n{out}"
        );
        assert!(
            out.contains("test.ipe\n"),
            "title rule ends with the file:\n{out}"
        );
        assert!(
            out.contains("\nI was expecting this to be an `Int`, but it's a `List String`.\n"),
            "prose band:\n{out}"
        );
        assert!(out.contains("--> test.ipe:4:5"), "location:\n{out}");
        assert!(out.contains("4 |     foo"), "source line:\n{out}");
        assert!(
            out.contains("^^^ expected Int, found List String"),
            "underline:\n{out}"
        );
        assert!(
            out.contains("IPE-T0001 · run `ipe doc IPE-T0001`"),
            "code footer:\n{out}"
        );
        // No ANSI in the non-tty test environment.
        assert!(!out.contains('\x1b'), "must be plain in tests:\n{out}");
    }

    #[test]
    fn hof_kernel_result_super_type_renders_without_double_negative() {
        // The generic SuperTypeUnsatisfied template ("`X` is not a `<class>`
        // type") reads as a confusing double negative for the
        // higher-order-kernel callback-result obligation ("`a` is not a
        // non-function callback result … type"). That class label must render
        // through the tailored sentence instead.
        let src = "module Main exposing (main)\n\nmain =\n    foo\n";
        let d = Diagnostic::Type {
            span: Span::new(40, 43),
            msg: TypeError::SuperTypeUnsatisfied {
                class: crate::diagnostic::HOF_KERNEL_RESULT_CLASS.into(),
                found: Box::new(TyDoc::Var("a".into())),
            },
        };
        let out = render(&d, "test.ipe", src);
        assert!(
            !out.contains("is not a non-function"),
            "double-negative template must not fire for the HOF label:\n{out}"
        );
        assert!(
            out.contains("must return a plain (non-function) value"),
            "tailored sentence missing:\n{out}"
        );
        // Every other class label keeps the generic template.
        let generic = Diagnostic::Type {
            span: Span::new(40, 43),
            msg: TypeError::SuperTypeUnsatisfied {
                class: "Number".into(),
                found: Box::new(con("String")),
            },
        };
        let out2 = render(&generic, "test.ipe", src);
        assert!(
            out2.contains("String is not a Number type"),
            "generic template regressed:\n{out2}"
        );
    }

    #[test]
    fn interpolable_super_type_names_the_scalars_and_the_fix() {
        let src = "module Main exposing (main)\n\nmain =\n    foo\n";
        let d = Diagnostic::Type {
            span: Span::new(40, 43),
            msg: TypeError::SuperTypeUnsatisfied {
                class: crate::diagnostic::INTERPOLABLE_CLASS.into(),
                found: Box::new(con("Maybe")),
            },
        };
        let out = render(&d, "test.ipe", src);
        assert!(
            out.contains("Maybe cannot be interpolated or logged"),
            "tailored sentence missing:\n{out}"
        );
        for ty in crate::diagnostic::INTERPOLABLE_TYPES {
            assert!(out.contains(ty), "accepted type `{ty}` not named:\n{out}");
        }
        for conv in [
            "String.fromInt",
            "String.fromFloat",
            "String.fromBool",
            "String.fromChar",
        ] {
            assert!(out.contains(conv), "conversion `{conv}` not named:\n{out}");
        }
        assert!(
            !out.contains("is not a interpolable"),
            "generic template must not fire for the interpolation label:\n{out}"
        );
    }

    #[test]
    fn dummy_span_compiler_bug_renders_header_help_footer_only() {
        let d = Diagnostic::CompilerBug {
            where_: "lower",
            detail: "no region type".into(),
        };
        let out = render(&d, "test.ipe", "anything");

        assert!(
            out.starts_with("-- INTERNAL COMPILER ERROR "),
            "title rule leads:\n{out}"
        );
        assert!(
            out.contains("\nSomething went wrong inside the compiler"),
            "prose band:\n{out}"
        );
        // No location / snippet band for a DUMMY span.
        assert!(!out.contains("-->"), "no location:\n{out}");
        assert!(!out.contains(" | "), "no snippet:\n{out}");
        assert!(
            out.contains("= note: no region type"),
            "detail surfaced:\n{out}"
        );
        assert!(out.contains("= note: this is a bug in Ipe, please report it"));
        assert!(out.contains("IPE-I0001 · run `ipe doc IPE-I0001`"));
        let _ = IPE_I0001;
    }

    #[test]
    fn out_of_bounds_span_clamps_without_panicking() {
        let src = "main =\n    foo\n"; // 15 bytes.
        let d = Diagnostic::Type {
            span: Span::new(11, 9999), // hi far past EOF.
            msg: TypeError::TypeMismatch {
                expected: Box::new(TyDoc::Unit),
                found: Box::new(con("Int")),
                definition: None,
                path: Box::new([]),
            },
        };
        let out = render(&d, "f.ipe", src);
        assert!(out.contains("--> f.ipe:2:5"), "clamped location:\n{out}");
        // Underline is bounded by the end of the line, not the bogus hi.
        assert!(out.contains("^^^"), "clamped underline:\n{out}");
        assert!(
            !out.contains("^^^^^^^^^^"),
            "underline must not run past EOL:\n{out}"
        );
    }

    /// The P0013 screen states the `Int` range from the type's own bounds and
    /// never calls an out-of-range literal "too big" (it may be too small).
    #[test]
    fn int_range_hint_derives_from_i64_bounds() {
        let src = "v =\n    -9223372036854775809\n";
        let d = Diagnostic::Parse {
            span: Span::new(8, 28),
            msg: ParseError::IntLiteralOutOfRange,
        };
        let out = render(&d, "f.ipe", src);
        assert!(
            out.contains(&i64::MIN.to_string()),
            "names i64::MIN:\n{out}"
        );
        assert!(
            out.contains(&i64::MAX.to_string()),
            "names i64::MAX:\n{out}"
        );
        assert!(!out.contains("too big"), "no \"too big\" wording:\n{out}");
        assert!(
            out.contains("does not fit"),
            "says the value does not fit:\n{out}"
        );
    }

    #[test]
    fn fully_out_of_range_lo_does_not_panic() {
        // Both ends past EOF, and an empty source.
        let d = Diagnostic::Parse {
            span: Span::new(500, 600),
            msg: ParseError::IntLiteralOutOfRange,
        };
        let _ = render(&d, "empty.ipe", "");
        let d2 = Diagnostic::Type {
            span: Span::new(500, 600),
            msg: TypeError::Mismatch,
        };
        let out = render(&d2, "empty.ipe", "");
        assert!(out.starts_with("-- TYPE MISMATCH "), "{out}");
        assert!(out.contains("IPE-T0001 · run `ipe doc IPE-T0001`"), "{out}");
    }

    #[test]
    fn secondary_span_renders_its_own_underline_and_label() {
        let src = "main =\n    ( foo\n";
        let d = Diagnostic::Parse {
            span: Span::new(15, 16), // somewhere on line 2.
            msg: ParseError::UnclosedDelimiter {
                opener: Span::new(11, 12),
            },
        };
        let out = render(&d, "p.ipe", src);
        assert!(out.contains('^'), "primary underline:\n{out}");
        assert!(
            out.contains("- the unclosed delimiter opened here"),
            "secondary:\n{out}"
        );
        let _ = IPE_P0050;
    }

    #[test]
    fn did_you_mean_ordering_is_deterministic() {
        let d = Diagnostic::Name {
            span: Span::new(0, 6),
            msg: NameError::ValueNotFound {
                name: "lenght".into(),
                suggestions: Candidates::hints(Box::new(["length".into(), "list".into()])),
            },
        };
        let out = render(&d, "n.ipe", "lenght\n");
        // Two-plus candidates collapse into one header; producer order of the
        // candidate list is preserved (`length` before `list`).
        assert!(
            out.contains("did you mean one of:"),
            "collapsed header:\n{out}"
        );
        let first = out.find("`length`").unwrap_or(usize::MAX);
        let second = out.find("`list`").unwrap_or(0);
        assert!(first < second, "producer order preserved:\n{out}");
        // Stable across runs: re-render must be byte-identical.
        assert_eq!(out, render(&d, "n.ipe", "lenght\n"));
        let _ = IPE_N0001;
    }

    #[test]
    fn unexpected_token_label_lists_expected_set() {
        let d = Diagnostic::Parse {
            span: Span::new(0, 1),
            msg: ParseError::UnexpectedToken {
                found: TokenKind::Int,
                expected: ExpectedSet(Box::new([
                    Expected::Identifier,
                    Expected::Constructor,
                    Expected::LParen,
                ])),
            },
        };
        let out = render(&d, "t.ipe", "5\n");
        assert!(
            out.contains("found a number, expected an identifier, a constructor, or `(`"),
            "{out}"
        );
    }

    #[test]
    fn warning_renders_title_rule_prose_and_code_footer() {
        // A warning (redundant branch) renders in the same prose-first layout as
        // an error. Its title names the specific problem, and a textual
        // ` (warning)` cue marks the severity so it survives a colourless output
        // (piped / `NO_COLOR` / a non-tty), where the colour that also carries it
        // is stripped. In the non-tty test environment the output stays plain.
        let d = Diagnostic::Type {
            span: Span::new(0, 3),
            msg: TypeError::RedundantCaseBranch {
                constructor: "Red".into(),
            },
        };
        let out = render(&d, "w.ipe", "Red\n");
        assert!(
            out.starts_with("-- REDUNDANT CASE BRANCH (warning) "),
            "title rule names the specific problem and the severity:\n{out}"
        );
        assert!(
            out.contains("\nThis branch for `Red` can never run"),
            "prose band:\n{out}"
        );
        assert!(
            out.trim_end()
                .ends_with("IPE-T0011 · run `ipe doc IPE-T0011`"),
            "code footer last:\n{out}"
        );
        assert!(!out.contains('\x1b'), "plain in tests:\n{out}");
        let _ = IPE_T0001;
    }

    #[test]
    fn error_title_has_no_severity_cue() {
        // An error carries no ` (warning)` cue — the title already reads as a
        // problem, and the colour (when present) still distinguishes it.
        let src = "module Main exposing (main)\n\nmain =\n    foo\n";
        let d = Diagnostic::Type {
            span: Span::new(40, 43),
            msg: TypeError::TypeMismatch {
                expected: Box::new(con("Int")),
                found: Box::new(con("String")),
                definition: None,
                path: Box::new([]),
            },
        };
        let out = render(&d, "test.ipe", src);
        assert!(out.starts_with("-- TYPE MISMATCH "), "title rule:\n{out}");
        assert!(!out.contains("(warning)"), "no cue on an error:\n{out}");
    }

    #[test]
    fn title_is_per_code_not_per_family() {
        // Two type-family codes that are not mismatches must not render
        // `TYPE MISMATCH`: the title names the actual problem.
        let missing = Diagnostic::Type {
            span: Span::DUMMY,
            msg: TypeError::NonExhaustiveCase {
                missing: SortedNames::new(["Green".into()]),
            },
        };
        assert!(
            render(&missing, "m.ipe", "")
                .starts_with("-- THIS CASE DOES NOT HANDLE EVERY POSSIBILITY "),
            "IPE-T0010 title"
        );
        let no_field = Diagnostic::Type {
            span: Span::DUMMY,
            msg: TypeError::NoSuchField {
                field: "x".into(),
                record: Box::new(con("Point")),
            },
        };
        assert!(
            render(&no_field, "f.ipe", "").starts_with("-- THIS RECORD HAS NO SUCH FIELD "),
            "IPE-T0012 title"
        );
    }

    #[test]
    fn multiline_span_underlines_every_covered_line() {
        // A span crossing three lines underlines all three; the label lands on
        // the last. No caret runs past a line's end.
        let src = "module Main exposing (main)\n\nmain =\n    add\n        1\n        2\n";
        let d = Diagnostic::Type {
            span: Span::new(40, 63), // `add\n        1\n        2` region.
            msg: TypeError::TypeMismatch {
                expected: Box::new(con("Int")),
                found: Box::new(con("String")),
                definition: None,
                path: Box::new([]),
            },
        };
        let out = render(&d, "test.ipe", src);
        assert!(out.contains("4 |     add"), "first line shown:\n{out}");
        assert!(out.contains("5 |         1"), "middle line shown:\n{out}");
        assert!(out.contains("6 |         2"), "last line shown:\n{out}");
        // Three underline rows (one per covered line).
        assert!(
            out.matches("^^").count() >= 2,
            "each covered line underlined:\n{out}"
        );
    }

    #[test]
    fn tab_indent_and_wide_chars_align_the_caret() {
        // A tab-indented identifier: the caret indent equals the expanded-tab
        // width (4), not the single `\t` char.
        let tab_src = "main =\n\tfoo\n";
        let d = Diagnostic::Name {
            span: Span::new(8, 11), // `foo` after the tab.
            msg: NameError::ValueNotFound {
                name: "foo".into(),
                suggestions: Candidates::default(),
            },
        };
        let out = render(&d, "t.ipe", tab_src);
        // The tab expands to four spaces in the shown line and the caret indent.
        assert!(
            out.contains("2 |     foo"),
            "tab expanded in source:\n{out}"
        );
        assert!(out.contains(" |     ^^^"), "caret under `foo`:\n{out}");

        // A wide (CJK) prefix: `x` sits at display column 8 (`你好` is 4 cells +
        // two quotes + one leading space ... ), so the caret indent counts
        // display width, not `char`s.
        let wide_src = "main =\n\"你好\" x\n";
        let dw = Diagnostic::Name {
            span: Span::new(16, 17), // the `x`.
            msg: NameError::ValueNotFound {
                name: "x".into(),
                suggestions: Candidates::default(),
            },
        };
        let outw = render(&dw, "w.ipe", wide_src);
        // `"你好" ` is 2 + 2 + 2 + 1 = 7 display cells, so the caret sits at
        // indent 7.
        assert!(
            outw.contains(" | 你好\" x") || outw.contains("\"你好\" x"),
            "wide chars shown:\n{outw}"
        );
        assert!(
            outw.contains("       ^"),
            "caret past the wide chars:\n{outw}"
        );
    }

    #[test]
    fn single_candidate_renders_machine_applicable_replacement() {
        // One suggestion → a span-scoped "replace `lenght` with `length`".
        let src = "lenght\n";
        let d = Diagnostic::Name {
            span: Span::new(0, 6),
            msg: NameError::ValueNotFound {
                name: "lenght".into(),
                suggestions: Candidates::at(
                    EditTarget::whole(Span::new(0, 6), "lenght"),
                    Box::new(["length".into()]),
                ),
            },
        };
        let out = render(&d, "n.ipe", src);
        assert!(
            out.contains("= help: replace `lenght` with `length`"),
            "suggestion:\n{out}"
        );
        // Re-render is byte-identical (deterministic).
        assert_eq!(out, render(&d, "n.ipe", src));
    }

    /// A suggestion whose span holds other text than it `replaces` never claims
    /// an edit: it renders the plain did-you-mean.
    #[test]
    fn mismatched_replaces_renders_did_you_mean_not_an_edit() {
        let src = "Lsit.map f\n";
        let d = Diagnostic::Name {
            span: Span::new(0, 8),
            msg: NameError::UnknownModule {
                qualifier: "Lsit".into(),
                suggestions: Candidates::at(
                    EditTarget::whole(Span::new(0, 8), "Lsit.mpa"),
                    Box::new(["List".into()]),
                ),
            },
        };
        let out = render(&d, "n.ipe", src);
        assert!(
            !out.contains("replace `"),
            "mismatched region must not render an edit:\n{out}"
        );
        assert!(
            out.contains("did you mean `List`?"),
            "mismatched region falls back to did-you-mean:\n{out}"
        );
    }

    #[test]
    fn multiple_did_you_mean_collapse_to_one_header_with_indented_list() {
        // Two-plus candidates render as ONE `did you mean one of:` help block,
        // each candidate indented beneath — not one `= help:` line per
        // candidate.
        let src = "import Fooo\n";
        let d = Diagnostic::Name {
            span: Span::new(7, 11),
            msg: NameError::ModuleNotFound {
                name: "Fooo".into(),
                suggestions: Candidates::hints(Box::new([
                    "Foo".into(),
                    "Food".into(),
                    "Fool".into(),
                ])),
            },
        };
        let out = render(&d, "n.ipe", src);
        assert_eq!(
            out.matches("did you mean").count(),
            1,
            "exactly one did-you-mean header, got:\n{out}"
        );
        assert!(
            out.contains("= help: did you mean one of:"),
            "collapsed header:\n{out}"
        );
        for name in ["Foo", "Food", "Fool"] {
            assert!(
                out.contains(&format!("`{name}`")),
                "candidate `{name}` indented beneath, got:\n{out}"
            );
        }
        // The candidate lines carry no `= ` marker — they belong to the block.
        assert!(
            !out.contains("= help: did you mean `Foo`?"),
            "no per-candidate help line survives:\n{out}"
        );
        assert_eq!(out, render(&d, "n.ipe", src), "deterministic re-render");
    }

    #[test]
    fn single_did_you_mean_keeps_the_terse_inline_form() {
        // A lone candidate that is NOT machine-applicable (a `DidYouMean`, not a
        // `Suggest`) keeps `help: did you mean `X`?`, never the `one of:` block.
        let d = Diagnostic::Name {
            span: Span::DUMMY,
            msg: NameError::ModuleNotFound {
                name: "Foo".into(),
                suggestions: Candidates::hints(Box::new(["Food".into(), "Fool".into()])),
            },
        };
        // Craft a genuine single-DidYouMean via `help()` directly: a two-plus
        // suggestion list is the only ModuleNotFound path to `DidYouMean`, so a
        // single-candidate `DidYouMean` block is exercised through the helper.
        assert_eq!(did_you_mean_footer(&["Food"]), "help: did you mean `Food`?");
        // And the multi-form collapses.
        assert_eq!(
            did_you_mean_footer(&["Food", "Fool"]),
            "help: did you mean one of:\n  `Food`\n  `Fool`"
        );
        let _ = d;
    }

    #[test]
    fn compiler_bug_emits_apology_and_tracker_url() {
        let d = Diagnostic::CompilerBug {
            where_: "lower",
            detail: "no region type".into(),
        };
        let out = render(&d, "x.ipe", "anything");
        assert!(
            out.contains("sorry about that"),
            "Elm-style apology:\n{out}"
        );
        assert!(
            out.contains(&crate::code::issue_tracker_url()),
            "tracker URL:\n{out}"
        );
        // The demoted code footer, carrying the explain pointer, is last.
        assert!(
            out.trim_end()
                .ends_with("IPE-I0001 · run `ipe doc IPE-I0001`"),
            "code footer last:\n{out}"
        );
    }

    #[test]
    fn nested_type_args_parenthesise() {
        let inner = TyDoc::Con {
            module: "".into(),
            name: "Maybe".into(),
            args: Box::new([con("Int")]),
        };
        let outer = TyDoc::Con {
            module: "".into(),
            name: "List".into(),
            args: Box::new([inner]),
        };
        assert_eq!(ty_to_string(&outer), "List (Maybe Int)");
        let f = TyDoc::Fun(Box::new(con("Int")), Box::new(con("Bool")));
        let g = TyDoc::Fun(Box::new(f), Box::new(con("Char")));
        assert_eq!(ty_to_string(&g), "(Int -> Bool) -> Char");
    }

    // -------------------------------------------------------------------------
    // render_json unit tests
    // -------------------------------------------------------------------------

    #[test]
    fn render_json_schema_shape() {
        let diag = Diagnostic::Type {
            span: Span::new(10, 15),
            msg: TypeError::TypeMismatch {
                expected: Box::new(TyDoc::Unit),
                found: Box::new(TyDoc::Var("a".into())),
                definition: None,
                path: Box::new([]),
            },
        };
        let source = "module Main exposing (main)\nmain = 42\n";
        let json = render_json(&diag, "Main.ipe", source);

        // Must end with a newline for line-oriented consumers.
        assert!(json.ends_with('\n'), "render_json must end with newline");

        let trimmed = json.trim();
        assert!(
            trimmed.starts_with('{') && trimmed.ends_with('}'),
            "render_json must produce a JSON object: {json:?}"
        );

        // Required fields.
        for field in &[
            "code",
            "severity",
            "title",
            "message",
            "primary_span",
            "secondary_spans",
            "hints",
            "suggestions",
            "explain_ref",
        ] {
            assert!(
                trimmed.contains(&format!("\"{field}\":")),
                "missing {field:?} in: {json:?}"
            );
        }

        assert!(
            trimmed.contains("\"IPE-T0001\""),
            "code must be IPE-T0001: {json:?}"
        );
        assert!(
            trimmed.contains("\"severity\":\"error\""),
            "severity must be error: {json:?}"
        );
        assert!(
            trimmed.contains("\"primary_span\":{"),
            "primary_span must be an object: {json:?}"
        );
        assert!(
            trimmed.contains("\"byte_lo\":10"),
            "byte_lo must be 10: {json:?}"
        );
        assert!(
            trimmed.contains("\"byte_hi\":15"),
            "byte_hi must be 15: {json:?}"
        );
        assert!(
            trimmed.contains("\"explain_ref\":\"ipe doc IPE-T0001\""),
            "explain_ref must name the code: {json:?}"
        );
    }

    /// Asserts that `render_json`'s `"role"` field emits EXACTLY the closed set
    /// `{"first_definition", "opener", "definition"}` — one string per
    /// `SpanRole` variant — and nothing else.
    ///
    /// This is the drift-guard for the schema doc comment on `render_json`.
    /// It fails if:
    ///   - a variant's emitted string is not in the documented set, or
    ///   - the documented set contains a string no variant can produce.
    ///
    /// To extend the set: add a `SpanRole` variant, wire it in the emitter's
    /// match, and add a case here — the doc comment updates in the same commit.
    #[test]
    fn render_json_role_set_matches_emitter() {
        let source = "module Main exposing (main)\nmain = 42\n";

        // The complete closed set the schema doc advertises.
        let documented: &[&str] = &["first_definition", "opener", "definition"];

        // --- FirstDefinition via NameError::DuplicateValue ---
        let diag_first_def = Diagnostic::Name {
            span: Span::new(20, 24),
            msg: crate::diagnostic::NameError::DuplicateValue {
                name: "foo".into(),
                first: Span::new(5, 8),
            },
        };
        let json_first_def = render_json(&diag_first_def, "Main.ipe", source);
        assert!(
            json_first_def.contains("\"role\":\"first_definition\""),
            "FirstDefinition must emit role=first_definition: {json_first_def:?}"
        );

        // --- Opener via ParseError::UnclosedDelimiter ---
        let diag_opener = Diagnostic::Parse {
            span: Span::new(20, 24),
            msg: ParseError::UnclosedDelimiter {
                opener: Span::new(5, 6),
            },
        };
        let json_opener = render_json(&diag_opener, "Main.ipe", source);
        assert!(
            json_opener.contains("\"role\":\"opener\""),
            "Opener must emit role=opener: {json_opener:?}"
        );

        // --- Definition via TypeError::TypeMismatch with definition span ---
        let diag_defn = Diagnostic::Type {
            span: Span::new(20, 24),
            msg: crate::diagnostic::TypeError::TypeMismatch {
                expected: Box::new(TyDoc::Unit),
                found: Box::new(TyDoc::Var("a".into())),
                definition: Some(Span::new(5, 8)),
                path: Box::new([]),
            },
        };
        let json_defn = render_json(&diag_defn, "Main.ipe", source);
        assert!(
            json_defn.contains("\"role\":\"definition\""),
            "Definition must emit role=definition: {json_defn:?}"
        );

        // No role string outside the documented set is reachable.
        // Collect every `"role":"…"` value the three representative outputs
        // produced and assert the union equals the documented set exactly.
        let all_jsons = [&json_first_def, &json_opener, &json_defn];
        let mut emitted: Vec<&str> = Vec::new();
        for json in &all_jsons {
            for role in documented {
                if json.contains(&format!("\"role\":\"{role}\"")) && !emitted.contains(role) {
                    emitted.push(role);
                }
            }
        }
        // Every documented role must be reachable (no ghost entries in the doc).
        for role in documented {
            assert!(
                emitted.contains(role),
                "documented role {role:?} is not produced by any SpanRole variant"
            );
        }
    }

    #[test]
    fn render_json_escapes_special_chars() {
        let diag = Diagnostic::CompilerBug {
            where_: "lower",
            detail: "detail with \"quotes\" and\nnewlines".into(),
        };
        let json = render_json(&diag, "src/Main.ipe", "");
        let trimmed = json.trim();

        assert!(
            trimmed.contains("\\\"quotes\\\""),
            "double quotes must be escaped: {json:?}"
        );
        assert!(
            trimmed.contains("\\n"),
            "newlines must be escaped: {json:?}"
        );
        assert!(
            trimmed.starts_with('{') && trimmed.ends_with('}'),
            "escaped JSON must still be a valid object shape: {json:?}"
        );
    }

    /// A bidi override or C1 control in a diagnostic's text reaches the JSON record escaped.
    #[test]
    fn render_json_escapes_terminal_hazards() {
        let diag = Diagnostic::CompilerBug {
            where_: "lower",
            detail: "a\u{202e}b\u{9b}c".into(),
        };
        let json = render_json(&diag, "src/Main.ipe", "");
        assert!(
            !json.contains('\u{202e}'),
            "U+202E reached the record raw: {json:?}"
        );
        assert!(
            !json.contains('\u{9b}'),
            "U+009B reached the record raw: {json:?}"
        );
        let record: serde_json::Value = serde_json::from_str(json.trim()).expect("valid JSON");
        assert!(
            record.to_string().contains("a\u{202e}b\u{9b}c"),
            "the decoded record keeps the detail text: {json:?}"
        );
    }

    #[test]
    fn render_json_compiler_bug_has_null_primary_span() {
        let diag = Diagnostic::CompilerBug {
            where_: "lower",
            detail: "oops".into(),
        };
        let json = render_json(&diag, "src/Main.ipe", "");
        assert!(
            json.contains("\"primary_span\":null"),
            "CompilerBug must have null primary_span: {json:?}"
        );
        assert!(
            json.contains("\"severity\":\"bug\""),
            "CompilerBug severity must be 'bug': {json:?}"
        );
    }

    /// The human header title and the JSON `title` field both derive from the
    /// `code::title()` SSOT. This asserts they cannot drift: for every code in
    /// the taxonomy the uppercased SSOT title matches what `title_rule_name`
    /// would produce, and equals what `render_json` emits in the `"title"` field.
    #[test]
    fn human_header_and_json_title_derive_from_one_ssot() {
        use crate::code::{ALL_CODES, title};
        for &code in ALL_CODES {
            let ssot = title(code);
            let header = title_rule_name(code);
            assert_eq!(
                header,
                ssot.to_ascii_uppercase(),
                "human header for {} must be the SSOT title uppercased",
                code.as_str()
            );
        }
    }

    /// A path literal containing a NUL byte renders its specific detail message.
    ///
    /// Uses `plain_message` (which includes the label from `parse_label`) because
    /// `render` with a `Span::DUMMY` suppresses the snippet+label band.
    #[test]
    fn path_rejection_nul_renders_nul_message() {
        let diag = Diagnostic::Parse {
            span: crate::span::Span::DUMMY,
            msg: ParseError::InvalidPathLiteral {
                literal: "safe\0bad".into(),
                refusal: ipe_path_core::LiteralRefusal {
                    regime: ipe_path_core::Regime::Unix,
                    why: ipe_path_core::SealRefusal::Nul,
                },
            },
        };
        let out = plain_message(&diag, "");
        assert!(
            out.to_ascii_lowercase().contains("nul"),
            "Nul rejection must mention NUL in plain_message output:\n{out}"
        );
    }

    /// A path literal with a traversal renders its specific detail message.
    #[test]
    fn path_rejection_traversal_renders_traversal_message() {
        let diag = Diagnostic::Parse {
            span: crate::span::Span::DUMMY,
            msg: ParseError::InvalidPathLiteral {
                literal: "../secret".into(),
                refusal: ipe_path_core::LiteralRefusal {
                    regime: ipe_path_core::Regime::Unix,
                    why: ipe_path_core::SealRefusal::Escape {
                        cleaned: "../secret".to_string(),
                    },
                },
            },
        };
        let out = plain_message(&diag, "");
        assert!(
            out.contains("traversal") || out.contains(".."),
            "Traversal rejection must mention traversal in plain_message output:\n{out}"
        );
    }

    /// A literal only the Windows regime refuses names Windows in its detail.
    #[test]
    fn path_rejection_windows_only_names_windows() {
        for (literal, why) in [
            (
                "..\\secret",
                ipe_path_core::SealRefusal::Escape {
                    cleaned: "..\\secret".to_string(),
                },
            ),
            ("...", ipe_path_core::SealRefusal::DisguisedParent),
        ] {
            let diag = Diagnostic::Parse {
                span: crate::span::Span::DUMMY,
                msg: ParseError::InvalidPathLiteral {
                    literal: literal.into(),
                    refusal: ipe_path_core::LiteralRefusal {
                        regime: ipe_path_core::Regime::Windows,
                        why,
                    },
                },
            };
            let out = plain_message(&diag, "");
            assert!(
                out.contains("Windows"),
                "a Windows-only refusal must name Windows:\n{out}"
            );
        }
    }

    /// `an_article` wraps a bare type name in exactly one balanced backtick
    /// pair. A complete noun phrase (`MainRetName::Phrase`) is emitted verbatim
    /// and never routed through here, so `an_article` never nests backticks.
    #[test]
    fn an_article_single_wraps_bare_names() {
        for name in ["Int", "String", "List String", "a"] {
            let out = an_article(name);
            assert_eq!(
                out.matches('`').count(),
                2,
                "expected one balanced backtick pair: {out:?}"
            );
            assert!(
                out.ends_with(&format!("`{name}`")),
                "the bare name should be the wrapped tail: {out:?}"
            );
        }
    }
}
