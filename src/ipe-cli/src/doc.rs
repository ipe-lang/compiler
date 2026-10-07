//! `ipe doc` — API documentation generation.
//!
//! Generates reference documentation for an Ipê package from its own source: the
//! public API a consumer sees, each entry carrying its checker-inferred type
//! signature, its doc-comment, and a stable source location.
//!
//! ## Output layout
//!
//! Each rendering writes into its own subfolder of the output base (`doc/` by
//! default, overridden with `--out DIR`):
//!
//! - `<base>/json/docs.json` — the machine-readable source of truth.
//! - `<base>/markdown/<Module>.md` and `<base>/markdown/index.md` — Markdown views.
//! - `<base>/html/index.html`, `<base>/html/<Module>.html`, `<base>/html/style.css`
//!   — the self-contained HTML site.
//!
//! Cross-links within each format are relative to that format's subfolder. The
//! logical anchor scheme (`Module#Name`) is format-neutral and identical across
//! all three renderings.
//!
//! ## Stdlib documentation without a project
//!
//! The command succeeds in any directory. When no project source is reachable at
//! `PATH`, it falls back to stdlib-only documentation rather than erroring. Running
//! `ipe doc --write-format html` in an empty directory writes the full stdlib
//! reference to `doc/html/`.
//!
//! ## Module index hierarchy
//!
//! The module listing in HTML and Markdown is a namespace tree — `Ipe.Db.Codec`
//! nests under `Ipe.Db`, not in a flat alphabetical list. A prefix that has no
//! module at its exact dotted path renders as a non-link section header.
//!
//! ## Command surface
//!
//! The command surface is a closed [`DocMode`] parsed at the CLI boundary, so an
//! invalid flag combination is unrepresentable downstream (parse, don't validate;
//! make-invalid-states-unrepresentable):
//!
//! * `ipe doc [PATH] [--out DIR] [--write-format markdown|json|html|all]` — generate
//!   renderings under `<out>/{json,markdown,html}/`. Works without a project.
//!   Includes all stdlib modules (both compiled-source and kernel-backed) alongside
//!   any project modules found at `PATH`.
//! * `ipe doc list [--plain|--json]` — list all stdlib modules (and project modules),
//!   one per line. Default: guttered human output; `--plain`: bare names; `--json`:
//!   `{"modules":[…]}`. The former `--list` flag is a deprecated alias that still
//!   works and prints a notice pointing at `list`.
//! * `ipe doc <MODULE> [--plain|--json]` — dump one module's exposed types, values, and
//!   functions with their type signatures (e.g. `ipe doc Ipe.List`). Default: human;
//!   `--plain`: flush-left; `--json`: stable structured record.
//! * `ipe doc serve [PATH] [--port N]` — build the HTML site and preview it
//!   read-only on `http://127.0.0.1:<port>` (loopback only; the port defaults to
//!   an auto-selected free one).
//! * `ipe doc check [PATH]` — a coverage gate that writes nothing and exits
//!   non-zero when an exposed binding lacks a doc-comment. Stdlib modules are exempt.
//! * `ipe doc --check-examples` — extract every fenced ` ```ipe ` block from every
//!   `{-| … -}` doc-string in the standard library and type-check each one. A block
//!   that carries `-->` result annotations is also compiled and run (when `IPE_E2E=1`
//!   is set) and the printed output is asserted against the annotation. Exits non-zero
//!   when any block fails its expectation.
//!
//! The machine-readable [`docs.json`](DocsJson) is the source of truth — one
//! record per exposed module, with the module's doc-comment and its exposed
//! unions and values (name + type + comment + resolved cross-references). Both
//! the Markdown and the self-contained HTML site are pure views over that same
//! in-memory model. The schema is versioned ([`DOCS_JSON_VERSION`]) so a
//! downstream consumer can rely on it.
//!
//! ## Cross-references
//!
//! Every type name in a rendered signature that resolves — via the
//! canonicaliser's already-computed [`TyDoc`] identity, never a text guess — to a
//! type documented in this package becomes a link to that entry's stable anchor
//! (`Module#Name`, identical across json / Markdown / HTML). A built-in with no
//! in-package definition (e.g. `Int`) renders as plain text.
//!
//! ## Two provenances, joined by name
//!
//! Type signatures come from the type checker — this module reuses
//! [`crate::api_surface::extract_tree`], the same projection `ipe diff` uses, so
//! a documented type is exactly the checked type and is never re-parsed. Ipê's
//! lexer discards every comment before the AST exists, so the `{-| … -}` and
//! `-- |` doc-comments are recovered at the driver boundary by the shared
//! extractor ([`scan_doc_comments`] over [`ipe_docs::stdlib_docs`]) and joined to
//! the checked surface by binding name.
//! Neither pass runs the emit tier — `ipe doc` needs types, not code.
//!
//! ## Stdlib coverage
//!
//! Two kinds of stdlib module exist:
//!
//! * **Compiled-source** (`ipe_stdlib::COMPILED_STD_MODULES`): modules with embedded Ipê
//!   source (e.g. `Ipe.Css`, `Ipe.Test`). These are type-checked as embedded stdlib
//!   (so they may declare the reserved `Ipe.*` namespace a user module may not); their
//!   doc-comments are scanned from the embedded source.
//! * **Kernel-qualifier** (`ipe_canon::STDLIB_MODULE_QUALIFIERS`): modules backed by the
//!   kernel registry (e.g. `Ipe.List`, `Ipe.String`). Type signatures come from
//!   [`ipe_types::kernel_type_table`]; doc-comments are absent (signatures are the
//!   contract).
//!
//! `ipe doc check` exempts stdlib modules from the coverage gate — signatures are
//! sufficient; prose is optional for compiler-internal stdlib.
//!
//! Still out of scope (tracked separately): inter-*package* linking (needs the
//! package index), full-text search, and remote hosting. `serve` is a local
//! read-only preview of the static site, never a publish path.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use ipe_diagnostics::{TyDoc, render_ty};
use ipe_docs::{CommandInfo, Index, html};
use ipe_intern::Interner;
use ipe_types::{VarNamer, kernel_type_table, ty_to_doc};

use crate::CliError;
use crate::api_surface::{ModuleApi, ModulePath, PublicApi, UnionApi, extract_walked, read_tree};
use crate::cli_args::OutputFormat;
use crate::doc_bundle::{BundleSource, DocBundle, DocEntry, DocKind, is_qualified};
use crate::doc_pick::Pick;
use crate::doc_search::{DocMiss, DocQuery, MAX_QUERY_CHARS, QueryRefusal, Ranked};
use crate::text;

/// The `docs.json` schema version. Bumped only on an incompatible shape change,
/// so a consumer can refuse a document it does not understand rather than
/// mis-reading it.
pub const DOCS_JSON_VERSION: u32 = 2;

/// Which renderings `ipe doc` writes — a closed set, so an unknown `--write-format`
/// value is rejected at the CLI boundary rather than carried downstream.
///
/// `docs.json` (the machine-readable source of truth) is always written; a
/// [`WriteFormat`] selects which human-facing view(s) are written beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteFormat {
    /// `docs.json` only — the machine-readable source of truth.
    Json,
    /// `docs.json` + per-module Markdown.
    Markdown,
    /// `docs.json` + the self-contained HTML site.
    Html,
    /// `docs.json` + Markdown + HTML (the default).
    All,
}

impl WriteFormat {
    /// Whether this format writes the per-module Markdown.
    const fn wants_markdown(self) -> bool {
        matches!(self, Self::Markdown | Self::All)
    }

    /// Whether this format writes the self-contained HTML site.
    const fn wants_html(self) -> bool {
        matches!(self, Self::Html | Self::All)
    }
}

/// What `ipe doc` was asked to do — a closed set.
///
/// No code past the parser can hold an invalid mix
/// (make-invalid-states-unrepresentable). `Generate` carries only its own flags
/// (`--out`, `--write-format`); `Serve` carries only `--port`; `Check` carries
/// none; `List` and `Query` carry only `--plain`/`--json` — so mixing flags
/// across subcommands has no representation to construct.
#[derive(Debug, PartialEq, Eq)]
pub enum DocMode {
    /// Write `docs.json` and the selected renderings to `out`.
    Generate {
        /// The package to document — a directory or a single `.ipe` file.
        path: PathBuf,
        /// Where the rendered documentation is written.
        out: PathBuf,
        /// Which human-facing renderings are written beside `docs.json`.
        write_format: WriteFormat,
    },
    /// Build the HTML site and serve it read-only on loopback.
    Serve {
        /// The package to document — a directory or a single `.ipe` file.
        path: PathBuf,
        /// The loopback port to bind. `None` auto-selects a free one (bind
        /// `127.0.0.1:0`, let the OS assign); `Some(n)` pins it and errors if it
        /// is taken.
        port: Option<u16>,
    },
    /// Verify every exposed binding is documented; write nothing.
    Check {
        /// The package to check (only project modules, never stdlib).
        path: PathBuf,
    },
    /// List all stdlib + project module names.
    List {
        /// The package whose modules are listed alongside stdlib (defaults to `.`).
        path: PathBuf,
        /// How to render the list.
        format: OutputFormat,
    },
    /// Print one module's exposed types and values with their type signatures.
    Query {
        /// The dotted module name to look up (e.g. `Ipe.List`).
        module: String,
        /// How to render the result.
        format: OutputFormat,
    },
    /// Type-check every fenced ` ```ipe ` block in every `{-| … -}` doc-string
    /// across the standard library. When `IPE_E2E=1` is set, blocks with `-->`
    /// result annotations are also compiled, run, and their output asserted.
    /// Exits non-zero when any block fails its expectation.
    CheckExamples,
    /// Look up any entity by key via the `ipe_docs` index.
    ///
    /// Accepts symbols (`List.map`), modules (`List`), diagnostic codes
    /// (`IPE-L0107`), language constructs (`case`), and CLI commands (`version`).
    Lookup {
        /// The documentation key to resolve.
        key: String,
        /// How to render the result.
        format: OutputFormat,
    },
    /// Search the stdlib API by type signature (Elm/Hoogle-style).
    ///
    /// Parses `query` as an Ipê type expression, alpha-normalizes it, and
    /// returns ranked symbol matches. An unparseable query is a typed error.
    TypeSearch {
        /// The type-expression query string, e.g. `List a -> (a -> b) -> List b`.
        query: String,
        /// How to render the results.
        format: OutputFormat,
    },
}

/// The default output directory when `--out` is omitted, mirroring Elm's `doc/`.
const DEFAULT_OUT: &str = "doc";

/// The default package path when a positional is omitted — the current project.
const DEFAULT_PATH: &str = ".";

/// The `ipe doc` subcommand a leading token selects. The bare form (no leading
/// subcommand) is `generate`.
enum Sub {
    Generate,
    Serve,
    Check,
    List,
    Query(String),
    CheckExamples,
    Lookup(String),
}

/// Accumulated flag values while parsing `ipe doc`'s argument tail.
#[derive(Default)]
struct ParsedFlags {
    path: Option<String>,
    out: Option<String>,
    write_format: Option<WriteFormat>,
    port: Option<u16>,
    output_format: Option<OutputFormat>,
}

/// Parse `ipe doc`'s argument tail into a [`DocMode`].
///
/// The bare form is `generate`; a leading bare word — `serve`, `check`, or
/// `list` — selects that mode, and a leading non-flag positional that looks like
/// a dotted module name (starts with an uppercase letter) selects `query`. The
/// legacy `--list` flag is a deprecated alias for the `list` mode, kept
/// dispatchable so it does not break existing invocations. Each mode accepts
/// ONLY its own flags, so a flag meaningless for the chosen mode is rejected
/// here rather than carried into an unrepresentable [`DocMode`].
///
/// # Errors
/// [`CliError::Usage`] naming the exact problem.
pub fn parse_doc(rest: &[String]) -> Result<DocMode, CliError> {
    parse_doc_with(rest, &mut |msg| {
        crate::screen::chatter(crate::screen::Stream::Stderr, crate::screen::Tone::Aux, msg);
    })
}

/// The stderr notice emitted when the deprecated `--list` alias is used.
const LIST_DEPRECATION_NOTICE: &str =
    "note: `ipe doc --list` is deprecated; use `ipe doc list` instead";

/// [`parse_doc`] with the deprecation-notice sink injected, so a test can
/// observe the alias notice without inspecting a process's stderr.
#[allow(clippy::too_many_lines)]
fn parse_doc_with(rest: &[String], notice: &mut dyn FnMut(&str)) -> Result<DocMode, CliError> {
    let mut it = rest.iter().peekable();

    // `--check-examples` selects the doc-test gate; detected before other flags.
    let has_check_examples = rest.iter().any(|s| s == "--check-examples");

    // `--type <query>` selects the type-signature search mode. Detected early
    // because the query value can contain spaces and special characters that
    // would otherwise confuse the positional-argument scanner.
    let type_query: Option<String> = rest
        .windows(2)
        .find_map(|pair| match pair {
            [flag, val] if flag == "--type" => Some(val.clone()),
            _ => None,
        })
        .or_else(|| {
            // Also accept `--type=<query>` (single token).
            rest.iter()
                .find_map(|s| s.strip_prefix("--type=").map(str::to_owned))
        });

    // The deprecated `--list` flag still selects the `list` mode. It is a
    // flag-style alias for the bare `list` word, detected before the positional
    // scan so it works in any position.
    let has_list_flag = rest.iter().any(|s| s == "--list");
    if has_list_flag {
        notice(LIST_DEPRECATION_NOTICE);
    }

    // `--type` is mutually exclusive with all other subcommands.
    if let Some(query) = type_query {
        if has_check_examples || has_list_flag {
            return Err(CliError::Usage(text::msg::doc_type_exclusive()));
        }
        // Consume remaining flags for TypeSearch (only --plain/--json allowed).
        let mut output_format: Option<OutputFormat> = None;
        for tok in rest {
            match tok.as_str() {
                "--type" => {}
                t if t.starts_with("--type=") => {}
                "--plain" => {
                    if output_format.is_some() {
                        return Err(CliError::Usage(text::msg::plain_json_exclusive(&"doc")));
                    }
                    output_format = Some(OutputFormat::Plain);
                }
                "--json" => {
                    if output_format.is_some() {
                        return Err(CliError::Usage(text::msg::plain_json_exclusive(&"doc")));
                    }
                    output_format = Some(OutputFormat::Json);
                }
                // Skip the query value token (it follows --type).
                _ if rest
                    .windows(2)
                    .any(|p| matches!(p, [f, v] if f == "--type" && v == tok)) => {}
                flag if flag.starts_with('-') => {
                    return Err(CliError::Usage(text::msg::unknown_flag(
                        &"doc --type",
                        &flag,
                    )));
                }
                _ => {
                    return Err(CliError::Usage(text::msg::doc_type_unexpected_positional()));
                }
            }
        }
        return Ok(DocMode::TypeSearch {
            query,
            format: output_format.unwrap_or_default(),
        });
    }

    let sub = if has_check_examples {
        Sub::CheckExamples
    } else if has_list_flag {
        // Consume any `--list` flag found; the rest are positional/format flags.
        Sub::List
    } else {
        match it.peek().map(|s| s.as_str()) {
            Some("serve") => {
                it.next();
                Sub::Serve
            }
            Some("check") => {
                it.next();
                Sub::Check
            }
            Some("list") => {
                it.next();
                Sub::List
            }
            // A blank positional names nothing; refused rather than read as a
            // project path or a match-everything term.
            Some(first) if first.trim().is_empty() => {
                return Err(query_refused(QueryRefusal::Empty));
            }
            // A `kind:key` term whose prefix is a known kind is a bundle lookup,
            // whatever its key holds (an operator symbol may carry `/`), unless a
            // generate-only flag marks the positional as a project path.
            Some(first)
                if is_qualified(first)
                    && !rest.iter().any(|a| a == "--out" || a == "--write-format") =>
            {
                let key = (*first).to_owned();
                it.next();
                Sub::Lookup(key)
            }
            // A diagnostic code (`IPE-X0000`) or a symbol key (`List.map`) routes
            // to the content index. A diagnostic code always starts uppercase and
            // contains a `-`; a symbol key starts uppercase and contains a `.`
            // followed by a lowercase letter.
            Some(first)
                if !first.starts_with('-')
                    && first.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                    && (first.contains('-') || is_symbol_key(first)) =>
            {
                let key = (*first).to_owned();
                it.next();
                Sub::Lookup(key)
            }
            // A module-path positional is a module API query only when every
            // dot-separated segment satisfies the module-name grammar. A host
            // path never does: `/`, `\` and `:` are not grammar characters, so
            // a Windows drive path (`D:\pkg`) or a separator path can never be
            // read as a module on any platform.
            Some(first) if !first.starts_with('-') && is_module_name(first) => {
                let name = (*first).to_owned();
                it.next();
                Sub::Query(name)
            }
            // An uppercase-leading positional that fails the module grammar is
            // a host path, never a module query. Leave it unconsumed so the
            // flag scan below (`parse_doc_flags`) picks it up as the `generate`
            // project path.
            Some(first)
                if !first.starts_with('-')
                    && first.chars().next().is_some_and(|c| c.is_ascii_uppercase()) =>
            {
                Sub::Generate
            }
            // A lowercase bare word is a content-index lookup key only when no
            // generate-specific flags (`--out`, `--write-format`) appear in the
            // remaining arguments — those flags are unambiguous signals that the
            // word is a project path for the `generate` subcommand.
            //
            // A positional carrying host-path syntax (`/`, `\`, `:`) is never a
            // lookup key regardless of case — `src/x` and `d:\pkg` fall through
            // to the generate arm below exactly like their uppercase cousins.
            Some(first)
                if !first.starts_with('-')
                    && !first.is_empty()
                    && !has_host_path_syntax(first)
                    && !rest.iter().any(|a| a == "--out" || a == "--write-format") =>
            {
                let key = (*first).to_owned();
                it.next();
                Sub::Lookup(key)
            }
            _ => Sub::Generate,
        }
    };

    let mut flags = ParsedFlags::default();
    parse_doc_flags(&mut it, &sub, &mut flags)?;

    let path = PathBuf::from(flags.path.as_deref().unwrap_or(DEFAULT_PATH));
    let format = flags.output_format.unwrap_or_default();
    Ok(match sub {
        Sub::Generate => DocMode::Generate {
            path,
            out: PathBuf::from(flags.out.as_deref().unwrap_or(DEFAULT_OUT)),
            write_format: flags.write_format.unwrap_or(WriteFormat::All),
        },
        Sub::Serve => DocMode::Serve {
            path,
            port: flags.port,
        },
        Sub::Check => DocMode::Check { path },
        Sub::List => DocMode::List { path, format },
        Sub::Query(module) => DocMode::Query {
            module: parsed_term(&module)?,
            format,
        },
        Sub::CheckExamples => DocMode::CheckExamples,
        Sub::Lookup(key) => DocMode::Lookup {
            key: parsed_term(&key)?,
            format,
        },
    })
}

/// The trimmed text of a lookup term proven a [`DocQuery`], the key part of a
/// `kind:key` term proven one too.
///
/// # Errors
/// [`CliError::Usage`] naming the [`QueryRefusal`].
fn parsed_term(raw: &str) -> Result<String, CliError> {
    let query = DocQuery::parse(raw).map_err(query_refused)?;
    if is_qualified(query.text())
        && let Some((_, key)) = crate::doc_bundle::split_qualified(query.text())
    {
        DocQuery::parse(key).map_err(query_refused)?;
    }
    Ok(query.text().to_owned())
}

/// The usage error for a refused `ipe doc` term.
fn query_refused(refusal: QueryRefusal) -> CliError {
    CliError::Usage(match refusal {
        QueryRefusal::Empty => text::msg::doc_query_empty(),
        QueryRefusal::TooLong => text::msg::doc_query_too_long(&MAX_QUERY_CHARS),
        QueryRefusal::ControlChar => text::msg::doc_query_control(),
    })
}

/// Parse the flag portion of `ipe doc`'s argument tail into [`ParsedFlags`].
///
/// Called from [`parse_doc`] after the leading subcommand token has been
/// consumed. Rejects any flag that does not belong to `sub`.
///
/// # Errors
/// [`CliError::Usage`] for an unknown or misplaced flag.
fn parse_doc_flags(
    it: &mut std::iter::Peekable<std::slice::Iter<'_, String>>,
    sub: &Sub,
    flags: &mut ParsedFlags,
) -> Result<(), CliError> {
    while let Some(arg) = it.next() {
        match arg.as_str() {
            // Skip flags already handled by the caller.
            "--list" | "--check-examples" => {}
            "--out" | "--write-format" if !matches!(sub, Sub::Generate) => {
                return Err(CliError::Usage(text::msg::doc_generate_only_flag(
                    &sub_name(sub),
                    &arg,
                )));
            }
            "--port" if !matches!(sub, Sub::Serve) => {
                return Err(CliError::Usage(text::msg::doc_port_serve_only(&sub_name(
                    sub,
                ))));
            }
            "--plain" | "--json" if !matches!(sub, Sub::List | Sub::Query(_) | Sub::Lookup(_)) => {
                return Err(CliError::Usage(text::msg::doc_lookup_only_flag(
                    &sub_name(sub),
                    &arg,
                )));
            }
            "--out" => {
                let value = it.next().cloned().ok_or_else(|| {
                    CliError::Usage(text::msg::flag_needs_value(&"doc", &"--out"))
                })?;
                if flags.out.is_some() {
                    return Err(CliError::Usage(text::msg::flag_repeated(&"doc", &"--out")));
                }
                flags.out = Some(value);
            }
            "--write-format" => {
                let value = it.next().ok_or_else(|| {
                    CliError::Usage(text::msg::flag_needs_value(&"doc", &"--write-format"))
                })?;
                if flags.write_format.is_some() {
                    return Err(CliError::Usage(text::msg::flag_repeated(
                        &"doc",
                        &"--write-format",
                    )));
                }
                flags.write_format = Some(parse_write_format(value)?);
            }
            "--port" => {
                let value = it
                    .next()
                    .ok_or(CliError::Usage(text::msg::doc_serve_port_needs_number()))?;
                if flags.port.is_some() {
                    return Err(CliError::Usage(text::msg::flag_repeated(
                        &"doc serve",
                        &"--port",
                    )));
                }
                flags.port = Some(parse_port(value)?);
            }
            "--plain" => {
                if flags.output_format.is_some() {
                    return Err(CliError::Usage(text::msg::plain_json_exclusive(&"doc")));
                }
                flags.output_format = Some(OutputFormat::Plain);
            }
            "--json" => {
                if flags.output_format.is_some() {
                    return Err(CliError::Usage(text::msg::plain_json_exclusive(&"doc")));
                }
                flags.output_format = Some(OutputFormat::Json);
            }
            flag if flag.starts_with('-') => {
                return Err(CliError::Usage(text::msg::unknown_flag(&"doc", &flag)));
            }
            positional => {
                if matches!(sub, Sub::Query(_) | Sub::Lookup(_)) {
                    return Err(CliError::Usage(text::msg::doc_single_key()));
                }
                if flags.path.is_some() {
                    return Err(CliError::Usage(text::msg::doc_single_path()));
                }
                flags.path = Some(positional.to_owned());
            }
        }
    }
    Ok(())
}

/// The subcommand's name for an error message.
const fn sub_name(sub: &Sub) -> &'static str {
    match sub {
        Sub::Generate => "generate",
        Sub::Serve => "serve",
        Sub::Check => "check",
        Sub::List => "list",
        Sub::Query(_) => "<module>",
        Sub::CheckExamples => "--check-examples",
        Sub::Lookup(_) => "<key>",
    }
}

/// Parse a `--write-format` value into a [`WriteFormat`], rejecting an unknown spelling.
fn parse_write_format(value: &str) -> Result<WriteFormat, CliError> {
    match value {
        "json" => Ok(WriteFormat::Json),
        "markdown" => Ok(WriteFormat::Markdown),
        "html" => Ok(WriteFormat::Html),
        "all" => Ok(WriteFormat::All),
        other => Err(CliError::Usage(text::msg::doc_unknown_write_format(&other))),
    }
}

/// Parse a `--port` value into a `u16`, rejecting a non-numeric or out-of-range
/// value (and `0`, which would silently auto-select — omit `--port` for that).
fn parse_port(value: &str) -> Result<u16, CliError> {
    match value.parse::<u16>() {
        Ok(0) => Err(CliError::Usage(text::msg::port_zero(&"doc serve"))),
        Ok(p) => Ok(p),
        Err(_) => Err(CliError::Usage(text::msg::port_invalid(
            &"doc serve",
            &value,
        ))),
    }
}

// Construct pages for `ipe doc <key>` (CLI path) are sourced from the
// compile-time embedded corpus in `doc_bundle::EMBEDDED_CONSTRUCTS` — the same
// `include_dir!` static that feeds `DocBundle::build`. A new
// `docs/constructs/<name>.md` file is automatically available everywhere; no
// hand-maintained table is required.

/// Return `true` when `s` looks like a member key: it contains a `.` and its last segment starts
/// lowercase — a value of a module, e.g.
///
/// `List.map`, `Ipe.List.map`, `Ipe.Time.unixMillis`. This distinguishes a member lookup from a
/// plain module name (`Ipe.List`, `List`), which is routed to the API query instead.
fn is_symbol_key(s: &str) -> bool {
    s.rsplit_once('.')
        .and_then(|(_, member)| member.chars().next())
        .is_some_and(|c| c.is_ascii_lowercase())
}

/// Return `true` when every dot-separated segment of `s` is a valid module
/// name segment: an ASCII-uppercase first letter, then only ASCII
/// alphanumerics or `_`.
///
/// No separator (`/`, `\`), drive colon (`:`) or other punctuation is a
/// grammar character, so a host path can never satisfy this grammar on any
/// platform — the parse stays pure and host-independent.
fn is_module_name(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').all(|segment| {
            let mut chars = segment.chars();
            chars.next().is_some_and(|c| c.is_ascii_uppercase())
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

/// Return `true` when `s` carries a host-path syntax character — a separator
/// (`/`, `\`) or a drive colon (`:`).
///
/// None of these is a grammar character in a module name or a content-index
/// key, on any platform; a positional that contains one is always a host
/// path, whatever its case. Checked independently of [`is_module_name`] so
/// the exclusion also covers the lowercase content-index arm, which has no
/// case restriction to lean on.
fn has_host_path_syntax(s: &str) -> bool {
    s.contains(['/', '\\', ':'])
}

/// Build the `ipe_docs` index, wiring in the CLI command registry.
///
/// Diagnostics are indexed from the compile-time embedded explain pages (same
/// source as `ipe explain`) — no filesystem lookup required. Language constructs
/// are indexed from the same compile-time embedded corpus (`EMBEDDED_CONSTRUCTS`
/// in `doc_bundle`) that feeds `DocBundle::build`, so `ipe doc <key>` and the
/// HTML site are always in sync. Commands are injected from `help.rs`'s
/// `COMMANDS` registry.
fn build_index() -> Result<Index, CliError> {
    use ipe_docs::IndexBuilder;
    let mut builder = IndexBuilder::new();

    builder
        .add_stdlib()
        .map_err(|e| CliError::Usage(text::msg::doc_stdlib_index_failed(&e)))?;
    // The compiled-source stdlib modules (`Ipe.Time`, …) carry members too, so
    // `ipe doc Ipe.Time.unixMillis` resolves like `ipe doc List.map`.
    builder
        .add_compiled_stdlib()
        .map_err(|e| CliError::Usage(text::msg::doc_stdlib_index_failed(&e)))?;

    // Diagnostics: indexed from the compile-time embedded explain pages.
    for code in ipe_diagnostics::ALL_CODES {
        let text = ipe_diagnostics::explain_page(*code)
            .unwrap_or("")
            .to_owned();
        builder.insert(
            code.as_str().to_owned(),
            ipe_docs::Entry {
                kind: ipe_docs::EntryKind::Diagnostic,
                source_key: code.as_str().to_owned(),
                text,
            },
        );
    }

    // Constructs: sourced from the same embedded corpus as DocBundle::build so
    // `ipe doc <key>` and the HTML site never drift.  Front-matter is stripped
    // for terminal display; the slug/key extraction reuses the bundle's own
    // parsing helpers so there is one code path for both surfaces.
    {
        use crate::doc_bundle::DocKind;
        // Ingest into a temporary map, then harvest parsed entries into the
        // ipe_docs index.  Errors are silently ignored here — the same policy as
        // the previous hand-maintained table: a malformed file is skipped rather
        // than making `ipe doc <key>` fail entirely.
        let mut maps: BTreeMap<DocKind, BTreeMap<String, crate::doc_bundle::DocEntry>> =
            BTreeMap::new();
        let _ = crate::doc_bundle::ingest_embedded_dir(
            &crate::doc_bundle::EMBEDDED_CONSTRUCTS,
            DocKind::Construct,
            &mut maps,
        );
        for entry in maps
            .get(&DocKind::Construct)
            .into_iter()
            .flat_map(|m| m.values())
        {
            builder.insert(
                entry.key.clone(),
                ipe_docs::Entry {
                    kind: ipe_docs::EntryKind::Construct,
                    source_key: entry.key.clone(),
                    // `body` already has front-matter stripped by `parse_markdown_file`.
                    text: entry.body.clone(),
                },
            );
        }
    }

    // Commands: sourced from the COMMANDS registry so the index never drifts.
    let commands: Vec<CommandInfo> = crate::help::documented_command_keys()
        .into_iter()
        .filter_map(|name| {
            crate::help::command_doc_markdown(name).map(|help| CommandInfo { name, help })
        })
        .collect();
    builder.add_commands(&commands);

    // Environment variables: sourced from the ENV_VARS registry (single SSOT).
    builder.add_env_vars();

    Ok(builder.finish())
}

/// Build the unified [`DocBundle`] from all documentation sources.
///
/// Modules and symbols from the stdlib, diagnostic codes from the embedded
/// explain pages, CLI commands from `help.rs`, and the four directory-convention
/// kinds (constructs, idioms, topics, guides) are all indexed together.
///
/// The four directory-convention kinds are always populated from the compile-time
/// embedded corpus (`docs/{constructs,idioms,topics,guide}/` baked into the
/// binary), so `ipe doc serve` and `ipe doc --write-format html` render those
/// sections correctly regardless of the working directory. When `docs_root` also
/// exists on disk, any page whose key is not already in the embedded corpus is
/// merged in as an additive overlay (useful for previewing a new page before it
/// is committed).
fn build_doc_bundle(docs_root: &std::path::Path) -> Result<DocBundle, CliError> {
    // Modules: one entry per stdlib module name.
    let module_sources: Vec<BundleSource> = stdlib_module_names()
        .into_iter()
        .map(|name| BundleSource::titled(name.clone(), name))
        .collect();

    // Symbols: sourced from the ipe_docs index (already built from parsed
    // stdlib source).
    let mut symbol_sources: Vec<BundleSource> = Vec::new();
    {
        use ipe_docs::IndexBuilder;
        let mut builder = IndexBuilder::new();
        let _ = builder.add_stdlib();
        let _ = builder.add_compiled_stdlib();
        let idx = builder.finish();
        for key in idx.keys() {
            if let Some(entry) = idx.resolve(key)
                && matches!(entry.kind, ipe_docs::EntryKind::Symbol)
            {
                symbol_sources.push(BundleSource::with_body(
                    key.to_owned(),
                    key.to_owned(),
                    entry.text.clone(),
                ));
            }
        }
    }

    // Diagnostics: from the embedded explain pages. The title is the page's
    // human heading (never the code repeated), so a list reads
    // `IPE-Xnnnn  <title>` rather than the code twice.
    let diagnostic_sources: Vec<BundleSource> = ipe_diagnostics::ALL_CODES
        .iter()
        .map(|code| {
            let body = ipe_diagnostics::explain_page(*code)
                .unwrap_or("")
                .to_owned();
            let title = explain_title(&body).unwrap_or_else(|| code.as_str().to_owned());
            BundleSource::with_body(code.as_str().to_owned(), title, body)
        })
        .collect();

    // CLI commands: from the COMMANDS registry. The summary is the title (so a
    // list reads `<command>  <summary>` in an aligned table); the body is the
    // command's full help rendered as Markdown from the same registry, so the
    // HTML command page mirrors `ipe <command> --help`.
    let cli_sources: Vec<BundleSource> = crate::help::documented_command_keys()
        .into_iter()
        .filter_map(|name| {
            let summary = crate::help::command_summary(name)?;
            let body = crate::help::command_doc_markdown(name)?;
            Some(BundleSource::with_body(
                name.to_owned(),
                summary.to_owned(),
                body,
            ))
        })
        .collect();

    DocBundle::build(
        docs_root,
        &module_sources,
        &symbol_sources,
        &diagnostic_sources,
        &cli_sources,
    )
    .map_err(|e| CliError::Usage(text::msg::doc_bundle_build_error(&e)))
}

/// `ipe doc kind:key` -- exact scoped bundle lookup.
///
/// Resolves a `kind:key` qualified reference against the unified bundle and
/// renders the matched entry. On a miss, lists the entries of that kind that
/// rank closest to the key, each as the exact term that opens it.
fn run_bundle_lookup(key: &str, format: OutputFormat) -> Result<(), CliError> {
    // Locate the docs root relative to the repo, falling back gracefully when
    // running outside the repo tree (e.g. a user's home directory).
    let docs_root = locate_docs_root();
    let bundle = build_doc_bundle(&docs_root)?;

    match bundle.resolve_qualified(key) {
        Ok(entry) => {
            render_bundle_entry(entry, format);
            Ok(())
        }
        Err(crate::doc_bundle::BundleError::UnknownKind(prefix)) => {
            Err(CliError::Usage(text::msg::doc_unknown_kind(&prefix)))
        }
        Err(crate::doc_bundle::BundleError::UnknownKey { kind, key: k }) => {
            let query = DocQuery::parse(&k).map_err(query_refused)?;
            let ranked = crate::doc_search::rank(bundle.entries_for_kind(kind), &query);
            Err(miss_error(key, &ranked, format))
        }
        Err(e) => Err(CliError::Usage(text::msg::command_refusal(&"doc", &e))),
    }
}

/// `ipe doc <bare>` -- exact lookup, then a ranked miss list across all kinds.
///
/// First tries the existing `ipe_docs` index for exact matches (diagnostic
/// codes, symbol keys, module names), then a project module member, then a
/// unique exact bundle key. Only when all of those miss does the bundle
/// ranking run, so a precise hit never has a list put in front of it.
fn run_doc_lookup_with_fuzzy(key: &str, format: OutputFormat) -> Result<(), CliError> {
    // Try the legacy exact index first.
    let index = build_index()?;
    if let Some(entry) = index.resolve(key) {
        use crate::screen::{Screen, Stream, emit_machine};
        match format {
            OutputFormat::Plain => emit_machine(Stream::Stdout, &render_doc_entry_plain(entry)),
            OutputFormat::Json => emit_machine(Stream::Stdout, &render_doc_entry_json(entry)),
            OutputFormat::Human => {
                let mut screen = Screen::new(Stream::Stdout);
                let body = render_doc_entry_human(entry, screen.palette());
                screen.styled(&body).emit();
            }
        }
        return Ok(());
    }

    // A member of a module the index does not carry (a project module).
    match resolve_member(key) {
        MemberResolution::Found(module, member) => {
            render_member(&module, &member, format);
            return Ok(());
        }
        MemberResolution::Ambiguous(candidates) => {
            return Err(ambiguous_module_error(key, &candidates, format));
        }
        MemberResolution::Miss => {}
    }

    // No exact match: a unique exact key of a kind the index does not carry (a
    // topic, guide, or idiom) opens directly; anything else is a miss that
    // lists the closest entries of every kind.
    let docs_root = locate_docs_root();
    let bundle = build_doc_bundle(&docs_root)?;
    let query = DocQuery::parse(key).map_err(query_refused)?;
    if let Some(only) = crate::doc_search::unique_exact(bundle.all_entries(), &query) {
        render_bundle_entry(only, format);
        return Ok(());
    }
    Err(doc_miss(key, &bundle, format))
}

/// The error for a query that named no entry: [`CliError::DocNotFound`] with the entries of any
/// kind that rank closest to it.
///
/// Under a machine format it is written as the machine error envelope instead of the human frame.
fn doc_miss(query: &str, bundle: &DocBundle, format: OutputFormat) -> CliError {
    match DocQuery::parse(query) {
        Ok(parsed) => miss_error(
            query,
            &crate::doc_search::rank(bundle.all_entries(), &parsed),
            format,
        ),
        Err(refusal) => query_refused(refusal),
    }
}

/// The [`CliError::DocNotFound`] for `shown`, listing `ranked`, each entry as its
/// [`rerun_term`].
///
/// Under a machine format it is written as the machine error envelope instead of the human frame.
fn miss_error(shown: &str, ranked: &Ranked<'_>, format: OutputFormat) -> CliError {
    let modules = stdlib_module_names();
    let err = CliError::DocNotFound {
        miss: DocMiss::new(shown, ranked, |entry| rerun_term(entry, &modules)),
    };
    match format {
        OutputFormat::Human => err,
        OutputFormat::Plain | OutputFormat::Json => {
            crate::driver::emit_machine_error(format, "doc", &err)
        }
    }
}

/// The `ipe doc` argument that opens `entry` exactly.
///
/// A stdlib module named by a key that resolves to it alone, and a symbol
/// whose key the bare-word router sends to the symbol index, are listed bare
/// (`Ipe.List`, `Ipe.List.map`); every other entry is listed `kind:key`, which
/// the bundle resolves exactly whatever the key holds.
fn rerun_term(entry: &DocEntry, stdlib_modules: &[String]) -> String {
    let bare = match entry.kind {
        DocKind::Module => {
            is_module_name(&entry.key)
                && matches!(
                    resolve_stdlib_candidate(&entry.key, stdlib_modules),
                    StdlibCandidate::One(only) if only == entry.key
                )
        }
        DocKind::Symbol => {
            entry
                .key
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_uppercase())
                && is_symbol_key(&entry.key)
                && !has_host_path_syntax(&entry.key)
        }
        DocKind::Diagnostic
        | DocKind::Construct
        | DocKind::Idiom
        | DocKind::Topic
        | DocKind::Guide
        | DocKind::Cli => false,
    };
    if bare {
        entry.key.clone()
    } else {
        format!("{}:{}", entry.kind.prefix(), entry.key)
    }
}

/// One `Module.member` resolution's outcome.
enum MemberResolution {
    Found(ModuleDoc, String),
    /// The module part's short name matched more than one dotted stdlib
    /// module; every match, sorted.
    Ambiguous(Vec<String>),
    Miss,
}

/// The error for a query whose short name matches more than one stdlib
/// module: a typed miss listing every candidate, never a silent pick of the
/// first.
///
/// Under a machine format it is written as the machine error envelope instead of the human frame.
fn ambiguous_module_error(query: &str, candidates: &[String], format: OutputFormat) -> CliError {
    let block = text::TerminalBlock::lines(candidates.iter().map(|c| format!("  {c}")));
    let err = CliError::Usage(text::msg::doc_ambiguous_module(&query, &block));
    match format {
        OutputFormat::Human => err,
        OutputFormat::Plain | OutputFormat::Json => {
            crate::driver::emit_machine_error(format, "doc", &err)
        }
    }
}

/// Resolve `Module.member` to the module's doc and the member's name.
///
/// Matches (`Ipe.Time.unixMillis`, `Main.helper`) when the module exists and
/// exposes a value or type of that name.
fn resolve_member(key: &str) -> MemberResolution {
    let Some((module_name, member)) = key.rsplit_once('.') else {
        return MemberResolution::Miss;
    };
    match find_module_doc(module_name) {
        ModuleLookup::Found(module) => {
            let exposed = module.values.iter().any(|v| v.name == member)
                || module.unions.iter().any(|u| u.name == member);
            if exposed {
                MemberResolution::Found(module, member.to_owned())
            } else {
                MemberResolution::Miss
            }
        }
        ModuleLookup::Ambiguous(candidates) => MemberResolution::Ambiguous(candidates),
        ModuleLookup::Miss => MemberResolution::Miss,
    }
}

/// One module-name resolution's outcome, across project and stdlib.
enum ModuleLookup {
    Found(ModuleDoc),
    /// The stdlib short name matched more than one dotted module; every
    /// match, sorted.
    Ambiguous(Vec<String>),
    Miss,
}

/// Find a module's doc by name: a project module first (it shadows the
/// standard library), then the standard library.
fn find_module_doc(module_name: &str) -> ModuleLookup {
    if let Some(module) = query_project_modules()
        .into_iter()
        .find(|m| m.name == module_name)
    {
        return ModuleLookup::Found(module);
    }
    match query_single_stdlib_module(module_name) {
        StdlibModuleLookup::Found(module) => ModuleLookup::Found(module),
        StdlibModuleLookup::Ambiguous(candidates) => ModuleLookup::Ambiguous(candidates),
        StdlibModuleLookup::Miss => ModuleLookup::Miss,
    }
}

/// Render one member of `module` per `format`: its signature (or type
/// declaration) and its doc comment.
fn render_member(module: &ModuleDoc, member: &str, format: OutputFormat) {
    use crate::screen::{Screen, Stream, Tone, emit_machine};
    let key = format!("{}.{member}", module.name);
    let value = module.values.iter().find(|v| v.name == member);
    let union = module.unions.iter().find(|u| u.name == member);
    let (declaration, comment) = match (value, union) {
        (Some(v), _) => (format!("{} : {}", v.name, v.signature), v.comment.as_str()),
        (None, Some(u)) => (
            format!("type {}{}", u.name, union_params(u.params)),
            u.comment.as_str(),
        ),
        (None, None) => (key.clone(), ""),
    };
    match format {
        OutputFormat::Plain => {
            let mut out = declaration;
            out.push('\n');
            if !comment.is_empty() {
                out.push_str(comment);
                out.push('\n');
            }
            emit_machine(Stream::Stdout, &out);
        }
        OutputFormat::Json => {
            let out = format!(
                "{{\"kind\":\"symbol\",\"key\":{},\"text\":{}}}\n",
                json_string(&key),
                json_string(&format!("{declaration}\n{comment}")),
            );
            emit_machine(Stream::Stdout, &out);
        }
        OutputFormat::Human => {
            let mut screen = Screen::new(Stream::Stdout);
            screen
                .line(Tone::Text, &format!("{key}  [symbol]"))
                .blank()
                .line(Tone::Success, &declaration);
            if !comment.is_empty() {
                screen.blank().line(Tone::Text, comment);
            }
            screen.emit();
        }
    }
}

/// `ipe doc --type "<type expr>"` — search the stdlib API by type signature.
///
/// Builds the full stdlib docs, normalizes each symbol's `signature_ty`, and
/// scores it against the parsed + normalized query. Results are printed ranked
/// (lower score = better), up to 20 hits.
///
/// Fail-closed: an unparseable query exits non-zero with a descriptive message.
fn run_type_search(query: &str, format: OutputFormat) -> Result<(), CliError> {
    use crate::doc_type_search::{
        TypeSearchError, render_type_matches_human, render_type_matches_json, type_search,
    };

    let (docs, _) = build_docs(&PathBuf::from(DEFAULT_PATH))?;
    let hits = type_search(&docs.modules, query, 20).map_err(TypeSearchError::into_cli_error)?;

    let stdout = std::io::stdout();
    match format {
        OutputFormat::Plain | OutputFormat::Human => {
            let text = render_type_matches_human(&hits);
            if text.is_empty() {
                return Err(CliError::Usage(text::msg::doc_type_no_match(&query)));
            }
            if matches!(format, OutputFormat::Human) {
                let p = crate::style::Palette::for_stream(&stdout);
                let header = format!(
                    "{}Type-signature matches for `{}`{}\n\n",
                    p.bold,
                    crate::style::TerminalSafe::sanitize(query),
                    p.reset
                );
                crate::screen::Screen::new(crate::screen::Stream::Stdout)
                    .styled(&format!("{header}{text}"))
                    .emit();
            } else {
                crate::screen::emit_machine(crate::screen::Stream::Stdout, &text);
            }
        }
        OutputFormat::Json => {
            crate::screen::emit_machine(
                crate::screen::Stream::Stdout,
                &format!("{}\n", render_type_matches_json(&hits)),
            );
        }
    }
    Ok(())
}

/// Render a [`crate::doc_bundle::DocEntry`] per the requested output format.
fn render_bundle_entry(entry: &crate::doc_bundle::DocEntry, format: OutputFormat) {
    use crate::screen::{Screen, Stream, emit_machine};
    match format {
        OutputFormat::Plain => {
            let mut out = entry.body.clone();
            if !out.ends_with('\n') {
                out.push('\n');
            }
            emit_machine(Stream::Stdout, &out);
        }
        OutputFormat::Json => {
            let out = format!(
                "{{\"kind\":{},\"key\":{},\"title\":{},\"body\":{}}}\n",
                json_string(entry.kind.prefix()),
                json_string(&entry.key),
                json_string(&entry.title),
                json_string(&entry.body),
            );
            emit_machine(Stream::Stdout, &out);
        }
        OutputFormat::Human => {
            let mut screen = Screen::new(Stream::Stdout);
            let p = screen.palette();
            let mut out = String::new();
            let _ = writeln!(
                out,
                "{}{}{}  {}[{}]{}",
                p.bold, entry.key, p.reset, p.dim, entry.kind, p.reset
            );
            if !entry.body.is_empty() {
                out.push('\n');
                out.push_str(&entry.body);
                if !entry.body.ends_with('\n') {
                    out.push('\n');
                }
            }
            screen.styled(&out).emit();
        }
    }
}

/// Locate the `docs/` directory relative to the binary's own location, falling
/// back to the current directory's `docs/` when a repo layout is not found.
/// Returns a path that may not exist; callers must tolerate an absent root.
fn locate_docs_root() -> std::path::PathBuf {
    // Walk up from cwd looking for a `docs/` that exists.
    let mut dir = std::env::current_dir().unwrap_or_default();
    loop {
        let candidate = dir.join("docs");
        if candidate.is_dir() {
            return candidate;
        }
        match dir.parent() {
            Some(parent) => dir = parent.to_owned(),
            None => break,
        }
    }
    std::path::PathBuf::from("docs")
}

/// Plain (terse) rendering of a documentation entry: signature + example.
fn render_doc_entry_plain(entry: &ipe_docs::Entry) -> String {
    let mut out = entry.text.clone();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// JSON rendering of a documentation entry.
fn render_doc_entry_json(entry: &ipe_docs::Entry) -> String {
    let kind = match entry.kind {
        ipe_docs::EntryKind::Symbol => "symbol",
        ipe_docs::EntryKind::Module => "module",
        ipe_docs::EntryKind::Diagnostic => "diagnostic",
        ipe_docs::EntryKind::Construct => "construct",
        ipe_docs::EntryKind::Command => "command",
        ipe_docs::EntryKind::EnvVar => "env-var",
    };
    format!(
        "{{\"kind\":{},\"key\":{},\"text\":{}}}\n",
        json_string(kind),
        json_string(&entry.source_key),
        json_string(&entry.text),
    )
}

/// Human (rich) rendering of a documentation entry with ANSI colour.
fn render_doc_entry_human(entry: &ipe_docs::Entry, p: &crate::style::Palette) -> String {
    let kind_label = match entry.kind {
        ipe_docs::EntryKind::Symbol => "symbol",
        ipe_docs::EntryKind::Module => "module",
        ipe_docs::EntryKind::Diagnostic => "diagnostic",
        ipe_docs::EntryKind::Construct => "construct",
        ipe_docs::EntryKind::Command => "command",
        ipe_docs::EntryKind::EnvVar => "env-var",
    };
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{}{}{}  {}[{}]{}",
        p.bold, entry.source_key, p.reset, p.dim, kind_label, p.reset
    );
    if !entry.text.is_empty() {
        out.push('\n');
        out.push_str(&entry.text);
        if !entry.text.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

/// Run `ipe doc` for the parsed [`DocMode`].
///
/// # Errors
/// [`CliError::Usage`] for a misuse the parser could not have caught, [`CliError`]
/// wrapping a [`crate::api_surface::DiffError`] when the package cannot be typed,
/// [`CliError::Io`] on a write failure, and [`CliError::Usage`] carrying the
/// coverage report when `check` finds an undocumented binding.
pub fn run_doc(rest: &[String]) -> Result<(), CliError> {
    let mode = parse_doc(rest)?;
    let human = matches!(
        mode,
        DocMode::Lookup {
            format: OutputFormat::Human,
            ..
        } | DocMode::Query {
            format: OutputFormat::Human,
            ..
        }
    );
    match dispatch(mode) {
        Err(CliError::DocNotFound { miss })
            if human && !miss.hits.is_empty() && crate::unsafe_ack::is_interactive() =>
        {
            open_picked(miss)
        }
        outcome => outcome,
    }
}

/// Show a human miss list on a terminal and open the entry the person picks.
///
/// The list and the prompt go to stderr, the answer is read from stdin
/// through [`crate::doc_pick::pick`]; the picked term is dispatched once, never
/// re-prompted, so a pick cannot loop.
///
/// # Errors
/// [`CliError::Usage`] when the prompt ends without a pick, else whatever the
/// picked entry's lookup returns.
fn open_picked(miss: DocMiss) -> Result<(), CliError> {
    let terms: Vec<String> = miss
        .hits
        .iter()
        .map(|hit| hit.term.as_str().to_owned())
        .collect();
    crate::screen::report_error(&CliError::DocNotFound { miss });
    let picked = crate::doc_pick::pick(
        &mut std::io::stdin().lock(),
        &mut std::io::stderr(),
        terms.len(),
    );
    let chosen = match picked {
        Pick::Chosen(at) => terms.get(at),
        Pick::Cancelled | Pick::Exhausted => None,
    };
    match chosen {
        Some(term) => dispatch(parse_doc(std::slice::from_ref(term))?),
        None => Err(CliError::Usage(text::msg::doc_pick_none())),
    }
}

/// Run one parsed [`DocMode`].
fn dispatch(mode: DocMode) -> Result<(), CliError> {
    match mode {
        DocMode::Generate {
            path,
            out,
            write_format,
        } => generate(&path, &out, write_format),
        DocMode::Serve { path, port } => serve(&path, port),
        DocMode::Check { path } => check(&path),
        DocMode::List { path, format } => {
            list_modules(&path, format);
            Ok(())
        }
        DocMode::Query { module, format } => query_module(&module, format),
        DocMode::CheckExamples => check_examples(),
        DocMode::Lookup { key, format } => {
            if is_qualified(&key) {
                run_bundle_lookup(&key, format)
            } else {
                run_doc_lookup_with_fuzzy(&key, format)
            }
        }
        DocMode::TypeSearch { query, format } => run_type_search(&query, format),
    }
}

/// The complete documentation of one package — the in-memory model every
/// rendering (JSON, Markdown) is a pure view over.
#[derive(Debug, PartialEq, Eq)]
pub struct DocsJson {
    /// The schema version this document was produced under.
    pub version: u32,
    /// One record per exposed module, in module-path order.
    pub modules: Vec<ModuleDoc>,
    /// The package's compiler-derived control model + capability set — the SAME
    /// disclosure `ipe audit` surfaces, reused here so a reader sees what a
    /// dependency actually does before adopting it. `None` for a stdlib-only
    /// render outside any project (no package to disclose).
    pub disclosure: Option<PackageDisclosure>,
}

/// The package's compiler-derived control model and capability set, as disclosed
/// to a documentation reader.
///
/// A pure view over the audit's own [`crate::audit::Disclosure`] — the control
/// model is the word `ipe audit` discloses (a closed control model or `"library"`
/// for a package with no runnable entry), and the capabilities are the same
/// inferred whole-tree union. `ipe doc` never re-derives either; it reads the one
/// disclosure the audit does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageDisclosure {
    /// The disclosed control-model word (`tea` / `server` / `direct` / `library`).
    pub control_model: String,
    /// The disclosed capability axes' canonical words, in the audit's order.
    pub capabilities: Vec<String>,
}

/// Which group a documented module belongs to.
///
/// The doc listing presents `Local` modules first, under their own labelled
/// section, so a reader sees their own API before the standard library.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleKind {
    /// A module from the package being documented.
    Local,
    /// A bundled standard-library module.
    Stdlib,
}

/// The stable machine tag a `docs.json` consumer reads to group a module.
const fn module_kind_tag(kind: ModuleKind) -> &'static str {
    match kind {
        ModuleKind::Local => "local",
        ModuleKind::Stdlib => "stdlib",
    }
}

/// One exposed module's documentation: its doc-comment plus its exposed unions
/// and values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDoc {
    /// The dotted module name (`Ipe.String`).
    pub name: String,
    /// Whether this is a project module or a bundled stdlib module.
    pub kind: ModuleKind,
    /// The module's own header doc-comment, empty when it has none.
    pub comment: String,
    /// Exposed union types, in name order.
    pub unions: Vec<UnionDoc>,
    /// Exposed values, in name order.
    pub values: Vec<ValueDoc>,
}

/// One exposed value's documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueDoc {
    /// The value name.
    pub name: String,
    /// Its checker-inferred, α-canonicalised type signature.
    pub signature: String,
    /// The same signature in its resolved [`TyDoc`] form, whose type-constructor
    /// nodes carry the canonicaliser's resolved module + name. Cross-references
    /// are computed from this — never from the flat string — so a link is a real
    /// resolved identity, not a text match.
    pub signature_ty: TyDoc,
    /// Its doc-comment, empty when it has none.
    pub comment: String,
}

/// One exposed union type's documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnionDoc {
    /// The union type name.
    pub name: String,
    /// Its type-parameter arity (`Maybe a` → 1).
    pub params: usize,
    /// Constructor name → argument signatures, in declaration order.
    pub ctors: Vec<CtorDoc>,
    /// The union's doc-comment, empty when it has none.
    pub comment: String,
}

/// One constructor's rendered shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtorDoc {
    /// The constructor name.
    pub name: String,
    /// Its argument signatures, in declaration order.
    pub args: Vec<String>,
    /// Its arguments' resolved type documents, in declaration order (parallel to
    /// [`Self::args`]), for cross-reference linking.
    pub arg_types: Vec<TyDoc>,
}

/// A binding whose doc-comment is missing, reported by [`check`].
#[derive(Debug, PartialEq, Eq)]
struct Undocumented {
    module: String,
    /// The binding name (a value, or a union type name).
    name: String,
}

/// Build the in-memory [`DocsJson`] for the package at `path`, including both
/// project modules and all stdlib modules (compiled-source + kernel-backed).
///
/// Project modules go through one `read_tree` walk + `extract_walked`.
/// Compiled-source stdlib modules go through the same type-checker path.
/// Kernel-qualifier stdlib modules use [`kernel_type_table`] for signatures.
///
/// Modules are listed in name order: stdlib first (alphabetically), then project.
/// The API and the doc comments come from ONE walk, whose root is returned as
/// the [`DocInputs::Tree`] the build read.
fn build_docs(path: &Path) -> Result<(DocsJson, DocInputs), CliError> {
    let walked = read_tree(path).map_err(CliError::from)?;
    let api: PublicApi = extract_walked(&walked).map_err(CliError::from)?;
    let sources = &walked.modules;

    // Collect project modules.
    let mut project_modules: Vec<ModuleDoc> = Vec::with_capacity(api.modules.len());
    for (module_path, module_api) in &api.modules {
        let comments = sources
            .get(module_path)
            .map(|(_, src)| scan_doc_comments(src))
            .unwrap_or_default();
        project_modules.push(module_doc(
            module_path,
            module_api,
            &comments,
            ModuleKind::Local,
        ));
    }
    project_modules.sort_by(|a, b| a.name.cmp(&b.name));

    // Collect stdlib modules (both compiled-source and kernel-backed).
    let mut stdlib = build_stdlib_docs();
    stdlib.sort_by(|a, b| a.name.cmp(&b.name));

    // A project module shadows a stdlib module of the same name — project wins.
    let project_names: BTreeSet<&str> = project_modules.iter().map(|m| m.name.as_str()).collect();
    stdlib.retain(|m| !project_names.contains(m.name.as_str()));

    // Present the user's own modules first, then the standard library.
    let mut modules = project_modules;
    modules.extend(stdlib);

    let docs = DocsJson {
        version: DOCS_JSON_VERSION,
        modules,
        disclosure: package_disclosure(path)?,
    };
    Ok((docs, DocInputs::Tree(walked.root)))
}

/// The package's compiler-derived disclosure (control model + capability set),
/// reusing the SAME [`crate::audit::disclose_package`] the `ipe audit` gate reads
/// — never a second derivation that could disagree with the audit's answer.
///
/// `Ok(None)` only when the project directory carries no `package.ipe`: a bare
/// source tree has no manifest to infer a whole-tree capability set from, so there
/// is genuinely no package to disclose — the honest absence, not a permissive
/// default. Whenever a manifest IS present, the disclosure is derived and any
/// failure propagates, fail-closed exactly as the audit does (a runnable entry
/// whose source cannot be read or parsed is a hard rejection, never `None`).
///
/// # Errors
/// Any [`crate::audit::disclose_package`] failure when a manifest is present —
/// an unreadable/unparseable entry, or a capability-inference error.
fn package_disclosure(path: &Path) -> Result<Option<PackageDisclosure>, CliError> {
    // Distinguish a genuinely manifest-less tree (no package to disclose) from a
    // manifest-bearing package whose disclosure must be derived fail-closed. Only
    // the former is a silent `None`; a present-but-failing manifest propagates.
    if !path.is_dir() || crate::project::manifest_in_dir(path).is_none() {
        return Ok(None);
    }
    let disclosure = crate::audit::disclose_package(path)?;
    Ok(Some(PackageDisclosure {
        control_model: disclosure.control_model_word().to_owned(),
        capabilities: disclosure
            .capabilities()
            .iter()
            .map(|c| c.as_str().to_owned())
            .collect(),
    }))
}

/// Build the in-memory [`DocsJson`] for the package at `path`, project modules only.
///
/// Used by `check` — stdlib modules are exempt from the coverage gate.
fn build_project_docs(path: &Path) -> Result<DocsJson, CliError> {
    let walked = read_tree(path).map_err(CliError::from)?;
    let api: PublicApi = extract_walked(&walked).map_err(CliError::from)?;
    let sources = &walked.modules;

    let mut modules = Vec::with_capacity(api.modules.len());
    for (module_path, module_api) in &api.modules {
        let comments = sources
            .get(module_path)
            .map(|(_, src)| scan_doc_comments(src))
            .unwrap_or_default();
        modules.push(module_doc(
            module_path,
            module_api,
            &comments,
            ModuleKind::Local,
        ));
    }
    // The coverage gate (`ipe doc --check`) reasons over documentation coverage
    // only; the package disclosure is a `generate`/`query` surface, not part of
    // the coverage contract.
    Ok(DocsJson {
        version: DOCS_JSON_VERSION,
        modules,
        disclosure: None,
    })
}

/// Enumerate every stdlib module name (both compiled-source and kernel-qualifier),
/// sorted alphabetically.
fn stdlib_module_names() -> Vec<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();

    // Compiled-source modules (Ipe.Css, Ipe.Test, …).
    for m in ipe_stdlib::COMPILED_STD_MODULES {
        names.insert(m.dotted.to_owned());
    }

    // Documentation-only reserved qualifiers (Ipe.Ffi.Kernel, Ipe.Ffi.Rust).
    for m in ipe_stdlib::DOC_ONLY_MODULES {
        names.insert(m.dotted.to_owned());
    }

    // Kernel-qualifier modules (Ipe.List, Ipe.String, …).
    for (segments, _qualifier) in ipe_canon::STDLIB_MODULE_QUALIFIERS {
        names.insert(segments.join("."));
    }

    // `Ipe.Tea.Terminal` is superseded by `Ipe.Color`; suppress its module
    // pages from the doc site so the reference tree does not expose a retired
    // namespace.  The qualifier entries still exist in the compiler (they must, for
    // backwards import compatibility), but they carry no user-visible doc page.
    names.retain(|n| !n.starts_with("Ipe.Tea.Terminal"));

    names.into_iter().collect()
}

/// Build [`ModuleDoc`]s for every stdlib module.
///
/// Compiled-source modules are type-checked using the same pipeline as project
/// modules (injecting each individually as a minimal package). Kernel-qualifier
/// modules use [`kernel_type_table`] for type signatures; doc-comments are empty
/// (signatures are the contract for kernel-backed stdlib).
fn build_stdlib_docs() -> Vec<ModuleDoc> {
    let mut modules: BTreeMap<String, ModuleDoc> = BTreeMap::new();

    // ── Compiled-source stdlib modules ────────────────────────────────────────
    // Each compiled-source module is type-checked as embedded stdlib (so it may
    // declare the reserved `Ipe.*` namespace); signatures and unions come from the
    // type checker, doc-comments from the embedded source. Every module yields a
    // ModuleDoc — a type-check failure degrades to a doc-comment-only entry rather
    // than being dropped, so every `--list` name is queryable (see the invariant
    // enforced by `stdlib_module_names`, reconciled below).
    //
    // `Ipe.Tea.Terminal` is superseded by `Ipe.Color`; its compiled-source
    // modules are skipped so the doc site does not expose retired namespace pages.
    for csm in ipe_stdlib::COMPILED_STD_MODULES {
        if csm.dotted.starts_with("Ipe.Tea.Terminal") {
            continue;
        }
        let segments: Vec<String> = csm.dotted.split('.').map(str::to_owned).collect();
        modules.insert(
            csm.dotted.to_owned(),
            build_compiled_std_module_doc(&segments, csm.source),
        );
    }

    // ── Documentation-only reserved qualifiers ────────────────────────────────
    // `Ipe.Ffi.Kernel` / `Ipe.Ffi.Rust` are compiler-recognised FFI qualifiers,
    // not importable modules; their embedded source carries doc-comments and
    // signatures for discoverability only. They are documented from the raw
    // source so a body-less signature surfaces its doc + signature line without
    // depending on a type-check the veneer intentionally does not satisfy.
    for dom in ipe_stdlib::DOC_ONLY_MODULES {
        let segments: Vec<String> = dom.dotted.split('.').map(str::to_owned).collect();
        modules.insert(
            dom.dotted.to_owned(),
            build_source_only_module_doc(&segments, dom.source),
        );
    }

    // ── Kernel-qualifier stdlib modules ───────────────────────────────────────
    // Signatures come from kernel_type_table; doc-comments are absent for these
    // compiler-internal modules (signatures are the contract). If the kernel
    // type table cannot be constructed, kernel modules are omitted (names still
    // appear in --list via stdlib_module_names).
    if let Ok(kernel_docs) = build_kernel_module_docs() {
        for (name, doc) in kernel_docs {
            modules.entry(name).or_insert(doc);
        }
    }

    // ── SSOT reconciliation ───────────────────────────────────────────────────
    // `stdlib_module_names` is the single source of truth for which stdlib modules
    // exist — the same set `--list` advertises. Guarantee a queryable ModuleDoc
    // for every one of those names, so a listed-but-unqueryable module (a `--list`
    // entry that 404s on `ipe doc <name>`) is unrepresentable.
    for name in stdlib_module_names() {
        modules
            .entry(name.clone())
            .or_insert_with(|| empty_stdlib_module_doc(&name));
    }

    modules.into_values().collect()
}

/// One stdlib module-name query's outcome, against a candidate set.
///
/// A query matches zero, one, or more than one dotted name under the
/// short/full-name rule — never silently the first of several.
#[derive(Debug)]
enum StdlibCandidate {
    None,
    One(String),
    Ambiguous(Vec<String>),
}

/// Resolve `query` against `candidates` under the stdlib short/full-name rule
/// ([`ipe_docs::stdlib_module_matches`]).
///
/// The single place a stdlib module *name* query is turned into zero, one, or
/// more than one dotted match — every caller (member lookup, direct module
/// query) goes through this, so a key form that resolves for one never
/// silently misses, or silently picks among several, for another.
fn resolve_stdlib_candidate(query: &str, candidates: &[String]) -> StdlibCandidate {
    let matches: Vec<String> = candidates
        .iter()
        .filter(|dotted| ipe_docs::stdlib_module_matches(query, dotted))
        .cloned()
        .collect();
    match matches.as_slice() {
        [] => StdlibCandidate::None,
        [one] => StdlibCandidate::One(one.clone()),
        _ => StdlibCandidate::Ambiguous(matches),
    }
}

/// One `ipe doc <Module>` stdlib lookup's outcome.
enum StdlibModuleLookup {
    Found(ModuleDoc),
    /// `module_name`'s short name matched more than one dotted module; every
    /// match, sorted.
    Ambiguous(Vec<String>),
    Miss,
}

/// Resolve and build the [`ModuleDoc`] for a single stdlib module by name,
/// type-checking only that module rather than the whole compiled-source set.
///
/// `module_name` is resolved to a dotted name via [`resolve_stdlib_candidate`]
/// (the short/full-name rule applied over every stdlib module,
/// [`stdlib_module_names`]) first; a unique match then goes through the same
/// three-way bucket as [`build_stdlib_docs`], stopping at the first match so
/// `ipe doc <Module>` costs one type-check instead of ~130:
///
/// 1. A compiled-source module (`COMPILED_STD_MODULES`) — build only that one
///    (the single expensive per-module type-check), matching what the full pass
///    would have produced for this name.
/// 2. A kernel-qualifier module — the kernel type table is a single shared db, so
///    the full kernel-doc pass already costs one check; take this name's entry.
/// 3. A listed-but-otherwise-undocumentable name — the signature-less fallback,
///    preserving the `--list` == queryable SSOT invariant.
fn query_single_stdlib_module(module_name: &str) -> StdlibModuleLookup {
    let names = stdlib_module_names();
    let dotted = match resolve_stdlib_candidate(module_name, &names) {
        StdlibCandidate::None => return StdlibModuleLookup::Miss,
        StdlibCandidate::Ambiguous(candidates) => return StdlibModuleLookup::Ambiguous(candidates),
        StdlibCandidate::One(dotted) => dotted,
    };

    // 1. Compiled-source: type-check only the matching module.
    for csm in ipe_stdlib::COMPILED_STD_MODULES {
        if csm.dotted == dotted {
            let segments: Vec<String> = csm.dotted.split('.').map(str::to_owned).collect();
            return StdlibModuleLookup::Found(build_compiled_std_module_doc(&segments, csm.source));
        }
    }

    // 2. Kernel-qualifier: the type table is one shared db; take this entry.
    if let Ok(mut kernel_docs) = build_kernel_module_docs()
        && let Some(doc) = kernel_docs.remove(&dotted)
    {
        return StdlibModuleLookup::Found(doc);
    }

    // 3. Listed-name SSOT fallback: a queryable, signature-less entry. `dotted`
    // came from `stdlib_module_names()` itself, so this is always reachable.
    StdlibModuleLookup::Found(empty_stdlib_module_doc(&dotted))
}

/// A signature-less [`ModuleDoc`] carrying only the module name — the last-resort
/// entry for a listed stdlib module the richer paths could not document, so a
/// `--list` name is never unqueryable.
fn empty_stdlib_module_doc(name: &str) -> ModuleDoc {
    ModuleDoc {
        name: name.to_owned(),
        kind: ModuleKind::Stdlib,
        comment: String::new(),
        unions: Vec::new(),
        values: Vec::new(),
    }
}

/// Build a [`ModuleDoc`] for one compiled-source stdlib module.
///
/// Type-checks the embedded source as embedded stdlib (via
/// [`crate::api_surface::extract_stdlib_module`], which grants the reserved-`Ipe.*`
/// declaration a project's injected closure already grants it) to recover full
/// signatures and unions, joining them to the doc-comments scanned from the
/// source. Always yields a [`ModuleDoc`]: if the module cannot be type-checked,
/// the result degrades to the scanned doc-comments over an empty API rather than
/// disappearing, so the module stays queryable and `--list`/query agree.
fn build_compiled_std_module_doc(segments: &[String], source: &str) -> ModuleDoc {
    use crate::api_surface::extract_stdlib_module;

    let comments = scan_doc_comments(source);
    let module_api = extract_stdlib_module(segments, source)
        .ok()
        .and_then(|api| api.modules.get(segments).cloned())
        .unwrap_or_default();
    let segments_vec: Vec<String> = segments.to_vec();
    module_doc(&segments_vec, &module_api, &comments, ModuleKind::Stdlib)
}

/// Build a [`ModuleDoc`] for a documentation-only reserved qualifier
/// (`Ipe.Ffi.Kernel` / `Ipe.Ffi.Rust`) straight from its embedded source.
///
/// These qualifiers are recognised structurally by the compiler, never compiled
/// as importable modules, so there is no type-checked API to read. The
/// module-header doc and each exposed member's `name : Type` signature line +
/// doc-comment are relayed verbatim from the source via
/// [`ipe_docs::stdlib_docs::extract_module_doc`]; the resolved-type field is a
/// placeholder ([`TyDoc::Unit`]) because no cross-reference identity exists for a
/// compiler primitive. Always yields a [`ModuleDoc`] so the qualifier stays
/// queryable and `--list`/query agree.
fn build_source_only_module_doc(segments: &[String], source: &str) -> ModuleDoc {
    let extracted = ipe_docs::stdlib_docs::extract_module_doc(&segments.join("."), source);
    let values = extracted
        .exports
        .into_iter()
        .filter(|e| e.signature.is_some())
        .map(|e| ValueDoc {
            name: e.name,
            signature: e.signature.unwrap_or_default(),
            signature_ty: TyDoc::Unit,
            comment: e.doc.unwrap_or_default(),
        })
        .collect();
    ModuleDoc {
        name: segments.join("."),
        kind: ModuleKind::Stdlib,
        comment: extracted.module_doc.unwrap_or_default(),
        unions: Vec::new(),
        values,
    }
}

/// Build [`ModuleDoc`]s for every kernel-qualifier stdlib module.
///
/// The canonical qualifier table ([`ipe_canon::STDLIB_MODULE_QUALIFIERS`]) maps
/// import path → short qualifier. The kernel type table maps
/// [`ipe_kernels::StdlibKernel`] → Ipê type; each kernel's [`StdlibDecl`] gives
/// the qualifier and member name. These three tables are joined here to produce
/// per-module value lists with checker-inferred type signatures.
fn build_kernel_module_docs() -> Result<BTreeMap<String, ModuleDoc>, CliError> {
    // Build a reverse map from qualifier short name → full dotted module path.
    let qualifier_to_path: BTreeMap<String, String> = ipe_canon::STDLIB_MODULE_QUALIFIERS
        .iter()
        .map(|(segments, qualifier)| ((*qualifier).to_owned(), segments.join(".")))
        .collect();

    // Get the full type table for all kernel functions.
    let mut interner = Interner::new();
    let type_table = kernel_type_table(&mut interner)
        .map_err(|d| CliError::Usage(text::msg::doc_kernel_table_error(&format!("{d:?}"))))?;

    // Group by module path and build ValueDoc for each kernel.
    let mut by_module: BTreeMap<String, Vec<ValueDoc>> = BTreeMap::new();
    for (kernel, ty) in type_table {
        let decl = kernel.decl();
        let Some(module_path) = qualifier_to_path.get(decl.qualifier) else {
            continue;
        };
        let mut namer = VarNamer::new();
        let Ok(ty_doc) = ty_to_doc(&ty, &interner, &mut namer) else {
            continue; // skip kernels whose type fails to render
        };
        let signature = render_ty(&ty_doc);
        by_module
            .entry(module_path.clone())
            .or_default()
            .push(ValueDoc {
                name: decl.name.to_owned(),
                signature,
                signature_ty: ty_doc,
                comment: String::new(),
            });
    }

    // Assemble ModuleDoc for each module, values in name order.
    let mut docs: BTreeMap<String, ModuleDoc> = BTreeMap::new();
    for (module_path, mut values) in by_module {
        values.sort_by(|a, b| a.name.cmp(&b.name));
        docs.insert(
            module_path.clone(),
            ModuleDoc {
                name: module_path,
                kind: ModuleKind::Stdlib,
                comment: String::new(),
                unions: Vec::new(),
                values,
            },
        );
    }
    Ok(docs)
}

/// List all stdlib + project modules, rendered per `format`.
///
/// `--list` output:
/// * Human (default): guttered module names with a header.
/// * `--plain`: one bare module name per line, no framing.
/// * `--json`: `{"modules":["Ipe.List","Ipe.String",…]}`.
fn list_modules(path: &Path, format: OutputFormat) {
    use crate::screen::{Screen, Stream, emit_machine};
    use crate::style::GUTTER;

    // Collect stdlib names.
    let stdlib: Vec<String> = stdlib_module_names();

    // Collect project module names (best-effort; an unresolvable project is skipped
    // so `--list` always succeeds for stdlib).
    let project: Vec<String> = read_tree(path).map_or_else(
        |_| Vec::new(),
        |walked| {
            let mut names: Vec<String> = walked.modules.keys().map(|p| p.join(".")).collect();
            names.sort();
            names
        },
    );

    // A project module shadows a stdlib module of the same name.
    let mut project_names: Vec<String> = project;
    project_names.sort();
    let project_set: BTreeSet<&str> = project_names.iter().map(String::as_str).collect();
    let stdlib_names: Vec<String> = stdlib
        .into_iter()
        .filter(|n| !project_set.contains(n.as_str()))
        .collect();

    // Present the user's own modules first, then the standard library.
    let ordered: Vec<&String> = project_names.iter().chain(stdlib_names.iter()).collect();

    match format {
        OutputFormat::Plain => {
            // One queryable module name per line (project first, then stdlib).
            // Kept flat — every line must resolve on `ipe doc <name>`; the
            // namespace hierarchy is presented in the human listing, the
            // Markdown index, and the HTML nav (which can show pure-prefix
            // headers a plain, machine-readable list must not).
            let mut out = String::new();
            for name in &ordered {
                let _ = writeln!(out, "{name}");
            }
            emit_machine(Stream::Stdout, &out);
        }
        OutputFormat::Json => {
            let names: Vec<&str> = ordered.iter().map(|n| n.as_str()).collect();
            let out = crate::cli_args::json::object(&[(
                "modules",
                crate::cli_args::json::string_array(&names),
            )]);
            emit_machine(Stream::Stdout, &format!("{out}\n"));
        }
        OutputFormat::Human => {
            let mut body = String::new();
            let _ = writeln!(
                body,
                "{GUTTER}{} ({}):\n",
                crate::text::site_project_modules(),
                project_names.len()
            );
            if project_names.is_empty() {
                let _ = writeln!(body, "{GUTTER}  (none)\n");
            } else {
                let proj_refs: Vec<&str> = project_names.iter().map(String::as_str).collect();
                let tree = build_namespace_tree(&proj_refs);
                let mut tree_out = String::new();
                render_plain_tree(&tree, 0, &mut tree_out);
                for line in tree_out.lines() {
                    let _ = writeln!(body, "{GUTTER}  {line}");
                }
                body.push('\n');
            }
            let _ = writeln!(
                body,
                "{GUTTER}{} ({}):\n",
                crate::text::site_standard_library(),
                stdlib_names.len()
            );
            let stdlib_refs: Vec<&str> = stdlib_names.iter().map(String::as_str).collect();
            let tree = build_namespace_tree(&stdlib_refs);
            let mut tree_out = String::new();
            render_plain_tree(&tree, 0, &mut tree_out);
            for line in tree_out.lines() {
                let _ = writeln!(body, "{GUTTER}  {line}");
            }
            // Module names come from project source: sanitise before framing.
            Screen::new(Stream::Stdout)
                .guttered(crate::style::TerminalSafe::sanitize(&body).as_str())
                .emit();
        }
    }
}

/// Collect project [`ModuleDoc`]s from the current directory (best-effort).
///
/// Returns an empty vec when the project cannot be read or typed, so `query`
/// can still serve stdlib modules when no project is present.
fn query_project_modules() -> Vec<ModuleDoc> {
    read_tree(Path::new(DEFAULT_PATH)).map_or_else(
        |_| Vec::new(),
        |walked| {
            let Ok(api) = extract_walked(&walked) else {
                return Vec::new();
            };
            let sources = &walked.modules;
            api.modules
                .iter()
                .map(|(module_path, module_api)| {
                    let comments = sources
                        .get(module_path)
                        .map(|(_, src)| scan_doc_comments(src))
                        .unwrap_or_default();
                    module_doc(module_path, module_api, &comments, ModuleKind::Local)
                })
                .collect()
        },
    )
}

/// Render a single [`ModuleDoc`] in human-readable guttered form.
fn render_module_human(module: &ModuleDoc, index: &AnchorIndex) {
    use crate::style::GUTTER;

    let md = module.comment.as_str();
    let mut body = format!("{GUTTER}{}\n\n", module.name);
    if !md.is_empty() {
        let _ = writeln!(body, "{GUTTER}{md}\n");
    }
    for union in &module.unions {
        let _ = writeln!(
            body,
            "{GUTTER}  type {}{}",
            union.name,
            union_params(union.params)
        );
        if !union.comment.is_empty() {
            let _ = writeln!(body, "{GUTTER}    {}", union.comment);
        }
    }
    for value in &module.values {
        let sig = {
            let pieces = signature_pieces(&value.signature_ty, index);
            let mut s = String::new();
            for p in &pieces {
                match p {
                    SigPiece::Text(t) | SigPiece::Link { text: t, .. } => s.push_str(t),
                }
            }
            s
        };
        let _ = writeln!(body, "{GUTTER}  {} : {}", value.name, sig);
        if !value.comment.is_empty() {
            let _ = writeln!(body, "{GUTTER}    {}", value.comment);
        }
    }
    // Doc comments and names are project source text: sanitise before framing.
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .guttered(crate::style::TerminalSafe::sanitize(&body).as_str())
        .emit();
}

/// Query one module's API and render it per `format`.
///
/// Resolves `module_name` against stdlib + project (project overrides stdlib on
/// a name collision). Errors with a typed message on an unknown module.
fn query_module(module_name: &str, format: OutputFormat) -> Result<(), CliError> {
    // Project wins over stdlib on name collision. Project modules are already a
    // single resolved pass; the stdlib side is resolved lazily so a single-name
    // query type-checks one module, not all ~130 compiled-source modules.
    let project = query_project_modules();
    if let Some(module) = project.into_iter().find(|m| m.name == module_name) {
        render_query_module(&module, format);
        return Ok(());
    }

    match query_single_stdlib_module(module_name) {
        StdlibModuleLookup::Found(module) => {
            render_query_module(&module, format);
            Ok(())
        }
        StdlibModuleLookup::Ambiguous(candidates) => {
            Err(ambiguous_module_error(module_name, &candidates, format))
        }
        // `Module.member` (a type or an uppercase-led value path) or a miss:
        // resolve the member, else suggest the closest entries of any kind.
        StdlibModuleLookup::Miss => match resolve_member(module_name) {
            MemberResolution::Found(owner, member) => {
                render_member(&owner, &member, format);
                Ok(())
            }
            MemberResolution::Ambiguous(candidates) => {
                Err(ambiguous_module_error(module_name, &candidates, format))
            }
            MemberResolution::Miss => {
                let bundle = build_doc_bundle(&locate_docs_root())?;
                Err(doc_miss(module_name, &bundle, format))
            }
        },
    }
}

/// Render a resolved module's API per `format`.
fn render_query_module(module: &ModuleDoc, format: OutputFormat) {
    // Build a single-module DocsJson for the anchor index (cross-reference
    // resolution within this module's own types).
    let docs = DocsJson {
        version: DOCS_JSON_VERSION,
        modules: vec![module.clone()],
        disclosure: None,
    };
    let index = AnchorIndex::build(&docs);

    match format {
        OutputFormat::Plain => {
            // Flush-left: one entry per line, `name : signature`.
            let mut out = String::new();
            for union in &module.unions {
                let _ = writeln!(out, "type {}{}", union.name, union_params(union.params));
            }
            for value in &module.values {
                let _ = writeln!(out, "{} : {}", value.name, value.signature);
            }
            crate::screen::emit_machine(crate::screen::Stream::Stdout, &out);
        }
        OutputFormat::Json => {
            let mut out = String::new();
            render_module_json(&mut out, module, &index);
            out.push('\n');
            crate::screen::emit_machine(crate::screen::Stream::Stdout, &out);
        }
        OutputFormat::Human => {
            render_module_human(module, &index);
        }
    }
}

/// Assemble one [`ModuleDoc`] from its checked API surface and its scanned
/// doc-comments.
fn module_doc(
    module_path: &ModulePath,
    api: &ModuleApi,
    comments: &DocComments,
    kind: ModuleKind,
) -> ModuleDoc {
    let unions = api
        .unions
        .iter()
        .map(|(name, union)| union_doc(name, union, comments))
        .collect();
    let values = api
        .values
        .iter()
        .map(|(name, signature)| ValueDoc {
            name: name.clone(),
            signature: signature.clone(),
            signature_ty: api.value_types.get(name).cloned().unwrap_or(TyDoc::Unit),
            comment: comments.get(name).unwrap_or_default(),
        })
        .collect();
    ModuleDoc {
        name: module_path.join("."),
        kind,
        comment: comments.module.clone(),
        unions,
        values,
    }
}

/// Assemble one [`UnionDoc`] from its checked shape and its scanned comment.
fn union_doc(name: &str, union: &UnionApi, comments: &DocComments) -> UnionDoc {
    let ctors = union
        .ctors
        .iter()
        .map(|(ctor_name, args)| CtorDoc {
            name: ctor_name.clone(),
            args: args.clone(),
            arg_types: union.ctor_types.get(ctor_name).cloned().unwrap_or_default(),
        })
        .collect();
    UnionDoc {
        name: name.to_owned(),
        params: union.params,
        ctors,
        comment: comments.get(name).unwrap_or_default(),
    }
}

/// The doc-comments scanned out of one module's source: the module header's own
/// comment and a per-binding-name map.
#[derive(Debug, Default, PartialEq, Eq)]
struct DocComments {
    /// The doc-comment directly above the `module` header, empty when absent.
    module: String,
    /// Exported name → its doc-comment (`{-| … -}` or `-- |`). A name is a
    /// top-level value or a type; its comment sits directly above it.
    bindings: BTreeMap<String, String>,
}

impl DocComments {
    /// The doc-comment for `name`, or an empty string when it has none.
    fn get(&self, name: &str) -> Option<String> {
        self.bindings.get(name).cloned()
    }
}

/// Read one module's doc-comments through the shared extractor
/// ([`ipe_docs::stdlib_docs::extract_module_doc`]), the one reader of both the
/// `{-| … -}` and the `-- |` forms, so `ipe doc` and the generated reference
/// show the same prose for the same declaration.
///
/// A doc-comment attaches to the declaration directly below it (no blank line
/// between); the module header's comment sits directly above `module`.
fn scan_doc_comments(src: &str) -> DocComments {
    let doc = ipe_docs::stdlib_docs::extract_module_doc("", src);
    DocComments {
        module: doc.module_doc.unwrap_or_default(),
        bindings: doc
            .exports
            .into_iter()
            .filter_map(|export| export.doc.map(|text| (export.name, text)))
            .collect(),
    }
}

/// The set of type constructors this package documents, so a reference in a
/// signature can be resolved to an in-package definition (and only then linked).
///
/// A `(module, type-name)` pair is present exactly when that module exposes that
/// union type. A `TyDoc::Con` whose resolved `(module, name)` is absent — a
/// built-in like `Int`, or a type from another package — is left as plain text,
/// never a dangling link.
struct AnchorIndex {
    types: BTreeSet<(String, String)>,
}

impl AnchorIndex {
    /// Build the index from every module's exposed union types.
    fn build(docs: &DocsJson) -> Self {
        let mut types = BTreeSet::new();
        for module in &docs.modules {
            for union in &module.unions {
                types.insert((module.name.clone(), union.name.clone()));
            }
        }
        Self { types }
    }

    /// The link target for a type constructor resolved to `(module, name)`, or
    /// `None` when it is not documented in this package.
    fn type_ref(&self, module: &str, name: &str) -> Option<TypeRef> {
        if self.types.contains(&(module.to_owned(), name.to_owned())) {
            Some(TypeRef {
                module: module.to_owned(),
                name: name.to_owned(),
            })
        } else {
            None
        }
    }
}

/// A resolved, in-package type reference — the address a cross-reference links
/// to. The anchor is `Module#Name`, identical across json, Markdown, and HTML.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TypeRef {
    module: String,
    name: String,
}

impl TypeRef {
    /// The stable logical anchor `Module#Name`, shared by every rendering — the
    /// address a `docs.json` consumer records.
    fn anchor(&self) -> String {
        format!("{}#{}", self.module, self.name)
    }

    /// The physical link to this entry within a rendered site of extension `ext`
    /// (`html` or `md`): `Module-stem.ext#Name`. Deterministic from the logical
    /// anchor, so json / Markdown / HTML all point at the one entry.
    fn href(&self, ext: &str) -> String {
        format!("{}.{ext}#{}", module_stem(&self.module), self.name)
    }
}

/// The stem of a module's page filename (`Ipe.String` → `Ipe-String`), shared by
/// its `.md` and `.html` pages so an anchor address is the same in both.
fn module_stem(module: &str) -> String {
    module.replace('.', "-")
}

/// The one canonical href for a bundle entry, relative to a page whose distance
/// from the site root is `base` (`""` at the root, `"../"` one level deep).
///
/// This is the single source of truth every link builder shares — the search
/// script, the index pages, and page emission — so a link and the file it points
/// at are computed identically and can never drift (issue #1874, item 9):
///
/// - A **module** page lives at the root as `<Module-stem>.html`; a symbol links
///   to its module page with a `#<symbol>` fragment.
/// - Every other kind lives at `<kind>/<key>.html`.
fn entry_href(kind: crate::doc_bundle::DocKind, key: &str, base: &str) -> String {
    use crate::doc_bundle::DocKind;
    match kind {
        DocKind::Module => format!("{base}{}.html", module_stem(key)),
        DocKind::Symbol => {
            // `Module.symbol` → the module page anchored at the symbol.
            match key.rsplit_once('.') {
                Some((module, sym)) => format!("{base}{}.html#{sym}", module_stem(module)),
                None => format!("{base}{}.html", module_stem(key)),
            }
        }
        _ => format!("{base}{}/{key}.html", kind.prefix()),
    }
}

/// The site-map key (never base-relative) for a bundle entry's generated file —
/// the flat path the serve loop and the on-disk writer store it under. Symbols
/// have no page of their own (they live as anchors on their module page), so
/// this returns `None` for them.
fn entry_page_key(kind: crate::doc_bundle::DocKind, key: &str) -> Option<String> {
    use crate::doc_bundle::DocKind;
    match kind {
        DocKind::Module | DocKind::Symbol => None,
        _ => Some(format!("{}/{key}.html", kind.prefix())),
    }
}

/// One piece of a rendered signature: either plain text, or an in-package type
/// reference to link. A [`TyDoc`] renders to a flat sequence of these, so a
/// renderer emits links (HTML `<a>`, Markdown `[…](…)`) without re-parsing the
/// string.
enum SigPiece {
    /// Literal text (punctuation, arrows, variables, built-in type names).
    Text(String),
    /// An in-package type name that links to its definition.
    Link { text: String, target: TypeRef },
}

/// Render a value's signature [`TyDoc`] into a flat piece sequence, linking every
/// type constructor that resolves to an in-package definition.
fn signature_pieces(ty: &TyDoc, index: &AnchorIndex) -> Vec<SigPiece> {
    let mut pieces = Vec::new();
    push_ty(ty, index, Prec::Top, &mut pieces);
    pieces
}

/// Precedence context for parenthesising, mirroring [`render_ty`]'s own rules so
/// the linked rendering reads identically to the flat string.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Prec {
    /// Top level — no parentheses added.
    Top,
    /// Left of an arrow — a nested arrow is parenthesised.
    FunLhs,
    /// A constructor argument — a nested application or arrow is parenthesised.
    Arg,
}

/// Append literal text to the piece sequence, coalescing with a trailing text
/// piece so links stay whole tokens.
fn push_text(pieces: &mut Vec<SigPiece>, text: &str) {
    if let Some(SigPiece::Text(last)) = pieces.last_mut() {
        last.push_str(text);
    } else {
        pieces.push(SigPiece::Text(text.to_owned()));
    }
}

/// Walk a [`TyDoc`] at the given precedence, emitting text and link pieces.
fn push_ty(ty: &TyDoc, index: &AnchorIndex, prec: Prec, pieces: &mut Vec<SigPiece>) {
    match ty {
        TyDoc::Unit => push_text(pieces, "()"),
        TyDoc::Var(v) => push_text(pieces, v),
        TyDoc::Con { module, name, args } => {
            let parens = prec == Prec::Arg && !args.is_empty();
            if parens {
                push_text(pieces, "(");
            }
            let head = if module.is_empty() {
                name.to_string()
            } else {
                format!("{module}.{name}")
            };
            match index.type_ref(module, name) {
                Some(target) => pieces.push(SigPiece::Link { text: head, target }),
                None => push_text(pieces, &head),
            }
            for arg in args {
                push_text(pieces, " ");
                push_ty(arg, index, Prec::Arg, pieces);
            }
            if parens {
                push_text(pieces, ")");
            }
        }
        TyDoc::Fun(a, b) => {
            let parens = prec != Prec::Top;
            if parens {
                push_text(pieces, "(");
            }
            push_ty(a, index, Prec::FunLhs, pieces);
            push_text(pieces, " -> ");
            push_ty(b, index, Prec::Top, pieces);
            if parens {
                push_text(pieces, ")");
            }
        }
        TyDoc::Tuple(elems) => {
            push_text(pieces, "(");
            for (i, e) in elems.iter().enumerate() {
                if i > 0 {
                    push_text(pieces, ", ");
                }
                push_ty(e, index, Prec::Top, pieces);
            }
            push_text(pieces, ")");
        }
        TyDoc::Record(fields) => {
            if fields.is_empty() {
                push_text(pieces, "{}");
                return;
            }
            push_text(pieces, "{ ");
            for (i, (fname, fty)) in fields.iter().enumerate() {
                if i > 0 {
                    push_text(pieces, ", ");
                }
                push_text(pieces, &format!("{fname} : "));
                push_ty(fty, index, Prec::Top, pieces);
            }
            push_text(pieces, " }");
        }
    }
}

/// The distinct in-package type references a signature resolves to, in
/// first-seen order — the structured cross-references `docs.json` records.
fn signature_references(ty: &TyDoc, index: &AnchorIndex) -> Vec<TypeRef> {
    let mut refs = Vec::new();
    for piece in signature_pieces(ty, index) {
        if let SigPiece::Link { target, .. } = piece
            && !refs.contains(&target)
        {
            refs.push(target);
        }
    }
    refs
}

/// The renderings for one `ipe doc` generate call, split by format subdirectory.
///
/// Returns three maps keyed by bare filename (no subfolder prefix):
/// - `json_files`: the `docs.json` source of truth
/// - `markdown_files`: per-module `.md` pages + the Markdown index
/// - `html_files`: the self-contained HTML site (`index.html`, per-module
///   pages, `style.css`, per-kind index pages)
///
/// The caller writes each map into its matching `<base>/json/`,
/// `<base>/markdown/`, or `<base>/html/` subfolder. Cross-links within each
/// format are relative to that subfolder (e.g. HTML `<a href="Ipe-List.html">`
/// resolves within `html/`; Markdown `[…](Ipe-List.md)` within `markdown/`).
/// The `docs.json` cross-reference anchors are format-neutral logical
/// addresses, identical across all three renderings.
/// Resolve a page-relative href against the directory its page lives in,
/// dropping any `#fragment`, to the flat site-map key it must hit. `..` walks
/// up, `.`/empty segments are ignored.
fn resolve_site_href(page_key: &str, href: &str) -> String {
    let target = href.split('#').next().unwrap_or(href);
    let dir = page_key.rsplit_once('/').map_or("", |(d, _)| d);
    let mut parts: Vec<&str> = Vec::new();
    if !dir.is_empty() {
        parts.extend(dir.split('/'));
    }
    for seg in target.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    parts.join("/")
}

/// Rewrite any relative `<a href="…">…</a>` whose target is not a generated
/// page into a plain `<span class="dead-link">…</span>`.
///
/// Curated Markdown bodies cross-reference source paths (`../adr/*.md`, example
/// sources, bare construct slugs) that the self-contained site does not
/// generate. Rendering those as live anchors would 404; degrading them to
/// styled text keeps the prose readable and the site link-clean (fail-closed:
/// a link the site cannot honour never ships as a dead link). Absolute
/// (`http`/`https`/`mailto`) and pure-`#fragment` hrefs are left untouched.
fn neutralize_dead_links(html: &str, page_key: &str, site: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(pos) = rest.find("<a href=\"") {
        let (before, from_anchor) = rest.split_at(pos);
        let attr_start = pos + "<a href=\"".len();
        let Some(quote_end) = rest.get(attr_start..).and_then(|r| r.find('"')) else {
            // Malformed anchor open: emit the remainder verbatim and stop.
            out.push_str(rest);
            return out;
        };
        let href = rest.get(attr_start..attr_start + quote_end).unwrap_or("");
        let Some(close_tag) = from_anchor.find('>') else {
            out.push_str(rest);
            return out;
        };
        let Some(end_anchor) = from_anchor.find("</a>") else {
            out.push_str(rest);
            return out;
        };
        let inner = from_anchor
            .get(close_tag + 1..end_anchor)
            .unwrap_or_default();
        out.push_str(before);

        let is_absolute = href.is_empty()
            || href.starts_with('#')
            || href.starts_with("http://")
            || href.starts_with("https://")
            || href.starts_with("mailto:");
        let resolves = is_absolute || {
            let target = resolve_site_href(page_key, href);
            target.is_empty() || site.contains_key(&target)
        };
        if resolves {
            out.push_str(from_anchor.get(..end_anchor + "</a>".len()).unwrap_or(""));
        } else {
            let _ = write!(out, "<span class=\"dead-link\">{inner}</span>");
        }
        rest = from_anchor.get(end_anchor + "</a>".len()..).unwrap_or("");
    }
    out.push_str(rest);
    out
}

/// Rewrite dead relative links across every HTML page in a site map in place.
fn neutralize_site_dead_links(site: &mut BTreeMap<String, String>) {
    let keys: Vec<String> = site.keys().cloned().collect();
    let snapshot = site.clone();
    for key in keys {
        if !std::path::Path::new(&key)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("html"))
        {
            continue;
        }
        if let Some(html) = site.get(&key) {
            let fixed = neutralize_dead_links(html, &key, &snapshot);
            site.insert(key, fixed);
        }
    }
}

fn render_site_split(
    docs: &DocsJson,
    bundle: &crate::doc_bundle::DocBundle,
    write_format: WriteFormat,
) -> (
    BTreeMap<String, String>,
    BTreeMap<String, String>,
    BTreeMap<String, String>,
) {
    let index = AnchorIndex::build(docs);
    let mut json_files = BTreeMap::new();
    let mut markdown_files = BTreeMap::new();
    let mut html_files = BTreeMap::new();

    json_files.insert("docs.json".to_owned(), render_json(docs));

    if write_format.wants_markdown() {
        markdown_files.insert("index.md".to_owned(), render_markdown_index(docs));
        for module in &docs.modules {
            markdown_files.insert(
                format!("{}.md", module_stem(&module.name)),
                render_markdown(module, &index),
            );
        }
    }

    if write_format.wants_html() {
        let search_script = build_site_search_script(docs, bundle, "");
        html_files.insert(
            "index.html".to_owned(),
            render_html_index(docs, bundle, &search_script),
        );
        html_files.insert("style.css".to_owned(), STYLE_CSS.to_owned());
        for module in &docs.modules {
            html_files.insert(
                format!("{}.html", module_stem(&module.name)),
                render_html_module(module, &index, &search_script),
            );
        }
        // Per-kind index pages: module/index.html, diagnostic/index.html,
        // cli/index.html, and one page per curated kind.
        let ref_search = build_site_search_script(docs, bundle, "../");
        html_files.insert(
            "module/index.html".to_owned(),
            render_reference_index(docs, &ref_search),
        );
        html_files.insert(
            "diagnostic/index.html".to_owned(),
            render_diagnostic_index(bundle, &ref_search),
        );
        html_files.insert(
            "cli/index.html".to_owned(),
            render_cli_index(bundle, &ref_search),
        );
        for (path, content) in render_curated_kind_indexes(bundle, &ref_search) {
            html_files.insert(path, content);
        }
        for (path, content) in render_entry_pages(bundle, &ref_search) {
            html_files.insert(path, content);
        }
        neutralize_site_dead_links(&mut html_files);
    }

    (json_files, markdown_files, html_files)
}

/// Build the flat file map for the HTTP serve loop (HTML only, no disk writes).
fn render_site_for_serve(
    docs: &DocsJson,
    bundle: &crate::doc_bundle::DocBundle,
) -> BTreeMap<String, String> {
    let index = AnchorIndex::build(docs);
    let search_script = build_site_search_script(docs, bundle, "");
    let ref_search = build_site_search_script(docs, bundle, "../");
    let mut files = BTreeMap::new();
    files.insert(
        "index.html".to_owned(),
        render_html_index(docs, bundle, &search_script),
    );
    files.insert("style.css".to_owned(), STYLE_CSS.to_owned());
    for module in &docs.modules {
        files.insert(
            format!("{}.html", module_stem(&module.name)),
            render_html_module(module, &index, &search_script),
        );
    }
    files.insert(
        "module/index.html".to_owned(),
        render_reference_index(docs, &ref_search),
    );
    files.insert(
        "diagnostic/index.html".to_owned(),
        render_diagnostic_index(bundle, &ref_search),
    );
    files.insert(
        "cli/index.html".to_owned(),
        render_cli_index(bundle, &ref_search),
    );
    for (path, content) in render_curated_kind_indexes(bundle, &ref_search) {
        files.insert(path, content);
    }
    // Per-entry pages: the targets every diagnostic / CLI / curated link points
    // at. Without these the links 404 (issue #1874, item 9).
    for (path, content) in render_entry_pages(bundle, &ref_search) {
        files.insert(path, content);
    }
    neutralize_site_dead_links(&mut files);
    files
}

/// Build the search script with the full entry index for the site.
///
/// `href_base` is the JS-level base prefix for building entry hrefs (`""` for
/// root-level pages, `"../"` for pages one level deep like `module/index.html`).
fn build_site_search_script(
    docs: &DocsJson,
    bundle: &crate::doc_bundle::DocBundle,
    href_base: &str,
) -> String {
    use crate::doc_bundle::DocKind;
    use std::collections::HashSet;
    // The stems that actually have a generated module page. A module/symbol
    // search entry is only included when it resolves to one of these, so a
    // result can never land on a page that was never generated (issue #1874,
    // items 9 and 16 — the short-form symbol duplicates would otherwise point at
    // a non-existent `Short.html`).
    let module_stems: HashSet<String> = docs.modules.iter().map(|m| module_stem(&m.name)).collect();

    // Precompute each entry's href through the one canonical scheme so a search
    // result lands on a generated page — the JS never rebuilds a path.
    let mut entries: Vec<SearchEntry> = Vec::new();
    for e in bundle.all_entries() {
        let target_stem = match e.kind {
            DocKind::Module => Some(module_stem(&e.key)),
            DocKind::Symbol => e
                .key
                .rsplit_once('.')
                .map(|(module, _)| module_stem(module)),
            _ => None,
        };
        // Skip a module/symbol entry whose page was not generated (a short-form
        // duplicate whose stem has no page); keep the fully-qualified form.
        if let Some(stem) = &target_stem
            && !module_stems.contains(stem)
        {
            continue;
        }
        entries.push(SearchEntry {
            kind: e.kind.prefix(),
            key: e.key.clone(),
            title: e.title.clone(),
            href: entry_href(e.kind, &e.key, href_base),
        });
    }
    build_search_script(&entries)
}

/// One searchable entry as embedded in a page's inline index: its kind label,
/// key, title, and its already-resolved href (relative to that page).
struct SearchEntry {
    kind: &'static str,
    key: String,
    title: String,
    href: String,
}

/// Generate `docs.json` and the selected renderings for the package at `path`,
/// writing them under `out/{json,markdown,html}/` subfolders.
///
/// Attempts full project + stdlib documentation. When no project source is
/// reachable at `path` (an empty directory, no `.ipe` modules), falls back to
/// stdlib-only so the command succeeds in any directory, including an empty
/// scratch dir. A project that exists but fails to build surfaces its error
/// rather than collapsing to a stdlib-only site.
///
/// # Errors
/// [`CliError::Io`] on a write failure, plus any real project build error from
/// [`build_docs_or_stdlib`].
fn generate(path: &Path, out: &Path, write_format: WriteFormat) -> Result<(), CliError> {
    crate::style::print_command_header();
    let (docs, inputs) = build_docs_or_stdlib(path)?;
    let docs_root = locate_docs_root();
    let bundle = build_doc_bundle(&docs_root)?;

    let (json_files, markdown_files, html_files) = render_site_split(&docs, &bundle, write_format);

    // The site overwrites same-named files, so it is written only into a
    // directory ipe owns and proven disjoint from the documented package —
    // never over a user's own `doc/`, the package itself, or the tree it read.
    let site = claim_site(path, &inputs, out)?;
    write_format_dir(&site, "json", &json_files)?;
    if write_format.wants_markdown() {
        write_format_dir(&site, "markdown", &markdown_files)?;
    }
    if write_format.wants_html() {
        write_format_dir(&site, "html", &html_files)?;
    }

    // Disclose the package's compiler-derived control model + capability set — the
    // same signal `ipe audit` surfaces, so a reader sees what the package does.
    if let Some(disclosure) = &docs.disclosure {
        let caps = if disclosure.capabilities.is_empty() {
            "none".to_owned()
        } else {
            disclosure.capabilities.join(", ")
        };
        crate::screen::status(
            crate::screen::Stream::Stdout,
            true,
            &crate::style::TerminalSafe::sanitize(&format!(
                "control model: {}; capabilities: {caps}",
                disclosure.control_model,
            )),
        );
    }

    crate::screen::status(
        crate::screen::Stream::Stdout,
        true,
        &crate::style::TerminalSafe::sanitize(&format!(
            "documented {} module{} to {}",
            docs.modules.len(),
            if docs.modules.len() == 1 { "" } else { "s" },
            out.display()
        )),
    );
    Ok(())
}

/// Claim `out` as the site directory for the package at `path`.
///
/// `out` is proven disjoint from the package root, its manifest sources, and
/// the module tree `inputs` names before it is claimed; a package directory
/// without a manifest is its own root.
///
/// # Errors
/// [`CliError::OutputRefused`] when `out` is the package, holds it, overlaps
/// a source tree, or is not ipe's; a manifest parse error.
fn claim_site(
    path: &Path,
    inputs: &DocInputs,
    out: &Path,
) -> Result<crate::output_dir::OwnedDir, CliError> {
    use crate::output_dir::{OutputRoot, ProjectPaths};
    let project = match crate::project::manifest_in_dir(path) {
        Some(manifest) => ProjectPaths::from_manifest(&crate::project::parse_manifest(&manifest)?),
        None if path.is_dir() => ProjectPaths::of_file(path),
        None => ProjectPaths::discover(path)?,
    };
    let project = match inputs {
        DocInputs::Tree(tree) => project.with_sources(tree),
        DocInputs::StdlibOnly => project,
    };
    OutputRoot::at(out, &project)?.claim()
}

/// The project inputs a documentation build read.
#[derive(Debug)]
enum DocInputs {
    /// The module tree walked ([`crate::api_surface::WalkedTree::root`]): a file,
    /// `src/`, or a flat directory.
    Tree(PathBuf),
    /// No project module was read; the site documents the stdlib alone.
    StdlibOnly,
}

/// Write every file in `files` into `<site>/<subdir>/`.
///
/// Each file is an [`crate::output_dir::OwnedPath`], so a symlink planted
/// anywhere in the owned site is refused rather than written through.
///
/// # Errors
/// [`CliError::OutputRefused`] for a symlink or non-plain name on the way;
/// [`CliError::Io`] on any filesystem failure.
fn write_format_dir(
    site: &crate::output_dir::OwnedDir,
    subdir: &str,
    files: &BTreeMap<String, String>,
) -> Result<(), CliError> {
    site.path_to(subdir)?.ensure_dir()?;
    for (name, contents) in files {
        site.path_to(Path::new(subdir).join(name))?
            .write(contents.as_bytes())?;
    }
    Ok(())
}

/// Build project + stdlib docs, falling back to stdlib-only ONLY when no project
/// is reachable at `path`.
///
/// The fallback is reserved for [`DiffError::Empty`] — a directory carrying no
/// `.ipe` modules, where stdlib-only is the correct and complete answer. Every
/// other build failure (an unreadable module, a typecheck error, an open
/// interface) is a real project error the user must see, so it is propagated
/// rather than masked behind a plausible stdlib-only site that silently omits
/// every project module.
///
/// # Errors
/// Any non-empty [`build_docs`] failure: [`CliError::DiscoveryLimitReached`]
/// for a real symlink cycle or a tree deeper than the discovery depth
/// ceiling; [`CliError::Diff`] wrapping [`crate::api_surface::DiffError::Io`]
/// for an unreadable module or source directory; [`CliError::Diff`] wrapping
/// [`crate::api_surface::DiffError::Typecheck`] for a typecheck failure; or
/// [`CliError::Diff`] wrapping [`crate::api_surface::DiffError::OpenInterface`]
/// for an open interface.
fn build_docs_or_stdlib(path: &Path) -> Result<(DocsJson, DocInputs), CliError> {
    build_docs(path).or_else(|err| match err {
        CliError::Diff(crate::api_surface::DiffError::Empty { .. }) => {
            Ok((build_stdlib_only_docs(), DocInputs::StdlibOnly))
        }
        other => Err(other),
    })
}

/// Build a stdlib-only [`DocsJson`] without accessing any project on disk.
///
/// Used when `ipe doc --write-format <fmt>` is invoked outside a project
/// directory. The project extraction pipeline (`extract_tree`/`read_tree`) is
/// not called; only stdlib modules are enumerated.
fn build_stdlib_only_docs() -> DocsJson {
    let mut stdlib = build_stdlib_docs();
    stdlib.sort_by(|a, b| a.name.cmp(&b.name));
    DocsJson {
        version: DOCS_JSON_VERSION,
        modules: stdlib,
        // No project on disk to disclose — a stdlib-only render carries no
        // package control model or capability set.
        disclosure: None,
    }
}

/// Verify every exposed binding in the package at `path` carries a doc-comment.
///
/// Writes nothing; exits non-zero (a [`CliError::DocCoverage`] carrying the
/// report) when any exposed value or union type lacks a doc-comment.
/// Stdlib modules are exempt — their signatures are the contract, doc-comments
/// are optional.
///
/// # Errors
/// As [`build_project_docs`], plus [`CliError::DocCoverage`] listing every
/// undocumented binding when coverage is incomplete.
fn check(path: &Path) -> Result<(), CliError> {
    let docs = build_project_docs(path)?;

    let mut gaps: Vec<Undocumented> = Vec::new();
    let mut exposed = 0usize;
    for module in &docs.modules {
        for value in &module.values {
            exposed += 1;
            if value.comment.is_empty() {
                gaps.push(Undocumented {
                    module: module.name.clone(),
                    name: value.name.clone(),
                });
            }
        }
        for union in &module.unions {
            exposed += 1;
            if union.comment.is_empty() {
                gaps.push(Undocumented {
                    module: module.name.clone(),
                    name: union.name.clone(),
                });
            }
        }
    }

    if gaps.is_empty() {
        crate::screen::Screen::new(crate::screen::Stream::Stdout)
            .line(
                crate::screen::Tone::Text,
                &format!("all {exposed} exposed binding(s) are documented"),
            )
            .emit();
        return Ok(());
    }

    let mut report = format!(
        "{} of {} exposed binding(s) lack a doc-comment:\n",
        gaps.len(),
        exposed
    );
    for gap in &gaps {
        let _ = writeln!(report, "  {}.{}", gap.module, gap.name);
    }
    report.push_str(
        "add a `{-| … -}` doc-comment above each, or hide it from the module's exposing list",
    );
    Err(CliError::DocCoverage(crate::style::TerminalSafe::sanitize(
        &report,
    )))
}

/// One extracted doc-string example awaiting verification.
struct Example {
    /// Human-readable label, e.g. `Ipe.Maybe::withDefault example 1`.
    label: String,
    /// The fenced ` ```ipe ` block body, already stripped of the fence lines.
    body: String,
    /// Expected result lines from `-->` annotations in the body, in order.
    /// Each element is the trimmed right-hand side of a `-->` arrow.
    expected_results: Vec<String>,
}

/// Extract all `{-| … -}` doc-string blocks from an Ipê source text and return
/// every ` ```ipe ` fenced example within them.
///
/// Each returned [`Example`] carries a label (for error reporting), the raw
/// block body, and the `-->` expected-result lines parsed out of the body
/// (for the result-assertion tier).
fn extract_doc_examples(module_name: &str, src: &str) -> Vec<Example> {
    const OPEN: &str = "{-|";
    const CLOSE: &str = "-}";
    const FENCE_OPEN: &str = "```ipe";
    const FENCE_CLOSE: &str = "```";

    let mut examples = Vec::new();
    let mut search_from = 0usize;
    let mut example_idx = 0usize;

    while let Some(open_rel) = src[search_from..].find(OPEN) {
        let block_start = search_from + open_rel + OPEN.len();
        let Some(close_rel) = src[block_start..].find(CLOSE) else {
            break;
        };
        let block_end = block_start + close_rel;
        let block_body = &src[block_start..block_end];

        // Find ` ```ipe ` fences within this doc-string body.
        let mut fence_search = 0usize;
        while let Some(fence_open_rel) = block_body[fence_search..].find(FENCE_OPEN) {
            let after_open = fence_search + fence_open_rel + FENCE_OPEN.len();
            // Skip the rest of the opening fence line.
            let content_start = block_body[after_open..]
                .find('\n')
                .map_or(block_body.len(), |nl| after_open + nl + 1);
            // The rest of the opening fence line is the info string. A `skip`
            // there (e.g. ` ```ipe ipe:skip `) marks a documentation-only example
            // — shown to the reader but exempt from the type-check, for snippets
            // that need context this gate cannot supply (e.g. a cross-module
            // import the synthetic example module does not inject).
            let fence_info = block_body[after_open..content_start].trim();
            // Find the closing fence.
            let Some(close_fence_rel) = block_body[content_start..].find(FENCE_CLOSE) else {
                fence_search = after_open;
                continue;
            };
            let content_end = content_start + close_fence_rel;
            if fence_info.contains("skip") {
                fence_search = content_end + FENCE_CLOSE.len();
                continue;
            }
            let raw_body = block_body[content_start..content_end].trim_end_matches('\n');

            example_idx += 1;
            let label = format!("{module_name} example {example_idx}");

            // Parse `-->` result annotations out of the body lines.
            let mut expected_results: Vec<String> = Vec::new();
            for line in raw_body.lines() {
                if let Some(arrow_pos) = line.find("-->") {
                    let result = line[arrow_pos + 3..].trim();
                    if !result.is_empty() {
                        expected_results.push(result.to_owned());
                    }
                }
            }

            examples.push(Example {
                label,
                body: raw_body.to_owned(),
                expected_results,
            });

            fence_search = content_end + FENCE_CLOSE.len();
        }

        search_from = block_end + CLOSE.len();
    }

    examples
}

/// The dotted module path an `import` line names, if the line is one.
///
/// `import Ipe.Duration as Duration exposing (Duration)` yields `Ipe.Duration`.
/// A line that is not a top-level import returns `None`.
fn import_line_module(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("import ")?;
    Some(rest.split_whitespace().next().unwrap_or(rest))
}

/// The top-level `import …` lines of a module source, verbatim.
///
/// A doc-string example is scoped exactly as the documenting module is: it sees
/// that module's own imports (aliases included), so a qualified name the module
/// imports — `Duration.millis` under `import Ipe.Duration as Duration` — resolves
/// in the example without the example having to restate the import.
fn extract_module_imports(src: &str) -> Vec<String> {
    src.lines()
        .filter(|line| line.starts_with("import "))
        .map(str::to_owned)
        .collect()
}

/// Synthesize a minimal compilable module wrapping `body`.
///
/// If `body` already starts with `module ` it is returned as-is. Otherwise a
/// `module Main exposing (..)` header is prepended. The module that the
/// doc-string belongs to (`source_module`, e.g. `Ipe.Maybe`) is imported with
/// `exposing (..)` so unqualified names from it resolve, and that module's own
/// imports (`module_imports`, e.g. `import Ipe.Duration as Duration`) are
/// injected so an example naming a qualified import of the documenting module
/// resolves exactly as it does inside that module.
///
/// Lines that contain `-->` are treated as expression/result assertions. The
/// expression (the part before `-->`) is assigned to a fresh top-level binding
/// (`docCheckN = <expr>`) so the type-checker can infer its type without
/// needing a `main` entry point.
fn synthesize_module(body: &str, source_module: &str, module_imports: &[String]) -> String {
    if body.trim_start().starts_with("module ") {
        return body.to_owned();
    }

    let mut out = String::from("module Main exposing (..)\n");

    // Track which modules are already imported so no module is imported twice
    // (a duplicate import is itself a type error).
    let mut imported: Vec<&str> = Vec::new();

    // Import the module whose doc-string this example comes from; its
    // unqualified names are in scope in the example.
    if !source_module.is_empty() {
        let short = source_module
            .split('.')
            .next_back()
            .unwrap_or(source_module);
        out.push('\n');
        let _ = writeln!(out, "import {source_module} as {short} exposing (..)");
        imported.push(source_module);
    }

    // Inject the documenting module's own imports, so the example resolves the
    // qualified names that module has in scope (aliases and `exposing` included).
    for import in module_imports {
        if let Some(module) = import_line_module(import)
            && !imported.contains(&module)
        {
            out.push('\n');
            out.push_str(import);
            imported.push(module);
        }
    }

    // Fall back to a fixed set of common imports for a qualified prefix the
    // example uses that the documenting module does not itself import (e.g. a
    // `Ipe.Maybe` example that reaches for `List.map`).
    for (prefix, import) in &[
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
    ] {
        let Some(module_for_prefix) = import_line_module(import) else {
            continue;
        };
        if body.contains(prefix) && !imported.contains(&module_for_prefix) {
            out.push('\n');
            out.push_str(import);
            imported.push(module_for_prefix);
        }
    }

    out.push('\n');

    // Every example body is one or more expressions, each optionally followed
    // by a `-->` result or a `-- ==` explanatory comment. An expression may span
    // several lines (a pipeline, a call with bracketed arguments), so a bare
    // expression cannot be emitted as a top-level line — it needs a binding.
    // Each expression becomes a `docCheckN = <expr>` top-level binding so the
    // type-checker can reach it without a `main` entry point.
    //
    // Grouping: blank lines separate independent expressions. Within a run of
    // non-blank lines, a line carrying an inline `-->` (non-empty left side) is
    // one complete single-line expression; consecutive lines without an inline
    // `-->` accumulate into one multi-line expression, terminated by a blank
    // line, a following inline-`-->` line, or a trailing annotation line (a
    // standalone `-->` result or a `-- ==` comment).
    let mut check_idx = 0usize;
    let mut pending: Vec<&str> = Vec::new();

    let flush = |out: &mut String, check_idx: &mut usize, pending: &mut Vec<&str>| {
        if pending.is_empty() {
            return;
        }
        let expr = pending.join(" ");
        let expr = expr.trim();
        if !expr.is_empty() {
            *check_idx += 1;
            out.push('\n');
            let _ = writeln!(out, "docCheck{check_idx} = {expr}");
        }
        pending.clear();
    };

    for line in body.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() {
            flush(&mut out, &mut check_idx, &mut pending);
            continue;
        }

        // A `-- ==` comment shows an order-unspecified expected result for the
        // preceding expression; it annotates, it does not extend the expression.
        if trimmed.starts_with("-- ") || trimmed == "--" {
            flush(&mut out, &mut check_idx, &mut pending);
            continue;
        }

        // A top-level construct (an example that opens with its own `import`) is
        // emitted verbatim, never folded into an expression binding.
        if trimmed.starts_with("import ")
            || trimmed.starts_with("module ")
            || trimmed.starts_with("type ")
        {
            flush(&mut out, &mut check_idx, &mut pending);
            out.push('\n');
            out.push_str(line);
            continue;
        }

        if let Some(arrow_pos) = line.find("-->") {
            let expr = line[..arrow_pos].trim();
            // A standalone `--> result` closes the accumulated expression; an
            // inline `expr --> result` closes any pending expression, then binds
            // the single-line expression on its own.
            flush(&mut out, &mut check_idx, &mut pending);
            if !expr.is_empty() {
                pending.push(expr);
                flush(&mut out, &mut check_idx, &mut pending);
            }
            continue;
        }

        pending.push(trimmed);
    }
    flush(&mut out, &mut check_idx, &mut pending);

    out.push('\n');
    out
}

/// The `CARGO_TARGET_DIR` an `ipe dev run` child spawned by the doc-example gate
/// should inherit so its build links against the warm shared dependency target.
///
/// Resolution mirrors the E2E harness's fail-safe: an absolute
/// `IPE_ORACLE_SHARED_TARGET` (all CI's e2e/seal jobs export) wins; else an
/// ambient `CARGO_TARGET_DIR` a local lane set; else `None` (inherit unchanged,
/// so a bare local run stays hermetic). A non-absolute shared value fails safe
/// to the ambient value rather than pinning a relative target.
///
/// This translation lives in the doc-gate test path only — production `ipe dev run`
/// never reads `IPE_ORACLE_SHARED_TARGET`; it honours an inherited
/// `CARGO_TARGET_DIR`, which is exactly what this sets on the child.
fn child_shared_target_dir() -> Option<std::ffi::OsString> {
    fn non_empty_absolute(value: &str) -> Option<std::ffi::OsString> {
        let trimmed = value.trim();
        (!trimmed.is_empty() && std::path::Path::new(trimmed).is_absolute())
            .then(|| std::ffi::OsString::from(trimmed))
    }
    if let Some(shared) = ipe_env::var("IPE_ORACLE_SHARED_TARGET")
        .ok()
        .and_then(|raw| non_empty_absolute(&raw))
    {
        return Some(shared);
    }
    ipe_env::var("CARGO_TARGET_DIR").ok().and_then(|raw| {
        let trimmed = raw.trim();
        (!trimmed.is_empty()).then(|| std::ffi::OsString::from(trimmed))
    })
}

/// Run the compiled example at `snippet_path` and assert its output matches the
/// `-->` annotated results (one per line, in order).
///
/// Runs the current binary as `ipe dev run <snippet_path>`, held to
/// [`crate::remote_ingest::SELF_RUN_LIMITS`], and compares stdout against the
/// expected output. Returns `Err(description)` on a mismatch or
/// subprocess failure; `Ok(())` when the output matches.
fn run_example_and_check(
    snippet_path: &Path,
    label: &str,
    expected: &[String],
) -> Result<(), String> {
    use std::process::Command;

    // Locate this binary (we re-invoke ourselves as `ipe dev run`).
    let ipe_bin = std::env::current_exe()
        .map_err(|e| format!("{label}: could not locate ipe binary: {e}"))?;

    let mut cmd = Command::new(&ipe_bin);
    cmd.args(crate::verb::Verb::DEV_RUN.argv())
        .arg(snippet_path);
    // Forward the warm shared target into the `ipe dev run` child's CARGO_TARGET_DIR.
    // CI's e2e/seal jobs export ONLY IPE_ORACLE_SHARED_TARGET, which production
    // `ipe dev run` never reads; without this translation the child cold-builds the
    // whole runtime tree per example. Absent it (a bare local run) the child
    // inherits the ambient env unchanged.
    if let Some(target) = child_shared_target_dir() {
        cmd.env("CARGO_TARGET_DIR", target);
        // THE SEAL: every example emits under the default `ipe-app` name, so
        // sharing ONE warm target risks cargo reusing a prior example's compiled
        // `ipe-app` crate and greening a broken emit. Give each example a UNIQUE
        // package name (honoured by the single-file emit) so its app crate owns
        // its own fingerprint — a genuinely broken emit still fails to build even
        // against the warm target. Only set alongside the shared target, so an
        // ordinary local run keeps the plain `ipe-app` default.
        cmd.env("IPE_EMIT_PACKAGE_NAME", format!("ipe-doc-example-{label}"));
    }
    let out = crate::remote_ingest::run_local(
        cmd,
        crate::remote_ingest::SELF_RUN_LIMITS,
        crate::remote_ingest::LocalSource::SelfRun,
    )
    .map_err(|e| format!("{label}: ipe dev run failed: {e}"))?;

    if !out.status.success() {
        let stderr = out.stderr.to_terminal();
        return Err(format!(
            "{label}: ipe dev run exited non-zero\n       {stderr}"
        ));
    }

    let actual = String::from_utf8_lossy(&out.stdout);
    let actual_lines: Vec<&str> = actual.lines().filter(|l| !l.trim().is_empty()).collect();

    if actual_lines.len() != expected.len() {
        return Err(format!(
            "{label}: expected {} output line(s) but got {}\n       expected: {:?}\n       actual:   {:?}",
            expected.len(),
            actual_lines.len(),
            expected,
            actual_lines,
        ));
    }

    for (i, (exp, got)) in expected.iter().zip(actual_lines.iter()).enumerate() {
        if exp.trim() != got.trim() {
            return Err(format!(
                "{label}: result line {} mismatch\n       expected: {exp}\n       actual:   {got}",
                i + 1
            ));
        }
    }

    Ok(())
}

/// Doc-test gate: extract every fenced ` ```ipe ` example from every
/// `{-| … -}` doc-string across the standard library and type-check each one.
///
/// When `IPE_E2E=1` is set in the environment, examples with `-->` result
/// annotations are also compiled, run, and their printed output asserted.
///
/// # Errors
/// [`CliError::DocExamplesFailed`] when any block fails its expectation.
fn check_examples() -> Result<(), CliError> {
    // Collect all stdlib sources: the kernel-typed modules and the compiled-source ones.
    let all_sources: Vec<(&str, &str)> = crate::stdlib::MODULES
        .iter()
        .map(|m| (m.name, m.source))
        .chain(
            crate::stdlib::COMPILED_STD_MODULES
                .iter()
                .map(|m| (m.dotted, m.source)),
        )
        .collect();

    let mut total = 0usize;
    let mut passed = 0usize;
    let mut failed: Vec<String> = Vec::new();

    // Write examples to a temp dir; RAII cleanup on exit.
    let tmp_dir =
        crate::scratch::ScratchDir::new("ipe-doc-examples").map_err(|e| CliError::Io {
            path: std::path::PathBuf::from("ipe-doc-examples"),
            source: e,
        })?;
    let snippet_leaf = crate::scratch::LeafName::new("Main.ipe").map_err(|e| CliError::Io {
        path: std::path::PathBuf::from("Main.ipe"),
        source: e.into(),
    })?;

    for (module_name, src) in &all_sources {
        let examples = extract_doc_examples(module_name, src);
        let module_imports = extract_module_imports(src);
        for ex in &examples {
            total += 1;
            let module_src = synthesize_module(&ex.body, module_name, &module_imports);

            // Write to a temp file.
            let snippet_path = tmp_dir.child(&snippet_leaf);
            std::fs::write(&snippet_path, &module_src)
                .map_err(|e| crate::io_err(&snippet_path, e))?;

            // Tier 1: type-check the example (always).
            match crate::typecheck_entry_via_graph(&snippet_path) {
                Ok(()) => {
                    crate::screen::chatter(
                        crate::screen::Stream::Stderr,
                        crate::screen::Tone::Success,
                        &format!("ok   {}", ex.label),
                    );
                    passed += 1;
                }
                Err(err) => {
                    crate::screen::chatter(
                        crate::screen::Stream::Stderr,
                        crate::screen::Tone::UserError,
                        &format!("FAIL {}: does not type-check\n     {err}", ex.label),
                    );
                    failed.push(format!("{}: does not type-check", ex.label));
                    // Skip result-checking for examples that don't even type-check.
                    continue;
                }
            }

            // Tier 2: if the example has `-->` annotations AND IPE_E2E=1 is set,
            // run the example and assert its printed output.
            if !ex.expected_results.is_empty()
                && ipe_env::var_os("IPE_E2E").is_some_and(|v| v == "1")
            {
                match run_example_and_check(&snippet_path, &ex.label, &ex.expected_results) {
                    Ok(()) => {}
                    Err(msg) => {
                        crate::screen::chatter(
                            crate::screen::Stream::Stderr,
                            crate::screen::Tone::UserError,
                            &format!("FAIL {msg}"),
                        );
                        failed.push(msg);
                    }
                }
            }
        }
    }

    crate::screen::Screen::new(crate::screen::Stream::Stderr)
        .blank()
        .line(
            crate::screen::Tone::Text,
            &format!("doc-example gate: {passed}/{total} passed"),
        )
        .emit_chatter();

    if failed.is_empty() {
        crate::screen::Screen::new(crate::screen::Stream::Stdout)
            .line(
                crate::screen::Tone::Text,
                &format!("all {total} doc-string example(s) type-check"),
            )
            .emit();
        Ok(())
    } else {
        let mut report = format!(
            "{} of {} doc-string example(s) failed:\n",
            failed.len(),
            total
        );
        for msg in &failed {
            let _ = writeln!(report, "  FAIL: {msg}");
        }
        let _ = write!(
            report,
            "fix each failing example or mark it with ` ```ipe ipe:skip ` to exempt it"
        );
        Err(CliError::DocExamplesFailed(
            crate::style::TerminalSafe::sanitize(&report),
        ))
    }
}

/// Render [`DocsJson`] as JSON.
///
/// A small hand-written serializer (the driver has no `serde` dependency) that
/// emits the versioned, stable schema: `{ "version", "modules": [ … ] }`. The
/// key order is fixed and the whole document is a deterministic function of the
/// model, so a consumer diffing two runs sees only real API changes.
fn render_json(docs: &DocsJson) -> String {
    let index = AnchorIndex::build(docs);
    let mut out = String::new();
    out.push_str("{\n");
    let _ = writeln!(out, "  \"version\": {},", docs.version);
    out.push_str("  \"modules\": [\n");
    for (i, module) in docs.modules.iter().enumerate() {
        render_module_json(&mut out, module, &index);
        out.push_str(if i + 1 < docs.modules.len() {
            ",\n"
        } else {
            "\n"
        });
    }
    out.push_str("  ]");
    if let Some(disclosure) = &docs.disclosure {
        out.push_str(",\n");
        render_disclosure_json(&mut out, disclosure);
    } else {
        out.push('\n');
    }
    out.push_str("}\n");
    out
}

/// Render the package disclosure object — the SAME control-model word and
/// capability vocabulary the `ipe audit` verdict emits, so a consumer reads one
/// disclosure across both surfaces.
fn render_disclosure_json(out: &mut String, disclosure: &PackageDisclosure) {
    out.push_str("  \"disclosure\": {\n");
    let _ = writeln!(
        out,
        "    \"controlModel\": {},",
        json_string(&disclosure.control_model)
    );
    let caps = disclosure
        .capabilities
        .iter()
        .map(|c| json_string(c))
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(out, "    \"capabilities\": [{caps}]");
    out.push_str("  }\n");
}

/// Render one module object into the JSON buffer at a fixed two-space indent.
fn render_module_json(out: &mut String, module: &ModuleDoc, index: &AnchorIndex) {
    out.push_str("    {\n");
    let _ = writeln!(out, "      \"name\": {},", json_string(&module.name));
    let _ = writeln!(
        out,
        "      \"kind\": {},",
        json_string(module_kind_tag(module.kind))
    );
    let _ = writeln!(out, "      \"comment\": {},", json_string(&module.comment));

    out.push_str("      \"unions\": [");
    for (i, union) in module.unions.iter().enumerate() {
        out.push_str(if i == 0 { "\n" } else { ",\n" });
        out.push_str("        {\n");
        let _ = writeln!(out, "          \"name\": {},", json_string(&union.name));
        let _ = writeln!(out, "          \"params\": {},", union.params);
        let _ = writeln!(
            out,
            "          \"comment\": {},",
            json_string(&union.comment)
        );
        out.push_str("          \"constructors\": [");
        for (j, ctor) in union.ctors.iter().enumerate() {
            out.push_str(if j == 0 { "\n" } else { ",\n" });
            out.push_str("            {\n");
            let _ = writeln!(out, "              \"name\": {},", json_string(&ctor.name));
            let args = ctor
                .args
                .iter()
                .map(|a| json_string(a))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(out, "              \"args\": [{args}]");
            out.push_str("            }");
        }
        out.push_str(if union.ctors.is_empty() {
            "]\n"
        } else {
            "\n          ]\n"
        });
        out.push_str("        }");
    }
    out.push_str(if module.unions.is_empty() {
        "],\n"
    } else {
        "\n      ],\n"
    });

    out.push_str("      \"values\": [");
    for (i, value) in module.values.iter().enumerate() {
        out.push_str(if i == 0 { "\n" } else { ",\n" });
        out.push_str("        {\n");
        let _ = writeln!(out, "          \"name\": {},", json_string(&value.name));
        let _ = writeln!(
            out,
            "          \"signature\": {},",
            json_string(&value.signature)
        );
        let _ = writeln!(
            out,
            "          \"comment\": {},",
            json_string(&value.comment)
        );
        // The in-package cross-references this signature resolves to — the
        // structured form a `docs.json` consumer resolves, with the anchor
        // shared by the Markdown and HTML renderings.
        let refs = signature_references(&value.signature_ty, index);
        out.push_str("          \"references\": [");
        for (k, r) in refs.iter().enumerate() {
            out.push_str(if k == 0 { "\n" } else { ",\n" });
            out.push_str("            {\n");
            let _ = writeln!(out, "              \"module\": {},", json_string(&r.module));
            let _ = writeln!(out, "              \"name\": {},", json_string(&r.name));
            let _ = writeln!(
                out,
                "              \"anchor\": {}",
                json_string(&r.anchor())
            );
            out.push_str("            }");
        }
        out.push_str(if refs.is_empty() {
            "]\n"
        } else {
            "\n          ]\n"
        });
        out.push_str("        }");
    }
    out.push_str(if module.values.is_empty() {
        "]\n"
    } else {
        "\n      ]\n"
    });
    out.push_str("    }");
}

/// Encode a string as a JSON string literal via the CLI's one JSON-string SSOT
/// ([`crate::cli_args::json::string`]) so the multi-line `docs.json` and the
/// compact `--json` verdicts escape identically.
fn json_string(s: &str) -> String {
    crate::cli_args::json::string(s)
}

/// The type-parameter suffix a union type displays (`Maybe` at arity 1 → ` a`).
fn union_params(params: usize) -> String {
    if params == 0 {
        return String::new();
    }
    let names: Vec<String> = (0..params)
        .map(|i| ipe_types::letters(u32::try_from(i).unwrap_or(u32::MAX)).to_string())
        .collect();
    format!(" {}", names.join(" "))
}

/// Render a signature's pieces as Markdown: an in-package type is a
/// `[Type](page#anchor)` link, everything else is inline `` `code` ``.
fn markdown_signature(pieces: &[SigPiece]) -> String {
    let mut out = String::new();
    for piece in pieces {
        match piece {
            SigPiece::Text(t) => {
                let _ = write!(out, "`{t}`");
            }
            SigPiece::Link { text, target } => {
                let _ = write!(out, "[`{text}`]({})", target.href("md"));
            }
        }
    }
    out
}

/// Render one module's documentation as Markdown — a pure view over its
/// [`ModuleDoc`], with in-package type references linked via `index`.
fn render_markdown(module: &ModuleDoc, index: &AnchorIndex) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# {}\n", module.name);
    if !module.comment.is_empty() {
        let _ = writeln!(out, "{}\n", module.comment);
    }

    if !module.unions.is_empty() {
        out.push_str("## Types\n\n");
        for union in &module.unions {
            let _ = writeln!(out, "### `{}{}`\n", union.name, union_params(union.params));
            if !union.comment.is_empty() {
                let _ = writeln!(out, "{}\n", union.comment);
            }
            for ctor in &union.ctors {
                if ctor.args.is_empty() {
                    let _ = writeln!(out, "- `{}`", ctor.name);
                } else {
                    let mut line = format!("`{} `", ctor.name);
                    for arg in &ctor.arg_types {
                        line.push_str(&markdown_signature(&signature_pieces(arg, index)));
                        line.push(' ');
                    }
                    let _ = writeln!(out, "- {}", line.trim_end());
                }
            }
            out.push('\n');
        }
    }

    if !module.values.is_empty() {
        out.push_str("## Values\n\n");
        for value in &module.values {
            let sig = markdown_signature(&signature_pieces(&value.signature_ty, index));
            let _ = writeln!(out, "### `{}`\n", value.name);
            let _ = writeln!(out, "`{} :` {}\n", value.name, sig);
            if !value.comment.is_empty() {
                let _ = writeln!(out, "{}\n", value.comment);
            }
        }
    }
    out
}

// ===========================================================================
// Namespace hierarchy — shared by Markdown index, HTML nav, and plain list.
// ===========================================================================

/// A node in the namespace tree built from dotted module names.
///
/// Each node represents one segment (e.g. `Db` within `Ipe.Db`). A node is a
/// *module* when a [`ModuleDoc`] exists at its exact dotted path; it is a
/// *namespace header* when it has children but no module of its own at that
/// exact path. Children are kept in sorted order so every level renders
/// alphabetically.
struct NamespaceNode {
    /// The dotted path to this node (e.g. `Ipe.Db`).
    full_name: String,
    /// Whether a [`ModuleDoc`] exists at this exact path.
    is_module: bool,
    /// Child nodes, sorted alphabetically by their trailing segment.
    children: Vec<Self>,
}

/// Build a namespace tree from a flat, sorted slice of module names.
///
/// Returns the root children (the top-level segments). A pure prefix node
/// that has children but no module of its own at its exact path is marked
/// `is_module = false` and renders as a non-link header.
fn build_namespace_tree(names: &[&str]) -> Vec<NamespaceNode> {
    let mut roots: Vec<NamespaceNode> = Vec::new();
    for name in names {
        insert_into_tree(&mut roots, &name.split('.').collect::<Vec<_>>(), 0);
    }
    roots
}

/// Recursively insert a dotted module name into the tree at `depth`.
fn insert_into_tree(nodes: &mut Vec<NamespaceNode>, segments: &[&str], depth: usize) {
    if depth >= segments.len() {
        return;
    }
    let Some(prefix_segs) = segments.get(..=depth) else {
        return;
    };
    let prefix = prefix_segs.join(".");

    if let Some(node) = nodes.iter_mut().find(|n| n.full_name == prefix) {
        if depth + 1 == segments.len() {
            node.is_module = true;
        } else {
            insert_into_tree(&mut node.children, segments, depth + 1);
        }
    } else {
        let is_module = depth + 1 == segments.len();
        let mut node = NamespaceNode {
            full_name: prefix,
            is_module,
            children: Vec::new(),
        };
        if !is_module {
            insert_into_tree(&mut node.children, segments, depth + 1);
        }
        nodes.push(node);
        nodes.sort_by(|a, b| a.full_name.cmp(&b.full_name));
    }
}

/// Render a namespace tree as indented Markdown lines.
///
/// Modules are links to their `.md` page; pure prefix headers are bold text
/// with no link. Each namespace depth is indented by exactly 2 spaces.
fn render_markdown_tree(nodes: &[NamespaceNode], depth: usize, out: &mut String) {
    let indent = "  ".repeat(depth);
    for node in nodes {
        if node.is_module {
            let stem = module_stem(&node.full_name);
            let _ = writeln!(out, "{indent}- [{name}]({stem}.md)", name = node.full_name);
        } else {
            let _ = writeln!(out, "{indent}- **{}**", node.full_name);
        }
        render_markdown_tree(&node.children, depth + 1, out);
    }
}

/// Render the Markdown index page for the whole doc set.
///
/// Presents project modules under their section first, then the stdlib, each
/// section as its own namespace tree. When only stdlib modules are present the
/// project section is omitted.
fn render_markdown_index(docs: &DocsJson) -> String {
    let mut out = String::from("# API documentation\n\n");

    let project_names: Vec<&str> = docs
        .modules
        .iter()
        .filter(|m| m.kind == ModuleKind::Local)
        .map(|m| m.name.as_str())
        .collect();

    let stdlib_names: Vec<&str> = docs
        .modules
        .iter()
        .filter(|m| m.kind == ModuleKind::Stdlib)
        .map(|m| m.name.as_str())
        .collect();

    if !project_names.is_empty() {
        let _ = writeln!(out, "## {}\n", crate::text::site_project_modules());
        let tree = build_namespace_tree(&project_names);
        render_markdown_tree(&tree, 0, &mut out);
        out.push('\n');
    }

    if !stdlib_names.is_empty() {
        let _ = writeln!(out, "## {}\n", crate::text::site_standard_library());
        let tree = build_namespace_tree(&stdlib_names);
        render_markdown_tree(&tree, 0, &mut out);
    }

    out
}

/// Render a namespace tree into a string with 2-space indent per depth.
///
/// Module nodes emit their full dotted name; pure prefix header nodes emit
/// their full dotted name followed by `/` to indicate they are a namespace
/// without a module at that exact path.
fn render_plain_tree(nodes: &[NamespaceNode], depth: usize, out: &mut String) {
    let indent = "  ".repeat(depth);
    for node in nodes {
        if node.is_module {
            let _ = writeln!(out, "{indent}{}", node.full_name);
        } else {
            let _ = writeln!(out, "{indent}{}/", node.full_name);
        }
        render_plain_tree(&node.children, depth + 1, out);
    }
}

// ===========================================================================
// HTML site — a self-contained static rendering over the same `DocsJson` model.
// ===========================================================================

/// The bundled stylesheet the HTML site links, written once beside the pages so
/// the site is self-contained and opens over `file://` with no network fetch.
const STYLE_CSS: &str = "\
/* Palette: dark by default, following the system preference; the light set
   applies under a light system preference or an explicit [data-theme]. */
:root {
  color-scheme: light dark;
  --bg: #1e232b;
  --surface: #262c36;
  --fg: #e6e9ee;
  --fg-body: #cdd3db;
  --muted: #9aa2ad;
  --accent: #f2e29a;
  --accent-strong: #f7ecb0;
  --border: #3a4150;
  --inline-bg: #2c333f;
  --code-kw: #d6a2ff; --code-ty: #8fd3e8; --code-tv: #b8c0cc; --code-fn: #9ec1ff;
  --code-kn: #7fd0ff; --code-ct: #ffbe7a; --code-va: #d7dbe0; --code-mo: #b7a6ff;
  --code-op: #cdd3db; --code-st: #9be3a6; --code-nm: #ffb28a; --code-cm: #8b93a0;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #ffffff; --surface: #f4f5f7; --fg: #1c2128; --fg-body: #2f3641;
    --muted: #616873; --accent: #8a6d00; --accent-strong: #6f5700;
    --border: #d7dbe0; --inline-bg: #eceef1;
    --code-kw: #7c3aed; --code-ty: #0e7490; --code-tv: #6b7280; --code-fn: #1d4ed8;
    --code-kn: #0369a1; --code-ct: #b45309; --code-va: #374151; --code-mo: #4338ca;
    --code-op: #374151; --code-st: #166534; --code-nm: #9a3412; --code-cm: #6b7280;
  }
}
:root[data-theme=light] {
  --bg: #ffffff; --surface: #f4f5f7; --fg: #1c2128; --fg-body: #2f3641;
  --muted: #616873; --accent: #8a6d00; --accent-strong: #6f5700;
  --border: #d7dbe0; --inline-bg: #eceef1;
  --code-kw: #7c3aed; --code-ty: #0e7490; --code-tv: #6b7280; --code-fn: #1d4ed8;
  --code-kn: #0369a1; --code-ct: #b45309; --code-va: #374151; --code-mo: #4338ca;
  --code-op: #374151; --code-st: #166534; --code-nm: #9a3412; --code-cm: #6b7280;
}
:root[data-theme=dark] {
  --bg: #1e232b; --surface: #262c36; --fg: #e6e9ee; --fg-body: #cdd3db;
  --muted: #9aa2ad; --accent: #f2e29a; --accent-strong: #f7ecb0;
  --border: #3a4150; --inline-bg: #2c333f;
  --code-kw: #d6a2ff; --code-ty: #8fd3e8; --code-tv: #b8c0cc; --code-fn: #9ec1ff;
  --code-kn: #7fd0ff; --code-ct: #ffbe7a; --code-va: #d7dbe0; --code-mo: #b7a6ff;
  --code-op: #cdd3db; --code-st: #9be3a6; --code-nm: #ffb28a; --code-cm: #8b93a0;
}
*, *::before, *::after { box-sizing: border-box; }
body {
  font: 16px/1.6 system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
  margin: 0; padding: 0; max-width: none;
  background: var(--bg); color: var(--fg);
}
.page-body { max-width: 60rem; margin-inline: auto; padding: 1.5rem 2rem; }
h1 { font-size: 1.6rem; color: var(--accent); }
h2 { font-size: 1.2rem; margin-top: 2rem; color: var(--accent); }
h3 { font-size: 1.05rem; margin-top: 1.5rem; color: var(--accent); }
h4, h5, h6 { font-size: 1rem; margin-top: 1.2rem; color: var(--fg); }
table.doc-table {
  border-collapse: collapse; margin: 1rem 0; width: 100%;
  font-size: 0.9rem;
}
table.doc-table th, table.doc-table td {
  border: 1px solid var(--border); padding: 0.4rem 0.7rem; text-align: left;
  vertical-align: top;
}
table.doc-table th { background: var(--surface); color: var(--fg); }
.dead-link { color: inherit; }
a { color: var(--accent); text-decoration: none; }
a:hover, a:focus { color: var(--accent-strong); text-decoration: underline; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.skip-link {
  position: absolute; left: -999px; top: 0; z-index: 200;
  background: var(--surface); color: var(--fg); padding: 0.5rem 0.9rem;
  border: 1px solid var(--border); border-radius: 0 0 6px 0;
}
.skip-link:focus { left: 0; }
nav.site-header {
  background: var(--surface); border-bottom: 1px solid var(--border);
  padding: 0.6rem 1.5rem; display: flex; align-items: center; gap: 1.2rem;
  flex-wrap: wrap; position: sticky; top: 0; z-index: 10;
}
nav.site-header .site-title {
  font-weight: 700; color: var(--accent-strong); font-size: 1rem;
  text-decoration: none; margin-right: 0.4rem;
}
nav.site-header .site-title .title-short { display: none; }
.nav-links { display: contents; }
nav.site-header a { color: var(--fg); font-size: 0.9rem; }
nav.site-header a:hover, nav.site-header a:focus { color: var(--accent-strong); }
nav.site-header a.active { color: var(--accent); font-weight: 600; }
nav.site-header .sep {
  color: var(--border); font-size: 1.2rem; line-height: 1;
  user-select: none;
}
nav.site-header .search-wrap { margin-left: auto; position: relative; }
nav.site-header input.nav-search {
  width: 14rem; padding: 0.25rem 0.6rem; font-size: 0.9rem;
  background: var(--bg); color: var(--fg);
  border: 1px solid var(--border); border-radius: 4px;
}
nav.site-header input.nav-search:focus { outline: 2px solid var(--accent); }
.theme-toggle, .nav-toggle {
  background: var(--bg); color: var(--fg); border: 1px solid var(--border);
  border-radius: 4px; padding: 0.2rem 0.5rem; font-size: 1rem; cursor: pointer;
  line-height: 1.2;
}
.theme-toggle:hover, .nav-toggle:hover { color: var(--accent-strong); }
.theme-toggle .theme-icon-light { display: none; }
:root[data-theme=light] .theme-toggle .theme-icon-light { display: inline; }
:root[data-theme=light] .theme-toggle .theme-icon-dark { display: none; }
@media (prefers-color-scheme: light) {
  :root:not([data-theme]) .theme-toggle .theme-icon-light { display: inline; }
  :root:not([data-theme]) .theme-toggle .theme-icon-dark { display: none; }
}
.nav-toggle { display: none; }
.nav-toggle .nav-toggle-close { display: none; }
.search-results {
  position: absolute; top: calc(100% + 4px); right: 0; width: 20rem;
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 6px; list-style: none; margin: 0; padding: 0.25rem 0;
  z-index: 100; display: none; max-height: 18rem; overflow-y: auto;
}
.search-results li a {
  display: block; padding: 0.3rem 0.8rem; font-size: 0.85rem;
  color: var(--fg);
}
.search-results li a:hover, .search-results li.active a {
  background: var(--bg); color: var(--accent-strong);
}
.search-results li a .sr-kind { color: var(--muted); font-size: 0.75rem; margin-left: 0.4rem; }
nav.crumb { margin-bottom: 1.5rem; font-size: 0.9rem; }
input.filter {
  width: 100%; box-sizing: border-box; margin: 0.5rem 0 1.5rem;
  padding: 0.5rem 0.7rem; font-size: 1rem;
  background: var(--surface); color: var(--fg);
  border: 1px solid var(--border); border-radius: 6px;
}
input.filter:focus { outline: 2px solid var(--accent); outline-offset: 1px; }
section.group { margin-top: 1.5rem; }
ul.modules {
  list-style: none; padding: 0; margin: 0.5rem 0 0;
  columns: 3 14rem; column-gap: 2rem;
}
/* Root modules breathe; a parent and its children read as one tight block
   (issue #1874, item 15). */
ul.modules > li { margin: 0.55rem 0; break-inside: avoid; }
ul.modules ul { padding-left: 1.1rem; margin-top: 0.1rem; }
ul.modules ul li { margin: 0.12rem 0; }
section.entry { border-top: 1px solid var(--border); padding-top: 0.5rem; margin-top: 1.5rem; }
section.entry h3 { margin: 0 0 0.3rem; font-size: 1.05rem; color: var(--accent); }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
/* Inline code / symbols sit in a rounded-border rectangle for emphasis
   (issue #1874, item 11). */
p.comment code, li code, .entry-code code, code.inline {
  background: var(--inline-bg); border: 1px solid var(--border);
  border-radius: 4px; padding: 0.05em 0.35em; font-size: 0.88em;
}
pre.sig {
  background: var(--surface); padding: 0.4rem 0.6rem;
  border-radius: 4px; overflow-x: auto; border: 1px solid var(--border);
}
/* Readable body prose (issue #1874, item 11) — not the low-contrast muted grey. */
p.comment { margin: 0.5rem 0 0; color: var(--fg-body); }
ul.doc-list { margin: 0.5rem 0 0; padding-left: 1.4rem; color: var(--fg-body); }
ul.doc-list li { margin: 0.2rem 0; }
pre.doc-code {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 4px; padding: 0.6rem 0.8rem; overflow-x: auto;
  margin: 0.6rem 0 0; color: var(--fg);
}
pre.doc-code code { background: none; padding: 0; border: 0; }
/* Non-clickable namespace headers: dimmed grey, NOT italic (issue #1874, item 14). */
span.ns-header { color: var(--muted); font-style: normal; }
section.kind-group { margin-bottom: 2.5rem; }
section.kind-group h2 { margin-bottom: 0.6rem; }
ul.curated-entries {
  list-style: none; padding: 0; margin: 0;
}
ul.curated-entries li { margin: 0.6rem 0; }
ul.curated-entries .entry-title { font-weight: 600; }
ul.curated-entries .entry-summary { color: var(--muted); font-size: 0.9rem; margin-left: 0.5rem; }
ul.index-entries {
  list-style: none; padding: 0; margin: 0.4rem 0;
}
ul.index-entries li { margin: 0.4rem 0; }
ul.index-entries .entry-key { color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.85rem; margin-left: 0.5rem; }
/* Aligned two-column table for the Diagnostics and CLI lists (items 5 and 7):
   the code/command in a fixed first column, the title in the next. */
ul.index-table li {
  display: grid; grid-template-columns: minmax(10rem, max-content) 1fr;
  gap: 0.75rem; align-items: baseline;
}
ul.index-table .entry-code {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  color: var(--accent);
}
ul.index-table .entry-title { color: var(--fg-body); font-weight: 400; }
p.entry-code { margin: 0.2rem 0 1rem; color: var(--muted); }
/* Syntax-highlight token classes, shared with the docs highlighter. */
.doc-code .kw, .sig .kw { color: var(--code-kw); font-weight: 600; }
.doc-code .ty, .sig .ty { color: var(--code-ty); }
.doc-code .tv, .sig .tv { color: var(--code-tv); }
.doc-code .fn, .sig .fn { color: var(--code-fn); }
.doc-code .kn, .sig .kn { color: var(--code-kn); font-weight: 500; }
.doc-code .ct, .sig .ct { color: var(--code-ct); }
.doc-code .va, .sig .va { color: var(--code-va); }
.doc-code .mo, .sig .mo { color: var(--code-mo); }
.doc-code .op, .sig .op { color: var(--code-op); }
.doc-code .st, .sig .st { color: var(--code-st); }
.doc-code .nm, .sig .nm { color: var(--code-nm); }
.doc-code .cm, .sig .cm { color: var(--code-cm); font-style: italic; }
/* Floating round scroll-to-top button (issue #1874, item 17). */
.scroll-top {
  position: fixed; bottom: 1.5rem; right: 1.5rem; width: 2.75rem; height: 2.75rem;
  border-radius: 50%; border: 1px solid var(--border); background: var(--surface);
  color: var(--accent); font-size: 1.2rem; cursor: pointer; display: none;
  align-items: center; justify-content: center; z-index: 50;
  box-shadow: 0 2px 8px rgba(0,0,0,0.25);
}
.scroll-top.visible { display: flex; }
.scroll-top:hover { color: var(--accent-strong); }
@media (max-width: 48rem) {
  ul.modules { columns: 1; }
  nav.site-header { gap: 0.6rem; }
  nav.site-header .site-title .title-full { display: none; }
  nav.site-header .site-title .title-short { display: inline; }
  .nav-toggle { display: inline-block; margin-left: auto; order: 3; }
  nav.site-header .search-wrap { margin-left: 0; }
  .nav-links {
    display: none; order: 4; flex-basis: 100%;
    flex-direction: column; align-items: flex-start; gap: 0.6rem;
    margin-top: 0.6rem; padding-top: 0.6rem; border-top: 1px solid var(--border);
  }
  .nav-links.open { display: flex; }
  .nav-links .sep { display: none; }
  .nav-links .search-wrap { width: 100%; }
  .nav-links input.nav-search { width: 100%; }
  .search-results { width: 100%; }
  .nav-toggle[aria-expanded=true] .nav-toggle-open { display: none; }
  .nav-toggle[aria-expanded=true] .nav-toggle-close { display: inline; }
  ul.index-table li { grid-template-columns: 1fr; gap: 0.1rem; }
}
@media (prefers-reduced-motion: reduce) { html { scroll-behavior: auto; } }
";

/// The inline filter script bundled into the module-list index page.
///
/// Hides any module list item whose lowercased `data-name` does not contain
/// the (lowercased) query, and collapses a section that ends up with no
/// visible module. No external dependency.
const FILTER_SCRIPT: &str = "\
<script>
(function () {
  var box = document.getElementById('filter');
  if (!box) return;
  var items = Array.prototype.slice.call(document.querySelectorAll('li.module'));
  var groups = Array.prototype.slice.call(document.querySelectorAll('section.group'));
  box.addEventListener('input', function () {
    var q = box.value.trim().toLowerCase();
    items.forEach(function (li) {
      var name = li.getAttribute('data-name') || '';
      li.hidden = q !== '' && name.indexOf(q) === -1;
    });
    groups.forEach(function (sec) {
      var any = sec.querySelectorAll('li.module:not([hidden])').length > 0;
      sec.hidden = !any;
    });
  });
})();
</script>
";

/// The inline search script embedded in every HTML page.
///
/// Reads the `ENTRY_INDEX` JSON variable (embedded per-page) and does
/// client-side substring filtering against key and title. Selecting a result
/// navigates to that entry's page. Degrades gracefully when JS is off: the
/// header links still work, the search box is simply non-functional.
const SEARCH_SCRIPT_TEMPLATE: &str = "\
<script>
(function () {
  var INDEX = ENTRY_INDEX_PLACEHOLDER;
  var box = document.getElementById('nav-search');
  var list = document.getElementById('search-results');
  if (!box || !list) return;
  var active = -1;
  function esc(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }
  function setExpanded(on) { box.setAttribute('aria-expanded', on ? 'true' : 'false'); }
  function show(entries) {
    list.innerHTML = '';
    active = -1;
    entries.slice(0, 12).forEach(function (e) {
      var li = document.createElement('li');
      li.setAttribute('role', 'option');
      var a = document.createElement('a');
      a.href = e.href;
      a.setAttribute('tabindex', '-1');
      a.innerHTML = '<span class=\"sr-title\">' + esc(e.title) + '</span>'
        + '<span class=\"sr-kind\">' + esc(e.kind) + '</span>';
      li.appendChild(a);
      list.appendChild(li);
    });
    var any = entries.length > 0;
    list.style.display = any ? 'block' : 'none';
    setExpanded(any);
  }
  function rank(q) {
    var ql = q.toLowerCase();
    var scored = INDEX.map(function (e) {
      var k = e.key.toLowerCase(), t = e.title.toLowerCase();
      var s = 0;
      if (k === ql || t === ql) s = 1000;
      else if (k.indexOf(ql) === 0) s = 800;
      else if (t.indexOf(ql) === 0) s = 600;
      else if (k.indexOf(ql) !== -1) s = 400;
      else if (t.indexOf(ql) !== -1) s = 200;
      return { e: e, s: s };
    }).filter(function (x) { return x.s > 0; });
    scored.sort(function (a, b) { return b.s - a.s; });
    return scored.map(function (x) { return x.e; });
  }
  function highlight(items) {
    for (var i = 0; i < items.length; i++) {
      items[i].setAttribute('aria-selected', i === active ? 'true' : 'false');
      items[i].className = i === active ? 'active' : '';
    }
  }
  box.addEventListener('input', function () {
    var q = box.value.trim();
    if (q.length < 1) { list.style.display = 'none'; setExpanded(false); return; }
    show(rank(q));
  });
  box.addEventListener('keydown', function (ev) {
    var items = list.querySelectorAll('li');
    if (!items.length) return;
    if (ev.key === 'ArrowDown') { ev.preventDefault(); active = Math.min(active + 1, items.length - 1); highlight(items); }
    else if (ev.key === 'ArrowUp') { ev.preventDefault(); active = Math.max(active - 1, 0); highlight(items); }
    else if (ev.key === 'Enter' && active >= 0) {
      var a = items[active].querySelector('a');
      if (a) { ev.preventDefault(); window.location.href = a.href; }
    } else if (ev.key === 'Escape') { list.style.display = 'none'; setExpanded(false); }
  });
  document.addEventListener('click', function (ev) {
    if (!box.contains(ev.target) && !list.contains(ev.target)) {
      list.style.display = 'none';
      setExpanded(false);
    }
  });
})();
</script>
";

/// Which section of the navigation is currently active.
#[derive(Clone, Copy, PartialEq, Eq)]
enum NavSection {
    Home,
    Guide,
    Topic,
    Idiom,
    Construct,
    Reference,
    Diagnostic,
    Cli,
}

/// Render the persistent site header.
///
/// `base` is the relative path prefix needed to reach the site root from the
/// current page (empty string `""` for root-level pages, `"../"` for pages
/// one directory deep). The active section is highlighted.
fn render_header(active: NavSection, base: &str, search_script: &str) -> String {
    use crate::text;

    let link = |section: NavSection, href: &str, label: &str| -> String {
        let cls = if active == section {
            " class=\"active\""
        } else {
            ""
        };
        format!("<a href=\"{base}{href}\"{cls}>{}</a>", html::escape(label))
    };
    let mut h = format!(
        "<a class=\"skip-link\" href=\"#content\">{}</a>\n\
         <nav class=\"site-header\" aria-label=\"{}\">\n",
        html::escape(text::site_skip_link()),
        html::escape(text::site_nav_label()),
    );
    // The full title on desktop; the mobile CSS swaps in the short form via a
    // second span — never a bare \"Ipê docs\" (issue #1874, item 20).
    let _ = writeln!(
        h,
        "<a class=\"site-title\" href=\"{base}index.html\">\
         <span class=\"title-full\">{}</span>\
         <span class=\"title-short\">{}</span></a>",
        html::escape(text::site_title_full()),
        html::escape(text::site_title_short()),
    );
    let _ = writeln!(
        h,
        "<button class=\"nav-toggle\" id=\"nav-toggle\" type=\"button\" \
         aria-label=\"{}\" aria-expanded=\"false\" aria-controls=\"nav-links\">\
         <span class=\"nav-toggle-open\">\u{2630}</span>\
         <span class=\"nav-toggle-close\">\u{2715}</span></button>",
        html::escape(text::site_menu_label()),
    );
    h.push_str("<div class=\"nav-links\" id=\"nav-links\">\n");
    h.push_str(&link(
        NavSection::Guide,
        "guide/index.html",
        text::site_guides(),
    ));
    h.push('\n');
    h.push_str(&link(
        NavSection::Topic,
        "topic/index.html",
        text::site_topics(),
    ));
    h.push('\n');
    h.push_str(&link(
        NavSection::Idiom,
        "idiom/index.html",
        text::site_idioms(),
    ));
    h.push('\n');
    h.push_str(&link(
        NavSection::Construct,
        "construct/index.html",
        text::site_constructs(),
    ));
    h.push('\n');
    h.push_str("<span class=\"sep\" aria-hidden=\"true\">\u{2502}</span>\n");
    h.push_str(&link(
        NavSection::Reference,
        "module/index.html",
        text::site_reference(),
    ));
    h.push('\n');
    h.push_str(&link(
        NavSection::Diagnostic,
        "diagnostic/index.html",
        text::site_diagnostics(),
    ));
    h.push('\n');
    h.push_str(&link(NavSection::Cli, "cli/index.html", text::site_cli()));
    h.push('\n');
    let _ = writeln!(
        h,
        "<span class=\"search-wrap\" role=\"search\">\
         <input type=\"search\" id=\"nav-search\" class=\"nav-search\" \
         placeholder=\"{}\" aria-label=\"{}\" \
         role=\"combobox\" aria-expanded=\"false\" aria-controls=\"search-results\" \
         aria-autocomplete=\"list\" autocomplete=\"off\">\
         <ul class=\"search-results\" id=\"search-results\" role=\"listbox\" \
         aria-label=\"{}\"></ul>\
         </span>",
        html::escape(text::site_search_placeholder()),
        html::escape(text::site_search_label()),
        html::escape(text::site_search_results_label()),
    );
    let _ = writeln!(
        h,
        "<button class=\"theme-toggle\" id=\"theme-toggle\" type=\"button\" \
         aria-label=\"{}\" aria-pressed=\"false\">\
         <span class=\"theme-icon-dark\" aria-hidden=\"true\">\u{263e}</span>\
         <span class=\"theme-icon-light\" aria-hidden=\"true\">\u{2600}</span></button>",
        html::escape(text::site_theme_toggle_label()),
    );
    h.push_str("</div>\n");
    h.push_str("</nav>\n");
    h.push_str(search_script);
    h.push_str(NAV_UX_SCRIPT);
    h
}

/// The inline script powering the theme toggle (item 19), the mobile hamburger
/// (item 20), and the floating scroll-to-top button (item 17). Static — no user
/// content reaches it.
const NAV_UX_SCRIPT: &str = "\
<script>
(function () {
  var root = document.documentElement;
  // Theme: stored choice wins, else the system preference (the default).
  var stored = null;
  try { stored = localStorage.getItem('ipe-theme'); } catch (e) {}
  function apply(theme) {
    if (theme === 'light' || theme === 'dark') { root.setAttribute('data-theme', theme); }
    else { root.removeAttribute('data-theme'); }
    var btn = document.getElementById('theme-toggle');
    if (btn) {
      var dark = theme === 'dark' ||
        (theme !== 'light' && window.matchMedia &&
         window.matchMedia('(prefers-color-scheme: dark)').matches);
      btn.setAttribute('aria-pressed', dark ? 'true' : 'false');
    }
  }
  apply(stored);
  var toggle = document.getElementById('theme-toggle');
  if (toggle) {
    toggle.addEventListener('click', function () {
      var cur = root.getAttribute('data-theme');
      var sysDark = window.matchMedia &&
        window.matchMedia('(prefers-color-scheme: dark)').matches;
      var isDark = cur ? cur === 'dark' : sysDark;
      var next = isDark ? 'light' : 'dark';
      try { localStorage.setItem('ipe-theme', next); } catch (e) {}
      apply(next);
    });
  }
  // Mobile menu.
  var navToggle = document.getElementById('nav-toggle');
  var navLinks = document.getElementById('nav-links');
  if (navToggle && navLinks) {
    navToggle.addEventListener('click', function () {
      var open = navLinks.classList.toggle('open');
      navToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
  }
  // Scroll-to-top.
  var top = document.getElementById('scroll-top');
  if (top) {
    window.addEventListener('scroll', function () {
      top.classList.toggle('visible', window.scrollY > 300);
    }, { passive: true });
    top.addEventListener('click', function () {
      var reduce = window.matchMedia &&
        window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      window.scrollTo({ top: 0, behavior: reduce ? 'auto' : 'smooth' });
    });
  }
})();
</script>
";

/// Parse a leading `[label](url)` link. Returns the label text, the URL, and
/// the byte length consumed, or `None` when the slice does not open a
/// well-formed link. Nested brackets in the label and parens in the URL are
/// not supported (rendered literally) — a deliberately small, safe subset.
fn parse_link(s: &str) -> Option<(String, String, usize)> {
    let after_open = s.strip_prefix('[')?;
    let close = after_open.find(']')?;
    let label = after_open.get(..close)?;
    let after_label = after_open.get(close + 1..)?;
    let after_paren = after_label.strip_prefix('(')?;
    let close_paren = after_paren.find(')')?;
    let url = after_paren.get(..close_paren)?;
    // Reject a scheme that could execute script through the one doc-path
    // href-safety SSOT (`ipe_docs::markdown::SafeHref`); a link the SSOT refuses
    // is left literal rather than unwrapped (`?` early-returns on refusal).
    ipe_docs::markdown::SafeHref::parse(url)?;
    let consumed = 1 + close + 1 + 1 + close_paren + 1;
    Some((label.to_owned(), url.to_owned(), consumed))
}

/// Render a doc-comment / Markdown body to HTML through the one doc-side
/// Markdown path: the `Ipe.Markdown` port's parser and escape-by-default walker
/// (`ipe_docs::markdown`). Headings are shifted so a body heading nests under
/// the page chrome, prose carries the `comment` class, and fenced code is
/// Ipê-highlighted. Unrecognised or malformed markup renders as safe escaped
/// text — never a panic, never injected markup.
fn render_comment_html(comment: &str) -> String {
    use ipe_docs::markdown::{parse::parse_blocks, walker};

    // Section headings inside a page body start at h3 so they nest under the
    // page's own h1/h2 chrome (the walker clamps at h6).
    let normalised = fence_indented_code(comment);
    let highlight = |body: &str| highlight_ipe_snippet(body);
    let opts = walker::WalkOptions {
        heading_offset: 2,
        code_renderer: Some(&highlight),
        para_class: Some("comment"),
    };
    walker::blocks_to_html(&parse_blocks(&normalised), &opts)
}

/// Normalise a doc-comment body into `Ipe.Markdown` source before parsing.
///
/// A doc-comment may present an example as a four-space-indented block (the
/// stdlib convention). `Ipe.Markdown` — the parse SSOT — recognises only fenced
/// code, so this boundary transform rewrites each maximal run of four-space
/// indented lines into a ```` ``` ````-fenced block (the four-space marker
/// stripped), leaving the SSOT parser as the single Markdown authority. Lines
/// already inside a fence, and list/table/blockquote continuations, are left
/// untouched so the transform never fabricates a code block from list content.
fn fence_indented_code(body: &str) -> String {
    let mut out = String::new();
    let mut in_fence = false;
    let mut in_indented = false;
    // Whether the previous non-blank line was a block that legitimately carries
    // indented continuations (a list / table / blockquote), where a four-space
    // line is continuation, not a standalone code block.
    let mut prev_was_container = false;

    let close_indent = |out: &mut String, in_indented: &mut bool| {
        if *in_indented {
            out.push_str("```\n");
            *in_indented = false;
        }
    };

    for line in body.lines() {
        let is_fence_delim = line.trim_start().starts_with("```");
        if in_fence {
            // Inside an author fence: copy verbatim, toggle out on the closer.
            out.push_str(line);
            out.push('\n');
            if is_fence_delim {
                in_fence = false;
            }
            continue;
        }
        if is_fence_delim {
            close_indent(&mut out, &mut in_indented);
            in_fence = true;
            prev_was_container = false;
            out.push_str(line);
            out.push('\n');
            continue;
        }

        let line_indented = line.starts_with("    ");
        let is_blank = line.trim().is_empty();

        if in_indented {
            if line_indented {
                // Continue the code block, stripping the four-space marker.
                out.push_str(line.get(4..).unwrap_or(""));
            } else if is_blank {
                // A blank line may separate two indented paragraphs of the same
                // block; keep it inside the fence (emitted below).
            } else {
                // A non-indented, non-blank line ends the code block.
                close_indent(&mut out, &mut in_indented);
                prev_was_container = is_container_line(line);
                out.push_str(line);
            }
            out.push('\n');
            continue;
        }

        // Not currently in an indented run. A four-space line opens one only
        // when it is not a continuation of a list/table/blockquote.
        if line_indented && !prev_was_container {
            out.push_str("```\n");
            in_indented = true;
            out.push_str(line.get(4..).unwrap_or(""));
            out.push('\n');
            continue;
        }

        if !is_blank {
            prev_was_container = is_container_line(line);
        }
        out.push_str(line);
        out.push('\n');
    }
    close_indent(&mut out, &mut in_indented);
    out
}

/// Whether a line opens or continues a list / table / blockquote — a context
/// where an indented follow-on line is a continuation, not a code block.
fn is_container_line(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("- ")
        || t.starts_with("* ")
        || t.starts_with("+ ")
        || t.starts_with('|')
        || t.starts_with("> ")
        || t == ">"
        || t.split_once(". ")
            .is_some_and(|(n, _)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Syntax-highlight an Ipê snippet into `<code>…</code>` inner HTML.
///
/// The snippet is fed through the shared `ipe_docs` highlighter (the real lexer,
/// no hand-rolled tokenizer); when it does not parse as a module — most excerpts
/// do not — the highlighter falls back to escaped text. Deterministic and
/// escape-safe: no snippet content can inject markup.
fn highlight_ipe_snippet(source: &str) -> String {
    ipe_docs::render::highlight_snippet(source)
}

/// Render a signature's pieces as HTML: an in-package type is an `<a href>` to
/// its anchor, everything else is escaped text.
fn html_signature(pieces: &[SigPiece]) -> String {
    let mut out = String::new();
    for piece in pieces {
        match piece {
            SigPiece::Text(t) => out.push_str(&html::escape(t)),
            SigPiece::Link { text, target } => {
                let _ = write!(
                    out,
                    "<a href=\"{}\">{}</a>",
                    html::escape(&target.href("html")),
                    html::escape(text)
                );
            }
        }
    }
    out
}

/// Wrap a page body in the shared HTML shell (doctype, `<head>` linking the
/// bundled stylesheet, `<body>`).
///
/// `css_href` is the relative path to `style.css` from the page's location.
/// `header` is the rendered persistent nav header (already HTML, inserted
/// before the body wrapper). When absent, a bare `<body>` is emitted (used
/// only by legacy callers that do not yet carry a header).
fn html_page(title: &str, css_href: &str, header: &str, body: &str) -> String {
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{}</title>\n<link rel=\"stylesheet\" href=\"{css_href}\">\n</head>\n\
         <body>\n{header}<main id=\"content\" class=\"page-body\">\n{body}</main>\n\
         <button id=\"scroll-top\" class=\"scroll-top\" type=\"button\" \
         aria-label=\"{}\">\u{2191}</button>\n</body>\n</html>\n",
        html::escape(title),
        html::escape(crate::text::site_scroll_top_label()),
    )
}

/// Build the search script with the embedded entry index.
///
/// Each entry carries its already-resolved `href` (relative to the page the
/// script is embedded in), so the JS navigates straight to a generated file and
/// never rebuilds a path from parts.
fn build_search_script(entries: &[SearchEntry]) -> String {
    use crate::cli_args::json;
    let mut json_buf = String::from("[");
    for (i, e) in entries.iter().enumerate() {
        if i > 0 {
            json_buf.push(',');
        }
        let _ = std::fmt::Write::write_fmt(
            &mut json_buf,
            format_args!(
                "{{\"kind\":{},\"key\":{},\"title\":{},\"href\":{}}}",
                json::string(e.kind),
                json::string(&e.key),
                json::string(&e.title),
                json::string(&e.href),
            ),
        );
    }
    json_buf.push(']');

    // The JSON is embedded inside a `<script>` element, so a value holding
    // `</script>` (or any markup) must not close it, even though doc keys and
    // titles are repo-controlled.
    let json_buf = ipe_diagnostics::json::script_embed(&json_buf);

    SEARCH_SCRIPT_TEMPLATE.replace("ENTRY_INDEX_PLACEHOLDER", &json_buf)
}

/// Sort curated entries: entries with an explicit `order:` first (ascending),
/// then alphabetically by title for the remainder.
fn sort_curated_entries(entries: &mut Vec<&crate::doc_bundle::DocEntry>) {
    entries.sort_by(|a, b| match (a.order, b.order) {
        (Some(oa), Some(ob)) => oa.cmp(&ob).then_with(|| a.title.cmp(&b.title)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.title.cmp(&b.title),
    });
}

/// Extract a human title from a Markdown body: the text of its first ATX
/// heading (`# …`), with any leading diagnostic code and backtick markers
/// stripped. Returns `None` when the body has no heading — the caller then falls
/// back to the entry key.
fn explain_title(body: &str) -> Option<String> {
    for line in body.lines() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix('#') else {
            if t.is_empty() {
                continue;
            }
            // A body that opens with prose (no heading) has no title to lift.
            return None;
        };
        let heading = rest.trim_start_matches('#').trim();
        // Drop a leading `IPE-Xnnnn` code token plus its separator so the title is
        // the description, not the code the list already prints alongside it.
        let heading = strip_leading_code(heading);
        let plain: String = heading.chars().filter(|&c| c != '`').collect();
        let plain = plain.trim().to_owned();
        if plain.is_empty() {
            return None;
        }
        return Some(plain);
    }
    None
}

/// Strip a leading `IPE-Xnnnn` diagnostic code and its trailing separator
/// (`:`, `—`, `-`, or whitespace) from a heading, so `IPE-E0001 — Foo` becomes
/// `Foo`. A heading without such a prefix is returned unchanged.
fn strip_leading_code(heading: &str) -> &str {
    let Some(rest) = heading.strip_prefix("IPE-") else {
        return heading;
    };
    // The code token is `IPE-` followed by non-space, non-separator characters.
    let code_len = rest
        .find(|c: char| c.is_whitespace() || c == ':' || c == '—')
        .unwrap_or(rest.len());
    let after = rest[code_len..].trim_start_matches([' ', '\t', ':', '—', '-']);
    if after.is_empty() {
        heading
    } else {
        after.trim()
    }
}

/// Extract a one-line summary from a Markdown body -- the first non-blank,
/// non-heading prose sentence (stripped of backtick markers). Returns an empty
/// string when no suitable sentence is found.
fn first_sentence(body: &str) -> String {
    for line in body.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with("---") {
            continue;
        }
        // A plain-text summary: unwrap `[text](url)` links to their text and drop
        // backtick/emphasis markers so no Markdown syntax leaks into the escaped
        // summary.
        let unlinked = strip_markdown_links(t);
        let plain: String = unlinked
            .chars()
            .filter(|&c| !matches!(c, '`' | '*' | '_'))
            .take(120)
            .collect();
        return plain;
    }
    String::new()
}

/// Replace every `[text](url)` with just `text`, leaving other text untouched.
/// A malformed pair is left verbatim.
fn strip_markdown_links(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('[') {
        out.push_str(rest.get(..open).unwrap_or(""));
        let after = rest.get(open..).unwrap_or("");
        if let Some((label, _url, consumed)) = parse_link(after) {
            out.push_str(&label);
            rest = after.get(consumed..).unwrap_or("");
        } else {
            out.push('[');
            rest = after.get(1..).unwrap_or("");
        }
    }
    out.push_str(rest);
    out
}

/// Render the Reference (module) index page.
///
/// Lists all module entries; each links to its module page. Modules are
/// presented in the same hierarchical namespace tree used on the old landing.
fn render_reference_index(docs: &DocsJson, search_script: &str) -> String {
    let header = render_header(NavSection::Reference, "../", search_script);
    let title = crate::text::site_reference();
    let mut body = format!(
        "<h1>{}</h1>\n\
         <input type=\"search\" id=\"filter\" class=\"filter\" \
         placeholder=\"{}\" aria-label=\"{}\" \
         autocomplete=\"off\">\n",
        html::escape(title),
        html::escape(crate::text::site_filter_modules()),
        html::escape(crate::text::site_filter_modules_label()),
    );

    render_html_module_section_relative(
        &mut body,
        docs,
        ModuleKind::Local,
        crate::text::site_project_modules(),
    );
    render_html_module_section_relative(
        &mut body,
        docs,
        ModuleKind::Stdlib,
        crate::text::site_standard_library(),
    );

    body.push_str(FILTER_SCRIPT);
    html_page(title, "../style.css", &header, &body)
}

/// Render one module section for the reference index.
///
/// Like `render_html_module_section` but links resolve relative to
/// `module/index.html` (one level down), so paths are `../{stem}.html`.
fn render_html_module_section_relative(
    body: &mut String,
    docs: &DocsJson,
    kind: ModuleKind,
    label: &str,
) {
    let names: Vec<&str> = docs
        .modules
        .iter()
        .filter(|m| m.kind == kind)
        .map(|m| m.name.as_str())
        .collect();
    if names.is_empty() {
        return;
    }
    let _ = writeln!(
        body,
        "<section class=\"group\"><h2>{}</h2>",
        html::escape(label)
    );
    let tree = build_namespace_tree(&names);
    render_html_tree_relative(&tree, body);
    body.push_str("</section>\n");
}

/// Render a namespace tree with links relative to a subdirectory page.
///
/// Module links use `../{stem}.html` (one level up from `module/index.html`).
fn render_html_tree_relative(nodes: &[NamespaceNode], out: &mut String) {
    out.push_str("<ul class=\"modules\">\n");
    for node in nodes {
        out.push_str("<li class=\"module\"");
        let _ = write!(
            out,
            " data-name=\"{}\"",
            html::escape(&node.full_name.to_lowercase())
        );
        out.push('>');
        if node.is_module {
            let stem = module_stem(&node.full_name);
            let _ = write!(
                out,
                "<a href=\"../{}.html\">{}</a>",
                html::escape(&stem),
                html::escape(&node.full_name)
            );
        } else {
            let _ = write!(
                out,
                "<span class=\"ns-header\">{}</span>",
                html::escape(&node.full_name)
            );
        }
        if !node.children.is_empty() {
            out.push('\n');
            render_html_tree_relative(&node.children, out);
        }
        out.push_str("</li>\n");
    }
    out.push_str("</ul>\n");
}

/// Render the Diagnostics index page.
///
/// Lists all `Diagnostic` entries (`IPE-Xnnnn — title`), each linking to its
/// page.
fn render_diagnostic_index(bundle: &crate::doc_bundle::DocBundle, search_script: &str) -> String {
    let header = render_header(NavSection::Diagnostic, "../", search_script);
    let title = crate::text::site_diagnostics();
    let mut body = format!("<h1>{}</h1>\n", html::escape(title));
    body.push_str(&render_code_families());
    body.push_str("<ul class=\"index-entries index-table\">\n");
    let mut entries: Vec<&crate::doc_bundle::DocEntry> = bundle
        .entries_for_kind(crate::doc_bundle::DocKind::Diagnostic)
        .collect();
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    for entry in entries {
        let href = entry_href(entry.kind, &entry.key, "../");
        // `<code>` (accent) then the human title — never the code twice
        // (issue #1874, item 5).
        let _ = writeln!(
            body,
            "<li><a class=\"entry-code\" href=\"{}\">{}</a>\
             <a class=\"entry-title\" href=\"{}\">{}</a></li>",
            html::escape(&href),
            html::escape(&entry.key),
            html::escape(&href),
            html::escape(&entry.title),
        );
    }
    body.push_str("</ul>\n");
    html_page(title, "../style.css", &header, &body)
}

/// The Diagnostics page's key to the code letters.
///
/// Says what each `IPE-<letter>` family covers, read from the diagnostics
/// family table ([`ipe_diagnostics::FAMILIES`]) so a new family appears here by
/// construction.
fn render_code_families() -> String {
    let mut out = format!(
        "<p class=\"code-families-intro\">{}</p>\n<dl class=\"code-families\">\n",
        crate::text::site_code_families_intro(),
    );
    for row in ipe_diagnostics::FAMILIES {
        let _ = writeln!(
            out,
            "<dt><code>{}</code></dt><dd>{}</dd>",
            row.letter,
            html::escape(row.summary),
        );
    }
    out.push_str("</dl>\n");
    out
}

/// Render the CLI index page.
///
/// Lists all `Cli` entries (subcommand — summary), each linking to its page.
fn render_cli_index(bundle: &crate::doc_bundle::DocBundle, search_script: &str) -> String {
    let header = render_header(NavSection::Cli, "../", search_script);
    let title = crate::text::site_cli();
    let mut body = format!("<h1>{}</h1>\n", html::escape(title));
    // A two-column aligned table: command in one column, summary in the next, so
    // every summary starts at the same indentation (issue #1874, item 7).
    body.push_str("<ul class=\"index-entries index-table\">\n");
    let mut entries: Vec<&crate::doc_bundle::DocEntry> = bundle
        .entries_for_kind(crate::doc_bundle::DocKind::Cli)
        .collect();
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    for entry in entries {
        let href = entry_href(entry.kind, &entry.key, "../");
        let summary = if entry.title.is_empty() {
            first_sentence(&entry.body)
        } else {
            entry.title.clone()
        };
        let _ = write!(
            body,
            "<li><a class=\"entry-code\" href=\"{}\">{}</a>",
            html::escape(&href),
            html::escape(&entry.key),
        );
        if !summary.is_empty() {
            let _ = write!(
                body,
                "<span class=\"entry-title\">{}</span>",
                html::escape(&summary),
            );
        }
        body.push_str("</li>\n");
    }
    body.push_str("</ul>\n");
    html_page(title, "../style.css", &header, &body)
}

/// Render per-kind index pages for curated kinds (Guide, Topic, Idiom, Construct).
///
/// Each page lists its entries with title and summary. Returns a map of
/// `{kind}/index.html` → HTML content.
fn render_curated_kind_indexes(
    bundle: &crate::doc_bundle::DocBundle,
    search_script: &str,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let curated = [
        (
            crate::doc_bundle::DocKind::Guide,
            crate::text::site_guides(),
            NavSection::Guide,
        ),
        (
            crate::doc_bundle::DocKind::Topic,
            crate::text::site_topics(),
            NavSection::Topic,
        ),
        (
            crate::doc_bundle::DocKind::Idiom,
            crate::text::site_idioms(),
            NavSection::Idiom,
        ),
        (
            crate::doc_bundle::DocKind::Construct,
            crate::text::site_constructs(),
            NavSection::Construct,
        ),
    ];
    for (kind, label, nav) in curated {
        let header = render_header(nav, "../", search_script);
        let mut body = format!("<h1>{}</h1>\n", html::escape(label));
        let mut entries: Vec<&crate::doc_bundle::DocEntry> =
            bundle.entries_for_kind(kind).collect();
        sort_curated_entries(&mut entries);
        body.push_str("<ul class=\"curated-entries\">\n");
        for entry in entries {
            let href = entry_href(kind, &entry.key, "../");
            let summary = first_sentence(&entry.body);
            let _ = write!(
                body,
                "<li><a href=\"{}\" class=\"entry-title\">{}</a>",
                html::escape(&href),
                html::escape(&entry.title)
            );
            if !summary.is_empty() {
                let _ = write!(
                    body,
                    "<span class=\"entry-summary\">{}</span>",
                    html::escape(&summary)
                );
            }
            body.push_str("</li>\n");
        }
        body.push_str("</ul>\n");
        let page = html_page(label, "../style.css", &header, &body);
        out.insert(format!("{}/index.html", kind.prefix()), page);
    }
    out
}

/// The navigation section a bundle kind belongs to, for header highlighting.
const fn nav_section_for(kind: crate::doc_bundle::DocKind) -> NavSection {
    use crate::doc_bundle::DocKind;
    match kind {
        DocKind::Guide => NavSection::Guide,
        DocKind::Topic => NavSection::Topic,
        DocKind::Idiom => NavSection::Idiom,
        DocKind::Construct => NavSection::Construct,
        DocKind::Diagnostic => NavSection::Diagnostic,
        DocKind::Cli => NavSection::Cli,
        DocKind::Module | DocKind::Symbol => NavSection::Reference,
    }
}

/// Render a full page for a single non-module bundle entry (a diagnostic, a CLI
/// command, or a curated guide/topic/idiom/construct).
///
/// The body is the entry's Markdown, rendered through the shared block renderer
/// so lists, code, and inline spans display consistently with module pages. The
/// page lives one directory deep (`<kind>/<key>.html`), so links resolve with a
/// `"../"` base.
fn render_entry_page(
    kind: crate::doc_bundle::DocKind,
    entry: &crate::doc_bundle::DocEntry,
    search_script: &str,
) -> String {
    let header = render_header(nav_section_for(kind), "../", search_script);
    let mut body = String::new();
    let _ = writeln!(body, "<h1>{}</h1>", html::escape(&entry.title));
    if entry.key != entry.title {
        let _ = writeln!(
            body,
            "<p class=\"entry-code\"><code>{}</code></p>",
            html::escape(&entry.key)
        );
    }
    if entry.body.is_empty() {
        let _ = writeln!(
            body,
            "<p class=\"comment\">{}</p>",
            html::escape(crate::text::site_no_documentation())
        );
    } else {
        // Entry bodies are sourced from Markdown files (explain pages, construct
        // docs, command help) — rendered through the one doc-side Markdown path
        // (`ipe_docs::markdown` port + escape-by-default walker) so headings, code
        // fences, tables, and links all work consistently. Fenced code is routed
        // through the shared token-classifier highlighter (no second lexer).
        body.push_str(&ipe_docs::render::markdown_to_html(&entry.body));
    }
    html_page(&entry.title, "../style.css", &header, &body)
}

/// Emit a `<kind>/<key>.html` page for every non-module bundle entry, keyed by
/// its flat site-map path. These are the per-entry targets every diagnostic /
/// CLI / curated link points at; generating them here is what makes those links
/// resolve (issue #1874, item 9).
fn render_entry_pages(
    bundle: &crate::doc_bundle::DocBundle,
    search_script: &str,
) -> BTreeMap<String, String> {
    use crate::doc_bundle::DocKind;
    let mut out = BTreeMap::new();
    let kinds = [
        DocKind::Diagnostic,
        DocKind::Cli,
        DocKind::Guide,
        DocKind::Topic,
        DocKind::Idiom,
        DocKind::Construct,
    ];
    for kind in kinds {
        for entry in bundle.entries_for_kind(kind) {
            if let Some(path) = entry_page_key(kind, &entry.key) {
                out.insert(path, render_entry_page(kind, entry, search_script));
            }
        }
    }
    out
}

/// Render the teach-first landing page.
///
/// Lists curated kinds in teach order: Guides → Topics → Idioms → Constructs.
/// Each kind section lists its entries ordered by front-matter `order:` then
/// alphabetically by title. Generated kinds (Reference, Diagnostics, CLI) are
/// reachable in one click from the header.
fn render_html_index(
    _docs: &DocsJson,
    bundle: &crate::doc_bundle::DocBundle,
    search_script: &str,
) -> String {
    let header = render_header(NavSection::Home, "", search_script);
    let title = crate::text::site_documentation();
    let heading = format!("<h1>{}</h1>\n", html::escape(title));
    let mut body = heading.clone();

    let curated = [
        (
            crate::doc_bundle::DocKind::Guide,
            crate::text::site_guides(),
        ),
        (
            crate::doc_bundle::DocKind::Topic,
            crate::text::site_topics(),
        ),
        (
            crate::doc_bundle::DocKind::Idiom,
            crate::text::site_idioms(),
        ),
        (
            crate::doc_bundle::DocKind::Construct,
            crate::text::site_constructs(),
        ),
    ];

    for (kind, label) in curated {
        let mut entries: Vec<&crate::doc_bundle::DocEntry> =
            bundle.entries_for_kind(kind).collect();
        if entries.is_empty() {
            continue;
        }
        sort_curated_entries(&mut entries);
        let _ = writeln!(body, "<section class=\"kind-group\">");
        let _ = writeln!(body, "<h2>{}</h2>", html::escape(label));
        body.push_str("<ul class=\"curated-entries\">\n");
        for entry in entries {
            let href = entry_href(kind, &entry.key, "");
            let summary = first_sentence(&entry.body);
            let _ = write!(
                body,
                "<li><a href=\"{}\" class=\"entry-title\">{}</a>",
                html::escape(&href),
                html::escape(&entry.title)
            );
            if !summary.is_empty() {
                let _ = write!(
                    body,
                    "<span class=\"entry-summary\">{}</span>",
                    html::escape(&summary)
                );
            }
            body.push_str("</li>\n");
        }
        body.push_str("</ul>\n</section>\n");
    }

    if body == heading {
        // No curated entries yet -- show the module index as a fallback.
        let _ = writeln!(body, "<p>{}</p>", crate::text::site_reference_fallback());
    }

    html_page(title, "style.css", &header, &body)
}

/// Render one module's page — its doc-comment, its exposed types and values,
/// each entry carrying a stable `id` anchor and its cross-linked signature.
fn render_html_module(module: &ModuleDoc, index: &AnchorIndex, search_script: &str) -> String {
    let header = render_header(NavSection::Reference, "", search_script);
    let mut body = String::from("<nav class=\"crumb\"><a href=\"module/index.html\">&larr; ");
    body.push_str(&html::escape(crate::text::site_reference()));
    body.push_str("</a></nav>\n");
    let _ = writeln!(body, "<h1>{}</h1>", html::escape(&module.name));
    if !module.comment.is_empty() {
        body.push_str(&render_comment_html(&module.comment));
    }

    if !module.unions.is_empty() {
        let _ = writeln!(body, "<h2>{}</h2>", html::escape(crate::text::site_types()));
        for union in &module.unions {
            let _ = writeln!(
                body,
                "<section class=\"entry\" id=\"{}\">\n<h3><code>{}{}</code></h3>",
                html::escape(&union.name),
                html::escape(&union.name),
                html::escape(&union_params(union.params))
            );
            if !union.comment.is_empty() {
                body.push_str(&render_comment_html(&union.comment));
            }
            for ctor in &union.ctors {
                body.push_str("<pre class=\"sig\">");
                body.push_str(&html::escape(&ctor.name));
                for arg in &ctor.arg_types {
                    body.push(' ');
                    body.push_str(&html_signature(&signature_pieces(arg, index)));
                }
                body.push_str("</pre>\n");
            }
            body.push_str("</section>\n");
        }
    }

    if !module.values.is_empty() {
        let _ = writeln!(
            body,
            "<h2>{}</h2>",
            html::escape(crate::text::site_values())
        );
        for value in &module.values {
            let sig = html_signature(&signature_pieces(&value.signature_ty, index));
            let _ = writeln!(
                body,
                "<section class=\"entry\" id=\"{}\">\n<h3><code>{}</code></h3>\n\
                 <pre class=\"sig\">{} : {sig}</pre>",
                html::escape(&value.name),
                html::escape(&value.name),
                html::escape(&value.name)
            );
            if !value.comment.is_empty() {
                body.push_str(&render_comment_html(&value.comment));
            }
            body.push_str("</section>\n");
        }
    }

    html_page(&module.name, "style.css", &header, &body)
}

// ===========================================================================
// serve — a read-only, loopback-only preview of the built HTML site.
// ===========================================================================

/// Build the HTML site for the package at `path` and serve it read-only on
/// loopback, blocking until interrupted.
///
/// The site is built once in memory (never written to disk — to keep files, run
/// `ipe doc`), then served from a single-threaded blocking HTTP/1.1 loop over
/// `std::net::TcpListener`. It binds `127.0.0.1` only; `port` `None` lets the OS
/// assign a free port (bind `:0`), `Some(n)` pins one and errors if it is taken.
///
/// The default browser is opened on the served URL; a headless caller sets
/// `IPE_DOC_NO_OPEN` to skip that (the URL is printed either way).
///
/// # Errors
/// [`CliError::Io`] if the loopback port cannot be bound (a pinned port already
/// in use), plus any error from [`build_docs`].
fn serve(path: &Path, port: Option<u16>) -> Result<(), CliError> {
    use std::net::TcpListener;

    crate::style::print_command_header();
    let (docs, _) = build_docs_or_stdlib(path)?;
    let docs_root = locate_docs_root();
    let bundle = build_doc_bundle(&docs_root)?;
    let site = render_site_for_serve(&docs, &bundle);

    let addr = format!("127.0.0.1:{}", port.unwrap_or(0));
    let listener = TcpListener::bind(&addr).map_err(|e| crate::io_err(Path::new(&addr), e))?;
    let bound = listener
        .local_addr()
        .map_err(|e| crate::io_err(Path::new(&addr), e))?;

    let url = format!("http://{bound}/");
    crate::screen::status(
        crate::screen::Stream::Stdout,
        true,
        &crate::style::TerminalSafe::sanitize(&format!(
            "serving docs at {url} (read-only, loopback; Ctrl-C to stop)"
        )),
    );
    // A headless caller (CI, a test, a remote shell) opts out of the browser pop
    // with `IPE_DOC_NO_OPEN`; the URL is already printed, so the preview stays
    // reachable.
    if ipe_env::var_os("IPE_DOC_NO_OPEN").is_none()
        && let Ok(url) =
            crate::browser::BrowserUrl::parse(&url, crate::browser::BrowserOrigin::Loopback)
    {
        let _ = crate::browser::open_url(&url);
    }

    // A single dropped connection must not take the server down; `flatten` skips
    // the `Err`s and serves each accepted stream.
    for mut conn in listener.incoming().flatten() {
        serve_one(&mut conn, &site);
    }
    Ok(())
}

/// Serve one HTTP/1.1 request from the in-memory `site`, read-only.
///
/// Reads the request line, maps its path to a built file (`/` → `index.html`),
/// and writes the file with its content type — or a `404` when the path names no
/// built file. Only `GET`/`HEAD`-shaped requests are honoured; the body, if any,
/// is ignored (nothing here writes or executes).
/// The largest request line the doc server will read before giving up. A request
/// line is a method, a path, and a version; a few kilobytes covers any real one,
/// and the cap turns a client that streams bytes without a newline into a bounded
/// read rather than an unbounded buffer growth.
const DOC_SERVE_REQUEST_LINE_CAP: usize = 16 * 1024;

/// The wall-clock a single read may block before the doc server abandons the
/// connection, so a client that opens a socket and never sends stalls one
/// connection briefly instead of pinning the accept loop forever.
const DOC_SERVE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

fn serve_one(conn: &mut std::net::TcpStream, site: &BTreeMap<String, String>) {
    use std::io::{BufRead, BufReader, Read, Write};

    // Bound the wait: a peer that connects and never writes stalls this one
    // connection for at most the timeout, never the whole loop (a remote
    // exhaustion vector otherwise).
    if conn.set_read_timeout(Some(DOC_SERVE_READ_TIMEOUT)).is_err() {
        return;
    }
    let Ok(clone) = conn.try_clone() else {
        return;
    };
    // Bound the size: read at most one capped request line. `take` caps the byte
    // count, so a client that never sends a newline yields a bounded buffer, not
    // unbounded growth. A line that fills the cap without a terminating newline is
    // an over-long request: fail closed with `431` rather than act on a truncated
    // request line.
    let mut reader = BufReader::new(clone.take(DOC_SERVE_REQUEST_LINE_CAP as u64));
    let mut request_line = String::new();
    let Ok(read) = reader.read_line(&mut request_line) else {
        return;
    };
    if read >= DOC_SERVE_REQUEST_LINE_CAP && !request_line.ends_with('\n') {
        let overflow = http_response(
            "431 Request Header Fields Too Large",
            "text/plain; charset=utf-8",
            "request line too long\n",
        );
        let _ = conn.write_all(overflow.as_bytes());
        let _ = conn.flush();
        return;
    }

    let path = request_line.split_whitespace().nth(1).unwrap_or("/");
    let name = serve_file_name(path);

    let response = site.get(&name).map_or_else(
        || http_response("404 Not Found", "text/plain; charset=utf-8", "not found\n"),
        |body| http_response("200 OK", content_type(&name), body),
    );
    let _ = conn.write_all(response.as_bytes());
    let _ = conn.flush();
}

/// Map a request path to a built-file key: `/` (or empty) → `index.html`,
/// otherwise the leading `/` is stripped and any `?query`/`#frag` dropped. The
/// result is a bare filename — a `..` or nested path simply misses the flat site
/// map and 404s, so no traversal can escape it.
fn serve_file_name(path: &str) -> String {
    let path = path.split(['?', '#']).next().unwrap_or(path);
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        "index.html".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// The content type for a built file, by extension.
fn content_type(name: &str) -> &'static str {
    match Path::new(name).extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("md") => "text/markdown; charset=utf-8",
        _ => "text/plain; charset=utf-8",
    }
}

/// A complete HTTP/1.1 response with an explicit `Content-Length` and a
/// `Connection: close` (the loop serves one request per connection).
fn http_response(status: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal_text(rest: &[&str]) -> String {
        let parsed = parse_doc(&s(rest));
        assert!(
            matches!(parsed, Err(CliError::Usage(_))),
            "{rest:?} must be a usage refusal, got {parsed:?}"
        );
        parsed.err().map(|err| err.to_string()).unwrap_or_default()
    }

    #[test]
    fn a_blank_term_is_refused_not_read_as_a_path() {
        let empty = query_refused(QueryRefusal::Empty).to_string();
        for blank in ["", " ", "\u{a0}\u{a0}"] {
            assert_eq!(refusal_text(&[blank]), empty, "{blank:?}");
            assert_eq!(refusal_text(&[blank, "--json"]), empty, "{blank:?}");
        }
        assert_eq!(refusal_text(&["topic:"]), empty, "an empty key part");
        assert_eq!(refusal_text(&["topic:   "]), empty, "a blank key part");
    }

    #[test]
    fn a_hazardous_or_over_long_term_is_refused_by_its_kind() {
        let control = query_refused(QueryRefusal::ControlChar).to_string();
        for raw in [
            "map\u{1b}[2J",
            "Ipe.List.map\u{7}",
            "topic:x\u{202e}",
            "map\tx",
        ] {
            assert_eq!(refusal_text(&[raw]), control, "{raw:?}");
        }
        let too_long = query_refused(QueryRefusal::TooLong).to_string();
        let over = "a".repeat(MAX_QUERY_CHARS.saturating_add(1));
        assert_eq!(refusal_text(&[over.as_str()]), too_long);
        let longest = "a".repeat(MAX_QUERY_CHARS);
        assert!(matches!(
            parse_doc(&s(&[longest.as_str()])),
            Ok(DocMode::Lookup { .. })
        ));
    }

    #[test]
    fn a_term_is_trimmed_before_lookup() {
        assert_eq!(
            parse_doc(&s(&["  select "])).ok(),
            Some(DocMode::Lookup {
                key: "select".to_owned(),
                format: OutputFormat::Human,
            })
        );
    }

    #[test]
    fn a_qualified_term_is_a_lookup_whatever_its_key_holds() {
        for term in ["topic:pipelines", "symbol:Ipe.Basics.//", "cli:build"] {
            assert_eq!(
                parse_doc(&s(&[term, "--plain"])).ok(),
                Some(DocMode::Lookup {
                    key: term.to_owned(),
                    format: OutputFormat::Plain,
                }),
                "{term:?}"
            );
        }
        assert!(
            matches!(
                parse_doc(&s(&["topic:x", "--out", "site"])),
                Ok(DocMode::Generate { .. })
            ),
            "a generate-only flag keeps the positional a project path"
        );
        for path in ["d:\\pkg", "D:\\pkg", "src/x", "nokind:x"] {
            assert!(
                matches!(parse_doc(&s(&[path])), Ok(DocMode::Generate { .. })),
                "{path:?} stays a project path"
            );
        }
    }

    #[test]
    fn a_rerun_term_is_bare_only_where_the_bare_router_finds_the_entry() {
        let entry = |kind, key: &str| DocEntry {
            kind,
            key: key.to_owned(),
            title: key.to_owned(),
            body: String::new(),
            order: None,
        };
        let modules = [
            "Ipe.List".to_owned(),
            "Ipe.Http.Json".to_owned(),
            "Ipe.Json".to_owned(),
        ];
        let cases = [
            (entry(DocKind::Module, "Ipe.List"), "Ipe.List"),
            (entry(DocKind::Module, "Ipe.Json"), "Ipe.Json"),
            (entry(DocKind::Module, "Ipe.Http.Json"), "Ipe.Http.Json"),
            (entry(DocKind::Symbol, "Ipe.List.map"), "Ipe.List.map"),
            (
                entry(DocKind::Symbol, "Ipe.Maybe.Maybe"),
                "symbol:Ipe.Maybe.Maybe",
            ),
            (
                entry(DocKind::Symbol, "Ipe.Basics.//"),
                "symbol:Ipe.Basics.//",
            ),
            (entry(DocKind::Topic, "pipelines"), "topic:pipelines"),
            (
                entry(DocKind::Diagnostic, "IPE-E0001"),
                "diagnostic:IPE-E0001",
            ),
            (entry(DocKind::Cli, "build"), "cli:build"),
        ];
        for (e, want) in &cases {
            assert_eq!(rerun_term(e, &modules), *want, "{}", e.key);
        }
    }

    /// Every entry of the real bundle, listed as its rerun term, parses back
    /// to a lookup that opens that same entry — the machine re-run contract.
    #[test]
    fn every_listed_term_opens_its_entry_when_passed_back() {
        let bundle = build_doc_bundle(&locate_docs_root()).expect("the doc bundle builds");
        let index = build_index().expect("the doc index builds");
        let modules = stdlib_module_names();
        let mut checked = 0_usize;
        for entry in bundle.all_entries() {
            let term = rerun_term(entry, &modules);
            let Ok(query) = DocQuery::parse(&term) else {
                continue;
            };
            assert_eq!(
                query.text(),
                term,
                "a listed term carries no edge whitespace"
            );
            let parsed = parse_doc(&s(&[term.as_str(), "--json"]));
            assert!(parsed.is_ok(), "{term:?} parsed to {parsed:?}");
            let Ok(mode) = parsed else {
                return;
            };
            match mode {
                DocMode::Lookup { key, .. } if is_qualified(&key) => {
                    assert_eq!(key, term);
                    let resolved = bundle.resolve_qualified(&key).ok();
                    assert_eq!(resolved, Some(entry), "{term:?}");
                }
                DocMode::Lookup { key, .. } => {
                    assert_eq!(key, term);
                    assert_eq!(entry.kind, DocKind::Symbol, "{term:?}");
                    assert!(
                        index
                            .resolve(&key)
                            .is_some_and(|e| matches!(e.kind, ipe_docs::EntryKind::Symbol)),
                        "{term:?} must open the symbol through the index"
                    );
                }
                DocMode::Query { module, .. } => {
                    assert_eq!(module, term);
                    assert_eq!(entry.kind, DocKind::Module, "{term:?}");
                    assert!(
                        matches!(
                            resolve_stdlib_candidate(&module, &modules),
                            StdlibCandidate::One(only) if only == entry.key
                        ),
                        "{term:?} must name exactly its module"
                    );
                }
                other => assert!(
                    matches!(other, DocMode::Lookup { .. }),
                    "{term:?} parsed to {other:?}, not a lookup"
                ),
            }
            checked = checked.saturating_add(1);
        }
        assert!(checked > 0, "the bundle holds entries to walk");
    }

    #[test]
    fn a_miss_lists_only_rerun_terms_under_every_format() {
        let bundle = build_doc_bundle(&locate_docs_root()).expect("the doc bundle builds");
        let query = DocQuery::parse("pipelin").expect("a valid query");
        let ranked = crate::doc_search::rank(bundle.all_entries(), &query);
        let err = miss_error("pipelin", &ranked, OutputFormat::Human);
        assert!(
            matches!(err, CliError::DocNotFound { .. }),
            "a human miss stays the typed error: {err:?}"
        );
        let CliError::DocNotFound { miss } = err else {
            return;
        };
        assert!(!miss.hits.is_empty());
        let modules = stdlib_module_names();
        for (hit, entry) in miss.hits.iter().zip(&ranked.entries) {
            assert_eq!(hit.term.as_str(), rerun_term(entry, &modules));
        }
        assert!(matches!(
            miss_error("pipelin", &ranked, OutputFormat::Plain),
            CliError::DiagnosticJsonEmitted
        ));
    }

    /// A search entry holding `</script>`, `<!--`, `&` or U+2028 reaches the
    /// embedded index escaped, and the index still decodes to the entry.
    #[test]
    fn search_script_index_holds_no_script_breaking_character() {
        let title = "a</script><!--&\u{2028}\u{2029}b";
        let script = build_search_script(&[SearchEntry {
            kind: "symbol",
            key: "Main.x".to_owned(),
            title: title.to_owned(),
            href: "Main.html#x".to_owned(),
        }]);
        let index = script
            .split_once("var INDEX = ")
            .and_then(|(_, rest)| rest.split_once(";\n"))
            .map(|(index, _)| index)
            .expect("the index assignment");
        for raw in ['<', '>', '&', '\u{2028}', '\u{2029}'] {
            assert!(
                !index.contains(raw),
                "{raw:?} reached the index raw: {index}"
            );
        }
        let parsed: serde_json::Value = serde_json::from_str(index).expect("valid JSON");
        let decoded = parsed
            .get(0)
            .and_then(|entry| entry.get("title"))
            .and_then(serde_json::Value::as_str);
        assert_eq!(decoded, Some(title));
    }

    /// The Diagnostics page explains every code letter, from the family table.
    #[test]
    fn diagnostics_page_explains_every_code_family() {
        let page = render_diagnostic_index(&DocBundle::empty(), "");
        for row in ipe_diagnostics::FAMILIES {
            assert!(
                page.contains(&format!("<dt><code>{}</code></dt>", row.letter)),
                "family {} missing:\n{page}",
                row.letter
            );
            assert!(page.contains(&html::escape(row.summary)), "{page}");
        }
    }

    /// A member key routes to the lookup, whatever the case of the module path.
    #[test]
    fn a_member_key_is_a_symbol_key() {
        assert!(is_symbol_key("Ipe.Time.unixMillis"));
        assert!(is_symbol_key("List.map"));
        assert!(!is_symbol_key("Ipe.List"));
        assert!(!is_symbol_key("List"));
        assert!(matches!(
            parse_doc(&s(&["Ipe.Time.unixMillis"])),
            Ok(DocMode::Lookup { .. })
        ));
    }

    #[test]
    fn module_name_grammar_refuses_host_path_spellings() {
        assert!(is_module_name("Ipe.List"));
        assert!(is_module_name("List"));
        assert!(!is_module_name("D:\\pkg"));
        assert!(!is_module_name("Users/alice/pkg"));
        assert!(!is_module_name("\\\\?\\D:\\pkg"));
        assert!(!is_module_name(""));
        assert!(!is_module_name("Ipe."));
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn parse_bare_is_generate_with_defaults() {
        let m = parse_doc(&[]).expect("empty doc");
        assert_eq!(
            m,
            DocMode::Generate {
                path: PathBuf::from("."),
                out: PathBuf::from("doc"),
                write_format: WriteFormat::All,
            }
        );
    }

    #[test]
    fn parse_generate_takes_path_and_out() {
        let m = parse_doc(&s(&["pkg", "--out", "site"])).expect("generate");
        assert_eq!(
            m,
            DocMode::Generate {
                path: PathBuf::from("pkg"),
                out: PathBuf::from("site"),
                write_format: WriteFormat::All,
            }
        );
    }

    #[test]
    fn parse_write_format_selects_a_single_rendering() {
        let m = parse_doc(&s(&["--write-format", "html"])).expect("write-format html");
        assert_eq!(
            m,
            DocMode::Generate {
                path: PathBuf::from("."),
                out: PathBuf::from("doc"),
                write_format: WriteFormat::Html,
            }
        );
    }

    #[test]
    fn parse_rejects_unknown_write_format() {
        assert!(matches!(
            parse_doc(&s(&["--write-format", "pdf"])),
            Err(CliError::Usage(_))
        ));
    }

    #[test]
    fn parse_list_flag_returns_list_mode() {
        let m = parse_doc(&s(&["--list"])).expect("list");
        assert!(matches!(m, DocMode::List { .. }));
    }

    #[test]
    fn parse_list_flag_with_plain() {
        let m = parse_doc(&s(&["--list", "--plain"])).expect("list plain");
        assert!(matches!(
            m,
            DocMode::List {
                format: OutputFormat::Plain,
                ..
            }
        ));
    }

    #[test]
    fn parse_list_flag_with_json() {
        let m = parse_doc(&s(&["--list", "--json"])).expect("list json");
        assert!(matches!(
            m,
            DocMode::List {
                format: OutputFormat::Json,
                ..
            }
        ));
    }

    #[test]
    fn parse_bare_list_word_returns_list_mode() {
        let m = parse_doc(&s(&["list"])).expect("list");
        assert!(matches!(m, DocMode::List { .. }));
    }

    #[test]
    fn parse_bare_list_word_with_plain_and_json() {
        let plain = parse_doc(&s(&["list", "--plain"])).expect("list plain");
        assert!(matches!(
            plain,
            DocMode::List {
                format: OutputFormat::Plain,
                ..
            }
        ));
        let json = parse_doc(&s(&["list", "--json"])).expect("list json");
        assert!(matches!(
            json,
            DocMode::List {
                format: OutputFormat::Json,
                ..
            }
        ));
    }

    #[test]
    fn deprecated_list_flag_still_dispatches_and_warns() {
        // The `--list` alias must keep selecting `list` (never-break-users) while
        // emitting a one-time notice steering the caller to the bare word.
        let mut notices: Vec<String> = Vec::new();
        let m = parse_doc_with(&s(&["--list", "--plain"]), &mut |msg| {
            notices.push(msg.to_owned());
        })
        .expect("deprecated --list");
        assert!(matches!(
            m,
            DocMode::List {
                format: OutputFormat::Plain,
                ..
            }
        ));
        assert_eq!(
            notices.len(),
            1,
            "exactly one deprecation notice: {notices:?}"
        );
        let note = notices.first().map(String::as_str).unwrap_or_default();
        assert!(
            note.contains("--list") && note.contains("deprecated") && note.contains("doc list"),
            "the notice names the deprecated flag and its replacement: {note}"
        );
    }

    #[test]
    fn bare_list_word_emits_no_deprecation_notice() {
        let mut notices: Vec<String> = Vec::new();
        let _ = parse_doc_with(&s(&["list"]), &mut |msg| notices.push(msg.to_owned()))
            .expect("bare list");
        assert!(
            notices.is_empty(),
            "bare `list` is not deprecated: {notices:?}"
        );
    }

    #[test]
    fn parse_module_query_returns_query_mode() {
        let m = parse_doc(&s(&["Ipe.List"])).expect("query Ipe.List");
        assert_eq!(
            m,
            DocMode::Query {
                module: "Ipe.List".to_owned(),
                format: OutputFormat::Human,
            }
        );
    }

    #[test]
    fn parse_module_query_with_plain() {
        let m = parse_doc(&s(&["Ipe.String", "--plain"])).expect("query plain");
        assert_eq!(
            m,
            DocMode::Query {
                module: "Ipe.String".to_owned(),
                format: OutputFormat::Plain,
            }
        );
    }

    #[test]
    fn parse_module_query_with_json() {
        let m = parse_doc(&s(&["Ipe.Http", "--json"])).expect("query json");
        assert_eq!(
            m,
            DocMode::Query {
                module: "Ipe.Http".to_owned(),
                format: OutputFormat::Json,
            }
        );
    }

    #[test]
    fn a_module_name_is_still_a_query() {
        // The grammar tightening must not regress a legitimate module query.
        let m = parse_doc(&s(&["Ipe.List"])).expect("module name positional");
        assert_eq!(
            m,
            DocMode::Query {
                module: "Ipe.List".to_owned(),
                format: OutputFormat::Human,
            }
        );
    }

    #[test]
    fn a_drive_path_positional_selects_generate() {
        // Without the grammar check, the uppercase drive letter alone used to
        // route this to `Sub::Query("D:\\pkg")`.
        let m = parse_doc(&s(&["D:\\pkg"])).expect("drive path positional");
        assert_eq!(
            m,
            DocMode::Generate {
                path: PathBuf::from("D:\\pkg"),
                out: PathBuf::from("doc"),
                write_format: WriteFormat::All,
            }
        );
    }

    #[test]
    fn a_separator_path_is_never_a_module_query() {
        let m = parse_doc(&s(&["Users/alice/pkg"])).expect("separator path positional");
        assert!(
            !matches!(m, DocMode::Query { .. }),
            "a separator positional must never be a module query: {m:?}"
        );
        assert_eq!(
            m,
            DocMode::Generate {
                path: PathBuf::from("Users/alice/pkg"),
                out: PathBuf::from("doc"),
                write_format: WriteFormat::All,
            }
        );
    }

    #[test]
    fn host_path_syntax_detection_covers_separators_and_drive_colon() {
        assert!(has_host_path_syntax("src/x"));
        assert!(has_host_path_syntax("d:\\pkg"));
        assert!(has_host_path_syntax("D:\\pkg"));
        assert!(!has_host_path_syntax("list"));
        assert!(!has_host_path_syntax("Ipe.List"));
    }

    #[test]
    fn a_lowercase_drive_path_is_never_a_lookup_key() {
        // A lowercase drive letter must not read as a content-index lookup
        // key either — host-path syntax rules out `Sub::Lookup` whatever the
        // case, the same way it rules out `Sub::Query` for uppercase paths.
        let m = parse_doc(&s(&["d:\\pkg"])).expect("lowercase drive path positional");
        assert!(
            !matches!(m, DocMode::Lookup { .. }),
            "a drive-colon positional must never be a lookup key: {m:?}"
        );
        assert_eq!(
            m,
            DocMode::Generate {
                path: PathBuf::from("d:\\pkg"),
                out: PathBuf::from("doc"),
                write_format: WriteFormat::All,
            }
        );
    }

    #[test]
    fn a_lowercase_separator_path_is_never_a_lookup_key() {
        let m = parse_doc(&s(&["src/x"])).expect("lowercase separator path positional");
        assert!(
            !matches!(m, DocMode::Lookup { .. }),
            "a separator positional must never be a lookup key: {m:?}"
        );
        assert_eq!(
            m,
            DocMode::Generate {
                path: PathBuf::from("src/x"),
                out: PathBuf::from("doc"),
                write_format: WriteFormat::All,
            }
        );
    }

    #[test]
    fn parse_serve_auto_selects_port() {
        let m = parse_doc(&s(&["serve", "pkg"])).expect("serve");
        assert_eq!(
            m,
            DocMode::Serve {
                path: PathBuf::from("pkg"),
                port: None,
            }
        );
    }

    #[test]
    fn parse_serve_pins_a_port() {
        let m = parse_doc(&s(&["serve", "--port", "8080"])).expect("serve port");
        assert_eq!(
            m,
            DocMode::Serve {
                path: PathBuf::from("."),
                port: Some(8080),
            }
        );
    }

    #[test]
    fn serve_rejects_generate_flags() {
        // `--write-format`/`--out` are meaningless when serving HTML —
        // unrepresentable in `DocMode::Serve`, so rejected at the boundary.
        assert!(parse_doc(&s(&["serve", "--write-format", "json"])).is_err());
        assert!(parse_doc(&s(&["serve", "--out", "x"])).is_err());
    }

    #[test]
    fn generate_rejects_port_flag() {
        // `--port` has no meaning without a server; unrepresentable in Generate.
        assert!(parse_doc(&s(&["--port", "8080"])).is_err());
    }

    #[test]
    fn serve_rejects_malformed_port() {
        assert!(parse_doc(&s(&["serve", "--port", "nope"])).is_err());
        assert!(parse_doc(&s(&["serve", "--port", "0"])).is_err());
    }

    #[test]
    fn parse_check_takes_path() {
        let m = parse_doc(&s(&["check", "pkg"])).expect("check");
        assert_eq!(
            m,
            DocMode::Check {
                path: PathBuf::from("pkg"),
            }
        );
    }

    #[test]
    fn parse_check_defaults_path_to_cwd() {
        let m = parse_doc(&s(&["check"])).expect("check default");
        assert_eq!(
            m,
            DocMode::Check {
                path: PathBuf::from(".")
            }
        );
    }

    #[test]
    fn check_rejects_out_flag() {
        // `--out` is meaningless under check — and unrepresentable in `DocMode`,
        // so it is rejected at the boundary, not silently ignored.
        assert!(matches!(
            parse_doc(&s(&["check", "--out", "x"])),
            Err(CliError::Usage(_))
        ));
    }

    #[test]
    fn generate_rejects_duplicate_out() {
        assert!(parse_doc(&s(&["--out", "a", "--out", "b"])).is_err());
    }

    #[test]
    fn generate_rejects_missing_out_value() {
        assert!(parse_doc(&s(&["--out"])).is_err());
    }

    #[test]
    fn rejects_unknown_flag() {
        assert!(matches!(
            parse_doc(&s(&["--bogus"])),
            Err(CliError::Usage(_))
        ));
    }

    #[test]
    fn rejects_second_positional() {
        assert!(parse_doc(&s(&["a", "b"])).is_err());
    }

    /// Every value a compiled-source stdlib module exposes reaches the `ipe doc`
    /// surface with its checker signature and the doc-comment the shared
    /// extractor reads — a kernel alias included, and either comment form.
    #[test]
    fn compiled_stdlib_values_carry_signature_and_shared_comment() {
        let mut gaps = Vec::new();
        for module in ipe_stdlib::COMPILED_STD_MODULES {
            let segments: Vec<String> = module.dotted.split('.').map(str::to_owned).collect();
            let doc = build_compiled_std_module_doc(&segments, module.source);
            let shared = ipe_docs::stdlib_docs::extract_module_doc(module.dotted, module.source);
            for export in &shared.exports {
                if !export.name.starts_with(|c: char| c.is_ascii_lowercase()) {
                    continue;
                }
                let Some(value) = doc.values.iter().find(|v| v.name == export.name) else {
                    gaps.push(format!("{}.{}: missing", module.dotted, export.name));
                    continue;
                };
                if value.signature.is_empty() {
                    gaps.push(format!("{}.{}: no signature", module.dotted, export.name));
                }
                if value.comment != export.doc.as_deref().unwrap_or_default() {
                    gaps.push(format!(
                        "{}.{}: comment differs",
                        module.dotted, export.name
                    ));
                }
            }
        }
        assert!(
            gaps.is_empty(),
            "stdlib values off the doc surface:\n{}",
            gaps.join("\n")
        );
    }

    #[test]
    fn scans_block_doc_comments() {
        let src = "module M exposing (foo)\n\n{-| The foo value.\n\n```ipe\nfoo --> 1\n```\n-}\nfoo : Int\nfoo = 1\n";
        let comments = scan_doc_comments(src);
        assert_eq!(
            comments.get("foo").as_deref(),
            Some("The foo value.\n\n```ipe\nfoo --> 1\n```")
        );
    }

    #[test]
    fn scans_module_and_binding_comments() {
        let src = "-- | The module.\nmodule M exposing (foo)\n\n\
                   -- | The foo value.\n-- more foo.\nfoo : Int\nfoo = 1\n";
        let comments = scan_doc_comments(src);
        assert_eq!(comments.module, "The module.");
        assert_eq!(
            comments.get("foo").as_deref(),
            Some("The foo value.\nmore foo.")
        );
    }

    #[test]
    fn scans_type_and_alias_names() {
        let union = scan_doc_comments("-- | A color.\ntype Color = Red | Blue\n");
        assert_eq!(union.get("Color").as_deref(), Some("A color."));
        let alias = scan_doc_comments("-- | A name.\ntype alias Name = String\n");
        assert_eq!(alias.get("Name").as_deref(), Some("A name."));
    }

    #[test]
    fn undocumented_binding_has_empty_comment() {
        let comments = scan_doc_comments("module M exposing (foo)\nfoo : Int\nfoo = 1\n");
        assert!(comments.get("foo").is_none());
        assert!(comments.module.is_empty());
    }

    #[test]
    fn json_escapes_control_and_quote() {
        assert_eq!(json_string("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\"");
    }

    #[test]
    fn doc_entry_json_escapes_control_bytes_and_parses() {
        // A diagnostic/symbol `text` is a multi-line body carrying raw `\n` and
        // C0 control bytes; the `ipe doc <key> --json` surface must escape them so
        // the output round-trips through a strict JSON parser (RFC 8259) rather
        // than leaking a raw U+000A that a serde/`jq` consumer rejects.
        let text = "line one\nline two\u{1}tail";
        let entry = ipe_docs::Entry {
            kind: ipe_docs::EntryKind::Diagnostic,
            source_key: "IPE-L0107".to_owned(),
            text: text.to_owned(),
        };
        let rendered = render_doc_entry_json(&entry);
        // No raw control byte survives on the wire: the only newline is the
        // trailing record separator this renderer appends.
        assert_eq!(rendered.matches('\n').count(), 1);
        assert!(rendered.ends_with('\n'));
        assert!(!rendered.trim_end_matches('\n').contains('\n'));
        let value: serde_json::Value =
            serde_json::from_str(&rendered).expect("--json output must be valid JSON");
        assert_eq!(
            value.get("kind").and_then(serde_json::Value::as_str),
            Some("diagnostic")
        );
        assert_eq!(
            value.get("key").and_then(serde_json::Value::as_str),
            Some("IPE-L0107")
        );
        assert_eq!(
            value.get("text").and_then(serde_json::Value::as_str),
            Some(text)
        );
    }

    /// A resolved type-constructor `TyDoc`, e.g. `con("M", "Color", [])`.
    fn con(module: &str, name: &str, args: Vec<TyDoc>) -> TyDoc {
        TyDoc::Con {
            module: module.into(),
            name: name.into(),
            args: args.into_boxed_slice(),
        }
    }

    /// A one-module package documenting a `Color` type and a `paint` value whose
    /// signature mentions both the in-package `Color` and the built-in `Int`.
    fn color_module() -> ModuleDoc {
        ModuleDoc {
            name: "M".to_owned(),
            kind: ModuleKind::Local,
            comment: "A module.".to_owned(),
            unions: vec![UnionDoc {
                name: "Color".to_owned(),
                params: 0,
                ctors: vec![CtorDoc {
                    name: "Red".to_owned(),
                    args: vec![],
                    arg_types: vec![],
                }],
                comment: "A color.".to_owned(),
            }],
            values: vec![ValueDoc {
                name: "paint".to_owned(),
                signature: "M.Color -> Int".to_owned(),
                // `M.Color` is in-package (links); `Int` is a built-in (plain).
                signature_ty: TyDoc::Fun(
                    Box::new(con("M", "Color", vec![])),
                    Box::new(con("", "Int", vec![])),
                ),
                comment: "The paint.".to_owned(),
            }],
        }
    }

    fn one_module_docs(module: ModuleDoc) -> DocsJson {
        DocsJson {
            version: DOCS_JSON_VERSION,
            modules: vec![module],
            disclosure: None,
        }
    }

    #[test]
    fn markdown_renders_module_values_and_types() {
        let module = color_module();
        let docs = one_module_docs(color_module());
        let index = AnchorIndex::build(&docs);
        let md = render_markdown(&module, &index);
        assert!(md.contains("# M"));
        assert!(md.contains("A module."));
        assert!(md.contains("### `Color`"));
        assert!(md.contains("- `Red`"));
        assert!(md.contains("### `paint`"));
        assert!(md.contains("The paint."));
    }

    #[test]
    fn cross_reference_links_in_package_type_and_not_a_builtin() {
        let module = color_module();
        let docs = one_module_docs(color_module());
        let index = AnchorIndex::build(&docs);
        let value = module.values.first().expect("one value");
        let pieces = signature_pieces(&value.signature_ty, &index);

        // `M.Color` resolves in-package → a link to its anchor.
        let linked: Vec<&TypeRef> = pieces
            .iter()
            .filter_map(|p| match p {
                SigPiece::Link { target, .. } => Some(target),
                SigPiece::Text(_) => None,
            })
            .collect();
        assert_eq!(linked.len(), 1, "exactly the in-package type links");
        let only = linked.first().expect("one linked type");
        assert_eq!(only.anchor(), "M#Color");
        assert_eq!(only.href("html"), "M.html#Color");

        // The whole rendered text still reads as the signature, `Int` inline.
        let html = html_signature(&pieces);
        assert!(
            html.contains("<a href=\"M.html#Color\">M.Color</a>"),
            "{html}"
        );
        assert!(
            html.contains("-&gt; Int"),
            "the builtin stays plain: {html}"
        );
        assert!(
            !html.contains(">Int</a>"),
            "no link is emitted for a builtin"
        );
    }

    #[test]
    fn json_records_the_cross_reference() {
        let docs = one_module_docs(color_module());
        let json = render_json(&docs);
        assert!(json.contains("\"anchor\": \"M#Color\""), "{json}");
        // The built-in `Int` produces no reference entry.
        assert!(!json.contains("\"name\": \"Int\""), "{json}");
    }

    #[test]
    fn html_index_and_module_pages_are_self_contained() {
        let module = color_module();
        let docs = one_module_docs(color_module());
        let index = AnchorIndex::build(&docs);
        let bundle = crate::doc_bundle::DocBundle::empty();
        let search_script = build_site_search_script(&docs, &bundle, "");

        let idx = render_html_index(&docs, &bundle, &search_script);
        assert!(idx.contains("<!DOCTYPE html>"));
        assert!(idx.contains("href=\"style.css\""), "links the bundled CSS");
        // The header is present on the landing page with all nav links.
        assert!(
            idx.contains("module/index.html"),
            "reference link present: {idx}"
        );
        assert!(
            idx.contains("nav-search"),
            "the nav search box is present: {idx}"
        );

        let page = render_html_module(&module, &index, &search_script);
        assert!(
            page.contains("id=\"Color\""),
            "the type has a stable anchor"
        );
        assert!(
            page.contains("id=\"paint\""),
            "the value has a stable anchor"
        );
        assert!(
            page.contains("<a href=\"M.html#Color\">M.Color</a>"),
            "the in-package type links: {page}"
        );
        // Module page carries the persistent header.
        assert!(
            page.contains("module/index.html"),
            "module page has reference link: {page}"
        );
    }

    /// A minimal stdlib-kind module for ordering/labelling tests.
    fn stdlib_module(name: &str) -> ModuleDoc {
        ModuleDoc {
            name: name.to_owned(),
            kind: ModuleKind::Stdlib,
            comment: String::new(),
            unions: Vec::new(),
            values: Vec::new(),
        }
    }

    /// A minimal local-kind module for ordering/labelling tests.
    fn local_module(name: &str) -> ModuleDoc {
        ModuleDoc {
            name: name.to_owned(),
            kind: ModuleKind::Local,
            comment: String::new(),
            unions: Vec::new(),
            values: Vec::new(),
        }
    }

    #[test]
    fn reference_index_groups_local_before_stdlib_with_section_labels() {
        // Feed both kinds; the reference index presents them in their section order.
        let docs = DocsJson {
            version: DOCS_JSON_VERSION,
            modules: vec![local_module("App"), stdlib_module("Ipe.List")],
            disclosure: None,
        };
        let bundle = crate::doc_bundle::DocBundle::empty();
        let search_script = build_site_search_script(&docs, &bundle, "../");
        let idx = render_reference_index(&docs, &search_script);

        // Both section labels render.
        assert!(
            idx.contains(crate::text::site_project_modules()),
            "project label: {idx}"
        );
        assert!(
            idx.contains(crate::text::site_standard_library()),
            "stdlib label: {idx}"
        );
        // The project section precedes the standard-library section.
        let p = idx
            .find(crate::text::site_project_modules())
            .expect("project label present");
        let s = idx
            .find(crate::text::site_standard_library())
            .expect("stdlib label present");
        assert!(p < s, "project section comes first: {idx}");
        // The reference index lists the module with a link to its page.
        assert!(idx.contains("App.html"), "App module linked: {idx}");
    }

    /// A module name or a curated key holding a quote cannot close the `href`
    /// attribute on the reference index, a curated kind index, or the landing.
    #[test]
    fn index_hrefs_escape_key_quotes() {
        let docs = one_module_docs(local_module("A\"B"));
        let mut bundle = crate::doc_bundle::DocBundle::empty();
        bundle
            .insert(
                crate::doc_bundle::DocKind::Guide,
                "g\"k".to_owned(),
                "Guide".to_owned(),
                String::new(),
            )
            .expect("insert");
        let search = build_site_search_script(&docs, &bundle, "../");

        let reference = render_reference_index(&docs, &search);
        assert!(
            reference.contains("href=\"../A&quot;B.html\""),
            "reference index href: {reference}"
        );

        let curated = render_curated_kind_indexes(&bundle, &search);
        let guides = curated.get("guide/index.html").expect("guide index");
        assert!(
            guides.contains("href=\"../guide/g&quot;k.html\""),
            "guide index href: {guides}"
        );

        let landing = render_html_index(&docs, &bundle, &search);
        assert!(
            landing.contains("href=\"guide/g&quot;k.html\""),
            "landing href: {landing}"
        );
    }

    #[test]
    fn html_style_is_soft_dark_with_accent_and_multicolumn_module_list() {
        // The accent custom property is defined once in :root.
        assert!(STYLE_CSS.contains("--accent:"), "accent var: {STYLE_CSS}");
        // The module index lays out in responsive multi-column form.
        assert!(
            STYLE_CSS.contains("columns:"),
            "multi-column module list: {STYLE_CSS}"
        );
        // A soft dark background, not pure black.
        assert!(
            STYLE_CSS.contains("--bg:") && !STYLE_CSS.contains("--bg: #000"),
            "soft (non-pure-black) background: {STYLE_CSS}"
        );
        // It collapses to one column on a narrow viewport.
        assert!(
            STYLE_CSS.contains("columns: 1"),
            "collapses to one column when narrow: {STYLE_CSS}"
        );
    }

    #[test]
    fn json_records_the_module_kind() {
        let docs = DocsJson {
            version: DOCS_JSON_VERSION,
            modules: vec![local_module("App"), stdlib_module("Ipe.List")],
            disclosure: None,
        };
        let json = render_json(&docs);
        assert!(json.contains("\"kind\": \"local\""), "{json}");
        assert!(json.contains("\"kind\": \"stdlib\""), "{json}");
        // Local precedes stdlib in the serialized order.
        let l = json.find("\"kind\": \"local\"").expect("local kind");
        let s = json.find("\"kind\": \"stdlib\"").expect("stdlib kind");
        assert!(l < s, "the model is serialized local-first: {json}");
    }

    #[test]
    fn json_render_with_disclosure_emits_the_audit_vocabulary() {
        // The `ipe doc` JSON surfaces the SAME control-model word + capability
        // vocabulary `ipe audit` discloses. A `direct` entry that reaches the
        // network discloses exactly that.
        let docs = DocsJson {
            version: DOCS_JSON_VERSION,
            modules: vec![local_module("App")],
            disclosure: Some(PackageDisclosure {
                control_model: "direct".to_owned(),
                capabilities: vec!["network".to_owned(), "filesystem".to_owned()],
            }),
        };
        let json = render_json(&docs);
        assert!(
            json.contains("\"disclosure\": {"),
            "the disclosure object is present: {json}"
        );
        assert!(
            json.contains("\"controlModel\": \"direct\""),
            "the control model uses the audit's word: {json}"
        );
        assert!(
            json.contains("\"capabilities\": [\"network\", \"filesystem\"]"),
            "the capability axes are the audit's words in order: {json}"
        );
    }

    #[test]
    fn json_render_without_disclosure_omits_the_object() {
        // A stdlib-only render (no project) discloses nothing — the object is
        // absent, never a permissive placeholder.
        let docs = DocsJson {
            version: DOCS_JSON_VERSION,
            modules: vec![stdlib_module("Ipe.List")],
            disclosure: None,
        };
        let json = render_json(&docs);
        assert!(
            !json.contains("\"disclosure\""),
            "no project ⇒ no disclosure object: {json}"
        );
    }

    #[test]
    fn html_escapes_markup_in_names_and_comments() {
        assert_eq!(html::escape("a<b>&\"'"), "a&lt;b&gt;&amp;&quot;&#39;");
    }

    #[test]
    fn render_comment_indented_block_preserves_relative_indentation() {
        let comment = "    line_a\n        line_b";
        let html = render_comment_html(comment);
        assert!(html.contains("<pre class=\"doc-code\"><code>"), "{html}");
        assert!(html.contains("line_a\n    line_b"), "{html}");
    }

    #[test]
    fn render_comment_inline_backtick_becomes_code_element() {
        let comment = "Call `foo` here.";
        let html = render_comment_html(comment);
        assert!(html.contains("<code>foo</code>"), "{html}");
        assert!(html.contains("<p class=\"comment\">"), "{html}");
    }

    #[test]
    fn render_comment_fenced_block_renders_in_pre_without_delimiters() {
        let comment = "Example:\n```ipe\nfoo =\n    bar\n```\nEnd.";
        let html = render_comment_html(comment);
        assert!(html.contains("<pre class=\"doc-code\"><code>"), "{html}");
        assert!(html.contains("foo =\n    bar"), "{html}");
        assert!(!html.contains("```"), "{html}");
        assert!(html.contains("End."), "{html}");
    }

    #[test]
    fn render_comment_atx_heading_becomes_nested_heading() {
        let html = render_comment_html("# Top\n\n## Sub\n\nbody");
        // A page-body heading nests under the page's own h1/h2 chrome, so `#`
        // becomes `<h3>` and `##` becomes `<h4>`; never a literal `#`.
        assert!(html.contains("<h3>Top</h3>"), "{html}");
        assert!(html.contains("<h4>Sub</h4>"), "{html}");
        assert!(!html.contains("# "), "no raw ATX marker survives: {html}");
    }

    #[test]
    fn render_comment_link_becomes_anchor() {
        let html = render_comment_html("See [the docs](guide.html) now.");
        assert!(
            html.contains("<a href=\"guide.html\">the docs</a>"),
            "{html}"
        );
        assert!(!html.contains("]("), "no raw link markup survives: {html}");
    }

    #[test]
    fn render_comment_emphasis_becomes_strong_and_em() {
        // `**`/`*` are the only emphasis markers the `Ipe.Markdown` parse SSOT
        // recognises; `_` is literal text (rendered verbatim, never `<em>`).
        let html = render_comment_html("A **bold** and an *italic* and an _under_.");
        assert!(html.contains("<strong>bold</strong>"), "{html}");
        assert!(html.contains("<em>italic</em>"), "{html}");
        assert!(
            !html.contains("<em>under</em>"),
            "underscore is not emphasis: {html}"
        );
        assert!(html.contains("_under_"), "underscore stays literal: {html}");
    }

    #[test]
    fn render_comment_table_becomes_html_table() {
        let html = render_comment_html("| A | B |\n|---|---|\n| 1 | 2 |");
        assert!(html.contains("<table class=\"doc-table\">"), "{html}");
        assert!(html.contains("<th>A</th>"), "{html}");
        assert!(html.contains("<td>1</td>"), "{html}");
        // The `|---|` separator row is consumed, never emitted as a data row.
        assert!(!html.contains("---"), "separator row dropped: {html}");
    }

    #[test]
    fn render_comment_rejects_javascript_link_scheme() {
        // A `javascript:` target must not become an executable link; it stays
        // literal text (fail-closed).
        let html = render_comment_html("[x](javascript:alert(1))");
        assert!(
            !html.contains("href=\"javascript:"),
            "javascript scheme must not become an anchor: {html}"
        );
    }

    #[test]
    fn render_comment_malformed_link_is_never_a_live_anchor() {
        // The fail-closed guarantee that matters: a malformed `[x](y …` (no
        // closing paren) never becomes a live anchor, and every byte stays
        // HTML-escaped — no markup can be injected. Under the `Ipe.Markdown`
        // parse SSOT an unclosed `*`/`` ` `` degrades gracefully by consuming to
        // end (inert emphasis/code), which is harmless; the security property is
        // the absence of any `href`, not the absence of formatting tags.
        let html = render_comment_html("a * b and [x](y and `z");
        assert!(
            !html.contains("<a "),
            "malformed link is not an anchor: {html}"
        );
        assert!(!html.contains("href="), "no href emitted at all: {html}");
        assert!(!html.contains("<script"), "no injected markup: {html}");
    }

    #[test]
    fn render_comment_indented_multiline_example_stays_one_code_block() {
        // A stdlib-style four-space-indented example (blank lines between its
        // lines) is normalised to a single fenced block before the SSOT parser
        // runs, so it renders as one `<pre>` code block, not run-together prose.
        let comment = "Intro line:\n\n    foo : Int\n    foo =\n        1\n\nOutro.";
        let html = render_comment_html(comment);
        assert!(
            html.contains("<pre class=\"doc-code\">"),
            "indented example must render as a code block: {html}"
        );
        assert!(html.contains("foo : Int"), "code body preserved: {html}");
        assert!(html.contains("Outro."), "trailing prose preserved: {html}");
        // The four-space markers are stripped, never emitted as literal indent.
        assert!(!html.contains("    foo : Int"), "marker stripped: {html}");
    }

    #[test]
    fn fence_indented_code_does_not_fire_inside_a_list() {
        // A four-space continuation under a bullet is list content, not a code
        // block: the normaliser must leave it for the SSOT list parser.
        let out = super::fence_indented_code("- item one\n    still the item\n- item two");
        assert!(
            !out.contains("```"),
            "list continuation must not become a fence: {out:?}"
        );
    }

    #[test]
    fn fence_indented_code_leaves_author_fences_untouched() {
        // Content already inside an author ```` ``` ```` fence is copied verbatim,
        // even when a line happens to be four-space indented.
        let src = "```\n    indented in fence\n```";
        assert_eq!(
            super::fence_indented_code(src),
            "```\n    indented in fence\n```\n"
        );
    }

    /// The HTML command page renders the same command metadata as
    /// `ipe <command>`'s help: the two are projected from the one `COMMANDS`
    /// table in `help.rs`, so a page can never advertise a flag or argument the
    /// terminal help omits.
    #[test]
    fn html_command_page_mirrors_command_help_ssot() {
        let verb = crate::verb::Verb::DEV_BUILD;
        let command = verb.help_key();
        let markdown = crate::help::command_doc_markdown(command).expect("dev build has help");
        let entry = crate::doc_bundle::DocEntry {
            kind: crate::doc_bundle::DocKind::Cli,
            key: command.to_owned(),
            title: crate::help::command_summary(command).unwrap().to_owned(),
            body: markdown,
            order: None,
        };
        let html = render_entry_page(crate::doc_bundle::DocKind::Cli, &entry, "");

        // Every option flag and its description from the SSOT appears on the page.
        let mut seen = false;
        for spec in crate::help::all_command_specs() {
            if spec.name != verb.name() {
                continue;
            }
            seen = true;
            for opt in &spec.options {
                assert!(
                    html.contains(&html::escape(opt.flag)),
                    "HTML command page omits flag {} from the help SSOT",
                    opt.flag
                );
            }
        }
        assert!(seen, "no command spec is named {verb}");
        // The synopsis and the Arguments/Options headings are present.
        assert!(html.contains("ipe dev build"), "synopsis present: {html}");
        assert!(html.contains("Arguments"), "arguments section present");
        assert!(html.contains("Options"), "options section present");
        // No raw Markdown leaks through the renderer.
        assert!(!html.contains("## "), "no raw ATX heading survives");
    }

    /// `ipe doc serve` and `ipe doc --write-format html` are two views over one
    /// site model: the HTML each surface produces is byte-identical, so a fix to
    /// the engine fixes both at once.
    #[test]
    fn serve_html_matches_write_format_html_byte_for_byte() {
        let docs = build_stdlib_only_docs();
        let bundle = build_doc_bundle(&locate_docs_root()).expect("bundle builds");
        let (_json, _md, split_html) = render_site_split(&docs, &bundle, WriteFormat::Html);
        let serve_html = render_site_for_serve(&docs, &bundle);
        assert_eq!(
            split_html, serve_html,
            "serve and write-format html must produce an identical site map"
        );
    }

    #[test]
    fn serve_file_name_maps_root_and_strips_query() {
        assert_eq!(serve_file_name("/"), "index.html");
        assert_eq!(serve_file_name(""), "index.html");
        assert_eq!(serve_file_name("/M.html"), "M.html");
        assert_eq!(serve_file_name("/style.css?v=1"), "style.css");
        // A traversal attempt is just a filename that misses the flat map.
        assert_eq!(serve_file_name("/../etc/passwd"), "../etc/passwd");
    }

    #[test]
    fn http_response_has_length_and_close() {
        let r = http_response("200 OK", "text/html; charset=utf-8", "hi");
        assert!(r.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(r.contains("Content-Length: 2\r\n"));
        assert!(r.contains("Connection: close\r\n"));
        assert!(r.ends_with("\r\n\r\nhi"));
    }

    // ── Per-format subfolder layout ────────────────────────────────────────

    #[test]
    fn render_site_split_writes_three_separate_maps() {
        let docs = DocsJson {
            version: DOCS_JSON_VERSION,
            modules: vec![local_module("App"), stdlib_module("Ipe.List")],
            disclosure: None,
        };
        let bundle = crate::doc_bundle::DocBundle::empty();
        let (json, markdown, html) = render_site_split(&docs, &bundle, WriteFormat::All);
        assert!(json.contains_key("docs.json"), "json map has docs.json");
        assert!(
            markdown.contains_key("index.md"),
            "markdown map has index.md"
        );
        assert!(
            markdown.contains_key("App.md"),
            "markdown map has module page"
        );
        assert!(
            markdown.contains_key("Ipe-List.md"),
            "markdown map has stdlib page"
        );
        assert!(html.contains_key("index.html"), "html map has index.html");
        assert!(html.contains_key("style.css"), "html map has stylesheet");
        assert!(html.contains_key("App.html"), "html map has module page");
        // Per-kind index pages are included in the html map.
        assert!(
            html.contains_key("module/index.html"),
            "html map has reference index: {html:?}"
        );
        assert!(
            html.contains_key("diagnostic/index.html"),
            "html map has diagnostics index: {html:?}"
        );
        assert!(
            html.contains_key("cli/index.html"),
            "html map has cli index: {html:?}"
        );
    }

    #[test]
    fn render_site_split_json_only_omits_markdown_and_html() {
        let docs = one_module_docs(local_module("App"));
        let bundle = crate::doc_bundle::DocBundle::empty();
        let (json, markdown, html) = render_site_split(&docs, &bundle, WriteFormat::Json);
        assert!(json.contains_key("docs.json"));
        assert!(markdown.is_empty(), "no markdown for Json format");
        assert!(html.is_empty(), "no html for Json format");
    }

    #[test]
    fn render_site_split_markdown_only_omits_html() {
        let docs = one_module_docs(local_module("App"));
        let bundle = crate::doc_bundle::DocBundle::empty();
        let (json, markdown, html) = render_site_split(&docs, &bundle, WriteFormat::Markdown);
        assert!(json.contains_key("docs.json"));
        assert!(!markdown.is_empty());
        assert!(html.is_empty());
    }

    #[test]
    fn write_format_dir_creates_subfolder_and_writes_files() {
        use std::fs;
        let tmp = ipe_test_temp::temp_root().join(format!("ipe-doc-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let mut files = BTreeMap::new();
        files.insert("docs.json".to_owned(), "{\"v\":1}".to_owned());
        let site = crate::output_dir::OwnedDir::claim(&tmp).expect("claim site");
        write_format_dir(&site, "json", &files).expect("write_format_dir");
        let written = tmp.join("json").join("docs.json");
        assert!(written.exists(), "docs.json written under json/");
        let _ = fs::remove_dir_all(&tmp);
    }

    /// A doc site planted with a symlinked directory or file is refused.
    ///
    /// The link targets survive byte-for-byte.
    #[cfg(unix)]
    #[test]
    fn write_format_dir_refuses_planted_symlinks() {
        use std::fs;
        let tmp =
            ipe_test_temp::temp_root().join(format!("ipe-doc-symlink-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let victim = tmp.join("victim");
        fs::create_dir_all(&victim).expect("victim dir");
        fs::write(victim.join("docs.json"), "keep").expect("victim file");
        let site = crate::output_dir::OwnedDir::claim(&tmp.join("site")).expect("claim site");
        std::os::unix::fs::symlink(&victim, tmp.join("site").join("json")).expect("dir link");
        fs::create_dir_all(tmp.join("site").join("html")).expect("html dir");
        std::os::unix::fs::symlink(victim.join("docs.json"), tmp.join("site/html/index.html"))
            .expect("file link");

        let mut files = BTreeMap::new();
        files.insert("docs.json".to_owned(), "evil".to_owned());
        let dir_link = write_format_dir(&site, "json", &files);
        assert!(
            matches!(dir_link, Err(CliError::OutputRefused(_))),
            "a symlinked json/ must be refused, got {dir_link:?}"
        );
        let mut html = BTreeMap::new();
        html.insert("index.html".to_owned(), "evil".to_owned());
        let file_link = write_format_dir(&site, "html", &html);
        assert!(
            matches!(file_link, Err(CliError::OutputRefused(_))),
            "a symlinked page must be refused, got {file_link:?}"
        );
        assert_eq!(
            fs::read_to_string(victim.join("docs.json")).ok().as_deref(),
            Some("keep")
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    /// The inputs a successful project documentation build reports for `path`.
    fn tree(path: &Path) -> DocInputs {
        DocInputs::Tree(read_tree(path).expect("read module tree").root)
    }

    /// A site inside the module tree a documentation build read is refused.
    ///
    /// A manifest-less flat package is its own tree, so any site inside it is
    /// turned away; the same site beside a `src/` tree is claimed.
    #[test]
    fn claim_site_refuses_an_out_inside_the_read_module_tree() {
        use std::fs;
        let tmp = ipe_test_temp::temp_root().join(format!("ipe-doc-tree-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let flat = tmp.join("flat");
        fs::create_dir_all(&flat).expect("flat dir");
        fs::write(flat.join("Main.ipe"), "module Main exposing (..)\n").expect("module");

        let inputs = tree(&flat);
        assert!(
            matches!(&inputs, DocInputs::Tree(t) if t == &flat),
            "a flat package's tree is the package itself, got {inputs:?}"
        );
        let inside = claim_site(&flat, &inputs, &flat.join("doc"));
        assert!(
            matches!(
                inside,
                Err(CliError::OutputRefused(
                    crate::output_dir::OutputRefusal::InsideSources { .. }
                ))
            ),
            "a site inside the read module tree must be refused, got {inside:?}"
        );
        let hint = inside
            .as_ref()
            .err()
            .map(ToString::to_string)
            .unwrap_or_default();
        assert!(
            hint.contains("--out <dir>"),
            "the refusal names the way out, got {hint:?}"
        );
        assert!(!flat.join("doc").exists(), "nothing created on refusal");
        let nested = claim_site(&flat, &inputs, &flat.join("sub").join("doc"));
        assert!(
            matches!(nested, Err(CliError::OutputRefused(_))),
            "a deeper site inside the tree is refused too, got {nested:?}"
        );

        let pkg = tmp.join("pkg");
        fs::create_dir_all(pkg.join("src")).expect("src dir");
        fs::write(
            pkg.join("src").join("Main.ipe"),
            "module Main exposing (..)\n",
        )
        .expect("module");
        let beside = claim_site(&pkg, &tree(&pkg), &pkg.join("doc"));
        assert!(
            beside.is_ok(),
            "a site beside `src/` is claimed, got {beside:?}"
        );
        let in_src = claim_site(&pkg, &tree(&pkg), &pkg.join("src").join("doc"));
        assert!(
            matches!(in_src, Err(CliError::OutputRefused(_))),
            "a site inside `src/` is refused, got {in_src:?}"
        );
        assert_eq!(
            fs::read_to_string(flat.join("Main.ipe")).ok().as_deref(),
            Some("module Main exposing (..)\n")
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    /// A doc site overlapping the documented package is refused before any write.
    ///
    /// The package directory, a directory holding it, and a lone entry's own
    /// directory are each turned away; a site inside the package is claimed.
    #[test]
    fn claim_site_refuses_an_out_overlapping_the_package() {
        use std::fs;
        let tmp =
            ipe_test_temp::temp_root().join(format!("ipe-doc-overlap-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let pkg = tmp.join("pkg");
        fs::create_dir_all(pkg.join("src")).expect("src dir");
        fs::write(
            pkg.join("src").join("Main.ipe"),
            "module Main exposing (..)\n",
        )
        .expect("module");
        fs::write(pkg.join("keep.txt"), "keep").expect("user file");

        for out in [pkg.clone(), tmp.clone()] {
            let site = claim_site(&pkg, &tree(&pkg), &out);
            assert!(
                matches!(site, Err(CliError::OutputRefused(_))),
                "an out holding the package must be refused, got {site:?}"
            );
        }
        let lone = tmp.join("lone");
        fs::create_dir_all(&lone).expect("lone dir");
        let inside = claim_site(&lone.join("Main.ipe"), &DocInputs::StdlibOnly, &lone);
        assert!(
            matches!(inside, Err(CliError::OutputRefused(_))),
            "the entry's own directory must be refused, got {inside:?}"
        );
        assert_eq!(
            fs::read_to_string(pkg.join("keep.txt")).ok().as_deref(),
            Some("keep")
        );
        assert!(
            claim_site(&pkg, &tree(&pkg), &pkg.join("doc")).is_ok(),
            "a site inside the package is claimed"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    // ── Stdlib docs without a project ─────────────────────────────────────

    #[test]
    fn build_stdlib_only_docs_contains_known_modules() {
        let docs = build_stdlib_only_docs();
        let names: Vec<&str> = docs.modules.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"Ipe.List"), "Ipe.List in stdlib: {names:?}");
        assert!(
            names.contains(&"Ipe.String"),
            "Ipe.String in stdlib: {names:?}"
        );
        assert!(!docs.modules.is_empty(), "at least one module");
    }

    #[test]
    fn build_stdlib_only_docs_all_modules_are_stdlib_kind() {
        let docs = build_stdlib_only_docs();
        for m in &docs.modules {
            assert_eq!(
                m.kind,
                ModuleKind::Stdlib,
                "{} should be Stdlib kind",
                m.name
            );
        }
    }

    // ── Fallback is reserved for an empty tree, never a broken project ────────

    #[test]
    fn build_docs_or_stdlib_falls_back_on_empty_dir() {
        use std::fs;
        let tmp = ipe_test_temp::temp_root().join(format!("ipe-doc-empty-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).expect("create empty dir");

        let (docs, inputs) =
            build_docs_or_stdlib(&tmp).expect("empty dir falls back to stdlib-only");
        assert!(
            matches!(inputs, DocInputs::StdlibOnly),
            "no project tree was read"
        );
        assert!(
            docs.modules.iter().all(|m| m.kind == ModuleKind::Stdlib),
            "empty-dir fallback yields stdlib-only modules"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn build_docs_or_stdlib_propagates_a_broken_project() {
        use std::fs;
        let tmp = ipe_test_temp::temp_root().join(format!("ipe-doc-broken-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).expect("create project dir");
        // A syntactically broken module: a real project that must NOT collapse to
        // a plausible stdlib-only site.
        fs::write(tmp.join("Main.ipe"), "module Main exposing (..)\n\nx =\n")
            .expect("write broken module");

        let result = build_docs_or_stdlib(&tmp);
        assert!(
            result.is_err(),
            "a broken project surfaces its build error rather than falling back"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    /// An unreadable `src/` is a real I/O refusal, not a symlink cycle and not
    /// an empty-tree fallback — `ipe doc` must relay it as such.
    #[cfg(unix)]
    #[test]
    fn build_docs_or_stdlib_propagates_io_error_for_unreadable_src() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt as _;

        let tmp =
            ipe_test_temp::temp_root().join(format!("ipe-doc-unreadable-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let src = tmp.join("src");
        fs::create_dir_all(&src).expect("create src/");

        fs::set_permissions(&src, fs::Permissions::from_mode(0o000))
            .expect("chmod src/ unreadable");

        let result = build_docs_or_stdlib(&tmp);

        // Restore before any cleanup/assert: remove_dir_all must descend into src/.
        fs::set_permissions(&src, fs::Permissions::from_mode(0o755)).expect("restore perms");

        let Err(err) = result else {
            // Running privileged (e.g. root), a 0o000 mode never actually blocks
            // the read — there is no refusal to observe on this run.
            let _ = fs::remove_dir_all(&tmp);
            return;
        };
        assert!(
            matches!(
                &err,
                CliError::SourceRefused {
                    path,
                    reason: crate::io_bounded::SourceRefusal::AccessDenied,
                } if path == &src
            ),
            "an unreadable src/ must surface as the typed access-denied refusal naming it, got {err:?}"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    // ── Hierarchical namespace tree ────────────────────────────────────────

    #[test]
    fn namespace_tree_nests_children_under_shared_prefix() {
        let names = ["Ipe.Db", "Ipe.Db.Codec", "Ipe.Db.Store", "Ipe.List"];
        let tree = build_namespace_tree(&names);
        // Top level: Ipe (namespace only, has children)
        assert_eq!(tree.len(), 1, "one top-level node: Ipe");
        let ipe = tree.first().expect("one top-level Ipe node");
        assert_eq!(ipe.full_name, "Ipe");
        assert!(!ipe.is_module, "Ipe itself is not a module here");
        // Children of Ipe: Db, List
        let child_names: Vec<&str> = ipe.children.iter().map(|n| n.full_name.as_str()).collect();
        assert!(
            child_names.contains(&"Ipe.Db"),
            "Ipe.Db is a child: {child_names:?}"
        );
        assert!(
            child_names.contains(&"Ipe.List"),
            "Ipe.List is a child: {child_names:?}"
        );
        // Ipe.Db has children Codec and Store
        let db = ipe
            .children
            .iter()
            .find(|n| n.full_name == "Ipe.Db")
            .expect("Ipe.Db node");
        assert!(db.is_module, "Ipe.Db is itself a module");
        let db_children: Vec<&str> = db.children.iter().map(|n| n.full_name.as_str()).collect();
        assert!(
            db_children.contains(&"Ipe.Db.Codec"),
            "Codec nested: {db_children:?}"
        );
        assert!(
            db_children.contains(&"Ipe.Db.Store"),
            "Store nested: {db_children:?}"
        );
    }

    #[test]
    fn markdown_index_indents_submodule_two_spaces_under_parent() {
        let docs = DocsJson {
            version: DOCS_JSON_VERSION,
            modules: vec![
                stdlib_module("Ipe.Db"),
                stdlib_module("Ipe.Db.Codec"),
                stdlib_module("Ipe.Db.Store"),
                stdlib_module("Ipe.List"),
            ],
            disclosure: None,
        };
        let idx = render_markdown_index(&docs);
        // Ipe.Db.Codec must appear indented under Ipe.Db — two extra spaces.
        // In the tree: Ipe (depth 0) -> Ipe.Db (depth 1) -> Ipe.Db.Codec (depth 2)
        // render_markdown_tree uses depth relative to its call site (0 for roots).
        // Root = Ipe at depth 0 → "- **Ipe**"
        // Ipe.Db at depth 1 → "  - [Ipe.Db](...)"
        // Ipe.Db.Codec at depth 2 → "    - [Ipe.Db.Codec](...)"
        let codec_line = idx
            .lines()
            .find(|l| l.contains("Ipe.Db.Codec"))
            .expect("Ipe.Db.Codec in index");
        let db_line = idx
            .lines()
            .find(|l| {
                l.contains("Ipe.Db)")
                    || (l.contains("Ipe.Db") && !l.contains("Codec") && !l.contains("Store"))
            })
            .expect("Ipe.Db in index");
        // codec_line must have more leading spaces than db_line
        let codec_indent = codec_line.len() - codec_line.trim_start().len();
        let db_indent = db_line.len() - db_line.trim_start().len();
        assert!(
            codec_indent > db_indent,
            "Ipe.Db.Codec is indented more than Ipe.Db: db={db_indent} codec={codec_indent}\n{idx}"
        );
        // The difference should be exactly 2 (one extra depth level)
        assert_eq!(
            codec_indent - db_indent,
            2,
            "exactly 2 extra spaces per depth: {idx}"
        );
    }

    #[test]
    fn reference_index_nests_submodules_in_child_ul() {
        let docs = DocsJson {
            version: DOCS_JSON_VERSION,
            modules: vec![
                stdlib_module("Ipe.Db"),
                stdlib_module("Ipe.Db.Codec"),
                stdlib_module("Ipe.List"),
            ],
            disclosure: None,
        };
        let bundle = crate::doc_bundle::DocBundle::empty();
        let search_script = build_site_search_script(&docs, &bundle, "../");
        let idx = render_reference_index(&docs, &search_script);
        // Ipe.Db.Codec must appear inside a nested <ul> inside Ipe's <li>
        // The simplest proxy: Ipe.Db.Codec's <a> appears after Ipe.Db's <a>,
        // and there must be a nested <ul> between them.
        let db_pos = idx.find("Ipe-Db.html").expect("Ipe.Db link");
        let codec_pos = idx.find("Ipe-Db-Codec.html").expect("Ipe.Db.Codec link");
        assert!(codec_pos > db_pos, "Codec comes after Db in markup");
        // A <ul> must appear between Db and Codec (nesting).
        let between = &idx[db_pos..codec_pos];
        assert!(
            between.contains("<ul"),
            "nested <ul> between Db and Codec: {between}"
        );
    }

    #[test]
    fn pure_prefix_namespace_renders_as_non_link_header_in_html() {
        // "Ipe" has no module of its own; only Ipe.List and Ipe.String exist.
        let docs = DocsJson {
            version: DOCS_JSON_VERSION,
            modules: vec![stdlib_module("Ipe.List"), stdlib_module("Ipe.String")],
            disclosure: None,
        };
        let bundle = crate::doc_bundle::DocBundle::empty();
        let search_script = build_site_search_script(&docs, &bundle, "../");
        let idx = render_reference_index(&docs, &search_script);
        // "Ipe" should appear as a span.ns-header, not a link.
        assert!(
            idx.contains("class=\"ns-header\">Ipe<"),
            "Ipe prefix is a non-link header: {idx}"
        );
        assert!(
            !idx.contains("href=\"Ipe.html\""),
            "no link for pure prefix node: {idx}"
        );
    }

    #[test]
    fn markdown_index_renders_pure_prefix_as_bold_non_link() {
        let docs = DocsJson {
            version: DOCS_JSON_VERSION,
            modules: vec![stdlib_module("Ipe.List"), stdlib_module("Ipe.String")],
            disclosure: None,
        };
        let idx = render_markdown_index(&docs);
        // "Ipe" prefix has no module → bold non-link header.
        assert!(idx.contains("**Ipe**"), "pure prefix is bold: {idx}");
        assert!(!idx.contains("[Ipe]"), "pure prefix is not linked: {idx}");
    }

    // ── Slice-2: HTML site navigation ─────────────────────────────────────

    /// Build a minimal bundle with one entry per generated kind plus curated.
    fn nav_test_bundle() -> crate::doc_bundle::DocBundle {
        use crate::doc_bundle::{BundleSource, DocBundle};
        let modules = vec![BundleSource::titled("Ipe.List", "Ipe.List")];
        let symbols = vec![];
        let diagnostics = vec![BundleSource::with_body(
            "IPE-L0107",
            "IPE-L0107",
            "No functions in record fields.",
        )];
        let cli = vec![BundleSource::with_body(
            "build",
            "build",
            "Compile the project.",
        )];
        // docs_root does not exist on disk; the embedded corpus still populates
        // the four curated kinds (construct, idiom, topic, guide).
        let docs_root = std::path::Path::new("/nonexistent");
        DocBundle::build(docs_root, &modules, &symbols, &diagnostics, &cli)
            .expect("nav_test_bundle")
    }

    #[test]
    fn header_appears_on_landing_module_and_guide_pages() {
        let docs = one_module_docs(local_module("App"));
        let bundle = nav_test_bundle();
        let search = build_site_search_script(&docs, &bundle, "");
        let ref_search = build_site_search_script(&docs, &bundle, "../");

        // Landing page.
        let landing = render_html_index(&docs, &bundle, &search);
        assert!(
            landing.contains("module/index.html"),
            "landing header has reference link: {landing}"
        );
        assert!(
            landing.contains("diagnostic/index.html"),
            "landing header has diagnostics link: {landing}"
        );
        assert!(
            landing.contains("cli/index.html"),
            "landing header has cli link: {landing}"
        );

        // Module page.
        let anchor = AnchorIndex::build(&docs);
        let module_page =
            render_html_module(docs.modules.first().expect("one module"), &anchor, &search);
        assert!(
            module_page.contains("module/index.html"),
            "module page header has reference link: {module_page}"
        );
        assert!(
            module_page.contains("diagnostic/index.html"),
            "module page header has diagnostics link: {module_page}"
        );

        // Reference index page (one level down, uses ../).
        let ref_page = render_reference_index(&docs, &ref_search);
        assert!(
            ref_page.contains("../module/index.html")
                || ref_page.contains("../diagnostic/index.html"),
            "reference index header present: {ref_page}"
        );
    }

    #[test]
    fn landing_page_lists_curated_kinds_in_teach_order() {
        // The landing page places Guides before Topics, Topics before Idioms, etc.
        // With an empty bundle the landing renders a fallback paragraph.
        // We need entries in curated kinds to verify order.
        use crate::doc_bundle::DocBundle;
        let docs = one_module_docs(local_module("App"));
        let bundle = {
            let mut b = DocBundle::empty();
            b.insert(
                crate::doc_bundle::DocKind::Guide,
                "getting-started".to_owned(),
                "Getting Started".to_owned(),
                "Begin here.".to_owned(),
            )
            .unwrap();
            b.insert(
                crate::doc_bundle::DocKind::Topic,
                "types".to_owned(),
                "Types".to_owned(),
                "Type system overview.".to_owned(),
            )
            .unwrap();
            b
        };
        let search = build_site_search_script(&docs, &bundle, "");
        let landing = render_html_index(&docs, &bundle, &search);

        // "Guides" section heading must precede "Topics" section heading.
        let guide_pos = landing.find("Guides").expect("Guides section");
        let topic_pos = landing.find("Topics").expect("Topics section");
        assert!(
            guide_pos < topic_pos,
            "Guides precedes Topics in teach order: {landing}"
        );
    }

    #[test]
    fn landing_respects_front_matter_order_within_kind() {
        // sort_curated_entries puts order=0 before order=1, and both before unordered.
        let first = crate::doc_bundle::DocEntry {
            kind: crate::doc_bundle::DocKind::Guide,
            key: "first".to_owned(),
            title: "First Guide".to_owned(),
            body: String::new(),
            order: Some(0),
        };
        let second = crate::doc_bundle::DocEntry {
            kind: crate::doc_bundle::DocKind::Guide,
            key: "second".to_owned(),
            title: "Second Guide".to_owned(),
            body: String::new(),
            order: Some(1),
        };
        let unordered = crate::doc_bundle::DocEntry {
            kind: crate::doc_bundle::DocKind::Guide,
            key: "zz-alpha".to_owned(),
            title: "Alpha".to_owned(),
            body: String::new(),
            order: None,
        };
        let mut to_sort = vec![&second, &unordered, &first];
        sort_curated_entries(&mut to_sort);
        assert_eq!(
            to_sort.first().map(|e| e.key.as_str()),
            Some("first"),
            "order:0 comes first"
        );
        assert_eq!(
            to_sort.get(1).map(|e| e.key.as_str()),
            Some("second"),
            "order:1 comes second"
        );
        assert_eq!(
            to_sort.last().map(|e| e.key.as_str()),
            Some("zz-alpha"),
            "unordered entry last"
        );
    }

    #[test]
    fn reference_index_is_one_click_from_header() {
        let docs = DocsJson {
            version: DOCS_JSON_VERSION,
            modules: vec![stdlib_module("Ipe.List")],
            disclosure: None,
        };
        let bundle = nav_test_bundle();
        let ref_search = build_site_search_script(&docs, &bundle, "../");
        let ref_page = render_reference_index(&docs, &ref_search);

        // The reference page lists the known module with a link.
        assert!(
            ref_page.contains("Ipe.List"),
            "Ipe.List appears in reference index: {ref_page}"
        );
        assert!(
            ref_page.contains("Ipe-List.html"),
            "reference index links to module page: {ref_page}"
        );
    }

    #[test]
    fn diagnostic_index_lists_known_code() {
        let bundle = nav_test_bundle();
        let docs = DocsJson {
            version: DOCS_JSON_VERSION,
            modules: Vec::new(),
            disclosure: None,
        };
        let ref_search = build_site_search_script(&docs, &bundle, "../");
        let page = render_diagnostic_index(&bundle, &ref_search);

        assert!(
            page.contains("IPE-L0107"),
            "known diagnostic appears in index: {page}"
        );
        assert!(
            page.contains("<!DOCTYPE html>"),
            "diagnostics index is a valid HTML page: {page}"
        );
    }

    #[test]
    fn cli_index_lists_known_subcommand() {
        let bundle = nav_test_bundle();
        let docs = DocsJson {
            version: DOCS_JSON_VERSION,
            modules: Vec::new(),
            disclosure: None,
        };
        let ref_search = build_site_search_script(&docs, &bundle, "../");
        let page = render_cli_index(&bundle, &ref_search);

        assert!(
            page.contains("build"),
            "known cli command appears in index: {page}"
        );
        assert!(
            page.contains("<!DOCTYPE html>"),
            "cli index is a valid HTML page: {page}"
        );
    }

    #[test]
    fn search_index_is_embedded_valid_json_with_multiple_kinds() {
        let bundle = nav_test_bundle();
        // `nav_test_bundle` carries an `Ipe.List` module; the docs must list it so
        // its search entry survives the has-a-page filter.
        let docs = DocsJson {
            version: DOCS_JSON_VERSION,
            modules: vec![stdlib_module("Ipe.List")],
            disclosure: None,
        };
        let script = build_site_search_script(&docs, &bundle, "");

        // The script contains a JSON array literal starting with '['.
        let json_start = script.find('[').expect("JSON array start in script");
        let json_end = script.rfind(']').expect("JSON array end in script");
        let json_str = &script[json_start..=json_end];

        // Must be parseable as a JSON array (minimal validation without serde).
        assert!(json_str.starts_with('['), "JSON array starts with [");
        assert!(json_str.ends_with(']'), "JSON array ends with ]");

        // Contains entries for multiple kinds (module + diagnostic + cli).
        assert!(
            json_str.contains("\"module\"") && json_str.contains("\"diagnostic\""),
            "search index contains multiple kinds: {json_str}"
        );

        // The inline script element is present.
        assert!(
            script.contains("<script>"),
            "search script contains <script> tag"
        );
    }

    #[test]
    fn serve_file_name_handles_subdirectory_paths() {
        // Paths like /module/index.html must map correctly.
        assert_eq!(serve_file_name("/module/index.html"), "module/index.html");
        assert_eq!(
            serve_file_name("/diagnostic/index.html"),
            "diagnostic/index.html"
        );
        assert_eq!(serve_file_name("/cli/index.html"), "cli/index.html");
    }

    /// Extract every relative `href="…"` from an HTML page, dropping absolute
    /// URLs, in-page fragments, and mailto/anchor-only links — the set a link
    /// checker must resolve against the generated file map.
    fn extract_relative_hrefs(html: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = html;
        while let Some(pos) = rest.find("href=\"") {
            rest = &rest[pos + 6..];
            let Some(end) = rest.find('"') else { break };
            let raw = &rest[..end];
            rest = &rest[end + 1..];
            // Skip absolute schemes and pure fragments.
            if raw.is_empty()
                || raw.starts_with('#')
                || raw.starts_with("http://")
                || raw.starts_with("https://")
                || raw.starts_with("mailto:")
            {
                continue;
            }
            out.push(raw.to_owned());
        }
        out
    }

    /// Resolve a page-relative href against the directory the page lives in,
    /// dropping any `#fragment`, to the flat site-map key it must hit.
    ///
    /// `page_key` is the map key of the page the href appears on (e.g.
    /// `diagnostic/IPE-E0001.html`); its parent directory is the base.
    fn resolve_href(page_key: &str, href: &str) -> String {
        let target = href.split('#').next().unwrap_or(href);
        let dir = page_key.rsplit_once('/').map_or("", |(d, _)| d);
        let mut parts: Vec<&str> = Vec::new();
        if !dir.is_empty() {
            parts.extend(dir.split('/'));
        }
        for seg in target.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                other => parts.push(other),
            }
        }
        parts.join("/")
    }

    /// The link-integrity regression gate (issue #1874, item 9): every relative
    /// href on every generated page must resolve to a generated file. This is
    /// what would have caught the pervasive dead links, and prevents a
    /// href-scheme / output-path drift from recurring.
    #[test]
    fn every_generated_href_resolves_to_a_generated_file() {
        let docs = build_stdlib_only_docs();
        let docs_root = locate_docs_root();
        let bundle = build_doc_bundle(&docs_root).expect("bundle");
        let site = render_site_for_serve(&docs, &bundle);

        let mut missing: Vec<String> = Vec::new();
        for (page_key, html) in &site {
            if !std::path::Path::new(page_key)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("html"))
            {
                continue;
            }
            for href in extract_relative_hrefs(html) {
                let resolved = resolve_href(page_key, &href);
                if resolved.is_empty() || site.contains_key(&resolved) {
                    continue;
                }
                missing.push(format!("{page_key} -> {href} (resolved {resolved})"));
            }
        }
        assert!(
            missing.is_empty(),
            "every generated href must resolve to a generated file; {} dead link(s):\n{}",
            missing.len(),
            missing.join("\n"),
        );
    }

    /// Every diagnostic and CLI entry has a generated per-entry page at exactly
    /// the path its links point to (the fix for items 6, 8, and the curated
    /// 404s under item 9).
    #[test]
    fn per_entry_pages_exist_for_every_linked_kind() {
        use crate::doc_bundle::DocKind;
        let docs = build_stdlib_only_docs();
        let docs_root = locate_docs_root();
        let bundle = build_doc_bundle(&docs_root).expect("bundle");
        let site = render_site_for_serve(&docs, &bundle);

        for kind in [DocKind::Diagnostic, DocKind::Cli] {
            let mut count = 0usize;
            for entry in bundle.entries_for_kind(kind) {
                let key = entry_page_key(kind, &entry.key).expect("kind has per-entry pages");
                assert!(
                    site.contains_key(&key),
                    "{kind} entry `{}` must have a generated page at {key}",
                    entry.key
                );
                count += 1;
            }
            assert!(count > 0, "{kind} must contribute at least one entry");
        }
    }

    #[test]
    fn extract_module_imports_reads_top_level_import_lines() {
        let src = "\
module Ipe.Task exposing (..)

import Ipe.Ffi.Kernel as Kernel
import Ipe.Duration as Duration exposing (Duration)

withBaseMs = something
";
        assert_eq!(
            extract_module_imports(src),
            s(&[
                "import Ipe.Ffi.Kernel as Kernel",
                "import Ipe.Duration as Duration exposing (Duration)",
            ])
        );
    }

    #[test]
    fn import_line_module_reads_the_dotted_path() {
        assert_eq!(
            import_line_module("import Ipe.Duration as Duration exposing (Duration)"),
            Some("Ipe.Duration")
        );
        assert_eq!(
            import_line_module("import Ipe.Ffi.Kernel as Kernel"),
            Some("Ipe.Ffi.Kernel")
        );
        assert_eq!(import_line_module("withBaseMs = something"), None);
    }

    #[test]
    fn synthesize_injects_a_qualified_name_the_module_imports() {
        // An example that names `Duration.millis` — a qualified import of the
        // documenting module, NOT one of its exports — must have that import
        // injected so it resolves exactly as it does inside the module.
        let imports = s(&["import Ipe.Duration as Duration exposing (Duration)"]);
        let out = synthesize_module(
            "withBaseMs (Duration.millis 250) policy",
            "Ipe.Task",
            &imports,
        );
        assert!(
            out.contains("import Ipe.Duration as Duration exposing (Duration)"),
            "expected the module's own Duration import to be injected:\n{out}"
        );
        assert!(
            out.contains("import Ipe.Task as Task exposing (..)"),
            "expected the documenting module to be imported:\n{out}"
        );
    }

    #[test]
    fn synthesize_does_not_import_a_module_twice() {
        // The documenting module's import list and the common-prefix fallback
        // must not both emit an import for the same module.
        let imports = s(&["import Ipe.List as List"]);
        let out = synthesize_module("List.map f xs", "Ipe.Maybe", &imports);
        assert_eq!(
            out.matches("import Ipe.List").count(),
            1,
            "Ipe.List must be imported exactly once:\n{out}"
        );
    }

    #[test]
    fn doc_serve_answers_a_normal_request() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("addr");

        let handle = std::thread::Builder::new()
            .spawn(move || {
                let mut site: BTreeMap<String, String> = BTreeMap::new();
                site.insert("index.html".to_owned(), "<h1>hi</h1>".to_owned());
                let (mut conn, _) = listener.accept().expect("accept");
                serve_one(&mut conn, &site);
            })
            .expect("spawn test thread");

        let mut client = TcpStream::connect(addr).expect("connect");
        client
            .write_all(b"GET / HTTP/1.1\r\n\r\n")
            .expect("write request");
        let mut resp = String::new();
        client.read_to_string(&mut resp).expect("read response");
        handle.join().expect("server thread");

        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(resp.contains("<h1>hi</h1>"), "body served: {resp}");
    }

    #[test]
    fn doc_serve_does_not_hang_on_a_headerless_flood() {
        // A client that streams bytes without ever sending a newline must not
        // grow the server's buffer without bound nor pin the connection: the
        // capped read gives up past the cap and the request-line read timeout
        // bounds the wait, so `serve_one` returns and the test completes.
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};
        use std::time::Instant;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("addr");

        let handle = std::thread::Builder::new()
            .spawn(move || {
                let site: BTreeMap<String, String> = BTreeMap::new();
                let (mut conn, _) = listener.accept().expect("accept");
                let started = Instant::now();
                serve_one(&mut conn, &site);
                started.elapsed()
            })
            .expect("spawn test thread");

        let mut client = TcpStream::connect(addr).expect("connect");
        // Send well past the request-line cap with no newline. Ignore write
        // errors: the server closing early (cap hit) is exactly the bounded
        // behaviour under test.
        let chunk = vec![b'a'; 64 * 1024];
        for _ in 0..64 {
            if client.write_all(&chunk).is_err() {
                break;
            }
        }
        drop(client);
        let elapsed = handle.join().expect("server thread");
        // The read timeout is 10s; a bounded server returns well within it. A
        // regression that reverted to an unbounded `read_line` would block until
        // the client closed (here) or forever (a real slow-loris).
        assert!(
            elapsed < DOC_SERVE_READ_TIMEOUT * 3,
            "serve_one must return promptly, took {elapsed:?}"
        );
    }

    #[test]
    fn doc_serve_rejects_an_over_long_request_line_with_431() {
        // A request line that fills the cap without a terminating newline is
        // fail-closed: the server answers `431` and never acts on the truncated
        // line, so an over-long line can neither be served nor grow the buffer
        // past the cap.
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("addr");

        let handle = std::thread::Builder::new()
            .spawn(move || {
                let mut site: BTreeMap<String, String> = BTreeMap::new();
                site.insert("index.html".to_owned(), "<h1>hi</h1>".to_owned());
                let (mut conn, _) = listener.accept().expect("accept");
                serve_one(&mut conn, &site);
            })
            .expect("spawn test thread");

        let mut client = TcpStream::connect(addr).expect("connect");
        // Exactly the cap in bytes, no newline: the server's capped read consumes
        // every byte sent (so the close is a clean FIN, not an RST that would
        // discard the response) yet still sees no line terminator, which is the
        // over-long condition. Send-then-shutdown so the read below sees the full
        // `431` before the server closes.
        let over_long = vec![b'a'; DOC_SERVE_REQUEST_LINE_CAP];
        client.write_all(&over_long).expect("write over-long line");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown write");
        let mut resp = String::new();
        client.read_to_string(&mut resp).expect("read response");
        handle.join().expect("server thread");

        assert!(
            resp.starts_with("HTTP/1.1 431 Request Header Fields Too Large"),
            "over-long line must be rejected with 431, got: {resp}"
        );
        assert!(
            !resp.contains("<h1>hi</h1>"),
            "an over-long line must not be served a body: {resp}"
        );
    }

    // ── Defect-1: command-page SSOT equivalence ───────────────────────────────

    /// Every `ipe` subcommand's summary text (from the `COMMANDS` SSOT in
    /// `help.rs`) must appear verbatim in the HTML rendered for that command's
    /// doc-site page.  A drift between `ipe <cmd> --help` and the HTML site is
    /// unrepresentable: both draw from `command_doc_markdown`.
    #[test]
    fn command_page_html_mirrors_help_ssot() {
        let docs = build_stdlib_only_docs();
        let docs_root = locate_docs_root();
        let bundle = build_doc_bundle(&docs_root).expect("bundle");
        let site = render_site_for_serve(&docs, &bundle);

        for name in crate::help::documented_command_keys() {
            let Some(md) = crate::help::command_doc_markdown(name) else {
                continue;
            };
            // The command's page lives at `cli/<name>.html`.
            let page_key = format!("cli/{name}.html");
            let Some(html) = site.get(&page_key) else {
                // No page generated for this command (hidden or not yet in bundle).
                continue;
            };
            // The first line of the Markdown is the command summary; it must appear
            // in the rendered HTML.
            let first_line = md.lines().next().unwrap_or("").trim();
            if !first_line.is_empty() {
                assert!(
                    html.contains(first_line),
                    "command `{name}`: summary from help SSOT must appear in HTML page; \
                     expected `{first_line}` in {page_key}"
                );
            }
        }
    }

    // ── Defect-2: Tea.Terminal absent from reference tree ─────────────────────

    /// The `Ipe.Tea.Terminal` namespace is superseded by `Ipe.Color`; the
    /// generated site must not emit any page referencing it.
    #[test]
    fn tea_terminal_namespace_absent_from_site() {
        let docs = build_stdlib_only_docs();
        let docs_root = locate_docs_root();
        let bundle = build_doc_bundle(&docs_root).expect("bundle");
        let site = render_site_for_serve(&docs, &bundle);

        for path in site.keys() {
            assert!(
                !path.contains("Tea.Terminal") && !path.contains("Tea-Terminal"),
                "deprecated Tea.Terminal namespace must not appear as a site path; \
                 found: {path}"
            );
        }
    }

    // ── Defect-5: serve == write-format html ─────────────────────────────────

    /// `render_site_for_serve` and the HTML output of `render_site_split` must
    /// produce byte-identical file maps for the same inputs.  This is the
    /// regression gate that ensures `ipe doc serve` and `ipe doc --write-format
    /// html` always show the same content.
    #[test]
    fn serve_html_equals_write_format_html() {
        let docs = build_stdlib_only_docs();
        let docs_root = locate_docs_root();
        let bundle = build_doc_bundle(&docs_root).expect("bundle");

        let serve = render_site_for_serve(&docs, &bundle);
        let (_, _, write_html) = render_site_split(&docs, &bundle, WriteFormat::Html);

        // Both maps must have the same keys.
        let mut serve_keys: Vec<&str> = serve.keys().map(String::as_str).collect();
        let mut write_keys: Vec<&str> = write_html.keys().map(String::as_str).collect();
        serve_keys.sort_unstable();
        write_keys.sort_unstable();
        assert_eq!(
            serve_keys, write_keys,
            "serve and write-format html must generate the same file set"
        );

        // Every file must be byte-identical.
        for key in &serve_keys {
            let s = serve.get(*key).map_or("", String::as_str);
            let w = write_html.get(*key).map_or("", String::as_str);
            assert_eq!(
                s, w,
                "serve and write-format html must produce identical content for `{key}`"
            );
        }
    }

    // ── #3198: one rule resolves module and member doc keys ──────────────────

    /// A short name shared by two dotted candidates is a typed `Ambiguous` miss
    /// naming every candidate — never a silent pick of the first. No such
    /// collision exists in real stdlib data today, so the collision is
    /// constructed: a bare `List` alongside `Ipe.List` both carry the short
    /// name `List`.
    #[test]
    fn resolve_stdlib_candidate_reports_ambiguous_short_names() {
        let candidates = vec!["Ipe.List".to_owned(), "List".to_owned()];

        assert!(matches!(
            resolve_stdlib_candidate("List", &candidates),
            StdlibCandidate::Ambiguous(ref cs) if cs.len() == 2
        ));
        // The full dotted form is never ambiguous, even when its short form is.
        assert!(matches!(
            resolve_stdlib_candidate("Ipe.List", &candidates),
            StdlibCandidate::One(ref d) if d == "Ipe.List"
        ));
        assert!(matches!(
            resolve_stdlib_candidate("Nope", &candidates),
            StdlibCandidate::None
        ));
    }

    /// The class-closing property, exhaustively: every stdlib module
    /// `stdlib_module_names` advertises resolves under both its full and short
    /// form — the same table `ipe doc --list` and every module lookup share.
    #[test]
    fn every_stdlib_module_resolves_by_full_and_short_name() {
        let names = stdlib_module_names();
        assert!(!names.is_empty(), "the stdlib module table is non-empty");
        for dotted in &names {
            assert!(
                matches!(
                    &resolve_stdlib_candidate(dotted, &names),
                    StdlibCandidate::One(d) if d == dotted
                ),
                "full name `{dotted}` must resolve to itself"
            );

            let short = ipe_docs::stdlib_short_name(dotted);
            let resolved = resolve_stdlib_candidate(short, &names);
            let matches_dotted = match &resolved {
                StdlibCandidate::One(d) => d == dotted,
                StdlibCandidate::Ambiguous(cs) => cs.contains(dotted),
                StdlibCandidate::None => false,
            };
            assert!(
                matches_dotted,
                "short name `{short}` (from `{dotted}`) must resolve to `{dotted}`, got {resolved:?}"
            );
        }
    }

    /// An unknown module-shaped key misses cleanly, at no type-check cost (the
    /// candidate table rules it out before any module is built).
    #[test]
    fn find_module_doc_misses_an_unknown_module() {
        assert!(matches!(find_module_doc("NotAModule"), ModuleLookup::Miss));
        assert!(matches!(find_module_doc("Ipe.Nope"), ModuleLookup::Miss));
    }
}
