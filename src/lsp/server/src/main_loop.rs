//! The single-writer main loop: document sync in receipt order on this
//! thread, diagnostics on cancellable worker threads, latest-generation-wins
//! publishing.

use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use crossbeam_channel::{Receiver, Sender, select};
use lsp_server::{Connection, Message, Notification, Request, Response};
use lsp_types::notification::{
    DidChangeTextDocument, DidChangeWatchedFiles, DidCloseTextDocument, DidOpenTextDocument,
    DidSaveTextDocument, Notification as _, PublishDiagnostics,
};
use lsp_types::{InitializeParams, PublishDiagnosticsParams, TextDocumentContentChangeEvent, Url};

use ipe_lsp_features::{PositionEncoding, diagnostics, offset};

use crate::ServerError;
use crate::loader::{
    LoadDisposition, LoadError, LoadedFile, LoadedProject, ModuleOrigin, ProjectLoader,
};

/// The typed outcome of an LSP feature request. `null` is reserved for
/// `NoResult`; a params-decode failure and an internal encoding bug are
/// distinct error variants and never collapse to `null`.
enum FeatureOutcome {
    /// A serializable feature payload (already a well-typed `lsp_types` value).
    Payload(serde_json::Value),
    /// The genuine "nothing here" answer — the ONLY source of protocol null.
    NoResult,
    /// The client sent params this method cannot decode.
    InvalidParams(String),
    /// A payload that should have serialized failed to — an internal bug.
    Encode(serde_json::Error),
}

impl FeatureOutcome {
    /// The sole path to `Payload`: serializes `value` or returns `Encode` on
    /// failure. Never returns `Payload(Null)` for an encoding error.
    fn payload<T: serde::Serialize>(value: T) -> Self {
        match serde_json::to_value(value) {
            Ok(v) => Self::Payload(v),
            Err(e) => Self::Encode(e),
        }
    }

    /// Lifts `Option<T>` to an outcome: `None` maps to `NoResult`, `Some` goes
    /// through `payload`.
    fn maybe<T: serde::Serialize>(value: Option<T>) -> Self {
        value.map_or(Self::NoResult, Self::payload)
    }
}

/// One finished diagnostics computation, tagged with the input generation it
/// was computed against so a stale batch is recognisably droppable.
struct DiagnosticsBatch {
    generation: u64,
    per_uri: Vec<(Url, Vec<lsp_types::Diagnostic>)>,
}

/// An open editor buffer: its text and the client's version of it.
struct Overlay {
    text: String,
    version: i32,
}

/// One adopted project layout: its module set and both path-module maps.
struct Layout {
    entry_module: Vec<String>,
    /// The loaded modules (disk truth; overlays shadow it).
    disk: BTreeMap<Vec<String>, LoadedFile>,
    module_of_path: BTreeMap<PathBuf, Vec<String>>,
    /// Reverse of `module_of_path`: a user module's normalized on-disk path.
    ///
    /// Built once per layout in [`Layout::of`] so per-request URI resolution
    /// and per-edit overlay lookup are `O(log n)`, not a linear scan or a
    /// re-canonicalize.
    path_of_module: BTreeMap<Vec<String>, PathBuf>,
    /// Where `lint.ipe` is read from, if the load resolved it.
    lint_source: LintSource,
}

/// Where a layout reads `lint.ipe` from.
///
/// Only a completed load names the project's configuration. A fallback has no
/// proof of it, so it runs no rule rather than read a guessed directory whose
/// absent `lint.ipe` would enable rules the project disabled.
enum LintSource {
    /// The directory the loader named, the one `ipe lint` reads for the same project.
    Project(PathBuf),
    /// No load resolved the project, so no configuration is known.
    Unresolved,
}

impl LintSource {
    /// The directory to read `lint.ipe` from; `None` when unresolved.
    fn dir(&self) -> Option<&Path> {
        match self {
            Self::Project(dir) => Some(dir),
            Self::Unresolved => None,
        }
    }
}

impl Layout {
    /// Index a loaded project, whose `lint.ipe` directory the loader resolved.
    fn of(project: LoadedProject) -> Self {
        Self::index(
            project.files,
            project.entry_module,
            LintSource::Project(project.lint_config_dir),
        )
    }

    /// Index a module set, canonicalizing each user path once.
    fn index(
        files: BTreeMap<Vec<String>, LoadedFile>,
        entry_module: Vec<String>,
        lint_source: LintSource,
    ) -> Self {
        let path_of_module: BTreeMap<Vec<String>, PathBuf> = files
            .iter()
            .filter(|(_, file)| file.origin == ModuleOrigin::User)
            .map(|(module, file)| (module.clone(), normalize(&file.path)))
            .collect();
        let module_of_path = path_of_module
            .iter()
            .map(|(module, path)| (path.clone(), module.clone()))
            .collect();
        Self {
            entry_module,
            disk: files,
            module_of_path,
            path_of_module,
            lint_source,
        }
    }
}

/// The layout the server analyzes, as the latest load verdict allows.
///
/// A refused load always reaches [`Served::Refused`]: no layout, trusted or
/// fallback, outlives a refusal, so no analysis of a refused project stays
/// published.
enum Served {
    /// No layout: nothing loaded yet, or a degraded load had no buffer to serve.
    Unloaded,
    /// The single-file layout of a degraded load.
    Fallback(Layout),
    /// No layout: the load was refused for a cause no buffer edit lifts.
    ///
    /// Only an open, save, close, or watched-file event re-runs the load,
    /// the watched-file event anchored at the refused path.
    Refused {
        /// The path whose load was refused.
        anchor: PathBuf,
        /// Why the load was refused, published on `anchor`.
        error: LoadError,
    },
    /// The layout of a successful load.
    Trusted(Layout),
}

impl Served {
    /// The layout being analyzed, if any.
    const fn layout(&self) -> Option<&Layout> {
        match self {
            Self::Unloaded | Self::Refused { .. } => None,
            Self::Fallback(layout) | Self::Trusted(layout) => Some(layout),
        }
    }

    /// Whether an edit to the buffer re-runs the load.
    ///
    /// Only an unloaded or degraded state retries: the edit may be the one
    /// that lets the load succeed. A trusted layout is settled, and a refusal
    /// counted nothing the buffer holds, so re-running it per keystroke would
    /// repeat the refused filesystem work for the same verdict.
    const fn retries_on_edit(&self) -> bool {
        matches!(self, Self::Unloaded | Self::Fallback(_))
    }

    /// The path a watched-file event re-runs the load from, if any.
    fn watched_file_anchor(&self) -> Option<PathBuf> {
        match self {
            Self::Unloaded => None,
            Self::Refused { anchor, .. } => Some(anchor.clone()),
            Self::Fallback(layout) | Self::Trusted(layout) => {
                layout.module_of_path.keys().next().cloned()
            }
        }
    }
}

struct State {
    workspace_root: Option<PathBuf>,
    encoding: PositionEncoding,
    db: ipe_db::IpeDatabase,
    root: Option<ipe_db::SourceRoot>,
    /// Open editor buffers, keyed by normalized path.
    overlays: BTreeMap<PathBuf, Overlay>,
    served: Served,
    generation: u64,
    /// The single in-flight diagnostics worker. At most one exists at a time:
    /// a new `recompute` call joins (cancels) the previous one before spawning
    /// its replacement.
    worker: Option<thread::JoinHandle<()>>,
    /// The in-flight worker's cancel flag, set before joining a superseded
    /// worker so its lint tail (which never demands the db again, and so cannot
    /// unwind via salsa `Cancelled`) exits within one module's lint time
    /// instead of stalling the main loop for a full lint pass.
    worker_cancel: Option<Arc<AtomicBool>>,
    /// Last non-empty payload per URI, for change-suppression and clearing.
    last_published: BTreeMap<Url, Vec<lsp_types::Diagnostic>>,
    /// The documentation index (stdlib symbol/module docs, diagnostic explain
    /// pages, env vars), built once at startup and reused across requests to
    /// enrich hover / completion / signature help. `None` when the embedded
    /// index fails to build — enrichment is then simply absent (fail-closed),
    /// never a crash or a wrong doc.
    docs: Option<ipe_docs::Index>,
    /// Whether the client accepts versioned `documentChanges` in a workspace edit.
    document_changes: bool,
}

impl State {
    /// The entry module of the served layout; empty when none is served.
    fn entry_module(&self) -> &[String] {
        let none: &[String] = &[];
        self.served
            .layout()
            .map_or(none, |layout| layout.entry_module.as_slice())
    }

    /// The module a normalized path maps to in the served layout.
    fn module_of_path(&self, path: &Path) -> Option<&Vec<String>> {
        self.served.layout()?.module_of_path.get(path)
    }

    /// The document URI of a user module, when it has an on-disk path.
    fn uri_for_module(&self, module: &[String]) -> Option<Url> {
        let path = self.served.layout()?.path_of_module.get(module)?;
        Url::from_file_path(path).ok()
    }

    /// Resolve a document URI to its module path and input handle. The handle's
    /// text is read by borrowing `file.text(&state.db)` at the use site, so the
    /// full document is never cloned just to satisfy the borrow checker.
    fn locate(&self, uri: &Url) -> Option<(Vec<String>, ipe_db::SourceFile)> {
        let path = normalize(&uri.to_file_path().ok()?);
        let module = self.module_of_path(&path)?.clone();
        let root = self.root?;
        let file = root.files(&self.db).get(&module).copied()?;
        Some((module, file))
    }

    /// `uri`'s known overlay version, or `None` when the client hasn't
    /// advertised `documentChanges` support or the document isn't an open
    /// overlay. The single source every provider's `WorkspaceEdit` reads to
    /// decide whether an edit can be versioned.
    fn document_version(&self, uri: &Url) -> Option<i32> {
        uri.to_file_path()
            .ok()
            .filter(|_| self.document_changes)
            .and_then(|path| self.overlays.get(&normalize(&path)))
            .map(|o| o.version)
    }

    fn new(workspace_root: Option<PathBuf>, encoding: PositionEncoding) -> Self {
        Self {
            workspace_root,
            encoding,
            db: ipe_db::IpeDatabase::new(),
            root: None,
            overlays: BTreeMap::new(),
            served: Served::Unloaded,
            generation: 0,
            worker: None,
            worker_cancel: None,
            last_published: BTreeMap::new(),
            // Built once from data compiled into the binary; a build failure
            // leaves enrichment off rather than blocking the server.
            docs: ipe_docs::Index::build_embedded().ok(),
            document_changes: false,
        }
    }

    /// The cached documentation index, when it built successfully.
    const fn docs(&self) -> Option<&ipe_docs::Index> {
        self.docs.as_ref()
    }
}

pub fn run(
    connection: &Connection,
    init: &InitializeParams,
    encoding: PositionEncoding,
    loader: &dyn ProjectLoader,
) -> Result<(), ServerError> {
    let (diag_tx, diag_rx): (Sender<DiagnosticsBatch>, Receiver<DiagnosticsBatch>) =
        crossbeam_channel::unbounded();
    let mut state = State::new(workspace_root_of(init), encoding);
    state.document_changes = init
        .capabilities
        .workspace
        .as_ref()
        .and_then(|w| w.workspace_edit.as_ref())
        .and_then(|e| e.document_changes)
        .unwrap_or(false);

    loop {
        select! {
            recv(connection.receiver) -> msg => {
                let Ok(msg) = msg else { break };
                match msg {
                    Message::Request(request) => {
                        match connection.handle_shutdown(&request) {
                            Ok(true) => break,
                            Ok(false) => handle_request(&state, connection, &request),
                            Err(err) => return Err(ServerError::new(err)),
                        }
                    }
                    Message::Notification(notification) => {
                        handle_notification(&mut state, loader, &notification, &diag_tx);
                    }
                    Message::Response(_) => {}
                }
            }
            recv(diag_rx) -> batch => {
                if let Ok(batch) = batch {
                    publish(&mut state, connection, batch);
                }
            }
        }
    }
    Ok(())
}

fn workspace_root_of(init: &InitializeParams) -> Option<PathBuf> {
    if let Some(folder) = init
        .workspace_folders
        .as_ref()
        .and_then(|folders| folders.first())
        && let Ok(path) = folder.uri.to_file_path()
    {
        return Some(path);
    }
    #[allow(deprecated)] // `root_uri` is the fallback older clients still send.
    init.root_uri
        .as_ref()
        .and_then(|uri| uri.to_file_path().ok())
}

fn handle_request(state: &State, connection: &Connection, request: &Request) {
    let method = request.method.clone();
    let id = request.id.clone();

    // Panic boundary: mirrors the diagnostics worker's guard (main_loop.rs
    // recompute). A salsa dependency-cycle panic or any other panic in a
    // handler becomes a per-request LSP error response; the select! loop and
    // all other open documents are unaffected.
    //
    // AssertUnwindSafe: `state` and `request` are accessed read-only inside
    // the closure; no interior mutation escapes the catch_unwind boundary, so
    // the assertion is sound.
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
        salsa::Cancelled::catch(AssertUnwindSafe(|| dispatch(state, request)))
    }));

    let response = match outcome {
        Ok(Ok(Some(FeatureOutcome::Payload(v)))) => Response::new_ok(id, v),
        Ok(Ok(Some(FeatureOutcome::NoResult))) => Response::new_ok(id, serde_json::Value::Null),
        Ok(Ok(Some(FeatureOutcome::InvalidParams(msg)))) => {
            Response::new_err(id, lsp_server::ErrorCode::InvalidParams as i32, msg)
        }
        Ok(Ok(Some(FeatureOutcome::Encode(err)))) => {
            eprintln!("[ipe lsp] internal encode error for `{method}`: {err}");
            Response::new_err(
                id,
                lsp_server::ErrorCode::InternalError as i32,
                format!("internal encoding error: {err}"),
            )
        }
        Ok(Ok(None)) => Response::new_err(
            id,
            lsp_server::ErrorCode::MethodNotFound as i32,
            format!("ipe-lsp does not handle `{method}` yet"),
        ),
        Ok(Err(_cancelled)) => Response::new_err(
            id,
            lsp_server::ErrorCode::ContentModified as i32,
            "request superseded by a newer edit".into(),
        ),
        Err(_panic) => {
            eprintln!("[ipe lsp] internal error: request `{method}` panicked");
            Response::new_err(
                id,
                lsp_server::ErrorCode::InternalError as i32,
                format!("internal error handling `{method}`"),
            )
        }
    };
    let _ = connection.sender.send(Message::Response(response));
}

/// Dispatch an LSP request to the appropriate handler, returning its typed
/// outcome, or `None` for an unrecognised method.
fn dispatch(state: &State, request: &Request) -> Option<FeatureOutcome> {
    match request.method.as_str() {
        "textDocument/hover" => Some(hover_result(state, &request.params)),
        "textDocument/documentSymbol" => Some(document_symbols_result(state, &request.params)),
        "textDocument/documentLink" => Some(document_links_result(state, &request.params)),
        "textDocument/foldingRange" => Some(folding_ranges_result(state, &request.params)),
        "textDocument/completion" => Some(completion_result(state, &request.params)),
        "textDocument/definition" => Some(definition_result(state, &request.params)),
        "textDocument/typeDefinition" => Some(type_definition_result(state, &request.params)),
        "textDocument/references" => Some(references_result(state, &request.params)),
        "textDocument/prepareRename" => Some(prepare_rename_result(state, &request.params)),
        "textDocument/rename" => Some(rename_result(state, &request.params)),
        "textDocument/formatting" => Some(formatting_result(state, &request.params)),
        "textDocument/rangeFormatting" => Some(range_formatting_result(state, &request.params)),
        "textDocument/codeAction" => Some(code_action_result(state, &request.params)),
        "textDocument/semanticTokens/full" => {
            Some(semantic_tokens_full_result(state, &request.params))
        }
        "textDocument/signatureHelp" => Some(signature_help_result(state, &request.params)),
        "textDocument/inlayHint" => Some(inlay_hints_result(state, &request.params)),
        "textDocument/documentHighlight" => Some(document_highlight_result(state, &request.params)),
        "workspace/symbol" => Some(workspace_symbol_result(state, &request.params)),
        "textDocument/selectionRange" => Some(selection_range_result(state, &request.params)),
        "textDocument/semanticTokens/range" => {
            Some(semantic_tokens_range_result(state, &request.params))
        }
        _ => None,
    }
}

/// Resolve a document URI to its module, file handle, and borrowed source
/// text, or return `NoResult` when the document is unknown. Used by every
/// handler that needs only a located file (groups B and C).
fn locate_ctx(
    state: &State,
    uri: &Url,
) -> Result<(Vec<String>, ipe_db::SourceFile), FeatureOutcome> {
    state.locate(uri).ok_or(FeatureOutcome::NoResult)
}

/// Context for a position-bearing request (group A). Collapses: locate →
/// `NoResult`, root-missing → `NoResult`, entry-file-missing → `NoResult`,
/// UTF-16 → byte offset (saturating at `u32::MAX`).
struct PosCtx<'db> {
    module: Vec<String>,
    file: ipe_db::SourceFile,
    /// Source text borrowed from the salsa database for this request.
    text: &'db str,
    root: ipe_db::SourceRoot,
    entry_file: ipe_db::SourceFile,
    /// Byte offset of the cursor position, saturated to `u32::MAX`.
    byte: u32,
}

fn position_ctx<'db>(
    state: &'db State,
    uri: &Url,
    position: lsp_types::Position,
) -> Result<PosCtx<'db>, FeatureOutcome> {
    let (module, file) = locate_ctx(state, uri)?;
    let text = file.text(&state.db);
    let Some(root) = state.root else {
        return Err(FeatureOutcome::NoResult);
    };
    let Some(entry_file) = root.files(&state.db).get(state.entry_module()).copied() else {
        return Err(FeatureOutcome::NoResult);
    };
    let byte = offset::position_to_offset(text, position, state.encoding);
    let byte = u32::try_from(byte).unwrap_or(u32::MAX);
    Ok(PosCtx {
        module,
        file,
        text,
        root,
        entry_file,
        byte,
    })
}

/// `textDocument/hover` — the solved type of the innermost expression at the
/// cursor. `null` for an unknown document, an unsolvable program, or a
/// position on no expression (never a guess).
fn hover_result(state: &State, params: &serde_json::Value) -> FeatureOutcome {
    let Ok(params) = serde_json::from_value::<lsp_types::HoverParams>(params.clone()) else {
        return FeatureOutcome::InvalidParams("invalid params for textDocument/hover".into());
    };
    let position = params.text_document_position_params;
    let Ok(ctx) = position_ctx(state, &position.text_document.uri, position.position) else {
        return FeatureOutcome::NoResult;
    };
    ipe_lsp_features::hover::hover(
        &state.db,
        ctx.root,
        ctx.entry_file,
        ctx.file,
        &ctx.module,
        ctx.byte,
        state.docs(),
    )
    .map_or(FeatureOutcome::NoResult, |info| {
        let range = Some(ipe_lsp_features::offset::span_to_range(
            ctx.text,
            info.span,
            state.encoding,
        ));
        let ty_marked = lsp_types::MarkedString::LanguageString(lsp_types::LanguageString {
            language: "ipe".to_owned(),
            value: info.ty,
        });
        // Beneath the type, disclose the compiler-derived control model — the
        // same signal `ipe audit`/`ipe doc` surface, so the editor reads one
        // derivation — then the binding's doc-string when it has one.
        let mut parts = vec![ty_marked];
        if let Some(model) = info.control_model {
            parts.push(lsp_types::MarkedString::String(format!(
                "control model: {model}"
            )));
        }
        if let Some(doc) = info.doc {
            parts.push(lsp_types::MarkedString::String(doc));
        }
        let contents = if parts.len() == 1 {
            lsp_types::HoverContents::Scalar(parts.remove(0))
        } else {
            lsp_types::HoverContents::Array(parts)
        };
        FeatureOutcome::payload(lsp_types::Hover { contents, range })
    })
}

/// `textDocument/documentLink` — every resolved `import` as a link to the
/// imported module's file.
fn document_links_result(state: &State, params: &serde_json::Value) -> FeatureOutcome {
    let Ok(params) = serde_json::from_value::<lsp_types::DocumentLinkParams>(params.clone()) else {
        return FeatureOutcome::InvalidParams(
            "invalid params for textDocument/documentLink".into(),
        );
    };
    let Some((_module, file)) = state.locate(&params.text_document.uri) else {
        return FeatureOutcome::NoResult;
    };
    let text = file.text(&state.db);
    let Some(root) = state.root else {
        return FeatureOutcome::NoResult;
    };
    let links: Vec<lsp_types::DocumentLink> =
        ipe_lsp_features::links::document_links(&state.db, root, file)
            .into_iter()
            .filter_map(|link| {
                let target = state.uri_for_module(&link.target_module)?;
                Some(lsp_types::DocumentLink {
                    range: ipe_lsp_features::offset::span_to_range(text, link.span, state.encoding),
                    target: Some(target),
                    tooltip: None,
                    data: None,
                })
            })
            .collect();
    FeatureOutcome::payload(links)
}

/// `textDocument/foldingRange` — the import block plus every multi-line
/// top-level declaration.
fn folding_ranges_result(state: &State, params: &serde_json::Value) -> FeatureOutcome {
    let Ok(params) = serde_json::from_value::<lsp_types::FoldingRangeParams>(params.clone()) else {
        return FeatureOutcome::InvalidParams(
            "invalid params for textDocument/foldingRange".into(),
        );
    };
    let Ok((_module, file)) = locate_ctx(state, &params.text_document.uri) else {
        return FeatureOutcome::NoResult;
    };
    let ranges = ipe_lsp_features::folding::folding_ranges(&state.db, file, state.encoding);
    FeatureOutcome::payload(ranges)
}

/// `textDocument/documentSymbol` — the parse tree's hierarchical outline.
fn document_symbols_result(state: &State, params: &serde_json::Value) -> FeatureOutcome {
    let Ok(params) = serde_json::from_value::<lsp_types::DocumentSymbolParams>(params.clone())
    else {
        return FeatureOutcome::InvalidParams(
            "invalid params for textDocument/documentSymbol".into(),
        );
    };
    let Ok((_module, file)) = locate_ctx(state, &params.text_document.uri) else {
        return FeatureOutcome::NoResult;
    };
    let symbols = ipe_lsp_features::symbols::document_symbols(&state.db, file, state.encoding);
    FeatureOutcome::payload(lsp_types::DocumentSymbolResponse::Nested(symbols))
}

/// `textDocument/completion` — in-scope identifiers at the cursor position.
fn completion_result(state: &State, params: &serde_json::Value) -> FeatureOutcome {
    let Ok(params) = serde_json::from_value::<lsp_types::CompletionParams>(params.clone()) else {
        return FeatureOutcome::InvalidParams("invalid params for textDocument/completion".into());
    };
    let position = params.text_document_position;
    // Convert the UTF-16 cursor position to a byte offset so completion can read
    // the type the surrounding context expects there (type-directed ranking).
    let Ok(ctx) = position_ctx(state, &position.text_document.uri, position.position) else {
        return FeatureOutcome::NoResult;
    };
    // A `Qualifier.member` trigger (`Font.`, `F.bol`, `Ipe.Ui.Font.`) is
    // answered from that qualifier's own exports only — never the global
    // list — and closes even for an unknown qualifier (`Some(vec![])`, not a
    // fallback to the unqualified path). Only a byte that is not on such a
    // trigger at all falls through to whole-scope completion.
    let items = ipe_lsp_features::completion::qualified_completions(
        &state.db,
        ctx.root,
        ctx.entry_file,
        &ctx.module,
        ctx.byte,
        state.encoding,
        state.docs(),
    )
    .unwrap_or_else(|| {
        ipe_lsp_features::completion::completions(
            &state.db,
            ctx.root,
            ctx.entry_file,
            &ctx.module,
            ctx.byte,
            state.encoding,
            state.docs(),
        )
    });
    FeatureOutcome::payload(lsp_types::CompletionResponse::List(
        lsp_types::CompletionList {
            is_incomplete: false,
            items,
        },
    ))
}

/// `textDocument/definition` — jump to the defining site of the name under
/// the cursor.
fn definition_result(state: &State, params: &serde_json::Value) -> FeatureOutcome {
    let Ok(params) = serde_json::from_value::<lsp_types::GotoDefinitionParams>(params.clone())
    else {
        return FeatureOutcome::InvalidParams("invalid params for textDocument/definition".into());
    };
    let position = params.text_document_position_params;
    let Ok(ctx) = position_ctx(state, &position.text_document.uri, position.position) else {
        return FeatureOutcome::NoResult;
    };
    let Some(def) = ipe_lsp_features::navigation::goto_definition(
        &state.db,
        ctx.root,
        ctx.entry_file,
        &ctx.module,
        ctx.byte,
    ) else {
        return FeatureOutcome::NoResult;
    };
    let Some(def_uri) = state.uri_for_module(&def.module) else {
        return FeatureOutcome::NoResult;
    };
    // Borrow the target text to convert the byte span to a range.
    let empty = String::new();
    let def_text = ctx
        .root
        .files(&state.db)
        .get(&def.module)
        .map_or(&empty, |f| f.text(&state.db));
    let range = ipe_lsp_features::offset::span_to_range(def_text, def.span, state.encoding);
    let location = lsp_types::Location {
        uri: def_uri,
        range,
    };
    FeatureOutcome::payload(location)
}

/// `textDocument/typeDefinition` — jump to the declaration of the *type* of the
/// expression under the cursor. `null` when the cursor is on no solved region,
/// the type is not a named type (a function / tuple / record / variable), or
/// the type is declared outside the project (a kernel / stdlib type).
fn type_definition_result(state: &State, params: &serde_json::Value) -> FeatureOutcome {
    let Ok(params) = serde_json::from_value::<lsp_types::GotoDefinitionParams>(params.clone())
    else {
        return FeatureOutcome::InvalidParams(
            "invalid params for textDocument/typeDefinition".into(),
        );
    };
    let position = params.text_document_position_params;
    let Ok(ctx) = position_ctx(state, &position.text_document.uri, position.position) else {
        return FeatureOutcome::NoResult;
    };
    let Some(def) = ipe_lsp_features::navigation::type_definition(
        &state.db,
        ctx.root,
        ctx.entry_file,
        &ctx.module,
        ctx.byte,
    ) else {
        return FeatureOutcome::NoResult;
    };
    let Some(def_uri) = state.uri_for_module(&def.module) else {
        return FeatureOutcome::NoResult;
    };
    let empty = String::new();
    let def_text = ctx
        .root
        .files(&state.db)
        .get(&def.module)
        .map_or(&empty, |f| f.text(&state.db));
    let range = ipe_lsp_features::offset::span_to_range(def_text, def.span, state.encoding);
    FeatureOutcome::payload(lsp_types::Location {
        uri: def_uri,
        range,
    })
}

/// `textDocument/references` — every use site of the name under the cursor.
fn references_result(state: &State, params: &serde_json::Value) -> FeatureOutcome {
    let Ok(params) = serde_json::from_value::<lsp_types::ReferenceParams>(params.clone()) else {
        return FeatureOutcome::InvalidParams("invalid params for textDocument/references".into());
    };
    let position = params.text_document_position;
    let Ok(ctx) = position_ctx(state, &position.text_document.uri, position.position) else {
        return FeatureOutcome::NoResult;
    };
    // Resolve via goto_definition to get the canonical (home, name) pair.
    let Some(def) = ipe_lsp_features::navigation::goto_definition(
        &state.db,
        ctx.root,
        ctx.entry_file,
        &ctx.module,
        ctx.byte,
    ) else {
        return FeatureOutcome::NoResult;
    };
    // Borrow each module's salsa-owned text rather than cloning the whole file:
    // once for the definition, and once per module a reference lands in.
    let files = ctx.root.files(&state.db);
    let text_of = |module: &[String]| files.get(module).map(|f| f.text(&state.db));
    let Some(def_text) = text_of(&def.module) else {
        return FeatureOutcome::NoResult;
    };
    let lo = def.span.lo as usize;
    let hi = def.span.hi as usize;
    let Some(def_name) = def_text.get(lo..hi) else {
        return FeatureOutcome::NoResult;
    };
    let refs = ipe_lsp_features::navigation::find_references(
        &state.db,
        ctx.root,
        ctx.entry_file,
        &def.module,
        def_name,
    );
    let mut locations: Vec<lsp_types::Location> = Vec::new();
    // Include definition if requested.
    if params.context.include_declaration
        && let Some(def_uri) = state.uri_for_module(&def.module)
    {
        let range = ipe_lsp_features::offset::span_to_range(def_text, def.span, state.encoding);
        locations.push(lsp_types::Location {
            uri: def_uri,
            range,
        });
    }
    for r in refs {
        let Some(ref_uri) = state.uri_for_module(&r.module) else {
            continue;
        };
        let Some(ref_text) = text_of(&r.module) else {
            continue;
        };
        let range = ipe_lsp_features::offset::span_to_range(ref_text, r.span, state.encoding);
        locations.push(lsp_types::Location {
            uri: ref_uri,
            range,
        });
    }
    FeatureOutcome::payload(locations)
}

/// `textDocument/prepareRename` — validate the position is renameable and
/// return the current identifier and its range.
fn prepare_rename_result(state: &State, params: &serde_json::Value) -> FeatureOutcome {
    let Ok(params) =
        serde_json::from_value::<lsp_types::TextDocumentPositionParams>(params.clone())
    else {
        return FeatureOutcome::InvalidParams(
            "invalid params for textDocument/prepareRename".into(),
        );
    };
    let Ok(ctx) = position_ctx(state, &params.text_document.uri, params.position) else {
        return FeatureOutcome::NoResult;
    };
    let Some(prep) = ipe_lsp_features::rename::prepare_rename(
        &state.db,
        ctx.root,
        ctx.entry_file,
        &ctx.module,
        ctx.byte,
    ) else {
        return FeatureOutcome::NoResult;
    };
    let range = ipe_lsp_features::offset::span_to_range(ctx.text, prep.span, state.encoding);
    // Return `{ range, placeholder }` — the standard `PrepareRenameResponse`.
    let response = lsp_types::PrepareRenameResponse::RangeWithPlaceholder {
        range,
        placeholder: prep.name,
    };
    FeatureOutcome::payload(response)
}

/// `textDocument/rename` — apply a rename across all references.
fn rename_result(state: &State, params: &serde_json::Value) -> FeatureOutcome {
    let Ok(params) = serde_json::from_value::<lsp_types::RenameParams>(params.clone()) else {
        return FeatureOutcome::InvalidParams("invalid params for textDocument/rename".into());
    };
    let position = params.text_document_position;
    let Ok(ctx) = position_ctx(state, &position.text_document.uri, position.position) else {
        return FeatureOutcome::NoResult;
    };
    let db = &state.db;
    let uri_of = |m: &[String]| state.uri_for_module(m);
    let text_of =
        |m: &[String]| -> Option<String> { ctx.root.files(db).get(m).map(|f| f.text(db).clone()) };
    let version_of = |uri: &Url| state.document_version(uri);
    let req = ipe_lsp_features::rename::RenameRequest {
        byte: ctx.byte,
        new_name: &params.new_name,
        encoding: state.encoding,
        document_changes_supported: state.document_changes,
    };
    let resolver = ipe_lsp_features::rename::ModuleResolver {
        uri_of_module: &uri_of,
        text_of_module: &text_of,
        version_of: &version_of,
    };
    let Some(ws_edit) = ipe_lsp_features::rename::rename(
        db,
        ctx.root,
        ctx.entry_file,
        &ctx.module,
        &req,
        &resolver,
    ) else {
        return FeatureOutcome::NoResult;
    };
    FeatureOutcome::payload(ws_edit)
}

/// Normalize a path for map keys: canonical when the file exists, verbatim
/// otherwise (fixture loaders use paths that exist nowhere).
fn normalize(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn handle_notification(
    state: &mut State,
    loader: &dyn ProjectLoader,
    notification: &Notification,
    diag_tx: &Sender<DiagnosticsBatch>,
) {
    match notification.method.as_str() {
        DidOpenTextDocument::METHOD => {
            let Ok(params) = serde_json::from_value::<lsp_types::DidOpenTextDocumentParams>(
                notification.params.clone(),
            ) else {
                return;
            };
            let Ok(path) = params.text_document.uri.to_file_path() else {
                return;
            };
            if path.extension().and_then(|e| e.to_str()) != Some("ipe") {
                return;
            }
            let path = normalize(&path);
            state.overlays.insert(
                path.clone(),
                Overlay {
                    text: params.text_document.text,
                    version: params.text_document.version,
                },
            );
            ensure_project(state, loader, &path);
            sync_inputs(state);
            recompute(state, diag_tx);
        }
        DidChangeTextDocument::METHOD => {
            let Ok(params) = serde_json::from_value::<lsp_types::DidChangeTextDocumentParams>(
                notification.params.clone(),
            ) else {
                return;
            };
            let Ok(path) = params.text_document.uri.to_file_path() else {
                return;
            };
            let path = normalize(&path);
            let encoding = state.encoding;
            let Some(overlay) = state.overlays.get_mut(&path) else {
                return;
            };
            for change in &params.content_changes {
                apply_content_change(&mut overlay.text, change, encoding);
            }
            overlay.version = params.text_document.version;
            if state.served.retries_on_edit() {
                // Unloaded or degraded; the edit may have fixed the very
                // defect (a module header, an oversized import closure) that
                // blocked the load.
                ensure_project_fresh(state, loader, &path);
            }
            sync_inputs(state);
            recompute(state, diag_tx);
        }
        DidSaveTextDocument::METHOD => {
            let Ok(params) = serde_json::from_value::<lsp_types::DidSaveTextDocumentParams>(
                notification.params.clone(),
            ) else {
                return;
            };
            let Ok(path) = params.text_document.uri.to_file_path() else {
                return;
            };
            // Re-resolve the layout from disk (files may have been added,
            // renamed, or removed since the last load).
            ensure_project_fresh(state, loader, &normalize(&path));
            sync_inputs(state);
            recompute(state, diag_tx);
        }
        DidCloseTextDocument::METHOD => {
            let Ok(params) = serde_json::from_value::<lsp_types::DidCloseTextDocumentParams>(
                notification.params.clone(),
            ) else {
                return;
            };
            let Ok(path) = params.text_document.uri.to_file_path() else {
                return;
            };
            let path = normalize(&path);
            state.overlays.remove(&path);
            // The closed buffer reverts to disk truth.
            ensure_project_fresh(state, loader, &path);
            sync_inputs(state);
            recompute(state, diag_tx);
        }
        DidChangeWatchedFiles::METHOD => {
            if let Some(anchor) = state.served.watched_file_anchor() {
                ensure_project_fresh(state, loader, &anchor);
                sync_inputs(state);
                recompute(state, diag_tx);
            }
        }
        _ => {}
    }
}

/// Load the project for `path` if the current layout does not know it.
fn ensure_project(state: &mut State, loader: &dyn ProjectLoader, path: &Path) {
    if matches!(&state.served, Served::Trusted(layout) if layout.module_of_path.contains_key(path))
    {
        return;
    }
    ensure_project_fresh(state, loader, path);
}

/// Unconditionally re-resolve the project layout anchored at `path`.
fn ensure_project_fresh(state: &mut State, loader: &dyn ProjectLoader, path: &Path) {
    let open_text = state.overlays.get(path).map(|o| o.text.as_str());
    let verdict = loader.load(state.workspace_root.as_deref(), path, open_text);
    let previous = std::mem::replace(&mut state.served, Served::Unloaded);
    state.served = match verdict {
        Ok(project) => Served::Trusted(Layout::of(project)),
        Err(err) => match (err.disposition(), previous) {
            // A refusal withdraws every layout, a trusted one included: the
            // compiler refuses the project, so no analysis of it stays shown.
            (LoadDisposition::Refuse, _) => {
                eprintln!("[ipe lsp] project load refused: {err}");
                Served::Refused {
                    anchor: path.to_path_buf(),
                    error: err,
                }
            }
            // A degraded load keeps a previously-good layout rather than
            // replacing it: a fallback would drop every other module from the
            // salsa root and clear their real diagnostics on the next publish.
            // Save and watched-file events retry unconditionally.
            (LoadDisposition::Degrade, Served::Trusted(layout)) => {
                eprintln!("[ipe lsp] project load failed, keeping the last good layout: {err}");
                Served::Trusted(layout)
            }
            (LoadDisposition::Degrade, Served::Fallback(layout)) => {
                eprintln!("[ipe lsp] project load failed: {err}");
                Served::Fallback(layout)
            }
            (LoadDisposition::Degrade, Served::Unloaded | Served::Refused { .. }) => {
                eprintln!("[ipe lsp] project load failed: {err}");
                // Degrade to a single-file layout so parse diagnostics still
                // flow for the open buffer; retried on the next edit.
                state.overlays.get(path).map_or(Served::Unloaded, |o| {
                    Served::Fallback(single_file_layout(path, o.text.clone()))
                })
            }
        },
    };
}

/// The one-module layout of a buffer served on its own.
///
/// Its lint source is [`LintSource::Unresolved`]: the failed load named no
/// project, so no `lint.ipe` is known to configure its rules.
fn single_file_layout(path: &Path, text: String) -> Layout {
    let module = vec![module_name_fallback(path)];
    let mut files = BTreeMap::new();
    files.insert(
        module.clone(),
        LoadedFile {
            path: path.to_path_buf(),
            text,
            origin: ModuleOrigin::User,
        },
    );
    Layout::index(files, module, LintSource::Unresolved)
}

fn module_name_fallback(path: &Path) -> String {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("Main")
        .to_owned()
}

/// Reconcile the salsa inputs with the current layout, open-buffer overlays
/// shadowing disk text.
fn sync_inputs(state: &mut State) {
    let desired: BTreeMap<Vec<String>, (String, ModuleOrigin)> =
        state.served.layout().map_or_else(BTreeMap::new, |layout| {
            layout
                .disk
                .iter()
                .map(|(module, file)| {
                    // Only a user module can carry an open-buffer overlay, and
                    // its normalized path was canonicalized once in
                    // `Layout::of`; reuse it rather than re-canonicalizing
                    // every module (a syscall) on each keystroke.
                    let overlay = layout
                        .path_of_module
                        .get(module)
                        .and_then(|path| state.overlays.get(path))
                        .map(|o| &o.text);
                    let text = overlay.unwrap_or(&file.text).clone();
                    (module.clone(), (text, file.origin))
                })
                .collect()
        });
    if let Some(root) = state.root {
        // Blocks until any in-flight worker's cancelled query unwinds and
        // drops its database clone — the cancellation edge.
        ipe_db::sync_source_root(&mut state.db, root, &desired);
    } else if !desired.is_empty() {
        let files: BTreeMap<Vec<String>, ipe_db::SourceFile> = desired
            .iter()
            .map(|(module, (text, origin))| {
                (
                    module.clone(),
                    ipe_db::SourceFile::new(&state.db, module.clone(), text.clone(), *origin),
                )
            })
            .collect();
        state.root = Some(ipe_db::SourceRoot::new(&state.db, files));
    }
}

fn apply_content_change(
    text: &mut String,
    change: &TextDocumentContentChangeEvent,
    encoding: PositionEncoding,
) {
    match change.range {
        None => {
            text.clone_from(&change.text);
        }
        Some(range) => {
            let start = offset::position_to_offset(text, range.start, encoding);
            let end = offset::position_to_offset(text, range.end, encoding).max(start);
            text.replace_range(start..end, &change.text);
        }
    }
}

/// Spawn a diagnostics worker against the current inputs, enforcing a
/// single-slot latest-wins discipline.
///
/// Any previously running worker is cancelled by mutating `state.db` (which
/// triggers salsa's `Cancelled` unwind in the worker's cloned snapshot) and
/// then joining the handle before the new worker is spawned. This guarantees
/// at most one live worker at any time, so fast edits cannot accumulate
/// unbounded threads or memory.
fn recompute(state: &mut State, diag_tx: &Sender<DiagnosticsBatch>) {
    let served = state.root.and_then(|root| {
        let entry_file = root.files(&state.db).get(state.entry_module()).copied()?;
        Some((root, entry_file))
    });

    // Bump the generation first so the outgoing worker's batch is stale.
    state.generation = state.generation.wrapping_add(1);

    let Some((root, entry_file)) = served else {
        // Nothing is analyzed: the batch holds only a refusal's own
        // diagnostic, so publishing it clears every earlier finding.
        let per_uri = match &state.served {
            Served::Refused { anchor, error } => Url::from_file_path(anchor)
                .map(|uri| vec![(uri, vec![load_refusal_diagnostic(error)])])
                .unwrap_or_default(),
            Served::Unloaded | Served::Fallback(_) | Served::Trusted(_) => Vec::new(),
        };
        let _ = diag_tx.send(DiagnosticsBatch {
            generation: state.generation,
            per_uri,
        });
        return;
    };

    // Cancel the previous worker by joining it. The worker holds a cloned
    // `IpeDatabase`; `sync_source_root` (called on every edit before
    // `recompute`) already mutates the shared salsa storage, causing the
    // cloned snapshot's next query to unwind with `Cancelled`. Joining here
    // ensures the old thread has exited and released its resources before we
    // allocate the next clone.
    if let Some(cancel) = state.worker_cancel.take() {
        // Signal the outgoing worker before joining: the compiler-diagnostics
        // phase unwinds via salsa `Cancelled` on the next demand, but the lint
        // tail has no further demand, so this flag is what lets it stop early.
        cancel.store(true, Ordering::Relaxed);
    }
    if let Some(prev) = state.worker.take() {
        // Ignore join errors — a panicking worker is already logged inside.
        let _ = prev.join();
    }

    let generation = state.generation;
    let db = state.db.clone();
    let encoding = state.encoding;
    let entry_module = state.entry_module().to_vec();
    let mut uri_of: BTreeMap<Vec<String>, Url> = BTreeMap::new();
    if let Some(layout) = state.served.layout() {
        for (module, path) in &layout.path_of_module {
            if let Ok(uri) = Url::from_file_path(path) {
                uri_of.insert(module.clone(), uri);
            }
        }
    }
    // Load `lint.ipe` once per recompute cycle, on the main thread where
    // filesystem I/O is allowed. The worker receives the verdict, not a path,
    // so it never touches the filesystem.
    let lint = state
        .served
        .layout()
        .and_then(|layout| layout.lint_source.dir())
        .map_or(LintPass::Skipped, LintPass::load);
    let cancel = Arc::new(AtomicBool::new(false));
    state.worker_cancel = Some(cancel.clone());
    let tx = diag_tx.clone();
    let spawned = thread::Builder::new()
        .name("ipe-lsp-diagnostics".to_owned())
        .spawn(move || {
            let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
                salsa::Cancelled::catch(AssertUnwindSafe(|| {
                    compute_batch(
                        &db,
                        root,
                        entry_file,
                        &uri_of,
                        &entry_module,
                        encoding,
                        &cancel,
                        &lint,
                    )
                }))
            }));
            match outcome {
                Ok(Ok(per_uri)) => {
                    let _ = tx.send(DiagnosticsBatch {
                        generation,
                        per_uri,
                    });
                }
                Ok(Err(_cancelled)) => {} // superseded — the newer worker owns the push
                Err(_panic) => {
                    eprintln!("[ipe lsp] internal error: diagnostics worker panicked");
                }
            }
        });
    match spawned {
        Ok(handle) => state.worker = Some(handle),
        Err(e) => {
            // No worker is running for this generation; the next edit's
            // recompute spawns a fresh one, so this is a skipped cycle, not a
            // stuck one.
            state.worker = None;
            eprintln!(
                "[ipe lsp] internal error: diagnostics worker thread refused: {:?}",
                e.kind()
            );
        }
    }
}

/// The diagnostic a refused project load publishes on the refused path.
fn load_refusal_diagnostic(error: &LoadError) -> lsp_types::Diagnostic {
    lsp_types::Diagnostic {
        range: lsp_types::Range::default(),
        severity: Some(lsp_types::DiagnosticSeverity::ERROR),
        code: None,
        code_description: None,
        source: Some("ipe".to_owned()),
        message: format!("project load refused: {error}"),
        related_information: None,
        tags: None,
        data: None,
    }
}

/// The lint pass of one recompute, fixed by whether `lint.ipe` loaded.
enum LintPass {
    /// No rule runs: no layout is served, or its lint source is unresolved.
    Skipped,
    /// Lint with the loaded configuration.
    Run(ipe_lint::LintConfig),
    /// `lint.ipe` was refused: no rule runs and its diagnostic is published instead.
    Withheld {
        /// The `lint.ipe` document, when its path forms a URI.
        uri: Option<Url>,
        /// The refusal, carrying the loader's typed error.
        diagnostic: Box<lsp_types::Diagnostic>,
    },
}

impl LintPass {
    /// Load `lint.ipe` from `dir` through the loader `ipe lint` uses.
    fn load(dir: &Path) -> Self {
        match ipe_lint::load_lint_config(dir) {
            Ok(config) => Self::Run(config),
            Err(err) => Self::Withheld {
                uri: Url::from_file_path(dir.join(ipe_lint::LINT_CONFIG_FILE)).ok(),
                diagnostic: Box::new(lint_config_diagnostic(&err)),
            },
        }
    }
}

/// The diagnostic a refused `lint.ipe` publishes on itself.
fn lint_config_diagnostic(err: &ipe_lint::LintConfigLoadError) -> lsp_types::Diagnostic {
    lsp_types::Diagnostic {
        range: lsp_types::Range::default(),
        severity: Some(lsp_types::DiagnosticSeverity::ERROR),
        code: None,
        code_description: None,
        source: Some("ipe-lint".to_owned()),
        message: format!("{err}; no lint rule runs until it loads"),
        related_information: None,
        tags: None,
        data: None,
    }
}

/// Pure worker body: collect, attribute, and map diagnostics to URIs.
/// A diagnostic owned by a module with no URI (injected stdlib) is
/// re-attributed to the entry document rather than dropped.
#[allow(clippy::too_many_arguments)] // all args are logically distinct; a struct wrapper adds ceremony
fn compute_batch(
    db: &ipe_db::IpeDatabase,
    root: ipe_db::SourceRoot,
    entry_file: ipe_db::SourceFile,
    uri_of: &BTreeMap<Vec<String>, Url>,
    entry_module: &[String],
    encoding: PositionEncoding,
    cancel: &AtomicBool,
    lint: &LintPass,
) -> Vec<(Url, Vec<lsp_types::Diagnostic>)> {
    let collected = diagnostics::collect(db, root, entry_file);
    let files = root.files(db);
    let entry_uri = uri_of.get(entry_module).cloned();
    let mut per_uri: BTreeMap<Url, Vec<lsp_types::Diagnostic>> = uri_of
        .values()
        .map(|uri| (uri.clone(), Vec::new()))
        .collect();
    let empty = String::new();
    for module_diags in collected {
        if module_diags.diagnostics.is_empty() {
            continue;
        }
        let direct_uri = uri_of.get(&module_diags.module).cloned();
        let re_attributed = direct_uri.is_none();
        let Some(uri) = direct_uri.or_else(|| entry_uri.clone()) else {
            continue;
        };
        // Borrow the salsa-owned text rather than cloning the whole module.
        let text = files
            .get(&module_diags.module)
            .map_or(&empty, |file| file.text(db));
        for diag in &module_diags.diagnostics {
            let mut lsp = diagnostics::to_lsp(diag, text, encoding);
            if re_attributed {
                lsp.range = lsp_types::Range::default();
                lsp.message = format!(
                    "in module {}: {}",
                    module_diags.module.join("."),
                    lsp.message
                );
            }
            per_uri.entry(uri.clone()).or_default().push(lsp);
        }
    }

    // A superseded worker skips the whole lint pass — the expensive tail that
    // never demands the db again and so cannot unwind via salsa `Cancelled`.
    // The newer worker owns the next publish, so dropping this one's lint work
    // is observationally identical.
    if cancel.load(Ordering::Relaxed) {
        return per_uri.into_iter().collect();
    }

    // Lint findings flow through the SAME diagnostics transport, appended after
    // the compiler's own diagnostics for each user document (the way clippy flows
    // through rust-analyzer). Only modules the editor owns a file for are linted —
    // injected stdlib is not the user's code. A refused `lint.ipe` runs no rule:
    // its diagnostic is published in place of every finding.
    let lint_config = match lint {
        LintPass::Run(config) => config,
        LintPass::Withheld { uri, diagnostic } => {
            if let Some(uri) = uri.clone().or(entry_uri) {
                per_uri
                    .entry(uri)
                    .or_default()
                    .push(diagnostic.as_ref().clone());
            }
            return per_uri.into_iter().collect();
        }
        LintPass::Skipped => return per_uri.into_iter().collect(),
    };
    let user_texts: BTreeMap<Vec<String>, String> = uri_of
        .keys()
        .filter_map(|module| {
            files
                .get(module)
                .map(|file| (module.clone(), file.text(db).clone()))
        })
        .collect();
    for (module, lints) in diagnostics::collect_lint(&user_texts, lint_config, encoding) {
        if let Some(uri) = uri_of.get(&module) {
            per_uri.entry(uri.clone()).or_default().extend(lints);
        }
    }

    per_uri.into_iter().collect()
}

/// `textDocument/formatting` — reformat the whole document.
fn formatting_result(state: &State, params: &serde_json::Value) -> FeatureOutcome {
    let Ok(params) = serde_json::from_value::<lsp_types::DocumentFormattingParams>(params.clone())
    else {
        return FeatureOutcome::InvalidParams("invalid params for textDocument/formatting".into());
    };
    let Ok((_module, file)) = locate_ctx(state, &params.text_document.uri) else {
        return FeatureOutcome::NoResult;
    };
    let edits = ipe_lsp_features::formatting::format_document(&state.db, file, state.encoding);
    FeatureOutcome::payload(edits)
}

/// `textDocument/rangeFormatting` — reformat a selected range.
fn range_formatting_result(state: &State, params: &serde_json::Value) -> FeatureOutcome {
    let Ok(params) =
        serde_json::from_value::<lsp_types::DocumentRangeFormattingParams>(params.clone())
    else {
        return FeatureOutcome::InvalidParams(
            "invalid params for textDocument/rangeFormatting".into(),
        );
    };
    let Ok((_module, file)) = locate_ctx(state, &params.text_document.uri) else {
        return FeatureOutcome::NoResult;
    };
    let edits =
        ipe_lsp_features::formatting::format_range(&state.db, file, params.range, state.encoding);
    FeatureOutcome::payload(edits)
}

/// `textDocument/codeAction` — diagnostic-driven quick-fixes.
fn code_action_result(state: &State, params: &serde_json::Value) -> FeatureOutcome {
    let Ok(params) = serde_json::from_value::<lsp_types::CodeActionParams>(params.clone()) else {
        return FeatureOutcome::InvalidParams("invalid params for textDocument/codeAction".into());
    };
    let Some((module, file)) = state.locate(&params.text_document.uri) else {
        return FeatureOutcome::NoResult;
    };
    let text = file.text(&state.db);
    let Some(root) = state.root else {
        return FeatureOutcome::NoResult;
    };
    let Some(entry_file) = root.files(&state.db).get(state.entry_module()).copied() else {
        return FeatureOutcome::NoResult;
    };
    let view = ipe_lsp_features::code_actions::DbView {
        db: &state.db,
        root,
        entry: entry_file,
    };
    let only = params.context.only.as_deref();
    let version = state.document_version(&params.text_document.uri);
    let mut actions = ipe_lsp_features::code_actions::code_actions(
        view,
        &module,
        ipe_lsp_features::workspace_edit::Document {
            uri: &params.text_document.uri,
            text,
            version,
        },
        params.range,
        &params.context.diagnostics,
        state.encoding,
    );
    actions.extend(ipe_lsp_features::refactor::refactor_actions(
        view,
        &module,
        &params.text_document.uri,
        params.range,
        text,
        state.encoding,
        version,
    ));
    ipe_lsp_features::action_kind::retain_offered(&mut actions, only);
    // Whole-document `source.*` rewrites run only when `only` names a source
    // kind, and never over a `lint.ipe` that is unresolved or failed to load.
    if ipe_lsp_features::source_actions::requested(only) {
        let lint_config = state
            .served
            .layout()
            .and_then(|layout| layout.lint_source.dir())
            .map(ipe_lint::load_lint_config);
        match lint_config {
            None => {}
            Some(Ok(lint_config)) => {
                actions.extend(ipe_lsp_features::source_actions::source_actions(
                    &module,
                    ipe_lsp_features::workspace_edit::Document {
                        uri: &params.text_document.uri,
                        text,
                        version,
                    },
                    &lint_config,
                    only,
                    state.encoding,
                ));
            }
            Some(Err(e)) => eprintln!("[ipe lsp] {e}; no source actions offered"),
        }
    }
    FeatureOutcome::payload(actions)
}

/// `textDocument/semanticTokens/full` — full semantic token encoding.
fn semantic_tokens_full_result(state: &State, params: &serde_json::Value) -> FeatureOutcome {
    let Ok(params) = serde_json::from_value::<lsp_types::SemanticTokensParams>(params.clone())
    else {
        return FeatureOutcome::InvalidParams(
            "invalid params for textDocument/semanticTokens/full".into(),
        );
    };
    let Ok((_module, file)) = locate_ctx(state, &params.text_document.uri) else {
        return FeatureOutcome::NoResult;
    };
    let result =
        ipe_lsp_features::semantic_tokens::semantic_tokens_full(&state.db, file, state.encoding);
    FeatureOutcome::payload(result)
}

/// `textDocument/signatureHelp` — callee signature at the cursor.
fn signature_help_result(state: &State, params: &serde_json::Value) -> FeatureOutcome {
    let Ok(params) = serde_json::from_value::<lsp_types::SignatureHelpParams>(params.clone())
    else {
        return FeatureOutcome::InvalidParams(
            "invalid params for textDocument/signatureHelp".into(),
        );
    };
    let position = params.text_document_position_params;
    let Ok(ctx) = position_ctx(state, &position.text_document.uri, position.position) else {
        return FeatureOutcome::NoResult;
    };
    FeatureOutcome::maybe(ipe_lsp_features::signature_help::signature_help(
        &state.db,
        ctx.root,
        ctx.entry_file,
        &ctx.module,
        ctx.byte,
        state.docs(),
    ))
}

/// `textDocument/inlayHint` — type annotation inlay hints.
fn inlay_hints_result(state: &State, params: &serde_json::Value) -> FeatureOutcome {
    let Ok(params) = serde_json::from_value::<lsp_types::InlayHintParams>(params.clone()) else {
        return FeatureOutcome::InvalidParams("invalid params for textDocument/inlayHint".into());
    };
    let Some((module, _file)) = state.locate(&params.text_document.uri) else {
        return FeatureOutcome::NoResult;
    };
    let Some(root) = state.root else {
        return FeatureOutcome::NoResult;
    };
    let Some(entry_file) = root.files(&state.db).get(state.entry_module()).copied() else {
        return FeatureOutcome::NoResult;
    };
    let hints = ipe_lsp_features::inlay_hints::inlay_hints(
        &state.db,
        root,
        entry_file,
        &module,
        params.range,
        state.encoding,
    );
    FeatureOutcome::payload(hints)
}

/// `textDocument/documentHighlight` — all occurrences of the name under the
/// cursor in the same document, as read/write/text highlight ranges.
fn document_highlight_result(state: &State, params: &serde_json::Value) -> FeatureOutcome {
    let Ok(params) = serde_json::from_value::<lsp_types::DocumentHighlightParams>(params.clone())
    else {
        return FeatureOutcome::InvalidParams(
            "invalid params for textDocument/documentHighlight".into(),
        );
    };
    let position = params.text_document_position_params;
    let Ok(ctx) = position_ctx(state, &position.text_document.uri, position.position) else {
        return FeatureOutcome::NoResult;
    };
    // Resolve to the canonical (home, name) pair via goto_definition.
    let Some(def) = ipe_lsp_features::navigation::goto_definition(
        &state.db,
        ctx.root,
        ctx.entry_file,
        &ctx.module,
        ctx.byte,
    ) else {
        return FeatureOutcome::NoResult;
    };
    let files = ctx.root.files(&state.db);
    let text_of = |m: &[String]| files.get(m).map(|f| f.text(&state.db));
    let Some(def_text) = text_of(&def.module) else {
        return FeatureOutcome::NoResult;
    };
    let lo = def.span.lo as usize;
    let hi = def.span.hi as usize;
    let Some(def_name) = def_text.get(lo..hi) else {
        return FeatureOutcome::NoResult;
    };
    // Collect references across all modules, then filter to the requested document.
    let refs = ipe_lsp_features::navigation::find_references(
        &state.db,
        ctx.root,
        ctx.entry_file,
        &def.module,
        def_name,
    );
    let mut highlights: Vec<lsp_types::DocumentHighlight> = Vec::new();
    // Include the definition site when it is in the same document.
    if def.module == ctx.module {
        let range = ipe_lsp_features::offset::span_to_range(def_text, def.span, state.encoding);
        highlights.push(lsp_types::DocumentHighlight {
            range,
            kind: Some(lsp_types::DocumentHighlightKind::TEXT),
        });
    }
    for r in refs {
        if r.module != ctx.module {
            continue;
        }
        let Some(ref_text) = text_of(&r.module) else {
            continue;
        };
        let range = ipe_lsp_features::offset::span_to_range(ref_text, r.span, state.encoding);
        highlights.push(lsp_types::DocumentHighlight {
            range,
            kind: Some(lsp_types::DocumentHighlightKind::TEXT),
        });
    }
    FeatureOutcome::payload(highlights)
}

/// `workspace/symbol` — project-wide symbol search filtered by `query`.
///
/// An empty query returns all symbols. A non-empty query performs a
/// case-insensitive substring match on the symbol name.
fn workspace_symbol_result(state: &State, params: &serde_json::Value) -> FeatureOutcome {
    let Ok(params) = serde_json::from_value::<lsp_types::WorkspaceSymbolParams>(params.clone())
    else {
        return FeatureOutcome::InvalidParams("invalid params for workspace/symbol".into());
    };
    let Some(root) = state.root else {
        return FeatureOutcome::NoResult;
    };
    let query = params.query.to_lowercase();
    let files = root.files(&state.db);
    let mut results: Vec<lsp_types::WorkspaceSymbol> = Vec::new();
    // Iterate all modules with a known URI; skip modules with no on-disk path.
    for (module_path, &file) in files {
        let Some(uri) = state.uri_for_module(module_path) else {
            continue;
        };
        let syms = ipe_lsp_features::symbols::document_symbols(&state.db, file, state.encoding);
        for sym in syms {
            if query.is_empty() || sym.name.to_lowercase().contains(&query) {
                let location = lsp_types::OneOf::Left(lsp_types::Location {
                    uri: uri.clone(),
                    range: sym.range,
                });
                results.push(lsp_types::WorkspaceSymbol {
                    name: sym.name,
                    kind: sym.kind,
                    tags: None,
                    container_name: Some(module_path.join(".")),
                    location,
                    data: None,
                });
            }
            // Include union constructor children as separate workspace symbols.
            for child in sym.children.into_iter().flatten() {
                if query.is_empty() || child.name.to_lowercase().contains(&query) {
                    let location = lsp_types::OneOf::Left(lsp_types::Location {
                        uri: uri.clone(),
                        range: child.range,
                    });
                    results.push(lsp_types::WorkspaceSymbol {
                        name: child.name,
                        kind: child.kind,
                        tags: None,
                        container_name: Some(module_path.join(".")),
                        location,
                        data: None,
                    });
                }
            }
        }
    }
    FeatureOutcome::payload(results)
}

/// `textDocument/selectionRange` — syntactic expand-selection ranges.
fn selection_range_result(state: &State, params: &serde_json::Value) -> FeatureOutcome {
    let Ok(params) = serde_json::from_value::<lsp_types::SelectionRangeParams>(params.clone())
    else {
        return FeatureOutcome::InvalidParams(
            "invalid params for textDocument/selectionRange".into(),
        );
    };
    let Ok((_module, file)) = locate_ctx(state, &params.text_document.uri) else {
        return FeatureOutcome::NoResult;
    };
    let ranges = ipe_lsp_features::selection_range::selection_ranges(
        &state.db,
        file,
        &params.positions,
        state.encoding,
    );
    FeatureOutcome::payload(ranges)
}

/// `textDocument/semanticTokens/range` — semantic tokens for a sub-range of
/// the document. Delta-encoded relative to the first token in the range.
fn semantic_tokens_range_result(state: &State, params: &serde_json::Value) -> FeatureOutcome {
    let Ok(params) = serde_json::from_value::<lsp_types::SemanticTokensRangeParams>(params.clone())
    else {
        return FeatureOutcome::InvalidParams(
            "invalid params for textDocument/semanticTokens/range".into(),
        );
    };
    let Ok((_module, file)) = locate_ctx(state, &params.text_document.uri) else {
        return FeatureOutcome::NoResult;
    };
    let result = ipe_lsp_features::semantic_tokens::semantic_tokens_range(
        &state.db,
        file,
        params.range,
        state.encoding,
    );
    FeatureOutcome::payload(result)
}

/// Latest-generation-wins publishing with change suppression: identical
/// payloads are not re-sent, and a URI whose diagnostics healed (or whose
/// module left the project) gets one clearing empty push.
fn publish(state: &mut State, connection: &Connection, batch: DiagnosticsBatch) {
    if batch.generation != state.generation {
        return;
    }
    let mut current: BTreeMap<Url, Vec<lsp_types::Diagnostic>> =
        batch.per_uri.into_iter().collect();
    for uri in state.last_published.keys() {
        current.entry(uri.clone()).or_default();
    }
    for (uri, diags) in &current {
        let previous = state.last_published.get(uri);
        if diags.is_empty() && previous.is_none() {
            continue; // nothing was ever shown here — nothing to clear
        }
        if previous == Some(diags) {
            continue;
        }
        let params = PublishDiagnosticsParams {
            uri: uri.clone(),
            diagnostics: diags.clone(),
            version: None,
        };
        let note = Notification::new(PublishDiagnostics::METHOD.to_owned(), params);
        let _ = connection.sender.send(Message::Notification(note));
    }
    state.last_published = current
        .into_iter()
        .filter(|(_, diags)| !diags.is_empty())
        .collect();
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use crossbeam_channel::RecvTimeoutError;

    use super::{
        Connection, DiagnosticsBatch, DidChangeTextDocument, DidChangeWatchedFiles, FeatureOutcome,
        Layout, LoadedFile, LoadedProject, Message, ModuleOrigin, Notification, Overlay, Path,
        PathBuf, PositionEncoding, ProjectLoader, PublishDiagnostics, PublishDiagnosticsParams,
        Served, State, TextDocumentContentChangeEvent, Url, code_action_result,
        ensure_project_fresh, handle_notification, normalize, publish, recompute, sync_inputs,
    };
    use crate::loader::{LimitSource, LoadDisposition, LoadError};
    use ipe_lint::{LintConfigLoadError, WorkspaceReadError, load_lint_config};
    use lsp_types::notification::Notification as _;

    /// A fresh, empty scratch directory for one `lint.ipe` test.
    fn lint_dir(name: &str) -> PathBuf {
        let dir =
            ipe_test_temp::temp_root().join(format!("ipe-lsp-lint-{}-{name}", std::process::id()));
        if dir.exists() {
            assert!(std::fs::remove_dir_all(&dir).is_ok(), "clear {dir:?}");
        }
        assert!(std::fs::create_dir_all(&dir).is_ok(), "create {dir:?}");
        dir
    }

    #[test]
    fn an_absent_lint_config_is_the_default() {
        let dir = lint_dir("absent");
        assert!(load_lint_config(&dir).is_ok());
    }

    #[test]
    fn an_oversized_lint_config_is_refused() {
        let dir = lint_dir("oversized");
        let over = usize::try_from(ipe_lint::LINT_CONFIG_MAX_BYTES.saturating_add(1));
        assert!(
            matches!(over, Ok(n) if std::fs::write(dir.join(ipe_lint::LINT_CONFIG_FILE), vec![b' '; n]).is_ok())
        );
        assert!(matches!(
            load_lint_config(&dir),
            Err(LintConfigLoadError::Read(
                WorkspaceReadError::TooLarge { .. }
            ))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_non_file_lint_config_is_refused() {
        let dir = lint_dir("not-a-file");
        assert!(std::fs::create_dir_all(dir.join(ipe_lint::LINT_CONFIG_FILE)).is_ok());
        assert!(matches!(
            load_lint_config(&dir),
            Err(LintConfigLoadError::Read(WorkspaceReadError::NotAFile))
        ));
    }

    #[test]
    fn an_invalid_lint_config_is_refused() {
        let dir = lint_dir("invalid");
        assert!(std::fs::write(dir.join(ipe_lint::LINT_CONFIG_FILE), "module (((\n").is_ok());
        assert!(matches!(
            load_lint_config(&dir),
            Err(LintConfigLoadError::Invalid(_))
        ));
    }

    /// A FIFO planted at `lint.ipe` is refused at once: the main loop never
    /// waits on a writer that will not come.
    #[cfg(unix)]
    #[test]
    fn a_fifo_lint_config_is_refused_without_blocking() {
        let dir = lint_dir("fifo");
        let made = std::process::Command::new("mkfifo")
            .arg(dir.join(ipe_lint::LINT_CONFIG_FILE))
            .status();
        assert!(matches!(made, Ok(s) if s.success()), "mkfifo: {made:?}");
        let (tx, rx) = crossbeam_channel::bounded(1);
        std::thread::Builder::new()
            .spawn(move || {
                let _ = tx.send(load_lint_config(&dir));
            })
            .expect("spawn test thread");
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(10)),
            Ok(Err(LintConfigLoadError::Read(WorkspaceReadError::NotAFile)))
        ));
    }

    /// A module a default-on lint rule flags: an `if` restating its condition.
    const LINTED_TEXT: &str = "module Main exposing (flag)\n\nflag : Bool -> Bool\nflag ready =\n    if ready then True else False\n";

    /// One diagnostics batch of a `LINTED_TEXT` project whose `lint.ipe` lives in `dir`.
    fn lint_batch(dir: &Path) -> BTreeMap<Url, Vec<lsp_types::Diagnostic>> {
        let main_path = normalize(dir).join("Main.ipe");
        served_batch(
            &BufferCeilingLoader::new(usize::MAX),
            &main_path,
            LINTED_TEXT,
        )
        .1
    }

    /// Open `text` at `main_path` through `loader` and take one diagnostics batch.
    fn served_batch(
        loader: &dyn ProjectLoader,
        main_path: &Path,
        text: &str,
    ) -> (State, BTreeMap<Url, Vec<lsp_types::Diagnostic>>) {
        let mut state = State::new(None, PositionEncoding::Utf16);
        state.overlays.insert(
            main_path.to_path_buf(),
            Overlay {
                text: text.to_owned(),
                version: 0,
            },
        );
        ensure_project_fresh(&mut state, loader, main_path);
        sync_inputs(&mut state);
        let (diag_tx, diag_rx) = crossbeam_channel::unbounded::<DiagnosticsBatch>();
        recompute(&mut state, &diag_tx);
        let batch = diag_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("diagnostics batch")
            .per_uri
            .into_iter()
            .collect();
        (state, batch)
    }

    /// A package loader whose load either names the package root's `lint.ipe`
    /// directory or fails in a pipeline stage (a broken `package.ipe`).
    struct PackageLoader {
        root: PathBuf,
        degrade: bool,
    }

    impl ProjectLoader for PackageLoader {
        fn load(
            &self,
            _workspace_root: Option<&Path>,
            open_file: &Path,
            open_text: Option<&str>,
        ) -> Result<LoadedProject, LoadError> {
            if self.degrade {
                return Err(LoadError::Pipeline("package.ipe: bad header".to_owned()));
            }
            let mut files = BTreeMap::new();
            files.insert(
                vec!["Main".to_owned()],
                LoadedFile {
                    path: open_file.to_path_buf(),
                    text: open_text.unwrap_or_default().to_owned(),
                    origin: ModuleOrigin::User,
                },
            );
            Ok(LoadedProject {
                files,
                entry_module: vec!["Main".to_owned()],
                lint_config_dir: self.root.clone(),
            })
        }
    }

    /// A package root whose `lint.ipe` denies the rule `LINTED_TEXT` trips,
    /// plus the path of its `src/Main.ipe`, where no `lint.ipe` lives.
    fn package_with_lint_config(name: &str) -> (PathBuf, PathBuf) {
        let root = normalize(&lint_dir(name));
        assert!(
            std::fs::write(
                root.join(ipe_lint::LINT_CONFIG_FILE),
                "module Lint exposing (lint)\n\nlint =\n    Lint.config\n        |> Lint.deny \"no-redundant-bool-if\"\n",
            )
            .is_ok()
        );
        assert!(std::fs::create_dir_all(root.join("src")).is_ok());
        let main_path = root.join("src").join("Main.ipe");
        (root, main_path)
    }

    /// Every `source.*` code action offered for `main_path` under `state`.
    fn source_action_kinds(state: &State, main_path: &Path) -> Vec<String> {
        let Ok(uri) = Url::from_file_path(main_path) else {
            return vec!["<no uri>".to_owned()];
        };
        let params = serde_json::json!({
            "textDocument": { "uri": uri },
            "range": {
                "start": { "line": 0, "character": 0 },
                "end": { "line": 0, "character": 0 }
            },
            "context": { "diagnostics": [], "only": ["source"] }
        });
        let FeatureOutcome::Payload(serde_json::Value::Array(actions)) =
            code_action_result(state, &params)
        else {
            return Vec::new();
        };
        actions
            .iter()
            .filter_map(|action| action.get("kind")?.as_str())
            .filter(|kind| kind.starts_with("source"))
            .map(str::to_owned)
            .collect()
    }

    /// Imports out of order: `source.organizeImports` has an edit to offer.
    const UNSORTED_TEXT: &str = "module Main exposing (main)\n\nimport Zeta\nimport Alpha\n\nmain =\n    (Zeta.a, Alpha.b)\n";

    #[test]
    fn a_resolved_package_lints_with_the_root_lint_config() {
        let (root, main_path) = package_with_lint_config("pkg-resolved");
        let loader = PackageLoader {
            root,
            degrade: false,
        };
        let (state, batch) = served_batch(&loader, &main_path, LINTED_TEXT);
        assert!(matches!(state.served, Served::Trusted(_)));
        let denied = batch.values().flatten().any(|d| {
            d.code
                == Some(lsp_types::NumberOrString::String(
                    "lint/no-redundant-bool-if".to_owned(),
                ))
                && d.severity == Some(lsp_types::DiagnosticSeverity::ERROR)
        });
        assert!(denied, "the root `lint.ipe` denies the rule: {batch:?}");
        let (state, _) = served_batch(&loader, &main_path, UNSORTED_TEXT);
        assert!(
            source_action_kinds(&state, &main_path)
                .iter()
                .any(|kind| kind == "source.organizeImports"),
            "a resolved project offers its source actions"
        );
    }

    #[test]
    fn a_degraded_package_load_runs_no_lint_rule() {
        let (root, main_path) = package_with_lint_config("pkg-degraded");
        let loader = PackageLoader {
            root: root.clone(),
            degrade: true,
        };
        let (state, batch) = served_batch(&loader, &main_path, LINTED_TEXT);
        assert!(matches!(state.served, Served::Fallback(_)));
        assert_eq!(
            lint_findings(&batch, &lint_config_uri(&root)),
            0,
            "a fallback never lints with a guessed `lint.ipe`: {batch:?}"
        );
        assert!(
            batch
                .values()
                .flatten()
                .all(|d| d.source.as_deref() != Some("ipe-lint")),
            "a fallback publishes no lint diagnostic at all: {batch:?}"
        );
    }

    #[test]
    fn a_degraded_package_load_offers_no_source_action() {
        let (root, main_path) = package_with_lint_config("pkg-degraded-actions");
        let loader = PackageLoader {
            root,
            degrade: true,
        };
        let (state, _) = served_batch(&loader, &main_path, UNSORTED_TEXT);
        assert!(matches!(state.served, Served::Fallback(_)));
        assert!(
            source_action_kinds(&state, &main_path).is_empty(),
            "a fallback offers no source action over an unresolved `lint.ipe`"
        );
    }

    /// The URI of the `lint.ipe` in `dir`.
    fn lint_config_uri(dir: &Path) -> Url {
        Url::from_file_path(normalize(dir).join(ipe_lint::LINT_CONFIG_FILE)).expect("config uri")
    }

    /// How many lint findings `batch` carries outside the `lint.ipe` document.
    fn lint_findings(batch: &BTreeMap<Url, Vec<lsp_types::Diagnostic>>, config: &Url) -> usize {
        batch
            .iter()
            .filter(|(uri, _)| *uri != config)
            .flat_map(|(_, diags)| diags)
            .filter(|d| d.source.as_deref() == Some("ipe-lint"))
            .count()
    }

    /// Assert `batch` carries exactly one refusal on `lint.ipe` and no finding.
    fn assert_lint_withheld(batch: &BTreeMap<Url, Vec<lsp_types::Diagnostic>>, config: &Url) {
        let on_config = batch.get(config).map_or(&[][..], Vec::as_slice);
        assert!(
            matches!(on_config, [d] if d.severity == Some(lsp_types::DiagnosticSeverity::ERROR)
                && d.message.contains("no lint rule runs")),
            "a refused `lint.ipe` publishes one error on itself: {on_config:?}"
        );
        assert_eq!(
            lint_findings(batch, config),
            0,
            "a refused `lint.ipe` runs no rule, the defaults included"
        );
    }

    #[test]
    fn an_absent_lint_config_lints_with_the_defaults() {
        let dir = lint_dir("lsp-absent");
        let config = lint_config_uri(&dir);
        let batch = lint_batch(&dir);
        assert!(
            !batch.contains_key(&config),
            "no diagnostic on an absent config"
        );
        assert!(
            lint_findings(&batch, &config) > 0,
            "the default rules flag the fixture: {batch:?}"
        );
    }

    #[test]
    fn an_invalid_lint_config_withholds_lint_and_publishes_its_refusal() {
        let dir = lint_dir("lsp-invalid");
        assert!(std::fs::write(dir.join(ipe_lint::LINT_CONFIG_FILE), "module (((\n").is_ok());
        assert_lint_withheld(&lint_batch(&dir), &lint_config_uri(&dir));
    }

    #[test]
    fn an_oversized_lint_config_withholds_lint_and_publishes_its_refusal() {
        let dir = lint_dir("lsp-oversized");
        let over = usize::try_from(ipe_lint::LINT_CONFIG_MAX_BYTES.saturating_add(1));
        assert!(
            matches!(over, Ok(n) if std::fs::write(dir.join(ipe_lint::LINT_CONFIG_FILE), vec![b' '; n]).is_ok())
        );
        assert_lint_withheld(&lint_batch(&dir), &lint_config_uri(&dir));
    }

    const MAIN_TEXT: &str = "module Main exposing (main)\n\nimport Ipe.Io as Io\n\nmain : Task Error ()\nmain =\n    Io.println \"ok\"\n";
    const LIB_TEXT: &str = "module Lib exposing (bad)\n\nbad : Int\nbad = \"nope\"\n";

    /// A two-module loader (`Main` open buffer + a static `Lib` with a real
    /// type error) that fails the NEXT `load` call when armed — the
    /// transient-failure shape `ensure_project_fresh` must survive without
    /// dropping the previously-good layout.
    struct TwoModuleLoader {
        fail_next: Arc<AtomicBool>,
        lib_path: PathBuf,
    }

    impl ProjectLoader for TwoModuleLoader {
        fn load(
            &self,
            _workspace_root: Option<&Path>,
            open_file: &Path,
            open_text: Option<&str>,
        ) -> Result<LoadedProject, LoadError> {
            if self.fail_next.swap(false, Ordering::SeqCst) {
                return Err(LoadError::Io("simulated transient failure".to_owned()));
            }
            let mut files = BTreeMap::new();
            files.insert(
                vec!["Main".to_owned()],
                LoadedFile {
                    path: open_file.to_path_buf(),
                    text: open_text.unwrap_or(MAIN_TEXT).to_owned(),
                    origin: ModuleOrigin::User,
                },
            );
            files.insert(
                vec!["Lib".to_owned()],
                LoadedFile {
                    path: self.lib_path.clone(),
                    text: LIB_TEXT.to_owned(),
                    origin: ModuleOrigin::User,
                },
            );
            for module in ipe_stdlib::COMPILED_STD_MODULES {
                let path: Vec<String> = module.dotted.split('.').map(str::to_owned).collect();
                files.insert(
                    path.clone(),
                    LoadedFile {
                        path: PathBuf::from(format!(
                            "<stdlib>/{}.ipe",
                            module.dotted.replace('.', "/")
                        )),
                        text: module.source.to_owned(),
                        origin: ModuleOrigin::EmbeddedStdlib,
                    },
                );
            }
            Ok(LoadedProject {
                files,
                entry_module: vec!["Main".to_owned()],
                lint_config_dir: ipe_lint::lint_config_dir(open_file),
            })
        }
    }

    #[test]
    fn load_error_disposition_splits_degrade_from_refuse() {
        let detail = || "detail".to_owned();
        for degraded in [
            LoadError::Pipeline(detail()),
            LoadError::Io(detail()),
            LoadError::Refused(detail()),
            LoadError::Limit {
                lifted_by: LimitSource::Buffer,
                detail: detail(),
            },
        ] {
            assert_eq!(
                degraded.disposition(),
                LoadDisposition::Degrade,
                "{degraded:?}"
            );
        }
        for refused in [
            LoadError::Limit {
                lifted_by: LimitSource::Filesystem,
                detail: detail(),
            },
            LoadError::FfiUntrusted(detail()),
            LoadError::ManifestUntrusted(detail()),
        ] {
            assert_eq!(
                refused.disposition(),
                LoadDisposition::Refuse,
                "{refused:?}"
            );
            assert_eq!(refused.to_string(), "detail");
        }
    }

    /// A loader whose every `load` fails with one fixed error.
    struct FailingLoader(LoadError);

    impl ProjectLoader for FailingLoader {
        fn load(
            &self,
            _workspace_root: Option<&Path>,
            _open_file: &Path,
            _open_text: Option<&str>,
        ) -> Result<LoadedProject, LoadError> {
            Err(self.0.clone())
        }
    }

    /// Every refusal a load can end in, one per refusing variant.
    fn every_refusal() -> [LoadError; 3] {
        [
            LoadError::Limit {
                lifted_by: LimitSource::Filesystem,
                detail: "ceiling".to_owned(),
            },
            LoadError::FfiUntrusted("untrusted".to_owned()),
            LoadError::ManifestUntrusted("untrusted".to_owned()),
        ]
    }

    #[test]
    fn a_refused_load_serves_no_layout() {
        let main_path = normalize(Path::new("/lsp-refuse-test/Main.ipe"));
        for refusal in every_refusal() {
            let mut state = State::new(None, PositionEncoding::Utf16);
            state.overlays.insert(
                main_path.clone(),
                Overlay {
                    text: MAIN_TEXT.to_owned(),
                    version: 0,
                },
            );
            ensure_project_fresh(&mut state, &FailingLoader(refusal), &main_path);
            assert!(
                matches!(&state.served, Served::Refused { anchor, .. } if *anchor == main_path),
                "a refusal must adopt no layout and anchor at the refused path"
            );
            assert!(
                state.served.layout().is_none(),
                "a refusal serves no layout"
            );
            assert!(
                !state.served.retries_on_edit(),
                "a refusal no edit can lift must not re-run the load per keystroke"
            );
            assert_eq!(
                state.served.watched_file_anchor(),
                Some(main_path.clone()),
                "a watched-file event must re-run the refused load"
            );
        }
    }

    /// A loader that counts its loads and refuses on a filesystem ceiling while armed.
    struct CountingRefusalLoader {
        loads: AtomicUsize,
        refusing: AtomicBool,
    }

    impl CountingRefusalLoader {
        const fn refusing() -> Self {
            Self {
                loads: AtomicUsize::new(0),
                refusing: AtomicBool::new(true),
            }
        }

        fn loads(&self) -> usize {
            self.loads.load(Ordering::SeqCst)
        }
    }

    impl ProjectLoader for CountingRefusalLoader {
        fn load(
            &self,
            _workspace_root: Option<&Path>,
            open_file: &Path,
            open_text: Option<&str>,
        ) -> Result<LoadedProject, LoadError> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            if self.refusing.load(Ordering::SeqCst) {
                return Err(LoadError::Limit {
                    lifted_by: LimitSource::Filesystem,
                    detail: "manifest walk ceiling".to_owned(),
                });
            }
            let mut files = BTreeMap::new();
            files.insert(
                vec!["Main".to_owned()],
                LoadedFile {
                    path: open_file.to_path_buf(),
                    text: open_text.unwrap_or(MAIN_TEXT).to_owned(),
                    origin: ModuleOrigin::User,
                },
            );
            Ok(LoadedProject {
                files,
                entry_module: vec!["Main".to_owned()],
                lint_config_dir: ipe_lint::lint_config_dir(open_file),
            })
        }
    }

    /// Deliver an empty `workspace/didChangeWatchedFiles` notification.
    fn did_change_watched_files(
        state: &mut State,
        loader: &dyn ProjectLoader,
        diag_tx: &crossbeam_channel::Sender<DiagnosticsBatch>,
    ) {
        let params = lsp_types::DidChangeWatchedFilesParams { changes: vec![] };
        let note = Notification::new(DidChangeWatchedFiles::METHOD.to_owned(), params);
        handle_notification(state, loader, &note, diag_tx);
    }

    #[test]
    fn a_refused_load_is_not_rerun_by_a_keystroke() {
        let main_path = normalize(Path::new("/lsp-refuse-keystroke-test/Main.ipe"));
        let loader = CountingRefusalLoader::refusing();
        let (diag_tx, _diag_rx) = crossbeam_channel::unbounded::<DiagnosticsBatch>();
        let mut state = State::new(None, PositionEncoding::Utf16);
        state.overlays.insert(
            main_path.clone(),
            Overlay {
                text: MAIN_TEXT.to_owned(),
                version: 0,
            },
        );
        ensure_project_fresh(&mut state, &loader, &main_path);
        assert_eq!(loader.loads(), 1, "the refused load ran once");
        for _ in 0..3 {
            did_change(&mut state, &loader, &main_path, MAIN_TEXT, &diag_tx);
        }
        assert_eq!(
            loader.loads(),
            1,
            "a keystroke must not re-run a load refused on the filesystem"
        );
        assert!(
            matches!(state.served, Served::Refused { .. }),
            "the refusal stands until a filesystem event"
        );
    }

    #[test]
    fn a_refused_load_is_rerun_by_a_watched_file_event() {
        let main_path = normalize(Path::new("/lsp-refuse-watched-test/Main.ipe"));
        let loader = CountingRefusalLoader::refusing();
        let (diag_tx, _diag_rx) = crossbeam_channel::unbounded::<DiagnosticsBatch>();
        let mut state = State::new(None, PositionEncoding::Utf16);
        state.overlays.insert(
            main_path.clone(),
            Overlay {
                text: MAIN_TEXT.to_owned(),
                version: 0,
            },
        );
        ensure_project_fresh(&mut state, &loader, &main_path);
        did_change_watched_files(&mut state, &loader, &diag_tx);
        assert_eq!(
            loader.loads(),
            2,
            "a watched-file event must re-run the refused load"
        );
        assert!(
            matches!(state.served, Served::Refused { .. }),
            "an unchanged filesystem refuses again"
        );
        loader.refusing.store(false, Ordering::SeqCst);
        did_change_watched_files(&mut state, &loader, &diag_tx);
        assert_eq!(loader.loads(), 3);
        assert!(
            matches!(state.served, Served::Trusted(_)),
            "the filesystem change that lifts the ceiling must be served"
        );
    }

    #[test]
    fn nothing_loaded_gives_a_watched_file_event_no_anchor() {
        let loader = CountingRefusalLoader::refusing();
        let (diag_tx, _diag_rx) = crossbeam_channel::unbounded::<DiagnosticsBatch>();
        let mut state = State::new(None, PositionEncoding::Utf16);
        did_change_watched_files(&mut state, &loader, &diag_tx);
        assert_eq!(loader.loads(), 0, "no anchor, no load");
        assert!(matches!(state.served, Served::Unloaded));
    }

    /// The last `publishDiagnostics` payload per URI `client` received.
    fn drain_published(client: &Connection) -> BTreeMap<Url, Vec<lsp_types::Diagnostic>> {
        let mut last = BTreeMap::new();
        while let Ok(msg) = client.receiver.recv_timeout(Duration::from_millis(500)) {
            if let Message::Notification(note) = msg
                && note.method == PublishDiagnostics::METHOD
                && let Ok(params) = serde_json::from_value::<PublishDiagnosticsParams>(note.params)
            {
                last.insert(params.uri, params.diagnostics);
            }
        }
        last
    }

    /// Sync, recompute, and publish `state`'s diagnostics through `server`.
    fn recompute_and_publish(state: &mut State, server: &Connection) {
        let (diag_tx, diag_rx) = crossbeam_channel::unbounded::<DiagnosticsBatch>();
        sync_inputs(state);
        recompute(state, &diag_tx);
        let batch = diag_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("diagnostics batch");
        publish(state, server, batch);
    }

    #[test]
    fn a_refusal_after_a_trusted_load_withdraws_its_analysis() {
        let main_path = normalize(Path::new("/lsp-refuse-withdraw-test/Main.ipe"));
        let lib_path = normalize(Path::new("/lsp-refuse-withdraw-test/Lib.ipe"));
        let main_uri = Url::from_file_path(&main_path).expect("main uri");
        let lib_uri = Url::from_file_path(&lib_path).expect("lib uri");
        let loader = TwoModuleLoader {
            fail_next: Arc::new(AtomicBool::new(false)),
            lib_path,
        };
        for refusal in every_refusal() {
            let mut state = State::new(None, PositionEncoding::Utf16);
            state.overlays.insert(
                main_path.clone(),
                Overlay {
                    text: MAIN_TEXT.to_owned(),
                    version: 0,
                },
            );
            let (server, client) = Connection::memory();
            ensure_project_fresh(&mut state, &loader, &main_path);
            assert!(matches!(state.served, Served::Trusted(_)), "first load");
            recompute_and_publish(&mut state, &server);
            assert!(
                drain_published(&client)
                    .get(&lib_uri)
                    .is_some_and(|diags| !diags.is_empty()),
                "the trusted analysis publishes Lib's type error"
            );

            let detail = refusal.to_string();
            ensure_project_fresh(&mut state, &FailingLoader(refusal), &main_path);
            assert!(
                matches!(&state.served, Served::Refused { anchor, .. } if *anchor == main_path),
                "a refusal withdraws the trusted layout"
            );
            recompute_and_publish(&mut state, &server);
            let after = drain_published(&client);
            assert!(
                after.get(&lib_uri).is_some_and(Vec::is_empty),
                "the refusal clears the stale finding on Lib: {after:?}"
            );
            let on_main = after.get(&main_uri).map_or(&[][..], Vec::as_slice);
            assert!(
                matches!(on_main, [d] if d.severity == Some(lsp_types::DiagnosticSeverity::ERROR)
                    && d.message.contains(&detail)),
                "the refused path shows only the refusal: {on_main:?}"
            );
        }
    }

    #[test]
    fn a_refused_first_load_publishes_its_refusal() {
        let main_path = normalize(Path::new("/lsp-refuse-first-test/Main.ipe"));
        let main_uri = Url::from_file_path(&main_path).expect("main uri");
        for refusal in every_refusal() {
            let mut state = State::new(None, PositionEncoding::Utf16);
            let (server, client) = Connection::memory();
            let detail = refusal.to_string();
            ensure_project_fresh(&mut state, &FailingLoader(refusal), &main_path);
            recompute_and_publish(&mut state, &server);
            let published = drain_published(&client);
            let on_main = published.get(&main_uri).map_or(&[][..], Vec::as_slice);
            assert!(
                matches!(on_main, [d] if d.message.contains(&detail)),
                "a refusal reaches the client as a diagnostic: {published:?}"
            );
        }
    }

    #[test]
    fn a_degraded_load_serves_the_single_file_fallback() {
        let main_path = normalize(Path::new("/lsp-degrade-test/Main.ipe"));
        for degraded in [
            LoadError::Pipeline("bad header".to_owned()),
            LoadError::Refused("not a regular file".to_owned()),
            LoadError::Limit {
                lifted_by: LimitSource::Buffer,
                detail: "import closure ceiling".to_owned(),
            },
        ] {
            let mut state = State::new(None, PositionEncoding::Utf16);
            state.overlays.insert(
                main_path.clone(),
                Overlay {
                    text: MAIN_TEXT.to_owned(),
                    version: 0,
                },
            );
            ensure_project_fresh(&mut state, &FailingLoader(degraded), &main_path);
            assert!(
                matches!(state.served, Served::Fallback(_)),
                "a degrade must adopt the open buffer"
            );
            assert!(
                state.served.retries_on_edit(),
                "a degrade must arm the per-edit retry"
            );
        }
    }

    /// A loader answering by the open buffer's size, the shape of a loose file's closure ceiling.
    ///
    /// A buffer longer than `ceiling` bytes hits a buffer-counted limit;
    /// arming `refuse_next` makes the next load a filesystem-counted one.
    struct BufferCeilingLoader {
        ceiling: usize,
        refuse_next: AtomicBool,
    }

    impl BufferCeilingLoader {
        const fn new(ceiling: usize) -> Self {
            Self {
                ceiling,
                refuse_next: AtomicBool::new(false),
            }
        }
    }

    impl ProjectLoader for BufferCeilingLoader {
        fn load(
            &self,
            _workspace_root: Option<&Path>,
            open_file: &Path,
            open_text: Option<&str>,
        ) -> Result<LoadedProject, LoadError> {
            if self.refuse_next.swap(false, Ordering::SeqCst) {
                return Err(LoadError::Limit {
                    lifted_by: LimitSource::Filesystem,
                    detail: "manifest walk ceiling".to_owned(),
                });
            }
            let text = open_text.unwrap_or_default();
            if text.len() > self.ceiling {
                return Err(LoadError::Limit {
                    lifted_by: LimitSource::Buffer,
                    detail: "import closure ceiling".to_owned(),
                });
            }
            let mut files = BTreeMap::new();
            files.insert(
                vec!["Main".to_owned()],
                LoadedFile {
                    path: open_file.to_path_buf(),
                    text: text.to_owned(),
                    origin: ModuleOrigin::User,
                },
            );
            Ok(LoadedProject {
                files,
                entry_module: vec!["Main".to_owned()],
                lint_config_dir: ipe_lint::lint_config_dir(open_file),
            })
        }
    }

    /// Replace the whole buffer at `path` through a `didChange` notification.
    #[allow(clippy::expect_used)] // test fixture: an absolute path always has a file URI
    fn did_change(
        state: &mut State,
        loader: &dyn ProjectLoader,
        path: &Path,
        text: &str,
        diag_tx: &crossbeam_channel::Sender<DiagnosticsBatch>,
    ) {
        let params = lsp_types::DidChangeTextDocumentParams {
            text_document: lsp_types::VersionedTextDocumentIdentifier {
                uri: Url::from_file_path(path).expect("file uri"),
                version: 2,
            },
            content_changes: vec![TextDocumentContentChangeEvent {
                range: None,
                range_length: None,
                text: text.to_owned(),
            }],
        };
        let note = Notification::new(DidChangeTextDocument::METHOD.to_owned(), params);
        handle_notification(state, loader, &note, diag_tx);
    }

    /// The buffer past its padding: the same module, longer than `MAIN_TEXT`.
    fn oversized_main() -> String {
        format!("{MAIN_TEXT}\n-- padding past the ceiling\n")
    }

    #[test]
    fn a_buffer_limit_degrades_and_an_edit_under_it_is_served_on_did_change() {
        let main_path = normalize(Path::new("/lsp-buffer-limit-test/Main.ipe"));
        let loader = BufferCeilingLoader::new(MAIN_TEXT.len());
        let (diag_tx, _diag_rx) = crossbeam_channel::unbounded::<DiagnosticsBatch>();
        let mut state = State::new(None, PositionEncoding::Utf16);
        state.overlays.insert(
            main_path.clone(),
            Overlay {
                text: oversized_main(),
                version: 0,
            },
        );
        ensure_project_fresh(&mut state, &loader, &main_path);
        assert!(
            matches!(state.served, Served::Fallback(_)),
            "a buffer-counted limit must degrade, not refuse"
        );
        did_change(&mut state, &loader, &main_path, MAIN_TEXT, &diag_tx);
        assert!(
            matches!(state.served, Served::Trusted(_)),
            "an edit under the limit must be re-served as the trusted layout"
        );
    }

    #[test]
    #[allow(clippy::expect_used)] // test fixture: an absolute path always has a file URI
    fn degrade_then_refuse_serves_nothing_until_a_watched_file_event() {
        let main_path = normalize(Path::new("/lsp-degrade-refuse-test/Main.ipe"));
        let main_uri = Url::from_file_path(&main_path).expect("main uri");
        let loader = BufferCeilingLoader::new(MAIN_TEXT.len());
        let (diag_tx, diag_rx) = crossbeam_channel::unbounded::<DiagnosticsBatch>();
        let mut state = State::new(None, PositionEncoding::Utf16);
        state.overlays.insert(
            main_path.clone(),
            Overlay {
                text: oversized_main(),
                version: 0,
            },
        );
        ensure_project_fresh(&mut state, &loader, &main_path);
        sync_inputs(&mut state);
        assert!(
            matches!(state.served, Served::Fallback(_)),
            "degraded first"
        );
        assert!(state.locate(&main_uri).is_some(), "the fallback is served");

        loader.refuse_next.store(true, Ordering::SeqCst);
        did_change(&mut state, &loader, &main_path, &oversized_main(), &diag_tx);
        assert!(
            matches!(state.served, Served::Refused { .. }),
            "a refusal must drop the fallback, not keep serving it"
        );
        assert!(
            state.locate(&main_uri).is_none(),
            "no request may be answered from the dropped fallback"
        );
        assert_eq!(
            state.root.map_or(0, |root| root.files(&state.db).len()),
            0,
            "the analyzed module set must be empty"
        );
        let cleared = diag_rx.try_recv().expect("a clearing diagnostics batch");
        assert_eq!(cleared.generation, state.generation);
        assert!(
            matches!(cleared.per_uri.as_slice(), [(uri, diags)]
                if *uri == main_uri && matches!(diags.as_slice(), [d] if d.message.contains("manifest walk ceiling"))),
            "the fallback's diagnostics are cleared, replaced only by the refusal itself: {:?}",
            cleared.per_uri
        );

        did_change(&mut state, &loader, &main_path, MAIN_TEXT, &diag_tx);
        assert!(
            matches!(state.served, Served::Refused { .. }),
            "an edit must not re-run a load refused on the filesystem"
        );
        assert!(
            state.locate(&main_uri).is_none(),
            "the refusal still serves nothing"
        );

        did_change_watched_files(&mut state, &loader, &diag_tx);
        assert!(
            matches!(state.served, Served::Trusted(_)),
            "a watched-file event must retry the load and serve its layout"
        );
        assert!(
            state.locate(&main_uri).is_some(),
            "the trusted layout is served"
        );
    }

    /// A load failure on an already-well-formed project (CO-INCR-007) must
    /// not clear `Lib`'s real diagnostics: the prior layout is kept and
    /// retried later, not replaced by the single-file fallback.
    #[test]
    fn transient_load_failure_keeps_prior_layout_diagnostics() {
        let main_path = normalize(Path::new("/lsp-278-test/Main.ipe"));
        let lib_path = normalize(Path::new("/lsp-278-test/Lib.ipe"));
        let lib_uri = Url::from_file_path(&lib_path).expect("lib uri");
        let fail_next = Arc::new(AtomicBool::new(false));
        let loader = TwoModuleLoader {
            fail_next: fail_next.clone(),
            lib_path,
        };

        let mut state = State::new(None, PositionEncoding::Utf16);
        state.overlays.insert(
            main_path.clone(),
            Overlay {
                text: MAIN_TEXT.to_owned(),
                version: 0,
            },
        );

        // First load succeeds: both modules known, Lib carries a real
        // compiler diagnostic.
        ensure_project_fresh(&mut state, &loader, &main_path);
        assert!(
            matches!(state.served, Served::Trusted(_)),
            "first load must succeed cleanly"
        );
        sync_inputs(&mut state);

        let (diag_tx, diag_rx) = crossbeam_channel::unbounded::<DiagnosticsBatch>();
        recompute(&mut state, &diag_tx);
        let batch1 = diag_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("first diagnostics batch");

        let (server_side, client) = Connection::memory();
        publish(&mut state, &server_side, batch1);

        let mut saw_lib_diagnostic = false;
        while let Ok(msg) = client.receiver.recv_timeout(Duration::from_millis(500)) {
            if let Message::Notification(note) = msg
                && note.method == PublishDiagnostics::METHOD
                && let Ok(params) = serde_json::from_value::<PublishDiagnosticsParams>(note.params)
                && params.uri == lib_uri
                && !params.diagnostics.is_empty()
            {
                saw_lib_diagnostic = true;
            }
        }
        assert!(
            saw_lib_diagnostic,
            "Lib's real diagnostic must publish before the transient failure"
        );

        // Arm a transient failure on the NEXT load — the shape of a
        // `didSave`/`DidChangeWatchedFiles` re-resolve racing a momentary
        // I/O error or a mid-rename tree.
        fail_next.store(true, Ordering::SeqCst);
        ensure_project_fresh(&mut state, &loader, &main_path);
        sync_inputs(&mut state);
        recompute(&mut state, &diag_tx);
        let batch2 = diag_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("second diagnostics batch");
        publish(&mut state, &server_side, batch2);

        // The prior layout must survive: no clearing push for Lib's
        // diagnostics reaches the client.
        loop {
            match client.receiver.recv_timeout(Duration::from_millis(500)) {
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => break,
                Ok(Message::Notification(note)) if note.method == PublishDiagnostics::METHOD => {
                    let params: PublishDiagnosticsParams =
                        serde_json::from_value(note.params).expect("valid params");
                    if params.uri == lib_uri {
                        assert!(
                            !params.diagnostics.is_empty(),
                            "a transient load failure must not clear Lib's real diagnostics"
                        );
                    }
                }
                Ok(_) => {}
            }
        }
    }

    /// Rapid successive `recompute` calls must not accumulate live worker
    /// threads, and stale batches must not reach the editor.
    ///
    /// Properties verified:
    /// (a) The worker slot holds at most one `JoinHandle` after each `recompute`
    ///     (bounded-threads invariant).
    /// (b) Every batch that arrives in the channel has a generation number no
    ///     greater than the final state generation (no generation can exceed the
    ///     current counter).
    /// (c) The consumer-side filter in `publish` rejects every batch whose
    ///     generation is less than the final state generation — only the latest
    ///     batch is ever applied.
    #[test]
    fn recompute_holds_at_most_one_live_worker() {
        let main_path = normalize(Path::new("/lsp-single-worker-test/Main.ipe"));
        let lib_path = normalize(Path::new("/lsp-single-worker-test/Lib.ipe"));
        let loader = TwoModuleLoader {
            fail_next: Arc::new(AtomicBool::new(false)),
            lib_path,
        };

        let mut state = State::new(None, PositionEncoding::Utf16);
        state.overlays.insert(
            main_path.clone(),
            Overlay {
                text: MAIN_TEXT.to_owned(),
                version: 0,
            },
        );

        ensure_project_fresh(&mut state, &loader, &main_path);
        sync_inputs(&mut state);

        let (diag_tx, diag_rx) = crossbeam_channel::unbounded::<DiagnosticsBatch>();

        // Fire several recompute calls in quick succession. Each call joins the
        // previous worker before spawning, so the slot holds at most one handle.
        for _ in 0..5 {
            recompute(&mut state, &diag_tx);
            // (a) Worker slot must be occupied — never accumulates.
            assert!(
                state.worker.is_some(),
                "worker slot must be occupied after recompute"
            );
        }

        // Wait for the final generation's batch to arrive (the last worker was
        // just spawned so it may still be running). Then drain any further batches
        // that arrive in quick succession.
        let final_generation = state.generation;
        let (server_side, client) = Connection::memory();
        let mut delivered_count = 0usize;

        // Block until the final-generation batch arrives.
        let mut current_generation_seen = false;
        loop {
            let batch = diag_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("diagnostics batch must arrive within timeout");

            // (b) No batch may claim a generation beyond the current counter.
            assert!(
                batch.generation <= final_generation,
                "batch generation {} exceeds final generation {}",
                batch.generation,
                final_generation,
            );
            delivered_count += 1;
            if batch.generation == final_generation {
                current_generation_seen = true;
            }
            // (c) Pass every batch through the consumer-side filter: stale batches
            // must be silently dropped; only the batch matching the final generation
            // is applied and forwarded to the editor.
            publish(&mut state, &server_side, batch);

            if current_generation_seen {
                break;
            }
        }

        // Drain any trailing batches that land within a short window.
        while let Ok(batch) = diag_rx.recv_timeout(Duration::from_millis(200)) {
            assert!(
                batch.generation <= final_generation,
                "late batch generation {} exceeds final generation {}",
                batch.generation,
                final_generation,
            );
            delivered_count += 1;
            publish(&mut state, &server_side, batch);
        }

        // The final generation must have been delivered.
        assert!(
            current_generation_seen,
            "the latest generation batch must be delivered"
        );

        // Verify publish suppressed stale notifications. The client receives
        // notifications only from the final-generation batch; superseded batches
        // are silently filtered and produce no output.
        let mut notification_count = 0usize;
        while let Ok(msg) = client.receiver.recv_timeout(Duration::from_millis(50)) {
            if let Message::Notification(note) = msg
                && note.method == PublishDiagnostics::METHOD
            {
                notification_count += 1;
            }
        }
        // With two URIs in the test layout, the final batch produces at most 2
        // notifications. Stale batches must have produced none — so total
        // notifications must be bounded by the number of URIs, not by the number
        // of delivered batches.
        assert!(
            notification_count <= 2,
            "stale batches must not produce notifications; got {notification_count} notifications from {delivered_count} total batches"
        );
    }

    // -----------------------------------------------------------------------
    // FeatureOutcome boundary tests
    // -----------------------------------------------------------------------

    /// A `Serialize` impl that always fails, used to exercise the `Encode`
    /// variant without depending on any `lsp_types` value.
    struct AlwaysFailsSerialize;

    impl serde::Serialize for AlwaysFailsSerialize {
        fn serialize<S: serde::Serializer>(&self, _s: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom(
                "intentional serialization failure",
            ))
        }
    }

    /// An encoding failure becomes `FeatureOutcome::Encode`, never `Payload(Null)`.
    #[test]
    fn payload_constructor_yields_encode_on_serialization_failure() {
        let outcome = FeatureOutcome::payload(AlwaysFailsSerialize);
        assert!(
            matches!(outcome, FeatureOutcome::Encode(_)),
            "a serialization failure must produce Encode, not Payload or NoResult"
        );
    }

    /// `FeatureOutcome::maybe` on `None` yields `NoResult`.
    #[test]
    fn maybe_constructor_none_yields_no_result() {
        let outcome = FeatureOutcome::maybe::<AlwaysFailsSerialize>(None);
        assert!(
            matches!(outcome, FeatureOutcome::NoResult),
            "maybe(None) must yield NoResult"
        );
    }

    /// `FeatureOutcome::maybe` on `Some(value)` that fails serialization yields `Encode`.
    #[test]
    fn maybe_constructor_some_failing_serialize_yields_encode() {
        let outcome = FeatureOutcome::maybe(Some(AlwaysFailsSerialize));
        assert!(
            matches!(outcome, FeatureOutcome::Encode(_)),
            "maybe(Some(unserializable)) must yield Encode, not NoResult or Payload"
        );
    }

    /// A well-typed value produces `Payload` with the expected JSON.
    #[test]
    fn payload_constructor_yields_payload_on_success() {
        let outcome = FeatureOutcome::payload(42u32);
        assert!(
            matches!(&outcome, FeatureOutcome::Payload(v) if *v == serde_json::json!(42)),
            "a well-typed value must produce Payload with the expected JSON"
        );
    }

    /// Asserts the encoding-to-null laundering pattern no longer appears in this
    /// file — the structural invariant established by the typed boundary.
    #[test]
    fn no_unwrap_or_null_launder_sites_remain_in_main_loop() {
        let src = include_str!("main_loop.rs");
        // Assemble the needle from fragments so this guard never matches its own
        // source text.
        let needle = format!("unwrap_or(serde_json::{}::Null)", "Value");
        let count = src.matches(needle.as_str()).count();
        assert_eq!(
            count, 0,
            "found {count} encoding-to-null launder site(s); all encoding failures \
             must go through FeatureOutcome::payload"
        );
    }

    // -----------------------------------------------------------------------
    // New handler tests
    // -----------------------------------------------------------------------

    /// Build a minimal two-module `State` (Helper + Main) from in-memory text.
    fn two_module_state() -> (State, PathBuf, PathBuf) {
        const HELPER: &str = "module Helper exposing (three)\n\nthree : Int\nthree = 3\n";
        const MAIN_SRC: &str = "module Main exposing (main)\n\nimport Helper exposing (three)\n\nmain : Int\nmain = three\n";

        let helper_path = normalize(Path::new("/test-proj/Helper.ipe"));
        let main_path = normalize(Path::new("/test-proj/Main.ipe"));
        let mut state = State::new(None, PositionEncoding::Utf8);

        let mut files = BTreeMap::new();
        files.insert(
            vec!["Helper".to_owned()],
            LoadedFile {
                path: helper_path.clone(),
                text: HELPER.to_owned(),
                origin: ModuleOrigin::User,
            },
        );
        files.insert(
            vec!["Main".to_owned()],
            LoadedFile {
                path: main_path.clone(),
                text: MAIN_SRC.to_owned(),
                origin: ModuleOrigin::User,
            },
        );
        let project = LoadedProject {
            files,
            entry_module: vec!["Main".to_owned()],
            lint_config_dir: ipe_lint::lint_config_dir(&main_path),
        };
        state.served = Served::Trusted(Layout::of(project));
        sync_inputs(&mut state);
        (state, helper_path, main_path)
    }

    /// `textDocument/documentHighlight` on the definition of `three` in
    /// `Helper` returns at least one highlight range (the definition site).
    #[test]
    fn document_highlight_returns_highlights_for_symbol_use() {
        let (state, _, main_path) = two_module_state();
        let main_uri = Url::from_file_path(&main_path).expect("main uri");

        // Cursor on the `three` use in `main = three` (Main line 5, col 7). A
        // reference position is where goto-definition — and thus highlight —
        // resolves the symbol; a definition name or annotation is not a
        // reference and yields no result.
        let params = serde_json::json!({
            "textDocument": { "uri": main_uri.as_str() },
            "position": { "line": 5, "character": 7 },
            "context": { "includeDeclaration": true }
        });

        let outcome = super::document_highlight_result(&state, &params);
        assert!(
            matches!(outcome, FeatureOutcome::Payload(_)),
            "expected Payload outcome from document_highlight_result"
        );
        let FeatureOutcome::Payload(json) = outcome else {
            return;
        };
        let highlights: Vec<lsp_types::DocumentHighlight> =
            serde_json::from_value(json).expect("valid highlights JSON");
        assert!(
            !highlights.is_empty(),
            "cursor on a `three` use must return at least one highlight"
        );
        // Every highlight is in the Main document (same-document filter).
        for h in &highlights {
            assert!(
                h.range.start.line >= 2,
                "highlight range must be within the import/use spans"
            );
        }
    }

    /// `workspace/symbol` with an empty query returns symbols from every
    /// module that has an on-disk path.
    #[test]
    fn workspace_symbol_empty_query_returns_all_symbols() {
        let (state, _, _) = two_module_state();

        let params = serde_json::json!({ "query": "" });
        let outcome = super::workspace_symbol_result(&state, &params);
        assert!(
            matches!(outcome, FeatureOutcome::Payload(_)),
            "expected Payload from workspace_symbol_result"
        );
        let FeatureOutcome::Payload(json) = outcome else {
            return;
        };
        let symbols: Vec<lsp_types::WorkspaceSymbol> =
            serde_json::from_value(json).expect("valid workspace symbols JSON");

        // At minimum: `three` from Helper + `main` from Main.
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains(&"three"),
            "workspace symbols must include 'three' from Helper; got {names:?}"
        );
        assert!(
            names.contains(&"main"),
            "workspace symbols must include 'main' from Main; got {names:?}"
        );
    }

    /// `workspace/symbol` with a non-empty query filters by case-insensitive
    /// substring — `"thr"` matches `three` but not `main`.
    #[test]
    fn workspace_symbol_query_filters_by_name() {
        let (state, _, _) = two_module_state();

        let params = serde_json::json!({ "query": "thr" });
        let outcome = super::workspace_symbol_result(&state, &params);
        assert!(
            matches!(outcome, FeatureOutcome::Payload(_)),
            "expected Payload from workspace_symbol_result"
        );
        let FeatureOutcome::Payload(json) = outcome else {
            return;
        };
        let symbols: Vec<lsp_types::WorkspaceSymbol> =
            serde_json::from_value(json).expect("valid workspace symbols JSON");
        assert!(
            symbols
                .iter()
                .all(|s| s.name.to_lowercase().contains("thr")),
            "all results must match query 'thr'; got {:?}",
            symbols.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
        assert!(!symbols.is_empty(), "'thr' must match at least 'three'");
    }

    /// Asserts that no handler still carries a bare `-> serde_json::Value` return type.
    #[test]
    fn no_handler_returns_bare_serde_json_value() {
        let src = include_str!("main_loop.rs");
        let bare_signatures: Vec<&str> = src
            .lines()
            .filter(|line| {
                line.contains("_result(")
                    && line.contains("-> serde_json::Value")
                    && !line.trim_start().starts_with("//")
            })
            .collect();
        assert!(
            bare_signatures.is_empty(),
            "handler(s) still return bare serde_json::Value: {bare_signatures:?}"
        );
    }
}
