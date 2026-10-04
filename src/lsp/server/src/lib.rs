#![forbid(unsafe_code)]
//! `ipe_lsp_server` — the Ipê language server's JSON-RPC main loop.
//!
//! A thin, synchronous single-writer loop over [`lsp_server`]: the loop owns
//! the one [`ipe_db::IpeDatabase`], mutates its inputs on document
//! notifications (in receipt order), and computes diagnostics on a worker
//! thread holding a cloned database handle — exactly `ipe dev watch`'s
//! orchestrator/worker split. A superseding edit cancels the in-flight
//! worker through salsa's own `Cancelled` unwind, so a stale diagnostics
//! push cannot be delivered.
//!
//! The server owns no language logic: feature payloads come from
//! [`ipe_lsp_features`], which reads the same memoized `ipe_db` queries
//! `ipe dev build` runs. Project layout resolution (filesystem, manifest,
//! stdlib injection) is injected through [`ProjectLoader`] by the CLI
//! driver — this crate and the driver are the only I/O holders; the query
//! layer never reads a file.

mod loader;
mod main_loop;

use std::fmt;

use lsp_server::Connection;
use lsp_types::{
    CompletionOptions, DocumentLinkOptions, FoldingRangeProviderCapability,
    HoverProviderCapability, InitializeParams, InitializeResult, OneOf, PositionEncodingKind,
    RenameOptions, SaveOptions, SelectionRangeProviderCapability, SemanticTokensFullOptions,
    SemanticTokensOptions, SemanticTokensServerCapabilities, ServerCapabilities, ServerInfo,
    SignatureHelpOptions, TextDocumentSyncCapability, TextDocumentSyncKind,
    TextDocumentSyncOptions, TextDocumentSyncSaveOptions, TypeDefinitionProviderCapability,
};

use ipe_lsp_features::PositionEncoding;
pub use loader::{
    LimitSource, LoadDisposition, LoadError, LoadedFile, LoadedProject, ModuleOrigin, ProjectLoader,
};

/// A fatal server failure: a protocol-level error on the JSON-RPC channel.
/// Per-request failures never surface here — they answer the one request
/// with an error response and the server keeps serving.
#[derive(Debug)]
pub struct ServerError {
    detail: String,
}

impl ServerError {
    fn new(detail: impl fmt::Display) -> Self {
        Self {
            detail: detail.to_string(),
        }
    }
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for ServerError {}

/// Serve LSP over stdio until the client sends `shutdown` + `exit`.
///
/// # Errors
/// [`ServerError`] on a protocol-level failure (malformed initialize
/// handshake, closed channel); never for a compile diagnostic.
pub fn run_stdio(loader: &dyn ProjectLoader) -> Result<(), ServerError> {
    let (connection, io_threads) = Connection::stdio();
    let served = run_with_connection(&connection, loader);
    // The connection owns the last live `Sender` feeding the writer I/O
    // thread; it must drop BEFORE the join below, or the writer never
    // observes disconnect and the process wedges on exit.
    drop(connection);
    io_threads.join().map_err(ServerError::new)?;
    served
}

/// Serve LSP over an existing connection (tests use
/// [`Connection::memory`]).
///
/// # Errors
/// [`ServerError`] on a protocol-level failure.
pub fn run_with_connection(
    connection: &Connection,
    loader: &dyn ProjectLoader,
) -> Result<(), ServerError> {
    let (id, params_json) = connection.initialize_start().map_err(ServerError::new)?;
    let init: InitializeParams = serde_json::from_value(params_json).map_err(ServerError::new)?;
    let encoding = negotiate_encoding(&init);
    let result = InitializeResult {
        capabilities: server_capabilities(encoding),
        server_info: Some(ServerInfo {
            name: "ipe-lsp".to_owned(),
            version: None,
        }),
    };
    let result_json = serde_json::to_value(result).map_err(ServerError::new)?;
    connection
        .initialize_finish(id, result_json)
        .map_err(ServerError::new)?;
    main_loop::run(connection, &init, encoding, loader)
}

/// Prefer UTF-8 offsets (the identity for compiler byte spans) when the
/// client offers them; UTF-16 (the mandatory LSP default) otherwise.
fn negotiate_encoding(init: &InitializeParams) -> PositionEncoding {
    let offers_utf8 = init
        .capabilities
        .general
        .as_ref()
        .and_then(|general| general.position_encodings.as_ref())
        .is_some_and(|encodings| encodings.contains(&PositionEncodingKind::UTF8));
    if offers_utf8 {
        PositionEncoding::Utf8
    } else {
        PositionEncoding::Utf16
    }
}

/// Exactly what this server serves today — capabilities never
/// over-advertise.
fn server_capabilities(encoding: PositionEncoding) -> ServerCapabilities {
    let position_encoding = match encoding {
        PositionEncoding::Utf8 => PositionEncodingKind::UTF8,
        PositionEncoding::Utf16 => PositionEncodingKind::UTF16,
    };
    ServerCapabilities {
        position_encoding: Some(position_encoding),
        hover_provider: Some(HoverProviderCapability::Simple(true)),
        document_symbol_provider: Some(OneOf::Left(true)),
        document_link_provider: Some(DocumentLinkOptions {
            resolve_provider: Some(false),
            work_done_progress_options: lsp_types::WorkDoneProgressOptions::default(),
        }),
        folding_range_provider: Some(FoldingRangeProviderCapability::Simple(true)),
        completion_provider: Some(CompletionOptions {
            trigger_characters: Some(vec![".".to_owned(), " ".to_owned()]),
            resolve_provider: Some(false),
            work_done_progress_options: lsp_types::WorkDoneProgressOptions::default(),
            ..CompletionOptions::default()
        }),
        definition_provider: Some(OneOf::Left(true)),
        type_definition_provider: Some(TypeDefinitionProviderCapability::Simple(true)),
        references_provider: Some(OneOf::Left(true)),
        rename_provider: Some(OneOf::Right(RenameOptions {
            prepare_provider: Some(true),
            work_done_progress_options: lsp_types::WorkDoneProgressOptions::default(),
        })),
        document_formatting_provider: Some(OneOf::Left(true)),
        document_range_formatting_provider: Some(OneOf::Left(true)),
        code_action_provider: Some(lsp_types::CodeActionProviderCapability::Options(
            lsp_types::CodeActionOptions {
                code_action_kinds: Some({
                    let mut kinds = vec![lsp_types::CodeActionKind::QUICKFIX];
                    kinds.extend(ipe_lsp_features::refactor::advertised_kinds());
                    kinds.extend(ipe_lsp_features::source_actions::advertised_kinds());
                    kinds
                }),
                resolve_provider: Some(false),
                work_done_progress_options: lsp_types::WorkDoneProgressOptions::default(),
            },
        )),
        document_highlight_provider: Some(OneOf::Left(true)),
        workspace_symbol_provider: Some(OneOf::Left(true)),
        selection_range_provider: Some(SelectionRangeProviderCapability::Simple(true)),
        semantic_tokens_provider: Some(SemanticTokensServerCapabilities::SemanticTokensOptions(
            SemanticTokensOptions {
                work_done_progress_options: lsp_types::WorkDoneProgressOptions::default(),
                legend: ipe_lsp_features::semantic_tokens::legend(),
                range: Some(true),
                full: Some(SemanticTokensFullOptions::Bool(true)),
            },
        )),
        signature_help_provider: Some(SignatureHelpOptions {
            trigger_characters: Some(vec![" ".to_owned(), "(".to_owned()]),
            retrigger_characters: None,
            work_done_progress_options: lsp_types::WorkDoneProgressOptions::default(),
        }),
        inlay_hint_provider: Some(OneOf::Left(true)),
        text_document_sync: Some(TextDocumentSyncCapability::Options(
            TextDocumentSyncOptions {
                open_close: Some(true),
                change: Some(TextDocumentSyncKind::INCREMENTAL),
                will_save: None,
                will_save_wait_until: None,
                save: Some(TextDocumentSyncSaveOptions::SaveOptions(SaveOptions {
                    include_text: Some(false),
                })),
            },
        )),
        ..ServerCapabilities::default()
    }
}
