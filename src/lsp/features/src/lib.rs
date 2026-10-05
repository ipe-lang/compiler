#![forbid(unsafe_code)]
//! `ipe_lsp_features` — pure LSP feature handlers over the `ipe_db` salsa
//! graph.
//!
//! Every handler here is a pure function from (database snapshot, position)
//! to an LSP payload. This crate owns **no** parser, resolver, or solver of
//! its own: diagnostics, types, and navigation targets are read from the same
//! memoized `ipe_db` queries `ipe dev build` and `ipe dev watch` run, so an answer
//! that disagrees with the compiler has no code path. No function here
//! touches `std::fs`, `std::env`, or the clock — file text enters through
//! the `SourceFile` inputs the driver (the LSP server crate) sets.

pub mod action_kind;
pub mod code_actions;
pub mod completion;
pub mod db_access;
pub mod diagnostics;
pub mod docs_lookup;
pub mod expected_type;
pub mod folding;
pub mod formatting;
pub mod hover;
pub mod inlay_hints;
pub mod links;
pub mod navigation;
pub mod offset;
pub mod refactor;
pub mod rename;
pub mod selection_range;
pub mod semantic_tokens;
pub mod signature_help;
pub mod source_actions;
pub mod symbols;
pub mod workspace_edit;

pub use offset::PositionEncoding;
