//! The stdlib coverage matrix: one deep enumeration of the exported surface, one
//! `surface × aspect` runner, and the static (registry-only) aspect columns.
//!
//! "No stdlib symbol is forgotten in any aspect" is otherwise a hope split across
//! shallow gates with seams between them. Here the surface is enumerated once
//! ([`surface::StdlibSurface`]), every aspect is a column applied to every symbol
//! ([`matrix::run`]), and a hole is named at its `(symbol, aspect)` coordinate.
//! The [`contract`] types are the seam the dynamic/build columns code to.

pub mod cli_surface;
pub mod columns_cli;
pub mod columns_compiler;
pub mod columns_doc;
pub mod columns_env;
pub mod columns_runtime;
pub mod columns_static;
pub mod compiler_surface;
pub mod contract;
pub mod diagnostic_surface;
pub mod env_surface;
pub mod error;
pub mod foreign_surface;
pub mod matrix;
pub mod package_surface;
pub mod probe;
pub mod source_tree;
pub mod surface;
