//! Target-neutral DOM data path: structural diff (`Html` → `Vec<Patch>`),
//! the per-commit handler index, the focus keep, the node keep of a children
//! swap, and typed form decoding.
//!
//! These are pure over `crate::html` (no tokio, no server dependency) and are
//! shared by every patch consumer: the Ipe.Web SSE wire, the Webview IPC
//! bridge, and the browser-WASM client sink. `web::mod` re-exports them so
//! existing `web::diff::Patch`-style paths stay valid.

pub mod diff;
pub use diff::*;
pub mod dispatch;
pub use dispatch::*;
pub mod focus;
pub mod keep;
// `form.rs` decodes typed form records through `serde_urlencoded`. Its consumers
// are the render hosts — the Live web wire (`web::mod`), the browser-WASM sink
// (`wasm::mod`), and the native webview bridge — all of which select the
// server-free `web-core` render core (where `serde_urlencoded` lives). Gated on
// that floor so a non-render program drops the module and the
// `serde_urlencoded`/`form_urlencoded` crates.
#[cfg(feature = "web-core")]
pub mod form;
#[cfg(feature = "web-core")]
pub use form::*;
pub mod req;
pub use req::*;
