//! `ipe_path_core` — the single source of truth for Ipê's lexical path
//! seal.
//!
//! Both the runtime `Path.fromString` seal (`ipe_runtime::path`) and the
//! compiler's literal-path gate (`ipe_diagnostics::path_check`) validate
//! through the SAME `seal`, so the algorithm lives ONCE and both consumers use
//! it. Neither keeps its own copy. The crate is dependency-free (std only) so
//! the compiler can seal a literal without pulling in the runtime's heavy
//! optional dependencies (tokio, serde, sqlx, …).
//!
//! # One file, two consumers, no drift
//!
//! The algorithm's SOURCE lives in the runtime's own tree at
//! `src/runtime/rust/src/path_core.rs`, so it vendors automatically with the
//! runtime module (`mod ipe_runtime`) that emitted apps source-copy — a
//! standalone `extern crate ipe_path_core` would not survive that copy. This
//! crate `include!`s that same file, so `ipe_diagnostics` still consumes the
//! ONE source of truth: there is a single definition of `seal` / `clean_with` /
//! `escapes_root` / `volume_name_len` / `ElementClass` / `has_nul`, and the
//! runtime seal and the compile-time gate cannot drift.
//!
//! # One seal, every regime
//!
//! * [`seal`] — THE constructor of a path's text under one [`Regime`]. The
//!   runtime drives it with [`HOST`].
//! * [`PathLitText::seal`] — the COMPILE-TIME gate. The compiler does not know
//!   the final target OS, so it seals a literal under EVERY regime and refuses
//!   it when any regime refuses; the literal then carries each regime's sealed
//!   form, and the emitted program selects the host one.
//! * [`ElementClass`] — the one per-element classifier under Windows filename
//!   canonicalisation ([`ElementClass::of`], [`ElementClass::windows_elements`]),
//!   read by the seal and the runtime child-join parse.
//! * [`ChildElement`] — the one per-element join verdict under either regime
//!   ([`ChildElement::parse`]), read by every join beneath a root.
//! * [`RelPath`] — a relative path whose every segment that verdict admits as
//!   a name, built only by [`RelPath::from_segments`]; a static-file mount
//!   parses its request path into one before any join.

// Splice in the ONE source of truth, which physically lives in the runtime's
// source tree so it vendors with `mod ipe_runtime` into every emitted app.
include!("../../../runtime/rust/src/path_core.rs");
