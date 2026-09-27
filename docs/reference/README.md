# Reference

Generated API reference.

## Standard library

[`stdlib.md`](stdlib.md) is the standard-library index — every module with a
one-line summary per documented symbol, each linked to a per-module detail page
under [`stdlib/`](stdlib/).

Generated from stdlib doc-strings by `gen-stdlib-docs`; do not edit by hand.
A drift gate in CI regenerates and fails on any difference.

## Environment variables

[`env.md`](env.md) is the complete operator reference for every `IPE_*`
environment variable — name, default, one-line effect, subsystem, and security
class (Tunable / Secret / SecurityTunable).

Generated from the central registry in `src/ipe-docs/src/env_vars.rs` by
`gen-env-docs`; do not edit by hand. A drift gate in CI regenerates and fails
on any difference.

## Version requirements

[`requirements.md`](requirements.md) states the Rust toolchain (pinned exactly)
and the minimum SQLite / PostgreSQL versions `Ipe.Db` accepts (a floor).

Generated from `rust-toolchain.toml`, the workspace `Cargo.toml`, and
`src/runtime/rust/src/db.rs` by `gen-requirements-docs`; do not edit by hand.
A drift gate in CI regenerates and fails on any difference.
