# zed-ipe

A [Zed](https://zed.dev/) extension for Ipê: syntax highlighting through the
`tree-sitter-ipe` grammar, and the `ipe lsp` language server (completion,
go-to-definition, code actions, diagnostics, formatting).

Install it with `editors/zed/configure.sh`, which assembles the extension —
this directory plus the grammar's `queries/highlights.scm`, its single source —
into `~/.local/share/ipe/zed-ipe`; then run **zed: install dev extension** in
Zed and pick that directory. Installing this directory directly gives no
highlighting (the query is not duplicated here).

- `extension.toml` holds placeholders for the grammar's `repository` and
  `rev`: `configure.sh` fills them with the source and commit the assembled
  highlight query came from (a checkout's `HEAD`, served from the checkout, or
  the commit `IPE_EDITORS_REF` names on GitHub), so the grammar Zed builds and
  the query always match; a grammar change needs no pin bump.
  `editors/tests/configure-test.sh` replays Zed's grammar checkout and refuses
  a pin whose grammar differs.
- `src/lib.rs` starts `ipe lsp` from the project's `PATH`.
- `.cargo/config.toml` keeps host-only `rustflags` from a global cargo config
  (e.g. a mold linker flag) out of Zed's wasm build.

See `docs/topics/editor-integration.md` for every editor.
