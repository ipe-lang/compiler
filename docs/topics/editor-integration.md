# Editor integration

## Quick start

One command per editor. Each script checks its prerequisites, installs what the
editor needs, verifies the result, and exits non-zero — without claiming
success — when any step fails:

```bash
# Helix 24.03+
curl -fsSL https://raw.githubusercontent.com/ipe-lang/compiler/main/editors/helix/configure.sh | sh

# Neovim 0.11+
curl -fsSL https://raw.githubusercontent.com/ipe-lang/compiler/main/editors/neovim/configure.sh | sh

# Emacs 29+ and Doom Emacs
curl -fsSL https://raw.githubusercontent.com/ipe-lang/compiler/main/editors/emacs/configure.sh | sh

# Zed (prepares the extension, then one click in Zed)
curl -fsSL https://raw.githubusercontent.com/ipe-lang/compiler/main/editors/zed/configure.sh | sh
```

From a checkout, `sh editors/<editor>/configure.sh` does the same with the
checkout's files. The scripts are idempotent. Every file they change is first
copied to a fresh `<file>.ipe-backup-<timestamp>`; in a config file they own
only the block between the `>>> ipe` / `<<< ipe` marker lines, and leave the
rest of the file byte for byte. Set `IPE_EDITORS_REF` to fetch a tag or commit
instead of `main`.

Open the folder holding `package.ipe` (not a loose file): go-to-definition and
the other cross-module features resolve against that package. A standard-library
name (`List.map`, …) has no source on disk, so it reports "no definition";
hover still shows its type.

---

Two pieces make an editor understand Ipê:

- **`ipe lsp`** — semantics over stdio: type-directed completion,
  go-to-definition, find-references, rename, formatting, code actions (add a
  missing annotation or import, remove an unused import, …, plus the
  whole-document `source.organizeImports` and `source.fixAll`), semantic
  tokens, signature help, inlay hints and diagnostics.
- **`tree-sitter-ipe`** — syntax highlighting from the grammar in
  `editors/tree-sitter-ipe/` (Helix, Neovim, Zed). Emacs highlights through
  `ipe-mode`'s own font-lock rules.

Completion is type-directed: where the context expects a type (a function
argument, a typed binding's body, a branch, a list element), candidates of that
type come first and the type's constructors are surfaced. Every suggestion comes
from the type-checker `ipe dev build` runs. After a qualifier (`Font.`, an alias
`F.`, or a full dotted path `Ipe.Ui.Font.`), completion is scoped to exactly
that module's exposed members — never the whole in-scope list — and accepting
an item replaces whatever member name is already typed rather than appending to
it.

Lint findings arrive with the diagnostics, configured by the same `lint.ipe`
`ipe lint` reads (next to `package.ipe`, or next to a loose file). A `lint.ipe`
that fails to load — invalid, oversized, or not a regular file — shows one error
on `lint.ipe` itself and no lint findings until it loads. A file shown before its
project loads (a broken `package.ipe`, say) gets no lint findings and no
`source.fixAll` until the load succeeds: the editor never lints with rules the
project did not configure.

A project the compiler refuses to load (an untrusted FFI or manifest, a source
past a size limit) shows one error — the refusal `ipe dev build` would print — on
the file that triggered the load, and every earlier finding is withdrawn: the
editor never keeps showing analysis of a project the compiler rejects.

## Helix

`editors/helix/configure.sh` builds the grammar with your C compiler into
`~/.config/helix/runtime/grammars/`, installs the matching queries into
`runtime/queries/ipe/`, writes the language + `ipe lsp` definition into
`languages.toml` as a managed block, and confirms with `hx --health ipe`
(restoring `languages.toml` if Helix rejects it). A hand-written Ipê definition
already in `languages.toml` is left alone with a warning — TOML forbids a second
`[language-server.ipe-lsp]` table.

The managed block is `editors/helix/languages.toml` verbatim — copy it by hand if
you prefer; it defines the `ipe` language and `ipe lsp` as its server.

Keys: `gd` go to definition, `<space>a` code actions (cursor on the
diagnostic), completion as you type (`C-x` to ask). Formatting runs through
`ipe lsp` on save. Inline diagnostics (`end-of-line-diagnostics`,
`[editor.inline-diagnostics]`) need Helix 25.01+; older Helix rejects the whole
`config.toml` when they are present.

## Neovim

`editors/neovim/configure.sh` needs Neovim 0.11+ (its built-in LSP client) and
no plugins. It installs into Neovim's data `site` directory — on the default
`runtimepath`, outside your config:

| File | Role |
|------|------|
| `parser/ipe.so` | the grammar, built locally |
| `queries/ipe/*.scm` | highlight and other queries |
| `plugin/ipe.lua` | filetype, `vim.treesitter.start`, `vim.lsp.config("ipe", …)` + `vim.lsp.enable` |

It then checks headlessly that the parser, the highlight query and the LSP
config load. Query files an older script left in `~/.config/nvim/queries/ipe/`
would shadow the new ones, so that directory is moved aside (never deleted).

Keys (Neovim defaults): completion pops up after `.` (`<C-x><C-o>` any time),
`<C-]>` go to definition, `gra` code actions, `gq` formats through `ipe lsp`.
The plugin is `editors/neovim/ipe.lua` if you prefer to vendor it.

## Emacs and Doom Emacs

`editors/emacs/configure.sh` needs Emacs 29+ (for the built-in Eglot client). It
installs `ipe-mode.el` into `~/.local/share/ipe/emacs/` and adds a managed block
loading it:

```elisp
(add-to-list 'load-path "~/.local/share/ipe/emacs")
(require 'ipe-mode)
```

The block goes into your init file (`~/.emacs`, `~/.emacs.d/init.el` or
`~/.config/emacs/init.el`, in Emacs's own lookup order; `EMACSDIR` overrides) —
or, when that directory is **Doom Emacs**, into `$DOOMDIR/config.el` (no
`doom sync` needed; the script refuses if Doom has no private config yet). A
batch Emacs then checks the mode loads, highlights, and registers `ipe lsp`.

`ipe-mode` gives font-lock highlighting, `--` / `{- -}` comments, 4-space
indentation, a project root at `package.ipe`, and starts Eglot automatically
(`ipe-auto-eglot`). Keys: `completion-at-point` (`C-M-i`, or your Corfu/Company
popup), `M-.` go to definition (`gd` under Evil), `C-c C-a` code actions,
`C-c C-f` format; `ipe-format-on-save` formats before saving.

## Zed

Zed loads language support only from extensions, and installs a local extension
only from its UI. `editors/zed/configure.sh` assembles the extension —
`editors/zed-ipe` plus the grammar's highlight query — into
`~/.local/share/ipe/zed-ipe` and prints the remaining step:

1. In Zed run **zed: install dev extension**.
2. Choose `~/.local/share/ipe/zed-ipe`.

Zed then compiles the grammar (pinned to a commit in `extension.toml`) and the
extension's small Rust part — a `cargo build --target wasm32-wasip2`, Zed's own
extension-compile target — highlights `.ipe` files, and starts `ipe lsp` from
your `PATH`. This needs a **rustup-managed** Rust toolchain (a distro-packaged
`rustc` can't add targets); `configure.sh` adds `wasm32-wasip2` up front so a
missing target surfaces as a clear message instead of Zed's opaque "compiling
Rust extension" failure, but you can add it yourself first with
`rustup target add wasm32-wasip2`. Trust the project when Zed asks — language
servers stay off in untrusted folders. `settings.json` needs no Ipê entries;
the script never edits it and only warns about keys an older version merged in.

Keys (Zed defaults): completion as you type, `F12` go to definition,
`ctrl-.` code actions; format on save uses `ipe lsp`.

## Other editors

Any LSP client works: run `ipe lsp` over stdio for `*.ipe` files, with the
folder holding `package.ipe` as the workspace root. For highlighting, build the
grammar from `editors/tree-sitter-ipe/` (see its README) and use its
`queries/`.

## Grammar maintenance

The generated parser (`src/parser.c`) is committed so editors build it without
the tree-sitter CLI. Regenerate it at ABI 14 — the newest ABI every supported
host loads:

```bash
cd editors/tree-sitter-ipe && tree-sitter generate --abi 14
```

After a grammar or query change, update `rev` in `editors/zed-ipe/extension.toml`
to a commit that contains it; `editors/tests/configure-test.sh` fails while the
pinned commit's grammar differs from the checkout's.
