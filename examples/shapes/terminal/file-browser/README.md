# file-browser — `Tui.tea` with a `Ui.cells` hexdump island

A keyboard-driven directory browser. `Tui.tea` renders a typed
`Ipe.Ui` `Element` tree to terminal cells; inside that structured view sits a
raw `Ui.cells` island — a hexdump of the selected file's first bytes, painted
character by character.

- `File.readDir "."` lists the working directory at startup.
- Arrow keys (or `j` / `k`) move the selection; `Enter` reads the selected file
  with `File.readFileBytes` and renders its bytes as the `Ui.cells` grid.
- `q` (or `Ctrl-C`) quits.

`Ui.cells : List (List Char) -> Element msg` is **terminal-only**: the same
program in the `Web` or `WebView` shape is rejected at compile time with
`IPE-L0132`.

## Run

```
ipe dev run examples/shapes/terminal/file-browser
```

This is a full-screen terminal app, so it needs a real terminal (a TTY); run it
directly in your shell, not through a pipe.
