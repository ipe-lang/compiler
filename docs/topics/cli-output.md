# CLI output

`ipe` is **human-first by default and machine-readable on request**. Every
command reads well in a terminal; the commands that emit data can also print a
clean, scriptable form when you ask for one.

## Human by default

With no output flag, every command prints a human-friendly form: a two-space
left gutter on prose lines, and colour when — and only when — the output is a
terminal. Piped or redirected output, or any run with `NO_COLOR` set, is clean
plain text with no escape codes.

```
$ ipe capabilities examples/shapes/script/release-preflight/src/Main.ipe
  This program exercises 2 security capabilities:
    • network
    • clock
```

The gutter and colour rule are the same everywhere — every command, and the
installer, indent identically — because they come from one place in the code.

## Stage progress

A multi-step command reports each step as one settled line. While a step runs it
is a light-yellow spinner and label; on success the same line is rewritten in
place to a light-green `✓` and message, on failure to a light-red `✗` and
message. Illustrative — the three states of one line, not three commands:

```
  ⠙ Resolving the latest release…      (while it runs)
  ✓ Found ipe-v0.1.36                  (on success — the same line)
  ✗ Binary for latest release not found — set IPE_VERSION=vX.Y.Z   (on failure)
```

Off a terminal (piped, redirected, or `NO_COLOR`) each step is a single
flush-left plain line with no spinner, no in-place rewrite, and no ANSI, so
`curl … | sh` logs and scripts stay clean. The installer (`install.sh`)
and `ipe upgrade` render this shape; other commands adopt it incrementally.

## `--plain` and `--json`

The data-producing commands — `capabilities`, `diff`, `version`, and `doc`
(`list` and single-module lookups) — accept two mutually-exclusive machine forms:

- **`--plain`** — unstyled, **flush-left**, one record per line, so `grep`,
  `cut`, and `awk` slice it cleanly.
- **`--json`** — a stable, documented object, so `jq` reads it.

Passing both `--plain` and `--json` together is a usage error. The other
commands (`run`, `build`, `init`, `watch`, `fix`, `fmt`) and `--help` do not take
these flags — they are not data producers.

### `capabilities`

```
$ ipe capabilities --plain <entry>
network
clock

$ ipe capabilities --json <entry>
{"schema":"ipe.cli.capabilities/1","status":"ok","command":"capabilities","payload":{"capabilities":["network","clock"]}}
```

`--plain` is the bare capability names, one per line — a pure program prints
nothing, so `| wc -l` counts them. `--json` is the shared `{schema, status,
command, payload}` machine envelope; the sorted name array (empty for a pure
program) rides under `payload.capabilities`, so `jq '.payload.capabilities'`
reads it.

> **Migration.** `--plain` is byte-for-byte the old default `ipe capabilities`
> output. A script that parsed the bare list adopts `--plain` with no other
> change; the unflagged command is now the human report.

### `version`

```
$ ipe version --plain
0.1.11

$ ipe version --json
{"schema":"ipe.cli.version/1","status":"ok","command":"version","payload":{"version":"0.1.11"}}
```

`--json` is the shared `{schema, status, command, payload}` machine envelope; the
version string rides under `payload.version` (`jq -r '.payload.version'`).

### `doc` (list and module lookups)

`ipe doc list` lists every stdlib and project module; `ipe doc <Module>` shows
one module's types and values with signatures. Both accept the machine forms:
`--plain` prints one entry per line (so `cut`/`awk` slice it), `--json` prints
the machine-readable record. Looking up a single **key** — a diagnostic code
(`ipe doc IPE-L0107`), a symbol (`ipe doc List.map`), a language construct
(`ipe doc case`), or a command (`ipe doc version`) — prints a human teaching page
and takes no output flag.

> **Migration.** `ipe explain` has been folded into `ipe doc`: use `ipe doc
> <key>` to explain a diagnostic code. The old command still forwards to `ipe
> doc` so existing scripts keep working, but it is no longer a data producer.

### `diff`

`--plain` prints one flush-left record per line: a `change\t<detail>` row per
public-API change, then a `bump\t<compatibility>\t<required>\t<floor>` verdict
row. `--json` prints
`{"compatibility": …, "required": …, "floor": …, "changes": [<detail>, …]}`.

## `ipe dev run` passes the program through

`ipe dev run` compiles your program and then runs it. **Your program's stdout is
passed through untouched** — no gutter, no colour, no wrapping — so a program
that emits its own machine output stays pipeable. `ipe`'s own messages (compile
progress, errors) go to **stderr**, out of the way of that stdout.

## Errors show the command's help

Misusing a command — a bad or missing argument, an unknown flag, `--plain` and
`--json` together — prints that command's **full `--help` page to stderr** and
exits non-zero. There is no terse one-line `usage:`; the same page you would
read from `ipe <command> --help` is the error output, uniformly across every
command and subcommand. Help you asked for goes to stdout and exits zero; help
shown because of a mistake goes to stderr and exits non-zero.
