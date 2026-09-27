# code-review

A small Ipê/TEA web app that reads an `ipe-index` `index.db` as its review
backlog: it lists the units the index has queued for review, shows each unit's
source slice and context, and drains a unit's `change_queue` row once decided.
`main : Task Error ()` serves the embedded TEA app over `Ipe.Server.Http`, so
the program stands on its own — no wrapper script.

## Prerequisites

This app is written in Ipê, so the `ipe` compiler must be installed and on your
`PATH`. Install it from the repo root with `./install.sh`; confirm with `ipe
version`.

The app reviews an `ipe-index` database, so you also need one. Build it once
from the repo root:

```bash
tools/scripts/ipe-index index      # → .ipe-index/index.db
```

See `tools/ipe-index/README.md` for that tool.

## Configuration

Two environment variables are **required** — `main` checks both at startup and
exits with an actionable message if either is unset, so a misconfigured run
fails closed rather than opening a wrong-path database:

| Variable         | Meaning                                              |
|------------------|------------------------------------------------------|
| `IPE_INDEX_DB`   | Path or `sqlite://` URL of the `ipe-index` DB.       |
| `IPE_INDEX_ROOT` | Repo root the index's `tag:relative` paths join to.  |

The index DB is opened read-only for listing and read-write only to delete a
consumed `change_queue` row. `IPE_REVIEW_DB` is optional and defaults to
`review.db` (the app creates and owns this database).

## The queue page

The header names the index DB by file name (hover it for the full location),
its size in binary units — taken from SQLite's `page_count × page_size`, so no
file-system call or shell-out is needed — and how many units are queued (one
`COUNT(*)` over the same rows the pages list). The queue is paged 50 units at a
time with Prev/Next controls: each page fetches only its own rows (bound
`LIMIT`/`OFFSET` parameters), reads only its units' source files, and looks up
their reviews in one query. Units whose code changed since their last review
come first within each page. While a page loads the body says so, and a failed
load shows its error rather than an empty queue.

## Running

From the repo root:

```bash
IPE_INDEX_DB="$PWD/.ipe-index/index.db" IPE_INDEX_ROOT="$PWD" ipe run
```

`ipe run` builds and serves on <http://localhost:8000>. `ipe type-check` runs a
fast check with no runtime, and `ipe build` compiles to a native binary.

If you run from inside a compiler checkout, `ipe` may auto-discover the
checkout's vendored runtime snapshot instead of its own version-matched one,
failing the build with a version skew. Point the build at the installed
compiler's runtime to avoid it:

```bash
ver=$(ipe version | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+$/) print $i}')
IPE_RUNTIME_DIR="$HOME/.ipe/runtime/$ver/rust" ipe run
```
</content>
</invoke>
