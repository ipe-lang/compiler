# code-review

A small Ipê/TEA web app that reads an `ipe-index` `index.db` as its review
backlog: it lists the index's open units (every current unit whose
`(uid, body_hash)` pair has no decision), shows each unit's source slice and
context, and records each decision in the index's `reviewed` copy.
`main : Task Error ()` serves the embedded TEA app over `Ipe.Server.Http`, so
the program stands on its own — no wrapper script.

## Prerequisites

This app is written in Ipê, so the `ipe` compiler must be on your `PATH` at
release `ipe-v0.5.0` or later. Confirm with `ipe version`. Install the latest
release from the repo root with `./install.sh`.

A compiler built from a checkout of this repository also works. From the repo
root:

```bash
cargo build --release -p ipe      # → target/release/ipe
```

Put `target/release` on your `PATH`, or call that binary by its path.

The app reviews an `ipe-index` database, so you also need one. Build it once
from the repo root:

```bash
tools/scripts/ipe-index index      # → .ipe-index/index.db
```

See `tools/ipe-index/README.md` for that tool.

## Configuration

The app reads three environment variables: two are **required** and one is
optional. `main` parses all three at startup, then opens and probes each
location before it listens, and exits non-zero with a message naming the
variable if any is unset or unusable. A misconfigured run fails closed rather
than serving a page that later fails, opening a wrong-path database, or
joining a stored path outside the repo:

| Variable         | Meaning                                                       |
|------------------|---------------------------------------------------------------|
| `IPE_INDEX_DB`   | Path or `sqlite://` URL of the `ipe-index` DB.                |
| `IPE_INDEX_ROOT` | Repo root the index's `ipe:relative` paths join to; must be an existing directory holding the indexed files, checked at startup. |
| `IPE_REVIEW_DB`  | Optional path or `sqlite://` URL of the review DB; defaults to `review.db`. |

A relative path in any of the three resolves against the working directory. A
file path containing `?`, `#` or `%` is refused — pass such a location as a
percent-encoded `sqlite://` URL. A `sqlite://` URL must carry no `?` query and
must name a database: the app appends the open mode itself. A `sqlite:` or
`file:` value without `//` is refused. A refused database location is reported
by variable name only, never by value, since a mistyped URL can carry a
password. Each refusal states one fix.

The startup probes: the index DB is opened read-only and every column a queue
page reads from its `open_units` view is selected, with the `reviewed` copy and
its `reviewed_stamp`, so a missing file or a database that is not an
`ipe-index` index stops startup; the review DB is opened (created when absent),
migrated, and its log head read; the root must be an existing directory. A probe failure names
the variable and the resolved file, which is a plain absolute path once
parsed.

`IPE_INDEX_ROOT` binds the repo tag `ipe`, the tag of `ipe-index`'s default
`--repo ipe:.`. A unit stored under any other tag (an index built with a second
`--repo`) is refused rather than read from that root, so the page never shows a
different file than the one the index recorded. A tag is the text before the
first `:` when no `/` precedes it, matching how `ipe-index` reads it back.

Every stored `tag:relative` path is sealed with `Ipe.Path.fromString` and joined
with `Ipe.Path.under`, so it must land strictly under its tag's root: an
empty, absolute, or NUL-bearing stored path, or one whose `..` climbs out of it,
is refused with an error naming it and the `Ipe.Path` reason. The check is
lexical, and the app's source read follows a symbolic link, so a link placed at
an indexed path after indexing can point a read outside the root. The index
itself never lists such a path: `ipe-index` leaves out every symbolic link,
submodule and non-UTF-8 name, reporting each on stderr, and reads names
NUL-separated so a newline in a file name cannot split one path into two.
A source file larger than 16 MiB is refused rather than read.

Diagnostics escape control characters: a stored path, an env value, or an error
shown on stderr or the page has every control, line-separator and bidi
character spelled as a visible escape (`\n`, `\r`, `\t`, `\u{1b}`, `\u{202e}`),
so index or env text cannot rewrite the terminal or reorder a displayed path.

The page applies the same escapes to everything it shows from the index or
the review DB: a unit's path, name, qualified name, kind, facing and purpose
are escaped once, where the row is decoded; each source token, link label and
refusal reason is escaped as it is rendered. A source line carrying bidi
overrides therefore shows each one as `\u{202e}`-style text instead of
rendering reordered (Trojan Source). `\` and `"` are shown as written.

A refusal needs a reason of at most 500 characters; a blank or longer one is
refused before anything is saved. A stored refusal whose reason breaks that
bound (saved before it, or edited in the database) still loads, shown by its
length, never its text.

History shows 100 reviews per page, newest first; each page reads only its own
rows, through an index in that order.

The queue lists the index's `open_units` view: its current units minus the
`(uid, body_hash)` pairs in its `reviewed` table, the app's copy of the review
DB's decisions. A unit is listed because its current body has no decision, not
because a change event names it, so an edited unit re-opens, a unit reverted
to a decided body stays decided, and a unit with no `change_queue` row is
still listed, badged UNRECORDED.

The progress counter in the header is the index's units minus its open units,
out of all its units. The page rows, the open count and the progress are read
in one index transaction, so they always describe the same index state, and a
load costs the same however large the index or the review history grows.
Deciding a unit raises the first number and leaves the second unchanged, and
a reload or a second tab shows the same numbers.

The review DB's `review` table is append-only (deleting or updating a row is
refused, and re-inserting a decided pair, `REPLACE` included, changes
nothing), and every decision the app records moves its `review_head`, a hash
chain over the decided pairs that starts from a random genesis. Startup
refuses a review DB whose append-only triggers are missing. The `reviewed`
copy is trusted only when its `reviewed_stamp` equals that head: draining a
decision moves the stamp along with the head, and any other stamp (a decision
whose drain failed, an index file replaced by another, a decision made from
another process) rebuilds the copy from the review DB before the page is
read. A row written into `review` by hand, outside the app, does not move
the head: its unit stays listed until the next rebuild. A replaced
review DB has a new genesis, so it re-opens every unit the old one decided.
Startup always rebuilds the copy once.

The index DB is opened read-only for listing and read-write (never created) only
to drain a decided unit: in one transaction its pair enters `reviewed`, its
consumed `change_queue` row is deleted, and the stamp moves. The app creates
and owns the review DB.

## Checks

From this directory, run the app's tests and the formatter check:

```bash
ipe test            # builds and runs tests/Main.ipe, reports pass/fail
ipe fmt --check     # lists unformatted files without rewriting them
```

`tests/Main.ipe` gathers every test module's checks into one run; `ipe test`
exits non-zero on a failing check. `ipe fmt` without `--check` rewrites the
files.

## Running

From this directory, against an index built at the repo root:

```bash
IPE_INDEX_DB=../../.ipe-index/index.db IPE_INDEX_ROOT=../.. ipe dev run
```

`ipe dev run` builds and serves on <http://localhost:8000>. Set `IPE_SERVER_PORT`
to listen on another port, e.g. `IPE_SERVER_PORT=8123 ipe dev run`; a value that is
not a decimal port in `1..=65535` (empty, non-numeric, signed, `0`, or too
large) is ignored and `8000` is used. `ipe type-check` runs a fast check with
no runtime, and `ipe dev build` compiles to a native binary.

The server binds `127.0.0.1` only, so other machines cannot reach it; to
serve it on the LAN, set `IPE_HTTP_BIND` (e.g. `IPE_HTTP_BIND=0.0.0.0`), which
prints a startup warning.

Both are development builds: with `IPE_CONSOLE_AUTH` unset, the embedded
console at `/_ipe/console` is open only while the server binds loopback, and on
an exposed bind (`IPE_HTTP_BIND=0.0.0.0`) it requires the admin token. An
`ipe release` artifact keeps the console closed until `IPE_CONSOLE_AUTH` is set.

A unit's source is shown, and can be approved or refused, only when its lines
in the file re-hash to the `body_hash` the index recorded; the hash is checked
again when the decision is saved. A unit whose file changed since indexing, or
whose range no longer fits the file, shows why in place of its source and has
no decision buttons. An index built before source attestation stores hashes
the app cannot verify, so every unit reads as unverifiable until the index is
rebuilt: `tools/scripts/ipe-index update` rebuilds an index of an older schema
in full, as `tools/scripts/ipe-index index` does.

The queue view loads one page of at most 200 open units (`pageSize` in `src/Lib/Index.ipe`).

If you run from inside a compiler checkout, `ipe` may auto-discover the
checkout's vendored runtime snapshot instead of its own version-matched one,
failing the build with a version skew. Point the build at the installed
compiler's runtime to avoid it:

```bash
ver=$(ipe version | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+$/) print $i}')
IPE_RUNTIME_DIR="$HOME/.ipe/runtime/$ver/rust" ipe dev run
```
