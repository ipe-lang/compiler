# code-review

A small Ipê/TEA web app that reads an `ipe-index` `index.db` as its review
backlog: it lists the units the index has queued for review, shows each unit's
source slice and context, and drains a unit's `change_queue` row once decided.
`main : Task Error ()` serves the embedded TEA app over `Ipe.Server.Http`, so
the program stands on its own — no wrapper script.

## Prerequisites

This app is written in Ipê, so the `ipe` compiler must be installed and on your
`PATH`, at release `ipe-v0.4.0` or later: the queue loader uses `Task.loop`,
which first ships in that release, so an older compiler refuses to build the
app. Install it from the repo root with `./install.sh`, which installs the
latest release; confirm with `ipe version`.

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
| `IPE_INDEX_ROOT` | Repo root the index's `ipe:relative` paths join to; must be an existing directory. |
| `IPE_REVIEW_DB`  | Optional path or `sqlite://` URL of the review DB; defaults to `review.db`. |

A relative path in any of the three resolves against the working directory. A
file path containing `?`, `#` or `%` is refused — pass such a location as a
percent-encoded `sqlite://` URL. A `sqlite://` URL must carry no `?` query and
must name a database: the app appends the open mode itself. A `sqlite:` or
`file:` value without `//` is refused. A refused database location is reported
by variable name only, never by value, since a mistyped URL can carry a
password. Each refusal states one fix.

The startup probes: the index DB is opened read-only and every column a queue
page reads is selected, so a missing file or a database that is not an
`ipe-index` index stops startup; the review DB is opened (created when absent)
and migrated; the root must be an existing directory. A probe failure names
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

The progress counter in the header counts the units whose current body hash
has a decision, out of the units decided or still queued. Each queue load
reads it as one SQL aggregate over the index's `reviewed` table, the app's
copy of its decided `(uid, body_hash)` pairs, so a load costs the same however
large the index or the review history grows. Deciding a unit raises the first
number and leaves the second unchanged, and a reload or a second tab shows the
same numbers. Each load also compares the copy's row count with the review
DB's; on a mismatch (a decision whose drain failed, a rebuilt index file, a
deleted review row) it rebuilds the copy from the review DB before counting,
and startup always rebuilds it once.

The index DB is opened read-only for listing and read-write (never created) only
to drain a decided unit: in one transaction its pair enters `reviewed` and its
consumed `change_queue` row is deleted. The app creates and owns the review DB.

## Running

From this directory, against an index built at the repo root:

```bash
IPE_INDEX_DB=../../.ipe-index/index.db IPE_INDEX_ROOT=../.. ipe run
```

`ipe run` builds and serves on <http://localhost:8000>. Set `IPE_SERVER_PORT`
to listen on another port, e.g. `IPE_SERVER_PORT=8123 ipe run`; a value that is
not a decimal port in `1..=65535` (empty, non-numeric, signed, `0`, or too
large) is ignored and `8000` is used. `ipe type-check` runs a fast check with
no runtime, and `ipe build` compiles to a native binary.

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

The queue view loads one page of at most 200 units (`pageSize` in `src/Lib/Index.ipe`).

If you run from inside a compiler checkout, `ipe` may auto-discover the
checkout's vendored runtime snapshot instead of its own version-matched one,
failing the build with a version skew. Point the build at the installed
compiler's runtime to avoid it:

```bash
ver=$(ipe version | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+$/) print $i}')
IPE_RUNTIME_DIR="$HOME/.ipe/runtime/$ver/rust" ipe run
```
