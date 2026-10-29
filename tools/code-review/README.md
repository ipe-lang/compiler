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

The app reads six environment variables: two are **required** and four are
optional. `main` parses all six at startup, then opens and probes each
location before it listens, and exits non-zero with a message naming the
variable if any is unset or unusable. An optional variable that is set but
cannot be read (a value that is not valid Unicode) is refused too, never taken
for unset. A misconfigured run fails closed rather
than serving a page that later fails, opening a wrong-path database, or
joining a stored path outside the repo:

| Variable         | Meaning                                                       |
|------------------|---------------------------------------------------------------|
| `IPE_INDEX_DB`   | File path of the `ipe-index` DB.                              |
| `IPE_INDEX_ROOT` | Repo root the index's `ipe:relative` paths join to; must be an existing directory holding the indexed files, checked at startup. |
| `IPE_INDEX_REPOS` | Optional roots of the other repositories the index records: `name=/absolute/path` entries joined by `,` (e.g. `ext=/srv/ext,docs=/srv/ipe/docs`). At most 65536 bytes in all, a name of at most 128 bytes, a path of at most 4096 bytes, and 64 roots counting `IPE_INDEX_ROOT`. |
| `IPE_REVIEW_DB`  | Optional file path of the review DB; defaults to `review.db`. |
| `IPE_HTTP_BIND` | Optional listen address: only `127.0.0.1` or `::1`, exactly; unset, the server binds `127.0.0.1`. Any other value (another address, a hostname such as `localhost`, empty, padded) refuses startup. Reach the server from another machine through an SSH tunnel. |
| `IPE_REVIEW_MAC_KEY` | Optional key that signs every decision: exactly 64 hex characters (32 random bytes). Unset, the server is read-only. |

A relative path in `IPE_INDEX_DB`, `IPE_INDEX_ROOT` or `IPE_REVIEW_DB` resolves
against the working directory; an `IPE_INDEX_REPOS` path must be absolute. Each database value is a file path, never a URL: any byte but `:` is
allowed in its file name, and is read literally. A refused database location is
reported by variable name only, never by value, since a mistyped URL can carry
a password. Each refusal states one fix.

The startup probes: the index DB is opened read-only and every column a queue
page reads from its `units`, `files` and `change_queue` tables is selected,
with the `reviewed` copy and its `reviewed_stamp`, so a missing file or a database that is not an
`ipe-index` index stops startup; the review DB is opened (created when absent),
migrated, and its log head read; the root must be an existing directory. A probe failure names
the variable and the resolved file, which is a plain absolute path once
parsed.

`IPE_INDEX_ROOT` binds the repo tag `ipe`, the tag of `ipe-index`'s default
`--repo ipe:.`. Each `IPE_INDEX_REPOS` entry binds one more tag, the name before
its first `=`, to the directory after it, for an index built with more than one
`--repo`:

```sh
IPE_INDEX_ROOT=/srv/ipe IPE_INDEX_REPOS="ext=/srv/ext,docs=/srv/ipe/docs" ipe dev run
```

An entry is refused, naming its position, when it is empty, has no `=`, has a
name that is not a repo tag (empty, or holding `/`, `:`, `=`, `,`, whitespace or
a control character), or has a path that is not absolute (a single leading `/`),
not written canonically (no `.` or `..` segment, no doubled or trailing `/`), or
not an existing directory. Nothing is trimmed or cleaned, and Windows drive and
UNC spellings are refused. A name bound twice (`ipe` included), two names on one
directory, or more than 64 roots is refused too. Roots may nest: a path under a
deeper root belongs to that root alone, so `ipe:docs/x` is refused when `docs`
is bound to `/srv/ipe/docs`.

At startup the bound tags must be exactly the repositories the index records,
each nested under the same enclosing root as `ipe-index` recorded it from the
files themselves: a repository the index records but no variable binds, a bound
tag the index does not record, or a root nested otherwise than the index
records stops startup. A tag is the text before the first `:` when no `/`
precedes it, matching how `ipe-index` reads it back. A unit or an unreviewable
file stored under a tag no root binds is never listed, counted in the queue or
its progress, or read; should one appear after startup (the index rebuilt while
the server runs), the queue header shows how many units and files it leaves
out.

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

A unit too large to draw with each escape marked is shown spelled out
instead, one block of plain text where every `\` of the source is doubled
and every character outside printable ASCII but a tab is escaped, so the
display stays exact and no character can pass for the `\` of an escape:
`\\` is one `\` of the source, `\r` and `\u{202e}` are characters it
holds, and a line `\…` stands for lines reviewed as their own units. A
unit is never withheld for its escapes.

A refusal needs a reason of at most 500 characters; a blank or longer one is
refused before anything is saved. A stored refusal whose reason breaks that
bound (saved before it, or edited in the database) still loads, shown by its
length, never its text.

History shows 100 reviews per page (`PageSize.history` in `src/Lib/PageSize.ipe`),
newest first; each page reads only its own rows, through an index in that order.

Each History entry names its unit by kind, qualified name, path and line, or
an unreviewable file by its path. A decision records that name in its signed
row, so an entry still names a unit or file the index no longer holds,
marked "no longer indexed"; a name is drawn only from a row whose signature
verifies, never from an unverified one. A row that does not verify, or a
legacy row, is named from the index while it holds the unit and otherwise
reads "unit no longer indexed (no verified record of its name)"; a uid never
stands in for a name. A unit whose kind, qualified name or path is longer
than 2048 characters cannot be decided.

The queue lists the index's current units minus the `(uid, body_hash)` pairs
in its `reviewed` table, the app's copy of the review DB's decisions. A unit
is listed because its current body has no decision, not because a change
event names it, so an edited unit re-opens, a unit reverted to a decided body
stays decided, and a unit with no `change_queue` row is still listed, badged
UNRECORDED. The app writes this query itself over the index's tables: it reads
no view, trigger or other object the index file defines (`ipe-index`'s own
`open_units` view included), since anyone who can write the file can redefine
them, and it compares pairs byte for byte, whatever collation the file
declares.

The index records what the code is; the app does not check that record
against the working tree. Anyone who can write the index file can therefore
change, remove or add rows of `units`, and the queue lists exactly what those
rows say: a unit whose row is removed, or whose `body_hash` is set to a pair
already decided, is not listed. Closing that needs each unit's row bound to
the tree it was indexed from, which the app does not do. The review decisions
themselves are not at risk: they live in the signed review log, and the
`reviewed` copy is checked against it on every load (below).

The progress counter in the header is the index's units minus its open units,
out of all its units. The page rows, the open count and the progress are read
in one index transaction, so they always describe the same index state, and a
load costs the same however large the index grows; against the review log it
adds one count of the log's entries up to its head (below).
Deciding a unit raises the first number and leaves the second unchanged, and
a reload or a second tab shows the same numbers.

### The review key

Every decision is a row of the review DB's `review_log`, signed with
HMAC-SHA-256 under `IPE_REVIEW_MAC_KEY`. Generate the key once and keep it
outside the review DB (a secret store or an env file only the operator reads),
since anyone who can read it can sign a decision:

```bash
openssl rand -hex 32      # → IPE_REVIEW_MAC_KEY
```

The value must be exactly 64 hex characters; upper and lower case are the
same key. Any other value set, empty or blank included, stops startup with a
message that names the variable, never its value. The key is never logged,
rendered or shown in an error. There is one key per review DB: its log head
holds a key check made with that key, and startup under any other key stops
with "the review log was signed by a different `IPE_REVIEW_MAC_KEY`", naming
the variable, never a key. A review DB with no key check yet is bound to the
running key at startup only when every row of its log verifies under it;
otherwise startup stops with the same message.

**Read-only mode.** With `IPE_REVIEW_MAC_KEY` unset the server starts
read-only and says so on stderr: the queue and history are shown, the Approve
and Refuse controls are not, and a decision is refused with a typed error, so
nothing is recorded. With no key nothing can be verified either, so no row
counts as decided and every unit stays in the queue.

### What counts as decided

A row counts as a decision only when its signature verifies under the key and
the log's chain is unbroken. The signature covers the log's random id, the
row's sequence number, the previous row's signature, the unit's `uid` and
`body_hash`, the decision, the reason (an absent reason and an empty one
differ), the review time and the recorded name of the unit or file, so an edit to any of them outside the tool, a
forged row, or a row copied from another review DB does not verify. Such a row
is shown in the history as not counted, with the reason, and its unit stays
in the queue.

`review_log` is append-only: deleting or updating a row is refused, and an
insert that would replace a row changes nothing. Each row links to the one
before it, and `review_log_head` holds the last row's sequence number and
signature; its one row can be neither deleted nor inserted again, and its
log id never changes. Every page load and every decision walk the whole
chain under the key, and both act on that one verdict; a gap in the
sequence, a link that does not match, a row whose signature does not verify,
or a last row that differs from the head is a break, and so is any row past
the head or below the first entry. The policy on a break is strict: no row
counts, the rows before the break included, the queue and history pages show
"The review log's chain breaks at entry N: a decision was removed, reordered
or replaced outside this tool." (or, for rows past the head or below the
first entry, "The review log holds N entries past its head" or "before its
first", then ": a decision was added outside this tool."), the queue page
offers no Approve or Refuse, and every new decision is refused until the log
is repaired, so nothing is appended to a broken chain. Startup refuses a
review DB whose append-only triggers, or the trigger that keeps each row's
name whole, are missing. It also refuses a review DB holding decisions
recorded before names were kept, which this reviewer cannot verify: start a
fresh review database.

Removing the last rows and rewriting the head to match, or restoring an older
copy of the whole file under the same key, cannot be told apart from a log
that never held those rows. It fails closed: the removed decisions read as
undecided, never as approved.

**Legacy rows.** Rows of the older, unsigned `review` table still load and are
shown in the history as recorded before rows were signed. They count as no
decision: their units are back in the queue, and deciding one again appends a
signed row.

The index's `reviewed` copy is trusted only when its `reviewed_stamp` matches
the log's current head and state, and its pairs are exactly the pairs that
page load's walk of the log verified (compared by a digest keyed by
`IPE_REVIEW_MAC_KEY`, so a pair written into the copy, removed or swapped
outside a drain is rebuilt away before anything is counted). That digest is
taken only over a copy proven to hold each pair once: `reviewed` must be a
plain table, no pair may repeat in it, its rows must read in strictly
ascending order and number exactly as many as the table holds, and the log
walk breaks at any entry deciding a pair an earlier entry decided ("The
review log's entry N decides a pair an earlier entry decided"): draining a decision moves the stamp along
with the head, and any other stamp (a decision whose drain failed, an index
file replaced by another, a decision made from another process) rebuilds the
copy from the verified rows of the review DB before the page is read. The
stamp records the walk's verdict, so an entry deleted, edited or added
outside the app, below the head or past it, changes the verdict at the next
page load: the copy is rebuilt from it, the banner shows, and a unit whose
decision no longer counts is back in the queue. A replaced review DB has a new log id, so it re-opens
every unit the old one decided. Startup always rebuilds the copy once.

A page is built only from a copy that proof admitted: the stamp check and the
digest comparison are one function, `proveCopy`, whose result is the only
value the page builder accepts, so no page can be assembled from a copy the
check did not pass. A copy that still fails after one rebuild fails the load
with the check it failed: a stamp not current for the log's verdict, a copy
with no proven digest (its table shape or row count), or pairs that differ
from the verified entries'.

The index DB is opened read-only for listing and read-write (never created) only
to drain a decided unit: the drain first looks the decided pair up in the
review log under the configured key and writes only the pair of a row whose
mac verified there; a pair that no verified row holds (none recorded, another
hash recorded, a row signed under another key, a broken log) writes nothing
and leaves the unit queued. In one transaction the log's pair enters
`reviewed`, the `change_queue` row consumed for that hash is deleted, and the
stamp moves. The app creates and owns the review DB.

### Unreviewable files

A file the index could not read as units (not UTF-8, too large, a symbolic
link, a submodule, an unreadable entry, …) is listed above the queue under
**Unreviewable files** with the index's reason. Each one counts as open in the
header and in the progress total, so the queue never reads as all reviewed
while one is open. A file that is not UTF-8, too large, a symbolic link, a
submodule or a git entry of unknown mode can be acknowledged or refused; the
decision binds the index's refusal digest of the file, so a changed file is
open again after the next `ipe-index` run. The History shows an
acknowledgement as **Acknowledged**, never as Approved: the log stores it as an
approval of the file, and the signed name tells the two apart. Before the decision is recorded the
index row is read again and a content reason is re-probed: a file that now
reads as text is refused, with "re-run the index". The other reasons say
"Cannot be acknowledged: fix it in the tree." and offer no decision. The list
shows up to 32 open files (`PageSize.queue` in `src/Lib/PageSize.ipe`), every
acknowledgeable one before any that cannot be acknowledged; the header counts
them all.

## Checks

From this directory, type-check the app itself, then run its tests and the
formatter check:

```bash
ipe type-check src/Main.ipe   # the shipped app's entry, refused or accepted
ipe test                      # builds and runs tests/Main.ipe, reports pass/fail
ipe fmt --check               # lists unformatted files without rewriting them
```

`ipe test` compiles `tests/Main.ipe` and the modules it imports, never
`src/Main.ipe`, so a green test run says nothing about whether the app itself
compiles: the `ipe type-check` step is what proves it. `tests/Main.ipe` gathers
every test module's checks into one run; `ipe test` exits non-zero on a failing
check. `ipe fmt` without `--check` rewrites the
files.

## Running

From this directory, against an index built at the repo root:

```bash
IPE_INDEX_DB=../../.ipe-index/index.db IPE_INDEX_ROOT=../.. ipe dev run
```

`ipe dev run` builds and serves on <http://localhost:8000>. Set `IPE_SERVER_PORT`
to listen on another port, e.g. `IPE_SERVER_PORT=8123 ipe dev run`, or the same
assignment before a built binary; a value that is
not a decimal port in `1..=65535` (empty, non-numeric, signed, `0`, or too
large) refuses startup, naming the variable. `ipe type-check` runs a fast check with
no runtime, and `ipe dev build` compiles to a native binary.

The review page is unauthenticated, so the server listens on loopback only:
`127.0.0.1`, or `::1` with `IPE_HTTP_BIND=::1`. Any other `IPE_HTTP_BIND`
value stops startup with exit status 1 before a database is opened. To review
from another machine, tunnel to it over SSH:

```bash
ssh -L 8000:127.0.0.1:8000 <host>    # then open http://localhost:8000 locally
```

Both are development builds: with `IPE_CONSOLE_AUTH` unset, the embedded
console at `/_ipe/console` is open on the loopback listener. An
`ipe release` artifact keeps the console closed until `IPE_CONSOLE_AUTH` is set.

A unit's source is shown, and can be approved or refused, only when its lines
in the file re-hash to the `body_hash` the index recorded; the hash is checked
again when the decision is saved. A unit whose file changed since indexing, or
whose range no longer fits the file, shows why in place of its source and has
no decision buttons. An index built before source attestation stores hashes
the app cannot verify, so every unit reads as unverifiable until the index is
rebuilt: `tools/scripts/ipe-index update` rebuilds an index of an older schema
in full, as `tools/scripts/ipe-index index` does.

The queue view loads one page of at most 32 open units (`PageSize.queue` in `src/Lib/PageSize.ipe`).

If you run from inside a compiler checkout, `ipe` may auto-discover the
checkout's vendored runtime snapshot instead of its own version-matched one,
failing the build with a version skew. Point the build at the installed
compiler's runtime to avoid it:

```bash
ver=$(ipe version | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+$/) print $i}')
IPE_RUNTIME_DIR="$HOME/.ipe/runtime/$ver/rust" ipe dev run
```
