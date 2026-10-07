# ipe-index — manual

A fast, sqlite-backed **code-relation index** over the Ipê repo. Ask it "where is
X defined", "who imports Y", "which examples exercise a module" — one answer,
instantly, instead of grepping and guessing.

**Rule of thumb:** reach for `ipe-index` before `rg` for structural questions
(defs, imports, dependents). Use `rg` only for free-text / substring hunts.

---

## Quick start

```bash
# From the repo root. The wrapper builds the Rust binary on first run.
tools/scripts/ipe-index index          # build the index → .ipe-index/index.db
tools/scripts/ipe-index locate Lowerer # where is `Lowerer` defined / impl'd?
tools/scripts/ipe-index wakeup         # one-screen digest of the whole index
```

`tools/scripts/ipe-index` is a thin wrapper that runs `cargo build --release`
(out-of-tree; a no-op when the binary is current, a rebuild after any change to
the tool) and execs the compiled binary — see the wrapper's own header for the
target-dir resolution order. Anywhere the docs say `ipe-index`, run
`tools/scripts/ipe-index` (or the resolved binary directly).

With a local git `post-commit` hook (see below) the index refreshes after
every commit, so you rarely run `index`/`update` by hand.

---

## Build & install

**Prerequisite:** a Rust toolchain (`cargo`). The crate is edition 2024, so use a
recent stable Rust (`rustup update`).

`ipe-index` is a standalone crate — its own `target/`, detached from the compiler
workspace, and never built in-tree (never under `tools/ipe-index/target`). You
don't have to build it by hand: the `tools/scripts/ipe-index` wrapper lets
cargo bring the out-of-tree release binary up to date on every run, then execs
it.

Nothing installs to your `PATH`: invoke the wrapper `tools/scripts/ipe-index`
(which finds the repo root, resolves the target dir, and execs the binary) or
run the resolved binary directly.

**Auto-refresh (recommended):** a local git `post-commit` hook keeps the index
from drifting. Hooks live in `.git/hooks/` and are not tracked, so after a
fresh clone seed the index once:

```bash
tools/scripts/ipe-index index      # builds the binary + indexes the repo
```

To keep it fresh automatically, add a `.git/hooks/post-commit` that runs
`tools/scripts/ipe-index update` (and make it executable). Run it through the
wrapper, so the hook never executes a binary older than the tool's source.

---

## The mental model

### One repo, tag-prefixed paths

Every path is prefixed with a repo tag so results tell you where they came from
and so a future multi-repo setup never collides:

| Tag   | Repo | What lives there |
|-------|------|------------------|
| `ipe:`| `.`  | Rust compiler (`src/compiler/`), runtime (`src/runtime/`), tooling (`tools/`), stdlib/examples (`*.ipe`) |

So a result reads `ipe:crates/ipe_lower/src/lower.rs:2518` — the prefix is the
repo.

### Languages, real defs

| Language          | Defs captured | Imports |
|-------------------|---------------|---------|
| Rust              | fn, struct, enum, trait, type, const, static, macro, mod, **impl targets** | `use` |
| TypeScript / JS   | function, arrow-const | `import` / `export … from` |
| Bash              | `name()` functions | `source` / `.` |
| Ipê               | bindings | `import` |

---

## Commands

### Finding things

```bash
ipe-index locate <Name>      # every def/impl site of a symbol
ipe-index deps <module>      # what <module> imports (substring match)
ipe-index rdeps <module>     # who imports <module> (exact; --subtree, --count)
ipe-index covers <module>    # which examples/fixtures exercise a module
```

`locate` example (each site carries the unit's qualified name + uid, so it
feeds the review commands below directly):

```
$ ipe-index locate Lowerer
ipe:src/compiler/lower/src/lower.rs:7758:12  def   crate::Lowerer  4a6585e9…
ipe:src/compiler/lower/src/lower.rs:8584:10  impl  crate::Lowerer  c8fdaf51…
```

`rdeps` example (who depends on a module, exact — won't fold in `Data.List`):

```bash
ipe-index rdeps Ipe.List --subtree   # also matches Ipe.List.*
ipe-index rdeps ipe_ir --count       # just the number
```

### Reviewing a change

The review path: start from what a diff touched, then follow each unit's blast
radius. Every command takes a symbol name, qualified name, or uid, and prints
clickable `file:line-line  kind  qualified  uid` coordinates.

```bash
ipe-index changed main..HEAD   # the units a git range touched (the review scope)
ipe-index context <unit>       # review card: location, kind/facing, purpose, blast counts
ipe-index callers <unit>       # who calls it — "what breaks if this changes?"
ipe-index callees <unit>       # what it calls — "what does this rely on?"
```

`changed` example (drives a branch/PR review — each uid pipes into `context`):

```
$ ipe-index changed HEAD~3..HEAD
ipe:src/compiler/lower/src/lower.rs:7758-7958   struct  crate::Lowerer     4a6585e9…
ipe:src/compiler/lower/src/lower.rs:19232-19472 fn      crate::lower_case  eb30de67…
```

`--repo <path>` points `changed` at the git repo to diff (default: current dir).

### Unit-level links (by uid)

```bash
ipe-index links <uid>        # outgoing links + calls of one unit
ipe-index neighbors <uid>    # links + callgraph edges around a unit, both directions
```

### Situational awareness

```bash
ipe-index wakeup     # digest: file/symbol/edge counts + role breakdown
ipe-index roles      # file counts per role (compiler-rs, runtime-rs, stdlib-ipe, …)
ipe-index pipeline   # module counts per compiler stage (parse/canon/type/build/generate)
```

### Rebuilding

```bash
ipe-index index      # full rebuild: re-extracts every tracked file
ipe-index update     # incremental: walk the same files `index` walks,
                     #   re-extract only those whose content stamp changed.
                     #   Falls back to a full index when the DB is absent, of
                     #   another schema or root set, holds a path with no stamp,
                     #   or was written by another ipe-index build.
```

A full rebuild re-extracts the whole repo, so it takes tens of seconds on this
repo; `update` re-extracts only what changed since the last run. Each indexed
file carries a content stamp (`blake3:` and the hex digest of the bytes its
units were extracted from), and `update` compares it with the file on disk, so
uncommitted edits, deletions and new untracked files are picked up exactly as a
fresh `index` would see them. A path that `update` no longer lists, or can no
longer read (gone, refused, over the read ceiling), leaves the index. Calls are
resolved over the whole index after every `index` and `update`, so the
callgraph is the same whatever order files were read in and whichever files
`update` re-extracted. Both run in one transaction: a failed run leaves the
previous index and queue in place.

**What the walk indexes:** every regular file git tracks, plus the untracked
files `.gitignore` does not exclude, read from NUL-separated git listings
(`git ls-files -z -s`, `git ls-files -z --others`), so a newline in a name never
splits it. The walk refuses, and names on stderr as `ipe-index: not indexing
…`, any entry git records as a symbolic link (mode 120000) or a submodule
(160000), an untracked nested repository, any name that is not UTF-8, and any
path that is not a regular file on disk, checked without following links at the
file and at every directory above it. Every read (indexing and `rename-symbol`)
repeats that check, reads from the handle it opened only if it is the file the
check saw, and stops at the 2 MB read ceiling. A file that becomes a link drops
out of the index on the next `update`. A tracked `leak.rs -> /etc/passwd` never reaches the index or the
review app:

```bash
ln -s /etc/passwd leak.rs && git add leak.rs
tools/scripts/ipe-index index   # ipe-index: not indexing leak.rs: tracked as a symbolic link
```

### The change queue (what the code-review app consumes)

`index` and `update` record per-unit `new`/`modified`/`deleted` events in a
`change_queue` table — the review backlog the sibling `code-review` app reads,
and drains one row at a time as a unit is decided.

The queue has one transition rule (`diff::reconcile`): every run diffs the
units it rebuilt against the units the queue was last reconciled with. A full
`index` is a rebuild of the tables, never of the queue — a unit whose body is
unchanged keeps its row, or stays drained. Only the first `index` of an empty
database queues every unit as `new`.

A `file` unit spans its whole file but reviews only its residual: the
non-blank lines no other unit of the file covers (imports, attributes,
top-level glue), each run of covered lines marked by one gap. An edit inside a
function queues that function alone; an edit to a top-level line queues the
file. A file whose units cover every non-blank line has no residual, so it gets
no file unit and nothing of it is queued beyond its units.

An index built before file units attested their residual is rebuilt in full by
the next `update`. A pending file row is then re-pointed at its residual
attestation, so it stays drainable. A file unit decided under its whole-file
hash is open again: the decided pair names bytes the unit no longer attests.

A `reviewed` table holds the code-review app's decided `(uid, body_hash)`
pairs, so the app counts review progress with one SQL aggregate. A
`reviewed_stamp` table (one row) names the review-database state that copy
reflects. The app is the sole writer of both; `index` keeps them across a
rebuild, as it keeps the queue.

The `open_units` view is the open backlog: every unit in `units` whose current
`(uid, body_hash)` is not in `reviewed`. Membership comes from the units the
working tree holds now, never from the queue: a unit that vanished is not
listed, a unit that returns under new bytes is open, and a unit that returns
under decided bytes stays decided. The queue only annotates a listed unit
(`change`, `old_hash`, and `enqueued_at` as its order); a unit with no queue
row for its current bytes is listed with a NULL `change` and `enqueued_at` 0,
ahead of every queued unit. The view is re-created whenever a binary opens an
index whose stored definition differs from its own.

```bash
sqlite3 .ipe-index/index.db \
  "SELECT COUNT(*) FROM open_units; SELECT path, qualified, change FROM open_units ORDER BY enqueued_at, uid LIMIT 5"
```

```bash
ipe-index pending                 # queued unit changes as JSON lines
ipe-index pending --since <sha>   # exclude rows enqueued by that update run
ipe-index pending --limit N       # cap the output
```

Every unit's `body_hash` is `sha256:` plus the lowercase hex SHA-256 of the
text it reviews. For a `file` unit that is its residual (`residual_text` in
`src/extract/mod.rs`): every row written as `\n` and its text, a kept line's
text the line, a covered run's text empty, so no source line can read as a
covered run; for every other unit it is the whole-line view: lines
`line_start..=line_end` of the file, split on `\n` with any `\r` kept, joined
with `\n` (`src/extract/view.rs`). The code-review app re-derives that hash
before it shows a unit, so the two sides share the vectors in
`tests/view_hash_vectors.json` and `tests/residual_vectors.json`.

### Rename planning (read-only)

```bash
ipe-index rename-path <old> [--to <new>]      # every edit site for a path rename
ipe-index rename-symbol <old> [--to <new>]    # every occurrence of a symbol name
    # rename-symbol also: --preserve <regex>… (skip matches), --map k=v,… (correlated)
```

Both emit JSON-line edit sites (`{kind,path,line,col,context,replacement?}`) and
never write. `<old>` for `rename-path` is the untagged repo-relative path
(e.g. `tools/ipe-index`), matched whole-segment across any repo tag.

---

## Flags

- `--db <path>` — index location (default `.ipe-index/index.db`, gitignored).
- `--repo <tag:path>` — repeatable; override the indexed repo set. Default is
  `ipe:.`. A tag is non-empty and holds no `/` and no `:` (the tags a stored
  `tag:path` reads back as; pinned by `tests/repo_tag_vectors.json`), and each
  tag is given once. Each tag names one directory: roots are compared by
  directory identity, not by spelling, so `a:.` with `b:./`, a `..` spelling,
  or a symbolic link to a declared root is refused as a second tag for one
  directory. The number of roots is capped by `max_repos` in
  `tests/max_repos.json`, and more than one root needs a platform with
  directory identity (Unix). Roots may nest: a file belongs only to the deepest declared root that contains it, so
  an outer root's walk and `update` skip everything under an inner root, which
  indexes those files under its own tag. A root that is a subdirectory of its
  work tree is diffed relative to itself (`git diff --relative`). A declared
  root replaced by another directory between parsing and the walk fails the
  run. The index records the root set it was built under; any change to that
  set makes `update` rebuild the whole index, and units whose owning root moved
  are re-queued under their new tagged path (deleted under the old one).

---

## How auto-update works

- `.git/hooks/post-commit` → `tools/scripts/ipe-index update` (quiet).

Hooks are local (`.git/hooks/`, not committed). After a fresh clone, re-run
`tools/scripts/ipe-index index` once (or reinstall the hook) to seed the index. See
`PORT.md` for design/status.
