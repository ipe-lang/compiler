# ipe-index — Rust code-relation index

**Status: SHIPPED.** `tools/scripts/ipe-index` is a thin wrapper that builds
(out-of-tree) and execs the Rust binary — see the wrapper's header for where.

## What it is

A single-repo, sqlite-backed code-relation index. Agents query it instead of
`rg` for "where is X defined / who imports Y / which examples exercise a
module".

### Single-repo, path-prefixed

Every file/symbol path is prefixed with a repo tag. A single repo is indexed
today, but the tag keeps results self-describing and leaves room for a future
multi-repo setup without a schema change:

| Tag  | Repo            | Roles indexed |
|------|-----------------|---------------|
| `ipe`| `.` (this repo) | `compiler-rs` (src/compiler/), `runtime-rs` (src/runtime/), `tool-rs` (tools/), `stdlib-ipe` (*.ipe), `example`, `fixture`, `console-ts`, `script-sh` |

### Languages

- **tree-sitter defs+imports:** Rust (fn/struct/enum/trait/type/const/static/macro/mod
  + impl targets), TypeScript/JS.
- **line-scan defs+imports:** Bash (`name()` funcs + `source`/`.`).
- **custom scan:** Ipê (bindings + imports).

## Commands

```
ipe-index index                 # rebuild → .ipe-index/index.db
ipe-index update                # incremental: re-extract files whose content stamp changed
ipe-index locate <name>         # every def site (file:line:col + qualified + uid)
ipe-index roles|pipeline|wakeup
ipe-index deps <m> | rdeps <m> | covers <m>
# review path — clickable file:line-line coordinates, name/qualified/uid accepted
ipe-index changed <range>       # units a git range touched (the review scope)
ipe-index context <unit>        # review card: location, kind/facing, purpose, blast counts
ipe-index callers <unit> | callees <unit>   # inbound / outbound blast radius
ipe-index links <uid> | neighbors <uid>     # per-unit links + callgraph edges
ipe-index pending               # change-queue rows (JSON) — code-review's backlog
ipe-index rename-path <old> | rename-symbol <old>   # read-only rename planning (JSON sites)
```

Default repos: `ipe:.`. Override with repeatable `--repo tag:path`. DB defaults
to `.ipe-index/index.db` (gitignored).

## Auto-update on every commit

- `.git/hooks/post-commit`: `tools/scripts/ipe-index update` (quiet; the
  wrapper rebuilds a stale binary first).

Hooks are local (`.git/hooks`, not committed). Re-install after a fresh clone.

## Notes

- **Incremental `update`** — walks the same files `index` walks and re-extracts
  each one whose content stamp (`blake3:` digest in `files.sha`) changed; a
  path no longer listed or readable leaves the index. Falls back to a full
  `index` when the DB is absent, of another schema or root set, or holds a path
  with no stamp. Open units match a fresh full index.
- **Rust `impl`-target capture** — `impl Foo` / `impl Trait for Foo` (incl.
  `impl Vec<T>`) stored as kind `impl` so `locate Foo` surfaces impl sites.

Usage manual: `README.md`.
