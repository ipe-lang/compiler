# Faster Rust builds

The Ipê compiler translates your program to Rust and hands it to Cargo. Most of
your build time is therefore Rust build time. This page explains the tools that
cut it most and how to apply them.

## Start with `ipe health`

```
ipe health
```

`ipe health` probes the tools listed on this page and tells you which are
missing or not yet wired in. For each gap it shows a diff-style preview of the
change it will make, then asks `[Y/n]`. Accept a fix once; it never prompts for
the same thing again.

To apply every fix non-interactively (for provisioning or CI):

```
ipe health --yes
```

The rest of this page documents what `ipe health` configures and how to do it
manually when you prefer.

---

## A fast linker

The linker is the last step of a native build. On a large project the default
linker accounts for several seconds of every rebuild. Replacing it cuts that
to under a second.

**`ipe health` probes** `mold`, `ld.lld`, and `ld.gold` in that order and
wires the first one that the current toolchain accepts, by writing a `rustflags`
array into `~/.cargo/config.toml` under the host target triple.

### Linux

**mold** is the fastest option. Install it from your package manager:

```
# Debian / Ubuntu
sudo apt install mold

# Fedora / RHEL
sudo dnf install mold

# Arch
sudo pacman -S mold
```

Then tell Cargo to use it for every native build — this is exactly what `ipe health` writes:

```toml
# ~/.cargo/config.toml
[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "link-arg=-fuse-ld=mold"]
```

Replace `x86_64-unknown-linux-gnu` with your host triple. Run `rustc -vV` and
look at the `host:` line (e.g. `aarch64-unknown-linux-gnu` on ARM Linux).

**lld** is an alternative if mold is not available. Install it via
`sudo apt install lld` (or the equivalent), then use `link-arg=-fuse-ld=lld`
in the same block.

### macOS (platform-specific — not verified on Linux)

On Apple Silicon and Intel Macs, the system linker (`ld-prime` on recent Xcode)
is already fast. If you want a cross-platform option, install lld via Homebrew:

```
brew install llvm
```

Then add to `~/.cargo/config.toml`:

```toml
[target.aarch64-apple-darwin]
rustflags = ["-C", "link-arg=-fuse-ld=lld"]
```

Use `x86_64-apple-darwin` for Intel Macs. `ipe health` applies the same
`-fuse-ld` flag form on macOS.

### Windows (platform-specific — not verified on Linux)

`rust-lld` ships with the Rust toolchain. Enable it in
`%USERPROFILE%\.cargo\config.toml`:

```toml
[target.x86_64-pc-windows-msvc]
linker = "rust-lld"
```

For the GNU ABI target use `x86_64-pc-windows-gnu` and `linker = "ld.lld"`.
`ipe health` on Windows writes `rustflags = ["-C", "link-arg=-fuse-ld=lld"]`
for the host triple.

---

## sccache

sccache caches compiled crates across builds and projects. A crate whose source
and flags have not changed is loaded from the cache rather than recompiled. It
matters most for:

- clean builds (warmth survives a `cargo clean`),
- switching between branches that share dependencies,
- CI where a populated cache is restored from an artifact store.

**Install:**

```
cargo install sccache
```

**Wire it as the Rust compiler wrapper** — this is exactly what `ipe health` writes:

```toml
# ~/.cargo/config.toml
[build]
rustc-wrapper = "sccache"
```

After the next build, run `sccache --show-stats` to confirm cache hits are
accumulating.

---

## A shared build target

By default, each project emits into its own `target/` directory. When you work
across multiple projects (or the compiler emits separate Cargo workspaces per
build), those directories stay cold to each other.

**`ipe health` offers to configure a single shared target** under
`$IPE_HOME/target` by writing to `$IPE_HOME/config.toml`:

```toml
# $IPE_HOME/config.toml
[build]
target-dir = "/path/to/ipe-home/target"
```

The key is `build.target-dir`, which is Cargo's own
[configuration key](https://doc.rust-lang.org/cargo/reference/config.html#buildtarget-dir).
All emitted projects that share this target reuse each other's compiled
dependencies.

> `ipe health` writes `build.target-dir` to `$IPE_HOME/config.toml`, not to
> `~/.cargo/config.toml`, so it applies only to projects emitted by the
> compiler. If you want the same directory for all your own Cargo projects too,
> copy the key to `~/.cargo/config.toml`.

---

## Dev-profile flags

The `[profile.dev]` block in a project's `Cargo.toml` controls compilation
flags for local builds. The flags here have been verified to parse and build
correctly on Linux.

```toml
# Cargo.toml
[profile.dev]
opt-level = 0          # no optimisations — fastest to compile; debug-run is slower
debug = 1              # line tables only, not full DWARF; smaller binary, fast gdb/lldb
split-debuginfo = "unpacked"  # keep debug info in separate .dwo files — faster linking
codegen-units = 256    # maximum parallelism within one compilation unit
incremental = true     # write fingerprinted artefacts so unchanged functions reuse them
```

Trade-offs:

| flag | what it speeds up | cost |
|---|---|---|
| `opt-level = 0` | compile time | runtime speed |
| `debug = 1` | link time, binary size | debugger variable inspection (source lines still work) |
| `split-debuginfo = "unpacked"` | link time | debug info is split across `.dwo` files |
| `codegen-units = 256` | compile time | slightly larger binary, reduced LLVM optimisation |
| `incremental = true` | rebuilds after small edits | first build slightly slower; disk use for fingerprint files |

On Linux, `split-debuginfo = "unpacked"` is the value to prefer; `"off"` turns
debug info off entirely; `"packed"` (the default on macOS) writes a single
`.dSYM` bundle. Cargo and `ipe dev build` accept all three values on Linux.

These flags affect rebuild latency (`opt-level`, `codegen-units`, `incremental`)
and link latency (`debug`, `split-debuginfo`). They do not affect release builds
(`[profile.release]` is separate).

---

## How these compose

Each optimisation targets a different bottleneck:

- **A fast linker** cuts link time on every build.
- **sccache** cuts compile time on a clean build or after a branch switch.
- **A shared target** keeps the linker's and sccache's warm artefacts alive
  across projects.
- **Dev-profile flags** reduce the work each build step must do.

Applied together they stack: a build that would take 30 seconds cold can
reach under 5 seconds for a one-line change.

---

## The dev loop: `ipe dev watch`

Once the build is fast, `ipe dev watch` keeps it running:

```
ipe dev watch
```

`ipe dev watch` listens for source changes, runs an incremental rebuild through the
salsa-aware pipeline, and restarts the process. The combination of `ipe dev watch`
and the flags above gives you sub-second feedback on most edits.

For a running app **that has a view surface**, `ipe dev watch` goes further on edits
that only change what the view *looks like*: a change to a static style value,
attribute, or text — and to the static *structure* of a subtree, such as adding,
removing, or reordering static elements or attributes — is hot-swapped into the
live program with **no recompile and no restart**, so the app updates in place
while keeping its current state. This applies to any part of a view that does not
depend on the model: an edit that reads the model, branches on it (`if` / `case`),
or touches a handler is a change to the program's behaviour, so it recompiles as
usual. The preview always runs the same code the shipped build does — a hot-swap
shows exactly what a full rebuild of the same source would.

**Which shapes hot-swap.** Appearance hot-swap needs a live, addressable view to
re-render into, so it is scoped to the two view-bearing shapes and delivered over
each one's own channel:

- **`Ipe.Tea.Web`** — over the app's `/_ipe/hot-appearance` endpoint; the browser
  repaints in place.
- **`Ipe.Tui`** — over the child's loopback control socket; the terminal UI
  repaints in place.

The two viewless / line-oriented shapes **rebuild instead** — appearance hot-swap
is not applicable to them, by design:

- **CLI** (`Ipe.Tea.Cli`) renders its line view synchronously as each line or
  message is folded; its committed transcript is already written and its live
  region is bounded, so there is no out-of-band region to repaint (and off-TTY it
  must never write terminal control codes into a pipe or log).
- **Worker** (`Ipe.Tea.Worker`) has no view at all.

For these shapes every edit — appearance-only or not — takes a full structural
rebuild. A rebuild-only shape never *skips* an edit: the change always lands, just
via a recompile rather than an in-place patch.

### Build-status banner (dev only)

For `Ipe.Tea.Web` apps, `ipe dev watch` surfaces build results directly in the
browser via the existing status banner at the bottom of the page:

- **Success** — a green "Reloaded ✓" toast appears briefly (auto-hides after
  ~1.5 s) after the page reloads following a successful rebuild.
- **Failure** — a red "Recompilation failed · &lt;first error line&gt;" banner
  appears and stays pinned until the next successful build clears it. No reload
  happens; the last-good binary keeps running.

The banner is **dev-only**: it is never shown in production builds (the endpoint
that pushes build status is not mounted when `production_from_env()` is true, and
the banner states are only reachable via that endpoint). Disable the banner
entirely with `IPE_WEB_BANNER=off`.

See [Getting started](getting-started.md) for a first project, and
[The Elm Architecture](the-elm-architecture.md) for the program model that
`ipe dev watch` loops over.
