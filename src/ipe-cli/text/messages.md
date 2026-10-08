# ipe messages

Every user-facing message the `ipe` CLI prints that is not a help page. Each
`## <key>` section holds one message; `{name}` marks a value filled in when the
message is shown. Edit the text here, never a Rust string: the catalog tests pin
every section to the Rust declaration that shows it, placeholder for
placeholder.

# Command-line misuse

## command-refusal

ipe {command}: {reason}

## unknown-flag

ipe {command}: unknown flag `{flag}`

## unknown-subcommand

ipe {command}: unknown subcommand `{sub}` (expected {expected})

## unexpected-argument

ipe {command}: unexpected argument `{arg}`

## flag-repeated

ipe {command}: {flag} given more than once

## plain-json-exclusive

ipe {command}: --plain and --json are mutually exclusive

## flag-needs-value

ipe {command}: {flag} needs a value

## unsupported-target

unsupported target `{target}` — supported: wasm, wasi, {supported}

## static-flags-with-wasm

--static / --allocator are native-target flags; they do not compose with --target {target}

## cfree-with-wasm

--cfree is a native-target flag; it does not compose with --target {target}

## emit-ir-with-out

--emit-ir does not compose with --out

## emit-ir-with-static

--emit-ir does not compose with --static

## emit-ir-with-target

--emit-ir does not compose with --target

## emit-ir-with-allocator

--emit-ir does not compose with --allocator

## emit-ir-with-cfree

--emit-ir does not compose with --cfree

## run-wasm-target

ipe dev run builds and executes a native binary; --target wasm has no native artifact to run — use `ipe dev build --target wasm` to produce a browser bundle

## run-wasi-native-flags

--static / --allocator / --cfree are native-target flags; they do not compose with --target wasi

## eject-out-required

ipe release eject: --out <dir> is required (the directory to write the standalone project to)

## release-no-wasi

ipe release build produces a browser bundle (`--target wasm`) or a native binary; it does not produce a WASI module — build one with `ipe dev build --target wasi`

## release-embed-bundle-exclusive

ipe release: --embed and --bundle are mutually exclusive (embed is the default single self-jailing binary; --bundle is the multi-file opt-out)

## port-zero

ipe {command}: --port 0 is not a real port; omit --port to auto-select a free one

## port-invalid

ipe {command}: --port `{value}` is not a port number (1-65535)

## fix-usage

usage: ipe fix <path> [--yes]

## lsp-takes-no-arguments

ipe lsp takes no arguments

## lint-single-path

ipe lint takes at most one path

## audit-advisory-db-exclusive

ipe package audit: --advisory-db and --no-advisory-db are mutually exclusive

## audit-single-path

ipe package audit: expected a single <path> argument

## audit-format-repeated

ipe package audit: an output-format flag was given more than once

## doc-type-exclusive

ipe doc: --type is mutually exclusive with --check-examples and --list

## doc-type-unexpected-positional

ipe doc --type: unexpected positional argument; use `ipe doc --type "<type expr>"`

## doc-serve-port-needs-number

ipe doc serve: --port needs a number

## doc-single-key

ipe doc: expected a single <key> argument

## doc-single-path

ipe doc: expected a single <path> argument

## ffi-inspector-not-found

ipe add: `ipe-ffi-inspector` not found beside the `ipe` binary or on PATH

## ffi-add-home-not-absolute

ipe add: HOME is not an absolute path; cannot create a safe scratch directory

## ffi-no-bubblewrap

ipe add: no bubblewrap isolation available — install `bwrap`, or set IPE_FFI_ALLOW_UNSANDBOXED=1 to accept running the crate's build scripts UNSANDBOXED (dangerous)

## ffi-add-no-payload

ipe add

## install-aborted

ipe install: aborted

## ffi-legacy-define-removed

[[rust.define.*]] is no longer supported — declare FFI types via `foreign` in `src/Ffi/<Crate>.ipe`

## rust-usage

usage: ipe rust <add|remove|install> <crate>[@<version>] [flags]

## rust-add-usage

usage: ipe rust add <crate>[@<version>] [--features a,b] [--yes] [--verbose]

## rust-add-aborted

ipe rust add: aborted

## rust-remove-usage

usage: ipe rust remove <crate>

## rust-install-usage

usage: ipe rust install [--yes] [--allow-build-scripts] [--verbose]

## rust-install-package-ipe-unsupported

ipe rust install: reading `[rust.dependencies]` / `[rust.wrapper]` bindings out of a package.ipe is not yet wired (part of the outstanding ergonomic Rust-FFI work) — the text inspector reads only a legacy ipe.toml

## rust-install-no-manifest

ipe rust install: no manifest with `[rust.dependencies]` in the current directory

## pkg-no-manifest

ipe add/remove: no `package.ipe` in the current directory (run inside an Ipê project)

## publish-single-path

ipe package publish: expected a single <path> argument

## watch-dir-no-manifest

directory supplied but no package.ipe found inside it

## legacy-toml-hint

no package.ipe in this directory (found a legacy ipe.toml — package.ipe is the project manifest the toolchain reads)

## manifest-untrusted

refusing to use the project manifest `{path}` found above the entry file: it is not owned by the current user, or another user can write or replace it. Fix its ownership/permissions, or pass the project directory explicitly

## manifest-symlink

refusing to use the project manifest `{path}` found above the entry file: it is a symbolic link. Replace it with the file itself, or pass the project directory explicitly

## manifest-unverifiable

refusing to use the project manifest `{path}` found above the entry file: its ownership cannot be verified on this platform. Pass the project directory instead of the file (for example `ipe dev build path/to/project`), whose `package.ipe` is then used as named

## no-entry

nothing to build here — pass a source file or run inside a project (a package.ipe, or a src/Main.ipe)

## internal-entry-not-in-source-map

internal: entry module not in source map

## internal-module-not-in-source-map

internal: module in topo order not in source map

## library-package-no-entry

this is a library package (it declares `exposedModules` and no runnable program) — there is no entry to build. Use `ipe type-check` to verify its public surface, or add a `Package.programs [ … ]` stage to declare a runnable entry

## debugger-needs-runtime-dep

`--debugger` needs the runtime crate: the vendored runtime source (`IPE_RUNTIME_VENDORED=1`) carries no debugger. Unset `IPE_RUNTIME_VENDORED` to build with it

## pkg-not-found-in-dir

no package.ipe found — run inside a project or pass its path

## package-usage

usage: ipe package <audit|audit-entry|publish|validate-entry> [<path>]

## package-validate-entry-usage

usage: ipe package validate-entry <packages/<name>.toml>

## package-audit-entry-single-path

ipe package audit-entry: expected a single entry-file path

## package-audit-entry-usage

usage: ipe package audit-entry <packages/<name>.toml> [--index <root>] [--attested-actor <login>]

## package-capability-inference-no-module

package capability inference: the package has no module to analyse

## package-manifest-name-required

package.ipe: missing a `name = "…"` field — a package must be named

## package-manifest-src-root-missing

package.ipe: the source root directory does not exist

## package-manifest-no-package-binding

package.ipe: no top-level `package = …` binding found

## package-manifest-no-package-binding-edit

package.ipe: no top-level `package = …` binding to edit

## package-manifest-package-not-record

package.ipe: the `package` value must be a record literal `{ … }` for `ipe add` to edit it

## package-manifest-deps-not-list

package.ipe: `dependencies` must be a list literal `[ … ]` for `ipe add` to edit it

## package-manifest-deps-brace-not-found

package.ipe: could not locate the `package` record's closing `}` to add a dependency

## package-manifest-deps-brace-out-of-range

package.ipe: the `package` record's closing `}` is out of range

## init-shape-needs-value

ipe init: `--shape` requires a value: script, tui, cli, worker, server, web

## diff-usage

usage: ipe diff <old-path> <new-path>
   or: ipe diff check <old-path> <new-path> <old-version> <new-version>

## health-yes-with-format

ipe health: --yes does not compose with --plain / --json (a data form never mutates)

## fmt-single-path

fmt: expected a single <path> argument

## fmt-stdin-and-path

fmt: --stdin and a <path> argument are mutually exclusive

## fmt-format-with-stdin

fmt: --plain / --json do not compose with --stdin (it already writes to stdout)

## fmt-format-needs-check

fmt: --plain / --json report the unformatted files of a --check scan; pass --check

## delivery-word-shadows-path

note: a path `{word}` exists but bare `{word}` selects the delivery; write `./{word}` to build that path

# Help layout

## verbs-label

Verbs:

## help-arguments-label

Arguments

## help-options-label

Options

## help-output-label

Output

# Static-build refusals

## unknown-allocator

unknown allocator {allocator} — expected one of: auto, system, dlmalloc, talc, mimalloc

## unknown-static-target

{target} is not a supported static target — supported: {supported}

## target-requires-static

--target {target} requires --static (cross-compiling a dynamic build is not supported)

## allocator-requires-static

--allocator {allocator} requires --static (allocator selection applies to static builds)

## talc-requires-arena-design

the talc allocator is not wired yet: a hosted talc #[global_allocator] needs a static arena design that has not landed. Use the dlmalloc default instead

## webview-static

an Ipe.WebView app cannot be built --static: it links the system webview (WebKit/WebView2), which has no static form

## target-not-installed

the target {triple} is not installed — run: rustup target add {triple}

## musl-c-compiler-missing

no musl-capable C compiler found for {triple} (the emitted project's zstd/ring dependencies compile C). Install one (Debian/Ubuntu: apt install musl-tools) or set CC_{triple_env}

## mimalloc-requires-c

--allocator {allocator} cannot combine with --cfree: mimalloc vendors and links C. Drop --cfree, or use the pure-Rust dlmalloc default

## libc-allocator-requires-c

--allocator {allocator} cannot combine with --cfree: the target libc's malloc links C. Drop --cfree, or use the pure-Rust dlmalloc default

## cfree-not-yet-wired

--cfree is not wired yet: the pure-Rust dependency swaps that make the default emitted graph link no C (flate2/zstd codecs, a ring-free rustls provider) have not landed, so the build would still pull C. Drop --cfree

## invalid-bool

{source}: expected true/false/1/0, got {value}

# Delivery refusals

## delivery-shape-mismatch

you asked for `{stated}`, but `main` is a `{pinned}` app. A program's shape is fixed by the head of `main` (what `view` renders) — the CLI word only double-checks it. Drop the `{stated}` word, or change `main` to a `{stated}` entry.

## delivery-served-not-a-word

`served` is the default runtime, so it is never written. The web shape runs served (a co-located server loop) unless you opt into `solo` (a self-contained client). Write `web` for served, or `web desktop` for served on the desktop.

## delivery-runtime-on-non-web

`solo` is a web runtime, but this is a `{shape}` app. Only the `web` shape has a runtime choice (served vs solo) — every other shape runs one way. Drop the runtime word.

## delivery-host-on-non-web

`{host}` is a web host, but this is a `{shape}` app. Hosts (desktop/ios/android) belong to the `web` shape's delivery axis; a `{shape}` app has one host. Drop the host word.

## delivery-served-host-not-mobile

`{host}` is a `solo` host, not a served host. Mobile ships a self-contained client (`web solo {host}`); served is the co-located server loop (served or `web desktop`). Write `web solo {host}` for mobile.

## delivery-static-not-allowed-webview

`web desktop` links the system webview at runtime, so it has no static binary. Use `web` (served), `tui`, `cli`, or `script` for a static musl binary, or ship the desktop app bundle.

## delivery-static-not-allowed

`{delivery}` targets wasm or a native bundle, so `--static` (a musl binary) does not apply. `--static` is for the co-located, no-webview shapes: `script`, `tui`, `cli`, or served `web`.

## delivery-unknown-token

`{got}` is not a runtime or host word. The web runtime word is `solo` (served is the default). Hosts are `desktop`, `ios`, `android`. Use `--static` for a musl binary or `--target` for a cross-compile triple.

## delivery-duplicate-token

`{got}` repeats the {kind} — each axis takes exactly one value. Write the {kind} once: e.g. `web solo` (not `web solo solo`) or `web desktop` (not `web desktop ios`). Drop the duplicate `{got}`.

## delivery-solo-requires-wasm-target

a `solo` delivery is a self-contained client that must compile to wasm, but the target resolved to native. The sandbox's native-deny guards are keyed to the wasm target, so a native `solo` build would ship native effects into the sandbox. Build for wasm — pass `--target wasm`, set `IPE_TARGET=wasm`, or set `[wasm] mode` in `package.ipe` — or drop `solo` for a co-located served delivery.

## delivery-wasm-target-requires-solo

a wasm compile target was requested, but the delivery is not `solo`. The wasm client target exists only to carry a self-contained `solo` app; every other shape has no wasm form. Deliver `web solo` to build for wasm, or drop the wasm target (`--target`/`IPE_TARGET`/`[wasm] mode`) for a native build.

## delivery-native-engine-refuses-wasm-triple

`{triple}` is a WebAssembly triple, but this build targets the native binary, which has no WASM form. The browser client compiles to `wasm32-unknown-unknown` (deliver `web solo`); the co-located WASI target compiles to `wasm32-wasip1`. Drop the WASM triple for a native build, or pick the delivery that carries it.

## delivery-solo-requires-browser-triple

a `web solo` client compiles only to `wasm32-unknown-unknown`, but `{triple}` was requested. The sandboxed browser client has exactly one triple — its wasm sandbox. Drop the triple (it is implied by `solo`), or drop `solo` for the delivery that carries `{triple}`.

## delivery-solo-refuses-wasi-triple

a `web solo` client cannot target `wasm32-wasip1`. The browser sandbox denies native effects and reaches the world only through Web-API capabilities; WASI is the co-located, native-ish target for a `tui`/`cli`/`script`/served-`web` program, never the browser sandbox. Deliver `web solo` to `wasm32-unknown-unknown`, or use a co-located shape for a WASI build.

## delivery-webview-has-no-static-triple

`{delivery}` links the system webview at runtime, so it has no static (musl) triple. Use `web` (served-live), `tui`, `cli`, or `script` for a static musl binary, or ship the desktop app bundle.

## delivery-wasi-refuses-solo-delivery

a co-located `wasm32-wasip1` build cannot carry a `solo` delivery. `solo` is the browser sandbox (`wasm32-unknown-unknown`), which denies native effects; WASI is the co-located, native-ish target that runs a script's own effect floor. Drop `solo` for a WASI build, or deliver `web solo` to the browser triple.

## delivery-wasi-requires-direct-shape

a co-located `wasm32-wasip1` build carries only a `Direct` script (a plain `Task Error ()` `main`), but this is a `{shape}` app. A `tui`/`cli`/`web` TEA loop needs the reactor spine, which does not build on WASI. Build the `{shape}` app natively, or ship a `Direct` script to `wasm32-wasip1`.

## delivery-wasi-requires-wasi-triple

a co-located WASI build compiles only to `wasm32-wasip1`, but `{triple}` was requested. The WASI engine has exactly one triple — its portable target. Drop the triple (it is implied by the WASI build), or pick the delivery that carries `{triple}`.

# Driver errors

## cli-static-refusal

static build refused: {refusal}

## cli-runtime-not-found

could not locate the Ipe runtime; set IPE_RUNTIME_DIR to an explicit path or pass --runtime <dir>

## cli-cache-home-unknown

could not determine the per-user cache directory: neither XDG_CACHE_HOME nor the home directory (HOME, or USERPROFILE on Windows) is set to an absolute path; set XDG_CACHE_HOME to an absolute, writable directory

## cli-env-dir-not-absolute

{var} is set but is not an absolute path; set it to an absolute directory or unset it to use the default location

## cli-runtime-dir-invalid

IPE_RUNTIME_DIR points at {path}, which is not an Ipe runtime crate root (its Cargo.toml must declare `name = "ipe-runtime-rust"`)

## cli-runtime-dir-invalid-inner-hint

  = help: this looks like the inner runtime module directory; point IPE_RUNTIME_DIR at the crate root that holds Cargo.toml (e.g. `src/runtime/rust`), not the `src/ipe_runtime` inside it

## cli-runtime-home-unknown

could not determine where to install the Ipe runtime: none of IPE_HOME, XDG_DATA_HOME, or HOME is set; set IPE_HOME to a writable directory

## cli-runtime-materialize-failed

could not install the Ipe runtime: {detail}
  the build was stopped rather than link an incomplete runtime

## cli-runtime-version-mismatch

the Ipe runtime at {path} is version {found}, but this compiler is {expected}; a program emitted by this compiler cannot link a different runtime.
  = help: this runtime is out of date. Remove the stale copy (the project's `out/` directory, or whatever `IPE_RUNTIME_DIR` points at) and rebuild — the matching runtime re-materializes automatically.

## cli-emitted-build-feature-missing

building {what} failed: it needs the runtime feature `{feature}`

## cli-emitted-build-feature-context

, but the runtime at {root} (version {version}) does not provide it

## cli-emitted-build-stale-runtime-hint

  = help: the runtime is out of date. Remove the stale copy (the project's `out/` directory, or whatever `IPE_RUNTIME_DIR` points at) and rebuild — the matching runtime re-materializes automatically.

## cli-cargo-fetch-failed

cargo exited {code} while fetching crates for {what}

## cli-cargo-fetch-failed-detail

cargo exited {code} while fetching crates for {what}:
{trimmed}

## cli-cargo-compile-failed

cargo exited {code} with no output while compiling {what}

## cli-cargo-compile-failed-detail

cargo exited {code} while compiling {what}:
{trimmed}

## cli-capability-mismatch-header

declared capabilities do not match the program's inferred set

## cli-capability-mismatch-missing

  used but not declared: {list}

## cli-capability-mismatch-extra

  declared but not used: {list}

## cli-hash-mismatch

package `{package}`: content hash mismatch — the fetched source does not match the hash the index pinned.
  expected: {expected}
  actual:   {actual}
the source was NOT trusted; nothing was written.

## cli-doc-not-found

no documentation entry is named `{query}`

## cli-doc-suggestions-header

Closest matches:

## cli-doc-suggestion-line

  {index}. ipe doc {term}  {summary} ({kind})

## cli-doc-nearest-header

No close match; the nearest entries:

## cli-doc-more-matches

More entries match; refine the term.

## cli-unknown-code

unknown error code `{input}`

## cli-unknown-code-did-you-mean

  did you mean: {first}

## cli-semver-rejected

version {proposed} does not clear the required {required} bump — the new version must be at least {floor}.

## cli-publish-refused

ipe package publish refused: {refusal}

## cli-version-refused

package `{package}`: {refusal}

## cli-unknown-group-verb

unknown `ipe {group}` verb `{attempted}`

## cli-unknown-group-suggestion

= help: maybe `ipe {group} {sugg}`?

## cli-group-required

`ipe {attempted}` is not a command on its own — it lives under a group

## cli-subcommand-required

`ipe {group}` needs a subcommand

## cli-group-required-form

= help: `ipe {form}`

## cli-verify-failed

verify: the {stage} stage failed

## cli-test-failed-suffix

one or more tests failed (runner exited {code})

## cli-upgrade-no-prebuilt

{glyph} No prebuilt binary for {version} on {platform}.
    Possibly the binaries for that version are still being generated.
    If you prefer, build from source:
        cargo install --git https://github.com/ipe-lang/compiler ipe

## cli-health-critical

health: a required prerequisite is missing (see the report above)

## cli-eject-unsupported

eject: {reason}

## cli-lint-gate-failed

lint: findings remain at or above the gate severity (see above)

## cli-file-too-large

{path}: file exceeds the {max}-byte read ceiling — refusing to allocate an unbounded buffer

## cli-remote-ingest-exceeded

{source}: remote transfer exceeded the {limit} ceiling — stopped; nothing was recorded

## cli-remote-ingest-timed-out

{source}: did not finish within {limit} — check the network or the source host; nothing was recorded

## cli-package-source-exceeded

{source}: the package source exceeds the {limit} ceiling ipe accepts — stopped; nothing was recorded. The publisher must shrink the published tree (drop build artefacts / vendored data) and republish

## cli-remote-ingest-refused

{source}: sent {shape}, which ipe does not accept — stopped; nothing was recorded

## cli-transfer-interrupted

a signal ended the transfer — stopped; nothing was recorded

## cli-local-limit-exceeded

{source}: exceeded the {limit} ceiling — stopped; nothing was recorded

## cli-local-timed-out

{source}: did not finish within {limit} — stopped; nothing was recorded

## cli-cargo-build-timed-out

cargo build did not finish within {wall} — stopped with every process it started; run `cargo build -vv` in the crate to see the step that hangs

## cli-local-tree-refused

{source}: holds {shape}, which ipe does not accept — stopped; nothing was recorded

## cli-child-pipe-held

{stream} of a finished child stayed open past the grace — a process it started still holds it; stopped

## cli-child-pipe-unread

reading the {stream} of a child failed ({kind}) — its output is incomplete, so it was not used; stopped

## cli-child-stderr-truncated

… stderr cut at the {limit} ceiling; the rest was dropped

## ffi-inspector-exited

ipe add: the FFI inspector exited with code {code}
{stderr}

## ffi-inspector-signalled

ipe add: a signal ended the FFI inspector
{stderr}

## ffi-inspector-not-utf8

ipe add: the FFI inspector's report is not valid UTF-8

## cli-source-not-regular-file

{path}: not a regular file — ipe reads source only from regular files, never a FIFO, device, socket, directory or a symlink met while walking modules; point ipe at a regular `.ipe` file

## cli-source-access-denied

{path}: permission denied — grant read access to the file (and read and search access to its directory) to compile it

## cli-source-symlink

{path}: is a symlink or is reached through one — ipe never follows a symlink to a file it finds by convention or while walking imports; replace the link with the real file or directory

## cli-path-escape

manifest path {raw} was rejected: {reason}

## cli-output-refused

output directory refused: {refusal}

## cli-discovery-limit-reached

module-discovery walk aborted: {detail}

## cli-device-named-module

{path}: module segment `{segment}` is a reserved Windows device name, so this file cannot be the same module on every platform — rename it

## cli-advisory-vulnerable

dependency `{package}` v{version} is affected by {severity}-severity advisory {id}:
  {description}{fixed_in}

## cli-advisory-fixed-in

  Fixed in: {v}

## cli-advisory-db-unreachable

advisory database is unreachable — refusing to treat the dep as safe:
  {detail}

## cli-advisory-db-malformed

advisory file {path} is malformed — refusing to treat the dep as safe:
  {detail}

## cli-wasi-run-feature-disabled

ipe dev run --target wasi needs the embedded wasmtime engine, but this `ipe` binary was built without the `wasi_run` feature.
  = help: build the module with `ipe dev build --target wasi` and run it under a WASI runtime, or reinstall an `ipe` compiled with `--features wasi_run` (the default in release packaging).

## cli-wasi-run-failed

ipe dev run --target wasi: the emitted wasm32-wasip1 module could not be run under the embedded wasmtime engine — {detail}

## cli-wasi-run-exited

the wasm32-wasip1 module exited with code {code}

## cli-unknown-command-line

unknown command `{attempted}`

## cli-unknown-command-suggestion

= help: maybe `{sugg}`?

## cli-io-not-found

no such file `{path}` — pass a source file, or run inside an Ipê project (a directory with a package.ipe, or a src/Main.ipe)

## cli-io-other

could not access `{path}` — {kind}

## cli-scratch-unavailable

could not create a private scratch directory under the OS temp directory — {kind}

## cli-thread-refused

the OS refused a thread for the {role} — {kind}

## thread-role-watch-session

watch session

## thread-role-watch-coalesce

watch change coalescer

## thread-role-watch-fs-relay

watch filesystem relay

## thread-role-watch-stop-relay

watch stop relay

## thread-role-watch-resolve-retry

watch dependency-resolve retry

## thread-role-watch-compile

watch compile worker

## thread-role-watch-cargo-waiter

watch cargo-build waiter

## thread-role-wasi-wall-clock

WASI wall-clock deadline

## watch-thread-refused

[ipe dev watch] warning: {detail}; the dependency-resolve retry is skipped

# Publish refusals

## publish-dirty-tree

the working tree at {source_root} has uncommitted changes — publish pins the exact committed revision, so commit (or stash) every change first; otherwise the pinned `sha256`/`rev` would not name the bytes you publish.

## publish-unpushed-head

HEAD ({rev}) is not reachable from any remote branch — a published version pins an immutable, fetchable revision, so push this commit to its remote before publishing.

## publish-duplicate-version

`{name}` {version} is already published in the index — a published version is immutable and must never be rewritten. Bump the version in `package.ipe` and publish the new one.

## publish-no-source

could not determine the package's source URL — the index needs a public git URL the resolver can fetch. Pass `--source <url>`, or set an `origin` remote on the package's git repository.

## publish-unsigned-commit

no commit-signing key is configured, so the publish commit could only be pushed unsigned — the curated index requires signed commits and would never merge it, so nothing was published. Run `ipe login --signing-key` to generate and register one, or set `IPE_PUBLISH_SIGNING_KEY` to the path of an SSH signing key (the private key file; its `.pub` must be registered as a signing key on your GitHub account), then publish again. A set but unreadable `IPE_PUBLISH_SIGNING_KEY` is refused too — it is never bypassed.

## publish-unresolvable-identity

could not resolve your GitHub identity for the index-PR commit — the curated index requires signed commits marked "Verified", which is only possible when the commit's committer is your authenticated GitHub account's verified noreply identity. Run `ipe login` so publish can sign the index PR under your verified GitHub identity, then publish again. Nothing was published.

# Lockfile refusals

## lock-missing-field

ipe.lock: a `[[package]]` is missing `{field}`

## lock-unknown-kind

ipe.lock: package `{package}` has an unrecognised `kind` value "{kind}" — re-run `ipe add` to regenerate

## lock-index-dep-local-rev

ipe.lock: package `{package}` is an index dependency but records a `local` rev — an index dependency is always pinned to a commit; re-run `ipe add`

## lock-unrecordable-local-source

package `{package}`: a path dependency's `source` must be a non-empty path of at most {max} bytes with no control characters or `"`, got: "{raw}"

## lock-non-utf8-local-path

package `{package}`: path dependency `{path}` is not valid UTF-8 and cannot be recorded in ipe.lock

# Version refusals

## version-refused-malformed

{raw} is not a valid semantic version: {reason}

## version-refused-build-metadata

version {version} carries build metadata (`+{build}`), which the package index refuses — semver precedence ignores it, so the version would not name one release unambiguously. Drop the `+…` suffix from the version.

## version-refused-not-above

version {candidate} is not above the greatest published version {greatest} — every new version must exceed every version already in the index. Publish a version above {greatest}.

# Documentation site

The labels of the generated documentation site (`ipe doc`). A label is plain
text, escaped where it lands; an entry that holds HTML tags is inserted as written.

## site-skip-link

Skip to content

## site-nav-label

Site

## site-title-full

Ipê language documentation

## site-title-short

Ipê language docs

## site-menu-label

Menu

## site-guides

Guides

## site-topics

Topics

## site-idioms

Idioms

## site-constructs

Constructs

## site-reference

Reference

## site-diagnostics

Diagnostics

## site-cli

CLI

## site-documentation

Documentation

## site-search-placeholder

Search…

## site-search-label

Search documentation

## site-search-results-label

Search results

## site-theme-toggle-label

Toggle light and dark theme

## site-scroll-top-label

Scroll to top

## site-filter-modules

Filter modules…

## site-filter-modules-label

Filter modules

## site-project-modules

Project modules

## site-standard-library

Standard library

## site-types

Types

## site-values

Values

## site-no-documentation

No further documentation yet.

## site-reference-fallback

See <a href="module/index.html">Reference</a> for the full API.

## site-code-families-intro

Every code reads <code>IPE-</code>, a family letter, and four digits. The letter names the part of the compiler that reports it:

# Output directories

## output-symlink

{path} is a symbolic link — ipe never writes or deletes through one; remove it or point --out at a real directory

## output-not-a-directory

{path} exists and is not a directory

## output-not-ipe-owned

{path} already holds files ipe did not create (no `{marker}` marker); ipe never overwrites them — remove the directory yourself or choose another --out

## output-project-root

{path} is the project root — build output goes in a separate directory (the default is `out/`)

## output-contains-project

{out} contains the project at {project} — build output must not enclose your sources

## output-inside-sources

{out} is inside the source root {sources} — build output must stay out of your sources; pass `--out <dir>` naming a directory outside them

## output-unresolved-sources

the source root {path} cannot be resolved — ipe cannot prove the output stays out of your sources; create it or fix `package.ipe`

## output-inside-ipe-owned

{out} is inside {owner}, which ipe owns and may delete (`ipe clean`) — an ejected project must live outside ipe's output and cache; choose another --out

## output-inside-claim

{out} is inside {owner}, which an ipe process is claiming as its output (it holds `{claim}`) — an ejected project must live outside ipe's output; choose another --out, or delete `{claim}` in {owner} when no ipe process is active there

## output-inside-vcs

{out} is inside a `.git` directory — build output must stay out of version-control metadata; choose another --out

## output-inside-cache-namespace

{out} is inside a `{namespace}` directory, whose contents ipe deletes by name (`ipe clean`) in whichever project holds it — output must stay out of every ipe cache namespace; choose another --out

## output-parent-traversal

{path} has a `..` that does not climb out of an existing directory that is not a link — name the directory directly

## output-unplaceable

{path} does not name one absolute place on every platform (a drive-relative path, a device path such as `\\.\pipe`, a `/`, `.` or `..` inside a `\\?\` path, or a name Windows rewrites: a trailing `.` or space, a `:`, a device name such as `NUL` or `COM1`) — name the directory by its full path

## output-not-fresh

{path} is not empty — eject writes a new project, so point --out at an absent or empty directory

## output-unsafe-component

{path} is not a plain relative path — refusing to write it

## output-outside-project

{path} resolves outside the project at {root} — a directory walk never rewrites it

## output-replaced

{path} was replaced after ipe claimed it — refusing to write or delete in it; run the command again

## output-too-deep

{path} is nested more than {limit} directories deep — ipe refuses to walk it; remove the tree yourself

## output-reparse-point

{path} is or lies under a reparse point (a OneDrive folder, a mount point, or a deduplicated directory) — ipe cannot prove where it leads; point --out at a directory outside it

## output-in-use

{path} is held open by another program (an editor, a file indexer, or antivirus) — close it there or let that program finish, then run the command again

## output-claim-busy

{path} is being claimed by another ipe process, still in progress after {waited}s — let that run finish, then run the command again; if no ipe process is active, another program holds `{claim}` locked: delete `{claim}` in {path} and run the command again

## output-claim-lock-unavailable

{path} is on a filesystem that refused a file lock ({kind}), so ipe cannot claim it safely — choose an --out on a local disk

## output-claim-interrupted

{path} holds a claim an ipe process left unfinished, with files ipe did not write beside it — check what is there, then delete `{marker}` and `{claim}` in it and run the command again

## output-claim-marker-unfinished

{path} holds a `{marker}` an interrupted ipe process left unfinished — check it is not a file of yours, then delete `{marker}` in it and run the command again

## output-claim-in-flight

{path} is being claimed by an ipe process, or holds a claim an interrupted run left — the next build finishes the claim; run the command again then

# Publisher identity

## login-empty

it is empty

## login-too-long

it is longer than {max} characters

## login-forbidden-byte

it holds a character other than an ASCII letter, digit, or hyphen

## login-edge-hyphen

it starts or ends with a hyphen

## login-double-hyphen

it holds consecutive hyphens

## blessing-no-proven-identity

no authenticated or attested publisher identity was presented, and a self-declared `publisher` is never trusted

## blessing-identity-mismatch

the proven identity `{proven}` does not match the claimed publisher `{claimed}`

## blessing-not-blessed

the proven identity `{proven}` is not the first-party publisher `{blessed}`

## attested-actor-not-login

ipe package audit-entry: --attested-actor {raw} is not a GitHub login: {refusal}

## audit-publisher-not-login

ipe package audit: --publisher {value} is not a GitHub login: {refusal}

## publish-source-owner-not-login

ipe package publish: the source URL's owner is not a GitHub login ({refusal}) — publish from a `https://github.com/<owner>/<repo>` source

## publish-fresh-needs-blessing

ipe package publish: `--fresh` on `{name}` requires an authenticated blessed publisher identity: {reason}. The identity is the account your `ipe login` token authenticates as, resolved only on a real publish — `--dry-run` makes no network call, so it can never preview a `--fresh` reset.

## publish-fresh-claim-not-covered

the proof does not cover the claimed publisher `{claimed}`

# Package index and audit

## audit-no-manifest

ipe package audit: no `package.ipe` in `{path}` — the gate audits a publishable Ipê package, which needs a manifest

## audit-not-a-package

ipe package audit: `{path}` is neither an Ipê project directory nor a package.ipe

## index-entry-path-invalid

{path} is not a `packages/<name>.toml` entry file — the file stem names the package

## index-entry-too-many-versions

ipe package audit-entry: `{name}` lists {count} versions, exceeding the {max} per-entry ceiling — a single submission cannot carry this many versions.

## index-entry-version-rewritten

ipe package audit-entry: `{name}` version {version} is already published and immutable, but the submitted entry rewrites it (source, rev, sha256, or capabilities differ). A published version must never be rewritten — publish a new version.

## index-entry-version-dropped

ipe package audit-entry: `{name}` drops the published version {version}, but the index is append-only: a published version must never be removed. Publish a new version instead.

## index-entry-version-dropped-reset-refused

ipe package audit-entry: `{name}` drops the published version {version}, but the index is append-only: a published version must never be removed. Publish a new version instead. The reserved smoke-namespace reset is refused: {refusal}.

## index-entry-source-moved

ipe package audit-entry: `{name}` version {version} declares source `{source}`, but this package's established source is `{expected}`. A package name is bound to one source repository; a version pointing elsewhere is a name-squat and is refused.

# Tooling commands

## clean-no-manifest

clean: no package.ipe here — run it from an Ipê project root

## diff-invalid-version

diff: {refusal}

## fmt-no-files

fmt: no .ipe files found at {root}

## fmt-unformatted-files

the following files are not formatted (run `ipe fmt` to fix):
{list}

## fmt-stdin-unformatted

stdin is not formatted (run `ipe fmt --stdin` to fix)

## fmt-no-such-path

fmt: no such file or directory: {root}

## fmt-output-too-large

formatted output of `{file}` would exceed {cap} bytes; the file is left unchanged. Split it into smaller modules.

## health-home-unknown

health: cannot locate your home directory (neither CARGO_HOME nor HOME is an absolute path)

## health-install-command-empty

health: an install command was empty

## health-install-launch-failed

health: could not launch `{program}`: {detail}

## health-install-failed

health: `{program}` exited non-zero — nothing was changed

## health-config-not-toml

health: {path} is not valid TOML ({detail}); refusing to overwrite it

## health-config-edit-unparsable

health: the edited config for {path} did not re-parse; no change was made

## lint-fix-with-format

ipe lint: --fix and a data form (--json/--plain) are mutually exclusive — a data form reports without mutating

## lsp-failed

lsp: {detail}

## watch-start-failed

watch: cannot start filesystem watcher: {detail}

## watch-path-failed

watch: cannot watch {path}: {detail}

## watch-proxy-bind-failed

watch: cannot bind the blue-green proxy on port {port}: {detail}

# Manifest refusals

## ships-repeated

package.ipe declares `{delivery}` twice in `ships`. A delivery is shipped once; a repeated entry is a confused manifest, not a request for two copies. Remove the duplicate.

## ships-shape-mismatch

package.ipe declares `{delivery}`, but `main` is a `{shape}` app. The web hosts (desktop, solo, solo ios, …) carry a self-contained web client; a `{shape}` app ships as a binary. Remove the entry, or change `main` to a `Web.tea` entry.

## pkg-add-escape-dependency

package.ipe: `{name}` is already a git/path escape dependency — `ipe add` records only an index requirement and never rewrites an author-written `depGit`/`depGitRev`/`depPath` entry. Edit the escape by hand, or remove it first.

## manifest-entry-empty-segment

package.ipe: program entry {entry} has an empty path segment (a leading, trailing, or doubled `/`). Write the entry relative to `src/`, with segments joined by a single `/`, e.g. `Cli/Main.ipe`.

## manifest-entry-dot-segment

package.ipe: program entry {entry} has a `.` or `..` path segment. An entry names a module file under `src/` directly, e.g. `Cli/Main.ipe`.

## manifest-entry-backslash

package.ipe: program entry {entry} contains a backslash. Separate path segments with `/` on every platform, e.g. `Cli/Main.ipe`.

## manifest-entry-drive-prefix

package.ipe: program entry {entry} starts with a drive prefix. An entry is relative to `src/`, e.g. `Cli/Main.ipe`.

## manifest-entry-extension

package.ipe: program entry {entry} does not end in `.ipe`. An entry names an Ipê source file, e.g. `Cli/Main.ipe`.

## manifest-entry-segment-invalid

package.ipe: program entry {entry} has a path segment {segment} that is not a valid module name (segments must match [A-Z][A-Za-z0-9_]*)

## manifest-entry-no-module

package.ipe: program entry {entry} names no module

## manifest-base-path-too-long

`delivery.browser.basePath` is {len} bytes, past the {max}-byte limit. Serve the bundle under a shorter path, e.g. `/app`.

## manifest-base-path-no-leading-slash

`delivery.browser.basePath` {base} does not start with `/`. Write `/` for the origin root, or an absolute path such as `/app`.

## manifest-base-path-trailing-slash

`delivery.browser.basePath` {base} ends with `/`, and only the root is `/`. Drop the trailing slash, e.g. `/app`.

## manifest-base-path-empty-segment

`delivery.browser.basePath` {base} has an empty segment (`//`). Join segments with a single `/`, e.g. `/apps/admin`.

## manifest-base-path-dot-segment

`delivery.browser.basePath` {base} has a `.` or `..` segment, which a browser resolves away. Name the path directly, e.g. `/app`.

## manifest-base-path-reserved-byte

`delivery.browser.basePath` {base} holds the byte {byte}. A segment holds only `A-Z a-z 0-9 - . _ ~`, and segments are joined by `/`, e.g. `/my-app`.

## manifest-not-package-ipe

{path}: not a package.ipe manifest. {hint}

## bundle-name-not-a-component

package.ipe: name `{name}` cannot be a macOS bundle directory — a bundle root must be one directory name that reads back as itself, and this name holds a path separator, a `..` traversal, an absolute path, a NUL byte, or a form the host file system would rewrite (on Windows: a trailing `.` or space, a control character, one of `:*?"<>|`, or a device name such as `NUL`). Choose a plain name without `/`, `\`, `..`, or control characters.

# Mobile shell bundles

## mobile-bundle-no-index

no index.html in the emitted wasm bundle at {dir} — expected a `--target wasm` SPA (index.html + boot script + pkg/*.wasm)

## mobile-bundle-unplaceable

cannot bundle {path} from the emitted wasm bundle: {reason}

## mobile-bundle-too-deep

the emitted wasm bundle nests directories deeper than {limit} levels at {path}

## mobile-bundle-too-many

the emitted wasm bundle holds more than {limit} entries

## mobile-bundle-replaced

the emitted wasm bundle at {path} was replaced after it was collected — build and package again

## mobile-bundle-io

reading {path}: {detail}

## mobile-asset-not-utf8

its name is not valid UTF-8, which a shell asset path cannot carry

## mobile-asset-bad-name

its name is not one plain entry name

## mobile-asset-kind

it is {kind}; only regular files and directories are bundled

# ipe doc

## doc-generate-only-flag

ipe doc {sub}: {flag} is a generate-only flag; run `ipe doc` to write files

## doc-port-serve-only

ipe doc {sub}: --port applies only to `ipe doc serve`

## doc-lookup-only-flag

ipe doc {sub}: {flag} applies only to `list`, `<module>` queries, and `<key>` lookups

## doc-unknown-write-format

ipe doc: unknown --write-format `{format}` (want markdown | json | html | all)

## doc-stdlib-index-failed

ipe doc: stdlib index failed: {detail}

## doc-bundle-build-error

ipe doc: bundle build error: {detail}

## doc-unknown-kind

ipe doc: `{prefix}` is not a known documentation kind
Known kinds: module, symbol, diagnostic, construct, idiom, topic, guide, cli

## doc-query-empty

ipe doc: the term is empty; name a module, symbol, or `kind:key` entry

## doc-query-too-long

ipe doc: the term is longer than {max} characters

## doc-query-control

ipe doc: the term contains a control character or escape sequence

## doc-pick-prompt

Open which entry? [1-{count}, Enter to cancel]

## doc-pick-retry

Not a listed number.

## doc-pick-none

ipe doc: no entry opened

## doc-ambiguous-module

ipe doc: `{query}` matches more than one stdlib module
{candidates}

## doc-type-no-match

ipe doc --type: no symbols match `{query}`

## doc-kernel-table-error

ipe doc: kernel type table error: {detail}

## doc-type-invalid-query

ipe doc --type: `{query}` is not a valid type expression

{detail}

Hint: use Ipê type syntax, e.g. `List a -> (a -> b) -> List b`

## doc-type-no-match-hint

ipe doc --type: no symbols match `{query}`

Try a broader query or `ipe doc list` to browse modules.

# Rust crates and FFI

## ffi-cache-untrusted

refusing to load the FFI cache at `{path}`: it is not owned by the current user, or another user can write to it — its `_bindings.rs` compiles unsandboxed into your crate. Fix its ownership/permissions or remove it

## ffi-cache-unverifiable

refusing to load the FFI cache at `{path}`: its ownership cannot be verified on this platform — its `_bindings.rs` compiles unsandboxed into your crate. Remove it

## ffi-cache-symlink

refusing to load the FFI cache: `{path}` is a symbolic link, which could redirect the cache to files another user controls. Replace it with a real directory or file, or remove it

## ffi-cache-not-regular

refusing to load the FFI cache: `{path}` is not a regular file. Remove it and re-run `ipe rust add` for the crate

## ffi-cache-too-many-entries

refusing to load the FFI cache at `{path}`: it holds more than {max} entries. Remove the entries that are not installed crates' artifacts

## ffi-module-clash

module `{module}` clashes with the installed FFI crate `{krate}` — the `Rust.*` namespace is reserved for FFI interface modules

## ffi-define-opaque-collision

installed FFI crate `{krate}` defines a `[rust.define.*]` type `{name}` whose name also names an inspected opaque type of the crate — the two are different Rust types that would collide on one nominal; rename the define type

## ffi-dependency-source-conflict

installed FFI crates bind dependency `{name}` to two different sources:
  {first}
  {second}

## ffi-dependency-pin-conflict

installed FFI crates pin dependency `{name}` to conflicting versions:
  ={first}
  ={second}
re-add one of the crates so the version pins agree

## ffi-dropped-transitive

installed FFI crates need different versions of dependency `{name}`, so the app does not declare it, but `{site}` names its crate `{ident}` directly
re-add the crates so their `{name}` versions agree

## ffi-emit-unlexable

generated FFI code at `{site}` is not valid Rust, so the crates it names cannot be checked — re-run `ipe add`

## ffi-transparent-without-shape

installed FFI crate `{krate}` marks `{name}` transparent in binding `{binding}` but carries no shape for it — re-run `ipe add`

## ffi-reserved-module-claimed

installed FFI crate `{krate}` claims the module `{module}`, which is reserved for the asserted-call surface (`Rust.Ffi.call`); remove or rename the crate

## ffi-reserved-wrapper-prefix

installed FFI crate `{krate}` declares wrapper `{wrapper}`, which uses the reserved asserted-shim prefix `{prefix}` — refusing to load the cache

## ffi-reserved-module-exists

module `{module}` already exists — it is reserved for the asserted-call surface (`Rust.Ffi.call`)

## ffi-asserted-empty-catalog

internal: asserted calls validated against an empty FFI catalog

## ffi-add-scratch-dir

ipe add: scratch dir: {detail}

## ffi-toolchain-bind-exposes-cargo-home

ipe add: refusing to bind `{bind}` into the jail: it contains the cargo home `{cargo_home}` and its `credentials.toml` — set RUSTUP_HOME and CARGO_HOME to disjoint directories

## ffi-cargo-home-unresolved

ipe add: cannot locate the cargo home, so the jail cannot keep its `credentials.toml` hidden — set CARGO_HOME or HOME to an absolute path

## ffi-jail-path-refused

ipe add: {detail} — set HOME, CARGO_HOME, and RUSTUP_HOME to absolute paths

## ffi-install-manifest-write-failed

ipe install: manifest write failed: {detail}

## ffi-install-manifest-chunk-write-failed

ipe install: manifest chunk write failed: {detail}

## ffi-regen-invalid-json

ffi regen: invalid inspector JSON: {detail}

## ffi-regen-unexpected-shape

ffi regen: unexpected inspector output shape: {output}

## ffi-regen-item-unnamed

ffi regen: inspector item has no `name` or `pkg` field: {item}

## ffi-install-invalid-json

ipe install: invalid inspector JSON: {detail}

## ffi-install-unexpected-shape

ipe install: unexpected inspector output shape: {output}

## ffi-define-crate-ambiguous

ipe: [[rust.define.{kind}]] `{name}` has no `crate` key but the manifest lists more than one [rust.dependencies] crate — add `crate = "<name>"` to say which crate it augments

## ffi-inspection-not-object-detail

ipe: inspection JSON is not an object: {detail}

## ffi-inspection-not-object

ipe: inspection JSON is not an object

## ffi-inspection-functions-not-array

ipe: inspection `functions` is not an array

## ffi-opaque-unknown-type

foreign `{name}`: `Opaque "{rust_type}"` names a type crate `{krate}` does not report — it is not an inspected type, so a handle over it cannot be minted (check the spelling, or that the crate exposes the type)

## ffi-opaque-is-transparent

foreign `{name}`: `Opaque "{rust_type}"` names a type the inspector surfaced TRANSPARENTLY (a value record/union), not an opaque handle — declare the Ipê record/ADT and let the inspector shape-match it instead of an `Opaque`

## ffi-opaque-without-path

foreign `{name}`: the inspector reported `{rust_type}` without a Rust path — it cannot be resolved to a handle

## ffi-opaque-declared-twice

foreign `{name}`: declared twice over different crate types — a handle nominal names exactly one Rust type

## located-refusal

{file}:{line}:{col}: {reason}

# ipe init

## init-shape-fixed

ipe init: this directory already holds a `{existing}` project (its `src/Main.ipe` pins the shape), but you asked for `{stated}`. A program's shape is fixed by the head of `main`, so `init` will not reshape it. Edit `src/Main.ipe` to change shape, or scaffold the new shape in a fresh directory.

## init-shape-disagrees

ipe init: shape positional `{positional}` and `--shape {flag}` disagree — write the shape once

## init-runtime-needs-web

ipe init: `{runtime}` is a web runtime, but you asked for a `{shape}` project. Only the `web` shape has a runtime choice (served vs solo) — every other shape runs one way. Drop the runtime word.

## init-unknown-shape

ipe init: unknown shape `{word}` — expected: script, tui, cli, worker, server, web

## init-unknown-runtime

ipe init: unknown runtime `{word}` — the web runtimes are: served (the default), solo

## init-unknown-shape-choice

ipe init: unknown shape `{word}` — expected 1-6 or one of: web, tui, cli, worker, server, script

## init-unknown-runtime-choice

ipe init: unknown runtime `{word}` — expected 1-2 or one of: served, solo

## init-no-project-name

init: cannot derive a project name from target {target}

# ipe login

## login-verification-url-refused

GitHub returned a verification URL that is not https on github.com — refusing to open it

## login-code-expired-before-approval

the authorization code expired before you approved it — run `ipe login` again

## login-token-malformed

GitHub returned a token with unexpected characters

## login-denied

authorization was denied on GitHub

## login-code-expired

the authorization code expired — run `ipe login` again

## login-github-reported

GitHub reported `{status}`

## login-response-unrecognised

GitHub's response had neither a token nor a recognised status

## login-curl-unavailable

could not run `curl` (needed for the GitHub OAuth request): {detail}

## login-curl-wait-failed

the OAuth request to GitHub failed while waiting for curl: {detail}

## login-request-failed

the OAuth request to GitHub failed: {detail}

## login-response-not-json

could not parse GitHub's response as JSON: {detail}

## login-response-missing

GitHub's response was missing `{key}`

## login-config-dir-unknown

could not determine a config directory (set HOME or XDG_CONFIG_HOME)

## login-create-failed

could not create {path}: {detail}

## login-write-failed

could not write {path}: {detail}

## login-move-failed

could not move the token into place at {path}: {detail}

## login-remove-failed

could not remove {path}: {detail}

## login-token-store-unsupported

cannot store the token on this platform: its file cannot be made readable by you alone — set `GITHUB_TOKEN` instead

## login-secret-not-owner-only

{path} is not private to you (another local user could read or replace it, or its filesystem ignores permission bits) — the token was not stored; make it owner-only (`chmod go-rwx`) on a filesystem that keeps permissions, or set `GITHUB_TOKEN` instead

## login-secret-symlinked-dir

{path} is a symbolic link — the token was not stored; point `XDG_CONFIG_HOME` (or `HOME`) at the real directory, or replace the link with the directory it names

## login-secret-not-regular-file

{path} is not a regular file — the token was not stored; move it aside and run `ipe login` again

## build-cache-dir-symlinked

warning: {path} is a symbolic link — the default build cache is disabled; point `IPE_HOME` at the real directory, or set `IPE_BUILD_CACHE_DIR`

## build-cache-dir-untrusted

warning: {path} is not private to you (another local user could write or replace it) — the default build cache is disabled; make it owner-only (`chmod go-w`), or set `IPE_BUILD_CACHE_DIR`

## login-status-logged-in

logged in — token stored at {path}

## login-status-corrupt

token file at {path} is unreadable or malformed — run `ipe login` to re-authorize

## login-status-exposed

token file at {path} is not private to you — publish will not use it; treat the token as exposed: revoke it in GitHub settings, then run `ipe login --logout` and `ipe login`

## login-status-symlinked-dir

token directory {path} is a symbolic link — publish will not read a token through it; point `XDG_CONFIG_HOME` (or `HOME`) at the real directory, or replace the link with the directory it names

## login-status-dir-untrusted

token directory {path} is not private to you (another local user could write or replace it) — publish will not read a token under it; if a token is stored there, treat it as exposed: revoke it in GitHub settings, then make the directory owner-only (`chmod go-w`) and run `ipe login --logout` and `ipe login`

## login-status-not-logged-in

not logged in — run `ipe login` to authorize

## login-stored

Logged in. Token stored at {path}

## login-logout-nothing

not logged in — nothing to remove

## login-logout-removed

logged out — removed {path}

## login-device-prompt

{purpose}, visit:
  {url}
and enter the code:  {code}

## login-grant-purpose-publish

To authorize ipe

## login-grant-purpose-signing-key

To let ipe add the signing key (scope `{scope}`, used once, never stored)

# Signing key

## signing-key-status-env

signing key: {path} (from {env})

## signing-key-status-env-unusable

signing key: {env} is set but names no readable key file — publish will refuse

## signing-key-status-stored

signing key: {path} (generated by `ipe login`)

## signing-key-status-stored-exposed

signing key: {path} is not private to you — publish will not use it; treat the key as exposed: delete it from your GitHub signing keys ({settings}), remove the file, and run `ipe login --signing-key` again

## signing-key-status-stored-unusable

signing key: {path} is not a usable key file — publish will not use it; move it aside and run `ipe login --signing-key` again

## signing-key-status-symlinked-dir

signing key: {path} is a symbolic link — publish will not use a key through it; point `XDG_CONFIG_HOME` (or `HOME`) at the real directory, or replace the link with the directory it names

## signing-key-status-dir-untrusted

signing key: {path} is not private to you (another local user could write or replace it) — publish will not use any key under it; if a key is stored there, treat it as exposed: delete it from your GitHub signing keys ({settings}), then make the directory owner-only (`chmod go-w`) and run `ipe login --signing-key` again

## signing-key-status-none

signing key: none — run `ipe login --signing-key` to generate and register one

## signing-key-already-configured

Publish signs with {path}.

## signing-key-env-unusable

{env} is set but names no readable key file, so publish will refuse. Point it at your signing key's private-key file, or unset it and run `ipe login --signing-key`.

## signing-key-declined

No signing key generated. `ipe package publish` needs one — run `ipe login --signing-key` any time, or set {env} to an existing signing key.

## signing-key-registered

Signing key registered on your GitHub account and stored at {path}. `ipe package publish` signs with it; review it at {settings}.

## signing-key-consent-question

No commit-signing key is configured. `ipe package publish` signs the index
commit with an SSH key registered on your GitHub account as a signing key.

ipe can generate a dedicated ed25519 key (no passphrase, mode 0600) at
  {path}
and register its public half as a signing key on your account. That needs a
second, one-time GitHub authorization with the `{scope}` scope;
its token is used for this single request and never stored. Revoke it any
time under Authorized OAuth Apps at
  {revoke_url}
(revoking ipe there also revokes the stored `ipe login` token).

Generate and register a signing key now?

## signing-key-hint-no-terminal

No commit-signing key is configured; `ipe package publish` needs one. Run `ipe login --signing-key` in a terminal to generate and register it.

## signing-key-needs-terminal

`--signing-key` asks for consent and a GitHub authorization, so it needs an interactive terminal

## signing-key-no-config-dir

could not determine a config directory for the signing key (set HOME or XDG_CONFIG_HOME)

## signing-key-store-unsupported

cannot store a signing key on this platform: its private key file cannot be made readable by you alone — no key was generated; set {env} to a signing key you keep private instead

## signing-key-not-owner-only

{path} is not private to you (another local user could read or replace it, or its filesystem ignores permission bits) — no signing key was registered; set {env} to a signing key you keep private instead

## signing-key-symlinked-dir

{path} is a symbolic link — no signing key was registered; point `XDG_CONFIG_HOME` (or `HOME`) at the real directory, or replace the link with the directory it names

## signing-key-stored-exposed

{path} is already registered as a signing key on your GitHub account, but is not private to you (another local user could read it) — no new signing key was generated; delete it from your GitHub signing keys ({settings}), remove the file, and run `ipe login --signing-key` again

## signing-key-occupied

{path} already exists but is not a usable signing key — move it aside and run `ipe login --signing-key` again

## signing-key-link-unsupported

{dir} does not support hard links ({detail}), which ipe needs to store the key without overwriting anything — no signing key was registered; set {env} to a signing key you registered yourself instead

## signing-key-generation-failed

the OS random-number generator failed, so no signing key was generated

## signing-key-write-failed

could not write {path}: {detail} — no signing key was registered

## signing-key-registration-failed

{reason} — no signing key was stored locally; run `ipe login --signing-key` to retry

## signing-key-commit-failed

the signing key was registered on GitHub, but could not be stored at {path}: {detail}. The local copy was removed; delete the key titled "{title}" at {settings} and run `ipe login --signing-key` again

## signing-key-authorization-failed

the key-registration authorization failed: {reason}

## signing-key-refused

GitHub refused the signing key (HTTP {status}): {message}

## signing-key-unreachable

could not reach GitHub: {reason}

# Packages

## pkg-invalid-requirement

ipe add: `{requirement}` is not a valid version requirement: {detail}

## pkg-usage

usage: ipe {command} <package>[@<version>]

## publish-fork-owner-unknown

ipe package publish: could not infer your GitHub fork owner from the source URL — pass `--fork <github-user>` (the owner of your fork of the index).

## publish-no-manifest

ipe package publish: no `package.ipe` in `{path}` — publish operates on a publishable Ipê package, which needs a manifest

## publish-not-a-package

ipe package publish: `{path}` is neither an Ipê project directory nor a package.ipe

## publish-no-version

ipe package publish: `{name}` declares no `version = "…"` — publish records the version being published, so the manifest must name one.

## publish-source-refused

ipe package publish: the source URL is not accepted — {detail}

## publish-rev-refused

ipe package publish: the revision is not accepted — {detail}

## publish-rev-not-sha

ipe package publish: `--rev` resolved to a non-SHA: {detail}

## publish-head-not-sha

ipe package publish: HEAD did not resolve to a full SHA: {detail}

## publish-fresh-refused

ipe package publish: `--fresh` is only permitted on a reserved-namespace package (the disposable smoke probe); it would otherwise erase `{name}`'s published history. Publish a new version without `--fresh` instead.

# Build and run

## run-main-anchor-absent

the emitted `fn main` anchor is absent, so the embedded capability floor cannot be retained past linker GC — refusing to write an unenforceable artifact

## run-main-anchor-ambiguous

the emitted source holds more than one `fn main` anchor, so the embedded capability floor has no single place to be retained from — refusing to write an ambiguous artifact

## run-floor-block-malformed

the emitted source carries a capability floor block other than the one ipe writes — refusing to embed a floor beside one it cannot account for

## run-profile-unparsable

{code}: {detail} — refusing to run (a profile that does not parse is not honored)

## build-entry-not-main

program entry module `{module}` is not yet buildable — a declared `programs` entry outside module `Main` type-checks (`ipe type-check`) but native emission still assumes a `Main` entry. Name the entry file `Main.ipe`, or track the multi-program emit follow-up

## pack-retired

ipe pack has been retired — app bundling is now the delivery grammar. Use `ipe dev build web desktop` / `ipe dev build web ios` / `ipe dev build web android` for a fast dev bundle, or `ipe release build web desktop|ios|android` for a production distributable. For the OS-permission dry-run, use `ipe release build --emit-permissions <ios|macos|android>`.

## build-binary-missing

ipe dev build: expected binary at {path} — cargo build succeeded but the binary is missing

## release-binary-missing

ipe release: expected binary at {path} — cargo build succeeded but binary is missing

## release-app-binary-missing

ipe release: expected app binary at {path} — cargo build succeeded but binary is missing

## emitted-crate-name-unreadable

the emitted crate manifest {path} names no plain `[package] name`, so its built binary cannot be located — rebuild the program to re-emit the crate

## cli-wrapper-source-refused

ipe release: the jail wrapper source at {root} is not verified: {reason}. A native-bearing release builds its wrapper only from the compiler source tree this `ipe` was built from; build `ipe` from its source checkout to release a native-bearing app

## wrapper-source-no-build-root

the build-time crate path has no workspace root above it

## wrapper-source-unsupported

this host cannot prove directory ownership

## wrapper-source-unproven

{path} is absent or not owner-trusted

## wrapper-source-unreadable

{path} could not be read as UTF-8 within the manifest size cap

## wrapper-source-unparsable

{path} is not valid TOML

## wrapper-source-not-workspace

its Cargo.toml has no [workspace] table

## wrapper-source-member-undeclared

the workspace members do not include {member}

## wrapper-source-package-mismatch

the wrapper member's package is not {package}

## cli-no-run-form

`ipe release run` runs a native program; the {target} target has no run form

## cli-no-run-form-hint

= help: build it with `ipe release build {form}`

## release-run-artifact-flags

ipe release run: {dir} is a built artifact directory; it runs as built and takes no build arguments

## release-run-bundle-incomplete

ipe release run: the bundle at {dir} has no {missing}; a bundle runs only with its wrapper, app and profile together

## release-run-wrapper-unverifiable

ipe release run: {dir} holds a wrapper with no app and profile beside it, so there is nothing to verify; ipe release run runs a bundle directory or a project

## wasm-bindgen-failed

wasm-bindgen failed (exit {code}); ensure wasm-bindgen-cli {version} is installed: cargo install wasm-bindgen-cli --version {version}

## wasi-artifact-missing

the wasm32-wasip1 build reported no `.wasm` artifact for {dir} — cargo's JSON message stream carried no `compiler-artifact` naming the module

## session-no-recordable

ipe dev run {flag}: {name} has no recordable session — recording and replay capture the update loop of a `Cli.tea` or `Worker.tea` app

## session-native-only

ipe dev run {flag}: works on a native run only — drop `--target wasi`

## session-ffi-unproven

ipe dev run {flag}: a program with Rust FFI cannot be recorded or replayed, since its replay is not proven deterministic — run it without {flag}

## session-flags-exclusive

ipe dev run: {first} and {second} cannot be combined — record a session, then replay it

## replay-no-default-log

ipe dev run --replay: no session log at {typed} or trace at {trace} — record one with `ipe dev run --record`

## replay-log-missing

ipe dev run --replay: no session log at {path} — record one with `ipe dev run --record`

## program-exited

{program} exited with code {code}

## cargo-metadata-failed

cargo metadata failed in {dir}: {detail}

## cargo-metadata-unparsable

cargo metadata emitted unparseable JSON: {detail}

## cargo-metadata-no-target-dir

cargo metadata reported no target_directory

## explain-moved

`ipe explain` has moved: use `ipe doc <key>` instead

Examples:
ipe doc IPE-L0107   look up a diagnostic code
ipe doc case        look up a language construct
ipe doc List.map    look up a stdlib symbol
ipe doc version     look up a command

## app-binary-missing

expected app binary at {path} — cargo build succeeded but the binary is missing

## wasm-ipe-binary-unknown

cannot locate the ipe binary to build wasm: {detail}

## mobile-wasm-build-failed

the `--target wasm` build failed (exit {code}) — the mobile shell hosts that bundle, so it must build first

## emit-permissions-failed

ipe {verb} --emit-permissions: {detail}

## package-validate-entry-single-path

ipe package validate-entry: expected a single entry-file path

## audit-entry-nothing-new

ipe package audit-entry: `{name}` — every version in the submitted entry is already in the baseline index; nothing new to audit

## upgrade-unsupported-platform

upgrade: not supported on this platform — run the installer manually:
  {command}

## upgrade-installer-launch-failed

upgrade: cannot launch the installer (needs `sh` and `curl`): {detail}

## upgrade-installer-download-failed

upgrade: the installer could not be downloaded — nothing was changed: {detail}

## upgrade-installer-wait-failed

upgrade: the installer could not be waited on: {detail}

## upgrade-installer-short-feed

upgrade: the installer exited before reading its whole script, so the upgrade cannot be confirmed: {detail}

## upgrade-installer-failed

upgrade: the installer exited non-zero — nothing was changed

# Command outcomes

## type-check-ok

No type errors — this program type-checks.

## upgrade-up-to-date

ipe {version} — already the latest release

## upgrade-feed-unreachable

couldn't reach the release feed — check your connection

## upgrade-available

ipe {current} → {latest} available

## upgrade-confirm

Upgrade now? [Y/n]

## release-embedded

released → {path} (single self-jailing binary; run `--capabilities` to audit)

## release-bundled

released (bundle) → {path} (run `./ipe-wrapper -- <args>`; WARNING: ipe-app can be run directly, bypassing the sandbox — prefer embed mode for production)

## mobile-android-note

note: an unsigned Android Gradle project is written here. `./gradlew assembleDebug` (with the Android SDK) builds an APK signed with the SDK's debug key, for local install only; a store build needs your own keystore — add a `signingConfig` for it to `app/build.gradle`, then run `./gradlew assembleRelease`.

## mobile-ios-note

note: the iOS shell project layout is written here, but a signed, runnable .ipa must be produced on a macOS runner with Xcode + a signing identity (out of scope).

# Consent refusals

## consent-item

  = {item}

## web-consent-disclosure

`{wire}` disclosed by {via}

## web-consent-disclosure-unattributed

`{wire}` disclosed by a module the build could not attribute

## web-consent-remedy

  = a web capability is granted ONLY by the top-level app's package.ipe; a dependency
    discloses but cannot self-authorise. Grant it after review by adding the axis,
    spelled `JsPort <Axis>`, to `accepts = [ … ]` in the `capabilities` record of
    package.ipe, or drop the dependency.

## native-ffi-crossing

`Rust.{krate}` crossed by {via}

## native-ffi-crossing-unattributed

a native crossing the build could not attribute to a crate

## native-ffi-consent-remedy

  = a native crossing is granted ONLY by the top-level app's package.ipe; a dependency
    crosses but cannot self-authorise. Its true effects are opaque to Ipê and
    contained at run by the OS jail, but the crossing itself needs the consumer's
    consent. Grant it after review by adding `NativeFfi` to `declares = [ … ]` in
    the `capabilities` record of package.ipe, or drop the dependency.

## control-model-consent-refusal

`{entry_module}` runs the `{model}` control model, which the declared `acceptsControl` set does not cover
  = the package opted into control-model consent by declaring `acceptsControl`,
    so that set must cover the program's actual control model; it does not
    list `{model}`, so the declared acceptance is stale.
  = cover it after review by adding `{ctor}` to `acceptsControl = [ … ]` in
    the `capabilities` record of package.ipe, or switch the entry to a listed
    control model.

## permission-consent-header

error[IPE-P0001]: the packaged {platform} manifest declares OS permission(s) the app has not accepted

## permission-consent-remedy

  = an OS permission is DERIVED from the app's `accepts` set, never hand-added; a
    permission with no backing accepted web capability cannot ship. Grant the backing
    capability after review by adding the axis to `accepts = [ … ]` under
    [capabilities] in package.ipe, or remove the permission from the override.

# Package resolution

## index-source-url-invalid

package `{pkg}`: `source` must be an https://, ssh://, or file:// URL (or a bare absolute path), got: {raw}

## index-source-url-plaintext

package `{pkg}`: `source` uses the unauthenticated, unencrypted git:// transport, got: {raw} — use the repository's https:// URL instead

## index-rev-injection

package `{pkg}`: `rev` contains an injection-shaped value, got: {raw}

## index-rev-not-immutable

package `{pkg}`: recorded `rev` is not an immutable commit SHA (expected 40 lowercase hex chars), got: {raw} — re-run `ipe add` to record an immutable pin

## index-rev-mixed-case-hex

package `{pkg}`: `rev` is hex-shaped but mixed-case, got: {raw} — a commit SHA is always lowercase; use the lowercase spelling or a distinct ref name

## index-rev-served-mismatch

package `{pkg}`: requested rev `{requested}` does not match the commit git served, `{served}` — a ref of the same name shadowed the full SHA; rename the ref or re-check the requested commit

## index-sha256-invalid

package `{pkg}`: `sha256` is not a 64-char lowercase-hex content hash, got: {raw}

## index-entry-unreadable

index entry for `{name}` exists but could not be read — {detail}

## add-package-not-in-index

add: package `{name}` is not in the index — check the name, or run `ipe rust add` for a Rust crate

## add-index-entry-unreadable

add: could not read the index entry for `{name}` — {kind}

## index-no-version-satisfies

package `{name}`: no published version satisfies `{req}` (available: {available})

## index-no-version-available

none

## index-publisher-not-login

package `{name}`: index entry `publisher` is not a GitHub login: {refusal}

## index-entry-missing-publisher

package `{name}`: index entry is missing `publisher`

## index-entry-no-versions

package `{name}`: index entry lists no `[[version]]`

## registry-json-malformed

package `{name}`: registry JSON is malformed ({detail})

## index-capability-unknown

package `{name}`: {detail}

## index-version-missing-field

package `{name}`: a `[[version]]` entry is missing `{field}`

## index-capabilities-not-array

package `{name}`: `capabilities` must be a `["…", …]` array, got: {raw}

## publish-rev-unresolved

ipe package publish: `git rev-parse --verify {refspec}` failed — ref {rev} does not resolve to a commit

## publish-scratch-io

ipe package publish: scratch filesystem error: {detail}

## publish-clone-failed

ipe package publish: could not clone your index fork `{fork_url}` — publish pushes the entry to your fork, so fork the index on GitHub first (a one-time step) and make sure git can reach it.
  git: {git}

## publish-push-failed

ipe package publish: could not push `{branch}` to `{fork_url}` — nothing was published. git pushes without a terminal prompt, so it authenticates only through a credential helper: configure one (`gh auth setup-git` sets up GitHub's), make sure your account can push to the fork, then open the PR here:
  {url}
  git: {git}

## publish-not-git-repo

ipe package publish: `{path}` is not a git repository — publish pins a committed, pushed revision, so the package must live in a git repo (or pass `--source`/`--rev`).

## publish-git-unavailable

ipe package publish: could not run `git`: {detail}

## publish-http-status-empty

ipe package publish: {op} got no HTTP status from curl — nothing was published.

## publish-http-status-not-digits

ipe package publish: {op} got a malformed HTTP status from curl, not 3 digits — nothing was published.

## publish-http-status-no-response

ipe package publish: {op} got no response (curl reported status `000`, usually a connection failure) — nothing was published.

## publish-http-status-out-of-range

ipe package publish: {op} got an out-of-range HTTP status from curl: {value} — nothing was published.

## publish-http-transport-failed

ipe package publish: {op} — curl could not complete the request: {detail} — nothing was published.

## publish-http-body-io

ipe package publish: {op} response body could not be read back from the scratch file — nothing was published.

## trust-token-invalid

registry trust: `{label}` must be a non-empty token with no whitespace or control characters, got: {raw}

## signature-bundle-malformed

package `{pkg}`: signature bundle is malformed ({detail})

## signature-required-absent

package `{pkg}`: no publisher signature is present, but the configured registry trust policy requires one (`require_signature = true`) — refusing to resolve an unsigned version

## signature-untrusted

package `{pkg}`: a publisher signature is present but was not trusted — {detail}

## trust-config-malformed

registry trust config is malformed ({detail})

## resolve-path-dep-missing

package `{name}`: path dependency `{path}` does not exist

## resolve-index-dep-escape

package `{name}`: an index dependency is resolved through `resolve_and_add`, not `resolve_escape`

## resolve-git-unavailable

package `{name}`: could not run `git`: {detail}

## resolve-git-failed

package `{name}`: `git {args}` failed: {stderr}

## resolve-fetched-commit-mismatch

package `{pkg}`: the source served commit {served} where commit {requested} was asked for — nothing was recorded; check that `rev` names a commit the source repository holds

## login-error

ipe login: {message}

## package-name-invalid

`{raw}` is not a valid package name: {why} — a name is joined into a filesystem path, so it must be a single portable path component (matching `[a-z0-9]([a-z0-9]|-[a-z0-9])*`)

## package-name-empty

a package name must not be empty

## package-name-too-long

a package name must be at most {max} bytes

## package-name-bad-start

a package name must start with an ASCII lowercase letter or digit

## package-name-doubled-dash

a package name must not contain a doubled `-`

## package-name-bad-char

a package name may contain only ASCII lowercase letters, digits, and `-`

## package-name-trailing-dash

a package name must not end with `-`
