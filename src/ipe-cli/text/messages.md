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

ipe run builds and executes a native binary; --target wasm has no native artifact to run — use `ipe build --target wasm` to produce a browser bundle

## run-wasi-native-flags

--static / --allocator / --cfree are native-target flags; they do not compose with --target wasi

## eject-out-required

ipe eject: --out <dir> is required (the directory to write the standalone project to)

## release-no-wasi

ipe release produces a browser bundle (`--target wasm`) or a native binary; it does not produce a WASI module — build one with `ipe build --target wasi`

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

## ffi-add-home-unset

ipe add: HOME is not set; cannot create a safe scratch directory

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

## no-entry

nothing to build here — pass a source file or run inside a project (a package.ipe, or a src/Main.ipe)

## internal-entry-not-in-source-map

internal: entry module not in source map

## internal-module-not-in-source-map

internal: module in topo order not in source map

## library-package-no-entry

this is a library package (it declares `exposedModules` and no runnable program) — there is no entry to build. Use `ipe type-check` to verify its public surface, or add a `Package.programs [ … ]` stage to declare a runnable entry

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

  ipe doc {key}  {title} ({kind})

## cli-unknown-code

unknown error code `{input}`

## cli-unknown-code-did-you-mean

  did you mean: {first}

## cli-semver-rejected

version {proposed} does not clear the required {required} bump — the new version must be at least {floor}.

## cli-publish-refused

ipe package publish refused: {refusal}

## cli-unknown-group-verb

unknown `ipe {group}` verb `{attempted}`

## cli-unknown-group-suggestion

= help: maybe `ipe {group} {sugg}`?

## cli-verify-failed

verify: the {stage} stage failed

## cli-test-failed-suffix

one or more tests failed (runner exited {code})

## cli-upgrade-no-prebuilt

{glyph} No prebuilt binary for {version} on {platform}.
    Possibly the binaries for that version are still being generated.
    If you prefer, build from source:
        cargo install --git https://github.com/arthurmaciel/ipe-lang ipe

## cli-health-critical

health: a required prerequisite is missing (see the report above)

## cli-eject-unsupported

eject: {reason}

## cli-lint-gate-failed

lint: findings remain at or above the gate severity (see above)

## cli-file-too-large

{path}: file exceeds the {max}-byte read ceiling — refusing to allocate an unbounded buffer

## cli-path-escape

manifest path {raw} was rejected: {reason}

## cli-output-refused

output directory refused: {refusal}

## cli-discovery-limit-reached

module-discovery walk aborted: {detail}

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

ipe run --target wasi needs the embedded wasmtime engine, but this `ipe` binary was built without the `wasi_run` feature.
  = help: build the module with `ipe build --target wasi` and run it under a WASI runtime, or reinstall an `ipe` compiled with `--features wasi_run` (the default in release packaging).

## cli-wasi-run-failed

ipe run --target wasi: the emitted wasm32-wasip1 module could not be run under the embedded wasmtime engine — {detail}

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

no commit-signing key is configured, so the publish commit could only be pushed unsigned — the curated index requires signed commits and would never merge it, so nothing was published. Set `IPE_PUBLISH_SIGNING_KEY` to the path of an SSH signing key (the private key file; its `.pub` must be registered as a signing key on your GitHub account) and publish again.

## publish-unresolvable-identity

could not resolve your GitHub identity for the index-PR commit — the curated index requires signed commits marked "Verified", which is only possible when the commit's committer is your authenticated GitHub account's verified noreply identity. Run `ipe login` so publish can sign the index PR under your verified GitHub identity, then publish again. Nothing was published.

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

{out} is inside the source root {sources} — build output must stay out of your sources

## output-unresolved-sources

the source root {path} cannot be resolved — ipe cannot prove the output stays out of your sources; create it or fix `package.ipe`

## output-inside-ipe-owned

{out} is inside {owner}, which ipe owns and may delete (`ipe clean`) — an ejected project must live outside ipe's output and cache; choose another --out

## output-inside-vcs

{out} is inside a `.git` directory — build output must stay out of version-control metadata; choose another --out

## output-inside-cache-namespace

{out} is inside a `{namespace}` directory, whose contents ipe deletes by name (`ipe clean`) in whichever project holds it — output must stay out of every ipe cache namespace; choose another --out

## output-parent-traversal

{path} has a `..` in a part that does not exist yet — name the directory directly

## output-not-fresh

{path} is not empty — eject writes a new project, so point --out at an absent or empty directory

## output-unsafe-component

{path} is not a plain relative path — refusing to write it

## output-outside-project

{path} resolves outside the project at {root} — a directory walk never rewrites it

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

diff: invalid version `{raw}`

## fmt-no-files

fmt: no .ipe files found at {root}

## fmt-unformatted-files

the following files are not formatted (run `ipe fmt` to fix):
{list}

## fmt-stdin-unformatted

stdin is not formatted (run `ipe fmt --stdin` to fix)

## fmt-no-such-path

fmt: no such file or directory: {root}

## health-home-unknown

health: cannot locate your home directory (neither CARGO_HOME nor HOME is set)

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

## manifest-entry-invalid

package.ipe: program entry {entry} is not a valid entry file

## manifest-entry-segment-invalid

package.ipe: program entry {entry} has a path segment {segment} that is not a valid module name (segments must match [A-Z][A-Za-z0-9_]*)

## manifest-entry-no-module

package.ipe: program entry {entry} names no module

## manifest-not-package-ipe

{path}: not a package.ipe manifest. {hint}

## bundle-name-not-a-component

package.ipe: name `{name}` cannot be a macOS bundle directory — a bundle root must be a single path component, but this name introduces a path separator, a `..` traversal, or an absolute path. Choose a name without `/`, `\`, or `..`.

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

## doc-no-entry-for-key

ipe doc: no `{kind}` entry for key `{key}`
Nearby keys:
{nearby}

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

refusing to load the FFI cache at `{path}`: it is not owned by the current user or is world-writable — its `_bindings.rs` compiles unsandboxed into your crate. Fix its ownership/permissions or remove it

## ffi-module-clash

module `{module}` clashes with the installed FFI crate `{krate}` — the `Rust.*` namespace is reserved for FFI interface modules

## ffi-define-opaque-collision

installed FFI crate `{krate}` defines a `[rust.define.*]` type `{name}` whose name also names an inspected opaque type of the crate — the two are different Rust types that would collide on one nominal; rename the define type

## ffi-dependency-line-unparsable

installed FFI crate `{krate}` emitted an unparsable dependency line: {line}

## ffi-dependency-pin-conflict

installed FFI crates pin dependency `{name}` to conflicting versions:
  ={first}
  ={second}
re-add one of the crates so the version pins agree

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

## ffi-install-manifest-write-failed

ipe install: manifest write failed: {detail}

## ffi-install-manifest-chunk-write-failed

ipe install: manifest chunk write failed: {detail}

## ffi-install-wrapper-crate

ipe install: wrapper crate `{path}`: {detail}

## ffi-install-project-root

ipe install: project root: {detail}

## ffi-install-wrapper-outside-root

ipe install: wrapper crate `{path}` resolves to {resolved} — outside the project root

## ffi-install-wrapper-not-utf8

ipe install: wrapper crate path `{path}` is not UTF-8

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

ipe build: the emitted `fn main` anchor is absent, so the capability floor cannot be retained past linker GC — refusing to write an unenforceable artifact

## run-profile-unparsable

{code}: {detail} — refusing to run (a profile that does not parse is not honored)

## run-floor-unreadable

{code}: the binary carries no readable capability floor — refusing to run an artifact whose floor cannot be verified

## build-entry-not-main

program entry module `{module}` is not yet buildable — a declared `programs` entry outside module `Main` type-checks (`ipe type-check`) but native emission still assumes a `Main` entry. Name the entry file `Main.ipe`, or track the multi-program emit follow-up

## pack-retired

ipe pack has been retired — app bundling is now the delivery grammar. Use `ipe build web desktop` / `ipe build web ios` / `ipe build web android` for a fast dev bundle, or `ipe release web desktop|ios|android` for a production distributable. For the OS-permission dry-run, use `ipe build --emit-permissions <ios|macos|android>`.

## build-binary-missing

ipe build: expected binary at {path} — cargo build succeeded but the binary is missing

## release-binary-missing

ipe release: expected binary at {path} — cargo build succeeded but binary is missing

## release-app-binary-missing

ipe release: expected app binary at {path} — cargo build succeeded but binary is missing

## release-workspace-root-unknown

ipe release: cannot locate workspace root (no Cargo.toml with [workspace] found in any parent directory)

## wasm-bindgen-failed

wasm-bindgen failed (exit {code}); ensure wasm-bindgen-cli {version} is installed: cargo install wasm-bindgen-cli --version {version}

## wasi-artifact-missing

the wasm32-wasip1 build reported no `.wasm` artifact for {dir} — cargo's JSON message stream carried no `compiler-artifact` naming the module

## session-no-recordable

ipe run {flag}: {name} has no recordable session — recording and replay capture the update loop of a `Cli.tea` or `Worker.tea` app

## session-native-only

ipe run {flag}: works on a native run only — drop `--target wasi`

## session-jailed

ipe run {flag}: a native-bearing program runs jailed, where the session log cannot be reached — record and replay a pure Ipê build of the app

## session-flags-exclusive

ipe run: {first} and {second} cannot be combined — record a session, then replay it

## replay-no-default-log

ipe run --replay: no session log at {typed} or trace at {trace} — record one with `ipe run --record`

## replay-log-missing

ipe run --replay: no session log at {path} — record one with `ipe run --record`

## program-exited

{program} exited with code {code}

## exec-no-artifact-dir

ipe exec: no artifact directory at {dir}

## exec-no-binary

ipe exec: no built binary at {path} — run `ipe build` first

## exec-profile-missing

ipe exec: {path} embeds a capability floor but carries no ipe.profile — the artifact is incomplete or tampered; refusing to run native code without its jail profile

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

## upgrade-installer-wait-failed

upgrade: the installer could not be waited on: {detail}

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

# Consent refusals

## consent-item

  = {item}

## web-consent-header

error[IPE-S0002]: this program reaches a browser web capability the app has not granted

## web-consent-disclosure

`{wire}` disclosed by {via}

## web-consent-disclosure-unattributed

`{wire}` disclosed by a module the build could not attribute

## web-consent-remedy

  = a web capability is granted ONLY by the top-level app's package.ipe; a dependency
    discloses but cannot self-authorise. Grant it after review by adding the axis to
    `accept = [ … ]` under [capabilities] in package.ipe, or drop the dependency.

## native-ffi-consent-header

error[IPE-S0003]: this program crosses into native `Rust.` code the app has not granted

## native-ffi-crossing

`Rust.{krate}` crossed by {via}

## native-ffi-crossing-unattributed

a native crossing the build could not attribute to a crate

## native-ffi-consent-remedy

  = a native crossing is granted ONLY by the top-level app's package.ipe; a dependency
    crosses but cannot self-authorise. Its true effects are opaque to Ipê and
    contained at run by the OS jail, but the crossing itself needs the consumer's
    consent. Grant it after review by adding `native-ffi` to `declared = [ … ]` under
    [capabilities] in package.ipe, or drop the dependency.

## control-model-consent-refusal

error[IPE-S0004]: `{entry_module}` runs the `{model}` control model, which the declared `acceptsControl` set does not cover
  = the package opted into control-model consent by declaring `acceptsControl`,
    so that set must cover the program's actual control model; it does not
    list `{model}`, so the declared acceptance is stale.
  = cover it after review by adding `{ctor}` to `acceptsControl = [ … ]`
    under [capabilities] in package.ipe, or switch the entry to a listed
    control model.

## permission-consent-header

error[IPE-P0001]: the packaged {platform} manifest declares OS permission(s) the app has not accepted

## permission-consent-remedy

  = an OS permission is DERIVED from the app's `accepts` set, never hand-added; a
    permission with no backing accepted web capability cannot ship. Grant the backing
    capability after review by adding the axis to `accepts = [ … ]` under
    [capabilities] in package.ipe, or remove the permission from the override.
