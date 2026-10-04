# Learning Ipê

A path from never having seen Ipê to finding the exact function you need. Start
at the top and follow the links; each page assumes only the ones before it.

## The path

1. [Getting started](getting-started.md) — install, create a project, write and
   run a first program.
2. [Pure functions and immutability](pure-functions.md) — why an Ipê value never
   changes, and how effects are handled without breaking that.
3. [Types and inference](types.md) — how the compiler knows every value's type,
   and how `Maybe` and `Result` make absence and failure explicit.
4. [The Elm Architecture](the-elm-architecture.md) — how a program that reacts
   to input over time is structured.

## Tooling

- [Linting](lint.md) — `ipe lint` (+ `--fix`): the idiom, consistency, and
  safety-by-convention checks over code that already type-checks, the
  Ipê-native `lint.ipe` config, and inline suppression.
- [Faster builds](faster-builds.md) — a fast linker (mold/lld), sccache, a
  shared build target, and dev-profile flags; what `ipe health` configures and
  how to apply each step manually.
- [Delivering an app](delivery.md) — shape vs delivery, then packaging a `Web`
  app into a desktop bundle (`ipe release build web desktop`) and a mobile
  system-webview shell (`ipe release build web solo ios|android`) through the one
  delivery grammar.
- [Publishing a package](publishing.md) — turn a library into a package other
  developers can `ipe add`: how the curated registry works, the one-time
  `ipe login` + signing-key setup, the `ipe package audit` Tier-1 gate, and
  `ipe package publish`.

## Standard-library guides

Each teaches the *mental model* of one module through a worked, runnable example,
then links to the per-symbol `ipe doc` reference. Read the one you need; they
cross-link where topics meet.

- **The prelude** — [Basics](basics.md) (the auto-imported helpers: `clamp`,
  `compare`, `min`/`max`), [Rendering values to String](tostring.md)
  (`String.fromInt`/`fromFloat`/`fromBool` and `{{expr}}` interpolation).
- **Core data** — [Lists](list.md) (ordered sequences, folds, pipelines),
  [Strings](string.md) (text and the parse boundary), [Characters](char.md)
  (code points, classification), [Tuples](tuple.md) (anonymous pairs),
  [Locales](locale.md) (opaque BCP-47 handle for locale-aware text operations).
- **Collections** — [Sets](set.md) (unique, unordered, membership),
  [Dictionaries](dict.md) (a value per key).
- **Absence, failure, and effects** — [Maybe](maybe.md) (a value that might be
  missing), [Result](result.md) (a failure that carries a reason), [Error](error.md)
  (the structured, classified failure type), [Tasks](task.md) (effects as values,
  sequenced and recovered).
- **Text and binary** — [Regular expressions](regex.md), [Text
  encodings](encoding.md) (base64/URL/hex), [Bytes](bytes.md) (raw octets),
  [Compression](compression.md) (gzip/zstd over bytes).
- **Serialization** — [Codec](codec.md) (one bidirectional codec for JSON and
  storage; the round-trip law by construction), [Database codecs](db-codec.md)
  (that one codec as a database row and back).
- **Files and configuration** — [Files](file.md) (typed paths, effects as tasks),
  [Paths](path.md) (opaque, traversal-safe filesystem paths),
  [Configuration](config.md) (typed TOML/YAML/JSON decoders), [CSV](csv.md).
- **Parsing structured text** — [Parser combinators](parser.md) (build a total
  `String -> Result` parser for a DSL or token stream, no regex).
- **Numbers and magnitudes** — [Math](math.md) (roots, trig, rounding, NaN),
  [Bitwise operations](bitwise.md) (an `Int` as a vector of bits),
  [Durations](duration.md) (unit-explicit time spans), [Byte sizes](bytesize.md)
  (unit-explicit byte quantities).
- **Exact quantities and money** — [Decimal](decimal.md) (arbitrary-precision
  decimal arithmetic), [Money](money.md) (currency-typed amounts, fair splits).
- **Randomness and identifiers** — [Randomness](random.md) (entropy vs seeded),
  [UUIDs](uuid.md) (random and time-ordered ids).
- **Addressing and routing** — [URLs](url.md) (typed, validated),
  [URL routing](url-parser.md) (typed route patterns), [Network
  primitives](net.md) (range-validated ports).
- **The process and the terminal** — [System](system.md) (arguments, environment,
  working directory, exit), [Standard I/O](io.md) (stdout/stderr/stdin, the
  password read), [Environment config](env.md) (build-time public config, wasm-safe),
  [Subprocesses](process.md) (running a child process with no shell).
- **Time and clocks** — [Time](time.md) (a typed instant, formatting, calendar
  arithmetic over durations), [Timestamp](timestamp.md) (the opaque instant type:
  shift by a span, measure the span between two).
- **Content and markup** — [HTML](html.md) (typed element trees, XSS-safe by
  construction), [HTML attributes](html-attributes.md) (fixed-key builders, boolean
  attributes as `Bool`), [Markdown](markdown.md) (a typed block tree, no raw HTML).
- **Instrumentation and delivery** — [Analytics](analytics.md) (consent-gated,
  PII-safe event tracking), [Email](email.md) (provider-abstract send with sealed
  credentials).
- **Web application surfaces** — [Page head](web-head.md) (typed `<head>` /
  SEO tags), [Console authentication](web-console.md) (gate the embedded console
  with the app's own auth), [Pub/sub](pubsub.md) (in-process typed broadcast),
  [Browser ports](js.md) (the typed Ipê↔JS seam).
- **Cryptography** — [Cryptography](crypto.md) (hashes, HMAC, AEAD, and the typed
  `Key` that makes key/message confusion a compile error).
- **Network and the web** — [HTTP client](http.md) (typed requests to a typed
  `Url`, SSRF-guarded), [WebSockets](websocket.md) (long-lived bidirectional
  frames on a typed `WsUrl`).
- **Building interfaces** — [Interface elements](ui.md) (the `Element` tree:
  layout, events, and accessibility roles), [Styling](css.md) (typed CSS values
  and rules).
- **Escape hatches** — the surfaces that bypass a safe default behind a disclosed
  `unsafe` capability: [the unsafe database surface](db-unsafe.md) (raw SQL,
  untyped column reads), [the unsafe Store surface](db-store-unsafe.md)
  (string-named columns for a dynamic table), [the unsafe HTML
  surface](html-unsafe.md) (raw markup / inline `<script>` past the escaper),
  [the unsafe page-head surface](web-head-unsafe.md) (a verbatim JSON-LD
  `<script>` block), [the secret-reveal hatch](secret-unsafe.md) (un-seal a
  `Secret` to a bare `String`). Reach for these only for a residual the safe
  surface cannot express.
- **Caching** — [Cache](cache.md) (bounded, in-memory LRU with optional TTL; a
  miss is a `Maybe`, not a failure).
- **Observability** — [Logging](log.md) (structured, levelled log records),
  [Log levels](level.md) (the `LogLevel` severity tag),
  [Tracing](trace.md) (application-level spans + the `Debug` development hatches).
- **Design tokens and layout** — [Palette](palette.md) (closed token sets and
  named magnitudes as types), [Grid tracks](grid.md) (typed CSS grid track lists,
  rendered to a `grid-template` string), [Transforms](transform.md) (typed CSS
  transforms, rendered to a `transform` declaration), [Transitions](transition.md)
  (typed transition steps, rendered to the CSS shorthand), [Animations](animation.md)
  (a typed animation `Spec`, rendered to the CSS shorthand),
  [Responsive breakpoints](responsive.md) (a viewport size classified into a typed
  `DeviceClass`).
- **Testing** — [Testing](test.md) (the in-process framework: tests as values,
  assertions as results, exit-coded runs).
- **Databases** — [Connection descriptors](dsn.md) (a typed, credential-safe
  `Dsn`; parse-don't-validate at the connection boundary), [Store](db-store.md)
  (a typed table derived from one codec; injection-safe, deny-by-default access),
  [Composing row-level security](db-store-rls-composition.md) (Owner / RBAC /
  Tenant / Sharing built by composition over the small policy core).

## Reference and lookup

- [Glossary](glossary.md) — every term of art, defined once.
- [**Module reference**](../reference/stdlib.md) — one page per `Ipe.*` module, each export
  with its signature, description, and a verified example; browsable with `ipe doc serve`.

## Looking something up from the terminal

```
ipe doc Ipe.List            # a module's exports
ipe doc Ipe.List.filterMap  # one function: signature, description, example
ipe doc IPE-T0014           # a diagnostic code
```

Add `--plain` for terse output or `--json` for the machine-readable record.
`ipe doc serve` opens the full documentation as a local site.
