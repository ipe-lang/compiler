# URL routing

`Ipe.Url.Parser` matches a parsed `Url` into typed route captures — turning
`/blog/42` into a `BlogPost 42` — through composable, pure-data patterns rather
than stringly key lookups over path segments.

## The mental model

Three knots.

- **A pattern matches an already-parsed `Url`, never a raw string.** The `Url`
  seal guarantees the address was validated; `parse` splits its path and query
  *once*, over the typed value, and never re-parses text. Routing therefore starts
  from a known-good URL — the parser cannot be handed a malformed one.
- **Patterns are pure data, and `parse` is total.** `s`, `int`, `string`,
  `slash` (`</>`), and `withQuery` build a `Pattern` out of plain data — no hidden
  functions inside. `parse : Pattern -> Url -> Maybe Captures` yields `Just` its
  *ordered* captures on a full match and `Nothing` otherwise — never a partial or
  ambiguous match, so match-or-not is a clean binary.
- **You apply the route constructors yourself, in ordinary code.** The pattern
  carries data; a `case` chain over the `parse` results reads the captures with
  `firstInt`/`firstString`/`firstQuery` and calls your route constructor. This is
  a [sanctioned divergence][principles] from `elm/url` (which threads a builder
  *through* the parser): here a constructor is only ever *called*, never stored, so
  it lowers cleanly on the Rust backend.

## A worked example: a request router

The example under
[`examples/shapes/script/url-router`](../../examples/shapes/script/url-router/src/Main.ipe)
matches request paths into a typed `Page` union — home, a blog post by id, a user
profile by name, and a search with an optional query.

Each route is one `parse` against a pure-data pattern; the first to match wins,
and its captures build the `Page`. `slash` sequences path segments; `int` and
`string` capture; `withQuery` attaches a query key:

```ipe
page url =
    case Parser.parse (Parser.slash (Parser.s "blog") Parser.int) url of

        Just caps ->
            BlogPost (Maybe.withDefault 0 (Parser.firstInt caps))

        Nothing ->
            pageUser url
```

The search route captures a query value, read back with `firstQuery`:

```ipe
pageSearch url =
    case Parser.parse (Parser.withQuery (Parser.s "search") (Parser.query "q")) url of

        Just caps ->
            Search (Parser.firstQuery caps)

        Nothing ->
            pageHome url
```

Dispatch parses the raw path into a validated `Url` first — routing never sees a
raw string — then matches it:

```ipe
dispatch rawPath =
    case Url.fromString ("https://app.example.com" ++ rawPath) of

        Ok url ->
            rawPath ++ "  ->  " ++ render (page url)

        Err _ ->
            rawPath ++ "  ->  (invalid url)"
```

Running it (`ipe dev run`) matches each path to its typed page, with the unmatched one
falling through to `NotFound`:

```
Routing:
  /  ->  Home
  /blog/42  ->  BlogPost 42
  /user/alice  ->  UserProfile alice
  /search?q=shoes  ->  Search shoes
  /nope/here  ->  NotFound
```

## The why

Matching over a *typed* `Url` rather than a raw path is [parse, don't
validate][principles] carried one layer up: the URL is validated once (by the
`Url` seal), split once (by `parse`), and every route arm works from typed
captures — no arm re-splits the path or re-decodes the query.

`parse` being total — `Just` ordered captures or `Nothing`, never a partial match
— is [make invalid states unrepresentable][principles]: there is no "matched three
of four segments" limbo a caller must reason about. And keeping a `Pattern` pure
data, with constructors applied in a `case` chain, is [soundness][principles]: the
divergence from Elm's function-carrying parser exists precisely so the router
lowers without storing a function value where the backend cannot yet box one.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Url.Parser` — `s`, `int`, `string`,
  `slash`, `withQuery`, `parse`, and the capture readers, with a full routing
  example and the sanctioned-divergence note.
- **Sibling guides:** [URLs](url.md) — the opaque, validated `Url` a pattern
  consumes; routing begins where URL parsing ends. [Maybe](maybe.md) — what `parse`
  and the capture readers return. [The Elm Architecture](the-elm-architecture.md)
  — where a router sits in a full app's `update`.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md).
  [Types and inference](types.md) — how the typed `Page` captures are tracked.
