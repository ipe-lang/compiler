# Web page head

`Ipe.Web.Head` gives typed helpers for the `<head>` of a web page — the title,
SEO meta tags, Open Graph properties, the canonical link, the theme colour, an
RSS discovery link. A web app supplies them through the optional
`head : Model -> List (Html msg)` field on its `Web.tea` config; the runtime calls
it once per full page load and splices the rendered tags into `<head>`, after the
required charset/viewport tags and before the style reset.

## The mental model

Three knots.

- **Head content is a function of the model, rendered per page.** The `head`
  callback runs on each full GET (initial load or in-app navigation), so the
  title and meta tags can differ per page without any imperative DOM poking. Live
  patches scope to `<body>`, so a head change takes effect on the next full load —
  which in-app navigation already performs.
- **Every helper returns `Html msg`, so it composes with the rest of the tree.**
  `title`, `meta`, `metaProperty`, `link`, `themeColor`, `canonical`, and `rss`
  all produce ordinary `Html msg`, so the list lines up with the `Ipe.Html`
  ecosystem. For a shape not covered here (a preload hint, a custom `<link>`), drop
  to `Html.node "link" [...]` in the same list. Head elements never carry event
  handlers — the driver never binds them.
- **URL-bearing tags require a validated `Url`, not a bare string.**
  `canonical` and `rss` take an `Ipe.Url.Url`, so the href is guaranteed absolute
  and scheme-valid. A bare `String` could silently emit a relative or
  `javascript:` href in a tag search engines and readers trust; requiring a `Url`
  closes that at the type boundary.

## A worked example: per-page SEO tags

The example under
[`examples/shapes/web/head-seo`](../../examples/shapes/web/head-seo/src/Main.ipe)
is a minimal `Web.tea` that supplies a `head` callback with title, description,
Open Graph, theme-colour, and a canonical link.

The canonical URL is emitted only when it parses — `Url.fromString` is the one
constructor and the boundary where an unparseable URL is turned away rather than
carried into a trusted tag:

```ipe
head : Model -> List (Html Msg)
head model =
    let
        base =
            [ Head.title model.pageTitle
            , Head.meta "description" "A minimal Ipe.Web page with typed head tags."
            , Head.metaProperty "og:title" model.pageTitle
            , Head.themeColor "#1a1a2e"
            ]
    in
    case Url.fromString "https://example.com/" of
        Ok url ->
            base ++ [ Head.canonical url ]

        Err _ ->
            base
```

The callback is wired through the optional `head` field on `Web.tea`:

```ipe
main =
    Web.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions
        , routes = [], notFound = Ignored
        , head = head
        }
```

Building it (`ipe dev build`) compiles the app; serving it renders the tags into
`<head>` on each page load.

## The why

Requiring a validated `Url` on `canonical` / `rss` is [security][principles]: a
canonical or feed href is a URL other systems act on, so admitting only a
parsed, absolute `Url` — never a bare string — keeps a `javascript:` or relative
href out of a trusted tag. Titles and attribute values being HTML-escaped by the
runtime is the same [XSS-safe-by-construction][html] discipline the [HTML](html.md)
guide describes, carried into the head. And head content being a pure function of
the model is [the Elm Architecture](the-elm-architecture.md): what the page
declares in its head is derived from state, not mutated in place.

[principles]: ../../PRINCIPLES.md
[html]: html.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Web.Head` — `title`, `meta`,
  `metaProperty`, `link`, `canonical`, `themeColor`, `rss`. The verbatim JSON-LD
  `<script>` hatch lives in `Ipe.Web.Head.Unsafe` (`unsafeJsonLd`), which discloses
  the `unsafe` capability.
- **Sibling guides:** [HTML](html.md) — the typed `Html msg` tree every helper
  returns, and the escaping that makes it XSS-safe. [URLs](url.md) — the validated
  `Url` `canonical` / `rss` require. [The Elm Architecture](the-elm-architecture.md)
  — how `head` fits the model/update/view loop.
