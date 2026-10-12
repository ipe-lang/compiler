# Markdown

`Ipe.Markdown` renders a chat-grade markdown subset — headers, paragraphs, lists,
code, tables, blockquotes, and inline emphasis — either straight to an
[`Ipe.Ui`](html.md) element tree for display, or to a typed *block tree* you can
walk yourself. The parser never emits raw HTML, so untrusted markdown is safe to
render with no extra sanitisation pass.

## The mental model

Three knots.

- **`parseBlocks` returns a typed tree, not text.** `Markdown.parseBlocks source :
  List Block` gives back distinct variants — `HeaderBlock`, `ParaBlock`,
  `BulletBlock`, `CodeBlock`, `TableBlock`, and so on — so a consumer matches on
  *structure* rather than re-scanning the raw string. The parse happens once; every
  reader works from the tree.
- **`render` produces a `Ui` element tree, styled by the surrounding theme.**
  `Markdown.render source` is the display path: it emits typed `Ipe.Ui` elements
  (no HTML-string round-trip), so headings, code surfaces, and blockquote rules
  inherit the page's own colours. For a script or a custom renderer, the public
  `parseBlocks` / `parseSpans` hand you the tree to walk directly.
- **No raw HTML — safe by construction.** The parser routes every output through
  typed constructors, never a raw-HTML pass-through, and link/image URLs are
  sanitised at the sink (a `javascript:` URL is neutralised there). You can feed it
  untrusted markdown — an agent response, a PR body — without a separate sanitiser.

## A worked example: walking the block tree

The example under
[`examples/shapes/script/markdown-parse`](../../examples/shapes/script/markdown-parse/src/Main.ipe)
parses a small release note and summarises each block by its variant — matching on
the typed tree, not the text.

Each block is a distinct constructor, so `describe` is an exhaustive `case` — the
compiler requires every variant be handled, so a new block type can't slip through
a wildcard:

```ipe
describe : Block -> String
describe block =
    case block of
        HeaderBlock level title ->
            "header " ++ headingText level ++ ": " ++ title

        ParaBlock body ->
            "paragraph (" ++ String.fromInt (String.length body) ++ " chars)"

        BulletBlock items ->
            "bullet list of " ++ String.fromInt (List.length items)

        -- … one arm per remaining variant …
```

Parsing the note and describing each block (`ipe dev run`):

```
Parsed markdown blocks:
  header H1: Release notes
  paragraph (37 chars)
  bullet list of 2
```

## The why

Returning a typed block tree rather than a rendered string is [parse, don't
validate][principles]: the raw markdown meets a type once, at `parseBlocks`, and
every downstream reader works from `Block` values — no code re-parses the text or
guesses at its structure. The exhaustive `case` the tree forces is [make invalid
states unrepresentable][principles]: a wildcard that silently swallowed a new
block variant is rejected by the compiler, so adding a variant forces every
consumer to consider it.

Never emitting raw HTML is [security][principles]'s fail-closed rule for rendered
content: because the parser has no raw-HTML path and sanitises URLs at the sink,
untrusted markdown cannot inject a script or a dangerous URL — the safe outcome is
the only one the renderer can produce, with no sanitiser for a caller to forget.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Markdown` — `render` / `renderInline` for
  display, `parseBlocks` / `parseSpans` for the typed trees, and the `Block` /
  `Span` variants.
- **Sibling guides:** [HTML](html.md) — the typed-tree, no-raw-HTML rendering model
  `Markdown.render` shares. [Lists](list.md) — the block tree is a `List Block` you
  fold and map. [Strings](string.md) — the markdown source and rendered text.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — `parseBlocks` is the boundary where markdown text becomes a typed tree. [Types
  and inference](types.md) — how the `Block` / `Span` variants are tracked.
