# Ipe.Ui text roles, section headings, typed white-space and the Ui.Unsafe home

Designed by: security-soundness-guardian
Base: origin/main 76e359f5e8ed17c43655d2e250c7de4a4dbc3d75

## Scope and consent

`Ipe.Ui` is self-sufficient and elm-ui-like. The maintainer has consented to
exactly these surface changes:

1. Add `Ui.codeBlock`, inline `Ui.code`, inline `Ui.kbd`, and a typed
   `Font.whiteSpace` over a closed union (never a `String`).
2. Move `Ui.taggedNode` and `Ui.input` to a new `Ipe.Ui.Unsafe` module.
3. Derive heading levels from `Ui.section` nesting depth, clamped to 6.

Nothing else joins the public surface. The project is pre-public, so the old
locations (`Ui.taggedNode`, `Ui.input`) and the integer heading constructors
(`Ui.descHeading`, `Region.heading`) are removed outright, with no shim.

The third decision names `Ui.section`, but `Ui.section` does not exist on
origin/main and is not in the addition list. Its exact shape is the first item
under DECISIONS NEEDED. The lane that wires headings waits for that answer.

Public signatures after this spec (section shape as recommended below):

```elm
-- Ipe.Ui
codeBlock : List (Attribute msg) -> List (Element msg) -> Element msg
code      : List (Attribute msg) -> List (Element msg) -> Element msg
kbd       : List (Attribute msg) -> List (Element msg) -> Element msg
section   : List (Attribute msg) -> { heading : List (Element msg), content : List (Element msg) } -> Element msg

-- Ipe.Ui.Font
type WhiteSpace = Normal | NoWrap | Pre | PreWrap | PreLine | BreakSpaces
whiteSpace : WhiteSpace -> Attribute msg

-- Ipe.Ui.Unsafe (importing it discloses `unsafe`)
taggedNode : String -> Description -> List (Attribute msg) -> List (Element msg) -> Element msg
input      : List (Attribute msg) -> Element msg
```

## Class-closing properties

Each change closes a class, not one site.

- **The Ui.Unsafe move.** No value built from the safe surface (`Ipe.Ui`,
  `Ipe.Ui.Font`, `Ipe.Markdown`, every other non-`Unsafe` stdlib module) is an
  `Element::TaggedNode`. Every safe-surface node gets its tag from a closed
  `NodeTag` enum chosen by its `Description`. A free-form tag string is reachable
  only through a module whose import discloses `unsafe`. Today `paragraph`,
  `textColumn`, `form` and `input` are built on `taggedNode`; after this spec,
  the only `Kernel.kernel "Ui_taggedNode"` binding in the tree is in
  `Ipe/Ui/Unsafe.ipe`.
- **Headings.** An out-of-range heading level has no representation. The level is
  a closed `HeadingLevel` (`H1`..`H6`) computed by the renderer from the number
  of enclosing section nodes, saturating at `H6`. No `Int` level exists anywhere:
  not in Ipê, not in the runtime `Description`, not in the compile-time template
  mirror. A heading exists only as the first child of a section, because the
  heading description has no public constructor.
- **Text roles.** `pre`, `code` and `kbd` are `NodeTag` variants whose text is
  always an escaped `HText` child. None of them is a raw-text element. A code
  block always renders as `<pre><code>…</code></pre>`, so the parser's
  leading-newline strip after `<pre>` never touches author text.
- **Typed white-space.** White-space mode is a closed runtime enum carried by
  `Attribute::AttrFontWhiteSpace(WhiteSpace)`. The CSS text comes from a
  `const` table, so no string reaches the style sink. The TUI reads the same
  value through two total predicates, `wraps()` and `preserves_newlines()`.
- **Parse-stable markup.** This is pre-existing and fixed here because the new
  block roles widen it. Every element the safe surface renders under a
  phrasing ancestor renders with a phrasing tag. The renderer threads a closed
  `ContentModel` (`Flow`, `Phrasing`) top-down. A flow-only `NodeTag` under
  `Phrasing` is demoted to `span`, keeping its CSS and losing its semantics. So
  the DOM the browser builds equals the tree the server rendered, and the
  client's id-keyed diff stays aligned with the DOM.

  Today `render_paragraph_child` adapts only direct children. A
  grandchild `Ui.column` inside `Ui.paragraph` renders
  `<p><span><div>`, and the `div` start tag closes the open `<p>`: the parser
  hoists the block out of the paragraph.

## Design

### Ipe.Ui.Unsafe

- New compiled-source module `src/stdlib/Ipe/Ui/Unsafe.ipe`, registered in
  `COMPILED_STD_MODULES` (`src/stdlib/src/lib.rs`), with these members:
  - `taggedNode = Kernel.kernel "Ui_taggedNode"`;
  - a private `descNone = Kernel.kernel "Ui_descNone"`;
  - `input attrs = taggedNode "input" descNone attrs []`.

  The module doc states that importing it discloses `unsafe`, in the same words
  as `Ipe/Html/Unsafe.ipe`.
- `Ipe.Ui` drops `taggedNode` and `input` from its exposing list and drops its
  `taggedNode` binding entirely. `paragraph`, `textColumn` and `form` become
  `node <private desc> …`, over new private nullary description kernels:

  | Builder      | Private description kernel | Description variant |
  |--------------|----------------------------|---------------------|
  | `paragraph`  | `descParagraph` (exists)   | `DescParagraph`     |
  | `textColumn` | `descTextColumn`           | `DescTextColumn`    |
  | `form`       | `descForm`                 | `DescForm`          |

- `Ipe.Ui` must never import `Ipe.Ui.Unsafe`. Capability disclosure is an
  OR-fold over every linked module (`imports_an_unsafe_submodule`, canon
  `resolve.rs`; folded in lower `link.rs`), so one such import would disclose
  `unsafe` for every Ui app. A stdlib source test pins this rule for all
  modules, not only `Ui`.
- Kernels `source_display_name`: add `UiTaggedNode => "Ui.Unsafe.taggedNode"`,
  beside `HtmlScriptNode => "Html.Unsafe.unsafeScript"`.
- The three admission boundaries for `TaggedNode` stay unchanged: construction
  in `ui_tagged_node_`, template materialisation (`template.rs` calls
  `ui_tagged_node_`), and the sink (`admit_rendered`, `render.rs`). That is
  defence in depth for the one free-form tag path.
- Callers that move to `import Ipe.Ui.Unsafe as UiUnsafe`:
  - `src/ipe-cli/tests/live_e2e.rs`: the raw form-post fixtures;
  - `tests/golden/stdui_input/Main.ipe`.

  The `Ui.input` idiom in `src/ipe-cli/templates/AGENTS.md.in` points
  text, password and checkbox inputs at the typed `Ipe.Ui.Input` controls. It
  names `Ui.Unsafe.input` only for types `Ipe.Ui.Input` lacks, such as `file`;
  see DECISIONS NEEDED.

### Runtime roles (`Description`, `NodeTag`, `HeadingLevel`, `ContentModel`)

- `src/runtime/rust/src/ui/element.rs` `Description`:
  - **Remove:** `DescHeading(i64)`.
  - **Add:** `DescSection`, `DescSectionHeading`, `DescCodeBlock`, `DescCode`,
    `DescKbd`, `DescTextColumn`, `DescForm`.
- `render.rs` `NodeTag`: a closed enum over every tag a `Description` or a
  landmark retag can produce:

  ```
  div, main, nav, footer, aside, p, label, button, section,
  h1-h6, pre, code, kbd, span, form
  ```

  - It has `ALL`, `as_str()` and `category() -> ContentModel`, declared once.
  - `tag_for_description` returns `NodeTag`, and its match has no wildcard.
  - `landmark_tag_for` returns `Option<NodeTag>` and lists every
    `Description` variant explicitly. The `_ => None` row is removed.
- `HeadingLevel` (`H1`..`H6`):
  - `fn deeper(self) -> Self` saturates at `H6`.
  - `fn tag(self) -> NodeTag`.
  - The render context carries `section: Option<HeadingLevel>`. Entering a
    `DescSection` node sets `Some(prev.map_or(H1, deeper))`.
  - `DescSectionHeading` renders `<hN>` from the current level, or `H1` when
    there is none. Ipê cannot build that case, but it is total.
  - Elements are built bottom-up and rendered top-down, so the level is only
    knowable in the renderer. `render_element_depth_in` and `render_node_as`
    take one `RenderCtx { depth, parent_axis, section, model }` by value, in
    place of today's `(depth, parent_axis)`. Every recursive call site
    (`render.rs` around 500, 1322, 1388, 1970) passes it.
- `ContentModel`:
  - Root and section content are `Flow`. Paragraph content, heading content,
    and `code`/`kbd` content are `Phrasing`.
  - A `Node` whose `NodeTag::category()` is `Flow` renders under `Phrasing` as
    `span` with `display:inline-block`, or with the inline-flex rewrite that
    `render_paragraph_child` applies today.
  - The descendants of a demoted node stay `Phrasing`.
  - A demoted section does not advance the heading level, and a demoted
    heading renders as `span`.
  - `render_paragraph_child` folds into this one rule, so there is no second
    copy.
  - `Element::TaggedNode` (Ui.Unsafe only) renders as written. Its content
    model is the caller's contract and is documented in `Ui/Unsafe.ipe`.
- `DescCodeBlock` renders `<pre style=…><code>children</code></pre>`:
  - The style and HTML attributes go on `pre`. The inner `code` carries none.
  - The default white-space is `pre` (UA default). An explicit
    `Font.whiteSpace` overrides it via the style string.
- `WhiteSpace` (runtime, `element.rs`):
  - Variants `Normal`, `NoWrap`, `Pre`, `PreWrap`, `PreLine`, `BreakSpaces`,
    declared once with `ALL`.
  - `css() -> &'static str` returns `normal`, `nowrap`, `pre`, `pre-wrap`,
    `pre-line` or `break-spaces`.
  - `const fn wraps()`: true for `Normal`, `PreWrap`, `PreLine` and
    `BreakSpaces`.
  - `const fn preserves_newlines()`: true for `Pre`, `PreWrap`, `PreLine` and
    `BreakSpaces`.
  - A `const` assertion checks that the texts are distinct.
- `Attribute::AttrFontWhiteSpace(WhiteSpace)` is emitted by the style builder
  as `white-space:<css()>`, with no sanitiser in between because the text is a
  closed literal.
- The paragraph and text-column identity moves from the `__paragraph` and
  `__textcolumn` style markers to `DescParagraph` and `DescTextColumn`, in both
  places that read it:
  - `render.rs`: `has_paragraph_marker` and the marker arm around line 116;
  - `tui/layout.rs`: `walk_attrs`, lines 698-699.

  `ui_paragraph_` in `helpers.rs` stops pushing the marker. A user
  `Ui.style "__paragraph" "true"` then no longer changes layout. The other
  layout markers are the subject of CONSIDERATION.
- New helpers in `ui/helpers.rs`:
  - one nullary `ui_desc_<role>_` per new description;
  - one nullary `ui_font_white_space_<mode>_` per `WhiteSpace` variant.

  `ui_desc_heading_` and `ui_region_heading_` are deleted.
- TUI (`tui/layout.rs`):
  - `DescSectionHeading` sets bold, as `DescHeading` does today.
  - `DescCodeBlock` lays out as a block.
  - `DescCode` and `DescKbd` lay out as inline text runs. The terminal is
    already monospace, so they add no decoration.
  - `AttrFontWhiteSpace` sets `wraps` and `preserves_newlines` on the walk.
    The paragraph wrap at line 190 consults `wraps`, and `extract_text`
    keeps `\n` when `preserves_newlines` holds.
  - The TUI does not model CSS space collapsing. That divergence is stated in
    the `Font.whiteSpace` doc.
- Compile-time template mirror (`ui/template.rs`):
  - `UiDescription` gains the new variants and loses `DescHeading(i64)`, with
    both `From` directions exhaustive.
  - The test at line 1764 that decodes backend JSON migrates off `DescHeading`
    and covers every variant.

### Ipe.Ui surface (`src/stdlib/Ipe/Ui.ipe`)

```elm
codeBlock attrs children = node descCodeBlock attrs children
code attrs children = node descCode attrs children
kbd attrs children = node descKbd attrs children
section attrs r = node descSection attrs (node descSectionHeading [] r.heading :: r.content)
```

- Every `desc*` above is a private, unexposed `Kernel.kernel "Ui_desc…"`
  alias.
- **Removed from the exposing list:** `descHeading`, `taggedNode`, `input`.
- The comment near line 751 that says `Ui.input` pairs with `descLabel` is
  rewritten to name `Ipe.Ui.Input`.
- `Ipe.Ui.Region` loses `heading`: canon `env.rs` around line 1408, plus the
  kernel.

### Ipe.Ui.Font becomes compiled source

Today `Font` is a native qualifier with no `.ipe` file, and a native qualifier
cannot carry a source union. Following the precedent of `Ipe.Ui` itself:

- **Canon.** Remove `(&["Ipe","Ui","Font"], "Font")` (`env.rs` line 100) and
  the `"Font"` member list (around 1365) from the native tables. The
  disjointness invariant forbids keeping both.
- **New file `src/stdlib/Ipe/Ui/Font.ipe`.**
  - Each of the 29 existing members becomes `x = Kernel.kernel "Font_x"`,
    resolving to its unchanged `KernelFn`. Their emitted calls do not change.
  - Add `type WhiteSpace = Normal | NoWrap | Pre | PreWrap | PreLine | BreakSpaces`,
    exposed as `WhiteSpace(..)`.
  - Add six private nullary aliases, `Font_whiteSpaceNormal` …
    `Font_whiteSpaceBreakSpaces`, and
    `whiteSpace ws = case ws of …`: one exhaustive arm per constructor, no
    wildcard.
- **Stdlib registration.** Register `Ipe.Ui.Font` in `COMPILED_STD_MODULES`.
- **Rejected alternative: a `BUILTIN_UNIONS` entry.** That would be a
  `BUILTIN_UNIONS` entry homed at `Font` (`canon/src/builtins.rs`, as
  `HttpMethod` is homed at `Http`), plus a `BUILTIN_TYPES` row. It also needs:
  - a lowering arm and an emit path;
  - a show-policy row and a runtime enum mirror.

  That is at least eight mirrored sites for a value only one kernel family
  consumes. The compiled-source union has no mirror outside the six nullary
  kernels, and a test pins their set.

### Ipe.Markdown

- `CodeBlock body` renders as follows. The `htmlAttribute "style"
  "…white-space:pre"` string is gone.

  ```elm
  Ui.codeBlock [ Ui.width Ui.fill, Ui.paddingXY 12 10, Ui.scrollbarX, Font.family …, Font.size 13, surface ] [ Ui.text body ]
  ```

  The surface colour stays the existing `codeSurfaceStyle` attribute minus the
  `overflow` and `white-space` parts.
- `CodeSpan text` renders as `Ui.code [ … ] [ Ui.text text ]`.
- Headings become sections. One pass over the flat block list keeps a stack of
  open sections, each tagged with its `HeadingLevel` from Markdown:
  - A header of level L closes every open section of level ≥ L, then opens a
    new one.
  - Blocks append to the innermost open section.

  The stack is at most 6 deep (Markdown levels 1..6). The pass builds each
  list by cons and reverses it once, so it is not quadratic.
  `renderHeader` becomes the heading content (styled spans), not a
  styled `Ui.el`. A document whose first heading is `###` renders it as `h1`,
  as the depth rule implies. The `Ipe.Markdown` doc says so.

## Safe-surface admission rule

- **Tags.** A safe-surface element's tag is a `NodeTag`. A test drives every
  `NodeTag::ALL` member through the production sink and checks
  `admit_element(tag, body) == Markup`:

  ```
  ui_layout -> render -> admit_rendered
  ```

  No `NodeTag` is `script`, `style`, `plaintext`, `textarea`, `title`,
  `iframe`, `noscript`, `xmp`, `template` or `svg`.
- **Free-form tags.** These come only from `Ipe.Ui.Unsafe.taggedNode`, through
  the existing three-boundary `admit_element` gate.
- **Attributes.** No new HTML attribute is emitted. Keys still pass
  `SafeAttrName::parse` (a safe name, not `on*`, not `srcdoc`), and URL values
  pass `sanitise_url_attr`. `AttrFontWhiteSpace` reaches only the `style`
  attribute, with closed text.
- **Escaping.** `pre`, `code` and `kbd` are ordinary elements. Their content is
  `HText` through `escape::html_text_into`, so `</code>`, `</pre>`, `<script>`
  and `&` in author text are inert. The `<pre><code>` structure keeps a leading
  `\n` in author text.
- **CSP.** The roles add no `<style>` element, no `<script>`, no inline handler
  and no `javascript:` URL. Their CSS rides the `style` attribute, which the
  existing profile allows only through `style-src-attr 'unsafe-inline'`
  (`csp.rs`). The CSP header is unchanged.
- **DOM clobbering.** The roles emit no `id` and no `name`.
  - Hard rule: never derive an `id` or anchor from heading or code text. Page
    content must not choose a document-level name.
  - Client lookups stay structural: `__ipeDocProp`, the `currentScript`
    sibling boot block, and the `typeof` check on `ipeOnReceive`.
  - `#ipe-root` is found by `getElementById`, and app content is its
    descendant, so the root is first in tree order. Content placed before
    `#ipe-root` (the page head) is outside this spec.
- **Parse stability.** This is the `ContentModel` rule above. The oracle is a
  browser-e2e check that the server HTML and the parsed DOM serialisation are
  equal.

## Files touched

- **Stdlib .ipe:**
  - new `src/stdlib/Ipe/Ui/Unsafe.ipe`;
  - new `src/stdlib/Ipe/Ui/Font.ipe`;
  - `src/stdlib/Ipe/Ui.ipe`;
  - `src/stdlib/Ipe/Markdown.ipe`.
- **Stdlib registry:** `src/stdlib/src/lib.rs`. Two `include_str!` entries,
  `COMPILED_STD_MODULES` entries (around 1866 and 1901), and the module-list
  doc near 265.
- **Canon:**
  - `src/compiler/canon/src/env.rs`: Font native entries removed, Region
    `heading` removed;
  - `src/compiler/canon/src/lib.rs`: the new N0025 tests.
- **Kernels registry:** `src/compiler/kernels/src/lib.rs`.
  - Add: the 7 `UiDesc*` kernels (`descSection`, `descSectionHeading`,
    `descCodeBlock`, `descCode`, `descKbd`, `descTextColumn`, `descForm`) and
    6 `FontWhiteSpace*` kernels, each at every mirrored site the `KernelDef`
    tripwire names (variant, `d(..)` descriptor, scheme, arity, runtime path).
  - Remove: `UiDescHeading` and `RegionHeading`.
  - Add the `source_display_name` arm for `UiTaggedNode`.
- **Types:** `src/compiler/types/src/constrain/tests/mod.rs` (kernel lists near
  791, 973, 987).
- **Lower:**
  - `src/compiler/lower/src/lower.rs`: `("Ui","descHeading")` near 28917 and
    `RegionHeading` near 26639 and 28897 removed; the new desc kernels added
    wherever the desc family is listed;
  - `src/compiler/lower/src/capabilities.rs`: tests.
- **Backend:**
  - `emit_ui_plan.rs`: classification list near 1305, plan rows near 1942;
  - `emit_ui_template.rs`: `CompileUiDesc` arms near 1682, gaining the new
    descs and losing `DescHeading`;
  - `emit_expr/kernel_calls.rs` (near 2735): comment and spelling only.
- **Runtime emit/render:**
  - `src/runtime/rust/src/ui/element.rs`, `ui/render.rs`, `ui/helpers.rs`,
    `ui/template.rs`;
  - `src/runtime/rust/src/tui/layout.rs`;
  - `src/runtime/rust/src/html.rs`: tests only.
- **Goldens.** Regenerate with `cargo run -p regen-goldens`; never hand-edit.
  - `tests/golden/stdui_input/Main.ipe`: `Ui.Unsafe.input`, plus one each of
    `codeBlock`, `code` and `kbd`, and `Font.whiteSpace` over every
    constructor;
  - `tests/golden/region_seal/Main.ipe`: nested `Ui.section`, replacing
    `Region.heading`;
  - the emitted `ipe_mod_ipe_*` seal goldens, which gain `Ipe.Ui.Font`;
  - the drivers `src/ipe-cli/tests/g_stdui/golden_stdui_input.rs` and
    `src/ipe-cli/tests/g_misc/golden_region_seal.rs`.
- **Docs regen.** Run `gen-stdlib-docs` and `git add` the new files:
  - `docs/reference/stdlib/Ui.md` and `docs/reference/stdlib.md`;
  - new `docs/reference/stdlib/Ui.Unsafe.md` and
    `docs/reference/stdlib/Ui.Font.md`.
- **Hand-written docs:**
  - `docs/guide/accessibility.md` (line 47);
  - `docs/guide/ui.md` (line 84);
  - `src/ipe-cli/templates/AGENTS.md.in`: the input idiom (813), the upload
    pattern (965), and a short text-roles note.
- **Examples:** `examples/shapes/web/ui-layout/src/Main.ipe` (line 70,
  `Ui.describe (Ui.descHeading 1)`), which becomes a `Ui.section`.
- **Other ipe-cli tests:**
  - `src/ipe-cli/tests/live_e2e.rs`: the `Ui.input` fixtures;
  - `src/ipe-cli/tests/watch_hot_appearance.rs`: the 1437 comment.
- **Browser e2e:**
  - new `tools/scripts/browser-e2e/ui-text-roles.spec.mjs`;
  - `tools/scripts/browser-e2e/run.sh`, which serves `ui-layout` on a third
    port;
  - the `browser-e2e` job in `.github/workflows/ci.yml`, which gains a compile,
    spawn and wait step for `ui-layout`. The status context is unchanged, so
    `check-manifest.yml` is unchanged.
- **tools/code-review.** No change. `Lib/View.ipe` uses only `Ui.html` and
  `Font.*`, and `Font.*` keeps every member name.

## Refusal tests (each names the CI job that compiles and runs it)

Every refusal test asserts the exact variant or code and is paired with a
control that runs the same input with the guarded difference removed and gets
`Ok`.

| Refusal | Where | CI job |
|---|---|---|
| `Ui.taggedNode` and `Ui.input` under `import Ipe.Ui as Ui` are `NameNotExposed` (IPE-N0022). Control: `UiUnsafe.taggedNode` resolves. | canon tests | `test` |
| `Ui.descHeading` and `Region.heading` no longer resolve, asserted by exact variant. Control: `Ui.section` resolves. | canon tests | `test` |
| `Font.whiteSpace "pre"` (a String) is a type mismatch. Control: `Font.whiteSpace Font.Pre` type-checks. | types tests | `test` |
| A user module named `Ipe.Ui.Unsafe`, and one named `Ipe.Ui.Font`, are `ReservedNamespace` (IPE-N0025). Control: the same source under `EmbeddedStdlib` canonicalises. | canon `lib.rs` | `test` |
| User source `Kernel.kernel "Font_whiteSpacePre"` is `KernelAliasInUserSource` (IPE-N0042). | canon tests | `test` |
| `import Ipe.Ui.Unsafe` discloses `unsafe`. Control: a program importing `Ipe.Ui`, `Ipe.Ui.Font` and `Ipe.Markdown` only does not. | `lower/src/capabilities.rs` | `test` |
| No non-`Unsafe` embedded stdlib module imports an `Ipe.*.Unsafe` module, and `Kernel.kernel "Ui_taggedNode"` appears only in `Ipe/Ui/Unsafe.ipe`. The source scan iterates `COMPILED_STD_MODULES`; a planted import in a copy of the `Ui` source turns it red. | `stdlib/src/lib.rs` tests | `test` |
| Every `NodeTag::ALL` member is admitted as `Markup` through `ui_layout` → `admit_rendered`. A denied tag through `UiUnsafe.taggedNode` still renders empty. | runtime `ui/render.rs` tests | `test` |
| Hostile text in `codeBlock`, `code` and `kbd` (`</code></pre><script>x</script>&`) renders escaped, contains no `<script`, and passes `admit_rendered`. | runtime tests | `test` |
| `codeBlock [] [text "\nx"]` renders `<pre…><code>\nx</code></pre>`, so the newline is not directly after `<pre>`. The browser reads `\nx` as the `code` `textContent`. | runtime tests; `ui-text-roles.spec.mjs` | `test`; `browser-e2e` |
| Nested sections at depths 1 to 8 give `h1`..`h6`, then `h6`, `h6` (at the ceiling and one past it). A bare `DescSectionHeading` gives `h1`. | runtime tests | `test` |
| A section in a paragraph, a code block in a paragraph, a paragraph in a heading, and a `column` grandchild in a paragraph each render with no flow tag below a phrasing ancestor (a walker over the rendered `Html`, using `NodeTag::category`). Control: the same subtree under `Flow` keeps its tags. | runtime tests | `test` |
| The same four shapes, served: the server HTML of `#ipe-root` equals `root.innerHTML` after the browser parses it. | `ui-text-roles.spec.mjs` | `browser-e2e` |
| The `WhiteSpace` CSS texts are distinct and each is a CSS keyword of `white-space` (a `const` assertion plus a test over `ALL`). The style builder emits `white-space:pre-wrap` for `PreWrap`. | runtime tests | `test` (assertion: every build) |
| The six `Font_whiteSpace*` kernels map one-to-one onto `WhiteSpace::ALL`. | runtime tests | `test` |
| TUI: a `NoWrap` paragraph wider than the canvas is not wrapped; `Pre` keeps `\n`; `Normal` wraps. A section heading is bold. | runtime `tui/layout.rs` tests (`tui` feature) | `runtime-full-features` |
| Every new kernel has a `UiEmitPlan` (the existing `exhaustiveness_partition`). | backend tests | `test` |
| Backend `CompileUiDesc` JSON for every variant decodes to runtime `UiDescription` and back. | runtime `template.rs` test | `test` |
| The seal: the golden programs (`stdui_input`, `region_seal`) build and run. | `golden_stdui_input.rs`, `golden_region_seal.rs` | `e2e` (`IPE_E2E=1`) |
| Markdown `# a`, `## b`, `### c`, then `## d` renders nested sections `h1 > h2 > h3` with `d` at `h2`. A fence renders `<pre><code>`, and inline code renders `<code>`. | ipe-cli emit test over `Markdown.toUi` | `e2e` |
| Generated docs match the regenerated output. | — | `stdlib-docs-drift` |

## BUG-CLASSES.md entries touched

| Class | Where it applies here | How it is closed |
|---|---|---|
| Refusal deferred to runtime | An invalid heading level was clamped at render time. | `HeadingLevel` is closed and derived. `Ui.Unsafe.taggedNode` literal-tag refusal stays at runtime; see LIMIT. |
| Closed set matched on text with a default row | `tag_for_description` (`_ => "h6"`) and `landmark_tag_for` (`_ => None`). | `NodeTag` and `HeadingLevel` are exhaustive enums with `ALL`. No wildcard remains. |
| Structural marker in the content alphabet | `__paragraph` and `__textcolumn` can be forged through public `Ui.style`. | Identity moves to `Description`. The remaining layout markers are the subject of CONSIDERATION. |
| Builtin identity by bare name | `WhiteSpace` must not be a reserved builtin name. | It is an ordinary source union homed at `Ipe.Ui.Font`. The lane checks `is_reserved_builtin_type_name("WhiteSpace")` is false. |
| Runtime struct reshaped under a compiler mirror | `UiDescription` mirrors backend `CompileUiDesc`. | Both change in one slice, with a full-variant round-trip test. |
| Page-config node found by a name page content can carry | Text roles near trusted page nodes. | The roles emit no `id` or `name`, and no id is derived from text. |
| Guard built but not wired; guarantee tested at a pure helper | Admission and content-model tests. | Driven through `ui_layout` and `admit_rendered`, not `render_paragraph_child` or `admit_element` alone. |
| Static model weaker than the runtime predicate | The content-model walker models the HTML parser. | The browser-e2e parse equality is the oracle. |
| Recursion depth chosen by input; quadratic accumulation in Ipê source | Section nesting and the Markdown outline. | Nesting rides the existing `MAX_HTML_DEPTH`, and the level saturates. The Markdown stack is at most 6 deep, with a single pass and one reverse. |
| Tests never compiled or run by CI | TUI tests are `tui`-gated. | They are named under `runtime-full-features`. |
| Vacuous refusal test; a refusal test that matches only the error family | Every name refusal. | Exact variant plus control, as in the table above. |
| Generated drift | New docs pages and goldens. | Regenerated, and the new files are `git add`ed. |

New class for the orchestrator to add (it is pre-existing, found here):
**Markup the HTML parser restructures**. A renderer that emits a flow element
under a phrasing ancestor (`<p><span><div>`) ships a tree the browser rebuilds
differently, so the DOM drifts from the server's tree and its diff ids. The
property that prevents it: the content model is threaded top-down, flow tags
are demoted under phrasing, and a browser parse-equality check holds.

## Implementor slices

Run in this order. Slices that touch kernels, goldens or arity tables are gated
alone.

1. **Runtime text roles and content model.** Runtime only:
   - `ui/element.rs`, `ui/render.rs`, `ui/helpers.rs`, `ui/template.rs`,
     `tui/layout.rs`, `html.rs` tests;
   - additive: the new `Description` variants, `NodeTag`, `HeadingLevel`,
     `ContentModel`, `RenderCtx`, `WhiteSpace`, `AttrFontWhiteSpace`, and the
     new helpers;
   - the paragraph and text-column identity moves to `Description`.

   `DescHeading(i64)` and its helpers stay until the section slice, so the
   branch builds alone. It can run in parallel with the Ui.Unsafe slice.
2. **Ipe.Ui.Unsafe module. Gated alone (kernels, goldens).** SCEF: trust
   boundary.
   - `Ui/Unsafe.ipe`; `Ui.ipe` (exposure, and the `taggedNode` binding
     removed);
   - `stdlib/src/lib.rs`; the kernels `source_display_name` arm;
   - the capability, N0025 and source-scan tests;
   - `live_e2e.rs`, `stdui_input` golden and regen, `AGENTS.md.in`, the
     guides, docs regen.

   It switches `paragraph`, `textColumn` and `form` to `node` with the
   `descTextColumn` and `descForm` kernels (kernels rows plus the
   `emit_ui_plan` and `emit_ui_template` arms). It needs the runtime slice
   merged first.
3. **Section headings and text roles wiring. Gated alone (kernels, goldens).**
   It waits for the section-shape decision.
   - Kernels: the 5 remaining desc kernels added, `UiDescHeading` and
     `RegionHeading` removed;
   - `emit_ui_plan`, `emit_ui_template`, `lower.rs`, the `env.rs` Region
     list, the constrain tests;
   - `Ui.ipe`: `codeBlock`, `code`, `kbd`, `section`, and `descHeading`
     removed;
   - `Markdown.ipe`, the `ui-layout` example, the `region_seal` golden and
     regen, docs regen;
   - runtime deletion of `DescHeading(i64)`, its template mirror variant, and
     `ui_desc_heading_` / `ui_region_heading_`.
4. **Ipe.Ui.Font module and whiteSpace. Gated alone (kernels, goldens).**
   - `Ui/Font.ipe`;
   - the Font entries removed from `env.rs`;
   - `stdlib/src/lib.rs`;
   - the 6 kernels and their `emit_ui_plan` rows;
   - `Markdown.ipe`: the `codeBlock` white-space, which drops the style
     string;
   - the `stdui_input` golden additions, regen, docs regen;
   - the type and N0042 tests.
5. **Parse-stability browser check.**
   - `ui-text-roles.spec.mjs` and `run.sh`;
   - the `browser-e2e` steps in `ci.yml`;
   - `ui-layout` example content for the four nesting shapes.

   It is file-disjoint from the Font slice, so it can run beside it after the
   section slice. It also runs the `browser-e2e` job locally, because the
   change touches the browser runtime path.

Slices 2, 3 and 4 all edit `kernels/src/lib.rs`, `stdlib/src/lib.rs` and the
goldens, so they are strictly sequential.

## LIMIT

- **Runtime-only refusal for free-form tags.** `Ui.Unsafe.taggedNode` with a
  literal denied tag (`"script"`) is still refused only at runtime, as an empty
  element. Refusing it in `ipe` needs one tag grammar shared by the compiler and
  the vendored runtime. The runtime crate cannot depend on compiler crates, so
  that is a separate design (generating the runtime denied-tag table from a
  compiler leaf, with an equality test). It is out of this spec's consent.
- **TUI white-space.** The TUI models wrap and newline preservation, not CSS
  space collapsing. This is documented in the `Font.whiteSpace` doc.
- **`textColumn` tag.** `textColumn` keeps its `<section>` tag (no accessible
  name, so no landmark) and does not advance the heading level.

## CONSIDERATION:

Typed layout markers (confidence ≥95%).

`Ui.row`, `Ui.column`, `Ui.wrappedRow` and `Ui.grid` mark themselves with
`AttrStyle("__row"|"__col"|"__wrappedrow"|"__grid", "true")`. The renderer and
the TUI decode layout from those keys. Public `Ui.style` can forge any of them
(`Ui.el [ Ui.style "__row" "true" ] …`), so content alphabet decides structure.

The structural fix is internal and adds no surface:

- a closed `Attribute::AttrLayout(LayoutKind)` set by the builder kernels;
- `Ui.style` refuses keys starting with `__`, as a typed refusal;
- the template mirror gains `Layout` with a round-trip test.

It touches the same `render.rs`, `tui/layout.rs` and `template.rs` as the
runtime slice. Run it as the slice after the Font slice, gated alone because it
regenerates goldens.

## DECISIONS NEEDED:

### Shape of `Ui.section`

**What.** The heading decision needs a section constructor and a heading. The
addition list does not name either.

**Why.** The shape decides whether a heading without a section, or a section
without a heading, can be built.

**How.** The options:

- **Record (recommended).** A heading-less section and a stray heading are both
  unrepresentable.

  ```elm
  Ui.section [] { heading = [ Ui.text "Install" ], content = [ Ui.paragraph [] [ … ] ] }
  ```

- **Separate `Ui.heading` and `Ui.section`.** Closer to HTML. A `Ui.heading`
  outside any section must render as `h1`, and a section may lack a heading,
  which is a screen-reader outline gap.

  ```elm
  Ui.section [] [ Ui.heading [] [ Ui.text "Install" ], Ui.paragraph [] [ … ] ]
  ```

- **Optional heading.** `{ heading : Maybe (List (Element msg)), content : … }`
  allows a heading-less section explicitly.

### Member names in `Ipe.Ui.Unsafe`

**What.** The new module's member names.

**Why.** Existing `Unsafe` modules prefix members (`Html.Unsafe.unsafeRaw`,
`Secret.Unsafe.unsafeReveal`).

**How.** The options:

- **Keep `taggedNode` and `input` (recommended).** This matches the decision's
  wording. The module import already discloses `unsafe`.

  ```elm
  UiUnsafe.taggedNode "dl" Ui.descNone [] items
  ```

- **Prefix: `unsafeTaggedNode` and `unsafeInput`.** Consistent with siblings,
  and every call site is greppable as unsafe.

  ```elm
  UiUnsafe.unsafeInput [ Ui.htmlAttribute "type" "file" ]
  ```

### File inputs after the move

**What.** `<input type=file>` (`Ui.onFile` uploads) and `type=submit` have no
typed `Ipe.Ui.Input` control.

**Why.** After the move, every app with an upload discloses `unsafe`.

**How.** The options:

- **Accept the disclosure for now (recommended inside this consent).** Document
  `UiUnsafe.input [ Ui.htmlAttribute "type" "file", Ui.onFile Picked ]`.
- **Add a typed `Input.file`.** This is new surface and needs the maintainer's
  consent.

  ```elm
  Input.file [] { onPick = Picked, accept = [ Image ] }
  ```

### Constructor exposure of `WhiteSpace`

**What.** How users name the constructors.

**Why.** Exposed unqualified, `Normal` and `Pre` would shadow user constructors
under `exposing (..)`.

**How.** The options:

- **Qualified use (recommended).** Expose `WhiteSpace(..)` from `Ipe.Ui.Font`
  and write `Font.whiteSpace Font.PreWrap`, as `Font.*` is already used
  qualified everywhere.

  ```elm
  Ui.el [ Font.whiteSpace Font.NoWrap ] (Ui.text label)
  ```

- **Prefixed constructors** (`WsNormal`, `WsPre`, …): collision-free, but
  noisier.
