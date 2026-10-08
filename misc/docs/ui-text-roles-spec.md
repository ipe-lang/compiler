# Ipe.Ui text roles, section headings, typed white-space and the Ui.Unsafe home

Designed by: security-soundness-guardian
Base: origin/main 76e359f5e8ed17c43655d2e250c7de4a4dbc3d75

## Scope and consent

`Ipe.Ui` is self-sufficient and elm-ui-like. The maintainer has consented to
exactly these surface changes:

1. Add `Ui.codeBlock`, inline `Ui.code`, inline `Ui.kbd`, and a typed
   `Font.whiteSpace` over a closed union (never a `String`).
2. Move `Ui.taggedNode` and `Ui.input` to a new `Ipe.Ui.Unsafe` module, as
   `unsafeTaggedNode` and `unsafeInput`.
3. Derive heading levels from `Ui.section` nesting depth, clamped to 6.
   `Ui.section` takes a `{ heading, content }` record.
4. Add a typed `Input.file`, and no other new API.

`Ipe.Ui.Unsafe` members carry the `unsafe` prefix, like the other `Unsafe`
modules (`Html.Unsafe.unsafeRaw`). `WhiteSpace` constructors are used qualified
(`Font.Pre`).

Nothing else joins the public surface. The typed layout attribute (see
"Typed layout attribute") changes no public signature: `Ui.style` keeps
`String -> String -> Attribute msg`, and the layout builders keep theirs.

The project is pre-public, so the old
locations (`Ui.taggedNode`, `Ui.input`) and the integer heading constructors
(`Ui.descHeading`, `Region.heading`) are removed outright, with no shim.

Public signatures after this spec:

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
unsafeTaggedNode : String -> Description -> List (Attribute msg) -> List (Element msg) -> Element msg
unsafeInput      : List (Attribute msg) -> Element msg

-- Ipe.Ui.Input (see "Input.file")
type alias Picked = { name : String, size : Int, mime : String }
type FileKind = Image | Audio | Video | Pdf | PlainText | Csv
type Accept = AnyFile | Only FileKind (List FileKind)
type Pick msg = PickOne (Picked -> msg) | PickMany (List Picked -> msg)
file : List (Attribute msg) -> { accept : Accept, pick : Pick msg, label : Label msg } -> Element msg
```

## Class-closing properties

Each change closes a class, not one site.

- **The Ui.Unsafe move.** No tag string written in Ipê code reaches the
  renderer from the safe surface (`Ipe.Ui`, `Ipe.Ui.Font`, `Ipe.Ui.Input`,
  `Ipe.Markdown`, and every other non-`Unsafe` stdlib module).
  - Safe-surface nodes built from Ipê get their tag from a closed `NodeTag`
    enum, chosen by their `Description`.
  - Runtime builders (`button`, `link`, `image`, the `Input` controls) still
    build `Element::TaggedNode`, but only with `'static` literal tags. Each of
    those literals is admitted by a test through the production sink.
  - A tag string chosen by Ipê code is reachable only through a module whose
    import discloses `unsafe`. Today `paragraph`, `textColumn`, `form` and
    `input` are built on `taggedNode`. After this spec, the only
    `Kernel.kernel "Ui_taggedNode"` binding in the tree is in
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
- **Typed layout.** Layout identity is never read from a style key. Whether a
  node is a row, a column, a wrapped row or a grid is a closed
  `LayoutKind` carried by `Attribute::AttrLayout`, set only by the layout
  builders. Whether a box flows inline is a fact of the render context, not
  of an attribute. Every `AttrStyle` key reaches the renderer only through
  `SafeCssPropertyName`, whose grammar has no `_`, so `Ui.style "__row" "true"`
  is a refused CSS property and changes nothing.
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
  - `unsafeTaggedNode = Kernel.kernel "Ui_taggedNode"`;
  - a private `descNone = Kernel.kernel "Ui_descNone"`;
  - `unsafeInput attrs = unsafeTaggedNode "input" descNone attrs []`.

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
- Kernels `source_display_name`: add `UiTaggedNode => "Ui.Unsafe.unsafeTaggedNode"`,
  beside `HtmlScriptNode => "Html.Unsafe.unsafeScript"`.
- The three admission boundaries for `TaggedNode` stay unchanged: construction
  in `ui_tagged_node_`, template materialisation (`template.rs` calls
  `ui_tagged_node_`), and the sink (`admit_rendered`, `render.rs`). That is
  defence in depth for the one free-form tag path.
- Callers that move to `import Ipe.Ui.Unsafe as UiUnsafe`:
  - `src/ipe-cli/tests/live_e2e.rs`: the raw form-post fixtures;
  - `tests/golden/stdui_input/Main.ipe`.

  The `Ui.input` idiom in `src/ipe-cli/templates/AGENTS.md.in` points
  text, password, checkbox and file inputs at the typed `Ipe.Ui.Input`
  controls (`Input.file` below). It names `UiUnsafe.unsafeInput` only for
  input types no typed control covers.

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
- **Empty headings.** A section whose heading has no content renders no `hN`
  and does not deepen the level, so the levels that do render stay
  contiguous and no heading is left with an empty accessible name.
  - One total predicate, `fn has_content(&Element<M>) -> bool` in `ui/`, is
    shared by the HTML renderer and the TUI. It is an exhaustive match over
    every `Element` variant, with no wildcard:
    - `Empty` (`Ui.none`) → false;
    - a text leaf → true iff some `char` of it is not `char::is_whitespace`
      (Unicode White_Space, so `" \t\n"` and U+00A0 count as empty);
    - a container (`Node`, `TaggedNode`, row/column/paragraph and the other
      container variants) → true iff some child `has_content`;
    - a non-text leaf that renders something visible or announced (image,
      input control, and the other leaf variants) → true;
    - a tagged element that presents its own box with no children
      (`textarea`, `select`, `iframe`, `object`, `canvas`, `video`, `audio`,
      `progress`, `meter`) → true;
    - a node carrying an `AttrNearby` overlay → true.

    The walk is bounded by the existing `MAX_HTML_DEPTH`. Past the ceiling it
    returns true: the heading is kept and the render's own depth refusal
    applies.
  - One classifier, `section_head(&Description, &[Element<M>]) -> SectionHead
    { NoHeading, Empty, Present }` in `ui/element.rs`, is computed once per
    node and shared by the HTML renderer and the TUI. Entering `DescSection`
    checks whether its first child is a `DescSectionHeading` node that
    `has_content`.
    - If so, the section sets `section = Some(prev.map_or(H1, deeper))` and
      renders the heading.
    - If not, the section keeps `section = prev` and skips that heading child
      entirely: no `hN`, no wrapper, no whitespace text. Content renders as
      usual.
  - The level is still derived only from sections whose headings render. For
    example, `section(heading "a") > section(heading []) > section(heading "b")`
    renders `h1 a`, then `h2 b`.
  - The rule reads only structure and Unicode White_Space, so the outcome is
    deterministic. Zero-width characters that are not White_Space (U+200B,
    U+FEFF) count as content. See LIMIT.
  - The `Ui.section` doc states the rule.
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
  - A demoted node keeps its landmark as `role`: the `describe` landmark
    first, else the one its own `Description` names. A heading keeps
    `role="heading"`/`aria-level` as before.
  - `Element::TaggedNode` renders its written tag. Slice 1b classifies that
    tag (see "Ancestor exclusions") so the content model and the exclusions
    apply to it too; a tag outside the classification table (a custom
    element) renders as written, which `Ui/Unsafe.ipe` documents.
- **Ancestor exclusions.** A flow/phrasing model cannot express the HTML
  rules that forbid an element below a given ancestor whatever the content
  model: `form` in `form`, interactive content in `button`, and `a` or other
  interactive content in `a`. The parser drops the inner `<form>` start tag
  and closes an open `button` or `a` early, so the browser tree differs from
  the server tree and its diff ids. Once `form` is `node descForm`
  (slice 2), `Ui.form [] [ Ui.form [] [] ]` reaches this from the safe
  surface.
  - `RenderCtx` gains `ancestors: Exclusions`, a set over the closed enum
    `Exclusion { Form, Interactive, Anchor }` (with `ALL`). It is passed by
    value like the other fields and starts empty at the root.
  - One classification table, `fn classify(&ResolvedTag) -> TagClass`,
    declared once: `TagClass { category: ContentModel, content:
    ContentModel, is: Exclusions, forbids: Exclusions }`. For `Typed` it
    reads `NodeTag`. For `Written` it matches the tag ASCII-case-insensitively
    against `NodeTag::ALL` and the interactive tags the runtime builders and
    `Ui.Unsafe` can write (`a`, `button`, `input`, `select`, `textarea`,
    `label`, `iframe`, `details`, `embed`, `audio`, `video`); a tag in
    neither is `Unclassified` and renders as written. The match has no
    wildcard over the table's members.
    - `form`: `is = {Form}`, `forbids = {Form}`.
    - `button`, `label`, `input`, `select`, `textarea`, `iframe`,
      `details`, `embed`, `audio`, `video`: `is = {Interactive}`.
      `button` also `forbids = {Interactive, Anchor}`.
    - `a`: `is = {Interactive, Anchor}`, `forbids = {Interactive, Anchor}`.
  - A node whose class `is` intersects `ctx.ancestors` renders as `span`
    through the same demotion as the content model (`demote_attrs`). It keeps
    its children, event attributes and landmark `role`, and drops the tag's
    form or interactive semantics. It adds nothing to `ancestors`, so its
    own descendants are judged against the real ancestors. The render
    reports it once per render through the developer diagnostic that
    reports a refused style key.
  - The child context is `ancestors ∪ class.forbids`.
  - The content model uses the same table, so a `Written` flow tag under
    phrasing (`Ui.Unsafe.unsafeTaggedNode "p"` inside a paragraph) is
    demoted like a typed one.
  - The TUI has no parser and is unaffected.
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
  layout markers move to a typed attribute in "Typed layout attribute".
- New helpers in `ui/helpers.rs`:
  - one nullary `ui_desc_<role>_` per new description;
  - one nullary `ui_font_white_space_<mode>_` per `WhiteSpace` variant.

  `ui_desc_heading_` and `ui_region_heading_` are deleted.
- TUI (`tui/layout.rs`):
  - `DescSectionHeading` sets bold, as `DescHeading` does today. The TUI has
    no heading levels, so depth only affects which headings render.
  - The TUI applies the same `section_head` rule. A section's first-child
    heading without content lays out as nothing: no bold blank row, and no
    spacing line reserved for it. Its section's content lays out as if the
    heading were absent. A heading anywhere else lays out as HTML renders it.
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

### Input.file

**Class-closing property.** A file control built from the safe surface can only
produce an `<input type=file>` whose attributes come from closed values. Every
browser-supplied pick is parsed once, at the event boundary, into a bounded
typed value before any `msg` is built. User attributes have no path onto the
`<input>` element. Whether one or many files may be picked is a constructor of
`Pick`, and that constructor also fixes the handler's payload type. So a
single-file handler cannot receive a list, and a many-file handler cannot
receive a bare value.

**Home.** `Ipe.Ui.Input` is a native qualifier today (canon `env.rs` around
lines 102 and 1416) and cannot carry source unions. It becomes the compiled
module `src/stdlib/Ipe/Ui/Input.ipe`, the same migration `Ipe.Ui.Font` gets:

- Each of its 18 existing members becomes an alias
  `x = Kernel.kernel "Input_x"` for its unchanged `KernelFn`. Their emitted
  calls do not change.
- The bare builtins `Label` and `Placeholder` keep their builtin homes and are
  only referenced from the module.
- `Input` leaves the native tables in `env.rs` and joins `COMPILED_STD_MODULES`.
- No name collides: none of `FileKind`, `Accept`, `Pick`, `Picked` or their
  constructors is a reserved builtin name. The lane re-checks this with
  `is_reserved_builtin_type_name` and the builtin constructor table.

**Surface** (the one consented API, with only its parameter types):

```elm
type FileKind = Image | Audio | Video | Pdf | PlainText | Csv
type Accept = AnyFile | Only FileKind (List FileKind)
type Pick msg = PickOne (Picked -> msg) | PickMany (List Picked -> msg)

file : List (Attribute msg) -> { accept : Accept, pick : Pick msg, label : Label msg } -> Element msg
```

- `Only` takes at least one kind, so an empty filter has no representation.
  `AnyFile` is the explicit "no filter" case.
- `Picked` is metadata only:

  ```elm
  type alias Picked = { name : String, size : Int, mime : String }
  ```

  No file bytes cross the wire, and the runtime keeps no per-session handle
  table. The app can show and check a selection; reading file content stays
  with the existing `Ui.onFile`. Every field is client-declared, and the
  `Input.file` doc says so.

  | Field  | Accepted values (anything else is refused) |
  |--------|--------------------------------------------|
  | `name` | 1 to 255 UTF-8 bytes (`MAX_PICKED_NAME_BYTES = 255`). |
  | `size` | ASCII decimal digits, no sign, no leading zero except `0` itself, at most 16 digits, value 0 to 2^53 − 1 (`MAX_PICKED_SIZE`, the largest integer a browser `Number` holds exactly). |
  | `mime` | Empty (the browser knows no type, and `File.type` is `""`), or `type/subtype` of at most 127 bytes (`MAX_PICKED_MIME_BYTES = 127`): exactly one `/`, each side non-empty, starting with an ASCII letter or digit and continuing with `[A-Za-z0-9!#$&^_.+-]` (the RFC 6838 restricted-name set). Parameters (`;`), spaces and any other byte are refused. |

  The four constants are declared once in `ui/input.rs`.

**Runtime.**

- `src/runtime/rust/src/ui/input.rs` gets `input_file_`, which does not go
  through `input_base_`.
- The `<input>` element's attribute list is built only by the runtime:
  - `type=file`;
  - `accept`, from `FileKind::accept_text()`, a `const` table:

    | Kind        | `accept` text            |
    |-------------|--------------------------|
    | `Image`     | `image/*`                |
    | `Audio`     | `audio/*`                |
    | `Video`     | `video/*`                |
    | `Pdf`       | `application/pdf,.pdf`   |
    | `PlainText` | `text/plain,.txt`        |
    | `Csv`       | `text/csv,.csv`          |

    Kinds are joined with `,`, de-duplicated in first-appearance order.
    `AnyFile` emits no `accept`.
  - `multiple`, present iff the pick is `PickMany`;
  - the handler event attribute;
  - the `id` that links the input to its label, generated the same way the
    other labelled inputs generate it. It is never derived from user text.
- User `attrs` are split by the existing `split_layout_attrs`. Both halves
  apply to the label wrapper only. None reaches the `<input>`: not
  `Ui.htmlAttribute` (`type`, `accept`, `capture`, `webkitdirectory`, `name`,
  `form`, `formaction`, `value`), not `Ui.style`, and not a second event
  handler such as `Ui.onFile`.
- A new handler shape is wired under a new wire event name, `ipe-pick`. It
  does not reuse `OnString` or `ipe-file`.
  - `html::Event::OnPick(String, PickHandler<M>)`, where
    `enum PickHandler<M> { One(Arc<dyn Fn(Picked) -> M>), Many(Arc<dyn Fn(Vec<Picked>) -> M>) }`.
  - Every exhaustive match over `html::Event` (`html.rs`, `dom/dispatch.rs`,
    `ui/render.rs`, `ui/template.rs`, `tui/focus.rs`) gains an explicit arm,
    with no wildcard.
- The client driver (`web/client.js`) handles `ipe-pick` beside the existing
  `ipe-file` driver:
  - It sends three wire arguments per selected file, in order: `File.name`,
    `String(File.size)` and `File.type`. It reads no file content. It sends
    at most `MAX_PICKED_FILES` files; more than that clears the input, sends
    nothing, and logs `console.warn`.
  - This is a UX check only. The server parse below is the boundary.
- `HandlerIndex::resolve` (`dom/dispatch.rs`) parses the wire arguments
  (`&[String]`, three per file) once with
  `parse_pick(args, &PickHandler) -> Result<Option<M>, PickRefusal>`, where
  `PickRefusal` is a closed enum. The count checks run first, in O(1), before
  any field is read:
  - `Malformed`: the argument count is not a multiple of 3.
  - `TooMany`: more than `MAX_PICKED_FILES = 32` files, declared once in
    `ui/input.rs`.
  - `WrongArity`: `One` with more than one file. Zero files give `Ok(None)`
    for both shapes and dispatch nothing, because a cancelled dialog is not a
    pick.
  - `NameEmpty`, `NameTooLong`: the `name` rule in the table above.
  - `SizeMalformed` (not the decimal grammar), `SizeOutOfRange` (above
    `MAX_PICKED_SIZE`): the `size` rule. A negative or fractional size is
    `SizeMalformed`, because `-` and `.` are outside the grammar.
  - `MimeTooLong`, `MimeMalformed`: the `mime` rule.

  Each field is parsed into its typed value exactly once here. A `Picked`
  exists only as the output of this parse.

  A refusal dispatches no `msg` and is logged as the typed refusal kind, never
  the entry's content. The request body stays bounded by the existing
  `IPE_WEB_MAX_BODY_BYTES` ceiling.
- `accept` and any client-declared MIME type are advisory: a browser lets the
  user pick "All files". The `Input.file` doc states that the kind filter is
  not a validation of the file, and that `Picked` fields come from the client.
  A file name is untrusted text, never a path.
- **Template baking.** `InputFile` is not on the `emit_ui_template` allowlist,
  so its subtree stays dynamic. This is the existing fail-closed default.
  `emit_ui_plan` gets a row for it.
- **TUI.** A terminal has no file picker.
  - `Input.file` lays out its label followed by a fixed, non-focusable note.
    The note's text is declared once beside the TUI's other fixed strings.
  - It registers no key handler and dispatches nothing.

### Typed layout attribute

**Class-closing property.** No reader of layout looks at an `AttrStyle` key.
Layout identity has its own closed type, and the style key space carries only
CSS property names. So no value of `Ui.style`'s arguments, and no attribute
list a program builds from the safe surface, can change a node's layout kind,
its flex axis, or whether it flows inline.

**Today.** `Ui.row`, `Ui.column`, `Ui.wrappedRow` and `Ui.grid` mark
themselves with `AttrStyle("__row"|"__col"|"__wrappedrow"|"__grid", "true")`
(`Ui.ipe` around 1339-1357; runtime writers `ui_row_`, `ui_column_`,
`ui_wrapped_row_` in `ui/helpers.rs`, `cells_row_`, `cells_column_` and
`cli_lines_` in `tui/mod.rs`). Readers match the key text before the CSS gate:
the `AttrStyle` arm of the style collector and `flex_axis_of` in
`ui/render.rs`, and `walk_attrs` in `tui/layout.rs`.
`render_paragraph_child` rewrites `__row` to `__inline_row` and `__col` to
`__inline_col`, and inserts `__inline`, all in the same key space, read back
by the collector and `is_inline_marked`. `walk_attrs` also reads
`__gridMin` and parses its value with `unwrap_or(0)`; nothing writes
`__gridMin`, so only a forged `Ui.style` reaches it. Any of these keys can be
forged: `Ui.el [ Ui.style "__row" "true" ] …` lays out as a row.

**Design.**

- `ui/element.rs` gains

  ```rust
  pub enum LayoutKind { Row, Column, WrappedRow, Grid }
  impl LayoutKind { pub const ALL: [LayoutKind; 4] = [...]; }
  ```

  and `Attribute::AttrLayout(LayoutKind)`. Paragraph and text column are not
  layout kinds; they are `Description`s (see "Runtime roles").
- Writers. `Ui.ipe` row, column, wrappedRow and grid prepend a private
  attribute alias instead of `style "__…" "true"`:

  ```elm
  layoutRow : Attribute msg
  layoutRow =
      Kernel.kernel "Ui_layoutRow"

  row attrs children =
      node descNone (layoutRow :: attrs) children
  ```

  The four aliases (`layoutRow`, `layoutColumn`, `layoutWrappedRow`,
  `layoutGrid`) are not in `Ipe.Ui`'s `exposing` list, and user
  `Kernel.kernel "Ui_layout…"` is `KernelAliasInUserSource` (IPE-N0042), so
  no user code can produce an `AttrLayout`. Four nullary kernels
  (`UiLayoutRow`, `UiLayoutColumn`, `UiLayoutWrappedRow`, `UiLayoutGrid`)
  map to `ui_layout_row_()` and its siblings, each returning
  `Attribute::AttrLayout(..)`. The runtime writers in `ui/helpers.rs` and
  `tui/mod.rs` push `AttrLayout` directly.
- Inline flow is a render-context fact. `render_paragraph_child` no longer
  rewrites attributes. It renders with a closed
  `enum Flow { Block, InlineRun }` set to `InlineRun`, threaded beside the
  `ContentModel` that slice 1 introduces. The CSS comes from one total
  function with an exhaustive match and no wildcard:

  ```rust
  fn layout_decls(kind: Option<LayoutKind>, flow: Flow) -> &'static [&'static str]
  ```

  | `kind` \ `flow` | `Block` | `InlineRun` |
  |---|---|---|
  | `Some(Row)` | `display:flex`, `flex-direction:row` | `display:inline-flex`, `flex-direction:row` |
  | `Some(Column)` | `display:flex`, `flex-direction:column` | `display:inline-flex`, `flex-direction:column` |
  | `Some(WrappedRow)` | `display:flex`, `flex-direction:row`, `flex-wrap:wrap` | `display:inline-flex`, `flex-direction:row`, `flex-wrap:wrap` |
  | `Some(Grid)` | `display:grid` | `display:inline-grid` |
  | `None` | none | `display:inline-block`, `vertical-align:baseline` |

  These are today's outputs for every pair the current code reaches. The
  `WrappedRow` and `Grid` cells under `InlineRun` are new: today a wrapped row
  or grid in a paragraph keeps its block display and breaks the `<p>`, which
  is the parse-stability defect the content-model rule closes.
  `flex_axis_of` matches `AttrLayout`, and `is_inline_marked` becomes a read
  of `flow`.
- The `AttrStyle` arm of the style collector has exactly one path:
  `SafeCssPropertyName::parse` on the key and `SafeCssValue::parse_reporting`
  on the value. Its grammar, `[A-Za-z0-9-]+`, has no `_`, so every `__…` key
  is refused there. The key gains `SafeCssPropertyName::parse_reporting`
  with the same `DeveloperLiteral` origin, so a refused key such as `__row`
  names itself in the developer diagnostic instead of vanishing silently.
- `tui/layout.rs` `walk_attrs` matches `AttrLayout` for direction and grid.
  The `__paragraph` and `__textcolumn` arms are gone after slice 1. The
  `__gridMin` arm is deleted, because it has no producer. If `grid_min_px`
  is then never written, the field and its branch go too, not kept as dead
  state. The only `AttrStyle` key the TUI still reads is `border-style`, a
  real CSS property.
- `ui/widget.rs`: the `__raw` assertion becomes "every `AttrStyle` key the
  widget emits parses as `SafeCssPropertyName`".
- Template mirror. `ui/template.rs` `UiAttribute` gains
  `Layout(LayoutKind)`, and backend `emit_ui_template.rs` `CompileUiAttr`
  gains `Layout(&'static str)`, its tag written by `tagged_enum_static_str`.
  `compile_attr` maps `(KernelFn::UiLayoutRow, [])` and its siblings to
  `Layout`. The four lowered wrapper bodies (`node descNone (layoutRow ::
  attrs) children`) templatize as the `style "__row" "true"` prepend does
  today. The tests at 2128-2213 and 3108-3203 are rewritten over the new
  body. A literal `Ui.style "__row" "true"` still bakes as `Style`, and the
  runtime gate refuses it at render.
- `Ui.style` keeps `String -> String -> Attribute msg`. A typed
  `CssProperty` union would need hundreds of constructors and a release per
  CSS property. It would add no security, because the key already meets its
  single parse at the style sink, and that parse refuses every non-CSS
  name. Once no reader decodes structure from the key space, a refused key
  is a dropped declaration, not a forged layout.

## Safe-surface admission rule

- **Tags.** A safe-surface element's tag is a `NodeTag`. A test drives every
  `NodeTag::ALL` member through the production sink and checks
  `admit_element(tag, body) == Markup`:

  ```
  ui_layout -> render -> admit_rendered
  ```

  No `NodeTag` is `script`, `style`, `plaintext`, `textarea`, `title`,
  `iframe`, `noscript`, `xmp`, `template` or `svg`. The same test drives every
  `'static` literal tag the runtime builders pass to `Element::TaggedNode`
  (`button`, `a`, `img`, `input`), found by a source scan of `ui/`, so a new
  literal cannot skip it.
- **File input.** `Input.file` emits `input` with a closed attribute set, and
  no user attribute reaches it (see "Input.file").
- **Free-form tags.** These come only from `Ipe.Ui.Unsafe.unsafeTaggedNode`, through
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
  - new `src/stdlib/Ipe/Ui/Input.ipe`;
  - `src/stdlib/Ipe/Ui.ipe`;
  - `src/stdlib/Ipe/Markdown.ipe`.
- **Stdlib registry:** `src/stdlib/src/lib.rs`. Three `include_str!` entries,
  `COMPILED_STD_MODULES` entries (around 1866 and 1901), and the module-list
  doc near 265.
- **Canon:**
  - `src/compiler/canon/src/env.rs`: the Font and Input native entries
    removed, Region `heading` removed;
  - `src/compiler/canon/src/lib.rs`: the new N0025 tests.
- **Kernels registry:** `src/compiler/kernels/src/lib.rs`.
  - Add: the 7 `UiDesc*` kernels (`descSection`, `descSectionHeading`,
    `descCodeBlock`, `descCode`, `descKbd`, `descTextColumn`, `descForm`) and
    6 `FontWhiteSpace*` kernels, each at every mirrored site the `KernelDef`
    tripwire names (variant, `d(..)` descriptor, scheme, arity, runtime path).
  - Remove: `UiDescHeading` and `RegionHeading`.
  - Add the `source_display_name` arm for `UiTaggedNode`.
  - Add `InputFile` (`d("Input","file",2,Ui,"input_file_",IpeOrder)`) with its
    scheme and record-field order, beside `InputCheckbox`.
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
  - `src/runtime/rust/src/html.rs`: tests, plus the `Event::OnPick` variant;
  - `src/runtime/rust/src/ui/input.rs`: `input_file_`, `FileKind`, `Accept`,
    `Picked`, `MAX_PICKED_FILES`;
  - `src/runtime/rust/src/dom/dispatch.rs`: `parse_pick` and `PickRefusal`;
  - `src/runtime/rust/src/tui/focus.rs`: the `OnPick` arm;
  - `src/runtime/rust/src/web/client.js`: the `ipe-pick` driver.
- **Goldens.** Regenerate with `cargo run -p regen-goldens`; never hand-edit.
  - `tests/golden/stdui_input/Main.ipe`: `UiUnsafe.unsafeInput`, plus one each of
    `codeBlock`, `code` and `kbd`, and `Font.whiteSpace` over every
    constructor;
  - `tests/golden/region_seal/Main.ipe`: nested `Ui.section`, replacing
    `Region.heading`, including an empty-heading section;
  - `tests/golden/stdui_input/Main.ipe` (the `Input.file` slice): one
    `Input.file` with `PickOne` and `Only`, and one with `PickMany` and
    `AnyFile`;
  - the emitted `ipe_mod_ipe_*` seal goldens, which gain `Ipe.Ui.Font` and
    `Ipe.Ui.Input`;
  - the drivers `src/ipe-cli/tests/g_stdui/golden_stdui_input.rs` and
    `src/ipe-cli/tests/g_misc/golden_region_seal.rs`.
- **Docs regen.** Run `gen-stdlib-docs` and `git add` the new files:
  - `docs/reference/stdlib/Ui.md` and `docs/reference/stdlib.md`;
  - new `docs/reference/stdlib/Ui.Unsafe.md`,
    `docs/reference/stdlib/Ui.Font.md` and `docs/reference/stdlib/Ui.Input.md`.
- **Hand-written docs:**
  - `docs/guide/accessibility.md` (line 47);
  - `docs/guide/ui.md` (line 84);
  - `src/ipe-cli/templates/AGENTS.md.in`: the input idiom (813), the upload
    pattern (965, rewritten to `Input.file`), and a short text-roles note.
- **Examples:** `examples/shapes/web/ui-layout/src/Main.ipe` (line 70,
  `Ui.describe (Ui.descHeading 1)`), which becomes a `Ui.section`.
- **Other ipe-cli tests:**
  - `src/ipe-cli/tests/live_e2e.rs`: the `Ui.input` fixtures;
  - `src/ipe-cli/tests/watch_hot_appearance.rs`: the 1437 comment.
- **Browser e2e:**
  - new `tools/scripts/browser-e2e/ui-text-roles.spec.mjs`;
  - new `tools/scripts/browser-e2e/ui-file-pick.spec.mjs` (the `Input.file`
    slice), driving the `ui-layout` example's file control with Playwright
    `setInputFiles`;
  - `tools/scripts/browser-e2e/run.sh`, which serves `ui-layout` on a third
    port;
  - the `browser-e2e` job in `.github/workflows/ci.yml`, which gains a compile,
    spawn and wait step for `ui-layout`. The status context is unchanged, so
    `check-manifest.yml` is unchanged.
- **Typed layout attribute slice:**
  - `src/stdlib/Ipe/Ui.ipe`: the four private `layout*` aliases and the
    row, column, wrappedRow and grid bodies;
  - `src/compiler/kernels/src/lib.rs`: `UiLayoutRow`, `UiLayoutColumn`,
    `UiLayoutWrappedRow` and `UiLayoutGrid` at every mirrored site;
  - `src/compiler/backend/rust/src/emit_ui_plan.rs`: their plan rows;
  - `src/compiler/backend/rust/src/emit_ui_template.rs`: `CompileUiAttr::Layout`,
    the `compile_attr` arms, and the wrapper-body tests;
  - `src/compiler/types/src/constrain/tests/mod.rs`: the kernel lists;
  - runtime `ui/element.rs` (`LayoutKind`, `AttrLayout`), `ui/render.rs`
    (`layout_decls`, `Flow`, `flex_axis_of`, `is_inline_marked`,
    `render_paragraph_child`, the `AttrStyle` arm), `ui/helpers.rs`
    (`ui_layout_*_`, `ui_row_`, `ui_column_`, `ui_wrapped_row_`),
    `ui/template.rs` (`UiAttribute::Layout`, the round-trip tests at 1385-1440),
    `ui/widget.rs` (the assertion), `tui/mod.rs` (`cells_row_`,
    `cells_column_`, `cli_lines_`), `tui/layout.rs` (`walk_attrs` and its tests
    near 2924, 2985, 3050, 3077, 3304 and 3325), and `css_safety.rs`
    (`SafeCssPropertyName::parse_reporting`);
  - every exhaustive match over `Attribute` gains an explicit `AttrLayout`
    arm, with no wildcard (the lane lists them with
    `tools/scripts/ipe-index rdeps Attribute`);
  - goldens regenerated (every golden that uses a layout builder).
- **tools/code-review.** No change. `Lib/View.ipe` uses only `Ui.html` and
  `Font.*`, and `Font.*` keeps every member name.

## Refusal tests (each names the CI job that compiles and runs it)

Every refusal test asserts the exact variant or code and is paired with a
control that runs the same input with the guarded difference removed and gets
`Ok`.

| Refusal | Where | CI job |
|---|---|---|
| `Ui.taggedNode` and `Ui.input` under `import Ipe.Ui as Ui` are `NameNotExposed` (IPE-N0022). Control: `UiUnsafe.unsafeTaggedNode` and `UiUnsafe.unsafeInput` resolve. `UiUnsafe.taggedNode` and `UiUnsafe.input` (unprefixed) are also `NameNotExposed`. | canon tests | `test` |
| `Ui.descHeading` and `Region.heading` no longer resolve, asserted by exact variant. Control: `Ui.section` resolves. | canon tests | `test` |
| `Font.whiteSpace "pre"` (a String) is a type mismatch. Control: `Font.whiteSpace Font.Pre` type-checks. | types tests | `test` |
| A user module named `Ipe.Ui.Unsafe`, and one named `Ipe.Ui.Font`, are `ReservedNamespace` (IPE-N0025). Control: the same source under `EmbeddedStdlib` canonicalises. | canon `lib.rs` | `test` |
| User source `Kernel.kernel "Font_whiteSpacePre"` is `KernelAliasInUserSource` (IPE-N0042). | canon tests | `test` |
| `import Ipe.Ui.Unsafe` discloses `unsafe`. Control: a program importing `Ipe.Ui`, `Ipe.Ui.Font` and `Ipe.Markdown` only does not. | `lower/src/capabilities.rs` | `test` |
| No non-`Unsafe` embedded stdlib module imports an `Ipe.*.Unsafe` module, and `Kernel.kernel "Ui_taggedNode"` appears only in `Ipe/Ui/Unsafe.ipe`. The source scan iterates `COMPILED_STD_MODULES`; a planted import in a copy of the `Ui` source turns it red. | `stdlib/src/lib.rs` tests | `test` |
| Every `NodeTag::ALL` member is admitted as `Markup` through `ui_layout` → `admit_rendered`. A denied tag through `UiUnsafe.unsafeTaggedNode` still renders empty. | runtime `ui/render.rs` tests | `test` |
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
| A demoted landmark keeps its role: a `describe descNavigation` node and a `node descMain` inside `Ui.paragraph` render `span` with `role="navigation"` and `role="main"`. Control: under a flow parent they render `<nav>` and `<main>` with no `role`. | runtime `ui/render.rs` tests | `test` |
| Overlays: a chain of `MAX_HTML_DEPTH + 2` nested `AttrNearby` overlays is truncated by the depth ceiling, and a 400 000-deep chain renders without overflowing (the overlay is moved, not cloned). Control: a 10-deep chain renders its leaf. | runtime `ui/render.rs` tests | `test` |
| Ancestor exclusions (slice 1b): `form` in `form`, `button` in `button`, `a` in `a`, and `a`/`input` in `button`, each typed and each written through `TaggedNode`, render the inner element as `span` with its children and events, and the developer diagnostic fires once. Control: the same element as a sibling keeps its tag. A walker over the rendered `Html` finds no element whose class `is` meets an ancestor's `forbids`. | runtime `ui/render.rs` tests | `test` |
| The same nested shapes, served: the server HTML of `#ipe-root` equals `root.innerHTML` after the browser parses it. | `ui-text-roles.spec.mjs` | `browser-e2e` |
| A written flow tag under phrasing (`unsafeTaggedNode "section"` in a paragraph) is demoted to `span`; an unclassified written tag (`my-widget`) renders as written. | runtime `ui/render.rs` tests | `test` |
| No `style "__paragraph"` or `style "__textcolumn"` in `src/stdlib/Ipe/` (slice 2), widened to every `style "__` in slice 7. A planted line in a copy of `Ui.ipe` turns it red. | `stdlib/src/lib.rs` tests | `test` |
| Empty heading: `section [] { heading = [], content = [p] }` renders `<section>` with no `h1`..`h6` element, and its content is unchanged. Control: `heading = [text "a"]` renders `h1`. | runtime `ui/render.rs` tests | `test` |
| Headings that count as empty: `[text " \t\n"]`, `[text "\u{00A0}"]`, `[Ui.none]`, `[el [] (text " ")]`, and a heading of three nested empty containers. Each gives no `hN`. Control: `[el [] (text " x ")]` is present. | runtime tests | `test` |
| Nested empty headings keep levels contiguous: `section "a" > section [] > section "b"` gives `h1 a`, `h2 b`, and `section [] > section [] > section "c"` gives `h1 c`. Seven present levels under two empty ones still saturate at `h6`. | runtime tests | `test` |
| `has_content` is an exhaustive match over `Element` with no wildcard (a source-scan test over its body), and it terminates past `MAX_HTML_DEPTH` (a heading nested one past the ceiling). | runtime tests | `test` |
| TUI: an empty-heading section lays out with no bold row and no blank row (its first line is the content's first line), and a present heading is bold. | runtime `tui/layout.rs` tests | `runtime-full-features` |
| `Input.file` admission: hostile `attrs` (`htmlAttribute "type" "text"`, `"accept" "*/*"`, `"webkitdirectory" ""`, `"capture" "user"`, `"name" "x"`, `"formaction" "/x"`, `Ui.style "x" "y"`, `Ui.onFile F`) render on the wrapper only. The rendered `<input>` carries exactly `type`, `id`, the event attribute, and `accept`/`multiple` when they apply. Asserted on the attribute set through `ui_layout` and `admit_rendered`. | runtime `ui/input.rs` tests | `test` |
| `accept` text: `AnyFile` gives no `accept`; `Only Image [ Pdf, Image ]` gives `image/*,application/pdf,.pdf`. `PickOne` gives no `multiple`; `PickMany` gives `multiple`. | runtime tests | `test` |
| `Input.file [] { accept = "image/*", … }` (a String) and `Only []` are type errors. A `Pick` handler of the wrong payload type (`PickOne Got` where `Got : List Picked -> Msg`) is a type error. Control: the well-typed call type-checks. | types tests | `test` |
| `parse_pick` counts: 4 arguments is `Malformed`; `One` with 2 files is `WrongArity`; 0 files is `Ok(None)` for `One` and `Many`; `Many` with 33 files is `TooMany`, and 32 is accepted. Each refusal dispatches no `msg`. Control: one valid file dispatches the expected `msg` with the exact `Picked`. | runtime `dom/dispatch.rs` tests | `test` |
| `parse_pick` `name`: `""` is `NameEmpty`; 256 bytes is `NameTooLong`, and 255 bytes is accepted; a 255-byte name ending in a multi-byte character is accepted and a 254-byte prefix plus a 2-byte character (256 bytes) is refused, so the count is bytes, not characters. | runtime `dom/dispatch.rs` tests | `test` |
| `parse_pick` `size`: `"9007199254740992"` (2^53) is `SizeOutOfRange`, and `"9007199254740991"` is accepted; `"-1"`, `"1.5"`, `"1e3"`, `"+1"`, `"01"`, `" 1"`, `""` and a 17-digit string are `SizeMalformed`; `"0"` is accepted. | runtime `dom/dispatch.rs` tests | `test` |
| `parse_pick` `mime`: 128 bytes is `MimeTooLong`, and a 127-byte `type/subtype` is accepted; `"text"`, `"/plain"`, `"text/"`, `"a/b/c"`, `"text/plain; charset=utf-8"`, `"text/pla in"` and a non-ASCII byte are `MimeMalformed`; `""` is accepted and yields `mime = ""`. | runtime `dom/dispatch.rs` tests | `test` |
| A refusal carries no input: `PickRefusal` is a fieldless enum with `ALL`, and a test drives each variant with a name and mime holding a marker string and checks the marker is absent from the refusal's `Display`. | runtime `dom/dispatch.rs` tests | `test` |
| A user module named `Ipe.Ui.Input` is `ReservedNamespace` (IPE-N0025). User `Kernel.kernel "Input_file"` is IPE-N0042. | canon tests | `test` |
| Browser: picking one file with `PickOne` dispatches one `msg`; two files under `PickOne` are impossible (no `multiple`); 33 files under `PickMany` dispatch nothing; the `<input>` has no attribute outside the closed set. | `ui-file-pick.spec.mjs` | `browser-e2e` |
| TUI: `Input.file` lays out its label and the fixed note, registers no focus or key handler, and dispatches nothing. | runtime `tui` tests | `runtime-full-features` |
| Layout forging: `Ui.el [ Ui.style k "true" ] [ a, b ]` for every former marker `k` (`__row`, `__col`, `__wrappedrow`, `__grid`, `__paragraph`, `__textcolumn`, `__inline`, `__inline_row`, `__inline_col`, `__gridMin`, `__raw`) renders with no `display:flex`, `display:grid`, `inline-flex` or `inline-block` declaration, emits no `k:` declaration, and reports the refused key through the developer diagnostic. Control: `Ui.row [] [ a, b ]` renders `display:flex;flex-direction:row`. Driven through `ui_layout` and `admit_rendered`. | runtime `ui/render.rs` tests | `test` |
| TUI layout forging: the same forged `Ui.el` lays out its children stacked (the default direction), not side by side, and a forged `__gridMin` leaves the grid at its default columns. Control: `cells_row_` lays them side by side. | runtime `tui/layout.rs` tests (`tui` feature) | `runtime-full-features` |
| `layout_decls` over every `(LayoutKind::ALL ∪ None) × Flow` pair gives the table in "Typed layout attribute", one assertion per cell. A wrapped row, a grid, a row and a column inside `Ui.paragraph` each render inline (`inline-flex` or `inline-grid`), and the paragraph-nesting walker finds no block display below the `<p>`. | runtime `ui/render.rs` tests | `test` |
| No layout reader decodes a style key: a source scan of `src/runtime/rust/src/ui/` and `src/runtime/rust/src/tui/` finds no string literal starting with `__` other than the `__ipe` page names, and no `AttrStyle` key comparison other than `"position"` and `"border-style"`; a scan of `src/stdlib/Ipe/` finds no `style "__`. A planted `"__row"` in a copy of `render.rs` turns it red. | runtime tests | `test` |
| `SafeCssPropertyName::parse_reporting` refuses `__row`, `_x`, `a_b`, `a:b`, `a;b`, `""` and `" "`, each with the developer diagnostic; it accepts `color`, `--ipe-grid-columns` and `margin-top`. | runtime `css_safety.rs` tests | `test` |
| User `Kernel.kernel "Ui_layoutRow"` is IPE-N0042, and `Ui.layoutRow` under `import Ipe.Ui as Ui` is `NameNotExposed` (IPE-N0022). Control: `Ui.row` resolves. | canon tests | `test` |
| Template mirror: `CompileUiAttr::Layout` JSON for every `LayoutKind::ALL` member decodes to the runtime `UiAttribute::Layout` and back, byte-identical. The `Ui.row` and `Ui.column` wrapper bodies over the new `layoutRow` prepend templatize. | backend `emit_ui_template.rs` and runtime `template.rs` tests | `test` |
| Every new layout kernel has a `UiEmitPlan` (the existing `exhaustiveness_partition`). | backend tests | `test` |
| The seal: the goldens that use layout builders build and run after regeneration. | golden drivers | `e2e` (`IPE_E2E=1`) |
| Generated docs match the regenerated output. | — | `stdlib-docs-drift` |

## BUG-CLASSES.md entries touched

| Class | Where it applies here | How it is closed |
|---|---|---|
| Refusal deferred to runtime | An invalid heading level was clamped at render time. | `HeadingLevel` is closed and derived. `Ui.Unsafe.unsafeTaggedNode` literal-tag refusal stays at runtime; see LIMIT. |
| Closed set matched on text with a default row | `tag_for_description` (`_ => "h6"`) and `landmark_tag_for` (`_ => None`). | `NodeTag` and `HeadingLevel` are exhaustive enums with `ALL`. No wildcard remains. |
| Structural marker in the content alphabet | Every `__row`/`__col`/`__wrappedrow`/`__grid`/`__paragraph`/`__textcolumn`/`__gridMin` marker can be forged through public `Ui.style`, and the `__inline*` markers are synthesised into the same key space. | Paragraph and text-column identity moves to `Description`. Row, column, wrapped row and grid move to `AttrLayout(LayoutKind)`. Inline flow becomes a render-context fact. `__gridMin`, which has no producer, loses its reader. No reader of layout looks at an `AttrStyle` key afterwards, which a source scan pins. |
| Closed set matched on text with a default row (layout) | `render.rs` and `tui/layout.rs` decode layout with `match k.as_str()` over marker text, where the default arm is "user CSS". | `LayoutKind` is an exhaustive enum with `ALL`. Its CSS comes from one total function over `(LayoutKind, Flow)`, and no wildcard remains in either reader. |
| Runtime struct reshaped under a compiler mirror (layout) | `UiAttribute` (runtime) mirrors `CompileUiAttr` (backend). | Both gain `Layout` in the same slice, with a round-trip test over `LayoutKind::ALL`. |
| Builtin identity by bare name | `WhiteSpace` must not be a reserved builtin name. | It is an ordinary source union homed at `Ipe.Ui.Font`. The lane checks `is_reserved_builtin_type_name("WhiteSpace")` is false. |
| Runtime struct reshaped under a compiler mirror | `UiDescription` mirrors backend `CompileUiDesc`. | Both change in one slice, with a full-variant round-trip test. |
| Page-config node found by a name page content can carry | Text roles near trusted page nodes. | The roles emit no `id` or `name`, and no id is derived from text. |
| Guard built but not wired; guarantee tested at a pure helper | Admission and content-model tests. | Driven through `ui_layout` and `admit_rendered`, not `render_paragraph_child` or `admit_element` alone. |
| Static model weaker than the runtime predicate | The content-model walker models the HTML parser. | The browser-e2e parse equality is the oracle. |
| Recursion depth chosen by input; quadratic accumulation in Ipê source | Section nesting and the Markdown outline. | Nesting rides the existing `MAX_HTML_DEPTH`, and the level saturates. The Markdown stack is at most 6 deep, with a single pass and one reverse. |
| Tests never compiled or run by CI | TUI tests are `tui`-gated. | They are named under `runtime-full-features`. |
| Vacuous refusal test; a refusal test that matches only the error family | Every name refusal. | Exact variant plus control, as in the table above. |
| Generated drift | New docs pages and goldens. | Regenerated, and the new files are `git add`ed. |
| Untrusted input trusted without a typed parse | Browser-supplied file picks. | `parse_pick` is the one boundary. It produces bounded typed `Picked` values or a closed `PickRefusal`, and refusals dispatch nothing. |
| Unbounded resource a remote party chooses | The file count and each `Picked` field. | `MAX_PICKED_FILES`, `MAX_PICKED_NAME_BYTES`, `MAX_PICKED_SIZE` and `MAX_PICKED_MIME_BYTES`, each with a one-past-the-ceiling refusal test. The count is checked before any field is read. |
| Caller attributes override a builder's fixed attributes | `Input.file`'s `<input>`. | The `<input>` attribute list is built only by the runtime, and user attrs go to the wrapper. Pre-existing: `input_base_` appends caller `control_attrs` after its fixed `type`/`value`. Browsers keep the first duplicate, but the shape is the same; the `Input.file` slice's guardian review checks it. |

| Markup the HTML parser restructures (ancestor exclusions) | `form` in `form`, interactive in `button`, `a` in `a`, and a written flow tag under phrasing. | `RenderCtx.ancestors` plus one `classify` table over typed and written tags; excluded descendants demote; a walker test and the browser parse-equality check pin it. |
| Retag drops a semantic attribute | Content-model demotion to `span`. | The demoted node carries its landmark `role`; a test with a flow control pins it. |

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
     `ContentModel`, `RenderCtx`, `has_content` and the empty-heading rule,
     `WhiteSpace`, `AttrFontWhiteSpace`, and the new helpers;
   - the paragraph and text-column identity moves to `Description`.

   `DescHeading(i64)` and its helpers stay until the section slice, so the
   branch builds alone.

1b. **Ancestor exclusions. Runtime only.** SCEF: correctness (parser
   restructuring).
   - `ui/render.rs` (`Exclusion`, `Exclusions`, `TagClass`, `classify`,
     `RenderCtx.ancestors`, the demotion), the developer-diagnostic reporter
     it shares with the refused style key;
   - `Ui/Unsafe.ipe` doc text is slice 2's, so 1b touches no `.ipe`.

   It runs after slice 1 and must merge before slice 2, which makes nested
   `node descForm` reachable from the safe surface.
2. **Ipe.Ui.Unsafe module. Gated alone (kernels, goldens).** SCEF: trust
   boundary.
   - `Ui/Unsafe.ipe`; `Ui.ipe` (exposure, and the `taggedNode` binding
     removed);
   - `stdlib/src/lib.rs`; the kernels `source_display_name` arm;
   - the capability, N0025 and source-scan tests;
   - `live_e2e.rs`, `stdui_input` golden and regen, `AGENTS.md.in`, the
     guides, docs regen.

   It switches `paragraph`, `textColumn` and `form` to `node` with the
   `descParagraph`, `descTextColumn` and `descForm` kernels (kernels rows plus
   the `emit_ui_plan` and `emit_ui_template` arms). The same edit deletes the
   dead `style "__paragraph" "true"` prepend in `Ui.paragraph` and the
   `__textcolumn` marker on `Ui.textColumn`, and the TUI `__textcolumn`
   reader in `walk_attrs` goes with it. A source scan over `src/stdlib/Ipe/`
   pins that no `style "__paragraph"` or `style "__textcolumn"` remains; slice
   7 widens it to every `style "__`. `ui_paragraph_` builds
   `Element::Node(DescParagraph, …)`. It needs slices 1 and 1b merged first.
3. **Section headings and text roles wiring. Gated alone (kernels, goldens).**
   The empty-heading rule's runtime half (`has_content` and the depth skip)
   lands in slice 1. This slice wires the Ipê side and the goldens.
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
6. **Ipe.Ui.Input module and `Input.file`. Gated alone (kernels, goldens).**
   SCEF: trust boundary (browser-supplied input).
   - `Ui/Input.ipe` (the 18 aliases plus the `Input.file` types);
   - the Input entries removed from `env.rs`;
   - `stdlib/src/lib.rs`;
   - the `InputFile` kernel and its `emit_ui_plan` row;
   - runtime `ui/input.rs`, `html.rs` (`OnPick`), `dom/dispatch.rs`
     (`parse_pick`), `tui/focus.rs`, `tui/layout.rs` (the note), and
     `web/client.js` (the `ipe-pick` driver);
   - the `stdui_input` golden additions and regen, `Ui.Input.md` regen, the
     `AGENTS.md.in` upload pattern;
   - `ui-file-pick.spec.mjs`, plus a file control in the `ui-layout` example.

   It runs after the Unsafe move, and after the Font slice, whose
   native-to-compiled migration it repeats. It also runs after the browser
   check, which first adds `ui-layout` to `run.sh` and `ci.yml`. It runs
   `browser-e2e` locally.

7. **Typed layout attribute. Gated alone (kernels, goldens, template
   mirror).** SCEF: correctness (forged structure).
   - the files under "Typed layout attribute slice" in "Files touched";
   - the goldens regenerated with `cargo run -p regen-goldens`.

   It runs after slice 1, which introduces `Flow`'s neighbour
   `ContentModel` and removes the paragraph and text-column markers, and
   after slice 6, the last slice that edits `kernels/src/lib.rs`, `Ui.ipe`
   and the goldens. It shares `ui/render.rs`, `tui/layout.rs` and
   `ui/template.rs` with slice 1 and `kernels/src/lib.rs` with slices 2, 3,
   4 and 6, so it is file-disjoint from none of them.

Slices 2, 3, 4, 6 and 7 all edit `kernels/src/lib.rs` and the goldens, so they
are strictly sequential. Slice 1 also edits
`tui/layout.rs`, `html.rs` and `ui/render.rs`; slice 6 starts from its merge.

## LIMIT

- **Runtime-only refusal for free-form tags.** `Ui.Unsafe.unsafeTaggedNode` with a
  literal denied tag (`"script"`) is still refused only at runtime, as an empty
  element. Refusing it in `ipe` needs one tag grammar shared by the compiler and
  the vendored runtime. The runtime crate cannot depend on compiler crates, so
  that is a separate design (generating the runtime denied-tag table from a
  compiler leaf, with an equality test). It is out of this spec's consent.
- **TUI white-space.** The TUI models wrap and newline preservation, not CSS
  space collapsing. This is documented in the `Font.whiteSpace` doc.
- **Invisible non-White_Space characters.** A heading made only of
  characters such as U+200B or U+FEFF counts as present and renders an `hN`
  that looks empty. Treating them as absent would mean choosing a character
  class beyond Unicode White_Space. No Unicode property names "invisible"
  exactly, so the rule stays on White_Space, and the `Ui.section` doc names
  this case.
- **File content.** `Input.file` delivers metadata only; it adds no
  file-content reading or upload path. The existing `Ui.onFile` data-URL path
  is unchanged. A later API that reads picked files is a new surface and
  needs its own consent.
- **Client-declared metadata.** `name`, `size` and `mime` are what the
  browser reports. The parse bounds and shapes them; it cannot prove them
  true.
- **`Ui.gridColumns` in the TUI.** `ui_grid_columns_` writes
  `--ipe-grid-columns`, which the TUI never reads, and the TUI's `__gridMin`
  reader has no producer. So `Ui.gridColumns n` has no TUI effect today. The
  layout slice deletes the forge-only reader. Making `Ui.gridColumns` drive
  the TUI grid means giving column count its own typed attribute read by both
  renderers. That changes `Ui.gridColumns`'s meaning in the TUI, so it is a
  separate fidelity change, not part of the forging fix.
- **`textColumn` tag.** `textColumn` keeps its `<section>` tag (no accessible
  name, so no landmark) and does not advance the heading level.

## CONSIDERATION:

This item is held at ≥95% confidence and is outside this spec's scope.

### Closed tags for runtime builders

The runtime builders (`button`, `link`, `image`, the `Input` controls) build
`Element::TaggedNode` with `'static` literal tag strings, which are only
proven admitted by the test above. Moving them to an `Element` variant that
carries a closed `NodeTag` would leave `Element::TaggedNode(String, …)`
constructed only by `ui_tagged_node_`. The "safe surface never builds a
free-form tag" property would then hold by type, not by test. That is about
57 match sites across 8 runtime files, so it is its own runtime-only spec.

## DECISIONS NEEDED:

None.
