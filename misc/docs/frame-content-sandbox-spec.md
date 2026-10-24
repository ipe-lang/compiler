# Framed content never shares the app's origin

Designed by: security-soundness-guardian
Reviewed by: security-soundness-guardian (anchors and order re-checked on `origin/main` `a95c1c1af`)

Scope: the runtime's HTML render sink, its SSE diff, and both clients' patch
appliers (`client.js`, the wasm client). Closes the frame residual of
`misc/docs/code-review-autofocus-spec.md` (the iframe section). No new CLI
surface, no new syntax, no new stdlib API, no `unsafe`. The change is a
deliberate pre-public break in what an app's `iframe`, `embed`, `object` and
`frame` elements do (see "Breaking change").

## Problem

The runtime owns when focus moves (BUG-CLASSES 8db, 8dy): it strips `autofocus`
from every fragment before its nodes connect, and focuses only for this tab's
own event. A framed document is out of reach of that strip. When an app renders
`Html.iframe [ Attr.src "/somewhere" ] []` (or `Html.node "IFRAME"`, `embed`,
`object`) pointing at a document served from the app's own origin, the framed
document is parsed by the browser, not by the runtime's holder:

- its `autofocus` candidate is delegated by the HTML autofocus algorithm to the
  top document, so a render the user never caused (a timer, another tab's frame)
  moves focus into the frame;
- more broadly, its scripts run with the app's origin: they can read and drive
  the app's DOM through `window.parent`, call `focus()` on any app control, read
  same-origin storage and cookies the app's own pages read, and post to the
  app's endpoints with the app's credentials.

The runtime holds no fact that proves a URL's origin differs from the app's:
there is no trusted public-origin setting, the `Host` header is wrong behind a
proxy, and a relative, protocol-relative, whitespace-only or redirected URL can
all resolve to the app's origin. "Cross-origin" is therefore never provable at
the render sink, and any rule keyed on it fails open.

## Class-closing property

**No document loaded by an element the safe surface renders can share the
app's origin.** Concretely, at every boundary that can put such an element in
the live DOM (server render, SSE diff, both clients' patch appliers):

1. every `iframe` (tag matched ASCII-case-insensitively) carries exactly one
   `sandbox` attribute whose tokens never include `allow-same-origin` or
   `allow-popups-to-escape-sandbox`, so its document gets an opaque origin and
   no popup it opens regains the real one;
2. every other frame-loading element — `embed` (loads `src`), `object` (loads
   `data`), `frame` (loads `src`) — that carries its loading attribute at all
   (any key case, any value, the empty value included) is refused, because the
   browser offers it no sandbox and the runtime cannot prove its URL foreign;
3. the patch wire cannot express removing or widening an iframe's sandbox, and
   cannot give a refused element its loading attribute after insertion.

With the property held, the framed document has no origin in common with the
app: autofocus delegation, `window.parent` DOM access and same-origin storage
all stop by the browser's own origin checks, not by a list of effects the
runtime thought of (BUG-CLASSES 8ch, "enumerate the sinks").

Why `allow-popups-to-escape-sandbox` is dropped too: a popup opened from a
sandboxed frame with that token loads its URL with the URL's real origin, which
for a same-origin URL is the app's, and reaches the app through
`window.opener`. It is the second way back to the shared origin.

Why refusal on presence, not on a non-empty value: `embed src=" "` and
`object data=" "` parse to the document's base URL, i.e. the app itself.

## Design

### 1. One policy, in `html.rs`

A pure, total function and two typed values (names are the implementer's to refine,
the shape is binding):

```rust
/// What the frame rule makes of an element before it renders.
pub(crate) enum FrameVerdict<'a> {
    /// Not a frame-loading element: render as is.
    NotAFrame,
    /// An `iframe`: render with this one canonical `sandbox` value, and
    /// drop every `sandbox` pair the app wrote.
    Sandboxed(SandboxTokens),
    /// A frame-loading element carrying its loading attribute.
    Refused(ElementRefusal),
}

/// A `sandbox` value that can never grant the app's origin back: only the
/// known tokens, ASCII-lowercased, deduped, in `SANDBOX_TOKENS` order, with
/// `allow-same-origin` and `allow-popups-to-escape-sandbox` unrepresentable.
pub(crate) struct SandboxTokens(/* bitset over SANDBOX_TOKENS */);

pub(crate) fn frame_verdict<'a>(
    tag: &str,
    attrs: impl Iterator<Item = (&'a str, &'a str)>,
) -> FrameVerdict<'a>;
```

- `SANDBOX_TOKENS` (const array, the SSOT): `allow-downloads`, `allow-forms`,
  `allow-modals`, `allow-orientation-lock`, `allow-pointer-lock`,
  `allow-popups`, `allow-presentation`, `allow-scripts`,
  `allow-storage-access-by-user-activation`, `allow-top-navigation`,
  `allow-top-navigation-by-user-activation`,
  `allow-top-navigation-to-custom-protocols`. The two forbidden tokens are NOT
  in the table, so `SandboxTokens` cannot hold them (make the invalid state
  unrepresentable — no "filter later" step).
- Tag and attribute keys are compared with `eq_ignore_ascii_case`, never Unicode
  case folding (BUG-CLASSES 8bt: U+212A KELVIN SIGN lowercases to `k`). A key
  or token holding a non-ASCII byte is never equal to a table entry.
- Tokens are split on ASCII whitespace (`\t \n \x0C \r` and space), as the
  browser splits them; every case-variant `sandbox` key is read, the last one
  wins (the render sink's existing exact-key last-wins rule, applied across
  case, because the browser keeps only one of them and which one depends on
  the parser path — never trust that choice). An absent or empty value, and
  `boolAttribute "sandbox" True` (painted `sandbox="true"`, an unknown token),
  give `SandboxTokens` empty, painted `sandbox=""`.
- `FRAME_LOADERS` (const array, the SSOT): `("embed", "src")`,
  `("object", "data")`, `("frame", "src")`. A matching tag carrying the paired
  key (any ASCII case, any value) is `Refused(ElementRefusal::UnsandboxableFrame)`.
- New `ElementRefusal::UnsandboxableFrame` variant, with this doc text (the
  typed refusal's wording; see "Refusal wording"):

  > An `embed`, `object` or `frame` that names a document to load. The browser
  > gives these elements no sandbox and the runtime holds no proof that the
  > document's origin differs from the app's, so the loaded document could act
  > as the app. Use `Html.iframe`, which the runtime always sandboxes.

### 2. Admission takes the attributes

`admit_rendered_in(ctx, tag, kids)` gains a required `attrs: &[Attribute<M>]`
argument and calls `frame_verdict` first; `Refused(r)` returns `Err(r)`. Every
caller is forced by the compiler to pass the element's attributes, so no walker
can judge an element without its frame verdict:

- the render sink (`html.rs`, the `HElement` arm near the existing
  `let Ok(rendered) = admit_rendered_in(ctx, tag, kids) else { return; };`);
- `dom/diff.rs` `diff_node_depth` (both sides), `is_refused_element`
  (an element gaining `data`/`src` therefore replaces the parent and the new
  side omits it, the existing admission-change path), and `for_each_autofocus`.

The constructors keep their defence-in-depth check (PRINCIPLES "Defend in
depth"): `admit_element` gains the same `attrs` argument and verdict, and its
callers pass them — `ui/helpers.rs` `html_node_` (refused → `HText("")`, as
today) and `ui/render.rs` (the two `admit_element(tag, &html_kids)` sites before
`Html::HElement`). `ui/helpers.rs` `ui_tagged_node_` builds a Ui node whose
attributes are Ui attributes; its frame check rests on the `ui/render.rs`
lowering, which every Ui tree passes through before it becomes `Html`; state
this in a one-line comment at `ui_tagged_node_`.

### 3. The sink paints one canonical sandbox

For `Sandboxed(tokens)` the render sink drops every pair whose key is an ASCII
case variant of `sandbox` and emits exactly one `sandbox="<tokens>"` (the
canonical spelling, attribute-escaped like every value). The diff's attribute
collector reads the same canonical value for an `iframe`, so the old and new
side always both carry `sandbox`: an app going from `allow-scripts` to no
sandbox attribute diffs to `sandbox` set to `""`, never to a removal, and a
case-variant `SANDBOX` the app adds or drops diffs to nothing.

The collector must be ONE function shared by the sink and the diff
(BUG-CLASSES 8dc "a second collector of a node's attributes"). The unmerged
branch `fix/focus-follows-own-action` (commit `ccde7d5b2`) already introduces
`html::attribute_pairs` as that one collector and moves the diff onto it; the
frame canonicalisation is a step inside it (`attribute_pairs(tag, attrs)`),
not a third loop. See "Sequencing".

### 4. The patch delta is typed

`Patch.attrs: HashMap<String, String>` with `""` meaning "remove" is the
in-band sentinel of BUG-CLASSES 8dc: the canonical empty sandbox `""` would
ship as a REMOVAL of the sandbox — exactly the escape this spec closes — and
`value=""`, `alt=""` already patch wrongly today. The delta becomes
`HashMap<String, Option<String>>`: `None` removes, `Some("")` sets the empty
value; on the wire a removal is JSON `null`, a set is a string; each client
refuses a value that is neither. This is the design of `ccde7d5b2`; this change takes
it, it does not invent a second encoding.

### 5. Both clients fence frames before their nodes connect

Defence in depth, and the only boundary that also covers
`Ipe.Html.Unsafe.unsafeRaw` markup carried by a patch:

- **Detached holder.** `client.js` `__ipeParseFor` and wasm
  `parse_detached` (`wasm/mod.rs`) already strip `autofocus` from the detached
  holder before its nodes connect (a detached holder loads no frame). Beside
  that strip, one `querySelectorAll("iframe, embed, object, frame")` over the
  holder (and a template's `.content`): each `iframe` gets its `sandbox`
  rewritten to the canonical tokens; each `embed`/`object`/`frame` carrying
  its loading attribute is removed. One query, never a per-node walk
  (BUG-CLASSES 8dy).
- **Attribute patch loop.** `client.js` `__ipeApplyPatches` and wasm
  `apply_patches`: on an element whose `localName` is `iframe`, a `sandbox`
  removal is refused and a `sandbox` set is re-canonicalised; before any `src`
  set on an `iframe` that has no `sandbox` attribute, `sandbox=""` is written
  first (the sandbox flags bind at navigation, so the order matters); a
  `src`/`data` set on `embed`/`object`/`frame` is dropped. wasm calls the
  `html.rs` policy directly (same crate); `attr_write` in `wasm/mod.rs`
  returns the typed `AttrWrite` for these cases, never a bool.
- **SSOT for the JS mirror.** `client.js` cannot import Rust, so it holds a
  literal copy of `SANDBOX_TOKENS` and `FRAME_LOADERS` in one marked
  declaration; a native test in `html.rs` reads `client.js` through
  `include_str!`, extracts that declaration, and asserts equality with the Rust
  constants (PRINCIPLES "Single source of truth": assert equality, never
  hand-sync). The test lives in `html.rs` so `web/mod.rs` is not touched.

## Files touched

Runtime:
- `src/runtime/rust/src/html.rs` — `FrameVerdict`, `SandboxTokens`,
  `SANDBOX_TOKENS`, `FRAME_LOADERS`, `frame_verdict`,
  `ElementRefusal::UnsandboxableFrame`, `admit_element` and
  `admit_rendered_in` take `attrs`, sink canonical sandbox, collector step,
  native tests.
- `src/runtime/rust/src/dom/diff.rs` — callers pass `attrs`; typed delta;
  native tests.
- `src/runtime/rust/src/ui/helpers.rs` — `html_node_` passes attrs; comment at
  `ui_tagged_node_`.
- `src/runtime/rust/src/ui/render.rs` — the two `admit_element` sites pass
  attrs.
- `src/runtime/rust/src/web/client.js` — holder fence, patch-loop rules, typed
  `null` removal, the token/loader declaration.
- `src/runtime/rust/src/wasm/mod.rs` — `parse_detached` fence, `apply_patches`
  and `attr_write` rules on the typed delta, wasm lib tests.
- `src/runtime/rust/src/web/style_inject.rs` — its patch test (around line
  1421) moves to the typed delta.
- `src/runtime/rust/tests/wasm_dom_paint.rs` — two DOM paint tests.

CI claims (test counts only):
- `.github/ci/test-claims.yml` — `expect_tests` for the wasm lib cell and
  `wasm_dom_paint`.
- `.github/workflows/ci.yml` — the matching `wasm_test_count.py N` pins in the
  `wasm-floor` job.

Browser e2e:
- `examples/shapes/web/focus-across-patch/src/Main.ipe` — a frame mode.
- `tools/scripts/browser-e2e/focus-across-patch.spec.mjs` — the frame refusal
  test.

Stdlib doc and generated docs (no API change):
- `src/stdlib/Ipe/Html.ipe` — doc comments of `iframe` and `embed`, and the
  module header's "renders nothing" list, state the rule.
- `docs/reference/stdlib/Html.md` — regenerated, never hand-edited.
- `docs/guide/ui.md` — one paragraph under the existing autofocus/refusal text.

Checklist:
- `misc/plugins/ipe/skills/lane-brief/BUG-CLASSES.md` — new class 8em (8dz is taken; if 8em is taken by the time this lands, the next free id), and the
  8dc / 8dy examples (see below).

Not touched: `web/mod.rs` (`CLIENT_JS` is `include_str!` of `client.js`; its
SRI pin is recomputed by the existing build, the implementer confirms no hand-pinned
hash), `src/stdlib/Ipe/Html/Attributes.ipe` (no new attribute builder), any
compiler crate, any IPE diagnostic.

## Refusal tests (each must go red with its rule removed)

Native, `src/runtime/rust/src/html.rs` `#[cfg(test)]` — CI job `test-run`
(workspace nextest archive):
1. `an_iframe_without_sandbox_renders_an_empty_sandbox` — `Html.iframe`
   (`node "iframe"`) and `node "IFRAME"` both paint exactly one `sandbox=""`.
2. `every_case_of_sandbox_folds_into_one_canonical_value` — `sandbox`,
   `SANDBOX`, `SandBox` on one element paint one `sandbox` with the last value's
   canonical tokens.
3. `allow_same_origin_never_reaches_the_page` — `"allow-scripts
   ALLOW-SAME-ORIGIN allow-same-origin allow-popups-to-escape-sandbox"` paints
   `sandbox="allow-scripts"`; a token with U+212A or a NUL is dropped.
4. `unknown_sandbox_tokens_are_dropped` — and `boolAttribute "sandbox" True`
   paints `sandbox=""`.
5. `a_frame_loader_with_its_url_renders_nothing` — `embed src`, `object data`,
   `frame src`, with keys `SRC`/`Data`, values `""`, `" "`, `"/"`,
   `"https://x"`; under an `svg` and a `foreignObject` ancestor; each renders
   nothing; `embed`/`object` without the loading attribute still render.
6. `html_node_refuses_a_frame_loader` — the `ui/helpers.rs` constructor path.
7. `client_js_frame_table_matches_the_runtime` — the SSOT equality test.

Native, `src/runtime/rust/src/dom/diff.rs` `#[cfg(test)]` — CI job `test-run`:
8. `dropping_an_iframe_sandbox_patches_an_empty_sandbox` — `allow-scripts` to
   absent yields `Some("")`, never `None`.
9. `a_case_variant_sandbox_change_patches_nothing`.
10. `an_embed_gaining_its_url_replaces_the_parent_without_it` — the new
    side's HTML omits the `embed`, no attribute patch names `src`.
11. `a_removal_is_null_and_an_empty_set_is_a_string` — serde encode then decode of the
    delta (the `ccde7d5b2` test if already landed; otherwise this one).

wasm lib, `src/runtime/rust/src/wasm/mod.rs` — CI job `wasm-floor`, wasm lib
cell:
12. `a_patch_never_removes_an_iframe_sandbox` — `attr_write` on `iframe`
    refuses `sandbox` removal and re-canonicalises a set.
13. `a_patch_never_gives_a_frame_loader_its_url` — `src` on `embed`, `data` on
    `object` dropped.
14. `an_iframe_src_patch_sandboxes_first` — no `sandbox` present: the write
    sequence is `sandbox=""` then `src`.

wasm DOM paint, `src/runtime/rust/tests/wasm_dom_paint.rs` — CI job
`wasm-floor`, "DOM paint (headless Chrome)" step:
15. `a_patched_iframe_connects_sandboxed` — a patch fragment with a bare
    `<iframe src="/">` connects with `sandbox=""`.
16. `a_patched_embed_with_a_url_never_connects` — `<embed src="/">` and
    `<object data="/">` in a fragment connect nothing.

The wasm lib and DOM paint counts in `test-claims.yml` and `ci.yml` rise by
exactly 3 and 2 from whatever value they hold when this change starts (they move
with the autofocus branch; read them, never copy a number from this spec —
BUG-CLASSES 8cb).

Browser e2e, `tools/scripts/browser-e2e/focus-across-patch.spec.mjs` — CI job
`browser-e2e`:
17. `focus-across-patch: a same-origin frame added by a render the tab did not
    cause never takes focus` — the fixture gains a `frame` query mode: loaded
    as `/?noauto&tick&frame`, the tick render adds
    `Html.iframe [ Attr.src "/" ] []` (the fixture's own root, which carries
    `autofocus`). Assert `document.activeElement` stays `BODY`, the iframe has
    `sandbox=""`, and its `contentDocument` is unreachable (`null`, opaque
    origin). Red-first: with the sink's sandbox step and the client fence both
    removed, the frame's autofocus takes focus (`activeElement` is the
    `IFRAME`); the implementer runs that mutation and records the red.
18. `focus-across-patch: a raw iframe in a patch connects sandboxed` — the
    same mode with the frame inside `Ipe.Html.Unsafe.unsafeRaw` markup added by
    the tick; asserts `sandbox` present after connection (pins the client
    fence alone; red with the fence removed).

## Refusal wording, and why no IPE code

IPE diagnostics (`src/compiler/diagnostics`, `explain/*.md`) are compile-time
codes; the E/F/I/L/N/P/S/T families carry no runtime family, and the
compiler cannot see a tag spelled at runtime (`Html.node tagFromModel`). Every
existing `ElementRefusal` (`UnsafeName`, `Unclosable`, `UntrustedScript`,
`UntrustedStyle`, `ScriptOutsideData`) is a silent render-nothing, documented
in `Html.md` ("renders nothing"). The frame rule follows that contract: the typed refusal
is the new `ElementRefusal::UnsandboxableFrame` variant (doc text in Design 1),
and the user-facing wording lives in the `Html.ipe` doc comments:

- on `iframe`: "Always sandboxed. The runtime paints `sandbox` on every
  `iframe`, keeping only the browser's known tokens. `allow-same-origin` and
  `allow-popups-to-escape-sandbox` are always removed, so the framed document
  never shares the app's origin. Opt into other tokens with
  `Attr.attribute "sandbox" "allow-scripts allow-forms"`."
- on `embed` and in the module's "renders nothing" list: "An `embed` with a
  `src`, an `object` with a `data`, or a `frame` with a `src` renders nothing:
  the browser gives them no sandbox and the runtime cannot prove the document
  they load comes from another origin. Use `iframe`."

A compile-time lint that flags a literal `Html.node "embed"` with `src` would
be new diagnostic surface; it is not part of this spec.

## Existing uses (checked with `rg`, not guessed)

- `src/stdlib/Ipe/Html.ipe`: the definitions `iframe = node "iframe"` and
  `embed = voidNode "embed"`; no `object` or `frame` builder.
- `docs/reference/stdlib/Html.md`: generated listing of the two.
- No use of `Html.iframe`, `Html.embed`, or `Html.node` with `iframe`, `embed`,
  `object` or `frame` in `examples/`, `tools/code-review/`, tests, goldens or
  the playground `index.html`.
- `Web.embed` (`KernelFn::WebEmbed`) mounts an app and is unrelated.
- Patch consumers of `Patch.attrs`: `dom/diff.rs`, `wasm/mod.rs`
  `apply_patches`, `client.js` `__ipeApplyPatches`, the `style_inject.rs`
  test. `ui/widget.rs` only documents the mechanism. No other reader of the
  wire shape.

So the break hits no in-tree program; the generated docs change through regen.

## Breaking change

- Every `iframe` is sandboxed; an app that framed its own pages and relied on
  `window.parent` access, same-origin storage, or scripts running (without
  opting into `allow-scripts`) stops working.
- `allow-same-origin` and `allow-popups-to-escape-sandbox` cannot be granted.
- `embed`/`object`/`frame` that load anything render nothing (video players,
  PDF viewers through `object`).

Allowed by the pre-public stance; confirmed as DECISION-PENDING 2.

## BUG-CLASSES entries

- **8dc** (in-band sentinel / second collector) — touched and closed for this
  change: the typed `Option<String>` delta removes the sentinel that would turn
  the canonical `sandbox=""` into a removal; the sandbox canonicalisation is a
  step in the one collector. Add this as an example.
- **8dy** (native effect fires on insertion) — touched: a frame is a native
  effect source the strip cannot reach; the fence sits beside the strip in the
  same detached holder. Add the frame to its "every path that inserts markup"
  check.
- **8bt** (ASCII-only case folding) — applied, not changed: tag, key and token
  comparisons are `eq_ignore_ascii_case`, pinned by test 3.
- **8ch** (hand-listed sinks) — applied: the property is an origin boundary
  the browser enforces, not a list of frame effects.
- **New 8em — "an element whose loaded document escapes the render sink"**:
  a sanitiser that judges the markup it renders is blind to a document an
  element tells the browser to fetch and parse (`iframe`, `embed`, `object`,
  `frame`); on the app's origin that document is the app. Rule: every
  document-loading element is either given an opaque origin by construction
  (`sandbox` without `allow-same-origin`) at every render and patch boundary,
  or refused when it carries its loading attribute, since a URL's origin is
  not provable at the sink. · Check: for each tag the sink admits, does the
  browser load and run a document from one of its attributes? · Test: each
  loader with its URL renders nothing; an iframe always paints a canonical
  sandbox; a patch can neither remove the sandbox nor add a loader's URL. ·
  e.g. this spec.

## Sequencing (file disjointness)

- The autofocus change merged to `main` as #3793 (`3db1be526`); this change
  branches off a freshly fetched `origin/main`. It is not split into a
  disjoint early half, because `admit_rendered_in`'s new argument forces the
  `diff.rs` callers into the same commit.
- The typed delta and the one collector (Design 3, 4) are NOT on `main`:
  `dom/diff.rs:26` still reads `pub attrs: HashMap<String, String>`. They exist
  only in commit `ccde7d5b2` on the held branch `fix/focus-follows-own-action`,
  whose other commits (merge-base `9c2f8899c`, `abb2895b4..6486d9373`) carry
  the focus-as-state design #3793 superseded; that branch is not landed.
  Decided order: the FIRST commit of this change ports `ccde7d5b2`'s typed
  delta and `html::attribute_pairs` alone, crediting that commit, and the
  branch is then closed. Ported: `Patch.attrs` as
  `HashMap<String, Option<String>>`, the one collector in `html.rs` used by
  the sink and `dom/diff.rs`, the `null`-or-string reader in `client.js` and
  `wasm/mod.rs`, and the `style_inject.rs` patch test. NOT ported: anything of
  `dom/focus.rs` (absent on `main`), `dom/dispatch.rs`, `wasm/widget.rs`, or
  its stamped-id alphabet changes, which target the superseded design. Only
  one encoding of the delta exists on `main` after the first commit.
- `focus-drop-on-patch-spec.md` edits `client.js` and `dom/diff.rs` too: it
  runs after this change merges, off the then-current `main`.
- `code-review-bounded-refuse-draft-spec.md` (the 413 reply marking in
  `client.js`) also runs after this change merges.
- Kernels, goldens and arity tables are not touched; the emitted Rust of user
  programs does not change (the runtime crate does).

## Stop conditions (exit with `LIMIT:`)

- The port of `ccde7d5b2` needs a file outside the list above, or any part of
  `dom/focus.rs`: stop; the delta design is re-planned against `main`.
- Canonicalising the sandbox needs a new `Ipe.Html.Attributes` builder, a
  config value, an env var or any trusted-origin fact: stop
  (DECISION-PENDING 1; new surface needs the maintainer).
- A test in the list cannot be made red by removing its rule: stop and report
  the test as vacuous rather than shipping it.
- `CLIENT_JS`'s SRI pin turns out hand-pinned in `web/mod.rs`: stop, since
  `web/mod.rs` is owned by the shutdown change running beside this one.

## DECISION-PENDING (maintainer)

1. **A trusted public origin.** Granting a frame `allow-same-origin`, or
   admitting an `embed`/`object` whose URL is truly cross-origin (a video
   player, a PDF), needs a fact the runtime does not have: the app's public
   origin, or an allow-list of foreign origins, from config or a capability.
   That is new surface. Until the maintainer decides, both are refused
   fail-closed. Opting an iframe into other tokens (`allow-scripts`,
   `allow-forms`, ...) needs no new API: `Attr.attribute "sandbox" "..."`
   already exists.
2. **Confirm the breaking stance** in "Breaking change".

## LIMIT and residuals

- **First-paint `unsafeRaw`.** An `Ipe.Html.Unsafe.unsafeRaw` iframe in the
  server's first paint is parsed by the browser directly, before any client
  code runs; the fence covers only patches. `unsafeRaw` is the named,
  capability-disclosing escape hatch, outside the safe surface this property
  speaks for; its doc gains one sentence saying framed content in raw markup is
  the author's to sandbox.
- **An opted-in `allow-scripts` frame** runs script with an opaque origin: it
  can still call `focus()` inside itself, which browsers may let move top-level
  focus into the frame. That is the app's explicit opt-in, documented on
  `iframe`; cross-origin focus without user activation is restricted by
  browsers, not by this runtime.
- **Same-origin content from another server** on the app's host (a sibling
  path behind the same proxy) is the deployment's concern; the property holds
  for it too, since it never relies on the URL.
- **CSP.** `object-src`/`frame-src` directives cannot express "not `'self'`
  but cross-origin allowed"; the response headers stay as they are
  (`IPE_WEB_FRAME_ANCESTORS`, `X-Frame-Options: SAMEORIGIN` govern who frames
  the app, not what it frames). A `object-src 'none'` header is a possible
  second boundary once DECISION-PENDING 1 is settled.
- `fencedframe` takes no URL attribute (its config is script-only) and has an
  opaque origin by design; `portal` is not shipped by browsers. Neither is
  listed; a test pins that `FRAME_LOADERS` and the sandbox rule cover exactly
  the four tags above, so adding one is a reviewed change.
