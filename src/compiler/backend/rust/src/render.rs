//! The deterministic renderer: lays a [`crate::doc::Doc`] out to bytes matching
//! `rustfmt --edition 2024 --style-edition 2024` for the construct shapes the
//! emitter produces. It is NOT a general rustfmt — only the emitter's shapes.
//!
//! Two layout mechanisms:
//!
//! * [`Doc::Group`] is flat-if-fits-else-break: if the group's flat rendering
//!   fits the remaining width AND it contains no [`Doc::HardLine`], every
//!   [`Doc::Line`] / [`Doc::Softline`] in it lays out flat (a space / nothing);
//!   otherwise every soft break in it becomes a newline plus the current indent.
//!   A [`Doc::HardLine`] always breaks and forces every enclosing group broken —
//!   that keeps a statement block (`{ let x = …; x }`) from ever inlining, while
//!   an inline structure (`(a, b)`, `if c {1} else {2}`, carrying only soft
//!   `Line`s) flattens when it fits.
//!
//! * [`Doc::Chain`] is rustfmt's binary-operator-chain layout, derived
//!   empirically from real rustfmt bytes and proven byte-exact against the
//!   golden corpus (`param_patterns`, `probe_tinytail`, `probe_callbreak`,
//!   `order2`): line-1 packs the maximal left-nested prefix that fits the width;
//!   the first operator that would overflow breaks, and from there EVERY
//!   subsequent operator breaks one-per-line to a single shared indent
//!   (chain-begin-line indent + 4), non-accumulating — with the sole exception
//!   that an operator following a multiline operand glues to that operand's
//!   closing-line column while the chain has not yet broken.

use crate::doc::{ChainOperand, Doc};

/// Rendering configuration. Mirrors the `rustfmt` knobs the golden harness pins.
#[derive(Debug, Clone, Copy)]
pub struct RenderConfig {
    /// The maximum line width (`rustfmt` `max_width`, default 100).
    pub max_width: usize,
    /// Columns that must stay free at the end of the current line — the trailing
    /// delimiter(s) `rustfmt` reserves after the construct being laid out (the
    /// `,` after a one-per-line list element, the `),` after the sole argument of
    /// an enclosing call). `rustfmt` carries this as the `Shape`'s reduced width;
    /// a node's fit test subtracts it so a construct that would end exactly at
    /// `max_width` still breaks to leave room for its trailing delimiter. Reset to
    /// `0` whenever a construct opens its own delimiters (its interior lines are
    /// measured against the full width; the reserve applies only to the LAST line
    /// the construct shares with the enclosing delimiter).
    pub reserve: usize,
    /// Set while rendering a block body that `rustfmt`'s `Shape`-width recursion gave
    /// up on (see [`render_brace_body_broken`]'s SHAPE-BUDGET GIVE-UP). `rustfmt`
    /// then keeps the whole body on its ORIGINAL single line — so even an
    /// unconditional [`Doc::HardLine`] (a statement-block separator) lays out as a
    /// single space here, inlining a `{ let x = …; x }` block onto the one line.
    inline_hard: bool,
}

impl Default for RenderConfig {
    fn default() -> Self {
        Self {
            max_width: 100,
            reserve: 0,
            inline_hard: false,
        }
    }
}

impl RenderConfig {
    /// This config with the trailing-delimiter `reserve` set to `n`.
    const fn with_reserve(self, n: usize) -> Self {
        Self { reserve: n, ..self }
    }

    /// This config with the trailing-delimiter `reserve` cleared — used when a
    /// construct opens its own delimiters, so its interior lines are measured
    /// against the full width.
    const fn no_reserve(self) -> Self {
        self.with_reserve(0)
    }

    /// The effective right margin for a construct's LAST line: `max_width` less the
    /// reserved trailing-delimiter columns.
    const fn margin(self) -> usize {
        self.max_width.saturating_sub(self.reserve)
    }
}

/// The number of columns a chain's broken operators indent past the chain's
/// begin-line indent. `rustfmt` uses one block-indent step (4).
const CHAIN_BREAK_INDENT: usize = 4;

/// `rustfmt`'s `fn_call_width` (default 60): the maximum width of a function-call
/// (or constructor / tuple) ARGUMENT LIST — the text between the parentheses,
/// excluding the callee and the delimiters — that `rustfmt` keeps on one line.
/// A call whose flat argument list exceeds this breaks one argument per line even
/// when the whole line would still fit `max_width`. Macro (`format!` / `vec!`)
/// argument lists use a different (wrap-to-`max_width`) layout and are not gated
/// by this width.
const FN_CALL_WIDTH: usize = 60;

/// Render `doc` to a string starting at column `col` with block indent `indent`.
/// `col` is where the document's first character will be placed (used for the
/// fit test); `indent` is the number of leading spaces a broken line receives.
pub fn render(doc: &Doc, cfg: RenderConfig) -> String {
    let mut out = String::new();
    render_at(doc, cfg, 0, 0, false, &mut out);
    out
}

/// Render `doc` as if its first character lands at column `col` with the given
/// block `indent` for any line it breaks onto. Used to lay out a construct that
/// is spliced after a fixed prefix already occupying the start of its line — the
/// `IpeStringify` `format!` body, which begins after `        ` (record) or after
/// the `… => ` arm head (enum), and whose broken argument lines nest from the
/// enclosing block indent, not from `col`. The returned string carries no leading
/// prefix for `col` (the caller already wrote it); every broken line carries its
/// own absolute indentation.
pub fn render_seeded(doc: &Doc, cfg: RenderConfig, indent: usize, col: usize) -> String {
    let mut out = String::new();
    render_at(doc, cfg, indent, col, false, &mut out);
    out
}

/// The current column after the last newline in `out`, i.e. how many characters
/// sit on the line so far. This is the live cursor the fit tests measure.
fn current_col(out: &str) -> usize {
    out.rfind('\n').map_or(out.len(), |nl| out.len() - nl - 1)
}

/// The column the next character will land on. Once anything has been written to
/// `out`, the live cursor ([`current_col`]) is authoritative — including after a
/// break reset it to the fresh line's indent. The seed `col` is used only for an
/// empty buffer (the render root, or a `fits` scratch measured from `start_col`),
/// where there is no cursor yet. Taking `max` here would leak a pre-newline
/// column past a break, so we deliberately prefer the live cursor.
fn eff_col(out: &str, col: usize) -> usize {
    if out.is_empty() {
        col
    } else {
        current_col(out)
    }
}

/// Render `doc` into `out`. `indent` is the block indent for newlines within
/// `doc`; `flat` is `true` when the nearest enclosing [`Doc::Group`] chose flat,
/// which turns a soft [`Doc::Line`] into a space and a [`Doc::Softline`] into
/// nothing. A [`Doc::HardLine`] ignores `flat` — it always breaks (and its
/// presence already forced every enclosing group broken, so it is never reached
/// with `flat == true` in practice, but it breaks unconditionally regardless).
/// `col` is the column the first char lands on.
fn render_at(
    doc: &Doc,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    match doc {
        Doc::Text(s) => out.push_str(s),
        Doc::Line => {
            if flat {
                out.push(' ');
            } else {
                out.push('\n');
                push_indent(indent, out);
            }
        }
        Doc::Softline => {
            if !flat {
                out.push('\n');
                push_indent(indent, out);
            }
        }
        Doc::HardLine => {
            // A given-up block body inlines onto its single original line: an
            // unconditional break becomes a single space, so `{ let x = …; x }` lays
            // out flat inside the braces `rustfmt` kept on one line.
            if cfg.inline_hard {
                out.push(' ');
            } else {
                out.push('\n');
                push_indent(indent, out);
            }
        }
        Doc::IfBroken(s) => {
            // Renders only when the nearest enclosing group broke (`!flat`) —
            // rustfmt's trailing comma on a broken delimited list. Nothing when
            // flat, so the flat form (and the `fits` measurement of it) carries no
            // trailing comma.
            if !flat {
                out.push_str(s);
            }
        }
        Doc::Concat(docs) => render_concat(docs, cfg, indent, col, flat, out),
        Doc::Nest(n, inner) => {
            render_at(inner, cfg, indent + n, col, flat, out);
        }
        Doc::Group(inner) => {
            let start_col = eff_col(out, col);
            // A group flattens only if its flat form is genuinely single-line and
            // fits AND it carries no `HardLine`. A statement block's `HardLine`s
            // keep it broken; a byte-leaf whose text embeds newlines (an
            // as-yet-unstructured multiline arg carried through the legacy string
            // emitter) makes the flat form multi-line — rustfmt breaks the enclosing
            // delimited list one element per line in that case rather than glue the
            // multiline arg inline. Its own soft `Line`s are what flatten or break
            // as a unit — the standard Wadler `group`, refined to reject an embedded
            // newline the width test alone would miss.
            let group_flat =
                flat || (!has_hard_break(inner) && fits_single_line(inner, cfg, start_col, indent));
            render_at(inner, cfg, indent, start_col, group_flat, out);
        }
        Doc::BraceBody(body) => render_brace_body(body, cfg, indent, col, flat, out),
        Doc::MatchArmTail { body, control } => {
            render_match_arm_tail(body, *control, cfg, indent, col, out);
        }
        Doc::Assign {
            prefix,
            rhs,
            trailer,
        } => {
            render_assign(prefix, rhs, *trailer, cfg, indent, col, flat, out);
        }
        Doc::Chain { operands } => {
            render_chain(operands, cfg, indent, col, flat, out);
        }
        Doc::CallArgs {
            open,
            elems,
            close,
            trailing_comma,
        } => {
            render_call_args(
                open,
                elems,
                close,
                *trailing_comma,
                cfg,
                indent,
                col,
                flat,
                out,
            );
        }
        Doc::StructLit {
            open,
            fields,
            close,
        } => {
            render_struct_lit(open, fields, close, cfg, indent, col, out);
        }
        Doc::TypeBound {
            ptr_open,
            head,
            traits,
            close,
        } => {
            render_type_bound(ptr_open, head, traits, close, cfg, indent, col, flat, out);
        }
        Doc::ElidableParen { inner } => render_elidable_paren(inner, cfg, indent, col, flat, out),
        Doc::OrPattern { alts } => render_or_pattern(alts, cfg, col, flat, out),
        Doc::MethodChain { receiver, method } => {
            render_method_chain(receiver, method, cfg, indent, col, flat, out);
        }
        Doc::IfElse { cond, then_, else_ } => {
            render_if_else(cond, then_, else_, cfg, indent, col, flat, out);
        }
    }
}

/// Render a [`Doc::Concat`]: each child in order, threading the reserve budget. A
/// child's own trailing `reserve` is the enclosing reserve PLUS the flat width of
/// every following sibling that lands on the SAME line — the closing delimiter text
/// a wrapper appends after a breakable construct (`Box::new(<closure>)`'s `)`, then
/// the enclosing `;`). Only siblings that render single-line count; once one would
/// break, the reserve no longer applies to earlier children (their tail is that
/// break, not the delimiter). This lets a `BraceBody`/`CallArgs` child re-test its
/// own fit against the width `rustfmt`'s `Shape` leaves after its trailing tokens.
fn render_concat(
    docs: &[Doc],
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    for (i, d) in docs.iter().enumerate() {
        let c = eff_col(out, col);
        let suffix = trailing_siblings_flat_width(docs.get(i + 1..).unwrap_or(&[]));
        let child_cfg = cfg.with_reserve(cfg.reserve + suffix);
        render_at(d, child_cfg, indent, c, flat, out);
    }
}

/// The columns `rustfmt` reserves out of an arm's width before rewriting its
/// pattern — the ` => {` that may follow the pattern on its line.
const ARM_PATTERN_RESERVE: usize = 5;

/// Render a [`Doc::OrPattern`]: the alternatives joined ` | ` when the flat run
/// fits the arm-pattern width, else one alternative per line at the pattern's
/// begin column, each subsequent line led by `| `.
///
/// The fit test is `rustfmt`'s own arm-pattern shape — `max_width` less
/// [`ARM_PATTERN_RESERVE`] — measured against `cfg.max_width` directly rather
/// than `cfg.margin()`: `rustfmt` builds the pattern's shape fresh from the
/// arm's indent, so the reservation REPLACES the enclosing trailing-sibling
/// reserve (the ` => ` text the arm concat carries) instead of stacking on it.
fn render_or_pattern(
    alts: &[std::borrow::Cow<'static, str>],
    cfg: RenderConfig,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    let start_col = eff_col(out, col);
    // Each ` | ` between two flat alternatives is 3 columns.
    let flat_w: usize =
        alts.iter().map(|a| a.len()).sum::<usize>() + 3 * alts.len().saturating_sub(1);
    if flat || start_col + flat_w + ARM_PATTERN_RESERVE <= cfg.max_width {
        for (i, alt) in alts.iter().enumerate() {
            if i > 0 {
                out.push_str(" | ");
            }
            out.push_str(alt);
        }
        return;
    }
    // Vertical: the pattern begins its arm's fresh line, so the begin-line
    // indent is its start column — every subsequent alternative lands there
    // behind a front-placed `| `.
    let begin = current_line_indent(out).unwrap_or(start_col);
    for (i, alt) in alts.iter().enumerate() {
        if i > 0 {
            out.push('\n');
            push_indent(begin, out);
            out.push_str("| ");
        }
        out.push_str(alt);
    }
}

/// Render a [`Doc::ElidableParen`]: drop the redundant wrapping parens when `inner`
/// already renders parenthesized (a doubled `(( … ))` collapses to `( … )`), matching
/// `rustfmt`; otherwise wrap `inner` in a `(` … `)` pair. The probe measures `inner`'s
/// first rendered character.
fn render_elidable_paren(
    inner: &Doc,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    if inner_renders_parenthesized(inner, cfg, eff_col(out, col), indent) {
        render_at(inner, cfg, indent, col, flat, out);
    } else {
        out.push('(');
        let c = current_col(out);
        render_at(inner, cfg, indent, c, flat, out);
        out.push(')');
    }
}

/// Render a [`Doc::MethodChain`]: the `receiver`, then the trailing `.method(…)`,
/// laid out per `rustfmt`'s method-chain rule. A SINGLE-LINE receiver glues the
/// method inline while the glued `receiver.method` fits the width — whether or not
/// the receiver carries a brace block (`(if a {…} else {…}).ipe_wrapping_add(x)`
/// stays on one line when it fits) — and drops the method to its own line one chain
/// step in only on overflow (`"long"\n    .to_string()`). A MULTILINE receiver
/// always drops the method to its own line: at the receiver's begin-line indent when
/// the receiver is a brace block ending on a de-indented `})` line (the
/// `CELL.get_or_init(|| {…})\n.clone()` shape), or one chain step in when the receiver
/// is ITSELF a broken method chain, so every `.method()` link aligns at the same
/// column (`x\n    .add(y)\n    .add(z)`). See [`Doc::MethodChain`]. `col` is where the
/// receiver's first character lands.
fn render_method_chain(
    receiver: &Doc,
    method: &Doc,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    // The method's own line aligns with the receiver's begin-line indent — the
    // indentation of the line the receiver starts on. When the buffer is empty the
    // receiver was seeded at `col` (its line's indent); otherwise read the current
    // line's leading-space count, falling back to the block indent mid-line.
    let begin_indent = if out.is_empty() {
        col
    } else {
        current_line_indent(out).unwrap_or(indent)
    };
    // Probe the receiver to decide whether the method glues (a simple non-brace
    // receiver) or breaks to its own line (a block-shaped receiver). The method
    // reserves width against the receiver's last line ONLY when it glues; a broken
    // method lands on a fresh line whose fit is measured separately.
    // A flat enclosing layout forces the whole chain inline: the receiver and the
    // trailing method glue on one line, no shape probe (`rustfmt` never breaks a
    // method chain that its parent laid out flat).
    if flat {
        render_at(receiver, cfg, indent, col, true, out);
        let c = current_col(out);
        render_at(method, cfg, indent, c, true, out);
        return;
    }
    let method_w = flat_leaf_len(method);
    let start_col = eff_col(out, col);
    let shape = receiver_shape(receiver, cfg, start_col, indent);
    // A single-line receiver glues the method inline (reserving the method's width
    // against the receiver's fit test); a multiline receiver already spans lines, so
    // the method lands on its own fresh line and needs no receiver-side reserve.
    let recv_reserve = if shape == ReceiverShape::Multiline {
        0
    } else {
        method_w
    };
    render_at(
        receiver,
        cfg.with_reserve(cfg.reserve + recv_reserve),
        indent,
        col,
        flat,
        out,
    );
    // A SINGLE-LINE receiver (plain or brace-carrying) keeps the method glued while
    // the whole `receiver.method` fits, dropping it onto its own line one chain step
    // in only on overflow (`"long"\n    .to_string()`). A MULTILINE receiver always
    // drops the method to its own line: at the begin-line indent when it is a brace
    // block ending on a de-indented `})` line, or one chain step in when it is itself
    // a broken method chain (so every link aligns at the same column). The glue
    // overflow is measured against the FULL `max_width` (the reserve was for the
    // glued case; a broken method lands on a fresh line the caller measures).
    match shape {
        ReceiverShape::Plain | ReceiverShape::SingleLineBrace => {
            // The flat case returned early above, so here the layout is broken: a
            // glued `receiver.method` that overflows drops the method to its own line.
            if current_col(out) + method_w > cfg.max_width {
                out.push('\n');
                push_indent(begin_indent + CHAIN_BREAK_INDENT, out);
            }
        }
        ReceiverShape::Multiline => {
            out.push('\n');
            let method_indent = if receiver_is_method_chain(receiver) {
                begin_indent + CHAIN_BREAK_INDENT
            } else {
                begin_indent
            };
            push_indent(method_indent, out);
        }
    }
    let c = current_col(out);
    render_at(method, cfg, indent, c, flat, out);
}

/// Whether `receiver` is itself a [`Doc::MethodChain`] — every `.method()` link of a
/// broken chain aligns at the same chain-step column, so a method applied to a broken
/// chain lands one step in (not at the chain root's begin-line indent, where a
/// brace-block receiver's method attaches). A transparent `Nest`/`Concat` wrapper is
/// looked through so a chain carried inside a positional wrapper still classifies.
fn receiver_is_method_chain(receiver: &Doc) -> bool {
    match receiver {
        Doc::MethodChain { .. } => true,
        Doc::Nest(_, inner) => receiver_is_method_chain(inner),
        Doc::Concat(docs) => docs.last().is_some_and(receiver_is_method_chain),
        _ => false,
    }
}

/// The layout shape of a [`Doc::MethodChain`] receiver, which drives whether its
/// trailing method glues and, when broken, at what indent it lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiverShape {
    /// A single-line non-brace expression (`get_or_init(|| (a / b))`): the method
    /// glues inline while `receiver.method` fits, else breaks one chain step in.
    Plain,
    /// A single-line receiver carrying a brace block (`(if a {…} else {…})`): laid out
    /// exactly like [`ReceiverShape::Plain`] — glued while it fits, one chain step in
    /// on overflow. The variant is kept distinct only to document the brace case.
    SingleLineBrace,
    /// A multiline receiver ending on a de-indented block-closing line (`})`) or a
    /// broken method chain: the method breaks to its own line — at the begin-line
    /// indent for a brace block, one chain step in for a chain receiver.
    Multiline,
}

/// Classify a [`Doc::MethodChain`] receiver's layout shape. A single-line receiver
/// (plain or brace-carrying) glues its trailing method while the line fits; a
/// multiline receiver always breaks the method to its own line. Probed by rendering
/// the receiver from `start_col` with no method reserve and inspecting its bytes.
fn receiver_shape(
    receiver: &Doc,
    cfg: RenderConfig,
    start_col: usize,
    indent: usize,
) -> ReceiverShape {
    let mut scratch = String::new();
    render_at(receiver, cfg, indent, start_col, false, &mut scratch);
    if scratch.contains('\n') {
        ReceiverShape::Multiline
    } else if scratch.contains('{') {
        ReceiverShape::SingleLineBrace
    } else {
        ReceiverShape::Plain
    }
}

/// Whether `inner` renders as ONE parenthesized group at `start_col` — a
/// self-parenthesizing block / paren-expr whose enclosing redundant paren pair
/// `rustfmt` elides. Probed by rendering `inner` flat: a leading `(` alone is not
/// enough, since `(r).f` also starts with `(` yet dropping its wrapping pair turns
/// the field-call callee `((r).f)(x)` into the method call `(r).f(x)`.
fn inner_renders_parenthesized(
    inner: &Doc,
    cfg: RenderConfig,
    start_col: usize,
    indent: usize,
) -> bool {
    let mut scratch = String::new();
    render_at(
        inner,
        cfg.no_reserve(),
        indent,
        start_col,
        true,
        &mut scratch,
    );
    is_single_paren_group(&scratch)
}

/// Whether `src` is exactly one balanced `( … )` group: it opens with `(` and the
/// paren that closes that first `(` is its last character. Parens inside string,
/// raw-string, and char literals are skipped; a `'` that opens no char literal is a
/// lifetime or label and is passed over.
fn is_single_paren_group(src: &str) -> bool {
    let bytes = src.as_bytes();
    if bytes.first() != Some(&b'(') {
        return false;
    }
    let mut depth = 0usize;
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'(' => depth = depth.saturating_add(1),
            b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return i.saturating_add(1) == bytes.len();
                }
            }
            b'"' => i = skip_string(bytes, i),
            b'r' if starts_raw_string(bytes, i) => i = skip_raw_string(bytes, i),
            b'\'' => i = skip_char_literal(bytes, i),
            _ => {}
        }
        i = i.saturating_add(1);
    }
    false
}

/// Whether the `r` at `at` opens a raw string (`r"` or `r#…"`) rather than ending
/// or starting an identifier: the byte before it is no identifier character.
fn starts_raw_string(bytes: &[u8], at: usize) -> bool {
    let prev_is_ident = at
        .checked_sub(1)
        .and_then(|p| bytes.get(p))
        .is_some_and(|&b| b.is_ascii_alphanumeric() || b == b'_');
    !prev_is_ident && matches!(bytes.get(at.saturating_add(1)), Some(b'"' | b'#'))
}

/// Index of the `"` closing the string literal whose opening `"` is at `open`
/// (the last index when unterminated).
fn skip_string(bytes: &[u8], open: usize) -> usize {
    let mut i = open.saturating_add(1);
    while let Some(&b) = bytes.get(i) {
        match b {
            b'\\' => i = i.saturating_add(2),
            b'"' => return i,
            _ => i = i.saturating_add(1),
        }
    }
    bytes.len().saturating_sub(1)
}

/// Index of the last character of the raw string `r#…"…"#…` whose `r` is at
/// `start`, or `start` itself when no `"` follows the `#` run.
fn skip_raw_string(bytes: &[u8], start: usize) -> usize {
    let mut i = start.saturating_add(1);
    let mut hashes = 0usize;
    while bytes.get(i) == Some(&b'#') {
        hashes = hashes.saturating_add(1);
        i = i.saturating_add(1);
    }
    if bytes.get(i) != Some(&b'"') {
        return start;
    }
    i = i.saturating_add(1);
    while let Some(&b) = bytes.get(i) {
        if b == b'"' {
            let after = i.saturating_add(1);
            let closing = bytes.get(after..after.saturating_add(hashes));
            if closing.is_some_and(|c| c.iter().all(|&h| h == b'#')) {
                return i.saturating_add(hashes);
            }
        }
        i = i.saturating_add(1);
    }
    bytes.len().saturating_sub(1)
}

/// Index of the `'` closing the char literal opened at `open`, or `open` itself
/// when the `'` begins a lifetime or label instead (`'a`, `'outer:`).
fn skip_char_literal(bytes: &[u8], open: usize) -> usize {
    let first = open.saturating_add(1);
    if bytes.get(first) == Some(&b'\\') {
        let mut i = first.saturating_add(2);
        while let Some(&b) = bytes.get(i) {
            if b == b'\'' {
                return i;
            }
            i = i.saturating_add(1);
        }
        return bytes.len().saturating_sub(1);
    }
    let close = first.saturating_add(utf8_width(bytes.get(first).copied()));
    if close > first && bytes.get(close) == Some(&b'\'') {
        close
    } else {
        open
    }
}

/// UTF-8 byte width of the codepoint whose lead byte is `lead`; `0` for none.
fn utf8_width(lead: Option<u8>) -> usize {
    match lead {
        None => 0,
        Some(b) if b < 0x80 => 1,
        Some(b) if b >= 0xF0 => 4,
        Some(b) if b >= 0xE0 => 3,
        Some(_) => 2,
    }
}

/// Render a [`Doc::TypeBound`] `Ptr<Head + T1 + …>` with `rustfmt`'s angle-bracket
/// break. Flat when it fits; else `Ptr<` then the bound list at one indent step
/// (`Head + T1 + …,`) with `>` dedented; else, when the bound list itself overflows
/// at that step, `Head` and each `+ Ti` on their own lines at a further indent step.
/// The break decision is independent of any enclosing group (`rustfmt` re-tests the
/// annotation against the width on its own line). `col` is where `ptr_open`'s first
/// character lands.
#[allow(
    clippy::too_many_arguments,
    reason = "renderer threads ptr/head/traits/close + col/indent"
)]
fn render_type_bound(
    ptr_open: &Doc,
    head: &Doc,
    traits: &[Doc],
    close: &Doc,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    let start_col = eff_col(out, col);
    // FLAT: an enclosing group that chose flat forces the inline form (used by the
    // assignment's `flat_width` measurement of its prefix); otherwise the inline
    // form holds only while `Ptr<Head + T1 + …>` fits the (reserve-reduced) width.
    let flat_w = type_bound_flat_width(ptr_open, head, traits, close, cfg);
    if flat || start_col + flat_w <= cfg.margin() {
        render_at(ptr_open, cfg.no_reserve(), indent, start_col, true, out);
        let c = current_col(out);
        render_at(head, cfg.no_reserve(), indent, c, true, out);
        for t in traits {
            out.push_str(" + ");
            let c = current_col(out);
            render_at(t, cfg.no_reserve(), indent, c, true, out);
        }
        let c = current_col(out);
        render_at(close, cfg, indent, c, true, out);
        return;
    }

    // Overflowing: break the angle brackets. `Ptr<` on this line, the bound list at
    // one indent step, `>` dedented back to `Ptr`'s column.
    render_at(ptr_open, cfg.no_reserve(), indent, start_col, false, out);
    let bound_indent = indent + CHAIN_BREAK_INDENT;

    // ANGLE-BREAK when the whole bound list (plus its trailing `,`) fits on one line
    // at the bound indent; otherwise BOUND-BREAK, each `+ Ti` on its own line at a
    // further indent step. The `head` and the traits open the bound list at
    // `bound_indent` either way.
    let bound_flat_w = type_bound_list_flat_width(head, traits, cfg);
    let angle_break = bound_indent + bound_flat_w < cfg.max_width;
    out.push('\n');
    push_indent(bound_indent, out);
    let c = current_col(out);
    render_at(head, cfg.no_reserve(), bound_indent, c, true, out);
    if angle_break {
        // The whole bound list stays on one line at `bound_indent`.
        for t in traits {
            out.push_str(" + ");
            let c = current_col(out);
            render_at(t, cfg.no_reserve(), bound_indent, c, true, out);
        }
    } else {
        // Each `+ Ti` on its own line at a further indent step.
        let trait_indent = bound_indent + CHAIN_BREAK_INDENT;
        for t in traits {
            out.push('\n');
            push_indent(trait_indent, out);
            out.push_str("+ ");
            let c = current_col(out);
            render_at(t, cfg.no_reserve(), trait_indent, c, false, out);
        }
    }
    out.push(',');
    out.push('\n');
    push_indent(indent, out);
    let c = current_col(out);
    render_at(close, cfg, indent, c, false, out);
}

/// The flat width of `Ptr<Head + T1 + …>` — the single-line footprint of a
/// [`Doc::TypeBound`], for its overflow test.
fn type_bound_flat_width(
    ptr_open: &Doc,
    head: &Doc,
    traits: &[Doc],
    close: &Doc,
    cfg: RenderConfig,
) -> usize {
    let mut scratch = String::new();
    render_at(ptr_open, cfg.no_reserve(), 0, 0, true, &mut scratch);
    render_at(
        head,
        cfg.no_reserve(),
        0,
        current_col(&scratch),
        true,
        &mut scratch,
    );
    for t in traits {
        scratch.push_str(" + ");
        let c = current_col(&scratch);
        render_at(t, cfg.no_reserve(), 0, c, true, &mut scratch);
    }
    let c = current_col(&scratch);
    render_at(close, cfg.no_reserve(), 0, c, true, &mut scratch);
    scratch.len()
}

/// The flat width of the bound list `Head + T1 + …` alone (no `Ptr<` / `>`), for
/// the angle-break-vs-bound-break decision.
fn type_bound_list_flat_width(head: &Doc, traits: &[Doc], cfg: RenderConfig) -> usize {
    let mut scratch = String::new();
    render_at(head, cfg.no_reserve(), 0, 0, true, &mut scratch);
    for t in traits {
        scratch.push_str(" + ");
        let c = current_col(&scratch);
        render_at(t, cfg.no_reserve(), 0, c, true, &mut scratch);
    }
    scratch.len()
}

/// Render a [`Doc::StructLit`] with `rustfmt`'s `struct_lit_width` rule: the flat
/// `Name { a: 1, b: 2 }` (spaces hugging the braces) when the FIELD TEXT fits 18
/// columns and the whole line fits `max_width`; otherwise one field per line with a
/// trailing comma, `close` dedented back to `open`'s column. The break decision is
/// independent of any enclosing group (`rustfmt` re-tests the field width on the
/// struct's own line), like [`Doc::CallArgs`].
#[allow(
    clippy::too_many_arguments,
    reason = "renderer threads open/close/col/indent"
)]
fn render_struct_lit(
    open: &Doc,
    fields: &[Doc],
    close: &Doc,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    out: &mut String,
) {
    let start_col = eff_col(out, col);
    // The `struct_lit_width` gate applies even when the enclosing group chose flat:
    // a struct literal whose field text exceeds 18 columns breaks and forces its
    // enclosing construct broken (like a `HardLine`), so `flat` alone does not force
    // it inline — `struct_lit_flat_fits` is the sole authority.
    if struct_lit_flat_fits(open, fields, close, cfg, start_col, indent) {
        // Flat: `Name { a: 1, b: 2 }` — a space hugs each brace.
        render_at(open, cfg.no_reserve(), indent, start_col, true, out);
        out.push(' ');
        render_flat_elems(fields, cfg, indent, out);
        out.push(' ');
        let c = current_col(out);
        render_at(close, cfg, indent, c, true, out);
        return;
    }
    // Broken: one field per line with a trailing comma — the same one-per-line
    // layout as a delimited list.
    render_one_per_line(open, fields, close, true, cfg, indent, start_col, out);
}

/// `rustfmt`'s `struct_lit_width` (default 18): the maximum width of a struct
/// literal's FIELD TEXT — the span between the braces, trimmed of the hugging
/// spaces — that stays on one line. A struct literal whose field text exceeds this
/// breaks one field per line even when the whole line still fits `max_width`.
const STRUCT_LIT_WIDTH: usize = 18;

/// Whether a struct literal `Name { fields }` may lay out flat from `start_col`:
/// genuinely single-line, the whole line (with the hugging spaces and the trailing
/// `reserve`) within `max_width`, AND the field text within `struct_lit_width`.
fn struct_lit_flat_fits(
    open: &Doc,
    fields: &[Doc],
    close: &Doc,
    cfg: RenderConfig,
    start_col: usize,
    indent: usize,
) -> bool {
    let mut scratch = String::new();
    render_at(
        open,
        cfg.no_reserve(),
        indent,
        start_col,
        true,
        &mut scratch,
    );
    let open_end = current_col(&scratch);
    scratch.push(' ');
    render_flat_elems(fields, cfg, indent, &mut scratch);
    let fields_end = current_col(&scratch);
    scratch.push(' ');
    render_at(
        close,
        cfg.no_reserve(),
        indent,
        fields_end + 1,
        true,
        &mut scratch,
    );
    if scratch.contains('\n') {
        return false;
    }
    if start_col + scratch.len() > cfg.margin() {
        return false;
    }
    // The field text is the span between the braces, excluding the hugging spaces.
    fields_end.saturating_sub(open_end) <= STRUCT_LIT_WIDTH
}

/// Render a [`Doc::BraceBody`]: the body inline (no braces) when it fits flat here,
/// else `{`, the body on its own line at one indent step, `}` dedented back.
/// `rustfmt` re-tests the closure/arm body against the width on its own line, so the
/// decision is independent of any enclosing group; a `HardLine` body always braces.
fn render_brace_body(
    body: &Doc,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    let start_col = eff_col(out, col);
    // A given-up block body (`inline_hard`) reproduces the ORIGINAL single-line text,
    // which the string emitter always writes WITH the closure braces (`move |_| {
    // rest }`) — `rustfmt` never strips them in a rewrite it abandoned. Keep the
    // braces, body inline.
    if cfg.inline_hard {
        out.push_str("{ ");
        render_at(body, cfg, indent, current_col(out), true, out);
        out.push_str(" }");
        return;
    }
    // The body inlines flat ONLY when its flat form is genuinely single-line — a
    // nested opaque variant (`CallArgs`/`StructLit`/`Chain`) hides its own
    // `HardLine` from `has_hard_break`, so its flat render can still embed a `\n`
    // (a block arg, a one-per-line-broken wide record). A first-line-only fit
    // would drop the braces on such a body; `fits_single_line` rejects the
    // embedded newline, keeping the block form `rustfmt` emits.
    let body_flat =
        flat || (!has_hard_break(body) && fits_single_line(body, cfg, start_col, indent));
    if body_flat {
        render_at(body, cfg, indent, start_col, true, out);
        return;
    }
    render_brace_body_broken(body, cfg, indent, start_col, out);
}

/// Render a [`Doc::BraceBody`] in its BROKEN braced form unconditionally: `{`, the
/// body on its own line at one indent step, `}` dedented back. Used both by
/// [`render_brace_body`] when the body does not fit flat and by the call-argument
/// combine, which forces a block-like closure body broken even when it would fit.
fn render_brace_body_broken(
    body: &Doc,
    cfg: RenderConfig,
    indent: usize,
    start_col: usize,
    out: &mut String,
) {
    out.push('{');
    render_at(
        &Doc::Nest(4, Box::new(Doc::HardLine)),
        cfg,
        indent,
        start_col,
        false,
        out,
    );
    let c = current_col(out);
    // SHAPE-BUDGET GIVE-UP: at a deep indent the block body's own broken layout can
    // place an UNBREAKABLE atomic leaf (a string literal / bare identifier that
    // `rustfmt` cannot split) past `max_width`. `rustfmt`'s `Shape`-width recursion
    // then abandons the broken rewrite and leaves the body on its ORIGINAL single
    // line inside the braces (an overflowing but un-splittable line). Model this by
    // rendering the body broken to a probe (whose OWN nested blocks already resolved
    // their give-ups, so a nested give-up's long line is a sealed, breakable-shaped
    // unit that does NOT count here) and checking for a fresh unbreakable-atom
    // overflow. When found, render the body flat instead. Only the block boundary
    // gives up; a nested call's give-up is decided by its own enclosing block, so
    // the decision does not cascade up through breakable constructs.
    if body_broken_forces_flat(body, cfg, indent + 4, c) {
        // Keep the whole body on its original single line, inlining even statement-
        // block `HardLine`s to a single space (`rustfmt`'s given-up rewrite).
        let flat_cfg = RenderConfig {
            inline_hard: true,
            ..cfg
        };
        render_at(body, flat_cfg, indent + 4, c, true, out);
    } else {
        render_at(body, cfg, indent + 4, c, false, out);
    }
    out.push('\n');
    push_indent(indent, out);
    out.push('}');
}

/// Whether a block body, rendered in its BROKEN form at `indent`, would place an
/// UNBREAKABLE atomic leaf past `max_width` — the deep-indent case where `rustfmt`
/// abandons the broken rewrite and keeps the body on its original single line.
///
/// The probe renders the body broken (nested blocks resolve their OWN give-ups
/// first, so a sealed give-up line is a breakable-shaped call that does not count);
/// then any resulting line that OVERFLOWS `max_width` AND is a single unbreakable
/// atom (a bare string literal / identifier / type with no top-level break point)
/// is the fresh give-up trigger. A breakable overflowing line (`f(…)`, a call whose
/// own break `rustfmt` would still take) is NOT a trigger — it belongs to that
/// construct's own layout, not this block's give-up.
fn body_broken_forces_flat(body: &Doc, cfg: RenderConfig, indent: usize, start_col: usize) -> bool {
    let mut probe = String::new();
    push_indent(start_col, &mut probe);
    render_at(body, cfg, indent, start_col, false, &mut probe);
    probe
        .split('\n')
        .any(|line| line.len() > cfg.max_width && line_is_unbreakable_atom(line))
}

/// `rustfmt`'s `single_line_if_else_max_width` (default 50): the maximum width of
/// an `if cond { then } else { else }` construct — measured WITHOUT the outer
/// parentheses the emitter wraps it in — that `rustfmt` keeps on one line. Wider
/// constructs break each branch body onto its own line. The threshold is absolute
/// (column-independent), so the decision is a function of the flat leaf widths.
const SINGLE_LINE_IF_ELSE_MAX_WIDTH: usize = 50;

/// The single-line width of an `if`/`else` construct WITHOUT the outer parens:
/// `if ` + cond + ` { ` + then + ` } else { ` + else + ` }`, from the flat leaf
/// widths (absolute, column-independent). One source of truth for BOTH the
/// render decision and `has_hard_break`, so the two cannot disagree about whether
/// an `IfElse` renders block-form.
fn if_else_construct_width(cond: &Doc, then_: &Doc, else_: &Doc) -> usize {
    "if ".len()
        + cond.normalized_leaves().len()
        + " { ".len()
        + then_.normalized_leaves().len()
        + " } else { ".len()
        + else_.normalized_leaves().len()
        + " }".len()
}

/// Render a [`Doc::IfElse`] with `rustfmt`'s `single_line_if_else_max_width` rule.
/// The single-line construct width WITHOUT the outer parens (the `if cond { then }
/// else { else }` text) is measured from the branches' flat leaves; when it is at
/// most [`SINGLE_LINE_IF_ELSE_MAX_WIDTH`] the whole construct stays inline `(if cond
/// { then } else { else })`, otherwise each branch body breaks onto its own line at
/// one indent step. The threshold is absolute, so the decision is independent of the
/// enclosing column (a wider enclosing group cannot force it broken, nor a deep
/// indent).
#[allow(
    clippy::too_many_arguments,
    reason = "renderer threads the three branch docs + cfg/indent/col/flat"
)]
fn render_if_else(
    cond: &Doc,
    then_: &Doc,
    else_: &Doc,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    let construct_width = if_else_construct_width(cond, then_, else_);

    let start_col = eff_col(out, col);
    if construct_width <= SINGLE_LINE_IF_ELSE_MAX_WIDTH {
        // Inline `(if cond { then } else { else })`. Soft `Line`s so a wider
        // enclosing group could in principle break it, but the width test already
        // guaranteed it fits.
        render_at(
            &Doc::concat(vec![
                Doc::text("(if "),
                cond.clone(),
                Doc::text(" { "),
                then_.clone(),
                Doc::text(" } else { "),
                else_.clone(),
                Doc::text(" })"),
            ]),
            cfg,
            indent,
            start_col,
            flat,
            out,
        );
        return;
    }

    // Broken block form. Braces sit at the enclosing block `indent`; each branch
    // body indents to `indent + 4`. `HardLine`s force the layout unconditionally,
    // matching `rustfmt`'s block-form `if` once past the single-line threshold.
    render_at(
        &Doc::concat(vec![
            Doc::text("(if "),
            cond.clone(),
            Doc::text(" {"),
            Doc::nest(4, Doc::concat(vec![Doc::HardLine, then_.clone()])),
            Doc::HardLine,
            Doc::text("} else {"),
            Doc::nest(4, Doc::concat(vec![Doc::HardLine, else_.clone()])),
            Doc::HardLine,
            Doc::text("})"),
        ]),
        cfg,
        indent,
        start_col,
        flat,
        out,
    );
}

/// Whether a rendered line, trimmed of indentation, is a single UNBREAKABLE atom:
/// a bare string literal or an identifier/path/type with no TOP-LEVEL break point —
/// no `(` / `[` / `{` group opener and no top-level `, ` separator outside a string
/// or bracket. Such a line cannot be split further, so an overflowing one is where
/// `rustfmt`'s `Shape`-width recursion gives up. A breakable line (a call `f(…)`, a
/// list, a `let … = …`) has a top-level opener/separator and is NOT an atom — its
/// own layout, not this block's give-up, governs it.
fn line_is_unbreakable_atom(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.is_empty() {
        return false;
    }
    let mut in_str = false;
    let mut escaped = false;
    let mut depth: i32 = 0;
    let mut prev = ' ';
    for c in trimmed.chars() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            prev = c;
            continue;
        }
        match c {
            '"' => in_str = true,
            // A group opener or a top-level separator is a break point, so the line
            // is a breakable construct (a call / list / `let`), not a single atom. A
            // top-level space between two non-delimiter tokens (`a b`, `x = y`) is a
            // break point too.
            '(' | '[' | '{' | ',' => return false,
            ' ' if depth == 0 => return false,
            '<' => depth += 1,
            '>' if prev != '-' => depth -= 1,
            _ => {}
        }
        prev = c;
    }
    true
}

/// Render a [`Doc::MatchArmTail`]: the body plus its trailing comma per `rustfmt`'s
/// arm brace/comma rule. Inline `body,` when it fits. When it overflows: a CONTROL
/// body is always wrapped in synthesized braces (comma dropped); a DELIMITED-tail
/// body that stays SINGLE-LINE on its own line at one indent step is ALSO wrapped in
/// a synthesized block (`rustfmt` prefers the whole body on its own line over
/// breaking its delimiters, comma dropped), and only a delimited body that STILL
/// overflows at that indent breaks inside its own brackets (comma kept). A
/// `HardLine` body always breaks.
fn render_match_arm_tail(
    body: &Doc,
    control: bool,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    out: &mut String,
) {
    let start_col = eff_col(out, col);
    // Inline `body,` only when the body's flat form is genuinely single-line. A
    // non-control body wrapping an opaque variant (`CallArgs` with a block arg,
    // a wide `StructLit`, a block-bearing `Chain`) hides its `HardLine` from
    // `has_hard_break`, so its flat render can embed a `\n`; a first-line-only fit
    // sees only the short first line and would inline it, dropping the arm braces
    // `rustfmt` keeps. `fits_single_line` rejects the embedded newline.
    let body_flat = !has_hard_break(body) && fits_single_line(body, cfg, start_col, indent);
    if body_flat {
        render_at(body, cfg, indent, start_col, true, out);
        out.push(',');
        return;
    }
    // rustfmt decides an overflowing arm body in three tiers (see
    // `emit_types::render_stringify_enum_arm`): a CONTROL body is always
    // brace-wrapped; a delimited CALL/MACRO body whose ARGUMENT TEXT fits
    // `fn_call_width` is brace-wrapped onto its own line (rustfmt prefers the whole
    // body single-line over breaking its delimiters); and a delimited body whose
    // argument text exceeds `fn_call_width` breaks in place inside its own
    // delimiters (comma kept). The gate is the argument-text width against
    // `fn_call_width`, NOT the whole body against `max_width` — a body that fits
    // `max_width` at `indent + 4` but whose args exceed 60 columns still breaks in
    // place. A non-delimited body (chain, `if`/`else`) has no argument list to gate,
    // so it falls back to the single-line-at-`indent + 4` test.
    let block_wrap = control || (!has_hard_break(body) && body_block_wraps(body, cfg, indent));
    if block_wrap {
        out.push('{');
        render_at(
            &Doc::Nest(4, Box::new(Doc::HardLine)),
            cfg,
            indent,
            start_col,
            false,
            out,
        );
        let c = current_col(out);
        render_at(body, cfg, indent + 4, c, false, out);
        out.push('\n');
        push_indent(indent, out);
        out.push('}');
    } else {
        render_at(body, cfg, indent, start_col, false, out);
        out.push(',');
    }
}

/// Whether an overflowing, non-control match-arm `body` is brace-wrapped onto its
/// own line (`Pat => { body }`) rather than broken in place inside its own
/// delimiters (`Pat => f(\n …\n),`).
///
/// For a delimited CALL/CTOR/MACRO body the decision is `rustfmt`'s
/// `fn_call_width` gate: the body's ARGUMENT TEXT (the span between its
/// delimiters, seeing through a single-argument combinable wrapper) is
/// brace-wrapped when it fits `fn_call_width` and delimiter-broken when it does
/// not. A body with no argument list of its own (a chain, an `if`/`else`) has no
/// such gate, so it falls back to whether the whole body fits single-line on its
/// own line at `indent + 4`.
fn body_block_wraps(body: &Doc, cfg: RenderConfig, indent: usize) -> bool {
    // See through a `Group` wrapper to the delimited construct it lays out.
    let inner = match body {
        Doc::Group(g) => g.as_ref(),
        other => other,
    };
    if let Doc::CallArgs { open, elems, .. } = inner {
        // Measure the argument text width: the flat span from just after the
        // opening delimiter to just before the closing one, seeing through a
        // single-argument combinable wrapper to the innermost combinable's own
        // argument span (`innermost_args_width`). The absolute column is
        // irrelevant to a width, so measure from column 0.
        let mut scratch = String::new();
        render_at(open, cfg, indent + 4, 0, true, &mut scratch);
        let open_end = current_col(&scratch);
        render_flat_elems(elems, cfg, indent + 4, &mut scratch);
        let elems_end = current_col(&scratch);
        let args_width = innermost_args_width(elems, open_end, elems_end);
        return args_width <= FN_CALL_WIDTH;
    }
    fits_single_line(body, cfg.no_reserve(), indent + 4, indent + 4)
}

/// Render an assignment with `rustfmt`'s dedicated RHS-break layout axis. See
/// [`Doc::Assign`]. `col` is where the assignment's first character lands;
/// `indent` is the enclosing block indent (broken RHS goes to `indent + 4`).
/// `trailer` is the width reserved after the RHS on its line (the trailing `;`).
#[allow(
    clippy::too_many_arguments,
    reason = "renderer threads col/indent/flat"
)]
fn render_assign(
    prefix: &Doc,
    rhs: &Doc,
    trailer: usize,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    let start_col = eff_col(out, col);
    let prefix_flat_w = flat_width(prefix, cfg, start_col, indent);
    let rhs_flat_w = flat_width(rhs, cfg, 0, indent);

    // FLAT: the whole `prefix rhs;` fits on the current line. An enclosing group
    // that already chose flat forces this too. A hard break in either side rules
    // it out (a statement-block RHS never lays out flat). A `flat_width` measures
    // only the first line, so an RHS wrapping an opaque variant (an applied-lambda
    // `let p: T = foo(let x = 1 in x)`) whose flat render embeds a `\n` would look
    // short here and glue the RHS flat, dropping the delimiters `rustfmt` keeps.
    // Treat such an embedded newline as overflow: the same-line form requires a
    // genuinely single-line RHS flat render.
    let same_line_end = start_col + prefix_flat_w + rhs_flat_w + trailer;
    let no_hard_break = !has_hard_break(prefix) && !has_hard_break(rhs);
    let rhs_single_line = flat_is_single_line(rhs, cfg, 0, indent);
    if flat || (no_hard_break && rhs_single_line && same_line_end <= cfg.max_width) {
        render_at(prefix, cfg, indent, start_col, true, out);
        let c = current_col(out);
        render_at(rhs, cfg, indent, c, true, out);
        return;
    }

    // The same-line form overflows. The `let name: TYPE = ` prefix stays flat
    // UNLESS its own flat width overflows the line — then `rustfmt` breaks the
    // TYPE's angle brackets (a `Doc::TypeBound` prefix does this) to shorten the
    // prefix before it even reaches the RHS. Rendering the prefix non-flat only when
    // it overflows keeps the RHS-break (which alone fixes a merely-`prefix+rhs`-wide
    // line) preferred, matching `rustfmt`.
    let prefix_overflows = start_col + prefix_flat_w > cfg.max_width;
    render_at(prefix, cfg, indent, start_col, !prefix_overflows, out);

    // When the prefix itself broke its TYPE across lines, its last line ends with
    // `> = ` and `rustfmt` GLUES the RHS onto it (the type-break already reclaimed
    // the width the RHS-break would have) — the RHS breaks into its own delimiters
    // in place, exactly the delimiter-break form. Skip the RHS-break axis.
    if prefix_overflows {
        let c = current_col(out);
        // The trailing `;` (the `trailer`) is reserved on the RHS's last line so a
        // glued closure body re-tests its fit with room for the statement terminator.
        render_at(
            rhs,
            cfg.with_reserve(cfg.reserve + trailer),
            indent,
            c,
            false,
            out,
        );
        return;
    }

    // RHS-BREAK: dropped onto its own line at one indent step past the block, the
    // RHS's FIRST line (laying out its own internal breaks — e.g. a closure body
    // block) fits the width. `rustfmt` prefers this next-line placement for a
    // value that would otherwise crowd the wide `let name: TYPE = ` prefix. The
    // trailer is charged against the first line only when the RHS does not break
    // internally (a single-line RHS carries the `;` on that one line).
    let rhs_indent = indent + CHAIN_BREAK_INDENT;
    let rhs_break_render = probe_render(rhs, cfg, rhs_indent, rhs_indent);
    let rhs_break_first = rhs_break_render
        .split('\n')
        .next()
        .unwrap_or(&rhs_break_render);
    let rhs_break_head_w = rhs_break_first.len().saturating_sub(rhs_indent);
    let rhs_breaks = rhs_break_render.contains('\n');
    let rhs_break_trailer = if rhs_breaks { 0 } else { trailer };

    // `rustfmt`'s `choose_rhs` accepts the next-line placement only when the
    // glued alternative is not strictly required:
    //  - GLUE-UNVIABLE: the RHS head before its open delimiter (a call's callee)
    //    does not fit the width remaining after `prefix` plus the trailer, so the
    //    glued rewrite fails outright and the RHS always drops to the next line —
    //    even with an over-wide body.
    //  - TAIL-FITS: the glued rewrite is viable, so next-line placement must
    //    prove itself better: no line of the RHS body carries content that alone
    //    exceeds `max_width` — an unbreakable run no indent can ever fit (the
    //    body `rustfmt` leaves as an over-wide raw snippet). Such a body makes
    //    the next-line form no better than the glued one, and the glued form wins.
    let glue_col = start_col + prefix_flat_w;
    let glue_render = probe_render(rhs, cfg, indent, glue_col);
    let glue_head = glue_render.split('\n').next().unwrap_or(&glue_render);
    let glue_head_core_w = glue_head
        .trim_end_matches(['(', '{', '['])
        .len()
        .saturating_sub(glue_col);
    let glue_viable = glue_col + glue_head_core_w + trailer <= cfg.max_width;
    let rhs_tail_fits = rhs_break_render
        .split('\n')
        .skip(1)
        .all(|line| line.trim_start().len() <= cfg.max_width);
    if no_hard_break
        && rhs_indent + rhs_break_head_w + rhs_break_trailer <= cfg.max_width
        && (!glue_viable || rhs_tail_fits)
    {
        // `rustfmt` leaves no trailing space on the `= ` line, so trim it before
        // the newline (the prefix carries the flat-case space after `=`).
        trim_trailing_spaces(out);
        out.push('\n');
        push_indent(rhs_indent, out);
        let c = current_col(out);
        render_at(rhs, cfg, rhs_indent, c, false, out);
        return;
    }

    // DELIMITER-BREAK: even at `indent + 4` the RHS's first line overflows, so
    // `rustfmt` keeps it glued to `= ` and breaks it into its own delimiters at
    // the block indent.
    let c = current_col(out);
    render_at(rhs, cfg, indent, c, false, out);
}

/// The combined flat width of the run of trailing sibling TEXT leaves that follow a
/// `Doc::Concat` child on the same line — the closing-delimiter text a wrapper
/// appends after a breakable child (`Box::new(<closure>)`'s `)`). Only bare text
/// leaves count: they are the delimiter tails that always sit on the child's last
/// line. The scan stops at the first non-text sibling (a nested structure begins its
/// own layout and does not reserve against an earlier child). Restricting to text
/// leaves keeps this O(remaining leaves) rather than re-rendering nested subtrees,
/// avoiding the exponential blowup a full per-child re-render would cause on deeply
/// nested closures. This is the extra `reserve` a child inherits so its own fit test
/// leaves room for its wrapper's tail.
fn trailing_siblings_flat_width(siblings: &[Doc]) -> usize {
    let mut total = 0usize;
    for s in siblings {
        match s {
            Doc::Text(t) => total += t.len(),
            _ => break,
        }
    }
    total
}

/// The width of `doc` rendered entirely flat from column `start_col` up to its
/// first hard break — the single-line footprint the assignment's fit tests
/// measure. Rendered into a scratch buffer with everything flat; a hard break
/// ends the measured line (a flat statement-block never arises in a fit-tested
/// path, but measuring to the first newline is the correct general rule).
fn flat_width(doc: &Doc, cfg: RenderConfig, start_col: usize, indent: usize) -> usize {
    let mut scratch = String::new();
    render_at(doc, cfg, indent, start_col, true, &mut scratch);
    scratch.split('\n').next().unwrap_or(&scratch).len()
}

/// Whether `doc` rendered entirely flat from column `start_col` is genuinely
/// single-line — no embedded `\n`. An opaque variant (`CallArgs`/`StructLit`/
/// `Chain`) hides its own `HardLine` from [`has_hard_break`], so a flat render of
/// it can still carry a newline (a block argument, a wide record broken
/// one-per-line). [`flat_width`] measures only the first line and misses that;
/// the assignment's same-line fit gates on this so it never glues a
/// multiline-flat RHS onto the prefix and drops the delimiters `rustfmt` keeps.
fn flat_is_single_line(doc: &Doc, cfg: RenderConfig, start_col: usize, indent: usize) -> bool {
    let mut scratch = String::new();
    render_at(doc, cfg, indent, start_col, true, &mut scratch);
    !scratch.contains('\n')
}

/// `doc` rendered from `start_col` at block indent `indent`, letting its own
/// groups decide their internal breaks (non-flat), with `start_col` leading
/// spaces so every line's length is an absolute column. The assignment axis
/// measures its candidate layouts (glued head, next-line head, tail lines) on
/// this probe without touching the real output buffer.
fn probe_render(doc: &Doc, cfg: RenderConfig, indent: usize, start_col: usize) -> String {
    let mut scratch = String::new();
    push_indent(start_col, &mut scratch);
    render_at(doc, cfg, indent, start_col, false, &mut scratch);
    scratch
}

/// Whether `doc` contains a [`Doc::HardLine`] that is NOT enclosed in a nested
/// group — an unconditional break that forces its enclosing group to stay broken.
/// A statement block carries a `HardLine` before each statement, so this returns
/// `true` for it; an inline structure carrying only soft `Line` / `Softline`
/// returns `false` and is free to flatten. Nested groups and chains hide their
/// own breaks (they decide their own layout independently).
fn has_hard_break(doc: &Doc) -> bool {
    match doc {
        Doc::HardLine => true,
        // A `BraceBody` decides its own layout independently (like `Group` and
        // `Chain`), so it hides its own breaks from the enclosing group — a
        // closure inside a call does not force the call multiline.
        Doc::Text(_)
        | Doc::Line
        | Doc::Softline
        | Doc::IfBroken(_)
        | Doc::Group(_)
        | Doc::BraceBody(_)
        | Doc::MatchArmTail { .. }
        | Doc::Assign { .. }
        | Doc::Chain { .. }
        // A `CallArgs` decides its own layout independently (like `Group`), so it
        // hides its own breaks — a combinable call inside another does not force
        // the outer to break its whole list; the combining rule glues instead.
        | Doc::CallArgs { .. }
        // A `StructLit` decides its own layout independently too (its own
        // `struct_lit_width` re-test), so it hides its breaks like `CallArgs`.
        | Doc::StructLit { .. }
        // A `TypeBound` decides its own angle-bracket break independently; it never
        // carries a `HardLine`.
        | Doc::TypeBound { .. }
        // A `MethodChain` decides its own layout independently (its receiver breaks
        // its own delimiters, the method drops to its own line), so it hides its
        // breaks like `CallArgs`.
        | Doc::MethodChain { .. }
        // An `OrPattern` decides its own flat-vs-vertical layout independently
        // and carries only text alternatives — never a hard break.
        | Doc::OrPattern { .. } => false,
        // An `IfElse` carries a break the enclosing `BraceBody` must see in TWO
        // cases, mirroring the old inline-`build_if` `Concat` whose `has_hard_break`
        // recursed into its children: (a) it renders block-form (wider than the
        // absolute `single_line_if_else_max_width`), or (b) a branch itself carries
        // a hard break (a `let..in` branch emits a `HardLine`). Otherwise `fits`
        // (which measures only the short first line `(if cond {`) would inline a
        // tall body into a closure/CAF brace-body and drop its braces. Width test
        // shared with `render_if_else`.
        Doc::IfElse { cond, then_, else_ } => {
            if_else_construct_width(cond, then_, else_) > SINGLE_LINE_IF_ELSE_MAX_WIDTH
                || has_hard_break(cond)
                || has_hard_break(then_)
                || has_hard_break(else_)
        }
        Doc::Concat(docs) => docs.iter().any(has_hard_break),
        // `Nest` is pure indentation and `ElidableParen` pure wrapping: each forwards
        // its break behavior to its inner (a paren-block carries the statement
        // `HardLine`s that force a break).
        Doc::Nest(_, inner) | Doc::ElidableParen { inner } => has_hard_break(inner),
    }
}

/// Push `n` spaces of indentation.
fn push_indent(n: usize, out: &mut String) {
    for _ in 0..n {
        out.push(' ');
    }
}

/// Drop trailing spaces from the end of `out`. Used before a break so a line
/// never ends in whitespace (`rustfmt` trims the space after `=` when the RHS
/// moves to the next line).
fn trim_trailing_spaces(out: &mut String) {
    let trimmed = out.trim_end_matches(' ').len();
    out.truncate(trimmed);
}

/// Whether `doc` rendered flat from column `start_col` is genuinely single-line
/// AND fits the width. A flat render that still carries a
/// newline — a byte-leaf whose legacy-emitter text embeds a multiline block — is
/// NOT single-line, so the enclosing [`Doc::Group`] must break its delimited list
/// one element per line rather than glue the multiline element inline. This is the
/// call-argument-head-glue rule: `rustfmt` keeps a call head glued and lays a
/// structured multiline argument out in place ONLY through the dedicated
/// [`Doc::BraceBody`] closure/arm shape; a plain multiline delimited element breaks
/// the whole list. Groups with only soft `Line`/`Softline` breaks never embed a
/// newline in their flat form, so a single-line render is exactly a fitting one.
fn fits_single_line(doc: &Doc, cfg: RenderConfig, start_col: usize, indent: usize) -> bool {
    let mut scratch = String::new();
    render_at(doc, cfg.no_reserve(), indent, start_col, true, &mut scratch);
    if scratch.contains('\n') {
        return false;
    }
    start_col + scratch.len() <= cfg.margin()
}

/// Whether a chain's operands rendered flat from `start_col` are genuinely
/// single-line AND fit the width — the whole-chain-flat fast-path probe. Equal to
/// [`fits_single_line`] on a `Doc::Chain` of the same operands (a flat `Doc::Chain`
/// renders through [`render_chain_flat`]), but probes the operands directly rather
/// than cloning them into a fresh `Doc::Chain` just to route through [`render_at`].
fn chain_flat_fits_single_line(
    operands: &[ChainOperand],
    cfg: RenderConfig,
    start_col: usize,
    indent: usize,
) -> bool {
    let mut scratch = String::new();
    render_chain_flat(operands, cfg.no_reserve(), indent, &mut scratch);
    if scratch.contains('\n') {
        return false;
    }
    start_col + scratch.len() <= cfg.margin()
}

/// Render a binop chain with rustfmt's layout.
///
/// `col` is where the chain's first character (its outermost `(`) lands;
/// `indent` is the enclosing block indent. Broken operators go to
/// `chain_begin_line_indent + CHAIN_BREAK_INDENT`, where the begin-line indent is
/// the indentation of the line the chain starts on.
fn render_chain(
    operands: &[ChainOperand],
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    // Whole-chain-flat fast path: if the entire flattened chain fits on the
    // current line AND no operand carries a hard break (a statement-block always
    // breaks, forcing the chain broken), emit it inline with no operator breaks.
    //
    // The whole-flat and per-operator glue fit tests honor the trailing-delimiter
    // `reserve`: the `,` (or `),`) `rustfmt` appends after the chain reduces the
    // width the chain's single line may occupy. `chain_flat_fits_single_line`/
    // `glue_fits` subtract `cfg.reserve` via `cfg.margin()`.
    //
    // The whole-flat fast path requires the chain to render GENUINELY single-line,
    // not merely first-line-fits: an operand carrying an independent-layout construct
    // (a `CallArgs` whose statement-block argument breaks) hides its `HardLine` from
    // `no_hard_break`, yet its flat render still spans multiple lines. `fits` would
    // measure only the (short) first line and wrongly flatten the whole chain, gluing
    // the block; the single-line check rejects the embedded newline so the chain
    // breaks and each operand lays out its own multiline argument.
    //
    // Both the `no_hard_break` walk and the single-line probe are guarded behind the
    // `flat` short-circuit: an enclosing group that already chose flat takes the fast
    // path directly, so neither the operand scan nor a whole-chain clone runs.
    if flat
        || (operands.iter().all(|o| !has_hard_break(&o.doc))
            && chain_flat_fits_single_line(operands, cfg, col, indent))
    {
        render_chain_flat(operands, cfg, indent, out);
        return;
    }

    // Broken layout. The shared indent for broken operators is the chain
    // begin-line's indentation plus one block step. The begin-line indent is the
    // column the chain starts at when that column IS the line's indentation
    // (chain sits at the start of a fresh continuation line); otherwise it is the
    // enclosing block indent. rustfmt keys the break indent off the block indent
    // of the statement/line the chain begins on.
    let begin_indent = current_line_indent(out).unwrap_or(indent);
    let shared_indent = begin_indent + CHAIN_BREAK_INDENT;

    // Two distinct line-1 packing regimes, both ended permanently by the first
    // break:
    //   * `flat_prefix` — the initial run of single-line operands, packed
    //     greedily while the operator plus operand fits the width (stair,
    //     tinytail). The first operand that overflows ends it.
    //   * multiline glue — once an operand renders multiline, the NEXT operator
    //     glues to that operand's closing line if it fits; but a single-line
    //     operand after a multiline one does NOT re-open the flat prefix, so the
    //     operator after IT breaks (param_patterns: `+ sum_pair` breaks after the
    //     single-line `ignore_arg`).
    // `broken` latches on the first break: no operator glues afterward.
    let mut broken = false;
    let mut flat_prefix = true;
    let mut prev_multiline = false;
    for (i, operand) in operands.iter().enumerate() {
        if i == 0 {
            let c = eff_col(out, col);
            let before = out.len();
            render_at(&operand.doc, cfg, indent, c, false, out);
            prev_multiline = out[before..].contains('\n');
            flat_prefix = !prev_multiline;
            continue;
        }
        // Non-first operands always carry a leading operator (the builder
        // invariant); an absent one degrades to no operator rather than panicking.
        let op = operand.leading_op.as_deref().unwrap_or("");

        if !broken {
            let cur = current_col(out);
            let can_glue = if flat_prefix {
                // In the flat prefix, an operator glues to a FOLLOWING operand only
                // when that operand renders single-line and fits. `rustfmt` breaks
                // the chain BEFORE an operand that would itself render multiline — it
                // never opens a multiline operand mid-line in a broken chain (the sole
                // multiline glue is onto a PRECEDING operand's closing line, the
                // `prev_multiline` arm below).
                let (fits, single_line) = glue_fits(&operand.doc, cfg, cur, indent, op);
                // The single-line probe column matches `glue_fits`'s own render column,
                // so under a zero reserve the two renders coincide and its verdict is
                // reused; a nonzero reserve tightens the operand's margin, so re-probe.
                fits && if cfg.reserve == 0 {
                    single_line
                } else {
                    renders_single_line(&operand.doc, cfg, cur + 1 + op.len() + 1, indent)
                }
            } else {
                // Past the flat prefix, an operator glues only immediately after a
                // multiline operand, at that operand's closing-line column.
                prev_multiline && glue_fits(&operand.doc, cfg, cur, indent, op).0
            };
            if can_glue {
                out.push(' ');
                out.push_str(op);
                out.push(' ');
                let c = current_col(out);
                let before = out.len();
                render_at(&operand.doc, cfg, indent, c, false, out);
                prev_multiline = out[before..].contains('\n');
                if prev_multiline {
                    flat_prefix = false;
                }
                continue;
            }
            broken = true;
        }
        // Broken: operator on its own line at the shared indent, operand after it.
        out.push('\n');
        push_indent(shared_indent, out);
        out.push_str(op);
        out.push(' ');
        let c = current_col(out);
        render_at(&operand.doc, cfg, shared_indent, c, false, out);
    }
}

/// Render a bracket-delimited argument list with `rustfmt`'s call-argument
/// COMBINING rule. See [`Doc::CallArgs`]. `col` is where `open`'s first character
/// lands; `indent` is the enclosing block indent.
#[allow(
    clippy::too_many_arguments,
    reason = "renderer threads open/close/col/indent/flat"
)]
fn render_call_args(
    open: &Doc,
    elems: &[Doc],
    close: &Doc,
    trailing_comma: bool,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    flat: bool,
    out: &mut String,
) {
    let start_col = eff_col(out, col);

    // FLAT: the whole `open a, b close` is genuinely single-line, fits the width,
    // and its argument text fits `fn_call_width`. An enclosing group that already
    // chose flat forces this too.
    if flat || call_args_flat_fits(open, elems, close, cfg, start_col, indent) {
        render_at(open, cfg, indent, start_col, true, out);
        render_flat_elems(elems, cfg, indent, out);
        let c = current_col(out);
        render_at(close, cfg, indent, c, true, out);
        return;
    }

    render_call_args_broken(
        open,
        elems,
        close,
        trailing_comma,
        cfg,
        indent,
        start_col,
        out,
    );
}

/// The broken layout of a [`Doc::CallArgs`]: the multiline-open glue, the last-
/// argument combine, or the one-per-line break, in `rustfmt`'s order. Split out of
/// [`render_call_args`] so the flat-fallback give-up can probe it before committing.
#[allow(
    clippy::too_many_arguments,
    reason = "renderer threads open/close/col/indent"
)]
fn render_call_args_broken(
    open: &Doc,
    elems: &[Doc],
    close: &Doc,
    trailing_comma: bool,
    cfg: RenderConfig,
    indent: usize,
    start_col: usize,
    out: &mut String,
) {
    // MULTILINE-OPEN GLUE: the `open` itself renders multi-line — a `(func)(args)`
    // whose `func` is a `({ … })` block that breaks — but the flat argument list
    // fits on the open's LAST line. `rustfmt` glues `(args)` onto the block's closing
    // `})` line rather than breaking the tiny argument list one-per-line. Render the
    // open non-flat, then the flat args and close on its last line.
    if !elems.is_empty() {
        // Render `open` once; its multiline-ness and closing column both read off
        // this single probe (the glue path re-renders it into `out` below).
        let mut probe = String::new();
        render_at(open, cfg.no_reserve(), indent, start_col, false, &mut probe);
        if probe.contains('\n') {
            let open_last = current_col(&probe);
            let mut argscratch = String::new();
            render_flat_elems(elems, cfg, indent, &mut argscratch);
            render_at(
                close,
                cfg.no_reserve(),
                indent,
                open_last,
                true,
                &mut argscratch,
            );
            if !argscratch.contains('\n') && open_last + argscratch.len() <= cfg.margin() {
                render_at(open, cfg.no_reserve(), indent, start_col, false, out);
                render_flat_elems(elems, cfg, indent, out);
                let c = current_col(out);
                render_at(close, cfg, indent, c, true, out);
                return;
            }
        }
    }

    // COMBINED (last-argument overflow / head-glue): the LAST element is a
    // combinable construct, and the head + every preceding argument (flat) + the
    // last element's own first line all fit on the first line within the width and
    // `fn_call_width`. `rustfmt` glues them and lets the last element break IN PLACE
    // at the current block indent — FORCED broken so it provides the multiline the
    // combine needs — then glues `close` onto its closing line: `f(a, g(\n …\n))` /
    // `f(g(\n …\n))` for the sole-argument case. No trailing comma.
    if let Some((last, prefix)) = elems.split_last() {
        // Outermost combine: the `fn_call_width` budget is measured from where THIS
        // call's arguments begin, and shared by every nested combine below. The
        // recursive `Shape` budget handed to `last` is `min(max_width − arg-start,
        // fn_call_width)`; each nested combine shrinks it one step.
        let open_end = start_col + flat_leaf_len(open);
        let budget = FN_CALL_WIDTH.min(cfg.max_width.saturating_sub(open_end));
        if last_arg_combines(
            open,
            prefix,
            last,
            None,
            Some(budget),
            cfg,
            start_col,
            indent,
        )
        .is_some()
        {
            render_at(open, cfg, indent, start_col, false, out);
            let base = current_col(out);
            for e in prefix {
                let c = current_col(out);
                render_at(e, cfg, indent, c, true, out);
                out.push_str(", ");
            }
            render_forced_break(last, base, budget, cfg, indent, current_col(out), out);
            let c = current_col(out);
            render_at(close, cfg, indent, c, false, out);
            return;
        }
    }

    // ONE-PER-LINE: `open`, each element on its own line at one indent step, a
    // break-conditional trailing comma (suppressed for a macro list), the close
    // dedented back to the group's start column.
    render_one_per_line(
        open,
        elems,
        close,
        trailing_comma,
        cfg,
        indent,
        start_col,
        out,
    );
}

/// Lay a delimited list out one element per line: `open`, each element on its own
/// line at one indent step, a trailing `,` after each (suppressed for the final
/// element of a macro list), the `close` dedented back to `start_col`. Each
/// element's last line carries a trailing comma, so it is rendered with a
/// one-column trailing `reserve` — `rustfmt`'s `Shape` width reduced by the comma
/// — while `open`/`close` open the list's own delimiters (enclosing reserve
/// cleared). Shared by the plain one-per-line break and the forced-break fallback.
#[allow(
    clippy::too_many_arguments,
    reason = "renderer threads open/close/col/indent"
)]
fn render_one_per_line(
    open: &Doc,
    elems: &[Doc],
    close: &Doc,
    trailing_comma: bool,
    cfg: RenderConfig,
    indent: usize,
    start_col: usize,
    out: &mut String,
) {
    render_at(open, cfg.no_reserve(), indent, start_col, false, out);
    let inner_indent = indent + CHAIN_BREAK_INDENT;
    let last = elems.len().saturating_sub(1);
    for (i, e) in elems.iter().enumerate() {
        out.push('\n');
        push_indent(inner_indent, out);
        let c = current_col(out);
        let has_comma = i < last || trailing_comma;
        let elem_cfg = if has_comma {
            cfg.with_reserve(1)
        } else {
            cfg.no_reserve()
        };
        render_at(e, elem_cfg, inner_indent, c, false, out);
        if has_comma {
            out.push(',');
        }
    }
    out.push('\n');
    push_indent(indent, out);
    let c = current_col(out);
    render_at(close, cfg, indent, c, false, out);
}

/// Whether the flat single-line form `open a, b close` may lay out flat from
/// `start_col`. Three conditions: it is genuinely single-line (no element embeds a
/// newline — a statement block forces the broken layout); the whole line fits
/// `max_width`; and, for a function-call/ctor/tuple list (`trailing_comma`), the
/// argument text (between the delimiters) fits `fn_call_width`. `rustfmt` breaks a
/// call whose argument list exceeds `fn_call_width` one argument per line even when
/// the whole line would still fit `max_width`. A macro list (`format!` / `vec!`,
/// `trailing_comma == false`) is not gated by `fn_call_width` here — it uses a
/// wrap-to-`max_width` layout decided elsewhere.
fn call_args_flat_fits(
    open: &Doc,
    elems: &[Doc],
    close: &Doc,
    cfg: RenderConfig,
    start_col: usize,
    indent: usize,
) -> bool {
    // The full flat line, for the single-line + `max_width` checks.
    let mut scratch = String::new();
    render_at(open, cfg, indent, start_col, true, &mut scratch);
    let open_end = current_col(&scratch);
    render_flat_elems(elems, cfg, indent, &mut scratch);
    let elems_end = current_col(&scratch);
    render_at(close, cfg, indent, elems_end, true, &mut scratch);
    if scratch.contains('\n') {
        return false;
    }
    if start_col + scratch.len() > cfg.max_width {
        return false;
    }
    // A sole BLOCK-LIKE argument (a `move |…|` / `|…|` closure or a brace block,
    // possibly behind a `Box::new(` wrapper) is `rustfmt`'s `overflow_delimited_expr`:
    // it is NOT gated by `fn_call_width`. Its flat form holds whenever the whole line
    // fits `max_width` (checked above) and stays single-line (`{ body }` inline) — so
    // `Box::new(move |x| { short_body })` stays on one line even though its argument
    // text exceeds 60 columns, breaking only when the line itself overflows.
    if let [only] = elems
        && is_block_like(only)
    {
        return true;
    }
    // `fn_call_width`: an argument list wider than 60 columns breaks even when the
    // whole line still fits `max_width`. The argument text is the span from just
    // after the opening delimiter to just before the closing one. This gates
    // function calls, constructors, tuples AND macro (`format!` / `vec!`) lists —
    // `rustfmt` applies the same 60-column argument budget to all of them.
    //
    // A single-argument call wrapping another combinable construct (`Box::new((a, b))`,
    // `outer(inner(a, b))`) is TRANSPARENT to this gate: `rustfmt` measures the
    // INNERMOST combinable's argument text, not the wrapper's (which includes the
    // inner delimiters). So `Box::new((a, b))` stays flat when `a, b` fits
    // `fn_call_width`, even though `(a, b)` plus the wrapper does not.
    let args_width = innermost_args_width(elems, open_end, elems_end);
    if args_width > FN_CALL_WIDTH {
        return false;
    }
    true
}

/// The `fn_call_width` argument text width of a call, seeing through a single-argument
/// combinable wrapper (`Box::new(<inner>)`, `outer(<inner>)`) to the INNERMOST
/// combinable's own argument text. `rustfmt` gates the flat layout on that innermost
/// width, not the wrapper's (which would double-count the inner delimiters). `open_end`
/// / `elems_end` bound the current call's own argument span; a single combinable inner
/// element recurses one delimiter step deeper.
fn innermost_args_width(elems: &[Doc], open_end: usize, elems_end: usize) -> usize {
    if let [only @ Doc::CallArgs { open, close, elems: inner, .. }] = elems
        // Only a DELIMITED-LITERAL inner (a tuple `(…)`, array `[…]` / `vec![…]`, or a
        // `Box::new(<delimited>)` wrapper of one) is transparent to `fn_call_width` —
        // `rustfmt`'s `overflow_delimited_expr`. A nested CALL or MACRO is measured with
        // its own delimiters counted (its combining is driven by the recursive `Shape`
        // budget, not this flat gate), so seeing through it would wrongly flatten a call
        // whose deep-nested budget has already run out.
        && is_delimited_expr(only)
    {
        let inner_open = open_end + flat_leaf_len(open);
        let inner_close = elems_end.saturating_sub(flat_leaf_len(close));
        return innermost_args_width(inner, inner_open, inner_close);
    }
    elems_end.saturating_sub(open_end)
}

/// Render the elements flat, separated by `, ` — the shared flat body of a
/// [`Doc::CallArgs`] (no trailing comma, matching the string emitter's join).
fn render_flat_elems(elems: &[Doc], cfg: RenderConfig, indent: usize, out: &mut String) {
    for (i, e) in elems.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        let c = current_col(out);
        render_at(e, cfg, indent, c, true, out);
    }
}

/// Whether the LAST element of a [`Doc::CallArgs`] can be COMBINED with the head
/// under `rustfmt`'s last-argument-overflow / combining rule — and if so, the
/// column its first character lands on (right after the flat `open a, b, ` head).
/// `open` and every preceding argument glue onto the first line, the last element
/// breaks in place (forced), and `close` glues onto its closing line, rather than
/// the whole list breaking one argument per line.
///
/// Gates, all required:
///
///   * STRUCTURAL — the last element must be a combinable construct: its own
///     braced/bracketed break — a [`Doc::CallArgs`] (call / macro / ctor / tuple /
///     list) or a brace block (a closure body / statement block opening with `{`),
///     possibly behind a leading `Box::new(` / `Some(` wrapper. A [`Doc::Chain`]
///     (a parenthesized operator run) and a parenthesized statement block
///     (`({ … })`) are NOT combinable — `rustfmt` breaks the outer list instead.
///   * PREFIX-FLAT — every preceding argument must sit flat on the first line.
///   * FIRST-LINE FIT — the head + preceding args + the last element's own
///     forced-broken first line must fit `max_width`, and the combined ARGUMENT
///     text on the first line must fit `fn_call_width` (the same budget a flat
///     call list obeys) so a call whose combined head overflows breaks one-per-line
///     instead.
#[allow(
    clippy::too_many_arguments,
    reason = "renderer threads combine base + col/indent"
)]
fn last_arg_combines(
    open: &Doc,
    prefix: &[Doc],
    last: &Doc,
    combine_base: Option<usize>,
    budget: Option<usize>,
    cfg: RenderConfig,
    start_col: usize,
    indent: usize,
) -> Option<usize> {
    // A SINGLE-argument call glues its argument's head freely (the combine chain
    // "may nest further, as long as all but the innermost construct have only a
    // single argument"); a MULTI-argument call overflows its LAST argument only when
    // that argument is a DELIMITED expression (a block / closure / tuple / array /
    // struct) — not a plain nested function call — subject to `fn_call_width`.
    let single_arg = prefix.is_empty();
    if single_arg {
        if !is_glue_shape(last) {
            return None;
        }
    } else if !is_delimited_expr(last) {
        return None;
    }
    // Build the first-line prefix (`open a, b, `) flat to find where `last` lands.
    let mut scratch = String::new();
    render_at(open, cfg, indent, start_col, true, &mut scratch);
    let open_end = current_col(&scratch);
    for e in prefix {
        let c = current_col(&scratch);
        render_at(e, cfg, indent, c, true, &mut scratch);
        scratch.push_str(", ");
    }
    if scratch.contains('\n') {
        // A preceding argument is itself multiline — it cannot sit flat.
        return None;
    }
    let last_col = start_col + scratch.len();
    if last_col > cfg.max_width {
        return None;
    }
    // The `fn_call_width` budget is measured from the OUTERMOST combining call's
    // argument-start column, shared by this and every nested combine — a deep glue
    // chain shares one 60-column budget, so an over-wide combined head breaks at
    // the level where the budget runs out rather than gluing indefinitely.
    let base = combine_base.unwrap_or(open_end);
    // A single-argument call glues ONLY when its argument cannot itself sit flat
    // within the shared budget — i.e. the argument's flat form (from the shared
    // base) overflows `fn_call_width`, or it is intrinsically multiline. When the
    // argument fits flat within that budget, `rustfmt` breaks the single-argument
    // call one-per-line to give the flat argument its own line rather than gluing.
    // A BLOCK-LIKE argument (a `move |…|` closure or a brace block) is `rustfmt`'s
    // `overflow_delimited_expr`: it is ALWAYS glued onto the call head, with only its
    // OWN body breaking — the call is never broken one-per-line to give it its own
    // line. So the "break to give the flat argument its own line" heuristic below is
    // skipped for it; only the first-line-fit gate (further down) can reject the glue.
    if single_arg && !has_hard_break(last) && !is_block_like(last) {
        let mut flat = String::new();
        render_at(last, cfg, indent, last_col, true, &mut flat);
        if !flat.contains('\n') && (last_col + flat.len()).saturating_sub(base) <= FN_CALL_WIDTH {
            return None;
        }
        // Recursive `Shape` budget: `rustfmt` shrinks the combining width one step per
        // nested single-argument call — `min(width − callee(, fn_call_width)` — and
        // breaks THIS call one-per-line (giving its argument its own line) rather than
        // gluing when the width for THIS call's argument runs out. `budget` is the
        // width the enclosing combine handed this call; shrinking it by this call's own
        // `open` gives the width available to open the argument's combining head. A flat
        // `fn_call_width` from the outermost base cannot see this shrink and keeps
        // gluing an ever-deeper chain past the point `rustfmt` stops. When the shrunk
        // budget cannot open the argument's head, break this call one-per-line.
        if let Some(b) = budget {
            let arg_budget = shrink_budget(b, open);
            let head_len = flat_leaf_len(last_head(last));
            if arg_budget <= head_len {
                return None;
            }
        }
    }
    // Render the last element FORCED broken from that column; its first line is the
    // combined head's tail. `budget` (when threaded) is the recursive `Shape` width
    // for `last`; a probe without a threaded budget measures at the full `fn_call_width`.
    let mut tail = String::new();
    render_forced_break(
        last,
        base,
        budget.unwrap_or(FN_CALL_WIDTH),
        cfg,
        indent,
        last_col,
        &mut tail,
    );
    let first = tail.split('\n').next().unwrap_or("");
    let first_line_end = last_col + first.len();
    if first_line_end > cfg.max_width {
        return None;
    }
    // A multi-argument overflow's combined first line obeys `fn_call_width`; a
    // single-argument glue chain is exempt (it only nests through single-arg heads).
    if !single_arg && first_line_end.saturating_sub(base) > FN_CALL_WIDTH {
        return None;
    }
    Some(last_col)
}

/// Render `doc` at `col` in FORCED-broken mode: a combinable construct is laid out
/// multiline even when its own width would fit flat, because it is the multiline
/// target of an enclosing call-argument combine. A [`Doc::CallArgs`] recurses the
/// combine on ITS last argument (sharing `combine_base` for the `fn_call_width`
/// budget), else breaks its argument list one per line; any other doc falls back to
/// the standard non-flat render (a statement block / closure body already breaks).
fn render_forced_break(
    doc: &Doc,
    combine_base: usize,
    budget: usize,
    cfg: RenderConfig,
    indent: usize,
    col: usize,
    out: &mut String,
) {
    match doc {
        Doc::CallArgs {
            open,
            elems,
            close,
            trailing_comma,
        } => {
            let start_col = eff_col(out, col);
            // Recurse the combine on the last argument first; if it does not apply,
            // fall through to the one-per-line break. The shared `combine_base` keeps
            // the `fn_call_width` budget anchored at the outermost combine; `budget`
            // is the recursive `Shape` width this call received for its argument, and
            // shrinks one step (`shrink_budget`) as the combine descends.
            if let Some((last, prefix)) = elems.split_last()
                && last_arg_combines(
                    open,
                    prefix,
                    last,
                    Some(combine_base),
                    Some(budget),
                    cfg,
                    start_col,
                    indent,
                )
                .is_some()
            {
                render_at(open, cfg, indent, start_col, false, out);
                for e in prefix {
                    let c = current_col(out);
                    render_at(e, cfg, indent, c, true, out);
                    out.push_str(", ");
                }
                let inner_budget = shrink_budget(budget, open);
                render_forced_break(
                    last,
                    combine_base,
                    inner_budget,
                    cfg,
                    indent,
                    current_col(out),
                    out,
                );
                let c = current_col(out);
                render_at(close, cfg, indent, c, false, out);
                return;
            }
            // One argument per line.
            render_one_per_line(
                open,
                elems,
                close,
                *trailing_comma,
                cfg,
                indent,
                start_col,
                out,
            );
        }
        // A struct literal `Name { … }` forced broken: one field per line. Its own
        // `struct_lit_width` re-test does not apply here (the combine forced it
        // multiline), so break its fields directly.
        Doc::StructLit {
            open,
            fields,
            close,
        } => {
            let start_col = eff_col(out, col);
            render_one_per_line(open, fields, close, true, cfg, indent, start_col, out);
        }
        // A wrapper like `Box::new(<CallArgs>)` / `Box::new(<StructLit>)`, or a
        // `move |…| -> R <braced-block>` closure: force-break the inner construct. A
        // leading wrapper text (`Box::new(`) shrinks the recursive `Shape` budget one
        // step before the inner combine. A closure's trailing braced-block `Group`
        // must be FORCED broken (its body onto its own line) — `rustfmt`'s
        // `overflow_delimited_expr` opens a block-like argument's body rather than
        // keeping it flat, even when the flat body alone would fit.
        Doc::Concat(parts) => {
            let is_closure = matches!(parts.first(), Some(Doc::Text(h)) if is_closure_head(h));
            let last = parts.len().saturating_sub(1);
            let mut inner_budget = budget;
            for (i, p) in parts.iter().enumerate() {
                let c = eff_col(out, col);
                if matches!(p, Doc::CallArgs { .. } | Doc::StructLit { .. }) {
                    render_forced_break(p, combine_base, inner_budget, cfg, indent, c, out);
                } else if (is_closure && i == last) || matches!(p, Doc::BraceBody(_)) {
                    // A closure body block, or a `BraceBody` inside a wrapper like
                    // `Box::new(move |_| <body>)`: force it broken. `rustfmt`'s
                    // `overflow_delimited_expr` opens a block-like argument's body onto
                    // its own line rather than keeping it flat, even when the flat body
                    // alone would fit — so the continuation closure of a broken
                    // `task_and_then` always braces (`Box::new(move |_| {\n … })`).
                    render_group_broken(p, cfg, indent, c, out);
                } else {
                    if let Doc::Text(_) = p {
                        inner_budget =
                            FN_CALL_WIDTH.min(inner_budget.saturating_sub(flat_leaf_len(p)));
                    }
                    render_at(p, cfg, indent, c, false, out);
                }
            }
        }
        // Any other doc breaks on its own (a block / closure body carries a
        // `HardLine`); render it non-flat.
        _ => render_at(doc, cfg, indent, col, false, out),
    }
}

/// Render a closure's braced body block with its braces/soft breaks FORCED — the
/// body onto its own line at one indent step, matching `rustfmt`'s
/// `overflow_delimited_expr` which opens a block-like argument even when its flat
/// body would fit. A `Group` body has its soft breaks forced; a `BraceBody` body is
/// forced to its braced multiline form (a `move |…| -> R ` closure carries a `Group`
/// body, a bare `|…| ` closure carries a `BraceBody`). Any other doc (a statement
/// block already carrying `HardLine`s) falls back to the standard non-flat render,
/// which breaks it anyway.
fn render_group_broken(doc: &Doc, cfg: RenderConfig, indent: usize, col: usize, out: &mut String) {
    match doc {
        Doc::Group(inner) => {
            let start_col = eff_col(out, col);
            render_at(inner, cfg, indent, start_col, false, out);
        }
        // A `BraceBody` closure body forced to its braced multiline form: the `|…| `
        // CAF closure body (a statement block) is opened here exactly as the
        // `move |…| -> R` closure's `Group` body is, so the combine glues the head
        // and breaks the body in place.
        Doc::BraceBody(body) => {
            let start_col = eff_col(out, col);
            render_brace_body_broken(body, cfg, indent, start_col, out);
        }
        _ => render_at(doc, cfg, indent, col, false, out),
    }
}

/// The opening head leaf (`f(`, `Box::new((`, `(`) of a combinable construct — the
/// text a nested combine glues onto and whose width shrinks the recursive `Shape`
/// budget one step. A [`Doc::CallArgs`] head is its `open`; a text-wrapped single
/// inner (`Box::new(<inner>)`) head is its leading `(`-terminated text; anything else
/// has no combining head (returns an empty leaf, width 0).
fn last_head(doc: &Doc) -> &Doc {
    match doc {
        Doc::CallArgs { open, .. } | Doc::StructLit { open, .. } => open,
        Doc::Concat(parts) => match parts.first() {
            Some(t @ Doc::Text(h)) if h.ends_with('(') && !h.contains('{') => t,
            _ => &EMPTY_LEAF,
        },
        _ => &EMPTY_LEAF,
    }
}

/// An empty text leaf, the zero-width combining head of a non-combinable construct.
static EMPTY_LEAF: Doc = Doc::Text(std::borrow::Cow::Borrowed(""));

/// The flat-rendered length of a delimiter/head leaf (`f(`, `Box::new((`), used to
/// shrink the recursive combining budget one nesting step.
fn flat_leaf_len(doc: &Doc) -> usize {
    let mut s = String::new();
    let cfg = RenderConfig::default();
    render_at(doc, cfg, 0, 0, true, &mut s);
    s.len()
}

/// The combining budget handed to a nested call's argument: the parent's budget
/// reduced by the parent call's own opening head, re-clamped to `fn_call_width`.
/// `rustfmt` shrinks the `Shape` width this way one step per nested combine.
fn shrink_budget(parent: usize, open: &Doc) -> usize {
    FN_CALL_WIDTH.min(parent.saturating_sub(flat_leaf_len(open)))
}

/// Whether `head` is a closure's parameter-list head — a `move |…| ` capturing
/// closure or a bare `|…| ` closure — that `rustfmt` glues a call head onto, letting
/// only the closure body break. Both open the same block-like layout; the sole
/// difference is the `move` capture keyword.
fn is_closure_head(head: &str) -> bool {
    head.starts_with("move |") || head == "|| "
}

/// Whether `doc` is a BLOCK-LIKE argument — a `|…|` / `move |…|` closure or a brace
/// block `{ … }` — that `rustfmt`'s `overflow_delimited_expr` always glues onto the
/// call head (breaking only its own body), rather than breaking the call one-per-line
/// to give the argument its own line. A `Box::new(<block-like>)` wrapper counts (the
/// wrapper glues and the inner block breaks). Distinct from [`is_glue_shape`], which
/// also admits nested calls / macros / tuples that DO get their own line when they
/// fit flat within the shared budget.
fn is_block_like(doc: &Doc) -> bool {
    match doc {
        Doc::BraceBody(_) => true,
        Doc::Group(inner) => is_block_like(inner),
        Doc::Concat(parts) => match parts.first() {
            // A `|…| ` / `move |…| ` closure head, or a brace block `{ … }` that is
            // not a `({` paren-wrapped statement block.
            Some(Doc::Text(head)) if is_closure_head(head) => true,
            Some(Doc::Text(head)) if head.ends_with('{') && !head.starts_with('(') => true,
            // A `Box::new(<block-like>)` / `Some(<block-like>)` wrapper.
            Some(Doc::Text(head)) if head.ends_with('(') && !head.contains('{') => {
                parts.get(1).is_some_and(is_block_like)
            }
            _ => false,
        },
        _ => false,
    }
}

/// Whether `doc` is a GLUE-shaped construct for the SINGLE-argument combine chain:
/// a [`Doc::CallArgs`] (any call / macro / ctor / tuple / list whose own delimiters
/// the outer head glues onto), a brace block (`{ … }`), or either behind a leading
/// `Box::new(` / `Some(` text wrapper. A [`Doc::Chain`] and a parenthesized
/// statement block (`({ … })`) are NOT glue-shaped.
fn is_glue_shape(doc: &Doc) -> bool {
    match doc {
        // A call/ctor/macro/tuple/list glues onto its own delimiters, and a struct
        // literal (`Name { … }`) is a brace-delimited construct `rustfmt` glues a
        // wrapper's head onto just like a call's `(`.
        Doc::CallArgs { .. } | Doc::StructLit { .. } => true,
        Doc::Group(inner) => is_glue_shape(inner),
        Doc::Concat(parts) => match parts.first() {
            // A `|…| ` / `move |…| ` closure head followed by its braced body — a
            // block-like expression `rustfmt` glues a wrapper's `(` onto, letting the
            // closure body break in place while the head stays on the wrapper's line.
            Some(Doc::Text(head)) if is_closure_head(head) => true,
            // A brace block `{ … }` (closure body / statement block) or a struct
            // literal `Name { … }` — a `{`-terminated head that is NOT a `({`
            // paren-wrapped statement block (which `rustfmt` does NOT combine).
            Some(Doc::Text(head)) if head.ends_with('{') && !head.starts_with('(') => true,
            // A `Box::new(<inner>)` / `Some(<inner>)` wrapper: a `(`-terminated head
            // (NOT a `({` paren-block), the inner glue construct, then a `)` tail.
            Some(Doc::Text(head)) if head.ends_with('(') && !head.contains('{') => {
                parts.get(1).is_some_and(is_glue_shape)
            }
            _ => false,
        },
        _ => false,
    }
}

/// Whether `doc` is a DELIMITED EXPRESSION for the MULTI-argument last-argument
/// overflow rule (`rustfmt`'s `overflow_delimited_expr`): a brace block / closure
/// body (`{ … }`), a tuple (`(…)`), or an array (`vec![…]`). A nested function CALL
/// or constructor is NOT a delimited expr for this rule — a multi-argument call
/// whose last argument is a plain call breaks one argument per line rather than
/// overflowing. A `Box::new(<delimited>)` wrapper counts (its inner is delimited).
fn is_delimited_expr(doc: &Doc) -> bool {
    match doc {
        Doc::CallArgs { open, elems, .. } => match open.as_ref() {
            // A tuple `(` or an array `vec![` / `[`.
            Doc::Text(h) if h.as_ref() == "(" || h.ends_with('[') => true,
            // A `Box::new(<delimited>)` / `Some(<delimited>)` single-arg wrapper:
            // delimited iff its inner is (its own `(`-ended named head).
            Doc::Text(h) if h.ends_with('(') && !h.contains('{') && elems.len() == 1 => {
                elems.first().is_some_and(is_delimited_expr)
            }
            _ => false,
        },
        // A struct literal (`Name { … }`) is a brace construct — a delimited expr
        // for the overflow rule.
        Doc::StructLit { .. } => true,
        Doc::Group(inner) => is_delimited_expr(inner),
        Doc::Concat(parts) => match parts.first() {
            // A brace block `{ … }` or a struct literal `Name { … }` — a
            // `{`-terminated head that is NOT a `({` paren-wrapped statement block.
            Some(Doc::Text(head)) if head.ends_with('{') && !head.starts_with('(') => true,
            Some(Doc::Text(head)) if head.ends_with('(') && !head.contains('{') => {
                parts.get(1).is_some_and(is_delimited_expr)
            }
            _ => false,
        },
        _ => false,
    }
}

/// Whether `op operand` glued onto the current line fits, paired with whether the
/// glued operand rendered single-line. The operand may render multiline; the fit
/// test measures only whether `op` plus the operand's FIRST line fits at the
/// current column (a multiline operand's later lines are free to break below). A
/// single-line operand must fit entirely. The `single_line` flag is the same fact
/// [`renders_single_line`] measures at the same column under a zero reserve, so a
/// caller with `cfg.reserve == 0` reads it here instead of re-rendering.
fn glue_fits(
    operand: &Doc,
    cfg: RenderConfig,
    col: usize,
    indent: usize,
    op: &str,
) -> (bool, bool) {
    // Column after " op " is appended.
    let after_op = col + 1 + op.len() + 1;
    if after_op > cfg.margin() {
        return (false, false);
    }
    let mut scratch = String::new();
    render_at(
        operand,
        cfg.no_reserve(),
        indent,
        after_op,
        false,
        &mut scratch,
    );
    let first_line = scratch.split('\n').next().unwrap_or("");
    let single_line = !scratch.contains('\n');
    // The trailing-delimiter `reserve` bites only when the operand renders
    // single-line here — then this glued line IS the chain's last line and the
    // enclosing `,` sits at its end. A multiline operand ends on a later line, so
    // its glued first line is measured against the full width.
    let margin = if single_line {
        cfg.margin()
    } else {
        cfg.max_width
    };
    (after_op + first_line.len() <= margin, single_line)
}

/// Whether `operand`, rendered non-flat from `col`, stays on a single line. A chain
/// operator glues to a FOLLOWING operand only when the operand is single-line;
/// `rustfmt` breaks the chain before an operand that would itself render multiline.
fn renders_single_line(operand: &Doc, cfg: RenderConfig, col: usize, indent: usize) -> bool {
    let mut scratch = String::new();
    render_at(operand, cfg, indent, col, false, &mut scratch);
    !scratch.contains('\n')
}

/// The indentation (leading-space count) of the line currently being written in
/// `out`, or `None` if the current line has non-space content already (the chain
/// starts mid-line, e.g. after `let z = `).
fn current_line_indent(out: &str) -> Option<usize> {
    let line_start = out.rfind('\n').map_or(0, |nl| nl + 1);
    let line = &out[line_start..];
    if line.chars().all(|c| c == ' ') {
        Some(line.len())
    } else {
        // Mid-line start: the break indent is keyed off the enclosing block, not
        // this column. Signal by returning None so the caller falls back to the
        // block indent.
        None
    }
}

/// Render every operand of a chain flat (inline), operators separated by spaces.
fn render_chain_flat(
    operands: &[ChainOperand],
    cfg: RenderConfig,
    indent: usize,
    out: &mut String,
) {
    for (i, operand) in operands.iter().enumerate() {
        if i > 0 {
            out.push(' ');
            out.push_str(operand.leading_op.as_deref().unwrap_or(""));
            out.push(' ');
        }
        let c = current_col(out);
        render_at(&operand.doc, cfg, indent, c, true, out);
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used, reason = "test assertions")]
mod p0_tests {
    //! P0 exit-gate: byte-diff the renderer against real-rustfmt output for the
    //! panel probe set. These fixtures are captured from
    //! `rustfmt --edition 2024 --style-edition 2024`; the renderer is fixed to
    //! match them, never the reverse.

    use super::*;
    use crate::doc::{ChainOperand, Doc};
    use std::borrow::Cow;

    /// A chain operand from a plain text leaf.
    fn op(leading: Option<&'static str>, text: String) -> ChainOperand {
        ChainOperand {
            leading_op: leading.map(Cow::Borrowed),
            doc: Doc::owned(text),
        }
    }

    /// Render a chain doc placed after `prefix` at block `indent`, returning the
    /// whole line(s) so the mid-line start column matches rustfmt's.
    fn render_line(prefix: &str, indent: usize, operands: &[ChainOperand]) -> String {
        let mut out = String::from(prefix);
        let col = current_col(&out);
        render_chain(
            operands,
            RenderConfig::default(),
            indent,
            col,
            false,
            &mut out,
        );
        out
    }

    #[test]
    fn stair_single_line_operands_break_tail_to_shared_indent() {
        // `let z = (((((aaaa(x) + b) + c) + d) + e) + f);` — all single-line
        // operands; line-1 packs the maximal flat-fitting prefix, then `+ e` and
        // `+ f` each break to col 8 (block indent 4 + 4). Captured from rustfmt.
        let operands = vec![
            op(None, "(((((longfunctioncallnamehere_aaaa(x)".into()),
            op(Some("+"), "bbbbbbbbbbb)".into()),
            op(Some("+"), "ccccccccccc)".into()),
            op(Some("+"), "ddddddddddd)".into()),
            op(Some("+"), "eeeeeeeeeee)".into()),
            op(
                Some("+"),
                "ffffffffffffffffffffffffffffffffffffffffffffff)".into(),
            ),
        ];
        let got = render_line("    let z = ", 4, &operands);
        let expected = "    let z = (((((longfunctioncallnamehere_aaaa(x) + bbbbbbbbbbb) + ccccccccccc) + ddddddddddd)\n        + eeeeeeeeeee)\n        + ffffffffffffffffffffffffffffffffffffffffffffff)";
        assert_eq!(
            got, expected,
            "\n--- got ---\n{got}\n--- want ---\n{expected}"
        );
    }

    #[test]
    fn stair2_tiny_tail_still_breaks() {
        // `+ ff` is tiny and fits remaining width, yet STILL breaks to the shared
        // indent: proves post-boundary breaks are unconditional, not width-tested.
        let operands = vec![
            op(
                None,
                "(((((longfunctioncallnamehere_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa(x)".into(),
            ),
            op(Some("+"), "bbbbbbbbbbb)".into()),
            op(Some("+"), "ccccccccccc)".into()),
            op(Some("+"), "ddddddddddd)".into()),
            op(Some("+"), "eeeeeeeeeee)".into()),
            op(Some("+"), "ff)".into()),
        ];
        let got = render_line("    let z = ", 4, &operands);
        let expected = "    let z = (((((longfunctioncallnamehere_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa(x) + bbbbbbbbbbb)\n        + ccccccccccc)\n        + ddddddddddd)\n        + eeeeeeeeeee)\n        + ff)";
        assert_eq!(
            got, expected,
            "\n--- got ---\n{got}\n--- want ---\n{expected}"
        );
    }

    /// A `{ <decl> <tail> }` block Doc with a statement, which ALWAYS breaks (a
    /// block containing any statement is never inlined — spec rule 3). The
    /// statement separators are `HardLine`s, so the block breaks unconditionally
    /// and forces any enclosing group broken, whatever the width.
    fn block(decl: &'static str, tail: &'static str) -> Doc {
        Doc::concat(vec![
            Doc::text("{"),
            Doc::nest(
                4,
                Doc::concat(vec![
                    Doc::HardLine,
                    Doc::text(decl),
                    Doc::HardLine,
                    Doc::text(tail),
                ]),
            ),
            Doc::HardLine,
            Doc::text("}"),
        ])
    }

    /// A `name(a, b, c)` call Doc whose arg list breaks one-per-line when it does
    /// not fit: `name(` + nested Softline-separated args with trailing comma, then
    /// Softline + `)`.
    fn call(name: &'static str, args: &[&'static str]) -> Doc {
        let mut inner = vec![];
        for a in args {
            inner.push(Doc::Softline);
            inner.push(Doc::owned(format!("{a},")));
        }
        Doc::group(Doc::concat(vec![
            Doc::owned(format!("{name}(")),
            Doc::nest(4, Doc::concat(inner)),
            Doc::Softline,
            Doc::text(")"),
        ]))
    }

    #[test]
    fn callbreak_two_operand_glue_after_forced_break_call() {
        // `(bcall(<3 long args, forced break>) + cccccccccccccccc)` — the left
        // operand's arg list breaks; the `+ c` operator GLUES to the `)` closing
        // line because it fits. Captured from rustfmt.
        let operands = vec![
            ChainOperand {
                leading_op: None,
                doc: Doc::concat(vec![
                    Doc::text("("),
                    call(
                        "bcall",
                        &[
                            "argument_number_one_long",
                            "argument_number_two_long",
                            "argument_number_three_verylong",
                        ],
                    ),
                ]),
            },
            op(Some("+"), "cccccccccccccccc)".into()),
        ];
        let got = render_line("    let z = ", 4, &operands);
        let expected = "    let z = (bcall(\n        argument_number_one_long,\n        argument_number_two_long,\n        argument_number_three_verylong,\n    ) + cccccccccccccccc)";
        assert_eq!(
            got, expected,
            "\n--- got ---\n{got}\n--- want ---\n{expected}"
        );
    }

    #[test]
    fn hyp_multiline_operand_drives_next_operator_glue() {
        // `(((mlcall_one({...}) + slshort) + mlcall_two({...})) + tail)`:
        //   op1 glues (operand0 multiline), op2 breaks (operand1 single-line),
        //   op3 breaks (already broken). Captured from rustfmt.
        let operands = vec![
            ChainOperand {
                leading_op: None,
                doc: Doc::concat(vec![
                    Doc::text("(((mlcall_one("),
                    block(
                        "let a = something_long_enough_to_force_break_here_now;",
                        "a",
                    ),
                    Doc::text(")"),
                ]),
            },
            op(Some("+"), "slshort)".into()),
            ChainOperand {
                leading_op: Some(Cow::Borrowed("+")),
                doc: Doc::concat(vec![
                    Doc::text("mlcall_two("),
                    block("let b = another_thing_long_enough_to_break_it;", "b"),
                    Doc::text("))"),
                ]),
            },
            op(Some("+"), "tail_operand_x)".into()),
        ];
        let got = render_line("    let z = ", 4, &operands);
        let expected = "    let z = (((mlcall_one({\n        let a = something_long_enough_to_force_break_here_now;\n        a\n    }) + slshort)\n        + mlcall_two({\n            let b = another_thing_long_enough_to_break_it;\n            b\n        }))\n        + tail_operand_x)";
        assert_eq!(
            got, expected,
            "\n--- got ---\n{got}\n--- want ---\n{expected}"
        );
    }

    #[test]
    fn whole_chain_fits_stays_inline() {
        // A short chain that fits entirely on the line: no operator breaks.
        let operands = vec![
            op(None, "((a".into()),
            op(Some("+"), "b)".into()),
            op(Some("+"), "c)".into()),
        ];
        let got = render_line("    let z = ", 4, &operands);
        assert_eq!(got, "    let z = ((a + b) + c)");
    }

    #[test]
    fn chain_node_is_necessary_a_group_cannot_render_glue_plus_break() {
        // A generic Group is all-flat-or-all-break: it cannot render the mixed
        // layout of `hyp` (op1 glued to a multiline operand's closing line, op2/op3
        // broken to a shared indent). Model the same operands as a Group over
        // Line-separated `op operand` pieces; when broken, EVERY Line breaks, so
        // op1 cannot stay glued. This proves the Chain variant earns its place.
        // The leading operand is padded past the width so the group cannot fit and
        // is forced broken — exercising the "all soft Lines break uniformly" path.
        let group = Doc::group(Doc::concat(vec![
            Doc::owned(format!("(((mlcall_one({}) ", "x".repeat(110))),
            Doc::text("+"),
            Doc::Line,
            Doc::text("slshort) +"),
            Doc::Line,
            Doc::text("mlcall_two({...})) +"),
            Doc::Line,
            Doc::text("tail_operand_x)"),
        ]));
        // The over-wide first operand forces the group broken.
        let mut out = String::from("    let z = ");
        render_at(
            &group,
            RenderConfig::default(),
            4,
            current_col(&out),
            false,
            &mut out,
        );
        // A Group breaks ALL its Lines: the first `+` cannot glue onto the same
        // line as a following operand the way the Chain node does. So this Group
        // rendering differs from the required `hyp` layout — demonstrating the
        // Chain node is not expressible as a plain Group.
        let group_lines: Vec<&str> = out.lines().collect();
        // Every operator sits at the end of its line (glued) in the Chain layout;
        // here they are split by unconditional Line breaks — the Group puts each
        // operand on its own line uniformly, which is NOT the rustfmt chain shape.
        assert!(
            group_lines.len() == 4,
            "a broken Group breaks every Line uniformly ({} lines), unlike the \
             chain's mixed glue+break — proving Chain is necessary",
            group_lines.len()
        );
    }

    #[test]
    fn seal_leaf_sequence_matches_across_all_chain_docs() {
        // SEAL: the whitespace-normalized leaf sequence is layout-invariant. Every
        // paren the emitter emits is carried as a Text leaf and survives rendering.
        // A chain doc's normalized leaves must equal its normalized rendered bytes.
        let operands = vec![
            op(None, "(((((longfunctioncallnamehere_aaaa(x)".into()),
            op(Some("+"), "bbbbbbbbbbb)".into()),
            op(Some("+"), "ccccccccccc)".into()),
            op(Some("+"), "ddddddddddd)".into()),
            op(Some("+"), "eeeeeeeeeee)".into()),
            op(Some("+"), "ff)".into()),
        ];
        let chain = Doc::Chain { operands };
        let rendered = render(&chain, RenderConfig::default());
        assert_eq!(
            crate::doc::whitespace_normalize(&rendered),
            chain.normalized_leaves(),
            "rendered bytes and Doc leaves must normalize to the same token sequence"
        );
    }

    /// A parenthesized arg list `name(a, b, c)`: a `Group` over `name(` + nested
    /// `Softline`-separated args (trailing comma) + `Softline` + `)`. Flat:
    /// `name(a, b, c)`. Broken: one arg per line, trailing comma, closing paren
    /// dedented to the group's start column.
    fn arg_group(name: &str, args: &[&str]) -> Doc {
        let mut inner = vec![Doc::owned(format!("{name}("))];
        let mut nested = vec![];
        for (i, a) in args.iter().enumerate() {
            if i == 0 {
                nested.push(Doc::Softline);
            } else {
                nested.push(Doc::text(","));
                nested.push(Doc::Line);
            }
            nested.push(Doc::owned((*a).to_owned()));
        }
        // Trailing comma appears only when broken; a `Softline`-guarded `,` would
        // vanish flat. Emit it as part of the last arg via a separate group-aware
        // token: here we keep it simple and match rustfmt's "trailing comma when
        // broken" by appending a `,` before the closing `Softline` only in the
        // broken layout. The renderer cannot conditionally add text, so we model
        // the common flat-fits case (no trailing comma) and the broken case is
        // covered by the call-arg builder in emit_doc; this fixture proves the
        // flatten/break decision itself.
        inner.push(Doc::nest(4, Doc::concat(nested)));
        inner.push(Doc::Softline);
        inner.push(Doc::text(")"));
        Doc::group(Doc::concat(inner))
    }

    #[test]
    fn group_with_soft_lines_flattens_when_it_fits() {
        // The whole call fits width 100 from column 0: every soft break lays out
        // flat — `Softline` -> nothing, `Line` -> a single space.
        let doc = arg_group("f", &["a", "b", "c"]);
        assert_eq!(render(&doc, RenderConfig::default()), "f(a, b, c)");
    }

    #[test]
    fn group_with_soft_lines_breaks_when_too_wide() {
        // The same shape, but the args overflow width 100: every soft break in the
        // group breaks uniformly — one arg per line at nest+4, closing paren back
        // at the group's start column.
        let long = "argument_that_is_quite_long_enough_to_matter";
        let doc = arg_group("some_function_name", &[long, long, long]);
        let got = render(&doc, RenderConfig::default());
        let expected = "some_function_name(\n    argument_that_is_quite_long_enough_to_matter,\n    argument_that_is_quite_long_enough_to_matter,\n    argument_that_is_quite_long_enough_to_matter\n)";
        assert_eq!(
            got, expected,
            "\n--- got ---\n{got}\n--- want ---\n{expected}"
        );
    }

    #[test]
    fn chain_operand_with_block_arg_call_breaks_not_glues() {
        // A chain operand `((((((((f({ <stmt block> }, 0)` whose call carries a
        // statement-block argument must break the CALL one-per-line — the block's
        // `HardLine` is hidden from `has_hard_break` by the `CallArgs`, so the chain's
        // whole-flat fast path must use the genuinely-single-line test (else it
        // glues the multiline block onto the call head). Captured from `rustfmt
        // --edition 2024 --style-edition 2024`.
        let block = Doc::concat(vec![
            Doc::text("{"),
            Doc::nest(
                4,
                Doc::concat(vec![
                    Doc::HardLine,
                    Doc::text("let x: i64 = 1;"),
                    Doc::HardLine,
                    Doc::text("x"),
                ]),
            ),
            Doc::HardLine,
            Doc::text("}"),
        ]);
        let call = Doc::call_args(
            Doc::text("crate::main_apply_i("),
            vec![block, Doc::text("0")],
            Doc::text(")"),
            true,
        );
        let op0 = Doc::concat(vec![Doc::text("(("), call]);
        let chain = Doc::Chain {
            operands: vec![
                ChainOperand {
                    leading_op: None,
                    doc: op0,
                },
                ChainOperand {
                    leading_op: Some(Cow::Borrowed("+")),
                    doc: Doc::text("crate::main_apply_p(1))"),
                },
            ],
        };
        let got = render(&chain, RenderConfig::default());
        // The call breaks one-per-line: the block at +4, then `0,`, `)` dedented,
        // then the glued `+ ...)`. NOT `main_apply_i({\n ... \n}, 0)` (block glued).
        assert!(
            got.contains("crate::main_apply_i(\n") && got.contains("\n    0,\n"),
            "the block-arg call must break one-per-line, not glue its block:\n{got}"
        );
    }

    #[test]
    fn group_with_hardline_never_flattens_even_when_it_would_fit() {
        // A tiny group whose flat width easily fits, but carrying a `HardLine`:
        // it must still break (a statement block never inlines).
        let doc = Doc::group(Doc::concat(vec![
            Doc::text("{"),
            Doc::nest(4, Doc::concat(vec![Doc::HardLine, Doc::text("x")])),
            Doc::HardLine,
            Doc::text("}"),
        ]));
        assert_eq!(render(&doc, RenderConfig::default()), "{\n    x\n}");
    }

    #[test]
    fn brace_body_vanishes_when_body_fits_flat() {
        // A `BraceBody` whose body fits the width renders JUST the body — no braces
        // — matching `rustfmt`'s `move |_| rest` brace-strip on a fitting closure.
        let doc = Doc::concat(vec![
            Doc::text("move |_| "),
            Doc::brace_body(Doc::text("short_rest")),
        ]);
        assert_eq!(render(&doc, RenderConfig::default()), "move |_| short_rest");
    }

    #[test]
    fn brace_body_braces_and_breaks_when_body_overflows() {
        // A `BraceBody` whose body overflows the width braces and breaks to a block:
        // `{`, the body on its own line at one indent step, `}` dedented back —
        // `rustfmt`'s block-form closure body.
        let wide = "a".repeat(110);
        let doc = Doc::concat(vec![
            Doc::text("move |_| "),
            Doc::brace_body(Doc::owned(wide.clone())),
        ]);
        let got = render(&doc, RenderConfig::default());
        let expected = format!("move |_| {{\n    {wide}\n}}");
        assert_eq!(
            got, expected,
            "\n--- got ---\n{got}\n--- want ---\n{expected}"
        );
    }

    #[test]
    fn brace_body_with_hardline_body_always_braces_even_when_narrow() {
        // A statement-block body carries a `HardLine`, so it can never fit flat and
        // the `BraceBody` always braces — a block closure body is always braced.
        let body = Doc::concat(vec![Doc::text("let y = 1;"), Doc::HardLine, Doc::text("y")]);
        let doc = Doc::concat(vec![Doc::text("move |_| "), Doc::brace_body(body)]);
        assert_eq!(
            render(&doc, RenderConfig::default()),
            "move |_| {\n    let y = 1;\n    y\n}"
        );
    }

    #[test]
    fn brace_body_with_wide_if_else_stays_braced() {
        // A WIDE (block-form) `IfElse` as a closure/CAF brace-body body must keep
        // its braces. `fits` measures only the short first line (`(if cond {`), so
        // without `has_hard_break` reporting the block-form `IfElse` as breaking,
        // the `BraceBody` would inline a tall body and DROP the braces — a SEAL
        // divergence (`move |_| (if …` instead of `move |_| { (if … } `). Pins the
        // `has_hard_break(Doc::IfElse)` block-form test against regression.
        let wide = Doc::if_else(
            Doc::text("condition_wide_enough_to_force_block_form_layout_xxxxx"),
            Doc::text("then_branch_value"),
            Doc::text("else_branch_value"),
        );
        let doc = Doc::concat(vec![Doc::text("move |_| "), Doc::brace_body(wide)]);
        let got = render(&doc, RenderConfig::default());
        assert!(
            got.starts_with("move |_| {\n"),
            "a wide if-else brace-body must render as a braced block, got:\n{got}"
        );
        assert!(
            got.trim_end().ends_with('}'),
            "the braced block must close with `}}`, got:\n{got}"
        );
    }

    #[test]
    fn brace_body_with_narrow_if_else_hardbreak_branch_stays_braced() {
        // A NARROW if-else (construct width <= threshold) whose BRANCH carries a
        // HardLine (a `let..in` / block branch) must still keep its brace-body
        // braces. `has_hard_break(Doc::IfElse)` recurses into the branches like the
        // old inline `build_if` Concat did; a width-only test would report false and
        // let `fits` (first-line-only) inline the tall branch and drop the braces.
        let block_branch = Doc::concat(vec![
            Doc::text("({"),
            Doc::nest(
                4,
                Doc::concat(vec![
                    Doc::HardLine,
                    Doc::text("let x = 1;"),
                    Doc::HardLine,
                    Doc::text("x"),
                ]),
            ),
            Doc::HardLine,
            Doc::text("})"),
        ]);
        // Narrow: the branch HardLines collapse to spaces in `normalized_leaves`.
        let narrow = Doc::if_else(Doc::text("c"), block_branch, Doc::text("e"));
        let doc = Doc::concat(vec![Doc::text("move |_| "), Doc::brace_body(narrow)]);
        let got = render(&doc, RenderConfig::default());
        assert!(
            got.starts_with("move |_| {\n"),
            "a narrow if-else with a hard-break branch must render as a braced block, got:\n{got}"
        );
    }

    #[test]
    fn brace_body_leaves_carry_the_braces_for_the_seal() {
        // The braces ARE part of the SEAL leaf sequence (the string emitter always
        // writes them), so the normalized leaves carry `{ body }` whether or not the
        // render drops the braces — the flat render diverges from the leaves on the
        // braces exactly as `IfBroken` diverges on the trailing comma.
        let doc = Doc::brace_body(Doc::text("rest"));
        assert_eq!(doc.normalized_leaves(), "{ rest }");
        // Flat render drops the braces (matches rustfmt), so rendered != leaves here.
        assert_eq!(render(&doc, RenderConfig::default()), "rest");
    }

    #[test]
    fn if_else_stays_inline_at_the_width_threshold_from_docs_alone() {
        // The `single_line_if_else_max_width` layout policy is verifiable from pure
        // `Doc`s — no IR. `if cond1234567890 { thenvalab } else { elsevalab }` is
        // exactly 50 columns WITHOUT the outer parens (the threshold), so it stays
        // inline whatever the enclosing indent.
        let doc = Doc::if_else(
            Doc::text("cond1234567890"),
            Doc::text("thenvalab"),
            Doc::text("elsevalab"),
        );
        let seeded = Doc::nest(4, doc);
        assert_eq!(
            render(&seeded, RenderConfig::default()),
            "(if cond1234567890 { thenvalab } else { elsevalab })",
            "a 50-wide construct stays inline"
        );
    }

    #[test]
    fn if_else_breaks_to_block_form_one_past_the_threshold() {
        // One column past the threshold (a 51-wide construct) breaks each branch body
        // onto its own line at one indent step, braces dedented back to the block
        // indent — the block form, decided by the renderer from the flat leaf widths.
        let doc = Doc::if_else(
            Doc::text("cond1234567890"),
            Doc::text("thenvalabc"),
            Doc::text("elsevalab"),
        );
        let stmt = Doc::nest(4, Doc::concat(vec![Doc::text("let z = "), doc]));
        let got = render(&stmt, RenderConfig::default());
        let expected = "let z = (if cond1234567890 {\n        thenvalabc\n    } else {\n        elsevalab\n    })";
        assert_eq!(
            got, expected,
            "\n--- got ---\n{got}\n--- want ---\n{expected}"
        );
    }

    #[test]
    fn if_else_leaves_carry_the_parens_and_braces_for_the_seal() {
        // The `(if … { … } else { … })` tokens ARE the SEAL leaf sequence (the string
        // emitter writes them adjacently), identical in both the inline and block
        // layouts — the block form's newlines normalize away.
        let doc = Doc::if_else(Doc::text("c"), Doc::text("t"), Doc::text("e"));
        assert_eq!(doc.normalized_leaves(), "(if c { t } else { e })");
    }

    /// A statement-block Doc `{ let x: i64 = 1; x }` — a `HardLine` before each
    /// statement, the closing brace on its own line. Its `HardLine` is hidden from
    /// `has_hard_break` once wrapped in a `CallArgs`.
    fn stmt_block() -> Doc {
        Doc::concat(vec![
            Doc::text("{"),
            Doc::nest(
                4,
                Doc::concat(vec![
                    Doc::HardLine,
                    Doc::text("let x: i64 = 1;"),
                    Doc::HardLine,
                    Doc::text("x"),
                ]),
            ),
            Doc::HardLine,
            Doc::text("}"),
        ])
    }

    /// A call `f({ <stmt block> }, 0)` carrying a statement-block first argument —
    /// the `CallArgs` variant hides the block's `HardLine` from `has_hard_break`,
    /// so only a genuinely-single-line fit rejects gluing it flat.
    fn call_with_block_arg() -> Doc {
        Doc::call_args(
            Doc::text("f("),
            vec![stmt_block(), Doc::text("0")],
            Doc::text(")"),
            true,
        )
    }

    #[test]
    fn brace_body_braces_when_body_is_wide_record_literal() {
        // A plain record literal wider than `STRUCT_LIT_WIDTH` (18) renders one field
        // per line even flat — the `StructLit` hides that multiline break from
        // `has_hard_break`. A first-line-only fit sees the short head `Rec {` and
        // would drop the closure braces; the single-line discipline rejects the
        // embedded newline, so the `BraceBody` braces and blocks. Prove-the-refusal
        // for the StructLit-through-BraceBody SEAL break.
        let record = Doc::struct_lit(
            Doc::text("Rec {"),
            vec![
                Doc::text("field_one: 111"),
                Doc::text("field_two: 222"),
                Doc::text("field_three: 333"),
            ],
            Doc::text("}"),
        );
        let doc = Doc::concat(vec![Doc::text("move |_| "), Doc::brace_body(record)]);
        let got = render(&doc, RenderConfig::default());
        assert!(
            got.starts_with("move |_| {\n") && got.trim_end().ends_with('}'),
            "a wide record body must brace/block, not inline flat:\n{got}"
        );
        assert!(
            got.contains("field_one: 111,\n"),
            "the record must break one field per line inside the block:\n{got}"
        );
    }

    #[test]
    fn brace_body_braces_when_body_is_call_with_block_arg() {
        // A closure body `f({ let x = 1; x }, 0)` whose call carries a statement-block
        // argument: the block's `HardLine` is hidden by the `CallArgs`, so the flat
        // render embeds a `\n`. A first-line-only fit sees the short head `f(` and
        // drops the closure braces; the single-line discipline keeps them.
        let doc = Doc::concat(vec![
            Doc::text("move |_| "),
            Doc::brace_body(call_with_block_arg()),
        ]);
        let got = render(&doc, RenderConfig::default());
        assert!(
            got.starts_with("move |_| {\n") && got.trim_end().ends_with('}'),
            "a block-arg call body must brace/block, not inline flat:\n{got}"
        );
        assert!(
            got.contains("f(\n"),
            "the block-arg call must break one arg per line inside the block:\n{got}"
        );
    }

    #[test]
    fn match_arm_tail_blocks_when_noncontrol_body_is_call_with_block_arg() {
        // A non-control arm body `f({ let x = 1; x }, 0)` (a `CallArgs`, not an
        // If/Let/chain): its block-arg `HardLine` is hidden from `has_hard_break`, so
        // the flat render embeds a `\n`. A first-line-only fit would inline `body,`;
        // the single-line discipline rejects the newline and the arm blocks.
        let doc = Doc::match_arm_tail(call_with_block_arg(), false);
        let got = render(&doc, RenderConfig::default());
        assert!(
            !got.starts_with("f({"),
            "the arm body must not glue its block onto the call head:\n{got}"
        );
        assert!(
            got.contains("f(\n"),
            "the block-arg call arm body must break one arg per line:\n{got}"
        );
    }

    /// Render an assignment `doc` as a block statement at block `indent`: seed the
    /// output with the indent, render, and append the trailing `;` the `trailer`
    /// accounted for. Returns the whole statement line(s), matching the column
    /// `rustfmt` captured its golden from.
    fn render_assign_stmt(indent: usize, prefix: &'static str, rhs: Doc) -> String {
        let mut out = String::new();
        push_indent(indent, &mut out);
        let doc = Doc::assign(Doc::text(prefix), rhs, 1);
        render_at(
            &doc,
            RenderConfig::default(),
            indent,
            current_col(&out),
            false,
            &mut out,
        );
        out.push(';');
        out
    }

    #[test]
    fn assign_stays_flat_when_prefix_and_rhs_fit() {
        // `let x: T = rhs;` that fits the width stays on one line: prefix then the
        // flat RHS, no break after `=`.
        let got = render_assign_stmt(4, "let x: i64 = ", Doc::text("Box::new(short)"));
        assert_eq!(got, "    let x: i64 = Box::new(short);");
    }

    #[test]
    fn assign_breaks_rhs_to_own_line_when_prefix_rhs_overflows() {
        // `let __ipe_fn: Box<…> = Box::new(…);` whose one-line form (with the `;`)
        // overflows width 100 but whose flat RHS fits on its own line at col 8
        // (block 4 + step 4): the RHS drops below the `=`, indented +4. Golden
        // captured from `rustfmt --edition 2024 --style-edition 2024`.
        let got = render_assign_stmt(
            4,
            "let __ipe_fn: Box<dyn Fn(i64, i64, i64) -> i64 + Send + 'static> = ",
            Doc::text("Box::new(move |aaaa: i64, bbbb: i64, cccc: i64| -> i64 { aaaa })"),
        );
        let expected = "    let __ipe_fn: Box<dyn Fn(i64, i64, i64) -> i64 + Send + 'static> =\n        Box::new(move |aaaa: i64, bbbb: i64, cccc: i64| -> i64 { aaaa });";
        assert_eq!(
            got, expected,
            "\n--- got ---\n{got}\n--- want ---\n{expected}"
        );
    }

    #[test]
    fn assign_falls_back_to_delimiter_break_when_rhs_first_line_overflows_on_own_line() {
        // When even at col 8 the RHS's FIRST line (its open-delimiter head, laid out
        // broken) overflows the width, RHS-break is unavailable — the flat RHS moved
        // to the next line would not fit either. The assignment keeps the RHS glued
        // to `= ` and breaks it into its own delimiters at the block indent (the
        // fallback). This exercises the third `render_assign` branch: the `= ` line
        // keeps the RHS head, and the RHS lays out non-flat (its `Softline`s break).
        //
        // The name is sized so the broken group's first line — `<name>(` at col 8 —
        // exceeds width 100, ruling out RHS-break.
        let long_name = "a_deliberately_enormous_callee_name_wide_enough_that_its_open_paren_alone_overflows_col_eight_pad";
        let rhs = arg_group(long_name, &["a", "b"]);
        let got = render_assign_stmt(4, "let n: T = ", rhs);
        // The RHS stayed glued to `= ` (no break after `=`) and broke its own args
        // one per line — the delimiter-break fallback, not the RHS-break.
        let first_line = got.lines().next().expect("at least one line");
        assert!(
            first_line.ends_with('('),
            "RHS head should stay glued to `= ` on the first line: {first_line}"
        );
        assert!(
            got.contains("\n        a,\n        b\n"),
            "the RHS should break its args in place at col 8:\n{got}"
        );
    }

    #[test]
    fn assign_leaves_are_break_invisible_matching_a_flat_prefix_rhs() {
        // The break after `= ` is pure whitespace: the normalized leaves of an
        // assignment equal `prefix rhs` with a single space — exactly what the
        // string emitter writes — so the SEAL holds across the break.
        let doc = Doc::assign(Doc::text("let x: T = "), Doc::text("value"), 1);
        assert_eq!(doc.normalized_leaves(), "let x: T = value");
    }

    #[test]
    fn assign_blocks_when_rhs_is_call_with_block_arg() {
        // An applied-lambda RHS `let p: T = f({ let x = 1; x }, 0);`: the block arg's
        // `HardLine` is hidden by the `CallArgs`, so `flat_width(rhs)` measures only
        // the short first line `f(` and the same-line form would glue the multiline
        // RHS onto the prefix, dropping the delimiters. The single-line gate treats
        // the embedded newline as overflow, so the RHS breaks its args in place.
        // Prove-the-refusal for the Assign-through-applied-lambda SEAL break.
        let got = render_assign_stmt(4, "let p: T = ", call_with_block_arg());
        assert!(
            !got.contains("f({"),
            "the RHS must not glue its block onto the call head:\n{got}"
        );
        assert!(
            got.contains("f(\n"),
            "the block-arg call RHS must break one arg per line:\n{got}"
        );
    }

    #[test]
    fn nested_group_refits_independently_of_broken_outer_group() {
        // An outer group forced broken (over-wide leading text) still lets an inner
        // group that fits lay out flat — groups decide their layout independently.
        let inner = arg_group("g", &["p", "q"]);
        let outer = Doc::group(Doc::concat(vec![
            Doc::owned(format!("outer_{}(", "z".repeat(110))),
            Doc::nest(4, Doc::concat(vec![Doc::Softline, inner])),
            Doc::Softline,
            Doc::text(")"),
        ]));
        let got = render(&outer, RenderConfig::default());
        // Outer breaks (its leading token overflows); inner `g(p, q)` fits and
        // stays flat on its own line.
        assert!(
            got.contains("\n    g(p, q)\n"),
            "inner group should flatten inside a broken outer group:\n{got}"
        );
    }

    /// A function-call argument list `name(args)` as a [`Doc::CallArgs`] with a
    /// break-conditional trailing comma. `args` are plain text leaves.
    fn callargs(name: &'static str, args: &[&'static str]) -> Doc {
        Doc::call_args(
            Doc::owned(format!("{name}(")),
            args.iter().map(|a| Doc::owned((*a).to_owned())).collect(),
            Doc::text(")"),
            true,
        )
    }

    #[test]
    fn call_args_flat_when_args_fit_fn_call_width() {
        // A call whose argument text fits `fn_call_width` (60) and whose line fits
        // `max_width` stays inline.
        let doc = callargs("some_call", &["a", "b"]);
        assert_eq!(render(&doc, RenderConfig::default()), "some_call(a, b)");
    }

    #[test]
    fn call_args_break_one_per_line_when_args_exceed_fn_call_width() {
        // A call whose ARGUMENT text exceeds `fn_call_width` (60) breaks one argument
        // per line with a trailing comma, even though the whole line still fits
        // `max_width` (100). Byte-golden from `rustfmt --edition 2024
        // --style-edition 2024`.
        let doc = callargs(
            "some_call",
            &[
                "argument_that_is_quite_long_enough_x",
                "argument_that_is_quite_long_enough_y",
            ],
        );
        let got = render(&doc, RenderConfig::default());
        let expected = "some_call(\n    argument_that_is_quite_long_enough_x,\n    argument_that_is_quite_long_enough_y,\n)";
        assert_eq!(
            got, expected,
            "\n--- got ---\n{got}\n--- want ---\n{expected}"
        );
    }

    #[test]
    fn call_args_single_arg_head_glue_chain_breaks_innermost() {
        // Nested single-argument calls glue their heads onto one line and the
        // innermost (a macro whose args exceed `fn_call_width`) breaks in place, its
        // closing delimiters collapsing onto the final line — `rustfmt`'s combining
        // rule. Byte-golden from `rustfmt --edition 2024 --style-edition 2024`.
        let inner = Doc::call_args(
            Doc::text("format!("),
            vec![
                Doc::text("\"{}{}\""),
                Doc::text("\"a\".to_string()"),
                Doc::text("\"b\".to_string()"),
            ],
            Doc::text(")"),
            false,
        );
        let mid = Doc::call_args(
            Doc::text("string_to_upper("),
            vec![inner],
            Doc::text(")"),
            true,
        );
        let doc = Doc::call_args(Doc::text("io_println("), vec![mid], Doc::text(")"), true);
        let got = render(&doc, RenderConfig::default());
        let expected = "io_println(string_to_upper(format!(\n    \"{}{}\",\n    \"a\".to_string(),\n    \"b\".to_string()\n)))";
        assert_eq!(
            got, expected,
            "\n--- got ---\n{got}\n--- want ---\n{expected}"
        );
    }

    #[test]
    fn call_args_multi_arg_overflows_trailing_block() {
        // A multi-argument call whose LAST argument is a delimited BLOCK overflows it
        // in place: the head + preceding args glue on the first line and the block
        // breaks below (`overflow_delimited_expr`). Byte-golden from `rustfmt
        // --edition 2024 --style-edition 2024`.
        let block = Doc::concat(vec![
            Doc::text("{"),
            Doc::nest(
                4,
                Doc::concat(vec![
                    Doc::HardLine,
                    Doc::text("let __ipe_fn: i64 = 1;"),
                    Doc::HardLine,
                    Doc::text("__ipe_fn"),
                ]),
            ),
            Doc::HardLine,
            Doc::text("}"),
        ]);
        let doc = Doc::call_args(
            Doc::text("ipe_result_map("),
            vec![Doc::text("ok_res(2)"), block],
            Doc::text(")"),
            true,
        );
        let got = render(&doc, RenderConfig::default());
        let expected = "ipe_result_map(ok_res(2), {\n    let __ipe_fn: i64 = 1;\n    __ipe_fn\n})";
        assert_eq!(
            got, expected,
            "\n--- got ---\n{got}\n--- want ---\n{expected}"
        );
    }

    #[test]
    fn call_args_flat_render_matches_seal_leaves() {
        // SEAL: a `CallArgs`'s normalized leaf sequence carries the delimiters and
        // elements joined by `, ` and NO trailing comma (the string emitter never
        // writes it) — so a FLAT render normalizes equal to the leaves. The broken
        // one-per-line render adds a SEAL-invisible trailing comma (like the plain
        // delimited group), so only the flat render matches byte-for-byte.
        let doc = callargs("f", &["a", "b"]);
        assert_eq!(doc.normalized_leaves(), "f(a, b)");
        assert_eq!(
            crate::doc::whitespace_normalize(&render(&doc, RenderConfig::default())),
            doc.normalized_leaves(),
        );
    }

    #[test]
    fn call_args_trailing_comma_is_seal_invisible_when_broken() {
        // The one-per-line trailing comma is NOT part of the SEAL leaf sequence: the
        // leaves are width-invariant (`f(a, b)`) whether or not the render breaks.
        let doc = callargs(
            "some_call",
            &[
                "argument_that_is_quite_long_enough_x",
                "argument_that_is_quite_long_enough_y",
            ],
        );
        assert_eq!(
            doc.normalized_leaves(),
            "some_call(argument_that_is_quite_long_enough_x, argument_that_is_quite_long_enough_y)",
        );
        // The broken render carries a trailing comma the leaves do not — exactly the
        // documented SEAL-invisible divergence, mirroring `Doc::IfBroken`.
        assert!(render(&doc, RenderConfig::default()).contains("_y,\n)"));
    }

    #[test]
    fn caf_closure_combines_and_method_drops_to_own_line() {
        // The CAF shape `CELL.get_or_init(|| { … }).clone()`: `rustfmt` combines the
        // sole closure argument onto the call head (`get_or_init(|| {` on one line,
        // no trailing comma, `})` at the call indent) and drops the trailing
        // `.clone()` onto its OWN line at the call's indent when the closure body
        // broke. The body here is forced multiline (a statement block).
        let body = Doc::concat(vec![
            Doc::text("{"),
            Doc::nest(
                4,
                Doc::concat(vec![
                    Doc::HardLine,
                    Doc::text("let (a, b) = (1, 2);"),
                    Doc::HardLine,
                    Doc::text("(a + b)"),
                ]),
            ),
            Doc::HardLine,
            Doc::text("}"),
        ]);
        let closure = Doc::concat(vec![Doc::text("|| "), Doc::brace_body(body)]);
        let receiver = Doc::call_args(
            Doc::text("CELL.get_or_init("),
            vec![closure],
            Doc::text(")"),
            true,
        );
        let doc = Doc::method_chain(receiver, Doc::text(".clone()"));
        let got = render_seeded(&doc, RenderConfig::default(), 4, 4);
        // The closure combines onto the call head, and `.clone()` sits on its own
        // line at the call indent after the multiline receiver's `})` closing line.
        assert!(
            got.starts_with("CELL.get_or_init(|| {\n"),
            "closure should combine onto the call head:\n{got}"
        );
        assert!(
            got.ends_with("\n    })\n    .clone()"),
            "`.clone()` should sit on its own line at the call indent:\n{got}"
        );
        // SEAL: the normalized leaves carry `.clone()` glued to the receiver's
        // closing `)` (no break), so the method-on-its-own-line layout is invisible
        // to the leaf sequence.
        assert!(doc.normalized_leaves().ends_with(").clone()"));
    }

    /// Only a render that is ONE balanced paren group makes the wrapping pair
    /// redundant: a field access on a parenthesized receiver keeps its parens, so a
    /// field-call callee stays `((r).f)(x)`, never the method call `(r).f(x)`.
    #[test]
    fn single_paren_group_admits_only_one_whole_group() {
        for whole in [
            "(x)",
            "({ a })",
            "((a)(b))",
            "(\")\")",
            "(')')",
            "(r#\")\"#)",
            "('a: loop {})",
        ] {
            assert!(is_single_paren_group(whole), "{whole} is one group");
        }
        for split in [
            "(r).f",
            "(a)(b)",
            "x",
            "",
            "(",
            "(a",
            "(\")\"",
            "(a).0",
            "(f)(\"(\")",
        ] {
            assert!(!is_single_paren_group(split), "{split} is not one group");
        }
    }

    #[test]
    fn field_callee_on_parenthesized_receiver_keeps_its_parens() {
        let callee = Doc::concat(vec![Doc::text("(r)"), Doc::text(".f")]);
        let doc = Doc::concat(vec![Doc::elidable_paren(callee), Doc::text("(x)")]);
        assert_eq!(render(&doc, RenderConfig::default()), "((r).f)(x)");
    }
}
