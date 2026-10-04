//! A readable, indented pretty-printer for the typed IR, backing the
//! `--emit-ir` developer flag. This is intentionally *not* the derived
//! `Debug` rendering: it resolves interned [`Symbol`]s back to their source
//! names and lays the program out as a shallow tree (modules → types / funcs →
//! params / expressions / match arms / kernels) that a human can scan.
//!
//! The function is pure and total: it never panics, never indexes a slice
//! directly, and resolves a forged or cross-interner symbol to an explicit
//! `<sym#N>` placeholder rather than crashing or silently emitting an empty
//! name. Output is deterministic — the same `(program, interner)` always
//! renders the same string.

use ipe_intern::{Interner, Symbol};

#[cfg(test)]
use crate::KernelFn;
use crate::ir::{
    Arm, BinOp, BoundSet, Callee, EnumDef, Expr, Func, IrType, Match, ModPath, Module, Pat,
    Program, SliceOwnership, TypeDef, UiCtor, UiPlain, Variant,
};

/// Upper bound on the nesting depth `ir_type_name`/`pat_name`/`write_expr`
/// will recurse before rendering a `<depth limit>` placeholder.
///
/// Past this depth these functions stop recursing rather than overflowing
/// the native stack. The real Rust backend emitter refuses a program past
/// this same depth (`ipe_backend_rust::emit_expr`'s `MAX_EMIT_DEPTH`,
/// IPE-L0200) — this is the single source of truth both share, so
/// `--emit-ir` (a dev-flag path with no other gate) can never stack-overflow
/// on a program the emitter would already have refused, nor drift out of
/// step with the real bound.
pub const MAX_IR_RENDER_DEPTH: u16 = 96;

/// A `<depth limit>` placeholder, rendered instead of recursing further once
/// [`MAX_IR_RENDER_DEPTH`] is exceeded.
const DEPTH_LIMIT_PLACEHOLDER: &str = "<depth limit>";

/// Render `program` as a readable indented tree, resolving every [`Symbol`]
/// against `interner`.
///
/// Pure and total: no panics, no direct indexing, deterministic output.
#[must_use]
pub fn pretty(program: &Program, interner: &Interner) -> String {
    let mut out = String::new();
    out.push_str("program\n");
    for module in &program.modules {
        write_module(&mut out, module, interner);
    }
    out
}

/// Append `text` at the given indentation `level` (two spaces per level),
/// followed by a newline.
fn line(out: &mut String, level: usize, text: &str) {
    for _ in 0..level {
        out.push_str("  ");
    }
    out.push_str(text);
    out.push('\n');
}

/// Resolve a symbol to its interned name, or an explicit placeholder when the
/// symbol was never handed out by this interner.
fn sym_name(interner: &Interner, sym: Symbol) -> String {
    interner
        .resolve(sym)
        .map_or_else(|| format!("<sym#{}>", sym.as_raw()), str::to_owned)
}

/// Render a dotted module path, e.g. `Ipe.Io`.
fn mod_path_name(interner: &Interner, path: &ModPath) -> String {
    path.0
        .iter()
        .map(|seg| sym_name(interner, *seg))
        .collect::<Vec<_>>()
        .join(".")
}

/// Render an [`IrType`] as its source-facing name.
///
/// Depth-bounded via [`ir_type_name_at`] (starting at depth 0) — every
/// call site here stays the plain 2-argument form; only the recursive
/// descent inside `ir_type_name_at` threads the counter.
fn ir_type_name(interner: &Interner, ty: &IrType) -> String {
    ir_type_name_at(interner, ty, 0)
}

/// [`ir_type_name`]'s depth-tracked recursion. Past [`MAX_IR_RENDER_DEPTH`]
/// this renders [`DEPTH_LIMIT_PLACEHOLDER`] instead of recursing further —
/// total and stack-safe on a pathologically nested type, matching the real
/// Rust backend emitter's own bound rather than trusting the caller never to
/// hand it one.
#[allow(clippy::too_many_lines)]
fn ir_type_name_at(interner: &Interner, ty: &IrType, depth: u16) -> String {
    if depth > MAX_IR_RENDER_DEPTH {
        return DEPTH_LIMIT_PLACEHOLDER.to_owned();
    }
    let depth = depth + 1;
    match ty {
        IrType::Int => "Int".to_owned(),
        IrType::Float => "Float".to_owned(),
        IrType::Bool => "Bool".to_owned(),
        IrType::Str => "String".to_owned(),
        IrType::Char => "Char".to_owned(),
        IrType::Unit => "()".to_owned(),
        IrType::Task(inner) => format!("Task Error {}", ir_type_name_at(interner, inner, depth)),
        // A generic type variable renders by its source name (e.g. `a`); the
        // Rust generic spelling (`T1`, …) is a backend concern, so the IR view
        // keeps the source-facing name.
        IrType::Generic(name) => sym_name(interner, *name),
        // A row variable renders by its source name (e.g. `r`) prefixed to mark
        // it as an open row — the backend erases it to a witness-bounded generic,
        // but the IR view keeps the source-facing spelling.
        IrType::RowGeneric(name) => format!("{{ {} | .. }}", sym_name(interner, *name)),
        // An enum renders by its type name, applied to its type arguments in
        // source-like prefix form (`Maybe Int`). A non-generic enum (empty
        // `args`) is just the bare type name.
        IrType::Enum { name, args, .. } => {
            let base = sym_name(interner, *name);
            if args.is_empty() {
                base
            } else {
                let rendered = args
                    .iter()
                    .map(|t| ir_type_name_at(interner, t, depth))
                    .collect::<Vec<_>>()
                    .join(" ");
                format!("{base} {rendered}")
            }
        }
        // The built-in `Maybe a` / `Result e a` render in source-like prefix
        // form, exactly like a generic enum would.
        IrType::Maybe(elem) => format!("Maybe {}", ir_type_name_at(interner, elem, depth)),
        IrType::Result(err, ok) => format!(
            "Result {} {}",
            ir_type_name_at(interner, err, depth),
            ir_type_name_at(interner, ok, depth)
        ),
        IrType::List(elem) => format!("List {}", ir_type_name_at(interner, elem, depth)),
        IrType::Dict(k, v) => format!(
            "Dict {} {}",
            ir_type_name_at(interner, k, depth),
            ir_type_name_at(interner, v, depth)
        ),
        IrType::Set(a) => format!("Set {}", ir_type_name_at(interner, a, depth)),
        IrType::Bytes => "Bytes".to_owned(),
        IrType::Json => "Json".to_owned(),
        IrType::Decoder(inner) => format!("Decoder {}", ir_type_name_at(interner, inner, depth)),
        IrType::Db => "Db".to_owned(),
        IrType::Cmd(inner) => format!("Cmd {}", ir_type_name_at(interner, inner, depth)),
        IrType::Sub(inner) => format!("Sub {}", ir_type_name_at(interner, inner, depth)),
        // Opaque server types — source-facing names match Ipê stdlib.
        IrType::ServerRequest => "Request".to_owned(),
        IrType::ServerResponse => "Response".to_owned(),
        IrType::ServerRoute => "Route".to_owned(),
        IrType::ServerCookie => "Cookie".to_owned(),
        // stream writer handle.
        IrType::StreamWriter => "StreamWriter".to_owned(),
        // HTTP request handle (opaque, structural record folded to this variant).
        IrType::HttpRequest => "HttpRequest".to_owned(),
        // Ipe.Regex compiled-pattern handle (opaque).
        IrType::Regex => "Regex".to_owned(),
        // Ipe.Http.Server.WebSocket opaque handles.
        IrType::WebSocketServer => "WebSocketServer".to_owned(),
        IrType::WebSocketServerCfg => "WebSocketServerCfg".to_owned(),
        // Ipe.Ui / Ipe.Html parametric types.
        IrType::Ui { ctor, msg } => {
            let ctor_name = match ctor {
                UiCtor::Html => "Html",
                UiCtor::Element => "Element",
                UiCtor::Cells => "Screen",
                UiCtor::UiAttribute => "Ui.Attribute",
                UiCtor::TuiAttribute => "Tui.Ui.Attribute",
                UiCtor::HtmlAttribute => "Html.Attribute",
                UiCtor::HtmlEvent => "Html.Event",
                // Ipe.Ui.Input parametric label / placeholder types.
                UiCtor::Label => "Input.Label",
                UiCtor::Placeholder => "Input.Placeholder",
                // Ipe.Ui.Input radio option type.
                UiCtor::RadioOption => "Input.RadioOption",
                // Ipe.Ui.Cli structured Lines view + its line-native attribute.
                UiCtor::CliLines => "Cli.Lines",
                UiCtor::CliAttribute => "Cli.Ui.Attribute",
            };
            format!("{} {}", ctor_name, ir_type_name_at(interner, msg, depth))
        }
        IrType::UiPlain(plain) => match plain {
            UiPlain::Length => "Length".to_owned(),
            UiPlain::Color => "Color".to_owned(),
            UiPlain::HAlign => "HAlign".to_owned(),
            UiPlain::VAlign => "VAlign".to_owned(),
            UiPlain::Location => "Location".to_owned(),
            UiPlain::PseudoClass => "PseudoClass".to_owned(),
            UiPlain::Description => "Description".to_owned(),
            UiPlain::LayoutContext => "LayoutContext".to_owned(),
            // Ipe.Color companion value types (opaque carriers over the
            // `ipe_runtime::color::*` runtime types).
            UiPlain::ColorError => "ColorError".to_owned(),
            UiPlain::TermProfile => "TermProfile".to_owned(),
            UiPlain::AnsiColor => "AnsiColor".to_owned(),
            UiPlain::WcagLevel => "WcagLevel".to_owned(),
            UiPlain::TextSize => "TextSize".to_owned(),
            UiPlain::Deficiency => "Deficiency".to_owned(),
        },
        IrType::WebReq => "WebReq".to_owned(),
        IrType::SessionHandle => "SessionHandle".to_owned(),
        IrType::WebRoute(page) => format!("WebRoute {}", ir_type_name_at(interner, page, depth)),
        IrType::CustomElement { down, up } => format!(
            "CustomElement {} {}",
            ir_type_name_at(interner, down, depth),
            ir_type_name_at(interner, up, depth)
        ),
        IrType::Tuple(elems) => {
            let inner = elems
                .iter()
                .map(|t| ir_type_name_at(interner, t, depth))
                .collect::<Vec<_>>()
                .join(", ");
            format!("({inner})")
        }
        IrType::Record(fields) => {
            // Render in field-name order (the BTreeMap is keyed by Symbol, so
            // sort the resolved names for a deterministic, source-like form).
            let mut entries: Vec<(String, String)> = fields
                .iter()
                .map(|(name, ty)| {
                    (
                        sym_name(interner, *name),
                        ir_type_name_at(interner, ty, depth),
                    )
                })
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            if entries.is_empty() {
                "{}".to_owned()
            } else {
                let inner = entries
                    .iter()
                    .map(|(n, t)| format!("{n} : {t}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{{ {inner} }}")
            }
        }
        // All three function carriers share one source-like arrow form `T0 ->
        // T1 -> R` (a nullary shows its unit parameter explicitly). The
        // Box-vs-Arc-vs-FnOnce carrier distinction is a backend Rust-emission
        // concern, invisible at the IR pretty-printer's source-facing level.
        IrType::Fun(params, ret)
        | IrType::SharedFun(params, ret)
        | IrType::FnOnceChain(params, ret) => {
            let mut parts: Vec<String> = params
                .iter()
                .map(|t| ir_type_name_at(interner, t, depth))
                .collect();
            if parts.is_empty() {
                parts.push("()".to_owned());
            }
            parts.push(ir_type_name_at(interner, ret, depth));
            parts.join(" -> ")
        }
        IrType::BackoffStrategy => "BackoffStrategy".to_owned(),
        IrType::Order => "Order".to_owned(),
        IrType::HttpMethod => "HttpMethod".to_owned(),
        IrType::Decimal => "Decimal".to_owned(),
        IrType::Principal => "Principal".to_owned(),
        IrType::AuthConfig => "AuthConfig".to_owned(),
        IrType::TokenSource => "TokenSource".to_owned(),
        IrType::ErrorKind => "ErrorKind".to_owned(),
        IrType::Error => "Error".to_owned(),
        IrType::ErrorDetails => "ErrorDetails".to_owned(),
        IrType::ErrorInfo => "ErrorInfo".to_owned(),
        IrType::PanicInfo => "PanicInfo".to_owned(),
        IrType::TypeInfo => "TypeInfo".to_owned(),
        IrType::SqlFragment => "SqlFragment".to_owned(),
        IrType::Secret => "Secret".to_owned(),
        IrType::Path => "Path".to_owned(),
        // Ipe.Process.runWith input config record.
        IrType::ProcessRunWithCfg => "ProcessRunWithCfg".to_owned(),
        // Ipe.Process.runInPty input config record.
        IrType::ProcessRunInPtyCfg => "ProcessRunInPtyCfg".to_owned(),
        // Ipe.Cache config / stats records.
        IrType::CacheCfg => "CacheCfg".to_owned(),
        IrType::CacheStats => "CacheStats".to_owned(),
        // Ipe.WebSocket connect-config record.
        IrType::WebSocketClientCfg => "WebSocketCfg".to_owned(),
        // Ipe.Csv document record.
        IrType::CsvDoc => "Csv".to_owned(),
        // Ipe.Email records + provider ADT (surface names as the Ipê author sees).
        IrType::EmailMessage => "EmailMessage".to_owned(),
        IrType::EmailAttachment => "Attachment".to_owned(),
        IrType::EmailSesConfig => "SesConfig".to_owned(),
        IrType::EmailSmtpConfig => "SmtpConfig".to_owned(),
        IrType::EmailProvider => "EmailProvider".to_owned(),
        // Typed-key newtypes (surface names as the Ipê author sees).
        IrType::CryptoKey => "Key".to_owned(),
        IrType::CryptoMac => "Mac".to_owned(),
        IrType::EmailAddress => "EmailAddress".to_owned(),
        IrType::Url => "Url".to_owned(),
        IrType::UrlRelative => "Url.Relative".to_owned(),
        IrType::Dsn => "Dsn".to_owned(),
        // The phantom access mode is shown for a readable IR dump; it never
        // renders to a standalone Rust type (erased at emit).
        IrType::Connection => "Connection".to_owned(),
        IrType::ConnReadOnly => "ReadOnly".to_owned(),
        IrType::ConnReadWrite => "ReadWrite".to_owned(),
        // The phantom shape marker is shown for a readable IR dump; it never
        // renders to a standalone Rust type (erased at emit).
        IrType::Setting => "Setting".to_owned(),
        IrType::ShapeWeb => "Web".to_owned(),
        IrType::ShapeWebView => "WebView".to_owned(),
        IrType::ShapeTerminal => "Terminal".to_owned(),
        IrType::Locale => "Locale".to_owned(),
        IrType::WebApp => "WebApp".to_owned(),
        IrType::TuiApp => "TuiApp".to_owned(),
        IrType::CliApp => "CliApp".to_owned(),
        IrType::WorkerApp => "WorkerApp".to_owned(),
    }
}

/// Render a binary operator's surface (Ipê source) token.
const fn binop_token(op: BinOp) -> &'static str {
    match op {
        BinOp::IntAdd | BinOp::FloatAdd | BinOp::Add => "+",
        BinOp::IntSub | BinOp::FloatSub | BinOp::Sub => "-",
        BinOp::IntMul | BinOp::FloatMul | BinOp::Mul => "*",
        BinOp::Div => "/",
        BinOp::Eq => "==",
        BinOp::Neq => "/=",
        BinOp::Lt => "<",
        BinOp::Gt => ">",
        BinOp::Le => "<=",
        BinOp::Ge => ">=",
        BinOp::And => "&&",
        BinOp::Or => "||",
        BinOp::IntDiv => "//",
        BinOp::Append => "++",
    }
}

/// Render a call target. Functions are shown by id (their name lives at the
/// declaration site); kernels by their qualified source name.
fn callee_name(callee: &Callee) -> String {
    match callee {
        Callee::Func(id) => format!("fn#{}", id.as_raw()),
        Callee::Kernel(kernel) => format!("kernel {}", kernel.source_display_name()),
        Callee::Ffi { ident, asserted } => {
            let tag = if *asserted { "ffi(asserted)" } else { "ffi" };
            format!("{tag} #{}", ident.as_raw())
        }
    }
}

/// Render a pattern, e.g. `Msg.Increment`, `Maybe.Just x`, `Maybe.Just _`.
/// Render a [`Pat`] as its source-facing name.
///
/// Depth-bounded via [`pat_name_at`] (starting at depth 0) — every call
/// site here stays the plain 2-argument form; only the recursive descent
/// inside `pat_name_at` threads the counter.
fn pat_name(interner: &Interner, pat: &Pat) -> String {
    pat_name_at(interner, pat, 0)
}

/// [`pat_name`]'s depth-tracked recursion. Past [`MAX_IR_RENDER_DEPTH`] this
/// renders [`DEPTH_LIMIT_PLACEHOLDER`] instead of recursing further —
/// total and stack-safe on a pathologically nested pattern, matching the
/// real Rust backend emitter's own bound rather than trusting the caller
/// never to hand it one.
fn pat_name_at(interner: &Interner, pat: &Pat, depth: u16) -> String {
    if depth > MAX_IR_RENDER_DEPTH {
        return DEPTH_LIMIT_PLACEHOLDER.to_owned();
    }
    let depth = depth + 1;
    match pat {
        Pat::Var(sym) => sym_name(interner, *sym),
        Pat::Wildcard => "_".to_owned(),
        Pat::Int(n) => n.to_string(),
        Pat::Bool(b) => if *b { "True" } else { "False" }.to_owned(),
        Pat::Char(c) => format!("'{c}'"),
        Pat::Str(s) => format!("{s:?}"),
        Pat::Alias(inner, name) => {
            format!(
                "{} as {}",
                pat_name_at(interner, inner, depth),
                sym_name(interner, *name)
            )
        }
        Pat::Tuple(elems) => {
            let inner = elems
                .iter()
                .map(|p| pat_name_at(interner, p, depth))
                .collect::<Vec<_>>()
                .join(", ");
            format!("({inner})")
        }
        Pat::Ctor {
            ty, variant, args, ..
        } => {
            let head = format!(
                "{}.{}",
                sym_name(interner, *ty),
                sym_name(interner, *variant)
            );
            if args.is_empty() {
                head
            } else {
                let subs = args
                    .iter()
                    .map(|p| pat_name_at(interner, p, depth))
                    .collect::<Vec<_>>()
                    .join(" ");
                format!("{head} {subs}")
            }
        }
        Pat::Record(fields) => {
            let inner = fields
                .iter()
                .map(|(sym, p)| {
                    format!(
                        "{} = {}",
                        sym_name(interner, *sym),
                        pat_name_at(interner, p, depth)
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("{{ {inner} }}")
        }
        Pat::Slice {
            prefix, rest, own, ..
        } => {
            let parts = prefix
                .iter()
                .map(|p| pat_name_at(interner, p, depth))
                .collect::<Vec<_>>()
                .join(", ");
            let shape = rest.as_ref().map_or_else(
                || format!("[{parts}]"),
                |r| format!("[{parts}, {} @ ..]", pat_name_at(interner, r, depth)),
            );
            match own {
                SliceOwnership::BorrowClone => shape,
                SliceOwnership::OwnedMove => format!("own {shape}"),
            }
        }
        Pat::Or(alts) => alts
            .iter()
            .map(|p| pat_name_at(interner, p, depth))
            .collect::<Vec<_>>()
            .join(" | "),
    }
}

fn write_module(out: &mut String, module: &Module, interner: &Interner) {
    line(
        out,
        1,
        &format!("module {}", mod_path_name(interner, &module.name)),
    );
    for ty in &module.types {
        write_type(out, ty, interner);
    }
    for func in &module.funcs {
        write_func(out, func, interner);
    }
    if let Some(entry) = module.entry {
        let name = module.funcs.iter().find(|f| f.id == entry).map_or_else(
            || format!("fn#{}", entry.as_raw()),
            |f| sym_name(interner, f.name),
        );
        line(out, 2, &format!("entry {name}"));
    }
}

fn write_type(out: &mut String, ty: &TypeDef, interner: &Interner) {
    match ty {
        TypeDef::Enum(EnumDef {
            name,
            type_params,
            variants,
            ..
        }) => {
            let rendered = variants
                .iter()
                .map(|v| variant_name(interner, v))
                .collect::<Vec<_>>()
                .join(" | ");
            // A generic enum shows its quantified type variables after the name
            // (`Maybe a`); a non-generic enum shows nothing, so existing output
            // is unchanged.
            let gens = if type_params.is_empty() {
                String::new()
            } else {
                let vars = type_params
                    .iter()
                    .map(|sym| sym_name(interner, *sym))
                    .collect::<Vec<_>>()
                    .join(" ");
                format!(" {vars}")
            };
            line(
                out,
                2,
                &format!("type {}{gens} = {rendered}", sym_name(interner, *name)),
            );
        }
    }
}

/// Render one enum variant in source-like form: `Increment`, `Just a`,
/// `Rect Float Float`.
fn variant_name(interner: &Interner, v: &Variant) -> String {
    let head = sym_name(interner, v.name);
    if v.fields.is_empty() {
        head
    } else {
        let fields = v
            .fields
            .iter()
            .map(|t| ir_type_name(interner, t))
            .collect::<Vec<_>>()
            .join(" ");
        format!("{head} {fields}")
    }
}

/// The debug-text suffix for one type parameter's bounds: empty for an
/// unbounded variable, or `: Add+Sub+…` listing each set flag in a
/// fixed order. This is the IR's human-readable dump, not the Rust emission —
/// the backend renders the real `::core::ops::*` / `PartialOrd` spellings.
fn bound_suffix(bounds: BoundSet) -> String {
    if bounds.is_unbounded() {
        return String::new();
    }
    let mut parts = Vec::new();
    if bounds.has_static() {
        parts.push("'static");
    }
    if bounds.has_add() {
        parts.push("Add");
    }
    if bounds.has_sub() {
        parts.push("Sub");
    }
    if bounds.has_mul() {
        parts.push("Mul");
    }
    if bounds.has_ord() {
        parts.push("Ord");
    }
    if bounds.has_eq() {
        parts.push("Eq");
    }
    if bounds.has_ord_total() {
        parts.push("OrdTotal");
    }
    if bounds.has_hash() {
        parts.push("Hash");
    }
    if bounds.has_copy() {
        parts.push("Copy");
    }
    if bounds.has_clone() {
        parts.push("Clone");
    }
    if bounds.has_show() {
        parts.push("Stringify");
    }
    if bounds.has_interpolable() {
        parts.push("Interpolable");
    }
    format!(": {}", parts.join("+"))
}

fn write_func(out: &mut String, func: &Func, interner: &Interner) {
    let params = func
        .params
        .iter()
        .map(|(sym, ty)| {
            format!(
                "{} : {}",
                sym_name(interner, *sym),
                ir_type_name(interner, ty)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    // A fully-parametric function shows its quantified type variables as
    // `<a, b>` after the name; a monomorphic function shows nothing, so
    // existing (empty `type_params`) output is unchanged.
    let generics = if func.type_params.is_empty() {
        String::new()
    } else {
        let vars = func
            .type_params
            .iter()
            .map(|(sym, bounds)| {
                let name = sym_name(interner, *sym);
                let suffix = bound_suffix(*bounds);
                format!("{name}{suffix}")
            })
            .collect::<Vec<_>>()
            .join(", ");
        format!("<{vars}>")
    };
    line(
        out,
        2,
        &format!(
            "fn#{} {}{generics}({params}) -> {}",
            func.id.as_raw(),
            sym_name(interner, func.name),
            ir_type_name(interner, &func.ret)
        ),
    );
    write_expr(out, &func.body, interner, 3);
}

/// Render a `let`-like binding node (`Let` / `Destructure`): a `header` line,
/// then the `value` and `body` sub-trees under labelled children. Shared by both
/// binding forms so each match arm stays a single call.
#[allow(clippy::too_many_arguments)] // depth threads alongside level for the stack-safety guard
fn write_binding(
    out: &mut String,
    header: &str,
    value: &Expr,
    body: &Expr,
    interner: &Interner,
    level: usize,
    depth: u16,
) {
    line(out, level, header);
    line(out, level + 1, "value");
    write_expr_at(out, value, interner, level + 2, depth);
    line(out, level + 1, "body");
    write_expr_at(out, body, interner, level + 2, depth);
}

/// Render an [`Expr`] as an indented tree.
///
/// Depth-bounded via [`write_expr_at`] (starting at depth 0) — the single
/// external call site (`write_func`) stays the plain 4-argument form; only
/// the mutually recursive family below (`write_expr_at` and its dispatch
/// siblings) threads the counter.
fn write_expr(out: &mut String, expr: &Expr, interner: &Interner, level: usize) {
    write_expr_at(out, expr, interner, level, 0);
}

/// [`write_expr`]'s depth-tracked recursion, mutually recursive with
/// `write_binding` / `write_tail_loop` / `write_task_seq` /
/// `write_task_seq_sync` / `write_fields` / `write_list` / `write_cons` /
/// `write_record` / `write_update` / `write_lambda` / `write_apply` /
/// `write_match` — every one of those is reached ONLY from within this
/// match, so `depth` incremented once here and threaded through covers the
/// whole family. Past [`MAX_IR_RENDER_DEPTH`] this renders
/// [`DEPTH_LIMIT_PLACEHOLDER`] instead of recursing further — total and
/// stack-safe on a pathologically nested expression, matching the real Rust
/// backend emitter's own bound (IPE-L0200) rather than trusting the caller
/// never to hand `--emit-ir` one.
#[allow(clippy::too_many_lines)] // an exhaustive per-variant walker; splitting it obscures the 1:1 map
fn write_expr_at(out: &mut String, expr: &Expr, interner: &Interner, level: usize, depth: u16) {
    if depth > MAX_IR_RENDER_DEPTH {
        line(out, level, DEPTH_LIMIT_PLACEHOLDER);
        return;
    }
    let depth = depth + 1;
    match expr {
        Expr::Int(n) => line(out, level, &format!("Int {n}")),
        Expr::Bool(b) => line(out, level, &format!("Bool {b}")),
        Expr::Float(f) => line(out, level, &format!("Float {f}")),
        Expr::Str(s) => line(out, level, &format!("Str {s:?}")),
        Expr::CustomElementRef { tag, js_path } => {
            line(out, level, &format!("CustomElementRef {tag:?} {js_path:?}"));
        }
        Expr::Char(c) => line(out, level, &format!("Char '{c}'")),
        Expr::Unit => line(out, level, "Unit"),
        Expr::Var(sym) => line(out, level, &format!("Var {}", sym_name(interner, *sym))),
        Expr::CloneVar(sym) => line(
            out,
            level,
            &format!("CloneVar {}", sym_name(interner, *sym)),
        ),
        Expr::Ctor {
            ty, variant, args, ..
        } => {
            line(
                out,
                level,
                &format!(
                    "Ctor {}.{}",
                    sym_name(interner, *ty),
                    sym_name(interner, *variant)
                ),
            );
            for arg in args {
                write_expr_at(out, arg, interner, level + 1, depth);
            }
        }
        Expr::BinOp { op, lhs, rhs } => {
            line(out, level, &format!("BinOp {}", binop_token(*op)));
            write_expr_at(out, lhs, interner, level + 1, depth);
            write_expr_at(out, rhs, interner, level + 1, depth);
        }
        Expr::Let { name, value, body } => {
            write_binding(
                out,
                &format!("Let {}", sym_name(interner, *name)),
                value,
                body,
                interner,
                level,
                depth,
            );
        }
        Expr::Destructure {
            binder,
            value,
            body,
        } => {
            write_binding(
                out,
                &format!("Destructure {}", pat_name(interner, binder)),
                value,
                body,
                interner,
                level,
                depth,
            );
        }
        Expr::If { cond, then_, else_ } => {
            line(out, level, "If");
            line(out, level + 1, "cond");
            write_expr_at(out, cond, interner, level + 2, depth);
            line(out, level + 1, "then");
            write_expr_at(out, then_, interner, level + 2, depth);
            line(out, level + 1, "else");
            write_expr_at(out, else_, interner, level + 2, depth);
        }
        Expr::Match(m) => write_match(out, m, interner, level, depth),
        Expr::Call { callee, args, .. } => {
            line(out, level, &format!("Call {}", callee_name(callee)));
            for arg in args {
                write_expr_at(out, arg, interner, level + 1, depth);
            }
        }
        Expr::Tuple(elems) => {
            line(out, level, "Tuple");
            for elem in elems {
                write_expr_at(out, elem, interner, level + 1, depth);
            }
        }
        Expr::List { elem, items } => write_list(out, elem, items, interner, level, depth),
        Expr::Cons { head, tail } => write_cons(out, head, tail, interner, level, depth),
        Expr::ListIndexClone { list, index, .. } => {
            line(out, level, &format!("ListIndexClone [{index}]"));
            write_expr_at(out, list, interner, level + 1, depth);
        }
        Expr::ListLenCheck { list, len, exact } => {
            let op = if *exact { "==" } else { ">=" };
            line(out, level, &format!("ListLenCheck len {op} {len}"));
            write_expr_at(out, list, interner, level + 1, depth);
        }
        Expr::Record { fields, .. } => write_record(out, fields, interner, level, depth),
        Expr::Access {
            record,
            field,
            field_ty: _,
        } => {
            line(
                out,
                level,
                &format!("Access .{}", sym_name(interner, *field)),
            );
            write_expr_at(out, record, interner, level + 1, depth);
        }
        Expr::Update { record, fields } => {
            write_update(out, record, fields, interner, level, depth);
        }
        Expr::Lambda { params, ret, body } => {
            write_lambda(out, "Lambda", params, ret, body, interner, level, depth);
        }
        Expr::SharedLambda { params, ret, body } => {
            write_lambda(
                out,
                "SharedLambda",
                params,
                ret,
                body,
                interner,
                level,
                depth,
            );
        }
        Expr::OnceLambda {
            params,
            ret,
            body,
            capture,
        } => {
            let label = format!("OnceLambda moves {}", sym_name(interner, capture.name));
            write_lambda(out, &label, params, ret, body, interner, level, depth);
        }
        Expr::Apply { func, args } => write_apply(out, func, args, interner, level, depth),
        Expr::FuncValue { callee, ty } => line(
            out,
            level,
            &format!(
                "FuncValue {} : {}",
                callee_name(callee),
                ir_type_name(interner, ty)
            ),
        ),
        Expr::TaskSeq { effect, rest } => {
            write_task_seq(out, effect, rest, interner, level, depth);
        }
        Expr::TailLoop { params, body } => {
            write_tail_loop(out, params, body, interner, level, depth);
        }
        Expr::TailRecur { args } => {
            line(out, level, "TailRecur");
            for arg in args {
                write_expr_at(out, arg, interner, level + 1, depth);
            }
        }
    }
}

/// Render a [`Expr::TailLoop`] node: a header line, one `param name : ty` line
/// per loop parameter, then the `body:` sub-tree. Extracted from [`write_expr`]
/// to stay within the 100-line limit clippy enforces (sibling of
/// [`write_task_seq`]).
fn write_tail_loop(
    out: &mut String,
    params: &[(Symbol, IrType)],
    body: &Expr,
    interner: &Interner,
    level: usize,
    depth: u16,
) {
    line(out, level, "TailLoop");
    for (name, ty) in params {
        line(
            out,
            level + 1,
            &format!(
                "param {} : {}",
                sym_name(interner, *name),
                ir_type_name(interner, ty)
            ),
        );
    }
    line(out, level + 1, "body");
    write_expr_at(out, body, interner, level + 2, depth);
}

/// Render a [`Expr::TaskSeq`] node: a header line followed by `effect:` and
/// `rest:` child sub-trees. Extracted from [`write_expr`] to stay within the
/// 100-line limit clippy enforces.
fn write_task_seq(
    out: &mut String,
    effect: &Expr,
    rest: &Expr,
    interner: &Interner,
    level: usize,
    depth: u16,
) {
    line(out, level, "TaskSeq");
    line(out, level + 1, "effect:");
    write_expr_at(out, effect, interner, level + 2, depth);
    line(out, level + 1, "rest:");
    write_expr_at(out, rest, interner, level + 2, depth);
}

/// Render the labelled `field <name>` / value child lines of a record literal /
/// update. Shared by [`write_record`] and [`write_update`].
fn write_fields(
    out: &mut String,
    fields: &[(Symbol, Expr)],
    interner: &Interner,
    level: usize,
    depth: u16,
) {
    for (name, value) in fields {
        line(out, level, &format!("field {}", sym_name(interner, *name)));
        write_expr_at(out, value, interner, level + 1, depth);
    }
}

/// Render a `Record` literal node. Split from [`write_expr`] to keep that match
/// small.
/// Render a list literal node: a `List : <elem>` header line followed by each
/// element expression one level deeper.
fn write_list(
    out: &mut String,
    elem: &IrType,
    items: &[Expr],
    interner: &Interner,
    level: usize,
    depth: u16,
) {
    line(
        out,
        level,
        &format!("List : {}", ir_type_name(interner, elem)),
    );
    for item in items {
        write_expr_at(out, item, interner, level + 1, depth);
    }
}

/// Render a cons node: a `Cons` header line followed by the head then the tail,
/// each one level deeper.
fn write_cons(
    out: &mut String,
    head: &Expr,
    tail: &Expr,
    interner: &Interner,
    level: usize,
    depth: u16,
) {
    line(out, level, "Cons");
    write_expr_at(out, head, interner, level + 1, depth);
    write_expr_at(out, tail, interner, level + 1, depth);
}

fn write_record(
    out: &mut String,
    fields: &[(Symbol, Expr)],
    interner: &Interner,
    level: usize,
    depth: u16,
) {
    line(out, level, "Record");
    write_fields(out, fields, interner, level + 1, depth);
}

/// Render an `Update` node: the copied `record` then the changed fields. Split
/// from [`write_expr`] to keep that match small.
fn write_update(
    out: &mut String,
    record: &Expr,
    fields: &[(Symbol, Expr)],
    interner: &Interner,
    level: usize,
    depth: u16,
) {
    line(out, level, "Update");
    line(out, level + 1, "record");
    write_expr_at(out, record, interner, level + 2, depth);
    write_fields(out, fields, interner, level + 1, depth);
}

/// Render a `Lambda` node: a header `Lambda (p0 : T0, ...) -> R` followed by its
/// body one level deeper. Split from [`write_expr`] to keep that match small.
#[allow(clippy::too_many_arguments)] // depth threads alongside level for the stack-safety guard
fn write_lambda(
    out: &mut String,
    label: &str,
    params: &[(Symbol, IrType)],
    ret: &IrType,
    body: &Expr,
    interner: &Interner,
    level: usize,
    depth: u16,
) {
    let rendered = params
        .iter()
        .map(|(sym, ty)| {
            format!(
                "{} : {}",
                sym_name(interner, *sym),
                ir_type_name(interner, ty)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    line(
        out,
        level,
        &format!("{label} ({rendered}) -> {}", ir_type_name(interner, ret)),
    );
    write_expr_at(out, body, interner, level + 1, depth);
}

/// Render an `Apply` node: a `func` sub-tree then one `arg` sub-tree per
/// argument. Split from [`write_expr`] to keep that match small.
fn write_apply(
    out: &mut String,
    func: &Expr,
    args: &[Expr],
    interner: &Interner,
    level: usize,
    depth: u16,
) {
    line(out, level, "Apply");
    line(out, level + 1, "func");
    write_expr_at(out, func, interner, level + 2, depth);
    for arg in args {
        line(out, level + 1, "arg");
        write_expr_at(out, arg, interner, level + 2, depth);
    }
}

fn write_match(out: &mut String, m: &Match, interner: &Interner, level: usize, depth: u16) {
    line(out, level, "Match");
    line(out, level + 1, "scrutinee");
    write_expr_at(out, m.scrutinee(), interner, level + 2, depth);
    for Arm { pat, body, guard } in m.arms() {
        line(out, level + 1, &format!("arm {}", pat_name(interner, pat)));
        if let Some(g) = guard {
            line(out, level + 2, "guard");
            write_expr_at(out, g, interner, level + 3, depth);
        }
        write_expr_at(out, body, interner, level + 2, depth);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CallPin, FuncId, OnFormKind};
    use ipe_diagnostics::DResult;

    /// Build the canonical program: a `Main` module with a `Msg` enum and a
    /// `main` function whose body is `Io.println (String.fromInt 1)`, plus a
    /// `tick` function with a `Match` over `Msg`.
    #[allow(clippy::too_many_lines)]
    fn m0_program(i: &mut Interner) -> DResult<Program> {
        let main_mod = i.intern("Main")?;
        let msg = i.intern("Msg")?;
        let inc = i.intern("Increment")?;
        let dec = i.intern("Decrement")?;
        let main_sym = i.intern("main")?;
        let tick = i.intern("tick")?;
        let count = i.intern("count")?;
        let m = i.intern("m")?;

        let main_func = Func {
            id: FuncId::from_raw(0),
            name: main_sym,
            home: ModPath(vec![]),
            type_params: vec![],
            row_params: vec![],
            params: vec![],
            ret: IrType::Task(Box::new(IrType::Unit)),
            body: Expr::Call {
                callee: Callee::Kernel(KernelFn::IoPrintln),
                args: vec![Expr::Call {
                    callee: Callee::Kernel(KernelFn::StringFromInt),
                    args: vec![Expr::Int(1)],
                    pin: CallPin::None,
                    on_form: OnFormKind::NotForm,
                }],
                pin: CallPin::None,
                on_form: OnFormKind::NotForm,
            },
        };

        let tick_arms = vec![
            Arm {
                pat: Pat::Ctor {
                    home: ModPath(vec![]),
                    ty: msg,
                    variant: inc,
                    args: vec![],
                },
                body: Expr::BinOp {
                    op: BinOp::IntAdd,
                    lhs: Box::new(Expr::Var(count)),
                    rhs: Box::new(Expr::Int(1)),
                },
                guard: None,
            },
            Arm {
                pat: Pat::Ctor {
                    home: ModPath(vec![]),
                    ty: msg,
                    variant: dec,
                    args: vec![],
                },
                body: Expr::BinOp {
                    op: BinOp::IntSub,
                    lhs: Box::new(Expr::Var(count)),
                    rhs: Box::new(Expr::Int(1)),
                },
                guard: None,
            },
        ];
        let tick_func = Func {
            id: FuncId::from_raw(1),
            name: tick,
            home: ModPath(vec![]),
            type_params: vec![],
            row_params: vec![],
            params: vec![
                (
                    m,
                    IrType::Enum {
                        home: ModPath(vec![]),
                        name: msg,
                        args: vec![],
                    },
                ),
                (count, IrType::Int),
            ],
            ret: IrType::Int,
            body: Expr::Match(Match::new(Expr::Var(m), tick_arms, &[inc, dec])?),
        };

        Ok(Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![main_mod]),
                types: vec![TypeDef::Enum(EnumDef {
                    home: ModPath(vec![]),
                    name: msg,
                    type_params: vec![],
                    variants: vec![
                        Variant {
                            name: inc,
                            fields: vec![],
                        },
                        Variant {
                            name: dec,
                            fields: vec![],
                        },
                    ],
                })],
                funcs: vec![main_func, tick_func],
                entry: Some(FuncId::from_raw(0)),
                records: vec![],
                uses_tea: false,
                uses_server: false,
                uses_http: false,
                uses_config: false,
                uses_compression: false,
                uses_csv: false,
                uses_cache: false,
                uses_encoding: false,
                uses_regex: false,
                uses_uuid: false,
                uses_random: false,
                uses_log: false,
                uses_decimal: false,
                uses_char_category: false,
                uses_crypto_core: false,
                uses_secret: false,
                uses_json: false,
                uses_crypto: false,
                uses_jwt: false,
                uses_url: false,
                uses_ui: false,
                uses_web: false,
                uses_tui: false,
                uses_console: false,
                uses_webview: false,
                uses_css: false,
                uses_auth: false,
                uses_principal: false,
                uses_websocket: false,
                uses_email: false,
                uses_locale: false,
                uses_time: false,
                uses_env_public: false,
                uses_debug: false,
                uses_ffi: false,
                uses_async_runtime: false,
            }],
        })
    }

    #[test]
    fn pretty_renders_m0_program() -> DResult<()> {
        let mut i = Interner::new();
        let program = m0_program(&mut i)?;
        let rendered = pretty(&program, &i);

        let expected = "\
program
  module Main
    type Msg = Increment | Decrement
    fn#0 main() -> Task Error ()
      Call kernel Io.println
        Call kernel String.fromInt
          Int 1
    fn#1 tick(m : Msg, count : Int) -> Int
      Match
        scrutinee
          Var m
        arm Msg.Increment
          BinOp +
            Var count
            Int 1
        arm Msg.Decrement
          BinOp -
            Var count
            Int 1
    entry main
";
        assert_eq!(rendered, expected);
        Ok(())
    }

    #[test]
    fn pretty_is_deterministic() -> DResult<()> {
        let mut i = Interner::new();
        let program = m0_program(&mut i)?;
        assert_eq!(pretty(&program, &i), pretty(&program, &i));
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)] // exhaustive `Module` literal (every `uses_*` flag)
    fn pretty_renders_let_if_and_extended_binops() -> DResult<()> {
        let mut i = Interner::new();
        let main_mod = i.intern("Main")?;
        let f = i.intern("f")?;
        let n = i.intern("n")?;
        let x = i.intern("x")?;

        // f(n : Int) -> Int = let x = n * 2 in if x >= 10 then x / 2 else x + 1
        let body = Expr::Let {
            name: x,
            value: Box::new(Expr::BinOp {
                op: BinOp::IntMul,
                lhs: Box::new(Expr::Var(n)),
                rhs: Box::new(Expr::Int(2)),
            }),
            body: Box::new(Expr::If {
                cond: Box::new(Expr::BinOp {
                    op: BinOp::Ge,
                    lhs: Box::new(Expr::Var(x)),
                    rhs: Box::new(Expr::Int(10)),
                }),
                then_: Box::new(Expr::BinOp {
                    op: BinOp::Div,
                    lhs: Box::new(Expr::Var(x)),
                    rhs: Box::new(Expr::Int(2)),
                }),
                else_: Box::new(Expr::BinOp {
                    op: BinOp::IntAdd,
                    lhs: Box::new(Expr::Var(x)),
                    rhs: Box::new(Expr::Int(1)),
                }),
            }),
        };
        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![main_mod]),
                types: vec![],
                funcs: vec![Func {
                    id: FuncId::from_raw(0),
                    name: f,
                    home: ModPath(vec![]),
                    type_params: vec![],
                    row_params: vec![],
                    params: vec![(n, IrType::Int)],
                    ret: IrType::Int,
                    body,
                }],
                entry: None,
                records: vec![],
                uses_tea: false,
                uses_server: false,
                uses_http: false,
                uses_config: false,
                uses_compression: false,
                uses_csv: false,
                uses_cache: false,
                uses_encoding: false,
                uses_regex: false,
                uses_uuid: false,
                uses_random: false,
                uses_log: false,
                uses_decimal: false,
                uses_char_category: false,
                uses_crypto_core: false,
                uses_secret: false,
                uses_json: false,
                uses_crypto: false,
                uses_jwt: false,
                uses_url: false,
                uses_ui: false,
                uses_web: false,
                uses_tui: false,
                uses_console: false,
                uses_webview: false,
                uses_css: false,
                uses_auth: false,
                uses_principal: false,
                uses_websocket: false,
                uses_email: false,
                uses_locale: false,
                uses_time: false,
                uses_env_public: false,
                uses_debug: false,
                uses_ffi: false,
                uses_async_runtime: false,
            }],
        };

        let expected = "\
program
  module Main
    fn#0 f(n : Int) -> Int
      Let x
        value
          BinOp *
            Var n
            Int 2
        body
          If
            cond
              BinOp >=
                Var x
                Int 10
            then
              BinOp /
                Var x
                Int 2
            else
              BinOp +
                Var x
                Int 1
";
        assert_eq!(pretty(&program, &i), expected);
        Ok(())
    }

    #[test]
    fn pretty_renders_tuple_expr_and_type() -> DResult<()> {
        let mut i = Interner::new();
        let main_mod = i.intern("Main")?;
        let f = i.intern("pair")?;
        let n = i.intern("n")?;

        // pair(n : Int) -> (Int, Bool) = (n, n)  (shape only; types illustrative)
        let body = Expr::Tuple(vec![Expr::Var(n), Expr::Int(1)]);
        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![main_mod]),
                types: vec![],
                funcs: vec![Func {
                    id: FuncId::from_raw(0),
                    name: f,
                    home: ModPath(vec![]),
                    type_params: vec![],
                    row_params: vec![],
                    params: vec![(n, IrType::Int)],
                    ret: IrType::Tuple(vec![IrType::Int, IrType::Bool]),
                    body,
                }],
                entry: None,
                records: vec![],
                uses_tea: false,
                uses_server: false,
                uses_http: false,
                uses_config: false,
                uses_compression: false,
                uses_csv: false,
                uses_cache: false,
                uses_encoding: false,
                uses_regex: false,
                uses_uuid: false,
                uses_random: false,
                uses_log: false,
                uses_decimal: false,
                uses_char_category: false,
                uses_crypto_core: false,
                uses_secret: false,
                uses_json: false,
                uses_crypto: false,
                uses_jwt: false,
                uses_url: false,
                uses_ui: false,
                uses_web: false,
                uses_tui: false,
                uses_console: false,
                uses_webview: false,
                uses_css: false,
                uses_auth: false,
                uses_principal: false,
                uses_websocket: false,
                uses_email: false,
                uses_locale: false,
                uses_time: false,
                uses_env_public: false,
                uses_debug: false,
                uses_ffi: false,
                uses_async_runtime: false,
            }],
        };

        let expected = "\
program
  module Main
    fn#0 pair(n : Int) -> (Int, Bool)
      Tuple
        Var n
        Int 1
";
        assert_eq!(pretty(&program, &i), expected);
        Ok(())
    }

    #[test]
    fn pretty_renders_record_expr_access_update_and_type() -> DResult<()> {
        use std::collections::BTreeMap;

        let mut i = Interner::new();
        let main_mod = i.intern("Main")?;
        let func = i.intern("move_")?;
        let param = i.intern("p")?;
        let x = i.intern("x")?;
        let y = i.intern("y")?;

        // move_(p : { x : Int, y : Int }) -> { x : Int, y : Int }
        //   = { p | x = p.x }   (shape only; values illustrative)
        let body = Expr::Update {
            record: Box::new(Expr::Var(param)),
            fields: vec![(
                x,
                Expr::Access {
                    record: Box::new(Expr::Var(param)),
                    field: x,
                    field_ty: IrType::Int,
                },
            )],
        };
        let mut rec_fields = BTreeMap::new();
        rec_fields.insert(x, IrType::Int);
        rec_fields.insert(y, IrType::Int);
        let rec_ty = IrType::Record(rec_fields);
        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![main_mod]),
                types: vec![],
                funcs: vec![Func {
                    id: FuncId::from_raw(0),
                    name: func,
                    home: ModPath(vec![]),
                    type_params: vec![],
                    row_params: vec![],
                    params: vec![(param, rec_ty.clone())],
                    ret: rec_ty,
                    body,
                }],
                entry: None,
                records: vec![],
                uses_tea: false,
                uses_server: false,
                uses_http: false,
                uses_config: false,
                uses_compression: false,
                uses_csv: false,
                uses_cache: false,
                uses_encoding: false,
                uses_regex: false,
                uses_uuid: false,
                uses_random: false,
                uses_log: false,
                uses_decimal: false,
                uses_char_category: false,
                uses_crypto_core: false,
                uses_secret: false,
                uses_json: false,
                uses_crypto: false,
                uses_jwt: false,
                uses_url: false,
                uses_ui: false,
                uses_web: false,
                uses_tui: false,
                uses_console: false,
                uses_webview: false,
                uses_css: false,
                uses_auth: false,
                uses_principal: false,
                uses_websocket: false,
                uses_email: false,
                uses_locale: false,
                uses_time: false,
                uses_env_public: false,
                uses_debug: false,
                uses_ffi: false,
                uses_async_runtime: false,
            }],
        };

        let expected = "\
program
  module Main
    fn#0 move_(p : { x : Int, y : Int }) -> { x : Int, y : Int }
      Update
        record
          Var p
        field x
          Access .x
            Var p
";
        assert_eq!(pretty(&program, &i), expected);
        Ok(())
    }

    #[test]
    fn pretty_renders_record_literal() -> DResult<()> {
        let mut i = Interner::new();
        let main_mod = i.intern("Main")?;
        let f = i.intern("origin")?;
        let x = i.intern("x")?;
        let y = i.intern("y")?;

        // origin() -> ... = { x = 1, y = 2 }
        let body = Expr::Record {
            fields: vec![(x, Expr::Int(1)), (y, Expr::Int(2))],
            ty: None,
        };
        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![main_mod]),
                types: vec![],
                funcs: vec![Func {
                    id: FuncId::from_raw(0),
                    name: f,
                    home: ModPath(vec![]),
                    type_params: vec![],
                    row_params: vec![],
                    params: vec![],
                    ret: IrType::Int,
                    body,
                }],
                entry: None,
                records: vec![],
                uses_tea: false,
                uses_server: false,
                uses_http: false,
                uses_config: false,
                uses_compression: false,
                uses_csv: false,
                uses_cache: false,
                uses_encoding: false,
                uses_regex: false,
                uses_uuid: false,
                uses_random: false,
                uses_log: false,
                uses_decimal: false,
                uses_char_category: false,
                uses_crypto_core: false,
                uses_secret: false,
                uses_json: false,
                uses_crypto: false,
                uses_jwt: false,
                uses_url: false,
                uses_ui: false,
                uses_web: false,
                uses_tui: false,
                uses_console: false,
                uses_webview: false,
                uses_css: false,
                uses_auth: false,
                uses_principal: false,
                uses_websocket: false,
                uses_email: false,
                uses_locale: false,
                uses_time: false,
                uses_env_public: false,
                uses_debug: false,
                uses_ffi: false,
                uses_async_runtime: false,
            }],
        };

        let expected = "\
program
  module Main
    fn#0 origin() -> Int
      Record
        field x
          Int 1
        field y
          Int 2
";
        assert_eq!(pretty(&program, &i), expected);
        Ok(())
    }

    #[test]
    fn pretty_renders_lambda_apply_and_fun_type() -> DResult<()> {
        let mut i = Interner::new();
        let main_mod = i.intern("Main")?;
        let f = i.intern("apply2")?;
        let g = i.intern("g")?;
        let x = i.intern("x")?;

        // apply2(g : Int -> Int) -> Int = (\x -> g x) 2
        let body = Expr::Apply {
            func: Box::new(Expr::Lambda {
                params: vec![(x, IrType::Int)],
                ret: IrType::Int,
                body: Box::new(Expr::Apply {
                    func: Box::new(Expr::Var(g)),
                    args: vec![Expr::Var(x)],
                }),
            }),
            args: vec![Expr::Int(2)],
        };
        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![main_mod]),
                types: vec![],
                funcs: vec![Func {
                    id: FuncId::from_raw(0),
                    name: f,
                    home: ModPath(vec![]),
                    type_params: vec![],
                    row_params: vec![],
                    params: vec![(g, IrType::Fun(vec![IrType::Int], Box::new(IrType::Int)))],
                    ret: IrType::Int,
                    body,
                }],
                entry: None,
                records: vec![],
                uses_tea: false,
                uses_server: false,
                uses_http: false,
                uses_config: false,
                uses_compression: false,
                uses_csv: false,
                uses_cache: false,
                uses_encoding: false,
                uses_regex: false,
                uses_uuid: false,
                uses_random: false,
                uses_log: false,
                uses_decimal: false,
                uses_char_category: false,
                uses_crypto_core: false,
                uses_secret: false,
                uses_json: false,
                uses_crypto: false,
                uses_jwt: false,
                uses_url: false,
                uses_ui: false,
                uses_web: false,
                uses_tui: false,
                uses_console: false,
                uses_webview: false,
                uses_css: false,
                uses_auth: false,
                uses_principal: false,
                uses_websocket: false,
                uses_email: false,
                uses_locale: false,
                uses_time: false,
                uses_env_public: false,
                uses_debug: false,
                uses_ffi: false,
                uses_async_runtime: false,
            }],
        };

        let expected = "\
program
  module Main
    fn#0 apply2(g : Int -> Int) -> Int
      Apply
        func
          Lambda (x : Int) -> Int
            Apply
              func
                Var g
              arg
                Var x
        arg
          Int 2
";
        assert_eq!(pretty(&program, &i), expected);
        Ok(())
    }

    #[test]
    fn pretty_renders_nullary_fun_type() -> DResult<()> {
        let mut i = Interner::new();
        let main_mod = i.intern("Main")?;
        let f = i.intern("thunk")?;

        // thunk(k : () -> Bool) -> Bool = ...  (body shape illustrative)
        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![main_mod]),
                types: vec![],
                funcs: vec![Func {
                    id: FuncId::from_raw(0),
                    name: f,
                    home: ModPath(vec![]),
                    type_params: vec![],
                    row_params: vec![],
                    params: vec![(i.intern("k")?, IrType::Fun(vec![], Box::new(IrType::Bool)))],
                    ret: IrType::Bool,
                    body: Expr::Int(0),
                }],
                entry: None,
                records: vec![],
                uses_tea: false,
                uses_server: false,
                uses_http: false,
                uses_config: false,
                uses_compression: false,
                uses_csv: false,
                uses_cache: false,
                uses_encoding: false,
                uses_regex: false,
                uses_uuid: false,
                uses_random: false,
                uses_log: false,
                uses_decimal: false,
                uses_char_category: false,
                uses_crypto_core: false,
                uses_secret: false,
                uses_json: false,
                uses_crypto: false,
                uses_jwt: false,
                uses_url: false,
                uses_ui: false,
                uses_web: false,
                uses_tui: false,
                uses_console: false,
                uses_webview: false,
                uses_css: false,
                uses_auth: false,
                uses_principal: false,
                uses_websocket: false,
                uses_email: false,
                uses_locale: false,
                uses_time: false,
                uses_env_public: false,
                uses_debug: false,
                uses_ffi: false,
                uses_async_runtime: false,
            }],
        };

        let expected = "\
program
  module Main
    fn#0 thunk(k : () -> Bool) -> Bool
      Int 0
";
        assert_eq!(pretty(&program, &i), expected);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)] // fixture builder — length is the enumerated IR it constructs
    fn pretty_renders_generic_adt_decl_ctor_and_pattern() -> DResult<()> {
        let mut i = Interner::new();
        let main_mod = i.intern("Main")?;
        let a = i.intern("a")?;
        let maybe = i.intern("Maybe")?;
        let just = i.intern("Just")?;
        let nothing = i.intern("Nothing")?;
        let unwrap = i.intern("unwrap")?;
        let m = i.intern("m")?;
        let x = i.intern("x")?;

        // type Maybe a = Just a | Nothing
        // unwrap(m : Maybe Int) -> Int =
        //   case m of Just x -> x ; Nothing -> 0
        let arms = vec![
            Arm {
                pat: Pat::Ctor {
                    home: ModPath(vec![]),
                    ty: maybe,
                    variant: just,
                    args: vec![Pat::Var(x)],
                },
                body: Expr::Var(x),
                guard: None,
            },
            Arm {
                pat: Pat::Ctor {
                    home: ModPath(vec![]),
                    ty: maybe,
                    variant: nothing,
                    args: vec![],
                },
                body: Expr::Int(0),
                guard: None,
            },
        ];
        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![main_mod]),
                types: vec![TypeDef::Enum(EnumDef {
                    home: ModPath(vec![]),
                    name: maybe,
                    type_params: vec![a],
                    variants: vec![
                        Variant {
                            name: just,
                            fields: vec![IrType::Generic(a)],
                        },
                        Variant {
                            name: nothing,
                            fields: vec![],
                        },
                    ],
                })],
                funcs: vec![Func {
                    id: FuncId::from_raw(0),
                    name: unwrap,
                    home: ModPath(vec![]),
                    type_params: vec![],
                    row_params: vec![],
                    params: vec![(
                        m,
                        IrType::Enum {
                            home: ModPath(vec![]),
                            name: maybe,
                            args: vec![IrType::Int],
                        },
                    )],
                    ret: IrType::Int,
                    body: Expr::Match(Match::new(Expr::Var(m), arms, &[just, nothing])?),
                }],
                entry: None,
                records: vec![],
                uses_tea: false,
                uses_server: false,
                uses_http: false,
                uses_config: false,
                uses_compression: false,
                uses_csv: false,
                uses_cache: false,
                uses_encoding: false,
                uses_regex: false,
                uses_uuid: false,
                uses_random: false,
                uses_log: false,
                uses_decimal: false,
                uses_char_category: false,
                uses_crypto_core: false,
                uses_secret: false,
                uses_json: false,
                uses_crypto: false,
                uses_jwt: false,
                uses_url: false,
                uses_ui: false,
                uses_web: false,
                uses_tui: false,
                uses_console: false,
                uses_webview: false,
                uses_css: false,
                uses_auth: false,
                uses_principal: false,
                uses_websocket: false,
                uses_email: false,
                uses_locale: false,
                uses_time: false,
                uses_env_public: false,
                uses_debug: false,
                uses_ffi: false,
                uses_async_runtime: false,
            }],
        };

        let expected = "\
program
  module Main
    type Maybe a = Just a | Nothing
    fn#0 unwrap(m : Maybe Int) -> Int
      Match
        scrutinee
          Var m
        arm Maybe.Just x
          Var x
        arm Maybe.Nothing
          Int 0
";
        assert_eq!(pretty(&program, &i), expected);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)] // exhaustive `Module` literal (every `uses_*` flag)
    fn pretty_renders_tuple_pattern_and_unit() -> DResult<()> {
        let mut i = Interner::new();
        let main_mod = i.intern("Main")?;
        let wrap = i.intern("Wrap")?;
        let mk_wrap = i.intern("MkWrap")?;
        let fst_of = i.intern("fstOf")?;
        let w = i.intern("w")?;
        let a = i.intern("a")?;
        let b = i.intern("b")?;
        let nop = i.intern("nop")?;

        // type Wrap = MkWrap (Int, Int)
        // fstOf(w : Wrap) -> Int = case w of MkWrap (a, b) -> a
        // nop() -> () = ()
        let arms = vec![Arm {
            pat: Pat::Ctor {
                home: ModPath(vec![]),
                ty: wrap,
                variant: mk_wrap,
                args: vec![Pat::Tuple(vec![Pat::Var(a), Pat::Var(b)])],
            },
            body: Expr::Var(a),
            guard: None,
        }];
        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![main_mod]),
                types: vec![TypeDef::Enum(EnumDef {
                    home: ModPath(vec![]),
                    name: wrap,
                    type_params: vec![],
                    variants: vec![Variant {
                        name: mk_wrap,
                        fields: vec![IrType::Tuple(vec![IrType::Int, IrType::Int])],
                    }],
                })],
                funcs: vec![
                    Func {
                        id: FuncId::from_raw(0),
                        name: fst_of,
                        home: ModPath(vec![]),
                        type_params: vec![],
                        row_params: vec![],
                        params: vec![(
                            w,
                            IrType::Enum {
                                home: ModPath(vec![]),
                                name: wrap,
                                args: vec![],
                            },
                        )],
                        ret: IrType::Int,
                        body: Expr::Match(Match::new(Expr::Var(w), arms, &[mk_wrap])?),
                    },
                    Func {
                        id: FuncId::from_raw(1),
                        name: nop,
                        home: ModPath(vec![]),
                        type_params: vec![],
                        row_params: vec![],
                        params: vec![],
                        ret: IrType::Unit,
                        body: Expr::Unit,
                    },
                ],
                entry: None,
                records: vec![],
                uses_tea: false,
                uses_server: false,
                uses_http: false,
                uses_config: false,
                uses_compression: false,
                uses_csv: false,
                uses_cache: false,
                uses_encoding: false,
                uses_regex: false,
                uses_uuid: false,
                uses_random: false,
                uses_log: false,
                uses_decimal: false,
                uses_char_category: false,
                uses_crypto_core: false,
                uses_secret: false,
                uses_json: false,
                uses_crypto: false,
                uses_jwt: false,
                uses_url: false,
                uses_ui: false,
                uses_web: false,
                uses_tui: false,
                uses_console: false,
                uses_webview: false,
                uses_css: false,
                uses_auth: false,
                uses_principal: false,
                uses_websocket: false,
                uses_email: false,
                uses_locale: false,
                uses_time: false,
                uses_env_public: false,
                uses_debug: false,
                uses_ffi: false,
                uses_async_runtime: false,
            }],
        };

        let expected = "\
program
  module Main
    type Wrap = MkWrap (Int, Int)
    fn#0 fstOf(w : Wrap) -> Int
      Match
        scrutinee
          Var w
        arm Wrap.MkWrap (a, b)
          Var a
    fn#1 nop() -> ()
      Unit
";
        assert_eq!(pretty(&program, &i), expected);
        Ok(())
    }

    #[test]
    fn pretty_resolves_forged_symbol_to_placeholder() {
        let i = Interner::new();
        // A program referencing a symbol this interner never handed out.
        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![Symbol::from_raw(999)]),
                types: vec![],
                funcs: vec![],
                entry: None,
                records: vec![],
                uses_tea: false,
                uses_server: false,
                uses_http: false,
                uses_config: false,
                uses_compression: false,
                uses_csv: false,
                uses_cache: false,
                uses_encoding: false,
                uses_regex: false,
                uses_uuid: false,
                uses_random: false,
                uses_log: false,
                uses_decimal: false,
                uses_char_category: false,
                uses_crypto_core: false,
                uses_secret: false,
                uses_json: false,
                uses_crypto: false,
                uses_jwt: false,
                uses_url: false,
                uses_ui: false,
                uses_web: false,
                uses_tui: false,
                uses_console: false,
                uses_webview: false,
                uses_css: false,
                uses_auth: false,
                uses_principal: false,
                uses_websocket: false,
                uses_email: false,
                uses_locale: false,
                uses_time: false,
                uses_env_public: false,
                uses_debug: false,
                uses_ffi: false,
                uses_async_runtime: false,
            }],
        };
        let rendered = pretty(&program, &i);
        assert!(rendered.contains("module <sym#999>"));
    }

    /// A single-func program whose body is a `BinOp` chain nested `levels`
    /// deep: `(((...(0 + 1) + 1)...) + 1)`.
    fn deeply_nested_binop_program(i: &mut Interner, levels: u32) -> DResult<Program> {
        let main_mod = i.intern("Main")?;
        let deep = i.intern("deep")?;
        let mut body = Expr::Int(0);
        for _ in 0..levels {
            body = Expr::BinOp {
                op: BinOp::IntAdd,
                lhs: Box::new(body),
                rhs: Box::new(Expr::Int(1)),
            };
        }
        Ok(Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![main_mod]),
                types: vec![],
                funcs: vec![Func {
                    id: FuncId::from_raw(0),
                    name: deep,
                    home: ModPath(vec![]),
                    type_params: vec![],
                    row_params: vec![],
                    params: vec![],
                    ret: IrType::Int,
                    body,
                }],
                entry: None,
                records: vec![],
                uses_tea: false,
                uses_server: false,
                uses_http: false,
                uses_config: false,
                uses_compression: false,
                uses_csv: false,
                uses_cache: false,
                uses_encoding: false,
                uses_regex: false,
                uses_uuid: false,
                uses_random: false,
                uses_log: false,
                uses_decimal: false,
                uses_char_category: false,
                uses_crypto_core: false,
                uses_secret: false,
                uses_json: false,
                uses_crypto: false,
                uses_jwt: false,
                uses_url: false,
                uses_ui: false,
                uses_web: false,
                uses_tui: false,
                uses_console: false,
                uses_webview: false,
                uses_css: false,
                uses_auth: false,
                uses_principal: false,
                uses_websocket: false,
                uses_email: false,
                uses_locale: false,
                uses_time: false,
                uses_ffi: false,
                uses_async_runtime: false,
                uses_env_public: false,
                uses_debug: false,
            }],
        })
    }

    /// CO-BACKEND-006: `--emit-ir` on a program nested well past the real
    /// emitter's bound (`ipe_backend_rust::MAX_EMIT_DEPTH`, IPE-L0200) must
    /// render a `<depth limit>` placeholder and return normally — never
    /// overflow the native stack — even though this dev-flag path has no
    /// other gate rejecting the program first.
    #[test]
    fn deeply_nested_expr_renders_depth_limit_placeholder_not_stack_overflow() -> DResult<()> {
        let mut i = Interner::new();
        // Far past MAX_IR_RENDER_DEPTH (96) — the same order of magnitude
        // the emitter-side hardening test uses to prove its own guard.
        let program = deeply_nested_binop_program(&mut i, 4096)?;
        let rendered = pretty(&program, &i);
        assert!(
            rendered.contains(DEPTH_LIMIT_PLACEHOLDER),
            "deep nesting must render the depth-limit placeholder:\n{rendered}"
        );
        Ok(())
    }

    /// An expression at the depth bound still renders in full — the guard is
    /// a ceiling, not an off-by-one rejection of legitimate programs.
    #[test]
    fn nesting_at_the_bound_still_renders_in_full() -> DResult<()> {
        let mut i = Interner::new();
        let program = deeply_nested_binop_program(&mut i, u32::from(MAX_IR_RENDER_DEPTH) / 2)?;
        let rendered = pretty(&program, &i);
        assert!(
            !rendered.contains(DEPTH_LIMIT_PLACEHOLDER),
            "in-bound nesting must render fully, not hit the placeholder:\n{rendered}"
        );
        // Every level renders its own `Int 0` / `Int 1` leaf.
        assert!(rendered.contains("Int 0"));
        assert!(rendered.contains("BinOp +"));
        Ok(())
    }
}
