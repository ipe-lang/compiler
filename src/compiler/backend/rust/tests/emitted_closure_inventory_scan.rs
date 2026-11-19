//! Every `move` closure the backend prints has an inventory row tied to
//! `ipe_ir::once_closure::boundary_kind`.
//!
//! The lowering decides whether a closure may move its captures out from the
//! IR closure verdict. A closure the emitter prints around an IR node is
//! covered by that verdict; a closure it prints around an already-emitted
//! expression (a kernel or wiring adapter) sits outside it. This ratchet lexes
//! every non-test fn of the backend's `src` tree, counts the string literals
//! that print a `move |` / `move ||` closure head (or a `move` keyword at the
//! literal's end or before a format placeholder, a head whose `|` is spliced
//! in), and holds the count per
//! `(file, fn)` against [`INVENTORY`]. A new producer without a row fails, and
//! so does a row whose count no longer matches.
//!
//! An adapter closure must capture no source local, so its literal is checked
//! too: the text after an [`Producer::Adapter`] head may splice in only the
//! format placeholders its row allowlists (fresh names, type text, runtime
//! text), and its `|` may not be spliced in at all. Emitted IR text after an
//! adapter head (`move || {effect_s}`) is refused.

use std::collections::BTreeMap;
use std::path::Path;

use ipe_ir::once_closure::{ClosureKind, MovedCapture, boundary_kind};
use ipe_ir::{Expr, IrType};
use proc_macro2::{Delimiter, TokenStream, TokenTree};

/// The IR closure form a producer prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    /// The closure literal printer shared by `Lambda`, `SharedLambda` and
    /// `OnceLambda`.
    Closure,
    /// The continuation a `TaskSeq` wraps around its `rest`.
    TaskSeqRest,
}

/// Every [`Form`], so each one is held against `boundary_kind`.
const FORMS: [Form; 2] = [Form::Closure, Form::TaskSeqRest];

/// What a `move` closure producer prints around.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Producer {
    /// An IR closure node, whose kind is `boundary_kind` of that node.
    Boundary(Form),
    /// A kernel or wiring adapter closure no IR node marks, so the capture
    /// verdict does not see it; the reason proves it wraps no source local, and
    /// the list names every format placeholder its literals may splice in after
    /// the `move` head (`""` is a positional `{}`).
    Adapter(AdapterReason, &'static [&'static str]),
    /// A layout check that matches a printed closure head and prints none.
    Recognizer,
}

/// Why a [`Producer::Adapter`] closure the capture verdict does not see is sound.
///
/// An adapted kernel slot has no reason here: it is emitted from its handler
/// normal form, its closure printed by the IR closure printer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdapterReason {
    /// The closure body names only a top-level item (the `update` fn, a page
    /// constructor) or fixed runtime text, never a source local.
    TopLevelFn,
    /// The closure captures only fresh `__`-prefixed bindings whose emitted
    /// value is bound by a `let` before the `move`, so the value is evaluated
    /// once outside the closure and no source local is captured.
    RuntimeValue,
}

/// Where a producer sits: the file relative to `src`, and the innermost named
/// fn.
type Site = (String, String);

/// Sites with the count that disagrees, one side of a [`drift`].
type Drifted = Vec<(Site, usize)>;

/// The sanctioned producers, as `(file, fn, count, producer)`.
const INVENTORY: &[(&str, &str, usize, Producer)] = &[
    (
        "emit_console.rs",
        "line_handler_bridge",
        1,
        Producer::Adapter(AdapterReason::RuntimeValue, &[]),
    ),
    (
        "emit_doc.rs",
        "build_closure",
        1,
        Producer::Boundary(Form::Closure),
    ),
    (
        "emit_doc.rs",
        "build_task_seq",
        1,
        Producer::Boundary(Form::TaskSeqRest),
    ),
    (
        "emit_expr/expr.rs",
        "emit_cmd_wiring_arm",
        1,
        Producer::Adapter(AdapterReason::RuntimeValue, &[]),
    ),
    (
        "emit_expr/expr.rs",
        "emit_expr_at",
        1,
        Producer::Boundary(Form::TaskSeqRest),
    ),
    (
        "emit_expr/func.rs",
        "emit_lambda_unboxed",
        1,
        Producer::Boundary(Form::Closure),
    ),
    (
        "emit_expr/kernel_calls.rs",
        "emit_json_decoder_call",
        2,
        Producer::Adapter(AdapterReason::RuntimeValue, &["params", "ret_s", "args"]),
    ),
    (
        "emit_expr/kernel_calls.rs",
        "emit_task_retry_call",
        1,
        Producer::Adapter(AdapterReason::RuntimeValue, &[]),
    ),
    (
        "emit_tui.rs",
        "key_event_bridge",
        1,
        Producer::Adapter(AdapterReason::RuntimeValue, &["struct_name"]),
    ),
    (
        "emit_web.rs",
        "emit_route_render",
        1,
        Producer::Adapter(AdapterReason::RuntimeValue, &["page_ty_s", "arms"]),
    ),
    (
        "emit_web.rs",
        "emit_web_route",
        2,
        Producer::Adapter(AdapterReason::TopLevelFn, &["ctor_s", ""]),
    ),
    (
        "emit_web.rs",
        "new",
        1,
        Producer::Adapter(AdapterReason::TopLevelFn, &[]),
    ),
    (
        "emit_web.rs",
        "set_page_closure",
        2,
        Producer::Adapter(AdapterReason::RuntimeValue, &["page_ty_s", "model_ty_s"]),
    ),
    (
        "emit_web.rs",
        "wrap_view",
        1,
        Producer::Adapter(AdapterReason::RuntimeValue, &[]),
    ),
    ("render.rs", "is_closure_head", 1, Producer::Recognizer),
    (
        "render/reference.rs",
        "is_closure_head",
        1,
        Producer::Recognizer,
    ),
];

/// The value of a string literal token, `None` for any other token.
fn str_value(tok: &TokenTree) -> Option<String> {
    let TokenTree::Literal(lit) = tok else {
        return None;
    };
    match syn::parse2::<syn::Lit>(TokenStream::from(TokenTree::Literal(lit.clone()))) {
        Ok(syn::Lit::Str(s)) => Some(s.value()),
        _ => None,
    }
}

/// The text after each `move |` / `move ||` closure head `text` prints.
///
/// A trailing `move` keyword, or one followed by a format placeholder, is a
/// head too: its `|` may sit in the next literal or the spliced text.
fn head_tails(text: &str) -> Vec<&str> {
    text.match_indices("move")
        .filter_map(|(at, word)| {
            let starts_word = text
                .get(..at)
                .and_then(|before| before.chars().next_back())
                .is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
            let tail = text.get(at + word.len()..)?;
            (starts_word && opens_params(tail)).then_some(tail)
        })
        .collect()
}

/// Whether the text after a `move` keyword opens a closure parameter list.
fn opens_params(tail: &str) -> bool {
    let rest = tail.trim_start();
    rest.is_empty() || rest.starts_with('|') || splices_first(rest)
}

/// Whether `text` starts with a format placeholder (not an escaped `{{`).
fn splices_first(text: &str) -> bool {
    text.starts_with('{') && !text.starts_with("{{")
}

/// How many closure heads `text` prints.
fn closure_heads(text: &str) -> usize {
    head_tails(text).len()
}

/// The names of the format placeholders in `text`, in order.
///
/// A positional `{}` is `""`; a format spec after `:` is dropped; the escapes
/// `{{` and `}}` are text.
fn placeholders(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        let escaped = chars.peek() == Some(&c);
        if escaped && (c == '{' || c == '}') {
            chars.next();
        } else if c == '{' {
            let body: String = chars.by_ref().take_while(|&b| b != '}').collect();
            let name = body.split_once(':').map_or(body.as_str(), |(name, _)| name);
            names.push(name.trim().to_owned());
        }
    }
    names
}

/// One printed closure head.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Head {
    /// The format placeholders after the `move` keyword in its literal.
    placeholders: Vec<String>,
    /// Whether its `|` is spliced in or sits in another literal, so the
    /// parameter list is not fixed text.
    split: bool,
}

impl Head {
    /// The head whose literal continues with `tail` after the `move` keyword.
    fn of_tail(tail: &str) -> Self {
        let rest = tail.trim_start();
        Self {
            placeholders: placeholders(tail),
            split: rest.is_empty() || splices_first(rest),
        }
    }
}

/// Whether `tok` is the punctuation `ch`.
fn is_punct(tok: Option<&TokenTree>, ch: char) -> bool {
    matches!(tok, Some(TokenTree::Punct(p)) if p.as_char() == ch)
}

/// Whether an attribute body is `test` or `cfg(test)`.
fn is_test_attr(body: &TokenStream) -> bool {
    let toks: Vec<TokenTree> = body.clone().into_iter().collect();
    match toks.as_slice() {
        [TokenTree::Ident(id)] => id == "test",
        [TokenTree::Ident(id), TokenTree::Group(args)] if id == "cfg" => {
            let inner: Vec<TokenTree> = args.stream().into_iter().collect();
            matches!(inner.as_slice(), [TokenTree::Ident(t)] if t == "test")
        }
        _ => false,
    }
}

/// The closure heads found, per site: their count and each head's shape.
#[derive(Debug, Default)]
struct Found {
    hits: BTreeMap<Site, usize>,
    heads: BTreeMap<Site, Vec<Head>>,
}

impl Found {
    /// Fold `other` into this result.
    fn absorb(&mut self, other: Self) {
        self.hits.extend(other.hits);
        self.heads.extend(other.heads);
    }
}

/// The producer counter over one file's token tree.
struct Scan<'a> {
    file: &'a str,
    found: Found,
}

impl Scan<'_> {
    /// Record the closure heads whose literal continues with `tails` in `func`.
    fn hit(&mut self, func: &str, tails: &[&str]) {
        let site = (self.file.to_owned(), func.to_owned());
        *self.found.hits.entry(site.clone()).or_insert(0) += tails.len();
        self.found
            .heads
            .entry(site)
            .or_default()
            .extend(tails.iter().copied().map(Head::of_tail));
    }

    /// Scan one token sequence inside the innermost named fn `func`, skipping
    /// every item gated by `#[test]` or `#[cfg(test)]`.
    fn stream(&mut self, stream: &TokenStream, func: &str) {
        let toks: Vec<TokenTree> = stream.clone().into_iter().collect();
        let mut test_gated = false;
        let mut i = 0;
        while let Some(tok) = toks.get(i) {
            // An attribute: `#[..]` (outer) or `#![..]` (inner).
            if is_punct(Some(tok), '#') {
                let inner = is_punct(toks.get(i + 1), '!');
                let at = if inner { i + 2 } else { i + 1 };
                if let Some(TokenTree::Group(g)) = toks.get(at)
                    && g.delimiter() == Delimiter::Bracket
                {
                    if !inner && is_test_attr(&g.stream()) {
                        test_gated = true;
                    }
                    i = at + 1;
                    continue;
                }
            }
            if let TokenTree::Ident(id) = tok {
                let word = id.to_string();
                // A named `fn` or `mod`: its body is the next brace group.
                if (word == "fn" || word == "mod")
                    && let Some(TokenTree::Ident(name)) = toks.get(i + 1)
                {
                    let mut k = i + 2;
                    while let Some(t) = toks.get(k) {
                        if is_punct(Some(t), ';')
                            || matches!(t, TokenTree::Group(g) if g.delimiter() == Delimiter::Brace)
                        {
                            break;
                        }
                        k += 1;
                    }
                    if let Some(TokenTree::Group(body)) = toks.get(k)
                        && body.delimiter() == Delimiter::Brace
                        && !test_gated
                    {
                        let name = name.to_string();
                        let inner_fn = if word == "fn" { name.as_str() } else { func };
                        self.stream(&body.stream(), inner_fn);
                    }
                    test_gated = false;
                    i = k + 1;
                    continue;
                }
                // A macro call `name!(..)`: its body is scanned as tokens.
                if is_punct(toks.get(i + 1), '!')
                    && let Some(TokenTree::Group(body)) = toks.get(i + 2)
                {
                    self.stream(&body.stream(), func);
                    test_gated = false;
                    i += 3;
                    continue;
                }
            }
            if let Some(text) = str_value(tok) {
                let tails = head_tails(&text);
                if !tails.is_empty() {
                    self.hit(func, &tails);
                }
            }
            if let TokenTree::Group(g) = tok {
                let brace = g.delimiter() == Delimiter::Brace;
                if !(brace && test_gated) {
                    self.stream(&g.stream(), func);
                }
                if brace {
                    test_gated = false;
                }
            }
            if is_punct(Some(tok), ';') {
                test_gated = false;
            }
            i += 1;
        }
    }
}

/// The closure producers in one source file, keyed by `(file, fn)`.
fn scan_source(file: &str, src: &str) -> Result<Found, String> {
    let stream: TokenStream = src
        .parse()
        .map_err(|e| format!("{file} does not lex: {e}"))?;
    let mut scan = Scan {
        file,
        found: Found::default(),
    };
    scan.stream(&stream, "<file>");
    Ok(scan.found)
}

/// The `/`-joined path of `path` relative to `root`.
fn relative(root: &Path, path: &Path) -> Result<String, String> {
    Ok(path
        .strip_prefix(root)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/"))
}

/// Scan one `.rs` file, naming it by its path relative to `root`.
fn scan_file(root: &Path, path: &Path, found: &mut Found) -> Result<(), String> {
    let rel = relative(root, path)?;
    let src = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    found.absorb(scan_source(&rel, &src)?);
    Ok(())
}

/// Scan every non-test `.rs` file under `dir` (a `tests` directory is test
/// code).
fn scan_dir(root: &Path, dir: &Path, found: &mut Found) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut paths = Vec::new();
    for entry in entries {
        paths.push(entry.map_err(|e| format!("{}: {e}", dir.display()))?.path());
    }
    paths.sort();
    for path in paths {
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "tests") {
                continue;
            }
            scan_dir(root, &path, found)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            scan_file(root, &path, found)?;
        }
    }
    Ok(())
}

/// The sites whose count differs from `inventory`, as `(unexpected, stale)`.
fn drift(
    found: &BTreeMap<Site, usize>,
    inventory: &[(&str, &str, usize, Producer)],
) -> (Drifted, Drifted) {
    let rows: BTreeMap<Site, usize> = inventory
        .iter()
        .map(|&(file, func, count, _)| ((file.to_owned(), func.to_owned()), count))
        .collect();
    let unexpected = found
        .iter()
        .filter(|(site, count)| rows.get(*site) != Some(*count))
        .map(|(site, count)| (site.clone(), *count))
        .collect();
    let stale = rows
        .iter()
        .filter(|(site, count)| found.get(*site) != Some(*count))
        .map(|(site, count)| (site.clone(), *count))
        .collect();
    (unexpected, stale)
}

/// The placeholders an [`AdapterReason`] admits after its rows' heads.
///
/// No reason admits emitted IR text: each admits only the names its row lists,
/// which are fresh `__`-prefixed bindings, type text or runtime text.
const fn admitted(
    reason: AdapterReason,
    allow: &'static [&'static str],
) -> &'static [&'static str] {
    match reason {
        AdapterReason::TopLevelFn | AdapterReason::RuntimeValue => allow,
    }
}

/// Every way the [`Producer::Adapter`] rows' heads in `heads` break their row.
///
/// A split head, a placeholder its row does not list, and a listed name no
/// head uses each give one line naming the site.
fn adapter_violations(
    heads: &BTreeMap<Site, Vec<Head>>,
    inventory: &[(&str, &str, usize, Producer)],
) -> Vec<String> {
    let mut out = Vec::new();
    for &(file, func, _, producer) in inventory {
        let Producer::Adapter(reason, allow) = producer else {
            continue;
        };
        let allowed = admitted(reason, allow);
        let site = (file.to_owned(), func.to_owned());
        let row_heads = heads.get(&site).map_or(&[][..], Vec::as_slice);
        for head in row_heads {
            if head.split {
                out.push(format!("{file}::{func}: a split `move` head"));
            }
            for name in &head.placeholders {
                if !allowed.contains(&name.as_str()) {
                    out.push(format!("{file}::{func}: `{{{name}}}` after a `move` head"));
                }
            }
        }
        for name in allowed {
            let used = row_heads
                .iter()
                .any(|head| head.placeholders.iter().any(|p| p == name));
            if !used {
                out.push(format!(
                    "{file}::{func}: allowlisted `{{{name}}}` is unused"
                ));
            }
        }
    }
    out
}

/// Every adapter closure the backend prints splices in only its row's listed
/// placeholders after its `move` head, and never its `|`.
#[test]
fn each_adapter_head_splices_only_its_listed_placeholders() -> Result<(), String> {
    let root = e2e_support::manifest_dir!().join("src");
    let mut found = Found::default();
    scan_dir(&root, &root, &mut found)?;
    let violations = adapter_violations(&found.heads, INVENTORY);
    assert!(
        violations.is_empty(),
        "an adapter closure may capture no source local: bind emitted text to a \
         fresh `__` name before the `move` head, or list a fresh-name/type \
         placeholder on its INVENTORY row.\n{violations:#?}"
    );
    Ok(())
}

/// The adapter-head violations of a synthetic source against `inventory`.
fn synthetic_violations(
    file: &str,
    src: &str,
    inventory: &[(&str, &str, usize, Producer)],
) -> Result<Vec<String>, String> {
    Ok(adapter_violations(
        &scan_source(file, src)?.heads,
        inventory,
    ))
}

/// The real cmd-wiring row: one runtime-value adapter head, nothing listed.
const CMD_WIRING_ROW: [(&str, &str, usize, Producer); 1] = [(
    "emit_expr/expr.rs",
    "emit_cmd_wiring_arm",
    1,
    Producer::Adapter(AdapterReason::RuntimeValue, &[]),
)];

/// An effect spliced into the cmd-wiring thunk is refused; bound to a fresh
/// name before the head, it passes.
#[test]
fn an_effect_spliced_after_the_cmd_wiring_head_is_refused() -> Result<(), String> {
    let spliced = synthetic_violations(
        "emit_expr/expr.rs",
        r#"fn emit_cmd_wiring_arm(effect_s: &str) -> String { format!("Box::new(move || {effect_s})") }"#,
        &CMD_WIRING_ROW,
    )?;
    assert_eq!(
        spliced,
        vec!["emit_expr/expr.rs::emit_cmd_wiring_arm: `{effect_s}` after a `move` head".to_owned()]
    );
    let bound = synthetic_violations(
        "emit_expr/expr.rs",
        r#"fn emit_cmd_wiring_arm(effect_s: &str) -> String { format!("{{ let __ipe_eff = {effect_s}; Box::new(move || __ipe_eff) }}") }"#,
        &CMD_WIRING_ROW,
    )?;
    assert_eq!(bound, Vec::<String>::new());
    Ok(())
}

/// A positional placeholder after an adapter head is refused unless listed.
#[test]
fn a_positional_placeholder_after_an_adapter_head_is_refused() -> Result<(), String> {
    let row = [(
        "emit_expr/kernel_calls.rs",
        "emit_wrap",
        1,
        Producer::Adapter(AdapterReason::RuntimeValue, &[]),
    )];
    let got = synthetic_violations(
        "emit_expr/kernel_calls.rs",
        r#"fn emit_wrap(a: &str, b: &str) -> String { format!("move |{}| (x)({})", a, b) }"#,
        &row,
    )?;
    assert_eq!(
        got,
        vec![
            "emit_expr/kernel_calls.rs::emit_wrap: `{}` after a `move` head".to_owned(),
            "emit_expr/kernel_calls.rs::emit_wrap: `{}` after a `move` head".to_owned(),
        ]
    );
    Ok(())
}

/// A listed type placeholder passes, with a format spec too, and an escaped
/// brace is text.
#[test]
fn a_listed_placeholder_after_an_adapter_head_passes() -> Result<(), String> {
    let row = [(
        "emit_web.rs",
        "page_closure",
        1,
        Producer::Adapter(AdapterReason::RuntimeValue, &["page_ty_s"]),
    )];
    let got = synthetic_violations(
        "emit_web.rs",
        r#"fn page_closure(page_ty_s: &str) -> String { format!("move |__page: &{page_ty_s:>0}| {{ __page }}") }"#,
        &row,
    )?;
    assert_eq!(got, Vec::<String>::new());
    Ok(())
}

/// A head whose `|` is spliced in or sits in another literal is refused in an
/// adapter row, and a listed name no head uses is stale.
#[test]
fn a_split_adapter_head_and_an_unused_listed_name_are_refused() -> Result<(), String> {
    let row = [(
        "emit_tui.rs",
        "bridge",
        2,
        Producer::Adapter(AdapterReason::TopLevelFn, &["p", "gone"]),
    )];
    let got = synthetic_violations(
        "emit_tui.rs",
        r#"fn bridge(o: &mut String, p: &str) { o.push_str(&format!("Box::new(move {p} x)")); o.push_str("Box::new(move "); }"#,
        &row,
    )?;
    assert_eq!(
        got,
        vec![
            "emit_tui.rs::bridge: a split `move` head".to_owned(),
            "emit_tui.rs::bridge: a split `move` head".to_owned(),
            "emit_tui.rs::bridge: allowlisted `{gone}` is unused".to_owned(),
        ]
    );
    Ok(())
}

/// A boundary row's head is held by the IR closure verdict, so its spliced body
/// is not an adapter violation.
#[test]
fn a_boundary_head_is_not_held_to_an_allowlist() -> Result<(), String> {
    let row = [(
        "emit_expr/func.rs",
        "emit_lambda_unboxed",
        1,
        Producer::Boundary(Form::Closure),
    )];
    let got = synthetic_violations(
        "emit_expr/func.rs",
        r#"fn emit_lambda_unboxed(b: &str) -> String { format!("move |x| -> R {{ {b} }}") }"#,
        &row,
    )?;
    assert_eq!(got, Vec::<String>::new());
    Ok(())
}

/// The backend prints exactly the inventoried `move` closures: a new
/// producer fails, and so does a row gone stale.
#[test]
fn every_emitted_move_closure_has_an_inventory_row() -> Result<(), String> {
    let root = e2e_support::manifest_dir!().join("src");
    let mut found = Found::default();
    scan_dir(&root, &root, &mut found)?;
    let (unexpected, stale) = drift(&found.hits, INVENTORY);
    assert!(
        unexpected.is_empty() && stale.is_empty(),
        "a `move` closure printed by the backend needs an INVENTORY row: \
         `Producer::Boundary` when it prints around an IR node `boundary_kind` \
         classifies, `Producer::Adapter` with the `AdapterReason` proving it \
         wraps no source local, `Producer::Recognizer` when it only matches a printed \
         head.\nunexpected (site, count): {unexpected:?}\nstale rows (site, \
         count): {stale:?}"
    );
    Ok(())
}

/// The IR nodes a [`Form`] prints, each with the kind `boundary_kind` must
/// give it.
fn exemplars(form: Form) -> Result<Vec<(Expr, ClosureKind)>, String> {
    let mut interner = ipe_intern::Interner::new();
    let x = interner.intern("x").map_err(|e| format!("{e:?}"))?;
    let params = vec![(x, IrType::Int)];
    let body = Box::new(Expr::Var(x));
    Ok(match form {
        Form::Closure => vec![
            (
                Expr::Lambda {
                    params: params.clone(),
                    ret: IrType::Int,
                    body: body.clone(),
                },
                ClosureKind::Recallable,
            ),
            (
                Expr::SharedLambda {
                    params: params.clone(),
                    ret: IrType::Int,
                    body: body.clone(),
                },
                ClosureKind::Recallable,
            ),
            (
                Expr::OnceLambda {
                    params,
                    ret: IrType::Int,
                    body,
                    capture: MovedCapture {
                        name: x,
                        lo: 0,
                        hi: 1,
                    },
                },
                ClosureKind::Once,
            ),
        ],
        Form::TaskSeqRest => vec![(
            Expr::TaskSeq {
                effect: Box::new(Expr::Unit),
                rest: Box::new(Expr::Unit),
            },
            ClosureKind::Once,
        )],
    })
}

/// Each boundary row's form reads the kind `boundary_kind` gives its IR
/// nodes, and every form has a printer row.
#[test]
fn each_boundary_row_agrees_with_boundary_kind() -> Result<(), String> {
    for form in FORMS {
        let nodes = exemplars(form)?;
        assert!(!nodes.is_empty(), "{form:?} names no IR node");
        for (node, kind) in nodes {
            assert_eq!(boundary_kind(&node), Some(kind), "{form:?}: {node:?}");
        }
        assert!(
            INVENTORY
                .iter()
                .any(|&(.., producer)| producer == Producer::Boundary(form)),
            "{form:?} has no printer row"
        );
    }
    Ok(())
}

/// The `TaskSeq` continuation is a once closure, so its runtime slot takes a
/// closure that moves a capture out; this compiles only while it does.
#[test]
fn a_task_seq_continuation_slot_takes_a_capture_moving_closure() {
    let owned = String::from("rest");
    let task = ipe_runtime_rust::task_and_then(
        ipe_runtime_rust::task_succeed::<String, ()>(()),
        Box::new(move |()| {
            drop(owned);
            ipe_runtime_rust::task_succeed(())
        }),
    );
    drop(task);
}

/// The producers of a synthetic source, as `(fn, count)`.
fn synthetic(src: &str) -> Result<Vec<(String, usize)>, String> {
    Ok(scan_source("synthetic.rs", src)?
        .hits
        .into_iter()
        .map(|((_, func), count)| (func, count))
        .collect())
}

/// Each spelling of a printed closure head is counted at its fn.
#[test]
fn each_printed_closure_head_is_counted() -> Result<(), String> {
    let cases: [(&str, usize); 7] = [
        (
            r#"fn emit(b: &str) -> String { format!("Box::new(move || {b})") }"#,
            1,
        ),
        (
            r#"fn emit() -> Doc { Doc::text(leaf!("Box::new(move |_| ")) }"#,
            1,
        ),
        (
            r#"fn emit(o: &mut String) { o.push_str(", Box::new(move |_| { "); }"#,
            1,
        ),
        (
            "fn emit() -> &'static str { \"Box::new(move \\\n    |_| x)\" }",
            1,
        ),
        (
            r#"fn emit(a: &str) -> String { format!("move |e| (move || {a})()") }"#,
            2,
        ),
        (
            r#"fn emit(o: &mut String) { o.push_str("Box::new(move "); o.push_str("|_| x)"); }"#,
            1,
        ),
        (
            r#"fn emit(p: &str) -> String { format!("Box::new(move {p} x)") }"#,
            1,
        ),
    ];
    for (src, count) in cases {
        assert_eq!(synthetic(src)?, vec![("emit".to_owned(), count)], "{src}");
    }
    Ok(())
}

/// One step past each spelling: a closure the emitter itself runs, a word
/// ending or starting with `move`, a `move` not opening a closure, comments
/// and test-only code print no closure head.
#[test]
fn text_that_prints_no_closure_head_is_not_counted() -> Result<(), String> {
    for src in [
        r"fn ok(v: Vec<u8>) -> Vec<u8> { v.into_iter().map(move |b| b).collect() }",
        r#"fn ok() -> &'static str { "remove |x|" }"#,
        r#"fn ok() -> &'static str { "moved |x|" }"#,
        r#"fn ok() -> &'static str { "move x |" }"#,
        r#"fn ok() -> String { format!("async move {{ x }}") }"#,
        "fn ok() {} // \"move |x|\"",
        r#"#[cfg(test)] mod tests { fn t() -> &'static str { "move |x| x" } }"#,
        r#"#[test] fn t() { let _ = "move || 1"; }"#,
    ] {
        assert_eq!(synthetic(src)?, vec![], "{src}");
    }
    Ok(())
}

/// A producer with no row is unexpected, and a row with no producer is stale.
#[test]
fn a_producer_without_a_row_and_a_row_without_a_producer_both_drift() -> Result<(), String> {
    let found = scan_source(
        "emit_expr/new.rs",
        r#"fn emit_new(b: &str) -> String { format!("Box::new(move || {b})") }"#,
    )?;
    let gone = [(
        "emit_expr/old.rs",
        "emit_old",
        1,
        Producer::Adapter(AdapterReason::RuntimeValue, &[]),
    )];
    let (unexpected, stale) = drift(&found.hits, &gone);
    let new_site = ("emit_expr/new.rs".to_owned(), "emit_new".to_owned());
    let old_site = ("emit_expr/old.rs".to_owned(), "emit_old".to_owned());
    assert_eq!(unexpected, vec![(new_site.clone(), 1)]);
    assert_eq!(stale, vec![(old_site, 1)]);
    let recount = [(
        "emit_expr/new.rs",
        "emit_new",
        2,
        Producer::Adapter(AdapterReason::RuntimeValue, &[]),
    )];
    let (unexpected, stale) = drift(&found.hits, &recount);
    assert_eq!(unexpected, vec![(new_site.clone(), 1)]);
    assert_eq!(stale, vec![(new_site, 2)]);
    Ok(())
}

/// An adapted-slot re-wrap of emitted handler text in `kernel_calls.rs` has no row.
#[test]
fn a_kernel_call_rewrap_of_emitted_handler_text_drifts() -> Result<(), String> {
    let found = scan_source(
        "emit_expr/kernel_calls.rs",
        r#"fn emit_ui_plan(h: &str) -> String { format!("ui_on_key_down_(::std::sync::Arc::new(move |_x| ({h})(_x)))") }"#,
    )?;
    let (unexpected, stale) = drift(&found.hits, INVENTORY);
    let site = (
        "emit_expr/kernel_calls.rs".to_owned(),
        "emit_ui_plan".to_owned(),
    );
    assert!(
        unexpected.contains(&(site, 1)),
        "unexpected: {unexpected:?}"
    );
    assert!(
        !stale.is_empty(),
        "the real rows are absent from the synthetic scan"
    );
    Ok(())
}
