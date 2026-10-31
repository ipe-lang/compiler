//! `JsonVal` depth safety: every walk over a JSON value runs in constant stack,
//! and the crossings into `serde_json`'s recursive walks are refused past one
//! backstop.
//!
//! The depth tests run on a spawned 256 KiB thread, so a walk that recurses
//! once per nesting level overflows here rather than in production. The source
//! scan refuses a production fn outside `json_val.rs` that matches on
//! `JsonVal::Array` / `JsonVal::Object` and calls itself. The site inventory
//! lists every production fn that reaches a value's children exactly once in
//! `ALLOWED_SITES`, with how that fn bounds its stack.
#![cfg(feature = "json")]
#![cfg(not(target_arch = "wasm32"))]

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{DefaultHasher, Hash, Hasher};

use ipe_runtime_rust::RetainedBytes;
use ipe_runtime_rust::json::{json_enc_canonical, json_enc_encode, json_enc_int, json_enc_object};
use ipe_runtime_rust::json_val::{
    BACKSTOP_REFUSAL, JSON_SERDE_NESTING_BACKSTOP, JsonMap, JsonVal, SERDE_CONTAINER_FLOOR,
    json_depth,
};
use proc_macro2::{Ident, Spacing, TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{
    Arm, Expr, ExprCall, ExprMethodCall, ExprPath, ImplItem, ImplItemConst, ImplItemFn, Item,
    ItemConst, ItemFn, ItemImpl, ItemMacro, ItemMod, ItemStatic, ItemTrait, ItemType, ItemUse,
    Macro, PatStruct, PatTupleStruct, Path, QSelf, ReturnType, Stmt, TraitItemConst, TraitItemFn,
    Type, UseGlob, UsePath, UseRename, UseTree,
};

#[path = "support/cfg_scan.rs"]
mod cfg_scan;
use cfg_scan::{cfg_test_only, expr_attrs, impl_item_attrs, item_attrs, trait_item_attrs};

#[path = "support/source_tree.rs"]
mod source_tree;
use source_tree::rust_sources;

/// The stack every depth test runs on.
const SMALL_STACK: usize = 256 * 1024;

/// Runs `body` on a fresh thread with `stack` bytes of stack and waits for it.
fn on_stack(stack: usize, body: impl FnOnce() + Send + 'static) {
    let finished = std::thread::Builder::new()
        .stack_size(stack)
        .spawn(body)
        .map(|handle| handle.join().is_ok());
    assert!(
        matches!(finished, Ok(true)),
        "the depth-test thread failed to spawn or to finish"
    );
}

/// `depth` nested arrays around an empty one: `json_depth` is `depth`.
fn deep_list(depth: usize) -> JsonVal {
    let mut value = JsonVal::Array(Vec::new());
    for _ in 1..depth {
        value = JsonVal::Array(vec![value]);
    }
    value
}

/// `depth` nested single-key objects around a scalar.
fn deep_object(depth: usize) -> JsonVal {
    let mut value = JsonVal::Null;
    for at in 0..depth {
        let mut map = JsonMap::new();
        map.insert(format!("k{}", at % 3), value);
        value = JsonVal::Object(map);
    }
    value
}

/// `depth` nested flow arrays as text, readable as JSON and as YAML.
fn flow(depth: usize) -> String {
    format!("{}{}", "[".repeat(depth), "]".repeat(depth))
}

fn hash_of(value: &JsonVal) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[test]
fn deep_list_encodes_without_overflow() {
    on_stack(SMALL_STACK, || {
        let encoded = json_enc_encode(0, deep_list(1_000_000));
        assert_eq!(encoded.len(), 2_000_000);
        assert!(encoded.starts_with("[["));
        assert!(encoded.ends_with("]]"));
    });
}

#[test]
fn deep_value_drops_without_overflow() {
    on_stack(SMALL_STACK, || {
        drop(deep_list(1_000_000));
        drop(deep_object(100_000));
    });
}

#[test]
fn deep_value_clone_eq_hash_debug_display() {
    on_stack(SMALL_STACK, || {
        let value = deep_list(100_000);
        let copy = value.clone();
        assert_eq!(json_depth(&copy), 100_000);
        assert!(value == copy);
        assert_eq!(hash_of(&value), hash_of(&copy));
        assert!(format!("{value:?}").starts_with("Array ["));
        assert_eq!(value.to_string().len(), 200_000);
        let object = deep_object(100_000);
        assert!(object.clone() == object);
        assert_eq!(hash_of(&object.clone()), hash_of(&object));
    });
}

/// The depth the pretty layouts are walked at. Pretty text grows with the
/// square of the depth ([`pretty_list_len`]), so this stays shallow enough to
/// print about 8 MB, on a 64 KiB stack where a writer recursing once per level
/// would need frames under 32 bytes to survive.
const PRETTY_DEPTH: usize = 2_048;

/// The length of `deep_list(depth)` in the pretty layout `width` spaces wide:
/// two brackets a level, and every non-empty level breaks a line before its
/// child, one unit deeper, and before its own `]`.
const fn pretty_list_len(depth: usize, width: usize) -> usize {
    2 * depth + 2 * (depth - 1) + width * (depth - 1) * (depth - 1)
}

#[test]
fn deep_value_pretty_display_and_encode() {
    on_stack(SMALL_STACK / 4, || {
        let value = deep_list(PRETTY_DEPTH);
        let shown = format!("{value:#}");
        assert!(shown.starts_with("[\n  [\n    ["));
        assert_eq!(shown.len(), pretty_list_len(PRETTY_DEPTH, 2));
        let encoded = json_enc_encode(2, value);
        assert!(
            encoded == shown,
            "pretty encode differs from pretty display"
        );
    });
}

#[test]
fn deep_value_canonical() {
    const DEPTH: usize = 100_000;
    on_stack(SMALL_STACK, || {
        let canonical = json_enc_canonical(&deep_object(DEPTH));
        let mut expected: String = (0..DEPTH)
            .rev()
            .map(|at| format!("{{\"k{}\":", at % 3))
            .collect();
        expected.push_str("null");
        expected.push_str(&"}".repeat(DEPTH));
        assert!(canonical == expected, "canonical text differs");
    });
}

#[test]
fn serde_serialize_refuses_past_backstop() {
    on_stack(SMALL_STACK * 4, || {
        let at = deep_list(JSON_SERDE_NESTING_BACKSTOP);
        assert!(serde_json::to_string(&at).is_ok());
        assert!(at.to_serde().is_ok());
        let past = deep_list(JSON_SERDE_NESTING_BACKSTOP + 1);
        let refused = serde_json::to_string(&past);
        assert!(
            refused
                .as_ref()
                .is_err_and(|error| error.to_string().contains(BACKSTOP_REFUSAL)),
            "{refused:?}"
        );
        let refused = past.to_serde();
        assert!(
            refused
                .as_ref()
                .is_err_and(|refusal| refusal.message() == BACKSTOP_REFUSAL),
            "{refused:?}"
        );
    });
}

#[cfg(feature = "config")]
#[test]
fn serde_deserialize_refuses_past_backstop() {
    fn parse(source: &str) -> Result<JsonVal, String> {
        let mut budget = serde_saphyr::Budget::default();
        budget.max_depth = JSON_SERDE_NESTING_BACKSTOP + 8;
        budget.flow_nesting_limit = JSON_SERDE_NESTING_BACKSTOP + 8;
        budget.max_documents = 1;
        let mut options = serde_saphyr::Options::default();
        options.budget = Some(budget);
        serde_saphyr::from_str_with_options::<JsonVal>(source, options)
            .map_err(|error| error.to_string())
    }
    on_stack(8 * 1024 * 1024, || {
        let at = parse(&flow(JSON_SERDE_NESTING_BACKSTOP));
        assert!(
            at.as_ref()
                .is_ok_and(|value| json_depth(value) == JSON_SERDE_NESTING_BACKSTOP),
            "{at:?}"
        );
        let past = parse(&flow(JSON_SERDE_NESTING_BACKSTOP + 1));
        assert!(
            past.as_ref()
                .is_err_and(|error| error.contains(BACKSTOP_REFUSAL)),
            "{past:?}"
        );
    });
}

/// `serde_json`'s own recursion limit refuses a document before the backstop
/// can: [`SERDE_CONTAINER_FLOOR`] containers parse, one more does not.
#[test]
fn serde_json_parse_stops_at_its_floor() {
    on_stack(SMALL_STACK * 4, || {
        let at = serde_json::from_str::<JsonVal>(&flow(SERDE_CONTAINER_FLOOR));
        assert!(
            at.as_ref()
                .is_ok_and(|value| json_depth(value) == SERDE_CONTAINER_FLOOR),
            "{at:?}"
        );
        let past = serde_json::from_str::<JsonVal>(&flow(SERDE_CONTAINER_FLOOR + 1));
        assert!(
            past.as_ref()
                .is_err_and(|error| error.to_string().contains("recursion limit exceeded")),
            "{past:?}"
        );
    });
}

/// A TOML document whose `json_depth` is `1 + header + (dotted - 1) + inline + 1`.
#[cfg(feature = "config")]
fn composed_toml(header: usize, dotted: usize, inline: usize) -> String {
    let header = vec!["h"; header].join(".");
    let dotted = vec!["d"; dotted].join(".");
    let open = "{ i = ".repeat(inline);
    let close = " }".repeat(inline);
    format!("[{header}]\n{dotted} = {open}1{close}\n")
}

#[cfg(feature = "config")]
#[test]
fn toml_nesting_past_backstop_is_refused() {
    use ipe_runtime_rust::config_decode::config_decode_toml;
    use ipe_runtime_rust::json::decode_value_identity;
    on_stack(1024 * 1024, || {
        let decode = |source: String| {
            config_decode_toml::<String, JsonVal>(source, decode_value_identity::<String>())
        };
        let past = composed_toml(100, 100, 56);
        assert!(
            matches!(decode(past), ipe_runtime_rust::IpeResult::Err(_)),
            "a TOML document 257 deep must be refused"
        );
        let within = composed_toml(70, 70, 59);
        assert!(
            matches!(
                decode(within),
                ipe_runtime_rust::IpeResult::Ok(ref value) if json_depth(value) == 200
            ),
            "a TOML document 200 deep must decode"
        );
    });
}

#[test]
fn deep_value_measures_retained_bytes_without_overflow() {
    on_stack(SMALL_STACK, || {
        assert!(deep_list(1_000_000).retained_bytes().is_some());
        assert!(deep_object(100_000).retained_bytes().is_some());
    });
}

#[test]
fn object_order_is_insertion_order_in_every_model() {
    let object = json_enc_object(vec![
        ("b".to_owned(), json_enc_int(1)),
        ("a".to_owned(), json_enc_int(2)),
    ]);
    assert_eq!(object.to_string(), r#"{"b":1,"a":2}"#);
    let encoded = json_enc_encode(0, object);
    assert_eq!(encoded, r#"{"b":1,"a":2}"#);
    let parsed: JsonVal = serde_json::from_str(&encoded).expect("parse the encoded object");
    assert_eq!(parsed.to_string(), r#"{"b":1,"a":2}"#);
    assert_eq!(json_enc_encode(0, parsed), r#"{"b":1,"a":2}"#);
}

#[test]
fn object_eq_and_hash_ignore_order() {
    let forward = json_enc_object(vec![
        ("a".to_owned(), json_enc_int(1)),
        ("b".to_owned(), json_enc_int(2)),
    ]);
    let backward = json_enc_object(vec![
        ("b".to_owned(), json_enc_int(2)),
        ("a".to_owned(), json_enc_int(1)),
    ]);
    assert!(forward == backward);
    assert_eq!(hash_of(&forward), hash_of(&backward));
    let other = json_enc_object(vec![("a".to_owned(), json_enc_int(2))]);
    assert!(forward != other);
}

// ---------------------------------------------------------------------------
// Source scan: no recursive walk over `JsonVal` outside `json_val.rs`.
// ---------------------------------------------------------------------------

/// One fn being scanned: its name, whether its body names a `JsonVal`
/// container variant, and whether it calls itself.
struct Frame {
    name: String,
    matches_container: bool,
    calls_itself: bool,
}

/// Every production fn of one file that recurses over a `JsonVal` container.
#[derive(Default)]
struct RecursionScan {
    frames: Vec<Frame>,
    found: Vec<String>,
}

impl RecursionScan {
    fn enter(&mut self, name: String) {
        self.frames.push(Frame {
            name,
            matches_container: false,
            calls_itself: false,
        });
    }

    fn leave(&mut self) {
        if let Some(frame) = self.frames.pop()
            && frame.matches_container
            && frame.calls_itself
        {
            self.found.push(frame.name);
        }
    }

    fn called(&mut self, name: &str) {
        if let Some(frame) = self.frames.last_mut()
            && frame.name == name
        {
            frame.calls_itself = true;
        }
    }
}

impl<'ast> Visit<'ast> for RecursionScan {
    fn visit_item(&mut self, item: &'ast Item) {
        if !cfg_test_only(item_attrs(item)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.enter(item.sig.ident.to_string());
        visit::visit_item_fn(self, item);
        self.leave();
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        if !cfg_test_only(impl_item_attrs(item)) {
            visit::visit_impl_item(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.enter(item.sig.ident.to_string());
        visit::visit_impl_item_fn(self, item);
        self.leave();
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        if cfg_test_only(trait_item_attrs(item)) {
            return;
        }
        if let syn::TraitItem::Fn(method) = item {
            self.enter(method.sig.ident.to_string());
            visit::visit_trait_item(self, item);
            self.leave();
        } else {
            visit::visit_trait_item(self, item);
        }
    }

    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        let attrs: &[syn::Attribute] = match stmt {
            Stmt::Local(local) => &local.attrs,
            Stmt::Macro(mac) => &mac.attrs,
            Stmt::Item(_) | Stmt::Expr(..) => &[],
        };
        if !cfg_test_only(attrs) {
            visit::visit_stmt(self, stmt);
        }
    }

    fn visit_arm(&mut self, arm: &'ast Arm) {
        if !cfg_test_only(&arm.attrs) {
            visit::visit_arm(self, arm);
        }
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        if !cfg_test_only(expr_attrs(expr)) {
            visit::visit_expr(self, expr);
        }
    }

    fn visit_path(&mut self, path: &'ast Path) {
        let names: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        let container = names
            .windows(2)
            .any(|pair| matches!(pair, [ty, variant] if ty == "JsonVal" && (variant == "Array" || variant == "Object")));
        if container && let Some(frame) = self.frames.last_mut() {
            frame.matches_container = true;
        }
        visit::visit_path(self, path);
    }

    fn visit_use_rename(&mut self, rename: &'ast UseRename) {
        if rename.ident == "JsonVal" {
            self.found.push(format!("use JsonVal as {}", rename.rename));
        }
        visit::visit_use_rename(self, rename);
    }

    fn visit_use_path(&mut self, path: &'ast UsePath) {
        if path.ident == "JsonVal"
            && matches!(path.tree.as_ref(), syn::UseTree::Glob(UseGlob { .. }))
        {
            self.found.push("use JsonVal::*".to_owned());
        }
        visit::visit_use_path(self, path);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(callee) = call.func.as_ref()
            && let Some(last) = callee.path.segments.last()
        {
            self.called(&last.ident.to_string());
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        self.called(&call.method.to_string());
        visit::visit_expr_method_call(self, call);
    }
}

/// Every production fn in `src` that matches a `JsonVal` container and calls
/// itself; a source that does not parse fails.
fn recursive_json_walks(name: &str, src: &str) -> Vec<String> {
    let parsed = syn::parse_file(src);
    assert!(
        parsed.is_ok(),
        "{name}: does not parse as Rust, so it cannot be proven free of recursive JSON walks: {:?}",
        parsed.as_ref().err().map(ToString::to_string)
    );
    let mut scan = RecursionScan::default();
    if let Ok(file) = &parsed {
        scan.visit_file(file);
    }
    scan.found
}

#[test]
fn a_recursive_walk_by_name_is_caught() {
    let src = r"
fn walk(value: &JsonVal) -> usize {
    match value {
        JsonVal::Array(items) => items.iter().map(walk).sum::<usize>() + walk(&items[0]),
        _ => 1,
    }
}
";
    assert_eq!(recursive_json_walks("fixture", src), vec!["walk"]);
}

#[test]
fn a_recursive_walk_through_self_path_is_caught() {
    let src = r"
impl Walker {
    fn walk(value: &JsonVal) -> usize {
        if let crate::json::JsonVal::Object(map) = value {
            return map.values().map(|v| Self::walk(v)).sum();
        }
        1
    }
}
";
    assert_eq!(recursive_json_walks("fixture", src), vec!["walk"]);
}

#[test]
fn a_recursive_walk_through_a_method_is_caught() {
    let src = r"
trait Depth {
    fn depth(&self) -> usize {
        match self.as_json() {
            JsonVal::Array(items) => 1 + items.iter().map(|i| i.depth()).max().unwrap_or(0),
            _ => 1,
        }
    }
}
";
    assert_eq!(recursive_json_walks("fixture", src), vec!["depth"]);
}

/// A renamed or glob-imported `JsonVal` would hide its variants from the path
/// match, so the import itself is refused.
#[test]
fn renaming_or_glob_importing_json_val_is_caught() {
    let src = "use crate::json::JsonVal as V;\nuse crate::json::{JsonVal as W};\nuse crate::json::JsonVal::*;\n";
    assert_eq!(
        recursive_json_walks("fixture", src),
        vec!["use JsonVal as V", "use JsonVal as W", "use JsonVal::*"]
    );
}

#[test]
fn a_cfg_test_walk_is_dropped_and_an_iterative_walk_is_clean() {
    let src = r"
#[cfg(test)]
fn walk(value: &JsonVal) -> usize {
    match value {
        JsonVal::Array(items) => items.iter().map(walk).sum(),
        _ => 1,
    }
}
fn count(root: &JsonVal) -> usize {
    let mut stack = vec![root];
    let mut seen = 0;
    while let Some(node) = stack.pop() {
        seen += 1;
        if let JsonVal::Array(items) = node {
            stack.extend(items.iter());
        }
    }
    seen
}
fn recurse_without_json(n: u32) -> u32 { if n == 0 { 0 } else { recurse_without_json(n - 1) } }
";
    assert_eq!(recursive_json_walks("fixture", src), Vec::<String>::new());
}

#[test]
#[should_panic(expected = "does not parse as Rust")]
fn a_source_that_does_not_parse_fails_the_recursion_scan() {
    let _ = recursive_json_walks("fixture", "fn walk( { JsonVal::Array(v) }");
}

/// No runtime source outside `json_val.rs` walks a `JsonVal` recursively.
#[test]
fn no_runtime_source_walks_a_json_value_recursively() {
    let root = e2e_support::manifest_dir!().join("src");
    let sources = rust_sources(&root);
    for required in ["json.rs", "json_val.rs", "seal_codec.rs", "jwt.rs", "db.rs"] {
        assert!(
            sources.iter().any(|(name, _)| name == required),
            "the source walk did not read {required}"
        );
    }
    let violations: Vec<String> = sources
        .iter()
        .filter(|(name, _)| name != "json_val.rs")
        .flat_map(|(name, src)| {
            recursive_json_walks(name, src)
                .into_iter()
                .map(move |walk| format!("{name}: {walk}"))
        })
        .collect();
    assert!(
        violations.is_empty(),
        "a recursive walk over `JsonVal` overflows the stack on deep input; \
         walk it with an explicit worklist in `json_val.rs`:\n{}",
        violations.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Site inventory: every production fn that reaches a `JsonVal`'s children.
// ---------------------------------------------------------------------------

/// `JsonVal` methods that hand out a child or the child collection.
const CHILD_ACCESSORS: [&str; 9] = [
    "as_array",
    "as_array_mut",
    "as_object",
    "as_object_mut",
    "into_array",
    "into_object",
    "node",
    "index_into",
    "index_into_mut",
];

/// `JsonVal` child lookups whose names other maps share: a call counts only in
/// a fn that also names a JSON type.
const SHARED_NAME_ACCESSORS: [&str; 2] = ["get", "get_mut"];

/// `JsonVal` methods whose JSON-typed result is the root itself, never a child.
const ROOT_RETURNING: [&str; 2] = ["from_serde", "take"];

const CONTAINER_VARIANTS: [&str; 2] = ["Array", "Object"];

/// The trait whose methods index into a value on behalf of `get`.
const INDEX_TRAIT: &str = "JsonIndex";

/// Return-type names that mark an accessor as handing out JSON.
const JSON_RETURN_NAMES: [&str; 5] = ["Self", "JsonVal", "JsonMap", "Node", "Vec"];

/// Most passes the alias learning takes before it must have settled.
const MAX_ALIAS_ROUNDS: usize = 16;

/// The key of whatever a file reaches outside any fn, const, static or macro.
const FILE_ITEMS: &str = "<file items>";

/// How an allowed site bounds its stack against an input-chosen depth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stack {
    /// Walks every level with an explicit heap worklist.
    Worklist,
    /// Reads one level of children and never descends.
    OneLevel,
    /// Recurses once per level, only after the root passed the
    /// `JSON_SERDE_NESTING_BACKSTOP` depth check.
    Depth256,
    /// Names its own fn only to call the same-named method on another type
    /// (a scalar child, the inner index); its own walk is one level or a
    /// worklist.
    Delegates,
}

/// Every production fn that reaches a `JsonVal`'s children, as (file, site,
/// how it bounds its stack, why).
const ALLOWED_SITES: &[(&str, &str, Stack, &str)] = &[
    (
        "config_decode.rs",
        "config_dict",
        Stack::OneLevel,
        "reads one decoded object's entries",
    ),
    (
        "db.rs",
        "db_decode_nullable",
        Stack::OneLevel,
        "looks up one column of a row",
    ),
    (
        "db.rs",
        "db_decode_optional",
        Stack::OneLevel,
        "looks up one column of a row",
    ),
    (
        "email.rs",
        "json_obj_set",
        Stack::OneLevel,
        "sets one key of a request object",
    ),
    (
        "email.rs",
        "send_ses",
        Stack::OneLevel,
        "reads one level of the provider reply",
    ),
    (
        "js_port.rs",
        "classify_inbound",
        Stack::OneLevel,
        "reads one frame's reserved fields",
    ),
    (
        "js_port.rs",
        "native::deliver_session_frame",
        Stack::OneLevel,
        "looks up one session stream",
    ),
    (
        "js_port.rs",
        "native::deliver_session_terminal",
        Stack::OneLevel,
        "looks up one session stream",
    ),
    (
        "js_port.rs",
        "native::request_with_mint",
        Stack::OneLevel,
        "reads one reply's fields",
    ),
    (
        "js_port.rs",
        "native::js_open_session",
        Stack::OneLevel,
        "reads one reply's fields",
    ),
    (
        "js_port.rs",
        "native::js_send_to_session",
        Stack::OneLevel,
        "looks up one session stream",
    ),
    (
        "js_port.rs",
        "native::js_close_session",
        Stack::OneLevel,
        "reads one reply's fields",
    ),
    (
        "js_port.rs",
        "wasm::deliver_session_frame",
        Stack::OneLevel,
        "looks up one session stream",
    ),
    (
        "js_port.rs",
        "wasm::js_close_session",
        Stack::OneLevel,
        "reads one reply's fields",
    ),
    (
        "json.rs",
        "<JsonVal as RetainedBytes>::retained_bytes",
        Stack::Worklist,
        "measures every node from a heap stack",
    ),
    (
        "json.rs",
        "decode_index",
        Stack::OneLevel,
        "reads one array slot; nesting is the decoder's, which the program bounds",
    ),
    (
        "json.rs",
        "decode_list",
        Stack::OneLevel,
        "reads one array's items; nesting is the decoder's, which the program bounds",
    ),
    (
        "json.rs",
        "decode_key_value_pairs",
        Stack::OneLevel,
        "reads one object's entries; nesting is the decoder's, which the program bounds",
    ),
    (
        "json.rs",
        "decode_pipeline_required_at",
        Stack::OneLevel,
        "follows a field path the program spells",
    ),
    (
        "json_val.rs",
        "<JsonVal as Drop>::drop",
        Stack::Worklist,
        "moves children onto a heap stack before freeing",
    ),
    (
        "json_val.rs",
        "JsonVal::node",
        Stack::OneLevel,
        "classifies one node",
    ),
    (
        "json_val.rs",
        "JsonVal::get",
        Stack::OneLevel,
        "indexes one level through `JsonIndex`",
    ),
    (
        "json_val.rs",
        "JsonVal::get_mut",
        Stack::OneLevel,
        "indexes one level through `JsonIndex`",
    ),
    (
        "json_val.rs",
        "JsonVal::is_array",
        Stack::OneLevel,
        "tests one node's variant",
    ),
    (
        "json_val.rs",
        "JsonVal::is_object",
        Stack::OneLevel,
        "tests one node's variant",
    ),
    (
        "json_val.rs",
        "JsonVal::as_array",
        Stack::OneLevel,
        "borrows one node's items",
    ),
    (
        "json_val.rs",
        "JsonVal::as_array_mut",
        Stack::OneLevel,
        "borrows one node's items",
    ),
    (
        "json_val.rs",
        "JsonVal::as_object",
        Stack::OneLevel,
        "borrows one node's entries",
    ),
    (
        "json_val.rs",
        "JsonVal::as_object_mut",
        Stack::OneLevel,
        "borrows one node's entries",
    ),
    (
        "json_val.rs",
        "JsonVal::into_array",
        Stack::OneLevel,
        "moves out one node's items",
    ),
    (
        "json_val.rs",
        "JsonVal::into_object",
        Stack::OneLevel,
        "moves out one node's entries",
    ),
    (
        "json_val.rs",
        "<usize as JsonIndex>::index_into",
        Stack::OneLevel,
        "reads one array slot",
    ),
    (
        "json_val.rs",
        "<usize as JsonIndex>::index_into_mut",
        Stack::OneLevel,
        "reads one array slot",
    ),
    (
        "json_val.rs",
        "<str as JsonIndex>::index_into",
        Stack::OneLevel,
        "reads one object key",
    ),
    (
        "json_val.rs",
        "<str as JsonIndex>::index_into_mut",
        Stack::OneLevel,
        "reads one object key",
    ),
    (
        "json_val.rs",
        "<String as JsonIndex>::index_into",
        Stack::Delegates,
        "forwards to the `str` index once",
    ),
    (
        "json_val.rs",
        "<String as JsonIndex>::index_into_mut",
        Stack::Delegates,
        "forwards to the `str` index once",
    ),
    (
        "json_val.rs",
        "<T as JsonIndex>::index_into",
        Stack::Delegates,
        "forwards to the referenced index once",
    ),
    (
        "json_val.rs",
        "<T as JsonIndex>::index_into_mut",
        Stack::Delegates,
        "forwards to the referenced index once",
    ),
    (
        "json_val.rs",
        "json_depth",
        Stack::Worklist,
        "measures depth from a heap stack",
    ),
    (
        "json_val.rs",
        "Frame::open",
        Stack::Worklist,
        "opens one frame of the post-order rebuild worklist",
    ),
    (
        "json_val.rs",
        "<JsonVal as PartialEq>::eq",
        Stack::Worklist,
        "compares node pairs from a heap stack",
    ),
    (
        "json_val.rs",
        "<JsonVal as Hash>::hash",
        Stack::Delegates,
        "hashes nodes from a heap stack; `hash` on a scalar child is not JSON",
    ),
    (
        "json_val.rs",
        "<JsonVal as Debug>::fmt",
        Stack::Worklist,
        "writes from a heap stack of open containers",
    ),
    (
        "json_val.rs",
        "write_json",
        Stack::Worklist,
        "writes from a heap stack of open containers",
    ),
    (
        "json_val.rs",
        "<Checked as Serialize>::serialize",
        Stack::Depth256,
        "serde recursion entered only below the backstop",
    ),
    (
        "jwt.rs",
        "read_numeric_date",
        Stack::OneLevel,
        "reads one claim",
    ),
    (
        "jwt.rs",
        "claims_set",
        Stack::OneLevel,
        "reads one claims object's entries",
    ),
    (
        "native_bridge.rs",
        "wire::parse_reply",
        Stack::OneLevel,
        "reads one reply's fields after serde's own nesting limit",
    ),
    (
        "web/additive.rs",
        "merge_additive",
        Stack::OneLevel,
        "merges one object's top-level entries",
    ),
    (
        "web/mod.rs",
        "handlers::event_handler",
        Stack::OneLevel,
        "reads one event payload's fields",
    ),
    (
        "web/mod.rs",
        "handlers::ScrubTarget::parse",
        Stack::OneLevel,
        "reads one target object's fields",
    ),
    (
        "web/transition.rs",
        "try_apply",
        Stack::OneLevel,
        "reads one transition object's fields",
    ),
    (
        "webview.rs",
        "imp::parse_ipc",
        Stack::OneLevel,
        "reads one IPC message's fields",
    ),
];

/// The (file, site) pairs `ALLOWED_SITES` lists.
fn allowed_sites() -> Vec<(&'static str, &'static str)> {
    ALLOWED_SITES
        .iter()
        .map(|&(file, site, _, _)| (file, site))
        .collect()
}

/// The (file, site) pairs `ALLOWED_SITES` permits to name their own fn.
fn recursion_tags() -> Vec<(&'static str, &'static str)> {
    ALLOWED_SITES
        .iter()
        .filter(|(_, _, stack, _)| matches!(stack, Stack::Depth256 | Stack::Delegates))
        .map(|&(file, site, _, _)| (file, site))
        .collect()
}

/// The last name a type spells, through references, groups and parentheses.
fn type_name(mut ty: &Type) -> Option<String> {
    loop {
        match ty {
            Type::Path(path) => return path.path.segments.last().map(|s| s.ident.to_string()),
            Type::Reference(reference) => ty = &reference.elem,
            Type::Group(group) => ty = &group.elem,
            Type::Paren(paren) => ty = &paren.elem,
            _ => return None,
        }
    }
}

/// The names that spell a JSON type or a container variant across the scanned
/// sources.
struct JsonNames {
    /// `JsonVal` and every alias of it.
    value: BTreeSet<String>,
    /// `value`, `JsonMap`, and every alias of `JsonMap`.
    json: BTreeSet<String>,
    /// Container variants imported bare, under their own name or a rename.
    variants: BTreeSet<String>,
}

impl JsonNames {
    /// Learns every `type` alias, `use … as` rename and variant import of
    /// `files`, repeating until a pass learns nothing new.
    fn learn(files: &[(&str, syn::File)]) -> Self {
        let mut names = Self {
            value: BTreeSet::from(["JsonVal".to_owned()]),
            json: BTreeSet::from(["JsonVal".to_owned(), "JsonMap".to_owned()]),
            variants: BTreeSet::new(),
        };
        let mut settled = false;
        for _ in 0..MAX_ALIAS_ROUNDS {
            let before = names.sizes();
            for (_, file) in files {
                let mut learner = NameLearner { names: &mut names };
                learner.visit_file(file);
            }
            if names.sizes() == before {
                settled = true;
                break;
            }
        }
        assert!(
            settled,
            "the JSON aliases did not settle within {MAX_ALIAS_ROUNDS} passes"
        );
        names
    }

    fn sizes(&self) -> (usize, usize, usize) {
        (self.value.len(), self.json.len(), self.variants.len())
    }

    /// Records `alias` as another name for `target` when `target` is a JSON type.
    fn learn_alias(&mut self, target: &str, alias: String) {
        if self.value.contains(target) {
            self.value.insert(alias.clone());
        }
        if self.json.contains(target) {
            self.json.insert(alias);
        }
    }

    fn owns_variant(&self, parent: Option<&str>, leaf: &str) -> bool {
        CONTAINER_VARIANTS.contains(&leaf) && parent.is_some_and(|p| self.value.contains(p))
    }

    fn learn_use(&mut self, tree: &UseTree, parent: Option<&str>) {
        match tree {
            UseTree::Path(path) => {
                let ident = path.ident.to_string();
                self.learn_use(&path.tree, Some(&ident));
            }
            UseTree::Name(name) => {
                let leaf = name.ident.to_string();
                if self.owns_variant(parent, &leaf) {
                    self.variants.insert(leaf);
                }
            }
            UseTree::Rename(rename) => {
                let alias = rename.rename.to_string();
                if rename.ident == "self" {
                    if let Some(parent) = parent {
                        self.learn_alias(parent, alias);
                    }
                } else {
                    let leaf = rename.ident.to_string();
                    if self.owns_variant(parent, &leaf) {
                        self.variants.insert(alias.clone());
                    }
                    self.learn_alias(&leaf, alias);
                }
            }
            UseTree::Glob(_) => {
                if parent.is_some_and(|p| self.value.contains(p)) {
                    self.variants.extend(CONTAINER_VARIANTS.map(str::to_owned));
                }
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.learn_use(item, parent);
                }
            }
        }
    }
}

/// One pass of alias learning over one file's production items.
struct NameLearner<'n> {
    names: &'n mut JsonNames,
}

impl<'ast> Visit<'ast> for NameLearner<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        if !cfg_test_only(item_attrs(item)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        if !cfg_test_only(impl_item_attrs(item)) {
            visit::visit_impl_item(self, item);
        }
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        if !cfg_test_only(trait_item_attrs(item)) {
            visit::visit_trait_item(self, item);
        }
    }

    fn visit_item_type(&mut self, item: &'ast ItemType) {
        if let Some(target) = type_name(&item.ty) {
            self.names.learn_alias(&target, item.ident.to_string());
        }
        visit::visit_item_type(self, item);
    }

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        self.names.learn_use(&item.tree, None);
    }
}

/// One fn, const, static or macro body being scanned.
struct Site {
    key: String,
    ident: String,
    reaches: bool,
    shared_accessor: bool,
    names_json: bool,
    calls_itself: bool,
}

impl Site {
    fn open(key: String, ident: String, names_json: bool) -> Self {
        Self {
            key,
            ident,
            reaches: false,
            shared_accessor: false,
            names_json,
            calls_itself: false,
        }
    }
}

/// Every production site of one file that reaches a `JsonVal`'s children: a
/// container pattern through `JsonVal`, an alias, `Self` in an impl on one, or
/// a bare imported variant; a child accessor called or named by path; or a
/// shared-name lookup in a site that names a JSON type. A closure counts
/// toward the fn it sits in, a nested fn on its own.
struct ReachScan<'n> {
    names: &'n JsonNames,
    scopes: Vec<String>,
    self_tys: Vec<Option<String>>,
    sites: Vec<Site>,
    reached: Vec<String>,
    recursive: Vec<String>,
}

impl<'n> ReachScan<'n> {
    fn new(names: &'n JsonNames) -> Self {
        Self {
            names,
            scopes: Vec::new(),
            self_tys: Vec::new(),
            sites: vec![Site::open(FILE_ITEMS.to_owned(), String::new(), false)],
            reached: Vec::new(),
            recursive: Vec::new(),
        }
    }

    fn self_ty_in(&self, set: &BTreeSet<String>) -> bool {
        self.self_tys
            .last()
            .and_then(Option::as_ref)
            .is_some_and(|ty| set.contains(ty))
    }

    /// Scans `body` as the site `label` in the current scope, named `ident`.
    fn in_site(&mut self, ident: &Ident, label: String, body: impl FnOnce(&mut Self)) {
        let key = if self.scopes.is_empty() {
            label
        } else {
            format!("{}::{label}", self.scopes.join("::"))
        };
        let names_json = self.self_ty_in(&self.names.json);
        self.sites
            .push(Site::open(key, ident.to_string(), names_json));
        self.scopes.push(ident.to_string());
        body(self);
        self.scopes.pop();
        if self.sites.len() > 1
            && let Some(site) = self.sites.pop()
        {
            self.record(site);
        }
    }

    fn record(&mut self, site: Site) {
        if site.reaches || (site.shared_accessor && site.names_json) {
            if site.calls_itself {
                self.recursive.push(site.key.clone());
            }
            self.reached.push(site.key);
        }
    }

    fn finish(mut self) -> (Vec<String>, Vec<String>) {
        while let Some(site) = self.sites.pop() {
            self.record(site);
        }
        (self.reached, self.recursive)
    }

    fn reach(&mut self) {
        if let Some(site) = self.sites.last_mut() {
            site.reaches = true;
        }
    }

    fn accessor(&mut self, name: &str) {
        let child = CHILD_ACCESSORS.contains(&name);
        let shared = SHARED_NAME_ACCESSORS.contains(&name);
        if let Some(site) = self.sites.last_mut() {
            site.reaches |= child;
            site.shared_accessor |= shared;
        }
    }

    fn mention(&mut self, name: &str) {
        if let Some(site) = self.sites.last_mut()
            && site.ident == name
        {
            site.calls_itself = true;
        }
    }

    fn mention_json(&mut self, name: &str) {
        if self.names.json.contains(name)
            && let Some(site) = self.sites.last_mut()
        {
            site.names_json = true;
        }
    }

    /// Whether `owner` (the segment before a variant) is `JsonVal` or an alias.
    fn owner_is_value(&self, owner: Option<&str>) -> bool {
        match owner {
            Some("Self") => self.self_ty_in(&self.names.value),
            Some(owner) => self.names.value.contains(owner),
            None => false,
        }
    }

    fn container_pattern(&self, qself: Option<&QSelf>, path: &Path) -> bool {
        let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        let Some(variant) = segments.last() else {
            return false;
        };
        let owner = match (qself, segments.len()) {
            (None, 1) => return self.names.variants.contains(variant),
            (Some(qself), 1) => type_name(&qself.ty),
            (_, len) => len.checked_sub(2).and_then(|at| segments.get(at)).cloned(),
        };
        if CONTAINER_VARIANTS.contains(&variant.as_str()) {
            self.owner_is_value(owner.as_deref())
        } else {
            self.names.variants.contains(variant)
        }
    }

    /// Applies the same rules to a macro's tokens, keyed on the `.` or `::`
    /// before each name.
    fn scan_tokens(&mut self, tokens: &TokenStream) {
        let mut pending = vec![tokens.clone()];
        while let Some(stream) = pending.pop() {
            let mut before: Vec<String> = Vec::new();
            let mut glue = false;
            for tree in stream {
                match tree {
                    TokenTree::Group(group) => {
                        pending.push(group.stream());
                        before.clear();
                        glue = false;
                    }
                    TokenTree::Ident(ident) => {
                        let name = ident.to_string();
                        self.token_ident(&name, &before);
                        before.push(name);
                        glue = false;
                    }
                    TokenTree::Punct(punct) => {
                        let ch = punct.as_char();
                        if glue && ch == ':' {
                            if let Some(last) = before.last_mut() {
                                *last = "::".to_owned();
                            }
                            glue = false;
                        } else {
                            before.push(ch.to_string());
                            glue = ch == ':' && punct.spacing() == Spacing::Joint;
                        }
                    }
                    TokenTree::Literal(literal) => {
                        before.push(literal.to_string());
                        glue = false;
                    }
                }
            }
        }
    }

    fn token_ident(&mut self, name: &str, before: &[String]) {
        let prev = before.last().map(String::as_str);
        self.mention_json(name);
        self.mention(name);
        if matches!(prev, Some("." | "::")) {
            self.accessor(name);
        }
        let reaches = if prev == Some("::") {
            let owner = before
                .len()
                .checked_sub(2)
                .and_then(|at| before.get(at))
                .map(String::as_str);
            CONTAINER_VARIANTS.contains(&name) && self.owner_is_value(owner)
        } else {
            self.names.variants.contains(name)
        };
        if reaches {
            self.reach();
        }
    }
}

impl<'ast> Visit<'ast> for ReachScan<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        if cfg_test_only(item_attrs(item)) {
            return;
        }
        if let Item::Verbatim(tokens) = item {
            self.scan_tokens(tokens);
        }
        visit::visit_item(self, item);
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        if !cfg_test_only(impl_item_attrs(item)) {
            visit::visit_impl_item(self, item);
        }
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        if !cfg_test_only(trait_item_attrs(item)) {
            visit::visit_trait_item(self, item);
        }
    }

    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        let attrs: &[syn::Attribute] = match stmt {
            Stmt::Local(local) => &local.attrs,
            Stmt::Macro(mac) => &mac.attrs,
            Stmt::Item(_) | Stmt::Expr(..) => &[],
        };
        if !cfg_test_only(attrs) {
            visit::visit_stmt(self, stmt);
        }
    }

    fn visit_arm(&mut self, arm: &'ast Arm) {
        if !cfg_test_only(&arm.attrs) {
            visit::visit_arm(self, arm);
        }
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        if cfg_test_only(expr_attrs(expr)) {
            return;
        }
        if let Expr::Verbatim(tokens) = expr {
            self.scan_tokens(tokens);
        }
        visit::visit_expr(self, expr);
    }

    fn visit_item_mod(&mut self, item: &'ast ItemMod) {
        if item.content.is_some() {
            self.scopes.push(item.ident.to_string());
            visit::visit_item_mod(self, item);
            self.scopes.pop();
        }
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        let self_ty = type_name(&item.self_ty);
        let ty = self_ty.clone().unwrap_or_else(|| "_".to_owned());
        let label = match item
            .trait_
            .as_ref()
            .and_then(|(path, _)| path.segments.last())
        {
            Some(tr) => format!("<{ty} as {}>", tr.ident),
            None => ty,
        };
        self.scopes.push(label);
        self.self_tys.push(self_ty);
        visit::visit_item_impl(self, item);
        self.self_tys.pop();
        self.scopes.pop();
    }

    fn visit_item_trait(&mut self, item: &'ast ItemTrait) {
        self.scopes.push(item.ident.to_string());
        self.self_tys.push(None);
        visit::visit_item_trait(self, item);
        self.self_tys.pop();
        self.scopes.pop();
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        let ident = &item.sig.ident;
        self.in_site(ident, ident.to_string(), |scan| {
            visit::visit_item_fn(scan, item)
        });
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        let ident = &item.sig.ident;
        self.in_site(ident, ident.to_string(), |scan| {
            visit::visit_impl_item_fn(scan, item);
        });
    }

    fn visit_trait_item_fn(&mut self, item: &'ast TraitItemFn) {
        let ident = &item.sig.ident;
        self.in_site(ident, ident.to_string(), |scan| {
            visit::visit_trait_item_fn(scan, item);
        });
    }

    fn visit_item_const(&mut self, item: &'ast ItemConst) {
        let ident = &item.ident;
        self.in_site(ident, ident.to_string(), |scan| {
            visit::visit_item_const(scan, item)
        });
    }

    fn visit_item_static(&mut self, item: &'ast ItemStatic) {
        let ident = &item.ident;
        self.in_site(ident, ident.to_string(), |scan| {
            visit::visit_item_static(scan, item)
        });
    }

    fn visit_impl_item_const(&mut self, item: &'ast ImplItemConst) {
        let ident = &item.ident;
        self.in_site(ident, ident.to_string(), |scan| {
            visit::visit_impl_item_const(scan, item);
        });
    }

    fn visit_trait_item_const(&mut self, item: &'ast TraitItemConst) {
        let ident = &item.ident;
        self.in_site(ident, ident.to_string(), |scan| {
            visit::visit_trait_item_const(scan, item);
        });
    }

    fn visit_item_macro(&mut self, item: &'ast ItemMacro) {
        match &item.ident {
            Some(ident) => self.in_site(ident, format!("macro_rules! {ident}"), |scan| {
                visit::visit_item_macro(scan, item);
            }),
            None => visit::visit_item_macro(self, item),
        }
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        if self.sites.len() > 1 {
            self.scan_tokens(&mac.tokens);
        } else if let Some(last) = mac.path.segments.last() {
            let ident = last.ident.clone();
            self.in_site(&ident, format!("{ident}!"), |scan| {
                scan.scan_tokens(&mac.tokens)
            });
        }
        visit::visit_macro(self, mac);
    }

    fn visit_pat_tuple_struct(&mut self, pat: &'ast PatTupleStruct) {
        if self.container_pattern(pat.qself.as_ref(), &pat.path) {
            self.reach();
        }
        visit::visit_pat_tuple_struct(self, pat);
    }

    fn visit_pat_struct(&mut self, pat: &'ast PatStruct) {
        if self.container_pattern(pat.qself.as_ref(), &pat.path) {
            self.reach();
        }
        visit::visit_pat_struct(self, pat);
    }

    fn visit_expr_path(&mut self, expr: &'ast ExprPath) {
        if let Some(last) = expr.path.segments.last() {
            let name = last.ident.to_string();
            if expr.qself.is_some() || expr.path.segments.len() > 1 {
                self.accessor(&name);
            }
            self.mention(&name);
        }
        visit::visit_expr_path(self, expr);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let name = call.method.to_string();
        self.accessor(&name);
        self.mention(&name);
        visit::visit_expr_method_call(self, call);
    }

    fn visit_ident(&mut self, ident: &'ast Ident) {
        self.mention_json(&ident.to_string());
    }
}

/// The production sites of `sources` that reach a `JsonVal`'s children, as
/// (file, site), and the ones among them that name their own fn.
struct Reach {
    reached: Vec<(String, String)>,
    recursive: Vec<(String, String)>,
}

/// Scans `sources` as (file, contents); a source that does not parse fails.
fn json_reach<S: AsRef<str>>(sources: &[(S, S)]) -> Reach {
    let mut files: Vec<(&str, syn::File)> = Vec::new();
    for (name, src) in sources {
        let parsed = syn::parse_file(src.as_ref());
        assert!(
            parsed.is_ok(),
            "{}: does not parse as Rust, so its JSON reach cannot be inventoried: {:?}",
            name.as_ref(),
            parsed.as_ref().err().map(ToString::to_string)
        );
        if let Ok(file) = parsed {
            files.push((name.as_ref(), file));
        }
    }
    let names = JsonNames::learn(&files);
    let mut reach = Reach {
        reached: Vec::new(),
        recursive: Vec::new(),
    };
    for (name, file) in &files {
        let mut scan = ReachScan::new(&names);
        scan.visit_file(file);
        let (reached, recursive) = scan.finish();
        reach
            .reached
            .extend(reached.into_iter().map(|site| ((*name).to_owned(), site)));
        reach
            .recursive
            .extend(recursive.into_iter().map(|site| ((*name).to_owned(), site)));
    }
    reach
}

/// Every (file, site) whose count in `found` differs from its count in
/// `listed`: a site found but unlisted, a stale entry, or a duplicate.
fn inventory_drift(found: &[(String, String)], listed: &[(&str, &str)]) -> Vec<String> {
    let mut counts: BTreeMap<(&str, &str), (usize, usize)> = BTreeMap::new();
    for (file, site) in found {
        counts.entry((file.as_str(), site.as_str())).or_default().0 += 1;
    }
    for &(file, site) in listed {
        counts.entry((file, site)).or_default().1 += 1;
    }
    counts
        .into_iter()
        .filter(|(_, (seen, named))| seen != named)
        .map(|((file, site), (seen, named))| {
            format!("{file}: {site}: found {seen} time(s), listed {named} time(s)")
        })
        .collect()
}

fn fixture_reach(src: &str) -> Vec<String> {
    json_reach(&[("fixture.rs", src)])
        .reached
        .into_iter()
        .map(|(_, site)| site)
        .collect()
}

/// Every name of an inherent `JsonVal` method or a `JsonIndex` method whose
/// return type names a JSON type or a child collection.
fn json_returning_accessors(src: &str) -> BTreeSet<String> {
    let parsed = syn::parse_file(src);
    assert!(parsed.is_ok(), "json_val.rs does not parse as Rust");
    let mut found = BTreeSet::new();
    let Ok(file) = parsed else {
        return found;
    };
    for item in &file.items {
        if cfg_test_only(item_attrs(item)) {
            continue;
        }
        let sigs: Vec<&syn::Signature> = match item {
            Item::Impl(block)
                if block.trait_.is_none()
                    && type_name(&block.self_ty).as_deref() == Some("JsonVal") =>
            {
                block
                    .items
                    .iter()
                    .filter(|method| !cfg_test_only(impl_item_attrs(method)))
                    .filter_map(|method| match method {
                        ImplItem::Fn(method) => Some(&method.sig),
                        _ => None,
                    })
                    .collect()
            }
            Item::Trait(index) if index.ident == INDEX_TRAIT => index
                .items
                .iter()
                .filter_map(|method| match method {
                    syn::TraitItem::Fn(method) => Some(&method.sig),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        for sig in sigs {
            let mut idents = TypeIdents::default();
            if let ReturnType::Type(_, ty) = &sig.output {
                idents.visit_type(ty);
            }
            if JSON_RETURN_NAMES
                .iter()
                .any(|name| idents.0.contains(*name))
            {
                found.insert(sig.ident.to_string());
            }
        }
    }
    found
}

/// Every name a type spells.
#[derive(Default)]
struct TypeIdents(BTreeSet<String>);

impl<'ast> Visit<'ast> for TypeIdents {
    fn visit_ident(&mut self, ident: &'ast Ident) {
        self.0.insert(ident.to_string());
    }
}

#[test]
fn the_accessor_lists_name_every_json_returning_accessor() {
    let sources = rust_sources(&e2e_support::manifest_dir!().join("src"));
    let src = sources
        .iter()
        .find(|(name, _)| name == "json_val.rs")
        .map(|(_, src)| src.as_str())
        .expect("the source walk reads json_val.rs");
    let listed: BTreeSet<String> = CHILD_ACCESSORS
        .iter()
        .chain(&SHARED_NAME_ACCESSORS)
        .chain(&ROOT_RETURNING)
        .map(|name| (*name).to_owned())
        .collect();
    assert_eq!(
        json_returning_accessors(src),
        listed,
        "a `JsonVal` accessor returning JSON must be classified as a child accessor, a \
         shared-name lookup, or a root-returning method"
    );
}

#[test]
fn an_accessor_reaches_by_method_path_or_qualified_self() {
    let src = r"
fn method(v: &Doc) -> usize { v.as_array().map_or(0, Vec::len) }
fn path(v: Doc) -> bool { JsonVal::into_object(v).is_some() }
fn qualified(v: &Doc) -> bool { <JsonVal>::as_object(v).is_some() }
fn unrelated(v: &Doc) -> usize { v.len() }
";
    assert_eq!(fixture_reach(src), vec!["method", "path", "qualified"]);
}

#[test]
fn a_bare_variant_from_a_grouped_import_reaches() {
    let src = r"
use crate::json_val::JsonVal::{Array, Object as Obj};
fn bare(v: &Doc) -> usize { if let Array(items) = v { items.len() } else { 0 } }
fn renamed(v: &Doc) -> bool { matches!(v, Obj(_)) }
fn other(v: &Shape) -> bool { matches!(v, Shape::Array(_)) }
";
    assert_eq!(fixture_reach(src), vec!["bare", "renamed"]);
}

#[test]
fn a_type_alias_or_renamed_import_reaches() {
    let src = r"
type Deeper = Doc;
type Doc = crate::json_val::JsonVal;
use crate::json_val::{JsonVal as V};
fn aliased(v: &Deeper) -> usize { match v { Deeper::Array(items) => items.len(), _ => 0 } }
fn renamed(v: &V) -> bool { if let V::Object(map) = v { map.is_empty() } else { false } }
fn looked_up(v: &Doc, key: &str) -> bool { v.get(key).is_some() }
";
    assert_eq!(fixture_reach(src), vec!["aliased", "renamed", "looked_up"]);
}

#[test]
fn self_variant_in_an_impl_on_json_val_reaches() {
    let src = r"
impl JsonVal {
    fn kids(&self) -> usize { match self { Self::Array(items) => items.len(), _ => 0 } }
}
impl Shape {
    fn kids(&self) -> usize { match self { Self::Array(items) => items.len(), _ => 0 } }
}
";
    assert_eq!(fixture_reach(src), vec!["JsonVal::kids"]);
}

#[test]
fn a_glob_imported_variant_reaches() {
    let src = r"
use crate::json_val::JsonVal::*;
fn globbed(v: &Doc) -> usize { match v { Object(map) => map.len(), _ => 0 } }
";
    assert_eq!(fixture_reach(src), vec!["globbed"]);
}

#[test]
fn a_closure_counts_toward_its_fn_and_a_nested_fn_on_its_own() {
    let src = r"
fn host() { fn inner(v: &Doc) -> Option<&Vec<Doc>> { v.as_array() } }
fn outer(values: &[Doc]) -> usize { values.iter().map(|v| v.as_object().map_or(0, |m| m.len())).sum() }
";
    assert_eq!(fixture_reach(src), vec!["host::inner", "outer"]);
}

#[test]
fn an_accessor_or_variant_inside_a_macro_reaches() {
    let src = r#"
fn in_macro(v: &Doc) -> String { format!("{:?}", v.as_array()) }
fn matched(v: &Doc) -> bool { matches!(v, JsonVal::Object(_)) }
macro_rules! children { ($v:expr) => { $v.into_array() }; }
"#;
    assert_eq!(
        fixture_reach(src),
        vec!["in_macro", "matched", "macro_rules! children"]
    );
}

#[test]
fn a_shared_name_lookup_reaches_only_where_a_json_type_is_named() {
    let src = r#"
fn lookup(map: &std::collections::HashMap<String, u32>) -> Option<&u32> { map.get("k") }
fn json_lookup(v: &JsonVal) -> Option<&JsonVal> { v.get("k") }
"#;
    assert_eq!(fixture_reach(src), vec!["json_lookup"]);
}

#[test]
fn a_cfg_test_site_is_not_inventoried() {
    let src = r"
#[cfg(test)]
fn probe(v: &JsonVal) -> bool { v.as_array().is_some() }
#[cfg(test)]
mod tests { fn probe(v: &JsonVal) -> bool { v.as_object().is_some() } }
";
    assert_eq!(fixture_reach(src), Vec::<String>::new());
}

#[test]
#[should_panic(expected = "does not parse as Rust")]
fn a_source_that_does_not_parse_fails_the_inventory() {
    let _ = fixture_reach("fn walk( { v.as_array() }");
}

#[test]
fn an_unlisted_site_a_stale_entry_or_a_duplicate_is_drift() {
    let found = vec![
        ("a.rs".to_owned(), "walk".to_owned()),
        ("a.rs".to_owned(), "read".to_owned()),
    ];
    assert_eq!(
        inventory_drift(&found, &[("a.rs", "walk"), ("a.rs", "read")]),
        Vec::<String>::new()
    );
    assert_eq!(
        inventory_drift(&found, &[("a.rs", "walk")]),
        vec!["a.rs: read: found 1 time(s), listed 0 time(s)"]
    );
    assert_eq!(
        inventory_drift(
            &found,
            &[("a.rs", "walk"), ("a.rs", "read"), ("b.rs", "gone")]
        ),
        vec!["b.rs: gone: found 0 time(s), listed 1 time(s)"]
    );
    assert_eq!(
        inventory_drift(
            &found,
            &[("a.rs", "walk"), ("a.rs", "walk"), ("a.rs", "read")]
        ),
        vec!["a.rs: walk: found 1 time(s), listed 2 time(s)"]
    );
}

#[test]
fn a_reaching_site_that_names_itself_is_recursive() {
    let src = r"
fn walk(v: &JsonVal) -> usize { v.as_array().map_or(1, |items| items.iter().map(walk).sum()) }
impl Tree { fn depth(&self) -> usize { self.0.as_object().map_or(1, |m| m.values().map(|c| c.depth()).sum()) } }
fn flat(v: &JsonVal) -> usize { v.as_array().map_or(0, Vec::len) }
";
    let reach = json_reach(&[("fixture.rs", src)]);
    assert_eq!(
        inventory_drift(&reach.recursive, &[("fixture.rs", "walk")]),
        vec!["fixture.rs: Tree::depth: found 1 time(s), listed 0 time(s)"]
    );
    assert_eq!(
        inventory_drift(
            &reach.reached,
            &[
                ("fixture.rs", "walk"),
                ("fixture.rs", "Tree::depth"),
                ("fixture.rs", "flat")
            ]
        ),
        Vec::<String>::new()
    );
}

/// Every production fn that reaches a `JsonVal`'s children is listed exactly
/// once in `ALLOWED_SITES`, with a reason.
#[test]
fn every_production_site_reaching_json_children_is_listed_once() {
    let sources = rust_sources(&e2e_support::manifest_dir!().join("src"));
    for required in ["json.rs", "json_val.rs", "js_port.rs", "web/mod.rs"] {
        assert!(
            sources.iter().any(|(name, _)| name == required),
            "the source walk did not read {required}"
        );
    }
    let reach = json_reach(&sources);
    let drift = inventory_drift(&reach.reached, &allowed_sites());
    assert!(
        drift.is_empty(),
        "every production fn that reaches a `JsonVal`'s children is listed once in \
         `ALLOWED_SITES` with how it bounds its stack; a new walk over every level uses an \
         explicit worklist:\n{}",
        drift.join("\n")
    );
    for (file, site, _, why) in ALLOWED_SITES {
        assert!(!why.trim().is_empty(), "{file}: {site}: no reason given");
    }
}

/// A listed site that names its own fn recurses per level unless it is tagged
/// `Depth256` (behind the backstop) or `Delegates` (a same-named call on
/// another type); each such tag must still hold. Mutual recursion (`a` calls
/// `b` calls `a`) is not traced; review covers it.
#[test]
fn every_self_naming_reaching_site_is_bounded_or_delegates() {
    let reach = json_reach(&rust_sources(&e2e_support::manifest_dir!().join("src")));
    let drift = inventory_drift(&reach.recursive, &recursion_tags());
    assert!(
        drift.is_empty(),
        "a fn that reaches a `JsonVal`'s children and calls itself overflows the stack on \
         deep input; walk it with an explicit worklist:\n{}",
        drift.join("\n")
    );
}
