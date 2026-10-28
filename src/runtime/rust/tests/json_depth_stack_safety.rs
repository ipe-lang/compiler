//! `JsonVal` depth safety: every walk over a JSON value runs in constant stack,
//! and the crossings into `serde_json`'s recursive walks are refused past one
//! backstop.
//!
//! The depth tests run on a spawned 256 KiB thread, so a walk that recurses
//! once per nesting level overflows here rather than in production. The source
//! scan refuses a production fn outside `json_val.rs` that matches on
//! `JsonVal::Array` / `JsonVal::Object` and calls itself.
#![cfg(feature = "json")]
#![cfg(not(target_arch = "wasm32"))]

use std::hash::{DefaultHasher, Hash, Hasher};

use ipe_runtime_rust::json::{json_enc_canonical, json_enc_encode, json_enc_int, json_enc_object};
use ipe_runtime_rust::json_val::{
    BACKSTOP_REFUSAL, JSON_SERDE_NESTING_BACKSTOP, JsonMap, JsonVal, json_depth,
};
use syn::visit::{self, Visit};
use syn::{
    Arm, Expr, ExprCall, ExprMethodCall, ImplItem, ImplItemFn, Item, ItemFn, Path, Stmt, UseGlob,
    UsePath, UseRename,
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
        assert!(format!("{value:#}").starts_with("[\n  ["));
        let object = deep_object(100_000);
        assert!(object.clone() == object);
        assert_eq!(hash_of(&object.clone()), hash_of(&object));
    });
}

#[test]
fn deep_value_canonical() {
    on_stack(SMALL_STACK, || {
        let canonical = json_enc_canonical(&deep_object(100_000));
        assert!(canonical.starts_with("{\"k"));
        assert!(canonical.ends_with("null}}"));
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
    fn flow(depth: usize) -> String {
        format!("{}{}", "[".repeat(depth), "]".repeat(depth))
    }
    fn parse(source: &str) -> Result<JsonVal, String> {
        let mut budget = serde_saphyr::Budget::default();
        budget.max_depth = JSON_SERDE_NESTING_BACKSTOP + 8;
        budget.max_documents = 1;
        let mut options = serde_saphyr::Options::default();
        options.budget = Some(budget);
        serde_saphyr::from_str_with_options::<JsonVal>(source, options)
            .map_err(|error| error.to_string())
    }
    on_stack(1024 * 1024, || {
        let at = parse(&flow(JSON_SERDE_NESTING_BACKSTOP));
        assert!(
            at.as_ref()
                .is_ok_and(|value| json_depth(value) == JSON_SERDE_NESTING_BACKSTOP),
            "{at:?}"
        );
        let past = parse(&flow(JSON_SERDE_NESTING_BACKSTOP + 1));
        assert!(past.is_err(), "{past:?}");
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
