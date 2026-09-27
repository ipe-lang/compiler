//! Ipê → Rust identifier naming rules.
//!
//! Ports the relevant arms of `Ipê/Generate/Rust/Builder/Naming.hs`:
//! `toCamelCase` / `toSnakeCase` and the module-prefixing used to derive Rust
//! type and function names. The conversions are written generally so they
//! match the reference across every module, not just `Main`.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use ipe_ir::KernelFn;

/// The first `snake_case` segment of every runtime-kernel Rust name — the set of
/// identifier prefixes the `ipe_runtime` glob (`pub use ipe_runtime::*;`) owns at
/// the emitted crate root.
///
/// Derived structurally from the authoritative kernel table ([`KernelFn::ALL`] ×
/// [`kernel_name`]) rather than a hand-maintained list, so it can never drift out
/// of sync with the kernels it must reserve: a kernel whose Rust name is
/// `auth_hash_password` contributes `auth`; `string_from_int` contributes
/// `string`. A user top-level function whose default `snake_case` name begins
/// with one of these segments would collide with a kernel at the crate root, so
/// [`module_value`] disambiguates it (see [`disambiguate_user_fn_name`]).
static KERNEL_NAME_PREFIXES: LazyLock<BTreeSet<&'static str>> = LazyLock::new(|| {
    KernelFn::ALL
        .iter()
        .map(|&k| {
            let name = kernel_name(k);
            name.split_once('_').map_or(name, |(head, _)| head)
        })
        .collect()
});

/// If a user top-level function's default `snake_case` name would collide with a
/// runtime-kernel namespace at the emitted crate root, return the disambiguated
/// name; otherwise `None`.
///
/// A user `module Auth` value `hashPassword` folds to `auth_hash_password` —
/// byte-identical to the `Ipe.Auth` kernel's runtime name. Once both the user
/// module's `pub use …::*` and `pub use ipe_runtime::*;` land at the crate root,
/// that name is doubly-defined: the user body's own call to the kernel resolves
/// to the user function (self-recursion), and the two definitions clash. The
/// structural fix is to prefix the user side with `user_`, which no kernel name
/// begins with, making the user function provably disjoint from every kernel
/// while leaving kernel call sites byte-identical. The check keys on the first
/// `snake_case` segment (the kernel-owned namespace), so `auth_mint_token` — a
/// user function with no kernel counterpart but in a kernel-owned namespace —
/// is disambiguated too, keeping the whole `Auth` module on one consistent
/// scheme.
#[must_use]
fn disambiguate_user_fn_name(default_snake: &str) -> Option<String> {
    let head = default_snake
        .split_once('_')
        .map_or(default_snake, |(head, _)| head);
    if KERNEL_NAME_PREFIXES.contains(head) {
        Some(format!("user_{default_snake}"))
    } else {
        None
    }
}

/// Convert a Ipê module-prefixed name to `UpperCamelCase` (used for type names).
///
/// `Ipe_Core_Error_Error` → `IpeCoreErrorError`, `Main_Msg` → `MainMsg`.
/// An underscore is dropped and the following character upper-cased; a trailing
/// underscore with no successor is kept verbatim (mirrors the reference compiler pattern
/// `go ('_':c:cs)` falling through to `go (c:cs)` when there is no `c`).
#[must_use]
pub fn to_camel_case(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = if let Some(&c) = chars.first() {
        out.extend(c.to_uppercase());
        1usize
    } else {
        0
    };
    while let Some(&c) = chars.get(i) {
        if c == '_' {
            if let Some(&n) = chars.get(i + 1) {
                out.extend(n.to_uppercase());
                i += 2;
                continue;
            }
            out.push('_');
        } else {
            out.push(c);
        }
        i += 1;
    }
    out
}

/// Convert a Ipê module-prefixed name to `snake_case` (used for function names).
///
/// `Ipe_Core_List_map` → `ipe_core_list_map`, `Main_update` → `main_update`.
/// Mirrors the reference compiler `toSnakeCase`: the leading character is lower-cased; an
/// underscore followed by a character emits `_` plus the lower-cased successor;
/// an interior upper-case character emits `_` plus its lower-case form.
#[must_use]
pub fn to_snake_case(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = if let Some(&c) = chars.first() {
        out.extend(c.to_lowercase());
        1usize
    } else {
        0
    };
    while let Some(&c) = chars.get(i) {
        if c == '_' {
            if let Some(&n) = chars.get(i + 1) {
                out.push('_');
                out.extend(n.to_lowercase());
                i += 2;
                continue;
            }
            out.push('_');
        } else if c.is_uppercase() {
            out.push('_');
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
        i += 1;
    }
    out
}

/// The dotted module prefix rendered with `_` separators (`["Ipê","Core","Io"]`
/// → `Ipe_Io`). This matches `moduleNameToRust` (dots → underscores) when
/// the path is supplied as already-split segments.
///
/// The fold is INJECTIVE on the segment list: a literal `_` inside a segment is
/// escaped to `__` before the single-`_` join, so the segment separator and an
/// in-segment underscore are never conflated. Without this, `["Std", "Ui"]` and
/// the single segment `["Std_Ui"]` would both fold to `"Std_Ui"` — two distinct
/// module homes producing one Rust `mod`/type/value name (E0428 + a silent
/// file-overwrite at the split boundary). Ipê module segments cannot contain
/// `.` (the parser splits paths on `.`), so an in-segment `_` is the ONLY
/// ambiguity, and escaping it restores injectivity. The escape is a NO-OP for
/// every segment that contains no `_`, so single-`.`-segment module names (every
/// real program's) fold byte-identically to the previous `join("_")`.
///
/// `pub` (rather than private) because `rust_file::mod_ident` reuses this exact
/// fold for the `ModPath -> Rust mod identifier` namespace. `naming` stays a
/// private module, so `pub` here is crate-scoped in practice
/// (`clippy::redundant_pub_crate` — a `pub(crate)` item inside a private module
/// is equivalent to `pub`).
pub fn module_prefix(module: &[&str]) -> String {
    module
        .iter()
        .map(|seg| seg.replace('_', "__"))
        .collect::<Vec<_>>()
        .join("_")
}

/// Rewrite an emitted identifier that collides with a Rust keyword so the
/// generated code compiles. A reserved name gains a trailing underscore
/// (`type` → `type_`, `Self` → `Self_`).
///
/// The trailing-underscore form is chosen over raw identifiers (`r#name`)
/// because it is valid for *every* keyword — `r#crate` / `r#self` / `r#Self` /
/// `r#super` are themselves rejected by the Rust grammar — so one rule covers
/// the whole set without special cases.
///
/// The rule is INJECTIVE: a bare `+_` on reserved names alone would map the
/// keyword `match` to `match_`, colliding with a user identifier literally
/// spelled `match_` (which would pass through unchanged) — two distinct source
/// names folding to one Rust name, an E0428 / silent-shadow at cargo time. To
/// keep the fold one-to-one, any identifier whose stem (after stripping trailing
/// underscores) is reserved is mangled by appending ONE MORE underscore than it
/// already carries: `match` → `match_`, `match_` → `match__`, `match__` →
/// `match___`. The reserved-mangle image (an odd count of trailing underscores
/// over a keyword stem is never required — each preimage adds exactly one) and
/// the pass-through image (non-reserved stem, kept verbatim) are provably
/// disjoint, so no two distinct inputs share an output.
#[must_use]
pub fn mangle_reserved(name: String) -> String {
    let trailing = name.len() - name.trim_end_matches('_').len();
    let stem = &name[..name.len() - trailing];
    if ipe_intern::is_rust_keyword(stem) {
        let mut mangled = String::with_capacity(name.len() + 1);
        mangled.push_str(&name);
        mangled.push('_');
        mangled
    } else {
        name
    }
}

/// The Rust enum/type name for a user type: `enum_name(["Main"], "Msg")` →
/// `MainMsg`. Mirrors `unionToRustTypeDef`'s `codegenName`. A name colliding
/// with a Rust keyword (e.g. a bare `type Self`) is mangled by
/// [`mangle_reserved`].
#[must_use]
pub fn enum_name(module: &[&str], ty: &str) -> String {
    mangle_reserved(to_camel_case(&format!("{}_{}", module_prefix(module), ty)))
}

/// The Rust function name for a top-level value: `module_value(["Main"],
/// "update")` → `main_update`.
///
/// The program entry `main` in module `Main` is special-cased to `ipe_main`
/// (the fixed `fn main` entry-point in the epilogue calls `ipe_main()`), matching
/// the reference compiler `rustName` rule in `ModuleEmitter.hs`.
#[must_use]
pub fn module_value(module: &[&str], name: &str) -> String {
    if name == "main" && module == ["Main"] {
        return "ipe_main".to_owned();
    }
    // A record type-alias auto-constructor is the ONLY top-level value
    // whose Ipê name begins with an uppercase letter (the parser forces every
    // other value / function name lowercase). Snake-casing it would fold the
    // case and could COLLIDE with a same-spelled lowercase value in the same
    // module — e.g. `type alias Row = { … }` yields the constructor `Row`, and a
    // value `row` in the same module would both mangle to `main_row` (a
    // duplicate-definition / wrong-arity miscompile). Emit the constructor's
    // name VERBATIM (case-preserved) so the ident keeps an uppercase letter and
    // is therefore provably disjoint from every snake-cased (all-lowercase)
    // value name, while remaining injective across constructors (Ipê names are
    // unique per module) and across modules (the snake-cased module prefix). The
    // module-level `#![allow(non_snake_case)]` suppresses the style lint.
    if name.chars().next().is_some_and(char::is_uppercase) {
        let prefix = to_snake_case(&module_prefix(module));
        return mangle_reserved(format!("{prefix}_{name}"));
    }
    let default_snake = to_snake_case(&format!("{}_{}", module_prefix(module), name));
    // A user module named after a kernel namespace (e.g. `module Auth`, whose
    // functions fold to `auth_*`) collides with the `ipe_runtime` glob at the
    // crate root. Prefix the user side with `user_` so it is provably disjoint
    // from every kernel; kernel call sites are untouched. See
    // [`disambiguate_user_fn_name`].
    let disambiguated = disambiguate_user_fn_name(&default_snake).unwrap_or(default_snake);
    mangle_reserved(disambiguated)
}

/// The base Rust struct name for a synthesised record shape, derived from its
/// sorted field names: `record_struct_name(["x", "y"])` → `RecXY`.
///
/// Mirrors the reference compiler Rust backend's `anonStructName` strategy (a name built
/// from the field set) but with a `Rec_` stem. The result is a *base* name; the
/// caller deduplicates across the program and appends a numeric suffix on the
/// rare event that two distinct field sets camel-case to the same string (e.g.
/// `["a_b"]` and `["a", "b"]`), keeping every synthesised struct collision-free.
/// A base that lands on a Rust keyword is mangled by [`mangle_reserved`].
#[must_use]
pub fn record_struct_name(field_names: &[String]) -> String {
    let joined = field_names.join("_");
    mangle_reserved(to_camel_case(&format!("Rec_{joined}")))
}

/// The field-witness trait name for a record field — field `name` →
/// `IpeHasName`. One trait per field name; the `IpeHas` prefix keeps the
/// namespace disjoint from the `Rec…` struct namespace and from every runtime
/// type. A row generic bounded by this trait can read the field through the
/// trait's getter, so rustc monomorphises the call per concrete record shape.
#[must_use]
pub fn field_witness_trait_name(field_name: &str) -> String {
    to_camel_case(&format!("Ipe_has_{field_name}"))
}

/// The field-witness getter method name — field `name` → `ipe_name`. The
/// `ipe_` prefix cannot collide with a Rust struct field or an inherent method
/// on a registry struct, so an impl of the witness trait can always name it.
#[must_use]
pub fn field_witness_getter_name(field_name: &str) -> String {
    format!("ipe_{}", mangle_reserved(field_name.to_owned()))
}

/// The field-witness associated-type name — field `name` → `Name`. Baking the
/// field type into an associated type (rather than the trait's type parameters)
/// lets one trait serve every field type: the impls stay type-agnostic and the
/// row bound `R: IpeHasName<Name = String>` does the type checking.
#[must_use]
pub fn field_witness_assoc_type_name(field_name: &str) -> String {
    to_camel_case(field_name)
}

/// The setter-witness trait name for a field — field `name` → `IpeWithName`.
/// Supertraits `IpeHasName` (an updatable field is always readable), declared
/// with `pub trait IpeWithName: IpeHasName { fn ipe_with_name(self, v:
/// Self::Name) -> Self; }`. Used for G2 (update-through-row) emission.
#[must_use]
pub fn field_setter_witness_trait_name(field_name: &str) -> String {
    to_camel_case(&format!("Ipe_with_{field_name}"))
}

/// The setter-witness method name — field `name` → `ipe_with_name`. The body
/// `{ rec | name = v }` on a row-typed receiver emits `rec.ipe_with_name(v)`,
/// which returns `Self` (the caller's concrete struct, preserving all other
/// fields via `Self { name: v, ..self }`).
#[must_use]
pub fn field_setter_witness_method_name(field_name: &str) -> String {
    format!("ipe_with_{}", mangle_reserved(field_name.to_owned()))
}

/// The Rust runtime function name a kernel built-in emits.
///
/// Delegates to <code>[`KernelFn::def`].runtime_fn</code> — the authoritative
/// per-kernel emit symbol lives in `ipe_kernels::KernelDef`, so this function
/// is a zero-cost projection. The `kernel_name_delegates_to_def_runtime_fn`
/// test guards the delegation.
#[must_use]
pub const fn kernel_name(k: KernelFn) -> &'static str {
    k.def().runtime_fn
}

#[cfg(test)]
mod tests {
    use super::{
        enum_name, field_witness_assoc_type_name, field_witness_getter_name,
        field_witness_trait_name, kernel_name, module_value, to_camel_case, to_snake_case,
    };
    use ipe_ir::KernelFn;

    #[test]
    fn field_witness_names_derive_from_field() {
        assert_eq!(field_witness_trait_name("name"), "IpeHasName");
        assert_eq!(field_witness_getter_name("name"), "ipe_name");
        assert_eq!(field_witness_assoc_type_name("name"), "Name");
    }

    #[test]
    fn field_witness_names_camel_case_multiword_fields() {
        // A snake_case Ipê field folds to one CamelCase token in the trait and
        // associated-type names, and stays snake in the prefixed getter.
        assert_eq!(field_witness_trait_name("first_name"), "IpeHasFirstName");
        assert_eq!(field_witness_assoc_type_name("first_name"), "FirstName");
        assert_eq!(field_witness_getter_name("first_name"), "ipe_first_name");
    }

    /// The hazard the row-witness disjointness gate exists to catch: two DISTINCT
    /// surface field names that camel-case to the SAME witness-trait name. Both
    /// spellings are valid lowercase-initial identifiers the parser admits, and
    /// `to_camel_case` erases the distinction, so `field_witness_trait_name` is
    /// NOT injective — the backend must not assume witness names are unique per
    /// field. `EmitCtx::assert_row_witness_names_disjoint` fails such a program
    /// closed rather than emit two `IpeHasFirstName` traits (E0428).
    #[test]
    fn witness_trait_name_is_not_injective_over_field_names() {
        assert_eq!(
            field_witness_trait_name("first_name"),
            field_witness_trait_name("firstName"),
            "snake and camel spellings of the same field collide to one \
             witness-trait name — the gate must reject their coexistence"
        );
    }

    #[test]
    fn field_witness_getter_mangles_reserved_field() {
        // A field whose name is a Rust keyword is keyword-mangled inside the
        // getter suffix, so the emitted method identifier is always valid — and
        // the `ipe_` prefix already keeps it clear of the reserved namespace.
        assert_eq!(field_witness_getter_name("type"), "ipe_type_");
    }

    /// A runtime `false` the optimiser cannot fold, so `assert!(false_marker(),
    /// …)` reads as a deliberate unconditional failure rather than a suspicious
    /// constant condition — keeps this file free of the `clippy::panic` deny.
    const fn false_marker() -> bool {
        std::hint::black_box(false)
    }

    #[test]
    fn camel_case_module_prefixed() {
        assert_eq!(to_camel_case("Main_Msg"), "MainMsg");
        assert_eq!(to_camel_case("Ipe_Core_Error_Error"), "IpeCoreErrorError");
    }

    #[test]
    fn snake_case_module_prefixed() {
        assert_eq!(to_snake_case("Main_update"), "main_update");
        assert_eq!(to_snake_case("Ipe_Core_List_map"), "ipe_core_list_map");
    }

    #[test]
    fn enum_and_value_names() {
        assert_eq!(enum_name(&["Main"], "Msg"), "MainMsg");
        assert_eq!(module_value(&["Main"], "update"), "main_update");
    }

    #[test]
    fn entry_main_is_ipe_main() {
        assert_eq!(module_value(&["Main"], "main"), "ipe_main");
        // `main` outside the `Main` module is NOT the entry.
        assert_eq!(module_value(&["Other"], "main"), "other_main");
    }

    #[test]
    fn record_ctor_name_is_case_preserved_and_collision_free() {
        // a record-alias auto-constructor's uppercase Ipê name must NOT
        // snake-case-fold into a same-spelled lowercase value's ident.
        assert_eq!(module_value(&["Main"], "Row"), "main_Row");
        assert_eq!(module_value(&["Main"], "row"), "main_row");
        assert_ne!(
            module_value(&["Main"], "Row"),
            module_value(&["Main"], "row"),
            "ctor `Row` and value `row` must be distinct idents"
        );
        // A multi-word ctor stays verbatim (never `main_user_profile`, which a
        // value `userProfile` could also produce).
        assert_eq!(module_value(&["Main"], "UserProfile"), "main_UserProfile");
        assert_ne!(
            module_value(&["Main"], "UserProfile"),
            module_value(&["Main"], "userProfile"),
        );
        // Multi-segment module prefix is still snake-cased; only the ctor name
        // is preserved.
        assert_eq!(
            module_value(&["Lib", "State"], "Widget"),
            "lib_state_Widget"
        );
    }

    #[test]
    fn user_module_named_after_kernel_namespace_is_disambiguated() {
        // A user `module Auth` value `hashPassword` folds to `auth_hash_password`,
        // byte-identical to the `Ipe.Auth` kernel runtime name — self-recursion +
        // duplicate-definition once both glob re-exports land at the crate root.
        // The `user_` prefix makes the user side provably disjoint from every
        // kernel while leaving the kernel name untouched.
        assert_eq!(
            kernel_name(KernelFn::AuthHashPassword),
            "auth_hash_password"
        );
        assert_eq!(
            module_value(&["Auth"], "hashPassword"),
            "user_auth_hash_password"
        );
        assert_ne!(
            module_value(&["Auth"], "hashPassword"),
            kernel_name(KernelFn::AuthHashPassword),
            "user Auth.hashPassword must not collide with the Ipe.Auth kernel"
        );
        // Every function in a kernel-owned namespace is disambiguated uniformly,
        // even one with no kernel counterpart (`mintToken`), so the whole module
        // stays on one consistent scheme.
        assert_eq!(module_value(&["Auth"], "mintToken"), "user_auth_mint_token");
        // A user module whose prefix is NOT a kernel namespace is untouched: the
        // composite-server's `Routes.Auth` folds to `routes_auth_*` (first segment
        // `routes`), so it keeps its default name.
        assert_eq!(
            module_value(&["Routes", "Auth"], "handleLogin"),
            "routes_auth_handle_login"
        );
        // The reserved set is derived from the live kernel table, so a `String`
        // module (matching the `String` kernel namespace) is reserved too.
        assert_eq!(
            module_value(&["String"], "myHelper"),
            "user_string_my_helper"
        );
    }

    /// `kernel_name` is a one-line delegation to `k.def().runtime_fn`.
    /// Verify the delegation holds: `kernel_name(k)` must equal `k.def().runtime_fn`
    /// for every kernel — which is guaranteed by construction, since the body IS
    /// `k.def().runtime_fn`. This test stays to catch any future refactor that
    /// accidentally reintroduces a standalone table.
    #[test]
    fn kernel_name_delegates_to_def_runtime_fn() {
        for &k in ipe_kernels::StdlibKernel::ALL {
            assert_eq!(
                kernel_name(k),
                k.def().runtime_fn,
                "{k:?}: kernel_name must equal def().runtime_fn (delegation invariant)"
            );
        }
    }

    #[test]
    fn kernel_names() {
        assert_eq!(kernel_name(KernelFn::StringFromInt), "string_from_int");
        assert_eq!(kernel_name(KernelFn::StringFromFloat), "string_from_float");
        assert_eq!(kernel_name(KernelFn::LogInfo), "log_info");
        assert_eq!(kernel_name(KernelFn::IoPrintln), "io_println");
        assert_eq!(kernel_name(KernelFn::IoEprintln), "io_eprintln");
        assert_eq!(kernel_name(KernelFn::DebugLog), "debug_log");
        assert_eq!(kernel_name(KernelFn::DebugTodo), "debug_todo");
        assert_eq!(kernel_name(KernelFn::DebugExplain), "debug_explain_");
        // ── Http kernels ──────────────────────────────────────────────
        assert_eq!(kernel_name(KernelFn::HttpGet), "http_get");
        assert_eq!(kernel_name(KernelFn::HttpPost), "http_post");
        assert_eq!(kernel_name(KernelFn::HttpRequest), "http_request");
        assert_eq!(kernel_name(KernelFn::HttpParseQuery), "http_parse_query");
        assert_eq!(
            kernel_name(KernelFn::HttpDefaultRequest),
            "http_default_request"
        );
        assert_eq!(kernel_name(KernelFn::HttpWithMethod), "http_with_method");
        assert_eq!(kernel_name(KernelFn::HttpWithTimeout), "http_with_timeout");
        assert_eq!(kernel_name(KernelFn::HttpWithBody), "http_with_body");
        assert_eq!(kernel_name(KernelFn::HttpWithHeader), "http_with_header");
        assert_eq!(kernel_name(KernelFn::HttpWithUrl), "http_with_url");
        assert_eq!(
            kernel_name(KernelFn::HttpWithRedirects),
            "http_with_redirects"
        );
        assert_eq!(
            kernel_name(KernelFn::HttpMethodFromString),
            "http_method_from_string"
        );
        assert_eq!(
            kernel_name(KernelFn::HttpMethodToString),
            "http_method_to_string"
        );
    }

    #[test]
    fn record_struct_names_from_field_sets() {
        use super::record_struct_name;
        assert_eq!(
            record_struct_name(&["x".to_owned(), "y".to_owned()]),
            "RecXY"
        );
        assert_eq!(
            record_struct_name(&["name".to_owned(), "age".to_owned()]),
            "RecNameAge"
        );
        // A single field.
        assert_eq!(record_struct_name(&["count".to_owned()]), "RecCount");
        // Different field sets that camel-case to the SAME base name — the
        // caller disambiguates with a numeric suffix; the base collision is a
        // documented possibility, not a panic.
        assert_eq!(record_struct_name(&["a_b".to_owned()]), "RecAB");
        assert_eq!(
            record_struct_name(&["a".to_owned(), "b".to_owned()]),
            "RecAB"
        );
    }

    #[test]
    fn non_reserved_names_pass_through() {
        assert_eq!(super::mangle_reserved("count".to_owned()), "count");
        assert_eq!(super::mangle_reserved("MainMsg".to_owned()), "MainMsg");
        assert_eq!(
            super::mangle_reserved("main_update".to_owned()),
            "main_update"
        );
    }

    #[test]
    fn reserved_names_get_a_trailing_underscore() {
        for kw in ipe_intern::RUST_KEYWORDS {
            assert_eq!(super::mangle_reserved((*kw).to_owned()), format!("{kw}_"));
        }
    }

    #[test]
    fn weak_keyword_field_names_keep_their_wire_spelling() {
        for name in ["union", "macro_rules", "raw", "safe"] {
            assert_eq!(super::mangle_reserved(name.to_owned()), name);
        }
    }

    #[test]
    fn reserved_collisions_mangle_at_emit_helpers() {
        // `main_loop` is not itself reserved, so the keyword segment passes
        // through unchanged once module-prefixed.
        assert_eq!(module_value(&["Main"], "loop"), "main_loop");
        // A bare module value whose snake form is the keyword `type` PLUS the
        // empty-name separator (`type_`) has the reserved stem `type`, so the
        // injective mangle appends one more underscore (`type__`) — keeping it
        // provably disjoint from the mangle of the bare keyword `type`
        // (`type_`), which a different fold could produce.
        assert_eq!(module_value(&["Type"], ""), "type__");
        // The enum-name path routes its camel result through `mangle_reserved`:
        // a camel output that lands on the keyword `Self` is mangled to `Self_`.
        assert_eq!(super::mangle_reserved(to_camel_case("Self")), "Self_");
    }

    /// `mangle_reserved` is INJECTIVE over the reserved set ∪ its `<kw>_` shadow
    /// set: no two distinct inputs share an output. The historical hole was the
    /// keyword `match` mangling to `match_` while a user identifier literally
    /// spelled `match_` passed through unchanged — both `match_`, a silent
    /// collision. The `+_`-per-reserved-stem rule sends `match_` to `match__`.
    #[test]
    fn mangle_reserved_is_injective_over_reserved_and_shadows() {
        use std::collections::BTreeMap;

        let mut images: BTreeMap<String, String> = BTreeMap::new();
        let mut inputs: Vec<String> = Vec::new();
        for kw in ipe_intern::RUST_KEYWORDS {
            // The keyword, plus its 0..=3-underscore shadows.
            inputs.push((*kw).to_owned());
            inputs.push(format!("{kw}_"));
            inputs.push(format!("{kw}__"));
            inputs.push(format!("{kw}___"));
        }
        // Non-reserved control inputs that must pass through untouched.
        inputs.push("count".to_owned());
        inputs.push("match_x".to_owned());
        inputs.push("matchx_".to_owned());

        for input in inputs {
            let out = super::mangle_reserved(input.clone());
            if let Some(prev) = images.insert(out.clone(), input.clone()) {
                assert!(
                    false_marker(),
                    "mangle_reserved not injective: {prev:?} and {input:?} both fold to {out:?}"
                );
            }
        }
    }
}
