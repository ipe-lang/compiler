//! `#[cfg(...)]` classification shared by the runtime's `syn` source scans
//! (`no_ungated_dial.rs`, `no_panicking_print_macro.rs`).
//!
//! A node is pruned only when its `cfg` provably holds under `test` alone, so
//! an unrecognised shape keeps the node scanned: a scan built on these helpers
//! can turn red on an unexpected attribute, never vacuously green.

use syn::punctuated::Punctuated;
use syn::{Attribute, Expr, ImplItem, Item, Meta, Token, TraitItem};

/// Whether `predicate` can hold only when `test` is set.
///
/// `all(…)` needs every member, so one test-only member suffices; `any(…)` is
/// test-only only when every member is. `not(…)`, `feature = "test"`, and any
/// other shape are not proven test-only, so the node they gate is scanned.
fn test_only(predicate: &Meta) -> bool {
    match predicate {
        Meta::Path(path) => path.is_ident("test"),
        Meta::List(list) => {
            let members = list
                .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                .ok();
            if list.path.is_ident("all") {
                members.is_some_and(|m| m.iter().any(test_only))
            } else if list.path.is_ident("any") {
                members.is_some_and(|m| !m.is_empty() && m.iter().all(test_only))
            } else {
                false
            }
        }
        Meta::NameValue(_) => false,
    }
}

/// Whether one of `attrs` is a `#[cfg(…)]` that holds only under `test`.
pub fn cfg_test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg") && attr.parse_args::<Meta>().is_ok_and(|p| test_only(&p))
    })
}

/// The outer attributes of `item`.
pub fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(i) => &i.attrs,
        Item::Enum(i) => &i.attrs,
        Item::ExternCrate(i) => &i.attrs,
        Item::Fn(i) => &i.attrs,
        Item::ForeignMod(i) => &i.attrs,
        Item::Impl(i) => &i.attrs,
        Item::Macro(i) => &i.attrs,
        Item::Mod(i) => &i.attrs,
        Item::Static(i) => &i.attrs,
        Item::Struct(i) => &i.attrs,
        Item::Trait(i) => &i.attrs,
        Item::TraitAlias(i) => &i.attrs,
        Item::Type(i) => &i.attrs,
        Item::Union(i) => &i.attrs,
        Item::Use(i) => &i.attrs,
        _ => &[],
    }
}

/// The outer attributes of `item`.
pub fn impl_item_attrs(item: &ImplItem) -> &[Attribute] {
    match item {
        ImplItem::Const(i) => &i.attrs,
        ImplItem::Fn(i) => &i.attrs,
        ImplItem::Type(i) => &i.attrs,
        ImplItem::Macro(i) => &i.attrs,
        _ => &[],
    }
}

/// The outer attributes of `item`.
pub fn trait_item_attrs(item: &TraitItem) -> &[Attribute] {
    match item {
        TraitItem::Const(i) => &i.attrs,
        TraitItem::Fn(i) => &i.attrs,
        TraitItem::Type(i) => &i.attrs,
        TraitItem::Macro(i) => &i.attrs,
        _ => &[],
    }
}

/// The outer attributes of `expr`, for every expression kind that can carry one.
///
/// An expression kind missing here keeps its attributes unread, so a
/// `#[cfg(test)]` on it is not honoured and the expression stays scanned.
pub fn expr_attrs(expr: &Expr) -> &[Attribute] {
    match expr {
        Expr::Array(e) => &e.attrs,
        Expr::Assign(e) => &e.attrs,
        Expr::Async(e) => &e.attrs,
        Expr::Await(e) => &e.attrs,
        Expr::Binary(e) => &e.attrs,
        Expr::Block(e) => &e.attrs,
        Expr::Call(e) => &e.attrs,
        Expr::Closure(e) => &e.attrs,
        Expr::Field(e) => &e.attrs,
        Expr::ForLoop(e) => &e.attrs,
        Expr::If(e) => &e.attrs,
        Expr::Lit(e) => &e.attrs,
        Expr::Loop(e) => &e.attrs,
        Expr::Macro(e) => &e.attrs,
        Expr::Match(e) => &e.attrs,
        Expr::MethodCall(e) => &e.attrs,
        Expr::Paren(e) => &e.attrs,
        Expr::Path(e) => &e.attrs,
        Expr::Reference(e) => &e.attrs,
        Expr::Return(e) => &e.attrs,
        Expr::Struct(e) => &e.attrs,
        Expr::Try(e) => &e.attrs,
        Expr::Tuple(e) => &e.attrs,
        Expr::Unary(e) => &e.attrs,
        Expr::Unsafe(e) => &e.attrs,
        Expr::While(e) => &e.attrs,
        _ => &[],
    }
}
