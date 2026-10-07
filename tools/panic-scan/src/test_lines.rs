//! Line spans of the test-only items in a Rust source file.
//!
//! A text audit that must skip test code reads these spans instead of
//! counting braces, so a brace inside a string or comment can never end a test
//! region early or carry one past its item. A span holds only lines the test
//! item owns outright: a line it shares with any other token stays in scope.

use std::ops::RangeInclusive;

use proc_macro2::{LineColumn, Span};
use syn::token::{Brace, Semi};
use syn::visit::{self, Visit};
use syn::{Attribute, Fields, ForeignItem, ImplItem, Item, MacroDelimiter, TraitItem};

use crate::{
    attrs_test_only, foreign_item_test_only, impl_item_test_only, item_test_only,
    trait_item_test_only,
};

/// 1-based inclusive line spans of the test-only items in `src`.
///
/// An item is test-only as [`crate::scan_str`] judges one: a test-only
/// `#[cfg(…)]`; a bare `#[test]` is production. Each span runs from the item's
/// first attribute to its closing brace or semicolon. The first line is left
/// out when anything but whitespace precedes the attribute, and the last when
/// anything but whitespace follows the close, so a production token sharing a
/// line with a test item is never skipped; an item that owns no whole line
/// yields no span. A file whose inner attributes are test-only is one span over
/// every line. A test-only item whose end cannot be located yields no span, so
/// its lines stay in scope.
///
/// # Errors
///
/// [`syn::Error`] when `src` does not parse as a Rust file.
pub fn test_only_item_lines(src: &str) -> Result<Vec<RangeInclusive<usize>>, syn::Error> {
    let file = syn::parse_file(src)?;
    if attrs_test_only(&file.attrs) {
        let whole_file = 1..=src.lines().count().max(1);
        return Ok(vec![whole_file]);
    }
    let mut spans = TestSpans {
        lines: src.lines().collect(),
        spans: Vec::new(),
    };
    spans.visit_file(&file);
    Ok(spans.spans)
}

/// The source lines and the spans collected so far.
struct TestSpans<'src> {
    lines: Vec<&'src str>,
    spans: Vec<RangeInclusive<usize>>,
}

impl TestSpans<'_> {
    /// Record the lines the item from the first of `attrs` to `end` owns
    /// outright, when both exist.
    fn record(&mut self, attrs: &[Attribute], end: Option<LineColumn>) {
        let (Some(first), Some(end)) = (attrs.first(), end) else {
            return;
        };
        let [pound] = first.pound_token.spans;
        let start = pound.start();
        let first_line = if self.blank_before(start) {
            start.line
        } else {
            start.line.saturating_add(1)
        };
        let last_line = if self.blank_after(end) {
            end.line
        } else {
            end.line.saturating_sub(1)
        };
        if first_line <= last_line {
            self.spans.push(first_line..=last_line);
        }
    }

    /// Whether only whitespace precedes `at` on its line.
    fn blank_before(&self, at: LineColumn) -> bool {
        self.line_text(at.line)
            .is_some_and(|text| text.chars().take(at.column).all(char::is_whitespace))
    }

    /// Whether only whitespace follows `at` on its line.
    fn blank_after(&self, at: LineColumn) -> bool {
        self.line_text(at.line)
            .is_some_and(|text| text.chars().skip(at.column).all(char::is_whitespace))
    }

    /// The text of 1-based line `line`.
    fn line_text(&self, line: usize) -> Option<&str> {
        self.lines.get(line.checked_sub(1)?).copied()
    }
}

impl<'ast> Visit<'ast> for TestSpans<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        if item_test_only(item) {
            self.record(item_attrs(item), item_end(item));
        } else {
            visit::visit_item(self, item);
        }
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        if impl_item_test_only(item) {
            let (attrs, end) = match item {
                ImplItem::Const(i) => (&i.attrs, Some(semi_end(&i.semi_token))),
                ImplItem::Fn(i) => (&i.attrs, Some(brace_end(&i.block.brace_token))),
                ImplItem::Type(i) => (&i.attrs, Some(semi_end(&i.semi_token))),
                ImplItem::Macro(i) => (
                    &i.attrs,
                    Some(macro_end(i.semi_token.as_ref(), &i.mac.delimiter)),
                ),
                _ => return,
            };
            self.record(attrs, end);
        } else {
            visit::visit_impl_item(self, item);
        }
    }

    fn visit_trait_item(&mut self, item: &'ast TraitItem) {
        if trait_item_test_only(item) {
            let (attrs, end) = match item {
                TraitItem::Const(i) => (&i.attrs, Some(semi_end(&i.semi_token))),
                TraitItem::Fn(i) => (
                    &i.attrs,
                    i.default
                        .as_ref()
                        .map(|b| brace_end(&b.brace_token))
                        .or_else(|| i.semi_token.as_ref().map(semi_end)),
                ),
                TraitItem::Type(i) => (&i.attrs, Some(semi_end(&i.semi_token))),
                TraitItem::Macro(i) => (
                    &i.attrs,
                    Some(macro_end(i.semi_token.as_ref(), &i.mac.delimiter)),
                ),
                _ => return,
            };
            self.record(attrs, end);
        } else {
            visit::visit_trait_item(self, item);
        }
    }

    fn visit_foreign_item(&mut self, item: &'ast ForeignItem) {
        if foreign_item_test_only(item) {
            let (attrs, end) = match item {
                ForeignItem::Fn(i) => (&i.attrs, Some(semi_end(&i.semi_token))),
                ForeignItem::Static(i) => (&i.attrs, Some(semi_end(&i.semi_token))),
                ForeignItem::Type(i) => (&i.attrs, Some(semi_end(&i.semi_token))),
                ForeignItem::Macro(i) => (
                    &i.attrs,
                    Some(macro_end(i.semi_token.as_ref(), &i.mac.delimiter)),
                ),
                _ => return,
            };
            self.record(attrs, end);
        } else {
            visit::visit_foreign_item(self, item);
        }
    }
}

/// The outer attributes of `item`.
fn item_attrs(item: &Item) -> &[Attribute] {
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

/// Where `item` ends: just past its closing brace or semicolon.
fn item_end(item: &Item) -> Option<LineColumn> {
    Some(match item {
        Item::Const(i) => semi_end(&i.semi_token),
        Item::Enum(i) => brace_end(&i.brace_token),
        Item::ExternCrate(i) => semi_end(&i.semi_token),
        Item::Fn(i) => brace_end(&i.block.brace_token),
        Item::ForeignMod(i) => brace_end(&i.brace_token),
        Item::Impl(i) => brace_end(&i.brace_token),
        Item::Macro(i) => macro_end(i.semi_token.as_ref(), &i.mac.delimiter),
        Item::Mod(i) => match (&i.content, &i.semi) {
            (Some((brace, _)), _) => brace_end(brace),
            (None, semi) => semi_end(semi.as_ref()?),
        },
        Item::Static(i) => semi_end(&i.semi_token),
        Item::Struct(i) => match &i.fields {
            Fields::Named(named) => brace_end(&named.brace_token),
            Fields::Unnamed(_) | Fields::Unit => semi_end(i.semi_token.as_ref()?),
        },
        Item::Trait(i) => brace_end(&i.brace_token),
        Item::TraitAlias(i) => semi_end(&i.semi_token),
        Item::Type(i) => semi_end(&i.semi_token),
        Item::Union(i) => brace_end(&i.fields.brace_token),
        Item::Use(i) => semi_end(&i.semi_token),
        _ => return None,
    })
}

/// Where a macro invocation ends: past its semicolon, else its closing delimiter.
fn macro_end(semi: Option<&Semi>, delimiter: &MacroDelimiter) -> LineColumn {
    semi.map_or_else(
        || match delimiter {
            MacroDelimiter::Paren(d) => end_of(d.span.close()),
            MacroDelimiter::Brace(d) => end_of(d.span.close()),
            MacroDelimiter::Bracket(d) => end_of(d.span.close()),
        },
        semi_end,
    )
}

/// Where a closing brace ends.
fn brace_end(brace: &Brace) -> LineColumn {
    end_of(brace.span.close())
}

/// Where a semicolon ends.
fn semi_end(semi: &Semi) -> LineColumn {
    let [span] = semi.spans;
    end_of(span)
}

/// The 1-based line and 0-based character column just past `span`.
fn end_of(span: Span) -> LineColumn {
    span.end()
}

#[cfg(test)]
mod tests {
    use super::test_only_item_lines;

    /// The span set holding exactly `span`.
    fn one_span(span: std::ops::RangeInclusive<usize>) -> Vec<std::ops::RangeInclusive<usize>> {
        vec![span]
    }

    /// Test-only items span attribute to close, and a brace in a string never moves the end.
    #[test]
    fn spans_run_from_the_attribute_to_the_item_end() {
        let src = "fn prod() {}\n\
                   #[cfg(test)]\n\
                   mod tests {\n\
                       const S: &str = \"}\";\n\
                       fn t() {}\n\
                   }\n\
                   fn after() {}\n\
                   #[cfg(all(test, unix))]\n\
                   use std::io;\n\
                   #[test]\n\
                   fn bare() {}\n\
                   #[cfg(any(test, feature = \"x\"))]\n\
                   fn maybe_prod() {}\n";
        assert_eq!(test_only_item_lines(src).ok(), Some(vec![2..=6, 8..=9]));
    }

    /// Test-only impl items are spanned inside a production impl.
    #[test]
    fn test_only_impl_items_are_spanned() {
        let src = "struct S;\nimpl S {\n    fn p() {}\n    #[cfg(test)]\n    fn t() {\n    }\n}\n";
        assert_eq!(test_only_item_lines(src).ok(), Some(one_span(4..=6)));
    }

    /// A test-only file is one span; an unparsable one is an error, never an empty span set.
    #[test]
    fn a_test_only_file_is_whole_and_garbage_is_refused() {
        assert_eq!(
            test_only_item_lines("#![cfg(test)]\nfn a() {}\nfn b() {}\n").ok(),
            Some(one_span(1..=3))
        );
        assert!(test_only_item_lines("fn (").is_err());
    }

    /// A line a test item shares with any other token is never in a span, so
    /// the production code on it stays audited.
    #[test]
    fn a_line_mixing_test_and_production_tokens_is_refused_a_span() {
        let head = "fn prod() { let _ = 1; } #[cfg(test)]\n\
                    mod tests {\n\
                        fn t() {}\n\
                    }\n";
        assert_eq!(test_only_item_lines(head).ok(), Some(one_span(2..=4)));
        let tail = "#[cfg(test)]\n\
                    mod tests {\n\
                        fn t() {}\n\
                    } fn prod() {}\n";
        assert_eq!(test_only_item_lines(tail).ok(), Some(one_span(1..=3)));
        let one_line = "#[cfg(test)] fn t() {} fn prod() {}\n";
        assert_eq!(test_only_item_lines(one_line).ok(), Some(vec![]));
        let alone = "  #[cfg(test)] fn t() {}  \n";
        assert_eq!(test_only_item_lines(alone).ok(), Some(one_span(1..=1)));
    }
}
