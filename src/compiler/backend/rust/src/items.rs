//! The single item-separator authority for emitted Rust source.
//!
//! Every module-scope item (an `enum`, `struct`, `impl`, `trait`, `fn`, a
//! comment-led section, the fixed preamble/prelude/epilogue blocks) reaches an
//! emitted `.rs` file through [`Items`], which lays them out separated by exactly
//! one blank line — the `rustfmt` item spacing — and skips an empty part by
//! construction. No emitter spaces adjacent items by hand, so a missing or a
//! doubled blank line between two items has no representation.

/// An ordered run of emitted Rust items, rendered one blank line apart.
#[derive(Debug, Default)]
pub struct Items {
    parts: Vec<String>,
}

impl Items {
    /// An empty run.
    #[must_use]
    pub const fn new() -> Self {
        Self { parts: Vec::new() }
    }

    /// Append one item (or an already-rendered run of items).
    ///
    /// Leading and trailing newlines are the joiner's to place, so they are
    /// trimmed; an item that is empty after trimming is skipped, so an empty
    /// section leaves no stray blank line.
    pub fn push(&mut self, item: &str) {
        let trimmed = item.trim_matches('\n');
        if !trimmed.is_empty() {
            self.parts.push(trimmed.to_owned());
        }
    }

    /// The items joined one blank line apart, ending in a single newline; the
    /// empty string when no item was pushed.
    #[must_use]
    pub fn render(&self) -> String {
        if self.parts.is_empty() {
            return String::new();
        }
        let mut out = self.parts.join("\n\n");
        out.push('\n');
        out
    }
}

/// A braced item `head { … }` whose body lines sit between the braces, or
/// `head {}` when the body is empty — never a brace pair around a blank line.
#[must_use]
pub fn braced(head: &str, body: &str) -> String {
    if body.is_empty() {
        format!("{head} {{}}")
    } else {
        format!("{head} {{\n{body}\n}}")
    }
}

#[cfg(test)]
mod tests {
    use super::{Items, braced};

    #[test]
    fn a_braced_item_with_no_body_closes_on_its_own_line() {
        assert_eq!(braced("pub struct Rec_", ""), "pub struct Rec_ {}");
        assert_eq!(
            braced("pub struct Rec", "    a: i64,"),
            "pub struct Rec {\n    a: i64,\n}"
        );
    }

    #[test]
    fn items_are_separated_by_exactly_one_blank_line() {
        let mut items = Items::new();
        items.push("enum A {}\n");
        items.push("impl A {}\n");
        assert_eq!(items.render(), "enum A {}\n\nimpl A {}\n");
    }

    #[test]
    fn surrounding_newlines_are_the_joiners_to_place() {
        let mut items = Items::new();
        items.push("\n\nfn a() {}\n\n\n");
        items.push("fn b() {}");
        assert_eq!(items.render(), "fn a() {}\n\nfn b() {}\n");
    }

    #[test]
    fn an_empty_item_leaves_no_blank_line() {
        let mut items = Items::new();
        items.push("fn a() {}\n");
        items.push("");
        items.push("\n\n");
        items.push("fn b() {}\n");
        assert_eq!(items.render(), "fn a() {}\n\nfn b() {}\n");
    }

    #[test]
    fn an_empty_run_renders_nothing() {
        let mut items = Items::new();
        items.push("\n");
        assert_eq!(items.render(), "");
    }

    #[test]
    fn interior_blank_lines_of_an_item_are_kept() {
        // A string literal inside an item may hold blank lines or a column-0
        // `}`; the joiner never rewrites an item's interior.
        let mut items = Items::new();
        items.push("const S: &str = \"a\n\n}\nb\";\n");
        assert_eq!(items.render(), "const S: &str = \"a\n\n}\nb\";\n");
    }
}
