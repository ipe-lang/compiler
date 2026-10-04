//! Binary-operator fixity: the one table every consumer groups a chain by.
//!
//! The parser records an operator chain flat; name resolution re-associates it
//! and the formatter decides where a multiline chain may break. Both read
//! [`fixity`], so the two can never disagree about how an expression groups.

/// Operator associativity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Assoc {
    /// `a op b op c` groups as `(a op b) op c`.
    Left,
    /// `a op b op c` groups as `a op (b op c)`.
    Right,
    /// Equal-precedence neighbours do not chain associatively.
    None,
}

/// The precedence (higher binds tighter) and associativity of one operator.
///
/// Built only by [`fixity`], so every value is a row of the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fixity {
    prec: u8,
    assoc: Assoc,
}

impl Fixity {
    const fn new(prec: u8, assoc: Assoc) -> Self {
        Self { prec, assoc }
    }

    /// The binding strength; higher binds tighter.
    #[must_use]
    pub const fn prec(self) -> u8 {
        self.prec
    }

    /// The associativity.
    #[must_use]
    pub const fn assoc(self) -> Assoc {
        self.assoc
    }
}

/// The fixity of `op`.
///
/// Covers the core operator set; any other operator defaults to `9 L`, the
/// same catch-all the reference grammar uses.
#[must_use]
pub const fn fixity(op: &str) -> Fixity {
    match op.as_bytes() {
        b"*" | b"/" | b"//" | b"%" => Fixity::new(7, Assoc::Left),
        // `|.` (parser-pipeline discard, yields left's result) shares prec 6
        // left-assoc with arithmetic `+`/`-`.
        b"+" | b"-" | b"|." => Fixity::new(6, Assoc::Left),
        b"++" | b"::" => Fixity::new(5, Assoc::Right),
        // `|=` (parser-pipeline keep, yields right's result): prec 5 like
        // `++`/`::` but left-assoc. `a |= b |. c` groups as `a |= (b |. c)`
        // because `|.` at 6 is tighter.
        b"|=" => Fixity::new(5, Assoc::Left),
        b"==" | b"/=" | b"<" | b">" | b"<=" | b">=" => Fixity::new(4, Assoc::None),
        b"&&" => Fixity::new(3, Assoc::Right),
        b"||" => Fixity::new(2, Assoc::Right),
        // Pipes are the loosest operators: `x |> f |> g` = `(x |> f) |> g`,
        // `f <| g <| x` = `f <| (g <| x)`.
        b"|>" => Fixity::new(0, Assoc::Left),
        b"<|" => Fixity::new(0, Assoc::Right),
        // Composition is the tightest: `f << g << h` = `f << (g << h)`.
        // `>>` is left-assoc (`(f >> g) >> h`), which is the `9 L` catch-all.
        b"<<" => Fixity::new(9, Assoc::Right),
        _ => Fixity::new(9, Assoc::Left),
    }
}

#[cfg(test)]
mod tests {
    use super::{Assoc, fixity};

    #[test]
    fn core_operator_fixities() {
        let table: &[(&str, u8, Assoc)] = &[
            ("*", 7, Assoc::Left),
            ("/", 7, Assoc::Left),
            ("//", 7, Assoc::Left),
            ("%", 7, Assoc::Left),
            ("+", 6, Assoc::Left),
            ("-", 6, Assoc::Left),
            ("|.", 6, Assoc::Left),
            ("++", 5, Assoc::Right),
            ("::", 5, Assoc::Right),
            ("|=", 5, Assoc::Left),
            ("==", 4, Assoc::None),
            ("/=", 4, Assoc::None),
            ("<", 4, Assoc::None),
            (">", 4, Assoc::None),
            ("<=", 4, Assoc::None),
            (">=", 4, Assoc::None),
            ("&&", 3, Assoc::Right),
            ("||", 2, Assoc::Right),
            ("|>", 0, Assoc::Left),
            ("<|", 0, Assoc::Right),
            ("<<", 9, Assoc::Right),
            (">>", 9, Assoc::Left),
        ];
        for &(op, prec, assoc) in table {
            let f = fixity(op);
            assert_eq!((f.prec(), f.assoc()), (prec, assoc), "fixity of `{op}`");
        }
    }

    #[test]
    fn unknown_operator_defaults_to_nine_left() {
        for op in ["<?>", "</>", "&", "", "===", "+ "] {
            let f = fixity(op);
            assert_eq!((f.prec(), f.assoc()), (9, Assoc::Left), "fixity of `{op}`");
        }
    }
}
