//! Binary operators: the closed set and the one fixity table it groups by.
//!
//! The parser records an operator chain flat, each operator one [`BinOp`];
//! name resolution re-associates the chain from [`BinOp::fixity`]. The set is
//! closed: an operator text outside it has no [`BinOp`], so it has no fixity.

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
/// Built only by [`BinOp::fixity`], so every value is a row of the table.
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

/// Declares [`BinOp`], [`BinOp::ALL`] and [`BinOp::text`] from one list.
///
/// A variant cannot be missing from `ALL` or lack a source text.
macro_rules! closed_binops {
    ($($doc:literal, $variant:ident, $text:literal;)+) => {
        /// One binary operator of the surface language.
        ///
        /// The set is closed: every operator the parser accepts is one variant, and
        /// [`BinOp::ALL`] lists each variant once, in declaration order.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum BinOp {
            $(
                #[doc = $doc]
                $variant,
            )+
        }

        impl BinOp {
            /// Every operator, once each, in declaration order.
            pub const ALL: [Self; Self::COUNT] = [$(Self::$variant),+];

            const COUNT: usize = [$(Self::$variant),+].len();

            /// The operator's source text.
            #[must_use]
            pub const fn text(self) -> &'static str {
                match self {
                    $(Self::$variant => $text,)+
                }
            }
        }
    };
}

closed_binops! {
    "`*`", Mul, "*";
    "`/`", FloatDiv, "/";
    "`//`", IntDiv, "//";
    "`+`", Add, "+";
    "`-`", Sub, "-";
    "`|.`, the parser-pipeline ignorer (yields the left result).", ParserIgnorer, "|.";
    "`++`", Append, "++";
    "`::`", Cons, "::";
    "`|=`, the parser-pipeline keeper (yields the right result).", ParserKeeper, "|=";
    "`==`", Eq, "==";
    "`/=`", Neq, "/=";
    "`<`", Lt, "<";
    "`>`", Gt, ">";
    "`<=`", Le, "<=";
    "`>=`", Ge, ">=";
    "`&&`", And, "&&";
    "`||`", Or, "||";
    "`|>`", PipeRight, "|>";
    "`<|`", PipeLeft, "<|";
    "`<<`", ComposeLeft, "<<";
    "`>>`", ComposeRight, ">>";
}

impl BinOp {
    /// The operator spelled exactly `text`, or `None` outside the closed set.
    #[must_use]
    pub const fn from_text(text: &str) -> Option<Self> {
        let mut rest: &[Self] = &Self::ALL;
        while let [op, tail @ ..] = rest {
            if bytes_eq(op.text().as_bytes(), text.as_bytes()) {
                return Some(*op);
            }
            rest = tail;
        }
        None
    }

    /// The operator's precedence and associativity.
    #[must_use]
    pub const fn fixity(self) -> Fixity {
        match self {
            Self::Mul | Self::FloatDiv | Self::IntDiv => Fixity::new(7, Assoc::Left),
            // `|.` shares prec 6 left-assoc with arithmetic `+`/`-`.
            Self::Add | Self::Sub | Self::ParserIgnorer => Fixity::new(6, Assoc::Left),
            Self::Append | Self::Cons => Fixity::new(5, Assoc::Right),
            // `|=`: prec 5 like `++`/`::` but left-assoc. `a |= b |. c` groups as
            // `a |= (b |. c)` because `|.` at 6 is tighter.
            Self::ParserKeeper => Fixity::new(5, Assoc::Left),
            Self::Eq | Self::Neq | Self::Lt | Self::Gt | Self::Le | Self::Ge => {
                Fixity::new(4, Assoc::None)
            }
            Self::And => Fixity::new(3, Assoc::Right),
            Self::Or => Fixity::new(2, Assoc::Right),
            // Pipes are the loosest operators: `x |> f |> g` = `(x |> f) |> g`,
            // `f <| g <| x` = `f <| (g <| x)`.
            Self::PipeRight => Fixity::new(0, Assoc::Left),
            Self::PipeLeft => Fixity::new(0, Assoc::Right),
            // Composition is the tightest: `f << g << h` = `f << (g << h)`,
            // `f >> g >> h` = `(f >> g) >> h`.
            Self::ComposeLeft => Fixity::new(9, Assoc::Right),
            Self::ComposeRight => Fixity::new(9, Assoc::Left),
        }
    }
}

/// A compiled-source stdlib module an operator desugars into a call to.
///
/// Its path segments and its dotted name are built from one list by
/// `operator_module!`, so they cannot disagree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperatorModule {
    segments: &'static [&'static str],
    dotted: &'static str,
}

impl OperatorModule {
    /// The module path, one segment each (`["Ipe", "Parser"]`).
    #[must_use]
    pub const fn segments(self) -> &'static [&'static str] {
        self.segments
    }

    /// The module name as an `import` writes it (`Ipe.Parser`).
    #[must_use]
    pub const fn dotted(self) -> &'static str {
        self.dotted
    }
}

/// Builds an [`OperatorModule`] from its path segments.
macro_rules! operator_module {
    ($first:literal $(, $rest:literal)*) => {
        OperatorModule {
            segments: &[$first $(, $rest)*],
            dotted: concat!($first $(, ".", $rest)*),
        }
    };
}

/// The module `|=` and `|.` desugar into: the stdlib registry embeds it under
/// this name, and name resolution calls into it by this path.
pub const PARSER_OPERATOR_MODULE: OperatorModule = operator_module!("Ipe", "Parser");

/// `const`-context byte-exact slice equality (`<[u8]>::eq` is not `const`).
const fn bytes_eq(mut a: &[u8], mut b: &[u8]) -> bool {
    loop {
        match (a, b) {
            ([], []) => return true,
            ([x, a_tail @ ..], [y, b_tail @ ..]) if *x == *y => {
                a = a_tail;
                b = b_tail;
            }
            _ => return false,
        }
    }
}

/// `true` iff [`BinOp::ALL`] holds every variant once in declaration order,
/// no two texts are equal, and each text round-trips through
/// [`BinOp::from_text`].
const fn closed_set_round_trips() -> bool {
    let mut position = 0;
    let mut rest: &[BinOp] = &BinOp::ALL;
    while let [op, tail @ ..] = rest {
        if *op as usize != position {
            return false;
        }
        let mut others: &[BinOp] = tail;
        while let [other, others_tail @ ..] = others {
            if bytes_eq(op.text().as_bytes(), other.text().as_bytes()) {
                return false;
            }
            others = others_tail;
        }
        if !matches!(BinOp::from_text(op.text()), Some(found) if found as usize == *op as usize) {
            return false;
        }
        position += 1;
        rest = tail;
    }
    true
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if `BinOp::ALL` misses or repeats a variant, two operators share a text, or a text does not round-trip through `from_text` [ledger #boundary]
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    closed_set_round_trips(),
    "BinOp::ALL must list every variant once in order, with distinct texts that round-trip"
);

#[cfg(test)]
mod tests {
    use super::{Assoc, BinOp, PARSER_OPERATOR_MODULE, closed_set_round_trips};

    #[test]
    fn core_operator_fixities() {
        let table: &[(&str, u8, Assoc)] = &[
            ("*", 7, Assoc::Left),
            ("/", 7, Assoc::Left),
            ("//", 7, Assoc::Left),
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
        assert_eq!(table.len(), BinOp::ALL.len(), "every operator has a row");
        for &(text, prec, assoc) in table {
            let op = BinOp::from_text(text);
            assert!(op.is_some(), "`{text}` is an operator");
            let Some(op) = op else { return };
            let f = op.fixity();
            assert_eq!((f.prec(), f.assoc()), (prec, assoc), "fixity of `{text}`");
        }
    }

    #[test]
    fn unknown_operator_text_is_none() {
        for text in ["%", "<?>", "</>", "&", "", "===", "+ ", "|", "."] {
            assert_eq!(BinOp::from_text(text), None, "`{text}` is not an operator");
        }
    }

    #[test]
    fn closed_set_text_round_trips() {
        assert!(closed_set_round_trips());
        for op in BinOp::ALL {
            assert_eq!(BinOp::from_text(op.text()), Some(op), "`{}`", op.text());
        }
    }

    #[test]
    fn parser_operator_module_segments_spell_its_dotted_name() {
        assert_eq!(PARSER_OPERATOR_MODULE.segments(), ["Ipe", "Parser"]);
        assert_eq!(PARSER_OPERATOR_MODULE.dotted(), "Ipe.Parser");
    }
}
