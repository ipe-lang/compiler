//! Binary operators: the closed set and the one fixity table it groups by.
//!
//! The parser records an operator chain flat, each operator one [`BinOp`];
//! name resolution re-associates the chain from [`BinOp::fixity`]. The set is
//! closed: an operator text outside it has no [`BinOp`], so it has no fixity.
//! [`climb`] is the one precedence climbing, and [`chain_groups`] is the
//! grouping the formatter lays a chain out by; a test pins that every group is
//! a subtree [`climb`] builds.

use ipe_diagnostics::Located;

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

/// One precedence group of a flat operator chain.
///
/// Operand `i` sits left of operator `i`; operator `i` sits between operands
/// `i` and `i + 1`. A group spans operands `lo..=hi`, splits at every operator
/// of its minimum precedence, and each maximal run of tighter operators
/// between two splits is one child group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainGroup {
    lo: usize,
    hi: usize,
    splits: Vec<usize>,
    children: Vec<usize>,
}

impl ChainGroup {
    /// The index of the group's first operand.
    #[must_use]
    pub const fn lo(&self) -> usize {
        self.lo
    }

    /// The index of the group's last operand.
    #[must_use]
    pub const fn hi(&self) -> usize {
        self.hi
    }

    /// The operator indices the group splits at, left to right.
    #[must_use]
    pub fn splits(&self) -> &[usize] {
        &self.splits
    }

    /// The child groups' indices in [`ChainGroups::groups`], left to right.
    #[must_use]
    pub fn children(&self) -> &[usize] {
        &self.children
    }
}

/// The precedence group tree of one operator chain; group `0` is the root.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChainGroups {
    groups: Vec<ChainGroup>,
}

impl ChainGroups {
    /// Every group; a child always sits after its parent.
    #[must_use]
    pub fn groups(&self) -> &[ChainGroup] {
        &self.groups
    }

    /// The root group, or `None` for a chain with no operator.
    #[must_use]
    pub fn root(&self) -> Option<&ChainGroup> {
        self.groups.first()
    }

    /// The group at `index`.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&ChainGroup> {
        self.groups.get(index)
    }
}

/// The precedence group tree of the chain whose operators are `ops`.
///
/// Built iteratively from a work list. Each operator is a split of exactly
/// one group, so the work is linear in `ops.len()` times the number of
/// distinct precedences.
#[must_use]
pub fn chain_groups(ops: &[BinOp]) -> ChainGroups {
    let mut groups: Vec<ChainGroup> = Vec::new();
    if ops.is_empty() {
        return ChainGroups { groups };
    }
    groups.push(ChainGroup {
        lo: 0,
        hi: ops.len(),
        splits: Vec::new(),
        children: Vec::new(),
    });
    let mut work: Vec<usize> = vec![0];
    while let Some(index) = work.pop() {
        let Some(group) = groups.get(index) else {
            continue;
        };
        let (lo, hi) = (group.lo, group.hi);
        let range = ops.get(lo..hi).unwrap_or_default();
        let Some(min) = range.iter().map(|op| op.fixity().prec()).min() else {
            continue;
        };
        let splits: Vec<usize> = range
            .iter()
            .enumerate()
            .filter(|(_, op)| op.fixity().prec() == min)
            .map(|(offset, _)| lo + offset)
            .collect();
        let mut children = Vec::new();
        let mut start = lo;
        for end in splits.iter().copied().chain(std::iter::once(hi)) {
            if end > start {
                children.push(groups.len());
                work.push(groups.len());
                groups.push(ChainGroup {
                    lo: start,
                    hi: end,
                    splits: Vec::new(),
                    children: Vec::new(),
                });
            }
            start = end + 1;
        }
        if let Some(group) = groups.get_mut(index) {
            group.splits = splits;
            group.children = children;
        }
    }
    ChainGroups { groups }
}

/// Folds `first rest…` into one tree by precedence climbing.
///
/// Call-stack depth is O(1) in chain length: a `pending` heap-stack holds
/// reduce-deferred `(left, op, prec)` frames, so no native frame is opened per
/// operator. A left- or non-associative operator reduces a pending operator at
/// least as tight (`top_prec >= prec`); a right-associative one reduces only a
/// strictly tighter one (`top_prec > prec`), so equal precedences nest
/// rightward.
///
/// # Errors
///
/// Whatever `combine` returns, or `bug()` if the pending stack breaks its
/// invariant.
pub fn climb<T, E>(
    first: T,
    rest: impl Iterator<Item = (Located<BinOp>, T)>,
    mut combine: impl FnMut(T, Located<BinOp>, T) -> Result<T, E>,
    bug: impl Fn() -> E,
) -> Result<T, E> {
    let mut pending: Vec<(T, Located<BinOp>, u8)> = Vec::new();
    let mut left = first;
    for (op, next) in rest {
        let op_fixity = op.value.fixity();
        let prec = op_fixity.prec();
        while let Some(&(_, _, top_prec)) = pending.last() {
            let should_reduce = match op_fixity.assoc() {
                Assoc::Left | Assoc::None => top_prec >= prec,
                Assoc::Right => top_prec > prec,
            };
            if !should_reduce {
                break;
            }
            let (l, top_op, _) = pending.pop().ok_or_else(&bug)?;
            left = combine(l, top_op, left)?;
        }
        pending.push((left, op, prec));
        left = next;
    }
    // The rightmost operator was pushed last, so LIFO pops fold correctly.
    while let Some((l, op, _)) = pending.pop() {
        left = combine(l, op, left)?;
    }
    Ok(left)
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
    use ipe_diagnostics::{Located, Span};

    use super::{
        Assoc, BinOp, PARSER_OPERATOR_MODULE, chain_groups, climb, closed_set_round_trips,
    };

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

    /// Every chain of one to three operators over [`BinOp::ALL`].
    fn chains_up_to_three() -> Vec<Vec<BinOp>> {
        let mut chains: Vec<Vec<BinOp>> = Vec::new();
        let mut last: Vec<Vec<BinOp>> = vec![Vec::new()];
        for _ in 0..3 {
            let next: Vec<Vec<BinOp>> = last
                .iter()
                .flat_map(|chain| {
                    BinOp::ALL.iter().map(move |op| {
                        let mut longer = chain.clone();
                        longer.push(*op);
                        longer
                    })
                })
                .collect();
            chains.extend(next.iter().cloned());
            last = next;
        }
        chains
    }

    /// Every group's operand range is the range of a subtree `climb` builds.
    #[test]
    fn groups_are_climb_subtrees() {
        let chains = chains_up_to_three();
        assert_eq!(chains.len(), 21 + 21 * 21 + 21 * 21 * 21);
        for ops in &chains {
            let mut subtrees: Vec<(usize, usize)> = Vec::new();
            let leaves = ops
                .iter()
                .enumerate()
                .map(|(i, op)| (Located::new(Span::new(0, 0), *op), (i + 1, i + 1)));
            let tree = climb(
                (0, 0),
                leaves,
                |l: (usize, usize), _, r: (usize, usize)| {
                    subtrees.push((l.0, r.1));
                    Ok::<_, ()>((l.0, r.1))
                },
                || (),
            );
            assert_eq!(tree, Ok((0, ops.len())), "{ops:?}");
            let groups = chain_groups(ops);
            let mut split_count = 0;
            for group in groups.groups() {
                split_count += group.splits().len();
                assert!(
                    subtrees.contains(&(group.lo(), group.hi())),
                    "{ops:?}: group {}..={} is not a climb subtree of {subtrees:?}",
                    group.lo(),
                    group.hi()
                );
            }
            assert_eq!(
                split_count,
                ops.len(),
                "{ops:?}: each operator splits one group"
            );
        }
    }

    #[test]
    fn chain_groups_split_at_the_loosest_operator() {
        let groups = chain_groups(&[BinOp::And, BinOp::Gt, BinOp::Add, BinOp::And]);
        let root = groups.root();
        assert!(root.is_some());
        let Some(root) = root else { return };
        assert_eq!((root.lo(), root.hi(), root.splits()), (0, 4, &[0, 3][..]));
        let children: Vec<(usize, usize)> = root
            .children()
            .iter()
            .filter_map(|i| groups.get(*i))
            .map(|g| (g.lo(), g.hi()))
            .collect();
        assert_eq!(children, [(1, 3)]);
        assert!(chain_groups(&[]).root().is_none());
    }
}
