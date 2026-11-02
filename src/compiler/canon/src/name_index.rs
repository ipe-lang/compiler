//! The resolved-name index: every name occurrence the resolver resolved, by span.
//!
//! The resolver is the one place that knows what each spelling means, so it
//! records every resolution it makes into a [`NameSink`] at the moment it makes
//! it. A later reader (go-to-definition, hover, references) asks the finished
//! [`NameIndex`] instead of re-walking the canonical AST and re-deriving scope:
//! one fact, recorded once, at its source.
//!
//! - A top-level name or an import maps to its declaring module and name.
//! - A constructor maps to its type's home, its type and its name.
//! - A local maps to the span of the binder that introduced it ([`BinderSite`]).
//! - A kernel maps to its registry entry and, when an Ipê module declares the
//!   alias, that module and name; a kernel-only function has no declaration.
//!
//! - A top-level value whose declaration failed maps to [`Target::Poisoned`].
//!
//! Two different targets recorded at one span leave that span ambiguous, and
//! an ambiguous span answers nothing rather than either target.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry as MapEntry;

use ipe_diagnostics::Span;
use ipe_intern::Symbol;
use ipe_kernels::StdlibKernel;

/// Where a lexical binder was introduced.
///
/// A binder with a real source span is a location; a binder the compiler
/// synthesised (a zero-width or dummy span) is never one, so no reader can
/// navigate to a place the user never wrote.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BinderSite(Site);

/// The two binder origins [`BinderSite`] keeps private.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Site {
    /// A binder the user wrote, at this span.
    At(Span),
    /// A binder with no source text.
    Synthetic,
}

impl BinderSite {
    /// The site of a binder introduced at `span`.
    ///
    /// A zero-width span (the dummy span included) names no source text, so
    /// it yields the synthetic site.
    #[must_use]
    pub const fn of(span: Span) -> Self {
        if span.lo < span.hi {
            Self(Site::At(span))
        } else {
            Self(Site::Synthetic)
        }
    }

    /// The binder's source span, or `None` for a synthesised binder.
    #[must_use]
    pub const fn location(self) -> Option<Span> {
        match self.0 {
            Site::At(span) => Some(span),
            Site::Synthetic => None,
        }
    }
}

/// A declaration: the module that declares a name, and the name.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DeclHome {
    /// The declaring module's path.
    pub module: Vec<Symbol>,
    /// The declared name.
    pub name: Symbol,
}

/// What one name occurrence resolved to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Target {
    /// A top-level value of a module.
    TopLevel {
        /// The declaring module's path.
        home: Vec<Symbol>,
        /// The value's name.
        name: Symbol,
    },
    /// A data constructor, used as a value or in a pattern.
    Ctor {
        /// The path of the module declaring the constructor's type.
        home: Vec<Symbol>,
        /// The constructor's type.
        type_name: Symbol,
        /// The constructor's name.
        name: Symbol,
    },
    /// A lexical binder.
    Local(BinderSite),
    /// A stdlib kernel.
    Kernel {
        /// The backing registry entry; `None` for a reachable member with no
        /// backing kernel.
        id: Option<StdlibKernel>,
        /// The Ipê declaration aliasing the kernel, when the occurrence reached
        /// it through one; `None` for a kernel-only function.
        declared: Option<DeclHome>,
    },
    /// A top-level value whose declaration failed to resolve.
    ///
    /// The occurrence names no declaration a reader may show: it answers
    /// nothing, and never the target an import of the same name would give.
    Poisoned,
}

/// One span's recorded answer.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Slot {
    /// Exactly one target was recorded at the span.
    One(Target),
    /// Two different targets were recorded at the span.
    Ambiguous,
}

/// The recorder the resolver writes every resolution into.
///
/// Built empty, filled while one module resolves, and closed by
/// [`NameSink::finish`] into the read-only [`NameIndex`].
#[derive(Debug, Default)]
pub struct NameSink {
    by_span: BTreeMap<Span, Slot>,
}

impl NameSink {
    /// An empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that the occurrence at `span` resolved to `target`.
    ///
    /// A zero-width span names no source text and is not recorded. Recording
    /// the same target twice is one entry; recording a different target at a
    /// span already holding one makes the span ambiguous, whichever came first.
    pub fn record(&mut self, span: Span, target: Target) {
        if span.lo >= span.hi {
            return;
        }
        match self.by_span.entry(span) {
            MapEntry::Vacant(slot) => {
                slot.insert(Slot::One(target));
            }
            MapEntry::Occupied(mut slot) => {
                if !matches!(slot.get(), Slot::One(held) if *held == target) {
                    slot.insert(Slot::Ambiguous);
                }
            }
        }
    }

    /// Close the sink into the index it recorded.
    #[must_use]
    pub fn finish(self) -> NameIndex {
        NameIndex {
            by_span: self.by_span,
        }
    }
}

/// Every resolved name occurrence of one module, by its source span.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct NameIndex {
    by_span: BTreeMap<Span, Slot>,
}

impl NameIndex {
    /// The target of the occurrence spanning exactly `span`.
    ///
    /// `None` when nothing resolved there or when the span is ambiguous.
    #[must_use]
    pub fn get(&self, span: Span) -> Option<&Target> {
        match self.by_span.get(&span) {
            Some(Slot::One(target)) => Some(target),
            Some(Slot::Ambiguous) | None => None,
        }
    }

    /// The innermost recorded occurrence containing byte `offset`.
    ///
    /// An occurrence contains the offsets from its start up to, not
    /// including, its end. When the innermost one is ambiguous, or two partly
    /// overlapping occurrences of one width tie for innermost, the answer is
    /// `None`: an enclosing occurrence never stands in for it.
    #[must_use]
    pub fn at(&self, offset: u32) -> Option<(Span, &Target)> {
        let upper = Span {
            lo: offset,
            hi: u32::MAX,
        };
        let mut innermost: Option<(Span, &Slot)> = None;
        let mut tied = false;
        for (span, slot) in self
            .by_span
            .range(..=upper)
            .filter(|(span, _)| offset < span.hi)
        {
            let width = span.hi.saturating_sub(span.lo);
            match innermost.map(|(held, _)| held.hi.saturating_sub(held.lo)) {
                Some(held) if width > held => {}
                Some(held) if width == held => tied = true,
                Some(_) | None => {
                    innermost = Some((*span, slot));
                    tied = false;
                }
            }
        }
        match innermost? {
            (span, Slot::One(target)) if !tied => Some((span, target)),
            (_, Slot::One(_) | Slot::Ambiguous) => None,
        }
    }

    /// Every unambiguous occurrence, in span order.
    pub fn entries(&self) -> impl Iterator<Item = (Span, &Target)> {
        self.by_span.iter().filter_map(|(span, slot)| match slot {
            Slot::One(target) => Some((*span, target)),
            Slot::Ambiguous => None,
        })
    }

    /// Mark every top-level occurrence of a failed declaration as poisoned.
    ///
    /// `failed` answers whether the value `name` of module `home` failed; each
    /// [`Target::TopLevel`] it holds for becomes [`Target::Poisoned`].
    pub fn poison(&mut self, failed: impl Fn(&[Symbol], Symbol) -> bool) {
        for slot in self.by_span.values_mut() {
            if let Slot::One(Target::TopLevel { home, name }) = slot
                && failed(home, *name)
            {
                *slot = Slot::One(Target::Poisoned);
            }
        }
    }

    /// The number of recorded spans, ambiguous ones included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_span.len()
    }

    /// Whether nothing was recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_span.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sym(n: u32) -> Symbol {
        Symbol::from_raw(n)
    }

    fn top(n: u32) -> Target {
        Target::TopLevel {
            home: vec![sym(1)],
            name: sym(n),
        }
    }

    #[test]
    fn a_synthetic_binder_is_never_a_location() {
        assert_eq!(BinderSite::of(Span::DUMMY).location(), None);
        assert_eq!(BinderSite::of(Span { lo: 7, hi: 7 }).location(), None);
        let real = Span { lo: 3, hi: 5 };
        assert_eq!(BinderSite::of(real).location(), Some(real));
    }

    #[test]
    fn two_targets_at_one_span_answer_nothing_in_either_order() {
        let span = Span { lo: 10, hi: 14 };
        for (first, second) in [(top(2), top(3)), (top(3), top(2))] {
            let mut sink = NameSink::new();
            sink.record(span, first);
            sink.record(span, second);
            let index = sink.finish();
            assert_eq!(index.get(span), None);
            assert_eq!(index.at(11), None);
            assert_eq!(index.entries().count(), 0);
        }
    }

    #[test]
    fn the_same_target_twice_stays_one_answer() {
        let span = Span { lo: 10, hi: 14 };
        let mut sink = NameSink::new();
        sink.record(span, top(2));
        sink.record(span, top(2));
        assert_eq!(sink.finish().get(span), Some(&top(2)));
    }

    #[test]
    fn an_ambiguous_span_stays_ambiguous_after_a_third_record() {
        let span = Span { lo: 10, hi: 14 };
        let mut sink = NameSink::new();
        sink.record(span, top(2));
        sink.record(span, top(3));
        sink.record(span, top(2));
        assert_eq!(sink.finish().get(span), None);
    }

    #[test]
    fn a_zero_width_span_is_never_recorded() {
        let mut sink = NameSink::new();
        sink.record(Span::DUMMY, top(2));
        sink.record(Span { lo: 4, hi: 4 }, top(2));
        assert!(sink.finish().is_empty());
    }

    #[test]
    fn the_innermost_occurrence_answers_and_an_ambiguous_one_never_falls_through() {
        let outer = Span { lo: 0, hi: 20 };
        let inner = Span { lo: 5, hi: 8 };
        let mut sink = NameSink::new();
        sink.record(outer, top(2));
        sink.record(inner, top(3));
        let index = sink.finish();
        assert_eq!(index.at(6), Some((inner, &top(3))));
        assert_eq!(index.at(1), Some((outer, &top(2))));
        assert_eq!(index.at(8), Some((outer, &top(2))));
        assert_eq!(index.at(20), None);

        let mut sink = NameSink::new();
        sink.record(outer, top(2));
        sink.record(inner, top(3));
        sink.record(inner, top(4));
        let index = sink.finish();
        assert_eq!(index.at(6), None);
    }

    #[test]
    fn two_partly_overlapping_occurrences_of_one_width_answer_nothing_where_they_meet() {
        let left = Span { lo: 0, hi: 5 };
        let right = Span { lo: 3, hi: 8 };
        let mut sink = NameSink::new();
        sink.record(left, top(2));
        sink.record(right, top(3));
        let index = sink.finish();
        assert_eq!(index.at(4), None);
        assert_eq!(index.at(1), Some((left, &top(2))));
        assert_eq!(index.at(6), Some((right, &top(3))));
    }
}

#[cfg(test)]
mod resolver_tests {
    use std::collections::BTreeMap;

    use ipe_diagnostics::Span;
    use ipe_intern::{Interner, Symbol};
    use ipe_kernels::StdlibKernel;

    use super::{BinderSite, DeclHome, NameIndex, Target};
    use crate::{
        ModuleCatalog, ModuleExports, ModuleOrigin, canonicalise_module_in_project,
        canonicalise_module_indexed,
    };

    type Outcome = Result<(), String>;

    /// Canonicalise `deps` in order, then `main`; the index of `main`.
    ///
    /// Every module sees the exports of each one before it. `main` is also
    /// canonicalised without the index, and the two modules must be equal.
    fn index_of(
        deps: &[(&str, ModuleOrigin)],
        main: &str,
    ) -> Result<(NameIndex, Interner), String> {
        let mut interner = Interner::new();
        let catalog = ModuleCatalog::new(["Lib", "Ipe.Task", "Ipe.Tally"].map(Box::<str>::from));
        let mut exports: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();
        for (src, origin) in deps {
            let parsed =
                ipe_parse::parse_module(src, &mut interner).map_err(|e| format!("{e:?}"))?;
            let expected = parsed.name.value.clone();
            let borrowed = exports.iter().map(|(k, v)| (k.clone(), v)).collect();
            let (_, module_exports, _) = canonicalise_module_indexed(
                &parsed,
                &expected,
                &borrowed,
                &catalog,
                *origin,
                &mut interner,
            )
            .map_err(|e| format!("{e:?}"))?;
            exports.insert(module_exports.path.clone(), module_exports);
        }
        let parsed = ipe_parse::parse_module(main, &mut interner).map_err(|e| format!("{e:?}"))?;
        let expected = parsed.name.value.clone();
        let borrowed: BTreeMap<Vec<Symbol>, &ModuleExports> =
            exports.iter().map(|(k, v)| (k.clone(), v)).collect();
        let (module, _, names) = canonicalise_module_indexed(
            &parsed,
            &expected,
            &borrowed,
            &catalog,
            ModuleOrigin::User,
            &mut interner,
        )
        .map_err(|e| format!("{e:?}"))?;
        let (unindexed, _) = canonicalise_module_in_project(
            &parsed,
            &expected,
            &borrowed,
            &catalog,
            ModuleOrigin::User,
            &mut interner,
        )
        .map_err(|e| format!("{e:?}"))?;
        // Recording the index never changes the module it is recorded from.
        if module != unindexed {
            return Err("the indexed module differs from the unindexed one".into());
        }
        Ok((names, interner))
    }

    /// The span of the `nth` (from zero) occurrence of `needle` in `src`.
    fn span_of(src: &str, needle: &str, nth: usize) -> Result<Span, String> {
        let missing = || format!("{needle} #{nth} not in source");
        let (lo, _) = src.match_indices(needle).nth(nth).ok_or_else(missing)?;
        let lo = u32::try_from(lo).map_err(|e| e.to_string())?;
        let len = u32::try_from(needle.len()).map_err(|e| e.to_string())?;
        let hi = lo.checked_add(len).ok_or_else(missing)?;
        Ok(Span { lo, hi })
    }

    /// The local target whose binder is `needle`'s `nth` occurrence.
    fn local_at(src: &str, needle: &str, nth: usize) -> Result<Target, String> {
        Ok(Target::Local(BinderSite::of(span_of(src, needle, nth)?)))
    }

    fn intern(interner: &mut Interner, text: &str) -> Result<Symbol, String> {
        interner.intern(text).map_err(|e| format!("{e:?}"))
    }

    fn path(interner: &mut Interner, segments: &[&str]) -> Result<Vec<Symbol>, String> {
        segments.iter().map(|s| intern(interner, s)).collect()
    }

    const LOCALS: &str = "module Main exposing (Shape(..), area, pick)\n\n\
                          type Shape\n    = Circle Int\n    | Square Int\n\n\
                          area : Shape -> Int\n\
                          area shape =\n    case shape of\n        \
                          Circle rad | Square rad ->\n            rad\n\n\
                          pick : { size : Int } -> Int\n\
                          pick { size } =\n    let\n        doubled =\n            size\n    \
                          in\n    case doubled of\n        (whole as alias) ->\n            alias\n";

    #[test]
    fn every_local_use_answers_its_binder() -> Outcome {
        let (index, _) = index_of(&[], LOCALS)?;
        // (needle, binder occurrence, use occurrence)
        let cases = [
            ("shape", 0, 1),
            ("size", 1, 2),
            ("doubled", 0, 1),
            ("alias", 0, 1),
        ];
        for (needle, binder, used) in cases {
            let expected = local_at(LOCALS, needle, binder)?;
            let use_span = span_of(LOCALS, needle, used)?;
            assert_eq!(index.get(use_span), Some(&expected), "{needle}");
        }
        Ok(())
    }

    #[test]
    fn a_later_or_alternative_answers_the_first_alternatives_binder() -> Outcome {
        let (index, _) = index_of(&[], LOCALS)?;
        let first = local_at(LOCALS, "rad", 0)?;
        for occurrence in [1, 2] {
            let span = span_of(LOCALS, "rad", occurrence)?;
            assert_eq!(index.get(span), Some(&first), "rad #{occurrence}");
        }
        Ok(())
    }

    #[test]
    fn a_constructor_occurrence_answers_its_declaration() -> Outcome {
        let (index, mut interner) = index_of(&[], LOCALS)?;
        let expected = Target::Ctor {
            home: path(&mut interner, &["Main"])?,
            type_name: intern(&mut interner, "Shape")?,
            name: intern(&mut interner, "Circle")?,
        };
        let pattern = span_of(LOCALS, "Circle rad", 0)?;
        assert_eq!(index.get(pattern), Some(&expected));
        Ok(())
    }

    const LIB: &str = "module Lib exposing (total)\n\ntotal : Int -> Int\ntotal n =\n    n\n";

    const TASK_STUB: &str =
        "module Ipe.Task exposing (succeed)\n\nsucceed : a -> a\nsucceed v =\n    v\n";

    const DO_MAIN: &str = "module Main exposing (main)\n\n\
                           import Ipe.Task\nimport Lib\n\n\
                           main : Int\n\
                           main =\n    do\n        step <- Task.succeed 1\n        \
                           Lib.total step\n";

    #[test]
    fn a_cross_module_occurrence_inside_do_answers_its_declaration() -> Outcome {
        let deps = [
            (TASK_STUB, ModuleOrigin::EmbeddedStdlib),
            (LIB, ModuleOrigin::User),
        ];
        let (index, mut interner) = index_of(&deps, DO_MAIN)?;
        let expected = Target::TopLevel {
            home: path(&mut interner, &["Lib"])?,
            name: intern(&mut interner, "total")?,
        };
        assert_eq!(
            index.get(span_of(DO_MAIN, "Lib.total", 0)?),
            Some(&expected)
        );
        let bound = local_at(DO_MAIN, "step", 0)?;
        assert_eq!(index.get(span_of(DO_MAIN, "step", 1)?), Some(&bound));
        Ok(())
    }

    const INTERPOLATED: &str = "module Main exposing (greet)\n\n\
                                greet : String -> String\n\
                                greet who =\n    \"\"\"hi {{who}} there\"\"\"\n";

    #[test]
    fn an_interpolated_name_is_never_answered_across_its_whole_string() -> Outcome {
        let (index, _) = index_of(&[], INTERPOLATED)?;
        let string = span_of(INTERPOLATED, "\"\"\"hi {{who}} there\"\"\"", 0)?;
        assert_eq!(index.get(string), None);
        let literal = span_of(INTERPOLATED, "hi ", 0)?;
        assert_eq!(index.at(literal.lo), None);
        // The binder itself is still recorded at its own span.
        let binder = local_at(INTERPOLATED, "who", 0)?;
        assert_eq!(index.get(span_of(INTERPOLATED, "who", 0)?), Some(&binder));
        Ok(())
    }

    const TALLY: &str = "module Ipe.Tally exposing (digest)\n\n\
                         import Ipe.Ffi.Kernel as Kernel\n\n\
                         digest : String -> String\n\
                         digest = Kernel.kernel \"Crypto_sha256\"\n";

    const KERNEL_MAIN: &str = "module Main exposing (a, b, c)\n\n\
                               import Ipe.Crypto\nimport Ipe.Tally exposing (digest)\n\n\
                               a : String\na =\n    Tally.digest \"x\"\n\n\
                               b : String\nb =\n    digest \"y\"\n\n\
                               c : String\nc =\n    Crypto.sha256 \"z\"\n";

    #[test]
    fn a_kernel_occurrence_answers_its_declaring_stdlib_module() -> Outcome {
        let deps = [(TALLY, ModuleOrigin::EmbeddedStdlib)];
        let (index, mut interner) = index_of(&deps, KERNEL_MAIN)?;
        let declared = Target::Kernel {
            id: Some(StdlibKernel::CryptoSha256),
            declared: Some(DeclHome {
                module: path(&mut interner, &["Ipe", "Tally"])?,
                name: intern(&mut interner, "digest")?,
            }),
        };
        let qualified = span_of(KERNEL_MAIN, "Tally.digest", 0)?;
        assert_eq!(index.get(qualified), Some(&declared));
        // Occurrence 0 is the import's exposing list, 1 is inside `Tally.digest`.
        let bare = span_of(KERNEL_MAIN, "digest", 2)?;
        assert_eq!(index.get(bare), Some(&declared));
        // A kernel-qualifier module has no Ipê declaration to answer.
        let kernel_only = span_of(KERNEL_MAIN, "Crypto.sha256", 0)?;
        let expected = Target::Kernel {
            id: Some(StdlibKernel::CryptoSha256),
            declared: None,
        };
        assert_eq!(index.get(kernel_only), Some(&expected));
        Ok(())
    }
}
