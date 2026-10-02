#![forbid(unsafe_code)]
use std::collections::{BTreeSet, HashMap};

use ipe_diagnostics::{DResult, Diagnostic};

mod rust_keywords;
mod rust_literal;
pub use rust_keywords::{RUST_KEYWORDS, is_rust_keyword};
pub use rust_literal::rust_str_lit;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Symbol(u32);

impl Symbol {
    /// Construct a `Symbol` from a raw index.
    ///
    /// # Invariant
    ///
    /// `n` MUST be an index previously handed out by an [`Interner::intern`]
    /// call on the *same* interner. A raw value that was never interned (a
    /// forged or cross-interner symbol) resolves to `None`, NOT to a silent
    /// empty string — see [`Interner::resolve`]. Prefer `intern` for any
    /// symbol you intend to resolve later; reach for `from_raw` only for
    /// stable sentinel encodings where the invariant is locally obvious.
    #[must_use]
    pub const fn from_raw(n: u32) -> Self {
        Self(n)
    }
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        self.0
    }
}

#[derive(Default)]
pub struct Interner {
    /// One shared `Arc<str>` per unique string, stored in BOTH `map` (as the
    /// key) and `strings` (as the id-indexed entry) — the second store is a
    /// refcount bump, not a second heap copy. `Arc` (not
    /// `Rc`) keeps `Interner: Send + Sync`.
    map: HashMap<std::sync::Arc<str>, Symbol>,
    strings: Vec<std::sync::Arc<str>>,
    /// When set, [`Self::fresh_symbols`] avoids exactly the names in this set
    /// instead of every already-interned string — see the incremental-build
    /// determinism note on that method. Set per build via
    /// [`Self::set_fresh_avoid`]; `None` uses the
    /// whole-table behaviour for callers that own a per-build interner.
    fresh_avoid: Option<BTreeSet<String>>,
}

impl Interner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern a string, returning its stable [`Symbol`].
    ///
    /// # Errors
    ///
    /// Returns [`Diagnostic::CompilerBug`] when the symbol table is exhausted
    /// — i.e. when `u32::MAX` distinct identifiers have already been interned.
    /// This guards against silently aliasing a new identifier onto
    /// `u32::MAX` (the saturating bug the old `unwrap_or` hid).
    pub fn intern(&mut self, s: &str) -> DResult<Symbol> {
        if let Some(&sym) = self.map.get(s) {
            return Ok(sym);
        }
        let id = u32::try_from(self.strings.len()).map_err(|_| Diagnostic::CompilerBug {
            where_: "intern",
            detail: "symbol table exhausted (u32::MAX identifiers)".to_owned(),
        })?;
        let sym = Symbol(id);
        let shared: std::sync::Arc<str> = std::sync::Arc::from(s);
        self.strings.push(std::sync::Arc::clone(&shared));
        self.map.insert(shared, sym);
        Ok(sym)
    }

    /// Mint `count` fresh symbols whose resolved strings are guaranteed to be
    /// distinct from one another *and* from every user identifier.
    ///
    /// Each name is `<prefix><n>` for the smallest run of `n` (from `0`) whose
    /// candidate does not collide, so the result can never alias a user
    /// identifier nor a previously minted fresh symbol of the same pool. The
    /// lowerer uses this for eta-expansion parameter names, which must not
    /// capture any name free in the supplied arguments.
    ///
    /// **Collision universe** — two modes:
    ///
    /// - [`Self::set_fresh_avoid`] set (the incremental driver path): a
    ///   candidate collides IFF it is in the avoid set — the identifier words
    ///   of the *current program*, a pure function of the build's source
    ///   inputs. This keeps the minted names deterministic on a **warm**
    ///   (reused) interner: names minted by a previous build's lowering are
    ///   NOT collisions (re-minting `eta_0` returns the same append-only
    ///   symbol), so a rebuild emits the same names a cold build would.
    /// - unset (per-build interners: unit tests, direct embedders): the
    ///   historical whole-table behaviour — any interned string collides.
    ///   Equivalent to the avoid-set mode on a cold interner, where every
    ///   interned string came from this build.
    ///
    /// # Errors
    ///
    /// Returns [`Diagnostic::CompilerBug`] when the `u32` suffix space is
    /// exhausted before `count` fresh names are found, or when [`Self::intern`]
    /// itself reports the symbol table full — both unreachable for any real
    /// program.
    pub fn fresh_symbols(&mut self, prefix: &str, count: usize) -> DResult<Vec<Symbol>> {
        let mut out = Vec::with_capacity(count);
        let mut n: u32 = 0;
        while out.len() < count {
            let candidate = format!("{prefix}{n}");
            let collides = match &self.fresh_avoid {
                Some(avoid) => avoid.contains(&candidate),
                None => self.map.contains_key(candidate.as_str()),
            };
            if !collides {
                out.push(self.intern(&candidate)?);
            }
            n = n.checked_add(1).ok_or_else(|| Diagnostic::CompilerBug {
                where_: "intern.fresh_symbols",
                detail: "exhausted u32 suffix space minting fresh symbols".to_owned(),
            })?;
        }
        Ok(out)
    }

    /// Set the fresh-name collision universe for the CURRENT build: the set
    /// of identifier words appearing in the program's source text (the
    /// driver computes it as a pure function of the build inputs — see
    /// `ipe_db::identifier_words`). Overwrites any previous build's set.
    ///
    /// Must over-approximate the program's user identifiers: extra entries
    /// only skip more candidate names (sound); a MISSING user identifier
    /// could let a minted name capture it (unsound) — which is why callers
    /// derive the set from a total scan of the source text rather than a
    /// per-AST-node walker that could silently under-approximate.
    pub fn set_fresh_avoid(&mut self, avoid: BTreeSet<String>) {
        self.fresh_avoid = Some(avoid);
    }

    /// Resolve a [`Symbol`] to its interned string.
    ///
    /// Returns `None` for a symbol this interner never handed out (a forged or
    /// cross-interner value) instead of a silent empty string — the caller
    /// decides whether that `None` is a genuine absence or an impossible
    /// invariant violation.
    #[must_use]
    pub fn resolve(&self, sym: Symbol) -> Option<&str> {
        self.strings.get(sym.0 as usize).map(AsRef::as_ref)
    }

    /// Whether `s` has already been interned, i.e. `intern(s)` would return an
    /// existing [`Symbol`] rather than minting a new one.
    ///
    /// Lets a caller mint a synthesized name (e.g. a generalized type
    /// variable's `"a"`, `"b"`, …) that is guaranteed not to alias a real user
    /// identifier, without provisionally interning-then-discarding candidates.
    #[must_use]
    pub fn contains(&self, s: &str) -> bool {
        self.map.contains_key(s)
    }

    /// Read-only string → [`Symbol`] lookup: returns the existing symbol for
    /// `s`, or `None` if it was never interned. Unlike [`Self::intern`] this
    /// takes `&self` and never mints — for a caller that must reference an
    /// already-interned identifier (e.g. a record field name known to appear in
    /// the program) without a `&mut Interner`.
    #[must_use]
    pub fn lookup(&self, s: &str) -> Option<Symbol> {
        self.map.get(s).copied()
    }
}

// ---------------------------------------------------------------------------
// Cross-process persistence: `Symbol`'s ambient-interner `serde` impls
// ---------------------------------------------------------------------------
//
// A [`Symbol`] is a raw `u32` index into ONE process's [`Interner`] — its
// numeric value is meaningless (not merely "differently numbered") against
// any other interner, including a fresh one in a later `ipe` invocation.
// Persisting a `Symbol` to disk therefore requires a RELOCATION pass: write
// its resolved STRING, and on load, re-intern that string into the
// CURRENT process's interner (a fresh append) and use whatever numeric id
// that re-intern hands back. This is the standard technique real
// interned-string systems use for cross-session persistence (the same
// shape `rust-analyzer`/`string-cache` use for their own interners).
//
// ## Why ambient (thread-local) context, not `DeserializeSeed`
//
// `serde`'s context-carrying alternative to `Deserialize` is
// [`serde::de::DeserializeSeed`], but it does not compose through
// `#[derive(Deserialize)]`: a derived impl on a struct/enum ALWAYS calls
// `T::deserialize` on each field, never a seed — so a `Vec<Symbol>` nested
// three levels deep inside a derived `ipe_ir` type has no way to receive a
// seed without every intermediate container (`Vec`, `BTreeMap`, `Option`,
// every enum variant) ALSO being hand-written to thread it through. Given
// how pervasively `Symbol` appears across `ipe_ir` (function names, type
// names, field names, pattern binders, …), that would mean hand-writing
// `Deserialize` for roughly twenty IR types instead of one — exactly the
// "more mechanical, less error-prone" trade-off this design favours the
// other way.
//
// Ambient (thread-local) context is the standard workaround: install the
// interner for the duration of one (de)serialize call via a scope guard,
// let `#[derive(Serialize, Deserialize)]` work completely unmodified on
// every `ipe_ir` type, and have ONLY `Symbol` itself consult the ambient
// slot. This is sound because:
//
// - the interner is genuinely call-scoped (installed immediately before
//   the (de)serialize call, uninstalled immediately after via `Drop`),
//   never a true global — two unrelated builds never share state;
// - the stack shape (not a single `Option`) lets a nested (de)serialize
//   call install its own interner and restore the outer one on drop,
//   though nothing in this compiler nests today — the cost of the safety
//   margin is one `Vec::push`/`pop`;
// - it introduces NO `unsafe` code (this crate is `#![forbid(unsafe_code)]`
//   and stays that way) — a thread-local `RefCell` is the entire mechanism.
//
// ## Security: a persisted `Symbol` string is untrusted input
//
// `Interner::intern` accepts ANY string by design (it is a pure append-only
// table with no opinion about identifier shapes — see its own doc). The
// backend, however, trusts an interned string VERBATIM when emitting Rust
// identifiers (`ipe_backend_rust`'s `resolve_ident`/`emit_ident` do not
// sanitise; `naming::mangle_reserved` only appends `_` on an EXACT keyword
// match). A cache file is written by a previous, possibly-compromised or
// tampered, process — so a poisoned entry containing e.g. `"x; std::process
// ::exit(1); //"` as a `Symbol`'s text could splice arbitrary Rust source
// into the next build's emitted `main.rs`, reached the moment `cargo build`
// compiles it. [`Symbol::deserialize`] therefore validates every string
// through [`is_valid_symbol_text`] BEFORE interning it, mirroring
// `ipe_backend::RelPath`'s hand-written `Deserialize` (reject, don't trust)
// for the exact same "untrusted disk boundary" reason.

use std::cell::RefCell;
use std::sync::{Arc, Mutex, PoisonError};

thread_local! {
    static SERDE_INTERNER_STACK: RefCell<Vec<Arc<Mutex<Interner>>>> =
        const { RefCell::new(Vec::new()) };
}

/// Whether `s` is a legal [`Symbol`] text.
///
/// The FULL union of shapes any legitimate compiler-internal string ever
/// takes across the whole pipeline: one or more ASCII identifier segments
/// (`[A-Za-z_][A-Za-z0-9_]*` — the SAME grammar `ipe_parse`'s lexer
/// enforces for `Tok::Ident` via `is_ident_start`/`is_ident_continue`,
/// `crates/ipe_parse/src/lexer.rs`), optionally dot-joined for a qualified
/// path segment (`lex_ident`'s greedy `.seg` continuation scan, same file)
/// — never leading, trailing, or doubled.
///
/// This single grammar also covers every non-lexer-scanned shape a
/// `Symbol` is ever built from: [`Interner::fresh_symbols`]' `<prefix><n>`
/// pools (`eta_0`, `cap_3`, …), `ipe_types`' single-letter-plus-digit
/// type-variable mint (`a`, `a1`, `z12`, …), and the handful of hardcoded
/// compiler-internal qualifier aliases that embed a literal dot (`"Db.
/// Decode"`) — every one of those already fits `[A-Za-z_][A-Za-z0-9_]*`
/// segments joined by `.`.
///
/// `Interner::intern` itself deliberately does NOT enforce this predicate
/// (it is a pure append-only table with no opinion about identifier
/// shapes — every real caller only ever calls it with a lexer-scanned or
/// compiler-synthesised string, so validation would be pure overhead on
/// the hot in-process path). This predicate exists ONLY as the
/// deserialize-boundary gate for a persisted cache entry, where a forged
/// string is untrusted input that could otherwise reach
/// `ipe_backend_rust`'s identifier emission unsanitised (see this module's
/// doc section above).
#[must_use]
pub fn is_valid_symbol_text(s: &str) -> bool {
    const fn is_start(c: char) -> bool {
        c.is_ascii_alphabetic() || c == '_'
    }
    const fn is_continue(c: char) -> bool {
        c.is_ascii_alphanumeric() || c == '_'
    }
    // `"".split('.')` yields one empty segment, which already fails the
    // `chars.next()` check below — this early return is purely a
    // documentation aid, not load-bearing.
    if s.is_empty() {
        return false;
    }
    s.split('.').all(|seg| {
        let mut chars = seg.chars();
        chars.next().is_some_and(is_start) && chars.all(is_continue)
    })
}

/// Whether `s` is a legal Rust identifier that can be emitted verbatim.
///
/// Strictly STRICTER than [`is_valid_symbol_text`]: dots are NOT allowed,
/// because `ipe_backend_rust` emits interned strings verbatim as Rust
/// identifiers — a dot in that position produces field-access syntax (`foo.bar`)
/// instead of an identifier, breaking the emitted Rust without any injection.
///
/// Use this predicate wherever a resolved symbol is about to be written as a
/// bare Rust identifier (value names, variant names, parameter names, etc.).
/// Use [`is_valid_symbol_text`] at the deserialize boundary where dot-joined
/// qualified names (e.g. `"Db.Decode"`) are legitimately stored as symbols.
#[must_use]
pub fn is_valid_ident_text(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut chars = s.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    first_ok && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// RAII guard installing an ambient interner for [`Symbol`]'s `serde` impls.
///
/// Installs `interner` as the ambient context [`Symbol`]'s
/// `serde::Serialize`/`Deserialize` impls resolve/re-intern through, on the
/// CURRENT THREAD, for the guard's lifetime. See this module's doc section
/// for why ambient thread-local context is the sound choice here.
///
/// A missing guard is not a soundness hole: [`Symbol::serialize`]/
/// [`Symbol::deserialize`] both fail with a descriptive `serde` error
/// rather than panicking or silently producing a bogus symbol — a
/// programmer-error class of bug (a persistence call site forgot to
/// install the guard), never triggerable by untrusted input.
#[must_use = "the ambient interner is uninstalled when this guard drops"]
pub struct SerdeInternerGuard(());

impl SerdeInternerGuard {
    /// Install `interner` as the ambient serde context.
    pub fn install(interner: Arc<Mutex<Interner>>) -> Self {
        SERDE_INTERNER_STACK.with(|stack| stack.borrow_mut().push(interner));
        Self(())
    }
}

impl Drop for SerdeInternerGuard {
    fn drop(&mut self) {
        SERDE_INTERNER_STACK.with(|stack| {
            stack.borrow_mut().pop();
        });
    }
}

/// Run `f` with a reference to the innermost ambient interner, or return
/// `None` when no [`SerdeInternerGuard`] is currently installed on this
/// thread.
fn with_ambient_interner<R>(f: impl FnOnce(&Arc<Mutex<Interner>>) -> R) -> Option<R> {
    SERDE_INTERNER_STACK.with(|stack| stack.borrow().last().map(f))
}

/// Serialises as the `Symbol`'s resolved STRING (never the raw numeric id —
/// see this module's doc section for why a raw id cannot survive a process
/// boundary). Requires an ambient interner ([`SerdeInternerGuard::install`])
/// that can resolve `self`; both failure modes (no guard installed, or a
/// forged/cross-interner `Symbol` the ambient interner never handed out)
/// are reported as a `serde` error, never a panic.
impl serde::Serialize for Symbol {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize on the borrowed `&str` from `resolve` inside the lock scope,
        // rather than cloning it into an owned `String` just to escape the scope
        // — byte-identical output, one lock, zero interim allocation. The
        // serializer is a `FnOnce`, so it is moved into the closure and consumed
        // on exactly one of the two arms below.
        let outcome = with_ambient_interner(|interner| {
            let guard = interner.lock().unwrap_or_else(PoisonError::into_inner);
            guard.resolve(*self).map_or_else(
                || {
                    Err(serde::ser::Error::custom(
                        "ipe_intern::Symbol::serialize: symbol resolves to no string in \
                         the ambient interner (a forged or cross-interner Symbol)",
                    ))
                },
                |text| serializer.serialize_str(text),
            )
        });
        outcome.unwrap_or_else(|| {
            Err(serde::ser::Error::custom(
                "ipe_intern::Symbol::serialize: no ambient interner installed \
                 (missing SerdeInternerGuard::install)",
            ))
        })
    }
}

/// **Deliberately hand-written, never `#[derive(Deserialize)]`** — mirrors
/// `ipe_backend::RelPath`'s hand-written `Deserialize` for the same reason:
/// a derived impl on a bare `u32` newtype would reconstruct a raw,
/// meaningless cross-process index directly from untrusted bytes. This impl
/// instead reads the resolved STRING, validates it via
/// [`is_valid_symbol_text`] (rejecting a poisoned/tampered entry — see this
/// module's doc section's security note), and re-interns it into the
/// CURRENT process's ambient interner ([`SerdeInternerGuard::install`]) —
/// the relocation pass. The returned `Symbol`'s numeric id is whatever this
/// process's interner assigns; it is NOT expected to match the id the
/// writing process had, only the resolved STRING (semantic identity, the
/// only identity a `Symbol` carries once you cross a process boundary).
impl<'de> serde::Deserialize<'de> for Symbol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        if !is_valid_symbol_text(&text) {
            return Err(serde::de::Error::custom(format!(
                "ipe_intern::Symbol::deserialize: invalid symbol text {text:?} \
                 (must be one or more ASCII identifier segments \
                 `[A-Za-z_][A-Za-z0-9_]*` joined by a single `.`)"
            )));
        }
        let interned = with_ambient_interner(|interner| {
            let mut guard = interner.lock().unwrap_or_else(PoisonError::into_inner);
            guard.intern(&text)
        });
        match interned {
            None => Err(serde::de::Error::custom(
                "ipe_intern::Symbol::deserialize: no ambient interner installed \
                 (missing SerdeInternerGuard::install)",
            )),
            Some(Err(diag)) => Err(serde::de::Error::custom(format!(
                "ipe_intern::Symbol::deserialize: intern failed: {diag:?}"
            ))),
            Some(Ok(sym)) => Ok(sym),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    #[test]
    fn intern_dedups_and_resolves() -> ipe_diagnostics::DResult<()> {
        let mut i = Interner::new();
        let a = i.intern("Increment")?;
        let b = i.intern("Increment")?;
        let c = i.intern("Decrement")?;
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(i.resolve(a), Some("Increment"));
        assert_eq!(i.resolve(c), Some("Decrement"));
        Ok(())
    }
    #[test]
    fn resolve_unknown_is_none_not_panic() {
        let i = Interner::new();
        assert_eq!(i.resolve(Symbol::from_raw(999)), None);
    }

    #[test]
    fn fresh_symbols_are_distinct_and_named_in_order() -> ipe_diagnostics::DResult<()> {
        let mut i = Interner::new();
        let pool = i.fresh_symbols("eta_", 3)?;
        let names: Vec<Option<&str>> = pool.iter().map(|&s| i.resolve(s)).collect();
        assert_eq!(
            names,
            vec![Some("eta_0"), Some("eta_1"), Some("eta_2")],
            "named by ascending suffix"
        );
        // Distinct symbols.
        let unique: BTreeSet<Symbol> = pool.iter().copied().collect();
        assert_eq!(unique.len(), pool.len(), "every minted symbol is distinct");
        Ok(())
    }

    #[test]
    fn fresh_symbols_skip_already_interned_collisions() -> ipe_diagnostics::DResult<()> {
        let mut i = Interner::new();
        // A user identifier that would collide with the first candidate.
        let user = i.intern("eta_0")?;
        let pool = i.fresh_symbols("eta_", 2)?;
        // The minted names step over the pre-existing `eta_0`.
        let names: Vec<Option<&str>> = pool.iter().map(|&s| i.resolve(s)).collect();
        assert_eq!(names, vec![Some("eta_1"), Some("eta_2")]);
        assert!(
            pool.iter().all(|&s| s != user),
            "a fresh symbol never aliases a user name"
        );
        Ok(())
    }

    #[test]
    fn fresh_symbols_zero_count_is_empty() -> ipe_diagnostics::DResult<()> {
        let mut i = Interner::new();
        assert!(i.fresh_symbols("eta_", 0)?.is_empty());
        Ok(())
    }

    /// Avoid-set mode: re-minting a pool on a WARM interner (previous build's
    /// pool names already interned) yields the SAME names — the previous
    /// build's synthetic names are not collisions, only the program's
    /// identifier words are. This is the Task-18 warm/cold byte-parity
    /// property at the interner level.
    #[test]
    fn fresh_symbols_avoid_set_is_stable_across_rebuilds() -> ipe_diagnostics::DResult<()> {
        let mut i = Interner::new();
        i.set_fresh_avoid(BTreeSet::new());
        let run1 = i.fresh_symbols("eta_", 2)?;
        let run2 = i.fresh_symbols("eta_", 2)?;
        assert_eq!(run1, run2, "warm re-mint returns the same symbols");
        let names: Vec<Option<&str>> = run2.iter().map(|&s| i.resolve(s)).collect();
        assert_eq!(names, vec![Some("eta_0"), Some("eta_1")]);
        Ok(())
    }

    /// Avoid-set mode still dodges the program's user identifiers.
    #[test]
    fn fresh_symbols_avoid_set_dodges_user_identifiers() -> ipe_diagnostics::DResult<()> {
        let mut i = Interner::new();
        let user = i.intern("eta_0")?;
        i.set_fresh_avoid(BTreeSet::from(["eta_0".to_owned()]));
        let pool = i.fresh_symbols("eta_", 2)?;
        let names: Vec<Option<&str>> = pool.iter().map(|&s| i.resolve(s)).collect();
        assert_eq!(names, vec![Some("eta_1"), Some("eta_2")]);
        assert!(
            pool.iter().all(|&s| s != user),
            "a fresh symbol never aliases a user name"
        );
        Ok(())
    }

    /// A later build's avoid set replaces the earlier one: a user identifier
    /// REMOVED from the program frees its candidate again (cold-build
    /// equivalence — the collision universe is per build, not sticky).
    #[test]
    fn fresh_symbols_avoid_set_is_per_build_not_sticky() -> ipe_diagnostics::DResult<()> {
        let mut i = Interner::new();
        i.set_fresh_avoid(BTreeSet::from(["eta_0".to_owned()]));
        let run1 = i.fresh_symbols("eta_", 1)?;
        assert_eq!(
            run1.first().and_then(|&s| i.resolve(s)),
            Some("eta_1"),
            "avoided while the program names eta_0"
        );
        // Next build: the program no longer names `eta_0`.
        i.set_fresh_avoid(BTreeSet::new());
        let run2 = i.fresh_symbols("eta_", 1)?;
        assert_eq!(
            run2.first().and_then(|&s| i.resolve(s)),
            Some("eta_0"),
            "freed once the program stops naming it (cold-build equivalence)"
        );
        Ok(())
    }
}

/// Tests for `Symbol`'s cross-process `serde` persistence — the relocation
/// pass this module's doc section describes. Kept in a separate `mod` (not
/// folded into the existing `tests` module above) since these need
/// `serde_json` and exercise a materially different concern (persistence
/// soundness across simulated process boundaries, not interner mechanics).
#[cfg(test)]
mod serde_persistence_tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[test]
    fn valid_symbol_text_accepts_every_real_shape() {
        // Plain lexer-scanned identifiers.
        assert!(is_valid_symbol_text("Increment"));
        assert!(is_valid_symbol_text("count"));
        assert!(is_valid_symbol_text("_private"));
        // Dot-joined qualified segments (a single `Tok::Ident` can itself
        // contain dots — `ipe_parse::lexer::lex_ident`).
        assert!(is_valid_symbol_text("Module.Sub.name"));
        assert!(is_valid_symbol_text("Db.Decode"));
        // Fresh/synthetic pool names (`Interner::fresh_symbols`).
        assert!(is_valid_symbol_text("eta_0"));
        assert!(is_valid_symbol_text("cap_12"));
        assert!(is_valid_symbol_text("destr_thunk_3"));
        // Type-variable mint shapes (`ipe_types::doc::letters`).
        assert!(is_valid_symbol_text("a"));
        assert!(is_valid_symbol_text("a1"));
        assert!(is_valid_symbol_text("z12"));
    }

    #[test]
    fn valid_symbol_text_rejects_every_poisoned_shape() {
        assert!(!is_valid_symbol_text(""), "empty string");
        assert!(!is_valid_symbol_text("."), "bare dot");
        assert!(!is_valid_symbol_text(".leading"), "leading dot");
        assert!(!is_valid_symbol_text("trailing."), "trailing dot");
        assert!(!is_valid_symbol_text("a..b"), "doubled dot");
        assert!(!is_valid_symbol_text("1abc"), "digit-leading segment");
        assert!(!is_valid_symbol_text("a b"), "embedded space");
        assert!(!is_valid_symbol_text("a;b"), "embedded semicolon");
        assert!(!is_valid_symbol_text("a{b}"), "embedded braces");
        assert!(!is_valid_symbol_text("a\nb"), "embedded newline");
        assert!(!is_valid_symbol_text("a\0b"), "embedded NUL byte");
        assert!(
            !is_valid_symbol_text("x; std::process::exit(1); //"),
            "Rust-injection-shaped payload"
        );
        assert!(
            !is_valid_symbol_text("naïve"),
            "non-ASCII (lexer is ASCII-only)"
        );
    }

    #[test]
    fn round_trips_within_one_interner() -> ipe_diagnostics::DResult<()> {
        let mut plain = Interner::new();
        let sym = plain.intern("Increment")?;
        let interner = Arc::new(Mutex::new(plain));

        let json = {
            let _guard = SerdeInternerGuard::install(Arc::clone(&interner));
            serde_json::to_string(&sym).expect("serialize must succeed")
        };
        assert_eq!(json, "\"Increment\"");

        let round_tripped: Symbol = {
            let _guard = SerdeInternerGuard::install(Arc::clone(&interner));
            serde_json::from_str(&json).expect("deserialize must succeed")
        };
        assert_eq!(round_tripped, sym, "same interner: id AND string agree");
        Ok(())
    }

    /// **The mission proof.** A same-process round trip (the test above)
    /// cannot distinguish "the relocation pass correctly re-interns by
    /// string" from "the id happened to survive by coincidence" — both
    /// interners would assign id 0 to the first symbol either way. This
    /// test deliberately makes the WRITE-side and READ-side interner
    /// states diverge (different, differently-ordered noise interned into
    /// each) so a raw-id bug WOULD manifest as a wrong resolved string,
    /// then asserts the resolved string is correct regardless.
    #[test]
    fn serialize_then_deserialize_survives_cross_process_id_drift() -> ipe_diagnostics::DResult<()>
    {
        // "Process A" (the writer): intern some unrelated names first, so
        // "Increment" lands at a NON-ZERO, process-A-specific id.
        let mut interner_a = Interner::new();
        interner_a.intern("foo")?;
        interner_a.intern("bar")?;
        interner_a.intern("baz")?;
        let sym_a = interner_a.intern("Increment")?;
        let interner_a = Arc::new(Mutex::new(interner_a));

        let json = {
            let _guard = SerdeInternerGuard::install(Arc::clone(&interner_a));
            serde_json::to_string(&sym_a).expect("serialize must succeed")
        };
        assert_eq!(
            json, "\"Increment\"",
            "serializes as the resolved string, not a raw id"
        );

        // "Process B" (the reader): a FRESH interner polluted with a
        // DIFFERENT set of names, in a different order, so "Increment"
        // would land at a DIFFERENT numeric id than in process A even
        // once re-interned — id drift is real, not hypothetical.
        let mut interner_b = Interner::new();
        interner_b.intern("zzz_noise_1")?;
        interner_b.intern("zzz_noise_2")?;
        let interner_b = Arc::new(Mutex::new(interner_b));
        let sym_b: Symbol = {
            let _guard = SerdeInternerGuard::install(Arc::clone(&interner_b));
            serde_json::from_str(&json).expect("deserialize must succeed")
        };

        // The raw ids MUST differ (proves the drift scenario is genuine,
        // not accidentally identical) ...
        assert_ne!(
            sym_a.as_raw(),
            sym_b.as_raw(),
            "the two interners' differing noise must produce different raw ids \
             for this test to actually probe drift"
        );
        // ... yet the semantic identity — what the symbol RESOLVES TO in
        // its OWN process's interner — must be identical. This is the
        // property that makes a persisted `ipe_ir::Program` behave
        // identically to a freshly-lowered one across a process boundary.
        let resolved_b: Option<String> = {
            let guard = interner_b
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.resolve(sym_b).map(str::to_owned)
        };
        assert_eq!(
            resolved_b.as_deref(),
            Some("Increment"),
            "relocated symbol must resolve to the SAME string in the reader's \
             own interner, despite the numeric id having drifted"
        );
        Ok(())
    }

    #[test]
    fn serialize_without_ambient_interner_fails_closed() -> ipe_diagnostics::DResult<()> {
        let mut i = Interner::new();
        let sym = i.intern("x")?;
        // No `SerdeInternerGuard::install` call anywhere in this scope.
        let err = serde_json::to_string(&sym).expect_err("must fail without ambient context");
        assert!(err.to_string().contains("no ambient interner installed"));
        Ok(())
    }

    #[test]
    fn deserialize_without_ambient_interner_fails_closed() {
        let err: Result<Symbol, _> = serde_json::from_str("\"x\"");
        let err = err.expect_err("must fail without ambient context");
        assert!(err.to_string().contains("no ambient interner installed"));
    }

    #[test]
    fn deserialize_rejects_poisoned_symbol_text() {
        let interner = Arc::new(Mutex::new(Interner::new()));
        let _guard = SerdeInternerGuard::install(Arc::clone(&interner));
        let err: Result<Symbol, _> = serde_json::from_str("\"x; std::process::exit(1); //\"");
        assert!(
            err.is_err(),
            "an injection-shaped symbol text must be rejected at deserialize time"
        );
        // The poisoned text must never have reached `intern` at all — the
        // interner stays empty.
        let resolved_zero: Option<String> = {
            let guard = interner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.resolve(Symbol::from_raw(0)).map(str::to_owned)
        };
        assert!(
            resolved_zero.is_none(),
            "a rejected symbol text must never be interned"
        );
    }

    #[test]
    fn deserialize_rejects_forged_control_character_payloads() {
        let interner = Arc::new(Mutex::new(Interner::new()));
        let _guard = SerdeInternerGuard::install(Arc::clone(&interner));
        for poisoned in [
            "\"\"",
            "\"a\\nb\"",
            "\"a\\u0000b\"",
            "\".leading\"",
            "\"a..b\"",
        ] {
            let err: Result<Symbol, _> = serde_json::from_str(poisoned);
            assert!(err.is_err(), "must reject poisoned payload {poisoned}");
        }
    }

    /// `is_valid_ident_text` rejects dot-joined strings that `is_valid_symbol_text`
    /// accepts — a dot-joined symbol that passes the deserialize gate must still
    /// be rejected when used as a bare Rust identifier in emission.
    #[test]
    fn is_valid_ident_text_rejects_dotted_symbols() {
        // These pass the deserialize gate (legitimately dot-qualified names).
        assert!(is_valid_symbol_text("Module.Sub.name"));
        assert!(is_valid_symbol_text("Db.Decode"));
        // But they are NOT safe for verbatim identifier emission.
        assert!(
            !is_valid_ident_text("Module.Sub.name"),
            "dot-joined symbol rejected by ident gate"
        );
        assert!(
            !is_valid_ident_text("Db.Decode"),
            "dot-joined symbol rejected by ident gate"
        );
        assert!(
            !is_valid_ident_text("foo.bar"),
            "dot-joined symbol rejected by ident gate"
        );
    }

    /// Plain single-segment names that are legal Rust identifiers pass both gates.
    #[test]
    fn is_valid_ident_text_accepts_plain_identifiers() {
        for name in [
            "Increment",
            "count",
            "_private",
            "eta_0",
            "cap_12",
            "a",
            "z12",
        ] {
            assert!(
                is_valid_ident_text(name),
                "plain ident {name:?} must pass ident gate"
            );
            assert!(
                is_valid_symbol_text(name),
                "plain ident {name:?} must pass symbol gate"
            );
        }
    }

    #[test]
    fn nested_guards_restore_the_outer_interner_on_drop() -> ipe_diagnostics::DResult<()> {
        let mut outer_i = Interner::new();
        let outer_sym = outer_i.intern("outer")?;
        let outer = Arc::new(Mutex::new(outer_i));

        let mut inner_i = Interner::new();
        let inner_sym = inner_i.intern("inner")?;
        let inner = Arc::new(Mutex::new(inner_i));

        let outer_guard = SerdeInternerGuard::install(Arc::clone(&outer));
        let outer_json = serde_json::to_string(&outer_sym).expect("outer serialize must succeed");
        {
            let _inner_guard = SerdeInternerGuard::install(Arc::clone(&inner));
            let inner_json =
                serde_json::to_string(&inner_sym).expect("inner serialize must succeed");
            assert_eq!(inner_json, "\"inner\"");
        }
        // The inner guard dropped; the outer interner must be ambient again.
        let restored_json =
            serde_json::to_string(&outer_sym).expect("outer serialize after inner drop");
        assert_eq!(restored_json, outer_json);
        drop(outer_guard);
        Ok(())
    }
}
