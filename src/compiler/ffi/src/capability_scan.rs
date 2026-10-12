//! Static capability inference over author-supplied wrapper Rust — the honesty
//! check on a `[rust.wrapper]` capability declaration (FFI Tier 2, spec §5).
//!
//! It lexes wrapper source with `proc-macro2`, the SAME token model
//! `tools/panic-scan` uses, so a capability-bearing path named inside a string
//! literal or a comment is invisible (a string is one opaque `Literal`; comments
//! are dropped) and one split across lines (`std::\nnet::TcpStream`) is still
//! found. That closes the trivial evasions a text scan would miss.
//!
//! # What this PROPOSES, and what enforces
//!
//! This scan is **imprecise by design** — it cannot see through a macro that
//! expands to `std::net`, a re-export (`use std::fs as f; f::read`), a capability
//! reached only through a dependency crate, or a call behind a type alias. It
//! therefore only *proposes* a coarse over-approximation and, more importantly,
//! answers one load-bearing yes/no: does this wrapper reach ANY
//! capability whose effects Ipê cannot yet contain at run? Because there is no
//! runtime sandbox around the emitted app in this release (the wrapper's Rust
//! runs with the user's full ambient authority at `ipe dev run`), a wrapper that
//! reaches such a capability CANNOT be soundly admitted — the install refuses it
//! rather than admit an unenforced capability. See [`ScanOutcome`].
//!
//! The scan is deliberately biased toward FALSE POSITIVES: over-flagging refuses
//! a wrapper that might have been safe (an annoyance the author resolves by
//! narrowing the wrapper), whereas a false negative would admit an unconstrained
//! capability. Every ambiguous or unenumerable construct (`extern`, `#[link]`,
//! `libc::`, `include!`, `#[path]`, a source that does not lex) is treated as an
//! **opaque** refuse trigger, never as "no capability found". Aliasing the
//! crate root itself (`use std as s`, `extern crate std`) is one of these: the
//! alias carries the whole `std` surface no path rule can see, so it refuses.

use std::collections::BTreeSet;

use ipe_diagnostics::terminal::TerminalSafe;
pub use ipe_kernels::Capability;
use proc_macro2::{Delimiter, TokenStream, TokenTree};
use std::str::FromStr;

/// A capability-bearing standard-library path root and the [`Capability`] it
/// maps to. Matched as a `first :: second` token pair (`std :: net`,
/// `process :: Command`), so a path split across lines is still caught.
struct PathRule {
    /// The leading identifier (`std`, `process`, `fs`, …).
    first: &'static str,
    /// The identifier that must immediately follow `::`.
    second: &'static str,
    /// The capability this path root exercises.
    cap: Capability,
}

/// The capability-bearing `first::second` path roots. Coarse: `std::net`
/// anything is [`Capability::Network`], `std::fs` anything is
/// [`Capability::Filesystem`]. The list also covers the common bare roots a
/// wrapper reaches after `use std::net::*` (`TcpStream`, `File`, `Command`).
const PATH_RULES: &[PathRule] = &[
    // Network.
    PathRule {
        first: "std",
        second: "net",
        cap: Capability::Network,
    },
    PathRule {
        first: "net",
        second: "TcpStream",
        cap: Capability::Network,
    },
    PathRule {
        first: "net",
        second: "TcpListener",
        cap: Capability::Network,
    },
    PathRule {
        first: "net",
        second: "UdpSocket",
        cap: Capability::Network,
    },
    // Filesystem.
    PathRule {
        first: "std",
        second: "fs",
        cap: Capability::Filesystem,
    },
    PathRule {
        first: "fs",
        second: "File",
        cap: Capability::Filesystem,
    },
    PathRule {
        first: "fs",
        second: "OpenOptions",
        cap: Capability::Filesystem,
    },
    // Subprocess.
    PathRule {
        first: "std",
        second: "process",
        cap: Capability::Subprocess,
    },
    PathRule {
        first: "process",
        second: "Command",
        cap: Capability::Subprocess,
    },
    // Environment.
    PathRule {
        first: "std",
        second: "env",
        cap: Capability::Env,
    },
    // Clock.
    PathRule {
        first: "std",
        second: "time",
        cap: Capability::Clock,
    },
    PathRule {
        first: "time",
        second: "Instant",
        cap: Capability::Clock,
    },
    PathRule {
        first: "time",
        second: "SystemTime",
        cap: Capability::Clock,
    },
    // Inline assembly via `std::arch` / `core::arch` — raw syscall capability;
    // treated as NativeFfi opacity because its effects are unenumerable.
    PathRule {
        first: "std",
        second: "arch",
        cap: Capability::NativeFfi,
    },
    PathRule {
        first: "core",
        second: "arch",
        cap: Capability::NativeFfi,
    },
    // `std::os` — the OS-specific surface (unix sockets, raw file descriptors,
    // platform extensions). Every sub-path crosses the OS boundary; treated as
    // NativeFfi opacity so any `std::os::…` use refuses rather than admits.
    PathRule {
        first: "std",
        second: "os",
        cap: Capability::NativeFfi,
    },
];

/// Bare capability-bearing type/const identifiers a wrapper reaches after a
/// glob or explicit `use` (`use std::net::TcpStream; … TcpStream::connect`).
/// These are ONE identifier, so they are matched by name alone — imprecise (a
/// user type coincidentally named `File` would over-flag), which is the safe
/// direction: over-flagging refuses, it never admits.
///
/// Note: `asm` / `global_asm` are NOT listed here — they must be followed by
/// `!` to be macro invocations; the `scan_ident` match handles them exactly.
const BARE_IDENTS: &[(&str, Capability)] = &[
    ("TcpStream", Capability::Network),
    ("TcpListener", Capability::Network),
    ("UdpSocket", Capability::Network),
    ("OpenOptions", Capability::Filesystem),
    // Unix-socket and raw-fd types reached after `use std::os::unix::net::*`
    // or `use std::os::fd::*`. Each crosses the OS boundary (network socket or
    // raw file descriptor); treated as NativeFfi because the capability scan
    // cannot enumerate their effects at the token level.
    ("UnixStream", Capability::NativeFfi),
    ("UnixListener", Capability::NativeFfi),
    ("RawFd", Capability::NativeFfi),
    ("OwnedFd", Capability::NativeFfi),
    ("from_raw_fd", Capability::NativeFfi),
];

/// The set of runtime-enforced axes a target's jail actually confines at the OS
/// boundary.
///
/// A `Copy` bitset over the runtime-enforced axes (network, filesystem,
/// database, env, subprocess, native-ffi). It is the honest per-target
/// vocabulary the admit path keys off: an axis is confined iff it is a member.
/// Clock/random are never members (they are non-determinism, not an isolation
/// surface — they are enforceable on every target, jail or none).
///
/// This lets a target confine a PARTIAL set. A Windows host that confines
/// subprocess+filesystem+env via Job Objects + launcher scrub but cannot deny
/// sockets under a restricted-token fallback carries a set WITHOUT `network`,
/// so a filesystem wrapper admits and a network wrapper refuse-gaps — each
/// honestly, without over-claiming the uncontained axis.
///
/// Make-invalid-states-unrepresentable: there is no "fully contained" flag
/// distinct from the set — a target is fully contained iff its set equals
/// [`Self::FULL`] ([`Self::is_full`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilitySet {
    /// One bit per runtime-enforced axis (see [`Self::AXES`]). A bitset keeps
    /// the type `Copy` so the admit-path predicates stay `const fn`.
    bits: u8,
}

impl CapabilitySet {
    /// The runtime-enforced axes, in bit order. These are exactly the
    /// capabilities whose runtime effects need OS confinement — the axes for
    /// which "is this axis in the jail's confined set?" is a real question.
    /// Clock/random are deliberately absent (never an isolation surface).
    ///
    /// A jail confines a target's app on some subset of these; membership in a
    /// [`CapabilitySet`] answers, per axis, whether THIS target's jail does.
    pub const AXES: &'static [Capability] = &[
        Capability::Network,
        Capability::Filesystem,
        Capability::Database,
        Capability::Env,
        Capability::Subprocess,
        Capability::NativeFfi,
    ];

    /// The empty confined set — the old `RefuseGap` posture: the jail confines
    /// no runtime-enforced axis, so every such axis is refused. The fail-closed
    /// default for an unknown or stub target.
    pub const EMPTY: Self = Self { bits: 0 };

    /// The full confined set — every runtime-enforced axis contained, the old
    /// all-or-nothing `Holds` posture. Linux (bwrap+seccomp) and macOS
    /// (sandbox-exec+launcher-scrub) confine all axes, so this is their set.
    pub const FULL: Self = Self {
        bits: (1 << Self::AXES.len()) - 1,
    };

    /// The bit index of a runtime-enforced axis, or `None` for clock/random
    /// (which are not confinement axes and can never be set members).
    const fn axis_bit(cap: Capability) -> Option<u8> {
        match cap {
            Capability::Network => Some(0),
            Capability::Filesystem => Some(1),
            Capability::Database => Some(2),
            Capability::Env => Some(3),
            Capability::Subprocess => Some(4),
            // `ffi-raw` shares the native-ffi bit: an asserted call is a native
            // crossing, and the one mechanism that contains native code — the
            // whole-process jail — contains it identically. A jail can never
            // confine one without the other, so a separate bit would be a
            // second list that could silently disagree.
            Capability::NativeFfi | Capability::FfiRaw => Some(5),
            // `unsafe` is a provenance label, not a confinement axis: there is
            // no runtime surface a jail could isolate, so it is never a set
            // member — the same posture as clock/random. `custom-element` is a
            // disclosure of shipped browser JS: it has no SERVER-side runtime
            // surface a jail could isolate (the JS runs in the client page), so it
            // too is never a confinement-set member.
            Capability::Clock
            | Capability::Random
            | Capability::Unsafe
            | Capability::CustomElement
            // `js-port` discloses typed data exchange with page JS; like
            // `custom-element` it has no server-side runtime surface a jail could
            // isolate (the far side is the client page), so it is never a
            // confinement-set member. The whole `JsPort(_)` web family is one arm:
            // every web sub-axis runs in the client page, so none is a jail axis.
            | Capability::JsPort(_) => None,
        }
    }

    /// Whether the jail confines `cap` on this target. Clock/random are never
    /// members: they are non-determinism, so the question does not apply and the
    /// answer is a plain `false` (not-a-member), which the unenforceable check
    /// reads correctly (they are enforceable regardless of the jail).
    #[must_use]
    pub const fn confines(self, cap: Capability) -> bool {
        match Self::axis_bit(cap) {
            Some(bit) => self.bits & (1 << bit) != 0,
            None => false,
        }
    }

    /// The confined set with `cap` added. A no-op for clock/random (not
    /// confinement axes). Used to construct a partial set axis by axis.
    #[must_use]
    pub const fn with(self, cap: Capability) -> Self {
        match Self::axis_bit(cap) {
            Some(bit) => Self {
                bits: self.bits | (1 << bit),
            },
            None => self,
        }
    }

    /// Whether this target confines EVERY runtime-enforced axis — the sole
    /// meaning of "fully contained". A partial set is never full, so partial
    /// coverage cannot masquerade as total.
    #[must_use]
    pub const fn is_full(self) -> bool {
        self.bits == Self::FULL.bits
    }

    /// Whether this target confines NO runtime-enforced axis — the refuse-gap
    /// posture on every axis.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }
}

/// Which runtime-enforced axes a wrapper's run/deploy target actually confines
/// at the OS boundary — the honest, PER-AXIS condition of the refuse-until-jail
/// → admit-and-isolate hand-off.
///
/// Admitting a real-capability wrapper is safe only on the axes the jail
/// actually confines. A single target-wide boolean would force over-claiming on
/// a target (Windows under a restricted-token fallback, a non-ACL volume) where
/// some axes hold and others do not — the exact admit-and-run-unconfined hazard
/// the macOS review caught. So the verdict carries the SET of confined axes and
/// the admit path decides per axis.
///
/// Linux and macOS confine every runtime-enforced axis, so their set is
/// [`CapabilitySet::FULL`] and behaviour is identical to the old all-or-nothing
/// `Holds`. A refuse-gap target carries [`CapabilitySet::EMPTY`], identical to
/// the old `RefuseGap`. There is no separate `RefuseGap` variant: it is exactly
/// `Holds(CapabilitySet::EMPTY)`, so "no axis confined" is unrepresentable in
/// two different ways.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JailForTarget {
    /// The jail confines exactly the runtime-enforced axes in this set. A
    /// runtime-enforced axis IN the set is contained (admissible); an axis NOT
    /// in the set is still unenforceable (refuse-gapped for that axis alone).
    /// [`CapabilitySet::FULL`] is the old whole-target `Holds`;
    /// [`CapabilitySet::EMPTY`] is the old whole-target `RefuseGap`.
    Holds(CapabilitySet),
}

impl JailForTarget {
    /// A whole-target refuse-gap: no axis confined. The conservative default
    /// when the target's jail status is unknown.
    pub const REFUSE_GAP: Self = Self::Holds(CapabilitySet::EMPTY);

    /// A whole-target jail that confines every runtime-enforced axis (Linux,
    /// macOS). The old all-or-nothing `Holds`.
    pub const FULLY_CONFINED: Self = Self::Holds(CapabilitySet::FULL);

    /// The set of axes this target's jail confines.
    #[must_use]
    pub const fn confined(self) -> CapabilitySet {
        match self {
            Self::Holds(set) => set,
        }
    }
}

/// Whether a capability's runtime effects Ipê CANNOT contain for the given
/// target — decided PER AXIS against the jail's confined set.
///
/// The hand-off (ADR 0004): a runtime-enforced axis IN the target's confined set
/// is *contained* (an undeclared syscall fails closed at the OS boundary), so it
/// is admissible. An axis NOT in the confined set has no jail confining it, so it
/// is still unenforceable and refused — the honest per-target, per-axis posture.
/// A full-set target ([`CapabilitySet::FULL`], i.e. Linux/macOS) contains every
/// axis, so nothing is unenforceable; an empty-set target
/// ([`CapabilitySet::EMPTY`]) confines nothing, so every runtime-enforced axis is
/// unenforceable — identical to the old all-or-nothing verdict.
///
/// [`Capability::NativeFfi`] is a runtime-enforced axis: where the jail confines
/// it (it is a member of the set) the whole process is contained regardless of
/// what native code does, so it is admissible-with-loud-consent; where it is not
/// confined it stays unenforceable.
///
/// [`Capability::Clock`] and [`Capability::Random`] are never unenforceable:
/// they are non-determinism, not exfiltration, carry no isolation surface, and
/// are never members of a [`CapabilitySet`] — so this returns `false` for them
/// on every target.
#[must_use]
pub const fn is_runtime_unenforceable_for(cap: Capability, jail: JailForTarget) -> bool {
    match cap {
        // Non-determinism, never an isolation surface: enforceable everywhere.
        // `unsafe` is likewise a provenance label with no isolation surface, so
        // the unenforceability question does not apply — never unenforceable.
        // `custom-element` discloses shipped browser JS, which has no server-side
        // runtime surface to enforce (it runs in the client page); the
        // unenforceability question does not apply to it either — never
        // unenforceable, its integrity is the served page's SRI pin.
        // `js-port` is the same class as `custom-element`: it discloses typed
        // exchange with page JS, which has no server-side runtime surface to
        // enforce, so the unenforceability question does not apply — its inbound
        // integrity is the fail-closed seal decoder, not a jail confinement.
        Capability::Clock
        | Capability::Random
        | Capability::Unsafe
        | Capability::CustomElement
        | Capability::JsPort(_) => false,
        // A runtime-enforced axis is unenforceable exactly where the target's
        // jail does NOT confine it.
        Capability::Network
        | Capability::Filesystem
        | Capability::Database
        | Capability::Env
        | Capability::Subprocess
        | Capability::NativeFfi
        | Capability::FfiRaw => !jail.confined().confines(cap),
    }
}

/// The pre-jail refuse-until-jail predicate.
///
/// Preserved for callers that have not yet threaded a target through; equivalent
/// to [`is_runtime_unenforceable_for`] with [`JailForTarget::REFUSE_GAP`] — the
/// conservative default (refuse) when the target's jail status is unknown.
#[must_use]
pub const fn is_runtime_unenforceable(cap: Capability) -> bool {
    is_runtime_unenforceable_for(cap, JailForTarget::REFUSE_GAP)
}

/// An OPAQUE construct the token scan cannot see past.
///
/// Its presence means the proposed set can no longer be trusted as complete, so
/// each variant is a refuse trigger, never a "no capability found".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opacity {
    /// A source file that does not lex as Rust tokens. A malformed (or
    /// deliberately un-lexable) file must refuse, never scan to an empty set.
    DoesNotLex {
        /// The file whose contents did not tokenise.
        file: TerminalSafe,
    },
    /// An `extern` block or `#[link]`/`libc::` reference — native FFI the scan
    /// is blind past. Its presence is exactly [`Capability::NativeFfi`]: the
    /// wrapper crosses into opaque native code whose effects cannot be inferred.
    NativeFfi {
        /// The file the construct was found in.
        file: TerminalSafe,
        /// The 1-based line.
        line: usize,
    },
    /// An `include!` or `#[path = "…"]` module — the scan cannot enumerate the
    /// source it pulls in, so the file set is not closed and a capability could
    /// hide in the unscanned text.
    UnenumerableModule {
        /// The file the construct was found in.
        file: TerminalSafe,
        /// The 1-based line.
        line: usize,
        /// A short label (`include!`, `#[path]`).
        construct: &'static str,
    },
}

impl std::fmt::Display for Opacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DoesNotLex { file } => write!(
                f,
                "`{file}` does not lex as Rust — its capabilities cannot be scanned, so the \
                 wrapper cannot be admitted (fix the source or narrow the wrapper)"
            ),
            Self::NativeFfi { file, line } => write!(
                f,
                "{file}:{line}: native FFI (`extern` / `#[link]` / `libc` / `asm!` / \
                 `global_asm!` / `core::arch` / `std::arch`) — the wrapper crosses into \
                 opaque native code whose effects cannot be inferred or contained"
            ),
            Self::UnenumerableModule {
                file,
                line,
                construct,
            } => write!(
                f,
                "{file}:{line}: `{construct}` pulls in source the scan cannot enumerate, so a \
                 hidden capability cannot be ruled out"
            ),
        }
    }
}

/// The outcome of scanning ONE wrapper source file (or unioned across files):
/// the coarse proposed capability set plus every opacity trigger found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanOutcome {
    /// The coarse over-approximating capability set the token scan proposes.
    /// Imprecise — a lower bound on the truth for the tokens it can see, an
    /// upper bound where a bare-ident match over-flags. Used for the diagnostic
    /// and the reconcile, never as the sole enforcement.
    pub proposed: BTreeSet<Capability>,
    /// Opaque constructs that make the scan untrustworthy as a completeness
    /// claim. A non-empty list is a hard refuse trigger regardless of
    /// `proposed`.
    pub opacities: Vec<Opacity>,
}

impl ScanOutcome {
    /// Fold another file's outcome into this one (the multi-file union).
    fn absorb(&mut self, other: Self) {
        self.proposed.extend(other.proposed);
        self.opacities.extend(other.opacities);
    }

    /// The proposed capabilities Ipê cannot enforce at run **for the given
    /// target** — the subset of [`Self::proposed`] for which admission would be
    /// unenforced. Decided per axis: a proposed axis is unenforceable exactly
    /// where the target's jail does not confine it, so on a
    /// [`CapabilitySet::FULL`] target this is empty (every axis contained) and on
    /// a [`CapabilitySet::EMPTY`] target it is every runtime-enforced proposed
    /// axis.
    #[must_use]
    pub fn unenforceable_for(&self, jail: JailForTarget) -> BTreeSet<Capability> {
        self.proposed
            .iter()
            .copied()
            .filter(|&c| is_runtime_unenforceable_for(c, jail))
            .collect()
    }

    /// The proposed capabilities unenforceable under the conservative
    /// refuse-gap posture (no jail) — preserved for callers that have not
    /// threaded a target through.
    #[must_use]
    pub fn unenforceable(&self) -> BTreeSet<Capability> {
        self.unenforceable_for(JailForTarget::REFUSE_GAP)
    }

    /// Whether the scan alone forces a refuse for the given target: it found an
    /// opaque construct, or it proposed a capability the target's jail cannot
    /// contain.
    #[must_use]
    pub fn must_refuse_for(&self, jail: JailForTarget) -> bool {
        !self.opacities.is_empty() || !self.unenforceable_for(jail).is_empty()
    }

    /// Whether the scan alone forces a refuse under the conservative refuse-gap
    /// posture (no jail).
    #[must_use]
    pub fn must_refuse(&self) -> bool {
        self.must_refuse_for(JailForTarget::REFUSE_GAP)
    }
}

/// Scan one wrapper source file for capability-bearing paths and opacity
/// triggers.
///
/// A file that does not lex yields an [`Opacity::DoesNotLex`] — NEVER an empty
/// proposed set, which would silently under-propose. `file` is a display label
/// used only in diagnostics, parsed once into [`TerminalSafe`] here since a
/// file name is untrusted; `src` is the file text.
#[must_use]
pub fn scan_source(file: &str, src: &str) -> ScanOutcome {
    let file = TerminalSafe::sanitize(file);
    let Ok(ts) = TokenStream::from_str(src) else {
        return ScanOutcome {
            proposed: BTreeSet::new(),
            opacities: vec![Opacity::DoesNotLex { file }],
        };
    };
    let mut outcome = ScanOutcome::default();
    scan_stream(&file, ts, &mut outcome);
    outcome
}

/// Union the scan over a whole set of `(file, source)` pairs — the wrapper's
/// every `.rs` file. The proposed set is the union; any file's opacity trigger
/// makes the whole wrapper refuse.
#[must_use]
pub fn scan_sources<'a>(sources: impl IntoIterator<Item = (&'a str, &'a str)>) -> ScanOutcome {
    let mut acc = ScanOutcome::default();
    for (file, src) in sources {
        acc.absorb(scan_source(file, src));
    }
    acc
}

/// Walk a token stream, recording capability paths, bare idents, and opacity
/// triggers. Recurses into every delimited group (fn bodies, `impl` blocks) so
/// a construct nowhere near the top level is still seen.
fn scan_stream(file: &TerminalSafe, ts: TokenStream, out: &mut ScanOutcome) {
    let toks: Vec<TokenTree> = ts.into_iter().collect();
    for i in 0..toks.len() {
        let Some(tok) = toks.get(i) else { continue };
        match tok {
            TokenTree::Ident(id) => scan_ident(file, &toks, i, id, out),
            // `#[path = "…"]` / `#[link(…)]` attribute — a module or native
            // library whose source is elsewhere.
            TokenTree::Punct(p) if p.as_char() == '#' => scan_attribute(file, &toks, i, p, out),
            _ => {}
        }
        if let Some(TokenTree::Group(g)) = toks.get(i) {
            scan_stream(file, g.stream(), out);
        }
    }
}

/// Handle an identifier token at index `i`: the `extern`/`libc`/`include`
/// opacity keywords and the capability-bearing `first::second` / bare-ident
/// path matches.
fn scan_ident(
    file: &TerminalSafe,
    toks: &[TokenTree],
    i: usize,
    id: &proc_macro2::Ident,
    out: &mut ScanOutcome,
) {
    // Compare on the UN-RAW spelling: a raw identifier `r#std` is the crate root
    // `std` to the Rust resolver, so `use r#std as s;` reaches `std::fs` exactly
    // as `use std as s;` does. Stripping the `r#` before every crate-root/keyword
    // match closes that aliasing evasion for this guard AND the path/extern/libc/
    // include matches below, which all key off `name`.
    let raw = id.to_string();
    let name = raw.strip_prefix("r#").unwrap_or(&raw);
    let line = id.span().start().line;
    match name {
        // `extern` block / `extern "C" fn` is native FFI. Bare `extern crate`
        // (a 2015-edition import) is NOT, so require the next token is not
        // `crate`.
        "extern" => {
            let next_is_crate =
                matches!(toks.get(i + 1), Some(TokenTree::Ident(n)) if *n == "crate");
            if !next_is_crate {
                out.opacities.push(Opacity::NativeFfi {
                    file: file.clone(),
                    line,
                });
                out.proposed.insert(Capability::NativeFfi);
            }
            return;
        }
        // `libc::…` — the canonical raw-syscall crate.
        "libc" if next_is_colon(toks, i) => {
            out.opacities.push(Opacity::NativeFfi {
                file: file.clone(),
                line,
            });
            out.proposed.insert(Capability::NativeFfi);
            return;
        }
        // `include!(…)` pulls in unscanned code.
        "include" if next_is_bang(toks, i) => {
            out.opacities.push(Opacity::UnenumerableModule {
                file: file.clone(),
                line,
                construct: "include!",
            });
            return;
        }
        // `asm!(…)` / `global_asm!(…)` — inline assembly issues raw syscalls
        // whose effects the scan cannot enumerate: NativeFfi opacity.
        "asm" | "global_asm" if next_is_bang(toks, i) => {
            out.opacities.push(Opacity::NativeFfi {
                file: file.clone(),
                line,
            });
            out.proposed.insert(Capability::NativeFfi);
            return;
        }
        _ => {}
    }
    // Bare capability idents (matched by name alone).
    for (bare, cap) in BARE_IDENTS {
        if name == *bare {
            out.proposed.insert(*cap);
        }
    }
    // `first :: second` — id, `:`, `:`, second-ident.
    if let Some(second) = colon_colon_ident(toks, i) {
        let mut rule_matched = false;
        for rule in PATH_RULES {
            if name == rule.first && second == rule.second {
                out.proposed.insert(rule.cap);
                rule_matched = true;
            }
        }
        // Catch-all: a `std::X` or `core::X` path whose second segment is not
        // in the allowlist is treated as an unenumerable OS/platform surface.
        // The allowlist is a closed set whose complement must refuse, not admit.
        // Over-refusing is the safe direction: an author who genuinely needs a
        // recognised-safe std sub-module will find it in the allowlist.
        if !rule_matched && (name == "std" || name == "core") {
            out.opacities.push(Opacity::UnenumerableModule {
                file: file.clone(),
                line,
                construct: "std::<unrecognised>",
            });
        }
    } else if name == "std" || name == "core" {
        // A `std` / `core` crate-root token that did NOT continue as a
        // recognised `::Ident` path. Deny by default on the CONTINUATION SHAPE,
        // rather than enumerate evasions: any shape that can rename or splat the
        // crate root is unenumerable and refused.
        //
        //   * followed by `::` whose next-next token is NOT an `Ident` — a
        //     `{…}` group (`std::{self as s}`, `std::{fs, …}`) or a `*` glob
        //     (`std::*`). A `self`-alias renames the crate root; a group or glob
        //     splats it. `colon_colon_ident` (which requires a 4th-token Ident)
        //     returned None for these, so neither the path rules nor the
        //     `std::<unrecognised>` catch-all above could see them.
        //   * not followed by `::` at all — an alias or bare import of the crate
        //     root: `use std as s;`, `use core as c;`, `extern crate std;`,
        //     `extern crate std as s;`. The alias bears a full-crate surface the
        //     path rules never see (`s::fs::…` matches nothing).
        //
        // Either way the whole crate root is reachable under a name the scan
        // cannot follow, so refuse — matching the closed-allowlist policy of the
        // catch-all above.
        let opaque = if next_is_colon(toks, i) {
            // `std ::` — the 4th token after `std` decides. `colon_colon_ident`
            // already handled the `::Ident` case (returned Some), so reaching
            // here with a `::` means the continuation is a Group or glob.
            !matches!(toks.get(i + 3), Some(TokenTree::Ident(_)))
        } else {
            // Bare / aliased crate root.
            true
        };
        if opaque {
            out.opacities.push(Opacity::UnenumerableModule {
                file: file.clone(),
                line,
                construct: "std-root-alias",
            });
        }
    }
}

/// Handle a `#` at index `i`: an `#[path = "…"]` (unenumerable module) or
/// `#[link(…)]` (native library) attribute.
fn scan_attribute(
    file: &TerminalSafe,
    toks: &[TokenTree],
    i: usize,
    p: &proc_macro2::Punct,
    out: &mut ScanOutcome,
) {
    let Some(TokenTree::Group(g)) = toks.get(i + 1) else {
        return;
    };
    if g.delimiter() != Delimiter::Bracket {
        return;
    }
    let inner: String = g
        .stream()
        .to_string()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let construct = if inner.starts_with("link") {
        // `#[link(...)]` links a native library.
        out.proposed.insert(Capability::NativeFfi);
        "#[link]"
    } else if inner.starts_with("path=") {
        "#[path]"
    } else {
        return;
    };
    out.opacities.push(Opacity::UnenumerableModule {
        file: file.clone(),
        line: p.span().start().line,
        construct,
    });
}

/// Whether the token after `i` is a `:` punct (the start of a `::` path).
fn next_is_colon(toks: &[TokenTree], i: usize) -> bool {
    matches!(toks.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == ':')
}

/// Whether the token after `i` is a `!` punct (a macro invocation).
fn next_is_bang(toks: &[TokenTree], i: usize) -> bool {
    matches!(toks.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == '!')
}

/// The identifier following a `:: ` at index `i` (`id :: second`), if the two
/// puncts are both colons and the fourth token is an identifier.
fn colon_colon_ident(toks: &[TokenTree], i: usize) -> Option<String> {
    let (Some(TokenTree::Punct(c1)), Some(TokenTree::Punct(c2)), Some(TokenTree::Ident(second))) =
        (toks.get(i + 1), toks.get(i + 2), toks.get(i + 3))
    else {
        return None;
    };
    if c1.as_char() == ':' && c2.as_char() == ':' {
        // Un-raw the trailing segment too: `std::r#fs` reaches `std::fs`.
        let s = second.to_string();
        Some(s.strip_prefix("r#").unwrap_or(&s).to_owned())
    } else {
        None
    }
}

/// The install-time reconcile verdict for a wrapper: either admissible (its
/// effects are all containable, and the declaration covers what the scan sees)
/// or refused, carrying every reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The wrapper may be installed. `declared` is echoed for the consent
    /// summary; `native_ffi` flags whether the author consented to
    /// [`Capability::NativeFfi`] (surfaced loudly) — always `false` here in this
    /// release, since native-ffi is unenforceable and thus refused, but the
    /// field keeps the consent surface explicit.
    Admit {
        /// The author's declared set (the consent surface).
        declared: BTreeSet<Capability>,
    },
    /// The wrapper is refused. Every reason is listed so the author sees the
    /// whole picture, not just the first blocker.
    Refuse {
        /// The reasons the wrapper cannot be admitted.
        reasons: Vec<RefuseReason>,
        /// The scan's proposed set, surfaced so the author can reconcile their
        /// declaration against what the wrapper actually reaches.
        proposed: BTreeSet<Capability>,
    },
}

/// One reason a wrapper is refused at install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefuseReason {
    /// The author DECLARED a capability Ipê cannot enforce at run (no runtime
    /// jail exists in this release). Refuse rather than admit unenforced.
    DeclaredUnenforceable {
        /// The declared-but-unenforceable capability.
        cap: Capability,
    },
    /// The scan INFERRED the wrapper reaches a capability Ipê cannot enforce at
    /// run — whether or not it was declared. The wrapper's runtime effects are
    /// uncontained, so it cannot be admitted.
    InferredUnenforceable {
        /// The inferred-but-unenforceable capability.
        cap: Capability,
    },
    /// The scan hit an opaque construct (native FFI, an unenumerable module, a
    /// non-lexing file) that makes the inference untrustworthy as a completeness
    /// claim.
    Opaque {
        /// The opacity trigger.
        opacity: Opacity,
    },
    /// The wrapper crate declares a non-`std` Cargo dependency. A dependency's
    /// capabilities live in source the scan never opens (`reqwest::get` is
    /// Network the wrapper's own `.rs` never names), so a wrapper with external
    /// deps is opaque and refused in this release.
    NonStdDependency {
        /// The dependency name, terminal-safe: it comes from the wrapper's
        /// own `Cargo.toml` and is shown in the refusal.
        name: TerminalSafe,
    },
}

impl std::fmt::Display for RefuseReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeclaredUnenforceable { cap } => write!(
                f,
                "declares `{}`, which has no runtime enforcement in this release — a wrapper's \
                 Rust runs unsandboxed at `ipe dev run`, so this capability cannot be contained yet",
                cap.as_str()
            ),
            Self::InferredUnenforceable { cap } => write!(
                f,
                "reaches `{}` (inferred from its source), which has no runtime enforcement in \
                 this release — its effects would be uncontained at run",
                cap.as_str()
            ),
            Self::Opaque { opacity } => write!(f, "{opacity}"),
            Self::NonStdDependency { name } => write!(
                f,
                "depends on `{name}` — a dependency's capabilities live in source this scan \
                 cannot see, so a wrapper with external dependencies cannot be admitted yet"
            ),
        }
    }
}

/// Reconcile a wrapper's declared capability set against the scan of its source,
/// and decide admissibility **per axis against the target's confined set**.
///
/// The hand-off (ADR 0004): the refuse-until-jail posture is lifted to
/// admit-and-isolate on exactly the axes the target's jail confines. Each check
/// is per axis against [`JailForTarget::confined`]:
///
/// - A declared or inferred runtime-enforced axis is **admitted** where the jail
///   confines it (contained at the OS boundary), and **refused** where it does
///   not. A [`CapabilitySet::FULL`] target (Linux/macOS) admits every axis,
///   identical to the old whole-target `Holds`; a [`CapabilitySet::EMPTY`] target
///   refuses every runtime-enforced axis, identical to the old `RefuseGap`. A
///   partial-coverage target admits the axes it confines and refuses the rest.
/// - An opaque construct (native FFI, an unenumerable module, a non-lexing file)
///   or a non-`std` dependency hides which axes the wrapper actually reaches, so
///   it is safe **only where the jail confines EVERY runtime-enforced axis**
///   ([`CapabilitySet::is_full`]) — there, the boundary contains whatever hides
///   (contained, not caught). On a partial or empty set the hidden effect could
///   fall on an unconfined axis, so it **refuses**. This is the same
///   whole-target guarantee as before on a full set, tightened to honesty on a
///   partial one.
///
/// `non_std_deps` is the wrapper crate's non-`std` dependency names.
#[must_use]
pub fn reconcile_for(
    declared: &BTreeSet<Capability>,
    scan: &ScanOutcome,
    non_std_deps: &[String],
    jail: JailForTarget,
) -> Verdict {
    let mut reasons = Vec::new();

    // A declared unenforceable capability: the author's own claim names an
    // effect the jail does not confine on this target's axis.
    for &cap in declared {
        if is_runtime_unenforceable_for(cap, jail) {
            reasons.push(RefuseReason::DeclaredUnenforceable { cap });
        }
    }
    // An inferred unenforceable capability the declaration did NOT already
    // account for (avoid a duplicate reason for the same axis).
    for cap in scan.unenforceable_for(jail) {
        if !declared.contains(&cap) {
            reasons.push(RefuseReason::InferredUnenforceable { cap });
        }
    }

    // Opaque constructs and non-`std` dependencies hide WHICH axes are reached,
    // so they are only contained where the jail confines EVERY runtime-enforced
    // axis. On a partial or empty confined set the hidden effect could land on
    // an unconfined axis, so refuse.
    if !jail.confined().is_full() {
        for opacity in &scan.opacities {
            reasons.push(RefuseReason::Opaque {
                opacity: opacity.clone(),
            });
        }
        for name in non_std_deps {
            reasons.push(RefuseReason::NonStdDependency {
                name: TerminalSafe::sanitize(name),
            });
        }
    }

    if reasons.is_empty() {
        Verdict::Admit {
            declared: declared.clone(),
        }
    } else {
        Verdict::Refuse {
            reasons,
            proposed: scan.proposed.clone(),
        }
    }
}

/// Reconcile under the conservative refuse-gap posture (no jail) — preserved for
/// callers that have not yet threaded a target through. Equivalent to
/// [`reconcile_for`] with [`JailForTarget::REFUSE_GAP`].
#[must_use]
pub fn reconcile(
    declared: &BTreeSet<Capability>,
    scan: &ScanOutcome,
    non_std_deps: &[String],
) -> Verdict {
    reconcile_for(declared, scan, non_std_deps, JailForTarget::REFUSE_GAP)
}

/// Parse a raw `[rust.wrapper] capabilities = [...]` list into a typed set.
///
/// Fail-closed on an unknown name: a typo'd capability is a LOUD rejection,
/// never a capability the reconcile then silently fails to compare.
///
/// # Errors
///
/// The offending token, when a name is not one of the closed capability
/// vocabulary (`Capability::from_str`'s [`ipe_kernels::UnknownCapability`]).
pub fn parse_declared(
    names: &[String],
) -> Result<BTreeSet<Capability>, ipe_kernels::UnknownCapability> {
    let mut set = BTreeSet::new();
    for name in names {
        set.insert(Capability::from_str(name)?);
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(o: &ScanOutcome) -> Vec<&'static str> {
        o.proposed.iter().map(|c| c.as_str()).collect()
    }

    #[test]
    fn a_std_net_path_proposes_network() {
        let src = "pub fn f() { let _ = std::net::TcpStream::connect(\"x\"); }";
        let o = scan_source("lib.rs", src);
        assert!(o.proposed.contains(&Capability::Network), "{:?}", caps(&o));
        assert!(o.opacities.is_empty());
        assert!(o.must_refuse(), "network is unenforceable at run");
    }

    #[test]
    fn std_fs_and_process_and_env_are_each_proposed() {
        let src = "fn f() { std::fs::read(\"a\"); std::process::Command::new(\"x\"); std::env::var(\"Y\"); }";
        let o = scan_source("lib.rs", src);
        assert!(o.proposed.contains(&Capability::Filesystem));
        assert!(o.proposed.contains(&Capability::Subprocess));
        assert!(o.proposed.contains(&Capability::Env));
    }

    #[test]
    fn a_path_split_across_lines_is_still_found() {
        // The token model does not care about the newline between `std` and `::`.
        let src = "fn f() { let _ = std\n  ::\n  net::UdpSocket::bind(\"x\"); }";
        let o = scan_source("lib.rs", src);
        assert!(o.proposed.contains(&Capability::Network), "{:?}", caps(&o));
    }

    #[test]
    fn a_capability_named_in_a_string_or_comment_is_invisible() {
        // `std::net` appears only inside a string literal and a comment — the
        // token model never sees it as a path, so no false positive.
        let src = "fn f() -> &'static str {\n    // std::net::TcpStream is not used here\n    \"std::net::TcpStream\"\n}";
        let o = scan_source("lib.rs", src);
        assert!(
            o.proposed.is_empty(),
            "a string/comment mention must not propose: {:?}",
            caps(&o)
        );
        assert!(!o.must_refuse());
    }

    #[test]
    fn an_extern_block_is_native_ffi_and_refuses() {
        let src = "extern \"C\" { fn getpid() -> i32; }";
        let o = scan_source("lib.rs", src);
        assert!(o.proposed.contains(&Capability::NativeFfi));
        assert!(
            matches!(o.opacities.first(), Some(Opacity::NativeFfi { .. })),
            "{:?}",
            o.opacities
        );
        assert!(o.must_refuse());
    }

    #[test]
    fn an_extern_crate_is_not_native_ffi() {
        // `extern crate foo;` is a 2015-edition import, not an FFI block.
        let src = "extern crate serde; pub fn f() -> i32 { 1 }";
        let o = scan_source("lib.rs", src);
        assert!(
            !o.proposed.contains(&Capability::NativeFfi),
            "extern crate must not trip native-ffi: {:?}",
            o.opacities
        );
        assert!(o.opacities.is_empty());
    }

    #[test]
    fn a_libc_reference_is_native_ffi() {
        let src = "fn f() { unsafe { libc::exit(0); } }";
        let o = scan_source("lib.rs", src);
        assert!(o.proposed.contains(&Capability::NativeFfi));
        assert!(o.must_refuse());
    }

    #[test]
    fn an_include_macro_is_an_unenumerable_module() {
        let src = "include!(\"generated.rs\"); pub fn f() -> i32 { 1 }";
        let o = scan_source("lib.rs", src);
        assert!(
            matches!(
                o.opacities.first(),
                Some(Opacity::UnenumerableModule {
                    construct: "include!",
                    ..
                })
            ),
            "{:?}",
            o.opacities
        );
        assert!(o.must_refuse());
    }

    #[test]
    fn a_path_attribute_is_an_unenumerable_module() {
        let src = "#[path = \"other.rs\"]\nmod other;\npub fn f() -> i32 { 1 }";
        let o = scan_source("lib.rs", src);
        assert!(
            matches!(
                o.opacities.first(),
                Some(Opacity::UnenumerableModule {
                    construct: "#[path]",
                    ..
                })
            ),
            "{:?}",
            o.opacities
        );
        assert!(o.must_refuse());
    }

    #[test]
    fn a_crate_root_alias_of_std_is_an_unenumerable_module() {
        // `use std as s;` renames the crate root, so `s::fs::write(...)` matches
        // no path rule and would otherwise scan to an empty, admissible set. The
        // alias itself must refuse as an unenumerable module.
        let src = "use std as s; pub fn f() { s::fs::write(\"a\", \"b\").ok(); }";
        let o = scan_source("lib.rs", src);
        assert!(
            o.opacities.iter().any(|op| matches!(
                op,
                Opacity::UnenumerableModule {
                    construct: "std-root-alias",
                    ..
                }
            )),
            "aliasing the std crate root must refuse: {:?}",
            o.opacities
        );
        assert!(
            o.must_refuse(),
            "a hidden-capability alias must force a refuse"
        );
    }

    #[test]
    fn a_crate_root_alias_reaching_subprocess_refuses_exactly_as_the_unaliased_form() {
        // `use std as s; s::process::Command::new(...)` reaches the subprocess
        // surface through the aliased crate root: `s::process` matches no path
        // rule, so absent the crate-root guard the scan would admit a hidden
        // Subprocess capability. The alias declaration itself must refuse, and it
        // must do so identically to the un-aliased `std::process` form.
        let aliased = scan_source(
            "lib.rs",
            "use std as s; pub fn f() { s::process::Command::new(\"sh\").spawn().ok(); }",
        );
        assert!(
            aliased.opacities.iter().any(|op| matches!(
                op,
                Opacity::UnenumerableModule {
                    construct: "std-root-alias",
                    ..
                }
            )),
            "aliasing the crate root to reach subprocess must refuse: {:?}",
            aliased.opacities
        );
        assert!(
            aliased.must_refuse(),
            "the aliased subprocess reach must force a refuse"
        );

        let unaliased = scan_source(
            "lib.rs",
            "pub fn f() { std::process::Command::new(\"sh\").spawn().ok(); }",
        );
        assert!(
            unaliased.must_refuse(),
            "the un-aliased subprocess reach must also refuse"
        );
        assert!(
            unaliased.proposed.contains(&Capability::Subprocess),
            "the un-aliased form proposes Subprocess: {:?}",
            caps(&unaliased)
        );
    }

    #[test]
    fn a_crate_root_alias_of_core_is_an_unenumerable_module() {
        let src = "use core as c; pub fn f() -> c::cmp::Ordering { c::cmp::Ordering::Less }";
        let o = scan_source("lib.rs", src);
        assert!(
            o.opacities.iter().any(|op| matches!(
                op,
                Opacity::UnenumerableModule {
                    construct: "std-root-alias",
                    ..
                }
            )),
            "aliasing the core crate root must refuse: {:?}",
            o.opacities
        );
        assert!(o.must_refuse());
    }

    #[test]
    fn an_extern_crate_std_is_an_unenumerable_module() {
        // `extern crate std;` / `extern crate std as s;` is the 2015-edition
        // crate-root alias — the same evasion, caught when the scan reaches the
        // `std` ident (which is not followed by `::`).
        let src = "extern crate std as s; pub fn f() { s::fs::write(\"a\", \"b\").ok(); }";
        let o = scan_source("lib.rs", src);
        assert!(
            o.opacities.iter().any(|op| matches!(
                op,
                Opacity::UnenumerableModule {
                    construct: "std-root-alias",
                    ..
                }
            )),
            "extern crate std alias must refuse: {:?}",
            o.opacities
        );
        assert!(o.must_refuse());
    }

    #[test]
    fn an_extern_crate_of_a_third_party_still_does_not_refuse_here() {
        // A non-std `extern crate` is a plain dependency import; the crate-root
        // refuse rule is scoped to `std` / `core` and must not widen to it.
        let src = "extern crate serde as s; pub fn f() -> i32 { 1 }";
        let o = scan_source("lib.rs", src);
        assert!(
            !o.opacities.iter().any(|op| matches!(
                op,
                Opacity::UnenumerableModule {
                    construct: "std-root-alias",
                    ..
                }
            )),
            "a third-party extern crate must not trip the std-root rule: {:?}",
            o.opacities
        );
    }

    #[test]
    fn a_raw_ident_alias_of_std_still_refuses() {
        // `use r#std as s;` — the raw identifier `r#std` is the crate root `std`
        // to the resolver, so `s::fs::write(...)` reaches the filesystem. The scan
        // must compare on the un-raw spelling and still refuse the alias.
        let src = "use r#std as s; pub fn f() { s::fs::write(\"a\", \"b\").ok(); }";
        let o = scan_source("lib.rs", src);
        assert!(
            o.opacities.iter().any(|op| matches!(
                op,
                Opacity::UnenumerableModule {
                    construct: "std-root-alias",
                    ..
                }
            )),
            "a raw-identifier crate-root alias must refuse: {:?}",
            o.opacities
        );
        assert!(o.must_refuse(), "r#std aliasing must force a refuse");
    }

    #[test]
    fn a_nested_self_alias_of_std_still_refuses() {
        // `pub use std::{self as s};` renames the crate root through a `::{…}`
        // group. `std` is followed by `::` then a Group (not an Ident), so neither
        // the path rules nor the `std::<unrecognised>` catch-all fire — the
        // continuation-shape guard must refuse the self-import group.
        let src = "pub use std::{self as s}; pub fn f() { s::fs::write(\"a\", \"b\").ok(); }";
        let o = scan_source("lib.rs", src);
        assert!(
            o.opacities.iter().any(|op| matches!(
                op,
                Opacity::UnenumerableModule {
                    construct: "std-root-alias",
                    ..
                }
            )),
            "a nested `::{{self as s}}` crate-root alias must refuse: {:?}",
            o.opacities
        );
        assert!(o.must_refuse(), "a self-alias group must force a refuse");
    }

    #[test]
    fn a_glob_import_of_std_still_refuses() {
        // `use std::*;` splats the crate root into scope, so a later bare `fs`
        // resolves to `std::fs`. `std` is followed by `::` then a `*` glob (not an
        // Ident), which the continuation-shape guard must refuse.
        let src = "use std::*; pub fn f() { fs::write(\"a\", \"b\").ok(); }";
        let o = scan_source("lib.rs", src);
        assert!(
            o.opacities.iter().any(|op| matches!(
                op,
                Opacity::UnenumerableModule {
                    construct: "std-root-alias",
                    ..
                }
            )),
            "a glob import of the std crate root must refuse: {:?}",
            o.opacities
        );
        assert!(o.must_refuse(), "a std glob import must force a refuse");
    }

    #[test]
    fn a_non_lexing_source_refuses_never_proposes_empty() {
        // An unbalanced delimiter does not tokenise — must be DoesNotLex, not a
        // silent empty proposed set (the fail-closed rule on the lex path).
        let src = "pub fn f( { ) unbalanced";
        let o = scan_source("evil.rs", src);
        assert!(o.proposed.is_empty());
        assert!(
            matches!(o.opacities.first(), Some(Opacity::DoesNotLex { .. })),
            "{:?}",
            o.opacities
        );
        assert!(o.must_refuse(), "a non-lexing file must force a refuse");
    }

    #[test]
    fn a_pure_compute_wrapper_proposes_nothing_and_installs() {
        let src = "pub struct Engine { seed: i64 }\n\
                   pub fn make(seed: i64) -> Engine { Engine { seed } }\n\
                   pub fn describe(e: Engine) -> String { format!(\"engine<{}>\", e.seed) }";
        let o = scan_source("lib.rs", src);
        assert!(o.proposed.is_empty(), "{:?}", caps(&o));
        assert!(!o.must_refuse(), "a pure wrapper must be admissible");
    }

    #[test]
    fn clock_and_random_are_proposed_but_do_not_force_refuse() {
        // `std::time` proposes Clock, which is NOT runtime-unenforceable — a
        // pure clock read leaks no authority, so it does not force a refuse.
        let src = "fn f() { let _ = std::time::Instant::now(); }";
        let o = scan_source("lib.rs", src);
        assert!(o.proposed.contains(&Capability::Clock));
        assert!(
            !o.must_refuse(),
            "clock is non-determinism, not exfiltration — admissible unenforced"
        );
    }

    #[test]
    fn scan_sources_unions_across_files() {
        let a = ("a.rs", "fn f() { std::fs::read(\"x\"); }");
        let b = ("b.rs", "fn g() { std::net::TcpStream::connect(\"y\"); }");
        let o = scan_sources([a, b]);
        assert!(o.proposed.contains(&Capability::Filesystem));
        assert!(o.proposed.contains(&Capability::Network));
    }

    #[test]
    fn parse_declared_types_the_set_and_rejects_an_unknown_name() {
        let ok = parse_declared(&["network".to_owned(), "filesystem".to_owned()]).expect("parses");
        assert!(ok.contains(&Capability::Network));
        assert!(ok.contains(&Capability::Filesystem));
        let err = parse_declared(&["filesytem".to_owned()]).unwrap_err();
        assert_eq!(err.0, "filesytem");
    }

    fn set(caps: &[Capability]) -> BTreeSet<Capability> {
        caps.iter().copied().collect()
    }

    /// The refuse reasons + surfaced proposed set from a verdict, or `None` when
    /// it admitted. Lets a test assert on the reasons without a `panic!` arm.
    fn refusal(v: &Verdict) -> Option<(&[RefuseReason], &BTreeSet<Capability>)> {
        match v {
            Verdict::Refuse { reasons, proposed } => Some((reasons, proposed)),
            Verdict::Admit { .. } => None,
        }
    }

    #[test]
    fn a_pure_wrapper_with_no_declaration_is_admitted() {
        let scan = scan_source("lib.rs", "pub fn make(x: i64) -> i64 { x + 1 }");
        let v = reconcile(&BTreeSet::new(), &scan, &[]);
        assert!(matches!(v, Verdict::Admit { .. }), "{v:?}");
    }

    #[test]
    fn a_declared_network_wrapper_is_refused_no_runtime_jail() {
        // Even an HONESTLY declared network wrapper cannot install: there is no
        // runtime sandbox to contain the socket at `ipe dev run`.
        let scan = scan_source(
            "lib.rs",
            "pub fn f() { std::net::TcpStream::connect(\"x\"); }",
        );
        let v = reconcile(&set(&[Capability::Network]), &scan, &[]);
        let (reasons, _) = refusal(&v).expect("a network wrapper must be refused");
        // Declared-unenforceable fires; inferred is de-duped since it was declared.
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, RefuseReason::DeclaredUnenforceable { cap } if *cap == Capability::Network)),
            "{reasons:?}"
        );
        assert!(
            !reasons
                .iter()
                .any(|r| matches!(r, RefuseReason::InferredUnenforceable { .. })),
            "declared axis must not also fire inferred: {reasons:?}"
        );
    }

    #[test]
    fn an_undeclared_but_inferred_network_wrapper_is_refused() {
        // The author declared nothing, but the scan finds a socket — the hidden
        // effect is refused, and the proposed set is surfaced.
        let scan = scan_source(
            "lib.rs",
            "pub fn f() { std::net::TcpStream::connect(\"x\"); }",
        );
        let v = reconcile(&BTreeSet::new(), &scan, &[]);
        let (reasons, proposed) = refusal(&v).expect("an inferred network wrapper must be refused");
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, RefuseReason::InferredUnenforceable { cap } if *cap == Capability::Network)),
            "{reasons:?}"
        );
        assert!(proposed.contains(&Capability::Network), "surfaces proposed");
    }

    #[test]
    fn a_clock_only_wrapper_is_admitted() {
        // Clock is non-determinism, not exfiltration — admissible even unenforced.
        let scan = scan_source(
            "lib.rs",
            "pub fn f() -> u128 { std::time::Instant::now().elapsed().as_nanos() }",
        );
        let v = reconcile(&set(&[Capability::Clock]), &scan, &[]);
        assert!(matches!(v, Verdict::Admit { .. }), "{v:?}");
    }

    #[test]
    fn a_non_std_dependency_refuses_even_a_pure_looking_wrapper() {
        let scan = scan_source("lib.rs", "pub fn f() -> i64 { reqwest_get() }");
        let v = reconcile(&BTreeSet::new(), &scan, &["reqwest".to_owned()]);
        let (reasons, _) = refusal(&v).expect("a wrapper with a non-std dep must be refused");
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, RefuseReason::NonStdDependency { name } if name.as_str() == "reqwest")),
            "{reasons:?}"
        );
    }

    #[test]
    fn an_opaque_extern_wrapper_is_refused() {
        let scan = scan_source("lib.rs", "extern \"C\" { fn getpid() -> i32; }");
        let v = reconcile(&BTreeSet::new(), &scan, &[]);
        assert!(
            matches!(&v, Verdict::Refuse { reasons, .. } if reasons.iter().any(|r| matches!(r, RefuseReason::Opaque { .. }))),
            "{v:?}"
        );
    }

    #[test]
    fn is_runtime_unenforceable_partitions_the_vocabulary() {
        for cap in Capability::ALL {
            let unenf = is_runtime_unenforceable(*cap);
            match cap {
                // Non-determinism, the `unsafe` provenance label, and the
                // `custom-element` browser-JS disclosure carry no server-side
                // isolation surface — never refused-until-jail.
                Capability::Clock
                | Capability::Random
                | Capability::Unsafe
                | Capability::CustomElement
                | Capability::JsPort(_) => {
                    assert!(!unenf, "{cap:?}");
                }
                _ => assert!(unenf, "{cap:?} must be refused until a runtime jail exists"),
            }
        }
    }

    #[test]
    fn on_a_jail_holds_target_no_axis_is_unenforceable() {
        // The whole point of the hand-off: where the jail holds, every axis is
        // contained → nothing is unenforceable.
        for cap in Capability::ALL {
            assert!(
                !is_runtime_unenforceable_for(*cap, JailForTarget::FULLY_CONFINED),
                "{cap:?} must be enforceable (contained) where the jail holds"
            );
        }
    }

    #[test]
    fn on_a_refuse_gap_target_the_runtime_axes_stay_unenforceable() {
        // A refuse-gap target keeps the pre-jail posture.
        for cap in Capability::ALL {
            let unenf = is_runtime_unenforceable_for(*cap, JailForTarget::REFUSE_GAP);
            match cap {
                Capability::Clock
                | Capability::Random
                | Capability::Unsafe
                | Capability::CustomElement
                | Capability::JsPort(_) => {
                    assert!(!unenf, "{cap:?}");
                }
                _ => assert!(unenf, "{cap:?} stays refused on a refuse-gap target"),
            }
        }
    }

    #[test]
    fn reconcile_admits_a_network_wrapper_where_the_jail_holds() {
        // A declared-network wrapper, refused on a refuse-gap target, is ADMITTED
        // and isolated where the jail holds (the refuse-until-jail hand-off).
        let declared: BTreeSet<Capability> = BTreeSet::from([Capability::Network]);
        let scan = scan_source(
            "lib.rs",
            "pub fn f() { let _ = std::net::TcpStream::connect(\"x\"); }",
        );
        assert!(matches!(
            reconcile_for(&declared, &scan, &[], JailForTarget::REFUSE_GAP),
            Verdict::Refuse { .. }
        ));
        assert!(matches!(
            reconcile_for(&declared, &scan, &[], JailForTarget::FULLY_CONFINED),
            Verdict::Admit { .. }
        ));
    }

    #[test]
    fn reconcile_admits_an_opaque_wrapper_where_the_jail_holds() {
        // An opaque (native FFI) wrapper is CONTAINED by the jail, so it is
        // admitted where the jail holds (contained, not caught) — still refused
        // on a refuse-gap target.
        let scan = scan_source("lib.rs", "extern \"C\" { fn getpid() -> i32; }");
        assert!(matches!(
            reconcile_for(&BTreeSet::new(), &scan, &[], JailForTarget::REFUSE_GAP),
            Verdict::Refuse { .. }
        ));
        assert!(matches!(
            reconcile_for(&BTreeSet::new(), &scan, &[], JailForTarget::FULLY_CONFINED),
            Verdict::Admit { .. }
        ));
    }

    #[test]
    fn reconcile_admits_a_non_std_dep_wrapper_where_the_jail_holds() {
        // A non-std dependency's effects are invisible to the scan, but the jail
        // contains them at runtime → admitted where it holds.
        let scan = scan_source("lib.rs", "pub fn f() -> i64 { 0 }");
        assert!(matches!(
            reconcile_for(
                &BTreeSet::new(),
                &scan,
                &["reqwest".to_owned()],
                JailForTarget::REFUSE_GAP
            ),
            Verdict::Refuse { .. }
        ));
        assert!(matches!(
            reconcile_for(
                &BTreeSet::new(),
                &scan,
                &["reqwest".to_owned()],
                JailForTarget::FULLY_CONFINED
            ),
            Verdict::Admit { .. }
        ));
    }

    // ── the per-axis (partial-coverage) representation ───────────────────────

    #[test]
    fn a_partial_set_is_never_full_and_a_full_set_is_never_partial() {
        // make-invalid-states-unrepresentable: the ONLY way to say "fully
        // contained" is a set equal to FULL. A subset is never full.
        assert!(CapabilitySet::FULL.is_full());
        assert!(!CapabilitySet::EMPTY.is_full());
        assert!(CapabilitySet::EMPTY.is_empty());
        let partial = CapabilitySet::EMPTY
            .with(Capability::Subprocess)
            .with(Capability::Filesystem)
            .with(Capability::Env);
        assert!(!partial.is_full(), "a strict subset must not read as full");
        assert!(!partial.is_empty());
        assert!(partial.confines(Capability::Subprocess));
        assert!(!partial.confines(Capability::Network));
    }

    #[test]
    fn clock_and_random_are_never_confined_members_but_stay_enforceable() {
        // Non-determinism axes are never members of a confined set, yet
        // `is_runtime_unenforceable_for` reports them enforceable on every
        // target — they carry no isolation surface.
        for set in [CapabilitySet::EMPTY, CapabilitySet::FULL] {
            for cap in [Capability::Clock, Capability::Random] {
                assert!(!set.confines(cap), "{cap:?} is never a member");
                assert!(!is_runtime_unenforceable_for(
                    cap,
                    JailForTarget::Holds(set)
                ));
            }
        }
    }

    /// A hypothetical Windows-shaped partial-coverage target: Job Objects +
    /// launcher scrub confine subprocess/env/filesystem, but a restricted-token
    /// fallback cannot deny sockets, so `network` (and `database`, which lowers
    /// to network) leave the confined set.
    fn windows_partial_target() -> JailForTarget {
        JailForTarget::Holds(
            CapabilitySet::EMPTY
                .with(Capability::Subprocess)
                .with(Capability::Env)
                .with(Capability::Filesystem)
                .with(Capability::NativeFfi),
        )
    }

    #[test]
    fn a_partial_target_admits_confined_axes_and_refuse_gaps_the_rest() {
        // The load-bearing per-axis proof: on a target that confines filesystem
        // but NOT network, a filesystem wrapper admits while a network wrapper
        // refuses — each honestly, no over-claim.
        let jail = windows_partial_target();

        // Filesystem is confined → enforceable → admitted.
        assert!(!is_runtime_unenforceable_for(Capability::Filesystem, jail));
        let fs_scan = scan_source("lib.rs", "pub fn f() { std::fs::read(\"a\"); }");
        assert!(matches!(
            reconcile_for(&set(&[Capability::Filesystem]), &fs_scan, &[], jail),
            Verdict::Admit { .. }
        ));

        // Network is NOT confined → unenforceable → refused for that axis alone.
        assert!(is_runtime_unenforceable_for(Capability::Network, jail));
        let net_scan = scan_source(
            "lib.rs",
            "pub fn f() { std::net::TcpStream::connect(\"x\"); }",
        );
        let v = reconcile_for(&set(&[Capability::Network]), &net_scan, &[], jail);
        let (reasons, _) = refusal(&v).expect("a network wrapper refuses on a no-network target");
        assert!(
            reasons.iter().any(|r| matches!(
                r,
                RefuseReason::DeclaredUnenforceable { cap } if *cap == Capability::Network
            )),
            "{reasons:?}"
        );
    }

    #[test]
    fn a_partial_target_refuses_a_wrapper_reaching_one_confined_and_one_gapped_axis() {
        // A wrapper reaching BOTH a confined (filesystem) and a gapped (network)
        // axis refuses on the gapped axis only — the confined axis contributes no
        // reason, proving the decision is per axis, not whole-wrapper.
        let jail = windows_partial_target();
        let scan = scan_source(
            "lib.rs",
            "pub fn f() { std::fs::read(\"a\"); std::net::TcpStream::connect(\"x\"); }",
        );
        let v = reconcile_for(&BTreeSet::new(), &scan, &[], jail);
        let (reasons, _) = refusal(&v).expect("the network axis forces a refuse");
        assert!(
            reasons.iter().any(|r| matches!(
                r,
                RefuseReason::InferredUnenforceable { cap } if *cap == Capability::Network
            )),
            "{reasons:?}"
        );
        assert!(
            !reasons.iter().any(|r| matches!(
                r,
                RefuseReason::InferredUnenforceable { cap } if *cap == Capability::Filesystem
            )),
            "the confined filesystem axis must not contribute a refuse reason: {reasons:?}"
        );
    }

    #[test]
    fn a_partial_target_refuses_an_opaque_wrapper_because_hidden_axes_may_be_gapped() {
        // An opaque construct hides WHICH axes are reached, so it is only safe on
        // a FULL set. On a partial set (even one confining native-ffi) the hidden
        // effect could land on the unconfined network axis → refuse.
        let jail = windows_partial_target();
        let scan = scan_source("lib.rs", "extern \"C\" { fn getpid() -> i32; }");
        assert!(
            matches!(
                &reconcile_for(&BTreeSet::new(), &scan, &[], jail),
                Verdict::Refuse { reasons, .. }
                    if reasons.iter().any(|r| matches!(r, RefuseReason::Opaque { .. }))
            ),
            "a partial target must refuse an opaque wrapper"
        );
    }

    #[test]
    fn a_partial_target_refuses_a_non_std_dep_because_hidden_axes_may_be_gapped() {
        // A non-std dependency's effects are invisible, so — like an opaque
        // construct — it is contained only on a FULL set.
        let jail = windows_partial_target();
        let scan = scan_source("lib.rs", "pub fn f() -> i64 { 0 }");
        assert!(
            matches!(
                &reconcile_for(&BTreeSet::new(), &scan, &["reqwest".to_owned()], jail),
                Verdict::Refuse { reasons, .. }
                    if reasons.iter().any(|r| matches!(r, RefuseReason::NonStdDependency { .. }))
            ),
            "a partial target must refuse a non-std-dependency wrapper"
        );
    }

    #[test]
    fn a_full_set_behaves_identically_to_the_old_all_or_nothing_holds() {
        // Behaviour-preservation for Linux/macOS: FULLY_CONFINED (== FULL set)
        // yields the same verdicts the old whole-target `Holds` did — every axis
        // enforceable, and every previously-refused wrapper (network, opaque,
        // non-std dep) now admitted-and-isolated.
        assert!(JailForTarget::FULLY_CONFINED.confined().is_full());
        for cap in Capability::ALL {
            assert!(
                !is_runtime_unenforceable_for(*cap, JailForTarget::FULLY_CONFINED),
                "{cap:?} must be enforceable on a full-set target"
            );
        }
        let net = scan_source(
            "lib.rs",
            "pub fn f() { std::net::TcpStream::connect(\"x\"); }",
        );
        assert!(matches!(
            reconcile_for(
                &set(&[Capability::Network]),
                &net,
                &[],
                JailForTarget::FULLY_CONFINED
            ),
            Verdict::Admit { .. }
        ));
        let opaque = scan_source("lib.rs", "extern \"C\" { fn getpid() -> i32; }");
        assert!(matches!(
            reconcile_for(
                &BTreeSet::new(),
                &opaque,
                &[],
                JailForTarget::FULLY_CONFINED
            ),
            Verdict::Admit { .. }
        ));
        assert!(matches!(
            reconcile_for(
                &BTreeSet::new(),
                &scan_source("lib.rs", "pub fn f() -> i64 { 0 }"),
                &["reqwest".to_owned()],
                JailForTarget::FULLY_CONFINED
            ),
            Verdict::Admit { .. }
        ));
    }

    #[test]
    fn an_empty_set_behaves_identically_to_the_old_refuse_gap() {
        // The other behaviour-preservation edge: EMPTY set == old `RefuseGap` —
        // every runtime-enforced axis refused, opaque + non-std-dep refused.
        assert!(JailForTarget::REFUSE_GAP.confined().is_empty());
        for cap in Capability::ALL {
            let unenf = is_runtime_unenforceable_for(*cap, JailForTarget::REFUSE_GAP);
            match cap {
                // Non-determinism, the `unsafe` provenance label, and the
                // `custom-element` browser-JS disclosure carry no server-side
                // isolation surface, so they are enforceable on every target —
                // never refused, even on the empty set.
                Capability::Clock
                | Capability::Random
                | Capability::Unsafe
                | Capability::CustomElement
                | Capability::JsPort(_) => {
                    assert!(!unenf, "{cap:?}");
                }
                _ => assert!(unenf, "{cap:?} stays refused on an empty-set target"),
            }
        }
    }

    // -----------------------------------------------------------------------
    // Instance #4 regression — std::os and aliased OS paths must not admit
    // -----------------------------------------------------------------------

    #[test]
    fn std_os_unix_net_unixstream_refuses() {
        // Regression: `std::os::unix::net::UnixStream` was previously admitted
        // (proposed={}, opacities=[]) because `std::os` was absent from
        // PATH_RULES and the catch-all was missing.
        let src = "fn f() { let _ = std::os::unix::net::UnixStream::connect(\"/x\"); }";
        let o = scan_source("w.rs", src);
        assert!(
            !o.proposed.is_empty() || !o.opacities.is_empty(),
            "std::os::unix::net::UnixStream must not produce (empty proposed, empty opacities): \
             proposed={:?} opacities={:?}",
            o.proposed,
            o.opacities
        );
        assert!(
            o.must_refuse(),
            "std::os::unix::net::UnixStream must cause must_refuse()"
        );
        assert!(matches!(
            reconcile(&BTreeSet::new(), &o, &[]),
            Verdict::Refuse { .. }
        ));
    }

    #[test]
    fn std_os_unix_fs_refuses() {
        let src = "fn f() { std::os::unix::fs::symlink(\"/a\", \"/b\"); }";
        let o = scan_source("w.rs", src);
        assert!(
            !o.proposed.is_empty() || !o.opacities.is_empty(),
            "std::os::unix::fs must not produce (empty proposed, empty opacities)"
        );
        assert!(
            o.must_refuse(),
            "std::os::unix::fs must cause must_refuse()"
        );
    }

    #[test]
    fn std_os_fd_asrawfd_refuses() {
        let src = "use std::os::fd::AsRawFd; fn f<T: AsRawFd>(t: &T) { let _ = t.as_raw_fd(); }";
        let o = scan_source("w.rs", src);
        assert!(
            !o.proposed.is_empty() || !o.opacities.is_empty(),
            "std::os::fd must not produce (empty proposed, empty opacities)"
        );
        assert!(o.must_refuse(), "std::os::fd must cause must_refuse()");
    }

    #[test]
    fn bare_unix_stream_refuses() {
        // After `use std::os::unix::net::UnixStream`, the wrapper uses the bare
        // identifier — must still refuse.
        let src = "use std::os::unix::net::UnixStream; fn f() { UnixStream::connect(\"/x\"); }";
        let o = scan_source("w.rs", src);
        assert!(
            o.proposed.contains(&Capability::NativeFfi),
            "bare UnixStream must propose NativeFfi: {:?}",
            o.proposed
        );
        assert!(o.must_refuse(), "bare UnixStream must refuse");
    }

    #[test]
    fn bare_rawfd_refuses() {
        let src = "use std::os::fd::RawFd; fn f(fd: RawFd) {}";
        let o = scan_source("w.rs", src);
        assert!(
            o.proposed.contains(&Capability::NativeFfi),
            "bare RawFd must propose NativeFfi: {:?}",
            o.proposed
        );
    }

    #[test]
    fn recognised_std_net_does_not_gain_spurious_opacity() {
        // Non-regression: `std::net::TcpStream` is in PATH_RULES; it must NOT
        // trigger the catch-all and must NOT gain a spurious UnenumerableModule
        // opacity from the new guard.
        let src = "fn f() { let _ = std::net::TcpStream::connect(\"x:80\"); }";
        let o = scan_source("lib.rs", src);
        assert!(
            o.proposed.contains(&Capability::Network),
            "std::net must still propose Network"
        );
        assert!(
            o.opacities.is_empty(),
            "std::net must NOT gain a spurious opacity: {:?}",
            o.opacities
        );
    }

    #[test]
    fn pure_collections_hashmap_does_not_refuse() {
        // Non-regression: a wrapper that uses only `std::collections::HashMap`
        // (no capability) must still admit cleanly. The catch-all fires for
        // `std::collections` but that is an opacity, not a proposed capability;
        // on a full-set jail where every axis is confined it still admits.
        // Under REFUSE_GAP the opacity causes Refuse (hidden effect on an
        // unconfined axis) — which is the correct conservative behaviour.
        let src = "use std::collections::HashMap; fn f() -> HashMap<i64,i64> { HashMap::new() }";
        let o = scan_source("lib.rs", src);
        // The proposed set must not contain any runtime capability.
        for cap in &o.proposed {
            assert!(
                matches!(
                    cap,
                    Capability::Clock | Capability::Random | Capability::Unsafe
                ),
                "std::collections must not propose a runtime-enforced capability, got {cap:?}"
            );
        }
    }

    #[test]
    fn invariant_std_second_segment_produces_nonempty_proposed_or_opacities() {
        // Machine-checked: for every tested `std::<mod>` second segment, the
        // scan result must be non-empty proposed OR non-empty opacities. The
        // silent-empty state (empty proposed AND empty opacities) would mean
        // the allowlist's complement silently admits instead of refusing.
        let std_mods = &[
            "net",
            "fs",
            "process",
            "env",
            "time",
            "os",
            "arch",
            "io",
            "collections",
            "sync",
            "thread",
            "path",
            "ffi",
            "mem",
            "ptr",
            "alloc",
            "fmt",
            "convert",
            "ops",
            "hash",
            "cmp",
        ];
        for module in std_mods {
            let src = format!("fn f() {{ let _ = std::{module}::placeholder(); }}");
            let o = scan_source("lib.rs", &src);
            assert!(
                !o.proposed.is_empty() || !o.opacities.is_empty(),
                "std::{module} produced (empty proposed, empty opacities) — \
                 the allowlist complement must refuse, not silently admit"
            );
        }
    }
}
