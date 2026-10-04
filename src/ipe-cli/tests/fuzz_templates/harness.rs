//! Parse, render and check the fuzz templates under `tests/fuzz/`.
//!
//! A template is an Ipê program whose header declares typed slots (and, for an
//! ill-typed template, one hole and the code its mutant must be refused with).
//! The header is parsed once into [`Template`] / [`Mutant`]; rendering draws
//! every slot from its declared domain, so no fill outside the domain can be
//! built. One classifier ([`classify`]) judges every emitted run, so the CI
//! sweep and the long random run cannot disagree on what a failure is.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use ipe_diagnostics::{ALL_CODES, Code, IPE_N0001, IPE_N0005, IPE_T0001, IPE_T0010, IPE_T0012};

/// The well-typed template kinds, one directory each under `tests/fuzz/well-typed/`.
pub const WELL_TYPED: &[&str] = &[
    "adtcase",
    "arith",
    "dictops",
    "higherorder",
    "ifnestedlet",
    "letpoly",
    "listmap",
    "maybeandmap",
    "maybechain",
    "mm2typereuse",
    "mmnumberhelper",
    "mmrecpair",
    "mmvaluebind",
    "multilineinterp",
    "paramrecord",
    "pipeline",
    "recordupdate",
    "recursion",
    "resultmap2",
    "resultpipe",
    "setops",
    "strconcat",
    "tuple",
];

/// The ill-typed categories under `tests/fuzz/ill-typed/`, each with the code its mutant must get.
pub const ILL_TYPED: &[(&str, Code)] = &[
    ("cat1-undef-field", IPE_T0012),
    ("cat2-undef-var", IPE_N0001),
    ("cat3-unknown-member", IPE_N0005),
    ("cat4a-type-mismatch-strlen", IPE_T0001),
    ("cat4b-type-mismatch-if", IPE_T0001),
    ("cat5-ctor-arity", IPE_T0001),
    ("cat6-nonexhaustive-case", IPE_T0010),
    ("cat7-same-module-2type", IPE_T0001),
    ("cat8-cross-module-bad-inst", IPE_T0001),
];

/// The seed of the deterministic fills every check run renders.
pub const FIXED_SEED: u32 = 1_234_567;

/// How many seeded fills a check run renders per template, after the min and max fills.
pub const FIXED_SEED_ITERS: u32 = 2;

/// The most iterations a random run accepts.
pub const MAX_ITERS: u32 = 10_000;

/// The environment variable naming a random run's start seed.
pub const SEED_VAR: &str = "IPE_FUZZ_SEED";

/// The environment variable naming a random run's iteration count.
pub const ITERS_VAR: &str = "IPE_FUZZ_ITERS";

/// The longest string or list a slot may declare.
const MAX_LEN: u8 = 32;

/// How long one emitted binary may run before it counts as hung.
const RUN_DEADLINE: Duration = Duration::from_secs(30);

/// The most bytes read back from one captured output stream.
const MAX_CAPTURE: u64 = 1 << 20;

/// The manifest every rendered project carries, so project mode stops at it.
const PACKAGE_IPE: &str = "module Package exposing (package)\n\
    \n\
    import Ipe.Package exposing (..)\n\
    \n\
    \n\
    package : Package\n\
    package =\n\
    \x20   { name = \"ipe-app\"\n\
    \x20   , version = \"0.1.0\"\n\
    \x20   }\n";

/// The header line prefix every directive starts with.
const DIRECTIVE: &str = "-- fuzz-";

/// The line carrying a hole's base fill.
const BASE_LINE: &str = "--   base:";

/// The line carrying a hole's mutant fill.
const MUTANT_LINE: &str = "--   mutant:";

/// One file of a template.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileRole {
    /// `Main.ipe.tmpl`: the entry module, and the only file that carries a header.
    Main,
    /// `Lib.ipe.tmpl`: the sibling module of a multi-module template.
    Lib,
}

impl FileRole {
    /// The template file's name on disk.
    const fn template_name(self) -> &'static str {
        match self {
            Self::Main => "Main.ipe.tmpl",
            Self::Lib => "Lib.ipe.tmpl",
        }
    }

    /// The rendered module's file name.
    const fn module_name(self) -> &'static str {
        match self {
            Self::Main => "Main.ipe",
            Self::Lib => "Lib.ipe",
        }
    }
}

/// Why a template's text is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TemplateParseError {
    /// The template has no `Main.ipe.tmpl`.
    MissingMain,
    /// A file in the template directory is neither `Main.ipe.tmpl` nor `Lib.ipe.tmpl`.
    UnknownFile { name: String },
    /// A `-- fuzz-` line names no known directive.
    UnknownDirective { line: String },
    /// A `-- fuzz-` line appears after the header, or in a file other than `Main`.
    DirectiveOutsideHeader { line: String },
    /// A `fuzz-slot`, `fuzz-hole` or `fuzz-expect` line is malformed.
    BadDecl { line: String },
    /// Two slots or holes share a name.
    DuplicateName { name: String },
    /// A slot range has its minimum above its maximum.
    InvertedRange { slot: String },
    /// A slot's length is above the length cap.
    LengthAboveCap { slot: String },
    /// A hole is not followed by its `base:` and `mutant:` lines.
    MissingHoleFill { hole: String },
    /// `fuzz-expect` names no code of the diagnostic taxonomy.
    UnknownCode { raw: String },
    /// An ill-typed template declares no `fuzz-expect`.
    MissingExpect,
    /// An ill-typed template declares more than one `fuzz-expect`.
    DuplicateExpect,
    /// An ill-typed template declares no hole.
    ZeroHoles,
    /// An ill-typed template declares more than one hole.
    TwoOrMoreHoles,
    /// A well-typed template declares a hole.
    HoleInWellTyped,
    /// A well-typed template declares a `fuzz-expect`.
    ExpectInWellTyped,
    /// An `@` opens a token that has no closing `@` or no valid name.
    MalformedToken { text: String },
    /// An `@name@` token names no declared slot (or hole, in the body).
    UndeclaredToken { name: String },
    /// A declared slot appears in no file and no hole fill.
    UnusedSlot { name: String },
    /// The hole token appears other than exactly once across the files.
    HoleNotPlacedOnce { count: usize },
}

/// Why a template check fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HarnessError {
    /// The template's text was refused.
    Parse {
        template: String,
        error: TemplateParseError,
    },
    /// A well-typed template was rejected by the compiler.
    TemplateRejected { code: Option<Code>, detail: String },
    /// An ill-typed template's base fill was rejected, so its mutant proves nothing.
    BaseRejected { code: Option<Code>, detail: String },
    /// An ill-typed template's mutant was accepted.
    FalseAcceptance,
    /// An ill-typed template's mutant was rejected, but not with the declared code.
    WrongCode { expected: Code, got: Option<Code> },
    /// The template directories differ from the pinned lists.
    CatalogueDrift {
        missing: Vec<String>,
        extra: Vec<String>,
    },
    /// A catalogue (pinned list or directory) is empty.
    EmptyCatalogue { dir: String },
    /// A template's `fuzz-expect` differs from the code its pinned list entry carries.
    ExpectDrift {
        template: String,
        declared: Code,
        pinned: Code,
    },
    /// The emitted crate did not `cargo build`.
    CargoBuildFailed { detail: String },
    /// The emitted binary exited non-zero.
    RunFailed {
        exit: Option<i32>,
        stdout: String,
        stderr: String,
    },
    /// The emitted binary was still running at the deadline.
    RunTimedOut { stdout: String, stderr: String },
    /// The emitted binary printed a runtime-fault marker.
    PanicMarker {
        marker: String,
        exit: Option<i32>,
        stdout: String,
        stderr: String,
    },
    /// A scratch file or directory could not be written or read.
    Io { detail: String },
    /// A fill does not cover a slot the template renders.
    FillMismatch,
}

impl HarnessError {
    /// The [`Self::Io`] for `err`, naming what was being done.
    fn io(what: &str, err: &io::Error) -> Self {
        Self::Io {
            detail: format!("{what}: {err}"),
        }
    }
}

impl fmt::Display for TemplateParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingMain => f.write_str("no Main.ipe.tmpl"),
            Self::UnknownFile { name } => write!(f, "unknown template file {name:?}"),
            Self::UnknownDirective { line } => write!(f, "unknown directive {line:?}"),
            Self::DirectiveOutsideHeader { line } => {
                write!(f, "directive outside the Main header {line:?}")
            }
            Self::BadDecl { line } => write!(f, "malformed declaration {line:?}"),
            Self::DuplicateName { name } => write!(f, "slot or hole {name:?} declared twice"),
            Self::InvertedRange { slot } => write!(f, "slot {slot:?} has min above max"),
            Self::LengthAboveCap { slot } => {
                write!(f, "slot {slot:?} has a length above {MAX_LEN}")
            }
            Self::MissingHoleFill { hole } => {
                write!(f, "hole {hole:?} lacks its base: and mutant: lines")
            }
            Self::UnknownCode { raw } => write!(f, "unknown diagnostic code {raw:?}"),
            Self::MissingExpect => f.write_str("no fuzz-expect"),
            Self::DuplicateExpect => f.write_str("more than one fuzz-expect"),
            Self::ZeroHoles => f.write_str("no fuzz-hole"),
            Self::TwoOrMoreHoles => f.write_str("more than one fuzz-hole"),
            Self::HoleInWellTyped => f.write_str("a well-typed template declares a hole"),
            Self::ExpectInWellTyped => f.write_str("a well-typed template declares fuzz-expect"),
            Self::MalformedToken { text } => write!(f, "malformed token at {text:?}"),
            Self::UndeclaredToken { name } => write!(f, "undeclared token {name:?}"),
            Self::UnusedSlot { name } => write!(f, "slot {name:?} is never used"),
            Self::HoleNotPlacedOnce { count } => {
                write!(f, "the hole is placed {count} times, not once")
            }
        }
    }
}

/// The code's wire form, or `none` when the refusal carried no diagnostic.
fn code_text(code: Option<Code>) -> &'static str {
    code.map_or("none", Code::as_str)
}

impl fmt::Display for HarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse { template, error } => write!(f, "template {template:?}: {error}"),
            Self::TemplateRejected { code, detail } => {
                write!(
                    f,
                    "well-typed template rejected ({}): {detail:?}",
                    code_text(*code)
                )
            }
            Self::BaseRejected { code, detail } => {
                write!(f, "base fill rejected ({}): {detail:?}", code_text(*code))
            }
            Self::FalseAcceptance => f.write_str("the mutant type-checked"),
            Self::WrongCode { expected, got } => write!(
                f,
                "the mutant was refused with {}, not {}",
                code_text(*got),
                expected.as_str()
            ),
            Self::CatalogueDrift { missing, extra } => {
                write!(f, "catalogue drift: missing {missing:?}, extra {extra:?}")
            }
            Self::EmptyCatalogue { dir } => write!(f, "empty catalogue {dir:?}"),
            Self::ExpectDrift {
                template,
                declared,
                pinned,
            } => write!(
                f,
                "template {template:?} expects {}, its pinned entry {}",
                declared.as_str(),
                pinned.as_str()
            ),
            Self::CargoBuildFailed { detail } => write!(f, "cargo build failed: {detail:?}"),
            Self::RunFailed {
                exit,
                stdout,
                stderr,
            } => write!(f, "exit {exit:?}; stdout {stdout:?}; stderr {stderr:?}"),
            Self::RunTimedOut { stdout, stderr } => {
                write!(f, "timed out; stdout {stdout:?}; stderr {stderr:?}")
            }
            Self::PanicMarker {
                marker,
                exit,
                stdout,
                stderr,
            } => write!(
                f,
                "fault marker {marker:?}; exit {exit:?}; stdout {stdout:?}; stderr {stderr:?}"
            ),
            Self::Io { detail } => write!(f, "scratch I/O: {detail:?}"),
            Self::FillMismatch => f.write_str("a fill does not cover a rendered slot"),
        }
    }
}

/// A failed check, with everything needed to reproduce it.
#[derive(Debug)]
pub struct Failure {
    /// The template's name.
    pub template: String,
    /// The fill plan that rendered the failing sources.
    pub plan: FillPlan,
    /// Each rendered file's name and text.
    pub sources: Vec<(&'static str, String)>,
    /// What went wrong.
    pub error: HarnessError,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "template `{}` ({}): {}",
            self.template, self.plan, self.error
        )?;
        for (name, text) in &self.sources {
            writeln!(f, "--- {name}\n{text}")?;
        }
        Ok(())
    }
}

/// A checked result: `Ok`, or the failure with its reproduction context.
pub type Checked = Result<(), Box<Failure>>;

/// How a check run fills the slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FillPlan {
    /// Every slot at its domain minimum.
    Min,
    /// Every slot at its domain maximum, with the longest string or list.
    Max,
    /// Every slot drawn from the generator at this seed.
    Seeded(u32),
}

impl fmt::Display for FillPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Min => f.write_str("min fill"),
            Self::Max => f.write_str("max fill"),
            Self::Seeded(seed) => write!(f, "seed {seed}"),
        }
    }
}

/// The fill plans a check run renders for every template: min, max, then the fixed seeds.
pub fn check_plans() -> Vec<FillPlan> {
    let seeded = (0..FIXED_SEED_ITERS).map(|i| FillPlan::Seeded(FIXED_SEED.wrapping_add(i)));
    [FillPlan::Min, FillPlan::Max]
        .into_iter()
        .chain(seeded)
        .collect()
}

/// The linear congruential generator the fills are drawn from.
pub struct Lcg(u32);

impl Lcg {
    /// A generator started at `seed`.
    pub const fn new(seed: u32) -> Self {
        Self(seed)
    }

    /// The next 31-bit value.
    pub const fn next_value(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(1_103_515_245).wrapping_add(12_345) & 0x7FFF_FFFF;
        self.0
    }

    /// A value in `lo..=hi`; `lo <= hi` holds for every parsed slot.
    const fn between(&mut self, lo: u32, hi: u32) -> u32 {
        let span = hi.saturating_sub(lo).saturating_add(1);
        lo.saturating_add(self.next_value() % span)
    }
}

/// An inclusive range whose minimum is at most its maximum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Bounds<T> {
    lo: T,
    hi: T,
}

impl<T: Copy + PartialOrd + std::str::FromStr> Bounds<T> {
    /// Parse `lo` and `hi`, refusing an inverted range.
    fn parse(slot: &str, line: &str, lo: &str, hi: &str) -> Result<Self, TemplateParseError> {
        let bad = || TemplateParseError::BadDecl {
            line: line.to_owned(),
        };
        let lo: T = lo.parse().map_err(|_| bad())?;
        let hi: T = hi.parse().map_err(|_| bad())?;
        if lo > hi {
            return Err(TemplateParseError::InvertedRange {
                slot: slot.to_owned(),
            });
        }
        Ok(Self { lo, hi })
    }
}

/// A length range, capped at [`MAX_LEN`].
fn parse_len(slot: &str, line: &str, lo: &str, hi: &str) -> Result<Bounds<u8>, TemplateParseError> {
    let len = Bounds::<u8>::parse(slot, line, lo, hi)?;
    if len.hi > MAX_LEN {
        return Err(TemplateParseError::LengthAboveCap {
            slot: slot.to_owned(),
        });
    }
    Ok(len)
}

/// The domain a slot is drawn from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotKind {
    /// An integer literal in the range.
    Int(Bounds<u16>),
    /// A lowercase ASCII word whose length is in the range.
    Lower(Bounds<u8>),
    /// An integer list literal: length range, then element range.
    IntList(Bounds<u8>, Bounds<u16>),
    /// Four lowercase hex digits.
    Hex4,
}

impl SlotKind {
    /// Parse the kind and its arguments from a `fuzz-slot` line.
    fn parse(slot: &str, line: &str, words: &[&str]) -> Result<Self, TemplateParseError> {
        match words {
            ["Int", lo, hi] => Ok(Self::Int(Bounds::parse(slot, line, lo, hi)?)),
            ["Lower", lo, hi] => Ok(Self::Lower(parse_len(slot, line, lo, hi)?)),
            ["IntList", len_lo, len_hi, lo, hi] => Ok(Self::IntList(
                parse_len(slot, line, len_lo, len_hi)?,
                Bounds::parse(slot, line, lo, hi)?,
            )),
            ["Hex4"] => Ok(Self::Hex4),
            _ => Err(TemplateParseError::BadDecl {
                line: line.to_owned(),
            }),
        }
    }

    /// The rendered value for `plan`, drawing from `lcg` when the plan is seeded.
    fn fill(self, plan: FillPlan, lcg: &mut Lcg) -> String {
        match (self, plan) {
            (Self::Int(b), FillPlan::Min) => b.lo.to_string(),
            (Self::Int(b), FillPlan::Max) => b.hi.to_string(),
            (Self::Int(b), FillPlan::Seeded(_)) => {
                lcg.between(u32::from(b.lo), u32::from(b.hi)).to_string()
            }
            (Self::Lower(len), FillPlan::Min) => "a".repeat(usize::from(len.lo)),
            (Self::Lower(len), FillPlan::Max) => "z".repeat(usize::from(len.hi)),
            (Self::Lower(len), FillPlan::Seeded(_)) => {
                let n = lcg.between(u32::from(len.lo), u32::from(len.hi));
                (0..n).map(|_| lower_letter(lcg.next_value())).collect()
            }
            (Self::IntList(len, el), FillPlan::Min) => {
                int_list(std::iter::repeat_n(u32::from(el.lo), usize::from(len.lo)))
            }
            (Self::IntList(len, el), FillPlan::Max) => {
                int_list(std::iter::repeat_n(u32::from(el.hi), usize::from(len.hi)))
            }
            (Self::IntList(len, el), FillPlan::Seeded(_)) => {
                let n = lcg.between(u32::from(len.lo), u32::from(len.hi));
                int_list((0..n).map(|_| lcg.between(u32::from(el.lo), u32::from(el.hi))))
            }
            (Self::Hex4, FillPlan::Min) => "0000".to_owned(),
            (Self::Hex4, FillPlan::Max) => "ffff".to_owned(),
            (Self::Hex4, FillPlan::Seeded(_)) => format!("{:04x}", lcg.next_value() & 0xFFFF),
        }
    }
}

/// The lowercase letter `r` selects.
fn lower_letter(r: u32) -> char {
    // `r % 26` is below 26, so `nth` always finds a letter.
    (b'a'..=b'z').nth((r % 26) as usize).map_or('a', char::from)
}

/// An Ipê list literal of the integers.
fn int_list(items: impl Iterator<Item = u32>) -> String {
    let items: Vec<String> = items.map(|i| i.to_string()).collect();
    format!("[{}]", items.join(", "))
}

/// One piece of a template's text.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Segment {
    /// Literal text.
    Text(String),
    /// The slot at this index of the template's slot list.
    Slot(usize),
    /// The template's one hole.
    Hole,
}

/// A template's text with its tokens resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Source(Vec<Segment>);

/// A template file with its tokens resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TemplateFile {
    role: FileRole,
    body: Source,
}

/// A parsed well-typed template, or the shared body of an ill-typed one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    name: String,
    files: Vec<TemplateFile>,
    slots: Vec<(String, SlotKind)>,
}

/// A parsed ill-typed template: one body, one hole, and the code the mutant must get.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mutant {
    template: Template,
    base: Source,
    faulty: Source,
    expect: Code,
}

impl Mutant {
    /// The code the mutant must be refused with.
    pub const fn expect(&self) -> Code {
        self.expect
    }

    /// The template's name.
    pub fn name(&self) -> &str {
        &self.template.name
    }
}

impl Template {
    /// The template's name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A declared hole, before its fills are tokenized.
struct HoleDecl {
    name: String,
    base: String,
    mutant: String,
}

/// The directives of a `Main` header.
#[derive(Default)]
struct Header {
    slots: Vec<(String, SlotKind)>,
    holes: Vec<HoleDecl>,
    expects: Vec<Code>,
}

/// Whether `name` is a token name: a lowercase letter, then lowercase letters, digits or `_`.
fn is_token_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The text after `prefix` on `line`, trimmed; `None` when `line` does not start with it.
fn fill_after<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    line.strip_prefix(prefix).map(str::trim)
}

/// Parse a `Main` file's header, returning it and the body that follows.
fn parse_header(text: &str) -> Result<(Header, &str), TemplateParseError> {
    let mut header = Header::default();
    let mut rest = text;
    loop {
        let (line, after) = rest.split_once('\n').unwrap_or((rest, ""));
        let Some(directive) = line.strip_prefix(DIRECTIVE) else {
            return Ok((header, rest));
        };
        rest = after;
        let bad = || TemplateParseError::BadDecl {
            line: line.to_owned(),
        };
        let words: Vec<&str> = directive.split_whitespace().collect();
        match words.as_slice() {
            ["slot", name, ":", kind @ ..] if is_token_name(name) => {
                header
                    .slots
                    .push(((*name).to_owned(), SlotKind::parse(name, line, kind)?));
            }
            ["hole", name] if is_token_name(name) => {
                let (base_line, after_base) = rest.split_once('\n').unwrap_or((rest, ""));
                let (mutant_line, after_mutant) =
                    after_base.split_once('\n').unwrap_or((after_base, ""));
                let missing = || TemplateParseError::MissingHoleFill {
                    hole: (*name).to_owned(),
                };
                let base = fill_after(base_line, BASE_LINE).ok_or_else(missing)?;
                let mutant = fill_after(mutant_line, MUTANT_LINE).ok_or_else(missing)?;
                header.holes.push(HoleDecl {
                    name: (*name).to_owned(),
                    base: base.to_owned(),
                    mutant: mutant.to_owned(),
                });
                rest = after_mutant;
            }
            ["expect", raw] => {
                let code = ALL_CODES
                    .iter()
                    .copied()
                    .find(|c| c.as_str() == *raw)
                    .ok_or_else(|| TemplateParseError::UnknownCode {
                        raw: (*raw).to_owned(),
                    })?;
                header.expects.push(code);
            }
            ["slot" | "hole" | "expect", ..] => return Err(bad()),
            _ => {
                return Err(TemplateParseError::UnknownDirective {
                    line: line.to_owned(),
                });
            }
        }
    }
}

/// Refuse a `-- fuzz-` directive line anywhere in `body`.
fn refuse_stray_directive(body: &str) -> Result<(), TemplateParseError> {
    body.lines()
        .find(|l| l.starts_with(DIRECTIVE))
        .map_or(Ok(()), |line| {
            Err(TemplateParseError::DirectiveOutsideHeader {
                line: line.to_owned(),
            })
        })
}

/// Split `text` into literal text and resolved `@name@` tokens.
///
/// A slot token resolves to its index in `slots`; `hole` (when given) resolves to
/// [`Segment::Hole`]. Any other name is refused.
fn tokenize(
    text: &str,
    slots: &[(String, SlotKind)],
    hole: Option<&str>,
) -> Result<Source, TemplateParseError> {
    let mut segments = Vec::new();
    let mut rest = text;
    while let Some((before, after_at)) = rest.split_once('@') {
        if !before.is_empty() {
            segments.push(Segment::Text(before.to_owned()));
        }
        let malformed = || TemplateParseError::MalformedToken {
            text: after_at.lines().next().unwrap_or_default().to_owned(),
        };
        let (name, after) = after_at.split_once('@').ok_or_else(malformed)?;
        if !is_token_name(name) {
            return Err(malformed());
        }
        if hole == Some(name) {
            segments.push(Segment::Hole);
        } else {
            let index = slots
                .iter()
                .position(|(slot, _)| slot == name)
                .ok_or_else(|| TemplateParseError::UndeclaredToken {
                    name: name.to_owned(),
                })?;
            segments.push(Segment::Slot(index));
        }
        rest = after;
    }
    if !rest.is_empty() {
        segments.push(Segment::Text(rest.to_owned()));
    }
    Ok(Source(segments))
}

/// The pieces both template kinds share once the header is parsed.
struct Parsed {
    template: Template,
    header_holes: Vec<HoleDecl>,
    expects: Vec<Code>,
}

/// Parse a template's files: header, tokens, and the name checks both kinds share.
fn parse_common(name: &str, files: &[(FileRole, &str)]) -> Result<Parsed, TemplateParseError> {
    let main = files
        .iter()
        .find(|(role, _)| *role == FileRole::Main)
        .map(|(_, text)| *text)
        .ok_or(TemplateParseError::MissingMain)?;
    let (header, main_body) = parse_header(main)?;
    let mut seen = BTreeSet::new();
    let names = header
        .slots
        .iter()
        .map(|(n, _)| n)
        .chain(header.holes.iter().map(|h| &h.name));
    for n in names {
        if !seen.insert(n.as_str()) {
            return Err(TemplateParseError::DuplicateName { name: n.clone() });
        }
    }
    let hole = match header.holes.as_slice() {
        [one] => Some(one.name.as_str()),
        _ => None,
    };
    let mut parsed_files = Vec::new();
    for (role, text) in files {
        let body = if *role == FileRole::Main {
            main_body
        } else {
            *text
        };
        refuse_stray_directive(body)?;
        parsed_files.push(TemplateFile {
            role: *role,
            body: tokenize(body, &header.slots, hole)?,
        });
    }
    Ok(Parsed {
        template: Template {
            name: name.to_owned(),
            files: parsed_files,
            slots: header.slots,
        },
        header_holes: header.holes,
        expects: header.expects,
    })
}

/// Refuse a declared slot that no source uses.
fn refuse_unused_slots(
    slots: &[(String, SlotKind)],
    sources: &[&Source],
) -> Result<(), TemplateParseError> {
    for (index, (name, _)) in slots.iter().enumerate() {
        let used = sources.iter().any(|s| s.0.contains(&Segment::Slot(index)));
        if !used {
            return Err(TemplateParseError::UnusedSlot { name: name.clone() });
        }
    }
    Ok(())
}

/// Parse a well-typed template: slots only, no hole and no expected code.
pub fn parse_well_typed(
    name: &str,
    files: &[(FileRole, &str)],
) -> Result<Template, TemplateParseError> {
    let parsed = parse_common(name, files)?;
    if !parsed.header_holes.is_empty() {
        return Err(TemplateParseError::HoleInWellTyped);
    }
    if !parsed.expects.is_empty() {
        return Err(TemplateParseError::ExpectInWellTyped);
    }
    let bodies: Vec<&Source> = parsed.template.files.iter().map(|f| &f.body).collect();
    refuse_unused_slots(&parsed.template.slots, &bodies)?;
    Ok(parsed.template)
}

/// Parse an ill-typed template: exactly one hole, placed once, and exactly one expected code.
pub fn parse_ill_typed(
    name: &str,
    files: &[(FileRole, &str)],
) -> Result<Mutant, TemplateParseError> {
    let parsed = parse_common(name, files)?;
    let hole = match parsed.header_holes.as_slice() {
        [] => return Err(TemplateParseError::ZeroHoles),
        [one] => one,
        _ => return Err(TemplateParseError::TwoOrMoreHoles),
    };
    let expect = match parsed.expects.as_slice() {
        [] => return Err(TemplateParseError::MissingExpect),
        [one] => *one,
        _ => return Err(TemplateParseError::DuplicateExpect),
    };
    let count: usize = parsed
        .template
        .files
        .iter()
        .map(|f| f.body.0.iter().filter(|s| **s == Segment::Hole).count())
        .sum();
    if count != 1 {
        return Err(TemplateParseError::HoleNotPlacedOnce { count });
    }
    let slots = &parsed.template.slots;
    let base = tokenize(&hole.base, slots, None)?;
    let mutant = tokenize(&hole.mutant, slots, None)?;
    let mut sources: Vec<&Source> = parsed.template.files.iter().map(|f| &f.body).collect();
    sources.extend([&base, &mutant]);
    refuse_unused_slots(slots, &sources)?;
    Ok(Mutant {
        template: parsed.template,
        base,
        faulty: mutant,
        expect,
    })
}

/// The rendered text of each file.
type Rendered = Vec<(&'static str, String)>;

/// Render `source` with `values` for the slots and `hole` for the hole.
fn render_source(
    source: &Source,
    values: &[String],
    hole: Option<&str>,
) -> Result<String, HarnessError> {
    let mut out = String::new();
    for segment in &source.0 {
        let piece = match segment {
            Segment::Text(text) => Some(text.as_str()),
            Segment::Slot(index) => values.get(*index).map(String::as_str),
            Segment::Hole => hole,
        };
        out.push_str(piece.ok_or(HarnessError::FillMismatch)?);
    }
    Ok(out)
}

impl Template {
    /// The slot values `plan` selects, one per declared slot.
    fn values(&self, plan: FillPlan) -> Vec<String> {
        let mut lcg = Lcg::new(match plan {
            FillPlan::Seeded(seed) => seed,
            FillPlan::Min | FillPlan::Max => 0,
        });
        self.slots
            .iter()
            .map(|(_, kind)| kind.fill(plan, &mut lcg))
            .collect()
    }

    /// Render every file with `values`, filling the hole (if any) with `hole`.
    fn render_with(&self, values: &[String], hole: Option<&str>) -> Result<Rendered, HarnessError> {
        self.files
            .iter()
            .map(|f| render_source(&f.body, values, hole).map(|text| (f.role.module_name(), text)))
            .collect()
    }

    /// Render the template at `plan`.
    pub fn render(&self, plan: FillPlan) -> Result<Rendered, HarnessError> {
        self.render_with(&self.values(plan), None)
    }
}

impl Mutant {
    /// Render the base and the mutant at `plan`, sharing one set of slot values.
    pub fn render(&self, plan: FillPlan) -> Result<(Rendered, Rendered), HarnessError> {
        let values = self.template.values(plan);
        let base = render_source(&self.base, &values, None)?;
        let mutant = render_source(&self.faulty, &values, None)?;
        Ok((
            self.template.render_with(&values, Some(base.as_str()))?,
            self.template.render_with(&values, Some(mutant.as_str()))?,
        ))
    }
}

/// A scratch directory under the test temp root, removed on drop.
pub struct Scratch(PathBuf);

impl Scratch {
    /// Create a fresh, exclusively owned scratch directory tagged with `tag`.
    pub fn new(tag: &str) -> io::Result<Self> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let root = ipe_test_temp::temp_root();
        for _ in 0..64 {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = root.join(format!("ipe-fuzz-{}-{n}-{tag}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::other("no free scratch directory name"))
    }

    /// The directory's path.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// An accepted program: its scratch directory and the emitted crate inside it.
pub struct Built {
    scratch: Scratch,
    out: PathBuf,
}

/// The compiler's verdict on a rendered program.
pub enum Verdict {
    /// The program was accepted and emitted.
    Accepted(Built),
    /// The program was refused, with the diagnostic's code when it was a compile error.
    Rejected { code: Option<Code>, detail: String },
}

/// Write `files` as a project with its own `package.ipe` and build it in process.
pub fn build(
    tag: &str,
    files: &[(&'static str, String)],
    runtime: &Path,
) -> Result<Verdict, HarnessError> {
    let scratch = Scratch::new(tag).map_err(|e| HarnessError::io("create scratch", &e))?;
    let project = scratch.path().join("project");
    let src = project.join("src");
    std::fs::create_dir_all(&src).map_err(|e| HarnessError::io("create src", &e))?;
    std::fs::write(project.join("package.ipe"), PACKAGE_IPE)
        .map_err(|e| HarnessError::io("write package.ipe", &e))?;
    for (name, text) in files {
        std::fs::write(src.join(name), text).map_err(|e| HarnessError::io(name, &e))?;
    }
    let out = scratch.path().join("out");
    Ok(
        match ipe::build_project(&project.join("package.ipe"), &out, runtime) {
            Ok(()) => Verdict::Accepted(Built { scratch, out }),
            Err(ipe::CliError::Pipeline { src, diag, .. }) => Verdict::Rejected {
                code: Some(diag.code()),
                detail: ipe_diagnostics::plain_message(&diag, &src),
            },
            Err(other) => Verdict::Rejected {
                code: None,
                detail: other.to_string(),
            },
        },
    )
}

/// Wrap `error` with the template name, plan and rendered sources.
fn fail(
    template: &str,
    plan: FillPlan,
    sources: &[(&'static str, String)],
    error: HarnessError,
) -> Box<Failure> {
    Box::new(Failure {
        template: template.to_owned(),
        plan,
        sources: sources.to_vec(),
        error,
    })
}

/// Render `template` at `plan` and require the compiler to accept it.
pub fn accept_well_typed(
    template: &Template,
    plan: FillPlan,
    runtime: &Path,
) -> Result<Built, Box<Failure>> {
    let name = template.name();
    let files = template
        .render(plan)
        .map_err(|e| fail(name, plan, &[], e))?;
    match build(name, &files, runtime) {
        Ok(Verdict::Accepted(built)) => Ok(built),
        Ok(Verdict::Rejected { code, detail }) => Err(fail(
            name,
            plan,
            &files,
            HarnessError::TemplateRejected { code, detail },
        )),
        Err(e) => Err(fail(name, plan, &files, e)),
    }
}

/// Check that a well-typed template type-checks at `plan`.
pub fn check_well_typed(template: &Template, plan: FillPlan, runtime: &Path) -> Checked {
    accept_well_typed(template, plan, runtime).map(drop)
}

/// Check that a mutant's base is accepted and the mutant refused with exactly its code.
///
/// The guards run in order: a rejected base fails before the mutant is built,
/// so a rotted body can never pass as a correct refusal.
pub fn check_mutant(mutant: &Mutant, plan: FillPlan, runtime: &Path) -> Checked {
    let name = mutant.name();
    let (base, broken) = mutant.render(plan).map_err(|e| fail(name, plan, &[], e))?;
    if let Verdict::Rejected { code, detail } =
        build(name, &base, runtime).map_err(|e| fail(name, plan, &base, e))?
    {
        return Err(fail(
            name,
            plan,
            &base,
            HarnessError::BaseRejected { code, detail },
        ));
    }
    match build(name, &broken, runtime).map_err(|e| fail(name, plan, &broken, e))? {
        Verdict::Accepted(_) => Err(fail(name, plan, &broken, HarnessError::FalseAcceptance)),
        Verdict::Rejected { code, .. } if code == Some(mutant.expect) => Ok(()),
        Verdict::Rejected { code, .. } => Err(fail(
            name,
            plan,
            &broken,
            HarnessError::WrongCode {
                expected: mutant.expect,
                got: code,
            },
        )),
    }
}

/// What an emitted binary did.
pub struct RunCapture {
    /// The exit code, `None` when killed by a signal or at the deadline.
    pub exit: Option<i32>,
    /// Whether the binary was still running at the deadline.
    pub timed_out: bool,
    /// The captured standard output.
    pub stdout: String,
    /// The captured standard error.
    pub stderr: String,
}

/// The first line of `text` that carries a runtime-fault marker.
///
/// The markers are the runtime's classified fault log (`[error] Kind (ref id)`,
/// plain or JSON) and Rust's unhandled-panic report.
fn panic_marker(text: &str) -> Option<&str> {
    text.lines().find(|line| {
        let classified = line
            .strip_prefix("[error] ")
            .and_then(|rest| rest.split_once(" (ref "))
            .is_some_and(|(kind, _)| {
                !kind.is_empty() && kind.chars().all(|c| c.is_ascii_alphabetic())
            });
        classified
            || line.contains("\"level\":\"error\",\"kind\":\"")
            || line.contains("panicked at")
            || line.contains("RUST_BACKTRACE")
    })
}

/// Judge one emitted run: a timeout, then a fault marker, then a non-zero exit fails it.
pub fn classify(run: RunCapture) -> Result<(), HarnessError> {
    let RunCapture {
        exit,
        timed_out,
        stdout,
        stderr,
    } = run;
    if timed_out {
        return Err(HarnessError::RunTimedOut { stdout, stderr });
    }
    if let Some(marker) = panic_marker(&stdout).or_else(|| panic_marker(&stderr)) {
        return Err(HarnessError::PanicMarker {
            marker: marker.to_owned(),
            exit,
            stdout,
            stderr,
        });
    }
    if exit != Some(0) {
        return Err(HarnessError::RunFailed {
            exit,
            stdout,
            stderr,
        });
    }
    Ok(())
}

/// Read at most [`MAX_CAPTURE`] bytes of `path`, decoded lossily.
fn read_capped(path: &Path) -> Result<String, HarnessError> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|f| f.take(MAX_CAPTURE).read_to_end(&mut bytes))
        .map_err(|e| HarnessError::io("read captured output", &e))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Run `exe` in `dir` with its output captured to files, killing it at [`RUN_DEADLINE`].
fn run_bounded(exe: &Path, dir: &Path) -> Result<RunCapture, HarnessError> {
    let stdout_path = dir.join("run.stdout");
    let stderr_path = dir.join("run.stderr");
    let stdout = File::create(&stdout_path).map_err(|e| HarnessError::io("create stdout", &e))?;
    let stderr = File::create(&stderr_path).map_err(|e| HarnessError::io("create stderr", &e))?;
    let mut child = Command::new(exe)
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .map_err(|e| HarnessError::io("spawn emitted binary", &e))?;
    let mut waited: Option<io::Result<ExitStatus>> = None;
    let finished = e2e_support::wait_for(RUN_DEADLINE, || match child.try_wait() {
        Ok(None) => false,
        Ok(Some(status)) => {
            waited = Some(Ok(status));
            true
        }
        Err(e) => {
            waited = Some(Err(e));
            true
        }
    });
    if !finished {
        let _ = child.kill();
        let _ = child.wait();
    }
    let exit = match waited {
        Some(Ok(status)) => status.code(),
        Some(Err(e)) => return Err(HarnessError::io("wait for emitted binary", &e)),
        None => None,
    };
    Ok(RunCapture {
        exit,
        timed_out: !finished,
        stdout: read_capped(&stdout_path)?,
        stderr: read_capped(&stderr_path)?,
    })
}

/// Cargo-build an accepted program's emitted crate, run it, and classify the run.
pub fn build_and_run(built: &Built, golden: &str) -> Result<(), HarnessError> {
    let exe = e2e_support::build_rust_binary(golden, &built.out)
        .map_err(|detail| HarnessError::CargoBuildFailed { detail })?;
    classify(run_bounded(Path::new(&exe), built.scratch.path())?)
}

/// Check a well-typed template end to end: accepted, `cargo build`s, runs clean.
pub fn run_well_typed(template: &Template, plan: FillPlan, runtime: &Path) -> Checked {
    let built = accept_well_typed(template, plan, runtime)?;
    let golden = format!("fuzz_{}", template.name());
    build_and_run(&built, &golden).map_err(|e| {
        let sources = template.render(plan).unwrap_or_default();
        fail(template.name(), plan, &sources, e)
    })
}

/// Compare a pinned catalogue with the directories found on disk.
pub fn compare_catalogue(dir: &str, pinned: &[&str], found: &[String]) -> Result<(), HarnessError> {
    if pinned.is_empty() || found.is_empty() {
        return Err(HarnessError::EmptyCatalogue {
            dir: dir.to_owned(),
        });
    }
    let missing: Vec<String> = pinned
        .iter()
        .filter(|p| !found.iter().any(|f| f == *p))
        .map(|p| (*p).to_owned())
        .collect();
    let extra: Vec<String> = found
        .iter()
        .filter(|f| !pinned.contains(&f.as_str()))
        .cloned()
        .collect();
    if missing.is_empty() && extra.is_empty() {
        Ok(())
    } else {
        Err(HarnessError::CatalogueDrift { missing, extra })
    }
}

/// Require a mutant's declared code to equal the code its pinned list entry carries.
pub fn check_pinned_expect(mutant: &Mutant, pinned: Code) -> Result<(), HarnessError> {
    if mutant.expect == pinned {
        Ok(())
    } else {
        Err(HarnessError::ExpectDrift {
            template: mutant.name().to_owned(),
            declared: mutant.expect,
            pinned,
        })
    }
}

/// The `tests/fuzz/` directory.
pub fn fuzz_root() -> PathBuf {
    e2e_support::manifest_dir!()
        .join("..")
        .join("..")
        .join("tests")
        .join("fuzz")
}

/// The sorted names of the template directories under `dir`.
pub fn list_templates(dir: &Path) -> Result<Vec<String>, HarnessError> {
    let entries = std::fs::read_dir(dir).map_err(|e| HarnessError::io("list templates", &e))?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| HarnessError::io("list templates", &e))?;
        if entry.path().is_dir() {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    names.sort();
    Ok(names)
}

/// Read a template directory's files, refusing any file that is not a template file.
pub fn read_template_dir(dir: &Path, name: &str) -> Result<Vec<(FileRole, String)>, HarnessError> {
    let parse = |error| HarnessError::Parse {
        template: name.to_owned(),
        error,
    };
    let mut files = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| HarnessError::io("read template", &e))?;
    for entry in entries {
        let entry = entry.map_err(|e| HarnessError::io("read template", &e))?;
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let role = [FileRole::Main, FileRole::Lib]
            .into_iter()
            .find(|r| r.template_name() == file_name)
            .ok_or_else(|| parse(TemplateParseError::UnknownFile { name: file_name }))?;
        let text = std::fs::read_to_string(entry.path())
            .map_err(|e| HarnessError::io(role.template_name(), &e))?;
        files.push((role, text));
    }
    // Main first, so the rendered file order is the same on every platform.
    files.sort_by_key(|(role, _)| *role == FileRole::Lib);
    Ok(files)
}

/// The borrowed view the parse functions take.
fn as_parts(files: &[(FileRole, String)]) -> Vec<(FileRole, &str)> {
    files
        .iter()
        .map(|(role, text)| (*role, text.as_str()))
        .collect()
}

/// Load every pinned well-typed template, after checking the directory against the list.
pub fn load_well_typed() -> Result<Vec<Template>, HarnessError> {
    let dir = fuzz_root().join("well-typed");
    compare_catalogue("well-typed", WELL_TYPED, &list_templates(&dir)?)?;
    WELL_TYPED
        .iter()
        .map(|name| -> Result<Template, HarnessError> {
            let files = read_template_dir(&dir.join(name), name)?;
            parse_well_typed(name, &as_parts(&files)).map_err(|error| HarnessError::Parse {
                template: (*name).to_owned(),
                error,
            })
        })
        .collect()
}

/// Load every pinned ill-typed template, after checking the directory and each pinned code.
pub fn load_ill_typed() -> Result<Vec<Mutant>, HarnessError> {
    let dir = fuzz_root().join("ill-typed");
    let pinned: Vec<&str> = ILL_TYPED.iter().map(|(name, _)| *name).collect();
    compare_catalogue("ill-typed", &pinned, &list_templates(&dir)?)?;
    ILL_TYPED
        .iter()
        .map(|(name, code)| -> Result<Mutant, HarnessError> {
            let files = read_template_dir(&dir.join(name), name)?;
            let mutant =
                parse_ill_typed(name, &as_parts(&files)).map_err(|error| HarnessError::Parse {
                    template: (*name).to_owned(),
                    error,
                })?;
            check_pinned_expect(&mutant, *code)?;
            Ok(mutant)
        })
        .collect()
}

/// A random run's iteration count, in `1..=MAX_ITERS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FuzzIters(u32);

impl FuzzIters {
    /// The count.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Why a random-run knob is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KnobError {
    /// The value is not valid Unicode.
    NotUnicode { var: &'static str },
    /// The value is not a decimal `u32`.
    NotANumber { var: &'static str, raw: String },
    /// The iteration count is zero.
    Zero,
    /// The iteration count is above [`MAX_ITERS`].
    AboveCap { got: u32 },
}

/// Parse `raw` as a decimal `u32` for `var`.
fn parse_u32(var: &'static str, raw: &OsStr) -> Result<u32, KnobError> {
    let text = raw.to_str().ok_or(KnobError::NotUnicode { var })?;
    text.parse().map_err(|_| KnobError::NotANumber {
        var,
        raw: text.to_owned(),
    })
}

/// The random run's start seed: [`FIXED_SEED`] when unset.
pub fn parse_seed(raw: Option<&OsStr>) -> Result<u32, KnobError> {
    raw.map_or(Ok(FIXED_SEED), |raw| parse_u32(SEED_VAR, raw))
}

/// The random run's iteration count: [`FIXED_SEED_ITERS`] when unset.
pub fn parse_iters(raw: Option<&OsStr>) -> Result<FuzzIters, KnobError> {
    let Some(raw) = raw else {
        return Ok(FuzzIters(FIXED_SEED_ITERS));
    };
    match parse_u32(ITERS_VAR, raw)? {
        0 => Err(KnobError::Zero),
        n if n > MAX_ITERS => Err(KnobError::AboveCap { got: n }),
        n => Ok(FuzzIters(n)),
    }
}

/// The random run's knobs, read from the environment.
pub fn knobs_from_env() -> Result<(u32, FuzzIters), KnobError> {
    let seed = parse_seed(ipe_env::var_os(SEED_VAR).as_deref())?;
    let iters = parse_iters(ipe_env::var_os(ITERS_VAR).as_deref())?;
    Ok((seed, iters))
}

/// The item a random iteration at `seed` picks, and the plan that fills it.
pub fn pick<T>(items: &[T], seed: u32) -> Option<(&T, FillPlan)> {
    let mut lcg = Lcg::new(seed);
    let draw = lcg.next_value();
    let len = u32::try_from(items.len()).ok()?;
    let index = draw.checked_rem(len)?;
    items
        .get(index as usize)
        .map(|item| (item, FillPlan::Seeded(lcg.next_value())))
}
