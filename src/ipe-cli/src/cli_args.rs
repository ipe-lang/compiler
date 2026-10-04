//! Typed command-line argument parsing — the single validation boundary for
//! every subcommand's optional flags (parse, don't validate).
//!
//! Each subcommand parses its raw `&[String]` tail into a typed value in which
//! an invalid combination CANNOT be constructed: mutually-exclusive options are
//! an enum rather than two independent booleans, an option that requires another
//! is a variant that carries it, and a value option that may appear at most once
//! is rejected loudly on a second occurrence rather than silently last-writing.
//!
//! The parse returns `Ok(TypedArgs)` or a precise [`CliError::Usage`] /
//! [`CliError::Usage`] naming exactly what is wrong — never a panic, never a
//! silently-ignored flag. `run_build` / `run_run` / `run_watch` / `run_fix` /
//! `run_fmt` consume the typed value; the scattered ad-hoc checks they used to
//! carry are folded into these parses.

use crate::build_plan::{AllocatorChoice, StaticRequestLayer};
use crate::delivery::{DeliveryError, DeliveryTokens, Shape, TargetTriple};
use crate::verb::Verb;
use crate::{CliError, text};
pub use ipe_backend_rust::static_build::StaticTriple;

/// The delivery positionals a `build` / `run` / `watch` tail may carry after the
/// optional entry path: an optional leading `[shape]` cross-check word and the
/// `[runtime] [host] [target]` tail.
///
/// Constructed by [`take_delivery_positionals`], which splits a run of
/// positional tokens into the (optional) leading shape word and the rest,
/// parsing the rest into typed [`DeliveryTokens`] at this boundary — an
/// out-of-grammar token is a [`DeliveryError`] here, never a silent drop.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DeliveryPositionals {
    /// The leading `[shape]` cross-check word, when one was written. Validated
    /// against the compiler-pinned shape at resolution.
    pub stated_shape: Option<Shape>,
    /// The parsed `[runtime] [host] [target]` tail.
    pub tokens: DeliveryTokens,
}

/// Split a run of positional tokens into the delivery positionals: an optional
/// leading `[shape]` word, then the `[runtime] [host] [target]` tail.
///
/// A leading token that is a shape word (`web`/`tui`/`cli`/`worker`/`script`) is
/// the cross-check shape; any other leading token belongs to the tail (a
/// runtime/host/target), so a bare `ipe build solo` and a bare `ipe build web`
/// both parse. `server` is NOT a shape word — a server is a `script` — so a
/// leading `server` reads as an entry path, never a shape. The tail is parsed
/// by [`DeliveryTokens::parse`].
///
/// # Errors
/// [`DeliveryError`] surfaced as a [`CliError::Usage`] when a tail token is
/// neither `solo`, a host, nor a plausible target (e.g. the `served` word).
fn take_delivery_positionals(
    positionals: &[String],
    command: &str,
) -> Result<DeliveryPositionals, CliError> {
    let (stated_shape, tail) = match positionals.split_first() {
        Some((first, rest)) if Shape::from_word(first).is_some() => (Shape::from_word(first), rest),
        _ => (None, positionals),
    };
    let tokens = DeliveryTokens::parse(tail).map_err(|e| delivery_usage(command, &e))?;
    Ok(DeliveryPositionals {
        stated_shape,
        tokens,
    })
}

/// Render a [`DeliveryError`] as a `ipe <command>:` usage error — the delivery
/// refusals are pedagogical lessons, carried verbatim behind the command prefix.
#[must_use]
fn delivery_usage(command: &str, err: &DeliveryError) -> CliError {
    CliError::Usage(text::msg::command_refusal(&command, err))
}

/// The one phrasing for "a command was given a flag it does not recognise".
///
/// Every misuse site routes through here so the wording, the `` `backtick` ``
/// quoting of the offending token, and the `ipe <command>:` prefix have a single
/// source — a flag typo reads the same regardless of which command caught it.
/// Always backticks (never `Debug`/`{:?}` straight quotes), always the prefix.
#[must_use]
pub fn usage_unknown_flag(command: &str, flag: &str) -> CliError {
    CliError::Usage(text::msg::unknown_flag(&command, &flag))
}

/// The one phrasing for "a parent command was given a subcommand it does not
/// recognise", naming the accepted set so the fix is obvious.
#[must_use]
pub fn usage_unknown_subcommand(command: &str, sub: &str, expected: &str) -> CliError {
    CliError::Usage(text::msg::unknown_subcommand(&command, &sub, &expected))
}

/// The one phrasing for "a command that takes no positional was given one, or a
/// single-positional command was given a second".
#[must_use]
pub fn usage_unexpected_argument(command: &str, arg: &str) -> CliError {
    CliError::Usage(text::msg::unexpected_argument(&command, &arg))
}

/// How a data-producing command renders its result.
///
/// The default is the human-friendly form; `--plain` and `--json` are the two
/// machine forms, and they are mutually exclusive — a request for both is a usage
/// error rather than a silent last-wins, so a caller never gets a format it did
/// not ask for.
///
/// Only the commands that emit machine-consumable data accept these flags; the
/// exact set is the help SSOT's per-command flag list (`help::COMMANDS`), not a
/// list restated here — a command advertises `--plain`/`--json` there and parses
/// them through this type. Commands whose output is an action rather than data
/// (`run` / `build` / `init` / `watch`) and `--help` do not take them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// The default: human-friendly, guttered, coloured on a terminal.
    #[default]
    Human,
    /// `--plain` — unstyled, flush-left, one record per line (pipe-friendly).
    Plain,
    /// `--json` — a stable documented schema (machine-parseable).
    Json,
}

/// Compact single-line JSON building — the SSOT for every machine `--json`
/// verdict.
///
/// The verdicts are byte-uniform: no space after a comma or colon, one escaping
/// rule for strings. A command builds its verdict from these and never
/// hand-writes JSON punctuation.
pub mod json {
    /// Encode a string as a JSON string literal.
    ///
    /// The body comes from the display escaper
    /// [`ipe_diagnostics::json::string_body`]: `"`, `\`, and every terminal
    /// hazard (controls, bidi and other format characters) are escaped.
    #[must_use]
    pub fn string(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        ipe_diagnostics::json::string_body_into(s, &mut out);
        out.push('"');
        out
    }

    /// A compact JSON array of already-encoded values — `[a,b,c]`, no spaces.
    #[must_use]
    pub fn array(values: &[String]) -> String {
        format!("[{}]", values.join(","))
    }

    /// A compact JSON array of strings — each element is [`string`]-encoded.
    #[must_use]
    pub fn string_array(items: &[&str]) -> String {
        let encoded: Vec<String> = items.iter().map(|s| string(s)).collect();
        array(&encoded)
    }

    /// A compact JSON object from `(key, already-encoded-value)` pairs —
    /// `{"k":v,...}`, no spaces.
    ///
    /// Each key is [`string`]-encoded; each value is a caller-supplied JSON
    /// fragment ([`string`] for text, a bare `true`/number literal, or a nested
    /// [`array`]/[`object`]).
    #[must_use]
    pub fn object(fields: &[(&str, String)]) -> String {
        let body: Vec<String> = fields
            .iter()
            .map(|(k, v)| format!("{}:{v}", string(k)))
            .collect();
        format!("{{{}}}", body.join(","))
    }
}

/// Extract the output format from a raw argument tail in a FIRST, infallible
/// pass — before any fallible parse runs — so a parse error can still be
/// rendered in the format the caller asked for.
///
/// This scan never fails: it ignores every token that is not a format flag
/// (including the unknown flag or malformed argument that will make the real
/// parse fail), because its sole job is to learn the disclosure surface before
/// the fallible parse decides the outcome. `--json` wins over `--plain` when
/// both appear (both are machine surfaces; the real parse still rejects the
/// combination, and routing that conflict through a machine envelope keeps the
/// machine stream clean rather than leaking a human banner). Absent any format
/// flag the default is [`OutputFormat::Human`].
///
/// This is the SSOT the machine-mode command bodies (`build` / `run` /
/// `type-check`) use to resolve their format up front; it must agree with the
/// per-command parsers' own [`consume_format_flag`] result on any tail those
/// parsers accept, so a successful parse and this peek never disagree about the
/// chosen format.
#[must_use]
pub fn peek_output_format(rest: &[String]) -> OutputFormat {
    let mut saw_plain = false;
    for arg in rest {
        match arg.as_str() {
            "--json" => return OutputFormat::Json,
            "--plain" => saw_plain = true,
            _ => {}
        }
    }
    if saw_plain {
        OutputFormat::Plain
    } else {
        OutputFormat::Human
    }
}

/// Recognise `--plain` / `--json` in `flag`, folding the choice into `slot`.
/// Returns `Ok(true)` when `flag` was an output-format flag (consumed),
/// `Ok(false)` when it is some other token the caller must handle.
///
/// The two forms are mutually exclusive: a second, different format flag — or a
/// repeat that would re-assert the same one — is rejected here so `--plain
/// --json` can never resolve to a single silent winner.
///
/// Exposed as `pub(crate)` so command modules with bespoke argument parsers
/// (those that cannot use [`split_format`] directly) can consume format flags
/// without duplicating the mutual-exclusion logic.
///
/// # Errors
/// [`CliError::Usage`] when a format flag is given after a different one,
/// naming `command` so the message points at the misused command.
pub(crate) fn consume_format_flag(
    slot: &mut Option<OutputFormat>,
    flag: &str,
    command: &str,
) -> Result<bool, CliError> {
    let requested = match flag {
        "--plain" => OutputFormat::Plain,
        "--json" => OutputFormat::Json,
        _ => return Ok(false),
    };
    match slot {
        None => {
            *slot = Some(requested);
            Ok(true)
        }
        Some(existing) if *existing == requested => {
            Err(CliError::Usage(text::msg::flag_repeated(&command, &flag)))
        }
        Some(_) => Err(CliError::Usage(text::msg::plain_json_exclusive(&command))),
    }
}

/// Parse the shared output-format flags out of a command's argument tail.
///
/// Returns the chosen [`OutputFormat`] (defaulting to [`OutputFormat::Human`])
/// and the positional tokens with the format flags removed.
///
/// A token that is neither a recognised format flag nor a positional — any other
/// `-`-leading token — is an unknown flag, rejected here so it can never be
/// silently swallowed into the positional list and exit 0. This mirrors
/// [`single_positional`]'s rejection of `-`-leading tokens.
///
/// # Errors
/// [`CliError::Usage`] on `--plain --json` together, a repeated format flag,
/// or an unrecognised `-`-leading flag.
pub fn split_format<'a>(
    rest: &'a [String],
    command: &str,
) -> Result<(OutputFormat, Vec<&'a str>), CliError> {
    let mut format: Option<OutputFormat> = None;
    let mut positional: Vec<&'a str> = Vec::new();
    for arg in rest {
        if consume_format_flag(&mut format, arg, command)? {
            continue;
        }
        if arg.starts_with('-') {
            return Err(usage_unknown_flag(command, arg));
        }
        positional.push(arg);
    }
    Ok((format.unwrap_or_default(), positional))
}

/// Parse a command whose only argument is an optional single positional path.
///
/// At most one non-flag token, no options. Returns the positional when present,
/// `None` when the tail is empty (the caller supplies its own default).
///
/// # Errors
/// [`CliError::Usage`] on any flag (this command takes none) or a second
/// positional — never a silently-ignored token.
pub fn single_positional<'a>(
    rest: &'a [String],
    command: &str,
) -> Result<Option<&'a str>, CliError> {
    let mut positional: Option<&'a str> = None;
    for arg in rest {
        if arg.starts_with('-') {
            return Err(usage_unknown_flag(command, arg));
        }
        if positional.is_some() {
            return Err(usage_unexpected_argument(command, arg));
        }
        positional = Some(arg);
    }
    Ok(positional)
}

/// The machine-flag form of [`single_positional`]: an optional single positional
/// path plus the shared `--plain` / `--json` format flags.
///
/// Returns the positional (or `None`) and the chosen [`OutputFormat`].
///
/// # Errors
/// [`CliError::Usage`] on an unknown flag, a second positional, or
/// `--plain --json` together.
pub fn single_positional_with_format<'a>(
    rest: &'a [String],
    command: &str,
) -> Result<(Option<&'a str>, OutputFormat), CliError> {
    let (format, positional) = split_format(rest, command)?;
    match positional.split_first() {
        None => Ok((None, format)),
        Some((one, [])) => Ok((Some(*one), format)),
        Some((_, [extra, ..])) => Err(usage_unexpected_argument(command, extra)),
    }
}

/// Set a value option that may appear at most once, rejecting a duplicate with a
/// specific message rather than silently overwriting the earlier value.
///
/// # Errors
/// [`CliError::Usage`] when `slot` already holds a value.
fn set_once<T>(slot: &mut Option<T>, value: T, flag: &str, command: &str) -> Result<(), CliError> {
    if slot.is_some() {
        return Err(CliError::Usage(text::msg::flag_repeated(&command, &flag)));
    }
    *slot = Some(value);
    Ok(())
}

/// Select `ipe run`'s session mode, refusing a second `--record` / `--replay`.
fn set_session(slot: &mut SessionMode, mode: SessionMode) -> Result<(), CliError> {
    const LABEL: &str = Verb::DEV_RUN.name();
    if let Some(first) = slot.flag() {
        let second = mode.flag().unwrap_or(first);
        return Err(CliError::Usage(if first == second {
            text::msg::flag_repeated(&LABEL, &first)
        } else {
            text::msg::session_flags_exclusive(&first, &second)
        }));
    }
    *slot = mode;
    Ok(())
}

/// Pull the value that follows a value-taking flag, or fail with a message
/// naming the flag whose argument is missing (rather than the generic synopsis).
///
/// # Errors
/// [`CliError::Usage`] when the iterator is exhausted.
fn take_value(
    it: &mut std::iter::Peekable<std::slice::Iter<'_, String>>,
    flag: &str,
    command: &str,
) -> Result<String, CliError> {
    it.next()
        .cloned()
        .ok_or_else(|| CliError::Usage(text::msg::flag_needs_value(&command, &flag)))
}

/// Take the leading positional entry, if any: the first token, but ONLY when it
/// is not a flag. A leading `--flag` (e.g. `ipe build --emit-ir`) leaves the
/// entry unset — so the flag is parsed as a flag rather than silently swallowed
/// as a bogus entry path — and the caller falls back to its project-aware
/// default. Advances `it` past the entry only when one is taken.
fn take_leading_entry(
    it: &mut std::iter::Peekable<std::slice::Iter<'_, String>>,
) -> Option<String> {
    match it.peek() {
        Some(first) if !first.starts_with('-') => it.next().cloned(),
        _ => None,
    }
}

/// `true` when `token` is a delivery word — a shape (`web`/`tui`/…), the `solo`
/// runtime, the never-written `served`, or a host (`desktop`/`ios`/`android`).
/// Used to tell a leading entry-path positional from a leading delivery word so
/// `ipe build web` (a delivery) and `ipe build src/Main.ipe` (an entry) both
/// parse. A target triple is deliberately excluded: a leading bare triple with
/// no preceding shape word is meaningless, so it stays an entry-path candidate
/// and the delivery parse rejects it in tail position if it slips through.
fn is_delivery_word(token: &str) -> bool {
    Shape::from_word(token).is_some()
        || token == "solo"
        || token == "served"
        || crate::delivery::Host::from_word(token).is_some()
}

/// The disambiguation note for a leading delivery word that also names a path on
/// disk, or `None` when nothing shadows. `exists` reports whether `word` names an
/// existing filesystem entry; kept as a parameter so the decision is unit-testable
/// without touching the real filesystem.
fn shadowing_note(word: &str, exists: impl FnOnce(&str) -> bool) -> Option<String> {
    if is_delivery_word(word) && exists(word) {
        Some(text::delivery_word_shadows_path(&word).into())
    } else {
        None
    }
}

/// Take the leading positional entry only when it is a genuine entry path — not
/// a delivery word. `ipe build web desktop` leaves the entry unset (the project
/// default) and hands `web desktop` to the delivery parse; `ipe build
/// src/Main.ipe web` consumes the path, then hands `web` to delivery.
///
/// When a skipped leading delivery word also names a path on disk it prints a
/// one-line note pointing at the `./word` form, so the shadowed path is
/// discoverable rather than silently overridden by the delivery reading.
fn take_leading_entry_path(
    it: &mut std::iter::Peekable<std::slice::Iter<'_, String>>,
) -> Option<String> {
    match it.peek() {
        Some(first) if !first.starts_with('-') && !is_delivery_word(first) => it.next().cloned(),
        Some(first) => {
            if let Some(note) = shadowing_note(first, |w| std::path::Path::new(w).exists()) {
                crate::screen::chatter(
                    crate::screen::Stream::Stderr,
                    crate::screen::Tone::Aux,
                    &note,
                );
            }
            None
        }
        None => None,
    }
}

/// Collect the trailing positional run — every remaining non-flag token — for
/// the delivery grammar. Stops at the first flag; a flag interleaved after a
/// positional is still the caller's to parse (the caller loops on the same
/// iterator). Returns the collected words in order.
fn take_delivery_words(it: &mut std::iter::Peekable<std::slice::Iter<'_, String>>) -> Vec<String> {
    let mut words = Vec::new();
    while let Some(next) = it.peek() {
        if next.starts_with('-') {
            break;
        }
        words.push((*next).clone());
        it.next();
    }
    words
}

/// The static-request flags shared by `build` and `run`, parsed into a typed
/// layer. Each value flag is rejected on a second occurrence; the boolean flags
/// are idempotent (a repeat is harmless and stays accepted).
///
/// `--target` is parsed into the closed [`TargetTriple`] set and `--allocator`
/// into the closed [`AllocatorChoice`] at this boundary, so an out-of-set value
/// can never reach resolution.
#[derive(Default)]
struct StaticFlags {
    static_flag: bool,
    target: Option<TargetTriple>,
    allocator: Option<AllocatorChoice>,
    c_free: bool,
}

/// Parse a raw `--target` value into the shared [`TargetTriple`] set.
///
/// `build`, `run`, and `release` share this one vocabulary (parse, don't
/// validate): the browser bundle, the portable WASI module, or a supported
/// musl-static triple. An out-of-set value is refused here, with the same
/// message for every command; what a command cannot do with an in-set target
/// (`run` has no process to execute for `wasm`, `release` produces no `wasi`
/// module) is that command's own typed refusal.
///
/// # Errors
/// [`CliError::Usage`] naming every supported value when `raw` is outside
/// the vocabulary.
pub fn parse_target(raw: &str) -> Result<TargetTriple, CliError> {
    TargetTriple::from_flag(raw).ok_or_else(|| {
        CliError::Usage(text::msg::unsupported_target(
            &raw,
            &StaticTriple::SUPPORTED.join(", "),
        ))
    })
}

/// The WASM flavour an optional `--target` selects ([`WasmKind::None`] for a
/// native triple or no target).
#[must_use]
pub const fn wasm_kind_of(target: Option<TargetTriple>) -> WasmKind {
    match target {
        Some(TargetTriple::BrowserWasm) => WasmKind::Client,
        Some(TargetTriple::Wasm32Wasip1) => WasmKind::Wasi,
        Some(TargetTriple::Native(_)) | None => WasmKind::None,
    }
}

impl StaticFlags {
    /// Consume `flag` as a static-request flag, pulling its value from `it` where
    /// it takes one. Returns `Ok(false)` when `flag` is not a static-request flag
    /// (so the caller can try its own flags next).
    ///
    /// # Errors
    /// [`CliError::Usage`] on a missing value, a duplicate value flag, or an
    /// allocator name outside the closed set.
    fn consume(
        &mut self,
        flag: &str,
        it: &mut std::iter::Peekable<std::slice::Iter<'_, String>>,
        command: &str,
    ) -> Result<bool, CliError> {
        match flag {
            "--static" => self.static_flag = true,
            "--target" => {
                let target = parse_target(&take_value(it, "--target", command)?)?;
                set_once(&mut self.target, target, "--target", command)?;
            }
            "--allocator" => {
                let raw = take_value(it, "--allocator", command)?;
                let choice = AllocatorChoice::parse(&raw)
                    .map_err(|refusal| CliError::Usage(crate::text::Message::relay(&refusal)))?;
                set_once(&mut self.allocator, choice, "--allocator", command)?;
            }
            "--cfree" => self.c_free = true,
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// The CLI precedence layer these flags express.
    fn layer(self) -> StaticRequestLayer {
        StaticRequestLayer {
            static_build: self.static_flag.then_some(true),
            // Only a native triple enters static resolution; a WASM target is
            // its own axis, routed before this layer is built.
            target: match self.target {
                Some(TargetTriple::Native(triple)) => Some(triple.as_str().to_owned()),
                Some(TargetTriple::BrowserWasm | TargetTriple::Wasm32Wasip1) | None => None,
            },
            allocator: self.allocator,
            c_free: self.c_free.then_some(true),
        }
    }
}

/// A WebAssembly compilation target selected on the CLI.
///
/// `--target wasm` and `--target wasi` are two distinct pseudo-triples (not
/// static-link triples), captured as their own axis so the native static flags
/// cannot also apply. The two WASM flavours are kept cleanly separate at the
/// parse boundary
/// (parse, don't validate): `Client` is the sandboxed browser bundle
/// (`wasm32-unknown-unknown`, `web solo`); `Wasi` is the co-located portable
/// WASI target (`wasm32-wasip1`) for a `Direct`/`Script` program. `None` is the
/// ordinary native build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmKind {
    /// No WASM target: an ordinary native build.
    None,
    /// `--target wasm` — the sandboxed browser client bundle.
    Client,
    /// `--target wasi` — the co-located portable `wasm32-wasip1` module.
    Wasi,
}

impl WasmKind {
    /// Whether this is a WASM target at all (either flavour) — the axis that
    /// does not compose with the native static-link flags.
    #[must_use]
    pub const fn is_wasm(self) -> bool {
        matches!(self, Self::Client | Self::Wasi)
    }

    /// The `--target` word that selects this flavour, for a pedagogical message.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Client => "wasm",
            Self::Wasi => "wasi",
        }
    }
}

/// The compilation surface `ipe build` produces — dump the lowered IR, or emit
/// a native/wasm project.
///
/// Making this an enum is what forbids `--emit-ir --out X` / `--emit-ir
/// --static` / `--emit-ir --target wasm`: the IR-dump variant carries no emit
/// fields at all, so an emit flag combined with `--emit-ir` has nowhere to land
/// and is rejected at parse time rather than silently ignored by an early
/// return.
#[derive(Debug, PartialEq, Eq)]
pub enum BuildMode {
    /// `--emit-ir` — pretty-print the lowered IR to stdout and stop before
    /// codegen. Composes with nothing but `--fix` (a pre-pass over the source).
    EmitIr,
    /// The ordinary path — emit a Cargo project. Carries the emit-affecting
    /// options that `--emit-ir` cannot take.
    Emit {
        /// `--out <dir>` — where to write the emitted project.
        out: Option<String>,
        /// `--target wasm`/`--target wasi` selects a WASM target (a distinct
        /// compilation axis), captured here so `--static` / `--allocator`
        /// cannot also apply.
        wasm: WasmKind,
        /// The native static-request layer (`--static` / `--target <triple>` /
        /// `--allocator`). Empty under a WASM target.
        static_layer: StaticRequestLayer,
    },
}

/// Fully-parsed `ipe build` arguments.
// Four independent one-of-two CLI switches (`fix`, `accept_risks`, `debugger`,
// `quiet`) each maps naturally to a bool; a two-variant enum or state machine
// would obscure their independence rather than clarify it.
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct BuildArgs {
    /// The positional entry (`None` → project-aware default).
    pub entry: Option<String>,
    /// The delivery positionals (`[shape] [runtime] [host]`) that follow the
    /// entry — the shape cross-check and the web runtime/host selection.
    pub delivery: DeliveryPositionals,
    /// `--runtime <dir>` — vendor the runtime from here.
    pub runtime: Option<String>,
    /// `--fix` — apply machine-applicable fixes before building.
    pub fix: bool,
    /// `--accept-risks` — take responsibility for every disclosed `.Unsafe`
    /// escape-hatch import and proceed without the acknowledgment prompt. The
    /// one-off, non-interactive form of consent (the durable form is
    /// `[capabilities] accept = ["unsafe"]` in `package.ipe`).
    pub accept_risks: bool,
    /// `--debugger` — compile the development-only time-travelling debugger into
    /// the emitted runtime loop. Absent from `ipe release` so the debugger can
    /// never ship in a production artifact. Orthogonal to the `Debug.*`
    /// source-construct gate.
    pub debugger: bool,
    /// The emit surface (IR dump vs project emit).
    pub mode: BuildMode,
    /// `--json` — emit each diagnostic as a stable JSON object instead of the
    /// human-readable, decorated layout.
    pub format: OutputFormat,
    /// `-q` / `--quiet` — suppress progress chatter; only warnings and errors.
    pub quiet: bool,
}

/// Parse `ipe build`'s argument tail.
///
/// Rejects, at this single boundary: `--emit-ir` combined with any
/// emit-affecting flag (`--out` / `--static` / `--target` / `--allocator` /
/// `--cfree`); `--target wasm` combined with `--static` / `--allocator` /
/// `--cfree` (native-only flags); a duplicate value flag; a target or allocator
/// outside its closed set; and an unknown flag.
///
/// # Errors
/// [`CliError::Usage`] / [`CliError::Usage`] naming the exact problem.
#[allow(clippy::too_many_lines)] // one linear flag loop + the emit-compose rejection gate
pub fn parse_build(rest: &[String]) -> Result<BuildArgs, CliError> {
    const LABEL: &str = Verb::DEV_BUILD.name();
    let mut it = rest.iter().peekable();
    let entry = take_leading_entry_path(&mut it);
    let delivery = take_delivery_positionals(&take_delivery_words(&mut it), LABEL)?;

    let mut out: Option<String> = None;
    let mut runtime: Option<String> = None;
    let mut emit_ir = false;
    let mut fix = false;
    let mut accept_risks = false;
    let mut debugger = false;
    let mut quiet = false;
    let mut static_flags = StaticFlags::default();
    let mut format: Option<OutputFormat> = None;
    while let Some(flag) = it.next() {
        if static_flags.consume(flag, &mut it, LABEL)? {
            continue;
        }
        if consume_format_flag(&mut format, flag, LABEL)? {
            continue;
        }
        match flag.as_str() {
            "--out" => set_once(
                &mut out,
                take_value(&mut it, "--out", LABEL)?,
                "--out",
                LABEL,
            )?,
            "--runtime" => set_once(
                &mut runtime,
                take_value(&mut it, "--runtime", LABEL)?,
                "--runtime",
                LABEL,
            )?,
            "--emit-ir" => emit_ir = true,
            "--fix" => fix = true,
            "--accept-risks" => accept_risks = true,
            "--debugger" => debugger = true,
            "-q" | "--quiet" => quiet = true,
            other => {
                return Err(usage_unknown_flag(LABEL, other));
            }
        }
    }

    // `--target wasm`/`--target wasi` is a compilation-target axis, not a
    // static-link triple; it never enters static-request resolution and does not
    // compose with the native static flags.
    let wasm = wasm_kind_of(static_flags.target);
    if wasm.is_wasm() && (static_flags.static_flag || static_flags.allocator.is_some()) {
        return Err(CliError::Usage(text::msg::static_flags_with_wasm(
            &wasm.word(),
        )));
    }
    if wasm.is_wasm() && static_flags.c_free {
        return Err(CliError::Usage(text::msg::cfree_with_wasm(&wasm.word())));
    }

    let mode = if emit_ir {
        // `--emit-ir` stops before codegen, so every emit-affecting flag is
        // meaningless with it. Reject rather than silently ignore (the old early
        // return dropped them without a word).
        if out.is_some() {
            return Err(CliError::Usage(text::msg::emit_ir_with_out()));
        }
        if static_flags.static_flag {
            return Err(CliError::Usage(text::msg::emit_ir_with_static()));
        }
        if static_flags.target.is_some() {
            return Err(CliError::Usage(text::msg::emit_ir_with_target()));
        }
        if static_flags.allocator.is_some() {
            return Err(CliError::Usage(text::msg::emit_ir_with_allocator()));
        }
        if static_flags.c_free {
            return Err(CliError::Usage(text::msg::emit_ir_with_cfree()));
        }
        BuildMode::EmitIr
    } else if wasm.is_wasm() {
        // Clear the pseudo-triple so it never enters static resolution.
        BuildMode::Emit {
            out,
            wasm,
            static_layer: StaticRequestLayer::default(),
        }
    } else {
        BuildMode::Emit {
            out,
            wasm: WasmKind::None,
            static_layer: static_flags.layer(),
        }
    };

    Ok(BuildArgs {
        entry,
        delivery,
        runtime,
        fix,
        accept_risks,
        debugger,
        mode,
        format: format.unwrap_or_default(),
        quiet,
    })
}

/// What `ipe run` does with a cli/worker app's TEA session.
///
/// One value, so a run that both records and replays is unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SessionMode {
    /// Run live; record nothing.
    #[default]
    Live,
    /// `--record` — run live and write the session into the output root.
    Record,
    /// `--replay [<log>]` — re-fold a recorded log, or show a recorded trace,
    /// instead of running live.
    ///
    /// `None` reads the typed log `--record` last wrote into the output root,
    /// else the trace beside it.
    Replay(Option<String>),
}

impl SessionMode {
    /// `true` for an ordinary live run that neither records nor replays.
    #[must_use]
    pub const fn is_live(&self) -> bool {
        matches!(self, Self::Live)
    }

    /// The flag that selected this mode, for messages; `None` when live.
    #[must_use]
    pub const fn flag(&self) -> Option<&'static str> {
        match self {
            Self::Live => None,
            Self::Record => Some("--record"),
            Self::Replay(_) => Some("--replay"),
        }
    }
}

/// Fully-parsed `ipe run` arguments.
pub struct RunArgs {
    /// The positional entry (`None` → project-aware default).
    pub entry: Option<String>,
    /// The delivery positionals (`[shape] [runtime] [host]`) that follow the
    /// entry.
    pub delivery: DeliveryPositionals,
    /// `--out <dir>`.
    pub out: Option<String>,
    /// `--runtime <dir>`.
    pub runtime: Option<String>,
    /// The native static-request layer.
    pub static_layer: StaticRequestLayer,
    /// The WASM compilation target selected on the CLI. `Client` (`--target
    /// wasm`, the browser bundle) has no executable form under `ipe run` and is
    /// refused at parse; `Wasi` (`--target wasi`) routes `ipe run` to the
    /// embedded-wasmtime execution path; `None` is the ordinary native run.
    pub wasm: WasmKind,
    /// `--accept-risks` — take responsibility for every disclosed `.Unsafe`
    /// escape-hatch import and proceed without the acknowledgment prompt. Same
    /// one-off consent as `ipe build --accept-risks`.
    pub accept_risks: bool,
    /// `--debugger` — compile the development-only time-travelling debugger into
    /// the emitted runtime loop. Absent from `ipe release` so the debugger can
    /// never ship in a production artifact.
    pub debugger: bool,
    /// `--record` / `--replay [<log>]` — record a cli/worker app's TEA session,
    /// or re-fold a recorded one.
    ///
    /// Either forces `debugger` on. `--record` has the runtime dump the bounded,
    /// plain trace (one `"<msg> => <model>"` line per step) and the typed log
    /// into the output root on exit; `--replay` has it fold the typed log with
    /// every `Cmd` discarded and print each step, or shows a plain trace
    /// sanitised without building.
    pub session: SessionMode,
    /// Arguments after `--`, forwarded verbatim to the compiled binary.
    pub bin_args: Vec<String>,
    /// `--json` — emit each diagnostic as a stable JSON object instead of the
    /// human-readable, decorated layout.
    pub format: OutputFormat,
    /// `-q` / `--quiet` — suppress progress chatter; only warnings and errors.
    pub quiet: bool,
}

/// Parse `ipe run`'s argument tail.
///
/// Splits on the first `--`: everything before is `ipe`-owned, everything after
/// is forwarded to the emitted binary untouched. `ipe run` builds and executes a
/// process: a native binary, or — under `--target wasi` — the emitted
/// `wasm32-wasip1` module in an embedded wasmtime engine. `--target wasm` (the
/// browser bundle, which has no executable form) is rejected here rather than
/// flowing into static resolution and surfacing as a confusing "target requires
/// --static" refusal.
///
/// # Errors
/// [`CliError::Usage`] / [`CliError::Usage`] naming the exact problem.
pub fn parse_run(rest: &[String]) -> Result<RunArgs, CliError> {
    const LABEL: &str = Verb::DEV_RUN.name();
    let dash_dash = rest.iter().position(|a| a == "--");
    // `pos` is a valid index; `pos + 1 <= rest.len()` (a trailing `--` gives an
    // empty tail), so both splits are in bounds without an indexing panic.
    let (ipe_args, bin_args): (&[String], Vec<String>) = dash_dash.map_or_else(
        || (rest, Vec::new()),
        |pos| {
            let (before, after_incl) = rest.split_at(pos);
            (before, after_incl.get(1..).unwrap_or(&[]).to_vec())
        },
    );

    let mut it = ipe_args.iter().peekable();
    let entry = take_leading_entry_path(&mut it);
    let delivery = take_delivery_positionals(&take_delivery_words(&mut it), LABEL)?;

    let mut out: Option<String> = None;
    let mut runtime: Option<String> = None;
    let mut accept_risks = false;
    let mut debugger = false;
    let mut session = SessionMode::Live;
    let mut quiet = false;
    let mut static_flags = StaticFlags::default();
    let mut format: Option<OutputFormat> = None;
    while let Some(flag) = it.next() {
        if static_flags.consume(flag, &mut it, LABEL)? {
            continue;
        }
        if consume_format_flag(&mut format, flag, LABEL)? {
            continue;
        }
        match flag.as_str() {
            "--out" => set_once(
                &mut out,
                take_value(&mut it, "--out", LABEL)?,
                "--out",
                LABEL,
            )?,
            "--runtime" => set_once(
                &mut runtime,
                take_value(&mut it, "--runtime", LABEL)?,
                "--runtime",
                LABEL,
            )?,
            "--accept-risks" => accept_risks = true,
            "--debugger" => debugger = true,
            "--record" => set_session(&mut session, SessionMode::Record)?,
            "--replay" => {
                // Every positional precedes the flags, so a non-flag token
                // right after `--replay` can only be its log path.
                let log = it.next_if(|next| !next.starts_with('-')).cloned();
                set_session(&mut session, SessionMode::Replay(log))?;
            }
            "-q" | "--quiet" => quiet = true,
            other => {
                return Err(usage_unknown_flag(LABEL, other));
            }
        }
    }

    // `--target wasm`/`--target wasi` is a compilation-target axis, not a
    // static-link triple; classify it before `static_flags.layer()` consumes
    // the flags. `--target wasi` runs the emitted module under embedded
    // wasmtime, so it composes with none of the native static-link flags — the
    // same non-composition `ipe build` enforces (they lower to a native triple
    // that a wasm target has no use for).
    let wasm = wasm_kind_of(static_flags.target);
    match wasm {
        WasmKind::Client => {
            return Err(CliError::Usage(text::msg::run_wasm_target()));
        }
        WasmKind::Wasi => {
            if static_flags.static_flag || static_flags.allocator.is_some() || static_flags.c_free {
                return Err(CliError::Usage(text::msg::run_wasi_native_flags()));
            }
        }
        WasmKind::None => {}
    }

    // A wasm target's `--target` word is a pseudo-triple, not a static-link
    // triple; clear the static-request layer so it never enters static
    // resolution (which would refuse `--target wasi` as a native triple missing
    // `--static`) — mirroring `parse_build`'s wasm arm. The wasm flavour is
    // carried on `wasm` and routed by the compile target downstream.
    let static_layer = if wasm.is_wasm() {
        StaticRequestLayer::default()
    } else {
        static_flags.layer()
    };

    Ok(RunArgs {
        entry,
        delivery,
        out,
        runtime,
        static_layer,
        wasm,
        accept_risks,
        debugger,
        session,
        bin_args,
        format: format.unwrap_or_default(),
        quiet,
    })
}

/// Fully-parsed `ipe eject` arguments.
pub struct EjectArgs {
    /// The positional entry (`None` → project-aware default).
    pub entry: Option<String>,
    /// `--out <dir>` — where to write the self-contained project (required).
    pub out: String,
    /// `--runtime <dir>` — vendor the Ipê runtime source from here instead of
    /// the resolved in-repo / installed tree.
    pub runtime: Option<String>,
}

/// Parse `ipe eject`'s argument tail.
///
/// `--out <dir>` is required: eject writes a whole standalone project, so there
/// is no sensible in-place default the way a throwaway `ipe build` artifact has —
/// the destination must be named. Each value flag is rejected on a second
/// occurrence.
///
/// # Errors
/// [`CliError::Usage`] / [`CliError::Usage`] naming the exact problem,
/// including a missing `--out`.
pub fn parse_eject(rest: &[String]) -> Result<EjectArgs, CliError> {
    const LABEL: &str = Verb::RELEASE_EJECT.name();
    let mut it = rest.iter().peekable();
    let entry = take_leading_entry(&mut it);

    let mut out: Option<String> = None;
    let mut runtime: Option<String> = None;
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--out" => set_once(
                &mut out,
                take_value(&mut it, "--out", LABEL)?,
                "--out",
                LABEL,
            )?,
            "--runtime" => set_once(
                &mut runtime,
                take_value(&mut it, "--runtime", LABEL)?,
                "--runtime",
                LABEL,
            )?,
            other => {
                return Err(usage_unknown_flag(LABEL, other));
            }
        }
    }

    let out = out.ok_or_else(|| CliError::Usage(text::msg::eject_out_required()))?;

    Ok(EjectArgs {
        entry,
        out,
        runtime,
    })
}

/// Where `ipe release` sends its output artifact: a browser bundle or a
/// statically-linked native binary for a specific rustc target triple.
///
/// Constructed exclusively through [`ReleaseTarget::from_target`] over the
/// shared [`TargetTriple`] set, so the `"wasm"` sentinel cannot leak past the
/// CLI boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseTarget {
    /// `--target wasm`: emit a browser/Wasm bundle.
    Wasm,
    /// `--target <triple>` or the default (omitted): a musl-static native binary
    /// for the given [`ipe_backend_rust::static_build::StaticTriple`].
    Native(ipe_backend_rust::static_build::StaticTriple),
}

impl ReleaseTarget {
    /// The release destination for a parsed `--target` (or its absence).
    ///
    /// `None` → the default native triple; [`TargetTriple::BrowserWasm`] →
    /// [`Self::Wasm`]; [`TargetTriple::Native`] → [`Self::Native`].
    ///
    /// # Errors
    ///
    /// [`CliError::Usage`] for [`TargetTriple::Wasm32Wasip1`]: a release
    /// produces a browser bundle or a native binary, never a WASI module.
    pub fn from_target(target: Option<TargetTriple>) -> Result<Self, CliError> {
        match target {
            None => Ok(Self::Native(StaticTriple::default())),
            Some(TargetTriple::BrowserWasm) => Ok(Self::Wasm),
            Some(TargetTriple::Native(triple)) => Ok(Self::Native(triple)),
            Some(TargetTriple::Wasm32Wasip1) => Err(CliError::Usage(text::msg::release_no_wasi())),
        }
    }
}

/// How `ipe release` packages a native-bearing artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReleaseMode {
    /// Default: fuse app binary and profile into the wrapper for a single
    /// self-jailing binary — the only way to run it applies the sandbox.
    #[default]
    Embed,
    /// `--bundle`: the multi-file opt-out — wrapper, app, and profile as
    /// siblings in a directory. An operator can run the app binary directly,
    /// bypassing the sandbox; prefer `Embed` for production.
    Bundle,
}

/// Fully-parsed `ipe release` arguments.
#[derive(Debug)]
pub struct ReleaseArgs {
    /// The positional entry (`None` → project-aware default).
    pub entry: Option<String>,
    /// The delivery positionals (`[shape] [runtime] [host]`) that follow the
    /// entry — the shape cross-check and the web runtime/host selection. A
    /// `desktop`/`ios`/`android` host produces a production distributable bundle.
    pub delivery: DeliveryPositionals,
    /// `--out <dir>` — where to write the artifact (optional; defaults to
    /// `release/`).
    pub out: Option<String>,
    /// `--runtime <dir>` — vendor the Ipê runtime from here.
    pub runtime: Option<String>,
    /// `--target <value>` — the resolved build destination: a browser bundle
    /// (`wasm`) or a musl-static native triple.
    pub target: ReleaseTarget,
    /// How to package a native-bearing artifact (embed mode by default; unused
    /// for pure-native and wasm targets).
    pub mode: ReleaseMode,
    /// `--emit-permissions <ios|macos|android>` — read-only inspection: print the
    /// OS-permission declarations the app's accepted web capabilities derive on
    /// the given platform, and build nothing. The raw platform word, validated at
    /// execution against the closed `ios|macos|android` set.
    pub emit_permissions: Option<String>,
    /// `--plain` / `--json` — the layout of a refusal the build reports.
    pub format: OutputFormat,
}

/// Parse `ipe release build`'s argument tail.
///
/// `--out` is optional. `--target` accepts either a musl-static triple or the
/// literal `wasm`. `--static` is accepted on a native target, which a release
/// always links statically, and refused with `--target wasm`. Each value flag
/// is rejected on a second occurrence.
///
/// # Errors
///
/// [`CliError::Usage`] / [`CliError::Usage`] naming the exact problem.
pub fn parse_release_build(rest: &[String]) -> Result<ReleaseArgs, CliError> {
    const LABEL: &str = Verb::RELEASE_BUILD.name();
    let mut it = rest.iter().peekable();
    let entry = take_leading_entry_path(&mut it);
    let delivery = take_delivery_positionals(&take_delivery_words(&mut it), LABEL)?;

    let mut out: Option<String> = None;
    let mut runtime: Option<String> = None;
    let mut target: Option<TargetTriple> = None;
    let mut format: Option<OutputFormat> = None;
    let mut emit_permissions: Option<String> = None;
    let mut saw_embed = false;
    let mut saw_bundle = false;
    let mut saw_static = false;

    while let Some(flag) = it.next() {
        if consume_format_flag(&mut format, flag, LABEL)? {
            continue;
        }
        match flag.as_str() {
            "--out" => set_once(
                &mut out,
                take_value(&mut it, "--out", LABEL)?,
                "--out",
                LABEL,
            )?,
            "--runtime" => set_once(
                &mut runtime,
                take_value(&mut it, "--runtime", LABEL)?,
                "--runtime",
                LABEL,
            )?,
            "--target" => {
                let parsed = parse_target(&take_value(&mut it, "--target", LABEL)?)?;
                set_once(&mut target, parsed, "--target", LABEL)?;
            }
            "--emit-permissions" => set_once(
                &mut emit_permissions,
                take_value(&mut it, "--emit-permissions", LABEL)?,
                "--emit-permissions",
                LABEL,
            )?,
            "--embed" => saw_embed = true,
            "--bundle" => saw_bundle = true,
            "--static" => saw_static = true,
            other => {
                return Err(usage_unknown_flag(LABEL, other));
            }
        }
    }

    if saw_embed && saw_bundle {
        return Err(CliError::Usage(text::msg::release_embed_bundle_exclusive()));
    }

    let mode = if saw_bundle {
        ReleaseMode::Bundle
    } else {
        ReleaseMode::Embed
    };

    if saw_static && target == Some(TargetTriple::BrowserWasm) {
        return Err(CliError::Usage(text::msg::static_flags_with_wasm(
            &WasmKind::Client.word(),
        )));
    }

    let target = ReleaseTarget::from_target(target)?;

    Ok(ReleaseArgs {
        entry,
        delivery,
        out,
        runtime,
        target,
        mode,
        emit_permissions,
        format: format.unwrap_or_default(),
    })
}

/// A release target that produces an artifact with no form `ipe release run`
/// can execute: a browser bundle or a distributable host bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoRunTarget {
    /// `--target wasm` (or a manifest/`IPE_TARGET` resolution to it): a
    /// browser bundle.
    Wasm,
    /// `web solo`: the self-contained browser client.
    Solo,
    /// `web desktop`: a per-OS desktop bundle.
    Desktop,
    /// `web solo ios`: an iOS project.
    Ios,
    /// `web solo android`: an Android project.
    Android,
}

impl NoRunTarget {
    /// The target with no run form a delivery host selects, or `None` for the
    /// served/default host.
    #[must_use]
    pub const fn from_host(host: crate::delivery::Host) -> Option<Self> {
        match host {
            crate::delivery::Host::Default => None,
            crate::delivery::Host::Desktop => Some(Self::Desktop),
            crate::delivery::Host::Ios => Some(Self::Ios),
            crate::delivery::Host::Android => Some(Self::Android),
        }
    }

    /// The word naming the target in the refusal.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Wasm => "wasm",
            Self::Solo => "web solo",
            Self::Desktop => "desktop",
            Self::Ios => "ios",
            Self::Android => "android",
        }
    }

    /// The `ipe release build` arguments that produce this target's artifact.
    #[must_use]
    pub const fn build_form(self) -> &'static str {
        match self {
            Self::Wasm => "--target wasm",
            Self::Solo => "web solo",
            Self::Desktop => "web desktop",
            Self::Ios => "web solo ios",
            Self::Android => "web solo android",
        }
    }
}

/// Fully-parsed `ipe release run` arguments.
#[derive(Debug)]
pub struct ReleaseRunArgs {
    /// The release build the run executes: embed mode, no inspection flag.
    pub build: ReleaseArgs,
    /// Whether any build-selecting argument (`--out`, `--runtime`, `--target`,
    /// a delivery word) was written; a prebuilt artifact directory takes none.
    pub build_flags: bool,
    /// Arguments after `--`, forwarded verbatim to the program.
    pub app_args: Vec<String>,
}

/// Parse `ipe release run`'s argument tail.
///
/// Accepts `[<path>] [--out <dir>] [--runtime <dir>] [--target <triple>]
/// [-- <args>...]`. A target with no run form — `--target wasm`, `web solo`, a
/// desktop or mobile host — is refused here with [`CliError::NoRunForm`],
/// before any build.
///
/// # Errors
///
/// [`CliError::NoRunForm`] for a target with no run form; [`CliError::Usage`]
/// naming any other misuse.
pub fn parse_release_run(rest: &[String]) -> Result<ReleaseRunArgs, CliError> {
    const LABEL: &str = Verb::RELEASE_RUN.name();
    let (ipe_args, app_args): (&[String], Vec<String>) =
        rest.iter().position(|a| a == "--").map_or_else(
            || (rest, Vec::new()),
            |pos| {
                let (before, after_incl) = rest.split_at(pos);
                (before, after_incl.get(1..).unwrap_or(&[]).to_vec())
            },
        );

    let mut it = ipe_args.iter().peekable();
    let entry = take_leading_entry_path(&mut it);
    let words = take_delivery_words(&mut it);
    let delivery = take_delivery_positionals(&words, LABEL)?;

    let mut out: Option<String> = None;
    let mut runtime: Option<String> = None;
    let mut target: Option<TargetTriple> = None;
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--out" => set_once(
                &mut out,
                take_value(&mut it, "--out", LABEL)?,
                "--out",
                LABEL,
            )?,
            "--runtime" => set_once(
                &mut runtime,
                take_value(&mut it, "--runtime", LABEL)?,
                "--runtime",
                LABEL,
            )?,
            "--target" => {
                let parsed = parse_target(&take_value(&mut it, "--target", LABEL)?)?;
                set_once(&mut target, parsed, "--target", LABEL)?;
            }
            other => {
                return Err(usage_unknown_flag(LABEL, other));
            }
        }
    }

    if target == Some(TargetTriple::BrowserWasm) {
        return Err(CliError::NoRunForm {
            target: NoRunTarget::Wasm,
        });
    }
    if let Some(no_run) = NoRunTarget::from_host(delivery.tokens.host) {
        return Err(CliError::NoRunForm { target: no_run });
    }
    if delivery.tokens.runtime == Some(crate::delivery::Runtime::Solo) {
        return Err(CliError::NoRunForm {
            target: NoRunTarget::Solo,
        });
    }

    let build_flags = !words.is_empty() || out.is_some() || runtime.is_some() || target.is_some();
    let target = ReleaseTarget::from_target(target)?;

    Ok(ReleaseRunArgs {
        build: ReleaseArgs {
            entry,
            delivery,
            out,
            runtime,
            target,
            mode: ReleaseMode::Embed,
            emit_permissions: None,
            format: OutputFormat::Human,
        },
        build_flags,
        app_args,
    })
}

/// Fully-parsed `ipe watch` arguments.
pub struct WatchArgs {
    /// The positional entry (`None` → project-aware default).
    pub entry: Option<String>,
    /// The delivery positionals (`[shape] [runtime] [host]`) that follow the
    /// entry.
    pub delivery: DeliveryPositionals,
    /// `--out <dir>`.
    pub out: Option<String>,
    /// `--runtime <dir>`.
    pub runtime: Option<String>,
    /// `--port <n>` — the parsed, in-range port (default 8000).
    pub port: u16,
    /// `-q` / `--quiet` — suppress progress chatter; only warnings and errors.
    pub quiet: bool,
    /// `--reset-state` — force every returning session to a fresh `init` on
    /// the next rebuild, bypassing the additive-splice checkpoint. Dev escape
    /// hatch; off by default.
    pub reset_state: bool,
    /// `--debugger` — compile the development-only time-travelling debugger into
    /// the rebuilt runtime loop, exposing the in-app debugger overlay. Off by
    /// default (the recorder adds runtime weight); the same opt-in `ipe run` and
    /// `ipe build` offer.
    pub debugger: bool,
}

/// Parse `ipe watch`'s argument tail. `--port` is parsed into a `u16` at this
/// boundary, and each value flag is rejected on a second occurrence.
///
/// # Errors
/// [`CliError::Usage`] / [`CliError::Usage`] naming the exact problem.
pub fn parse_watch(rest: &[String]) -> Result<WatchArgs, CliError> {
    const LABEL: &str = Verb::DEV_WATCH.name();
    let mut it = rest.iter().peekable();
    let entry = take_leading_entry_path(&mut it);
    let delivery = take_delivery_positionals(&take_delivery_words(&mut it), LABEL)?;

    let mut out: Option<String> = None;
    let mut runtime: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut quiet = false;
    let mut reset_state = false;
    let mut debugger = false;
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--out" => set_once(
                &mut out,
                take_value(&mut it, "--out", LABEL)?,
                "--out",
                LABEL,
            )?,
            "--runtime" => set_once(
                &mut runtime,
                take_value(&mut it, "--runtime", LABEL)?,
                "--runtime",
                LABEL,
            )?,
            "--port" => {
                let raw = take_value(&mut it, "--port", LABEL)?;
                set_once(&mut port, parse_port(&raw, LABEL)?, "--port", LABEL)?;
            }
            "-q" | "--quiet" => quiet = true,
            "--reset-state" => reset_state = true,
            "--debugger" => debugger = true,
            other => {
                return Err(usage_unknown_flag(LABEL, other));
            }
        }
    }

    Ok(WatchArgs {
        entry,
        delivery,
        out,
        runtime,
        port: port.unwrap_or(8000),
        quiet,
        reset_state,
        debugger,
    })
}

/// Parse a `--port` value into a real TCP port for `command`.
///
/// Port 0 is rejected: it asks the OS for an ephemeral port, but a served
/// process threads the literal value into URLs and readiness probes, so a
/// accepted 0 would yield unreachable `localhost:0` targets. The teaching
/// message names the command and points at the fix.
///
/// # Errors
/// [`CliError::Usage`] on a non-numeric value or on `0`.
pub fn parse_port(value: &str, command: &str) -> Result<u16, CliError> {
    match value.parse::<u16>() {
        Ok(0) => Err(CliError::Usage(text::msg::port_zero(&command))),
        Ok(port) => Ok(port),
        Err(_) => Err(CliError::Usage(text::msg::port_invalid(&command, &value))),
    }
}

/// Fully-parsed `ipe fix` arguments.
pub struct FixArgs {
    /// The positional source file (required).
    pub entry: String,
    /// `--yes`/`-y` — durable authorization to apply every fix without prompting.
    pub auto: bool,
}

/// Parse `ipe fix`'s argument tail. The `<path>` positional is required; a
/// second positional, or a flag other than `--yes`/`-y`, is rejected.
///
/// Any leading-dash token is treated as a flag (never bound as the path),
/// matching the sibling parsers.
///
/// # Errors
/// [`CliError::Usage`] / [`CliError::Usage`] naming the exact problem.
pub fn parse_fix(rest: &[String]) -> Result<FixArgs, CliError> {
    let mut entry: Option<String> = None;
    let mut auto = false;
    for arg in rest {
        match arg.as_str() {
            "--yes" | "-y" => auto = true,
            flag if flag.starts_with('-') => {
                return Err(usage_unknown_flag("fix", flag));
            }
            positional => set_once(&mut entry, positional.to_owned(), "<path>", "fix")?,
        }
    }
    let entry = entry.ok_or_else(|| CliError::Usage(text::msg::fix_usage()))?;
    Ok(FixArgs { entry, auto })
}

/// Fully-parsed `ipe type-check` arguments.
pub struct TypeCheckArgs {
    /// The positional entry (`None` → project-aware default).
    pub entry: Option<String>,
    /// `--json` / `--plain` — machine output format (default: human).
    pub format: OutputFormat,
}

/// Parse `ipe type-check`'s argument tail: an optional single positional path,
/// plus the shared `--plain` / `--json` format flags.
///
/// # Errors
/// [`CliError::Usage`] on an unknown flag or a second positional argument.
pub fn parse_type_check(rest: &[String]) -> Result<TypeCheckArgs, CliError> {
    let mut entry: Option<String> = None;
    let mut format: Option<OutputFormat> = None;
    for arg in rest {
        if consume_format_flag(&mut format, arg, "type-check")? {
            continue;
        }
        if arg.starts_with('-') {
            return Err(usage_unknown_flag("type-check", arg));
        }
        set_once(&mut entry, arg.clone(), "<path>", "type-check")?;
    }
    Ok(TypeCheckArgs {
        entry,
        format: format.unwrap_or_default(),
    })
}

/// Fully-parsed `ipe health` arguments.
///
/// `--yes` is consent-by-flag: apply every fixable item non-interactively. It is
/// meaningless with `--plain` / `--json`, which are pure data forms that NEVER
/// mutate — pairing them is a usage error rather than a silently ignored flag, so
/// a machine consumer can never accidentally ask a data form to change the
/// system.
pub struct HealthArgs {
    /// How to render the report.
    pub format: OutputFormat,
    /// `--yes`/`-y` — apply every fixable item without prompting.
    pub assume_yes: bool,
}

/// Parse `ipe health`'s argument tail: the shared `--plain` / `--json` forms,
/// plus `--yes`/`-y`. Takes no positional argument.
///
/// # Errors
/// [`CliError::Usage`] on an unknown flag, a positional argument, or
/// `--yes` combined with `--plain` / `--json` (a data form never mutates).
pub fn parse_health(rest: &[String]) -> Result<HealthArgs, CliError> {
    let mut format: Option<OutputFormat> = None;
    let mut assume_yes = false;
    for arg in rest {
        if consume_format_flag(&mut format, arg, "health")? {
            continue;
        }
        match arg.as_str() {
            "--yes" | "-y" => assume_yes = true,
            flag if flag.starts_with('-') => {
                return Err(usage_unknown_flag("health", flag));
            }
            other => {
                return Err(usage_unexpected_argument("health", other));
            }
        }
    }
    let format = format.unwrap_or_default();
    if assume_yes && format != OutputFormat::Human {
        return Err(CliError::Usage(text::msg::health_yes_with_format()));
    }
    Ok(HealthArgs { format, assume_yes })
}

/// Fully-parsed `ipe fmt` mode — three dispatch paths, no ambiguous states.
///
/// Constructed exclusively by [`parse_fmt`], which rejects invalid combinations
/// at the boundary (parse, don't validate).
pub enum FmtMode {
    /// Format (or check) every `.ipe` file under `path` in place.
    /// `None` means the current directory `.`. `format` selects how a `--check`
    /// run reports the unformatted set (human list, or a machine `--json`/`--plain`
    /// file list); it is [`OutputFormat::Human`] for a plain in-place format.
    InPlace {
        path: Option<String>,
        check: bool,
        format: OutputFormat,
    },
    /// Read from stdin, write formatted result to stdout.
    Stdin,
    /// Read from stdin, print diff to stdout without writing.
    StdinCheck,
}

/// Parse `ipe fmt`'s argument tail into a [`FmtMode`].
///
/// * No flags, no path → `InPlace { path: None, check: false }`
/// * One path → `InPlace { path: Some(…), check: false }`
/// * `--check` → `InPlace { …, check: true }`
/// * `--check --json` / `--check --plain` → machine list of unformatted files
/// * `--stdin` → `Stdin`
/// * `--stdin --check` → `StdinCheck`
/// * `--stdin` + positional path → error (mutually exclusive)
///
/// A machine output format (`--json` / `--plain`) is meaningful only for a
/// `--check` scan (it reports which files are unformatted), and never with
/// `--stdin` (that path already writes the formatted text or a diff to stdout);
/// both misuses are rejected here.
///
/// # Errors
/// [`CliError::Usage`] / [`CliError::Usage`] naming the exact problem.
pub fn parse_fmt(rest: &[String]) -> Result<FmtMode, CliError> {
    let mut path: Option<String> = None;
    let mut check = false;
    let mut stdin = false;
    let mut format: Option<OutputFormat> = None;
    for arg in rest {
        if consume_format_flag(&mut format, arg, "fmt")? {
            continue;
        }
        match arg.as_str() {
            "--check" => check = true,
            "--stdin" => stdin = true,
            flag if flag.starts_with('-') => {
                return Err(usage_unknown_flag("fmt", flag));
            }
            positional => {
                if path.is_some() {
                    return Err(CliError::Usage(text::msg::fmt_single_path()));
                }
                path = Some(positional.to_owned());
            }
        }
    }
    if stdin && path.is_some() {
        return Err(CliError::Usage(text::msg::fmt_stdin_and_path()));
    }
    let format = format.unwrap_or_default();
    if format != OutputFormat::Human && stdin {
        return Err(CliError::Usage(text::msg::fmt_format_with_stdin()));
    }
    if format != OutputFormat::Human && !check {
        return Err(CliError::Usage(text::msg::fmt_format_needs_check()));
    }
    if stdin {
        if check {
            Ok(FmtMode::StdinCheck)
        } else {
            Ok(FmtMode::Stdin)
        }
    } else {
        Ok(FmtMode::InPlace {
            path,
            check,
            format,
        })
    }
}

#[cfg(test)]
#[allow(clippy::panic)] // a wrong enum variant in a unit test IS the failure
mod tests {
    use super::*;

    // ---- build --------------------------------------------------------------

    #[test]
    fn build_empty_is_emit_defaults() {
        let a = parse_build(&[]).expect("empty build");
        assert!(a.entry.is_none());
        assert!(!a.fix);
        match a.mode {
            BuildMode::Emit {
                out,
                wasm,
                static_layer,
            } => {
                assert!(out.is_none());
                assert_eq!(wasm, WasmKind::None);
                assert_eq!(static_layer, StaticRequestLayer::default());
            }
            BuildMode::EmitIr => panic!("default build must emit a project"),
        }
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    // ---- delivery positionals ----------------------------------------------

    #[test]
    fn build_leading_shape_word_is_delivery_not_entry() {
        // `ipe build web` is a delivery shape cross-check, not an entry file.
        let a = parse_build(&s(&["web"])).expect("web");
        assert!(a.entry.is_none());
        assert_eq!(a.delivery.stated_shape, Some(Shape::Web));
    }

    #[test]
    fn build_entry_path_then_delivery() {
        let a = parse_build(&s(&["src/Main.ipe", "web", "desktop"])).expect("entry+delivery");
        assert_eq!(a.entry.as_deref(), Some("src/Main.ipe"));
        assert_eq!(a.delivery.stated_shape, Some(Shape::Web));
        assert_eq!(a.delivery.tokens.host, crate::delivery::Host::Desktop);
    }

    #[test]
    fn build_web_solo_host_parses() {
        let a = parse_build(&s(&["web", "solo", "ios"])).expect("web solo ios");
        assert_eq!(a.delivery.stated_shape, Some(Shape::Web));
        assert_eq!(
            a.delivery.tokens.runtime,
            Some(crate::delivery::Runtime::Solo)
        );
        assert_eq!(a.delivery.tokens.host, crate::delivery::Host::Ios);
    }

    #[test]
    fn build_served_word_is_a_pedagogical_refusal() {
        let refused = parse_build(&s(&["web", "served"]));
        assert!(
            matches!(&refused, Err(CliError::Usage(m)) if m.contains("served")),
            "`served` must be refused as a word: {refused:?}"
        );
    }

    #[test]
    fn build_no_delivery_positionals_is_empty() {
        let a = parse_build(&[]).expect("empty");
        assert_eq!(a.delivery, DeliveryPositionals::default());
    }

    #[test]
    fn run_and_watch_take_delivery_positionals() {
        let r = parse_run(&s(&["web", "desktop"])).expect("run web desktop");
        assert_eq!(r.delivery.stated_shape, Some(Shape::Web));
        assert_eq!(r.delivery.tokens.host, crate::delivery::Host::Desktop);
        let w = parse_watch(&s(&["tui"])).expect("watch tui");
        assert_eq!(w.delivery.stated_shape, Some(Shape::Tui));
    }

    #[test]
    fn run_delivery_before_dash_dash_only() {
        // Positionals after `--` are the binary's, never delivery words.
        let r = parse_run(&s(&["web", "--", "spa"])).expect("run");
        assert_eq!(r.delivery.stated_shape, Some(Shape::Web));
        assert_eq!(r.bin_args, s(&["spa"]));
    }

    #[test]
    fn build_entry_and_flags() {
        let a =
            parse_build(&s(&["Main.ipe", "--out", "o", "--runtime", "r", "--fix"])).expect("valid");
        assert_eq!(a.entry.as_deref(), Some("Main.ipe"));
        assert_eq!(a.runtime.as_deref(), Some("r"));
        assert!(a.fix);
        match a.mode {
            BuildMode::Emit { out, .. } => assert_eq!(out.as_deref(), Some("o")),
            BuildMode::EmitIr => panic!(),
        }
    }

    #[test]
    fn build_emit_ir_rejects_out() {
        assert!(matches!(
            parse_build(&s(&["--emit-ir", "--out", "o"])),
            Err(CliError::Usage(_))
        ));
    }

    #[test]
    fn build_emit_ir_rejects_static_and_target_and_allocator() {
        assert!(parse_build(&s(&["--emit-ir", "--static"])).is_err());
        assert!(parse_build(&s(&["--emit-ir", "--target", "wasm"])).is_err());
        assert!(parse_build(&s(&["--emit-ir", "--allocator", "dlmalloc"])).is_err());
    }

    #[test]
    fn build_emit_ir_alone_and_with_fix_ok() {
        assert!(matches!(
            parse_build(&s(&["--emit-ir"])).expect("emit-ir").mode,
            BuildMode::EmitIr
        ));
        let a = parse_build(&s(&["Main.ipe", "--emit-ir", "--fix"])).expect("emit-ir + fix");
        assert!(a.fix);
        assert!(matches!(a.mode, BuildMode::EmitIr));
    }

    #[test]
    fn build_wasm_rejects_native_static_flags() {
        assert!(parse_build(&s(&["--target", "wasm", "--static"])).is_err());
        assert!(parse_build(&s(&["--target", "wasm", "--allocator", "dlmalloc"])).is_err());
    }

    #[test]
    fn build_wasi_rejects_native_static_flags() {
        // `--target wasi` is a WASM axis too: the native static-link flags do
        // not compose with it, symmetric with `--target wasm`.
        assert!(parse_build(&s(&["--target", "wasi", "--static"])).is_err());
        assert!(parse_build(&s(&["--target", "wasi", "--allocator", "dlmalloc"])).is_err());
        assert!(parse_build(&s(&["--target", "wasi", "--cfree"])).is_err());
    }

    #[test]
    fn build_wasm_alone_ok() {
        match parse_build(&s(&["--target", "wasm"])).expect("wasm").mode {
            BuildMode::Emit {
                wasm, static_layer, ..
            } => {
                assert_eq!(wasm, WasmKind::Client);
                // The pseudo-triple must be cleared so it never reaches resolution.
                assert_eq!(static_layer, StaticRequestLayer::default());
            }
            BuildMode::EmitIr => panic!(),
        }
    }

    #[test]
    fn build_wasi_alone_ok() {
        // `--target wasi` selects the co-located WASI flavour, cleared from the
        // static-request layer just like `--target wasm`.
        match parse_build(&s(&["--target", "wasi"])).expect("wasi").mode {
            BuildMode::Emit {
                wasm, static_layer, ..
            } => {
                assert_eq!(wasm, WasmKind::Wasi);
                assert_eq!(static_layer, StaticRequestLayer::default());
            }
            BuildMode::EmitIr => panic!(),
        }
    }

    #[test]
    fn build_static_native_ok() {
        match parse_build(&s(&["--static", "--target", "x86_64-unknown-linux-musl"]))
            .expect("static")
            .mode
        {
            BuildMode::Emit {
                wasm, static_layer, ..
            } => {
                assert_eq!(wasm, WasmKind::None);
                assert_eq!(static_layer.static_build, Some(true));
                assert_eq!(
                    static_layer.target.as_deref(),
                    Some("x86_64-unknown-linux-musl")
                );
            }
            BuildMode::EmitIr => panic!(),
        }
    }

    #[test]
    fn build_duplicate_out_rejected() {
        assert!(matches!(
            parse_build(&s(&["--out", "a", "--out", "b"])),
            Err(CliError::Usage(_))
        ));
    }

    #[test]
    fn build_duplicate_target_rejected() {
        assert!(parse_build(&s(&["--target", "a", "--target", "b"])).is_err());
    }

    #[test]
    fn build_unknown_allocator_rejected() {
        assert!(matches!(
            parse_build(&s(&["--static", "--allocator", "jemalloc"])),
            Err(CliError::Usage(_))
        ));
    }

    #[test]
    fn build_missing_value_rejected() {
        assert!(parse_build(&s(&["--out"])).is_err());
        assert!(parse_build(&s(&["Main.ipe", "--target"])).is_err());
    }

    #[test]
    fn build_unknown_flag_rejected() {
        assert!(matches!(
            parse_build(&s(&["--bogus"])),
            Err(CliError::Usage(_))
        ));
    }

    // ---- run ----------------------------------------------------------------

    #[test]
    fn run_empty_defaults() {
        let a = parse_run(&[]).expect("empty run");
        assert!(a.entry.is_none());
        assert!(a.bin_args.is_empty());
        assert_eq!(a.static_layer, StaticRequestLayer::default());
    }

    #[test]
    fn run_dash_dash_forwards_verbatim() {
        let a = parse_run(&s(&["Main.ipe", "--out", "o", "--", "--flag", "x"])).expect("dash");
        assert_eq!(a.entry.as_deref(), Some("Main.ipe"));
        assert_eq!(a.out.as_deref(), Some("o"));
        assert_eq!(a.bin_args, s(&["--flag", "x"]));
    }

    #[test]
    fn run_trailing_dash_dash_is_empty_forward() {
        let a = parse_run(&s(&["Main.ipe", "--"])).expect("trailing");
        assert!(a.bin_args.is_empty());
    }

    /// `--allow-slow-allocator` is not a flag: an explicit
    /// `--allocator system` is the choice itself.
    #[test]
    fn allow_slow_allocator_is_an_unknown_flag() {
        type Parser = fn(&[String]) -> Result<(), CliError>;
        let parsers: [Parser; 2] = [|a| parse_build(a).map(|_| ()), |a| parse_run(a).map(|_| ())];
        for parse in parsers {
            let err = parse(&s(&["--allow-slow-allocator"]));
            assert!(
                matches!(&err, Err(e) if e.to_string().contains("unknown flag")),
                "{err:?}"
            );
            assert!(parse(&s(&["--static", "--allocator", "system"])).is_ok());
        }
    }

    /// `build`, `run`, and `release` share one `--target` vocabulary.
    ///
    /// An in-set value parses for all three, and an out-of-set value is refused
    /// by all three with the same message. The only per-command refusals are
    /// semantic — `run` has no process to execute for `wasm`, and `release`
    /// produces no `wasi` module — and each names why.
    #[test]
    fn build_run_and_release_share_the_target_vocabulary() {
        let in_set = [
            "wasm",
            "wasi",
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-musl",
        ];
        for value in in_set {
            assert!(parse_target(value).is_ok(), "{value}");
            assert!(
                parse_build(&s(&["--target", value])).is_ok(),
                "build {value}"
            );
            let run = parse_run(&s(&["--target", value]));
            let release = parse_release_build(&s(&["--target", value]));
            match value {
                "wasm" => assert!(
                    matches!(&run, Err(e) if e.to_string().contains("no native artifact")),
                    "run wasm is a semantic refusal"
                ),
                _ => assert!(run.is_ok(), "run {value}"),
            }
            match value {
                "wasi" => assert!(
                    matches!(&release, Err(e) if e.to_string().contains("does not produce a WASI module")),
                    "release wasi is a semantic refusal"
                ),
                _ => assert!(release.is_ok(), "release {value}"),
            }
        }
        for value in ["x86_64-apple-darwin", "bogus", "WASM", ""] {
            let expected = parse_target(value).map(|_| ()).map_err(|e| e.to_string());
            assert!(expected.is_err(), "{value} is out of set");
            for got in [
                parse_build(&s(&["--target", value])).map(|_| ()),
                parse_run(&s(&["--target", value])).map(|_| ()),
                parse_release_build(&s(&["--target", value])).map(|_| ()),
            ] {
                assert_eq!(got.map_err(|e| e.to_string()), expected, "{value}");
            }
        }
    }

    #[test]
    fn run_wasm_target_rejected() {
        assert!(matches!(
            parse_run(&s(&["--target", "wasm"])),
            Err(CliError::Usage(_))
        ));
    }

    #[test]
    fn run_wasi_target_is_accepted_and_captured() {
        // `ipe run --target wasi` now EXECUTES the emitted `wasm32-wasip1` module
        // under embedded wasmtime, so the flag is accepted at parse and captured
        // as the WASI compilation target (routed to the wasmtime path downstream).
        let a = parse_run(&s(&["--target", "wasi"])).expect("wasi accepted");
        assert_eq!(a.wasm, WasmKind::Wasi);
    }

    #[test]
    fn run_wasi_does_not_compose_with_static_flags() {
        // `--target wasi` is a wasm axis; the native static-link flags do not
        // apply to it — the same non-composition `ipe build --target wasi` enforces.
        assert!(parse_run(&s(&["--target", "wasi", "--static"])).is_err());
        assert!(parse_run(&s(&["--target", "wasi", "--allocator", "dlmalloc"])).is_err());
        assert!(parse_run(&s(&["--target", "wasi", "--cfree"])).is_err());
    }

    #[test]
    fn run_forwarded_args_are_not_parsed() {
        // A `--out` AFTER `--` is the binary's, never ipe's.
        let a = parse_run(&s(&["Main.ipe", "--", "--out", "x", "--target", "wasm"])).expect("fwd");
        assert!(a.out.is_none());
        assert_eq!(a.bin_args, s(&["--out", "x", "--target", "wasm"]));
    }

    #[test]
    fn run_duplicate_out_rejected() {
        assert!(parse_run(&s(&["--out", "a", "--out", "b"])).is_err());
    }

    #[test]
    fn run_unknown_flag_rejected() {
        assert!(parse_run(&s(&["Main.ipe", "--bogus"])).is_err());
    }

    // ---- watch --------------------------------------------------------------

    #[test]
    fn watch_defaults_port_8000() {
        let a = parse_watch(&[]).expect("empty watch");
        assert_eq!(a.port, 8000);
    }

    #[test]
    fn watch_parses_port() {
        let a = parse_watch(&s(&["Main.ipe", "--port", "9090"])).expect("port");
        assert_eq!(a.port, 9090);
        assert_eq!(a.entry.as_deref(), Some("Main.ipe"));
    }

    #[test]
    fn watch_invalid_port_rejected() {
        assert!(parse_watch(&s(&["--port", "notanumber"])).is_err());
        assert!(parse_watch(&s(&["--port", "99999"])).is_err());
    }

    #[test]
    fn watch_rejects_port_zero() {
        // Port 0 is an ephemeral-port request, but watch threads the literal
        // value into URLs and readiness probes, so it is refused like doc serve.
        assert!(parse_watch(&s(&["--port", "0"])).is_err());
    }

    #[test]
    fn watch_duplicate_port_rejected() {
        assert!(parse_watch(&s(&["--port", "1", "--port", "2"])).is_err());
    }

    #[test]
    fn watch_rejects_build_flags() {
        // `--static` belongs to build/run, never watch.
        assert!(parse_watch(&s(&["--static"])).is_err());
    }

    #[test]
    fn watch_debugger_flag_off_by_default_and_parses() {
        assert!(!parse_watch(&[]).expect("empty watch").debugger);
        let a = parse_watch(&s(&["Main.ipe", "--debugger"])).expect("debugger");
        assert!(a.debugger);
    }

    // ---- fix ----------------------------------------------------------------

    #[test]
    fn fix_requires_path() {
        assert!(matches!(parse_fix(&[]), Err(CliError::Usage(_))));
    }

    #[test]
    fn fix_path_and_yes() {
        let a = parse_fix(&s(&["Main.ipe", "--yes"])).expect("fix");
        assert_eq!(a.entry, "Main.ipe");
        assert!(a.auto);
    }

    #[test]
    fn fix_second_positional_rejected() {
        assert!(parse_fix(&s(&["a.ipe", "b.ipe"])).is_err());
    }

    #[test]
    fn fix_unknown_flag_rejected() {
        assert!(parse_fix(&s(&["Main.ipe", "--bogus"])).is_err());
    }

    #[test]
    fn fix_accepts_short_yes_alias() {
        let a = parse_fix(&s(&["-y", "Main.ipe"])).expect("fix -y");
        assert_eq!(a.entry, "Main.ipe");
        assert!(a.auto);
    }

    #[test]
    fn fix_short_flag_is_never_bound_as_the_path() {
        // A single-dash token is a flag, not the entry path: `-z` is rejected as
        // an unknown flag rather than silently opened as a file named `-z`.
        assert!(parse_fix(&s(&["-z", "Main.ipe"])).is_err());
        assert!(matches!(parse_fix(&s(&["-z"])), Err(CliError::Usage(_))));
    }

    #[test]
    fn shadowing_note_only_fires_for_an_existing_delivery_word() {
        assert!(shadowing_note("web", |_| true).is_some());
        assert!(shadowing_note("web", |_| false).is_none());
        // A non-delivery leading token never yields a note (it is a real entry).
        assert!(shadowing_note("src", |_| true).is_none());
    }

    // ---- fmt ----------------------------------------------------------------

    #[test]
    fn fmt_empty_is_in_place_default() {
        let m = parse_fmt(&[]).expect("empty fmt");
        assert!(matches!(
            m,
            FmtMode::InPlace {
                path: None,
                check: false,
                ..
            }
        ));
    }

    #[test]
    fn fmt_path_sets_in_place() {
        let m = parse_fmt(&s(&["src"])).expect("fmt src");
        assert!(matches!(m, FmtMode::InPlace { path: Some(p), check: false, .. } if p == "src"));
    }

    #[test]
    fn fmt_check_and_path() {
        let m = parse_fmt(&s(&["src", "--check"])).expect("fmt");
        assert!(matches!(m, FmtMode::InPlace { path: Some(p), check: true, .. } if p == "src"));
    }

    #[test]
    fn fmt_stdin_only() {
        let m = parse_fmt(&s(&["--stdin"])).expect("stdin");
        assert!(matches!(m, FmtMode::Stdin));
    }

    #[test]
    fn fmt_stdin_check() {
        let m = parse_fmt(&s(&["--stdin", "--check"])).expect("stdin check");
        assert!(matches!(m, FmtMode::StdinCheck));
    }

    #[test]
    fn fmt_check_only() {
        let m = parse_fmt(&s(&["--check"])).expect("check only");
        assert!(matches!(
            m,
            FmtMode::InPlace {
                path: None,
                check: true,
                ..
            }
        ));
    }

    #[test]
    fn fmt_stdin_with_path_rejected() {
        assert!(parse_fmt(&s(&["--stdin", "src"])).is_err());
    }

    #[test]
    fn fmt_two_paths_rejected() {
        assert!(parse_fmt(&s(&["a", "b"])).is_err());
    }

    #[test]
    fn fmt_unknown_flag_rejected() {
        assert!(parse_fmt(&s(&["--bogus"])).is_err());
    }

    // ---- health -------------------------------------------------------------

    #[test]
    fn health_empty_is_human_no_yes() {
        let a = parse_health(&[]).expect("empty health");
        assert_eq!(a.format, OutputFormat::Human);
        assert!(!a.assume_yes);
    }

    #[test]
    fn health_yes_and_short_yes() {
        assert!(parse_health(&s(&["--yes"])).expect("yes").assume_yes);
        assert!(parse_health(&s(&["-y"])).expect("short yes").assume_yes);
    }

    #[test]
    fn health_plain_and_json_recognised() {
        assert_eq!(
            parse_health(&s(&["--plain"])).expect("plain").format,
            OutputFormat::Plain
        );
        assert_eq!(
            parse_health(&s(&["--json"])).expect("json").format,
            OutputFormat::Json
        );
    }

    #[test]
    fn health_yes_with_data_form_rejected() {
        // A data form never mutates, so --yes with it is a usage error.
        assert!(parse_health(&s(&["--yes", "--plain"])).is_err());
        assert!(parse_health(&s(&["--json", "-y"])).is_err());
    }

    #[test]
    fn health_positional_and_unknown_flag_rejected() {
        assert!(parse_health(&s(&["somefile"])).is_err());
        assert!(parse_health(&s(&["--bogus"])).is_err());
    }

    // ---- misuse discipline (unknown flags) ----------------------------------

    #[test]
    fn split_format_rejects_unknown_leading_dash_flag() {
        // A `-`-leading token that is not a format flag is an unknown flag, never
        // swallowed into the positional list.
        let err = split_format(&s(&["--nope"]), "capabilities").expect_err("must reject");
        assert!(
            matches!(err, CliError::Usage(m) if m == "ipe capabilities: unknown flag `--nope`")
        );
    }

    #[test]
    fn split_format_keeps_plain_positionals() {
        let a = s(&["file.ipe"]);
        let (_fmt, pos) = split_format(&a, "diff").expect("positional ok");
        assert_eq!(pos, vec!["file.ipe"]);
    }

    #[test]
    fn single_positional_with_format_parses_path_and_json() {
        let a = s(&["proj", "--json"]);
        let (path, fmt) = single_positional_with_format(&a, "test").expect("ok");
        assert_eq!(path, Some("proj"));
        assert_eq!(fmt, OutputFormat::Json);
    }

    #[test]
    fn single_positional_with_format_rejects_unknown_flag_and_extra() {
        assert!(single_positional_with_format(&s(&["--nope"]), "test").is_err());
        assert!(single_positional_with_format(&s(&["a", "b"]), "test").is_err());
        assert!(single_positional_with_format(&s(&["--plain", "--json"]), "verify").is_err());
    }

    #[test]
    fn misuse_helpers_have_one_phrasing() {
        // Always backticked, always the `ipe <command>:` prefix.
        assert_eq!(
            usage_unknown_flag(Verb::DEV_BUILD.name(), "--nope").to_string(),
            "ipe dev build: unknown flag `--nope`"
        );
        assert_eq!(
            usage_unknown_subcommand("rust", "bogus", "add, remove, or install").to_string(),
            "ipe rust: unknown subcommand `bogus` (expected add, remove, or install)"
        );
        assert_eq!(
            usage_unexpected_argument("clean", "x").to_string(),
            "ipe clean: unexpected argument `x`"
        );
    }

    // ---- fmt machine flags --------------------------------------------------

    #[test]
    fn fmt_check_json_and_plain_recognised() {
        assert!(matches!(
            parse_fmt(&s(&["--check", "--json"])).expect("check json"),
            FmtMode::InPlace {
                check: true,
                format: OutputFormat::Json,
                ..
            }
        ));
        assert!(matches!(
            parse_fmt(&s(&["--check", "--plain"])).expect("check plain"),
            FmtMode::InPlace {
                check: true,
                format: OutputFormat::Plain,
                ..
            }
        ));
    }

    #[test]
    fn fmt_format_without_check_or_with_stdin_rejected() {
        assert!(parse_fmt(&s(&["--json"])).is_err());
        assert!(parse_fmt(&s(&["--stdin", "--json"])).is_err());
        assert!(parse_fmt(&s(&["--check", "--plain", "--json"])).is_err());
    }

    // ---- compact JSON SSOT --------------------------------------------------

    #[test]
    fn json_helpers_are_compact_and_escaped() {
        assert_eq!(json::string("a\"b\\c"), "\"a\\\"b\\\\c\"");
        // No space after a comma — byte-uniform with capabilities/version.
        assert_eq!(json::string_array(&["A", "B"]), "[\"A\",\"B\"]");
        assert_eq!(
            json::object(&[("k", json::string("v")), ("n", "true".to_owned())]),
            "{\"k\":\"v\",\"n\":true}"
        );
        // The doc-list array shape is compact — no comma-space.
        assert!(!json::string_array(&["Main", "Ipe.List"]).contains(", "));
    }

    /// A C1 control or a bidi override reaches a `--json` record escaped, never raw.
    #[test]
    fn json_string_escapes_terminal_hazards() {
        assert_eq!(json::string("\u{9b}"), "\"\\u009b\"");
        assert_eq!(json::string("a\u{202e}b"), "\"a\\u202eb\"");
    }

    // ---- output format ------------------------------------------------------

    #[test]
    fn format_defaults_to_human_and_keeps_positionals() {
        let args = s(&["a", "b"]);
        let (fmt, pos) = split_format(&args, "diff").expect("no flags");
        assert_eq!(fmt, OutputFormat::Human);
        assert_eq!(pos, vec!["a", "b"]);
    }

    #[test]
    fn format_plain_and_json_are_recognised() {
        let plain = s(&["x", "--plain"]);
        let (fmt, pos) = split_format(&plain, "capabilities").expect("plain");
        assert_eq!(fmt, OutputFormat::Plain);
        assert_eq!(pos, vec!["x"]);
        let json = s(&["--json", "x"]);
        let (fmt, _) = split_format(&json, "capabilities").expect("json");
        assert_eq!(fmt, OutputFormat::Json);
    }

    #[test]
    fn format_rejects_both_flags_together() {
        assert!(matches!(
            split_format(&s(&["--plain", "--json"]), "version"),
            Err(CliError::Usage(_))
        ));
        assert!(split_format(&s(&["--json", "--plain"]), "version").is_err());
    }

    #[test]
    fn format_rejects_a_repeated_flag() {
        assert!(split_format(&s(&["--plain", "--plain"]), "diff").is_err());
    }

    // ---- release ------------------------------------------------------------

    #[test]
    fn release_defaults_to_embed_mode() {
        let a = parse_release_build(&[]).expect("empty release");
        assert_eq!(a.mode, ReleaseMode::Embed);
        assert_eq!(a.format, OutputFormat::Human);
    }

    #[test]
    fn release_embed_flag_is_default_mode() {
        let a = parse_release_build(&s(&["--embed"])).expect("--embed");
        assert_eq!(a.mode, ReleaseMode::Embed);
    }

    #[test]
    fn release_bundle_flag_selects_bundle_mode() {
        let a = parse_release_build(&s(&["--bundle"])).expect("--bundle");
        assert_eq!(a.mode, ReleaseMode::Bundle);
    }

    #[test]
    fn release_embed_and_bundle_together_rejected() {
        assert!(matches!(
            parse_release_build(&s(&["--embed", "--bundle"])),
            Err(CliError::Usage(_))
        ));
        assert!(parse_release_build(&s(&["--bundle", "--embed"])).is_err());
    }

    /// `--capabilities` / `--show-profile` are unknown flags of `release
    /// build`: `ipe capabilities` is the one inspection form.
    #[test]
    fn release_build_capabilities_flags_are_unknown() {
        for flag in ["--capabilities", "--show-profile"] {
            let err = parse_release_build(&s(&[flag]));
            assert!(
                matches!(&err, Err(CliError::Usage(m))
                    if m.to_string() == format!("ipe release build: unknown flag `{flag}`")),
                "{flag}: {err:?}"
            );
        }
    }

    #[test]
    fn release_takes_output_format() {
        let a = parse_release_build(&s(&["--json"])).expect("--json");
        assert_eq!(a.format, OutputFormat::Json);
    }

    /// `--static` is accepted on a native release (already static) and refused
    /// with `--target wasm`.
    #[test]
    fn release_static_composes_with_native_only() {
        let a = parse_release_build(&s(&["--static"])).expect("--static");
        assert!(matches!(a.target, ReleaseTarget::Native(_)));
        assert!(
            parse_release_build(&s(&["--static", "--target", "aarch64-unknown-linux-musl"]))
                .is_ok()
        );
        assert!(matches!(
            parse_release_build(&s(&["--static", "--target", "wasm"])),
            Err(CliError::Usage(_))
        ));
        assert!(matches!(
            parse_release_build(&s(&["--target", "wasm", "--static"])),
            Err(CliError::Usage(_))
        ));
    }

    /// `--emit-permissions` belongs to `release build` only.
    #[test]
    fn dev_build_emit_permissions_is_unknown_flag() {
        let err = parse_build(&s(&["--emit-permissions", "ios"]));
        assert!(
            matches!(&err, Err(CliError::Usage(m))
                if m.to_string() == "ipe dev build: unknown flag `--emit-permissions`"),
            "{err:?}"
        );
        let a = parse_release_build(&s(&["--emit-permissions", "ios"])).expect("release build");
        assert_eq!(a.emit_permissions.as_deref(), Some("ios"));
    }

    #[test]
    fn release_plain_and_json_together_rejected() {
        assert!(parse_release_build(&s(&["--plain", "--json"])).is_err());
    }

    #[test]
    fn release_wasm_target_accepted() {
        let a = parse_release_build(&s(&["--target", "wasm"])).expect("--target wasm");
        assert_eq!(a.target, ReleaseTarget::Wasm);
    }

    #[test]
    fn release_target_none_defaults_to_native_x86_64() {
        let a = parse_release_build(&[]).expect("empty release");
        assert_eq!(
            a.target,
            ReleaseTarget::Native(StaticTriple::X8664LinuxMusl)
        );
    }

    #[test]
    fn release_target_valid_triple_accepted() {
        let a = parse_release_build(&s(&["--target", "aarch64-unknown-linux-musl"]))
            .expect("--target aarch64");
        assert_eq!(
            a.target,
            ReleaseTarget::Native(StaticTriple::Aarch64LinuxMusl)
        );
    }

    #[test]
    fn release_target_invalid_triple_rejected() {
        let err = parse_release_build(&s(&["--target", "wasm32-unknown-bogus"]));
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("unsupported target"), "got: {msg}");
    }

    #[test]
    fn release_unknown_flag_rejected() {
        assert!(parse_release_build(&s(&["--optimize"])).is_err());
        assert!(parse_release_build(&s(&["--bogus"])).is_err());
    }

    #[test]
    fn release_out_default_is_none() {
        // No `--out` → `args.out` is None; `run_release` maps None to "release/".
        let a = parse_release_build(&[]).expect("empty release");
        assert!(a.out.is_none());
    }

    #[test]
    fn release_out_flag_accepted() {
        let a = parse_release_build(&s(&["--out", "dist"])).expect("--out dist");
        assert_eq!(a.out.as_deref(), Some("dist"));
    }

    #[test]
    fn release_out_flag_accepts_absolute_path() {
        let a = parse_release_build(&s(&["--out", "/tmp/my-release"])).expect("--out /tmp/…");
        assert_eq!(a.out.as_deref(), Some("/tmp/my-release"));
    }

    #[test]
    fn release_out_flag_missing_value_rejected() {
        assert!(parse_release_build(&s(&["--out"])).is_err());
    }

    #[test]
    fn release_out_flag_combined_with_target() {
        let a =
            parse_release_build(&s(&["--out", "dist", "--target", "wasm"])).expect("--out + wasm");
        assert_eq!(a.out.as_deref(), Some("dist"));
        assert_eq!(a.target, ReleaseTarget::Wasm);
    }
}
