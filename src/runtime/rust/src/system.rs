// System helpers — some generic over E (when returning IpeTask).
use super::path::{OsOrigin, from_os};
use super::{IpeError, IpeMaybe, IpeResult, IpeTask, ok_res, str_err};

// `std::env::set_var`/`remove_var` are documented as NOT thread-safe: a mutator
// reallocates the C `environ` block while another thread READS it — and the
// racing reader is NOT only `std::env::var`. libc readers (`getenv`, and
// `getaddrinfo` reached through `to_socket_addrs`), and any third-party crate,
// walk `environ` WITHOUT taking any lock we control. A process-global RwLock over
// the real environ can serialise only OUR readers, never those — so a mutator
// holding a write lock still races a concurrent libc `getaddrinfo`, a real
// use-after-free reachable from safe Ipê (`Task.parallel [System.setenv, Http.get]`).
//
// The runtime therefore NEVER mutates the real `environ` after startup. Ipê env
// writes land in a process-local overlay map guarded by this `RwLock`; every Ipê
// read (`read_env_var`/`read_env_var_os`) consults the overlay first and the real
// (immutable-after-startup) environ second. Children spawned by `Process.*`
// receive the overlay applied explicitly onto their `Command` env, so an
// overlay-set var still reaches a subprocess without touching the parent's
// `environ`. No `environ` mutation ⇒ no reader↔mutator race with ANY reader,
// ours or libc's — the hazard is removed, not merely serialised on one side.
type EnvOverlay = std::collections::HashMap<String, Option<String>>;

/// Process-local env overlay. `Some(value)` shadows/introduces a variable;
/// `None` is a tombstone that hides a variable present in the real environ. An
/// absent key defers to the real environ. Guarded so concurrent Ipê readers and
/// writers are consistent; the real `environ` is never mutated, so no reader of
/// any origin can race a mutation.
static ENV_OVERLAY: std::sync::LazyLock<std::sync::RwLock<EnvOverlay>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(std::collections::HashMap::new()));

/// A key/value pair Ipê may write to the env overlay: a key that is empty,
/// contains `=` or NUL, or a value containing NUL is rejected (would be an
/// invalid environment entry). `pub(crate)` so child-spawn paths reuse the same
/// admission rule the overlay applies.
pub(crate) fn env_entry_is_valid(key: &str, val: &str) -> bool {
    !(key.is_empty() || key.contains('=') || key.contains('\0') || val.contains('\0'))
}

/// Read an environment variable: the overlay wins over the real environ, so a
/// value Ipê set/removed via `System.setenv`/`unsetenv`/`loadEnv` is observed
/// consistently. `pub(crate)` so every non-test process-env read in the crate
/// routes through this one accessor — that is what makes the overlay authoritative
/// for Ipê by construction. The runtime's own settings follow the overlay too:
/// `NO_COLOR`, `IPE_EXPLAIN_VERBOSE`, and the debugger's `IPE_DEBUGGER_RECORD` /
/// `IPE_DEBUGGER_REPLAY` observe a value the program wrote, not only the
/// environment the process started with.
///
/// A temp-root key ([`super::scratch_core::TEMP_ROOT_NAMES`], any case) always
/// reads as unset: the temp root is a base other users can write, resolved only
/// by the scratch primitive behind its ownership checks, so no Ipê program or
/// runtime path builds a temporary name from it. `System.getenv "TMPDIR"` is
/// therefore `Err` and `getenvOr` yields its default, whatever the environ holds.
pub(crate) fn read_env_var(key: &str) -> Result<String, std::env::VarError> {
    if super::scratch_core::is_temp_root_key(key) {
        return Err(std::env::VarError::NotPresent);
    }
    let overlay = ENV_OVERLAY
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match overlay.get(key) {
        Some(Some(v)) => Ok(v.clone()),
        Some(None) => Err(std::env::VarError::NotPresent),
        #[allow(clippy::disallowed_methods)] // the accessor: overlay and temp roots answered first
        None => std::env::var(key),
    }
}

/// Longest prefix of a refused environment value echoed in its refusal.
pub const ENV_VALUE_SHOWN_CHARS: usize = 32;

/// What a present `0` means for one environment ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeroCeiling {
    /// `0` is refused like any other malformed value.
    Refused,
    /// `0` is a legal setting whose meaning the ceiling's consumer documents.
    Accepted,
}

/// One operator-tunable numeric ceiling read from the environment.
///
/// Every `IPE_*` numeric limit parses through [`EnvCeiling::parse`], the one
/// parser: an absent variable yields the default; a present value must be a
/// plain decimal (ASCII digits only) no larger than the ceiling's
/// [`Self::at_most`] bound and the consumer's integer type, and `0` follows the
/// ceiling's [`ZeroCeiling`]. Anything else — empty, signed,
/// padded, suffixed, overflowing, non-Unicode — is an [`EnvCeilingRefusal`], so
/// a typo never widens the ceiling to its default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvCeiling {
    name: &'static str,
    default: u64,
    zero: ZeroCeiling,
    unit: &'static str,
    max: u64,
}

impl EnvCeiling {
    /// A ceiling read from `name`, with its default, zero rule and unit phrase.
    ///
    /// `unit` completes the refusal "`name` must be a …", e.g. `"decimal byte count"`.
    #[must_use]
    pub const fn new(
        name: &'static str,
        default: u64,
        zero: ZeroCeiling,
        unit: &'static str,
    ) -> Self {
        Self {
            name,
            default,
            zero,
            unit,
            max: u64::MAX,
        }
    }

    /// This ceiling with the largest value its consumer can apply without
    /// failing (e.g. a `tokio` semaphore's permit limit); a larger setting is
    /// refused as too large.
    #[must_use]
    pub const fn at_most(self, max: u64) -> Self {
        Self { max, ..self }
    }

    /// The largest accepted value.
    #[must_use]
    pub const fn max_value(self) -> u64 {
        self.max
    }

    /// The environment variable this ceiling reads.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// The value applied while the variable is absent.
    #[must_use]
    pub const fn default_value(self) -> u64 {
        self.default
    }

    /// Parses a raw lookup of this ceiling's variable.
    ///
    /// # Errors
    ///
    /// Returns a refusal naming the variable when the value is present but not a
    /// plain decimal, is a refused `0`, or exceeds [`Self::max_value`].
    pub fn parse(self, raw: Result<String, std::env::VarError>) -> Result<u64, EnvCeilingRefusal> {
        let (shown, defect) = match raw {
            Err(std::env::VarError::NotPresent) => return Ok(self.default),
            Err(std::env::VarError::NotUnicode(os)) => (
                shown_env_value(os.as_encoded_bytes()),
                CeilingDefect::NotDecimal,
            ),
            Ok(v) => {
                let defect = if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                    CeilingDefect::NotDecimal
                } else {
                    match v.parse::<u64>() {
                        Ok(n) => match self.check(n) {
                            Ok(n) => return Ok(n),
                            Err(CeilingDefect::TooLarge) => {
                                return Err(self.refusal_over_bound(shown_env_value(v.as_bytes())));
                            }
                            Err(defect) => defect,
                        },
                        Err(_) => CeilingDefect::TooLarge,
                    }
                };
                (shown_env_value(v.as_bytes()), defect)
            }
        };
        Err(self.refusal(shown, defect))
    }

    /// [`Self::parse`] narrowed to the consumer's integer type `T`.
    ///
    /// # Errors
    ///
    /// Returns the [`Self::parse`] refusal, or a too-large refusal when the
    /// value (the default included) does not fit `T` on this platform.
    pub fn parse_as<T: TryFrom<u64>>(
        self,
        raw: Result<String, std::env::VarError>,
    ) -> Result<T, EnvCeilingRefusal> {
        let n = self.parse(raw)?;
        T::try_from(n).map_err(|_| self.refusal(n.to_string(), CeilingDefect::TooLarge))
    }

    /// The raw lookup of this ceiling's variable in the live environment (overlay first).
    ///
    /// # Errors
    ///
    /// [`std::env::VarError::NotPresent`] while the variable is unset, or
    /// `NotUnicode` for a non-UTF-8 value; [`Self::parse`] judges either.
    pub fn lookup(self) -> Result<String, std::env::VarError> {
        read_env_var(self.name)
    }

    /// Reads and parses this ceiling from the live environment (overlay first).
    ///
    /// # Errors
    ///
    /// Returns the [`Self::parse_as`] refusal for a present, malformed value.
    pub fn read<T: TryFrom<u64>>(self) -> Result<T, EnvCeilingRefusal> {
        self.parse_as(self.lookup())
    }

    /// Checks an in-code setting's value against this ceiling's bound.
    ///
    /// The value is a program literal, not an operator string, so it is never
    /// `NotDecimal`; it must be positive whatever the [`ZeroCeiling`], since an
    /// in-code `0` would be a sentinel for the default.
    ///
    /// # Errors
    ///
    /// A refusal naming `setting` when `value` is not positive or exceeds
    /// [`Self::max_value`].
    pub fn check_setting(
        self,
        setting: &'static str,
        value: i64,
    ) -> Result<u64, EnvCeilingRefusal> {
        let checked = u64::try_from(value)
            .ok()
            .filter(|n| *n > 0)
            .ok_or(CeilingDefect::Zero)
            .and_then(|n| self.check(n));
        checked.map_err(|defect| EnvCeilingRefusal {
            name: self.name,
            unit: self.unit,
            shown: value.to_string(),
            defect,
            source: CeilingSource::InCode {
                setting,
                max: self.max,
            },
        })
    }

    /// The default, checked against this ceiling's zero rule and bound.
    ///
    /// A ceiling whose bound another setting lowers (e.g. a window that must
    /// stay below a lifetime) can leave its own default out of range.
    ///
    /// # Errors
    ///
    /// A refusal naming the variable, to be set within the bound, when the
    /// default lies outside it.
    pub fn check_default(self) -> Result<u64, EnvCeilingRefusal> {
        self.check(self.default)
            .map_err(|defect| EnvCeilingRefusal {
                name: self.name,
                unit: self.unit,
                shown: self.default.to_string(),
                defect,
                source: CeilingSource::Default { max: self.max },
            })
    }

    /// A parsed value under this ceiling's zero rule and bound.
    const fn check(self, n: u64) -> Result<u64, CeilingDefect> {
        if n == 0 && matches!(self.zero, ZeroCeiling::Refused) {
            Err(CeilingDefect::Zero)
        } else if n > self.max {
            Err(CeilingDefect::TooLarge)
        } else {
            Ok(n)
        }
    }

    const fn refusal(self, shown: String, defect: CeilingDefect) -> EnvCeilingRefusal {
        EnvCeilingRefusal {
            name: self.name,
            unit: self.unit,
            shown,
            defect,
            source: CeilingSource::Env,
        }
    }

    /// A refusal of a parsed value above [`Self::max_value`].
    const fn refusal_over_bound(self, shown: String) -> EnvCeilingRefusal {
        EnvCeilingRefusal {
            name: self.name,
            unit: self.unit,
            shown,
            defect: CeilingDefect::TooLarge,
            source: CeilingSource::EnvOverBound { max: self.max },
        }
    }
}

/// One operator-tunable duration read from the environment, in whole seconds.
///
/// A present value is a bare decimal second count or one to three `<n>h`,
/// `<n>m`, `<n>s` segments, each unit at most once and in that order (`90s`,
/// `30m`, `1h30m`), ASCII only and unpadded. It then obeys the bound of
/// [`Self::at_most`] and a positive total, so every refusal is the
/// [`EnvCeilingRefusal`] an [`EnvCeiling`] raises, with the same escaped echo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvDuration {
    ceiling: EnvCeiling,
}

impl EnvDuration {
    /// A duration read from `name`, with its default in seconds and unit phrase.
    ///
    /// `unit` completes the refusal "`name` must be a …", e.g. `"duration"`.
    #[must_use]
    pub const fn new(name: &'static str, default_secs: u64, unit: &'static str) -> Self {
        Self {
            ceiling: EnvCeiling::new(name, default_secs, ZeroCeiling::Refused, unit),
        }
    }

    /// This duration with the largest total, in seconds, its consumer can apply.
    #[must_use]
    pub const fn at_most(self, max_secs: u64) -> Self {
        Self {
            ceiling: self.ceiling.at_most(max_secs),
        }
    }

    /// The environment variable this duration reads.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.ceiling.name()
    }

    /// The largest accepted total, in seconds.
    #[must_use]
    pub const fn max_value(self) -> u64 {
        self.ceiling.max_value()
    }

    /// The seconds applied while the variable is absent.
    #[must_use]
    pub const fn default_value(self) -> u64 {
        self.ceiling.default_value()
    }

    /// Parses a raw lookup of this duration's variable into whole seconds.
    ///
    /// # Errors
    ///
    /// Returns a refusal naming the variable when the value is present but not
    /// in the duration grammar, totals zero, or exceeds [`Self::max_value`].
    pub fn parse(self, raw: Result<String, std::env::VarError>) -> Result<u64, EnvCeilingRefusal> {
        let (shown, defect) = match raw {
            Err(std::env::VarError::NotPresent) => return Ok(self.ceiling.default),
            Err(std::env::VarError::NotUnicode(os)) => (
                shown_env_value(os.as_encoded_bytes()),
                CeilingDefect::NotDecimal,
            ),
            Ok(v) => match duration_secs(&v).map(|n| self.ceiling.check(n)) {
                Ok(Ok(n)) => return Ok(n),
                Ok(Err(CeilingDefect::TooLarge)) => {
                    return Err(self
                        .ceiling
                        .refusal_over_bound(shown_env_value(v.as_bytes())));
                }
                Ok(Err(defect)) | Err(defect) => (shown_env_value(v.as_bytes()), defect),
            },
        };
        Err(self.ceiling.refusal(shown, defect))
    }

    /// The raw lookup of this duration's variable in the live environment (overlay first).
    ///
    /// # Errors
    ///
    /// As [`EnvCeiling::lookup`].
    pub fn lookup(self) -> Result<String, std::env::VarError> {
        self.ceiling.lookup()
    }

    /// Reads and parses this duration from the live environment (overlay first).
    ///
    /// # Errors
    ///
    /// Returns the [`Self::parse`] refusal for a present, malformed value.
    pub fn read(self) -> Result<u64, EnvCeilingRefusal> {
        self.parse(self.lookup())
    }

    /// Checks an in-code setting's second count against this duration's bound.
    ///
    /// # Errors
    ///
    /// As [`EnvCeiling::check_setting`].
    pub fn check_setting(self, setting: &'static str, secs: i64) -> Result<u64, EnvCeilingRefusal> {
        self.ceiling.check_setting(setting, secs)
    }
}

/// The seconds of a bare second count or `h`/`m`/`s` segments.
///
/// Each unit appears at most once, largest first, so the loop runs at most
/// three times.
fn duration_secs(raw: &str) -> Result<u64, CeilingDefect> {
    let (mut digits, mut tail) = split_digits(raw);
    if digits.is_empty() {
        return Err(CeilingDefect::NotDecimal);
    }
    if tail.is_empty() {
        return digits_value(digits);
    }
    let mut total: u64 = 0;
    let mut previous = u64::MAX;
    loop {
        let mut chars = tail.chars();
        let unit: u64 = match chars.next() {
            Some('h') => 3600,
            Some('m') => 60,
            Some('s') => 1,
            _ => return Err(CeilingDefect::NotDecimal),
        };
        if unit >= previous {
            return Err(CeilingDefect::NotDecimal);
        }
        previous = unit;
        total = digits_value(digits)?
            .checked_mul(unit)
            .and_then(|segment| total.checked_add(segment))
            .ok_or(CeilingDefect::TooLarge)?;
        let after = chars.as_str();
        if after.is_empty() {
            return Ok(total);
        }
        (digits, tail) = split_digits(after);
        if digits.is_empty() {
            return Err(CeilingDefect::NotDecimal);
        }
    }
}

/// `text` split after its leading run of ASCII digits.
fn split_digits(text: &str) -> (&str, &str) {
    let run = text.bytes().take_while(u8::is_ascii_digit).count();
    text.split_at_checked(run).unwrap_or(("", text))
}

/// The value of a run of ASCII digits, or too large when it overflows `u64`.
fn digits_value(digits: &str) -> Result<u64, CeilingDefect> {
    digits
        .chars()
        .try_fold(0u64, |acc, c| {
            acc.checked_mul(10)?.checked_add(u64::from(c.to_digit(10)?))
        })
        .ok_or(CeilingDefect::TooLarge)
}

/// Why a present ceiling value was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeilingDefect {
    /// Not a plain run of ASCII digits (empty, signed, padded, suffixed, non-Unicode).
    NotDecimal,
    /// `0` on a ceiling whose [`ZeroCeiling`] refuses it.
    Zero,
    /// Digits only, but larger than the ceiling's bound or the consumer's
    /// integer type holds.
    TooLarge,
}

/// A present-but-malformed environment ceiling, naming the variable.
///
/// The echoed value is truncated to [`ENV_VALUE_SHOWN_CHARS`] and escaped, so
/// the refusal can neither flood nor forge the line it lands on. It reaches an
/// `IpeError` channel as `InvalidInput`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvCeilingRefusal {
    name: &'static str,
    unit: &'static str,
    shown: String,
    defect: CeilingDefect,
    source: CeilingSource,
}

/// Where a refused ceiling value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CeilingSource {
    /// The ceiling's environment variable.
    Env,
    /// The ceiling's environment variable, parsed but above its bound.
    EnvOverBound {
        /// The largest accepted value.
        max: u64,
    },
    /// The unset variable's default, checked by [`EnvCeiling::check_default`].
    Default {
        /// The largest accepted value.
        max: u64,
    },
    /// An in-code setting, checked by [`EnvCeiling::check_setting`].
    InCode {
        /// The setting's Ipê name, e.g. `Web.authMaxLifetime`.
        setting: &'static str,
        /// The largest accepted value.
        max: u64,
    },
}

impl EnvCeilingRefusal {
    /// The ceiling's environment variable, also for an in-code refusal.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The refused in-code setting's name, or `None` for an environment value.
    #[must_use]
    pub const fn setting(&self) -> Option<&'static str> {
        match self.source {
            CeilingSource::Env
            | CeilingSource::EnvOverBound { .. }
            | CeilingSource::Default { .. } => None,
            CeilingSource::InCode { setting, .. } => Some(setting),
        }
    }

    /// Why the value was refused.
    #[must_use]
    pub const fn defect(&self) -> CeilingDefect {
        self.defect
    }
}

impl std::fmt::Display for EnvCeilingRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            name, unit, shown, ..
        } = self;
        match (self.source, self.defect) {
            (CeilingSource::Env, CeilingDefect::NotDecimal) => {
                write!(f, "{name} must be a {unit} (got \"{shown}\")")
            }
            (CeilingSource::Env, CeilingDefect::Zero) => {
                write!(f, "{name} must be a positive {unit} (got \"{shown}\")")
            }
            (CeilingSource::Env, CeilingDefect::TooLarge) => {
                write!(f, "{name} is too large for this platform (got \"{shown}\")")
            }
            (CeilingSource::EnvOverBound { max }, _) => {
                write!(f, "{name} must be at most {max} (got \"{shown}\")")
            }
            (CeilingSource::Default { max }, _) => write!(
                f,
                "{name} is unset and its default {shown} is out of range; set {name} to at most {max}"
            ),
            (
                CeilingSource::InCode { setting, .. },
                CeilingDefect::NotDecimal | CeilingDefect::Zero,
            ) => {
                write!(f, "the `{setting}` setting must be positive (got {shown})")
            }
            (CeilingSource::InCode { setting, max }, CeilingDefect::TooLarge) => {
                write!(
                    f,
                    "the `{setting}` setting must be at most {max} (got {shown})"
                )
            }
        }
    }
}

impl std::error::Error for EnvCeilingRefusal {}

impl From<EnvCeilingRefusal> for String {
    fn from(refusal: EnvCeilingRefusal) -> Self {
        refusal.to_string()
    }
}

impl From<EnvCeilingRefusal> for IpeError {
    fn from(refusal: EnvCeilingRefusal) -> Self {
        Self::invalid_input(refusal.to_string())
    }
}

/// A present environment value outside its variable's grammar, naming the variable.
///
/// The echoed value is truncated and escaped as an [`EnvCeilingRefusal`]'s is,
/// and it reaches an `IpeError` channel as `InvalidInput`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvValueRefusal {
    name: &'static str,
    expected: &'static str,
    shown: String,
}

impl EnvValueRefusal {
    /// A refusal of `raw`, read from `name`, which must be `expected`.
    ///
    /// `expected` completes the refusal "`name` must be …", e.g. `"an IP address"`.
    #[must_use]
    pub fn new(name: &'static str, expected: &'static str, raw: &[u8]) -> Self {
        Self {
            name,
            expected,
            shown: shown_env_value(raw),
        }
    }

    /// The refused variable's name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }
}

impl std::fmt::Display for EnvValueRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            name,
            expected,
            shown,
        } = self;
        write!(f, "{name} must be {expected} (got \"{shown}\")")
    }
}

impl std::error::Error for EnvValueRefusal {}

impl From<EnvValueRefusal> for IpeError {
    fn from(refusal: EnvValueRefusal) -> Self {
        Self::invalid_input(refusal.to_string())
    }
}

/// Renders a refused environment value for its error text without losing or
/// smuggling a byte: valid UTF-8 keeps its printable characters and escapes
/// every other one (`char::escape_debug` — controls, ESC, CR/LF, bidi
/// overrides, `"` and `\`), and each byte that is not UTF-8 shows as `\xNN`.
/// At most [`ENV_VALUE_SHOWN_CHARS`] source characters or bytes are shown.
fn shown_env_value(raw: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let mut budget = ENV_VALUE_SHOWN_CHARS;
    for chunk in raw.utf8_chunks() {
        for c in chunk.valid().chars() {
            let Some(left) = budget.checked_sub(1) else {
                return out;
            };
            budget = left;
            out.extend(c.escape_debug());
        }
        for b in chunk.invalid() {
            let Some(left) = budget.checked_sub(1) else {
                return out;
            };
            budget = left;
            let _ = write!(out, "\\x{b:02X}");
        }
    }
    out
}

/// The invoking user's home directory: the one runtime home reader.
///
/// Reads the shared platform variable [`super::home_core::HOME_VAR`]
/// (`USERPROFILE` on Windows, `HOME` elsewhere), overlay-aware like
/// [`read_env_var`]. Gated to its readers: the console proxy's cached-binary
/// lookup, and off Unix the scratch primitive's profile-containment check.
///
/// # Errors
/// The [`HomeRefusal`](super::home_core::HomeRefusal) the variable earns.
#[cfg(any(all(feature = "web", feature = "http_client"), not(unix)))]
pub(crate) fn home_dir() -> Result<super::home_core::HomeDir, super::home_core::HomeRefusal> {
    home_dir_from_var(read_env_var(super::home_core::HOME_VAR))
}

/// Parse a home read into a `HomeDir`, or the refusal it earns.
///
/// Hands the overlay's result to the shared
/// [`super::home_core::HomeDir::try_parse`] undecoded (an absent variable is
/// `None`, a non-Unicode one keeps its raw value), so that parser owns every
/// decision about what counts as a home directory and which refusal a bad
/// value earns; this function makes none of them itself.
#[cfg(any(all(feature = "web", feature = "http_client"), not(unix)))]
fn home_dir_from_var(
    raw: Result<String, std::env::VarError>,
) -> Result<super::home_core::HomeDir, super::home_core::HomeRefusal> {
    use std::env::VarError;
    use std::ffi::OsString;
    let raw = match raw {
        Ok(text) => Some(OsString::from(text)),
        Err(VarError::NotPresent) => None,
        Err(VarError::NotUnicode(os)) => Some(os),
    };
    super::home_core::HomeDir::try_parse(raw)
}

/// Render a runtime status line (e.g. the HTTP `listening on` banner, or an
/// `[ipe.live]`/`[ipe.console]` session-store/console line) with a 4-space
/// left gutter ONLY when stderr is an interactive terminal; a piped or
/// redirected stderr (test harness, production log capture) stays flush-left so
/// downstream `contains(...)` matchers see the bare line. The `is_terminal`
/// decision is a parameter so the indent rule is testable without a pty.
///
/// Four spaces, not the CLI's plain 2-space `GUTTER`: under `ipe dev watch`, these
/// lines are the spawned app's own output, printed one level deeper than the
/// `[ipe dev watch] ...` status lines that frame it (which themselves render at
/// two gutter-widths) — so this nests under them rather than under the
/// top-level banner.
///
/// Unconditional: every `[ipe.<tag>] ...` runtime log line, in every feature
/// combination, flows through `emit_runtime_log` below, which calls this —
/// so it can never be dead code.
pub(crate) fn gutter_line(msg: &str, is_terminal: bool) -> String {
    if is_terminal {
        format!("    {msg}")
    } else {
        msg.to_string()
    }
}

/// How long every SQLite connection waits on another connection's lock.
///
/// Applied through the connect options, so the driver sets it on each
/// connection it opens and no pooled connection can carry another value. It
/// outlasts a full index rebuild holding the write lock; a writer still
/// waiting past it fails with `SQLITE_BUSY` through its caller's typed error.
///
/// It lives here, not in `db`, because `web::hub` and `telemetry_spill` open
/// SQLite connections in programs whose module set declares no `db`.
#[cfg(feature = "db")]
pub(crate) const SQLITE_BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Format characters that reorder, hide, or break a log line without being control bytes.
///
/// Exactly the Unicode `Cf` (format) category plus the `Zl`/`Zp` line and
/// paragraph separators: the bidirectional controls, the zero-width space,
/// joiners and word joiner, the invisible operators, the byte-order mark, the
/// soft hyphen, the prepended-number and annotation marks, and the whole tag
/// block (so a tag assigned later is already covered). Range for range the
/// compiler's terminal set (`ipe_diagnostics::terminal::DENIED_FORMAT_CHARS`),
/// which the runtime cannot import because it ships as source; a test asserts
/// the two tables equal, and the compiler's table is checked against the UCD.
pub(crate) const LOG_FORMAT_HAZARDS: &[std::ops::RangeInclusive<char>] = &[
    '\u{00AD}'..='\u{00AD}',   // SOFT HYPHEN
    '\u{0600}'..='\u{0605}',   // ARABIC NUMBER SIGN .. NUMBER MARK ABOVE
    '\u{061C}'..='\u{061C}',   // ARABIC LETTER MARK
    '\u{06DD}'..='\u{06DD}',   // ARABIC END OF AYAH
    '\u{070F}'..='\u{070F}',   // SYRIAC ABBREVIATION MARK
    '\u{0890}'..='\u{0891}',   // ARABIC POUND / PIASTRE MARK ABOVE
    '\u{08E2}'..='\u{08E2}',   // ARABIC DISPUTED END OF AYAH
    '\u{180E}'..='\u{180E}',   // MONGOLIAN VOWEL SEPARATOR
    '\u{200B}'..='\u{200F}',   // ZERO WIDTH SPACE, NON-JOINER, JOINER, LRM, RLM
    '\u{2028}'..='\u{2029}',   // LINE / PARAGRAPH SEPARATOR
    '\u{202A}'..='\u{202E}',   // bidi EMBEDDINGs, POP, OVERRIDEs
    '\u{2060}'..='\u{2064}',   // WORD JOINER, invisible operators
    '\u{2066}'..='\u{206F}',   // bidi ISOLATEs, deprecated format controls
    '\u{FEFF}'..='\u{FEFF}',   // ZERO WIDTH NO-BREAK SPACE (BOM)
    '\u{FFF9}'..='\u{FFFB}',   // INTERLINEAR ANNOTATION controls
    '\u{110BD}'..='\u{110BD}', // KAITHI NUMBER SIGN
    '\u{110CD}'..='\u{110CD}', // KAITHI NUMBER SIGN ABOVE
    '\u{13430}'..='\u{1343F}', // EGYPTIAN HIEROGLYPH format controls
    '\u{1BCA0}'..='\u{1BCA3}', // SHORTHAND FORMAT controls
    '\u{1D173}'..='\u{1D17A}', // MUSICAL SYMBOL BEGIN/END controls
    '\u{E0000}'..='\u{E007F}', // TAG block
];

/// Whether `c` must never reach an operator log line or terminal raw.
///
/// The set is Unicode `Cc`, `Cf`, `Zl` and `Zp`, the compiler's terminal set:
/// every control (C0 incl. CR/LF/ESC, DEL, C1 incl. NEL/CSI) plus
/// [`LOG_FORMAT_HAZARDS`]. The predicate behind [`scrub_log_controls`] and
/// the console ingest filter.
pub(crate) fn is_log_hazard(c: char) -> bool {
    if matches!(c, ' '..='~') {
        return false;
    }
    c.is_control() || LOG_FORMAT_HAZARDS.iter().any(|range| range.contains(&c))
}

/// Escape text bound for a plain operator log line, visibly and injectively.
///
/// Every log-hazard character (see [`is_log_hazard`]) becomes an escape (`\n`,
/// `\r`, `\t`, else `\u{XX}`) and `\` itself becomes `\\`, so untrusted input
/// (a driver error, a request path, an env-derived path, a trace value) can
/// neither forge extra records nor inject terminal escape sequences, the
/// escape stays visible rather than silently erased, and two distinct inputs
/// never print alike (the literal text `\u{200b}` prints as `\\u{200b}`, a
/// real U+200B as `\u{200b}`). The single plain-text log scrubber: every
/// plain-text log sink routes untrusted text through it. Its JSON counterpart
/// is `escape::json_str_body` (through `telemetry::json_escape`), which
/// escapes the same hazard set.
pub(crate) fn scrub_log_controls(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.chars().any(|c| c == '\\' || is_log_hazard(c)) {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len().saturating_add(16));
    for c in s.chars() {
        push_scrubbed(c, &mut out);
    }
    std::borrow::Cow::Owned(out)
}

/// The marker [`scrub_log_controls_capped`] appends when it cuts its output.
///
/// The scrub writes `\` only as the start of `\\`, `\n`, `\r`, `\t` or
/// `\u{…}`, so `\…` never occurs in scrubbed text: a cut record cannot pass
/// for an uncut one.
pub(crate) const SCRUB_TRUNCATED: &str = "\\…";

/// [`scrub_log_controls`] for an untrusted record, bounded to `max_bytes`.
///
/// The bound applies to the escaped output, never the input, and to whole
/// escapes only: when the next character's spelling would cross `max_bytes`
/// the output stops there and ends in [`SCRUB_TRUNCATED`]. The result is at
/// most `max_bytes + SCRUB_TRUNCATED.len()` bytes, and an uncut result decodes
/// to its input, so a hazard in a remote request path or an ingested record
/// shows as a visible escape and two distinct inputs never record alike.
#[cfg_attr(
    not(all(feature = "web-core", feature = "server")),
    allow(dead_code) // only the served request log and console ingest call it
)]
pub(crate) fn scrub_log_controls_capped(s: &str, max_bytes: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_bytes));
    for c in s.chars() {
        let before = out.len();
        push_scrubbed(c, &mut out);
        if out.len() > max_bytes {
            out.truncate(before);
            out.push_str(SCRUB_TRUNCATED);
            break;
        }
    }
    out
}

/// Append the scrubbed spelling of one character to `out`.
fn push_scrubbed(c: char, out: &mut String) {
    use std::fmt::Write as _;
    match c {
        '\\' => out.push_str("\\\\"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        c if is_log_hazard(c) => {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        }
        c => out.push(c),
    }
}

/// Write one line to stderr fallibly, dropping the error: `eprintln!` panics
/// when the write fails, and because Rust ignores SIGPIPE a hung-up reader
/// (`app 2>&1 | head`) surfaces as `EPIPE`. The single runtime stderr line
/// sink — `log.rs`, `debug.rs`, the tagged emitter below and every other
/// runtime diagnostic line route through it, so no stderr write can abort. Its
/// stdout sibling is [`write_stdout_line`]; callers are responsible for
/// scrubbing (via [`scrub_log_controls`]) any untrusted text before it reaches
/// either.
pub(crate) fn write_stderr_line(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

/// Write one line to stdout fallibly, dropping the error — the stdout mirror
/// of [`write_stderr_line`], for the identical `println!`-panics-on-`EPIPE`
/// reason. The single runtime stdout line sink: `log.rs` and every other
/// runtime stdout write (server status lines, CLI-op summaries) route through
/// it instead of a raw `println!`/`print!`, so a closed downstream pipe
/// (`ipe-app | head`) can never abort the process;
/// `tests/no_panicking_print_macro.rs` refuses any production print macro.
/// Always compiled, like its stderr sibling, so no feature combination can
/// leave a caller without it; only `log`, `db` and the served `web` surface
/// call it.
#[cfg_attr(
    not(any(
        feature = "log",
        feature = "db",
        all(feature = "web-core", feature = "server")
    )),
    allow(dead_code) // no stdout-writing module in this feature set
)]
pub(crate) fn write_stdout_line(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stdout().lock(), "{line}");
}

/// Build a `"[<stamp> ][ipe.<tag>] <msg>"` line with `msg` scrubbed. Private:
/// the only place the literal `"[ipe."` prefix is constructed; call sites use
/// `emit_runtime_log` / `emit_runtime_log_stamped`.
fn format_runtime_log(stamp: Option<&str>, tag: &str, msg: &str) -> String {
    let msg = scrub_log_controls(msg);
    match stamp {
        Some(stamp) => format!("{stamp} [ipe.{tag}] {msg}"),
        None => format!("[ipe.{tag}] {msg}"),
    }
}

/// The fully rendered (scrubbed, terminal-guttered) form of a tagged runtime
/// log line — exactly what the emitters write.
pub(crate) fn runtime_log_line(stamp: Option<&str>, tag: &str, msg: &str) -> String {
    use std::io::IsTerminal;
    gutter_line(
        &format_runtime_log(stamp, tag, msg),
        std::io::stderr().is_terminal(),
    )
}

/// The single emitter for every `[ipe.<tag>] ...` runtime log line — session
/// stores, live sessions, the console proxy, hub/push exporters, telemetry
/// spill, list/cache/webview warnings, and any future one. Every such site
/// routes through here instead of hand-rolling `eprintln!("[ipe.<tag>] ...")`,
/// so the control-character scrub, `gutter_line`'s human-terminal indent and the
/// broken-pipe-tolerant write apply uniformly with no bypass path. Pinned by the
/// source scan in `runtime_log_emitter_tests` below.
pub(crate) fn emit_runtime_log(tag: &str, msg: &str) {
    write_stderr_line(&runtime_log_line(None, tag, msg));
}

/// `emit_runtime_log` for a line that carries a leading timestamp before its
/// tag (the memory session-store startup line).
#[cfg(all(feature = "web-core", feature = "server"))]
pub(crate) fn emit_runtime_log_stamped(stamp: &str, tag: &str, msg: &str) {
    write_stderr_line(&runtime_log_line(Some(stamp), tag, msg));
}

/// A TCP port an HTTP listener may bind: `1..=65535`.
///
/// `0` (an OS-chosen ephemeral port the caller cannot reach) has no
/// representation, so no env layer can request it.
#[cfg(feature = "server")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ListenPort(std::num::NonZeroU16);

#[cfg(feature = "server")]
impl ListenPort {
    /// Parse an env value: `None` for empty, non-numeric, signed, `0`, or
    /// out-of-range text.
    ///
    /// Only ASCII digits are admitted: `u16`'s `FromStr` alone also accepts a
    /// leading `+`.
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        raw.parse::<u16>()
            .ok()
            .and_then(std::num::NonZeroU16::new)
            .map(Self)
    }

    /// The port as the listener's address integer.
    pub(crate) fn get(self) -> i64 {
        i64::from(self.0.get())
    }
}

/// Which layer chose a listener's port.
#[cfg(feature = "server")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PortOrigin {
    /// A supervisor set [`crate::LISTEN_PORT_RELOCATION_ENV`] on this process.
    Relocated,
    /// The operator set the runtime's documented port var.
    Operator,
    /// Neither env layer held a valid port: the program's own port.
    Source,
}

/// A listener port together with the layer that chose it.
#[cfg(feature = "server")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedPort {
    /// The port to bind.
    pub(crate) port: i64,
    /// The layer the port came from.
    pub(crate) origin: PortOrigin,
    /// The runtime's documented operator port var (`IPE_WEB_PORT` /
    /// `IPE_SERVER_PORT`), named by the bind-failure advice.
    pub(crate) operator_var: &'static str,
}

/// An operator-fixable reason the OS refused a listener bind.
///
/// Classified once from the bind's `io::ErrorKind`; any other kind stays an
/// unclassified I/O failure.
#[cfg(feature = "server")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BindRefusal {
    /// Another process is bound to the port (`AddrInUse`).
    PortInUse,
    /// The OS refused this process the port (`PermissionDenied`).
    PortRefused,
    /// The bind address is not an address of this host (`AddrNotAvailable`).
    AddressNotLocal,
}

#[cfg(feature = "server")]
impl BindRefusal {
    /// The operator-fixable refusal behind `kind`, or `None` for any other kind.
    pub(crate) const fn classify(kind: std::io::ErrorKind) -> Option<Self> {
        match kind {
            std::io::ErrorKind::AddrInUse => Some(Self::PortInUse),
            std::io::ErrorKind::PermissionDenied => Some(Self::PortRefused),
            std::io::ErrorKind::AddrNotAvailable => Some(Self::AddressNotLocal),
            _ => None,
        }
    }
}

/// The relaunch line a fix suggests: `assignment` before the command that
/// starts this program again.
///
/// A dev-loop build is started by `ipe dev run`; a release binary is started
/// directly, so its line names no `ipe` verb.
#[cfg(feature = "server")]
fn relaunch_line(posture: crate::telemetry::BuildPosture, assignment: &str) -> String {
    match posture {
        crate::telemetry::BuildPosture::Development => format!("{assignment} ipe dev run"),
        crate::telemetry::BuildPosture::Release => format!("{assignment} ./<program>"),
    }
}

#[cfg(feature = "server")]
impl ResolvedPort {
    /// The typed refusal for a bind of `addr` that failed with `error`.
    ///
    /// An operator-fixable kind ([`BindRefusal`]) gets its own error kind and a
    /// fix line chosen by how this binary was built; any other kind is an `Io`
    /// error naming `surface` and the address.
    pub(crate) fn bind_refusal(
        &self,
        surface: &str,
        addr: std::net::SocketAddr,
        error: &std::io::Error,
    ) -> IpeError {
        self.bind_refusal_for(
            crate::telemetry::BuildPosture::COMPILED,
            surface,
            addr,
            error,
        )
    }

    /// [`Self::bind_refusal`] under an explicit build `posture`.
    pub(crate) fn bind_refusal_for(
        &self,
        posture: crate::telemetry::BuildPosture,
        surface: &str,
        addr: std::net::SocketAddr,
        error: &std::io::Error,
    ) -> IpeError {
        let Some(refusal) = BindRefusal::classify(error.kind()) else {
            return IpeError::io(format!("{surface}: bind {addr}: {error}"));
        };
        let message = self.refusal_message(posture, refusal, addr.ip());
        match refusal {
            BindRefusal::PortInUse => IpeError::conflict(message),
            BindRefusal::PortRefused => IpeError::permission_denied().with_message(message),
            BindRefusal::AddressNotLocal => IpeError::invalid_input(message),
        }
    }

    /// The text of `refusal`: what failed, then the fix line.
    ///
    /// A port a supervisor chose names the supervisor, never the operator var
    /// the supervisor outranks; any other port advises the operator var.
    fn refusal_message(
        &self,
        posture: crate::telemetry::BuildPosture,
        refusal: BindRefusal,
        host: std::net::IpAddr,
    ) -> String {
        let port = self.port;
        let cause = match refusal {
            BindRefusal::PortInUse => {
                format!("port {port} is already in use — another application is bound to it.")
            }
            BindRefusal::PortRefused if port < 1024 => format!(
                "port {port} was refused to this process — ports below 1024 need elevated privileges."
            ),
            BindRefusal::PortRefused => {
                format!("port {port} was refused to this process by the operating system's policy.")
            }
            BindRefusal::AddressNotLocal => {
                let var = crate::app_config::HTTP_BIND_VAR;
                return format!(
                    "{host} is not an address of this host, so port {port} cannot be bound on it.\n\
                     Set {var} to one of this host's addresses, e.g.:\n\
                     {}",
                    relaunch_line(posture, &format!("{var}=127.0.0.1"))
                );
            }
        };
        let var = self.operator_var;
        match self.origin {
            PortOrigin::Relocated => format!(
                "{cause}\n\
                 The port was chosen by the supervisor (`ipe dev watch` or the dev console); \
                 restart it to pick a free port."
            ),
            PortOrigin::Operator | PortOrigin::Source => format!(
                "{cause}\n\
                 Set a different port with the {var} environment variable, e.g.:\n\
                 {}",
                relaunch_line(posture, &format!("{var}=8123"))
            ),
        }
    }
}

/// Resolve the port an HTTP listener binds, by fixed precedence: the
/// supervisor's `relocation` value, then the operator's value (`operator.1`, of
/// the var named `operator.0`), then the program's `source` port.
///
/// The first layer that parses as a [`ListenPort`] wins; an absent or malformed
/// layer falls through to the next, so no env text can yield `0` or an
/// out-of-range port. Pure over its inputs, so the precedence is unit-testable
/// without touching the process environment. Gated to `server`: both callers
/// (`server::server_listen`, `web::serve_web`) are.
#[cfg(feature = "server")]
pub(crate) fn resolve_listen_port(
    relocation: Option<String>,
    operator: (&'static str, Option<String>),
    source: i64,
) -> ResolvedPort {
    let (operator_var, operator_value) = operator;
    let layer = |raw: Option<String>| raw.as_deref().and_then(ListenPort::parse);
    let (port, origin) = layer(relocation).map_or_else(
        || {
            layer(operator_value).map_or((source, PortOrigin::Source), |p| {
                (p.get(), PortOrigin::Operator)
            })
        },
        |p| (p.get(), PortOrigin::Relocated),
    );
    ResolvedPort {
        port,
        origin,
        operator_var,
    }
}

/// [`resolve_listen_port`] over the live environment (overlay first): the
/// relocation var [`crate::LISTEN_PORT_RELOCATION_ENV`], then `operator`: the
/// operator var's name and the value its caller read under that constant key.
#[cfg(feature = "server")]
pub(crate) fn listen_port_from_env(
    operator: (&'static str, Option<String>),
    source: i64,
) -> ResolvedPort {
    resolve_listen_port(
        read_env_var(crate::LISTEN_PORT_RELOCATION_ENV).ok(),
        operator,
        source,
    )
}

/// Read an environment variable as an `OsString` — the `var_os` companion of
/// `read_env_var` (same overlay-first semantics). `None` when unset (or masked by
/// an overlay tombstone) or — unlike `read_env_var` — when the real value is not
/// valid Unicode. Gated to the feature whose module actually reads `var_os`
/// (`tui` — the `NO_COLOR` probe); widen the gate when another feature gains a
/// `var_os` reader, so it never sits as dead code under `-D warnings`. A
/// temp-root key reads as unset, as in `read_env_var`.
#[cfg(any(feature = "tui", feature = "debugger"))]
pub(crate) fn read_env_var_os(key: &str) -> Option<std::ffi::OsString> {
    if super::scratch_core::is_temp_root_key(key) {
        return None;
    }
    let overlay = ENV_OVERLAY
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match overlay.get(key) {
        Some(Some(v)) => Some(std::ffi::OsString::from(v)),
        Some(None) => None,
        #[allow(clippy::disallowed_methods)] // the accessor: overlay and temp roots answered first
        None => std::env::var_os(key),
    }
}

/// Snapshot the overlay as explicit child-env directives: `(key, Some(val))` sets
/// the var on the child, `(key, None)` removes it (so a tombstone masks an
/// inherited value). Applied by the `Process.*` spawn paths ON TOP of the
/// inherited real environ, so a child observes exactly the env Ipê observes
/// without the parent ever mutating its own `environ`.
pub(crate) fn env_overlay_snapshot() -> Vec<(String, Option<String>)> {
    let overlay = ENV_OVERLAY
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    overlay
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Set an environment variable in the process-local overlay (never the real
/// `environ`). A key/value the overlay would reject (`env_entry_is_valid`) is a
/// silent no-op rather than a panic.
pub(crate) fn locked_set_var(key: &str, val: &str) {
    if !env_entry_is_valid(key, val) {
        return;
    }
    let mut overlay = ENV_OVERLAY
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    overlay.insert(key.to_owned(), Some(val.to_owned()));
}

/// Set an overlay variable ONLY if it is currently absent (in BOTH the overlay
/// and the real environ), performing the presence check and the set atomically
/// under a SINGLE write-lock acquisition — no TOCTOU window a separate read + set
/// would open. Same admission rule as `locked_set_var` — never panics.
pub(crate) fn locked_set_var_if_absent(key: &str, val: &str) {
    if !env_entry_is_valid(key, val) {
        return;
    }
    let mut overlay = ENV_OVERLAY
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let absent = match overlay.get(key) {
        Some(Some(_)) => false,
        Some(None) => true,
        #[allow(clippy::disallowed_methods)] // presence in the real environ, never its value
        None => std::env::var_os(key).is_none(),
    };
    if absent {
        overlay.insert(key.to_owned(), Some(val.to_owned()));
    }
}

/// Remove an environment variable: record a tombstone in the overlay so the key
/// reads as unset even when present in the real environ. An empty/`=`-bearing/NUL
/// key is a no-op (never a valid var to remove).
pub(crate) fn locked_remove_var(key: &str) {
    if key.is_empty() || key.contains('=') || key.contains('\0') {
        return;
    }
    let mut overlay = ENV_OVERLAY
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    overlay.insert(key.to_owned(), None);
}

#[must_use]
pub fn system_args<E: Send + From<IpeError> + 'static>(_: ()) -> IpeTask<E, Vec<String>> {
    Box::pin(async move {
        match decode_args(std::env::args_os()) {
            Ok(args) => ok_res(args),
            Err(e) => IpeResult::Err(e.into()),
        }
    })
}

/// The one UTF-8 decode an OS argument passes through. The refusal names the
/// argument's position only: argv can carry a credential, so its bytes never
/// reach an error message.
fn utf8_arg(arg: std::ffi::OsString, index: usize) -> Result<String, IpeError> {
    arg.into_string().map_err(|_| {
        IpeError::invalid_input(format!("command-line argument {index} is not valid UTF-8"))
    })
}

/// Every argument after the program name, each decoded as UTF-8.
fn decode_args(argv: impl Iterator<Item = std::ffi::OsString>) -> Result<Vec<String>, IpeError> {
    argv.enumerate()
        .skip(1)
        .map(|(index, arg)| utf8_arg(arg, index))
        .collect()
}

/// The argument at `n` of the full vector (index 0 is the program name). A
/// negative `n`, or one past the target's `usize`, is out of range.
fn decode_arg_at(
    mut argv: impl Iterator<Item = std::ffi::OsString>,
    n: i64,
) -> Result<IpeMaybe<String>, IpeError> {
    let Ok(index) = usize::try_from(n) else {
        return Ok(IpeMaybe::Nothing);
    };
    match argv.nth(index) {
        Some(arg) => utf8_arg(arg, index).map(IpeMaybe::Just),
        None => Ok(IpeMaybe::Nothing),
    }
}

// ── shared blocking-pool helper ───────────────────────────────────────
//
// `process_run` calls `std::process::Command::output()`, which BLOCKS the
// calling thread until the child process exits — an arbitrarily long wait
// (the whole point of `Process.run` is running a caller-chosen subprocess).
// On a tokio worker thread that stalls every other task scheduled on it for
// the subprocess's full runtime — reactor starvation, same class as the
// bcrypt/gzip/zstd/file cases. `system` (this module) is UNCONDITIONALLY
// compiled (not gated behind any feature — see the module-level comment
// above `pub mod system;` in `mod.rs`), while `tokio` is an `optional = true`
// dependency, so `tokio` is not guaranteed present here. Same
// `#[cfg(feature = "tokio")]` / fallback split `file.rs` uses for its own
// `run_blocking` helper (real generated Ipê projects always have `tokio` —
// see `docs/adr/0003-security-render-and-data-access-invariants.md`
// §2.2 — so the fallback only matters for this crate's own narrow-feature
// standalone builds).
// The offload is `threads::run_blocking`: a blocking pool that cannot start a
// thread is an `Unavailable` error, and a build without the pool (no `tokio`, or
// wasm32) runs the closure inline.
async fn run_blocking<T, E, F>(f: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
    E: From<String> + crate::FromUnavailable,
{
    crate::threads::run_blocking("Process", "background process task panicked", f).await
}

/// The default combined-output capture ceiling (16 MiB), overridable via
/// `IPE_PROCESS_OUTPUT_MAX` (bytes). A subprocess is a caller-chosen program
/// that may write without bound (or be attacker-influenced); an uncapped
/// `Command::output()` buffers ALL of it in memory and can OOM the host. Reading
/// past the ceiling is an `Err`, never a silent truncation of a returned success
/// value.
const PROCESS_OUTPUT_CEILING: EnvCeiling = EnvCeiling::new(
    "IPE_PROCESS_OUTPUT_MAX",
    16 * 1024 * 1024,
    ZeroCeiling::Refused,
    "decimal byte count",
);

/// Resolves [`PROCESS_OUTPUT_CEILING`]; a malformed setting fails the spawn closed.
fn process_output_ceiling() -> Result<u64, EnvCeilingRefusal> {
    PROCESS_OUTPUT_CEILING.read()
}

/// The task a spawn kernel returns when its output ceiling is malformed.
fn refused_spawn<E: Send + From<String> + 'static, T: Send + 'static>(
    refusal: EnvCeilingRefusal,
) -> IpeTask<E, T> {
    crate::task::task_fail(String::from(refusal).into())
}

/// The captured result of a subprocess: its combined stdout+stderr (bounded)
/// and whether it exited successfully. `status` is the display form of the exit
/// status so the sync helper needs no `std::process` types in its signature.
struct ProcessCapture {
    combined: Vec<u8>,
    success: bool,
    status: String,
}

/// RAII owner of a spawned child: guarantees the child is reaped on EVERY exit
/// path (early `?` return, panic, or normal completion). `std::process::Child`'s
/// `Drop` does NOT kill or reap, so without this a read error or a bail would
/// leak a running, unreaped child (a zombie in a long-lived server). `wait()`
/// takes ownership so the destructor becomes a no-op once the caller has reaped
/// the child itself on the success path.
struct ChildGuard(Option<std::process::Child>);

impl ChildGuard {
    fn get_mut(&mut self) -> Option<&mut std::process::Child> {
        self.0.as_mut()
    }

    /// Reap the child ourselves, taking it out of the guard so `Drop` does
    /// nothing. Returns the exit status.
    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        match self.0.take() {
            Some(mut c) => c.wait(),
            None => Err(std::io::Error::other("child already reaped")),
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            // The child is still owned here => it was NOT reaped on a normal
            // path (an error/bail/panic left it running). Kill then reap so no
            // subprocess is left running and no zombie accumulates.
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Read up to `limit` bytes from `reader` on a dedicated thread. Draining each
/// pipe on its OWN thread avoids the sequential-drain deadlock: a child that
/// fills one pipe's kernel buffer while blocking on the other cannot wedge the
/// capture, because both pipes are drained concurrently. The `take(limit)` bound
/// caps peak per-stream allocation regardless of how much the child writes.
/// `limit` is a per-call value (`cap + 1`) passed by ownership, so concurrent
/// `process_run` calls never share or clobber it.
///
/// # Errors
///
/// The OS refused the thread.
fn spawn_capture_thread<R>(
    reader: Option<R>,
    limit: u64,
) -> std::io::Result<std::thread::JoinHandle<std::io::Result<Vec<u8>>>>
where
    R: std::io::Read + Send + 'static,
{
    crate::threads::spawn_named(CAPTURE_THREAD, move || {
        use std::io::Read as _;
        let mut buf = Vec::new();
        if let Some(reader) = reader {
            reader.take(limit).read_to_end(&mut buf)?;
        }
        Ok::<_, std::io::Error>(buf)
    })
}

/// The name of each subprocess output capture thread.
const CAPTURE_THREAD: &str = "ipe-capture";

/// The name of the pty master reader thread.
#[cfg(unix)]
const PTY_READ_THREAD: &str = "ipe-pty-read";

/// Spawn `cmd args` with NO shell (direct argv), capturing combined
/// stdout+stderr under `cap`. stdout and stderr are drained on SEPARATE threads
/// (no sequential-drain pipe deadlock), each bounded by `take(cap + 1)`; the
/// combined result over `cap` is an `Err`, never an unbounded allocation.
/// `stdin` is closed (`Stdio::null`) so a child reading stdin gets EOF and
/// cannot block the capture. The child is reaped on every exit path via
/// [`ChildGuard`].
/// Apply the process-local env overlay to a child `Command`: overlay sets become
/// `env`, tombstones become `env_remove`. The runtime never mutates its own
/// `environ`, so without this a child would inherit only the real environ and
/// miss every Ipê `System.setenv`/`unsetenv`/`loadEnv`. Applied BEFORE any
/// per-child override so an explicit override still wins.
fn apply_env_overlay(builder: &mut std::process::Command) {
    apply_env_directives(builder, env_overlay_snapshot());
}

/// Apply overlay `directives` to `builder`, then remove the supervisor's
/// listener relocation var ([`crate::LISTEN_PORT_RELOCATION_ENV`]).
///
/// The relocation var addresses this process alone, so a user-spawned child
/// never inherits it, whether it came from the real environ or the overlay.
fn apply_env_directives(
    builder: &mut std::process::Command,
    directives: Vec<(String, Option<String>)>,
) {
    for (k, v) in directives {
        match v {
            Some(val) => {
                builder.env(k, val);
            }
            None => {
                builder.env_remove(k);
            }
        }
    }
    builder.env_remove(crate::LISTEN_PORT_RELOCATION_ENV);
}

/// Env var a supervisor (`ipe dev watch`, the dev console proxy) sets on the child
/// it spawns to place that child's HTTP listener on a port the supervisor chose.
///
/// Internal plumbing, never operator configuration: it outranks the operator
/// port var (`IPE_WEB_PORT` / `IPE_SERVER_PORT`) and the source port, is left
/// out of the documented env registry, and is never inherited by a `Process.*`
/// child (only the program's own explicit per-child env entry sets it there).
/// Ungated, and defined in this module (vendored into every emitted project
/// and re-exported at the runtime root), so the `ipe` CLI, which links the
/// runtime without the `server` feature, and the runtime listeners share ONE
/// wire name.
pub const LISTEN_PORT_RELOCATION_ENV: &str = "IPE_INTERNAL_LISTEN_PORT";

/// Why a hardened spawn was refused.
///
/// Every variant is a refusal: a hardened spawn never degrades to an unhardened
/// one. The variants split on whether a child can exist. `Spawn` and
/// `SpawnPanicked` from `spawn_hardened_tokio` may follow the fork: tokio drops
/// a child it forked but failed to register without killing it, and that child
/// runs until this process exits, when the parent-death floor SIGTERMs it
/// (Linux only; elsewhere nothing bounds it by this process). Every other
/// variant, and every variant from `spawn_hardened`, leaves no child running.
#[derive(Debug)]
pub enum SpawnRefusal {
    /// The process-lifetime spawner thread could not be started.
    SpawnerUnavailable(std::io::ErrorKind),
    /// The spawner thread is gone: its job queue or the reply was disconnected.
    SpawnerGone,
    /// The spawner neither accepted nor answered the request within the ceiling.
    ///
    /// A child the spawner hands back for the abandoned request afterwards is
    /// killed; one tokio forks and then fails to register is the `Spawn` case,
    /// which no requester sees.
    ReplyTimedOut,
    /// The runtime refused the child listener claimed before the fork.
    ///
    /// Nothing was forked.
    #[cfg(all(feature = "web", unix))]
    ProbeRefused(std::io::Error),
    /// Claiming the child listener before the fork panicked.
    ///
    /// Nothing was forked. Tokio panics here when the runtime was built without
    /// `enable_io`. Reachable only where panics unwind: under `panic = "abort"`
    /// (every emitted release build) the panic aborts the process instead.
    #[cfg(all(feature = "web", unix))]
    ProbePanicked,
    /// The spawn panicked on the spawner thread, which caught it and lives on.
    ///
    /// From `spawn_hardened_tokio` the panic may follow the fork (tokio panics
    /// registering a child with a runtime missing a driver), leaving a child
    /// that only the parent-death floor bounds. Reachable only where panics
    /// unwind: under `panic = "abort"` (every emitted release build) the panic
    /// aborts the process, and the floor SIGTERMs any forked child.
    SpawnPanicked,
    /// `spawn_hardened_tokio` was called outside a tokio runtime.
    #[cfg(all(feature = "web", not(target_arch = "wasm32")))]
    NoRuntime,
    /// The spawn failed.
    ///
    /// From `spawn_hardened` nothing is left running: std reaps a child whose
    /// `exec` failed. From `spawn_hardened_tokio` the error may follow the
    /// fork, when tokio fails to register the forked child (a driver shutting
    /// down, a stdio or pidfd registration refused) and drops it unkilled; that
    /// child is bounded only by the parent-death floor.
    Spawn(std::io::Error),
    /// This host does not list the open descriptors a child would inherit.
    ///
    /// The descriptor floor walks the live listing (`/proc/self/fd` on Linux,
    /// `/dev/fd` on FreeBSD and macOS) to mark every inherited descriptor
    /// close-on-exec; without that listing nothing is forked.
    #[cfg(unix)]
    DescriptorTableUnlisted(std::io::Error),
}

impl std::fmt::Display for SpawnRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SpawnerUnavailable(kind) => {
                write!(f, "the process spawner thread could not start ({kind})")
            }
            Self::SpawnerGone => f.write_str("the process spawner thread is gone"),
            Self::ReplyTimedOut => f.write_str("the process spawner did not answer in time"),
            #[cfg(all(feature = "web", unix))]
            Self::ProbeRefused(e) => write!(
                f,
                "the tokio runtime refused a child listener; nothing was spawned ({})",
                e.kind()
            ),
            #[cfg(all(feature = "web", unix))]
            Self::ProbePanicked => f.write_str(
                "the tokio runtime has no IO or signal driver for a child; nothing was spawned",
            ),
            Self::SpawnPanicked => f.write_str("the spawn panicked on the process spawner thread"),
            #[cfg(all(feature = "web", not(target_arch = "wasm32")))]
            Self::NoRuntime => f.write_str("no tokio runtime is active on the spawning thread"),
            Self::Spawn(e) => write!(f, "spawn failed ({})", e.kind()),
            #[cfg(unix)]
            Self::DescriptorTableUnlisted(e) => write!(
                f,
                "this host does not list the open descriptors a child would inherit, so nothing was spawned ({}); {DESCRIPTOR_LISTING_HINT}",
                e.kind()
            ),
        }
    }
}

impl std::error::Error for SpawnRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(e) => Some(e),
            #[cfg(unix)]
            Self::DescriptorTableUnlisted(e) => Some(e),
            #[cfg(all(feature = "web", unix))]
            Self::ProbeRefused(e) => Some(e),
            #[cfg(all(feature = "web", unix))]
            Self::ProbePanicked => None,
            #[cfg(all(feature = "web", not(target_arch = "wasm32")))]
            Self::NoRuntime => None,
            Self::SpawnerUnavailable(_)
            | Self::SpawnerGone
            | Self::ReplyTimedOut
            | Self::SpawnPanicked => None,
        }
    }
}

impl From<SpawnRefusal> for std::io::Error {
    fn from(refusal: SpawnRefusal) -> Self {
        match refusal {
            SpawnRefusal::Spawn(e) => e,
            #[cfg(all(feature = "web", unix))]
            refused @ (SpawnRefusal::ProbeRefused(_) | SpawnRefusal::ProbePanicked) => {
                Self::other(refused)
            }
            #[cfg(all(feature = "web", not(target_arch = "wasm32")))]
            refused @ SpawnRefusal::NoRuntime => Self::other(refused),
            #[cfg(unix)]
            refused @ SpawnRefusal::DescriptorTableUnlisted(_) => Self::other(refused),
            refused @ (SpawnRefusal::SpawnerUnavailable(_)
            | SpawnRefusal::SpawnerGone
            | SpawnRefusal::ReplyTimedOut
            | SpawnRefusal::SpawnPanicked) => Self::other(refused),
        }
    }
}

/// What a host must provide for the descriptor floor, named in its refusal.
#[cfg(any(target_os = "linux", target_os = "android"))]
const DESCRIPTOR_LISTING_HINT: &str = "mount procfs at /proc";
/// What a host must provide for the descriptor floor, named in its refusal.
#[cfg(target_os = "freebsd")]
const DESCRIPTOR_LISTING_HINT: &str = "mount fdescfs with `mount -t fdescfs fdesc /dev/fd`";
/// What a host must provide for the descriptor floor, named in its refusal.
#[cfg(target_os = "macos")]
const DESCRIPTOR_LISTING_HINT: &str = "/dev/fd must be the kernel's descriptor listing";
/// What a host must provide for the descriptor floor, named in its refusal.
#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "macos"
    ))
))]
const DESCRIPTOR_LISTING_HINT: &str = "this platform has no supported descriptor listing";

/// Where the calling process's live descriptor listing is mounted.
#[cfg(any(target_os = "linux", target_os = "android"))]
const DESCRIPTOR_LISTING: &std::ffi::CStr = c"/proc/self/fd";
/// Where the calling process's live descriptor listing is mounted.
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
const DESCRIPTOR_LISTING: &std::ffi::CStr = c"/dev/fd";

/// The lowest descriptor number that is not stdin, stdout or stderr.
#[cfg(unix)]
const FIRST_UNNAMED_FD: std::os::fd::RawFd = 3;

/// Bytes of a descriptor number's listing name: ten digits, the NUL, a spare.
#[cfg(unix)]
const FD_NAME_LEN: usize = 12;

/// Bytes of the stack buffer the Linux listing walk reads entries into.
#[cfg(any(target_os = "linux", target_os = "android"))]
const LISTING_READ_BUF: usize = 1024;

/// Highest descriptor limit the `/dev/fd` probe walks up to; a larger limit refuses.
#[cfg(all(unix, any(target_os = "freebsd", target_os = "macos", test)))]
const DESCRIPTOR_PROBE_CEILING: u64 = 1 << 20;

/// The most descriptors one hardened child can be handed by name.
#[cfg(unix)]
pub const NAMED_FD_CAP: usize = 4;

/// Why a descriptor was refused a place in a [`NamedFds`] set.
#[cfg(unix)]
#[derive(Debug)]
pub enum NamedFdRefusal {
    /// The set already holds [`NAMED_FD_CAP`] descriptors.
    Full,
    /// The descriptor is stdin, stdout or stderr.
    ///
    /// std places the child's stdio over 0–2 before the floor runs, so a
    /// named descriptor there would be replaced, never inherited.
    Stdio,
    /// The descriptor is inheritable in this process.
    ///
    /// A named descriptor stays close-on-exec in the parent from birth to
    /// close, so no sibling forked concurrently can inherit it.
    Inheritable,
    /// The descriptor's flags could not be read.
    FlagsUnreadable(std::io::Error),
}

#[cfg(unix)]
impl std::fmt::Display for NamedFdRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => write!(
                f,
                "a child can be handed at most {NAMED_FD_CAP} descriptors"
            ),
            Self::Stdio => f.write_str("a stdio descriptor cannot be handed to a child by name"),
            Self::Inheritable => {
                f.write_str("a descriptor handed to a child must be close-on-exec in the parent")
            }
            Self::FlagsUnreadable(e) => {
                write!(f, "the descriptor's flags could not be read ({})", e.kind())
            }
        }
    }
}

#[cfg(unix)]
impl std::error::Error for NamedFdRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::FlagsUnreadable(e) => Some(e),
            Self::Full | Self::Stdio | Self::Inheritable => None,
        }
    }
}

/// The descriptors one hardened child inherits besides stdio.
///
/// Every member is close-on-exec in this process for its whole life. Only the
/// child clears that flag, in its own descriptor table after the fork, so a
/// sibling forked concurrently never inherits it. The capacity is fixed so the
/// child walks the set without allocating. The set moves into the spawn, and
/// this process's copies close when the spawn returns.
#[cfg(unix)]
#[derive(Debug, Default)]
pub struct NamedFds {
    slots: [Option<std::os::fd::OwnedFd>; NAMED_FD_CAP],
}

#[cfg(unix)]
impl NamedFds {
    /// The empty set: the child inherits only stdio.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            slots: [const { None }; NAMED_FD_CAP],
        }
    }

    /// Add `fd` to the set.
    ///
    /// # Errors
    ///
    /// The refusal, with `fd` handed back unclosed, when `fd` is a stdio
    /// number, is inheritable in this process, has unreadable flags, or the set
    /// is full.
    pub fn push(
        &mut self,
        fd: std::os::fd::OwnedFd,
    ) -> Result<(), (NamedFdRefusal, std::os::fd::OwnedFd)> {
        use std::os::fd::AsRawFd as _;
        let flags = match rustix::io::fcntl_getfd(&fd) {
            Ok(flags) => flags,
            Err(e) => return Err((NamedFdRefusal::FlagsUnreadable(e.into()), fd)),
        };
        if let Err(refusal) = admit_named(fd.as_raw_fd(), flags) {
            return Err((refusal, fd));
        }
        match self.slots.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some(fd);
                Ok(())
            }
            None => Err((NamedFdRefusal::Full, fd)),
        }
    }

    /// Make every member inheritable and rewind it, in the forked child.
    ///
    /// Allocation-free: it only issues `fcntl` and `lseek`. A member that
    /// cannot seek (a pipe or socket, `ESPIPE`) is handed over as it is.
    fn reopen_in_child(&self) -> rustix::io::Result<()> {
        for fd in self.slots.iter().flatten() {
            rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::empty())?;
            match rustix::fs::seek(fd, rustix::fs::SeekFrom::Start(0)) {
                Ok(_) | Err(rustix::io::Errno::SPIPE) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Admit descriptor number `raw` with descriptor flags `flags` into a named set.
#[cfg(unix)]
fn admit_named(raw: std::os::fd::RawFd, flags: rustix::io::FdFlags) -> Result<(), NamedFdRefusal> {
    if raw < FIRST_UNNAMED_FD {
        Err(NamedFdRefusal::Stdio)
    } else if flags.contains(rustix::io::FdFlags::CLOEXEC) {
        Ok(())
    } else {
        Err(NamedFdRefusal::Inheritable)
    }
}

/// The set a spawn hands its child: [`NamedFds`] on Unix, nothing elsewhere.
#[cfg(unix)]
type NamedSet = NamedFds;
/// The set a spawn hands its child: [`NamedFds`] on Unix, nothing elsewhere.
#[cfg(not(unix))]
type NamedSet = ();

/// Write `n`'s listing name (its decimal digits) into `buf`.
///
/// Allocation-free, for the forked child. `None` for a negative `n`.
#[cfg(unix)]
fn fd_name(n: std::os::fd::RawFd, buf: &mut [u8; FD_NAME_LEN]) -> Option<&std::ffi::CStr> {
    const DIGITS: &[u8; 10] = b"0123456789";
    let mut rest = u32::try_from(n).ok()?;
    let mut reversed = [0_u8; FD_NAME_LEN];
    let mut len = 0_usize;
    loop {
        let digit = DIGITS.get(usize::try_from(rest % 10).ok()?)?;
        *reversed.get_mut(len)? = *digit;
        len += 1;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    for (slot, digit) in buf.iter_mut().zip(reversed.get(..len)?.iter().rev()) {
        *slot = *digit;
    }
    *buf.get_mut(len)? = 0;
    std::ffi::CStr::from_bytes_with_nul(buf.get(..=len)?).ok()
}

/// The descriptor number a Linux listing entry names, or `None` for any other name.
#[cfg(all(unix, any(target_os = "linux", target_os = "android", test)))]
fn parse_fd_number(name: &[u8]) -> Option<std::os::fd::RawFd> {
    if name.is_empty() {
        return None;
    }
    name.iter()
        .try_fold(0, |number: std::os::fd::RawFd, &byte| {
            let digit = match byte {
                b'0'..=b'9' => std::os::fd::RawFd::from(byte - b'0'),
                _ => return None,
            };
            number.checked_mul(10)?.checked_add(digit)
        })
}

/// Whether descriptor `n` appears in `listing`, the open descriptor listing.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "macos"
))]
fn fd_listed(listing: &std::os::fd::OwnedFd, n: std::os::fd::RawFd) -> rustix::io::Result<bool> {
    let mut buf = [0_u8; FD_NAME_LEN];
    let name = fd_name(n, &mut buf).ok_or(rustix::io::Errno::INVAL)?;
    match rustix::fs::statat(listing, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT | rustix::io::Errno::BADF) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Open the directory at `at` as this process's live descriptor listing.
///
/// The listing is held at a number `>= 3` and must list that number itself,
/// so a directory that is not the live table (FreeBSD's static `/dev/fd`
/// without fdescfs, a `/proc` without procfs) is refused (`ENOENT`), never
/// walked as if it were complete.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "macos"
))]
fn open_descriptor_listing_at(at: &std::ffi::CStr) -> rustix::io::Result<std::os::fd::OwnedFd> {
    use rustix::fs::{Mode, OFlags};
    use std::os::fd::AsRawFd as _;
    let opened = rustix::fs::open(
        at,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let listing = rustix::io::fcntl_dupfd_cloexec(&opened, FIRST_UNNAMED_FD)?;
    drop(opened);
    if fd_listed(&listing, listing.as_raw_fd())? {
        Ok(listing)
    } else {
        Err(rustix::io::Errno::NOENT)
    }
}

/// Open this process's live descriptor listing.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "macos"
))]
fn open_descriptor_listing() -> rustix::io::Result<std::os::fd::OwnedFd> {
    open_descriptor_listing_at(DESCRIPTOR_LISTING)
}

/// Open this process's live descriptor listing: unsupported here (`ENOSYS`).
#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "macos"
    ))
))]
const fn open_descriptor_listing() -> rustix::io::Result<std::os::fd::OwnedFd> {
    Err(rustix::io::Errno::NOSYS)
}

/// Call `mark` on every open descriptor `>= 3` that `listing` names, except `listing` itself.
///
/// Walks the `/proc/self/fd` entries with `getdents64` into a stack buffer:
/// allocation-free, lock-free, async-signal-safe. An entry that is not a
/// descriptor number refuses (`EINVAL`).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn for_each_inherited_fd(
    listing: &std::os::fd::OwnedFd,
    mut mark: impl FnMut(std::os::fd::RawFd) -> rustix::io::Result<()>,
) -> rustix::io::Result<()> {
    use std::os::fd::AsRawFd as _;
    let own = listing.as_raw_fd();
    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); LISTING_READ_BUF];
    let mut entries = rustix::fs::RawDir::new(listing, &mut buf);
    while let Some(entry) = entries.next() {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let n = parse_fd_number(name).ok_or(rustix::io::Errno::INVAL)?;
        if n >= FIRST_UNNAMED_FD && n != own {
            mark(n)?;
        }
    }
    Ok(())
}

/// Call `mark` on every open descriptor `>= 3` that `listing` names, except `listing` itself.
///
/// Probes `/dev/fd/<n>` with `fstatat` for every number below the descriptor
/// limit: allocation-free, lock-free, async-signal-safe (no `readdir`, which
/// allocates). A limit past [`DESCRIPTOR_PROBE_CEILING`] refuses (`EMFILE`).
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
fn for_each_inherited_fd(
    listing: &std::os::fd::OwnedFd,
    mut mark: impl FnMut(std::os::fd::RawFd) -> rustix::io::Result<()>,
) -> rustix::io::Result<()> {
    use std::os::fd::AsRawFd as _;
    let own = listing.as_raw_fd();
    let limit = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    let bound =
        descriptor_probe_bound(limit.current, limit.maximum).ok_or(rustix::io::Errno::MFILE)?;
    for n in FIRST_UNNAMED_FD..bound {
        if n != own && fd_listed(listing, n)? {
            mark(n)?;
        }
    }
    Ok(())
}

/// Call `mark` on every inherited descriptor: unsupported here (`ENOSYS`).
#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "macos"
    ))
))]
fn for_each_inherited_fd(
    _listing: &std::os::fd::OwnedFd,
    _mark: impl FnMut(std::os::fd::RawFd) -> rustix::io::Result<()>,
) -> rustix::io::Result<()> {
    Err(rustix::io::Errno::NOSYS)
}

/// The exclusive descriptor number the `/dev/fd` probe walks up to.
///
/// The hard limit when it is finite and within [`DESCRIPTOR_PROBE_CEILING`]
/// (it also bounds a descriptor opened before the soft limit was lowered),
/// else the soft limit under the same ceiling, else `None` (refuse).
#[cfg(all(unix, any(target_os = "freebsd", target_os = "macos", test)))]
fn descriptor_probe_bound(
    current: Option<u64>,
    maximum: Option<u64>,
) -> Option<std::os::fd::RawFd> {
    let within = |limit: Option<u64>| limit.filter(|&l| l <= DESCRIPTOR_PROBE_CEILING);
    within(maximum)
        .or_else(|| within(current))
        .and_then(|l| std::os::fd::RawFd::try_from(l).ok())
}

/// Longest a hardened spawn waits for the spawner to accept and answer it.
const SPAWN_REPLY_CEILING: std::time::Duration = std::time::Duration::from_secs(30);

/// Most spawn requests queued on the spawner at once; a full queue is retried
/// until `SPAWN_REPLY_CEILING`, never grown.
const SPAWN_QUEUE_BOUND: usize = 16;

/// Pause between attempts to enqueue on a full spawner queue.
const SPAWN_QUEUE_RETRY: std::time::Duration = std::time::Duration::from_millis(1);

/// One spawn request, run on the spawner thread.
type SpawnJob = Box<dyn FnOnce() + Send + 'static>;

/// The spawner's job queue, or why its thread could not start.
type SpawnerSlot = Result<std::sync::mpsc::SyncSender<SpawnJob>, std::io::ErrorKind>;

/// The process-lifetime spawner thread's job queue.
///
/// The sender lives in a `static`, so the queue never disconnects and the
/// thread's `recv` loop never ends: the thread lives as long as the process.
/// `PR_SET_PDEATHSIG` fires when the FORKING THREAD exits, so forking only here
/// makes the signal mean "the process died", never "some worker thread was
/// reaped".
///
/// Jobs run one at a time, so a spawn stuck in the kernel (an `exec` in
/// uninterruptible sleep) delays every later request. The delay is bounded: a
/// queued requester gives up at `SPAWN_REPLY_CEILING` with `ReplyTimedOut`, and
/// the child forked for it afterwards is reclaimed, never handed out unhardened.
fn spawner() -> Result<&'static std::sync::mpsc::SyncSender<SpawnJob>, SpawnRefusal> {
    static SPAWNER: std::sync::OnceLock<SpawnerSlot> = std::sync::OnceLock::new();
    SPAWNER
        .get_or_init(|| {
            let (jobs, queue) = std::sync::mpsc::sync_channel::<SpawnJob>(SPAWN_QUEUE_BOUND);
            std::thread::Builder::new()
                .name("ipe-spawner".to_owned())
                .spawn(move || run_spawn_jobs(&queue))
                .map(|_| jobs)
                .map_err(|e| e.kind())
        })
        .as_ref()
        .map_err(|kind| SpawnRefusal::SpawnerUnavailable(*kind))
}

/// Run every job `queue` yields, until it disconnects.
///
/// A panicking job is contained so the spawner outlives it. A job's spawn
/// panic is answered inside the job as `SpawnPanicked`; this containment is
/// the backstop for a panic anywhere else in a job.
fn run_spawn_jobs(queue: &std::sync::mpsc::Receiver<SpawnJob>) {
    while let Ok(job) = queue.recv() {
        let _unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
    }
}

/// Run `spawn` on the spawner behind `jobs` and hand its child back.
///
/// A child whose requester is no longer waiting is passed to `discard` on the
/// spawner thread, so a child `spawn` hands back to an abandoned request never
/// stays running. A panic out of `spawn` is caught on the spawner thread and
/// answered as `SpawnPanicked`.
fn request_spawn<T: Send + 'static>(
    jobs: &std::sync::mpsc::SyncSender<SpawnJob>,
    ceiling: std::time::Duration,
    spawn: impl FnOnce() -> Result<T, SpawnRefusal> + Send + 'static,
    discard: fn(T),
) -> Result<T, SpawnRefusal> {
    use std::sync::mpsc::{RecvTimeoutError, SendError, TrySendError};

    let start = std::time::Instant::now();
    // Capacity 0 makes the reply a rendezvous: a child is handed over only to a
    // requester still inside `recv_timeout`. A buffered slot would accept a
    // child sent just after the requester timed out, and dropping the receiver
    // would then drop that child unkilled; with no slot the late `send` fails
    // and `discard` reclaims the child on the spawner thread.
    let (reply, answer) = std::sync::mpsc::sync_channel::<Result<T, SpawnRefusal>>(0);
    let mut job: SpawnJob = Box::new(move || {
        let spawned = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(spawn)) {
            Ok(spawned) => spawned,
            Err(_payload) => Err(SpawnRefusal::SpawnPanicked),
        };
        if let Err(SendError(Ok(child))) = reply.send(spawned) {
            discard(child);
        }
    });
    loop {
        match jobs.try_send(job) {
            Ok(()) => break,
            Err(TrySendError::Disconnected(_)) => return Err(SpawnRefusal::SpawnerGone),
            Err(TrySendError::Full(back)) => {
                if start.elapsed() >= ceiling {
                    return Err(SpawnRefusal::ReplyTimedOut);
                }
                job = back;
                std::thread::sleep(SPAWN_QUEUE_RETRY);
            }
        }
    }
    match answer.recv_timeout(ceiling.saturating_sub(start.elapsed())) {
        Ok(spawned) => spawned,
        Err(RecvTimeoutError::Timeout) => Err(SpawnRefusal::ReplyTimedOut),
        Err(RecvTimeoutError::Disconnected) => Err(SpawnRefusal::SpawnerGone),
    }
}

/// Spawn `cmd` with the hardened-child floor, forked by the spawner thread.
///
/// The child inherits stdio and no other descriptor of this process (the
/// descriptor floor; [`spawn_hardened_naming`] hands it more by name). On
/// Linux it is also SIGTERMed when this process dies by ANY means, and never
/// earlier: the forking thread is the process-lifetime spawner, not the
/// caller's (possibly short-lived) thread.
///
/// # Thread attributes
///
/// The child inherits the per-thread kernel attributes of the spawner thread,
/// not of the requesting thread: its seccomp filter, Landlock domain,
/// `no_new_privs` bit, CPU affinity and namespaces. A restriction a caller
/// applies only to its own thread does not reach the child.
///
/// # Errors
///
/// A `SpawnRefusal` when the spawner is unavailable, gone, or silent past
/// `SPAWN_REPLY_CEILING`, when this host does not list its open descriptors
/// (`DescriptorTableUnlisted`), or when the spawn itself fails. No refusal
/// leaves a child running, and none ever falls back to an unhardened spawn.
pub fn spawn_hardened(cmd: std::process::Command) -> Result<std::process::Child, SpawnRefusal> {
    spawn_hardened_on(spawner()?, SPAWN_REPLY_CEILING, cmd, NamedSet::default())
}

/// [`spawn_hardened`], also handing the child every descriptor in `named`.
///
/// Each named descriptor keeps its number in the child, is inheritable there,
/// and is rewound to offset 0 when it can seek. This process's copies close
/// when the spawn returns.
///
/// # Errors
///
/// The refusals of [`spawn_hardened`].
#[cfg(unix)]
pub fn spawn_hardened_naming(
    cmd: std::process::Command,
    named: NamedFds,
) -> Result<std::process::Child, SpawnRefusal> {
    spawn_hardened_on(spawner()?, SPAWN_REPLY_CEILING, cmd, named)
}

/// `spawn_hardened_naming` against an explicit spawner queue and reply ceiling.
fn spawn_hardened_on(
    jobs: &std::sync::mpsc::SyncSender<SpawnJob>,
    ceiling: std::time::Duration,
    mut cmd: std::process::Command,
    named: NamedSet,
) -> Result<std::process::Child, SpawnRefusal> {
    request_spawn(
        jobs,
        ceiling,
        move || {
            harden_spawned_child(&mut cmd, named)?;
            cmd.spawn().map_err(SpawnRefusal::Spawn)
        },
        |mut child: std::process::Child| {
            let _ = child.kill();
            let _ = child.wait();
        },
    )
}

/// Spawn a tokio `cmd` with the hardened-child floor, forked by the spawner thread.
///
/// The child inherits stdio and no other descriptor of this process. It is
/// registered with the caller's tokio runtime (the spawner enters the caller's
/// runtime handle to spawn it), so it is awaited like any tokio child, and the
/// caller's `kill_on_drop` still applies. A child abandoned by a timed-out
/// requester is killed; tokio's orphan queue reaps it when the runtime next
/// handles `SIGCHLD`.
///
/// Registering a child needs the runtime's IO and signal drivers, and tokio
/// panics when they are absent. On Unix the spawner claims a `SIGCHLD`
/// listener before it forks, so a runtime built without `enable_io` is refused
/// as `ProbePanicked`, and a refused listener as `ProbeRefused`, with no child
/// forked.
///
/// # Errors
///
/// `SpawnRefusal::NoRuntime` when called outside a tokio runtime, the probe
/// refusals above, otherwise the refusals of `spawn_hardened`. A `Spawn` or
/// `SpawnPanicked` refusal here may follow the fork and leave a child that only
/// the parent-death floor bounds (see [`SpawnRefusal`]). No refusal ever falls
/// back to an unhardened spawn.
#[cfg(all(feature = "web", not(target_arch = "wasm32")))]
pub fn spawn_hardened_tokio(
    mut cmd: tokio::process::Command,
) -> Result<tokio::process::Child, SpawnRefusal> {
    let handle = tokio::runtime::Handle::try_current().map_err(|_| SpawnRefusal::NoRuntime)?;
    request_spawn(
        spawner()?,
        SPAWN_REPLY_CEILING,
        move || {
            let _runtime = handle.enter();
            #[cfg(unix)]
            let _drivers = probe_child_listener()?;
            harden_spawned_child(cmd.as_std_mut(), NamedSet::default())?;
            cmd.spawn().map_err(SpawnRefusal::Spawn)
        },
        |mut child: tokio::process::Child| {
            let _ = child.start_kill();
        },
    )
}

/// Replace this process with `cmd` under the descriptor floor.
///
/// The new program inherits stdio and the descriptors in `named`, and no other
/// descriptor of this process. Returns only when the replacement did not
/// happen, with why.
#[cfg(unix)]
#[must_use]
pub fn exec_naming(mut cmd: std::process::Command, named: NamedFds) -> std::io::Error {
    use std::os::unix::process::CommandExt as _;
    match harden_child_parent_death(&mut cmd, ChildFloor::ProcessReplacement, named) {
        Ok(()) => cmd.exec(),
        Err(refused) => refused.into(),
    }
}

/// Claim a `SIGCHLD` listener on the entered runtime before any fork.
///
/// Tokio panics claiming it on a runtime without its IO or signal driver; the
/// panic is caught here so it surfaces as `ProbePanicked`, distinct from a
/// panic after the fork.
#[cfg(all(feature = "web", unix))]
fn probe_child_listener() -> Result<tokio::signal::unix::Signal, SpawnRefusal> {
    use tokio::signal::unix::{SignalKind, signal};
    match std::panic::catch_unwind(|| signal(SignalKind::child())) {
        Ok(Ok(listener)) => Ok(listener),
        Ok(Err(e)) => Err(SpawnRefusal::ProbeRefused(e)),
        Err(_payload) => Err(SpawnRefusal::ProbePanicked),
    }
}

/// Which process the hardened floor runs in.
#[cfg(unix)]
#[derive(Clone, Copy)]
enum ChildFloor {
    /// A child forked by the spawner thread: it also gets the parent-death floor.
    SpawnedChild,
    /// This process, about to replace itself through `exec`.
    ProcessReplacement,
}

/// Give a spawner-forked child the hardened floor, handing it `named`.
#[cfg(unix)]
fn harden_spawned_child(
    builder: &mut std::process::Command,
    named: NamedSet,
) -> Result<(), SpawnRefusal> {
    harden_child_parent_death(builder, ChildFloor::SpawnedChild, named)
}

/// Give a spawner-forked child the hardened floor: none exists off Unix.
#[cfg(not(unix))]
fn harden_spawned_child(
    _builder: &mut std::process::Command,
    _named: NamedSet,
) -> Result<(), SpawnRefusal> {
    Ok(())
}

/// The pid a spawned child must stay parented by: this process, on Linux.
#[cfg(target_os = "linux")]
fn parent_death_launcher() -> Option<rustix::process::Pid> {
    Some(rustix::process::getpid())
}

/// The pid a spawned child must stay parented by: unchecked off Linux.
#[cfg(all(unix, not(target_os = "linux")))]
const fn parent_death_launcher() -> Option<rustix::process::Pid> {
    None
}

/// Arm the parent-death signal in the forked child, then confirm its parent.
///
/// A failed `prctl` is non-fatal (best-effort hardening); a child already
/// reparented away from `launcher` is refused (`ESRCH`).
#[cfg(target_os = "linux")]
fn arm_parent_death(launcher: Option<rustix::process::Pid>) -> std::io::Result<()> {
    let Some(launcher) = launcher else {
        return Ok(());
    };
    let _ = rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::TERM));
    still_parented_by(launcher, rustix::process::getppid())
}

/// Arm the parent-death signal: no such signal exists off Linux.
#[cfg(all(unix, not(target_os = "linux")))]
const fn arm_parent_death(_launcher: Option<rustix::process::Pid>) -> std::io::Result<()> {
    Ok(())
}

/// Give a child the hardened floor: the descriptor floor, plus the
/// parent-death floor for a spawned child.
///
/// **Descriptor floor.** Before anything forks, this process must open its live
/// descriptor listing (`/proc/self/fd` on Linux, `/dev/fd` on FreeBSD and
/// macOS) or the spawn is refused as `DescriptorTableUnlisted`. In the child,
/// after std has placed stdio over 0–2, the hook re-opens that listing and
/// marks every descriptor `>= 3` close-on-exec in the child's own table, then
/// makes each `named` descriptor inheritable and rewinds it. So the new program
/// holds stdio and `named` only, whatever this process's other threads left
/// inheritable. A child that cannot list its table refuses to exec.
///
/// **Parent-death floor (Linux, spawned child).** If the parent process dies by
/// ANY means (SIGKILL, OOM, panic-abort — the paths a signal handler or `Drop`
/// can never run on) the kernel delivers SIGTERM to the child, so it can never
/// outlive the parent as an orphan holding a port or other resource. A parent
/// that dies after the fork but before the child armed the signal leaves the
/// child already reparented, so the signal would never fire; the child
/// therefore compares its parent pid, AFTER arming, with the launcher pid
/// captured before the spawn, and refuses to exec (`ESRCH`) on a mismatch.
///
/// THE single sanctioned `pre_exec` and `PR_SET_PDEATHSIG` site in the whole
/// workspace (see `PRINCIPLES.md` / `AGENTS.md`). Private: a spawned child is
/// hardened only inside a spawn job on the process-lifetime spawner thread
/// (`spawn_hardened`, `spawn_hardened_naming`, `spawn_hardened_tokio`), because
/// the kernel fires the signal when the thread that FORKED the child exits,
/// and only that thread lives as long as the process; a replacement is
/// hardened by `exec_naming`.
#[cfg(unix)]
fn harden_child_parent_death(
    builder: &mut std::process::Command,
    floor: ChildFloor,
    named: NamedFds,
) -> Result<(), SpawnRefusal> {
    use std::os::unix::process::CommandExt as _;
    drop(open_descriptor_listing().map_err(|e| SpawnRefusal::DescriptorTableUnlisted(e.into()))?);
    let launcher = match floor {
        ChildFloor::SpawnedChild => parent_death_launcher(),
        ChildFloor::ProcessReplacement => None,
    };
    // SAFETY: for a spawned child the closure runs in the forked,
    // single-threaded child between fork and exec. It issues only
    // async-signal-safe syscalls through rustix's safe wrappers (`prctl`,
    // `getppid`, `open`, `fcntl`, `getdents64`/`fstatat`, `getrlimit`, `lseek`,
    // `close`), reads the listing into a stack buffer, and builds its errors
    // from raw errnos: no allocation, no locks, no Rust runtime re-entry. It
    // closes nothing but the listing descriptor it opened itself. Each number
    // passed to `BorrowedFd::borrow_raw` was just listed as open in this
    // process's own table and the borrow lives for one `fcntl`; a number
    // closed in between makes that `fcntl` fail with `EBADF`, never touch
    // another object. For a process replacement other threads still run, so
    // the worst case is close-on-exec set on a number they reopened, which
    // only drops it from the replacement.
    // IPE-RUST-AUDIT:ACCEPTED — std `pre_exec` is an unsafe API with no safe
    // parent-death-signal or descriptor-floor equivalent, and the listed
    // numbers are raw; the workspace's sole non-FFI `unsafe`.
    #[allow(unsafe_code)]
    unsafe {
        builder.pre_exec(move || {
            arm_parent_death(launcher)?;
            let listing = open_descriptor_listing()?;
            for_each_inherited_fd(&listing, |n| {
                rustix::io::fcntl_setfd(
                    std::os::fd::BorrowedFd::borrow_raw(n),
                    rustix::io::FdFlags::CLOEXEC,
                )
            })?;
            drop(listing);
            named.reopen_in_child()?;
            Ok(())
        });
    }
    Ok(())
}

/// Refuse (`ESRCH`) unless the child's current `parent` is still `launcher`.
///
/// Runs in the forked child, so it only compares and builds an error from a
/// raw errno: no allocation.
#[cfg(target_os = "linux")]
fn still_parented_by(
    launcher: rustix::process::Pid,
    parent: Option<rustix::process::Pid>,
) -> std::io::Result<()> {
    if parent == Some(launcher) {
        Ok(())
    } else {
        Err(rustix::io::Errno::SRCH.into())
    }
}

fn process_run_sync(cmd: &str, args: &[String], cap: u64) -> Result<ProcessCapture, String> {
    use std::process::{Command, Stdio};

    let mut builder = Command::new(cmd);
    builder
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    apply_env_overlay(&mut builder);
    let child = builder.spawn().map_err(|e| format!("{cmd}: {e}"))?;
    let mut guard = ChildGuard(Some(child));

    // Per-stream read bound; passed by value to each capture thread (no shared
    // global, so concurrent `process_run` calls cannot clobber one another).
    let limit = cap.saturating_add(1);

    // Take the pipe handles so each thread owns its reader; a `?` before the
    // joins still reaps the child via `guard`'s `Drop`.
    let (stdout, stderr) = {
        let c = guard
            .get_mut()
            .ok_or_else(|| format!("{cmd}: child unexpectedly reaped"))?;
        (c.stdout.take(), c.stderr.take())
    };
    // A refused capture thread returns through `?`; `guard` kills and reaps the
    // child, which ends any capture already started.
    let out_handle = spawn_capture_thread(stdout, limit)
        .map_err(|e| format!("{cmd}: stdout capture thread refused: {e}"))?;
    let err_handle = spawn_capture_thread(stderr, limit)
        .map_err(|e| format!("{cmd}: stderr capture thread refused: {e}"))?;

    // A thread panic (e.g. OOM in the reader) surfaces as an `Err`, never a
    // propagated panic; `guard` still reaps the child on the `?` return.
    let mut combined = out_handle
        .join()
        .map_err(|_| format!("{cmd}: stdout capture thread panicked"))?
        .map_err(|e| format!("{cmd}: {e}"))?;
    let stderr_bytes = err_handle
        .join()
        .map_err(|_| format!("{cmd}: stderr capture thread panicked"))?
        .map_err(|e| format!("{cmd}: {e}"))?;
    // Combined = stdout then stderr (callers usually treat it as `2>&1`).
    combined.extend_from_slice(&stderr_bytes);

    if combined.len() as u64 > cap {
        // `guard`'s `Drop` kills + reaps the still-running child on this bail.
        return Err(format!(
            "{cmd}: output exceeds the {cap}-byte capture ceiling \
             (raise IPE_PROCESS_OUTPUT_MAX)"
        ));
    }

    let status = guard.wait().map_err(|e| format!("{cmd}: {e}"))?;
    Ok(ProcessCapture {
        combined,
        success: status.success(),
        status: format!("{status}"),
    })
}

/// `Ipe.Process.run : String -> List String -> Task Error String` — run a
/// subprocess with NO shell (the arguments are a direct `argv` vector, never
/// passed to `sh -c`, so a caller-controlled argument can never be reinterpreted
/// as shell syntax — no command injection). Returns the child's combined
/// stdout+stderr on a clean exit; a non-zero exit or a spawn failure is `Err`
/// carrying the captured output + the status. Total — every failure maps to
/// `Err`, never a panic.
///
/// SECURITY: `Process.run` is a server-only capability (`subprocess`):
/// default-denied under `--target wasm`, and a program that reaches it is tagged
/// with the `subprocess` capability so a sandbox can isolate it. Captured output
/// is bounded (`process_output_ceiling`) so an unbounded-output child cannot OOM
/// the host. Sandboxing which programs may be spawned is the calling
/// application's responsibility.
///
/// The blocking spawn+wait is offloaded via `run_blocking` (see the module-level
/// doc comment above) so a long-running subprocess can't stall the tokio worker
/// thread polling this future.
#[must_use]
pub fn process_run<E: Send + From<String> + crate::FromUnavailable + 'static>(
    cmd: String,
    args: Vec<String>,
) -> IpeTask<E, String> {
    match process_output_ceiling() {
        Ok(cap) => process_run_with_cap(cmd, args, cap),
        Err(refusal) => refused_spawn(refusal),
    }
}

/// `process_run` with the capture ceiling supplied explicitly rather than read
/// from the environment. `process_run` reads `process_output_ceiling()` once and
/// forwards it here; tests exercise a specific ceiling by passing it directly,
/// so no test mutates the process-global environment (which would race a
/// concurrent subprocess call reading the same var).
#[must_use]
fn process_run_with_cap<E: Send + From<String> + crate::FromUnavailable + 'static>(
    cmd: String,
    args: Vec<String>,
    cap: u64,
) -> IpeTask<E, String> {
    Box::pin(async move {
        // `process_run_sync` folds `cmd` into every `Err` string, so the outer
        // `Err` arm (a refused or panicked blocking task) doesn't need `cmd` —
        // it's moved into the closure.
        match run_blocking::<_, E, _>(move || process_run_sync(&cmd, &args, cap)).await {
            Ok(out) => {
                #[allow(clippy::disallowed_methods)] // process output reaches Ipê as `String` text
                let text = String::from_utf8_lossy(&out.combined).into_owned();
                if out.success {
                    ok_res(text)
                } else {
                    // Cap the captured output folded into the Err string: large /
                    // binary subprocess output bloats the error and may embed
                    // secrets the process printed. Truncate to a bounded prefix
                    // (on a char boundary) before prepending the status.
                    const MAX_ERR_OUTPUT: usize = 4096;
                    let snippet: String = if text.len() > MAX_ERR_OUTPUT {
                        let mut end = MAX_ERR_OUTPUT;
                        while end > 0 && !text.is_char_boundary(end) {
                            end -= 1;
                        }
                        // Total accessor — `end` is a char boundary <= len, so
                        // `get` yields Some; the fallback keeps it slice-free and
                        // clippy::indexing_slicing-clean for non-test runtime code.
                        format!("{}… (output truncated)", text.get(..end).unwrap_or(&text))
                    } else {
                        text
                    };
                    IpeResult::Err(str_err(&format!("{}: {}", snippet, out.status)))
                }
            }
            Err(e) => IpeResult::Err(e),
        }
    })
}
/// The structured result of a `runWith` spawn: independent exit code, stdout, and
/// stderr captures. Exposed as a `pub struct` so the emitter can access its fields
/// directly (the same pattern `email::EmailMessage` and `cache::CacheCfg` use).
///
/// Field names match the Ipê record keys verbatim (`exitCode` / `stdout` /
/// `stderr`); `#[allow(non_snake_case)]` suppresses the style lint for `exitCode`.
#[allow(non_snake_case)]
pub struct ProcessRunOutput {
    pub exitCode: i64,
    pub stdout: String,
    pub stderr: String,
}

/// Spawn `cmd args` under optional `cwd` and env overrides, capturing stdout and
/// stderr INDEPENDENTLY on SEPARATE threads (no sequential-drain pipe-deadlock),
/// each bounded by `take(cap + 1)`. Returns the exit code alongside the two
/// streams. The child is reaped on every exit path via `ChildGuard`. An env pair
/// whose key is empty, contains `=` or NUL, or whose value contains NUL is
/// silently skipped — the same guard `locked_set_var` applies.
fn process_run_with_sync(
    cmd: &str,
    args: &[String],
    cwd: Option<&std::path::Path>,
    env_overrides: &[(String, String)],
    cap: u64,
) -> Result<ProcessRunOutput, String> {
    use std::process::{Command, Stdio};

    let mut builder = Command::new(cmd);
    builder
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(dir) = cwd {
        builder.current_dir(dir);
    }

    // Overlay first (the env Ipê itself observes), then per-child overrides win.
    apply_env_overlay(&mut builder);
    for (k, v) in env_overrides {
        // Same admission rule as the overlay writers.
        if !env_entry_is_valid(k, v) {
            continue;
        }
        builder.env(k, v);
    }

    let child = builder.spawn().map_err(|e| format!("{cmd}: {e}"))?;
    let mut guard = ChildGuard(Some(child));

    let limit = cap.saturating_add(1);

    let (stdout_pipe, stderr_pipe) = {
        let c = guard
            .get_mut()
            .ok_or_else(|| format!("{cmd}: child unexpectedly reaped"))?;
        (c.stdout.take(), c.stderr.take())
    };
    // A refused capture thread returns through `?`; `guard` kills and reaps the
    // child, which ends any capture already started.
    let out_handle = spawn_capture_thread(stdout_pipe, limit)
        .map_err(|e| format!("{cmd}: stdout capture thread refused: {e}"))?;
    let err_handle = spawn_capture_thread(stderr_pipe, limit)
        .map_err(|e| format!("{cmd}: stderr capture thread refused: {e}"))?;

    let stdout_bytes = out_handle
        .join()
        .map_err(|_| format!("{cmd}: stdout capture thread panicked"))?
        .map_err(|e| format!("{cmd}: {e}"))?;
    let stderr_bytes = err_handle
        .join()
        .map_err(|_| format!("{cmd}: stderr capture thread panicked"))?
        .map_err(|e| format!("{cmd}: {e}"))?;

    if stdout_bytes.len() as u64 > cap {
        return Err(format!(
            "{cmd}: stdout exceeds the {cap}-byte capture ceiling \
             (raise IPE_PROCESS_OUTPUT_MAX)"
        ));
    }
    if stderr_bytes.len() as u64 > cap {
        return Err(format!(
            "{cmd}: stderr exceeds the {cap}-byte capture ceiling \
             (raise IPE_PROCESS_OUTPUT_MAX)"
        ));
    }

    let status = guard.wait().map_err(|e| format!("{cmd}: {e}"))?;
    #[allow(clippy::disallowed_methods)] // process output reaches Ipê as `String` text
    let stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();
    #[allow(clippy::disallowed_methods)] // process output reaches Ipê as `String` text
    let stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();

    #[allow(non_snake_case)]
    Ok(ProcessRunOutput {
        exitCode: i64::from(status.code().unwrap_or(-1)),
        stdout,
        stderr,
    })
}

/// `Ipe.Process.runWith` — spawn a child process with per-child cwd and env
/// overrides, capturing exit code, stdout, and stderr independently.
///
/// A non-zero exit is a NORMAL result carried in `exitCode`; only a spawn
/// failure fails the Task. Both streams are bounded by `IPE_PROCESS_OUTPUT_MAX`
/// (default 16 MiB) and drained concurrently (no pipe-deadlock). The blocking
/// spawn+wait is offloaded via `run_blocking` so a long-running child cannot
/// stall the tokio worker thread.
///
/// SECURITY: same `subprocess` capability gate as `Process.run`. Per-child
/// `cwd` and env overrides do NOT escape the jail/sandbox roots — the child
/// inherits its confined environment from the parent, and the overrides are
/// applied ON TOP of that already-confined environment.
#[must_use]
pub fn process_run_with<E: Send + From<String> + crate::FromUnavailable + 'static>(
    cfg: ProcessRunWithCfg,
) -> IpeTask<E, ProcessRunOutput> {
    match process_output_ceiling() {
        Ok(cap) => process_run_with_impl(cfg, cap),
        Err(refusal) => refused_spawn(refusal),
    }
}

/// `ProcessRunWithCfg` — the Ipê record `{ command, args, cwd, env }` lowered
/// to a plain Rust struct. Owned values let the closure move into `run_blocking`
/// without a lifetime on the borrow. The emitter constructs this directly
/// (same pattern as `EmailMessage` / `CacheCfg`).
///
/// Field names match the Ipê record keys verbatim (`exitCode` etc.); the
/// non_snake_case allow is per-field.
pub struct ProcessRunWithCfg {
    pub command: String,
    pub args: Vec<String>,
    /// `Nothing` → inherit the parent cwd; `Just(p)` → set the child's cwd.
    pub cwd: IpeMaybe<String>,
    /// Per-child env overrides as `(key, value)` pairs.
    pub env: Vec<(String, String)>,
}

crate::stringify::show_row!("ProcessRunWithCfg", Redacted, [] ProcessRunWithCfg, |_| crate::stringify::REDACTED_SHOW.to_owned());

#[must_use]
fn process_run_with_impl<E: Send + From<String> + crate::FromUnavailable + 'static>(
    cfg: ProcessRunWithCfg,
    cap: u64,
) -> IpeTask<E, ProcessRunOutput> {
    Box::pin(async move {
        let result = run_blocking::<_, E, _>(move || {
            let cwd_path: Option<std::path::PathBuf> = match &cfg.cwd {
                IpeMaybe::Just(p) => Some(std::path::PathBuf::from(p)),
                IpeMaybe::Nothing => None,
            };
            process_run_with_sync(&cfg.command, &cfg.args, cwd_path.as_deref(), &cfg.env, cap)
        })
        .await;
        match result {
            Ok(out) => ok_res(out),
            Err(e) => IpeResult::Err(e),
        }
    })
}

/// `ProcessRunInPtyCfg` — the Ipê record `{ command, args, cwd, env, cols, rows }`
/// lowered to a plain Rust struct. Owned values let the closure move into
/// `run_blocking` without a borrow lifetime. The emitter constructs this directly
/// (same pattern as [`ProcessRunWithCfg`]).
///
/// Field names match the Ipê record keys verbatim.
pub struct ProcessRunInPtyCfg {
    pub command: String,
    pub args: Vec<String>,
    /// `Nothing` → inherit the parent cwd; `Just(p)` → set the child's cwd.
    pub cwd: IpeMaybe<String>,
    /// Per-child env overrides as `(key, value)` pairs.
    pub env: Vec<(String, String)>,
    /// Terminal width in columns; clamped into `u16` for the `winsize`.
    pub cols: i64,
    /// Terminal height in rows; clamped into `u16` for the `winsize`.
    pub rows: i64,
}

crate::stringify::show_row!("ProcessRunInPtyCfg", Redacted, [] ProcessRunInPtyCfg, |_| crate::stringify::REDACTED_SHOW.to_owned());

/// The structured result of a `runInPty` spawn: the child's exit code and the
/// combined stream read from the pty master until the child exits. Exposed as a
/// `pub struct` so the emitter constructs the return record directly (same pattern
/// as [`ProcessRunOutput`]).
#[allow(non_snake_case)]
pub struct ProcessPtyOutput {
    pub exitCode: i64,
    pub output: String,
}

/// `Ipe.Process.runInPty cfg` — run a child under a real pseudo-terminal, so a
/// TUI child sees `isatty(stdout) == true`, sizes to `cols`×`rows`, and emits
/// terminal control sequences. Returns the child's exit code and the combined
/// output read from the pty master until EOF, bounded by the same capture ceiling
/// as `Process.run` (`IPE_PROCESS_OUTPUT_MAX`, default 16 MiB) — a child that
/// floods the pty past the ceiling is an `Err`, never an unbounded allocation.
///
/// SECURITY: same `subprocess` capability gate as `Process.run` — the pty is an
/// implementation detail of running a child, not a new external reach. Every
/// fallible pty/spawn/read step maps to a typed `Err` (fail closed); no path
/// panics or hangs.
///
/// Unix-only: the pty surface (`openpt`/`grantpt`/`unlockpt`/`ptsname`) has no
/// meaning on non-unix targets, where this returns an honest unsupported `Err`
/// rather than a silent no-op. The blocking spawn+read+wait is offloaded via
/// `run_blocking` so a long-running child cannot stall the tokio worker thread.
#[must_use]
pub fn process_run_in_pty<E: Send + From<String> + crate::FromUnavailable + 'static>(
    cfg: ProcessRunInPtyCfg,
) -> IpeTask<E, ProcessPtyOutput> {
    match process_output_ceiling() {
        Ok(cap) => process_run_in_pty_impl(cfg, cap),
        Err(refusal) => refused_spawn(refusal),
    }
}

#[must_use]
fn process_run_in_pty_impl<E: Send + From<String> + crate::FromUnavailable + 'static>(
    cfg: ProcessRunInPtyCfg,
    cap: u64,
) -> IpeTask<E, ProcessPtyOutput> {
    Box::pin(async move {
        match run_blocking::<_, E, _>(move || process_run_in_pty_sync(cfg, cap)).await {
            Ok(out) => ok_res(out),
            Err(e) => IpeResult::Err(e),
        }
    })
}

/// Non-unix fallback: the pty surface is unavailable, so fail closed with an
/// honest unsupported `Err` (never a silent success or no-op). Gated so the unix
/// body — which references `rustix::pty` — is the only code compiled where the
/// surface exists.
#[cfg(not(unix))]
fn process_run_in_pty_sync(
    _cfg: ProcessRunInPtyCfg,
    _cap: u64,
) -> Result<ProcessPtyOutput, String> {
    Err("Process.runInPty is only supported on Unix targets".to_owned())
}

/// Spawn `cfg.command cfg.args` under a freshly allocated pseudo-terminal, sized
/// to `cfg.cols`×`cfg.rows`, with the child's stdin/stdout/stderr all connected to
/// the pty replica. Reads the master to EOF into a buffer bounded by `cap` (a read
/// past the ceiling is an `Err`), then reaps the child via [`ChildGuard`].
///
/// Every fallible syscall maps to a typed `Err`:
/// - `openpt` (allocate the master) → `Err` on no-free-pty / EPERM.
/// - `grantpt` / `unlockpt` (grant + unlock the replica) → `Err` on failure.
/// - `ptsname` (resolve the replica path) → `Err` on failure.
/// - `open` (open the replica) → `Err` on failure.
/// - `tcsetwinsize` (set the window size) → `Err` on failure.
/// - `try_clone` (per-stdio replica handle) → `Err` on failure.
/// - `spawn` (start the child) → `Err` on failure.
/// - the master-read thread `join`/read → `Err` on panic or IO error.
/// - `wait` (reap) → `Err` on failure.
///
/// No `unsafe`: rustix's `pty`/`termios` wrappers and `std`'s `Stdio::from`
/// (fd → owned stdio) cover every step. The child's stdin also reads the pty
/// replica, so a child reading input blocks on the pty (EOF once the master is
/// closed) rather than the parent's stdin.
#[cfg(unix)]
fn process_run_in_pty_sync(cfg: ProcessRunInPtyCfg, cap: u64) -> Result<ProcessPtyOutput, String> {
    use std::io::Read as _;
    use std::process::{Command, Stdio};

    let cmd = &cfg.command;

    // Allocate the pty master with O_RDWR | O_NOCTTY (the parent must not acquire
    // the pty as its controlling terminal). `OpenptFlags::CLOEXEC` — keeping the
    // master out of the child's fd table — is only defined by rustix on
    // Linux/FreeBSD/NetBSD; where it is absent the master is simply left
    // inheritable (the child receives the replica as its stdio, never the master
    // handle by name), so its inheritance is inert.
    let openpt_flags = {
        let base = rustix::pty::OpenptFlags::RDWR | rustix::pty::OpenptFlags::NOCTTY;
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]
        {
            base | rustix::pty::OpenptFlags::CLOEXEC
        }
        #[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd")))]
        {
            base
        }
    };
    let master =
        rustix::pty::openpt(openpt_flags).map_err(|e| format!("{cmd}: pty openpt failed: {e}"))?;

    // Grant + unlock the replica side, then resolve its filesystem path.
    rustix::pty::grantpt(&master).map_err(|e| format!("{cmd}: pty grantpt failed: {e}"))?;
    rustix::pty::unlockpt(&master).map_err(|e| format!("{cmd}: pty unlockpt failed: {e}"))?;
    let replica_name = rustix::pty::ptsname(&master, Vec::new())
        .map_err(|e| format!("{cmd}: pty ptsname failed: {e}"))?;

    // Open the replica the child will inherit as its stdio. O_NOCTTY: the child
    // acquires the controlling terminal via `setsid` semantics of process
    // separation, not by this open (the parent must not become the session leader).
    let replica = rustix::fs::open(
        replica_name.as_c_str(),
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY,
        rustix::fs::Mode::empty(),
    )
    .map_err(|e| format!("{cmd}: pty replica open failed: {e}"))?;

    // Size the pty. Clamp the caller's cols/rows into the kernel's `u16` window
    // fields (a negative or over-large value is clamped to the representable
    // range rather than wrapping). ws_xpixel/ws_ypixel are 0 (unused).
    let winsize = rustix::termios::Winsize {
        ws_row: clamp_u16(cfg.rows),
        ws_col: clamp_u16(cfg.cols),
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    rustix::termios::tcsetwinsize(&replica, winsize)
        .map_err(|e| format!("{cmd}: pty tcsetwinsize failed: {e}"))?;

    // Each of the child's three stdio slots needs its own owned handle to the
    // replica (each `Stdio::from` consumes one). Clone the replica fd twice; the
    // original covers the third.
    let replica_out = replica
        .try_clone()
        .map_err(|e| format!("{cmd}: pty replica dup failed: {e}"))?;
    let replica_err = replica
        .try_clone()
        .map_err(|e| format!("{cmd}: pty replica dup failed: {e}"))?;

    let mut builder = Command::new(cmd);
    builder
        .args(&cfg.args)
        .stdin(Stdio::from(replica))
        .stdout(Stdio::from(replica_out))
        .stderr(Stdio::from(replica_err));

    if let IpeMaybe::Just(dir) = &cfg.cwd {
        builder.current_dir(dir);
    }
    // Overlay first (the env Ipê itself observes), then per-child overrides win.
    apply_env_overlay(&mut builder);
    for (k, v) in &cfg.env {
        // Same admission rule as the overlay writers.
        if !env_entry_is_valid(k, v) {
            continue;
        }
        builder.env(k, v);
    }

    let child = builder.spawn().map_err(|e| format!("{cmd}: {e}"))?;
    let mut guard = ChildGuard(Some(child));

    // Close the parent's replica handles by dropping the `Command`: it retains
    // ownership of the three `Stdio`-wrapped replica fds after `spawn` (spawn
    // dup'd them into the child, but the parent's originals stay open until the
    // `Command` is dropped). Once ONLY the child holds replica ends open, reading
    // the master returns EOF when the child exits — otherwise the parent's own
    // open replica keeps the master readable forever, and the read below hangs.
    drop(builder);

    // Read the master to end-of-stream on a dedicated thread, bounded by `cap + 1`
    // so a flooding child cannot allocate without bound. `File::from` takes
    // ownership of the master fd; the reader thread owns it for its lifetime.
    //
    // On Linux, once the child (the last replica holder) closes the replica, a
    // read of the master returns `EIO` rather than a clean `Ok(0)` EOF — this is
    // the documented pty-master end-of-stream signal, not a real IO fault. Treat
    // `EIO` (and an interrupted `EINTR`) as end-of-stream; any OTHER error is a
    // genuine failure and propagates. The manual loop enforces the `cap + 1`
    // ceiling on peak allocation regardless.
    let mut master_file = std::fs::File::from(master);
    let limit = cap.saturating_add(1);
    // A refused reader drops the master with its closure and returns through
    // `?`; `guard` kills and reaps the child.
    let read_handle: std::thread::JoinHandle<std::io::Result<Vec<u8>>> =
        crate::threads::spawn_named(PTY_READ_THREAD, move || {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                let filled = u64::try_from(buf.len()).unwrap_or(u64::MAX);
                if filled >= limit {
                    break;
                }
                match master_file.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        // Never grow past `limit`: take only up to the ceiling.
                        let room = usize::try_from(limit - filled).unwrap_or(usize::MAX);
                        let take = n.min(room);
                        buf.extend_from_slice(chunk.get(..take).unwrap_or(&[]));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    // `EIO` on a pty master = the replica side closed = EOF.
                    Err(e) if e.raw_os_error() == Some(5) => break,
                    Err(e) => return Err(e),
                }
            }
            Ok(buf)
        })
        .map_err(|e| format!("{cmd}: pty read thread refused: {e}"))?;

    let combined = read_handle
        .join()
        .map_err(|_| format!("{cmd}: pty read thread panicked"))?
        .map_err(|e| format!("{cmd}: pty read failed: {e}"))?;

    if combined.len() as u64 > cap {
        // `guard`'s `Drop` kills + reaps the still-running child on this bail.
        return Err(format!(
            "{cmd}: pty output exceeds the {cap}-byte capture ceiling \
             (raise IPE_PROCESS_OUTPUT_MAX)"
        ));
    }

    let status = guard.wait().map_err(|e| format!("{cmd}: {e}"))?;
    #[allow(clippy::disallowed_methods)] // process output reaches Ipê as `String` text
    let output = String::from_utf8_lossy(&combined).into_owned();

    #[allow(non_snake_case)]
    Ok(ProcessPtyOutput {
        exitCode: i64::from(status.code().unwrap_or(-1)),
        output,
    })
}

/// Clamp an `i64` terminal dimension into the kernel `winsize`'s `u16` field: a
/// negative value becomes 0, an over-large value saturates at `u16::MAX`. Keeps a
/// caller-supplied `cols`/`rows` from wrapping into a nonsense window size.
#[cfg(unix)]
fn clamp_u16(n: i64) -> u16 {
    // `clamp` bounds `n` into `[0, u16::MAX]`, so the value is exactly
    // representable and `try_from` cannot fail; the fallback keeps it cast-free.
    u16::try_from(n.clamp(0, i64::from(u16::MAX))).unwrap_or(u16::MAX)
}

/// Process-exit cleanup hook. `std::process::exit` (what `System.exit` lowers to)
/// bypasses Drop, so an RAII guard's destructor never runs on that path. A backend
/// driver that puts the terminal/process into a state needing restoration (the
/// Ipe.Tui driver: raw mode + alternate screen + hidden cursor + mouse reporting)
/// registers its idempotent teardown here; `exit_process` runs it BEFORE
/// `process::exit`. The hook runs teardown before process termination, so RAII-
/// bypassed cleanup (terminal restore, cursor reset) completes before the OS reclaims
/// the process. A plain `fn()` keeps the boundary clean — `system` (always compiled) never
/// references the feature-gated `tui`/crossterm; the TUI provides the function.
static EXIT_HOOK: std::sync::OnceLock<fn()> = std::sync::OnceLock::new();

/// Register the process-exit cleanup (idempotent target; set once per process —
/// there is a single backend driver). Subsequent registrations are ignored.
pub fn register_exit_hook(f: fn()) {
    let _ = EXIT_HOOK.set(f);
}

/// Run the registered exit hook, if any. Called by `exit_process`; also safe to
/// call from a backend driver's own normal-exit path (the hook is idempotent).
pub fn run_exit_hook() {
    if let Some(f) = EXIT_HOOK.get() {
        f();
    }
}

/// Ends the process with `code` after every pre-exit stage has run.
///
/// The one process exit in the runtime; the runtime `clippy.toml` denies
/// `std::process::exit` everywhere else. `process::exit` skips Drop, so the
/// stages Drop would have run happen here first: the registered exit hook
/// (terminal restore), then, in a build with the telemetry exporters, a flush
/// of their buffered batches bounded by the exporters' flush deadline.
///
/// A stage that panics is abandoned, never the exit: each stage runs under
/// `catch_unwind`, so the process ends with `code` whatever a stage does (a
/// tokio thread-start refusal inside the flush's `block_in_place`, a panicking
/// hook). Without that, the panic would unwind out of this `-> !` call and the
/// caller (a shutdown grace timer, a watchdog) would keep running.
pub fn exit_process(code: i32) -> ! {
    let _ = std::panic::catch_unwind(run_exit_hook);
    #[cfg(all(feature = "web", feature = "http_client", not(target_arch = "wasm32")))]
    let _ = std::panic::catch_unwind(crate::web::flush_exporters_before_exit);
    #[expect(clippy::disallowed_methods)] // the one process exit; proves the ban fires
    // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — the runtime's one process-exit funnel: every exit request (`System.exit`, server shutdown, a CLI db op) ends here after the pre-exit stages [ledger #boundary]
    std::process::exit(code);
}

/// The `System.exit` kernel: ends the process through `exit_process`.
pub fn system_exit(code: i64) -> ! {
    exit_process(code as i32)
}

/// `Ipe.System.getenv key : String -> Task Error String` — the env var as a
/// `Task`, failing when it cannot be read.
///
/// Returning a `IpeTask` (not a bare `String`) keeps `getenv` usable in a
/// `Task.andThen`/`Task.run` position, and an unset variable fails the task
/// (never `Ok("")`) so a chained `Task.andThen` short-circuits. The failure
/// carries its kind: `NotFound` for an absent variable or a temp-root key,
/// `InvalidInput` for a variable set to a value that is not valid Unicode. The
/// message names the key, never the value. `getenvOr` stays a bare `String`:
/// its default answers every failure.
#[must_use]
pub fn system_getenv<E: Send + From<IpeError> + 'static>(key: String) -> IpeTask<E, String> {
    Box::pin(async move {
        match getenv_text(&key, read_env_var(&key)) {
            Ok(v) => ok_res(v),
            Err(e) => IpeResult::Err(e.into()),
        }
    })
}

/// `Ipe.System.getenvOr key default` — the env var, or `default` when it cannot
/// be read.
///
/// A variable set to a value that is not valid Unicode answers `default`, the
/// same as an absent one: the bare `String` return has no failure channel.
#[must_use]
pub fn system_getenv_or(key: String, default: String) -> String {
    read_env_var(&key).unwrap_or(default)
}

/// `System.getenvInt key : String -> Task Error Int`.
///
/// Fails `NotFound` when the variable is unset and `InvalidInput` when it is not
/// valid Unicode or does not parse as an integer.
#[must_use]
pub fn system_getenv_int<E: Send + From<IpeError> + 'static>(key: String) -> IpeTask<E, i64> {
    Box::pin(async move {
        match getenv_int_value(&key, read_env_var(&key)) {
            Ok(n) => ok_res(n),
            Err(e) => IpeResult::Err(e.into()),
        }
    })
}

/// `System.getenvBool key : String -> Task Error Bool`.
///
/// Accepted truthy values: `true/yes/1/on/y/t` → true; `false/no/0/off/n/f`/empty
/// → false. Fails `NotFound` when the variable is unset and `InvalidInput` when
/// it is not valid Unicode or is anything else.
#[must_use]
pub fn system_getenv_bool<E: Send + From<IpeError> + 'static>(key: String) -> IpeTask<E, bool> {
    Box::pin(async move {
        match getenv_bool_value(&key, read_env_var(&key)) {
            Ok(b) => ok_res(b),
            Err(e) => IpeResult::Err(e.into()),
        }
    })
}

/// The text of one environment read, or the error naming which way it failed.
///
/// Absent → `NotFound`; set to non-Unicode bytes → `InvalidInput`. The message
/// names the key only, never the value.
fn getenv_text(key: &str, raw: Result<String, std::env::VarError>) -> Result<String, IpeError> {
    match raw {
        Ok(v) => Ok(v),
        Err(std::env::VarError::NotPresent) => {
            Err(IpeError::not_found()
                .with_message(format!("environment variable {key:?} is not set")))
        }
        Err(std::env::VarError::NotUnicode(_)) => Err(IpeError::invalid_input(format!(
            "environment variable {key:?} is set to a value that is not valid Unicode"
        ))),
    }
}

/// The integer one environment read holds, or the error naming why it has none.
fn getenv_int_value(key: &str, raw: Result<String, std::env::VarError>) -> Result<i64, IpeError> {
    getenv_text(key, raw)?.trim().parse::<i64>().map_err(|_| {
        IpeError::invalid_input(format!("environment variable {key:?} is not a valid int"))
    })
}

/// The boolean one environment read holds, or the error naming why it has none.
fn getenv_bool_value(key: &str, raw: Result<String, std::env::VarError>) -> Result<bool, IpeError> {
    match getenv_text(key, raw)?.trim().to_lowercase().as_str() {
        "true" | "yes" | "1" | "on" | "y" | "t" => Ok(true),
        "false" | "no" | "0" | "off" | "n" | "f" | "" => Ok(false),
        _ => Err(IpeError::invalid_input(format!(
            "environment variable {key:?} is not a valid bool"
        ))),
    }
}

/// `System.getArg n : Int -> Task Error (Maybe String)`. Indexes the FULL arg
/// vector, where index 0 is the program name (unlike `System.args`, which
/// skips it); out-of-range or negative → `Ok Nothing`; an argument that is not
/// valid UTF-8 → `Err` `InvalidInput`.
#[must_use]
pub fn system_get_arg<E: Send + From<IpeError> + 'static>(n: i64) -> IpeTask<E, IpeMaybe<String>> {
    Box::pin(async move {
        match decode_arg_at(std::env::args_os(), n) {
            Ok(out) => ok_res(out),
            Err(e) => IpeResult::Err(e.into()),
        }
    })
}

#[must_use]
pub fn system_setenv<E: Send + 'static>(key: String, val: String) -> IpeTask<E, ()> {
    Box::pin(async move {
        locked_set_var(&key, &val);
        ok_res(())
    })
}

#[must_use]
pub fn system_unsetenv<E: Send + 'static>(key: String) -> IpeTask<E, ()> {
    Box::pin(async move {
        locked_remove_var(&key);
        ok_res(())
    })
}

/// `System.cwd : () -> Task Error String`.
///
/// The working directory passes the host seal; one that is not valid UTF-8
/// is refused as invalid input, never rewritten lossily.
#[must_use]
pub fn system_cwd<E: Send + From<IpeError> + 'static>(_: ()) -> IpeTask<E, String> {
    Box::pin(async move {
        let cwd = std::env::current_dir()
            .map_err(|e| IpeError::from(format!("{e}")))
            .and_then(|p| from_os(p.as_path(), OsOrigin::SystemCwd));
        match cwd {
            Ok(p) => ok_res(p.into_string()),
            Err(e) => IpeResult::Err(e.into()),
        }
    })
}

/// `System.getcwd : () -> Task Error String` — backward-compat alias for `cwd`.
/// Wraps `System_cwd` with a unit arg.
#[must_use]
pub fn system_getcwd<E: Send + From<IpeError> + 'static>(unit: ()) -> IpeTask<E, String> {
    system_cwd(unit)
}

/// Blocking half of `system_load_env`: read + parse `.env` in the CWD and set
/// each var. Never fails — a missing/unreadable `.env` is silently a no-op,
/// matching the Ipê-facing contract (`loadEnv` never returns `Err`).
fn system_load_env_sync() {
    if let Ok(contents) = std::fs::read_to_string(".env") {
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let k = k.trim();
                let v = v.trim().trim_matches('"').trim_matches('\'');
                // Atomic check-and-set under one write lock — avoids the
                // TOCTOU window a separate read + set would open against a
                // concurrent mutator.
                locked_set_var_if_absent(k, v);
            }
        }
    }
}

/// `System.loadEnv : () -> Task Error ()`. Parses a `.env` file in the CWD
/// (KEY=VALUE per line, `#` comments, optional surrounding quotes) and sets
/// each var WITHOUT overriding one already present in the process environment
/// (process env wins, matching Ipê's precedence). A missing `.env` is a no-op
/// success.
///
/// `std::fs::read_to_string(".env")` is a blocking syscall, so it is offloaded
/// to the blocking pool (`threads::join_blocking`) rather than run inline inside
/// the `async move` body — the same offload `file.rs`/`compression.rs`/`csv.rs`/
/// `config_decode.rs` use. Real-world impact is low (`.env` is small and read
/// once at startup), but on a slow/network filesystem an inline read would stall
/// the tokio worker thread polling this future.
#[must_use]
pub fn system_load_env<E: Send + 'static>(_: ()) -> IpeTask<E, ()> {
    Box::pin(async move {
        // `loadEnv` never surfaces an `Err` for a missing/unreadable `.env`, and
        // a panicked read does not change that contract. A pool that cannot
        // start a thread reads the small file inline instead, so the overlay is
        // loaded either way.
        let offloaded = crate::threads::join_blocking("System.loadEnv", system_load_env_sync).await;
        if matches!(offloaded, Err(crate::threads::BlockingFailure::Refused(_))) {
            system_load_env_sync();
        }
        ok_res(())
    })
}

/// Asserts the shared [`EnvCeiling`] contract on `ceiling`.
///
/// Absent yields the default; every malformed spelling (empty, signed,
/// suffixed, padded, separated, hex, fractional, non-ASCII digits, overflowing,
/// non-Unicode) is refused naming the variable; `1` and the bound are
/// accepted and one past the bound is refused; `0` follows the ceiling's
/// [`ZeroCeiling`].
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) fn assert_env_ceiling_contract(ceiling: EnvCeiling) {
    assert_decimal_contract(ceiling, |raw| ceiling.parse(raw));
}

/// Asserts the [`EnvCeiling`] contract on an [`EnvDuration`].
///
/// A bare second count honours every clause of the decimal contract, and the
/// duration grammar adds its own refusals.
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) fn assert_env_duration_contract(duration: EnvDuration) {
    assert_decimal_contract(duration.ceiling, |raw| duration.parse(raw));
    let name = duration.name();
    let parse = |raw: &str| duration.parse(Ok(raw.to_owned()));
    for refused in [
        "1h30",
        "1d",
        "m",
        "h",
        "1h ",
        "1H",
        "1hm",
        "h1",
        "1m1h",
        "1h1h",
        "1h 30m",
        "1h-30m",
        "1h\u{FF11}m",
        "0s",
        "0h0m",
    ] {
        assert!(
            parse(refused).is_err_and(|r| r.name() == name),
            "{name}: {refused:?} must be refused naming the variable"
        );
    }
    for (spelled, secs) in [
        ("1s", 1),
        ("90s", 90),
        ("30m", 1800),
        ("1h", 3600),
        ("1h30m", 5400),
        ("1h30m15s", 5415),
        ("1h15s", 3615),
        ("0h30m", 1800),
    ] {
        if secs <= duration.max_value() {
            assert_eq!(
                parse(spelled),
                Ok(secs),
                "{name}: {spelled:?} is {secs} seconds"
            );
        }
    }
    assert!(
        parse("18446744073709551615h").is_err_and(|r| r.defect() == CeilingDefect::TooLarge),
        "{name}: an overflowing segment is refused as too large"
    );
}

/// The decimal clauses of the ceiling contract over one parser of raw lookups.
#[cfg(all(test, not(target_arch = "wasm32")))]
fn assert_decimal_contract(
    ceiling: EnvCeiling,
    parse_raw: impl Fn(Result<String, std::env::VarError>) -> Result<u64, EnvCeilingRefusal>,
) {
    use std::env::VarError;
    let name = ceiling.name();
    let parse = |raw: &str| parse_raw(Ok(raw.to_owned()));
    assert_eq!(
        parse_raw(Err(VarError::NotPresent)),
        Ok(ceiling.default_value()),
        "{name}: an absent value yields the default"
    );
    for refused in [
        "",
        "-1",
        "+1024",
        "16MiB",
        "1k",
        " 1024",
        "1024 ",
        "\t1",
        "1024\n",
        "1_024",
        "1,024",
        "0x10",
        "1.5",
        "1e3",
        "\u{FF11}",
        "18446744073709551616",
    ] {
        let outcome = parse(refused);
        assert!(
            outcome
                .as_ref()
                .is_err_and(|r| r.name() == name && r.to_string().starts_with(name)),
            "{name}: {refused:?} must be refused naming the variable, got {outcome:?}"
        );
    }
    assert!(
        parse("18446744073709551616").is_err_and(|r| r.defect() == CeilingDefect::TooLarge),
        "{name}: an overflowing value is refused as too large"
    );
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt as _;
        let not_unicode = std::ffi::OsString::from_vec(vec![b'1', 0xFF]);
        assert!(
            parse_raw(Err(VarError::NotUnicode(not_unicode)))
                .is_err_and(|r| r.defect() == CeilingDefect::NotDecimal),
            "{name}: a non-Unicode value is refused"
        );
    }
    assert_eq!(
        parse("1"),
        Ok(1),
        "{name}: the least positive value is accepted"
    );
    let max = ceiling.max_value();
    assert!(
        ceiling.default_value() <= max,
        "{name}: the default is within the bound"
    );
    assert_eq!(
        parse(&max.to_string()),
        Ok(max),
        "{name}: the largest value is accepted"
    );
    if let Some(past) = max.checked_add(1) {
        assert!(
            parse(&past.to_string()).is_err_and(|r| r.defect() == CeilingDefect::TooLarge),
            "{name}: one past the bound is refused as too large"
        );
    }
    match ceiling.zero {
        ZeroCeiling::Refused => assert!(
            parse("0").is_err_and(|r| r.defect() == CeilingDefect::Zero),
            "{name}: a refused zero is refused"
        ),
        ZeroCeiling::Accepted => assert_eq!(parse("0"), Ok(0), "{name}: zero is accepted"),
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod env_ceiling_tests {
    use super::{
        CeilingDefect, ENV_VALUE_SHOWN_CHARS, EnvCeiling, EnvDuration, EnvValueRefusal,
        PROCESS_OUTPUT_CEILING, ZeroCeiling, assert_env_ceiling_contract,
        assert_env_duration_contract, locked_remove_var, locked_set_var, process_output_ceiling,
    };

    #[test]
    fn an_in_code_setting_is_positive_and_within_the_bound() {
        for zero in [ZeroCeiling::Refused, ZeroCeiling::Accepted] {
            let ceiling = EnvCeiling::new("IPE_TEST_CEILING", 7, zero, "count").at_most(100);
            for (value, defect) in [
                (0, CeilingDefect::Zero),
                (-1, CeilingDefect::Zero),
                (i64::MIN, CeilingDefect::Zero),
                (101, CeilingDefect::TooLarge),
                (i64::MAX, CeilingDefect::TooLarge),
            ] {
                let refused = ceiling.check_setting("Test.limit", value);
                assert!(
                    refused
                        .as_ref()
                        .is_err_and(|r| r.defect() == defect && r.setting() == Some("Test.limit")),
                    "{value} must be refused as {defect:?} naming the setting, got {refused:?}"
                );
            }
            assert_eq!(ceiling.check_setting("Test.limit", 100), Ok(100));
            assert_eq!(ceiling.check_setting("Test.limit", 1), Ok(1));
        }
        let duration = EnvDuration::new("IPE_TEST_DURATION", 30, "duration").at_most(5400);
        assert_eq!(duration.check_setting("Test.ttl", 5400), Ok(5400));
        assert_eq!(
            duration
                .parse(Ok("2h".to_owned()))
                .map_err(|r| r.to_string()),
            Err("IPE_TEST_DURATION must be at most 5400 (got \"2h\")".to_owned()),
            "a duration above the bound names the bound in seconds"
        );
        assert!(
            duration
                .check_setting("Test.ttl", 5401)
                .is_err_and(|r| r.defect() == CeilingDefect::TooLarge)
        );
    }

    #[test]
    fn an_in_code_refusal_names_the_setting_not_the_variable() {
        let ceiling =
            EnvCeiling::new("IPE_TEST_CEILING", 7, ZeroCeiling::Refused, "count").at_most(100);
        let too_large = ceiling
            .check_setting("Test.limit", 101)
            .map_err(|r| r.to_string());
        assert_eq!(
            too_large,
            Err("the `Test.limit` setting must be at most 100 (got 101)".to_owned())
        );
        let zero = ceiling
            .check_setting("Test.limit", 0)
            .map_err(|r| r.to_string());
        assert_eq!(
            zero,
            Err("the `Test.limit` setting must be positive (got 0)".to_owned())
        );
        let lowered = EnvCeiling::new("IPE_TEST_CEILING", 7, ZeroCeiling::Refused, "count");
        assert_eq!(lowered.check_default(), Ok(7));
        assert_eq!(
            lowered.at_most(6).check_default().map_err(|r| r.to_string()),
            Err(
                "IPE_TEST_CEILING is unset and its default 7 is out of range; set IPE_TEST_CEILING to at most 6"
                    .to_owned()
            )
        );
        let env = ceiling.parse(Ok("101".to_owned()));
        assert!(
            env.is_err_and(
                |r| r.setting().is_none() && r.to_string().starts_with("IPE_TEST_CEILING")
            ),
            "an environment refusal names the variable"
        );
        assert_eq!(
            ceiling
                .parse(Ok("101".to_owned()))
                .map_err(|r| r.to_string()),
            Err("IPE_TEST_CEILING must be at most 100 (got \"101\")".to_owned()),
            "a value above the bound names the bound"
        );
        assert_eq!(
            ceiling
                .parse(Ok("99999999999999999999".to_owned()))
                .map_err(|r| r.to_string()),
            Err(
                "IPE_TEST_CEILING is too large for this platform (got \"99999999999999999999\")"
                    .to_owned()
            ),
            "a value no `u64` holds is too large for the platform"
        );
    }

    #[test]
    fn an_env_value_refusal_escapes_and_truncates_its_echo() {
        let refusal = EnvValueRefusal::new(
            "EXAMPLE_VALUE",
            "an IP address",
            format!("\u{1b}[31m\n{}", "x".repeat(ENV_VALUE_SHOWN_CHARS * 2)).as_bytes(),
        );
        let shown = refusal.to_string();
        assert_eq!(refusal.name(), "EXAMPLE_VALUE");
        assert!(!shown.contains('\u{1b}'), "ESC is escaped: {shown}");
        assert!(!shown.contains('\n'), "a newline is escaped: {shown}");
        assert!(
            shown.starts_with("EXAMPLE_VALUE must be an IP address (got \"\\u{1b}[31m\\n"),
            "{shown}"
        );
        assert_eq!(
            shown.matches('x').count(),
            ENV_VALUE_SHOWN_CHARS - 6,
            "the echo stops after its first source characters: {shown}"
        );
        let invalid = EnvValueRefusal::new("EXAMPLE_VALUE", "an IP address", b"\xFF1");
        assert_eq!(
            invalid.to_string(),
            "EXAMPLE_VALUE must be an IP address (got \"\\xFF1\")"
        );
    }

    #[test]
    fn a_duration_honours_the_contract_at_every_bound() {
        let base = EnvDuration::new("IPE_TEST_DURATION", 30, "duration");
        for duration in [
            base,
            base.at_most(59),
            base.at_most(86_400),
            base.at_most(34_560_000),
        ] {
            assert_env_duration_contract(duration);
        }
    }

    #[test]
    fn a_duration_total_past_its_bound_is_refused_whatever_the_spelling() {
        let duration = EnvDuration::new("IPE_TEST_DURATION", 30, "duration").at_most(5400);
        let parse = |raw: &str| duration.parse(Ok(raw.to_owned()));
        assert_eq!(parse("1h30m"), Ok(5400));
        assert_eq!(parse("5400"), Ok(5400));
        for past in ["1h30m1s", "5401", "2h", "91m"] {
            assert!(
                parse(past).is_err_and(|r| r.defect() == CeilingDefect::TooLarge),
                "{past:?} is past the bound"
            );
        }
    }

    #[test]
    fn a_duration_echo_is_truncated_and_escaped() {
        let duration = EnvDuration::new("IPE_TEST_DURATION", 30, "duration");
        let shown = duration
            .parse(Ok(format!("\u{1b}[31m{}", "9x".repeat(64))))
            .map_err(|r| r.to_string())
            .expect_err("a malformed duration is refused");
        assert!(
            !shown.contains('\u{1b}'),
            "a control byte is escaped: {shown}"
        );
        assert!(
            shown.starts_with("IPE_TEST_DURATION must be a duration"),
            "{shown}"
        );
    }

    #[test]
    fn a_duration_reads_the_live_environment() {
        let duration = EnvDuration::new("IPE_TEST_DURATION_LIVE", 30, "duration");
        locked_remove_var("IPE_TEST_DURATION_LIVE");
        let absent = duration.read();
        locked_set_var("IPE_TEST_DURATION_LIVE", "1h30m");
        let set = duration.read();
        locked_set_var("IPE_TEST_DURATION_LIVE", "1h30");
        let malformed = duration.read();
        locked_remove_var("IPE_TEST_DURATION_LIVE");
        assert_eq!(absent, Ok(30));
        assert_eq!(set, Ok(5400));
        assert!(malformed.is_err_and(|r| r.name() == "IPE_TEST_DURATION_LIVE"));
    }

    #[test]
    fn both_zero_rules_honour_the_contract() {
        for zero in [ZeroCeiling::Refused, ZeroCeiling::Accepted] {
            assert_env_ceiling_contract(EnvCeiling::new("IPE_TEST_CEILING", 7, zero, "count"));
        }
    }

    #[test]
    fn process_output_ceiling_refuses_a_malformed_value() {
        assert_env_ceiling_contract(PROCESS_OUTPUT_CEILING);
        locked_set_var("IPE_PROCESS_OUTPUT_MAX", "16MiB");
        let refused = process_output_ceiling();
        locked_remove_var("IPE_PROCESS_OUTPUT_MAX");
        assert!(
            refused.is_err_and(|r| r.name() == "IPE_PROCESS_OUTPUT_MAX"),
            "a suffixed output ceiling must refuse the spawn"
        );
    }

    #[test]
    fn a_narrowing_overflow_is_refused_too_large() {
        let ceiling = EnvCeiling::new("IPE_TEST_CEILING", 7, ZeroCeiling::Refused, "count");
        let refused = ceiling.parse_as::<u8>(Ok("256".to_owned()));
        assert!(refused.is_err_and(|r| r.defect() == CeilingDefect::TooLarge));
        assert_eq!(ceiling.parse_as::<u8>(Ok("255".to_owned())), Ok(255));
    }

    #[test]
    fn the_echoed_value_is_truncated_and_escaped() {
        let ceiling = EnvCeiling::new("IPE_TEST_CEILING", 7, ZeroCeiling::Refused, "count");
        let long = format!("\u{1b}[31m{}", "9x".repeat(64));
        let shown = ceiling
            .parse(Ok(long))
            .map_err(|r| r.to_string())
            .expect_err("a non-decimal value is refused");
        assert!(
            !shown.contains('\u{1b}'),
            "a control byte is escaped: {shown}"
        );
        assert!(
            shown.len()
                < "IPE_TEST_CEILING must be a count (got \"\")".len() + 8 * ENV_VALUE_SHOWN_CHARS,
            "the echo is bounded: {shown}"
        );
    }

    /// Every runtime source file, as `(path under src/, text)`.
    fn runtime_sources() -> Vec<(String, String)> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut pending = vec![root.clone()];
        let mut out = Vec::new();
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).expect("the runtime source tree is readable") {
                let path = entry.expect("a readable directory entry").path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let rel = path
                        .strip_prefix(&root)
                        .expect("under src/")
                        .to_string_lossy()
                        .replace('\\', "/");
                    let text = std::fs::read_to_string(&path).expect("a UTF-8 source file");
                    out.push((rel, text));
                }
            }
        }
        out
    }

    /// The functions that read the environment and parse a number without
    /// [`EnvCeiling`], as `(file, fn, why)`.
    const NON_CEILING_READS: [(&str, &str, &str); 3] = [
        (
            "control.rs",
            "control_port_from_env",
            "a port: absent or malformed opens no control socket",
        ),
        (
            "system.rs",
            "system_getenv_int",
            "`Env.getInt`: the parse failure is the kernel's own `Err` result",
        ),
        (
            "server.rs",
            "build_request",
            "the number parsed is a request's `Content-Length`; the environment read is `IPE_TRUSTED_PROXY`",
        ),
    ];

    /// The environment reads the scan follows.
    const ENV_READS: [&str; 3] = [
        concat!("read_env_var", "("),
        concat!("read_env_var_os", "("),
        concat!("std::env::var", "("),
    ];

    /// The exporter registry reads its names through a method on the variant.
    const EXPORTER_READ: (&str, [&str; 2]) = (
        concat!("ExporterEnv", "::"),
        [concat!(".read", "()"), concat!(".raw", "()")],
    );

    /// The integer and float types a numeric `str::parse` names.
    const NUMERIC_TYPES: [&str; 15] = [
        "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize",
        "f32", "f64", "NonZero",
    ];

    /// Each `fn` item of a source file, as `(name, text up to the next item)`.
    fn fn_items(text: &str) -> Vec<(&str, &str)> {
        let mut starts = Vec::new();
        let mut offset = 0;
        for line in text.split_inclusive('\n') {
            let mut head = line.trim_start();
            while let Some(rest) = ["pub(crate) ", "pub(super) ", "pub ", "const ", "async "]
                .into_iter()
                .find_map(|prefix| head.strip_prefix(prefix))
            {
                head = rest;
            }
            if let Some(after) = head.strip_prefix("fn ") {
                let len = after
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(after.len());
                if len > 0 {
                    starts.push((after.get(..len).unwrap_or_default(), offset));
                }
            }
            offset += line.len();
        }
        let ends = starts.iter().skip(1).map(|&(_, at)| at).chain([text.len()]);
        starts
            .iter()
            .zip(ends)
            .map(|(&(name, at), end)| (name, text.get(at..end).unwrap_or_default()))
            .collect()
    }

    fn reads_env(body: &str) -> bool {
        let (exporter, methods) = EXPORTER_READ;
        ENV_READS.iter().any(|read| body.contains(read))
            || (body.contains(exporter) && methods.iter().any(|m| body.contains(m)))
    }

    fn parses_number(body: &str) -> bool {
        body.contains(concat!(".parse", "()"))
            || NUMERIC_TYPES
                .iter()
                .any(|ty| body.contains(&format!("{}{ty}", concat!(".parse", "::<"))))
    }

    /// Whether `body` calls the free function `name` (not a method of that name).
    fn calls(body: &str, name: &str) -> bool {
        body.match_indices(&format!("{name}(")).any(|(at, _)| {
            body.get(..at)
                .and_then(|before| before.chars().next_back())
                .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
        })
    }

    /// No function reads the environment and parses a number outside
    /// [`EnvCeiling`] — directly, or through a same-file helper it hands the
    /// read to. Every hit must be a listed non-ceiling read; a listed function
    /// that no longer reads a number fails too.
    #[test]
    fn no_env_numeric_parse_bypasses_the_ceiling_parser() {
        let mut seen = Vec::new();
        let mut bypasses = Vec::new();
        for (file, text) in runtime_sources() {
            let items = fn_items(&text);
            let helpers: Vec<&str> = items
                .iter()
                .filter(|(_, body)| parses_number(body))
                .map(|&(name, _)| name)
                .collect();
            for &(name, body) in &items {
                if !reads_env(body) {
                    continue;
                }
                let helper = helpers
                    .iter()
                    .find(|&&helper| helper != name && calls(body, helper));
                if !parses_number(body) && helper.is_none() {
                    continue;
                }
                match NON_CEILING_READS
                    .iter()
                    .find(|(f, n, _)| *f == file && *n == name)
                {
                    Some(listed) => seen.push(*listed),
                    None => bypasses.push(match helper {
                        Some(helper) => format!("{file}: {name} via {helper}"),
                        None => format!("{file}: {name}"),
                    }),
                }
            }
        }
        assert!(
            bypasses.is_empty(),
            "parse these through `system::EnvCeiling`: {bypasses:#?}"
        );
        for listed in NON_CEILING_READS {
            assert!(
                seen.contains(&listed),
                "{listed:?} no longer reads a number; drop it from the list"
            );
        }
    }

    #[test]
    fn the_scan_follows_a_read_into_a_same_file_helper() {
        let text = concat!(
            "fn limit() -> usize {\n    helper(crate::system::",
            "read_env_var",
            "(\"IPE_X\").ok())\n}\n\nfn helper(raw: Option<String>) -> usize {\n    raw.and_then(|v| v",
            ".parse",
            "::<usize>().ok()).unwrap_or(1)\n}\n\nfn other() {\n    x.helper(1);\n}\n",
        );
        let items = fn_items(text);
        let names: Vec<&str> = items.iter().map(|&(name, _)| name).collect();
        assert_eq!(names, ["limit", "helper", "other"]);
        let body = |i: usize| items.get(i).map(|&(_, body)| body).unwrap_or_default();
        assert!(reads_env(body(0)) && !parses_number(body(0)) && calls(body(0), "helper"));
        assert!(parses_number(body(1)));
        assert!(
            !calls(body(2), "helper"),
            "a method of the same name is not the helper"
        );
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod temp_root_env_tests {
    use super::{locked_remove_var, locked_set_var, read_env_var};
    use std::env::VarError;

    /// Every spelling of a temp-root key reads as unset, even when Ipê set it.
    #[test]
    fn a_temp_root_key_is_never_answered() {
        for key in ["TMPDIR", "tmpdir", "TmpDir", "TMP", "tmp", "TEMP", "Temp"] {
            locked_set_var(key, "/attacker/base");
            assert_eq!(read_env_var(key), Err(VarError::NotPresent), "{key:?}");
            locked_remove_var(key);
            assert_eq!(read_env_var(key), Err(VarError::NotPresent), "{key:?}");
        }
    }

    /// The `OsString` reader refuses every temp-root spelling alike, even when
    /// Ipê set it.
    #[cfg(any(feature = "tui", feature = "debugger"))]
    #[test]
    fn a_temp_root_key_is_never_answered_as_os_string() {
        for key in ["TMPDIR", "tmpdir", "TmpDir", "TMP", "tmp", "TEMP", "Temp"] {
            locked_set_var(key, "/attacker/base");
            assert_eq!(super::read_env_var_os(key), None, "{key:?}");
            locked_remove_var(key);
            assert_eq!(super::read_env_var_os(key), None, "{key:?}");
        }
    }

    /// A key that only contains a temp-root name is answered normally.
    #[test]
    fn a_neighbouring_key_is_answered() {
        let key = "IPE_TEMP_ROOT_ENV_TEST_NEIGHBOUR";
        locked_set_var(key, "v");
        assert_eq!(read_env_var(key), Ok("v".to_owned()));
        locked_remove_var(key);
        for key in ["TMPDIR_", "IPE_TMP", "TEMPLATE", "CARGO_TARGET_TMPDIR"] {
            assert!(
                !super::super::scratch_core::is_temp_root_key(key),
                "{key:?}"
            );
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod getenv_kind_tests {
    use super::{
        locked_remove_var, locked_set_var, system_getenv, system_getenv_bool, system_getenv_int,
    };
    use crate::error::{IpeError, IpeErrorKind};
    use crate::{IpeResult, IpeTask};

    /// Marker bytes no failure message may carry, as ASCII or as a lossy rendering.
    const SECRET_MARKER: &str = "zq9";

    /// The variable the re-exec of the non-Unicode environ test is started with.
    #[cfg(unix)]
    const NOT_UNICODE_PROBE: &str = "IPE_GETENV_NOT_UNICODE_PROBE";

    /// A non-Unicode value that holds the marker.
    #[cfg(unix)]
    fn not_unicode_value() -> std::ffi::OsString {
        use std::os::unix::ffi::OsStringExt as _;
        std::ffi::OsString::from_vec(vec![0xFF, b'z', b'q', b'9', 0xFE])
    }

    #[allow(clippy::expect_used)] // test harness: a runtime that cannot start is an environment issue
    fn block<T: Send + 'static>(task: IpeTask<IpeError, T>) -> IpeResult<IpeError, T> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime");
        rt.block_on(task)
    }

    /// The kind and message of a failed task; `None` for a success.
    fn failure<T>(result: IpeResult<IpeError, T>) -> Option<(IpeErrorKind, String)> {
        match result {
            IpeResult::Err(IpeError::Error(kind, info)) => Some((kind, info.message)),
            IpeResult::Ok(_) => None,
        }
    }

    /// Whether `result` failed with `kind` and a message that names `key` and
    /// carries no byte of the value.
    fn fails_as<T>(result: IpeResult<IpeError, T>, kind: IpeErrorKind, key: &str) -> bool {
        failure(result).is_some_and(|(got, message)| {
            got == kind
                && message.contains(key)
                && !message.contains(SECRET_MARKER)
                && !message.contains('\u{FFFD}')
        })
    }

    /// Whether every `getenv*` kernel fails on `key` as `kind`.
    fn every_kernel_fails_as(key: &str, kind: IpeErrorKind) -> bool {
        fails_as(block(system_getenv::<IpeError>(key.to_owned())), kind, key)
            && fails_as(
                block(system_getenv_int::<IpeError>(key.to_owned())),
                kind,
                key,
            )
            && fails_as(
                block(system_getenv_bool::<IpeError>(key.to_owned())),
                kind,
                key,
            )
    }

    /// An absent variable is `NotFound` from every `getenv*` kernel.
    #[test]
    fn an_absent_key_is_not_found() {
        let key = "IPE_GETENV_KIND_ABSENT";
        locked_remove_var(key);
        assert!(every_kernel_fails_as(key, IpeErrorKind::NotFound));
    }

    /// A temp-root key is `NotFound`, even when the program set it.
    #[test]
    fn a_temp_root_key_is_not_found() {
        for key in ["TMPDIR", "TMP", "TEMP", "tmpdir"] {
            locked_set_var(key, "/attacker/base");
            assert!(
                every_kernel_fails_as(key, IpeErrorKind::NotFound),
                "{key:?}"
            );
            locked_remove_var(key);
        }
    }

    /// A value that is not Unicode is `InvalidInput`, never absence, and its
    /// bytes reach no message.
    #[cfg(unix)]
    #[test]
    fn a_non_unicode_value_is_invalid_input_without_echo() {
        use super::{getenv_bool_value, getenv_int_value, getenv_text};
        use std::env::VarError;
        let key = "IPE_GETENV_KIND_NOT_UNICODE";
        let raw = || Err::<String, _>(VarError::NotUnicode(not_unicode_value()));
        let failures = [
            getenv_text(key, raw()).err(),
            getenv_int_value(key, raw()).err(),
            getenv_bool_value(key, raw()).err(),
        ];
        for failed in failures {
            let result: IpeResult<IpeError, ()> = failed.map_or(IpeResult::Ok(()), IpeResult::Err);
            assert!(fails_as(result, IpeErrorKind::InvalidInput, key), "{key:?}");
        }
    }

    /// A value that does not parse is `InvalidInput`, and the value is not echoed.
    #[test]
    fn an_unparsable_value_is_invalid_input_without_echo() {
        let int_key = "IPE_GETENV_KIND_BAD_INT";
        locked_set_var(int_key, "abc-zq9");
        assert!(fails_as(
            block(system_getenv_int::<IpeError>(int_key.to_owned())),
            IpeErrorKind::InvalidInput,
            int_key
        ));
        let bool_key = "IPE_GETENV_KIND_BAD_BOOL";
        locked_set_var(bool_key, "maybe-zq9");
        assert!(fails_as(
            block(system_getenv_bool::<IpeError>(bool_key.to_owned())),
            IpeErrorKind::InvalidInput,
            bool_key
        ));
        locked_remove_var(int_key);
        locked_remove_var(bool_key);
    }

    /// A readable value still answers, so the kinds above are the only failures.
    #[test]
    fn a_readable_value_still_answers() {
        let key = "IPE_GETENV_KIND_READABLE";
        locked_set_var(key, " 42 ");
        assert!(matches!(
            block(system_getenv_int::<IpeError>(key.to_owned())),
            IpeResult::Ok(42)
        ));
        locked_set_var(key, "Yes");
        assert!(matches!(
            block(system_getenv_bool::<IpeError>(key.to_owned())),
            IpeResult::Ok(true)
        ));
        assert!(matches!(
            block(system_getenv::<IpeError>(key.to_owned())),
            IpeResult::Ok(v) if v == "Yes"
        ));
        locked_remove_var(key);
    }

    /// The real environ read fails `InvalidInput` for a non-Unicode value, and
    /// `getenvOr` answers its default.
    ///
    /// The value is set at spawn on a re-exec of this test binary that must run
    /// and pass this one test: the overlay holds only Unicode and the process
    /// environ is never mutated. The re-exec sees the probe and checks the
    /// kernels; the parent, without it, starts the re-exec.
    #[cfg(unix)]
    #[test]
    fn a_non_unicode_environ_value_is_invalid_input() {
        if super::read_env_var_os(NOT_UNICODE_PROBE).is_some() {
            assert!(every_kernel_fails_as(
                NOT_UNICODE_PROBE,
                IpeErrorKind::InvalidInput
            ));
            assert_eq!(
                super::system_getenv_or(NOT_UNICODE_PROBE.to_owned(), "fallback".to_owned()),
                "fallback",
                "`getenvOr` answers its default for a non-Unicode value"
            );
            return;
        }
        let module = module_path!();
        let name = format!(
            "{}::a_non_unicode_environ_value_is_invalid_input",
            module.split_once("::").map_or(module, |(_, rest)| rest)
        );
        let rerun = e2e_support::rerun_this_test_exact(&name, |cmd| {
            cmd.arg("--test-threads=1")
                .env(NOT_UNICODE_PROBE, not_unicode_value())
                .stdin(std::process::Stdio::null());
        });
        assert!(
            rerun.is_ok(),
            "the non-Unicode re-exec did not pass: {rerun:?}"
        );
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod exit_hook_tests {
    use super::{register_exit_hook, run_exit_hook};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    fn bump() {
        CALLS.fetch_add(1, Ordering::SeqCst);
    }

    /// The code the panicking-stage child asks to exit with.
    const PANICKING_STAGE_EXIT_CODE: i32 = 7;

    /// How long the parent waits for the panicking-stage child before it fails the test.
    const CHILD_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);

    /// An exit hook that panics, standing in for any panicking pre-exit stage.
    fn panicking_exit_hook() {
        panic!("a pre-exit stage panicked");
    }

    /// A panicking pre-exit stage cannot cancel the exit it precedes.
    ///
    /// Runs [`panicking_stage_child`] as a child process of this test binary,
    /// so its process-wide hook and its exit stay out of this process. A panic
    /// that unwinds out of `exit_process` fails the child's test, which ends the
    /// child with the test harness's failure code instead of the one asked for.
    #[allow(clippy::expect_used)] // test harness: a test binary that cannot re-run itself is an environment issue
    #[test]
    fn a_panicking_pre_exit_stage_still_ends_the_process() {
        let module = module_path!();
        let module = module.split_once("::").map_or(module, |(_, rest)| rest);
        let filter = format!("{module}::panicking_stage_child");
        let exe = std::env::current_exe().expect("the test binary");
        let mut child = std::process::Command::new(exe)
            .args([
                "--exact",
                filter.as_str(),
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("start the panicking-stage child");
        let started = std::time::Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().expect("poll the panicking-stage child") {
                break Some(status);
            }
            if started.elapsed() > CHILD_LIMIT {
                let _ = child.kill();
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        let out = child
            .wait_with_output()
            .expect("collect the child's output");
        let stdout = String::from_utf8(out.stdout).unwrap_or_default();
        let stderr = String::from_utf8(out.stderr).unwrap_or_default();
        assert!(
            status.is_some_and(|s| s.code() == Some(PANICKING_STAGE_EXIT_CODE)),
            "a panicking pre-exit stage cancelled the exit ({status:?}):\n{stdout}\n{stderr}"
        );
    }

    /// The child half of `a_panicking_pre_exit_stage_still_ends_the_process`.
    ///
    /// Ignored so it runs only as that test's child.
    #[ignore = "run as a child process by a_panicking_pre_exit_stage_still_ends_the_process"]
    #[test]
    fn panicking_stage_child() {
        register_exit_hook(panicking_exit_hook);
        super::exit_process(PANICKING_STAGE_EXIT_CODE);
    }

    #[test]
    fn exit_hook_runs_and_is_safe_without_registration() {
        // No hook registered yet → run_exit_hook must be a safe no-op (the common
        // CLI / server / non-TUI case — System.exit must not require a hook).
        run_exit_hook();
        // Register one and confirm it runs (the Ipe.Tui driver registers its
        // terminal-restore here so a System.exit quit doesn't bypass cleanup).
        register_exit_hook(bump);
        run_exit_hook();
        assert!(
            CALLS.load(Ordering::SeqCst) >= 1,
            "registered exit hook must run"
        );
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod gutter_line_tests {
    use super::gutter_line;

    #[test]
    fn indents_only_under_a_terminal() {
        // Terminal stderr → 4-space gutter for the human dev loop (nests under
        // the CLI's own `[ipe dev watch] ...` status lines).
        assert_eq!(
            gutter_line("[ipe.http.server] listening on http://127.0.0.1:8000", true),
            "    [ipe.http.server] listening on http://127.0.0.1:8000"
        );
        // Piped/redirected stderr (the E2E harness reads through a pipe) stays
        // flush-left so `contains("[ipe.http.server] listening on")` matchers hold.
        assert_eq!(
            gutter_line(
                "[ipe.http.server] listening on http://127.0.0.1:8000",
                false
            ),
            "[ipe.http.server] listening on http://127.0.0.1:8000"
        );
    }
}

/// Drift guard for the "every `[ipe.<tag>] ...` runtime log line goes through
/// one emitter" invariant: `emit_runtime_log`/`format_runtime_log` above are
/// meant to be the ONLY place that ever constructs the `"[ipe.<tag>]"` prefix.
/// A hand-rolled `eprintln!`/`println!`/`writeln!` carrying that literal
/// bypasses `gutter_line`'s terminal-indent handling, so this scans every
/// `.rs` file under the runtime crate's `src/` (this file excepted — it IS the
/// emitter) and fails if any such macro invocation still carries one. Styled
/// after `install_style_drift.rs`'s script-scanning drift tests: a plain
/// substring/window scan, not a real parser, is enough to catch the class of
/// regression (a new call site hand-rolling the tag) without reimplementing a
/// Rust parser.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod runtime_log_emitter_tests {
    use std::path::{Path, PathBuf};

    /// Walk `dir` collecting every `.rs` file, skipping `system.rs` (the
    /// sanctioned construction site) so the scan only sees call sites that
    /// must route through `emit_runtime_log`.
    fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("could not read dir {}: {e}", dir.display()));
        for entry in entries {
            let entry = entry.expect("readable dir entry");
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, out);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            if path.file_name().and_then(|f| f.to_str()) == Some("system.rs") {
                continue;
            }
            out.push(path);
        }
    }

    /// True when a `"[ipe.` literal appears within a short window after an
    /// `eprintln!`/`println!`/`writeln!` invocation in `content` — wide enough
    /// to span a realistic multi-line macro call, narrow enough not to bleed
    /// into an unrelated later macro call.
    fn has_hand_rolled_tag(content: &str) -> bool {
        for macro_name in ["eprintln!", "println!", "writeln!"] {
            let mut rest = content;
            while let Some(rel) = rest.find(macro_name) {
                let tail = rest.get(rel..).unwrap_or_default();
                let window_end = tail.char_indices().nth(400).map_or(tail.len(), |(i, _)| i);
                if tail
                    .get(..window_end)
                    .unwrap_or_default()
                    .contains("\"[ipe.")
                {
                    return true;
                }
                rest = tail.get(macro_name.len()..).unwrap_or_default();
            }
        }
        false
    }

    #[test]
    fn tag_scan_window_is_char_boundary_safe() {
        let multibyte = "\u{e9}".repeat(500);
        assert!(!has_hand_rolled_tag(&format!("eprintln!({multibyte})")));
        assert!(has_hand_rolled_tag(&format!(
            "\u{e9}eprintln!(\"[ipe.x] {multibyte}\")"
        )));
    }

    #[test]
    fn no_runtime_module_hand_rolls_an_ipe_tagged_log_line() {
        let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rs_files(&src_dir, &mut files);
        assert!(
            files.len() > 10,
            "sanity: expected to scan more than 10 files under {}, found {}",
            src_dir.display(),
            files.len()
        );

        let mut violations = Vec::new();
        for path in &files {
            let content = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));
            if has_hand_rolled_tag(&content) {
                violations.push(path.display().to_string());
            }
        }
        assert!(
            violations.is_empty(),
            "found `eprintln!`/`println!`/`writeln!` hand-rolling an `[ipe.<tag>]` \
             prefix outside system.rs — route through `crate::system::emit_runtime_log` \
             (or `crate::system::emit_runtime_log_stamped` for a timestamped line) instead:\n{}",
            violations.join("\n")
        );
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod scrub_log_controls_tests {
    use super::{runtime_log_line, scrub_log_controls};

    #[test]
    fn escapes_newline_esc_del_and_c1() {
        let out = scrub_log_controls("a\nb\r\x1b[2J\x7f\u{9b}\u{85}\0c\td");
        assert_eq!(out, "a\\nb\\r\\u{1b}[2J\\u{7f}\\u{9b}\\u{85}\\u{0}c\\td");
        assert!(
            !out.chars().any(char::is_control),
            "control survived: {out:?}"
        );
    }

    #[test]
    fn escapes_unicode_line_separators_and_bidi_controls() {
        let out = scrub_log_controls(
            "a\u{2028}b\u{2029}c\u{202e}d\u{2066}e\u{2069}f\u{200f}g\u{61c}h\u{202a}i",
        );
        assert_eq!(
            out,
            "a\\u{2028}b\\u{2029}c\\u{202e}d\\u{2066}e\\u{2069}f\\u{200f}g\\u{61c}h\\u{202a}i"
        );
        assert!(
            !out.chars().any(super::is_log_hazard),
            "hazard survived: {out:?}"
        );
    }

    #[test]
    fn printable_neighbours_stay_borrowed() {
        // One step past a format range, and a variation selector (`Mn`, not
        // `Cf`), stay verbatim.
        assert!(matches!(
            scrub_log_controls("\u{202f}\u{2070}\u{2027}\u{E0100}"),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    #[test]
    fn escapes_zero_width_tag_and_soft_hyphen() {
        let out = scrub_log_controls("adm\u{200B}in\u{E0041}\u{AD}\u{2060}\u{FEFF}");
        assert_eq!(out, "adm\\u{200b}in\\u{e0041}\\u{ad}\\u{2060}\\u{feff}");
    }

    #[test]
    fn log_format_hazards_equal_the_terminal_set() {
        assert_eq!(
            super::LOG_FORMAT_HAZARDS,
            ipe_diagnostics::terminal::DENIED_FORMAT_CHARS
        );
    }

    /// Every scalar value: the runtime predicate is the compiler's terminal set.
    #[test]
    fn is_log_hazard_is_the_terminal_set_for_every_char() {
        for c in (0..=u32::from(char::MAX)).filter_map(char::from_u32) {
            let terminal = ipe_diagnostics::terminal::is_display_hazard(c);
            assert_eq!(super::is_log_hazard(c), terminal, "U+{:04X}", u32::from(c));
        }
    }

    #[test]
    #[allow(clippy::expect_used)] // a malformed fixture fails the test
    fn log_hazard_fixture_matches_the_table() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/log_hazard_ranges.json"))
                .expect("fixture is JSON");
        let rows = fixture.as_array().expect("fixture is an array");
        let parsed: Vec<(u64, u64)> = rows
            .iter()
            .map(|row| {
                (
                    row.get("lo")
                        .and_then(serde_json::Value::as_u64)
                        .expect("lo"),
                    row.get("hi")
                        .and_then(serde_json::Value::as_u64)
                        .expect("hi"),
                )
            })
            .collect();
        let expected: Vec<(u64, u64)> = [(0, 31), (127, 159)]
            .into_iter()
            .chain(super::LOG_FORMAT_HAZARDS.iter().map(|range| {
                (
                    u64::from(u32::from(*range.start())),
                    u64::from(u32::from(*range.end())),
                )
            }))
            .collect();
        assert_eq!(parsed, expected);
    }

    /// Inverse of the scrub, for the injectivity proof: `\\`, `\n`, `\r`, `\t`, `\u{h}`.
    fn unscrub(s: &str) -> Option<String> {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match chars.next()? {
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    if chars.next()? != '{' {
                        return None;
                    }
                    let hex: String = chars.by_ref().take_while(|&h| h != '}').collect();
                    out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                }
                _ => return None,
            }
        }
        Some(out)
    }

    #[test]
    fn backslash_is_escaped_so_distinct_inputs_never_print_alike() {
        assert_ne!(
            scrub_log_controls("a\\u{200b}"),
            scrub_log_controls("a\u{200b}")
        );
        assert_ne!(scrub_log_controls("a\\nb"), scrub_log_controls("a\nb"));
        let path = scrub_log_controls("C:\\x");
        assert!(matches!(path, std::borrow::Cow::Owned(_)), "{path:?}");
        assert_eq!(path, "C:\\\\x");
    }

    #[test]
    fn scrub_output_decodes_back_to_its_input() {
        for input in [
            "a\nb\r\x1b[2J\x7f\u{9b}\u{85}\0c\td",
            "a\u{2028}b\u{2029}c\u{202e}d\u{2066}e\u{2069}f\u{200f}g\u{61c}h\u{202a}i",
            "adm\u{200B}in\u{E0041}\u{AD}\u{2060}\u{FEFF}",
            "GET /caf\u{e9} 200 3ms",
            "a\\u{200b}",
            "a\u{200b}",
            "C:\\x\\\\y\\",
        ] {
            let out = scrub_log_controls(input);
            assert_eq!(unscrub(&out).as_deref(), Some(input), "{out:?}");
        }
    }

    /// The cap bounds the escaped output, cuts on a whole escape, and marks the cut.
    #[test]
    fn capped_scrub_is_visible_bounded_and_marks_the_cut() {
        use super::{SCRUB_TRUNCATED, scrub_log_controls_capped};
        assert_ne!(
            scrub_log_controls_capped("/adm\u{200b}in", 256),
            scrub_log_controls_capped("/admin", 256)
        );
        assert_eq!(
            scrub_log_controls_capped("/adm\u{200b}in", 256),
            "/adm\\u{200b}in"
        );
        assert_eq!(scrub_log_controls_capped("/admin", 256), "/admin");
        // A cut never splits an escape and never passes for an uncut record.
        let cut = scrub_log_controls_capped("abc\u{e0041}", 8);
        assert_eq!(cut, format!("abc{SCRUB_TRUNCATED}"));
        assert_ne!(cut, scrub_log_controls_capped("abc\\…", 64));
        assert_eq!(unscrub("abc\\…"), None);
        for input in ["\u{202e}".repeat(100), "\\".repeat(300), "é".repeat(300)] {
            let out = scrub_log_controls_capped(&input, 256);
            assert!(out.len() <= 256 + SCRUB_TRUNCATED.len(), "{}", out.len());
            assert!(out.ends_with(SCRUB_TRUNCATED), "{out:?}");
            let kept = out.strip_suffix(SCRUB_TRUNCATED).unwrap_or(&out);
            let decoded = unscrub(kept);
            assert!(
                decoded.as_deref().is_some_and(|d| input.starts_with(d)),
                "{out:?}"
            );
        }
        for input in ["GET /caf\u{e9}", "a\u{2028}b\u{200B}c\u{E0041}d", "C:\\x"] {
            let out = scrub_log_controls_capped(input, 256);
            assert_eq!(out, scrub_log_controls(input));
            assert_eq!(unscrub(&out).as_deref(), Some(input));
        }
    }

    #[test]
    fn clean_text_is_borrowed_unchanged() {
        let out = scrub_log_controls("GET /caf\u{e9} 200 3ms");
        assert!(matches!(
            out,
            std::borrow::Cow::Borrowed("GET /caf\u{e9} 200 3ms")
        ));
    }

    #[test]
    fn emitted_line_cannot_forge_a_second_record() {
        let line = runtime_log_line(None, "http", "GET /x\r\n[ipe.http] forged\x1b[31m");
        assert!(
            !line.chars().any(super::is_log_hazard),
            "control survived: {line:?}"
        );
        assert_eq!(
            line.trim_start(),
            "[ipe.http] GET /x\\r\\n[ipe.http] forged\\u{1b}[31m"
        );
    }
}

#[cfg(all(test, feature = "web", feature = "http_client"))]
mod home_dir_tests {
    use super::home_dir_from_var;
    use std::env::VarError;

    // Shared with `ipe_sandbox::home`'s `tests` module: the same
    // `(raw, expected)` rows drive both crates' home readers.
    include!("../tests/data/home_cases.rs");

    #[test]
    fn every_home_parse_case_matches_the_shared_table() {
        for (raw, expected) in HOME_PARSE_CASES.iter().chain(HOME_PARSE_PLATFORM_CASES) {
            assert_eq!(
                home_dir_from_var(raw.map(str::to_owned).ok_or(VarError::NotPresent))
                    .ok()
                    .map(|home| home.as_path().to_path_buf()),
                expected.map(std::path::PathBuf::from),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn each_refused_home_names_its_reason() {
        for (raw, refusal) in HOME_REFUSAL_CASES.iter().chain(HOME_REFUSAL_PLATFORM_CASES) {
            assert_eq!(
                home_dir_from_var(raw.map(str::to_owned).ok_or(VarError::NotPresent)),
                Err(*refusal),
                "{raw:?}"
            );
        }
        assert_eq!(
            home_dir_from_var(Err(VarError::NotPresent)),
            Err(HomeRefusal::Unset)
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_non_utf8_home_value_is_refused() {
        use std::os::unix::ffi::OsStringExt as _;
        let raw = std::ffi::OsString::from_vec(b"/home/\xff".to_vec());
        assert_eq!(
            home_dir_from_var(Err(VarError::NotUnicode(raw))),
            Err(HomeRefusal::NotUtf8)
        );
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod parent_death_floor_tests {
    use super::{
        NamedSet, SpawnJob, SpawnRefusal, run_spawn_jobs, spawn_hardened, spawn_hardened_on,
    };
    use std::time::Duration;

    /// The floor installs a fork-time `pre_exec` (Linux `PR_SET_PDEATHSIG`); a
    /// child spawned through the spawner must still spawn and run normally — the
    /// prctl is async-signal-safe and best-effort, so it can never break the
    /// spawn.
    #[cfg(unix)]
    #[test]
    fn hardened_child_still_spawns_and_runs() {
        let mut child = spawn_hardened(std::process::Command::new("/bin/true"))
            .expect("hardened child must spawn");
        let status = child.wait().expect("reap hardened /bin/true");
        assert!(status.success(), "hardened /bin/true must exit 0");
    }

    /// A spawn the OS refuses surfaces as `SpawnRefusal::Spawn` carrying the OS
    /// error, which converts back to that same `io::Error` kind.
    #[test]
    fn an_os_refused_spawn_is_a_spawn_refusal() {
        let refused = spawn_hardened(std::process::Command::new("/nonexistent/ipe-spawn-probe"));
        let kind = match &refused {
            Err(SpawnRefusal::Spawn(e)) => Some(e.kind()),
            _ => None,
        };
        assert_eq!(kind, Some(std::io::ErrorKind::NotFound), "{refused:?}");
        let io = std::io::Error::from(SpawnRefusal::Spawn(std::io::ErrorKind::NotFound.into()));
        assert_eq!(io.kind(), std::io::ErrorKind::NotFound);
        let gone = std::io::Error::from(SpawnRefusal::SpawnerGone);
        assert_eq!(gone.kind(), std::io::ErrorKind::Other);
    }

    /// A spawner whose queue is gone refuses the request and forks nothing: no
    /// unhardened fallback runs the command.
    #[cfg(unix)]
    #[test]
    fn a_gone_spawner_refuses_and_never_spawns() {
        let (jobs, queue) = std::sync::mpsc::sync_channel::<SpawnJob>(1);
        drop(queue);
        let marker = crate::scratch_core::test_temp_root()
            .join(format!("ipe-spawner-gone-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c").arg(": > \"$1\"").arg("sh").arg(&marker);
        let refused = spawn_hardened_on(&jobs, Duration::from_secs(5), cmd, NamedSet::default());
        assert!(
            matches!(refused, Err(SpawnRefusal::SpawnerGone)),
            "{refused:?}"
        );
        assert!(
            !marker.exists(),
            "a refused spawn must never run the command"
        );
    }

    /// A request that finds the spawner queue still full at its ceiling is
    /// refused and forks nothing.
    #[cfg(unix)]
    #[test]
    fn a_full_queue_past_the_ceiling_refuses_and_never_spawns() {
        let (jobs, _queue) = std::sync::mpsc::sync_channel::<SpawnJob>(0);
        let marker = crate::scratch_core::test_temp_root()
            .join(format!("ipe-spawner-full-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c").arg(": > \"$1\"").arg("sh").arg(&marker);
        let refused = spawn_hardened_on(&jobs, Duration::ZERO, cmd, NamedSet::default());
        assert!(
            matches!(refused, Err(SpawnRefusal::ReplyTimedOut)),
            "{refused:?}"
        );
        assert!(
            !marker.exists(),
            "a refused spawn must never run the command"
        );
    }

    /// Unwinds out of a spawn job, the way a panicking job would.
    fn unwinding_job() {
        std::panic::resume_unwind(Box::new(()));
    }

    /// A job that panics leaves the spawner running the jobs after it.
    #[test]
    fn a_panicking_job_does_not_stop_the_spawner() {
        let (jobs, queue) = std::sync::mpsc::sync_channel::<SpawnJob>(2);
        let (ran, seen) = std::sync::mpsc::channel::<()>();
        jobs.send(Box::new(unwinding_job))
            .expect("queue the unwinding job");
        jobs.send(Box::new(move || {
            let _ = ran.send(());
        }))
        .expect("queue the next job");
        drop(jobs);
        let runner = std::thread::Builder::new()
            .spawn(move || run_spawn_jobs(&queue))
            .expect("spawn test thread");
        let next = seen.recv_timeout(Duration::from_secs(10));
        runner.join().expect("the spawner loop must not unwind");
        assert_eq!(next, Ok(()), "the job after an unwind must still run");
    }

    /// A spawn that panics on the spawner is refused as `SpawnPanicked`, never
    /// relabelled `SpawnerGone`, and the spawner runs the next request.
    #[test]
    fn a_panicking_spawn_is_refused_as_spawn_panicked() {
        use super::request_spawn;
        let (jobs, queue) = std::sync::mpsc::sync_channel::<SpawnJob>(1);
        let runner = std::thread::Builder::new()
            .spawn(move || run_spawn_jobs(&queue))
            .expect("spawn test thread");
        let refused = request_spawn(
            &jobs,
            Duration::from_secs(10),
            || -> Result<(), SpawnRefusal> { std::panic::resume_unwind(Box::new(())) },
            |(): ()| {},
        );
        let next = request_spawn(&jobs, Duration::from_secs(10), || Ok(()), |(): ()| {});
        drop(jobs);
        runner.join().expect("the spawner loop must not unwind");
        assert!(
            matches!(refused, Err(SpawnRefusal::SpawnPanicked)),
            "{refused:?}"
        );
        assert!(next.is_ok(), "{next:?}");
    }

    /// A tokio runtime without its IO driver is refused before the fork.
    ///
    /// The refusal is `ProbePanicked`, which only the pre-fork probe yields
    /// (without it tokio panics after the fork, as `SpawnPanicked`). The command
    /// would hold a pipe's only other write end: the pipe reaches EOF with no
    /// byte written, so no child ever ran, and it does so once the spawner has
    /// dropped the command, with no timing race.
    #[cfg(all(feature = "web", unix))]
    #[test]
    fn a_runtime_without_io_refuses_before_forking() {
        use super::spawn_hardened_tokio;
        use std::io::Read as _;
        let (mut reader, writer) = std::io::pipe().expect("pipe");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let mut cmd = tokio::process::Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("echo forked")
            .stdout(writer)
            .kill_on_drop(true);
        let refused = rt.block_on(async { spawn_hardened_tokio(cmd) });
        assert!(
            matches!(refused, Err(SpawnRefusal::ProbePanicked)),
            "{refused:?}"
        );
        let (drained, eof) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .spawn(move || {
                let mut out = Vec::new();
                let _ = drained.send(reader.read_to_end(&mut out).map(|_| out));
            })
            .expect("spawn test thread");
        let written = eof.recv_timeout(Duration::from_secs(10));
        assert!(
            matches!(&written, Ok(Ok(out)) if out.is_empty()),
            "a refused spawn must never run the command: {written:?}"
        );
    }

    /// A spawner that drops a request without answering it is reported gone.
    #[cfg(unix)]
    #[test]
    fn a_dropped_request_is_reported_gone() {
        let (jobs, queue) = std::sync::mpsc::sync_channel::<SpawnJob>(1);
        let dropper = std::thread::Builder::new()
            .spawn(move || drop(queue.recv()))
            .expect("spawn test thread");
        let refused = spawn_hardened_on(
            &jobs,
            Duration::from_secs(5),
            std::process::Command::new("/bin/true"),
            NamedSet::default(),
        );
        dropper.join().expect("dropper thread");
        assert!(
            matches!(refused, Err(SpawnRefusal::SpawnerGone)),
            "{refused:?}"
        );
    }

    /// A request abandoned past its ceiling is refused, and the child the
    /// spawner forks for it afterwards is killed and reaped rather than left
    /// running: the pipe the child holds reaches EOF long before the child's
    /// own 30s sleep would end.
    #[cfg(unix)]
    #[test]
    fn a_lost_reply_kills_and_reaps_the_child() {
        use std::io::Read as _;
        let (jobs, queue) = std::sync::mpsc::sync_channel::<SpawnJob>(1);
        let (mut reader, writer) = std::io::pipe().expect("pipe");
        let mut cmd = std::process::Command::new("/bin/sleep");
        cmd.arg("30").stdout(writer);
        let refused = spawn_hardened_on(&jobs, Duration::ZERO, cmd, NamedSet::default());
        assert!(
            matches!(refused, Err(SpawnRefusal::ReplyTimedOut)),
            "{refused:?}"
        );
        let job = queue.recv().expect("the abandoned request stays queued");
        let started = std::time::Instant::now();
        job();
        let mut drained = Vec::new();
        reader.read_to_end(&mut drained).expect("read to EOF");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the abandoned child must be killed, not left to run"
        );
    }

    /// A child reparented before it armed the signal (its launcher died in the
    /// fork-to-`prctl` window) is refused; one still parented by the launcher
    /// proceeds.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_reparented_child_is_refused() {
        use super::still_parented_by;
        let launcher = rustix::process::getpid();
        assert!(still_parented_by(launcher, Some(launcher)).is_ok());
        // Above every kernel `pid_max`, so never the launcher's own pid.
        let other = rustix::process::Pid::from_raw(i32::MAX).expect("positive pid");
        let refused = still_parented_by(launcher, Some(other)).map_err(|e| e.raw_os_error());
        assert_eq!(refused, Err(Some(rustix::io::Errno::SRCH.raw_os_error())));
        assert!(still_parented_by(launcher, None).is_err());
    }
}

#[cfg(test)]
#[cfg(unix)]
mod descriptor_floor_tests {
    use super::{
        DESCRIPTOR_PROBE_CEILING, FD_NAME_LEN, NAMED_FD_CAP, NamedFdRefusal, NamedFds, admit_named,
        descriptor_probe_bound, fd_name, parse_fd_number,
    };

    /// Open `/dev/null`, close-on-exec or inheritable.
    fn dev_null(cloexec: bool) -> std::os::fd::OwnedFd {
        use rustix::fs::{Mode, OFlags};
        let flags = if cloexec {
            OFlags::RDONLY | OFlags::CLOEXEC
        } else {
            OFlags::RDONLY
        };
        rustix::fs::open(c"/dev/null", flags, Mode::empty()).expect("open /dev/null")
    }

    /// A stdio number, an inheritable descriptor and a full set are each refused,
    /// and the refused descriptor is handed back open.
    #[test]
    fn named_fds_refuse_stdio_inheritable_and_full() {
        use std::os::fd::AsRawFd as _;
        assert!(matches!(
            admit_named(1, rustix::io::FdFlags::CLOEXEC),
            Err(NamedFdRefusal::Stdio)
        ));
        let mut named = NamedFds::none();
        let inheritable = dev_null(false);
        let raw = inheritable.as_raw_fd();
        let refused = named.push(inheritable);
        assert!(
            matches!(&refused, Err((NamedFdRefusal::Inheritable, back)) if back.as_raw_fd() == raw),
            "{refused:?}"
        );
        for _ in 0..NAMED_FD_CAP {
            assert!(named.push(dev_null(true)).is_ok());
        }
        let refused = named.push(dev_null(true));
        assert!(
            matches!(refused, Err((NamedFdRefusal::Full, _))),
            "{refused:?}"
        );
    }

    /// A directory that does not list this process's own descriptors is refused.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "macos"
    ))]
    #[test]
    fn a_static_directory_is_not_a_descriptor_listing() {
        use super::open_descriptor_listing_at;
        assert!(open_descriptor_listing_at(c"/").is_err());
        assert!(open_descriptor_listing_at(c"/nonexistent/ipe-fd-listing").is_err());
        assert!(super::open_descriptor_listing().is_ok());
    }

    /// Only a whole, in-range decimal number names a descriptor.
    #[test]
    fn only_a_decimal_number_names_a_descriptor() {
        assert_eq!(parse_fd_number(b"0"), Some(0));
        assert_eq!(parse_fd_number(b"2147483647"), Some(i32::MAX));
        assert_eq!(parse_fd_number(b""), None);
        assert_eq!(parse_fd_number(b"."), None);
        assert_eq!(parse_fd_number(b"3a"), None);
        assert_eq!(parse_fd_number(b"-3"), None);
        assert_eq!(parse_fd_number(b"2147483648"), None);
    }

    /// A descriptor number's listing name is its decimal digits.
    #[test]
    fn a_listing_name_round_trips() {
        for n in [0, 3, 10, 1023, i32::MAX] {
            let mut buf = [0_u8; FD_NAME_LEN];
            let name = fd_name(n, &mut buf).expect("non-negative number");
            assert_eq!(parse_fd_number(name.to_bytes()), Some(n));
        }
        let mut buf = [0_u8; FD_NAME_LEN];
        assert!(fd_name(-1, &mut buf).is_none());
    }

    /// The probe walks the finite hard limit, else the soft one, and refuses past the ceiling.
    #[test]
    fn the_probe_bound_refuses_past_its_ceiling() {
        let past = DESCRIPTOR_PROBE_CEILING + 1;
        assert_eq!(descriptor_probe_bound(Some(256), Some(4096)), Some(4096));
        assert_eq!(descriptor_probe_bound(Some(256), None), Some(256));
        assert_eq!(descriptor_probe_bound(Some(256), Some(past)), Some(256));
        assert_eq!(descriptor_probe_bound(None, None), None);
        assert_eq!(descriptor_probe_bound(Some(past), Some(past)), None);
    }
}

#[cfg(all(test, feature = "server"))]
mod listen_port_tests {
    use super::{PortOrigin, ResolvedPort, resolve_listen_port};
    use crate::telemetry::BuildPosture;

    /// Every value that is not a bindable `1..=65535` port.
    const GARBAGE: [&str; 15] = [
        "",
        "abc",
        "80a0",
        " ",
        "-",
        "+8080",
        "+0",
        "+",
        " 8080",
        "8080 ",
        "0",
        "-1",
        "65536",
        "70000",
        "99999999999",
    ];
    const OPERATOR_VARS: [&str; 2] = ["IPE_WEB_PORT", "IPE_SERVER_PORT"];

    fn resolve(
        relocation: Option<&str>,
        var: &'static str,
        operator: Option<&str>,
    ) -> ResolvedPort {
        resolve_listen_port(
            relocation.map(str::to_owned),
            (var, operator.map(str::to_owned)),
            8000,
        )
    }

    #[test]
    fn garbage_operator_value_falls_back_to_the_source_port() {
        for var in OPERATOR_VARS {
            for garbage in GARBAGE {
                let r = resolve(None, var, Some(garbage));
                assert_eq!(
                    (r.port, r.origin),
                    (8000, PortOrigin::Source),
                    "{var}={garbage:?} must fall back to the source port, never bind 0"
                );
            }
        }
    }

    #[test]
    fn relocation_outranks_a_valid_operator_value() {
        for var in OPERATOR_VARS {
            let r = resolve(Some("9100"), var, Some("9200"));
            assert_eq!((r.port, r.origin), (9100, PortOrigin::Relocated), "{var}");
        }
    }

    #[test]
    fn garbage_relocation_falls_through_to_operator_then_source() {
        for var in OPERATOR_VARS {
            for garbage in GARBAGE {
                let r = resolve(Some(garbage), var, Some("9200"));
                assert_eq!(
                    (r.port, r.origin, r.operator_var),
                    (9200, PortOrigin::Operator, var),
                    "relocation {garbage:?} must fall through to {var}"
                );
                let r = resolve(Some(garbage), var, None);
                assert_eq!(
                    (r.port, r.origin),
                    (8000, PortOrigin::Source),
                    "relocation {garbage:?} over no operator value must give the source port"
                );
            }
        }
    }

    #[test]
    fn absent_layers_give_the_source_and_port_bounds_are_accepted() {
        for var in OPERATOR_VARS {
            let r = resolve(None, var, None);
            assert_eq!((r.port, r.origin), (8000, PortOrigin::Source), "{var}");
            for edge in [("1", 1), ("65535", 65535)] {
                let r = resolve(Some(edge.0), var, None);
                assert_eq!((r.port, r.origin), (edge.1, PortOrigin::Relocated), "{var}");
                let r = resolve(None, var, Some(edge.0));
                assert_eq!((r.port, r.origin), (edge.1, PortOrigin::Operator), "{var}");
            }
        }
    }

    /// The message of an `AddrInUse` bind refusal under `posture`.
    fn in_use_message(r: ResolvedPort, posture: BuildPosture) -> String {
        crate::ipe_error_message(r.bind_refusal_for(
            posture,
            "listen",
            std::net::SocketAddr::from(([127, 0, 0, 1], 8000)),
            &std::io::Error::from(std::io::ErrorKind::AddrInUse),
        ))
    }

    #[test]
    fn relocated_bind_failure_advises_no_operator_var() {
        for var in OPERATOR_VARS {
            for posture in [BuildPosture::Development, BuildPosture::Release] {
                let msg = in_use_message(resolve(Some("9100"), var, Some("9200")), posture);
                assert!(
                    OPERATOR_VARS.iter().all(|v| !msg.contains(v)),
                    "a supervisor-chosen port must not advise an operator var: {msg}"
                );
                assert!(msg.contains("9100") && msg.contains("supervisor"), "{msg}");
            }
        }
    }

    #[test]
    fn operator_and_source_bind_failure_names_the_runtime_var() {
        for var in OPERATOR_VARS {
            for r in [resolve(None, var, Some("9200")), resolve(None, var, None)] {
                for (posture, launch) in [
                    (BuildPosture::Development, "ipe dev run"),
                    (BuildPosture::Release, "./<program>"),
                ] {
                    let msg = in_use_message(r, posture);
                    assert!(
                        msg.contains(&format!("{var}=8123 {launch}")),
                        "the advice must name {var} and how {posture:?} starts: {msg}"
                    );
                    assert!(
                        OPERATOR_VARS.iter().filter(|v| msg.contains(*v)).count() == 1,
                        "the advice names only this runtime's var: {msg}"
                    );
                }
                let release = in_use_message(r, BuildPosture::Release);
                assert!(
                    !release.contains("ipe dev"),
                    "a release binary is not started by `ipe dev run`: {release}"
                );
            }
        }
    }

    /// `bind_refusal` gives the refusal of the compiled posture.
    #[test]
    fn bind_refusal_follows_the_compiled_posture() {
        for var in OPERATOR_VARS {
            let r = resolve(None, var, None);
            let compiled = crate::ipe_error_message(r.bind_refusal(
                "listen",
                std::net::SocketAddr::from(([127, 0, 0, 1], 8000)),
                &std::io::Error::from(std::io::ErrorKind::AddrInUse),
            ));
            assert_eq!(compiled, in_use_message(r, BuildPosture::COMPILED));
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod env_overlay_tests {
    use super::*;

    /// A `Process.*` child never inherits the supervisor's relocation var: the
    /// built command removes it even when the overlay sets it.
    #[test]
    fn process_child_env_drops_the_listen_port_relocation_var() {
        let relocation = crate::LISTEN_PORT_RELOCATION_ENV;
        for directives in [
            vec![(relocation.to_owned(), Some("9100".to_owned()))],
            vec![("OVERLAY_TEST_KEEP".to_owned(), Some("1".to_owned()))],
            Vec::new(),
        ] {
            let mut cmd = std::process::Command::new("true");
            apply_env_directives(&mut cmd, directives);
            let entry = cmd
                .get_envs()
                .find(|(k, _)| *k == std::ffi::OsStr::new(relocation));
            assert!(
                matches!(entry, Some((_, None))),
                "the relocation var must be removed from a Process child: {entry:?}"
            );
        }
        let mut cmd = std::process::Command::new("true");
        apply_env_directives(
            &mut cmd,
            vec![("OVERLAY_TEST_KEEP".to_owned(), Some("1".to_owned()))],
        );
        assert!(
            cmd.get_envs()
                .any(|(k, v)| k == "OVERLAY_TEST_KEEP" && v == Some(std::ffi::OsStr::new("1"))),
            "other overlay sets still reach the child"
        );
    }

    /// Overlay set is observed by the reader; a tombstone masks a value present
    /// in the real environ; an untouched key still defers to the real environ.
    /// Uses a process-unique key so parallel test binaries never collide.
    #[test]
    fn overlay_set_remove_and_passthrough() {
        let key = format!("IPE_OVERLAY_PROBE_{}", std::process::id());

        // Absent everywhere → the reader reports unset.
        assert!(read_env_var(&key).is_err(), "probe must start unset");

        // Overlay set is observed WITHOUT mutating the real environ.
        locked_set_var(&key, "value");
        assert_eq!(read_env_var(&key).as_deref(), Ok("value"));
        #[allow(clippy::disallowed_methods)] // the raw environ itself is under test
        let real = std::env::var_os(&key);
        assert!(
            real.is_none(),
            "the real environ must NOT be mutated by an Ipê env write"
        );

        // set-if-absent does not override an existing overlay value.
        locked_set_var_if_absent(&key, "other");
        assert_eq!(read_env_var(&key).as_deref(), Ok("value"));

        // A tombstone masks the overlay value (reads as unset).
        locked_remove_var(&key);
        assert!(read_env_var(&key).is_err(), "tombstone must mask the value");

        // Passthrough: a key never touched by the overlay reads through to the
        // real environ (PATH is present on every supported target).
        assert!(
            read_env_var("PATH").is_ok(),
            "an untouched key must defer to the real environ"
        );
    }

    /// Soundness core: an Ipê env write must NEVER mutate the real `environ`,
    /// because a concurrent libc reader (`getaddrinfo` via `to_socket_addrs`)
    /// walks `environ` under no lock we hold. This drives that exact concurrent
    /// composition — a writer thread hammering the overlay while a reader thread
    /// resolves addresses — and asserts the writes stayed OUT of the real
    /// environ. Under the pre-fix `set_var` design this same interleaving is the
    /// use-after-free the issue describes.
    #[test]
    fn concurrent_writes_never_touch_real_environ() {
        use std::net::ToSocketAddrs;

        let key = format!("IPE_OVERLAY_RACE_{}", std::process::id());
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let writer = {
            let key = key.clone();
            let stop = stop.clone();
            std::thread::Builder::new()
                .spawn(move || {
                    let mut i: u64 = 0;
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        locked_set_var(&key, &i.to_string());
                        locked_remove_var(&key);
                        i = i.wrapping_add(1);
                    }
                })
                .expect("spawn test thread")
        };

        let reader = std::thread::Builder::new()
            .spawn(move || {
                for _ in 0..200 {
                    // Exercises libc `getaddrinfo`, the unlocked `environ` reader.
                    let _ = "localhost:0".to_socket_addrs().map(Iterator::count);
                }
            })
            .expect("spawn test thread");

        let _ = reader.join();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = writer.join();

        #[allow(clippy::disallowed_methods)] // the raw environ itself is under test
        let real = std::env::var_os(&key);
        assert!(
            real.is_none(),
            "an Ipê env write leaked into the real environ — the environ-reader race is back"
        );
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod process_run_tests {
    use super::*;

    fn block<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    /// Functional correctness (independent of whether `run_blocking` takes the
    /// real `spawn_blocking` path or the no-tokio-feature fallback — both
    /// paths must return the same result).
    #[test]
    fn success_returns_combined_output() {
        let res: IpeResult<String, String> = block(process_run::<String>(
            "echo".to_string(),
            vec!["hello".to_string()],
        ));
        match res {
            IpeResult::Ok(s) => assert!(s.contains("hello"), "unexpected output: {s:?}"),
            IpeResult::Err(e) => panic!("unexpected Err: {e}"),
        }
    }

    #[test]
    fn nonexistent_binary_errs() {
        let res: IpeResult<String, String> = block(process_run::<String>(
            "ipe-does-not-exist-binary-xyz".to_string(),
            vec![],
        ));
        assert!(matches!(res, IpeResult::Err(_)));
    }

    #[test]
    fn nonzero_exit_errs() {
        let res: IpeResult<String, String> =
            block(process_run::<String>("false".to_string(), vec![]));
        assert!(matches!(res, IpeResult::Err(_)));
    }

    /// No-shell proof: an argument containing shell metacharacters is passed
    /// literally as an argv element, never evaluated by `sh -c`. `printf %s`
    /// echoes it verbatim; a shell would have run the `; touch <marker>` clause
    /// (creating the file) and would NOT echo the clause back verbatim.
    #[test]
    fn args_are_literal_no_shell_interpretation() {
        let marker = crate::scratch_core::test_temp_root()
            .join(format!("ipe_noshell_{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let payload = format!("; touch {} ; echo pwned", marker.display());
        let res: IpeResult<String, String> = block(process_run::<String>(
            "printf".to_string(),
            vec!["%s".to_string(), payload.clone()],
        ));
        let marker_created = marker.exists();
        let _ = std::fs::remove_file(&marker);
        match res {
            IpeResult::Ok(s) => {
                // The whole payload is echoed back verbatim (one argv element),
                // proving no `sh -c` split it on `;`.
                assert_eq!(s, payload, "argv must be passed literally (no shell)");
            }
            IpeResult::Err(e) => panic!("unexpected Err: {e}"),
        }
        assert!(
            !marker_created,
            "the `; touch` clause ran — argv was evaluated by a shell (injection)"
        );
    }

    /// Deadlock regression: a child that writes a LOT to BOTH stdout and stderr
    /// (each well past a 64 KiB pipe buffer) must complete, not wedge. The
    /// sequential stdout-then-stderr drain would deadlock here — the child
    /// blocks on a full stderr pipe while we drain stdout, and vice versa. The
    /// concurrent per-stream capture threads make this terminate.
    #[test]
    fn large_stdout_and_stderr_does_not_deadlock() {
        // `sh` is the program under test (invoked as an argv vector, not via
        // this kernel's own shell — there is none): it writes ~512 KiB to each
        // stream, far exceeding the ~64 KiB kernel pipe buffer.
        let script = "yes ABCDEFGH | head -c 524288; yes abcdefgh | head -c 524288 >&2";
        let res: IpeResult<String, String> = block(process_run::<String>(
            "sh".to_string(),
            vec!["-c".to_string(), script.to_string()],
        ));
        match res {
            IpeResult::Ok(s) => assert_eq!(
                s.len(),
                524288 * 2,
                "combined output must be both streams in full"
            ),
            IpeResult::Err(e) => panic!("large dual-stream output must not deadlock/err: {e}"),
        }
    }

    /// DoS guard: a subprocess whose combined output exceeds the capture
    /// ceiling must `Err`, never buffer it all and OOM the host, and never
    /// silently truncate a returned success value.
    #[test]
    fn output_over_ceiling_errs() {
        // The ceiling is passed explicitly (not via a process-global env var),
        // so this runs safely in parallel with any other subprocess test.
        let res: IpeResult<String, String> = block(process_run_with_cap::<String>(
            "printf".to_string(),
            vec!["%s".to_string(), "x".repeat(64)],
            8,
        ));
        assert!(
            matches!(res, IpeResult::Err(_)),
            "64 bytes of output under an 8-byte ceiling must Err, not OOM/truncate"
        );
    }

    /// Whether a live process's command line carries `marker`.
    #[cfg(target_os = "linux")]
    fn a_process_carries(marker: &str) -> bool {
        std::fs::read_dir("/proc").is_ok_and(|entries| {
            entries.filter_map(Result::ok).any(|entry| {
                std::fs::read(entry.path().join("cmdline")).is_ok_and(|cmdline| {
                    cmdline
                        .split(|b| *b == 0)
                        .any(|arg| arg == marker.as_bytes())
                })
            })
        })
    }

    /// A refused capture thread is an `Err`, and the child it would have
    /// drained is killed and reaped rather than left running.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_refused_capture_thread_errs_and_reaps_the_child() {
        let marker = format!("ipe-capture-refusal-probe-{}", std::process::id());
        let _refusing = crate::threads::refusal_hook::refuse(CAPTURE_THREAD);
        let args = [
            "-c".to_owned(),
            // A builtin-only loop: `sh` never forks, so no grandchild can carry
            // the marker past the kill.
            "while :; do :; done".to_owned(),
            marker.clone(),
        ];
        let refused = process_run_sync("sh", &args, 64);
        assert!(
            matches!(&refused, Err(e) if e.contains("capture thread refused")),
            "{:?}",
            refused.as_ref().err()
        );
        assert!(
            !a_process_carries(&marker),
            "the child of a refused capture must be killed and reaped"
        );
    }

    /// A blocking pool that cannot start a thread makes the Task fail as
    /// `Unavailable`, the retryable kind.
    #[cfg(feature = "tokio")]
    #[test]
    fn a_refused_offload_is_an_unavailable_task_error() {
        let _refusing = crate::threads::refusal_hook::refuse("Process");
        let res = block(process_run::<IpeError>("true".to_owned(), vec![]));
        assert!(
            matches!(
                res,
                IpeResult::Err(ref e) if crate::ipe_error_kind(e.clone()) == crate::IpeErrorKind::Unavailable
            ),
            "{res:?}"
        );
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod process_run_with_tests {
    use super::*;

    fn block<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    fn cfg(command: &str, args: &[&str]) -> ProcessRunWithCfg {
        ProcessRunWithCfg {
            command: command.to_owned(),
            args: args.iter().map(|s| s.to_string()).collect(),
            cwd: IpeMaybe::Nothing,
            env: Vec::new(),
        }
    }

    /// Non-zero exit is carried in `exitCode` — the Task succeeds.
    #[test]
    fn nonzero_exit_is_normal_result_not_task_failure() {
        let res: IpeResult<String, ProcessRunOutput> =
            block(process_run_with::<String>(cfg("false", &[])));
        match res {
            IpeResult::Ok(out) => {
                assert_ne!(out.exitCode, 0, "false must exit non-zero");
            }
            IpeResult::Err(e) => panic!("spawn failure not expected: {e}"),
        }
    }

    /// Successful command: exit 0, stdout captured.
    #[test]
    fn success_captures_stdout_and_exit_zero() {
        let res: IpeResult<String, ProcessRunOutput> =
            block(process_run_with::<String>(cfg("echo", &["hello"])));
        match res {
            IpeResult::Ok(out) => {
                assert_eq!(out.exitCode, 0);
                assert!(
                    out.stdout.contains("hello"),
                    "expected stdout: {:?}",
                    out.stdout
                );
                assert!(out.stderr.is_empty(), "unexpected stderr: {:?}", out.stderr);
            }
            IpeResult::Err(e) => panic!("unexpected error: {e}"),
        }
    }

    /// stderr is captured separately from stdout.
    #[test]
    fn stderr_captured_separately() {
        let res: IpeResult<String, ProcessRunOutput> = block(process_run_with::<String>(cfg(
            "sh",
            &["-c", "echo err >&2"],
        )));
        match res {
            IpeResult::Ok(out) => {
                assert!(out.stdout.is_empty(), "unexpected stdout: {:?}", out.stdout);
                assert!(
                    out.stderr.contains("err"),
                    "expected stderr: {:?}",
                    out.stderr
                );
            }
            IpeResult::Err(e) => panic!("unexpected error: {e}"),
        }
    }

    /// Spawn failure (non-existent binary) → Task.fail.
    #[test]
    fn nonexistent_binary_fails_task() {
        let res: IpeResult<String, ProcessRunOutput> = block(process_run_with::<String>(cfg(
            "ipe-does-not-exist-xyz",
            &[],
        )));
        assert!(matches!(res, IpeResult::Err(_)));
    }

    /// A cwd override is honoured: the child's own idea of its directory
    /// must echo the target.
    ///
    /// `cmd /C cd` on Windows, never `sh`/`pwd` — Git Bash's `sh` rewrites
    /// the native path through its own MSYS translation, so its `pwd`
    /// output would never match the native override we set and check.
    #[test]
    fn cwd_override_is_honoured() {
        let tmp = crate::scratch_core::test_temp_root();
        let tmp_str = tmp.to_string_lossy().into_owned();
        #[cfg(not(windows))]
        let mut c = cfg("sh", &["-c", "pwd"]);
        #[cfg(windows)]
        let mut c = cfg("cmd", &["/C", "cd"]);
        c.cwd = IpeMaybe::Just(tmp_str.clone());
        let res: IpeResult<String, ProcessRunOutput> = block(process_run_with::<String>(c));
        match res {
            IpeResult::Ok(out) => {
                let canonical_tmp = std::fs::canonicalize(&tmp)
                    .unwrap_or(tmp.clone())
                    .to_string_lossy()
                    .into_owned();
                let got = out.stdout.trim().to_owned();
                assert!(
                    got == canonical_tmp || got == tmp_str,
                    "pwd must report the overridden cwd; got {got:?}, expected {canonical_tmp:?}"
                );
            }
            IpeResult::Err(e) => panic!("unexpected error: {e}"),
        }
    }

    /// env override is passed to the child; parent env is also inherited.
    #[test]
    fn env_override_is_passed_to_child() {
        let marker = format!("ipe_run_with_probe_{}", std::process::id());
        let mut c = cfg("sh", &["-c", "echo $IPE_RUN_WITH_TEST_VAR"]);
        c.env = vec![("IPE_RUN_WITH_TEST_VAR".to_owned(), marker.clone())];
        let res: IpeResult<String, ProcessRunOutput> = block(process_run_with::<String>(c));
        match res {
            IpeResult::Ok(out) => {
                assert!(
                    out.stdout.contains(&marker),
                    "env override must be visible to child; got {:?}",
                    out.stdout
                );
            }
            IpeResult::Err(e) => panic!("unexpected error: {e}"),
        }
    }

    /// The ceiling applies per-stream; a stream that exceeds it fails the Task.
    #[test]
    fn per_stream_ceiling_is_enforced() {
        let c = ProcessRunWithCfg {
            command: "printf".to_owned(),
            args: vec!["%s".to_owned(), "x".repeat(64)],
            cwd: IpeMaybe::Nothing,
            env: Vec::new(),
        };
        // Swap command for a ceiling test via the internal cap-threaded helper.
        let _ = c; // used below via process_run_with_impl directly
        let res: IpeResult<String, ProcessRunOutput> = block(process_run_with_impl::<String>(
            ProcessRunWithCfg {
                command: "printf".to_owned(),
                args: vec!["%s".to_owned(), "x".repeat(64)],
                cwd: IpeMaybe::Nothing,
                env: Vec::new(),
            },
            8,
        ));
        assert!(
            matches!(res, IpeResult::Err(_)),
            "64-byte output under an 8-byte ceiling must fail"
        );
    }

    /// No-shell guard: a shell-metacharacter argument is passed verbatim.
    #[test]
    fn args_passed_literally_no_shell() {
        let payload = "; echo pwned".to_owned();
        let res: IpeResult<String, ProcessRunOutput> =
            block(process_run_with::<String>(cfg("printf", &["%s", &payload])));
        match res {
            IpeResult::Ok(out) => {
                assert_eq!(
                    out.stdout, payload,
                    "argv must be literal, not shell-interpreted"
                );
            }
            IpeResult::Err(e) => panic!("unexpected error: {e}"),
        }
    }
}

#[cfg(all(test, feature = "tokio", unix))]
mod process_run_in_pty_tests {
    use super::*;

    // Test-only runtime builder: a current-thread runtime cannot fail to build here.
    #[allow(clippy::unwrap_used)]
    fn block<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    fn pty_cfg(command: &str, args: &[&str]) -> ProcessRunInPtyCfg {
        ProcessRunInPtyCfg {
            command: command.to_owned(),
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            cwd: IpeMaybe::Nothing,
            env: Vec::new(),
            cols: 80,
            rows: 24,
        }
    }

    /// A child that checks `isatty(stdout)` reports "tty" under the pty. The
    /// same probe run under plain `Process.run` (piped stdio) reports "notty" —
    /// so the pty path really connects a terminal, not a pipe.
    #[test]
    fn child_sees_a_tty_under_pty_but_not_under_plain_run() {
        // `test -t 1` is true exactly when stdout is a terminal.
        let probe = "if [ -t 1 ]; then echo tty; else echo notty; fi";

        let pty_res: IpeResult<String, ProcessPtyOutput> =
            block(process_run_in_pty::<String>(pty_cfg("sh", &["-c", probe])));
        match pty_res {
            IpeResult::Ok(out) => assert!(
                out.output.contains("tty") && !out.output.contains("notty"),
                "child under a pty must see a tty; got {:?}",
                out.output
            ),
            IpeResult::Err(e) => panic!("pty run unexpectedly failed: {e}"),
        }

        let plain_res: IpeResult<String, String> = block(process_run::<String>(
            "sh".to_owned(),
            vec!["-c".to_owned(), probe.to_owned()],
        ));
        match plain_res {
            IpeResult::Ok(text) => assert!(
                text.contains("notty"),
                "child under piped stdio must NOT see a tty; got {text:?}"
            ),
            IpeResult::Err(e) => panic!("plain run unexpectedly failed: {e}"),
        }
    }

    /// Exit code propagates: a child that exits 7 surfaces `exitCode == 7`.
    #[test]
    fn exit_code_propagates() {
        let res: IpeResult<String, ProcessPtyOutput> = block(process_run_in_pty::<String>(
            pty_cfg("sh", &["-c", "exit 7"]),
        ));
        match res {
            IpeResult::Ok(out) => assert_eq!(out.exitCode, 7, "exit code must propagate"),
            IpeResult::Err(e) => panic!("pty run unexpectedly failed: {e}"),
        }
    }

    /// A flooding child hits the output ceiling and fails the Task — no
    /// unbounded allocation / OOM. Uses the internal cap-threaded helper so the
    /// test pins a small ceiling without touching the process-global env var.
    #[test]
    fn flooding_child_hits_the_output_cap() {
        let res: IpeResult<String, ProcessPtyOutput> = block(process_run_in_pty_impl::<String>(
            ProcessRunInPtyCfg {
                command: "sh".to_owned(),
                // Emit far more than the 8-byte ceiling below.
                args: vec!["-c".to_owned(), "printf 'x%.0s' $(seq 1 4096)".to_owned()],
                cwd: IpeMaybe::Nothing,
                env: Vec::new(),
                cols: 80,
                rows: 24,
            },
            8,
        ));
        assert!(
            matches!(res, IpeResult::Err(_)),
            "output far exceeding an 8-byte ceiling must fail the Task"
        );
    }

    /// A non-existent binary fails the Task (spawn failure), never a hang.
    #[test]
    fn nonexistent_binary_fails_task() {
        let res: IpeResult<String, ProcessPtyOutput> = block(process_run_in_pty::<String>(
            pty_cfg("ipe-does-not-exist-xyz", &[]),
        ));
        assert!(
            matches!(res, IpeResult::Err(_)),
            "spawn failure must fail the Task"
        );
    }
}

#[cfg(all(test, feature = "tokio"))]
#[cfg(not(target_arch = "wasm32"))]
mod process_run_spawn_blocking_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Reactor-starvation guard: `Command::output()` blocks the calling thread until
    /// the child process exits. On a SINGLE-WORKER (current_thread) runtime,
    /// running that wait inline (no `spawn_blocking`) would starve every
    /// other task scheduled on that runtime for the subprocess's whole
    /// lifetime. This proves `process_run` offloads the wait to tokio's
    /// blocking-thread pool: a concurrently-spawned cheap ticker task must
    /// make progress (ticks > 0) WHILE the subprocess is running.
    ///
    /// Uses `sleep 1` as a cheap, portable way to force the subprocess to run
    /// long enough for at least one `yield_now` to land elsewhere. Pre-fix
    /// this is NOT a flaky race: the ticker makes EXACTLY zero progress
    /// deterministically, because the worker thread never yields back to the
    /// executor until `Command::output()` returns.
    #[test]
    fn process_run_does_not_starve_concurrent_async_work() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let ticks = rt.block_on(async move {
            let counter = Arc::new(AtomicU64::new(0));
            let counter2 = counter.clone();
            let ticker = tokio::spawn(async move {
                loop {
                    counter2.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            });
            let run_fut: IpeTask<String, String> =
                process_run("sleep".to_string(), vec!["1".to_string()]);
            let _res: IpeResult<String, String> = run_fut.await;
            ticker.abort();
            counter.load(Ordering::Relaxed)
        });

        assert!(
            ticks > 0,
            "concurrent ticker task made ZERO progress while process_run ran — \
             the blocking subprocess wait is starving the single-threaded executor \
             (spawn_blocking missing or not taking effect)"
        );
    }
}

#[cfg(all(test, feature = "tokio"))]
#[cfg(not(target_arch = "wasm32"))]
mod system_load_env_spawn_blocking_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Reactor-starvation guard: `system_load_env` reads `.env` via
    /// `std::fs::read_to_string`, a blocking syscall. It must route through the
    /// shared `run_blocking` helper (defined above in this file, already used
    /// by `process_run`) rather than run inline inside the `async move` body —
    /// the same offload `file.rs` / `compression.rs` / `csv.rs` /
    /// `config_decode.rs` use. This proves `system_load_env` offloads the read
    /// to tokio's blocking-thread pool: a concurrently-
    /// spawned cheap ticker task must make progress (ticks > 0) WHILE the
    /// read is in flight.
    ///
    /// Uses a large `.env` (64 MiB of comment padding, same idiom as
    /// `file.rs`'s `spawn_blocking_tests`) so the read takes measurable wall
    /// time. Pre-fix this is NOT a flaky race — the ticker makes EXACTLY
    /// zero progress deterministically, because the worker thread never
    /// yields back to the executor until `read_to_string` returns.
    ///
    /// `set_current_dir` mutates process-global state; safe here only
    /// because this crate's tests run one-process-per-test under `cargo
    /// nextest` (the codebase's existing convention for tests that mutate
    /// global process state — e.g. this same file's `exit_hook_tests` /
    /// `console.rs`'s `ingest_token_gate` mutate env vars directly for the
    /// same reason).
    #[test]
    fn system_load_env_does_not_starve_concurrent_async_work() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = crate::scratch_core::test_temp_root().join(format!(
            "ipe_load_env_spawn_blocking_probe_{}_{}",
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let env_path = dir.join(".env");
        // One huge comment line (skipped by the parser) + one real var —
        // large enough that the read takes measurable (not instant) wall
        // time, same idiom as `file.rs`'s spawn_blocking probe.
        let mut contents = String::from("# ");
        contents.push_str(&"x".repeat(64 * 1024 * 1024));
        contents.push('\n');
        contents.push_str("IPE_LOAD_ENV_PROBE_VAR=probe_value\n");
        std::fs::write(&env_path, contents).unwrap();

        let orig_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        locked_remove_var("IPE_LOAD_ENV_PROBE_VAR");

        let ticks = rt.block_on(async move {
            let counter = Arc::new(AtomicU64::new(0));
            let counter2 = counter.clone();
            let ticker = tokio::spawn(async move {
                loop {
                    counter2.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            });
            let load_fut: IpeTask<String, ()> = system_load_env(());
            let _res: IpeResult<String, ()> = load_fut.await;
            ticker.abort();
            counter.load(Ordering::Relaxed)
        });

        // Functional sanity: the real var was actually picked up.
        let loaded = read_env_var("IPE_LOAD_ENV_PROBE_VAR");

        std::env::set_current_dir(&orig_cwd).unwrap();
        locked_remove_var("IPE_LOAD_ENV_PROBE_VAR");
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            loaded.as_deref(),
            Ok("probe_value"),
            "system_load_env did not set the var from the probe .env file"
        );
        assert!(
            ticks > 0,
            "concurrent ticker task made ZERO progress while system_load_env ran — \
             the blocking .env read is starving the single-threaded executor \
             (spawn_blocking missing or not taking effect)"
        );
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod argv_tests {
    use super::super::IpeErrorKind;
    use super::{IpeError, IpeMaybe, decode_arg_at, decode_args};
    use std::ffi::OsString;

    fn argv(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    #[test]
    fn args_skip_the_program_name() {
        assert!(matches!(
            decode_args(argv(&["prog", "a", "b"]).into_iter()).as_deref(),
            Ok([a, b]) if a == "a" && b == "b"
        ));
    }

    #[test]
    fn arg_indexes_outside_the_vector_are_nothing() {
        let v = argv(&["prog", "a"]);
        assert!(matches!(
            decode_arg_at(v.clone().into_iter(), -1),
            Ok(IpeMaybe::Nothing)
        ));
        assert!(matches!(
            decode_arg_at(v.clone().into_iter(), 2),
            Ok(IpeMaybe::Nothing)
        ));
        // One past `u32::MAX`: a narrowing cast would wrap it to index 0.
        assert!(matches!(
            decode_arg_at(v.clone().into_iter(), i64::from(u32::MAX) + 1),
            Ok(IpeMaybe::Nothing)
        ));
        assert!(matches!(
            decode_arg_at(v.into_iter(), i64::MAX),
            Ok(IpeMaybe::Nothing)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_arguments_are_refused_without_echoing_their_bytes() {
        use std::os::unix::ffi::OsStringExt;
        let bad = || {
            vec![
                OsString::from("prog"),
                OsString::from_vec(b"secret\xff".to_vec()),
            ]
        };
        let all = decode_args(bad().into_iter()).map(|_| ());
        let one = decode_arg_at(bad().into_iter(), 1).map(|_| ());
        for refused in [all, one] {
            match refused {
                Err(IpeError::Error(IpeErrorKind::InvalidInput, info)) => {
                    assert!(
                        !info.message.contains("secret"),
                        "refusal echoed argv bytes: {}",
                        info.message
                    );
                }
                other => panic!("non-UTF-8 argument must be refused, got {other:?}"),
            }
        }
        assert!(matches!(
            decode_arg_at(bad().into_iter(), 0),
            Ok(IpeMaybe::Just(p)) if p == "prog"
        ));
    }
}
