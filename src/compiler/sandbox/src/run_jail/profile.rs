//! The platform-independent run-jail profile: the [`SandboxProfile`] model, its
//! capability-set lowering, and the strict parse/serialise/scan of the
//! `ipe.profile` and capability-floor wire forms. Nothing here is OS-specific —
//! a reader auditing the profile model never needs the per-platform arms.

use std::collections::BTreeSet;

use ipe_kernels::Capability;

// ── the database axis (a run-jail input, resolved from package.ipe) ──────────

/// How `Capability::Database` lowers for this project.
///
/// The driver decides whether a database effect is really a network effect (a
/// TCP driver) or a filesystem effect (an embedded/`SQLite` file). Resolved by
/// the CLI from the `package.ipe` driver selection before the profile is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseAxis {
    /// A TCP-connected database (`Postgres`, `MySQL`, …) → the `network` control.
    Network,
    /// A file-backed database (`SQLite`, an embedded store) → the `filesystem`
    /// control.
    Filesystem,
    /// No `database` capability is present, so the driver is irrelevant. Kept
    /// distinct from a *missing* driver: the caller supplies this only when the
    /// set does not include `database`, so an unknown driver where one is needed
    /// is still an error.
    NotApplicable,
}

/// Why a capability set could not be lowered to a profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    /// The set includes `database` but the `package.ipe` driver could not be
    /// resolved to a concrete axis. Fail-closed: dropping the axis would
    /// *tighten* the jail past what the program needs (a false-deny), and
    /// guessing an axis could under-isolate — so this refuses.
    UnknownDatabaseDriver,
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownDatabaseDriver => write!(
                f,
                "the program uses `database`, but the package.ipe database driver could not be \
                 resolved to a concrete axis (network or filesystem); refusing to build a jail \
                 that might over- or under-isolate it"
            ),
        }
    }
}

impl std::error::Error for ProfileError {}

// ── the platform-independent profile ────────────────────────────────────────

/// The filesystem scope a program runs under.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FilesystemScope {
    /// `filesystem` absent: `/` read-only, home/tmp masked, exactly one scoped
    /// writable tempdir. The maximally-isolated filesystem view.
    Isolated,
    /// `filesystem` granted: the working tree is bound read-write (still coarse
    /// — any path under it — per the first-cut map), except its version-control
    /// metadata ([`crate::VcsKind::ALL`]), which stays read-only: the host runs
    /// code that metadata names. An arm that cannot keep it read-only refuses
    /// a tree holding it. Metadata the program creates after the jail starts is
    /// not carved on every arm, so a tree is trusted only as far as the next
    /// tool the developer runs over it.
    WorkingTreeReadWrite,
}

/// The resource caps for a run-jailed app.
///
/// Distinct from the build jail's `ResourceLimits`, whose values (10 GiB AS,
/// 900 s wall/CPU) are tuned to kill a giant one-shot rustdoc and would wrongly
/// kill a legitimate long-lived server (a false-deny).
///
/// The mechanism (`prlimit` + optional `timeout`) is reused; the numbers are
/// not. `wall_secs = None` means no wall-clock kill (a server runs
/// indefinitely); a runaway is still bounded by the CPU/memory/proc caps, which
/// stay mandatory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RunResourceLimits {
    /// Address-space cap in bytes.
    pub as_bytes: u64,
    /// CPU-seconds cap (bounds a busy-loop even without a wall clock).
    pub cpu_secs: u64,
    /// Wall-clock cap in seconds, or `None` for no wall-clock kill.
    pub wall_secs: Option<u64>,
    /// Open-file-descriptor cap.
    pub fd_cap: u64,
    /// Process-count cap.
    pub proc_cap: u64,
}

impl Default for RunResourceLimits {
    fn default() -> Self {
        // A long-lived app, not a one-shot build: no wall clock, a generous CPU
        // ceiling (a runaway loop is still bounded, a slow server is not), a
        // large-but-finite address space, and sane FD/process caps.
        Self {
            as_bytes: 4 * 1024 * 1024 * 1024,
            cpu_secs: 86_400,
            wall_secs: None,
            fd_cap: 4096,
            proc_cap: 512,
        }
    }
}

impl RunResourceLimits {
    /// The CPU-second ceiling in Win32 Job-Object 100-nanosecond units, saturating
    /// at [`i64::MAX`].
    ///
    /// The Unix arms feed `cpu_secs` to `prlimit --cpu`; the Windows Job Object's
    /// `PerProcessUserTimeLimit` field is the same CPU ceiling expressed in 100-ns
    /// ticks. Kept as a pure, host-independent mapping so the conversion is
    /// unit-tested on any host, not only where the Win32 call links — and so an
    /// overflow saturates to the largest representable ceiling rather than
    /// wrapping to a tiny (or zero) limit that would kill a legitimate app early
    /// or, worse, silently drop the bound.
    #[must_use]
    pub fn cpu_time_100ns(&self) -> i64 {
        // 1 s = 10_000_000 × 100 ns. Saturate the multiply, then clamp into i64.
        let ticks = self.cpu_secs.saturating_mul(10_000_000);
        i64::try_from(ticks).unwrap_or(i64::MAX)
    }

    /// The address-space ceiling in bytes for the Win32 Job Object
    /// `JobMemoryLimit`, saturating at [`usize::MAX`].
    ///
    /// The Unix arms feed `as_bytes` to `prlimit --as`; the Job Object's
    /// `JobMemoryLimit` is the job-wide committed-bytes equivalent. A `u64` that
    /// exceeds a 32-bit `usize` saturates rather than truncating — a truncated
    /// value could set a ceiling far below the intended one (or zero), so
    /// saturation keeps the bound honest and never accidentally permissive-then-
    /// starved.
    #[must_use]
    pub fn job_memory_limit_bytes(&self) -> usize {
        usize::try_from(self.as_bytes).unwrap_or(usize::MAX)
    }
}

/// The platform-independent description of a run jail.
///
/// What the emitted app may touch, derived from its capability set. A
/// per-platform *builder* ([`run_jail_argv`] on Linux) turns this into a
/// concrete jail.
///
/// This is the value serialized into an artifact's `ipe.profile`. It is
/// deliberately NOT `Default`-constructible to an all-allowed value — the empty
/// capability set lowers to the maximally-isolated profile
/// ([`profile_from_capabilities`]), and a profile is only ever *built from a
/// set*, never conjured permissive.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SandboxProfile {
    /// `true` iff `network` is granted — the net namespace is shared with the
    /// host. `false` → a fresh empty net namespace (loopback only).
    pub network: bool,
    /// The filesystem scope.
    pub filesystem: FilesystemScope,
    /// The environment variables re-exported into the scrubbed env (the `env`
    /// axis's allowlist). Empty when `env` is absent.
    pub env_allowlist: Vec<String>,
    /// `true` iff `subprocess` is granted — the seccomp filter permits the
    /// task-creation family. `false` → the create family is denied (threads
    /// excepted).
    pub subprocess: bool,
    /// The resource caps.
    pub limits: RunResourceLimits,
}

impl SandboxProfile {
    /// The maximally-isolated profile: nothing granted. This is what the empty
    /// capability set lowers to, and the floor a tampered `ipe.profile` cannot
    /// go below undetected.
    #[must_use]
    pub fn maximally_isolated() -> Self {
        Self {
            network: false,
            filesystem: FilesystemScope::Isolated,
            env_allowlist: Vec::new(),
            subprocess: false,
            limits: RunResourceLimits::default(),
        }
    }

    /// Whether `self`'s filesystem scope isolates at least as much as `floor`'s:
    /// `Isolated` isolates more than (or equal to) any scope; a read-write tree
    /// is only OK if the floor also grants a read-write tree.
    #[must_use]
    const fn fs_at_least_as_isolated(&self, floor: &Self) -> bool {
        matches!(self.filesystem, FilesystemScope::Isolated)
            || matches!(floor.filesystem, FilesystemScope::WorkingTreeReadWrite)
    }

    /// The launcher's floor check against a [`parse_capfloor`]-derived floor.
    ///
    /// This is the single implementation of the profile-vs-floor anti-tamper
    /// predicate. Every axis comparison lives here; adding a new axis forces every
    /// call site to see the change. The embedded floor records the axis grants AND
    /// the exact set of granted env var *names* ([`to_capfloor_line`] serializes
    /// them), so the env axis is compared by name subset — identical to the other
    /// axes: every env var the profile grants must be one the floor also grants. A
    /// tampered `ipe.profile` that swaps *which* env vars it grants (even at the
    /// same count) is refused.
    ///
    /// [`to_capfloor_line`]: Self::to_capfloor_line
    #[must_use]
    pub fn satisfies_capfloor(&self, floor: &Self) -> bool {
        let network_ok = !self.network || floor.network;
        let subprocess_ok = !self.subprocess || floor.subprocess;
        let fs_ok = self.fs_at_least_as_isolated(floor);
        // Every env var the profile grants must be in the floor's allowlist — the
        // same ⊆ subset check the other axes get, now that the floor carries the
        // names, not just a count.
        let env_ok = self
            .env_allowlist
            .iter()
            .all(|v| floor.env_allowlist.contains(v));
        network_ok && subprocess_ok && fs_ok && env_ok
    }

    /// Whether `self` isolates *at least* as much as `floor` on every axis.
    ///
    /// Delegates to [`satisfies_capfloor`] — the single implementation of the
    /// per-axis tamper check — so the two cannot diverge.
    ///
    /// [`satisfies_capfloor`]: Self::satisfies_capfloor
    #[must_use]
    pub fn is_at_least_as_isolated_as(&self, floor: &Self) -> bool {
        self.satisfies_capfloor(floor)
    }

    /// Serialize the profile to the strict, line-oriented `ipe.profile` text.
    ///
    /// A tiny explicit grammar (not a general format) keeps the launcher's
    /// [`parse_profile`] a genuine *parse* — every field is named, every value is
    /// a fixed token, and anything unrecognized is a hard parse failure (⇒
    /// refuse-to-run), never a permissive default.
    #[must_use]
    pub fn to_profile_string(&self) -> String {
        use std::fmt::Write as _;
        let fs = match self.filesystem {
            FilesystemScope::Isolated => "isolated",
            FilesystemScope::WorkingTreeReadWrite => "working-tree-rw",
        };
        let mut s = String::from("ipe-profile 1\n");
        // Writing to a String is infallible, so the `write!` results are ignored.
        let _ = writeln!(s, "network {}", self.network);
        let _ = writeln!(s, "filesystem {fs}");
        let _ = writeln!(s, "subprocess {}", self.subprocess);
        for name in &self.env_allowlist {
            let _ = writeln!(s, "env {name}");
        }
        s
    }

    /// The compact capability-floor token line embedded read-only in the binary's
    /// `.rodata`. It records the *axis* grants AND the exact set of granted env
    /// var names (not resource limits — the launcher rebuilds a comparison floor
    /// from these), so a tampered `ipe.profile` can neither claim fewer axes nor
    /// swap *which* env vars it grants below what the binary was built for.
    ///
    /// Format: `ipe-capfloor 1 net=<b> fs=<isolated|rw> sub=<b> env=<names>
    /// intent=<release|development>` where `<names>` is the sorted, comma-joined
    /// set of granted env names (empty when none) and `intent` names the build
    /// pipeline that embedded the floor ([`FloorIntent`]). The names are bound by identity, so the floor compares env by the
    /// SAME ⊆ subset check as the other axes — a same-count name swap no longer
    /// passes. Env var names are POSIX identifiers (`[A-Za-z_][A-Za-z0-9_]*`), so
    /// they never contain a comma or whitespace; [`parse_capfloor`] fails closed
    /// on any name that does.
    #[must_use]
    pub fn to_capfloor_line(&self, intent: FloorIntent) -> String {
        let fs = match self.filesystem {
            FilesystemScope::Isolated => "isolated",
            FilesystemScope::WorkingTreeReadWrite => "rw",
        };
        let mut names: Vec<&str> = self.env_allowlist.iter().map(String::as_str).collect();
        names.sort_unstable();
        names.dedup();
        format!(
            "ipe-capfloor 1 net={} fs={fs} sub={} env={} intent={}",
            self.network,
            self.subprocess,
            names.join(","),
            intent.token()
        )
    }
}

/// The build pipeline that embedded an app's capability floor.
///
/// `ipe release run` and the release wrapper run only a [`FloorIntent::Release`]
/// app: a development build carries debug assertions, an unoptimised profile
/// and development-only behaviour that a deployment must not ship.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorIntent {
    /// Embedded by a development build (`ipe dev`), or by a floor line that
    /// names no intent.
    Development,
    /// Embedded by `ipe release build`.
    Release,
}

impl FloorIntent {
    /// The `intent=` token of the capfloor line.
    const fn token(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Release => "release",
        }
    }
}

/// A capability floor read from a binary: the axes it grants at most, and
/// the pipeline that embedded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapFloor {
    /// The grants the floor caps a profile at (limits are not part of a floor).
    pub axes: SandboxProfile,
    /// The build pipeline that embedded the floor.
    pub intent: FloorIntent,
}

/// Why a release app was refused against its profile before it ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorRefusal {
    /// The app carries no readable capability floor.
    Unreadable,
    /// The floor was embedded by a development build (`ipe dev`), not
    /// `ipe release build`.
    NotRelease,
    /// The profile grants more than the floor the app was built with.
    ProfileWider,
}

impl std::fmt::Display for FloorRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = super::RunJailDefect::ProfileWeakerThanFloor.code();
        match self {
            Self::Unreadable => write!(
                f,
                "{}: the binary embeds no readable capability floor — refusing to run an \
                 artifact whose confinement cannot be verified: rebuild it with \
                 `ipe release build`",
                code.as_str()
            ),
            Self::NotRelease => write!(
                f,
                "{}: the app is a development build (`ipe dev`), not an \
                 `ipe release build` artifact — a release runs only a release build: \
                 rebuild it with `ipe release build`",
                code.as_str()
            ),
            Self::ProfileWider => {
                write!(f, "{}", super::RunJailDefect::ProfileWeakerThanFloor)
            }
        }
    }
}

impl std::error::Error for FloorRefusal {}

/// Verify a release app's bytes against the profile it is to run under.
///
/// The one check `ipe release run` and the release wrapper both apply: the
/// app must embed a readable floor ([`scan_capfloor`]), that floor must be a
/// release build's, and the profile must grant no more than it
/// ([`SandboxProfile::satisfies_capfloor`]).
///
/// # Errors
///
/// [`FloorRefusal::Unreadable`] with no readable floor;
/// [`FloorRefusal::NotRelease`] for a development build's floor;
/// [`FloorRefusal::ProfileWider`] when the profile exceeds the floor.
pub fn verify_release_floor(
    profile: &SandboxProfile,
    app_bytes: &[u8],
) -> Result<(), FloorRefusal> {
    let floor = scan_capfloor(app_bytes).ok_or(FloorRefusal::Unreadable)?;
    match floor.intent {
        FloorIntent::Release => {}
        FloorIntent::Development => return Err(FloorRefusal::NotRelease),
    }
    if profile.satisfies_capfloor(&floor.axes) {
        Ok(())
    } else {
        Err(FloorRefusal::ProfileWider)
    }
}

/// Why an `ipe.profile` or capfloor could not be parsed. A parse failure is a
/// **refuse-to-run**, never a permissive fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// A malformed or unrecognized line/field.
    Malformed {
        /// A short reason.
        detail: String,
    },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed { detail } => write!(f, "malformed profile: {detail}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Strictly parse an `ipe.profile` string into a [`SandboxProfile`].
///
/// Parse-don't-validate: an unknown key, a malformed boolean, a missing required
/// field, or an unknown filesystem token is a hard [`ParseError`] — the launcher
/// refuses to run rather than fall back to anything permissive. Resource limits
/// are not in the wire format (they are a run-jail default, not a confinement
/// axis); the parsed profile uses [`RunResourceLimits::default`].
///
/// # Errors
///
/// [`ParseError::Malformed`] on any grammar violation.
pub fn parse_profile(text: &str) -> Result<SandboxProfile, ParseError> {
    let malformed = |detail: &str| ParseError::Malformed {
        detail: detail.to_owned(),
    };
    let parse_bool = |v: &str| match v {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(ParseError::Malformed {
            detail: format!("expected true/false, got {other:?}"),
        }),
    };

    let mut lines = text.lines();
    let header = lines.next().ok_or_else(|| malformed("empty profile"))?;
    if header != "ipe-profile 1" {
        return Err(malformed("missing or unsupported `ipe-profile 1` header"));
    }

    // Deny-by-default: start maximally isolated, relax only what the file names.
    let mut network: Option<bool> = None;
    let mut filesystem: Option<FilesystemScope> = None;
    let mut subprocess: Option<bool> = None;
    let mut env_allowlist: Vec<String> = Vec::new();

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once(' ')
            .ok_or_else(|| malformed(&format!("expected `key value`, got {line:?}")))?;
        match key {
            "network" => network = Some(parse_bool(value)?),
            "filesystem" => {
                filesystem = Some(match value {
                    "isolated" => FilesystemScope::Isolated,
                    "working-tree-rw" => FilesystemScope::WorkingTreeReadWrite,
                    other => return Err(malformed(&format!("unknown filesystem scope {other:?}"))),
                });
            }
            "subprocess" => subprocess = Some(parse_bool(value)?),
            "env" => env_allowlist.push(value.to_owned()),
            other => return Err(malformed(&format!("unknown key {other:?}"))),
        }
    }

    Ok(SandboxProfile {
        network: network.ok_or_else(|| malformed("missing `network`"))?,
        filesystem: filesystem.ok_or_else(|| malformed("missing `filesystem`"))?,
        subprocess: subprocess.ok_or_else(|| malformed("missing `subprocess`"))?,
        env_allowlist,
        limits: RunResourceLimits::default(),
    })
}

/// Strictly parse a capfloor line into the *comparison floor*.
///
/// The result's [`CapFloor::axes`] is a [`SandboxProfile`] whose axes AND env
/// allowlist are the floor the binary was built with; its
/// [`CapFloor::intent`] is the pipeline that embedded it, and a line naming
/// no intent is a [`FloorIntent::Development`] floor, never a release one. The env names are parsed from the sorted,
/// comma-joined `env=<names>` field ([`SandboxProfile::to_capfloor_line`]), so
/// the launcher can verify the profile grants only env vars the floor also
/// grants — an exact name subset, not a count.
///
/// # Errors
///
/// [`ParseError::Malformed`] on any grammar violation — a floor that cannot be
/// parsed means the binary's authoritative floor is unreadable, so the launcher
/// must refuse (never treat an unreadable floor as "no floor"). An env name that
/// is empty or carries a comma/whitespace (impossible for a POSIX env name) is a
/// malformed floor and refuses, as is an unknown or repeated `intent`.
pub fn parse_capfloor(line: &str) -> Result<CapFloor, ParseError> {
    let malformed = |detail: String| ParseError::Malformed { detail };
    let line = line.trim();
    let mut parts = line.split_whitespace();
    if parts.next() != Some("ipe-capfloor") || parts.next() != Some("1") {
        return Err(malformed("missing `ipe-capfloor 1` header".to_owned()));
    }
    let mut network = false;
    let mut filesystem = FilesystemScope::Isolated;
    let mut subprocess = false;
    let mut env_allowlist: Vec<String> = Vec::new();
    let mut intent: Option<FloorIntent> = None;
    for field in parts {
        let (k, v) = field
            .split_once('=')
            .ok_or_else(|| malformed(format!("expected key=value, got {field:?}")))?;
        match k {
            "net" => network = v == "true",
            "fs" => {
                filesystem = match v {
                    "isolated" => FilesystemScope::Isolated,
                    "rw" => FilesystemScope::WorkingTreeReadWrite,
                    other => return Err(malformed(format!("unknown fs {other:?}"))),
                };
            }
            "sub" => subprocess = v == "true",
            "env" => {
                env_allowlist = parse_capfloor_env_names(v)?;
            }
            "intent" => {
                let parsed = match v {
                    "release" => FloorIntent::Release,
                    "development" => FloorIntent::Development,
                    other => return Err(malformed(format!("unknown intent {other:?}"))),
                };
                if intent.replace(parsed).is_some() {
                    return Err(malformed("repeated intent field".to_owned()));
                }
            }
            other => return Err(malformed(format!("unknown capfloor field {other:?}"))),
        }
    }
    Ok(CapFloor {
        axes: SandboxProfile {
            network,
            filesystem,
            subprocess,
            env_allowlist,
            limits: RunResourceLimits::default(),
        },
        intent: intent.unwrap_or(FloorIntent::Development),
    })
}

/// Parse the `env=<names>` field of a capfloor line: a sorted, comma-joined set
/// of env var names, empty when no env var is granted.
///
/// Fail-closed: each name must be a non-empty POSIX env identifier
/// (`[A-Za-z_][A-Za-z0-9_]*`). An empty name (a stray/leading/trailing comma) or
/// any name outside that charset — neither of which [`SandboxProfile::to_capfloor_line`]
/// can emit — is a malformed floor and refuses. Since the writer already sorts
/// and dedups, the parsed set is returned as-is.
///
/// # Errors
///
/// [`ParseError::Malformed`] on an empty or non-identifier name.
fn parse_capfloor_env_names(v: &str) -> Result<Vec<String>, ParseError> {
    if v.is_empty() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for name in v.split(',') {
        if !is_posix_env_name(name) {
            return Err(ParseError::Malformed {
                detail: format!("malformed env name {name:?} in capfloor"),
            });
        }
        names.push(name.to_owned());
    }
    Ok(names)
}

/// Whether `name` is a non-empty POSIX environment-variable identifier: a first
/// char of `[A-Za-z_]`, then `[A-Za-z0-9_]*`. This is the charset the capfloor
/// `env=` field admits — anything else (a comma, whitespace, a digit-leading
/// name) is rejected, so the comma-joined encoding is unambiguous and a tampered
/// floor cannot smuggle a separator into a name.
fn is_posix_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Lower a capability set to a [`SandboxProfile`].
///
/// The profile set is `inferred ∪ declared` — the union guarantees *no
/// false-deny*: every capability anyone claims the program has is relaxed, so a
/// legitimately-declared effect is never blocked. `db_axis` resolves `database`
/// to a concrete axis (see [`DatabaseAxis`]); it is consulted only when the set
/// includes `database`.
///
/// The `match Capability` is **exhaustive with no `_`**: a new capability
/// variant fails to compile here until classified, so it can never silently
/// default to "allowed".
///
/// # Errors
///
/// [`ProfileError::UnknownDatabaseDriver`] when the set includes `database` but
/// `db_axis` is [`DatabaseAxis::NotApplicable`] (the driver could not be
/// resolved) — fail-closed rather than drop or mis-lower the axis.
pub fn profile_from_capabilities(
    inferred: &BTreeSet<Capability>,
    declared: &BTreeSet<Capability>,
    db_axis: DatabaseAxis,
    env_allowlist: &[String],
) -> Result<SandboxProfile, ProfileError> {
    let mut profile = SandboxProfile::maximally_isolated();

    // The union is the authoritative set (no false-deny).
    let union: BTreeSet<Capability> = inferred.union(declared).copied().collect();

    for &cap in &union {
        // The empty `clock/random` and `native-ffi` arms are DELIBERATELY
        // separate (not merged): each capability variant is explicitly
        // classified here, so a newly-added variant fails to compile until it is
        // given an arm — the deny-by-default structural guarantee. Merging the
        // no-op arms would defeat that, so the identical-arms lint is allowed.
        #[allow(clippy::match_same_arms)]
        match cap {
            Capability::Network => profile.network = true,
            Capability::Filesystem => {
                profile.filesystem = FilesystemScope::WorkingTreeReadWrite;
            }
            Capability::Database => match db_axis {
                DatabaseAxis::Network => profile.network = true,
                DatabaseAxis::Filesystem => {
                    profile.filesystem = FilesystemScope::WorkingTreeReadWrite;
                }
                DatabaseAxis::NotApplicable => return Err(ProfileError::UnknownDatabaseDriver),
            },
            Capability::Env => {
                // The env axis is granted: the manifest-named variables re-enter
                // the scrubbed environment. An empty allowlist here still means
                // "env granted but nothing named to re-export" — the axis is on,
                // the set of exported names is just empty.
                profile.env_allowlist = env_allowlist.to_vec();
            }
            Capability::Subprocess => profile.subprocess = true,
            // `clock`/`random` carry no OS control in the first cut: denying
            // time or RNG syscalls breaks far more than it contains, and neither
            // is a high-value exfiltration axis. Explicit no-op arms, not a
            // catch-all, so a new variant is still forced to be classified.
            Capability::Clock | Capability::Random => {}
            // `native-ffi` widens nothing by itself — its role is epistemic (it
            // means inference is blind, so the declared set is the ceiling). It
            // opens no control here; an explicit no-op arm. `ffi-raw` is the
            // same crossing under an author-asserted signature: pure
            // disclosure, no control of its own.
            Capability::NativeFfi | Capability::FfiRaw => {}
            // `unsafe` marks a value minted by assertion rather than by parse.
            // Like the FFI arms it is pure provenance disclosure, not a resource
            // axis the jail can open or close — an explicit no-op arm.
            Capability::Unsafe => {}
            // `custom-element` discloses that the program serves author browser
            // JS. That JS runs in the client page, never in the jailed server
            // process, so it is not an axis this OS jail opens or closes — an
            // explicit no-op arm. The disclosure is enforced by the served page's
            // SRI pin + CSP and surfaced to the consumer as a capability, not by
            // confining the server run.
            Capability::CustomElement => {}
            // `js-port` discloses that the program exchanges typed values with page
            // JavaScript over the raw port transport. Like `custom-element`, that JS
            // runs in the client page, never in the jailed server process, so it is
            // not an axis this OS jail opens or closes — an explicit no-op arm. The
            // disclosure is surfaced to the consumer as a capability and the inbound
            // seam is fail-closed by the seal decoder, not by confining the run.
            Capability::JsPort(_) => {}
        }
    }

    Ok(profile)
}

/// The marker that begins the capability-floor line embedded in the binary's
/// `.rodata`.
///
/// See the CLI's `capfloor_static_source`; [`scan_capfloor`] finds the floor by
/// this marker, which survives `strip` (`.rodata` is allocated).
pub const CAPFLOOR_MARKER: &str = "ipe-capfloor 1 ";

/// Ceiling on the bytes of a release app read for its floor scan.
///
/// 512 MiB is far above any statically-linked app while refusing a planted
/// device node or multi-GiB file before it is buffered whole.
pub const APP_READ_CAP: u64 = 512 * 1024 * 1024;

/// Ceiling on the bytes of a release bundle's `ipe.profile`.
pub const PROFILE_READ_CAP: u64 = 1024 * 1024;

/// Scan a binary's bytes for the embedded capability-floor line and parse it —
/// the tamper-safe floor read that does NOT execute the binary and survives
/// `strip`.
///
/// The floor is a `#[used]` static in `.rodata` (an allocated section `strip`
/// keeps), so it is present as raw bytes in the file. This scans for the unique
/// [`CAPFLOOR_MARKER`] prefix and parses the line up to the first NUL or
/// newline. A binary with no marker yields `None` — the launcher treats that as
/// "no readable floor" and refuses (never as "no floor, anything goes").
///
/// The floor is a *ceiling on grants*: the profile must not grant more than the
/// floor ([`SandboxProfile::satisfies_capfloor`]). So if the binary contains
/// MULTIPLE marker occurrences (it should not — the static is emitted once), the
/// STRICTEST (least-granting) floor wins: an attacker who appends a more
/// permissive floor line cannot raise the ceiling and relax the jail. Concretely
/// the floors are intersected (an axis is in the merged floor only if EVERY
/// occurrence grants it, and an env name survives only if EVERY occurrence grants
/// it — the name-set intersection). The merged intent is
/// [`FloorIntent::Release`] only if every occurrence names it, so a forged
/// release line beside a development floor cannot pass a development build
/// off as a release one.
#[must_use]
pub fn scan_capfloor(bytes: &[u8]) -> Option<CapFloor> {
    let marker = CAPFLOOR_MARKER.as_bytes();
    let mut floors: Vec<CapFloor> = Vec::new();
    // Every window that starts with the marker begins a candidate floor line.
    for (start, _) in bytes
        .windows(marker.len())
        .enumerate()
        .filter(|(_, w)| *w == marker)
    {
        // The line runs from the marker to the first NUL or newline.
        let rest = bytes.get(start..).unwrap_or(&[]);
        let end = rest
            .iter()
            .position(|&b| b == 0 || b == b'\n')
            .unwrap_or(rest.len());
        if let Ok(line) = std::str::from_utf8(rest.get(..end).unwrap_or(&[]))
            && let Ok(p) = parse_capfloor(line)
        {
            floors.push(p);
        }
    }
    let (first, rest) = floors.split_first()?;
    // Intersect to the strictest floor: an axis stays granted only if EVERY
    // occurrence grants it; the env ceiling is the NAME-SET intersection (a name
    // survives only if every occurrence grants it). A forged permissive copy
    // cannot raise the ceiling nor swap in a name the legitimate floor omits.
    let mut merged = first.axes.clone();
    let mut intent = first.intent;
    let mut env_names: BTreeSet<&str> = first
        .axes
        .env_allowlist
        .iter()
        .map(String::as_str)
        .collect();
    for CapFloor {
        axes: f,
        intent: occurrence_intent,
    } in rest
    {
        if *occurrence_intent == FloorIntent::Development {
            intent = FloorIntent::Development;
        }
        if !f.network {
            merged.network = false;
        }
        if matches!(f.filesystem, FilesystemScope::Isolated) {
            merged.filesystem = FilesystemScope::Isolated;
        }
        if !f.subprocess {
            merged.subprocess = false;
        }
        let occurrence: BTreeSet<&str> = f.env_allowlist.iter().map(String::as_str).collect();
        env_names.retain(|n| occurrence.contains(n));
    }
    merged.env_allowlist = env_names.into_iter().map(str::to_owned).collect();
    Some(CapFloor {
        axes: merged,
        intent,
    })
}

#[cfg(test)]
mod limit_mapping_tests {
    use super::RunResourceLimits;

    #[test]
    fn cpu_seconds_map_to_hundred_nanosecond_ticks() {
        // The Windows Job Object's PerProcessUserTimeLimit is the same CPU-second
        // ceiling as the Unix `prlimit --cpu`, expressed in 100-ns units:
        // 1 s = 10_000_000 ticks. The default run-jail cap must round-trip exactly.
        let l = RunResourceLimits {
            cpu_secs: 1,
            ..RunResourceLimits::default()
        };
        assert_eq!(l.cpu_time_100ns(), 10_000_000);
        let d = RunResourceLimits::default();
        assert_eq!(d.cpu_time_100ns(), 86_400 * 10_000_000);
    }

    #[test]
    fn an_absurd_cpu_ceiling_saturates_instead_of_wrapping_to_a_tiny_bound() {
        // A hostile or corrupt profile carrying a huge cpu_secs must NOT wrap the
        // 100-ns multiply into a small (or negative) i64 that would kill a
        // legitimate app almost immediately, nor silently drop the ceiling. It
        // saturates to the largest representable bound — still a bound.
        let l = RunResourceLimits {
            cpu_secs: u64::MAX,
            ..RunResourceLimits::default()
        };
        assert_eq!(l.cpu_time_100ns(), i64::MAX);
        // Just past the i64 tick ceiling also saturates rather than overflowing.
        let past = RunResourceLimits {
            cpu_secs: (i64::MAX as u64 / 10_000_000) + 1,
            ..RunResourceLimits::default()
        };
        assert_eq!(past.cpu_time_100ns(), i64::MAX);
    }

    #[test]
    fn address_space_maps_to_the_job_memory_byte_ceiling() {
        let l = RunResourceLimits {
            as_bytes: 4 * 1024 * 1024 * 1024,
            ..RunResourceLimits::default()
        };
        // On a 64-bit host the 4 GiB default fits usize exactly.
        assert_eq!(l.job_memory_limit_bytes() as u64, 4 * 1024 * 1024 * 1024);
    }

    #[test]
    fn an_over_usize_memory_ceiling_saturates_instead_of_truncating() {
        // A byte ceiling beyond a 32-bit usize must saturate to usize::MAX, never
        // truncate to a tiny value that would starve a legitimate app or, by
        // wrapping to zero, drop the memory bound entirely. On a 64-bit host
        // u64::MAX still exceeds usize::MAX only on 32-bit, so assert the invariant
        // that the result never exceeds usize::MAX and is monotone.
        let huge = RunResourceLimits {
            as_bytes: u64::MAX,
            ..RunResourceLimits::default()
        };
        assert_eq!(huge.job_memory_limit_bytes(), usize::MAX);
        // A value that fits is preserved exactly.
        let fits = RunResourceLimits {
            as_bytes: 1024,
            ..RunResourceLimits::default()
        };
        assert_eq!(fits.job_memory_limit_bytes(), 1024);
    }
}
