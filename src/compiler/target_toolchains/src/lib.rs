//! The static release targets and the host toolchain each one needs.
//!
//! One table answers, per supported triple: which C compilers may build its C
//! units, which variable cc-rs reads for that triple's compiler, which command
//! installs a native musl compiler on each Linux family, what to do on a host
//! of another architecture, and which linker the emitted crate's
//! `.cargo/config.toml` pins. The backend, the host toolchain resolver,
//! `ipe health`, the requirements reference and CI all read this table, so an
//! install hint cannot drift from the check it is meant to clear.
//!
//! The crate depends on nothing, so the docs generator reads the table without
//! linking a compiler crate.

/// A target triple the static path supports — a closed set.
///
/// Parse, don't validate: the CLI parses `--target` into this enum and refuses
/// anything else, so an unverifiable triple never reaches cargo. Growing the
/// set means adding a variant, its [`TargetToolchainRow`], and a CI leg that
/// proves it end to end.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Hash)]
pub enum StaticTriple {
    /// `x86_64-unknown-linux-musl` — a fully static ELF with no runtime deps.
    ///
    /// The default when `--static` is given without `--target`.
    #[default]
    X8664LinuxMusl,
    /// `aarch64-unknown-linux-musl` — a fully static `AArch64` ELF with no
    /// runtime deps.
    Aarch64LinuxMusl,
}

impl StaticTriple {
    /// Every supported triple, in declaration order.
    pub const ALL: [Self; 2] = [Self::X8664LinuxMusl, Self::Aarch64LinuxMusl];

    /// Every supported triple's spelling, for refusal messages.
    ///
    /// The same order as [`Self::ALL`]; a build-time assertion holds the two
    /// equal.
    pub const SUPPORTED: &'static [&'static str] =
        &["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"];

    /// The rustc target-triple spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X8664LinuxMusl => "x86_64-unknown-linux-musl",
            Self::Aarch64LinuxMusl => "aarch64-unknown-linux-musl",
        }
    }

    /// Parse a rustc triple into the supported set.
    ///
    /// `None` means the triple is not a supported static target; the CLI turns
    /// that into a typed refusal listing [`Self::SUPPORTED`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|triple| triple.as_str() == s)
    }

    /// The CPU architecture the triple's binaries run on.
    #[must_use]
    pub const fn arch(self) -> CpuArch {
        match self {
            Self::X8664LinuxMusl => CpuArch::X8664,
            Self::Aarch64LinuxMusl => CpuArch::Aarch64,
        }
    }

    /// The linker the emitted crate's `.cargo/config.toml` pins for this
    /// triple.
    #[must_use]
    pub const fn linker(self) -> TargetLinker {
        match self {
            Self::X8664LinuxMusl => TargetLinker::HostCc,
            Self::Aarch64LinuxMusl => TargetLinker::RustLld,
        }
    }

    /// The host toolchain this triple needs.
    #[must_use]
    pub const fn toolchain(self) -> &'static TargetToolchainRow {
        match self {
            Self::X8664LinuxMusl => &X8664_LINUX_MUSL,
            Self::Aarch64LinuxMusl => &AARCH64_LINUX_MUSL,
        }
    }
}

/// A CPU architecture a supported triple targets.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum CpuArch {
    /// `x86_64`.
    X8664,
    /// `aarch64`.
    Aarch64,
}

impl CpuArch {
    /// The architecture's name as triples and compiler names spell it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X8664 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
}

/// The linker a static triple's emitted crate links through.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum TargetLinker {
    /// The host C driver (`cc`), which must be a musl-capable compiler for the
    /// triple.
    HostCc,
    /// The `rust-lld` rustup bundles, linking against the musl startup objects
    /// rustup ships with the target (`link-self-contained=yes`), so no C cross
    /// linker is needed.
    RustLld,
}

/// A C compiler name the host toolchain resolver may probe for a static
/// triple — a closed set.
///
/// No `*-linux-gnu-gcc` is listed: a glibc compiler builds C units that call
/// glibc-only symbols (`open64`), which fail the musl link.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum CcCandidate {
    /// `x86_64-linux-musl-gcc`.
    X8664LinuxMuslGcc,
    /// `aarch64-linux-musl-gcc`.
    Aarch64LinuxMuslGcc,
    /// `musl-gcc`, the musl wrapper around the host's native compiler.
    ///
    /// It targets the host's own architecture, so only a probe of its output
    /// can admit it for a triple.
    MuslGcc,
}

impl CcCandidate {
    /// Every candidate, in declaration order.
    pub const ALL: [Self; 3] = [
        Self::X8664LinuxMuslGcc,
        Self::Aarch64LinuxMuslGcc,
        Self::MuslGcc,
    ];

    /// The program's file name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::X8664LinuxMuslGcc => "x86_64-linux-musl-gcc",
            Self::Aarch64LinuxMuslGcc => "aarch64-linux-musl-gcc",
            Self::MuslGcc => "musl-gcc",
        }
    }

    /// The architecture the name commits the compiler to.
    ///
    /// `None` for [`Self::MuslGcc`], whose target is the host's architecture.
    #[must_use]
    pub const fn arch(self) -> Option<CpuArch> {
        match self {
            Self::X8664LinuxMuslGcc => Some(CpuArch::X8664),
            Self::Aarch64LinuxMuslGcc => Some(CpuArch::Aarch64),
            Self::MuslGcc => None,
        }
    }
}

/// A Linux distribution family the table carries an install command for.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum PackageFamily {
    /// Debian and its derivatives (Ubuntu, Mint, …).
    Debian,
    /// Fedora and its relatives (RHEL, Rocky, …).
    Fedora,
    /// Arch Linux and its derivatives.
    Arch,
    /// Alpine Linux.
    Alpine,
}

impl PackageFamily {
    /// Every family, in declaration order.
    pub const ALL: [Self; 4] = [Self::Debian, Self::Fedora, Self::Arch, Self::Alpine];

    /// The family as the install guide names it.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Debian => "Debian, Ubuntu",
            Self::Fedora => "Fedora, RHEL, Rocky",
            Self::Arch => "Arch",
            Self::Alpine => "Alpine",
        }
    }

    /// The bit this family holds in a coverage mask.
    const fn bit(self) -> u8 {
        match self {
            Self::Debian => 1,
            Self::Fedora => 2,
            Self::Arch => 4,
            Self::Alpine => 8,
        }
    }
}

/// How an install command in the table was verified.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Verified {
    /// A CI job installs the package and builds the triple with it.
    CiJob(&'static str),
    /// The distribution's package index lists the package and the compiler it
    /// ships; no CI job runs it.
    PackageIndex,
}

/// What a host of another architecture than the triple's does to get a C
/// compiler for it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum CrossArchAdvice {
    /// No distribution package ships a musl cross compiler, so the user names
    /// one through the row's [`TargetToolchainRow::cc_env`].
    SetCcEnv,
}

/// The host toolchain one static triple needs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TargetToolchainRow {
    /// The triple this row describes.
    pub triple: StaticTriple,
    /// The variable cc-rs reads first for this triple's C compiler:
    /// `CC_` and the triple with every `-` written `_`.
    pub cc_env: &'static str,
    /// The C compiler names to probe, most specific first.
    pub cc_candidates: &'static [CcCandidate],
    /// The command that installs a native musl C compiler on a host of the
    /// triple's architecture, one per [`PackageFamily`].
    pub same_arch_packages: &'static [(PackageFamily, &'static str)],
    /// What a host of another architecture does instead.
    pub cross_arch: CrossArchAdvice,
    /// How each family's command in [`Self::same_arch_packages`] was verified,
    /// one per [`PackageFamily`].
    pub verified: &'static [(PackageFamily, Verified)],
}

impl TargetToolchainRow {
    /// The command installing a native musl compiler on `family`.
    #[must_use]
    pub fn install_command(&self, family: PackageFamily) -> Option<&'static str> {
        self.same_arch_packages
            .iter()
            .find(|(listed, _)| *listed == family)
            .map(|(_, command)| *command)
    }

    /// How `family`'s install command was verified.
    #[must_use]
    pub fn verified_by(&self, family: PackageFamily) -> Option<Verified> {
        self.verified
            .iter()
            .find(|(listed, _)| *listed == family)
            .map(|(_, how)| *how)
    }
}

/// The native musl compiler install command per family.
///
/// Every package listed ships `musl-gcc`, except Alpine's: Alpine's own C
/// library is musl, so `build-base`'s native `cc` already targets it.
const NATIVE_MUSL_PACKAGES: &[(PackageFamily, &str)] = &[
    (PackageFamily::Debian, "sudo apt install musl-tools"),
    (PackageFamily::Fedora, "sudo dnf install musl-gcc"),
    (PackageFamily::Arch, "sudo pacman -S --needed musl"),
    (PackageFamily::Alpine, "sudo apk add build-base"),
];

const X8664_LINUX_MUSL: TargetToolchainRow = TargetToolchainRow {
    triple: StaticTriple::X8664LinuxMusl,
    cc_env: "CC_x86_64_unknown_linux_musl",
    cc_candidates: &[CcCandidate::X8664LinuxMuslGcc, CcCandidate::MuslGcc],
    same_arch_packages: NATIVE_MUSL_PACKAGES,
    cross_arch: CrossArchAdvice::SetCcEnv,
    verified: &[
        (PackageFamily::Debian, Verified::CiJob("linux-static-x64")),
        (PackageFamily::Fedora, Verified::PackageIndex),
        (PackageFamily::Arch, Verified::PackageIndex),
        (PackageFamily::Alpine, Verified::PackageIndex),
    ],
};

const AARCH64_LINUX_MUSL: TargetToolchainRow = TargetToolchainRow {
    triple: StaticTriple::Aarch64LinuxMusl,
    cc_env: "CC_aarch64_unknown_linux_musl",
    cc_candidates: &[CcCandidate::Aarch64LinuxMuslGcc, CcCandidate::MuslGcc],
    same_arch_packages: NATIVE_MUSL_PACKAGES,
    cross_arch: CrossArchAdvice::SetCcEnv,
    verified: &[
        (PackageFamily::Debian, Verified::CiJob("linux-static-arm64")),
        (PackageFamily::Fedora, Verified::PackageIndex),
        (PackageFamily::Arch, Verified::PackageIndex),
        (PackageFamily::Alpine, Verified::PackageIndex),
    ],
};

/// Whether `env` is `CC_` followed by `triple` with every `-` written `_`.
#[must_use]
pub const fn is_underscored_cc_env(triple: &str, env: &str) -> bool {
    let mut env = env.as_bytes();
    match env {
        [b'C', b'C', b'_', rest @ ..] => env = rest,
        _ => return false,
    }
    let mut triple = triple.as_bytes();
    while let ([t, triple_rest @ ..], [e, env_rest @ ..]) = (triple, env) {
        let expected = if *t == b'-' { b'_' } else { *t };
        if *e != expected {
            return false;
        }
        triple = triple_rest;
        env = env_rest;
    }
    triple.is_empty() && env.is_empty()
}

/// Whether `a` and `b` are the same bytes.
const fn same_str(a: &str, b: &str) -> bool {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    while let ([x, a_rest @ ..], [y, b_rest @ ..]) = (a, b) {
        if *x != *y {
            return false;
        }
        a = a_rest;
        b = b_rest;
    }
    a.is_empty() && b.is_empty()
}

/// The coverage mask of every family, each bit set once.
const EVERY_FAMILY: u8 = {
    let mut mask = 0u8;
    let mut families: &[PackageFamily] = &PackageFamily::ALL;
    while let [family, rest @ ..] = families {
        mask |= family.bit();
        families = rest;
    }
    mask
};

/// Whether every row agrees with the facts it restates.
///
/// One pass over the rows: each row is the one its triple's
/// [`StaticTriple::toolchain`] returns, its `cc_env` is the underscored triple,
/// every candidate committed to an architecture names the triple's, and each
/// family appears exactly once in its install commands and its verifications.
/// [`StaticTriple::SUPPORTED`] spells [`StaticTriple::ALL`] in order.
const fn table_is_consistent() -> bool {
    let mut triples: &[StaticTriple] = &StaticTriple::ALL;
    let mut spellings: &[&str] = StaticTriple::SUPPORTED;
    while let ([triple, triples_rest @ ..], [spelling, spellings_rest @ ..]) = (triples, spellings)
    {
        let row = triple.toolchain();
        if !matches!(
            (row.triple, *triple),
            (StaticTriple::X8664LinuxMusl, StaticTriple::X8664LinuxMusl)
                | (
                    StaticTriple::Aarch64LinuxMusl,
                    StaticTriple::Aarch64LinuxMusl
                )
        ) || !same_str(triple.as_str(), spelling)
            || !is_underscored_cc_env(triple.as_str(), row.cc_env)
            || !candidates_fit(row.cc_candidates, triple.arch())
            || family_mask(row.same_arch_packages) != Some(EVERY_FAMILY)
            || verified_mask(row.verified) != Some(EVERY_FAMILY)
        {
            return false;
        }
        triples = triples_rest;
        spellings = spellings_rest;
    }
    triples.is_empty() && spellings.is_empty()
}

/// Whether `candidates` is non-empty and none names another architecture.
const fn candidates_fit(candidates: &[CcCandidate], arch: CpuArch) -> bool {
    if candidates.is_empty() {
        return false;
    }
    let mut rest = candidates;
    while let [candidate, later @ ..] = rest {
        match (candidate.arch(), arch) {
            (None, _)
            | (Some(CpuArch::X8664), CpuArch::X8664)
            | (Some(CpuArch::Aarch64), CpuArch::Aarch64) => {}
            (Some(_), _) => return false,
        }
        rest = later;
    }
    true
}

/// The families `commands` lists, or `None` when one is listed twice.
const fn family_mask(commands: &[(PackageFamily, &str)]) -> Option<u8> {
    let mut mask = 0u8;
    let mut rest = commands;
    while let [(family, _), later @ ..] = rest {
        if mask & family.bit() != 0 {
            return None;
        }
        mask |= family.bit();
        rest = later;
    }
    Some(mask)
}

/// The families `verified` lists, or `None` when one is listed twice.
const fn verified_mask(verified: &[(PackageFamily, Verified)]) -> Option<u8> {
    let mut mask = 0u8;
    let mut rest = verified;
    while let [(family, _), later @ ..] = rest {
        if mask & family.bit() != 0 {
            return None;
        }
        mask |= family.bit();
        rest = later;
    }
    Some(mask)
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a row's triple, `CC_` variable, candidate set, family commands or verification drift from one another [ledger #boundary]
const _: () = assert!(table_is_consistent());

#[cfg(test)]
mod tests {
    use super::{
        CcCandidate, CpuArch, PackageFamily, StaticTriple, TargetLinker, Verified, candidates_fit,
        family_mask, is_underscored_cc_env,
    };

    #[test]
    fn triple_parse_is_closed() {
        for triple in StaticTriple::ALL {
            assert_eq!(StaticTriple::parse(triple.as_str()), Some(triple));
        }
        for refused in [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-unknown-linux-musl ",
            "",
        ] {
            assert_eq!(StaticTriple::parse(refused), None, "{refused:?}");
        }
    }

    #[test]
    fn no_candidate_is_a_glibc_compiler() {
        for triple in StaticTriple::ALL {
            for candidate in triple.toolchain().cc_candidates {
                assert!(
                    !candidate.name().contains("-linux-gnu-"),
                    "{triple:?} probes the glibc compiler {}",
                    candidate.name()
                );
            }
        }
    }

    #[test]
    fn candidates_never_name_another_architecture() {
        for triple in StaticTriple::ALL {
            let row = triple.toolchain();
            assert_eq!(row.triple, triple);
            for candidate in row.cc_candidates {
                if let Some(arch) = candidate.arch() {
                    assert_eq!(arch, triple.arch(), "{triple:?}: {candidate:?}");
                    assert!(candidate.name().starts_with(arch.as_str()));
                }
            }
        }
        assert!(!candidates_fit(
            &[CcCandidate::X8664LinuxMuslGcc],
            CpuArch::Aarch64
        ));
        assert!(!candidates_fit(&[], CpuArch::X8664));
        assert!(candidates_fit(&[CcCandidate::MuslGcc], CpuArch::Aarch64));
    }

    #[test]
    fn cc_env_is_the_underscored_triple() {
        for triple in StaticTriple::ALL {
            let row = triple.toolchain();
            assert_eq!(
                row.cc_env,
                format!("CC_{}", triple.as_str().replace('-', "_"))
            );
            assert!(is_underscored_cc_env(triple.as_str(), row.cc_env));
        }
        let x64 = StaticTriple::X8664LinuxMusl.as_str();
        for refused in [
            "CC_x86_64-unknown-linux-musl",
            "CC_x86_64_unknown_linux_mus",
            "CC_x86_64_unknown_linux_musl_",
            "TARGET_CC",
            "CC",
            "",
        ] {
            assert!(!is_underscored_cc_env(x64, refused), "{refused:?}");
        }
    }

    #[test]
    fn every_family_has_one_command_and_one_verification() {
        for triple in StaticTriple::ALL {
            let row = triple.toolchain();
            for family in PackageFamily::ALL {
                assert!(
                    row.install_command(family).is_some(),
                    "{triple:?} {family:?}"
                );
                assert!(row.verified_by(family).is_some(), "{triple:?} {family:?}");
            }
        }
        assert_eq!(
            family_mask(&[(PackageFamily::Debian, "a"), (PackageFamily::Debian, "b")]),
            None
        );
    }

    #[test]
    fn debian_commands_are_proven_by_a_ci_job_per_triple() {
        let x64 = StaticTriple::X8664LinuxMusl.toolchain();
        let arm = StaticTriple::Aarch64LinuxMusl.toolchain();
        assert_eq!(
            x64.verified_by(PackageFamily::Debian),
            Some(Verified::CiJob("linux-static-x64"))
        );
        assert_eq!(
            arm.verified_by(PackageFamily::Debian),
            Some(Verified::CiJob("linux-static-arm64"))
        );
    }

    #[test]
    fn supported_spells_every_triple_in_order() {
        let spelled: Vec<&str> = StaticTriple::ALL.iter().map(|t| t.as_str()).collect();
        assert_eq!(spelled, StaticTriple::SUPPORTED);
    }

    #[test]
    fn aarch64_links_through_rust_lld() {
        assert_eq!(StaticTriple::X8664LinuxMusl.linker(), TargetLinker::HostCc);
        assert_eq!(
            StaticTriple::Aarch64LinuxMusl.linker(),
            TargetLinker::RustLld
        );
    }
}
