//! Static-build support for the emitted project (design:
//! `docs/architecture/static-compilation.md`).
//!
//! A fully-resolved [`StaticPlan`] arrives from the CLI's typed resolver —
//! every refusal gate (allocator cliff acknowledgment, unsupported target,
//! app-shape) has already passed by the time a plan reaches this module. The
//! module then makes the emitted crate static-correct **by construction**:
//!
//! * [`staticize_manifest`] activates exactly one `alloc_*` feature in the
//!   emitted `Cargo.toml`'s `default = [...]` list (the mutually-exclusive
//!   feature family the golden base manifest declares), so a standalone
//!   `cargo build --target <triple>` selects the planned allocator without
//!   any `--features` flag.
//! * [`cargo_config`] renders the emitted crate's `.cargo/config.toml`
//!   supplying `+crt-static` for the target, headed by
//!   [`CARGO_CONFIG_MARKER`] so the driver can recognise (and, on a later
//!   non-static build, remove) a file it generated.
//!
//! The webview-under-static refusal reads the backend's typed
//! [`ipe_backend::EmittedProject::uses_webview`] signal (a webview app links
//! the system webview and can never be a static artifact), not a re-parse of
//! the emitted manifest's default-feature list.
//!
//! Anchored-`replacen` surgery with fail-loud [`Diagnostic::CompilerBug`] on
//! anchor drift, exactly like the sibling `*_cargo_toml` functions in
//! [`crate::project`].

use ipe_diagnostics::{DResult, Diagnostic};

/// Target triples the static path supports — a closed set.
///
/// Parse, don't validate: the CLI parses `--target` into this enum and
/// refuses anything else, so an unverifiable triple can never reach cargo
/// and violate the SEAL. Growing the set (Windows `+crt-static`, wasm) means
/// adding a variant alongside a CI lane that proves it end-to-end.
///
/// Toolchain requirements per variant:
/// - [`Self::X8664LinuxMusl`]: `musl-tools` (apt) + `x86_64-unknown-linux-musl`
///   rustup target. Verified in CI on `ubuntu-latest`.
/// - [`Self::Aarch64LinuxMusl`]: `gcc-aarch64-linux-gnu` + `musl-cross` (or
///   `aarch64-linux-musl-gcc` from `musl.cc`) + `aarch64-unknown-linux-musl`
///   rustup target + `qemu-user-static` for cross-run verification.
///   CI: `ubuntu-24.04-arm` (native runner) or `ubuntu-latest` with the cross
///   toolchain installed. See `.github/workflows/static.yml` `linux-static-arm64`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum StaticTriple {
    /// `x86_64-unknown-linux-musl` — fully static ELF, zero runtime deps.
    /// The default when `--static` is given without `--target`.
    #[default]
    X8664LinuxMusl,
    /// `aarch64-unknown-linux-musl` — fully static `AArch64` ELF, zero runtime
    /// deps. Requires the `aarch64-unknown-linux-musl` rustup target and a
    /// musl-capable `AArch64` C linker (`aarch64-linux-musl-gcc` or equivalent).
    Aarch64LinuxMusl,
}

impl StaticTriple {
    /// The rustc target-triple spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X8664LinuxMusl => "x86_64-unknown-linux-musl",
            Self::Aarch64LinuxMusl => "aarch64-unknown-linux-musl",
        }
    }

    /// Parse a rustc triple into the supported set. `None` means the triple
    /// is not (yet) a supported static target — the CLI turns that into a
    /// typed refusal listing [`Self::SUPPORTED`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "x86_64-unknown-linux-musl" => Some(Self::X8664LinuxMusl),
            "aarch64-unknown-linux-musl" => Some(Self::Aarch64LinuxMusl),
            _ => None,
        }
    }

    /// Every supported triple, for refusal messages.
    pub const SUPPORTED: &'static [&'static str] =
        &["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"];

    /// C-compiler executable names the toolchain preflight probes on `PATH`
    /// for this triple, most-specific first.
    ///
    /// A C-carrying static build (the default: the emitted graph pulls the
    /// `zstd`/`ring` C units) needs a compiler that targets *this* triple. The
    /// names are architecture-specific: an `x86_64` host's
    /// `x86_64-linux-musl-gcc` cannot compile for aarch64, so probing it for an
    /// aarch64 plan would spuriously pass. aarch64 also accepts the
    /// widely-packaged GNU cross-compiler (`aarch64-linux-gnu-gcc`) because the
    /// bundled `rust-lld` self-contained link path supplies the musl startup
    /// objects — only the C units, not the final link, need the cross toolchain.
    #[must_use]
    pub const fn cc_candidates(self) -> &'static [&'static str] {
        match self {
            Self::X8664LinuxMusl => &["x86_64-linux-musl-gcc", "musl-gcc"],
            Self::Aarch64LinuxMusl => &["aarch64-linux-musl-gcc", "aarch64-linux-gnu-gcc"],
        }
    }
}

/// The allocator linked into a static artifact.
///
/// `System` is the target libc's malloc, constructed only from an explicit
/// `--allocator system` / `allocator = System` (on musl it is slower on
/// allocation-heavy work than the dlmalloc default).
/// `talc` has no variant: it is refused at CLI parse-resolution (hosted talc
/// needs an unsafe static arena — amendment A1), so an unsupported allocator
/// is unrepresentable in a plan.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StaticAllocator {
    /// Pure-Rust dlmalloc — the default for every static plan.
    Dlmalloc,
    /// C mimalloc — explicit opt-in (C toolchain + vendored C in the artifact).
    Mimalloc,
    /// The target libc's malloc — on musl this is the 0.14× cliff; only
    /// reachable through the acknowledgment gate.
    System,
}

impl StaticAllocator {
    /// The emitted cargo feature activating this allocator, or `None` for
    /// `System` (no feature ⇒ no `#[global_allocator]` item compiles).
    #[must_use]
    pub const fn feature(self) -> Option<&'static str> {
        match self {
            Self::Dlmalloc => Some("alloc_dlmalloc"),
            Self::Mimalloc => Some("alloc_mimalloc"),
            Self::System => None,
        }
    }
}

/// Whether a static artifact is permitted to link C, and — only where it is —
/// which allocator it carries.
///
/// This is make-invalid-states-unrepresentable applied to the C-free choice.
/// A C-free build links no C library at all, so it can carry only the pure-Rust
/// allocator; a C-requiring allocator (`Mimalloc`, which vendors and links C;
/// `System`, which is the target libc's C malloc) is a contradiction there. By
/// putting the allocator field *inside* [`Self::WithLibc`] and giving
/// [`Self::CFree`] no allocator field, the pair `{c-free, mimalloc}` cannot be
/// constructed — the contradiction is unrepresentable rather than guarded
/// against at runtime. The CLI resolver parses the flag combination into this
/// ADT once; downstream code receives only a valid profile, never a bool + an
/// allocator to re-check.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CProfile {
    /// The artifact links no C. Its allocator is necessarily the pure-Rust
    /// dlmalloc; there is no allocator field because no other choice is C-free.
    CFree,
    /// The artifact may link C (the default). The allocator is chosen here —
    /// the only place an allocator choice is offered.
    WithLibc { allocator: StaticAllocator },
}

impl CProfile {
    /// The allocator this profile links. C-free is always pure-Rust dlmalloc.
    #[must_use]
    pub const fn allocator(self) -> StaticAllocator {
        match self {
            Self::CFree => StaticAllocator::Dlmalloc,
            Self::WithLibc { allocator } => allocator,
        }
    }

    /// Whether the artifact is intended to link no C — the toolchain preflight
    /// skips the C-compiler probe under this profile (its whole reason, the
    /// `zstd`/`ring` C units, is gone).
    #[must_use]
    pub const fn is_c_free(self) -> bool {
        matches!(self, Self::CFree)
    }
}

/// A fully-resolved static build plan. Constructed only by the CLI's
/// resolver; reaching the emitter means every refusal gate already passed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StaticPlan {
    pub triple: StaticTriple,
    /// The C-linkage profile and (only where C is permitted) the allocator —
    /// one field, so a C-free plan cannot carry a C-requiring allocator.
    pub c_profile: CProfile,
}

impl StaticPlan {
    /// The allocator the emitted crate links.
    #[must_use]
    pub const fn allocator(self) -> StaticAllocator {
        self.c_profile.allocator()
    }

    /// Whether the plan links no C.
    #[must_use]
    pub const fn is_c_free(self) -> bool {
        self.c_profile.is_c_free()
    }
}

/// First line of every generated `.cargo/config.toml`.
///
/// The driver recognises a file starting with this marker as its own
/// output: it may overwrite or remove it, and will never touch a config a
/// user placed there by hand.
pub const CARGO_CONFIG_MARKER: &str =
    "# Generated by `ipe dev build --static` — do not edit; regenerated on every static build.";

/// Render the emitted crate's `.cargo/config.toml` for `plan`.
///
/// `+crt-static` produces the fully-static (static-pie) executable. No
/// `target-dir` key is ever written (the shared-target pin is the user's
/// concern), and no linker is pinned: the default driver links the verified
/// dep set (including the `zstd`/`ring` C units) when a musl-capable C
/// compiler is present — presence the CLI preflight has already checked.
#[must_use]
pub fn cargo_config(plan: &StaticPlan) -> String {
    // AArch64 links through the bundled `rust-lld` with a self-contained musl
    // startup, so a static AArch64 build needs only a C cross-compiler for the
    // C deps (zstd/ring) — no scarce `aarch64-linux-musl-gcc`. Native
    // x86_64-musl keeps the default linker.
    let cross_link = match plan.triple {
        StaticTriple::Aarch64LinuxMusl => {
            ", \"-C\", \"linker=rust-lld\", \"-C\", \"link-self-contained=yes\""
        }
        StaticTriple::X8664LinuxMusl => "",
    };
    format!(
        "{CARGO_CONFIG_MARKER}\n\
         [target.{triple}]\n\
         rustflags = [\"-C\", \"target-feature=+crt-static\"{cross_link}]\n",
        triple = plan.triple.as_str()
    )
}

/// Activate the chosen allocator feature in the emitted manifest.
///
/// Splices it as the LAST element of the `default = [...]` feature list —
/// the same generic closing-`]` anchor `server_cargo_toml` uses, so the
/// splice composes with every db/server/live/tui/webview surgery already
/// applied.
///
/// `System` is the identity: no feature ⇒ the emitted source's cfg-gated
/// allocator arms stay inert and the binary uses the target libc's malloc.
///
/// # Errors
///
/// [`Diagnostic::CompilerBug`] when the `default = [` anchor (or its closing
/// `]`) is absent, or when an `alloc_*` feature is already active — either
/// means the manifest drifted from the golden or the splice ran twice; both
/// are invariant breaches, never silently absorbed.
pub fn staticize_manifest(base: &str, allocator: StaticAllocator) -> DResult<String> {
    const DEFAULT_PREFIX: &str = "default = [";

    let Some(feature) = allocator.feature() else {
        return Ok(base.to_owned());
    };

    // Anchor on the `default = [` that BEGINS a line — never a `# … default = [`
    // comment that merely mentions the array (a manifest may document the anchor
    // in prose above it). A comment line starts with `#`, so the line-initial
    // constraint skips it.
    let pfx = base
        .match_indices(DEFAULT_PREFIX)
        .map(|(i, _)| i)
        .find(|&i| i == 0 || base.as_bytes().get(i - 1) == Some(&b'\n'))
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::static_build::staticize_manifest",
            detail: format!(
                "Cargo.toml line-initial anchor {DEFAULT_PREFIX:?} not found — golden drifted"
            ),
        })?;
    let search_from = pfx + DEFAULT_PREFIX.len();
    let rel = base
        .get(search_from..)
        .and_then(|s| s.find(']'))
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::static_build::staticize_manifest",
            detail: "default feature list has no closing ']' — golden drifted".to_owned(),
        })?;
    let close = search_from + rel;
    let default_list = base.get(search_from..close).unwrap_or("");
    if default_list.contains("alloc_") {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::static_build::staticize_manifest",
            detail: format!(
                "default feature list already activates an allocator ({default_list:?}) — \
                 the static splice must run exactly once"
            ),
        });
    }

    // Splice the allocator as the last element. An EMPTY list (`default = []` —
    // the dependency-model shape, where every runtime feature lives on the
    // `ipe_runtime` path dependency and the program crate's own default carries
    // only the allocator) takes the feature with no leading comma; a non-empty
    // list gets `, "feature"`.
    let sep = if default_list.trim().is_empty() {
        "\""
    } else {
        ", \""
    };
    let mut out = String::with_capacity(base.len() + feature.len() + 4);
    out.push_str(base.get(..close).unwrap_or(""));
    out.push_str(sep);
    out.push_str(feature);
    out.push('"');
    out.push_str(base.get(close..).unwrap_or(""));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        CARGO_CONFIG_MARKER, CProfile, StaticAllocator, StaticPlan, StaticTriple, cargo_config,
        staticize_manifest,
    };
    use ipe_diagnostics::DResult;

    /// The base manifest template — the exact text every emitted `Cargo.toml`
    /// starts from.
    const CARGO_TOML: &str = include_str!("../templates/Cargo.toml");

    fn default_line(manifest: &str) -> &str {
        manifest
            .lines()
            .find(|l| l.starts_with("default = ["))
            .unwrap_or("")
    }

    #[test]
    fn base_manifest_declares_the_alloc_family_but_activates_none() {
        assert!(CARGO_TOML.contains(r#"alloc_dlmalloc = ["dep:dlmalloc"]"#));
        assert!(CARGO_TOML.contains(r#"alloc_mimalloc = ["dep:mimalloc"]"#));
        assert!(
            !default_line(CARGO_TOML).contains("alloc_"),
            "default build must use the system allocator"
        );
        assert!(
            !CARGO_TOML.contains("static_alloc"),
            "the inherited static_alloc default must be gone"
        );
    }

    #[test]
    fn dlmalloc_splice_activates_exactly_one_alloc_feature() -> DResult<()> {
        let out = staticize_manifest(CARGO_TOML, StaticAllocator::Dlmalloc)?;
        let def = default_line(&out);
        assert!(def.contains(r#""alloc_dlmalloc""#), "{def}");
        assert_eq!(def.matches("alloc_").count(), 1, "{def}");
        Ok(())
    }

    #[test]
    fn mimalloc_splice_activates_exactly_one_alloc_feature() -> DResult<()> {
        let out = staticize_manifest(CARGO_TOML, StaticAllocator::Mimalloc)?;
        let def = default_line(&out);
        assert!(def.contains(r#""alloc_mimalloc""#), "{def}");
        assert_eq!(def.matches("alloc_").count(), 1, "{def}");
        Ok(())
    }

    #[test]
    fn system_splice_is_the_identity() -> DResult<()> {
        assert_eq!(
            staticize_manifest(CARGO_TOML, StaticAllocator::System)?,
            CARGO_TOML
        );
        Ok(())
    }

    #[test]
    fn double_splice_is_a_compiler_bug() -> DResult<()> {
        let once = staticize_manifest(CARGO_TOML, StaticAllocator::Dlmalloc)?;
        assert!(staticize_manifest(&once, StaticAllocator::Dlmalloc).is_err());
        Ok(())
    }

    #[test]
    fn anchor_miss_is_a_compiler_bug() {
        assert!(
            staticize_manifest("[package]\nname = \"x\"\n", StaticAllocator::Dlmalloc).is_err()
        );
    }

    #[test]
    fn splice_composes_with_server_style_appends() -> DResult<()> {
        // A db+server-shaped default list still gets exactly one allocator,
        // appended last.
        let base = CARGO_TOML.replacen(
            r#"default = ["json"]"#,
            r#"default = ["tokio", "crypto", "json", "db", "server"]"#,
            1,
        );
        let out = staticize_manifest(&base, StaticAllocator::Dlmalloc)?;
        assert!(
            default_line(&out)
                .contains(r#""tokio", "crypto", "json", "db", "server", "alloc_dlmalloc""#)
        );
        Ok(())
    }

    #[test]
    fn empty_dep_model_default_takes_the_allocator_without_a_leading_comma() -> DResult<()> {
        // The dependency-model emit carries every runtime feature on the
        // `ipe_runtime` path dependency, so the program crate's own list is
        // empty (`default = []`). The allocator must splice as the sole element
        // — `["alloc_dlmalloc"]`, NEVER the malformed `[, "alloc_dlmalloc"]`.
        let base = CARGO_TOML.replacen(r#"default = ["json"]"#, "default = []", 1);
        let out = staticize_manifest(&base, StaticAllocator::Dlmalloc)?;
        assert!(
            default_line(&out).contains(r#"default = ["alloc_dlmalloc"]"#),
            "{}",
            default_line(&out)
        );
        Ok(())
    }

    #[test]
    fn anchor_ignores_a_comment_that_mentions_the_default_list() -> DResult<()> {
        // A `# … default = [ …` comment above the real line must not shadow the
        // line-initial anchor: the allocator lands on the FEATURE line, and the
        // comment is left untouched.
        let base = "[features]\n\
                    # example: default = [\"json\"] is the anchor\n\
                    default = [\"json\"]\n";
        let out = staticize_manifest(base, StaticAllocator::Mimalloc)?;
        assert!(
            default_line(&out).contains(r#""alloc_mimalloc""#),
            "real default line must gain the allocator: {}",
            default_line(&out)
        );
        assert!(
            out.contains("# example: default = [\"json\"] is the anchor\n"),
            "the comment must be left verbatim"
        );
        Ok(())
    }

    #[test]
    fn cargo_config_pins_crt_static_and_nothing_else() {
        let cfg = cargo_config(&StaticPlan {
            triple: StaticTriple::X8664LinuxMusl,
            c_profile: CProfile::WithLibc {
                allocator: StaticAllocator::Dlmalloc,
            },
        });
        assert!(cfg.starts_with(CARGO_CONFIG_MARKER));
        assert!(cfg.contains("[target.x86_64-unknown-linux-musl]"));
        assert!(cfg.contains(r#""target-feature=+crt-static""#));
        assert!(
            !cfg.contains("target-dir"),
            "must not shadow the user's pin"
        );
        assert!(
            !cfg.contains("linker"),
            "no linker pin — preflight owns tooling checks"
        );
    }

    #[test]
    fn triple_parse_is_closed() {
        assert_eq!(
            StaticTriple::parse("x86_64-unknown-linux-musl"),
            Some(StaticTriple::X8664LinuxMusl)
        );
        assert_eq!(
            StaticTriple::parse("aarch64-unknown-linux-musl"),
            Some(StaticTriple::Aarch64LinuxMusl)
        );
        assert_eq!(StaticTriple::parse("x86_64-unknown-linux-gnu"), None);
        assert_eq!(StaticTriple::parse("aarch64-unknown-linux-gnu"), None);
        assert_eq!(StaticTriple::parse(""), None);
    }

    #[test]
    fn cc_candidates_are_triple_specific() {
        // x86_64 probes its own musl compilers and must NOT list an aarch64
        // name; aarch64 must NOT list the x86_64 name — a host carrying only
        // the wrong-arch compiler must not spuriously pass the preflight.
        let x64 = StaticTriple::X8664LinuxMusl.cc_candidates();
        let arm = StaticTriple::Aarch64LinuxMusl.cc_candidates();
        assert!(x64.contains(&"x86_64-linux-musl-gcc"));
        assert!(x64.contains(&"musl-gcc"));
        assert!(!x64.iter().any(|c| c.contains("aarch64")));
        assert!(arm.contains(&"aarch64-linux-musl-gcc"));
        assert!(arm.contains(&"aarch64-linux-gnu-gcc"));
        assert!(!arm.iter().any(|c| c.starts_with("x86_64")));
    }

    #[test]
    fn cfree_profile_forces_pure_rust_dlmalloc() {
        // The C-free profile carries no allocator field; its effective
        // allocator is pure-Rust dlmalloc, and no C-requiring allocator can be
        // paired with it because the enum simply has no such shape.
        assert_eq!(CProfile::CFree.allocator(), StaticAllocator::Dlmalloc);
        assert!(CProfile::CFree.is_c_free());
        assert!(
            !CProfile::WithLibc {
                allocator: StaticAllocator::Mimalloc
            }
            .is_c_free()
        );
    }

    #[test]
    fn aarch64_musl_cargo_config_pins_crt_static() {
        let cfg = cargo_config(&StaticPlan {
            triple: StaticTriple::Aarch64LinuxMusl,
            c_profile: CProfile::WithLibc {
                allocator: StaticAllocator::Dlmalloc,
            },
        });
        assert!(cfg.starts_with(CARGO_CONFIG_MARKER));
        assert!(cfg.contains("[target.aarch64-unknown-linux-musl]"));
        assert!(cfg.contains(r#""target-feature=+crt-static""#));
        assert!(
            !cfg.contains("target-dir"),
            "must not shadow the user's pin"
        );
        assert!(
            cfg.contains("linker=rust-lld"),
            "aarch64 pins rust-lld self-contained (portable, no scarce musl-cross-gcc)"
        );
    }
}
