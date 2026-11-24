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

/// The supported static triples and the host toolchain each needs live in the
/// one table every reader shares.
pub use ipe_target_toolchains::{CcCandidate, CpuArch, StaticTriple, TargetLinker};

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
/// concern). The linker follows the triple's [`TargetLinker`]: the host C
/// driver needs no pin, while `rust-lld` links self-contained against the musl
/// startup objects rustup ships with the target.
#[must_use]
pub fn cargo_config(plan: &StaticPlan) -> String {
    let link = match plan.triple.linker() {
        TargetLinker::HostCc => "",
        TargetLinker::RustLld => {
            ", \"-C\", \"linker=rust-lld\", \"-C\", \"link-self-contained=yes\""
        }
    };
    format!(
        "{CARGO_CONFIG_MARKER}\n\
         [target.{triple}]\n\
         rustflags = [\"-C\", \"target-feature=+crt-static\"{link}]\n",
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
        CARGO_CONFIG_MARKER, CProfile, StaticAllocator, StaticPlan, StaticTriple, TargetLinker,
        cargo_config, staticize_manifest,
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
    fn every_triple_config_follows_its_linker() {
        for triple in StaticTriple::ALL {
            let cfg = cargo_config(&StaticPlan {
                triple,
                c_profile: CProfile::CFree,
            });
            assert!(cfg.contains(&format!("[target.{}]", triple.as_str())));
            let pins_lld = cfg.contains("linker=rust-lld");
            assert_eq!(
                pins_lld,
                triple.linker() == TargetLinker::RustLld,
                "{triple:?}"
            );
            assert_eq!(cfg.contains("link-self-contained=yes"), pins_lld);
        }
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
            "aarch64 links through rust-lld self-contained"
        );
    }
}
