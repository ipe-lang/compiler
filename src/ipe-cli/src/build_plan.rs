//! Typed resolution of a static-build request into a backend
//! [`StaticPlan`] — parse, don't validate (design:
//! `docs/architecture/static-compilation.md`).
//!
//! The request arrives through three precedence layers — CLI flags, env
//! (`IPE_STATIC` / `IPE_TARGET` / `IPE_ALLOC`), `package.ipe` `[rust]` — merged
//! per-field (CLI > env > manifest) and resolved ONCE into
//! `Result<Option<StaticPlan>, Refusal>` before any compilation starts.
//! Downstream code sees either `None` (a normal dynamic build) or a plan
//! whose every gate already passed; an illegal combination never constructs
//! a plan, it surfaces a loud, typed [`Refusal`].

use std::fmt;

use ipe_backend_rust::static_build::{CProfile, StaticAllocator, StaticPlan, StaticTriple};

use crate::remote_ingest::{LocalCeiling, LocalSource, TOOL_QUERY_LIMITS, run_local};
use crate::text;

/// The user's allocator choice before AUTO resolution — a closed enum.
///
/// [`Self::parse`] rejects anything outside it (including `jemalloc` /
/// `snmalloc`, which the design documents and rejects) — no silent string
/// fall-through.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum AllocatorChoice {
    /// Resolve by target: musl-static → dlmalloc.
    #[default]
    Auto,
    /// The target libc's malloc — honoured as asked.
    ///
    /// On musl it is several times slower on allocation-heavy work than the dlmalloc default, which
    /// the `--allocator` help states; choosing it is the acknowledgment.
    System,
    /// Pure-Rust dlmalloc (the static default).
    Dlmalloc,
    /// Pure-Rust talc — parses (the enum stays closed and stable) but is
    /// refused at resolution until an arena design lands (amendment A1).
    Talc,
    /// C mimalloc — explicit opt-in carrying a C toolchain + vendored C.
    Mimalloc,
}

impl AllocatorChoice {
    /// Parse a user-supplied allocator name.
    ///
    /// # Errors
    /// [`Refusal::UnknownAllocator`] for any name outside the closed set.
    pub fn parse(s: &str) -> Result<Self, Refusal> {
        match s {
            "auto" => Ok(Self::Auto),
            "system" => Ok(Self::System),
            "dlmalloc" => Ok(Self::Dlmalloc),
            "talc" => Ok(Self::Talc),
            "mimalloc" => Ok(Self::Mimalloc),
            other => Err(Refusal::UnknownAllocator {
                got: other.to_owned(),
            }),
        }
    }
}

/// One precedence layer of the static request (CLI, env, or `package.ipe`).
/// Every field is `Option` so a layer overrides only what it actually sets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StaticRequestLayer {
    /// `--static` / `IPE_STATIC` / `[rust] static`.
    pub static_build: Option<bool>,
    /// `--target` / `IPE_TARGET` / `[rust] target` — a rustc triple string,
    /// parsed into the closed [`StaticTriple`] set at resolution.
    pub target: Option<String>,
    /// `--allocator` / `IPE_ALLOC` / `[rust] allocator`.
    pub allocator: Option<AllocatorChoice>,
    /// `--cfree` / `IPE_CFREE` / `[rust] cFree` — request a build that links
    /// no C. Resolved into [`CProfile::CFree`], where no C-requiring allocator
    /// can be paired with it.
    pub c_free: Option<bool>,
}

impl StaticRequestLayer {
    /// Per-field precedence merge: `self` wins over `weaker`.
    #[must_use]
    pub fn or(self, weaker: Self) -> Self {
        Self {
            static_build: self.static_build.or(weaker.static_build),
            target: self.target.or(weaker.target),
            allocator: self.allocator.or(weaker.allocator),
            c_free: self.c_free.or(weaker.c_free),
        }
    }
}

/// Read the env layer (`IPE_STATIC` / `IPE_TARGET` / `IPE_ALLOC`).
///
/// # Errors
/// [`Refusal::InvalidBool`] / [`Refusal::UnknownAllocator`] — a set-but-
/// malformed variable is refused, never silently ignored.
pub fn env_layer() -> Result<StaticRequestLayer, Refusal> {
    let static_build = match ipe_env::var("IPE_STATIC") {
        Ok(v) => Some(parse_bool("IPE_STATIC", &v)?),
        Err(_) => None,
    };
    let target = ipe_env::var("IPE_TARGET").ok();
    let allocator = match ipe_env::var("IPE_ALLOC") {
        Ok(v) => Some(AllocatorChoice::parse(&v)?),
        Err(_) => None,
    };
    let c_free = match ipe_env::var("IPE_CFREE") {
        Ok(v) => Some(parse_bool("IPE_CFREE", &v)?),
        Err(_) => None,
    };
    Ok(StaticRequestLayer {
        static_build,
        target,
        allocator,
        c_free,
    })
}

/// Parse a boolean request value (`package.ipe` setting or env var).
///
/// # Errors
/// [`Refusal::InvalidBool`] naming the source and the malformed value.
pub fn parse_bool(source: &'static str, v: &str) -> Result<bool, Refusal> {
    match v {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        other => Err(Refusal::InvalidBool {
            source,
            got: other.to_owned(),
        }),
    }
}

/// A typed reason a static-build request cannot be honoured. Surfaced
/// through `CliError::StaticRefusal`; every message is actionable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The allocator name is outside the closed set.
    UnknownAllocator { got: String },
    /// The requested triple is not a supported static target.
    UnknownStaticTarget { got: String },
    /// `--target` was given without `--static` — cross-compiling a dynamic
    /// build is not a wired path, and silently ignoring the flag would lie.
    TargetRequiresStatic { got: String },
    /// A non-default allocator was requested for a dynamic build — dynamic
    /// allocator selection is not a wired path.
    AllocatorRequiresStatic { got: AllocatorChoice },
    /// talc as a hosted `#[global_allocator]` needs an unsafe static arena
    /// with a hard heap cap — deferred until an arena design passes the
    /// no-unsafe gate (design amendment A1).
    TalcRequiresArenaDesign,
    /// The program is an `Ipe.WebView` app; it links the system webview and
    /// can never be a static artifact.
    WebviewStatic,
    /// The rustup toolchain has no std for the target.
    TargetNotInstalled { triple: &'static str },
    /// The dependency graph carries C compile units (`zstd`, `ring`) and no
    /// musl-capable C compiler is reachable.
    MuslCCompilerMissing { triple: &'static str },
    /// A C-requiring allocator was requested alongside `--cfree`. `mimalloc`
    /// vendors and links C; `system` is the target libc's C malloc — neither
    /// can exist in a C-free artifact.
    AllocatorRequiresC { got: AllocatorChoice },
    /// `--cfree` was requested, but the pure-Rust dependency swaps that make the
    /// default emitted graph link no C (`flate2`/`zstd` → pure-Rust codecs, a
    /// `ring`-free rustls provider) have not landed. The plan axis is wired end
    /// to end; honouring the flag now would emit a C-carrying build while
    /// skipping the C-compiler preflight — a build that lies about its promise
    /// and fails at link time. Refused until the swaps land.
    CfreeNotYetWired,
    /// A boolean request value (env var or `package.ipe` setting) is malformed.
    InvalidBool { source: &'static str, got: String },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnknownAllocator { got } => text::unknown_allocator(&format_args!("{got:?}")),
            Self::UnknownStaticTarget { got } => text::unknown_static_target(
                &format_args!("{got:?}"),
                &StaticTriple::SUPPORTED.join(", "),
            ),
            Self::TargetRequiresStatic { got } => text::target_requires_static(got),
            Self::AllocatorRequiresStatic { got } => {
                text::allocator_requires_static(&format_args!("{got:?}"))
            }
            Self::TalcRequiresArenaDesign => text::msg::talc_requires_arena_design(),
            Self::WebviewStatic => text::msg::webview_static(),
            Self::TargetNotInstalled { triple } => text::target_not_installed(triple),
            Self::MuslCCompilerMissing { triple } => {
                text::musl_c_compiler_missing(triple, &triple.replace('-', "_"))
            }
            Self::AllocatorRequiresC {
                got: got @ AllocatorChoice::Mimalloc,
            } => text::mimalloc_requires_c(&format_args!("{got:?}")),
            Self::AllocatorRequiresC { got } => {
                text::libc_allocator_requires_c(&format_args!("{got:?}"))
            }
            Self::CfreeNotYetWired => text::msg::cfree_not_yet_wired(),
            Self::InvalidBool { source, got } => {
                text::invalid_bool(source, &format_args!("{got:?}"))
            }
        };
        f.write_str(&message)
    }
}

/// Resolve the merged request into `Ok(None)` (dynamic build), a
/// [`StaticPlan`], or a [`Refusal`]. Pure — the AUTO table and every
/// combination gate live here and nowhere else.
///
/// # Errors
/// The [`Refusal`] naming the first gate the request fails.
pub fn resolve(merged: &StaticRequestLayer) -> Result<Option<StaticPlan>, Refusal> {
    let static_build = merged.static_build.unwrap_or(false);

    if !static_build {
        if let Some(target) = &merged.target {
            return Err(Refusal::TargetRequiresStatic {
                got: target.clone(),
            });
        }
        match merged.allocator.unwrap_or_default() {
            AllocatorChoice::Auto | AllocatorChoice::System => return Ok(None),
            got @ (AllocatorChoice::Dlmalloc
            | AllocatorChoice::Talc
            | AllocatorChoice::Mimalloc) => {
                return Err(Refusal::AllocatorRequiresStatic { got });
            }
        }
    }

    let triple = match &merged.target {
        None => StaticTriple::default(),
        Some(t) => {
            StaticTriple::parse(t).ok_or_else(|| Refusal::UnknownStaticTarget { got: t.clone() })?
        }
    };

    let c_free = merged.c_free.unwrap_or(false);
    let choice = merged.allocator.unwrap_or_default();

    // A C-free artifact links no C, so it can carry only the pure-Rust
    // allocator. Reject a C-requiring allocator here — before a plan is
    // constructed — so the contradiction never reaches the `CProfile` ADT (its
    // `CFree` variant has no allocator field to hold it). `Auto`/`Dlmalloc`
    // resolve to the pure-Rust dlmalloc and compose with C-free.
    if c_free {
        match choice {
            AllocatorChoice::Auto | AllocatorChoice::Dlmalloc => {}
            got @ (AllocatorChoice::Mimalloc | AllocatorChoice::System) => {
                return Err(Refusal::AllocatorRequiresC { got });
            }
            AllocatorChoice::Talc => return Err(Refusal::TalcRequiresArenaDesign),
        }
        // The C-free plan axis is wired end to end (flag → layer → profile →
        // preflight-skip), but the pure-Rust dependency swaps that make the
        // default graph actually link no C are a follow-up. Until they land,
        // honouring `--cfree` would emit a C-carrying build while skipping the
        // C-compiler preflight — a build that fails at link time. Refuse loudly.
        return Err(Refusal::CfreeNotYetWired);
    }

    let allocator = match choice {
        // AUTO on a musl-static target resolves to dlmalloc: pure Rust,
        // clears the musl-malloc cliff.
        AllocatorChoice::Auto | AllocatorChoice::Dlmalloc => StaticAllocator::Dlmalloc,
        AllocatorChoice::Mimalloc => StaticAllocator::Mimalloc,
        // An explicit `system` is the user's deliberate choice: honoured.
        AllocatorChoice::System => StaticAllocator::System,
        AllocatorChoice::Talc => return Err(Refusal::TalcRequiresArenaDesign),
    };

    Ok(Some(StaticPlan {
        triple,
        c_profile: CProfile::WithLibc { allocator },
    }))
}

/// Toolchain preflight for a resolved static plan.
///
/// The target's std must be installed and — unless the plan is C-free — a C
/// compiler that targets the plan's triple must be reachable, because the
/// default emitted dependency graph carries C compile units (`zstd`, `ring`).
/// Runs before the compile pipeline so the failure is an actionable refusal,
/// not a cryptic cargo error minutes later.
///
/// The probed compiler names come from the plan's triple
/// ([`StaticTriple::cc_candidates`]) so an aarch64 static build does not probe
/// `x86_64`-only compiler names (which would spuriously pass on an `x86_64` host).
/// Under a C-free plan the C-compiler check is skipped — there is no C unit to
/// compile.
///
/// Fail-soft when `rustup` itself is absent (non-rustup toolchains may well
/// have the target); the C-compiler check honours the standard `CC_*` /
/// `TARGET_CC` overrides before probing `PATH`.
///
/// # Errors
/// [`Refusal::TargetNotInstalled`] / [`Refusal::MuslCCompilerMissing`].
pub fn preflight(plan: &StaticPlan) -> Result<(), Refusal> {
    let installed = rustup_installed_targets();
    let cc_present = ipe_env::var_os(format!("CC_{}", plan.triple.as_str().replace('-', "_")))
        .is_some()
        || ipe_env::var_os("TARGET_CC").is_some()
        || plan
            .triple
            .cc_candidates()
            .iter()
            .any(|name| binary_on_path(name));
    preflight_with(plan, installed.as_deref(), cc_present)
}

/// [`preflight`]'s pure core.
///
/// The toolchain observations are injected as data so the gates are
/// unit-testable without a rustup installation. `installed` = `None` means
/// rustup is absent (fail-soft: skip the check). `c_cc_present` is ignored
/// when the plan is C-free — the C units it would satisfy are not in the graph.
///
/// # Errors
/// [`Refusal::TargetNotInstalled`] / [`Refusal::MuslCCompilerMissing`].
pub fn preflight_with(
    plan: &StaticPlan,
    installed: Option<&[String]>,
    c_cc_present: bool,
) -> Result<(), Refusal> {
    if let Some(targets) = installed
        && !targets.iter().any(|t| t == plan.triple.as_str())
    {
        return Err(Refusal::TargetNotInstalled {
            triple: plan.triple.as_str(),
        });
    }
    if !plan.is_c_free() && !c_cc_present {
        return Err(Refusal::MuslCCompilerMissing {
            triple: plan.triple.as_str(),
        });
    }
    Ok(())
}

/// The installed rustup targets, or `None` when `rustup` cannot be run
/// (absent or failing — both fail-soft).
fn rustup_installed_targets() -> Option<Vec<String>> {
    installed_targets_of(std::ffi::OsStr::new("rustup"), TOOL_QUERY_LIMITS)
}

/// The targets `rustup target list --installed` reports, the query held to `ceiling`.
///
/// `None` when the query cannot start, exits non-zero, crosses a ceiling (its
/// process group is killed), or prints a list that is not UTF-8: the check is
/// skipped, as when rustup is absent, and the cargo build that follows stays
/// the authority on whether the target's std is present.
fn installed_targets_of(rustup: &std::ffi::OsStr, ceiling: LocalCeiling) -> Option<Vec<String>> {
    let mut query = std::process::Command::new(rustup);
    query.args(["target", "list", "--installed"]);
    let output = run_local(query, ceiling, LocalSource::ToolQuery).ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    Some(text.lines().map(str::to_owned).collect())
}

/// Whether an executable named `name` exists on `PATH`.
fn binary_on_path(name: &str) -> bool {
    ipe_env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(name).is_file()))
}

#[cfg(test)]
mod tests {
    use super::{
        AllocatorChoice, Refusal, StaticRequestLayer, parse_bool, preflight_with, resolve,
    };
    use ipe_backend_rust::static_build::{CProfile, StaticAllocator, StaticPlan, StaticTriple};

    /// A [`StaticPlan`] carrying a C-requiring allocator (the common test
    /// shape). C-free plans are built directly with [`CProfile::CFree`].
    const fn with_libc(triple: StaticTriple, allocator: StaticAllocator) -> StaticPlan {
        StaticPlan {
            triple,
            c_profile: CProfile::WithLibc { allocator },
        }
    }

    fn layer(
        static_build: Option<bool>,
        target: Option<&str>,
        allocator: Option<AllocatorChoice>,
    ) -> StaticRequestLayer {
        StaticRequestLayer {
            static_build,
            target: target.map(str::to_owned),
            allocator,
            c_free: None,
        }
    }

    #[test]
    fn allocator_parse_is_closed() {
        assert_eq!(AllocatorChoice::parse("auto"), Ok(AllocatorChoice::Auto));
        assert_eq!(
            AllocatorChoice::parse("dlmalloc"),
            Ok(AllocatorChoice::Dlmalloc)
        );
        assert!(matches!(
            AllocatorChoice::parse("jemalloc"),
            Err(Refusal::UnknownAllocator { .. })
        ));
        assert!(matches!(
            AllocatorChoice::parse("snmalloc"),
            Err(Refusal::UnknownAllocator { .. })
        ));
        assert!(matches!(
            AllocatorChoice::parse(""),
            Err(Refusal::UnknownAllocator { .. })
        ));
    }

    #[test]
    fn no_request_resolves_to_dynamic() {
        assert_eq!(resolve(&StaticRequestLayer::default()), Ok(None));
    }

    #[test]
    fn auto_static_picks_musl_dlmalloc() {
        let plan = resolve(&layer(Some(true), None, None));
        assert_eq!(
            plan,
            Ok(Some(with_libc(
                StaticTriple::X8664LinuxMusl,
                StaticAllocator::Dlmalloc
            )))
        );
    }

    #[test]
    fn explicit_musl_target_accepted_unknown_target_refused() {
        assert!(resolve(&layer(Some(true), Some("x86_64-unknown-linux-musl"), None)).is_ok());
        assert!(resolve(&layer(Some(true), Some("aarch64-unknown-linux-musl"), None)).is_ok());
        assert!(matches!(
            resolve(&layer(
                Some(true),
                Some("riscv64gc-unknown-linux-musl"),
                None
            )),
            Err(Refusal::UnknownStaticTarget { .. })
        ));
        assert!(matches!(
            resolve(&layer(Some(true), Some("x86_64-apple-darwin"), None)),
            Err(Refusal::UnknownStaticTarget { .. })
        ));
    }

    #[test]
    fn target_without_static_is_refused() {
        assert!(matches!(
            resolve(&layer(None, Some("x86_64-unknown-linux-musl"), None)),
            Err(Refusal::TargetRequiresStatic { .. })
        ));
    }

    #[test]
    fn nondefault_allocator_without_static_is_refused() {
        assert!(matches!(
            resolve(&layer(None, None, Some(AllocatorChoice::Mimalloc))),
            Err(Refusal::AllocatorRequiresStatic { .. })
        ));
        // auto/system are the dynamic identity — no refusal.
        assert_eq!(
            resolve(&layer(None, None, Some(AllocatorChoice::System))),
            Ok(None)
        );
    }

    #[test]
    fn an_explicit_system_allocator_on_musl_is_honoured() {
        assert_eq!(
            resolve(&layer(Some(true), None, Some(AllocatorChoice::System))),
            Ok(Some(with_libc(
                StaticTriple::X8664LinuxMusl,
                StaticAllocator::System
            )))
        );
    }

    #[test]
    fn talc_is_refused_until_the_arena_design_lands() {
        assert_eq!(
            resolve(&layer(Some(true), None, Some(AllocatorChoice::Talc))),
            Err(Refusal::TalcRequiresArenaDesign)
        );
    }

    #[test]
    fn mimalloc_optin_resolves() {
        assert_eq!(
            resolve(&layer(Some(true), None, Some(AllocatorChoice::Mimalloc))),
            Ok(Some(with_libc(
                StaticTriple::X8664LinuxMusl,
                StaticAllocator::Mimalloc
            )))
        );
    }

    #[test]
    fn cfree_refused_until_dep_swaps_land_and_c_allocator_is_unrepresentable() {
        // The plan axis is wired, but honouring --cfree before the pure-Rust
        // dependency swaps land would emit a C-carrying build that skips the
        // C-compiler preflight — refused loudly, never silently degraded.
        assert_eq!(
            resolve(&StaticRequestLayer {
                static_build: Some(true),
                c_free: Some(true),
                ..StaticRequestLayer::default()
            }),
            Err(Refusal::CfreeNotYetWired)
        );
        // A C-requiring allocator under --cfree is a contradiction: it is
        // refused at resolution so no `CProfile` ever pairs C-free with a
        // C allocator (the ADT has no such shape).
        for got in [AllocatorChoice::Mimalloc, AllocatorChoice::System] {
            assert_eq!(
                resolve(&StaticRequestLayer {
                    static_build: Some(true),
                    allocator: Some(got),
                    c_free: Some(true),
                    ..StaticRequestLayer::default()
                }),
                Err(Refusal::AllocatorRequiresC { got })
            );
        }
    }

    #[test]
    fn precedence_cli_beats_env_beats_toml() {
        let cli = layer(None, None, Some(AllocatorChoice::Mimalloc));
        let env = layer(Some(true), None, Some(AllocatorChoice::System));
        let toml = layer(Some(false), None, Some(AllocatorChoice::Dlmalloc));
        let merged = cli.or(env).or(toml);
        assert_eq!(
            merged,
            layer(
                Some(true), // env (CLI unset)
                None,
                Some(AllocatorChoice::Mimalloc)
            )
        );
    }

    #[test]
    fn bool_values_parse_closed() {
        assert_eq!(parse_bool("IPE_STATIC", "1"), Ok(true));
        assert_eq!(parse_bool("IPE_STATIC", "true"), Ok(true));
        assert_eq!(parse_bool("IPE_STATIC", "0"), Ok(false));
        assert_eq!(parse_bool("IPE_STATIC", "false"), Ok(false));
        assert!(matches!(
            parse_bool("IPE_STATIC", "yes"),
            Err(Refusal::InvalidBool { .. })
        ));
    }

    #[test]
    fn preflight_gates_target_and_cc() {
        let plan = with_libc(StaticTriple::X8664LinuxMusl, StaticAllocator::Dlmalloc);
        let musl = "x86_64-unknown-linux-musl".to_owned();
        let gnu = "x86_64-unknown-linux-gnu".to_owned();
        assert!(preflight_with(&plan, Some(&[gnu.clone(), musl.clone()]), true).is_ok());
        assert!(matches!(
            preflight_with(&plan, Some(&[gnu]), true),
            Err(Refusal::TargetNotInstalled { .. })
        ));
        assert!(matches!(
            preflight_with(&plan, Some(&[musl]), false),
            Err(Refusal::MuslCCompilerMissing { .. })
        ));
        // rustup absent → fail-soft on the target check, cc still gated.
        assert!(preflight_with(&plan, None, true).is_ok());
        assert!(preflight_with(&plan, None, false).is_err());
    }

    #[test]
    fn preflight_skips_cc_probe_under_cfree() {
        // A C-free plan has no C unit to compile, so a missing C compiler is
        // not a refusal — only the target-installed check still applies.
        let plan = StaticPlan {
            triple: StaticTriple::Aarch64LinuxMusl,
            c_profile: CProfile::CFree,
        };
        let musl = "aarch64-unknown-linux-musl".to_owned();
        assert!(preflight_with(&plan, Some(&[musl]), false).is_ok());
        assert!(preflight_with(&plan, None, false).is_ok());
        // The target check is still enforced under C-free.
        assert!(matches!(
            preflight_with(
                &plan,
                Some(&["x86_64-unknown-linux-musl".to_owned()]),
                false
            ),
            Err(Refusal::TargetNotInstalled { .. })
        ));
    }

    /// The rustup target query driven through a stub that runs a shell `body`.
    #[cfg(unix)]
    mod stubbed_rustup {
        use super::super::installed_targets_of;
        use crate::remote_ingest::{LocalWall, TOOL_QUERY_LIMITS};
        use std::os::unix::fs::PermissionsExt as _;
        use std::path::{Path, PathBuf};
        use std::time::{Duration, Instant};

        /// A fresh scratch base for `tag` holding a stub `rustup` that runs `body`.
        fn stub(tag: &str, body: &str) -> PathBuf {
            let base = ipe_test_temp::temp_root().join(format!(
                "ipe-build-plan-rustup-{tag}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(&base).expect("scratch base");
            let path = base.join("rustup");
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write stub");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("stub executable");
            path
        }

        /// Remove the scratch base holding the stub at `path`.
        fn clean(path: &Path) {
            if let Some(base) = path.parent() {
                let _ = std::fs::remove_dir_all(base);
            }
        }

        #[test]
        fn the_installed_targets_are_read_one_per_line() {
            let rustup = stub("ok", "echo x86_64-unknown-linux-musl\necho wasm32-wasip1");
            assert_eq!(
                installed_targets_of(rustup.as_os_str(), TOOL_QUERY_LIMITS),
                Some(vec![
                    "x86_64-unknown-linux-musl".to_owned(),
                    "wasm32-wasip1".to_owned()
                ])
            );
            clean(&rustup);
        }

        #[test]
        fn a_target_query_past_its_wall_is_skipped() {
            let rustup = stub("wall", "echo x86_64-unknown-linux-musl\nexec sleep 30");
            let started = Instant::now();
            let targets = installed_targets_of(
                rustup.as_os_str(),
                TOOL_QUERY_LIMITS.with_wall(LocalWall::of_secs::<1>()),
            );
            assert_eq!(targets, None, "a query stopped at its wall reports no list");
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "the query is stopped at its wall, not at the child's exit"
            );
            clean(&rustup);
        }

        #[test]
        fn a_target_query_flooding_stdout_is_skipped() {
            let rustup = stub(
                "flood",
                "echo x86_64-unknown-linux-musl\nhead -c 131072 /dev/zero | tr '\\0' 'x'",
            );
            assert_eq!(
                installed_targets_of(rustup.as_os_str(), TOOL_QUERY_LIMITS),
                None,
                "a query past its stdout ceiling reports no list"
            );
            clean(&rustup);
        }
    }
}
