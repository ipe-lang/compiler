//! Static-compilation gates (design: `docs/architecture/static-compilation.md`).
//!
//! Ungated tests assert the emitted-project SHAPE of a static plan (allocator
//! feature spliced into the manifest, generated `.cargo/config.toml`, stale-
//! config hygiene, CLI refusal wiring). The full proof — the emitted crate
//! cargo-builds for `x86_64-unknown-linux-musl`, `ldd` reports it static, and
//! it runs — is gated behind `IPE_E2E_STATIC=1` (it needs the musl target, a
//! musl-capable C compiler, and a cold multi-minute dependency build).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use ipe::{BuildOptions, CliError, RootFixture, build_fixture_with_options, build_plan};
use ipe_backend_rust::static_build::{
    CARGO_CONFIG_MARKER, CProfile, StaticAllocator, StaticPlan, StaticTriple,
};

mod support;

use support::repo_root;

/// The hello program as a project in a private scratch tree.
#[allow(clippy::expect_used)] // test helper: a failed fixture setup IS the failure
fn hello_project() -> RootFixture {
    RootFixture::main(
        "module Main exposing (main)\n\
         import Ipe.Io as Io\n\
         \n\
         main =\n    Io.println \"static hello\"\n",
    )
    .expect("the hello project resolves")
}

const fn dlmalloc_plan() -> StaticPlan {
    StaticPlan {
        triple: StaticTriple::X8664LinuxMusl,
        c_profile: CProfile::WithLibc {
            allocator: StaticAllocator::Dlmalloc,
        },
    }
}

fn default_line(manifest: &str) -> String {
    manifest
        .lines()
        .find(|l| l.starts_with("default = ["))
        .unwrap_or("")
        .to_owned()
}

/// A static build emits the allocator feature + the generated cargo config;
/// a subsequent dynamic build of the SAME out-dir restores the baseline
/// byte-identically and removes the generated config (stale-config hygiene —
/// `+crt-static` must never leak into later dynamic builds).
#[test]
fn static_emit_activates_dlmalloc_and_dynamic_rebuild_restores_baseline() {
    let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("static_emit_shape");
    let _ = std::fs::remove_dir_all(&scratch);
    let project = hello_project();
    let out = scratch.join("out");
    let runtime = e2e_support::require_runtime().into_path_buf();

    let statik = BuildOptions {
        static_plan: Some(dlmalloc_plan()),
        ..BuildOptions::default()
    };
    build_fixture_with_options(&project, &out, &runtime, &statik).expect("static build");

    let manifest = std::fs::read_to_string(out.join("Cargo.toml")).expect("emitted manifest");
    let def = default_line(&manifest);
    assert!(def.contains(r#""alloc_dlmalloc""#), "{def}");
    assert_eq!(
        def.matches("alloc_").count(),
        1,
        "exactly one allocator: {def}"
    );

    let config_path = out.join(".cargo").join("config.toml");
    let config = std::fs::read_to_string(&config_path).expect("generated cargo config");
    assert!(config.starts_with(CARGO_CONFIG_MARKER));
    assert!(config.contains("[target.x86_64-unknown-linux-musl]"));
    assert!(config.contains(r#""target-feature=+crt-static""#));
    assert!(!config.contains("target-dir"));

    // Dynamic rebuild of the same out-dir: baseline restored, config gone.
    build_fixture_with_options(&project, &out, &runtime, &BuildOptions::default())
        .expect("dynamic rebuild");
    let manifest = std::fs::read_to_string(out.join("Cargo.toml")).expect("emitted manifest");
    assert!(
        !default_line(&manifest).contains("alloc_"),
        "dynamic default build must not activate an allocator"
    );
    assert!(
        !config_path.exists(),
        "the generated static config must be removed by a dynamic rebuild"
    );
}

/// A hand-written (non-generated) `.cargo/config.toml` placed in an
/// ipe-owned output dir is never touched by the hygiene pass — only files
/// starting with the generated marker are ours to delete.
#[test]
fn dynamic_build_leaves_user_cargo_config_alone() {
    let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("static_emit_user_config");
    let _ = std::fs::remove_dir_all(&scratch);
    let project = hello_project();
    let out = scratch.join("out");
    let runtime = e2e_support::require_runtime().into_path_buf();

    // The first build claims `out`; the user's config lands in the owned dir.
    build_fixture_with_options(&project, &out, &runtime, &BuildOptions::default())
        .expect("first dynamic build");
    let config_path = out.join(".cargo").join("config.toml");
    std::fs::create_dir_all(out.join(".cargo")).expect("mk .cargo");
    let user_config = "# hand-written by a user\n[net]\noffline = false\n";
    std::fs::write(&config_path, user_config).expect("write user config");

    build_fixture_with_options(&project, &out, &runtime, &BuildOptions::default())
        .expect("dynamic rebuild");
    let after = std::fs::read_to_string(&config_path).expect("user config must survive");
    assert_eq!(after, user_config);
}

/// The mimalloc opt-in splices its own feature.
#[test]
fn static_emit_mimalloc_optin_activates_mimalloc() {
    let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("static_emit_mimalloc");
    let _ = std::fs::remove_dir_all(&scratch);
    let project = hello_project();
    let out = scratch.join("out");
    let runtime = e2e_support::require_runtime().into_path_buf();

    let statik = BuildOptions {
        static_plan: Some(StaticPlan {
            triple: StaticTriple::X8664LinuxMusl,
            c_profile: CProfile::WithLibc {
                allocator: StaticAllocator::Mimalloc,
            },
        }),
        ..BuildOptions::default()
    };
    build_fixture_with_options(&project, &out, &runtime, &statik).expect("static build");
    let manifest = std::fs::read_to_string(out.join("Cargo.toml")).expect("emitted manifest");
    let def = default_line(&manifest);
    assert!(def.contains(r#""alloc_mimalloc""#), "{def}");
    assert_eq!(def.matches("alloc_").count(), 1, "{def}");
}

/// CLI flag refusals are BOTH typed and artifact-free:
///
/// * **Typed** — each refusal is asserted to be its SPECIFIC `CliError` /
///   `Refusal` variant (not a bare "is an error"), so a refusal that silently
///   changed class — or degraded into a generic error — fails the test.
/// * **Artifact-free** — each invocation is given an explicit `--out <fresh dir>`
///   that does not exist beforehand; after the refusal, that directory must
///   STILL not exist. A refusal that leaked a partially-emitted crate (created
///   the out dir before validating flags) would fail here. The refusals fire at
///   the CLI/plan boundary, before any compilation or filesystem write, so the
///   out dir is never created.
#[test]
fn cli_refusals_are_typed_and_artifact_free() {
    let project = hello_project();
    let project_arg = project.path().to_string_lossy().into_owned();
    // A fresh, guaranteed-absent out dir per case; the refusal must not create it.
    let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("cli_refusal_out");
    let _ = std::fs::remove_dir_all(&scratch);
    let mut case = 0u32;
    let mut refuse = |args: &[&str], label: &str| -> CliError {
        let out = scratch.join(format!("case_{case}"));
        case += 1;
        assert!(
            !out.exists(),
            "{label}: out dir must be absent before the refusal"
        );
        let mut argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        argv.push("--out".into());
        argv.push(out.to_string_lossy().into_owned());
        let err = ipe::run_cli(&argv).expect_err(label);
        assert!(
            !out.exists(),
            "{label}: refusal must be artifact-free — out dir {} was created",
            out.display()
        );
        err
    };

    // Unknown allocator: the closed `--allocator` enum is parsed at the CLI
    // boundary, so an unknown name is a typed command-usage refusal there — never
    // reaching the build plan. The dispatcher wraps it as `CommandUsage` so the
    // caller shows `build`'s help; the reason still names the bad allocator.
    let err = refuse(
        &[
            "dev",
            "build",
            project_arg.as_str(),
            "--static",
            "--allocator",
            "jemalloc",
        ],
        "unknown allocator must refuse",
    );
    assert!(
        matches!(&err, CliError::CommandUsage { command, reason } if *command == "dev build" && reason.as_str().contains("jemalloc")),
        "got: {err:?}"
    );

    // --target without --static.
    let err = refuse(
        &[
            "dev",
            "build",
            project_arg.as_str(),
            "--target",
            "x86_64-unknown-linux-musl",
        ],
        "--target without --static must refuse",
    );
    assert!(
        matches!(
            err,
            CliError::StaticRefusal(build_plan::Refusal::TargetRequiresStatic { .. })
        ),
        "wrong refusal: {err:?}"
    );

    // Unsupported static target.
    let err = refuse(
        &[
            "dev",
            "build",
            project_arg.as_str(),
            "--static",
            "--target",
            "x86_64-apple-darwin",
        ],
        "mac static must refuse",
    );
    // The closed `--target` vocabulary is parsed at the CLI boundary, so an
    // unsupported triple is a command-usage refusal there, naming the value.
    assert!(
        matches!(&err, CliError::CommandUsage { command, reason } if *command == "dev build" && reason.as_str().contains("x86_64-apple-darwin")),
        "wrong refusal: {err:?}"
    );

    // talc is refused until the arena design lands.
    let err = refuse(
        &[
            "dev",
            "build",
            project_arg.as_str(),
            "--static",
            "--allocator",
            "talc",
        ],
        "talc must refuse",
    );
    assert!(
        matches!(
            err,
            CliError::StaticRefusal(build_plan::Refusal::TalcRequiresArenaDesign)
        ),
        "wrong refusal: {err:?}"
    );
}

/// The C-free axis rejects its contradictions at the CLI boundary, before any
/// compilation or filesystem write. `--cfree` with a C-requiring allocator is
/// unrepresentable in a plan (the [`ipe_backend_rust::static_build::CProfile`]
/// `CFree` variant carries no allocator field); `--cfree` alone is refused
/// until the pure-Rust dependency swaps land, since the build would still pull
/// C and honouring the flag would be a lie.
#[test]
fn cfree_contradictions_are_refused_at_the_cli_boundary() {
    let project = hello_project();
    let project_arg = project.path().to_string_lossy().into_owned();
    let err = ipe::run_cli(&[
        "dev".into(),
        "build".into(),
        project_arg.clone(),
        "--static".into(),
        "--cfree".into(),
        "--allocator".into(),
        "mimalloc".into(),
    ])
    .expect_err("mimalloc under --cfree must refuse");
    assert!(
        matches!(
            err,
            CliError::StaticRefusal(build_plan::Refusal::AllocatorRequiresC { .. })
        ),
        "wrong refusal: {err:?}"
    );

    let err = ipe::run_cli(&[
        "dev".into(),
        "build".into(),
        project_arg,
        "--static".into(),
        "--cfree".into(),
    ])
    .expect_err("--cfree must refuse until dep swaps land");
    assert!(
        matches!(
            err,
            CliError::StaticRefusal(build_plan::Refusal::CfreeNotYetWired)
        ),
        "wrong refusal: {err:?}"
    );
}

/// The `run` subcommand carries the same static surface as `build` (one
/// shared flag parser + resolver) — refusals fire identically, before any
/// compilation or filesystem write.
#[test]
fn run_subcommand_refuses_like_build() {
    let project = hello_project();
    let project_arg = project.path().to_string_lossy().into_owned();
    let err = ipe::run_cli(&[
        "dev".into(),
        "run".into(),
        project_arg.clone(),
        "--static".into(),
        "--allocator".into(),
        "talc".into(),
    ])
    .expect_err("talc must refuse on run too");
    assert!(
        matches!(
            err,
            CliError::StaticRefusal(build_plan::Refusal::TalcRequiresArenaDesign)
        ),
        "wrong refusal"
    );

    let err = ipe::run_cli(&[
        "dev".into(),
        "run".into(),
        project_arg,
        "--target".into(),
        "x86_64-unknown-linux-musl".into(),
    ])
    .expect_err("--target without --static must refuse on run too");
    assert!(
        matches!(
            err,
            CliError::StaticRefusal(build_plan::Refusal::TargetRequiresStatic { .. })
        ),
        "wrong refusal"
    );
}

/// `package.ipe`'s `Package.static` / `Package.allocator` stages parse into the
/// typed request layer; an unknown allocator constructor is refused at
/// manifest-parse time.
#[test]
fn package_ipe_rust_stages_parse_and_reject_typos() {
    let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("static_toml_rust");
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(scratch.join("src")).expect("mk src");
    std::fs::write(
        scratch.join("src").join("Main.ipe"),
        "module Main exposing (main)\n",
    )
    .expect("write Main.ipe");

    let manifest_path = scratch.join("package.ipe");
    std::fs::write(
        &manifest_path,
        "module Package exposing (package)\n\n\npackage =\n\
         \x20   { name = \"p\"\n\
         \x20   , build =\n\
         \x20       { database = Sqlite\n\
         \x20       , static = True\n\
         \x20       , allocator = Dlmalloc\n\
         \x20       }\n\
         \x20   }\n",
    )
    .expect("write package.ipe");
    let parsed = ipe::project::parse_manifest(&manifest_path).expect("parse");
    assert_eq!(
        parsed.static_request,
        build_plan::StaticRequestLayer {
            static_build: Some(true),
            target: None,
            allocator: Some(build_plan::AllocatorChoice::Dlmalloc),
            c_free: None,
        }
    );

    std::fs::write(
        &manifest_path,
        "module Package exposing (package)\n\n\npackage =\n\
         \x20   { name = \"p\"\n\
         \x20   , build = { allocator = Jemallocc }\n\
         \x20   }\n",
    )
    .expect("write package.ipe");
    let err = ipe::project::parse_manifest(&manifest_path).expect_err("typo must refuse");
    assert!(
        matches!(err, CliError::Usage(_)),
        "an unknown allocator constructor is a manifest-parse refusal: {err:?}"
    );
    assert!(
        err.to_string().contains("is not an allocator"),
        "the refusal must name the unknown allocator: {err}"
    );
}

/// TLS must stay rustls with the BUNDLED webpki roots in every manifest
/// source the emitted project is assembled from. A native-TLS or
/// native-roots backend links OpenSSL / reads the host cert store — either
/// silently breaks the fully-static musl artifact (dynamic libssl) or makes
/// it host-dependent (no `/etc/ssl` in a `scratch` container).
///
/// Four sources write dependency lines into an emitted `Cargo.toml`:
/// the golden base manifest, the vendored runtime's manifest, the surgery
/// strings in the backend's `project.rs`, and the crate names, versions, pins
/// and drivers of `crate_specs.rs`. All four are scanned.
///
/// The check has two halves, and the POSITIVE half is what makes it sound:
///
/// * **Negative** — no source's effective (non-comment) content may contain a
///   native backend or OS root-store spelling ([`native_backend_in`]).
///   Comment lines are stripped so a comment DOCUMENTING a deliberate exclusion
///   (the runtime manifest says "the `native-tls` feature is deliberately NOT
///   listed") is not a false positive.
/// * **Positive** — every TLS-capable dep's effective line must carry its
///   rustls arm (`reqwest`/`lettre`), `sqlx` must carry exactly its SSOT
///   features, and `tokio-tungstenite` none of its own TLS features. This is the
///   guard that survives the comment-stripping: a negative-only scan could not
///   tell a documented exclusion from an actual flip to native-tls, but a
///   flipped backend loses its rustls feature and fails the positive assert.
///   Comments can only ADD text, never remove a required feature, so the
///   positive half cannot be blinded.
#[test]
fn tls_stays_rustls_with_bundled_roots_in_every_manifest_source() {
    fn read(path: &Path) -> String {
        let text = std::fs::read_to_string(path);
        assert!(
            text.is_ok(),
            "read {}: {:?}",
            path.display(),
            text.as_ref().err()
        );
        text.unwrap_or_default()
    }
    fn dep_line<'a>(text: &'a str, dep: &str, path: &Path) -> &'a str {
        let line = text.lines().find(|l| l.trim_start().starts_with(dep));
        assert!(line.is_some(), "{}: no {dep} dep line", path.display());
        line.unwrap_or_default()
    }

    // Scan only effective (non-comment) content: a comment DOCUMENTING that a
    // backend is deliberately excluded (e.g. "the `native-tls` feature is NOT
    // listed") is not a violation. TOML comments start with `#`, Rust with `//`.
    fn effective(text: &str) -> String {
        text.lines()
            .filter(|l| {
                let t = l.trim_start();
                !t.starts_with('#') && !t.starts_with("//")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    // `crate_specs.rs` names every emitted crate; its test module spells the
    // refused backends as fixtures, so only the code before it is scanned.
    fn production(text: &str, path: &Path) -> String {
        const TESTS: &str = "\n#[cfg(test)]\nmod tests {";
        let cut = text.find(TESTS);
        assert!(cut.is_some(), "{}: no `{TESTS}` to cut at", path.display());
        text.get(..cut.unwrap_or(0)).unwrap_or_default().to_owned()
    }

    let root = repo_root();
    let sources = [
        root.join("tests/golden/basics/Cargo.toml"),
        root.join("src/runtime/rust/Cargo.toml"),
        root.join("src/compiler/backend/rust/src/project.rs"),
        root.join("src/compiler/backend/rust/src/crate_specs.rs"),
    ];
    for path in &sources {
        let whole = read(path);
        let text = if path.ends_with("crate_specs.rs") {
            effective(&production(&whole, path))
        } else {
            effective(&whole)
        };
        assert_eq!(
            native_backend_in(&text),
            None,
            "{}: TLS must stay rustls-only with bundled webpki roots \
             (static-compilation contract)",
            path.display()
        );
    }

    // The emitter renders every TLS-capable line from its `crate_specs` pin, so
    // the pins carry the rustls arm with defaults off and no native backend;
    // `pin_drift` holds the runtime lines to the same pins.
    for (pin, arm) in [
        (ipe_backend_rust::crate_specs::REQWEST, "rustls-tls"),
        (ipe_backend_rust::crate_specs::LETTRE, "tokio1-rustls-tls"),
    ] {
        assert!(
            !pin.default_features && pin.features.contains(&arm),
            "{}: must be default-features = false + {arm}",
            pin.dependency_line(&[])
        );
    }
    for pin in ipe_backend_rust::crate_specs::ALL_PINNED {
        for feature in pin.features {
            assert_eq!(
                native_backend_in(feature),
                None,
                "{}: native TLS feature {feature:?}",
                pin.spec.name
            );
        }
    }
    {
        let path = root.join("src/runtime/rust/Cargo.toml");
        let text = read(&path);
        let reqwest = dep_line(&text, "reqwest", &path);
        assert!(
            reqwest.contains("default-features = false") && reqwest.contains(r#""rustls-tls""#),
            "{}: reqwest must be default-features = false + rustls-tls: {reqwest}",
            path.display()
        );
    }

    // The other TLS-capable deps are pinned to their rustls arms.
    let runtime_path = root.join("src/runtime/rust/Cargo.toml");
    let runtime = read(&runtime_path);
    let lettre = dep_line(&runtime, "lettre", &runtime_path);
    assert!(
        lettre.contains("default-features = false") && lettre.contains(r#""tokio1-rustls-tls""#),
        "lettre must be default-features = false + tokio1-rustls-tls: {lettre}"
    );
    // `sqlx` and `tokio-tungstenite` are checked structurally: the sqlx line is
    // the SSOT feature set with defaults off (its TLS arm is
    // `tls-rustls-ring-webpki`), and tungstenite carries no TLS feature at all:
    // the runtime owns the socket's TLS through `tokio-rustls`, whose lines
    // `crate_specs` pins.
    assert_eq!(
        refuse_legacy_tls_manifest(&runtime),
        Vec::<ManifestViolation>::new(),
        "{}: legacy TLS arm",
        runtime_path.display()
    );
}

/// One way a runtime manifest lets a legacy TLS or root-store arm back in.
#[derive(Debug, PartialEq, Eq)]
enum ManifestViolation {
    /// The text is not a TOML table.
    Unparsed(String),
    /// No `sqlx` dependency to check.
    SqlxAbsent,
    /// `sqlx` keeps its default features (`any`, `macros`, `migrate`).
    SqlxDefaultsOn,
    /// `sqlx`'s own features differ from the SSOT set.
    SqlxFeatures(BTreeSet<String>),
    /// The pre-0.9 `runtime-tokio-rustls` arm, which pins webpki-roots 0.x.
    LegacySqlxArm,
    /// A pinned crate under another key, which hides it from the checks.
    PinRenamed { krate: &'static str, key: String },
    /// A pinned crate inherited from a workspace table no check reads.
    PinInherited { krate: &'static str, table: String },
    /// A pinned crate with defaults on where the pin turns them off.
    PinDefaultsOn { krate: &'static str, table: String },
    /// A pinned crate feature outside the pin, on any dependency table.
    PinFeatureNotAdmitted {
        krate: &'static str,
        table: String,
        feature: String,
    },
    /// A `[features]` entry enabling a pinned crate feature outside the pin
    /// (for `sqlx`, outside [`ipe_backend_rust::crate_specs::SQLX_DRIVERS`]).
    FeatureEntryNotAdmitted(String),
}

/// The feature names a dependency table enables, or none.
fn dep_features(dep: &toml::Value) -> BTreeSet<String> {
    dep.get("features")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// How the `sqlx` dependency table leaves the SSOT line: defaults on, or a
/// feature set other than exactly [`ipe_backend_rust::crate_specs::SQLX`]'s.
fn sqlx_violations(sqlx: Option<&toml::Value>) -> Vec<ManifestViolation> {
    let Some(sqlx) = sqlx else {
        return vec![ManifestViolation::SqlxAbsent];
    };
    let mut found = Vec::new();
    if sqlx.get("default-features").and_then(toml::Value::as_bool) != Some(false) {
        found.push(ManifestViolation::SqlxDefaultsOn);
    }
    let got = dep_features(sqlx);
    let want: BTreeSet<String> = ipe_backend_rust::crate_specs::SQLX
        .features
        .iter()
        .map(|feature| (*feature).to_owned())
        .collect();
    if got != want {
        found.push(ManifestViolation::SqlxFeatures(got));
    }
    found
}

/// Every dependency table of a manifest, named by its TOML path.
///
/// The three top-level kinds and the same three under each `target.<cfg>`.
fn dependency_tables(table: &toml::Table) -> Vec<(String, &toml::Table)> {
    const KINDS: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];
    let mut tables = Vec::new();
    for kind in KINDS {
        if let Some(deps) = table.get(kind).and_then(toml::Value::as_table) {
            tables.push((kind.to_owned(), deps));
        }
    }
    let targets = table
        .get("target")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flatten();
    for (cfg, target) in targets {
        for kind in KINDS {
            if let Some(deps) = target.get(kind).and_then(toml::Value::as_table) {
                tables.push((format!("target.{cfg}.{kind}"), deps));
            }
        }
    }
    tables
}

/// The pin naming `krate`, if any.
fn pin_of(krate: &str) -> Option<&'static ipe_backend_rust::crate_specs::PinnedCrate> {
    ipe_backend_rust::crate_specs::ALL_PINNED
        .iter()
        .find(|pin| pin.spec.name == krate)
}

/// How one occurrence of a pinned crate widens its pin.
fn pin_occurrence_violations(
    pin: &'static ipe_backend_rust::crate_specs::PinnedCrate,
    table: &str,
    dep: &toml::Value,
) -> Vec<ManifestViolation> {
    let krate = pin.spec.name;
    let mut found = Vec::new();
    if dep.get("workspace").is_some() {
        found.push(ManifestViolation::PinInherited {
            krate,
            table: table.to_owned(),
        });
    }
    if !pin.default_features
        && dep.get("default-features").and_then(toml::Value::as_bool) != Some(false)
    {
        found.push(ManifestViolation::PinDefaultsOn {
            krate,
            table: table.to_owned(),
        });
    }
    for feature in dep_features(dep) {
        if !pin.features.contains(&feature.as_str()) {
            found.push(ManifestViolation::PinFeatureNotAdmitted {
                krate,
                table: table.to_owned(),
                feature,
            });
        }
    }
    found
}

/// Every legacy TLS arm `text` (a runtime `Cargo.toml`) admits.
///
/// The checks admit a closed set rather than refuse spellings: the `[dependencies]` sqlx
/// line is exactly the SSOT set with defaults off; every occurrence of a
/// pinned crate, in every dependency table including `target.<cfg>` ones,
/// keeps the pin's defaults and enables only pin features, under its own
/// name; every `[features]` entry naming a pinned crate enables only a pin
/// feature (a [`ipe_backend_rust::crate_specs::SQLX_DRIVERS`] driver for
/// sqlx); and no effective line names `runtime-tokio-rustls`.
fn refuse_legacy_tls_manifest(text: &str) -> Vec<ManifestViolation> {
    let table = match text.parse::<toml::Table>() {
        Ok(table) => table,
        Err(error) => return vec![ManifestViolation::Unparsed(error.to_string())],
    };
    let sqlx = ipe_backend_rust::crate_specs::SQLX.spec.name;
    let mut found = sqlx_violations(table.get("dependencies").and_then(|deps| deps.get(sqlx)));
    for (path, deps) in dependency_tables(&table) {
        for (key, dep) in deps {
            let package = dep
                .get("package")
                .and_then(toml::Value::as_str)
                .unwrap_or(key.as_str());
            let Some(pin) = pin_of(package) else {
                continue;
            };
            if package != key.as_str() {
                found.push(ManifestViolation::PinRenamed {
                    krate: pin.spec.name,
                    key: key.clone(),
                });
            }
            found.extend(pin_occurrence_violations(pin, &path, dep));
        }
    }
    let features = table
        .get("features")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flatten()
        .flat_map(|(_, list)| list.as_array().into_iter().flatten())
        .filter_map(toml::Value::as_str);
    for entry in features {
        let Some((krate, feature)) = entry.split_once('/') else {
            continue;
        };
        let Some(pin) = pin_of(krate.strip_suffix('?').unwrap_or(krate)) else {
            continue;
        };
        let admitted = if pin.spec.name == sqlx {
            ipe_backend_rust::crate_specs::SQLX_DRIVERS
        } else {
            pin.features
        };
        if !admitted.contains(&feature) {
            found.push(ManifestViolation::FeatureEntryNotAdmitted(entry.to_owned()));
        }
    }
    let mut effective = text
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'));
    if effective.any(|line| line.contains("runtime-tokio-rustls")) {
        found.push(ManifestViolation::LegacySqlxArm);
    }
    found
}

/// Every native backend spelling is found, and the rustls arms are not.
#[test]
fn native_backend_needles_cover_every_spelling() {
    for needle in OS_ROOT_STORES
        .into_iter()
        .chain(NATIVE_TLS_STACK)
        .chain(NATIVE_BACKEND_SPELLINGS)
    {
        assert!(
            native_backend_in(&format!("dep = {{ features = [\"{needle}\"] }}")).is_some(),
            "{needle}"
        );
    }
    for admitted in [
        "rustls-tls",
        "tokio1-rustls-tls",
        "webpki-roots",
        "handshake",
    ] {
        assert_eq!(native_backend_in(admitted), None, "{admitted}");
    }
}

/// A manifest holding exactly the admitted pins, features and an empty target
/// table for the refusal fixtures to extend.
fn admitted_tls_manifest() -> String {
    use ipe_backend_rust::crate_specs::{RUSTLS, SQLX, TOKIO_TUNGSTENITE};
    format!(
        "[dependencies]\n{}\n{}\n{}\n\
         [target.'cfg(unix)'.dev-dependencies]\n\
         [features]\n\
         db = [\"sqlx\", \"sqlx?/sqlite-bundled\", \"sqlx?/postgres\"]\n\
         websocket_client = [\"tokio-tungstenite\", \"tokio-tungstenite?/handshake\"]\n",
        SQLX.dependency_line(&[]),
        TOKIO_TUNGSTENITE.dependency_line(&[]),
        RUSTLS.dependency_line(&[]),
    )
}

/// The checker accepts the admitted manifest and refuses each `[dependencies]`
/// and `[features]` arm outside the admitted set on its own.
#[test]
fn legacy_tls_manifest_feature_arms_are_refused() {
    use ipe_backend_rust::crate_specs::{SQLX, TOKIO_TUNGSTENITE};
    let base = admitted_tls_manifest();
    assert_eq!(
        refuse_legacy_tls_manifest(&base),
        Vec::<ManifestViolation>::new()
    );

    let legacy_arm = base.replace("\"runtime-tokio\", ", "\"runtime-tokio-rustls\", ");
    assert!(
        refuse_legacy_tls_manifest(&legacy_arm).contains(&ManifestViolation::LegacySqlxArm),
        "{legacy_arm}"
    );
    let tungstenite_line = TOKIO_TUNGSTENITE.dependency_line(&[]);
    let tungstenite_roots = base.replace(
        &tungstenite_line,
        &TOKIO_TUNGSTENITE.dependency_line(&["__rustls-tls"]),
    );
    assert_eq!(
        refuse_legacy_tls_manifest(&tungstenite_roots),
        [ManifestViolation::PinFeatureNotAdmitted {
            krate: TOKIO_TUNGSTENITE.spec.name,
            table: "dependencies".to_owned(),
            feature: "__rustls-tls".to_owned(),
        }]
    );
    let tungstenite_by_feature = base.replace(
        "\"tokio-tungstenite?/handshake\"",
        "\"tokio-tungstenite?/handshake\", \"tokio-tungstenite?/url\"",
    );
    assert_eq!(
        refuse_legacy_tls_manifest(&tungstenite_by_feature),
        [ManifestViolation::FeatureEntryNotAdmitted(
            "tokio-tungstenite?/url".to_owned()
        )]
    );
    let wide_sqlite = base.replace("sqlx?/sqlite-bundled", "sqlx?/sqlite");
    assert_eq!(
        refuse_legacy_tls_manifest(&wide_sqlite),
        [ManifestViolation::FeatureEntryNotAdmitted(
            "sqlx?/sqlite".to_owned()
        )]
    );
    let sqlx_line_feature = base.replace("sqlx?/sqlite-bundled", "sqlx/sqlite-bundled");
    assert_eq!(
        refuse_legacy_tls_manifest(&sqlx_line_feature),
        Vec::<ManifestViolation>::new()
    );
    let sqlx_tls_entry = base.replace(
        "\"sqlx?/postgres\"",
        "\"sqlx?/postgres\", \"sqlx/tls-native-tls\"",
    );
    assert_eq!(
        refuse_legacy_tls_manifest(&sqlx_tls_entry),
        [ManifestViolation::FeatureEntryNotAdmitted(
            "sqlx/tls-native-tls".to_owned()
        )]
    );
    let defaults_on = base.replace(
        &SQLX.dependency_line(&[]),
        &SQLX
            .dependency_line(&[])
            .replace("default-features = false, ", ""),
    );
    assert_eq!(
        refuse_legacy_tls_manifest(&defaults_on),
        [
            ManifestViolation::SqlxDefaultsOn,
            ManifestViolation::PinDefaultsOn {
                krate: SQLX.spec.name,
                table: "dependencies".to_owned(),
            },
        ]
    );
}

/// The checker refuses an out-of-set pin in target, build, renamed and
/// inherited spellings, not only in plain `[dependencies]`.
#[test]
fn legacy_tls_manifest_other_tables_are_refused() {
    use ipe_backend_rust::crate_specs::{RUSTLS, TOKIO_TUNGSTENITE};
    let base = admitted_tls_manifest();
    let target_table = "target.'cfg(unix)'.dev-dependencies";
    let target_header = format!("[{target_table}]\n");
    let target_wide = base.replace(
        &target_header,
        &format!(
            "{target_header}{}\n",
            TOKIO_TUNGSTENITE.dependency_line(&["native-tls"])
        ),
    );
    assert_eq!(
        refuse_legacy_tls_manifest(&target_wide),
        [ManifestViolation::PinFeatureNotAdmitted {
            krate: TOKIO_TUNGSTENITE.spec.name,
            table: "target.cfg(unix).dev-dependencies".to_owned(),
            feature: "native-tls".to_owned(),
        }]
    );
    let target_defaults = base.replace(
        &target_header,
        &format!(
            "{target_header}{} = \"{}\"\n",
            RUSTLS.spec.name, RUSTLS.spec.version
        ),
    );
    assert_eq!(
        refuse_legacy_tls_manifest(&target_defaults),
        [ManifestViolation::PinDefaultsOn {
            krate: RUSTLS.spec.name,
            table: "target.cfg(unix).dev-dependencies".to_owned(),
        }]
    );
    let build_dep = format!(
        "{base}[build-dependencies]\n{}\n",
        RUSTLS.dependency_line(&["aws-lc-rs"])
    );
    assert_eq!(
        refuse_legacy_tls_manifest(&build_dep),
        [ManifestViolation::PinFeatureNotAdmitted {
            krate: RUSTLS.spec.name,
            table: "build-dependencies".to_owned(),
            feature: "aws-lc-rs".to_owned(),
        }]
    );
    let renamed = base.replace(
        &target_header,
        &format!(
            "{target_header}tls = {{ package = \"{}\", version = \"{}\", default-features = false }}\n",
            RUSTLS.spec.name, RUSTLS.spec.version
        ),
    );
    assert_eq!(
        refuse_legacy_tls_manifest(&renamed),
        [ManifestViolation::PinRenamed {
            krate: RUSTLS.spec.name,
            key: "tls".to_owned(),
        }]
    );
    let inherited = base.replace(
        &target_header,
        &format!(
            "{target_header}{} = {{ workspace = true, default-features = false }}\n",
            RUSTLS.spec.name
        ),
    );
    assert_eq!(
        refuse_legacy_tls_manifest(&inherited),
        [ManifestViolation::PinInherited {
            krate: RUSTLS.spec.name,
            table: "target.cfg(unix).dev-dependencies".to_owned(),
        }]
    );
}

/// The shipped runtime manifest passes the same checker.
#[test]
fn shipped_runtime_manifest_has_no_legacy_tls_arm() {
    let runtime_path = repo_root().join("src/runtime/rust/Cargo.toml");
    let runtime = std::fs::read_to_string(&runtime_path).unwrap_or_default();
    assert!(!runtime.is_empty(), "read {}", runtime_path.display());
    assert_eq!(
        refuse_legacy_tls_manifest(&runtime),
        Vec::<ManifestViolation>::new()
    );
}

/// One package of a parsed `Cargo.lock`.
struct LockedPackage {
    name: String,
    version: semver::Version,
    /// The raw `dependencies` edges: `name` or `name version [(source)]`.
    dependencies: Vec<String>,
}

/// A parsed `Cargo.lock`.
struct Lock {
    packages: Vec<LockedPackage>,
}

/// Which closure a lock must prove.
#[derive(Clone, Copy)]
enum LockScope {
    /// The lock resolves the runtime crate: walk its closure.
    WithRuntime,
    /// The lock has no runtime crate: only the roots version is checked,
    /// and a runtime in it is refused.
    RootsOnly,
}

/// One way a lock lets the legacy roots or an OS root store in.
#[derive(Debug, PartialEq, Eq)]
enum RootsViolation {
    /// The text is not a lock this check can read.
    Unparsed(String),
    /// A `webpki-roots` 0.x (RUSTSEC-2026-0381).
    LegacyRoots(semver::Version),
    /// The scope names the runtime, but the lock does not resolve it.
    RuntimeAbsent,
    /// The runtime resolves more than once: its closure is ambiguous.
    RuntimeAmbiguous,
    /// An edge names no package, or more than one.
    UnresolvedEdge { from: String, edge: String },
    /// The runtime closure reaches an OS root store or native TLS crate.
    RuntimeReaches(String),
    /// A lock scoped [`LockScope::RootsOnly`] resolves the runtime, whose
    /// closure that scope never walks.
    RuntimeInRootsOnlyLock,
}

const RUNTIME_PACKAGE: &str = "ipe-runtime-rust";
const LEGACY_ROOTS: &str = "webpki-roots";
const OS_ROOT_STORES: [&str; 2] = ["rustls-native-certs", "rustls-platform-verifier"];
/// The native TLS stack and the OS trust stores it reaches.
///
/// Workspace tools outside the runtime lock some of these through
/// `rustls-native-certs`, so `deny.toml` cannot ban them; the runtime closure
/// walk refuses them.
const NATIVE_TLS_STACK: [&str; 8] = [
    "native-tls",
    "openssl-sys",
    "openssl-probe",
    "security-framework",
    "schannel",
    "boring",
    "boring-sys",
    "tokio-boring",
];
/// Spellings of a native backend that are not crate names: a feature or a
/// manifest key that selects one.
const NATIVE_BACKEND_SPELLINGS: [&str; 5] = [
    "openssl",
    "native-certs",
    "native-roots",
    "platform-verifier",
    "rustls-tls-native-roots",
];

/// The first native TLS backend or OS trust-store spelling in `text`.
///
/// One closed set serves the manifest scan and the pinned-feature scan; the
/// lock walk matches its two crate-name halves by exact package name.
fn native_backend_in(text: &str) -> Option<&'static str> {
    OS_ROOT_STORES
        .into_iter()
        .chain(NATIVE_TLS_STACK)
        .chain(NATIVE_BACKEND_SPELLINGS)
        .find(|needle| text.contains(*needle))
}

/// Parse a `Cargo.lock` text once into typed packages.
fn parse_lock(text: &str) -> Result<Lock, RootsViolation> {
    let table = text
        .parse::<toml::Table>()
        .map_err(|error| RootsViolation::Unparsed(error.to_string()))?;
    let entries = table
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| RootsViolation::Unparsed("no [[package]] array".to_owned()))?;
    let mut packages = Vec::with_capacity(entries.len());
    for entry in entries {
        let field = |key: &str| entry.get(key).and_then(toml::Value::as_str);
        let (Some(name), Some(version)) = (field("name"), field("version")) else {
            return Err(RootsViolation::Unparsed(format!(
                "package without name/version: {entry}"
            )));
        };
        let version = semver::Version::parse(version)
            .map_err(|error| RootsViolation::Unparsed(format!("{name} {version}: {error}")))?;
        let dependencies = match entry.get("dependencies") {
            None => Vec::new(),
            Some(list) => list
                .as_array()
                .ok_or_else(|| {
                    RootsViolation::Unparsed(format!("{name}: dependencies not a list"))
                })?
                .iter()
                .map(|edge| {
                    edge.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| RootsViolation::Unparsed(format!("{name}: non-string edge")))
                })
                .collect::<Result<_, _>>()?,
        };
        packages.push(LockedPackage {
            name: name.to_owned(),
            version,
            dependencies,
        });
    }
    Ok(Lock { packages })
}

/// The one package `edge` names. An edge that names none or several is
/// refused: the walk fails closed rather than skip a branch.
fn resolve_edge(lock: &Lock, from: &str, edge: &str) -> Result<usize, RootsViolation> {
    let mut words = edge.split_whitespace();
    let name = words.next().unwrap_or_default();
    let version = words.next();
    let mut hits = lock.packages.iter().enumerate().filter(|(_, package)| {
        package.name == name && version.is_none_or(|v| package.version.to_string() == v)
    });
    match (hits.next(), hits.next()) {
        (Some((at, _)), None) => Ok(at),
        _ => Err(RootsViolation::UnresolvedEdge {
            from: from.to_owned(),
            edge: edge.to_owned(),
        }),
    }
}

/// No `webpki-roots` 0.x anywhere in `lock`, and the runtime where `scope` says.
///
/// Under [`LockScope::WithRuntime`] no OS root store or native TLS crate is in
/// the runtime's dependency closure; under [`LockScope::RootsOnly`] the lock
/// has no runtime at all.
fn refuse_legacy_roots(lock: &Lock, scope: LockScope) -> Result<(), RootsViolation> {
    if let Some(legacy) = lock
        .packages
        .iter()
        .find(|package| package.name == LEGACY_ROOTS && package.version.major == 0)
    {
        return Err(RootsViolation::LegacyRoots(legacy.version.clone()));
    }
    let mut runtimes = lock
        .packages
        .iter()
        .enumerate()
        .filter(|(_, package)| package.name == RUNTIME_PACKAGE);
    let first = runtimes.next();
    if matches!(scope, LockScope::RootsOnly) {
        return if first.is_some() {
            Err(RootsViolation::RuntimeInRootsOnlyLock)
        } else {
            Ok(())
        };
    }
    let runtime = match (first, runtimes.next()) {
        (Some((at, _)), None) => at,
        (None, _) => return Err(RootsViolation::RuntimeAbsent),
        (Some(_), Some(_)) => return Err(RootsViolation::RuntimeAmbiguous),
    };
    let mut seen = vec![false; lock.packages.len()];
    let mut pending = vec![runtime];
    while let Some(at) = pending.pop() {
        let Some(package) = lock.packages.get(at) else {
            continue;
        };
        if seen.get(at).copied().unwrap_or(true) {
            continue;
        }
        if let Some(mark) = seen.get_mut(at) {
            *mark = true;
        }
        let name = package.name.as_str();
        if OS_ROOT_STORES.contains(&name) || NATIVE_TLS_STACK.contains(&name) {
            return Err(RootsViolation::RuntimeReaches(package.name.clone()));
        }
        for edge in &package.dependencies {
            pending.push(resolve_edge(lock, &package.name, edge)?);
        }
    }
    Ok(())
}

/// Every tracked `Cargo.lock`, repository-root-relative, as `git` lists it.
fn tracked_locks() -> BTreeSet<String> {
    let result = Command::new("git")
        .arg("-C")
        .arg(repo_root())
        .args(["ls-files", "--", "*Cargo.lock"])
        .output();
    assert!(result.is_ok(), "run `git ls-files`: {result:?}");
    let Ok(out) = result else {
        return BTreeSet::new();
    };
    assert!(
        out.status.success(),
        "`git ls-files` failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The lock assertion refuses legacy roots, an OS store or native TLS crate
/// reached from the runtime, and a runtime in a roots-only lock.
///
/// It accepts every tracked repo lock, each under its declared scope.
#[test]
fn legacy_roots_are_refused_in_every_lock() {
    let lock = |body: &str| {
        let parsed = parse_lock(&format!("version = 4\n{body}"));
        assert!(parsed.is_ok(), "fixture lock must parse: {body}");
        parsed.unwrap_or_else(|_| Lock {
            packages: Vec::new(),
        })
    };
    let runtime_with = |dep: &str| {
        format!(
            "[[package]]\nname = \"ipe-runtime-rust\"\nversion = \"0.7.0\"\ndependencies = [\"sqlx-core\"]\n\
             [[package]]\nname = \"sqlx-core\"\nversion = \"0.9.0\"\ndependencies = [\"{dep}\"]\n"
        )
    };

    let roots_1 = lock(
        &(runtime_with("webpki-roots")
            + "[[package]]\nname = \"webpki-roots\"\nversion = \"1.0.10\"\n"),
    );
    assert_eq!(
        refuse_legacy_roots(&roots_1, LockScope::WithRuntime),
        Ok(())
    );

    let legacy = lock(
        &(runtime_with("webpki-roots 0.26.11")
            + "[[package]]\nname = \"webpki-roots\"\nversion = \"0.26.11\"\n\
           [[package]]\nname = \"webpki-roots\"\nversion = \"1.0.10\"\n"),
    );
    assert_eq!(
        refuse_legacy_roots(&legacy, LockScope::RootsOnly),
        Err(RootsViolation::LegacyRoots(semver::Version::new(0, 26, 11)))
    );
    for store in OS_ROOT_STORES.into_iter().chain(NATIVE_TLS_STACK) {
        let reached = lock(
            &(runtime_with(store)
                + &format!("[[package]]\nname = \"{store}\"\nversion = \"0.8.0\"\n")),
        );
        assert_eq!(
            refuse_legacy_roots(&reached, LockScope::WithRuntime),
            Err(RootsViolation::RuntimeReaches(store.to_owned()))
        );
        // Outside the runtime closure an OS store is cargo-deny's to scope.
        let elsewhere = lock(
            &(runtime_with("webpki-roots")
                + "[[package]]\nname = \"webpki-roots\"\nversion = \"1.0.10\"\n"
                + &format!(
                    "[[package]]\nname = \"ipe\"\nversion = \"0.7.0\"\ndependencies = [\"{store}\"]\n\
                 [[package]]\nname = \"{store}\"\nversion = \"0.8.0\"\n"
                )),
        );
        assert_eq!(
            refuse_legacy_roots(&elsewhere, LockScope::WithRuntime),
            Ok(())
        );
    }
    let dangling = lock(&runtime_with("webpki-roots"));
    assert!(
        matches!(
            refuse_legacy_roots(&dangling, LockScope::WithRuntime),
            Err(RootsViolation::UnresolvedEdge { .. })
        ),
        "an edge to no package must fail closed"
    );
    let no_runtime = lock("[[package]]\nname = \"webpki-roots\"\nversion = \"1.0.10\"\n");
    assert_eq!(
        refuse_legacy_roots(&no_runtime, LockScope::WithRuntime),
        Err(RootsViolation::RuntimeAbsent)
    );
    assert_eq!(
        refuse_legacy_roots(&no_runtime, LockScope::RootsOnly),
        Ok(())
    );
    assert_eq!(
        refuse_legacy_roots(&roots_1, LockScope::RootsOnly),
        Err(RootsViolation::RuntimeInRootsOnlyLock)
    );

    let scopes = BTreeMap::from([
        ("Cargo.lock".to_owned(), LockScope::WithRuntime),
        (
            "editors/zed-ipe/Cargo.lock".to_owned(),
            LockScope::RootsOnly,
        ),
        (
            "tools/ipe-index/Cargo.lock".to_owned(),
            LockScope::RootsOnly,
        ),
    ]);
    assert_eq!(
        tracked_locks(),
        scopes.keys().cloned().collect::<BTreeSet<_>>(),
        "every tracked Cargo.lock needs a scope here, and only those"
    );
    for (path, scope) in scopes {
        let text = std::fs::read_to_string(repo_root().join(&path)).unwrap_or_default();
        assert!(!text.is_empty(), "read {path}");
        let parsed = parse_lock(&text);
        assert!(parsed.is_ok(), "{path}: {:?}", parsed.as_ref().err());
        if let Ok(parsed) = parsed {
            assert_eq!(refuse_legacy_roots(&parsed, scope), Ok(()), "{path}");
        }
    }
}

/// One way the `deny.toml` roots ban fails to mean "webpki-roots below 1".
#[derive(Debug, PartialEq, Eq)]
enum DenyViolation {
    /// The text is not a TOML table with a `bans.deny` list.
    Unparsed(String),
    /// No `bans.deny` entry names the crate.
    EntryAbsent(&'static str),
    /// The roots entry is not spelled `name:<req>` (`@` bans every version or
    /// none, depending on the requirement).
    NotNameColonReq(String),
    /// The requirement does not parse as a semver requirement.
    BadReq(String),
    /// The requirement lets the legacy roots through.
    AdmitsLegacy(String),
    /// The requirement bans the current roots.
    BansCurrent(String),
}

/// The `crate` spellings of `deny.toml`'s `bans.deny` entries.
fn deny_entries(text: &str) -> Result<Vec<String>, DenyViolation> {
    let table = text
        .parse::<toml::Table>()
        .map_err(|error| DenyViolation::Unparsed(error.to_string()))?;
    let list = table
        .get("bans")
        .and_then(|bans| bans.get("deny"))
        .and_then(toml::Value::as_array)
        .ok_or_else(|| DenyViolation::Unparsed("no bans.deny list".to_owned()))?;
    Ok(list
        .iter()
        .filter_map(|entry| entry.get("crate").and_then(toml::Value::as_str))
        .map(str::to_owned)
        .collect())
}

/// The roots ban is `webpki-roots:<req>` with `<req>` matching 0.26.11 and not
/// 1.0.10, and both OS root stores are banned by name.
fn refuse_weak_roots_ban(text: &str) -> Result<(), DenyViolation> {
    let entries = deny_entries(text)?;
    let roots = entries
        .iter()
        .find(|spec| spec.starts_with(LEGACY_ROOTS))
        .ok_or(DenyViolation::EntryAbsent(LEGACY_ROOTS))?;
    let Some(req) = roots
        .split_once(':')
        .filter(|(name, _)| *name == LEGACY_ROOTS)
        .map(|(_, req)| req)
    else {
        return Err(DenyViolation::NotNameColonReq(roots.clone()));
    };
    let req = semver::VersionReq::parse(req).map_err(|_| DenyViolation::BadReq(roots.clone()))?;
    if !req.matches(&semver::Version::new(0, 26, 11)) {
        return Err(DenyViolation::AdmitsLegacy(roots.clone()));
    }
    if req.matches(&semver::Version::new(1, 0, 10)) {
        return Err(DenyViolation::BansCurrent(roots.clone()));
    }
    for store in OS_ROOT_STORES {
        if !entries.iter().any(|spec| spec == store) {
            return Err(DenyViolation::EntryAbsent(store));
        }
    }
    Ok(())
}

/// The `deny.toml` roots ban keeps the `name:<req>` meaning, and the repo's
/// ban is that one.
#[test]
fn roots_ban_is_spelled_name_colon_req() {
    let ban = |roots: &str| {
        format!(
            "[bans]\ndeny = [\n  {{ crate = \"{roots}\" }},\n  \
             {{ crate = \"rustls-native-certs\", wrappers = [\"rustls-platform-verifier\"] }},\n  \
             {{ crate = \"rustls-platform-verifier\", wrappers = [\"reqwest\"] }},\n]\n"
        )
    };
    assert_eq!(refuse_weak_roots_ban(&ban("webpki-roots:<1")), Ok(()));
    assert_eq!(refuse_weak_roots_ban(&ban("webpki-roots:0.26")), Ok(()));
    for (spelling, refusal) in [
        (
            "webpki-roots@<1",
            DenyViolation::NotNameColonReq("webpki-roots@<1".to_owned()),
        ),
        (
            "webpki-roots@<1.0.0",
            DenyViolation::NotNameColonReq("webpki-roots@<1.0.0".to_owned()),
        ),
        (
            "webpki-roots:<0.26",
            DenyViolation::AdmitsLegacy("webpki-roots:<0.26".to_owned()),
        ),
        (
            "webpki-roots:*",
            DenyViolation::BansCurrent("webpki-roots:*".to_owned()),
        ),
        (
            "webpki-roots:<<1",
            DenyViolation::BadReq("webpki-roots:<<1".to_owned()),
        ),
    ] {
        assert_eq!(
            refuse_weak_roots_ban(&ban(spelling)),
            Err(refusal),
            "{spelling}"
        );
    }
    assert_eq!(
        refuse_weak_roots_ban("[bans]\ndeny = [{ crate = \"rustls-native-certs\" }]\n"),
        Err(DenyViolation::EntryAbsent(LEGACY_ROOTS))
    );
    let without_store =
        "[bans]\ndeny = [{ crate = \"webpki-roots:<1\" }, { crate = \"rustls-native-certs\" }]\n";
    assert_eq!(
        refuse_weak_roots_ban(without_store),
        Err(DenyViolation::EntryAbsent("rustls-platform-verifier"))
    );

    let text = std::fs::read_to_string(repo_root().join("deny.toml")).unwrap_or_default();
    assert!(!text.is_empty(), "read deny.toml");
    assert_eq!(refuse_weak_roots_ban(&text), Ok(()));
}

/// Full static proof (THE SEAL, end to end): emit `examples/shapes/non-tea/hello-world`
/// under the dlmalloc static plan, `cargo build` it standalone for musl with
/// CWD = the emitted crate dir (cargo discovers `.cargo/config.toml` from
/// CWD, not from `--manifest-path`), then assert the binary is genuinely
/// static (`ldd`) and runs. Gated: `IPE_E2E_STATIC=1`.
#[test]
fn end_to_end_static_binary_is_static_and_runs() {
    if ipe_env::var("IPE_E2E_STATIC").is_err() {
        return;
    }
    let root = repo_root();
    let manifest = root
        .join("examples")
        .join("shapes")
        .join("non-tea")
        .join("hello-world")
        .join("package.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("static_e2e");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();

    let plan = dlmalloc_plan();
    build_plan::preflight(&plan).expect("toolchain preflight (musl target + C compiler)");
    ipe::build_project_with_options(
        &manifest,
        &out,
        &runtime,
        &BuildOptions {
            static_plan: Some(plan),
            ..BuildOptions::default()
        },
    )
    .expect("static emit");

    // Standalone cargo build, CWD = emitted crate dir, for a foreign musl
    // triple: its dependency tree is not the shared target's, so this build
    // gets its own private tree.
    let isolated =
        e2e_support::target::isolated(e2e_support::target::IsolationReason::ForeignTriple)
            .expect("isolated build target");
    let target = e2e_support::target::BuildTarget::Isolated(isolated);
    let status = e2e_support::target::cargo_command(&target)
        .arg("build")
        .args(["--target", plan.triple.as_str()])
        .current_dir(&out)
        .status()
        .expect("spawn cargo");
    assert!(status.success(), "cargo build --target musl failed (SEAL)");

    let bin = target
        .path()
        .join(plan.triple.as_str())
        .join("debug")
        .join(ipe::emitted_bin_filename(&out).expect("the emitted manifest names its crate"));

    // Assert static-ness — never assume it. `ldd` exits non-zero for a
    // static binary on some platforms; the message is the contract.
    let ldd = std::process::Command::new("ldd")
        .arg(&bin)
        .output()
        .expect("run ldd");
    let ldd_text = format!(
        "{}{}",
        String::from_utf8_lossy(&ldd.stdout),
        String::from_utf8_lossy(&ldd.stderr)
    );
    assert!(
        ldd_text.contains("statically linked") || ldd_text.contains("not a dynamic executable"),
        "binary is not static: {ldd_text}"
    );

    // And it runs.
    let run = std::process::Command::new(&bin)
        .output()
        .expect("run binary");
    assert!(run.status.success(), "static binary exited non-zero");
    assert_eq!(String::from_utf8_lossy(&run.stdout), "Hello, Ipê!\n");
}

/// `ipe dev run --static` end to end: the driver emits, cargo-builds for the
/// musl triple, resolves the relocated target dir, and execs a genuinely
/// static binary. Gated: `IPE_E2E_STATIC=1`.
#[test]
fn ipe_run_static_builds_and_executes_a_static_binary() {
    if ipe_env::var("IPE_E2E_STATIC").is_err() {
        return;
    }
    let root = repo_root();
    let project = root
        .join("examples")
        .join("shapes")
        .join("non-tea")
        .join("hello-world");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("static_run_e2e");
    let _ = std::fs::remove_dir_all(&out);

    // The static musl build's dependency tree is not the shared target's: an
    // exclusive private tree.
    let isolated =
        e2e_support::target::isolated(e2e_support::target::IsolationReason::ForeignTriple)
            .expect("isolated build target");
    let target = e2e_support::target::BuildTarget::Isolated(isolated);

    let run = e2e_support::target::ipe_command(&support::ipe_bin(), &target)
        .args(["dev", "run"])
        .arg(&project)
        .args(["--static", "--out"])
        .arg(&out)
        .output()
        .expect("spawn ipe dev run --static");
    assert!(
        run.status.success(),
        "ipe dev run --static failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        String::from_utf8_lossy(&run.stdout).contains("Hello, Ipê!"),
        "expected program output, got: {}",
        String::from_utf8_lossy(&run.stdout)
    );

    // The executed artifact must be genuinely static. `--out` names the output
    // root; the emitted crate is its `rust/` area.
    let bin = target
        .path()
        .join("x86_64-unknown-linux-musl")
        .join("debug")
        .join(
            ipe::emitted_bin_filename(&out.join("rust"))
                .expect("the emitted manifest names its crate"),
        );
    let ldd = std::process::Command::new("ldd")
        .arg(&bin)
        .output()
        .expect("run ldd");
    let ldd_text = format!(
        "{}{}",
        String::from_utf8_lossy(&ldd.stdout),
        String::from_utf8_lossy(&ldd.stderr)
    );
    assert!(
        ldd_text.contains("statically linked") || ldd_text.contains("not a dynamic executable"),
        "ipe dev run --static executed a non-static binary: {ldd_text}"
    );
}
