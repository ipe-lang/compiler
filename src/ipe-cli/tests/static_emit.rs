//! Static-compilation gates (design: `docs/architecture/static-compilation.md`).
//!
//! Ungated tests assert the emitted-project SHAPE of a static plan (allocator
//! feature spliced into the manifest, generated `.cargo/config.toml`, stale-
//! config hygiene, CLI refusal wiring). The full proof — the emitted crate
//! cargo-builds for `x86_64-unknown-linux-musl`, `ldd` reports it static, and
//! it runs — is gated behind `IPE_E2E_STATIC=1` (it needs the musl target, a
//! musl-capable C compiler, and a cold multi-minute dependency build).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

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
            "NoSuch.ipe",
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
            "NoSuch.ipe",
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
            "NoSuch.ipe",
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
            "NoSuch.ipe",
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
    let err = ipe::run_cli(&[
        "dev".into(),
        "build".into(),
        "NoSuch.ipe".into(),
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
        "NoSuch.ipe".into(),
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
    let err = ipe::run_cli(&[
        "dev".into(),
        "run".into(),
        "NoSuch.ipe".into(),
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
        "NoSuch.ipe".into(),
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
/// Three sources write dependency lines into an emitted `Cargo.toml`:
/// the golden base manifest, the vendored runtime's manifest, and the
/// surgery strings in the backend's `project.rs`. All three are scanned.
///
/// The check has two halves, and the POSITIVE half is what makes it sound:
///
/// * **Negative** — no source's effective (non-comment) content may contain a
///   forbidden backend (`native-tls`, `openssl`, `rustls-tls-native-roots`).
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

    let root = repo_root();
    let sources = [
        root.join("tests/golden/basics/Cargo.toml"),
        root.join("src/runtime/rust/Cargo.toml"),
        root.join("src/compiler/backend/rust/src/project.rs"),
    ];
    for path in &sources {
        let text = effective(&read(path));
        for forbidden in ["native-tls", "openssl", "rustls-tls-native-roots"] {
            assert!(
                !text.contains(forbidden),
                "{}: contains {forbidden:?} — TLS must stay rustls-only with bundled \
                 webpki roots (static-compilation contract)",
                path.display()
            );
        }
    }

    // The reqwest dep line itself: rustls backend, default features off (the
    // default feature set would pull no TLS at all — `rustls-tls` bundles
    // webpki-roots, keeping cert verification host-independent).
    //
    // `reqwest` is only linked when a program reaches the outbound HTTP surface,
    // so it is NOT in the base `tests/golden/basics/Cargo.toml` (a pure
    // hello-world). The canonical `reqwest` dep line lives in
    // `src/runtime/rust/Cargo.toml` (the vendored source); the emitter's
    // `http_client_cargo_toml` reproduces the same rustls feature set (its
    // `"rustls-tls"` literal is covered by the forbidden-backend scan above,
    // which includes `project.rs`).
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
    /// A `tokio-tungstenite` TLS or root-store feature: the runtime owns TLS.
    TungsteniteTls(String),
    /// The wide `sqlite` driver, which also enables deserialize,
    /// load-extension and unlock-notify.
    WideSqliteDriver(String),
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

/// Every legacy TLS arm `text` (a runtime `Cargo.toml`) admits: the sqlx line
/// is exactly the SSOT set with defaults off, tungstenite carries no TLS or
/// root-store feature (on its line or through a `[features]` entry), no
/// effective line names `runtime-tokio-rustls`, and no feature enables the
/// wide sqlite driver.
fn refuse_legacy_tls_manifest(text: &str) -> Vec<ManifestViolation> {
    let table = match text.parse::<toml::Table>() {
        Ok(table) => table,
        Err(error) => return vec![ManifestViolation::Unparsed(error.to_string())],
    };
    let mut found = sqlx_violations(
        table
            .get("dependencies")
            .and_then(|deps| deps.get(ipe_backend_rust::crate_specs::SQLX.spec.name)),
    );
    let tls_arm = |feature: &str| {
        ["rustls", "native-tls", "webpki"]
            .iter()
            .any(|arm| feature.contains(arm))
    };
    let tungstenite = ipe_backend_rust::crate_specs::TOKIO_TUNGSTENITE.spec.name;
    for section in ["dependencies", "dev-dependencies"] {
        if let Some(dep) = table.get(section).and_then(|deps| deps.get(tungstenite)) {
            for feature in dep_features(dep)
                .into_iter()
                .filter(|f| tls_arm(f.as_str()))
            {
                found.push(ManifestViolation::TungsteniteTls(feature));
            }
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
        let krate = krate.trim_end_matches('?');
        if krate == tungstenite && tls_arm(feature) {
            found.push(ManifestViolation::TungsteniteTls(entry.to_owned()));
        }
        if krate == ipe_backend_rust::crate_specs::SQLX.spec.name && feature == "sqlite" {
            found.push(ManifestViolation::WideSqliteDriver(entry.to_owned()));
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

/// The manifest checker refuses each legacy arm on its own and accepts the
/// real runtime manifest.
#[test]
fn legacy_tls_manifest_arms_are_refused() {
    let base = "[dependencies]\n\
        sqlx = { version = \"0.9\", default-features = false, features = [\"runtime-tokio\", \"tls-rustls-ring-webpki\", \"json\"], optional = true }\n\
        tokio-tungstenite = { version = \"0.30\", default-features = false, features = [\"handshake\"], optional = true }\n\
        [features]\n\
        db = [\"sqlx\", \"sqlx?/sqlite-bundled\", \"sqlx?/postgres\"]\n\
        websocket_client = [\"tokio-tungstenite\"]\n";
    assert_eq!(
        refuse_legacy_tls_manifest(base),
        Vec::<ManifestViolation>::new()
    );

    let legacy_arm = base.replace("\"runtime-tokio\", ", "\"runtime-tokio-rustls\", ");
    assert!(
        refuse_legacy_tls_manifest(&legacy_arm).contains(&ManifestViolation::LegacySqlxArm),
        "{legacy_arm}"
    );
    let tungstenite_roots = base.replace(
        "[\"handshake\"]",
        "[\"handshake\", \"rustls-tls-webpki-roots\"]",
    );
    assert_eq!(
        refuse_legacy_tls_manifest(&tungstenite_roots),
        [ManifestViolation::TungsteniteTls(
            "rustls-tls-webpki-roots".to_owned()
        )]
    );
    let tungstenite_by_feature = base.replace(
        "[\"tokio-tungstenite\"]",
        "[\"tokio-tungstenite\", \"tokio-tungstenite?/native-tls\"]",
    );
    assert_eq!(
        refuse_legacy_tls_manifest(&tungstenite_by_feature),
        [ManifestViolation::TungsteniteTls(
            "tokio-tungstenite?/native-tls".to_owned()
        )]
    );
    let wide_sqlite = base.replace("sqlx?/sqlite-bundled", "sqlx?/sqlite");
    assert_eq!(
        refuse_legacy_tls_manifest(&wide_sqlite),
        [ManifestViolation::WideSqliteDriver(
            "sqlx?/sqlite".to_owned()
        )]
    );
    let defaults_on = base.replace(
        "default-features = false, features = [\"runtime-tokio\"",
        "features = [\"runtime-tokio\"",
    );
    assert_eq!(
        refuse_legacy_tls_manifest(&defaults_on),
        [ManifestViolation::SqlxDefaultsOn]
    );

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
    /// The lock has no runtime crate: only the roots version is checked.
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
    /// The runtime closure reaches an OS root store crate.
    RuntimeReaches(String),
}

const RUNTIME_PACKAGE: &str = "ipe-runtime-rust";
const LEGACY_ROOTS: &str = "webpki-roots";
const OS_ROOT_STORES: [&str; 2] = ["rustls-native-certs", "rustls-platform-verifier"];

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

/// No `webpki-roots` 0.x anywhere in `lock`, and, under
/// [`LockScope::WithRuntime`], no OS root store in the runtime's dependency
/// closure.
fn refuse_legacy_roots(lock: &Lock, scope: LockScope) -> Result<(), RootsViolation> {
    if let Some(legacy) = lock
        .packages
        .iter()
        .find(|package| package.name == LEGACY_ROOTS && package.version.major == 0)
    {
        return Err(RootsViolation::LegacyRoots(legacy.version.clone()));
    }
    if matches!(scope, LockScope::RootsOnly) {
        return Ok(());
    }
    let mut runtimes = lock
        .packages
        .iter()
        .enumerate()
        .filter(|(_, package)| package.name == RUNTIME_PACKAGE);
    let runtime = match (runtimes.next(), runtimes.next()) {
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
        if OS_ROOT_STORES.contains(&package.name.as_str()) {
            return Err(RootsViolation::RuntimeReaches(package.name.clone()));
        }
        for edge in &package.dependencies {
            pending.push(resolve_edge(lock, &package.name, edge)?);
        }
    }
    Ok(())
}

/// The lock assertion refuses legacy roots and an OS root store reached from
/// the runtime, and accepts the three real repo locks.
#[test]
fn legacy_roots_are_refused_in_every_lock() {
    let lock = |body: &str| {
        let parsed = parse_lock(&format!("version = 4\n{body}"));
        assert!(parsed.is_ok(), "fixture lock must parse: {body}");
        parsed.unwrap_or(Lock {
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
    for store in OS_ROOT_STORES {
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

    for (path, scope) in [
        ("Cargo.lock", LockScope::WithRuntime),
        ("editors/zed-ipe/Cargo.lock", LockScope::RootsOnly),
        ("tools/ipe-index/Cargo.lock", LockScope::RootsOnly),
    ] {
        let text = std::fs::read_to_string(repo_root().join(path)).unwrap_or_default();
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
    let req = match roots.split_once(':') {
        Some((name, req)) if name == LEGACY_ROOTS => req,
        _ => return Err(DenyViolation::NotNameColonReq(roots.clone())),
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

    // Standalone cargo build, CWD = emitted crate dir. The target dir forwards
    // the warm shared target: CI exports only IPE_ORACLE_SHARED_TARGET, so a
    // plain CARGO_TARGET_DIR read would miss it and cold-build the whole dep
    // tree. `child_shared_target_from_env` resolves that variable (else an
    // ambient CARGO_TARGET_DIR a local lane set), falling back to an isolated
    // dir inside the crate so a bare runner stays hermetic.
    let target_dir = e2e_support::child_shared_target_from_env()
        .map_or_else(|| out.join("target"), PathBuf::from);
    let status = std::process::Command::new("cargo")
        .arg("build")
        .args(["--target", plan.triple.as_str()])
        .env("CARGO_TARGET_DIR", &target_dir)
        .current_dir(&out)
        .status()
        .expect("spawn cargo");
    assert!(status.success(), "cargo build --target musl failed (SEAL)");

    let bin = target_dir
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
    let entry = root
        .join("examples")
        .join("shapes")
        .join("non-tea")
        .join("hello-world")
        .join("src")
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("static_run_e2e");
    let _ = std::fs::remove_dir_all(&out);

    // Forward the warm shared target (IPE_ORACLE_SHARED_TARGET in CI, else an
    // ambient CARGO_TARGET_DIR a local lane set), staying hermetic inside the
    // scratch dir when neither is present.
    let target_dir = e2e_support::child_shared_target_from_env()
        .map_or_else(|| out.join("target"), PathBuf::from);

    let run = std::process::Command::new(support::ipe_bin())
        .args(["dev", "run"])
        .arg(&entry)
        .args(["--static", "--out"])
        .arg(&out)
        .env("CARGO_TARGET_DIR", &target_dir)
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
    let bin = target_dir
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
