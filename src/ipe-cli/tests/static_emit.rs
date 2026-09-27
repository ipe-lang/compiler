//! Static-compilation gates (design: `docs/architecture/static-compilation.md`).
//!
//! Ungated tests assert the emitted-project SHAPE of a static plan (allocator
//! feature spliced into the manifest, generated `.cargo/config.toml`, stale-
//! config hygiene, CLI refusal wiring). The full proof — the emitted crate
//! cargo-builds for `x86_64-unknown-linux-musl`, `ldd` reports it static, and
//! it runs — is gated behind `IPE_E2E_STATIC=1` (it needs the musl target, a
//! musl-capable C compiler, and a cold multi-minute dependency build).

use std::path::{Path, PathBuf};

use ipe::{BuildOptions, CliError, build_plan};
use ipe_backend_rust::static_build::{
    CARGO_CONFIG_MARKER, CProfile, StaticAllocator, StaticPlan, StaticTriple,
};

mod support;

use support::repo_root;

fn write_hello(dir: &Path) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let entry = dir.join("Main.ipe");
    std::fs::write(
        &entry,
        "module Main exposing (main)\n\
         import Ipe.Io as Io\n\
         \n\
         main =\n    Io.println \"static hello\"\n",
    )?;
    Ok(entry)
}

const fn dlmalloc_plan() -> StaticPlan {
    StaticPlan {
        triple: StaticTriple::X8664LinuxMusl,
        c_profile: CProfile::WithLibc {
            allocator: StaticAllocator::Dlmalloc,
        },
    }
}

/// The binary cargo produces for an emitted crate, located under a target-
/// profile dir. Cargo names it after the crate's `[package] name`, which carries
/// a per-project identity hash (`ipe-app_<hash>`), so the artifact is NOT plain
/// `ipe-app`; resolve the name from the manifest cargo built from rather than
/// assume it. Falls back to `ipe-app` when the manifest is unreadable.
fn emitted_bin_name(crate_dir: &Path) -> String {
    let Ok(text) = std::fs::read_to_string(crate_dir.join("Cargo.toml")) else {
        return "ipe-app".to_owned();
    };
    let mut in_package = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix('[') {
            in_package = rest.starts_with("package]");
            continue;
        }
        if in_package
            && let Some(rest) = trimmed.strip_prefix("name")
            && let Some(rest) = rest.trim_start().strip_prefix('=')
        {
            let value = rest.trim().trim_matches('"');
            if !value.is_empty() {
                return value.to_owned();
            }
        }
    }
    "ipe-app".to_owned()
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
    let entry = write_hello(&scratch.join("srcdir")).expect("write hello source");
    let out = scratch.join("out");
    let runtime = ipe::resolve_runtime().expect("runtime must resolve");

    let statik = BuildOptions {
        static_plan: Some(dlmalloc_plan()),
        ..BuildOptions::default()
    };
    ipe::build_with_options(&entry, &out, &runtime, statik).expect("static build");

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
    ipe::build_with_options(&entry, &out, &runtime, BuildOptions::default())
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
    let entry = write_hello(&scratch.join("srcdir")).expect("write hello source");
    let out = scratch.join("out");
    let runtime = ipe::resolve_runtime().expect("runtime must resolve");

    // The first build claims `out`; the user's config lands in the owned dir.
    ipe::build_with_options(&entry, &out, &runtime, BuildOptions::default())
        .expect("first dynamic build");
    let config_path = out.join(".cargo").join("config.toml");
    std::fs::create_dir_all(out.join(".cargo")).expect("mk .cargo");
    let user_config = "# hand-written by a user\n[net]\noffline = false\n";
    std::fs::write(&config_path, user_config).expect("write user config");

    ipe::build_with_options(&entry, &out, &runtime, BuildOptions::default())
        .expect("dynamic rebuild");
    let after = std::fs::read_to_string(&config_path).expect("user config must survive");
    assert_eq!(after, user_config);
}

/// The mimalloc opt-in splices its own feature.
#[test]
fn static_emit_mimalloc_optin_activates_mimalloc() {
    let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("static_emit_mimalloc");
    let _ = std::fs::remove_dir_all(&scratch);
    let entry = write_hello(&scratch.join("srcdir")).expect("write hello source");
    let out = scratch.join("out");
    let runtime = ipe::resolve_runtime().expect("runtime must resolve");

    let statik = BuildOptions {
        static_plan: Some(StaticPlan {
            triple: StaticTriple::X8664LinuxMusl,
            c_profile: CProfile::WithLibc {
                allocator: StaticAllocator::Mimalloc,
            },
        }),
        ..BuildOptions::default()
    };
    ipe::build_with_options(&entry, &out, &runtime, statik).expect("static build");
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
        &["build", "NoSuch.ipe", "--static", "--allocator", "jemalloc"],
        "unknown allocator must refuse",
    );
    assert!(
        matches!(&err, CliError::CommandUsage { command: "build", reason } if reason.as_str().contains("jemalloc")),
        "got: {err:?}"
    );

    // --target without --static.
    let err = refuse(
        &[
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
        matches!(&err, CliError::CommandUsage { command: "build", reason } if reason.as_str().contains("x86_64-apple-darwin")),
        "wrong refusal: {err:?}"
    );

    // talc is refused until the arena design lands.
    let err = refuse(
        &["build", "NoSuch.ipe", "--static", "--allocator", "talc"],
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
        matches!(err, CliError::UsageOwned(_)),
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
///   rustls arm (`reqwest`/`lettre`/`sqlx`/`tokio-tungstenite`). This is the
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
    let sqlx = dep_line(&runtime, "sqlx", &runtime_path);
    assert!(
        sqlx.contains(r#""runtime-tokio-rustls""#),
        "sqlx must use the runtime-tokio-rustls arm: {sqlx}"
    );

    // POSITIVE proof for the WebSocket TLS dep — the strengthening that makes
    // this test robust against the comment-stripping in `effective()`. The
    // negative forbidden-backend scan above filters out comment lines so a
    // comment DOCUMENTING the `native-tls` exclusion is not a false positive;
    // but that same filtering means a negative scan alone could not tell a
    // documented exclusion apart from an actual flip. Asserting the POSITIVE —
    // `tokio-tungstenite` carries its rustls feature on its effective (non-
    // comment) dep line — cannot be defeated by any comment: if the backend were
    // flipped to native-tls, the rustls feature would be gone and this fails.
    let tungstenite = dep_line(&runtime, "tokio-tungstenite", &runtime_path);
    assert!(
        tungstenite.contains(r#""rustls-tls-webpki-roots""#),
        "tokio-tungstenite must carry the rustls-tls-webpki-roots arm (rustls-only \
         TLS, bundled webpki roots — no native-tls): {tungstenite}"
    );
}

/// Full static proof (THE SEAL, end to end): emit `examples/shapes/non-tea/hello-world`
/// under the dlmalloc static plan, `cargo build` it standalone for musl with
/// CWD = the emitted crate dir (cargo discovers `.cargo/config.toml` from
/// CWD, not from `--manifest-path`), then assert the binary is genuinely
/// static (`ldd`) and runs. Gated: `IPE_E2E_STATIC=1`.
#[test]
fn end_to_end_static_binary_is_static_and_runs() {
    if std::env::var("IPE_E2E_STATIC").is_err() {
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
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("static_e2e");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = ipe::resolve_runtime().expect("runtime must resolve");

    let plan = dlmalloc_plan();
    build_plan::preflight(&plan).expect("toolchain preflight (musl target + C compiler)");
    ipe::build_with_options(
        &entry,
        &out,
        &runtime,
        BuildOptions {
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
        .join(emitted_bin_name(&out));

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

/// `ipe run --static` end to end: the driver emits, cargo-builds for the
/// musl triple, resolves the relocated target dir, and execs a genuinely
/// static binary. Gated: `IPE_E2E_STATIC=1`.
#[test]
fn ipe_run_static_builds_and_executes_a_static_binary() {
    if std::env::var("IPE_E2E_STATIC").is_err() {
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
        .args(["run"])
        .arg(&entry)
        .args(["--static", "--out"])
        .arg(&out)
        .env("CARGO_TARGET_DIR", &target_dir)
        .output()
        .expect("spawn ipe run --static");
    assert!(
        run.status.success(),
        "ipe run --static failed\nstdout: {}\nstderr: {}",
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
        .join(emitted_bin_name(&out.join("rust")));
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
        "ipe run --static executed a non-static binary: {ldd_text}"
    );
}
