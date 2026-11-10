//! Every native runtime feature set the backend selects has a warning-denying
//! clippy leg in CI.
//!
//! The emitted crate compiles `ipe-runtime-rust` under exactly the feature set
//! [`RustBackend::runtime_feature_names`] selects, so a runtime warning that
//! fires only under one set reaches the user's terminal unless that set is
//! linted on its own. This module is the native twin of
//! `wasm_featureset_closure`:
//!
//! 1. each surface flag, alone, plus each build mode (the database drivers,
//!    the development intent, the debugger, the watch-mode terminal channel)
//!    is asked of the real backend for its native feature set;
//! 2. the union of those sets must name every native feature the runtime
//!    feature enum declares, so a new feature without a basis case goes red;
//! 3. every distinct set must have a leg in the `runtime-feature-combos-run`
//!    job of `ci.yml`, and the same command in `check-manifest.yml`, of the
//!    exact form `cargo clippy -p ipe-runtime-rust --no-default-features
//!    --features <set> --all-targets -- -D warnings`, alone in an
//!    unconditional step.
//!
//! The failure message prints the exact legs to add.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ipe_backend_rust::{
    BuildIntent, DbDriver, RuntimeContentId, RuntimeDep, RustBackend, tokio_projection_table,
};
use ipe_intern::{Interner, Symbol};
use ipe_ir::{EnumDef, ModPath, Module, Program, TypeDef};

/// The browser-only feature, never selected on a native target.
const WASM_ONLY: &str = "wasm-client";

/// The CI job whose steps carry the native feature-set legs.
const CI_JOB: &str = "runtime-feature-combos-run";

/// The `check-manifest.yml` context that mirrors [`CI_JOB`].
const MANIFEST_CONTEXT: &str = "runtime-feature-combos";

/// One surface flag a body-free module can carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Surface {
    Tea,
    Server,
    Ui,
    Web,
    Tui,
    Console,
    Webview,
    Css,
    Auth,
    Principal,
    Websocket,
    Email,
    Locale,
    Time,
    EnvPublic,
    Http,
    Config,
    Compression,
    Csv,
    Cache,
    Encoding,
    Regex,
    Uuid,
    Random,
    Log,
    Decimal,
    CharCategory,
    CryptoCore,
    Secret,
    Json,
    Crypto,
    Jwt,
    Url,
    AsyncRuntime,
}

impl Surface {
    /// Every surface flag of [`Module`] the feature selection reads.
    const ALL: [Self; 34] = [
        Self::Tea,
        Self::Server,
        Self::Ui,
        Self::Web,
        Self::Tui,
        Self::Console,
        Self::Webview,
        Self::Css,
        Self::Auth,
        Self::Principal,
        Self::Websocket,
        Self::Email,
        Self::Locale,
        Self::Time,
        Self::EnvPublic,
        Self::Http,
        Self::Config,
        Self::Compression,
        Self::Csv,
        Self::Cache,
        Self::Encoding,
        Self::Regex,
        Self::Uuid,
        Self::Random,
        Self::Log,
        Self::Decimal,
        Self::CharCategory,
        Self::CryptoCore,
        Self::Secret,
        Self::Json,
        Self::Crypto,
        Self::Jwt,
        Self::Url,
        Self::AsyncRuntime,
    ];
}

/// A body-free module with only `surface` set (no surface for `None`).
///
/// The struct literal names every field, so a new `uses_*` flag on [`Module`]
/// fails to compile here until it is given a [`Surface`] case.
fn module_with(name: Symbol, surface: Option<Surface>) -> Module {
    let on = |s: Surface| surface == Some(s);
    Module {
        name: ModPath(vec![name]),
        types: vec![],
        funcs: vec![],
        entry: None,
        records: vec![],
        uses_tea: on(Surface::Tea),
        uses_server: on(Surface::Server),
        uses_ui: on(Surface::Ui) || on(Surface::Tui),
        uses_web: on(Surface::Web),
        uses_tui: on(Surface::Tui),
        uses_console: on(Surface::Console),
        uses_webview: on(Surface::Webview),
        uses_css: on(Surface::Css),
        uses_auth: on(Surface::Auth),
        uses_principal: on(Surface::Principal),
        uses_websocket: on(Surface::Websocket),
        uses_email: on(Surface::Email),
        uses_locale: on(Surface::Locale),
        uses_time: on(Surface::Time),
        uses_env_public: on(Surface::EnvPublic),
        uses_http: on(Surface::Http),
        uses_config: on(Surface::Config),
        uses_compression: on(Surface::Compression),
        uses_csv: on(Surface::Csv),
        uses_cache: on(Surface::Cache),
        uses_encoding: on(Surface::Encoding),
        uses_regex: on(Surface::Regex),
        uses_uuid: on(Surface::Uuid),
        uses_random: on(Surface::Random),
        uses_log: on(Surface::Log),
        uses_decimal: on(Surface::Decimal),
        uses_char_category: on(Surface::CharCategory),
        uses_crypto_core: on(Surface::CryptoCore),
        uses_secret: on(Surface::Secret),
        uses_json: on(Surface::Json),
        uses_crypto: on(Surface::Crypto),
        uses_jwt: on(Surface::Jwt),
        uses_url: on(Surface::Url),
        uses_debug: false,
        uses_ffi: false,
        uses_async_runtime: on(Surface::AsyncRuntime),
    }
}

/// A body-free module carrying the injected `SqlValue` enum, the signal a
/// lowered `Db` program gives the backend.
#[allow(clippy::expect_used)] // the interner refusing a fixed name is a broken fixture
fn db_module(interner: &mut Interner, name: Symbol) -> Module {
    let sqlvalue = interner.intern("SqlValue").expect("intern SqlValue");
    let mut module = module_with(name, None);
    module.types.push(TypeDef::Enum(EnumDef {
        name: sqlvalue,
        home: ModPath(vec![name]),
        variants: vec![],
        type_params: vec![],
    }));
    module
}

/// One way the backend can be asked for a native feature set.
struct Case {
    module: Module,
    intent: BuildIntent,
    driver: DbDriver,
    debugger: bool,
    hot_appearance: bool,
}

impl Case {
    const fn release(module: Module) -> Self {
        Self {
            module,
            intent: BuildIntent::Release,
            driver: DbDriver::Sqlite,
            debugger: false,
            hot_appearance: false,
        }
    }

    /// The feature set the backend selects for this case.
    #[allow(clippy::expect_used)] // a body-free program the backend refuses is a broken fixture
    fn features(self, interner: &Interner) -> BTreeSet<String> {
        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: BTreeSet::new(),
            modules: vec![self.module],
        };
        RustBackend::new(interner)
            .with_runtime_dep(Some(RuntimeDep {
                content: RuntimeContentId::from_digest_bytes([0; 16]),
            }))
            .with_build_intent(self.intent)
            .with_db_driver(self.driver)
            .with_debugger(self.debugger)
            .with_hot_appearance(self.hot_appearance)
            .runtime_feature_names(&program)
            .expect("runtime_feature_names must succeed for a body-free native program")
            .into_iter()
            .map(str::to_owned)
            .collect()
    }
}

/// Every distinct native feature set of the basis: no surface, each surface
/// alone, each database driver, and each build mode.
#[allow(clippy::expect_used)] // the interner refusing a fixed name is a broken fixture
fn basis_sets() -> BTreeSet<BTreeSet<String>> {
    let mut interner = Interner::new();
    let main = interner.intern("Main").expect("intern Main");
    let sqlite = db_module(&mut interner, main);
    let postgres = db_module(&mut interner, main);
    let mut cases = vec![Case::release(module_with(main, None))];
    cases.extend(
        Surface::ALL
            .iter()
            .map(|s| Case::release(module_with(main, Some(*s)))),
    );
    cases.push(Case::release(sqlite));
    cases.push(Case {
        driver: DbDriver::Postgres,
        ..Case::release(postgres)
    });
    cases.push(Case {
        intent: BuildIntent::Development,
        ..Case::release(module_with(main, None))
    });
    cases.push(Case {
        intent: BuildIntent::Development,
        debugger: true,
        ..Case::release(module_with(main, None))
    });
    cases.push(Case {
        intent: BuildIntent::Development,
        hot_appearance: true,
        ..Case::release(module_with(main, Some(Surface::Tui)))
    });
    cases.into_iter().map(|c| c.features(&interner)).collect()
}

/// Every native feature the runtime feature enum declares.
fn native_universe() -> BTreeSet<String> {
    tokio_projection_table()
        .into_iter()
        .map(|(name, _)| name.to_owned())
        .filter(|name| name != WASM_ONLY)
        .collect()
}

/// The universe members no basis set selects.
fn uncovered(universe: &BTreeSet<String>, basis: &BTreeSet<BTreeSet<String>>) -> Vec<String> {
    let reached: BTreeSet<&String> = basis.iter().flatten().collect();
    universe
        .iter()
        .filter(|f| !reached.contains(f))
        .cloned()
        .collect()
}

/// The exact leg command for `set`.
fn leg_command(set: &BTreeSet<String>) -> String {
    if set.is_empty() {
        "cargo clippy -p ipe-runtime-rust --no-default-features --all-targets -- -D warnings"
            .to_owned()
    } else {
        let list: Vec<&str> = set.iter().map(String::as_str).collect();
        format!(
            "cargo clippy -p ipe-runtime-rust --no-default-features --features {} --all-targets -- -D warnings",
            list.join(",")
        )
    }
}

/// The feature set a counted leg lints, or `None` when `cmd` is not a leg of
/// the exact counted form.
fn leg_features(cmd: &str) -> Option<BTreeSet<String>> {
    let tokens: Vec<&str> = cmd.split_whitespace().collect();
    let rest = tokens.strip_prefix(
        &[
            "cargo",
            "clippy",
            "-p",
            "ipe-runtime-rust",
            "--no-default-features",
        ][..],
    )?;
    let rest = rest.strip_suffix(&["--all-targets", "--", "-D", "warnings"][..])?;
    match rest {
        [] => Some(BTreeSet::new()),
        ["--features", list] => {
            let set: BTreeSet<String> = list.split(',').map(str::to_owned).collect();
            (!set.iter().any(String::is_empty)).then_some(set)
        }
        _ => None,
    }
}

/// The lines of the top-level `jobs:` entry `job` in a workflow.
fn job_lines<'a>(workflow: &'a str, job: &str) -> Vec<&'a str> {
    let header = format!("  {job}:");
    workflow
        .lines()
        .skip_while(|line| *line != header)
        .skip(1)
        .take_while(|line| {
            line.is_empty() || line.starts_with("   ") || line.trim_start().starts_with('#')
        })
        .collect()
}

/// The feature sets of the counted legs of `job`: each a step that is exactly
/// `- run: <leg>`, with no other key that could skip, soften or reshape it,
/// in a job with no `continue-on-error` and no `env`.
fn workflow_leg_sets(workflow: &str, job: &str) -> BTreeSet<BTreeSet<String>> {
    let lines = job_lines(workflow, job);
    let job_softened = lines.iter().any(|line| {
        let key = line.trim_start();
        line.starts_with("    ")
            && !line.starts_with("     ")
            && (key.starts_with("continue-on-error:") || key.starts_with("env:"))
    });
    if job_softened {
        return BTreeSet::new();
    }
    let mut steps: Vec<Vec<&str>> = Vec::new();
    for line in lines {
        if line.trim_start().starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if line.starts_with("      - ") {
            steps.push(vec![line]);
        } else if let Some(step) = steps.last_mut() {
            step.push(line);
        }
    }
    steps
        .iter()
        .filter_map(|step| match step.as_slice() {
            [only] => only
                .trim_start()
                .strip_prefix("- run: ")
                .and_then(leg_features),
            _ => None,
        })
        .collect()
}

/// The feature sets of the counted legs in `context`'s local run list.
fn manifest_leg_sets(manifest: &str, context: &str) -> BTreeSet<BTreeSet<String>> {
    let header = format!("  - context: {context}");
    manifest
        .lines()
        .skip_while(|line| *line != header)
        .skip(1)
        .take_while(|line| !line.starts_with("  - context:"))
        .filter_map(|line| line.trim_start().strip_prefix("- ").and_then(leg_features))
        .collect()
}

/// The basis sets without a counted leg in `legs`, as the commands to add.
fn missing_legs(
    basis: &BTreeSet<BTreeSet<String>>,
    legs: &BTreeSet<BTreeSet<String>>,
) -> Vec<String> {
    basis
        .iter()
        .filter(|set| !legs.contains(*set))
        .map(leg_command)
        .collect()
}

/// The repository root, the nearest ancestor of this crate holding `.github`.
#[allow(clippy::expect_used)] // a checkout without its CI configuration is a broken environment
fn repo_root() -> PathBuf {
    let manifest = e2e_support::manifest_dir!();
    let mut here: Option<&Path> = Some(&manifest);
    std::iter::from_fn(|| {
        let dir = here?;
        here = dir.parent();
        Some(dir.to_path_buf())
    })
    .find(|dir| {
        dir.join(".github")
            .join("workflows")
            .join("ci.yml")
            .is_file()
    })
    .expect("the repository root holding .github/workflows/ci.yml must resolve")
}

#[allow(clippy::expect_used)] // an unreadable CI file is a broken checkout
fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).expect("read the CI configuration")
}

#[test]
fn the_basis_reaches_every_native_feature() {
    let missing = uncovered(&native_universe(), &basis_sets());
    assert!(
        missing.is_empty(),
        "native runtime features no basis case selects: {missing:?}\n\
         add a surface or build-mode case that selects each, so its feature set gets a leg"
    );
}

#[test]
fn every_native_feature_set_has_a_ci_leg() {
    let basis = basis_sets();
    let missing = missing_legs(
        &basis,
        &workflow_leg_sets(&read(".github/workflows/ci.yml"), CI_JOB),
    );
    assert!(
        missing.is_empty(),
        "add these legs to the `{CI_JOB}` job of .github/workflows/ci.yml, \
         each its own unconditional `- run:` step:\n{}",
        missing.join("\n")
    );
}

#[test]
fn every_native_feature_set_has_a_manifest_mirror() {
    let basis = basis_sets();
    let missing = missing_legs(
        &basis,
        &manifest_leg_sets(&read(".github/ci/check-manifest.yml"), MANIFEST_CONTEXT),
    );
    assert!(
        missing.is_empty(),
        "add these commands to the `{MANIFEST_CONTEXT}` local run list of \
         .github/ci/check-manifest.yml:\n{}",
        missing.join("\n")
    );
}

#[test]
fn a_feature_no_basis_case_selects_is_reported() {
    let mut universe = native_universe();
    universe.insert("a-new-feature".to_owned());
    assert_eq!(
        uncovered(&universe, &basis_sets()),
        vec!["a-new-feature".to_owned()]
    );
}

#[test]
fn a_basis_set_without_its_leg_is_reported() {
    let set: BTreeSet<String> = ["async", "random"].map(str::to_owned).into();
    let basis: BTreeSet<BTreeSet<String>> = [set.clone()].into();
    let leg = leg_command(&set);
    let with_leg = format!("jobs:\n  {CI_JOB}:\n    steps:\n      - run: {leg}\n");
    assert!(missing_legs(&basis, &workflow_leg_sets(&with_leg, CI_JOB)).is_empty());
    let without = format!("jobs:\n  {CI_JOB}:\n    steps:\n      - run: cargo build\n");
    assert_eq!(
        missing_legs(&basis, &workflow_leg_sets(&without, CI_JOB)),
        vec![leg]
    );
}

#[test]
fn a_leg_that_can_be_skipped_or_softened_does_not_count() {
    let set: BTreeSet<String> = ["json"].map(str::to_owned).into();
    let basis: BTreeSet<BTreeSet<String>> = [set.clone()].into();
    let leg = leg_command(&set);
    let shapes = [
        format!("      - if: false\n        run: {leg}\n"),
        format!("      - run: {leg}\n        continue-on-error: true\n"),
        format!("      - run: {leg}\n        env:\n          RUSTFLAGS: --cap-lints=allow\n"),
        format!("    continue-on-error: true\n    steps:\n      - run: {leg}\n"),
        format!("      - run: {}\n", leg.replace(" -- -D warnings", "")),
        format!(
            "      - run: {}\n",
            leg.replace("--features json", "--features json --all-features")
        ),
    ];
    for steps in shapes {
        let workflow = format!("jobs:\n  {CI_JOB}:\n    steps:\n{steps}");
        assert_eq!(
            missing_legs(&basis, &workflow_leg_sets(&workflow, CI_JOB)),
            vec![leg.clone()],
            "this leg shape must not count:\n{workflow}"
        );
    }
}

#[test]
fn a_manifest_command_outside_the_context_does_not_count() {
    let set: BTreeSet<String> = ["json"].map(str::to_owned).into();
    let basis: BTreeSet<BTreeSet<String>> = [set.clone()].into();
    let leg = leg_command(&set);
    let manifest = format!(
        "  - context: {MANIFEST_CONTEXT}\n    local:\n      run:\n        - cargo build\n\
         \x20 - context: other\n    local:\n      run:\n        - {leg}\n"
    );
    assert_eq!(
        missing_legs(&basis, &manifest_leg_sets(&manifest, MANIFEST_CONTEXT)),
        vec![leg]
    );
}
