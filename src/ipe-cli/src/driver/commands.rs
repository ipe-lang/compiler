use super::{
    AnalysisTarget, BuildOptions, BundleHost, CliError, CollectedSources, OutTarget,
    RuntimeContext, apply_fixes_cmd, attribute_canon_errors, attribute_post_link_error,
    bluegreen_enabled, build_loose_file_into, build_project_into, bundle_delivery,
    collect_entry_and_siblings, collect_manifest_rooted_entry, collect_test_sources,
    compile_prepared, create_source_root, emit_machine_error, emit_permissions,
    find_manifest_for_ipe_file, frame_infer_error, gate_decoder_pipelines, home_to_source_map,
    io_err, resolve_analysis_entry, resolve_analysis_target, resolve_vendored_runtime_dir,
    run_version, runtime_dep_from_env, single_file_cargo_name_from_env,
};
use crate::cargo_step::{
    CargoBuild, CargoCrate, CargoOutput, CargoProfile, CargoTarget, EmbeddedApp, Verbosity,
};
use crate::contained_path::ResolvedPath;
use crate::output_dir::{EmitTarget, OutputArea, OutputRoot, OwnedDir, ProjectPaths};
use crate::style::TerminalSafe;
use crate::verb::{CommandName, DevVerb, ReleaseVerb, Umbrella, Verb};
use crate::{
    ALL_CODES, BTreeMap, Interner, Path, PathBuf, build_plan, cli_args, delivery, explain_page,
    ffi, fs, help, io_bounded, native_ffi_consent, package_manifest, project, run_sandbox,
    runtime_embed, screen, style, text, title, toolchain, unsafe_ack, wasi_run, watch, web_consent,
};

/// A request for help asks for output, not an error: it prints to stdout and
/// exits successfully. Returned by [`intercept_help`] so [`run_cli`] can honour
/// it before any command runs.
pub struct HelpRequest;

/// Recognise a help request in `args` and, when found, print the matching page
/// to stdout. Handles the top-level screen (no args, or a leading `--help` /
/// `-h` / `help`) and every per-command page (`<cmd> --help` or `help <cmd>`).
///
/// When `--json` accompanies the help flag the output is a stable JSON object
/// (schema `"ipe.cli.help/1"`) rather than the human screen — both for the
/// top-level grammar and for `<cmd> --help --json`. Human output remains the
/// default; `--json` is explicit opt-in.
///
/// Returns `Some(HelpRequest)` when help was printed (the caller returns `Ok`),
/// or `None` when `args` is an ordinary command to dispatch.
pub fn intercept_help(args: &[String]) -> Option<HelpRequest> {
    let is_help_flag = |a: &str| a == "--help" || a == "-h" || a == "help";
    let has_json = |slice: &[String]| slice.iter().any(|a| a == "--json");

    // No arguments, or a leading bare help token: the top-level screen.
    match args.split_first() {
        None => {
            show_top_level_help();
            return Some(HelpRequest);
        }
        Some((first, rest)) if is_help_flag(first) => {
            // Detect `--json` in the remaining tokens.
            let want_json = has_json(rest);
            // Strip --json from the token list before looking for a command name.
            let rest_no_json: Vec<&String> =
                rest.iter().filter(|a| a.as_str() != "--json").collect();

            if want_json {
                // `--help --json [<cmd>]` / `help --json [<cmd>]`
                let named_json = rest_no_json
                    .first()
                    .and_then(|c| help::command_json(c.as_str()));
                let json = named_json.unwrap_or_else(help::help_json);
                screen::emit_machine(screen::Stream::Stdout, &json);
            } else {
                // `help <name>` / `--help <name>`: that command's page, a
                // group's subpage, or the top-level screen — in that order.
                let named = rest_no_json.first().and_then(|c| {
                    help::command(c.as_str(), &std::io::stdout())
                        .or_else(|| help::group(c.as_str(), &std::io::stdout()))
                });
                match named {
                    Some(page) => show_help_page(&page),
                    None => show_top_level_help(),
                }
            }
            return Some(HelpRequest);
        }
        _ => {}
    }

    // `ipe <group> <verb> --help`: the grouped verb's own page, keyed by its
    // typed `Verb`. Checked BEFORE the group branch so a member verb's `--help`
    // resolves to the verb, not the group subpage.
    if let Some((group, tail)) = args.split_first()
        && let Some((sub, rest)) = tail.split_first()
        && let Some(verb) = help::group_member(group, sub)
        && rest.iter().any(|a| is_help_flag(a))
    {
        if has_json(rest) {
            if let Some(json) = help::command_json(verb.name()) {
                screen::emit_machine(screen::Stream::Stdout, &json);
                return Some(HelpRequest);
            }
        } else if let Some(page) = help::command(verb.name(), &std::io::stdout()) {
            show_help_page(&page);
            return Some(HelpRequest);
        }
    }

    // A help flag directly on a group (`ipe dev --help`): its subpage. A bare
    // group is not a help request — `run_cli` refuses it with
    // [`CliError::GroupRequired`].
    if let Some((first, rest)) = args.split_first()
        && help::is_group(first)
        && rest.first().is_some_and(|a| is_help_flag(a))
        && let Some(page) = help::group(first, &std::io::stdout())
    {
        show_help_page(&page);
        return Some(HelpRequest);
    }

    // `<cmd> --help [--json]`: a top-level command's own page. A legacy verb
    // name is no command, so a bare `build --help` falls through to its refusal.
    if let Some((cmd, rest)) = args.split_first()
        && help::is_command(cmd)
        && rest.iter().any(|a| is_help_flag(a))
    {
        if has_json(rest) {
            if let Some(json) = help::command_json(cmd) {
                screen::emit_machine(screen::Stream::Stdout, &json);
                return Some(HelpRequest);
            }
        } else if let Some(page) = help::command(cmd, &std::io::stdout()) {
            show_help_page(&page);
            return Some(HelpRequest);
        }
    }
    None
}

/// Print a rendered help page (already guttered and styled for stdout) in the
/// screen frame on stdout.
fn show_help_page(page: &str) {
    let mut out = screen::Screen::new(screen::Stream::Stdout);
    out.guttered(page);
    out.emit();
}

/// Print the top-level overview in the screen frame on stdout, closed by the
/// bug footer.
fn show_top_level_help() {
    let mut out = screen::Screen::new(screen::Stream::Stdout);
    out.guttered(&help::top_level(&std::io::stdout()))
        .with_bug_footer();
    out.emit();
}

/// Parse `argv` (excluding the program name) and run the requested command.
///
/// # Errors
/// Returns [`CliError`] on misuse, a compile failure, or a filesystem error.
pub fn run_cli(args: &[String]) -> Result<(), CliError> {
    if intercept_help(args).is_some() {
        return Ok(());
    }
    // `--version`/`-V` is an alias of the `version` command, symmetric with the
    // `--help`/`-h` interception above: the near-universal version probe that
    // editors, version managers, and CI use must not fall through to
    // unknown-command. Any trailing flags (e.g. `--json`) pass to the command.
    if let Some((first, rest)) = args.split_first()
        && (first == "--version" || first == "-V")
    {
        return with_help_on_misuse("version", run_version(rest));
    }
    let Some((cmd, rest)) = args.split_first() else {
        // A bare `ipe` (no command) carries an empty token and just shows help.
        return Err(CliError::UnknownCommand {
            attempted: TerminalSafe::sanitize(""),
        });
    };
    // `ipe explain` has been folded into `ipe doc`. Print a pointer and
    // forward to `run_explain` so existing scripts keep working with a
    // deprecation notice rather than a hard failure.
    if cmd == "explain" {
        return with_help_on_misuse("doc", run_explain(rest));
    }
    // `ipe pack` has been folded into the delivery grammar: app bundling is one
    // `ipe <verb> <shape> <host>` vocabulary, not a parallel flag language. Point
    // the old command at its delivery-grammar equivalent rather than failing with
    // a bare unknown-command.
    if cmd == "pack" {
        return Err(CliError::Usage(text::msg::pack_retired()));
    }
    // A legacy verb name has no handler: its one representation is this
    // refusal naming the grouped forms.
    if let Some(&(_, forms)) = GROUP_REQUIRED
        .iter()
        .find(|(name, _)| *name == cmd.as_str())
    {
        return Err(group_required(cmd, forms, rest));
    }
    // An umbrella group (`ipe dev <verb> …`) resolves its member to a typed
    // `Verb`, and `dispatch` runs it with the umbrella's posture. A bare group
    // refuses; a `release` followed by a non-member token (`release web`)
    // refuses with the `release build` form carrying that tail; a `dev`
    // followed by a non-member token is an unknown verb of the group.
    if let Some(umbrella) = Umbrella::from_name(cmd) {
        let Some((sub, tail)) = rest.split_first() else {
            return Err(group_required(cmd, bare_group_forms(umbrella), &[]));
        };
        return match (Verb::member(umbrella, sub), umbrella) {
            (Some(verb), _) => dispatch(verb, tail),
            (None, Umbrella::Release) => Err(group_required(cmd, &[Verb::RELEASE_BUILD], rest)),
            (None, Umbrella::Dev) => Err(CliError::UnknownGroupSub {
                group: umbrella.name(),
                attempted: TerminalSafe::sanitize(sub),
            }),
        };
    }
    // One registry drives both dispatch and help: a command runs exactly when it
    // is described, so the two cannot drift. The handler carries the canonical
    // static name its misuse `--help` page keys on. `--version`/`-V` is aliased
    // to the `version` command above the dispatch table.
    match help::handler(cmd.as_str()) {
        Some((name, run)) => with_help_on_misuse(name, run(rest)),
        // An unknown command is misuse: show the top-level help and fail. Unlike
        // an explicit `--help`, this is not a request, so it exits non-zero. The
        // typed token is kept so a near-miss can be suggested.
        None => Err(CliError::UnknownCommand {
            attempted: TerminalSafe::sanitize(cmd),
        }),
    }
}

/// The legacy verb names and the grouped forms each refusal names.
///
/// A name here has no handler and no help page: typing it yields
/// [`CliError::GroupRequired`] and nothing else.
pub const GROUP_REQUIRED: &[(&str, &[Verb])] = &[
    ("build", &[Verb::DEV_BUILD, Verb::RELEASE_BUILD]),
    ("run", &[Verb::DEV_RUN, Verb::RELEASE_RUN]),
    ("watch", &[Verb::DEV_WATCH]),
    ("exec", &[Verb::RELEASE_RUN]),
    ("eject", &[Verb::RELEASE_EJECT]),
];

/// The forms a bare umbrella group's refusal names.
///
/// A bare `ipe dev` names none; its members stay discoverable through
/// `ipe dev --help`.
const fn bare_group_forms(umbrella: Umbrella) -> &'static [Verb] {
    match umbrella {
        Umbrella::Dev => &[],
        Umbrella::Release => &[Verb::RELEASE_BUILD, Verb::RELEASE_RUN, Verb::RELEASE_EJECT],
    }
}

/// The [`CliError::GroupRequired`] refusal for `attempted` followed by `tail`.
///
/// Both echo user argv, so both are sanitized for the terminal.
fn group_required(attempted: &str, forms: &'static [Verb], tail: &[String]) -> CliError {
    CliError::GroupRequired {
        attempted: TerminalSafe::sanitize(attempted),
        forms,
        tail: TerminalSafe::sanitize(&tail.join(" ")),
    }
}

/// Run the grouped verb `verb` on its argument tail.
///
/// The match is exhaustive over [`Verb`], so a verb added to the type has no
/// representation until it is given a handler here. A usage error renders the
/// verb's own help page.
///
/// # Errors
///
/// Whatever the verb's handler returns, with usage errors mapped to
/// [`CliError::CommandUsage`].
pub fn dispatch(verb: Verb, args: &[String]) -> Result<(), CliError> {
    let result = match verb {
        Verb::Dev(DevVerb::Build) => run_build(args),
        Verb::Dev(DevVerb::Run) => run_run(args),
        Verb::Dev(DevVerb::Watch) => run_watch(args),
        Verb::Release(ReleaseVerb::Build) => run_release(args),
        Verb::Release(ReleaseVerb::Run) => run_release_run(args),
        Verb::Release(ReleaseVerb::Eject) => run_eject(args),
    };
    with_help_on_misuse(verb, result)
}

/// Map a known command's raw usage error into a [`CliError::CommandUsage`] so the
/// caller prints that command's full, indented `--help` page — the uniform
/// "misuse shows help" output. Any non-usage error (a compile failure, a
/// filesystem error) passes through untouched, since it is not a help-worthy
/// misuse. `command` is always a known command or grouped verb.
pub fn with_help_on_misuse(
    command: impl Into<CommandName>,
    result: Result<(), CliError>,
) -> Result<(), CliError> {
    match result {
        Err(CliError::Usage(reason)) => Err(CliError::CommandUsage {
            command: command.into(),
            reason: TerminalSafe::sanitize(&reason),
        }),
        other => other,
    }
}

/// Project-aware default entry for `build`, `run`, or `watch` without a positional.
///
/// Resolution order:
/// 1. `./package.ipe` exists — entry `"."` (project mode; `discover_manifest`
///    reads the directory's `package.ipe`).
/// 2. `./src/Main.ipe` exists — entry `"src/Main.ipe"` (single-file
///    shorthand without a manifest).
/// 3. A bare `./ipe.toml` with no `package.ipe` — a clear legacy-toml error, so
///    the legacy manifest never silently governs a build.
/// 4. Neither — usage error: nothing to build here.
pub fn default_entry() -> Result<String, CliError> {
    if std::path::Path::new(package_manifest::PACKAGE_IPE).exists() {
        return Ok(".".to_owned());
    }
    if std::path::Path::new("src/Main.ipe").exists() {
        return Ok("src/Main.ipe".to_owned());
    }
    if project::has_only_legacy_toml(std::path::Path::new(".")) {
        return Err(CliError::Usage(text::msg::legacy_toml_hint()));
    }
    Err(CliError::Usage(text::msg::no_entry()))
}

/// `ipe dev watch [<path>]` — rebuild and re-run on every source change
/// (`crate::watch`). Never returns
/// `Err` for a build failure (INV-3: a red build is logged, not fatal);
/// only misuse / setup failures propagate.
pub fn run_watch(rest: &[String]) -> Result<(), CliError> {
    let args = cli_args::parse_watch(rest)?;
    let entry = match args.entry {
        Some(e) => e,
        None => default_entry()?,
    };

    // Validate the delivery grammar against the shape `main` pins: the `[shape]`
    // cross-check and the `[runtime] [host]` tail. `ipe dev watch` is a dev
    // build-run-reload loop that serves the served runtime; it takes no `--static`.
    // A grammar refusal (e.g. `web solo ios`, which cannot be watched — see the
    // spec's mobile-watch note) is caught here before the loop starts.
    let delivery = resolve_delivery(
        Path::new(&entry),
        &args.delivery,
        false,
        Verb::DEV_WATCH.name(),
    )?;

    // A Tui app with no interactive terminal is refused right here — before
    // any compile or cargo work — same as `ipe dev run`.
    gate_terminal(Verb::DEV_WATCH.name(), delivery.shape())?;
    // Watch is always a native dependency-model dev build (it never vendors the
    // runtime tree, nor targets wasm), so — like `ipe dev build` on its default path
    // — it must NOT require the vendored runtime source subtree. It resolves the
    // dependency crate root itself via `runtime_embed::resolve` once the loop
    // starts (see `watch::run`); the vendored tree is honoured only when passed
    // explicitly with `--runtime`. Requiring `resolve_runtime` up front made
    // `ipe dev watch` fail to locate the runtime in an installed checkout where the
    // vendored subtree is absent but the dependency crate root resolves fine.
    let runtime_dir = resolve_vendored_runtime_dir(args.runtime.clone(), false)?;

    // Fail closed before the watch loop starts: `ipe dev watch` rebuilds with cargo
    // on every change, so a missing toolchain is reported once, up front, with
    // its root cause — not as a per-rebuild opaque spawn error.
    let cargo_bin = toolchain::require_cargo(toolchain::ToolIntent::Watch)?;

    let output = resolve_output_root(args.out.as_deref(), Path::new(&entry), None)?;
    let rust_area = output.area(&[OutputArea::Rust]);
    let out_dir = rust_area.path()?;

    let mut opts = watch::WatchOptions::new(PathBuf::from(entry), out_dir, runtime_dir);
    opts.out_target = Some(EmitTarget::Area(rust_area));
    opts.port = args.port;
    opts.cargo_path = cargo_bin.path().to_path_buf();
    opts.quiet = args.quiet;
    opts.bluegreen = bluegreen_enabled();
    opts.reset_state = args.reset_state;
    opts.debugger = args.debugger;
    // Version header: human mode only (not quiet, not piped).
    if !args.quiet {
        use std::io::IsTerminal as _;
        if std::io::stderr().is_terminal() {
            style::print_command_header();
        }
    }
    watch::run(&opts)
}

/// Resolve the output root for a build of `entry`.
///
/// `--out <dir>` or `<project>/out`, proven claimable by ipe and disjoint from
/// the project's sources.
///
/// # Errors
/// [`CliError::OutputRefused`] when the location overlaps the project or holds
/// files ipe did not create; manifest discovery errors when `manifest` is absent
/// and the entry's project must be discovered.
pub fn resolve_output_root(
    out: Option<&str>,
    entry: &Path,
    manifest: Option<&project::ProjectManifest>,
) -> Result<OutputRoot, CliError> {
    let paths = match manifest {
        Some(m) => ProjectPaths::from_manifest(m),
        None => ProjectPaths::discover(entry)?,
    };
    OutputRoot::resolve(out, &paths)
}

/// Classify the shape `main` pins for the entry the user named, reading the
/// entry `.ipe` source and inspecting `main`'s head (spec § 0, § 1).
///
/// The shape is the single source of truth for delivery: it is derived from
/// code, never from config or the CLI. `entry_arg` is the raw positional (a
/// `.ipe` file, a project directory, or a bare `.`); it is routed to its entry
/// source file the same way the analysis surfaces route it. A source that does
/// not parse yields [`delivery::Shape::Script`] — the cross-check then does not
/// fire and the build pipeline reports the real parse error with a blamed span.
///
/// # Errors
/// [`CliError::Io`] when the entry source cannot be read, or the manifest /
/// entry-resolution errors of [`resolve_analysis_entry`].
pub fn classify_entry_shape(entry_arg: &Path) -> Result<delivery::Shape, CliError> {
    let entry_file = resolve_analysis_entry(entry_arg)?;
    let source = io_bounded::read_to_string_capped(&entry_file, io_bounded::SOURCE_READ_CAP)?;
    let mut interner = Interner::new();
    // A parse failure is the compile pipeline's to report (with a blamed span);
    // the shape cross-check simply does not fire, so classify as a script.
    let shape = ipe_parse::parse_module(&source, &mut interner)
        .map_or(ipe_canon::shape_source::MainShape::Script, |module| {
            ipe_canon::shape_source::classify_main_shape(&module, &interner)
        });
    Ok(delivery::Shape::from_main(shape))
}

/// Resolve the delivery for a `build` / `run` / `watch` invocation: classify the
/// shape `main` pins, cross-check the optional `[shape]` positional against it,
/// resolve the `[runtime] [host]` tail, and gate `--static`.
///
/// This is the one place the CLI turns the delivery grammar into a validated
/// [`delivery::Delivery`], from which `is_webview_native()` drives the backend
/// `webview_host` signal and the packager routing. Every refusal is a
/// pedagogical [`delivery::DeliveryError`], surfaced as a usage error.
///
/// # Errors
/// [`CliError::Usage`] carrying the delivery lesson on a shape mismatch, an
/// invalid runtime/host combination, or a `--static` request the delivery
/// cannot honour; the I/O errors of [`classify_entry_shape`].
pub fn resolve_delivery(
    entry_arg: &Path,
    positionals: &cli_args::DeliveryPositionals,
    wants_static: bool,
    command: &str,
) -> Result<delivery::Delivery, CliError> {
    let pinned = classify_entry_shape(entry_arg)?;
    delivery::Delivery::resolve_checked(
        pinned,
        positionals.stated_shape,
        &positionals.tokens,
        wants_static,
    )
    .map_err(|e| CliError::Usage(text::msg::command_refusal(&command, &e)))
}

/// Route an entry argument to its `package.ipe`, when one governs it.
///
/// A directory must contain one, and a `.ipe` entry walks up the tree looking
/// for one (returning no manifest — single-file mode — when none exists, and
/// refusing one that fails the owner rule). A directory carrying only a legacy
/// `ipe.toml` is a clear legacy-toml error.
pub fn discover_manifest(entry_path: &Path) -> Result<Option<PathBuf>, CliError> {
    if entry_path.is_dir() {
        if let Some(manifest) = project::manifest_in_dir(entry_path) {
            return Ok(Some(manifest));
        }
        if project::has_only_legacy_toml(entry_path) {
            return Err(CliError::Usage(text::msg::legacy_toml_hint()));
        }
        Err(CliError::Usage(text::msg::watch_dir_no_manifest()))
    } else {
        find_manifest_for_ipe_file(entry_path)
    }
}

/// Resolve the static request with full precedence — CLI flags > env
/// (`IPE_STATIC` / `IPE_TARGET` / `IPE_ALLOC`) > `package.ipe` `[rust]` > AUTO —
/// into a typed plan (or a typed refusal — no artifact), run the toolchain
/// preflight, and surface the mimalloc opt-in notice. Shared by `build` and
/// `run`; resolved ONCE before any compilation starts.
///
/// `IPE_TARGET=wasm`/`IPE_TARGET=wasi` is a wasm-target axis signal (resolved
/// by [`resolve_compile_target`]) and is NOT a static-link triple; it is
/// stripped here so it never reaches the musl-triple gate in
/// [`build_plan::resolve`].
pub fn resolve_static_plan(
    cli_layer: build_plan::StaticRequestLayer,
    manifest: Option<&Path>,
    output_format: cli_args::OutputFormat,
) -> Result<Option<ipe_backend_rust::static_build::StaticPlan>, CliError> {
    let toml_layer = match manifest {
        Some(m) => project::parse_manifest(m)?.static_request,
        None => build_plan::StaticRequestLayer::default(),
    };
    let mut env = build_plan::env_layer()?;
    if matches!(env.target.as_deref(), Some("wasm" | "wasi")) {
        env.target = None;
    }
    let merged = cli_layer.or(env).or(toml_layer);
    let static_plan = build_plan::resolve(&merged)?;
    if let Some(plan) = &static_plan {
        build_plan::preflight(plan)?;
        if plan.allocator() == ipe_backend_rust::static_build::StaticAllocator::Mimalloc
            && output_format == cli_args::OutputFormat::Human
        {
            // The design's explicit opt-in notice: the C cost is acknowledged,
            // never silent. Human mode only — machine streams must stay
            // furniture-free (see #2590).
            crate::screen::chatter(
                crate::screen::Stream::Stderr,
                crate::screen::Tone::Text,
                "note: mimalloc adds a C toolchain and unsafe FFI, vendors C source, and \
                     freezes it into the artifact for CVE-rebuild purposes; chosen explicitly.",
            );
        }
    }
    Ok(static_plan)
}

/// Resolve the wasm-vs-native target with the three-tier precedence chain:
/// The compilation target a `build`/`run`/`release` invocation resolves to —
/// the single typed successor to the old wasm-vs-native bit.
///
/// Three cells, one per emitted [`ipe_ir::Target`]: the native host binary, the
/// sandboxed browser client (`wasm32-unknown-unknown`), and the co-located
/// portable WASI module (`wasm32-wasip1`). Every downstream fork — the emit
/// target, the `(engine, triple)` matrix gate, and the post-emit build path —
/// reads this one value, so the three cases can never drift out of agreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompileTarget {
    /// The native host binary (server / CLI / TUI / desktop / script).
    Native,
    /// The sandboxed browser WASM client (`--target wasm`, `web solo`).
    WasmClient,
    /// The co-located portable WASI module (`--target wasi`) — a
    /// `Direct`/`Script` program's native effect floor over `wasm32-wasip1`.
    WasmWasi,
}

impl CompileTarget {
    /// The backend [`ipe_ir::Target`] this compile target emits for.
    const fn ir_target(self) -> ipe_ir::Target {
        match self {
            Self::Native => ipe_ir::Target::Native,
            Self::WasmClient => ipe_ir::Target::WasmClient,
            Self::WasmWasi => ipe_ir::Target::WasmWasi,
        }
    }

    /// The `(engine, triple)` pair the delivery validity matrix
    /// ([`delivery::Delivery::admit_triple`]) gates on. This is the single point
    /// that maps the resolved target to the typed matrix axes, so the matrix —
    /// not a separate biconditional — is the live gate at every callsite. The
    /// WASI cell admits ONLY the sealed `Direct`/`Script` floor; every non-viable
    /// shape (TEA/Server/Web) is refused there fail-closed.
    const fn engine_triple(self) -> (delivery::Engine, Option<delivery::TargetTriple>) {
        match self {
            Self::Native => (delivery::Engine::Native, None),
            Self::WasmClient => (
                delivery::Engine::WasmClient,
                Some(delivery::TargetTriple::BrowserWasm),
            ),
            Self::WasmWasi => (
                delivery::Engine::WasmWasi,
                Some(delivery::TargetTriple::Wasm32Wasip1),
            ),
        }
    }

    /// Whether this target emits a WebAssembly module (either flavour) — the
    /// builds that shell out to a wasm cross-compile rather than the native
    /// toolchain resolution + exec path.
    const fn is_wasm(self) -> bool {
        matches!(self, Self::WasmClient | Self::WasmWasi)
    }
}

/// Resolve the compilation target from the precedence chain: the CLI
/// `--target` flavour > `IPE_TARGET` env (`wasm`/`wasi`) > `[wasm].mode` in
/// `package.ipe` (browser client only) > default native.
///
/// `cli_wasm` carries the parsed CLI `--target` flavour from `BuildMode::Emit`.
/// `wasm_config` is `None` when there is no manifest (sibling-discovery build);
/// the manifest `[wasm].mode` selects the browser client only (WASI is an
/// explicit per-invocation target, never a project-default).
pub fn resolve_compile_target(
    cli_wasm: cli_args::WasmKind,
    wasm_config: Option<&project::WasmConfig>,
) -> CompileTarget {
    match cli_wasm {
        cli_args::WasmKind::Client => return CompileTarget::WasmClient,
        cli_args::WasmKind::Wasi => return CompileTarget::WasmWasi,
        cli_args::WasmKind::None => {}
    }
    match ipe_env::var("IPE_TARGET").ok().as_deref() {
        Some("wasm") => return CompileTarget::WasmClient,
        Some("wasi") => return CompileTarget::WasmWasi,
        _ => {}
    }
    if wasm_config.is_some_and(project::WasmConfig::implies_wasm_target) {
        return CompileTarget::WasmClient;
    }
    CompileTarget::Native
}

/// `ipe dev build [<path>]` — compile a program to a native or WebAssembly artifact.
// A linear pipeline (parse → discover manifest → acknowledge unsafe → resolve
// target → emit → cargo build); the steps share enough locals that splitting
// reads worse than the whole.
/// The outcome of a successful `ipe dev build`, carrying the facts needed to render
/// either a human progress line or a JSON success object.
pub struct BuildSuccess {
    /// The entry source file that was compiled.
    entry: String,
    /// The output directory holding the emitted Rust project.
    out_dir: PathBuf,
}

#[allow(clippy::too_many_lines)]
pub fn run_build(rest: &[String]) -> Result<(), CliError> {
    // Resolve the output format in a first, infallible pass — before the
    // fallible parse in the body — so a parse error still renders through the
    // machine surface the caller asked for rather than the human banner.
    let format = cli_args::peek_output_format(rest);
    let result = run_build_body(rest);
    match result {
        Err(e) => Err(if format == cli_args::OutputFormat::Human {
            e
        } else {
            emit_machine_error(format, Verb::DEV_BUILD.name(), &e)
        }),
        Ok(success) => {
            if format == cli_args::OutputFormat::Json {
                // Machine-readable success: one JSON object to stdout.
                let json = serde_json::json!({
                    "status": "ok",
                    "entry": success.entry,
                    "out": success.out_dir.to_string_lossy(),
                });
                screen::emit_machine(screen::Stream::Stdout, &format!("{json}\n"));
            }
            // Human progress line already printed inside run_build_body.
            Ok(())
        }
    }
}

/// Inner implementation of `run_build`, format-agnostic on the success path.
/// Returns a [`BuildSuccess`] describing the outcome; the caller renders it.
#[allow(clippy::too_many_lines)]
pub fn run_build_body(rest: &[String]) -> Result<BuildSuccess, CliError> {
    let args = cli_args::parse_build(rest)?;
    let entry = match args.entry {
        Some(e) => e,
        None => default_entry()?,
    };
    let entry_path = PathBuf::from(&entry);

    let wants_static = matches!(
        &args.mode,
        cli_args::BuildMode::Emit { static_layer, .. }
            if static_layer.static_build == Some(true)
    );

    // Parse guaranteed `--emit-ir` composes with no emit-affecting flag, so the
    // IR-dump path carries no options to drop.
    let (out, wasm_target, cli_layer) = match args.mode {
        cli_args::BuildMode::EmitIr => {
            // `--emit-ir` reads a single entry file, so route a directory / bare
            // `.` project root to its entry `.ipe` — the same convention the
            // analysis surfaces use — rather than handing the directory straight
            // to the source reader (which would fail with a raw "Is a directory").
            // A file argument is never substituted for the project's default
            // entry; only widened to `tests ∪ src` when it names a test file.
            let ir_target = resolve_analysis_target(&entry_path)?;
            let tree = emit_ir_text_for_target(&ir_target)?;
            screen::emit_machine(screen::Stream::Stdout, &tree);
            return Ok(BuildSuccess {
                entry,
                out_dir: PathBuf::new(),
            });
        }
        cli_args::BuildMode::Emit {
            out,
            wasm,
            static_layer,
        } => (out, wasm, static_layer),
    };

    // Route the build:
    //   1. Directory → expect package.ipe inside it.
    //   2. .ipe file → walk up looking for package.ipe (project-mode); fall back
    //      to sibling discovery when no manifest exists, so a multi-file project
    //      built via the file-path shorthand still compiles the whole module
    //      graph rather than the single entry file.
    let manifest = discover_manifest(&entry_path)?;

    // Parse the manifest early to read [wasm].mode for target inference.
    // build_project_with_options re-parses it later to fill in publicEnv /
    // hydrate-mode; the double parse is acceptable (manifests are small).
    let manifest_parsed = manifest
        .as_deref()
        .map(project::parse_manifest)
        .transpose()?;
    let manifest_wasm: Option<project::WasmConfig> =
        manifest_parsed.as_ref().map(|m| m.wasm.clone());

    // Static-flag contradictions (--cfree + C-requiring allocator,
    // --target without --static, talc-without-arena) are pure over the CLI +
    // env + manifest layers and touch no source. Resolving here — before
    // resolve_delivery reads the entry file — ensures a refused build produces
    // no artifact and touches nothing, even when the entry path does not exist.
    let static_plan = resolve_static_plan(cli_layer, manifest.as_deref(), args.format)?;

    // Resolve the delivery grammar against the shape `main` pins: the optional
    // `[shape]` cross-check, the `[runtime] [host]` tail, and the `--static`
    // gate. Runs after the static-plan check so a flag contradiction fires
    // before the entry file is read. A webview-native `web desktop` drives
    // `webview_host` below.
    let delivery = resolve_delivery(
        &entry_path,
        &args.delivery,
        wants_static,
        Verb::DEV_BUILD.name(),
    )?;

    // Human-friendly progress: the consent gates and the compile+emit below are
    // otherwise silent, so the banner and a start line come first and a done line
    // closes the build. Shown only on an interactive terminal so piped / CI output
    // stays clean; status goes to stderr (stdout carries data). Suppressed in
    // quiet mode (only warnings/errors) and in JSON mode (machine output only —
    // one JSON object to stdout at the end).
    let show_progress = !args.quiet && args.format != cli_args::OutputFormat::Json && {
        use std::io::IsTerminal as _;
        std::io::stderr().is_terminal()
    };
    if show_progress {
        style::print_command_header();
        crate::screen::chatter(
            crate::screen::Stream::Stderr,
            crate::screen::Tone::Text,
            &format!(
                "{} building {entry}",
                style::outcome_glyph(style::Outcome::Step)
            ),
        );
    }

    // A `desktop`/`ios`/`android` host is an application bundle, not a plain
    // artifact: it is routed through the delivery-grammar bundler (a fast dev
    // bundle for `build`) once the consent gates below admit it.
    let bundle_host = BundleHost::from_delivery_host(delivery.host())?;

    // `--fix` carries durable authorization: apply machine-applicable fixes
    // non-interactively before the capability resolution and the build see the
    // source, so the consented capability set describes the source that is
    // actually compiled.
    if bundle_host.is_none() && args.fix {
        apply_fixes_cmd(&entry_path, true, &mut std::io::stdout())?;
    }

    // Trust-boundary consent gates over ONE capability resolution — ahead of the
    // bundle route so a `desktop`/`ios`/`android` bundle build is gated too (a
    // bundle is a distributable), and ahead of the (costly) emit + cargo build.
    // A disclosed `.Unsafe` import needs `--accept-risks`, the manifest token, or
    // an interactive yes (a non-interactive build without consent fails closed
    // rather than blocking on a prompt); a disclosed `js-port:<axis>` must be
    // granted by THIS app's `[capabilities] accept`; a disclosed `native-ffi`
    // crossing by THIS app's `[capabilities] declared`.
    let consented = consent_to_capabilities(
        manifest_parsed.as_ref(),
        manifest.as_deref(),
        &entry_path,
        args.accept_risks,
    )?;

    if let Some(host) = bundle_host {
        bundle_delivery(host, Verb::DEV_BUILD.bundle_profile(), Some(entry.as_str()))?;
        return Ok(BuildSuccess {
            entry,
            out_dir: PathBuf::new(),
        });
    }

    // Precedence: CLI --target wasm|wasi > IPE_TARGET=wasm|wasi > [wasm].mode.
    let compile_target = resolve_compile_target(wasm_target, manifest_wasm.as_ref());

    // The delivery runtime and the compile target are derived independently; fail
    // closed unless they agree — the `(engine, triple)` validity matrix is the
    // single live gate. A `spa` delivery MUST compile to the browser wasm engine,
    // and the browser engine MUST carry a `spa` delivery; a co-located native
    // delivery MUST resolve to the native engine; the co-located WASI engine
    // admits ONLY the sealed `Direct`/`Script` floor (TEA/Server/Web refused
    // fail-closed, so THE SEAL holds). This keeps the wasm-keyed native-deny
    // backstops reachable for every sandboxed client, and is the structural
    // successor to the `spa` IFF wasm biconditional (it subsumes it and adds the
    // third — triple — axis).
    let (engine, triple) = compile_target.engine_triple();
    delivery
        .admit_triple(engine, triple)
        .map_err(|e| CliError::Usage(text::msg::command_refusal(&Verb::DEV_BUILD, &e)))?;

    // The dependency model (native OR wasm) needs no vendored tree — the runtime
    // is a path dependency. Only a dep-model-OFF build vendors the source subtree.
    let runtime_dep = runtime_dep_from_env();
    let runtime_dir = resolve_vendored_runtime_dir(args.runtime, !runtime_dep)?;

    // Fail closed before emitting: `ipe dev build` compiles the emitted project so a
    // reported success means the crate actually built. A missing toolchain is a
    // clear root-cause error now, not an opaque OS spawn error after the
    // (wasted) emit. The wasm branch delegates to `bundle_wasm`, which resolves
    // cargo itself, so only the native branch resolves here — the resolved path
    // is reused for its build.
    let native_cargo = if compile_target.is_wasm() {
        None
    } else {
        Some(toolchain::require_cargo(toolchain::ToolIntent::Build)?)
    };

    // Resolved only now, after every refusal above; nothing is created until the
    // emit writes its crate.
    let output = resolve_output_root(out.as_deref(), &entry_path, manifest_parsed.as_ref())?;
    let rust_area = output.area(&[OutputArea::Rust]);
    let out_dir = rust_area.path()?;

    let options = BuildOptions {
        static_plan,
        target: compile_target.ir_target(),
        wasm_public_env: Vec::new(),
        wasm_hydrate_mode: false,
        // A `dev build` is a development artifact — Debug.* is permitted.
        intent: Verb::DEV_BUILD.intent(),
        runtime_dep,
        // `ipe dev build` never tree-shakes the vendored tree — a dep-model build
        // carries no vendored source, and a vendored (`IPE_RUNTIME_VENDORED`)
        // build keeps the full tree so rustc, not the driver, drops the unreached
        // files. Only `ipe release eject` sets this.
        tree_shake_vendored: false,
        // Manifest projects overwrite this from `package.ipe` in
        // build_project_with_options; a single-file (no-manifest) build keeps
        // this value, defaulting to `ipe-app` unless `IPE_EMIT_PACKAGE_NAME`
        // names a unique per-build crate (the shared-target coverage harness).
        cargo_name: single_file_cargo_name_from_env(),
        debugger: args.debugger,
        // `ipe dev build` never emits appearance hot-swap scaffolding — that is a
        // `ipe dev watch`-only dev affordance. A release artifact stays clean.
        hot_appearance: false,
        // A webview-native `web desktop` delivery links the system webview and
        // selects the webview executor; every other delivery does not.
        webview_host: delivery.is_webview_native(),
        // Filled from the manifest `delivery.desktop` in
        // build_project_with_options once the manifest is parsed.
        webview_window: None,
    };

    // No manifest found: compile entry + all sibling .ipe files in the same
    // directory. Byte-identical to `build` when the directory holds only the
    // entry file (regression-covered by the golden suite).
    let crate_dir = emit_into(
        &entry_path,
        manifest.as_deref(),
        &EmitTarget::Area(rust_area),
        &runtime_dir,
        options,
    )?;

    let native_artifact = match compile_target {
        CompileTarget::WasmClient => {
            bundle_wasm(&crate_dir)?;
            None
        }
        CompileTarget::WasmWasi => {
            bundle_wasi(&crate_dir)?;
            None
        }
        CompileTarget::Native => Some(compile_and_finalize_native_build(
            &output,
            &crate_dir,
            NativeBuild {
                cargo: native_cargo,
                static_plan,
                runtime_dep,
                quiet: args.quiet,
            },
            manifest.as_deref(),
            &consented,
        )?),
    };

    if show_progress {
        // A native build reports the runnable binary's project-local path (the
        // `out/bin` copy); a wasm bundle reports the emitted output directory.
        let destination = native_artifact.as_ref().map_or_else(
            || out_dir.display().to_string(),
            |p| p.display().to_string(),
        );
        crate::screen::chatter(
            crate::screen::Stream::Stderr,
            crate::screen::Tone::Success,
            &format!(
                "{} built → {}",
                style::outcome_glyph(style::Outcome::Success),
                destination
            ),
        );
    }
    Ok(BuildSuccess { entry, out_dir })
}

/// Emit the program at `entry_path` into `target`, returning the claimed crate directory.
///
/// The manifest project is emitted when one was found, else the entry with
/// its sibling files.
///
/// # Errors
/// As [`build_project_into`] and [`build_loose_file_into`].
fn emit_into(
    entry_path: &Path,
    manifest: Option<&Path>,
    target: &EmitTarget,
    runtime_dir: &Path,
    options: BuildOptions,
) -> Result<OwnedDir, CliError> {
    let out = OutTarget::Proven(target);
    match manifest {
        Some(m) => build_project_into(m, out, runtime_dir, &options),
        None => build_loose_file_into(entry_path, out, runtime_dir, options),
    }
}

/// How [`compile_and_finalize_native_build`] runs `cargo build`.
pub struct NativeBuild {
    /// The resolved `cargo`; `None` re-resolves it.
    pub cargo: Option<toolchain::CargoBin>,
    /// The static-link target, when the build is static.
    pub static_plan: Option<ipe_backend_rust::static_build::StaticPlan>,
    /// Whether the emitted crate depends on the runtime.
    pub runtime_dep: bool,
    /// Pass `-q` to cargo instead of its terminal UI.
    pub quiet: bool,
}

/// Compile the just-emitted native crate and write its runtime-enforcement
/// artifacts. Split out of [`run_build`] so each stays a readable unit.
///
/// The compile is the SEAL: a reported build success MUST mean the crate
/// actually built, so a non-zero cargo exit surfaces as a typed
/// [`CliError::EmittedBuildFailed`] rather than a silent exit-0 that would mask a
/// miscompile. It also produces the `target/debug/ipe-app` binary that
/// `ipe release run` later runs. CWD = the emitted crate dir so the generated
/// `.cargo/config.toml` is discovered; a static plan additionally selects the
/// target triple explicitly.
///
/// A native-bearing artifact then carries its own runtime enforcement — an
/// `ipe.profile` mirror plus the authoritative capability floor embedded in the
/// binary — so the jail travels with a copied-off-host artifact (ADR 0004). A
/// pure Ipê artifact is structurally bounded and needs neither profile nor floor.
///
/// Returns the path the built binary was copied to under the project
/// (`<project>/out/bin/<name>`), so the artifact is findable regardless of a
/// shared `CARGO_TARGET_DIR`.
///
/// # Errors
/// - [`CliError::EmittedBuildFailed`] when the emitted crate fails to compile.
/// - [`CliError::Io`] when the artifact cannot be copied into the project.
/// - The toolchain, manifest-parse, and profile-construction errors of the
///   steps it composes.
pub fn compile_and_finalize_native_build(
    output: &OutputRoot,
    crate_dir: &OwnedDir,
    build: NativeBuild,
    manifest: Option<&Path>,
    consented: &ConsentedCapabilities,
) -> Result<PathBuf, CliError> {
    let NativeBuild {
        cargo: native_cargo,
        static_plan,
        runtime_dep,
        quiet,
    } = build;
    // `native_cargo` is `Some` on every native path (the caller's wasm branch
    // returns before here); the fallback re-resolves rather than unwrapping so
    // the toolchain error stays typed even if that invariant ever changes.
    let cargo_bin = match native_cargo {
        Some(bin) => bin,
        None => toolchain::require_cargo(toolchain::ToolIntent::Build)?,
    };
    let out_dir = crate_dir.path();
    let runtime = if runtime_dep {
        runtime_context_for_message()
    } else {
        None
    };
    CargoBuild {
        cargo: &cargo_bin,
        krate: CargoCrate::Emitted(crate_dir),
        profile: CargoProfile::Dev,
        target: static_plan
            .as_ref()
            .map_or(CargoTarget::Host, |plan| CargoTarget::Static(plan.triple)),
        output: CargoOutput::Human(Verbosity::of_quiet(quiet)),
        what: "the emitted program",
        runtime,
    }
    .run()?;

    let manifest_parsed = match manifest {
        Some(m) => Some(project::parse_manifest(m)?),
        None => None,
    };

    // Copy the just-built binary into a stable per-project location. With the
    // Ipê-recommended shared `CARGO_TARGET_DIR`, the artifact lands in the
    // shared cache (`<shared-target>/<profile>/<name>`), not under the project,
    // where a user cannot readily find it. The copy runs immediately after this
    // invocation's `cargo build` returns, resolving the artifact path from
    // `cargo metadata`; a binary missing at that path fails closed (no stale
    // copy). Copy (never hardlink): the shared target is often a different mount.
    let artifact = copy_native_artifact(
        &cargo_bin,
        out_dir,
        &output.claim_area(&[OutputArea::Bin])?,
        static_plan.as_ref(),
        manifest_parsed.as_ref(),
    )?;
    let driver = manifest_parsed
        .as_ref()
        .map_or(ipe_backend_rust::DbDriver::Sqlite, |m| m.driver);
    let resolved = consented.resolved();
    if run_sandbox::is_native_bearing(&resolved.union()) {
        let profile = run_sandbox::build_profile(resolved, driver)?;
        run_sandbox::write_build_artifacts(crate_dir, &profile)?;
    }
    Ok(artifact)
}

/// Copy the freshly built native debug binary out of the (possibly shared)
/// cargo target directory into `<project>/out/bin/<name>`, a stable path under
/// the project the user can find and run regardless of `CARGO_TARGET_DIR`.
///
/// The source path is resolved through `cargo metadata`'s authoritative
/// `target_directory` (never a guess at where cargo put it) plus the `debug`
/// profile and — under a static plan — the explicit target triple, exactly as
/// the `release` path resolves its own artifact. Returns the destination path so
/// the caller can report it. Copy (not hardlink): the shared target is often on
/// a different mount.
fn copy_native_artifact(
    cargo_bin: &toolchain::CargoBin,
    out_dir: &Path,
    bin_dir: &OwnedDir,
    static_plan: Option<&ipe_backend_rust::static_build::StaticPlan>,
    manifest: Option<&project::ProjectManifest>,
) -> Result<PathBuf, CliError> {
    let target_dir = crate::cargo_step::target_directory(cargo_bin, out_dir)?;
    // LOCATE the built binary by its emitted crate identity (the hashed
    // `<friendly>_<hash>` cargo actually produces); DELIVER it under the plain
    // friendly project name, so the user-facing artifact stays `out/bin/<name>`
    // regardless of the internal per-project identity hash.
    let bin_name = emitted_bin_filename(out_dir);
    let friendly = friendly_artifact_filename(manifest);
    let mut src = target_dir;
    if let Some(plan) = static_plan {
        src.push(plan.triple.as_str());
    }
    src.push("debug");
    src.push(&bin_name);
    if !src.is_file() {
        return Err(CliError::Usage(text::msg::build_binary_missing(
            &src.display(),
        )));
    }
    let dest = bin_dir.path_to(&friendly)?;
    dest.copy_from(&src)?;
    let dest = dest.path();
    #[cfg(unix)]
    set_executable(&dest)?;
    Ok(dest)
}

/// `ipe release eject [<path>] --out <dir>` — emit a self-contained Rust Cargo project a
/// user can `cargo build` with no `ipe` toolchain installed.
///
/// The escape hatch from the dependency-crate model: where `ipe dev build` emits a
/// project that names the runtime as a path dependency (resolved by the
/// toolchain), eject VENDORS the runtime source into the output — and tree-shakes
/// it to only the modules the program reaches. The emitted `ipe_runtime/mod.rs`
/// already declares `pub mod X;` for exactly the reached top-level modules, so
/// [`build_emit_manifest`] copies only those source files. The result is a
/// small, auditable, offline-buildable crate: pure, reviewable Rust with no
/// external runtime path and no registry fetch.
///
/// Eject is native-only and FFI-free by contract:
///   - A foreign-crate FFI binding would need external crates pulled from a
///     registry, which the source-only, self-contained contract forbids — so an
///     FFI-bearing program is a hard [`CliError::EjectUnsupported`] refusal
///     rather than a tree that would not resolve offline.
///   - `--target wasm` is a distinct compilation axis with its own bundling
///     step; eject targets a plain-`cargo build` native crate.
///
/// # Errors
/// [`CliError::EjectUnsupported`] for an FFI-bearing program; the same
/// pipeline / filesystem / runtime-resolution errors as [`build_project`].
pub fn run_eject(rest: &[String]) -> Result<(), CliError> {
    let args = cli_args::parse_eject(rest)?;
    let entry = match args.entry {
        Some(e) => e,
        None => default_entry()?,
    };
    let entry_path = PathBuf::from(&entry);

    // Fail closed on an FFI-bearing project BEFORE any emit: eject vendors only
    // the embedded runtime SOURCE, so a program binding a foreign Rust crate
    // cannot be made self-contained (its external crates would be a registry
    // fetch at the ejected project's `cargo build`). Detecting it from the
    // installed FFI catalog is the same trusted signal the build pipeline reads;
    // a non-empty catalog means at least one `Rust.` binding is in scope.
    if !ffi::load_catalog_for(&entry_path)?.is_empty() {
        return Err(CliError::EjectUnsupported {
            reason: TerminalSafe::sanitize(
                "this program binds a foreign Rust crate (FFI). Eject vendors only the \
                 embedded runtime source, so it cannot produce a self-contained project for \
                 a program that pulls external crates — build it with `ipe release build` instead",
            ),
        });
    }

    let manifest = discover_manifest(&entry_path)?;

    // Eject targets a plain native `cargo build`; a wasm target has its own
    // bundling step and a distinct closed vendoring template. Refuse a wasm
    // request from ANY tier — the `IPE_TARGET=wasm|wasi` env OR a project's
    // `[wasm].mode` — rather than silently emit a native tree for a wasm app.
    // (`parse_eject` has no `--target` flag, so the CLI tier cannot select wasm
    // here; `WasmKind::None` for the CLI axis is exact.)
    let manifest_parsed = manifest
        .as_deref()
        .map(project::parse_manifest)
        .transpose()?;
    let manifest_wasm: Option<&project::WasmConfig> = manifest_parsed.as_ref().map(|m| &m.wasm);
    if resolve_compile_target(cli_args::WasmKind::None, manifest_wasm).is_wasm() {
        return Err(CliError::EjectUnsupported {
            reason: TerminalSafe::sanitize(
                "eject produces a native Cargo project; a wasm target has a separate \
                 bundling step — use `ipe release build --target wasm` (browser) or \
                 `ipe dev build --target wasi` (wasm32-wasip1)",
            ),
        });
    }

    let runtime_dir = resolve_vendored_runtime_dir(args.runtime, true)?;

    // The ejected project is handed to the user, so it goes to a fresh
    // directory clear of the sources and of every tree ipe owns — never over
    // anything already there. It is claimed before the build, so the emit
    // adopts it and no ancestor is ever marked ipe-owned.
    let paths = match manifest_parsed.as_ref() {
        Some(m) => ProjectPaths::from_manifest(m),
        None => ProjectPaths::discover(&entry_path)?,
    };
    let target = OutputRoot::fresh(&args.out, &paths)?.claim()?;

    let options = eject_options();

    let show_progress = {
        use std::io::IsTerminal as _;
        std::io::stderr().is_terminal()
    };
    if show_progress {
        crate::screen::chatter(
            crate::screen::Stream::Stderr,
            crate::screen::Tone::Text,
            &format!(
                "{} ejecting {entry}",
                style::outcome_glyph(style::Outcome::Step)
            ),
        );
    }

    emit_into(
        &entry_path,
        manifest.as_deref(),
        &EmitTarget::Claimed(target.owned().clone()),
        &runtime_dir,
        options,
    )
    .map(drop)?;
    // From here on the tree is the user's: ipe drops its ownership marker so no
    // later ipe command treats the ejected project as disposable output.
    let out_dir = target.release_to_user()?;

    if show_progress {
        crate::screen::chatter(
            crate::screen::Stream::Stderr,
            crate::screen::Tone::Success,
            &format!(
                "{} ejected → {} (self-contained; `cd {} && cargo build`)",
                style::outcome_glyph(style::Outcome::Success),
                out_dir.display(),
                out_dir.display()
            ),
        );
    }
    Ok(())
}

/// The emit options `ipe release eject` builds with.
///
/// Eject hands over a shipped project, so it is a release build. It forces the
/// vendored, tree-shaken shape: a self-contained project names no runtime path
/// dependency (`runtime_dep = false`) and carries only the reached runtime
/// source (`tree_shake_vendored = true`). Static/wasm options stay at their
/// defaults — eject is the plain native standalone shape.
pub(super) fn eject_options() -> BuildOptions {
    BuildOptions {
        intent: Verb::RELEASE_EJECT.intent(),
        runtime_dep: false,
        tree_shake_vendored: true,
        ..BuildOptions::default()
    }
}

/// `ipe release build [<path>] [--out <dir>] [--target wasm|<triple>] [--embed]` —
/// build the production artifact for every app kind.
///
/// The artifact kind is determined by the app and the `--target` flag:
///
/// - **Native-bearing** (app crosses into `Rust.` / FFI): the jailed bundle —
///   `ipe-wrapper` (jailed launcher), `ipe-app` (statically-linked app binary),
///   and `ipe.profile` (serialised capability profile). The `--embed` flag
///   (the default) fuses all three into a single self-jailing binary.
/// - **Pure native** (no native/FFI content): a plain optimised binary under
///   the release cargo profile. No jail wrapper is needed; the binary is
///   structurally bounded to its inferred capabilities.
/// - **Browser/wasm** (`--target wasm`): the production browser bundle
///   (optimised `.wasm` + generated glue + assets) exactly as `ipe dev build
///   --target wasm` produces, but with the production flag set so the
///   `Ipe.Debug` gate (IPE-L0140) fires.
///
/// Every path states `BuildIntent::Release` so the `Ipe.Debug.*` gate fires
/// for all app kinds. `ipe dev build` and `ipe dev run` state `Development`
/// (`Debug.*` is permitted there).
///
/// ## Honest limit (native-bearing)
///
/// The inner `ipe-app` is a native ELF/Mach-O/PE binary — an operator can run
/// it directly without the wrapper, bypassing the jail. The wrapper makes the
/// sanctioned, jailed, profile-verified path the easy toolchain-free one; it
/// does not make unjailed execution impossible for a sufficiently privileged
/// local operator. This limit is documented, not a defect.
///
/// ## Security boundary
///
/// The jail enforcement is the SAME code path as `ipe release run` — both call into
/// `ipe_sandbox::run_jail::{scan_capfloor, satisfies_capfloor, exec_in_run_jail}`.
/// There is no second jail implementation; any future change to the jail
/// mechanism automatically applies to both paths.
///
/// # Errors
///
/// Build, toolchain, manifest-parse, filesystem, and capability-resolution
/// errors.
#[allow(clippy::too_many_lines)]
pub fn run_release(rest: &[String]) -> Result<(), CliError> {
    // Resolve the output format in a first, infallible pass so a refusal
    // renders through the machine surface the caller asked for.
    let format = cli_args::peek_output_format(rest);
    run_release_body(rest).map_err(|e| {
        if format == cli_args::OutputFormat::Human {
            e
        } else {
            emit_machine_error(format, Verb::RELEASE_BUILD.name(), &e)
        }
    })
}

/// The artifact a `release build` produces.
///
/// Built only by [`release_artifact`], whose exhaustive match leaves no target
/// that produces nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseArtifact {
    /// The production browser bundle (`wasm32-unknown-unknown`).
    Browser,
    /// A statically linked native binary for the triple.
    Native(ipe_backend_rust::static_build::StaticTriple),
}

impl ReleaseArtifact {
    /// The compile target this artifact emits for.
    #[must_use]
    pub const fn compile_target(self) -> CompileTarget {
        match self {
            Self::Browser => CompileTarget::WasmClient,
            Self::Native(_) => CompileTarget::Native,
        }
    }
}

/// The artifact a `release build` with `target` produces, given the target a
/// native `--target` resolves to through `IPE_TARGET` and `[wasm].mode`.
///
/// # Errors
///
/// [`CliError::Usage`] when the resolved target is the WASI module, which has
/// no release form.
pub const fn release_artifact(
    target: cli_args::ReleaseTarget,
    resolved: CompileTarget,
) -> Result<ReleaseArtifact, CliError> {
    match (target, resolved) {
        (cli_args::ReleaseTarget::Wasm, _)
        | (cli_args::ReleaseTarget::Native(_), CompileTarget::WasmClient) => {
            Ok(ReleaseArtifact::Browser)
        }
        (cli_args::ReleaseTarget::Native(triple), CompileTarget::Native) => {
            Ok(ReleaseArtifact::Native(triple))
        }
        (cli_args::ReleaseTarget::Native(_), CompileTarget::WasmWasi) => {
            Err(CliError::Usage(text::msg::release_no_wasi()))
        }
    }
}

/// The body of [`run_release`], format-agnostic.
pub fn run_release_body(rest: &[String]) -> Result<(), CliError> {
    let args = cli_args::parse_release_build(rest)?;

    // `--emit-permissions <platform>`: a read-only inspection — print the
    // OS-permission derivation and stop, before any compile.
    if let Some(platform) = args.emit_permissions.as_deref() {
        let entry = match args.entry.as_deref() {
            Some(e) => e.to_owned(),
            None => default_entry()?,
        };
        return emit_permissions(platform, Some(entry.as_str()), Verb::RELEASE_BUILD.name());
    }

    release_pipeline(&args, ReleasePurpose::Build)?;
    Ok(())
}

/// What a release pipeline run is for: the artifact alone, or the artifact
/// and then running it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleasePurpose {
    /// `ipe release build`.
    Build,
    /// `ipe release run`: a target with no run form refuses before any build.
    Run,
}

impl ReleasePurpose {
    /// The verb the pipeline reports and compiles under.
    #[must_use]
    pub const fn verb(self) -> Verb {
        match self {
            Self::Build => Verb::RELEASE_BUILD,
            Self::Run => Verb::RELEASE_RUN,
        }
    }
}

/// The artifact a release pipeline produced, located by the pipeline itself.
#[derive(Debug)]
pub enum ReleaseOutput {
    /// A browser bundle or a distributable host bundle: nothing to execute.
    Distributable,
    /// A pure-native static binary and the profile it runs jailed under.
    PureNative {
        /// The delivered binary.
        binary: PathBuf,
        /// The jail profile its consented capabilities lower to.
        profile: ipe_sandbox::run_jail::SandboxProfile,
    },
    /// The single self-jailing wrapper binary (embed mode).
    Embedded(PathBuf),
    /// The directory holding `ipe-wrapper`, `ipe-app` and `ipe.profile`.
    Bundle(PathBuf),
}

/// Produce the release artifact `args` selects, and return where it landed.
///
/// # Errors
///
/// Build, toolchain, manifest-parse, filesystem, capability-resolution and
/// wrapper-source errors; [`CliError::NoRunForm`] when `purpose` is
/// [`ReleasePurpose::Run`] and the resolved target has no run form.
#[allow(clippy::too_many_lines)]
pub fn release_pipeline(
    args: &cli_args::ReleaseArgs,
    purpose: ReleasePurpose,
) -> Result<ReleaseOutput, CliError> {
    let verb = purpose.verb();
    let entry = match args.entry.clone() {
        Some(e) => e,
        None => default_entry()?,
    };
    let entry_path = PathBuf::from(&entry);

    // Discover the manifest (same logic as build/eject).
    let manifest = discover_manifest(&entry_path)?;

    let manifest_parsed = match manifest.as_deref() {
        Some(m) => Some(project::parse_manifest(m)?),
        None => None,
    };

    // The same trust-boundary consent gates `build` and `run` enforce, applied
    // BEFORE any emit, cargo build, OR bundle — hoisted above the bundle
    // early-return so EVERY release target (served artifact AND a
    // desktop/ios/android distributable bundle) is gated. A distributable is the
    // most consequential output, so it must never ship a disclosed `.Unsafe`
    // escape hatch, `js-port:<axis>` web crossing, or `native-ffi` crossing that
    // the app's manifest did not grant. Release is non-interactive by design: it
    // carries no `--accept-risks` and never prompts, so an ungranted disclosure
    // fails closed here, and the durable manifest `[capabilities]` grant is the
    // only way through (a CI release must not block on a TTY prompt).
    let consented = consent_to_capabilities(
        manifest_parsed.as_ref(),
        manifest.as_deref(),
        &entry_path,
        false,
    )?;

    // A `desktop`/`ios`/`android` host is a production distributable bundle:
    // route it through the delivery-grammar bundler (the `release` production
    // profile). The served/default host falls through to the ordinary release
    // artifact below. The delivery grammar is the one vocabulary for every bundle
    // target.
    let bundle_delivery_resolved =
        resolve_delivery(&entry_path, &args.delivery, false, verb.name())?;
    if let (ReleasePurpose::Run, Some(target)) = (
        purpose,
        cli_args::NoRunTarget::from_host(bundle_delivery_resolved.host()),
    ) {
        return Err(CliError::NoRunForm { target });
    }
    if let Some(host) = BundleHost::from_delivery_host(bundle_delivery_resolved.host())? {
        bundle_delivery(host, verb.bundle_profile(), Some(entry.as_str()))?;
        return Ok(ReleaseOutput::Distributable);
    }

    let manifest_wasm: Option<project::WasmConfig> =
        manifest_parsed.as_ref().map(|m| m.wasm.clone());

    // Route on the typed artifact: the browser bundle or a static native
    // binary. A native `--target` still yields to `IPE_TARGET` and the
    // manifest's `[wasm].mode`; a WASI resolution has no release form and
    // refuses.
    let artifact = release_artifact(
        args.target.clone(),
        resolve_compile_target(cli_args::WasmKind::None, manifest_wasm.as_ref()),
    )?;
    let compile_target = artifact.compile_target();

    // Fail closed unless the delivery runtime and the compile target agree — the
    // `(engine, triple)` validity matrix is the single live gate — so a sandboxed
    // client is never released as a native binary with the wasm-keyed native-deny
    // backstops skipped.
    let (engine, triple) = compile_target.engine_triple();
    bundle_delivery_resolved
        .admit_triple(engine, triple)
        .map_err(|e| CliError::Usage(text::msg::command_refusal(&verb, &e)))?;

    // Native path: the triple the parse validated; the browser bundle
    // returns from its own arm.
    let triple = match artifact {
        ReleaseArtifact::Native(triple) => triple,
        ReleaseArtifact::Browser if purpose == ReleasePurpose::Run => {
            // A manifest `[wasm].mode` or `IPE_TARGET` resolution the parse
            // could not see: refused before anything is emitted.
            return Err(CliError::NoRunForm {
                target: cli_args::NoRunTarget::Wasm,
            });
        }
        ReleaseArtifact::Browser => {
            // Browser/wasm production path.
            let output =
                resolve_output_root(args.out.as_deref(), &entry_path, manifest_parsed.as_ref())?;
            let rust_area = output.area(&[OutputArea::Release, OutputArea::Rust]);
            let out_dir = rust_area.path()?;
            let runtime_dep = runtime_dep_from_env();
            let runtime_dir = resolve_vendored_runtime_dir(args.runtime.clone(), !runtime_dep)?;

            let show_progress = {
                use std::io::IsTerminal as _;
                std::io::stderr().is_terminal()
            };
            if show_progress {
                crate::screen::chatter(
                    crate::screen::Stream::Stderr,
                    crate::screen::Tone::Text,
                    &format!(
                        "{} releasing {entry} (wasm)",
                        style::outcome_glyph(style::Outcome::Step)
                    ),
                );
            }

            // Emit the Rust wasm project as a release build so the Debug gate fires.
            let options = BuildOptions {
                static_plan: None,
                target: ipe_ir::Target::WasmClient,
                wasm_public_env: manifest_parsed
                    .as_ref()
                    .map(|m| m.wasm.public_env.clone())
                    .unwrap_or_default(),
                wasm_hydrate_mode: manifest_wasm
                    .as_ref()
                    .is_some_and(|w| w.mode.as_deref() == Some("hydrate")),
                intent: verb.intent(),
                runtime_dep,
                tree_shake_vendored: false,
                cargo_name: String::new(),
                // The debugger is never enabled on a release build.
                debugger: false,
                // A release build never carries appearance hot-swap scaffolding.
                hot_appearance: false,
                // Set from the resolved delivery; a webview-native `web desktop` is wired
                // where the classified shape is known (build_project_with_options).
                webview_host: false,
                webview_window: None,
            };
            let crate_dir = emit_into(
                &entry_path,
                manifest.as_deref(),
                &EmitTarget::Area(rust_area),
                &runtime_dir,
                options,
            )?;
            bundle_wasm(&crate_dir)?;
            if show_progress {
                crate::screen::chatter(
                    crate::screen::Stream::Stderr,
                    crate::screen::Tone::Success,
                    &format!(
                        "{} released → {}/www/",
                        style::outcome_glyph(style::Outcome::Success),
                        out_dir.display()
                    ),
                );
            }
            return Ok(ReleaseOutput::Distributable);
        }
    };

    // The consented capabilities discriminate between native-bearing (needs jail
    // wrapper) and pure-native (plain optimised binary).
    let driver = manifest_parsed
        .as_ref()
        .map_or(ipe_backend_rust::DbDriver::Sqlite, |m| m.driver);
    let resolved = consented.resolved();

    let runtime_dir = resolve_vendored_runtime_dir(args.runtime.clone(), false)?;

    let show_progress = {
        use std::io::IsTerminal as _;
        std::io::stderr().is_terminal()
    };

    if !run_sandbox::is_native_bearing(&resolved.union()) {
        // Pure-native path: emit and build a plain release binary.
        let output =
            resolve_output_root(args.out.as_deref(), &entry_path, manifest_parsed.as_ref())?;
        let rust_area = output.area(&[OutputArea::Release, OutputArea::Rust]);
        let out_dir = rust_area.path()?;

        if show_progress {
            crate::screen::chatter(
                crate::screen::Stream::Stderr,
                crate::screen::Tone::Text,
                &format!(
                    "{} releasing {entry}",
                    style::outcome_glyph(style::Outcome::Step)
                ),
            );
        }

        let cargo_bin = toolchain::require_cargo(toolchain::ToolIntent::Build)?;

        let app_static_plan = Some(ipe_backend_rust::static_build::StaticPlan {
            triple,
            c_profile: ipe_backend_rust::static_build::CProfile::WithLibc {
                allocator: ipe_backend_rust::static_build::StaticAllocator::Dlmalloc,
            },
        });

        let options = BuildOptions {
            static_plan: app_static_plan,
            target: ipe_ir::Target::Native,
            intent: verb.intent(),
            runtime_dep: runtime_dep_from_env(),
            tree_shake_vendored: false,
            ..BuildOptions::default()
        };
        let crate_dir = emit_into(
            &entry_path,
            manifest.as_deref(),
            &EmitTarget::Area(rust_area),
            &runtime_dir,
            options,
        )?;

        CargoBuild {
            cargo: &cargo_bin,
            krate: CargoCrate::Emitted(&crate_dir),
            profile: CargoProfile::Release,
            target: CargoTarget::Static(triple),
            output: CargoOutput::Human(Verbosity::Progress),
            what: "the release binary",
            runtime: None,
        }
        .run()?;

        let app_target_dir = crate::cargo_step::target_directory(&cargo_bin, &out_dir)?;
        // Cargo names the built binary after the emitted crate IDENTITY (the
        // path-uniquified `<friendly>_<hash>`), so the artifact is LOCATED by that
        // identity; it is delivered under the plain FRIENDLY name so the hash the
        // crate carries only to own a unique shared-target slot never leaks into a
        // distributed filename.
        let bin_name = emitted_bin_filename(&out_dir);
        let bin_path = app_target_dir
            .join(triple.as_str())
            .join("release")
            .join(&bin_name);
        if !bin_path.is_file() {
            return Err(CliError::Usage(text::msg::release_binary_missing(
                &bin_path.display(),
            )));
        }
        // Copy the binary from the cargo target dir into the release area so the
        // artifact lands at a predictable path regardless of CARGO_TARGET_DIR.
        let dest = output
            .claim_area(&[OutputArea::Release])?
            .path_to(friendly_artifact_filename(manifest_parsed.as_ref()))?;
        dest.copy_from(&bin_path)?;
        let dest = dest.path();
        #[cfg(unix)]
        set_executable(&dest)?;
        if show_progress {
            crate::screen::chatter(
                crate::screen::Stream::Stderr,
                crate::screen::Tone::Success,
                &format!(
                    "{} released → {}",
                    style::outcome_glyph(style::Outcome::Success),
                    dest.display()
                ),
            );
        }
        let profile = run_sandbox::build_profile(resolved, driver)?;
        return Ok(ReleaseOutput::PureNative {
            binary: dest,
            profile,
        });
    }

    // Native-bearing path: jailed bundle. The wrapper builds only from the
    // verified compiler workspace this binary was compiled from, never from a
    // tree the current directory leads to; verified before anything is built.
    let wrapper_source = crate::wrapper_source::WrapperSource::resolve()
        .map_err(|r| CliError::WrapperSourceRefused(Box::new(r)))?;
    let output = resolve_output_root(args.out.as_deref(), &entry_path, manifest_parsed.as_ref())?;

    if show_progress {
        crate::screen::chatter(
            crate::screen::Stream::Stderr,
            crate::screen::Tone::Text,
            &format!(
                "{} releasing {entry}",
                style::outcome_glyph(style::Outcome::Step)
            ),
        );
    }

    let cargo_bin = toolchain::require_cargo(toolchain::ToolIntent::Build)?;

    // Step 1: emit + build the app binary (static, musl, production).
    let app_area = output.area(&[OutputArea::Release, OutputArea::App]);
    let app_out = app_area.path()?;
    let app_static_plan = Some(ipe_backend_rust::static_build::StaticPlan {
        triple,
        c_profile: ipe_backend_rust::static_build::CProfile::WithLibc {
            allocator: ipe_backend_rust::static_build::StaticAllocator::Dlmalloc,
        },
    });
    let options = BuildOptions {
        static_plan: app_static_plan,
        target: ipe_ir::Target::Native,
        intent: verb.intent(),
        runtime_dep: runtime_dep_from_env(),
        tree_shake_vendored: false,
        ..BuildOptions::default()
    };
    let app_dir = emit_into(
        &entry_path,
        manifest.as_deref(),
        &EmitTarget::Area(app_area),
        &runtime_dir,
        options,
    )?;

    CargoBuild {
        cargo: &cargo_bin,
        krate: CargoCrate::Emitted(&app_dir),
        profile: CargoProfile::Release,
        target: CargoTarget::Static(triple),
        output: CargoOutput::Human(Verbosity::Progress),
        what: "the release app",
        runtime: None,
    }
    .run()?;

    // Write the capability enforcement artifacts (ipe.profile + embedded floor).
    let profile = run_sandbox::build_profile(resolved, driver)?;
    run_sandbox::write_build_artifacts(&app_dir, &profile)?;

    // Locate the compiled app binary. The target dir may be a global
    // `CARGO_TARGET_DIR` (set by the user or the agent lane), so we resolve
    // it via cargo metadata rather than assuming `app_out/target/`.
    let app_target_dir = crate::cargo_step::target_directory(&cargo_bin, &app_out)?;
    let release_bin_name = emitted_bin_filename(&app_out);
    let app_binary = app_target_dir
        .join(triple.as_str())
        .join("release")
        .join(&release_bin_name);
    if !app_binary.is_file() {
        return Err(CliError::Usage(text::msg::release_app_binary_missing(
            &app_binary.display(),
        )));
    }
    let profile_src = app_out.join(RELEASE_PROFILE);

    // Step 2: build the wrapper binary (static, musl).
    let wrapper_triple = triple;
    let wrapper_static_plan = ipe_backend_rust::static_build::StaticPlan {
        triple: wrapper_triple,
        c_profile: ipe_backend_rust::static_build::CProfile::WithLibc {
            allocator: ipe_backend_rust::static_build::StaticAllocator::Dlmalloc,
        },
    };

    let embed = matches!(args.mode, cli_args::ReleaseMode::Embed).then_some(EmbeddedApp {
        binary: &app_binary,
        profile: &profile_src,
    });
    CargoBuild {
        cargo: &cargo_bin,
        krate: CargoCrate::ReleaseWrapper {
            source: &wrapper_source,
            embed,
        },
        profile: CargoProfile::Release,
        target: CargoTarget::Static(wrapper_static_plan.triple),
        output: CargoOutput::Human(Verbosity::Progress),
        what: "the release wrapper",
        runtime: None,
    }
    .run()?;

    // Step 3: lay out the bundle.
    let bundle_dir = output.claim_area(&[OutputArea::Release, OutputArea::Bundle])?;

    // Locate the wrapper binary. As with the app binary, the target dir may be
    // a global CARGO_TARGET_DIR; resolve via cargo metadata.
    let wrapper_target_dir =
        crate::cargo_step::target_directory(&cargo_bin, wrapper_source.root())?;
    let wrapper_src = wrapper_target_dir
        .join(wrapper_static_plan.triple.as_str())
        .join("release")
        .join(RELEASE_WRAPPER);

    let artifact = match args.mode {
        cli_args::ReleaseMode::Embed => {
            // Single-file embed: copy only the wrapper (app + profile baked in).
            let dest = bundle_dir.path_to(RELEASE_WRAPPER)?;
            dest.copy_from(&wrapper_src)?;
            let dest = dest.path();
            #[cfg(unix)]
            set_executable(&dest)?;
            dest
        }
        cli_args::ReleaseMode::Bundle => {
            // Bundle: wrapper + app + profile as siblings.
            let wrapper_dest = bundle_dir.path_to(RELEASE_WRAPPER)?;
            let app_dest = bundle_dir.path_to(RELEASE_APP)?;
            bundle_dir
                .path_to(RELEASE_PROFILE)?
                .copy_from(&profile_src)?;
            wrapper_dest.copy_from(&wrapper_src)?;
            app_dest.copy_from(&app_binary)?;
            #[cfg(unix)]
            {
                set_executable(&wrapper_dest.path())?;
                set_executable(&app_dest.path())?;
            }
            bundle_dir.path().to_path_buf()
        }
    };

    if show_progress {
        // Post-build report: how the binary is linked, where it landed, and the
        // capability model it will enforce.
        let cap_names: Vec<&'static str> = resolved.union().iter().map(|c| c.as_str()).collect();
        screen::chatter_styled(
            screen::Stream::Stderr,
            &release_bundle_report(&artifact, &cap_names, args.mode),
        );
        match args.mode {
            cli_args::ReleaseMode::Embed => crate::screen::chatter(
                crate::screen::Stream::Stderr,
                crate::screen::Tone::Success,
                &format!(
                    "{} {}",
                    style::outcome_glyph(style::Outcome::Success),
                    text::release_embedded(&artifact.display())
                ),
            ),
            cli_args::ReleaseMode::Bundle => crate::screen::chatter(
                crate::screen::Stream::Stderr,
                crate::screen::Tone::Success,
                &format!(
                    "{} {}",
                    style::outcome_glyph(style::Outcome::Success),
                    text::release_bundled(&artifact.display())
                ),
            ),
        }
    }
    Ok(match args.mode {
        cli_args::ReleaseMode::Embed => ReleaseOutput::Embedded(artifact),
        cli_args::ReleaseMode::Bundle => ReleaseOutput::Bundle(artifact),
    })
}

/// The human-readable post-build report for a native-bearing release bundle:
/// link kind, artifact path, and the enforced capability model.
pub fn release_bundle_report(
    artifact: &Path,
    capabilities: &[&str],
    mode: cli_args::ReleaseMode,
) -> String {
    use std::fmt::Write as _;

    let kind = match mode {
        cli_args::ReleaseMode::Embed => "single self-jailing binary",
        cli_args::ReleaseMode::Bundle => "multi-file bundle (wrapper + app + profile)",
    };
    let mut body = String::new();
    let _ = writeln!(body, "link: static (musl)");
    let _ = writeln!(body, "shape: {kind}");
    let _ = writeln!(body, "artifact: {}", artifact.display());
    if capabilities.is_empty() {
        let _ = writeln!(body, "capabilities: none");
    } else {
        let _ = writeln!(body, "capabilities: {}", capabilities.join(", "));
    }
    style::frame(&style::gutter(&body))
}

/// Set the executable bit on a file (Unix only; no-op on other platforms).
///
/// # Errors
///
/// [`CliError::Io`] when the permission cannot be set.
#[cfg(unix)]
pub fn set_executable(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt as _;
    let meta = std::fs::metadata(path).map_err(|e| CliError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut perms = meta.permissions();
    let mode = perms.mode() | 0o111;
    perms.set_mode(mode);
    std::fs::set_permissions(path, perms).map_err(|e| CliError::Io {
        path: path.to_path_buf(),
        source: e,
    })
}

/// Bytes one [`read_progress_chunk`] call reads before it ends the chunk
/// without a terminator.
pub const RELAY_CHUNK_CAP: usize = 64 * 1024;

/// Read the next chunk of `cargo`'s stderr into `out`, stopping at either a
/// newline (a completed message line) or a carriage return (the boundary of
/// cargo's in-place progress bar, which carries no newline). Returns the number
/// of bytes read; `0` marks end of stream. Reading to *either* terminator keeps
/// the live progress bar flowing rather than buffering until the next `\n`.
///
/// Bytes are decoded lossily so a non-UTF-8 byte from a compiler message never
/// aborts the build's progress relay.
///
/// A chunk is at most [`RELAY_CHUNK_CAP`] bytes: a longer run with neither
/// terminator ends at the first ASCII byte past it (a character boundary), and
/// at twice the cap whatever the byte.
///
/// # Errors
/// Propagates the underlying read error from the `cargo` stderr pipe.
pub fn read_progress_chunk<R: std::io::Read>(
    reader: &mut R,
    out: &mut String,
) -> std::io::Result<usize> {
    let mut bytes: Vec<u8> = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let n = reader.read(&mut byte)?;
        if n == 0 {
            break;
        }
        let [byte] = byte;
        bytes.push(byte);
        let full = bytes.len() >= RELAY_CHUNK_CAP
            && (byte.is_ascii() || bytes.len() >= RELAY_CHUNK_CAP.saturating_mul(2));
        if byte == b'\n' || byte == b'\r' || full {
            break;
        }
    }
    let total = bytes.len();
    out.push_str(&String::from_utf8_lossy(&bytes));
    Ok(total)
}

/// Apply three environment variables to `cmd` so `cargo` emits ANSI colour and
/// its `Building [===]` progress bar even through a pipe — but only when our own
/// stderr is a real terminal (`NO_COLOR` unset). Without the explicit width,
/// `cargo` draws no bar at all (it reads the bar width from its piped stderr,
/// which reports no size).
#[cfg(unix)]
pub fn force_cargo_terminal_ui(cmd: &mut std::process::Command) {
    let stderr = std::io::stderr();
    if !crate::style::use_color(&stderr) {
        return;
    }
    cmd.env("CARGO_TERM_COLOR", "always");
    cmd.env("CARGO_TERM_PROGRESS_WHEN", "always");
    let cols = terminal_width(&stderr).unwrap_or(80);
    cmd.env("CARGO_TERM_PROGRESS_WIDTH", cols.to_string());
}

/// No-op shim for non-Unix targets where `rustix::termios` is unavailable.
#[cfg(not(unix))]
pub fn force_cargo_terminal_ui(_cmd: &mut std::process::Command) {}

/// The column width of `stream`'s terminal, or `None` when it is not a terminal
/// or the size cannot be read. Uses `TIOCGWINSZ` via rustix — no libc binding.
#[cfg(unix)]
pub fn terminal_width(stream: &impl std::os::fd::AsFd) -> Option<u16> {
    let ws = rustix::termios::tcgetwinsize(stream).ok()?;
    (ws.ws_col > 0).then_some(ws.ws_col)
}

/// The runtime crate the emit will link against, as a [`RuntimeContext`] for a
/// build-failure message. `None` when no dependency-model runtime is resolved
/// (a wasm or vendored build), in which case a feature-gap message simply omits
/// the crate reference. Resolution failure is swallowed to `None` — this is only
/// for enriching an error message, never a gate.
pub fn runtime_context_for_message() -> Option<RuntimeContext> {
    runtime_embed::resolve().ok().map(|r| RuntimeContext {
        root: TerminalSafe::sanitize(&r.root().display().to_string()),
        version: TerminalSafe::sanitize(r.version()),
    })
}

/// The on-disk size of a just-produced artifact, or a typed [`CliError::Io`]
/// naming the path when it cannot be stat'd. A size probe reads the real file:
/// an absent or unreadable artifact is a bug to SURFACE, never a silent `0`
/// (`metadata().map_or(0, …)` would paper over a missing module as a plausible
/// "0 KB", hiding the fault).
///
/// # Errors
/// [`CliError::Io`] when the artifact at `path` cannot be stat'd (missing or
/// unreadable) — the artifact should exist by the time this is called, so a
/// failure is a real defect the caller must not swallow.
pub fn artifact_size_bytes(path: &Path) -> Result<u64, CliError> {
    fs::metadata(path)
        .map(|m| m.len())
        .map_err(|e| io_err(path, e))
}

/// Render a byte count as a human size that is ACCURATE for any nonzero file:
/// below 1 `KiB` it reports the exact byte count (so a small-but-real module
/// never truncates to a misleading `0 KB`), at or above 1 `KiB` it reports
/// `KiB` to one decimal (integer `bytes / 1024` alone would drop the fraction
/// and round a 1.9 `KiB` module down to `1 KiB`).
pub fn format_artifact_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} bytes")
    } else {
        // One decimal of KiB, computed in integer tenths so no float rounding
        // can nudge the reported value; `bytes >= 1024` here, so the whole part
        // is at least 1 and never reads as `0`.
        let tenths = bytes * 10 / 1024;
        format!("{}.{} KiB", tenths / 10, tenths % 10)
    }
}

/// The `wasm-bindgen-cli` version that matches the runtime's pinned `wasm-bindgen` crate.
///
/// `src/runtime/rust/Cargo.toml`'s `wasm-bindgen` dependency line is the
/// canonical spelling of this version; `ipe_backend_rust::project`'s
/// `wasm_bindgen_version_matches_the_runtime_pin` test fails the build the
/// instant this constant drifts from it.
const WASM_BINDGEN_VERSION: &str = "0.2.126";

/// Run the three post-emit bundle steps for `--target wasm`:
/// 1. `cargo build --target wasm32-unknown-unknown --release` (THE SEAL cross-target)
/// 2. `wasm-bindgen` CLI — emits the JS glue + `www/pkg/ipe_app_bg.wasm`
/// 3. `wasm-opt -Oz` — optional; silently skipped when not on PATH
///
/// Writes the final `www/pkg/` tree into `<crate_dir>/www/pkg/`. On success
/// the directory at `<crate_dir>/www/` is a self-contained static SPA ready to
/// serve.
///
/// # Errors
/// [`CliError::EmittedBuildFailed`] when the wasm `cargo build` fails;
/// [`CliError::Usage`] when `wasm-bindgen` fails;
/// [`CliError::OutputRefused`] when `crate_dir` was replaced since its claim.
pub fn bundle_wasm(crate_dir: &OwnedDir) -> Result<(), CliError> {
    let out_dir = crate_dir.path();
    // Fail closed before the cross-compile: a missing toolchain becomes a clear
    // root-cause message rather than an opaque OS spawn error.
    let cargo_bin = toolchain::require_cargo(toolchain::ToolIntent::BundleWasm)?;

    // Step 1: compile to .wasm
    // The wasm build uses the SAME dependency-model runtime crate the native path
    // does (selected via the `wasm-client` floor). Attach the resolved runtime
    // context so a `cargo build` failure that names a missing runtime feature can
    // point at the exact crate; resolution failure degrades to `None` (message
    // enrichment only, never a gate — the missing-path-dependency error cargo
    // itself raises is already fail-closed).
    CargoBuild {
        cargo: &cargo_bin,
        krate: CargoCrate::Emitted(crate_dir),
        profile: CargoProfile::Release,
        target: CargoTarget::WasmBrowser,
        output: CargoOutput::Human(Verbosity::Progress),
        what: "the emitted wasm program",
        runtime: runtime_context_for_message(),
    }
    .run()?;

    // Step 2: wasm-bindgen — locate the .wasm the cargo build just produced
    // (`CARGO_TARGET_DIR` may relocate it; probe the env var first, then the
    // per-project fallback the emitted manifest's `[workspace]` detachment
    // would use).
    let wasm_path = {
        let via_env = ipe_env::var_os("CARGO_TARGET_DIR").map(|d| {
            std::path::PathBuf::from(d)
                .join("wasm32-unknown-unknown")
                .join("release")
                .join("ipe_app.wasm")
        });
        let via_crate = out_dir
            .join("target")
            .join("wasm32-unknown-unknown")
            .join("release")
            .join("ipe_app.wasm");
        via_env.filter(|p| p.is_file()).unwrap_or(via_crate)
    };

    bundle_wasm_pkg(
        crate_dir,
        &wasm_path,
        &WasmTools {
            bindgen: Path::new("wasm-bindgen"),
            opt: Path::new("wasm-opt"),
        },
    )
}

/// The post-link wasm tools `bundle_wasm` runs, by program path.
struct WasmTools<'a> {
    /// The `wasm-bindgen` CLI.
    bindgen: &'a Path,
    /// The optional `wasm-opt` size pass.
    opt: &'a Path,
}

/// Bundle the linked `wasm_path` into the owned crate's `www/pkg/` with `tools`.
///
/// # Errors
/// [`CliError::Usage`] when `wasm-bindgen` fails; [`CliError::OutputRefused`]
/// when `crate_dir` was replaced before or while either tool ran;
/// [`CliError::Io`] on a filesystem or spawn failure.
fn bundle_wasm_pkg(
    crate_dir: &OwnedDir,
    wasm_path: &Path,
    tools: &WasmTools<'_>,
) -> Result<(), CliError> {
    let out_dir = crate_dir.path();
    // `wasm-bindgen` and `wasm-opt` write into `www/pkg/` by path, so it is
    // rebuilt empty under the owned crate: a symlink at any level is refused and
    // nothing planted inside it can redirect their writes. Each tool's writes
    // are proven to have landed in the owned crate once it exits.
    let pkg_rel = Path::new("www").join("pkg");
    let pkg = crate_dir.path_to(&pkg_rel)?;
    pkg.remove()?;
    pkg.ensure_dir()?;
    let pkg_dir = pkg.path();
    let prove_pkg = || -> Result<(), CliError> {
        crate_dir.verify()?;
        crate_dir.path_to(&pkg_rel).map(drop)
    };

    let wb_status = std::process::Command::new(tools.bindgen)
        .args([
            wasm_path.to_string_lossy().as_ref(),
            "--target",
            "web",
            "--no-typescript",
            "--out-dir",
            pkg_dir.to_string_lossy().as_ref(),
        ])
        .status()
        .map_err(|e| CliError::Io {
            path: wasm_path.to_path_buf(),
            source: e,
        })?;
    if !wb_status.success() {
        let code = wb_status.code().unwrap_or(1);
        return Err(CliError::Usage(text::msg::wasm_bindgen_failed(
            &code,
            &WASM_BINDGEN_VERSION,
        )));
    }
    prove_pkg()?;

    // Step 3: wasm-opt -Oz — optional size pass; silently skip when absent
    // (`Command::new` returns `Err` when the tool is missing).
    let bg_wasm = pkg_dir.join("ipe_app_bg.wasm");
    if bg_wasm.is_file()
        && let Ok(status) = std::process::Command::new(tools.opt)
            .args([
                bg_wasm.to_string_lossy().as_ref(),
                "-Oz",
                "-o",
                bg_wasm.to_string_lossy().as_ref(),
            ])
            .status()
        && !status.success()
    {
        // wasm-opt found but failed — non-fatal; the unoptimised bundle
        // is still correct. Log and continue.
        crate::screen::chatter(
            crate::screen::Stream::Stderr,
            crate::screen::Tone::Text,
            &format!(
                "note: wasm-opt exited {}; bundle is unoptimised but functional",
                status.code().unwrap_or(1)
            ),
        );
    }

    prove_pkg()?;
    let bundle_size = format_artifact_size(artifact_size_bytes(&bg_wasm)?);
    let www = out_dir.join("www");
    crate::screen::chatter(
        crate::screen::Stream::Stderr,
        crate::screen::Tone::Text,
        &format!(
            "wasm bundle ready at {www}/\n\
             bundle size: {bundle_size} ({bg})\n\
             serve with: python3 -m http.server -d {www} 8080",
            www = www.display(),
            bg = bg_wasm.display(),
        ),
    );
    Ok(())
}

/// Cross-compile the emitted co-located WASI crate for `wasm32-wasip1`.
///
/// Unlike [`bundle_wasm`] (the browser client), a WASI module needs no
/// wasm-bindgen JS glue and no `www/pkg` SPA tree: the emitted crate IS the
/// module. The single post-emit step is the `wasm32-wasip1` cross-compile,
/// which is also THE SEAL — a reported success means the `ipe`-accepted program
/// actually `cargo build`s for the target. The emitter ships the crate's own
/// `.cargo/config.toml` (the wasip1 `rust-lld` linker override), so this build
/// clears any ambient `RUSTFLAGS`/`CARGO_ENCODED_RUSTFLAGS` a dev host or CI
/// runner exports (a global `RUSTFLAGS` outranks a `[target.<triple>]` config,
/// which would mask the emitted linker override) — the module an end user gets
/// is governed by exactly the config the emitter ships.
///
/// # Errors
/// [`CliError::EmittedBuildFailed`] when the wasip1 `cargo build` fails;
/// [`CliError::OutputRefused`] when `crate_dir` was replaced since its claim.
pub fn bundle_wasi(crate_dir: &OwnedDir) -> Result<PathBuf, CliError> {
    let out_dir = crate_dir.path();
    // Fail closed before the cross-compile: a missing toolchain becomes a clear
    // root-cause message rather than an opaque OS spawn error.
    let cargo_bin = toolchain::require_cargo(toolchain::ToolIntent::BundleWasm)?;

    // One JSON message per line on stdout, so the exact artifact path cargo
    // writes is read from the build itself, never reconstructed from a
    // target-dir guess that a toggled `CARGO_TARGET_DIR` or a relocated
    // `cargo metadata` can invalidate.
    let messages = CargoBuild {
        cargo: &cargo_bin,
        krate: CargoCrate::Emitted(crate_dir),
        profile: CargoProfile::Release,
        target: CargoTarget::Wasip1,
        output: CargoOutput::JsonStream(Verbosity::Progress),
        what: "the emitted wasm32-wasip1 module",
        runtime: runtime_context_for_message(),
    }
    .run()?;

    // The authoritative module path: the `.wasm` bin artifact cargo reported it
    // wrote. Same value the executor loads — build-output and load-path are one
    // by construction, immune to any target-dir divergence.
    let module = wasi_artifact_path(&messages, out_dir)?;
    let module_size = format_artifact_size(artifact_size_bytes(&module)?);
    crate::screen::chatter(
        crate::screen::Stream::Stderr,
        crate::screen::Tone::Text,
        &format!(
            "wasm32-wasip1 module ready at {module}\n\
             module size: {module_size}\n\
             run with: wasmtime {module}",
            module = module.display(),
        ),
    );
    Ok(module)
}

/// Extract the emitted `wasm32-wasip1` module path from cargo's
/// `--message-format=json` stream. Each stdout line is a JSON object; a
/// `compiler-artifact` message for a `bin` target carries the produced files in
/// `filenames` (and `executable`). The module is the `.wasm` under
/// `wasm32-wasip1/release` — parsed from the build, never reconstructed.
///
/// # Errors
/// [`CliError::Usage`] when no such artifact appears in the stream (a
/// cargo/JSON-schema mismatch surfaces here as a precise root-cause message
/// rather than a downstream "could not load the module" from a guessed path).
fn wasi_artifact_path(messages: &str, out_dir: &Path) -> Result<PathBuf, CliError> {
    let is_wasi_wasm = |p: &Path| {
        p.extension().is_some_and(|e| e == "wasm")
            && p.components().any(|c| c.as_os_str() == "wasm32-wasip1")
    };

    for line in messages.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(line) else {
            // A non-JSON line (colour codes forced onto stdout, a stray print)
            // is not the artifact stream — skip rather than fail the parse.
            continue;
        };
        if msg.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact") {
            continue;
        }
        // Prefer the explicit executable, then any produced filename; take the
        // first that is a `.wasm` under the wasip1 triple.
        let candidates = msg.get("executable").into_iter().chain(
            msg.get("filenames")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten(),
        );
        for candidate in candidates {
            if let Some(path) = candidate.as_str() {
                let path = PathBuf::from(path);
                if is_wasi_wasm(&path) {
                    return Ok(path);
                }
            }
        }
    }

    Err(CliError::Usage(text::msg::wasi_artifact_missing(
        &out_dir.display(),
    )))
}

/// The session env a recording or replaying child gets.
///
/// Parsed once from [`cli_args::SessionMode`] and the output root, so the exec
/// sites never re-derive a path.
#[derive(Debug)]
pub enum SessionEnv {
    /// An ordinary run: no session variable.
    Live,
    /// `--record`: the runtime dumps the trace (and the typed log beside it) here.
    Record(PathBuf),
    /// `--replay`: the runtime re-folds the typed log here instead of running.
    Replay(PathBuf),
}

/// Inject the session variable into a child `Command`; a no-op for a live run.
///
/// The variable names are the runtime's own [`ipe_runtime_rust::RECORD_ENV`] /
/// [`ipe_runtime_rust::REPLAY_ENV`] constants — one source of truth for the wire
/// names across the two crates, never hand-duplicated literals.
fn set_session_env(cmd: &mut std::process::Command, session: &SessionEnv) {
    match session {
        SessionEnv::Live => {}
        SessionEnv::Record(path) => {
            cmd.env(ipe_runtime_rust::RECORD_ENV, path.as_os_str());
        }
        SessionEnv::Replay(path) => {
            cmd.env(ipe_runtime_rust::REPLAY_ENV, path.as_os_str());
        }
    }
}

/// The plain trace an `ipe dev run --record` session writes in the output root.
pub const RECORD_LOG_FILE: &str = "session.ipelog";

/// The typed log an `ipe dev run --record` session writes beside the trace — the
/// log `ipe dev run --replay` reads by default.
///
/// Derived from the runtime's [`ipe_runtime_rust::TYPED_LOG_EXTENSION`], the
/// same rule the recorder applies, so the two can never name different files.
#[must_use]
pub fn typed_log_file() -> PathBuf {
    Path::new(RECORD_LOG_FILE).with_extension(ipe_runtime_rust::TYPED_LOG_EXTENSION)
}

/// Refuse `ipe dev run --record` / `--replay` for a program whose shape or target
/// has no recordable session.
///
/// A record request never silently yields no log, and a replay request never
/// silently runs the app live.
///
/// The recorder lives in the cli (`Cli.tea`) and worker (`Worker.tea`) update
/// loops and dumps (or replays) its log from the directly executed native
/// binary; a script or TUI/web app has no such loop, and a `--target wasi` run
/// executes in wasmtime. Pure over the delivery shape and compile target, so it
/// runs before any capability resolution or consent prompt.
///
/// # Errors
/// [`CliError::Usage`] naming why the session cannot be recorded or
/// replayed.
pub fn gate_session(
    flag: &str,
    shape: delivery::Shape,
    compile_target: CompileTarget,
) -> Result<(), CliError> {
    let shape_name = match shape {
        delivery::Shape::Cli | delivery::Shape::Worker => None,
        delivery::Shape::Script => Some("a script"),
        delivery::Shape::Tui => Some("a TUI app"),
        delivery::Shape::Web => Some("a web app"),
    };
    if let Some(name) = shape_name {
        return Err(CliError::Usage(text::msg::session_no_recordable(
            &flag, &name,
        )));
    }
    if compile_target.is_wasm() {
        return Err(CliError::Usage(text::msg::session_native_only(&flag)));
    }
    Ok(())
}

/// Refuse `ipe dev run --record` / `--replay` for a native-bearing program.
///
/// A native-bearing program runs inside the jail, where the session log is not
/// reachable. Judges the capabilities the run's consent gates already resolved,
/// so the session gate never re-infers them.
///
/// # Errors
/// [`CliError::Usage`] when the resolved capability union is
/// native-bearing.
pub fn gate_session_capabilities(
    flag: &str,
    resolved: &run_sandbox::ResolvedCapabilities,
) -> Result<(), CliError> {
    if run_sandbox::is_native_bearing(&resolved.union()) {
        return Err(CliError::Usage(text::msg::session_jailed(&flag)));
    }
    Ok(())
}

/// Refuse a Tui app before any build work when no interactive terminal is
/// reachable. No-op for every other shape.
///
/// Shares its one typed decision — and its one refusal text — with the
/// runtime's own `TuiGuard` guard, via `ipe_runtime_rust::terminal_access`:
/// a piped `ipe dev run`/`ipe dev watch` is turned away the same way whether the
/// check runs here (before the build) or inside the built binary.
///
/// # Errors
/// [`CliError::Usage`] naming which terminal fact is missing.
pub fn gate_terminal(command: &'static str, shape: delivery::Shape) -> Result<(), CliError> {
    gate_terminal_decision(command, shape, ipe_runtime_rust::terminal_access::probe())
}

/// The pure decision behind [`gate_terminal`], parametrized over the terminal
/// access decision. Split out so the refusal wiring — shape gate, message,
/// command name — is table-tested against both [`TerminalAccess`] variants
/// without depending on whether the TEST process itself has a real tty,
/// which a test must never assume.
///
/// [`TerminalAccess`]: ipe_runtime_rust::terminal_access::TerminalAccess
pub fn gate_terminal_decision(
    command: &'static str,
    shape: delivery::Shape,
    access: ipe_runtime_rust::terminal_access::TerminalAccess,
) -> Result<(), CliError> {
    if shape != delivery::Shape::Tui {
        return Ok(());
    }
    if let ipe_runtime_rust::terminal_access::TerminalAccess::Refused(reason) = access {
        return Err(CliError::Usage(text::msg::command_refusal(
            &command,
            &reason.text(),
        )));
    }
    Ok(())
}

/// What a run does with its session, resolved once the output root is known.
#[derive(Debug)]
pub enum SessionPlan {
    /// Build the app and run it with this session env.
    Run(SessionEnv),
    /// Show the plain trace at this path: nothing is built and nothing re-runs.
    ShowTrace(PathBuf),
}

/// Resolve what a run does with its session, once the output root is known.
///
/// `--replay` folds a typed log or shows a plain trace (`.ipelog`) — the only
/// reader of a trace-only session. With no path it takes the typed log
/// `--record` wrote, else the trace beside it. The log must exist as a regular
/// file before anything is built, so a missing log is refused up front; the
/// runtime reads a typed log through its own capped, fail-closed decoder, and
/// [`show_session_trace`] reads a trace through the capped reader.
///
/// # Errors
/// [`CliError::Usage`] when the replay log is missing or not a file; the
/// output-root errors of claiming the log path.
pub fn resolve_session_plan(
    session: &cli_args::SessionMode,
    output: &OutputRoot,
) -> Result<SessionPlan, CliError> {
    match session {
        cli_args::SessionMode::Live => Ok(SessionPlan::Run(SessionEnv::Live)),
        cli_args::SessionMode::Record => Ok(SessionPlan::Run(SessionEnv::Record(
            output.claim()?.path_to(RECORD_LOG_FILE)?.path(),
        ))),
        cli_args::SessionMode::Replay(Some(explicit)) => replay_plan(PathBuf::from(explicit)),
        cli_args::SessionMode::Replay(None) => {
            let owned = output.claim()?;
            let typed = owned.path_to(typed_log_file())?.path();
            if is_regular_file(&typed) {
                return Ok(SessionPlan::Run(SessionEnv::Replay(typed)));
            }
            let trace = owned.path_to(RECORD_LOG_FILE)?.path();
            if is_regular_file(&trace) {
                return Ok(SessionPlan::ShowTrace(trace));
            }
            Err(CliError::Usage(text::msg::replay_no_default_log(
                &typed.display(),
                &trace.display(),
            )))
        }
    }
}

/// The plan for the log a user named: a trace is shown, any other log folded.
///
/// # Errors
/// [`CliError::Usage`] naming the path and how to record a log, unless it
/// is a regular file.
pub fn replay_plan(path: PathBuf) -> Result<SessionPlan, CliError> {
    if !is_regular_file(&path) {
        return Err(CliError::Usage(text::msg::replay_log_missing(
            &path.display(),
        )));
    }
    if is_session_trace(&path) {
        Ok(SessionPlan::ShowTrace(path))
    } else {
        Ok(SessionPlan::Run(SessionEnv::Replay(path)))
    }
}

/// `true` when `path` names a regular file (following a symlink the user named).
fn is_regular_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file())
}

/// `true` when `path` has the plain trace's extension, the one `--record` writes.
#[must_use]
pub fn is_session_trace(path: &Path) -> bool {
    path.extension() == Path::new(RECORD_LOG_FILE).extension()
}

/// The line that labels a shown trace, so it is never mistaken for a replay.
const TRACE_LABEL: &str = "trace (not a replay — shown as recorded, nothing re-runs)";

/// One trace line made safe for any terminal, or `None` when nothing is left.
///
/// Delegates to [`style::TerminalLine`]: every escape sequence (CSI, OSC and
/// the rest) is dropped whole, then every remaining control character — C0,
/// `DEL` and C1 — and every denied format character, tab and newline
/// included, so the output carries none, whatever the stream is.
fn terminal_safe_line(body: &str) -> Option<String> {
    let plain = style::TerminalLine::sanitize(body);
    (!plain.is_empty()).then(|| format!("{plain}\n"))
}

/// Render a recorded trace read from `path`: the label, then one step per line.
///
/// Pure. The trace is untrusted — handed over, planted or hand-edited — so every
/// line, the label's path included, is stripped of control characters here,
/// independently of the strip the recorder applies when it writes.
#[must_use]
pub fn render_session_trace(path: &Path, text: &str) -> String {
    let mut out =
        terminal_safe_line(&format!("{TRACE_LABEL}: {}", path.display())).unwrap_or_default();
    for step in text.lines().filter_map(terminal_safe_line) {
        out.push_str(&step);
    }
    out
}

/// Read the recorded trace at `path` whole and render it sanitised.
///
/// # Errors
/// [`CliError::FileTooLarge`] past [`io_bounded::SESSION_TRACE_READ_CAP`];
/// [`CliError::Io`] when the trace cannot be read or is not UTF-8 (kind
/// `InvalidData`).
pub fn load_session_trace(path: &Path) -> Result<String, CliError> {
    let text = io_bounded::read_to_string_capped(path, io_bounded::SESSION_TRACE_READ_CAP)?;
    Ok(render_session_trace(path, &text))
}

/// Print the recorded trace at `path` to stdout, sanitised.
///
/// The read is capped and whole: an oversized or non-UTF-8 trace is refused
/// before anything is printed.
///
/// # Errors
/// As [`load_session_trace`]; [`CliError::Io`] when stdout cannot be written.
pub fn show_session_trace(path: &Path) -> Result<(), CliError> {
    use std::io::Write as _;
    let rendered = load_session_trace(path)?;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(rendered.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(|source| CliError::Io {
            path: path.to_path_buf(),
            source,
        })
}

/// `ipe dev run [<path>]` — compile a program and run the resulting binary.
///
/// One-shot build + run: compiles the entry to `out_dir` (same routing as
/// [`run_build`]), then invokes `cargo build` on the emitted project and
/// execs the resulting `ipe-app` binary, forwarding any arguments supplied
/// after `--` and propagating the binary's exit code.
///
/// Build failures (ipe compile step or cargo build step) surface as
/// [`CliError`] and print to stderr via the normal error path. The binary
/// exec step replaces the current process (Unix) or propagates the child's
/// exit code (all platforms) so the caller sees it as `ipe dev run`'s own exit.
pub fn run_run(rest: &[String]) -> Result<(), CliError> {
    // First, infallible format pass before the body's fallible parse, so a parse
    // error honours the requested machine surface (see [`run_build`]).
    let format = cli_args::peek_output_format(rest);
    run_run_body(rest).map_err(|e| {
        if format == cli_args::OutputFormat::Human {
            e
        } else {
            emit_machine_error(format, Verb::DEV_RUN.name(), &e)
        }
    })
}

/// Inner implementation of `run_run`, unaware of JSON formatting.
///
/// Parse the argument tail into a typed [`cli_args::RunArgs`], then run it.
pub fn run_run_body(rest: &[String]) -> Result<(), CliError> {
    let args = cli_args::parse_run(rest)?;
    run_run_with_args(args)
}

/// Execute a fully-parsed `ipe dev run`: compile → cargo build → jailed exec.
///
/// With `--record`, `IPE_DEBUGGER_RECORD` is injected into the executed child
/// so the runtime dumps the session's trace and typed log into the output root
/// on exit; with `--replay`, `IPE_DEBUGGER_REPLAY` names the typed log the child
/// re-folds instead of running live, and a plain trace is shown sanitised
/// without building anything.
// A linear pipeline (compile → cargo build → resolve capabilities → jail →
// exec); the steps share enough locals that splitting reads worse than the whole.
#[allow(clippy::too_many_lines)]
pub fn run_run_with_args(args: cli_args::RunArgs) -> Result<(), CliError> {
    let output_format = args.format;
    // A recording or replaying run compiles the debugger in unconditionally:
    // the runtime recorder, its log dump and its replay are all
    // `#[cfg(feature = "debugger")]`, so without the feature a record would
    // silently produce no log and a replay would silently run the app live.
    let session = args.session;
    let debugger = args.debugger || !session.is_live();
    let bin_args = args.bin_args;
    let cli_layer = args.static_layer;
    // The CLI `--target` flavour (`--target wasi` selects the co-located WASI
    // module the embedded wasmtime path runs; `--target wasm` was refused at
    // parse). Manifest `[wasm].mode` still selects only the browser client.
    let cli_wasm = args.wasm;
    let entry = match args.entry {
        Some(e) => e,
        None => default_entry()?,
    };

    let entry_path = PathBuf::from(&entry);

    // --- Step 1: ipe compile → emit the Rust project ---
    let manifest = discover_manifest(&entry_path)?;

    // Parse the manifest early to read [wasm].mode for target inference.
    let manifest_parsed = manifest
        .as_deref()
        .map(project::parse_manifest)
        .transpose()?;
    let manifest_wasm: Option<project::WasmConfig> =
        manifest_parsed.as_ref().map(|m| m.wasm.clone());

    let wants_static = cli_layer.static_build == Some(true);

    // Static-flag contradictions (--cfree + C-requiring allocator,
    // --target without --static, talc-without-arena) are pure over the CLI +
    // env + manifest layers and touch no source. Resolving here — before
    // resolve_delivery reads the entry file — ensures a refused run produces
    // no artifact and touches nothing, even when the entry path does not exist.
    let static_plan = resolve_static_plan(cli_layer, manifest.as_deref(), output_format)?;

    // Resolve the delivery grammar (shape cross-check, runtime/host, `--static`
    // gate) against the shape `main` pins — same as `ipe dev build`. A webview-native
    // `web desktop` drives `webview_host` below. Runs after the static-plan check
    // so a flag contradiction fires before the entry file is read.
    let delivery = resolve_delivery(
        &entry_path,
        &args.delivery,
        wants_static,
        Verb::DEV_RUN.name(),
    )?;

    // A Tui app with no interactive terminal is refused right here — before
    // any compile or cargo work — rather than building fully and only then
    // failing on the raw-mode syscall inside the built binary.
    gate_terminal(Verb::DEV_RUN.name(), delivery.shape())?;

    // Human-friendly progress: the consent gates and the compile+emit below are
    // otherwise silent, so the banner and the running step come first. On a
    // terminal only (piped / CI output stays clean); to stderr, so stdout carries
    // only the program's own output. The cargo build that follows streams its own
    // progress; the exec that ends `ipe dev run` leaves no room for a settled "done"
    // line, so the run just starts producing the program's output. Suppressed
    // when `--quiet` is set.
    let show_progress = !args.quiet && {
        use std::io::IsTerminal as _;
        std::io::stderr().is_terminal()
    };
    if show_progress {
        style::print_command_header();
        crate::screen::chatter(
            crate::screen::Stream::Stderr,
            crate::screen::Tone::Text,
            &format!(
                "{} building {entry}",
                style::outcome_glyph(style::Outcome::Step)
            ),
        );
    }

    // When the project declares [wasm].mode != "off", or IPE_TARGET=wasm is
    // set, treat `ipe dev run` as a browser wasm build-and-bundle (no native binary
    // to exec). `--target wasi` selects the co-located WASI module, which `ipe
    // dev run` EXECUTES under embedded wasmtime. A plain `ipe dev run` in a non-wasm
    // project stays native. (`--target wasm` was refused at parse: the browser
    // bundle has no executable form.)
    let compile_target = resolve_compile_target(cli_wasm, manifest_wasm.as_ref());
    let wasm_target = compile_target.is_wasm();

    // A session over a shape or target with no recordable update loop is
    // refused before capability resolution and any consent prompt.
    if let Some(flag) = session.flag() {
        gate_session(flag, delivery.shape(), compile_target)?;
    }

    // The same trust-boundary consent gates as `ipe dev build`, over ONE capability
    // resolution, BEFORE the (costly) emit + cargo build: a disclosed `.Unsafe`
    // import needs consent (a non-interactive run without it fails closed rather
    // than blocking on a prompt), and a disclosed `js-port:<axis>` / `native-ffi`
    // crossing must be granted by this app's manifest, else fail closed. The
    // consented set is the one the WASI context and the native jail enforce.
    let consented = consent_to_capabilities(
        manifest_parsed.as_ref(),
        manifest.as_deref(),
        &entry_path,
        args.accept_risks,
    )?;

    // Fail closed unless the delivery runtime and the compile target agree — the
    // `(engine, triple)` validity matrix is the single live gate — so the
    // wasm-keyed native-deny backstops are never skipped for a sandboxed client
    // that slipped through as a native run.
    let (engine, triple) = compile_target.engine_triple();
    delivery
        .admit_triple(engine, triple)
        .map_err(|e| CliError::Usage(text::msg::command_refusal(&Verb::DEV_RUN, &e)))?;

    // `ipe dev run --target wasi` EXECUTES the emitted module under embedded
    // wasmtime; fail closed BEFORE any emit or build when no engine is linked
    // (the `wasi_run` feature is off), so a `wasi_run`-less `ipe` returns a typed
    // refusal naming the feature with NO wasted work — never a panic, never a
    // silent native fallback. Ordered AFTER `admit_triple` so a non-viable shape
    // (Tea/Server/Web) is still refused at resolve first (the run path never
    // opens a looser door than build).
    if matches!(compile_target, CompileTarget::WasmWasi) {
        wasi_run::ensure_available()?;
    }

    if let Some(flag) = session.flag() {
        gate_session_capabilities(flag, consented.resolved())?;
    }

    // Resolved after every program refusal above. The session log lands in the
    // ipe-owned output root, never beside sources; a shown trace ends the run
    // here, before any toolchain check or build — nothing re-runs.
    let output = resolve_output_root(args.out.as_deref(), &entry_path, manifest_parsed.as_ref())?;
    let session_env = match resolve_session_plan(&session, &output)? {
        SessionPlan::Run(env) => env,
        SessionPlan::ShowTrace(trace) => return show_session_trace(&trace),
    };

    // The dependency model (native OR wasm) needs no vendored tree — the runtime
    // is a path dependency. Only a dep-model-OFF build vendors the source subtree.
    let runtime_dep = runtime_dep_from_env();
    let runtime_dir = resolve_vendored_runtime_dir(args.runtime, !runtime_dep)?;

    // Fail closed before emitting: `ipe dev run` shells out to cargo to build the
    // emitted project, so a missing toolchain is a clear root-cause error now,
    // not an opaque OS spawn error after the (wasted) compile. The wasm branch
    // delegates to `bundle_wasm`, which resolves cargo itself, so only the
    // native branch resolves here — the resolved path is reused for its build.
    let native_cargo = if wasm_target {
        None
    } else {
        Some(toolchain::require_cargo(toolchain::ToolIntent::Run)?)
    };

    let rust_area = output.area(&[OutputArea::Rust]);

    // `ipe dev run` is a DEVELOPMENT execution, so `Debug.*` is allowed
    // (production = false).
    let options = BuildOptions {
        static_plan,
        target: compile_target.ir_target(),
        wasm_public_env: Vec::new(),
        wasm_hydrate_mode: false,
        intent: Verb::DEV_RUN.intent(),
        runtime_dep,
        // `ipe dev run` builds and executes; it never tree-shakes the vendored tree
        // (only `ipe release eject` does).
        tree_shake_vendored: false,
        // Manifest projects overwrite this from `package.ipe` in
        // build_project_with_options; a single-file (no-manifest) run keeps this
        // value, defaulting to `ipe-app` unless `IPE_EMIT_PACKAGE_NAME` names a
        // unique per-build crate (the shared-target coverage harness).
        cargo_name: single_file_cargo_name_from_env(),
        debugger,
        // `ipe dev run` never emits appearance hot-swap scaffolding — that is a
        // `ipe dev watch`-only dev affordance.
        hot_appearance: false,
        // A webview-native `web desktop` delivery links the system webview and
        // selects the webview executor; every other delivery does not.
        webview_host: delivery.is_webview_native(),
        // Filled from the manifest `delivery.desktop` in
        // build_project_with_options once the manifest is parsed.
        webview_window: None,
    };

    // Nothing is created in the Rust area until the emit writes its crate.
    let out_dir = rust_area.path()?;

    let crate_dir = emit_into(
        &entry_path,
        manifest.as_deref(),
        &EmitTarget::Area(rust_area),
        &runtime_dir,
        options,
    )?;

    // Post-emit routing per compile target:
    //   * WasmClient — a browser bundle has no executable form under `ipe dev run`;
    //     produce the bundle (same step as `ipe dev build --target wasm`) and stop.
    //   * WasmWasi — build the `wasm32-wasip1` module (THE SEAL, via the SAME
    //     `bundle_wasi` build path `ipe dev build --target wasi` uses) and then
    //     EXECUTE it under embedded wasmtime, confined by a WASI context derived
    //     from the SAME declared capability floor the native run jail reads.
    //   * Native — fall through to the cargo build + jailed exec below.
    match compile_target {
        CompileTarget::WasmClient => return bundle_wasm(&crate_dir),
        CompileTarget::WasmWasi => {
            // The `wasi_run` feature gate already fired before emit (above), so
            // reaching here means the embedded engine is linked. Build the module
            // first — a green build is THE SEAL (ipe-accepts ⇒ cargo-builds for
            // the target) — then run it.
            let module = bundle_wasi(&crate_dir)?;
            // Derive the capability floor exactly as the native jail does (the
            // consented set → `build_profile`), so the WASI context enforces the
            // SAME deny-by-default model — defend-in-depth, one capability model
            // expressed two ways (seccomp+bwrap vs a `WasiCtx`).
            let driver = manifest_parsed
                .as_ref()
                .map_or(ipe_backend_rust::DbDriver::Sqlite, |m| m.driver);
            let profile = run_sandbox::build_profile(consented.resolved(), driver)?;
            let working_tree = std::env::current_dir().map_err(|e| CliError::Io {
                path: PathBuf::from("."),
                source: e,
            })?;
            // `module` is the exact path cargo reported writing (captured from
            // the build's JSON artifact stream), so the executor loads precisely
            // the module the build produced regardless of a relocated
            // `CARGO_TARGET_DIR` or a divergent `cargo metadata`.
            return wasi_run::run_wasi_module(&module, &profile, &working_tree, &bin_args);
        }
        CompileTarget::Native => {}
    }

    // --- Step 2: cargo build the emitted project ---
    // CWD = the emitted crate dir, so the generated `.cargo/config.toml`
    // (`+crt-static` under a static plan) is discovered. The static plan
    // additionally selects the target triple explicitly — the config carries
    // only rustflags, never a `[build] target` pin.
    // `native_cargo` is `Some` on every path that reaches here: the wasm branch
    // returned above, and the native branch resolved cargo before emitting. The
    // fallback re-resolves rather than unwrapping so the toolchain error stays
    // typed even if the branch invariant ever changes.
    let cargo_bin = match native_cargo {
        Some(bin) => bin,
        None => toolchain::require_cargo(toolchain::ToolIntent::Run)?,
    };
    let runtime = if runtime_dep && !wasm_target {
        runtime_context_for_message()
    } else {
        None
    };
    CargoBuild {
        cargo: &cargo_bin,
        krate: CargoCrate::Emitted(&crate_dir),
        profile: CargoProfile::Dev,
        target: static_plan
            .as_ref()
            .map_or(CargoTarget::Host, |plan| CargoTarget::Static(plan.triple)),
        output: CargoOutput::Human(Verbosity::of_quiet(args.quiet)),
        what: "the emitted program",
        runtime,
    }
    .run()?;

    // --- Step 3: exec the emitted binary, forwarding args and exit code ---
    // The binary name is read from the emitted crate's `Cargo.toml` — the
    // same file cargo just built from, so there is ONE source of truth and
    // no independent re-derivation can drift. Falls back to `"ipe-app"` when
    // the manifest is absent or unparseable.
    // The target directory is asked of cargo itself (`cargo metadata`) — a
    // `CARGO_TARGET_DIR` env or a user-level `[build] target-dir` pin
    // relocates the artifact, so a hardcoded `<out>/target` would exec a
    // missing or stale binary.
    let bin_name = emitted_bin_filename(&out_dir);
    let mut bin = crate::cargo_step::target_directory(&cargo_bin, &out_dir)?;
    if let Some(plan) = &static_plan {
        bin.push(plan.triple.as_str());
    }
    bin.push("debug");
    bin.push(&bin_name);

    // --- Step 3a: resolve the capability set and, for native code, the jail ---
    // The jail confines the emitted app to `inferred ∪ declared`. It is scoped to
    // native-bearing programs (ADR 0004): pure Ipê is structurally bounded to its
    // inferred capabilities and runs directly; only a `Rust.` crossing has
    // effects inference cannot prove, and only that is jailed. For a native
    // program a missing primitive is fail-closed (refuses unless recorded
    // consent).
    let driver = manifest_parsed
        .as_ref()
        .map_or(ipe_backend_rust::DbDriver::Sqlite, |m| m.driver);
    let resolved = consented.resolved();
    let union = resolved.union();
    let native = run_sandbox::is_native_bearing(&union);
    let profile = run_sandbox::build_profile(resolved, driver)?;
    let bin_args_os: Vec<std::ffi::OsString> =
        bin_args.iter().map(std::ffi::OsString::from).collect();

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        if native {
            // The scoped writable tempdir (the sole writable mount when
            // `filesystem` is absent) and the working tree (bound read-write only
            // when granted) — built only for a jailed run.
            let scoped_tmp = run_sandbox::make_scoped_tmp()?;
            let working_tree = std::env::current_dir().map_err(|e| CliError::Io {
                path: PathBuf::from("."),
                source: e,
            })?;
            // The jail is established and `exec_in_run_jail` replaces this process
            // with the jailed app (does not return on success). On a platform with
            // no jail primitive, the fail-closed policy either refuses or (recorded
            // consent) returns to run unconfined below.
            run_sandbox::jail_and_exec(
                &profile,
                &union,
                scoped_tmp.path(),
                &working_tree,
                &bin,
                &bin_args_os,
            )?;
        }
        // Pure Ipê (structural guarantee, no jail) or a native program that
        // proceeded unconfined after the recorded-consent warning: run directly.
        let mut cmd = std::process::Command::new(&bin);
        cmd.args(&bin_args);
        set_session_env(&mut cmd, &session_env);
        let err = cmd.exec();
        Err(CliError::Io {
            path: bin,
            source: err,
        })
    }
    #[cfg(not(unix))]
    {
        if native {
            // Off Unix there is no jail (the documented refuse-gap): `jail_and_exec`
            // applies the fail-closed policy — refuse the native program, or
            // (recorded consent) return Ok to run unconfined below.
            let scoped_tmp = run_sandbox::make_scoped_tmp()?;
            let working_tree = std::env::current_dir().map_err(|e| CliError::Io {
                path: PathBuf::from("."),
                source: e,
            })?;
            run_sandbox::jail_and_exec(
                &profile,
                &union,
                scoped_tmp.path(),
                &working_tree,
                &bin,
                &bin_args_os,
            )?;
        }
        let mut cmd = std::process::Command::new(&bin);
        cmd.args(&bin_args);
        set_session_env(&mut cmd, &session_env);
        let status = cmd.status().map_err(|e| CliError::Io {
            path: bin,
            source: e,
        })?;
        // Propagate the child's exit code.  `CliError` only models failure, so
        // a non-zero exit is surfaced as a usage-owned message; the caller
        // (main.rs) prints it to stderr and exits 1.
        if !status.success() {
            let code = status.code().unwrap_or(1);
            return Err(CliError::Usage(text::msg::program_exited(&bin_name, &code)));
        }
        Ok(())
    }
}

/// `ipe release run [<path>] [--out] [--runtime] [--target] [-- <args>...]`
/// — produce the release artifact, then run exactly the artifact the pipeline
/// returned, jailed.
///
/// Every run is confined: the embed-mode wrapper jails itself by
/// construction, and a bundle or a pure-native binary runs through
/// [`run_sandbox::exec_jailed`], which has no unconfined fallback. A `<path>`
/// naming a built artifact directory (one holding `ipe-wrapper`) runs that
/// artifact as built: a bundle's profile is strictly parsed and verified
/// against the floor embedded in its app before the jailed exec.
///
/// # Errors
///
/// [`CliError::NoRunForm`] for a target with no run form; every
/// [`release_pipeline`] error; an incomplete or unverifiable artifact
/// directory; a jail refusal.
pub fn run_release_run(rest: &[String]) -> Result<(), CliError> {
    let args = cli_args::parse_release_run(rest)?;
    let output = match prebuilt_artifact_dir(args.build.entry.as_deref()) {
        Some(dir) if args.build_flags => {
            return Err(CliError::Usage(text::msg::release_run_artifact_flags(
                &dir.display(),
            )));
        }
        Some(dir) => prebuilt_artifact(dir)?,
        None => release_pipeline(&args.build, ReleasePurpose::Run)?,
    };
    let app_args: Vec<std::ffi::OsString> =
        args.app_args.iter().map(std::ffi::OsString::from).collect();
    run_release_output(output, &app_args)
}

/// The built artifact directory `entry` names: a directory holding the
/// `ipe-wrapper` a native-bearing release lays out. A directory carrying a
/// project manifest is a project, never an artifact, whatever else it holds.
fn prebuilt_artifact_dir(entry: Option<&str>) -> Option<&Path> {
    let dir = Path::new(entry?);
    let present = |name: &str| std::fs::symlink_metadata(dir.join(name)).is_ok();
    let project = present(package_manifest::PACKAGE_IPE) || present(project::IPE_TOML);
    (!project && present(RELEASE_WRAPPER)).then_some(dir)
}

/// The wrapper's file name inside a release artifact directory.
const RELEASE_WRAPPER: &str = "ipe-wrapper";
/// The app's file name inside a release bundle.
const RELEASE_APP: &str = "ipe-app";
/// The jail profile's file name inside a release bundle.
const RELEASE_PROFILE: &str = "ipe.profile";

/// Classify a built artifact directory: a bundle when it carries an app and
/// a profile. A lone wrapper (an embed-mode build) refuses: its app and
/// profile are inside the wrapper, so nothing outside it can be verified, and
/// a file named `ipe-wrapper` is never executed on trust.
fn prebuilt_artifact(dir: &Path) -> Result<ReleaseOutput, CliError> {
    let present = |name: &str| std::fs::symlink_metadata(dir.join(name)).is_ok();
    let (app, profile) = (present(RELEASE_APP), present(RELEASE_PROFILE));
    match (app, profile) {
        (false, false) => Err(CliError::Usage(
            text::msg::release_run_wrapper_unverifiable(&dir.display()),
        )),
        (true, true) => Ok(ReleaseOutput::Bundle(dir.to_path_buf())),
        (true, false) | (false, true) => {
            let missing = if app { RELEASE_PROFILE } else { RELEASE_APP };
            Err(CliError::Usage(text::msg::release_run_bundle_incomplete(
                &dir.display(),
                &missing,
            )))
        }
    }
}

/// Run a release artifact, confined, with `app_args`.
///
/// The embed-mode wrapper the pipeline just built is executed with the app
/// arguments behind its `--`: it verifies its embedded profile against its
/// embedded floor and jails itself, failing closed. A bundle's app is read
/// once, verified against its profile, and those verified bytes run jailed; a
/// pure-native binary is jailed under the profile its consented capabilities
/// lower to.
fn run_release_output(
    output: ReleaseOutput,
    app_args: &[std::ffi::OsString],
) -> Result<(), CliError> {
    let working_tree = || {
        std::env::current_dir().map_err(|e| CliError::Io {
            path: PathBuf::from("."),
            source: e,
        })
    };
    match output {
        ReleaseOutput::Distributable => {
            // The pipeline refuses every no-run target under `Run`; a
            // distributable here has nothing to execute.
            Err(CliError::NoRunForm {
                target: cli_args::NoRunTarget::Wasm,
            })
        }
        ReleaseOutput::Embedded(wrapper) => exec_program(&wrapper, &wrapper_argv(app_args)),
        ReleaseOutput::Bundle(dir) => {
            let verified = run_sandbox::load_and_verify_artifact(
                &dir.join(RELEASE_PROFILE),
                &dir.join(RELEASE_APP),
            )?;
            let tmp = run_sandbox::make_scoped_tmp()?;
            Err(run_sandbox::exec_verified_jailed(
                &verified,
                tmp.path(),
                &working_tree()?,
                app_args,
            ))
        }
        ReleaseOutput::PureNative { binary, profile } => {
            let tmp = run_sandbox::make_scoped_tmp()?;
            Err(run_sandbox::exec_jailed(
                &profile,
                tmp.path(),
                &working_tree()?,
                &binary,
                app_args,
            ))
        }
    }
}

/// The embed-mode wrapper's argv for `app_args`: every app argument sits
/// behind the wrapper's `--`, so none is read as a wrapper flag.
fn wrapper_argv(app_args: &[std::ffi::OsString]) -> Vec<std::ffi::OsString> {
    std::iter::once(std::ffi::OsString::from("--"))
        .chain(app_args.iter().cloned())
        .collect()
}

/// Execute `program` with `args`: replace this process on Unix, or wait for
/// it and carry its exit status elsewhere.
fn exec_program(program: &Path, args: &[std::ffi::OsString]) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        let err = std::process::Command::new(program).args(args).exec();
        Err(CliError::Io {
            path: program.to_path_buf(),
            source: err,
        })
    }
    #[cfg(not(unix))]
    {
        let status = std::process::Command::new(program)
            .args(args)
            .status()
            .map_err(|e| CliError::Io {
                path: program.to_path_buf(),
                source: e,
            })?;
        if !status.success() {
            return Err(CliError::Usage(text::msg::program_exited(
                &program.display(),
                &status.code().unwrap_or(1),
            )));
        }
        Ok(())
    }
}

/// Read the emitted crate IDENTITY from an emitted project's `Cargo.toml`
/// `[package] name` so `ipe dev run` / `ipe release run` / `ipe test` locate the correct
/// built binary — cargo names the binary artifact after the crate, so this is
/// the per-project path-uniquified identity (`<friendly>_<hash>`), NOT the
/// user-facing friendly name. Falls back to `"ipe-app"` when the manifest is
/// absent or unparseable — never panics. For a user-facing artifact filename or
/// message use [`friendly_artifact_name`], which never carries the hash.
pub fn emitted_bin_name(crate_dir: &Path) -> String {
    let manifest = crate_dir.join("Cargo.toml");
    let Ok(text) = std::fs::read_to_string(&manifest) else {
        return "ipe-app".to_owned();
    };
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("name") {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let value = rest.trim().trim_matches('"');
                if !value.is_empty() {
                    return value.to_owned();
                }
            }
        }
    }
    "ipe-app".to_owned()
}

/// The on-disk filename cargo gives the emitted crate's executable, ready to
/// join onto a target-profile directory. It is [`emitted_bin_name`] (the crate
/// identity) plus the host's executable extension: `.exe` on Windows, empty
/// elsewhere. Locating the built artifact by the bare identity misses the file
/// on Windows, where cargo appends `.exe`; every caller that resolves a built
/// binary path uses this so the locate is host-correct on all targets.
pub fn emitted_bin_filename(crate_dir: &Path) -> String {
    format!(
        "{}{}",
        emitted_bin_name(crate_dir),
        std::env::consts::EXE_SUFFIX
    )
}

/// The user-facing artifact name for a project — the plain (sanitized) friendly
/// name, NEVER carrying the crate-identity hash. Used for a distributed artifact
/// filename or a "built X" message, so the hash the emitted crate uses to own a
/// unique shared-target slot stays internal. A single-file (no-manifest) build
/// has no project name and falls back to `"ipe-app"`, matching the emitted
/// single-file default.
fn friendly_artifact_name(manifest: Option<&project::ProjectManifest>) -> String {
    manifest.map_or_else(
        || "ipe-app".to_owned(),
        |m| ipe_backend_rust::sanitize_cargo_name(&m.name),
    )
}

/// The delivered artifact FILE name: the friendly name plus the platform
/// executable suffix (`.exe` on Windows), so a copied `out/bin/<name>` or a
/// released binary is runnable on the host that built it. Mirrors
/// `emitted_bin_filename`'s suffix rule from the one `EXE_SUFFIX` source, so the
/// located source file and the delivered file agree by construction rather than
/// only on Unix — where the suffix is empty and the omission is invisible.
fn friendly_artifact_filename(manifest: Option<&project::ProjectManifest>) -> String {
    format!(
        "{}{}",
        friendly_artifact_name(manifest),
        std::env::consts::EXE_SUFFIX
    )
}

/// `ipe explain` has been folded into `ipe doc`.
///
/// Invoking `ipe explain` emits a pointer to `ipe doc` and returns a usage
/// error so the dispatcher shows the `ipe doc` help page. The command is no
/// longer advertised; the COMMANDS registry entry was removed.
pub const fn run_explain(_rest: &[String]) -> Result<(), CliError> {
    Err(CliError::Usage(text::msg::explain_moved()))
}

/// `ipe fix <path>` — apply machine-applicable fixes to the source file.
/// Default is interactive per-edit confirmation;
/// `--yes` is durable authorization to apply every machine-applicable edit.
pub fn run_fix(rest: &[String]) -> Result<(), CliError> {
    let args = cli_args::parse_fix(rest)?;
    apply_fixes_cmd(
        &PathBuf::from(&args.entry),
        args.auto,
        &mut std::io::stdout(),
    )?;
    Ok(())
}

// ===========================================================================
// `explain` — code index, lookup, and did-you-mean
// ===========================================================================

/// The one-line-per-code index: `<CODE>  <title>\n`, in taxonomy order.
#[must_use]
pub fn code_index() -> String {
    let mut s = String::new();
    for &c in ALL_CODES {
        s.push_str(c.as_str());
        s.push_str("  ");
        s.push_str(title(c));
        s.push('\n');
    }
    s
}

/// Resolve a (case-insensitive) code string to its embedded explain page.
///
/// The input is trimmed and upper-cased before matching, so `ipe-t0001` and
/// `IPE-T0001` both resolve.
///
/// # Errors
/// Returns [`CliError::UnknownCode`] (carrying a deterministic did-you-mean
/// list) when the string is not a taxonomy code.
pub fn explain_lookup(input: &str) -> Result<&'static str, CliError> {
    let canonical = input.trim().to_ascii_uppercase();
    for &c in ALL_CODES {
        if c.as_str() == canonical {
            // `explain_page` is `Some` for every `ALL_CODES` member; the `None`
            // arm is surfaced as a typed error rather than a panic.
            return explain_page(c).map_or_else(
                || {
                    Err(CliError::UnknownCode {
                        input: input.trim().to_owned(),
                        suggestions: Vec::new(),
                    })
                },
                Ok,
            );
        }
    }
    Err(CliError::UnknownCode {
        input: input.trim().to_owned(),
        suggestions: did_you_mean_codes(&canonical),
    })
}

/// The known command closest to `attempted` by Levenshtein distance, within a
/// small edit threshold — the "maybe ...?" hint for a mistyped command. `None`
/// when nothing is close enough, so a wildly different token gets only the help
/// screen, not a misleading guess.
pub fn nearest_command(attempted: &str) -> Option<&'static str> {
    help::command_names()
        .into_iter()
        .map(|name| (levenshtein(attempted, name), name))
        .filter(|&(dist, _)| dist <= 3)
        .min_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)))
        .map(|(_, name)| name)
}

/// The verb of `group` closest to `attempted` by Levenshtein distance, within a
/// small edit threshold — the "maybe `ipe dev run`?" hint after a mistyped group
/// verb. `None` when nothing is close enough, or when `group` is not a known
/// group.
pub fn nearest_group_member(group: &str, attempted: &str) -> Option<&'static str> {
    help::group_members(group)?
        .iter()
        .map(|&verb| (levenshtein(attempted, verb), verb))
        .filter(|&(dist, _)| dist <= 3)
        .min_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)))
        .map(|(_, verb)| verb)
}

/// The closest known codes to `canonical` (already upper-cased), ranked by
/// `(Levenshtein, code)` and filtered to a small edit distance. Deterministic.
pub fn did_you_mean_codes(canonical: &str) -> Vec<&'static str> {
    let mut scored: Vec<(usize, &'static str)> = ALL_CODES
        .iter()
        .map(|&c| (levenshtein(canonical, c.as_str()), c.as_str()))
        .collect();
    scored.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));
    scored
        .into_iter()
        .filter(|&(dist, _)| dist <= 3)
        .take(3)
        .map(|(_, name)| name)
        .collect()
}

/// Classic two-row Levenshtein edit distance. Uses no slice indexing (only
/// `get`/`push`/`last`), so it cannot panic.
pub fn levenshtein(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur: Vec<usize> = Vec::with_capacity(b.len().saturating_add(1));
        cur.push(i.saturating_add(1));
        for (j, &cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            let del = prev.get(j.saturating_add(1)).copied().unwrap_or(usize::MAX);
            let ins = cur.get(j).copied().unwrap_or(usize::MAX);
            let sub = prev.get(j).copied().unwrap_or(usize::MAX);
            cur.push(
                del.saturating_add(1)
                    .min(ins.saturating_add(1))
                    .min(sub.saturating_add(cost)),
            );
        }
        prev = cur;
    }
    prev.last().copied().unwrap_or(0)
}

// ===========================================================================
// `--emit-ir` — pretty-print the lowered IR
// ===========================================================================

/// Run parse → canon → types → lower and return the pretty-printed IR tree,
/// stopping before codegen.
///
/// # Errors
/// Returns [`CliError::Pipeline`] when the compiler rejects the program, or
/// [`CliError::Io`] when the entry file cannot be read.
pub fn emit_ir_text(entry: &Path) -> Result<String, CliError> {
    let file = ResolvedPath::of(entry).map_err(|e| io_err(entry, e))?;
    emit_ir_text_for_target(&AnalysisTarget::Loose(file))
}

// ===========================================================================
// `capabilities` — report / verify a program's inferred capability set
// ===========================================================================

/// The whole set of security capabilities a program discloses: the kernel-derived
/// set [`ipe_lower::program_capabilities`] infers from the lowered program, PLUS
/// [`ipe_ir::Capability::CustomElement`] whenever the program constructs any
/// `customElement` handle.
///
/// The custom-element axis is derived from the SAME walk emission serves from —
/// [`ipe_canon::custom_element_gate::collect_widget_files`] over the pre-DCE
/// `linked` module — so the served-asset set and the disclosed-capability set are
/// one set by construction. A handle that is constructed but never mounted (and
/// so lowers to a capability-free leaf that DCE may drop) still ships its browser
/// JS through the emitted `widget_assets::register`, and this derivation discloses
/// it regardless of the lowered program's reachability. `collect_widget_files`
/// walks the whole linked program, so a handle constructed in an imported module
/// is disclosed transitively.
///
/// This is the single inference point every capability consumer routes through —
/// the report, the declared-set verify, package inference, and index admission —
/// so none of them can disclose a different set than the emitter serves.
pub fn capabilities_including_served_widgets(
    db: &dyn ipe_db::Db,
    root: ipe_db::SourceRoot,
    entry_file: ipe_db::SourceFile,
    program: &ipe_ir::Program,
) -> std::collections::BTreeSet<ipe_ir::Capability> {
    let mut caps = ipe_lower::program_capabilities(program);
    if program_constructs_a_widget(db, root, entry_file) {
        caps.insert(ipe_ir::Capability::CustomElement);
    }
    caps
}

/// True when the linked program constructs at least one `customElement` handle —
/// i.e. the emitter serves at least one widget asset for it. Reuses the exact
/// [`ipe_canon::custom_element_gate::collect_widget_files`] walk emission uses, so
/// the serve decision and this disclose decision are the same decision.
///
/// A program whose linking fails has no served widget (nothing is emitted), so a
/// link failure conservatively contributes no widget disclosure here; the failing
/// pipeline surfaces its own diagnostic through the caller's own lowering.
pub fn program_constructs_a_widget(
    db: &dyn ipe_db::Db,
    root: ipe_db::SourceRoot,
    entry_file: ipe_db::SourceFile,
) -> bool {
    ipe_db::linked_program(db, root, entry_file)
        .as_ref()
        .is_ok_and(|linked| {
            !ipe_canon::custom_element_gate::collect_widget_files(&linked.module).is_empty()
        })
}

/// Lower a single `.ipe` entry through the SAME injection-aware source-graph
/// pipeline the build path uses, returning the owning database (its interner
/// backs any downstream `ipe_ir::pretty`) and the lowered program.
///
/// This routes through sibling discovery + compiled-source stdlib injection +
/// the salsa `lower_program` query rather than a bare single-module
/// parse→canon→infer→lower. Without injection an entry importing a
/// compiled-source stdlib module (e.g. `Ipe.Test`) fails name resolution with
/// IPE-N0004 even though a real `ipe dev build` of the same program succeeds — the
/// analysis surfaces (`ipe capabilities`, `ipe dev build --emit-ir`) must resolve
/// such a module identically to the build.
///
/// # Errors
/// [`CliError::Pipeline`] carrying the first compiler diagnostic;
/// [`CliError::Io`] when a source file cannot be read.
pub fn lower_entry_via_graph(
    entry: &Path,
) -> Result<(ipe_db::IpeDatabase, std::sync::Arc<ipe_ir::Program>), CliError> {
    let graph = build_source_graph(entry)?;
    let program = graph.run_attributed(entry, |db, root, file| {
        ipe_db::lower_program(db, root, file).clone()
    })?;
    Ok((graph.db, program))
}

/// The salsa inputs one analysis needs: the owning database, the whole-program
/// source root, and the entry module's [`ipe_db::SourceFile`] handle — the
/// product of sibling discovery + compiled-source stdlib injection shared by
/// every single-entry analysis path.
pub struct SourceGraph {
    pub(crate) db: ipe_db::IpeDatabase,
    pub(crate) source_root: ipe_db::SourceRoot,
    pub(crate) entry_file: ipe_db::SourceFile,
    /// The whole module set (path → (file, src)) — every module a diagnostic
    /// span may index into, so a rejecting query can be framed against the
    /// source that OWNS the span rather than the entry file (the caret bug).
    sources: BTreeMap<Vec<String>, (PathBuf, String)>,
    /// The entry module's dotted path — its `(file, src)` is the fallback frame
    /// for a homeless / dummy-span diagnostic.
    entry_module_path: Vec<String>,
}

impl SourceGraph {
    /// Run the per-module canonicalisation blame loop, then map a rejecting
    /// query's [`ipe_db::PipelineError`] to the source file that OWNS it — the SAME
    /// attribution the build path uses (`attribute_canon_errors` +
    /// `attribute_post_link_error`), so `ipe type-check` and every other analysis
    /// surface frame a given diagnostic against the identical source as
    /// `ipe dev build`.
    ///
    /// A canon error (e.g. IPE-N0020) surfaces from the blame loop already
    /// framed against its own module; only a post-link error reaches the
    /// `run_query` closure, where a type-checker error's typed home (or, for a
    /// homeless link or lowering error, the byte-offset heuristic over the
    /// linked program) selects the owning source.
    ///
    /// # Errors
    /// [`CliError::Pipeline`] carrying the first compiler diagnostic; the query
    /// closure's own error otherwise.
    pub fn run_attributed<T>(
        &self,
        blame_path: &Path,
        run_query: impl FnOnce(
            &ipe_db::IpeDatabase,
            ipe_db::SourceRoot,
            ipe_db::SourceFile,
        ) -> Result<T, ipe_db::PipelineError>,
    ) -> Result<T, CliError> {
        attribute_canon_errors(
            &self.db,
            self.source_root,
            &self.sources,
            self.entry_file,
            blame_path,
        )?;
        run_query(&self.db, self.source_root, self.entry_file).map_err(|err| {
            // Canon succeeded, so the linked program exists; use it for the
            // byte-offset fallback when a link or lowering error's home is
            // empty. A link failure here (no linked program) frames against the
            // entry file.
            let entry = self
                .sources
                .get(&self.entry_module_path)
                .cloned()
                .unwrap_or_else(|| (blame_path.to_path_buf(), String::new()));
            let interner = ipe_db::Db::interner(&self.db).clone();
            let home_to_source = home_to_source_map(&interner, &self.sources);
            match (
                ipe_db::linked_program(&self.db, self.source_root, self.entry_file),
                err,
            ) {
                (Ok(linked), err) => {
                    attribute_post_link_error(&linked.module, &home_to_source, &entry, err)
                }
                (Err(_), ipe_db::PipelineError::Infer(infer)) => {
                    frame_infer_error(&home_to_source, &entry, infer)
                }
                (Err(link_diag), ipe_db::PipelineError::Lower(diag, home)) => {
                    // A link error has no linked program to scan; frame the
                    // ORIGINAL query diagnostic (not the link error) against the
                    // home module if known, else the entry file.
                    let (file, src) = if home.is_empty() {
                        entry
                    } else {
                        home_to_source.get(&home).cloned().unwrap_or(entry)
                    };
                    // `link_diag` is discarded: the query's own diagnostic is the
                    // one the user asked about; a link error would already have
                    // surfaced from the canon blame loop or a build.
                    let _ = link_diag;
                    CliError::Pipeline {
                        file,
                        src,
                        diag: Box::new(diag),
                    }
                }
            }
        })
    }
}

/// Build the injection-aware whole-program source graph for a single `.ipe`
/// entry: discover its siblings, inject the compiled-source stdlib closure, and
/// create the salsa source root. Shared by [`lower_entry_via_graph`] and
/// [`typecheck_entry_via_graph`] so the build, capabilities, `--emit-ir`, and
/// `check` surfaces all resolve the same module set — a compiled-source stdlib
/// import (e.g. `Ipe.Test`) resolves identically across every one.
///
/// # Errors
/// [`CliError::Pipeline`] when the entry does not parse; [`CliError::Io`] on any
/// filesystem failure; [`CliError::Usage`] if the entry is not in the built map.
pub fn build_source_graph(entry: &Path) -> Result<SourceGraph, CliError> {
    build_source_graph_from(collect_entry_and_siblings(entry)?, entry)
}

/// Build the whole-program source graph for a manifest-governed file analysed
/// by itself, over the src-rooted module set [`collect_manifest_rooted_entry`]
/// discovers (the same set `ipe dev build` compiles) — so a nested file importing
/// by its full module path (`Api.Handlers` importing `Api.Types`) resolves.
///
/// # Errors
/// Same as [`build_source_graph`].
pub fn build_source_graph_for_manifest_file(
    src_root: &Path,
    entry: &Path,
) -> Result<SourceGraph, CliError> {
    build_source_graph_from(collect_manifest_rooted_entry(src_root, entry)?, entry)
}

/// Build the whole-program source graph for a `tests/`-rooted entry, unioning
/// the project's `src/` tree with its `tests/` tree — [`collect_test_sources`],
/// `ipe verify`'s own `tests ∪ src` convention — so `ipe type-check tests/X.ipe`
/// and its sibling analysis surfaces see every module a test file may import
/// from either tree.
///
/// # Errors
/// Same as [`build_source_graph`].
pub fn build_source_graph_for_test(
    project_src_root: &Path,
    tests_root: &Path,
    test_entry: &Path,
) -> Result<SourceGraph, CliError> {
    build_source_graph_from(
        collect_test_sources(project_src_root, tests_root, test_entry)?,
        test_entry,
    )
}

/// The [`build_source_graph`] / [`build_source_graph_for_test`] shared core:
/// inject the compiled-source stdlib closure and the FFI seam into an already
/// collected module set, then create the salsa source root.
///
/// # Errors
/// [`CliError::Pipeline`] when a module does not parse; [`CliError::Io`] on any
/// filesystem failure; [`CliError::Usage`] if the entry is not in the built map.
fn build_source_graph_from(
    mut collected: CollectedSources,
    blame_path: &Path,
) -> Result<SourceGraph, CliError> {
    let injected =
        project::inject_compiled_std_closure(&mut collected.sources, &mut collected.discovered);
    // The SAME FFI seam the build runs: without it, a project with installed
    // crates (or asserted `Rust.Ffi.call` definitions) has no `Rust.*`
    // interface modules here, so `ipe type-check` / `ipe capabilities` /
    // `--emit-ir` would refuse a program the build accepts.
    let ffi_injected = ffi::prepare_ffi(&mut collected.sources, blame_path)?.injected;

    let db = ipe_db::IpeDatabase::new();
    let source_root = create_source_root(&db, &collected.sources, &injected, &ffi_injected);
    let Some(entry_file) = source_root
        .files(&db)
        .get(&collected.entry_module_path)
        .copied()
    else {
        return Err(CliError::Usage(
            text::msg::internal_entry_not_in_source_map(),
        ));
    };

    Ok(SourceGraph {
        db,
        source_root,
        entry_file,
        sources: collected.sources,
        entry_module_path: collected.entry_module_path,
    })
}

/// Collect the USER `.ipe` source texts a build sees, for the `.Unsafe`-import
/// scan. A manifest project reads every discovered module under its source root
/// (the same whole-tree posture package-capability inference takes); a
/// single-file entry reads the entry plus its imported siblings.
///
/// Fail-closed: any unreadable module causes an immediate `Err` so the
/// acknowledgment gate never operates on a partial source set.
///
/// # Errors
/// [`CliError::Io`] when any discovered module cannot be read; for a single
/// file, every [`loose_file_scan_sources`] error.
pub fn user_sources_for_unsafe_scan(
    manifest: Option<&Path>,
    entry: &Path,
) -> Result<Vec<String>, CliError> {
    if let Some(mpath) = manifest
        && let Ok(m) = project::parse_manifest(mpath)
        && let Ok(discovered) = project::discover_modules(&m.src_root)
    {
        return discovered
            .iter()
            .map(|d| crate::io_bounded::read_walked_source(d.path()))
            .collect::<Result<Vec<_>, _>>();
    }
    // Single file (or a manifest that failed to parse — the build will surface
    // that error itself): the entry and its siblings.
    loose_file_scan_sources(entry).map(|named| named.into_iter().map(|(_, src)| src).collect())
}

/// The loose-file closure's `(dotted-module-name, source)` pairs for a consent scan.
///
/// An entry that does not parse has no import closure to follow, so the scan
/// sees the entry's own text, keyed by its path; the build reports the parse
/// error itself. Every other failure — an unreadable entry or module, a file
/// or closure past its limit — propagates, so no gate judges a partial
/// source set.
///
/// # Errors
/// Every [`collect_entry_and_siblings`] error except the entry's own parse failure.
fn loose_file_scan_sources(entry: &Path) -> Result<Vec<(String, String)>, CliError> {
    match collect_entry_and_siblings(entry) {
        Ok(collected) => Ok(collected
            .sources
            .into_iter()
            .map(|(path, (_, src))| (path.join("."), src))
            .collect()),
        Err(CliError::Pipeline { file, src, .. }) if file.as_path() == entry => {
            Ok(vec![(entry.display().to_string(), src)])
        }
        Err(other) => Err(other),
    }
}

/// The program's resolved capability sets, admitted by every trust-boundary
/// consent gate.
///
/// The one constructor is [`consent_to_capabilities`]: it resolves (infers) the
/// capability set exactly once and runs the `.Unsafe`, web, and native-crossing
/// gates over that single value. Every downstream consumer — the build-artifact
/// profile, the release jail, the run jail, the WASI context — takes this
/// witness, so none of them re-infers, and none is reachable without consent.
pub struct ConsentedCapabilities {
    resolved: run_sandbox::ResolvedCapabilities,
}

impl ConsentedCapabilities {
    /// The inferred and declared sets the consent gates admitted.
    #[must_use]
    pub const fn resolved(&self) -> &run_sandbox::ResolvedCapabilities {
        &self.resolved
    }
}

/// Resolve the program's capabilities once and pass them through every
/// trust-boundary consent gate, shared by `ipe dev build`, `ipe dev run`, and
/// `ipe release`: the `.Unsafe` acknowledgment, then the app-boundary web
/// consent, then the app-boundary native-crossing consent. All three judge the
/// SAME resolved value, and the value is released only once all three admit it.
///
/// # Errors
/// The first gate refusal (`IPE-S0001` / `IPE-S0002` / `IPE-S0003`); the
/// capability-resolution errors it composes.
pub fn consent_to_capabilities(
    manifest_parsed: Option<&project::ProjectManifest>,
    manifest_path: Option<&Path>,
    entry: &Path,
    accept_risks_flag: bool,
) -> Result<ConsentedCapabilities, CliError> {
    let resolved = run_sandbox::resolve_for_run(manifest_parsed, manifest_path, entry)?;
    acknowledge_unsafe_imports(
        &resolved,
        manifest_parsed,
        manifest_path,
        entry,
        accept_risks_flag,
    )?;
    gate_web_consent(&resolved, manifest_parsed, manifest_path, entry)?;
    gate_native_ffi_consent(&resolved, manifest_parsed, manifest_path, entry)?;
    Ok(ConsentedCapabilities { resolved })
}

/// The acknowledgment gate for `Ipe.<M>.Unsafe` escape-hatch imports.
///
/// Judges the program's resolved capabilities, and — only when the disclosed
/// `unsafe` capability is present — surfaces the risk and requires consent
/// (the `--accept-risks` flag, a `[capabilities] accept = ["unsafe"]` manifest
/// token, or an interactive `y`). A non-interactive
/// build without pre-acceptance fails closed (`IPE-S0001`); it never blocks on a
/// prompt. A program with no `.Unsafe` import is untouched.
///
/// # Errors
/// [`CliError::Usage`] (`IPE-S0001`) when consent is required but absent;
/// the source-read errors of the provenance scan.
fn acknowledge_unsafe_imports(
    resolved: &run_sandbox::ResolvedCapabilities,
    manifest_parsed: Option<&project::ProjectManifest>,
    manifest_path: Option<&Path>,
    entry: &Path,
    accept_risks_flag: bool,
) -> Result<(), CliError> {
    // Short-circuit before any source read when the disclosed capability is
    // absent — the safe path does no work at all.
    if !resolved.inferred.contains(&ipe_ir::Capability::Unsafe) {
        return Ok(());
    }
    let sources = user_sources_for_unsafe_scan(manifest_path, entry)?;
    let via = unsafe_ack::unsafe_modules_in_sources(sources.iter().map(String::as_str));
    let manifest_accept = manifest_parsed
        .map(|m| m.capabilities_accept.clone())
        .unwrap_or_default();
    let mut stdin = std::io::stdin().lock();
    let mut stderr = std::io::stderr().lock();
    unsafe_ack::gate(
        &resolved.inferred,
        accept_risks_flag,
        &manifest_accept,
        &via,
        unsafe_ack::is_interactive(),
        &mut stdin,
        &mut stderr,
    )
}

/// The app-boundary web-capability consent gate, invoked right after the
/// `.Unsafe` acknowledgment.
///
/// Judges the program's resolved capabilities; if
/// any disclosed `js-port:<axis>` web capability is present, it demands that the
/// top-level app's `[capabilities] accept` set grant it. An ungranted (or
/// un-attributable) web axis is a fail-closed, typed refusal naming the disclosing
/// module — it never prompts and never composes a dependency's own grant. A
/// program that reaches no web capability is untouched.
///
/// # Errors
/// [`CliError::Usage`] (`IPE-S0002`) when a disclosed web axis is ungranted;
/// the source-read errors of the provenance scan.
fn gate_web_consent(
    resolved: &run_sandbox::ResolvedCapabilities,
    manifest_parsed: Option<&project::ProjectManifest>,
    manifest_path: Option<&Path>,
    entry: &Path,
) -> Result<(), CliError> {
    // Short-circuit before any source read when no web axis is disclosed.
    if !resolved
        .inferred
        .iter()
        .any(|c| matches!(c, ipe_ir::Capability::JsPort(_)))
    {
        return Ok(());
    }
    // Provenance over the whole module set (app + siblings + any dep modules the
    // infer path reads), keyed on the module path so the refusal names the
    // disclosing module. Total by construction: an inferred axis that no source
    // attributes is refused as un-attributable, never dropped.
    let named_sources = named_sources_for_web_scan(manifest_path, entry)?;
    let provenance = web_consent::WebAxisProvenance::from_sources(
        named_sources
            .iter()
            .map(|(name, src)| (name.as_str(), src.as_str())),
    );
    let granted = manifest_parsed
        .map(|m| m.capabilities_accept.clone())
        .unwrap_or_default();
    web_consent::gate(&resolved.inferred, &granted, &provenance)
}

/// The app-boundary native-crossing consent gate, invoked right after the
/// web-capability consent.
///
/// Judges the program's resolved capabilities; if
/// the disclosed `native-ffi` capability is present (any `Rust.` crossing), it
/// demands that the top-level app's `[capabilities] declared` set grant it. An
/// ungranted (or un-attributable) crossing is a fail-closed, typed refusal naming
/// the disclosing `Rust.<Crate>` module — it never prompts and never composes a
/// dependency's own grant. A program that crosses into no native code is
/// untouched.
///
/// The grant surface is `[capabilities] declared` (a package's *own* effects, the
/// same set `verify_capabilities` reconciles), not `accept` (a pre-acceptance of
/// a hazard the build would prompt about): a native crossing is a package's own
/// declared effect, so it belongs on the `declared` axis. The runtime jail
/// CONTAINS the crossing's opaque effects regardless; this gate is the consent
/// half — the crossing must be granted before the (costly) emit + cargo build.
///
/// # Errors
/// [`CliError::Usage`] (`IPE-S0003`) when the disclosed native crossing is
/// ungranted; the source-read errors of the provenance scan.
fn gate_native_ffi_consent(
    resolved: &run_sandbox::ResolvedCapabilities,
    manifest_parsed: Option<&project::ProjectManifest>,
    manifest_path: Option<&Path>,
    entry: &Path,
) -> Result<(), CliError> {
    // Short-circuit before any source read when no native crossing is disclosed.
    if !resolved.inferred.contains(&ipe_ir::Capability::NativeFfi) {
        return Ok(());
    }
    // Provenance over the whole module set (app + siblings + any dep modules the
    // infer path reads), keyed on the crate so the refusal names the disclosing
    // `Rust.<Crate>` import. Total by construction: an inferred crossing that no
    // source attributes is refused as un-attributable, never dropped.
    let named_sources = named_sources_for_web_scan(manifest_path, entry)?;
    let provenance = native_ffi_consent::NativeCrossingProvenance::from_sources(
        named_sources
            .iter()
            .map(|(name, src)| (name.as_str(), src.as_str())),
    );
    let granted = manifest_parsed
        .map(|m| m.capabilities.clone())
        .unwrap_or_default();
    native_ffi_consent::gate(&resolved.inferred, &granted, &provenance)
}

/// Collect `(dotted-module-name, source)` pairs spanning the app entry and its
/// siblings (and, when a manifest is present, every discovered package module),
/// for the web-axis provenance scan. Discovery failures propagate, exactly as
/// in the `.Unsafe` scan; see [`loose_file_scan_sources`].
pub fn named_sources_for_web_scan(
    manifest_path: Option<&Path>,
    entry: &Path,
) -> Result<Vec<(String, String)>, CliError> {
    if let Some(mpath) = manifest_path
        && let Ok(manifest) = project::parse_manifest(mpath)
    {
        let discovered = project::discover_modules(&manifest.src_root)?;
        let mut out = Vec::with_capacity(discovered.len());
        for m in &discovered {
            let src = crate::io_bounded::read_walked_source(m.path())?;
            out.push((m.module_path().join("."), src));
        }
        return Ok(out);
    }
    loose_file_scan_sources(entry)
}

/// Type-check a single `.ipe` entry through the SAME injection-aware
/// source-graph pipeline the build path uses, stopping at type-checking: it
/// demands the `typecheck` query (parse → canon → link → HM infer) and never
/// lowers to IR or emits Rust. This is what `ipe type-check` runs.
///
/// # Errors
/// [`CliError::Pipeline`] carrying the first compiler diagnostic;
/// [`CliError::Io`] when a source file cannot be read.
pub fn typecheck_entry_via_graph(entry: &Path) -> Result<(), CliError> {
    typecheck_graph(&build_source_graph(entry)?, entry)
}

/// The `tests/`-rooted sibling of [`typecheck_entry_via_graph`]: type-check a
/// test entry over the `tests ∪ src` module set [`build_source_graph_for_test`]
/// builds, so a test-only type error is caught by `ipe type-check` the same way
/// a src-tree error is.
///
/// # Errors
/// Same as [`typecheck_entry_via_graph`].
pub fn typecheck_test_entry_via_graph(
    project_src_root: &Path,
    tests_root: &Path,
    test_entry: &Path,
) -> Result<(), CliError> {
    typecheck_graph(
        &build_source_graph_for_test(project_src_root, tests_root, test_entry)?,
        test_entry,
    )
}

/// The manifest-rooted sibling of [`typecheck_entry_via_graph`]: type-check a
/// nested, non-entry file over the src-rooted module set
/// [`build_source_graph_for_manifest_file`] builds, so its imports resolve
/// against the project's real `src_root` rather than the file's own directory.
///
/// # Errors
/// Same as [`typecheck_entry_via_graph`].
pub fn typecheck_manifest_file_via_graph(src_root: &Path, entry: &Path) -> Result<(), CliError> {
    typecheck_graph(
        &build_source_graph_for_manifest_file(src_root, entry)?,
        entry,
    )
}

/// The [`typecheck_entry_via_graph`] / [`typecheck_test_entry_via_graph`]
/// shared core: type-check the given graph, then run the same IPE-N0040
/// decoder-direction gate the build path runs.
///
/// # Errors
/// [`CliError::Pipeline`] carrying the first compiler diagnostic.
fn typecheck_graph(graph: &SourceGraph, blame_path: &Path) -> Result<(), CliError> {
    graph.run_attributed(blame_path, |db, root, file| {
        // Type-check first so an ordinary type error surfaces ahead of the
        // decoder-direction gate; then run the SAME IPE-N0040 gate the build
        // path runs (`gate_decoder_pipelines`) over the linked module, so
        // `ipe type-check` rejects the hand-nested decoder footgun for the
        // earliest possible feedback rather than deferring it to `ipe dev build`.
        let linked = ipe_db::linked_program(db, root, file)
            .clone()
            .map_err(|d| ipe_db::PipelineError::Lower(d, Vec::new()))?;
        ipe_db::typecheck(db, root, file)
            .clone()
            .map_err(ipe_db::PipelineError::from)?;
        gate_decoder_pipelines(&linked.module)
    })
}

/// Judge one loose `.ipe` entry through the whole build front end, short of cargo.
///
/// The entry's source graph is built as [`build_source_graph`] builds it, then
/// run through [`compile_prepared`], the same canonicalise, link, target-gate,
/// type-check, decoder-direction-gate, lower and emit pipeline `ipe dev build`
/// runs, under a native development configuration. A refusal from any stage,
/// lowering and emit included, surfaces as the first diagnostic, so a caller
/// comparing its code sees the stage that actually refused the program. No
/// project is written and cargo never runs.
///
/// # Errors
/// [`CliError::Pipeline`] carrying the first compiler diagnostic;
/// [`CliError::Io`] when a source file cannot be read.
pub fn front_check_entry(entry: &Path) -> Result<(), CliError> {
    let graph = build_source_graph(entry)?;
    let config = ipe_db::BuildConfig::new(
        &graph.db,
        ipe_backend_rust::DbDriver::default(),
        None,
        ipe_ir::Target::Native,
        Vec::new(),
        false,
        ipe_backend_rust::BuildIntent::Development,
        None,
        false,
        String::new(),
        false,
        false,
    );
    compile_prepared(
        &graph.db,
        graph.source_root,
        &graph.sources,
        &graph.entry_module_path,
        entry,
        config,
    )?;
    Ok(())
}

/// Type-check the entry an [`AnalysisTarget`] names, dispatching to the `src`-
/// rooted or `tests ∪ src`-rooted graph builder depending on the variant —
/// the one place every `resolve_analysis_target` caller routes through so a
/// FILE argument is always analysed as itself.
///
/// # Errors
/// Same as [`typecheck_entry_via_graph`].
pub fn typecheck_target(target: &AnalysisTarget) -> Result<(), CliError> {
    match target {
        AnalysisTarget::Loose(file) => typecheck_entry_via_graph(file.as_path()),
        AnalysisTarget::Source { file, src_root } => {
            typecheck_manifest_file_via_graph(src_root.as_path(), file.as_path())
        }
        AnalysisTarget::Test {
            file,
            src_root,
            tests_root,
        } => {
            typecheck_test_entry_via_graph(src_root.as_path(), tests_root.as_path(), file.as_path())
        }
    }
}

/// Build the source graph an [`AnalysisTarget`] names, returning it alongside
/// the path an attributed query should blame diagnostics against.
///
/// # Errors
/// Same as [`build_source_graph`].
pub fn source_graph_for_target(
    target: &AnalysisTarget,
) -> Result<(SourceGraph, PathBuf), CliError> {
    match target {
        AnalysisTarget::Loose(file) => Ok((
            build_source_graph(file.as_path())?,
            file.as_path().to_path_buf(),
        )),
        AnalysisTarget::Source { file, src_root } => Ok((
            build_source_graph_for_manifest_file(src_root.as_path(), file.as_path())?,
            file.as_path().to_path_buf(),
        )),
        AnalysisTarget::Test {
            file,
            src_root,
            tests_root,
        } => Ok((
            build_source_graph_for_test(src_root.as_path(), tests_root.as_path(), file.as_path())?,
            file.as_path().to_path_buf(),
        )),
    }
}

/// [`emit_ir_text`] over an [`AnalysisTarget`] rather than a bare entry path,
/// so `ipe dev build --emit-ir <file>` never substitutes the project's default
/// entry for a named file.
///
/// # Errors
/// Same as [`emit_ir_text`].
pub fn emit_ir_text_for_target(target: &AnalysisTarget) -> Result<String, CliError> {
    let (graph, blame_path) = source_graph_for_target(target)?;
    let program = graph.run_attributed(&blame_path, |db, root, file| {
        ipe_db::lower_program(db, root, file).clone()
    })?;
    let interner = ipe_db::Db::interner(&graph.db).lock();
    Ok(ipe_ir::pretty(&program, &interner))
}

#[cfg(test)]
mod artifact_name_tests {
    use super::{friendly_artifact_filename, friendly_artifact_name};

    // The delivered file name is the friendly name plus the host executable
    // suffix. This is the invariant that keeps `out/bin/<name>` and a released
    // binary runnable on Windows, where a suffix-less delivery is otherwise
    // invisible on Unix CI (empty `EXE_SUFFIX`).
    #[test]
    fn delivered_filename_carries_the_platform_exe_suffix() {
        let name = friendly_artifact_name(None);
        let file = friendly_artifact_filename(None);
        assert_eq!(file, format!("{name}{}", std::env::consts::EXE_SUFFIX));
        assert!(
            file.starts_with(&name),
            "the delivered file name extends the friendly name"
        );
    }
}

#[cfg(test)]
mod capability_resolution_once_tests {
    //! Whole-program capability inference is the costliest pre-build step, and
    //! its result is a trust-boundary fact: `build`, `run`, and `release` each
    //! resolve it exactly once and hand that one value to every consent gate and
    //! every enforcement artifact through the `ConsentedCapabilities` witness.
    //! These tripwires pin that no second resolution site creeps back into this
    //! module.

    const SOURCE: &str = include_str!("commands.rs");
    // Spelled in pieces so the needles never match this module's own text.
    const RESOLVE_CALL: &str = concat!("resolve", "_for_run(");
    const INFER_CALL: &str = concat!("infer_package", "_capabilities(");
    const CONSENT_CALL: &str = concat!("consent_to", "_capabilities(");

    /// The text of the `pub fn` named `name`, up to the next top-level `pub fn`.
    fn fn_body(name: &str) -> Option<&'static str> {
        let head = format!("\npub fn {name}(");
        let start = SOURCE.find(&head)?;
        let rest = SOURCE.get(start + head.len()..)?;
        let end = rest.find("\npub fn ").unwrap_or(rest.len());
        rest.get(..end)
    }

    #[test]
    fn capability_resolution_has_one_consent_site() {
        // `consent_to_capabilities` (dev build / dev run / release build) is the
        // one resolution site; `ipe capabilities` is the inspection form.
        assert_eq!(SOURCE.matches(RESOLVE_CALL).count(), 1);
        assert_eq!(SOURCE.matches(INFER_CALL).count(), 0);
        for site in ["consent_to_capabilities"] {
            let body = fn_body(site);
            assert!(body.is_some(), "{site} is defined in this module");
            let Some(body) = body else { return };
            assert_eq!(body.matches(RESOLVE_CALL).count(), 1, "{site}");
        }
    }

    #[test]
    fn build_run_release_each_consent_exactly_once() {
        for entry_point in ["run_build_body", "release_pipeline", "run_run_with_args"] {
            let body = fn_body(entry_point);
            assert!(body.is_some(), "{entry_point} is defined in this module");
            let Some(body) = body else { return };
            assert_eq!(
                body.matches(CONSENT_CALL).count(),
                1,
                "{entry_point} resolves and consents to its capabilities exactly once"
            );
            assert_eq!(body.matches(RESOLVE_CALL).count(), 0, "{entry_point}");
        }
    }
}

#[cfg(test)]
#[cfg(unix)]
mod held_crate_tests {
    //! A tool that writes into a claimed crate by path is proven, once it exits,
    //! to have written into that same crate: a crate directory swapped while
    //! `cargo`, `wasm-bindgen` or `wasm-opt` ran fails the build closed, and no
    //! output of the swapped run is handed back.

    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    use super::{WasmTools, bundle_wasm_pkg};
    use crate::CliError;
    use crate::cargo_step::{
        CargoBuild, CargoCrate, CargoOutput, CargoProfile, CargoTarget, Verbosity,
    };
    use crate::output_dir::{OutputRefusal, OwnedDir};
    use crate::toolchain::CargoBin;

    /// A fresh scratch base for `tag`, holding a claimed `crate/`.
    fn scratch(tag: &str) -> (PathBuf, OwnedDir) {
        let base =
            ipe_test_temp::temp_root().join(format!("ipe-held-crate-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("scratch base");
        let crate_dir = OwnedDir::claim(&base.join("crate")).expect("claim crate");
        (base, crate_dir)
    }

    /// An executable `sh` stub `name` under `base` that runs `body`.
    fn stub(base: &Path, name: &str, body: &str) -> PathBuf {
        let path = base.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write stub");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("stub executable");
        path
    }

    /// The shell step that moves the crate aside and makes a fresh one at its path.
    fn swap(crate_dir: &OwnedDir) -> String {
        let p = crate_dir.path().display();
        format!("mv '{p}' '{p}.aside' && mkdir '{p}'")
    }

    /// Whether `result` is the replaced-crate refusal.
    const fn replaced<T>(result: &Result<T, CliError>) -> bool {
        matches!(
            result,
            Err(CliError::OutputRefused(OutputRefusal::Replaced(_)))
        )
    }

    /// A stub `cargo` that locks, builds, and prints one artifact line after `during`.
    fn cargo_stub(base: &Path, during: &str) -> PathBuf {
        stub(
            base,
            "cargo",
            &format!(
                "[ \"$1\" = generate-lockfile ] && exit 0\n{during}\n\
                 echo '{{\"reason\":\"compiler-artifact\",\"executable\":\"/x\"}}'"
            ),
        )
    }

    /// A quiet host build of `crate_dir` through `cargo`, its artifact stream returned.
    fn build_with(cargo: &Path, crate_dir: &OwnedDir) -> Result<String, CliError> {
        CargoBuild {
            cargo: &CargoBin::stub(cargo.to_path_buf()),
            krate: CargoCrate::Emitted(crate_dir),
            profile: CargoProfile::Dev,
            target: CargoTarget::Host,
            output: CargoOutput::JsonStream(Verbosity::Quiet),
            what: "the emitted program",
            runtime: None,
        }
        .run()
    }

    /// A crate replaced while `cargo` built it is refused, its artifact stream dropped.
    #[test]
    fn a_crate_replaced_during_the_cargo_build_is_refused() {
        let (base, crate_dir) = scratch("cargo-swap");
        let cargo = cargo_stub(&base, &swap(&crate_dir));
        let built = build_with(&cargo, &crate_dir);
        assert!(
            replaced(&built),
            "a swapped crate must fail closed with no executable, got {built:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The same build over an untouched crate hands its artifact stream back.
    #[test]
    fn an_untouched_crate_build_returns_its_artifact_stream() {
        let (base, crate_dir) = scratch("cargo-ok");
        let cargo = cargo_stub(&base, "true");
        let built = build_with(&cargo, &crate_dir);
        assert!(
            built
                .as_ref()
                .is_ok_and(|out| out.contains("compiler-artifact")),
            "an untouched crate builds, got {built:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Run [`bundle_wasm_pkg`] over `crate_dir` with stub tools running the given bodies.
    fn bundle_with(
        base: &Path,
        crate_dir: &OwnedDir,
        bindgen: &str,
        opt: &str,
    ) -> Result<(), CliError> {
        let bindgen = stub(base, "wasm-bindgen", bindgen);
        let opt = stub(base, "wasm-opt", opt);
        bundle_wasm_pkg(
            crate_dir,
            &base.join("ipe_app.wasm"),
            &WasmTools {
                bindgen: &bindgen,
                opt: &opt,
            },
        )
    }

    /// The `wasm-bindgen` stub body that writes the bundle into its `--out-dir`.
    const WRITE_BUNDLE: &str = "touch \"$6/ipe_app_bg.wasm\"";

    /// A crate replaced while `wasm-bindgen` wrote the bundle is refused.
    #[test]
    fn a_crate_replaced_during_wasm_bindgen_is_refused() {
        let (base, crate_dir) = scratch("bindgen-swap");
        let bundled = bundle_with(&base, &crate_dir, &swap(&crate_dir), "exit 0");
        assert!(replaced(&bundled), "got {bundled:?}");
        assert!(
            !crate_dir.path().join("www").exists(),
            "nothing is written into the replacement"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A crate replaced while `wasm-opt` rewrote the bundle is refused.
    #[test]
    fn a_crate_replaced_during_wasm_opt_is_refused() {
        let (base, crate_dir) = scratch("opt-swap");
        let bundled = bundle_with(&base, &crate_dir, WRITE_BUNDLE, &swap(&crate_dir));
        assert!(replaced(&bundled), "got {bundled:?}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Both tools over an untouched crate leave the bundle in its `www/pkg/`.
    #[test]
    fn an_untouched_crate_bundles_into_its_pkg() {
        let (base, crate_dir) = scratch("wasm-ok");
        let bundled = bundle_with(&base, &crate_dir, WRITE_BUNDLE, "exit 0");
        assert!(
            bundled.is_ok(),
            "an untouched crate bundles, got {bundled:?}"
        );
        let bundle = crate_dir
            .path()
            .join("www")
            .join("pkg")
            .join("ipe_app_bg.wasm");
        assert!(bundle.is_file(), "the bundle lands in the owned crate");
        let _ = std::fs::remove_dir_all(&base);
    }
}

#[cfg(test)]
mod help_on_misuse_tests {
    use super::{RELEASE_WRAPPER, prebuilt_artifact_dir, with_help_on_misuse, wrapper_argv};
    use crate::CliError;
    use crate::ffi::FfiPrepError;
    use crate::verb::Verb;
    use crate::{package_manifest, project};

    /// An FFI prep refusal is not command misuse: it passes through without the help page.
    #[test]
    fn with_help_on_misuse_leaves_ffi_prep_untouched() {
        let refusal = || FfiPrepError::DefineOpaqueCollision {
            slug: "a".to_owned(),
            name: "T".to_owned(),
        };
        let got = with_help_on_misuse(Verb::DEV_BUILD, Err(CliError::FfiPrep(Box::new(refusal()))));
        assert!(
            matches!(&got, Err(CliError::FfiPrep(inner)) if **inner == refusal()),
            "{got:?}"
        );
    }

    /// A directory with a project manifest is a project, never an artifact:
    /// a planted wrapper beside `package.ipe` or `ipe.toml` is not what
    /// `release run` runs. The same directory without a manifest is one.
    #[test]
    fn a_project_dir_is_never_a_prebuilt_artifact() {
        let tmp = ipe_test_temp::temp_root()
            .join(format!("ipec-prebuilt-project-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("create dir");
        std::fs::write(tmp.join(RELEASE_WRAPPER), b"").expect("write wrapper");
        let dir = tmp.to_string_lossy().into_owned();
        let bare = prebuilt_artifact_dir(Some(dir.as_str())).is_some();
        std::fs::write(tmp.join(package_manifest::PACKAGE_IPE), b"").expect("write manifest");
        let with_package = prebuilt_artifact_dir(Some(dir.as_str())).is_some();
        std::fs::remove_file(tmp.join(package_manifest::PACKAGE_IPE)).expect("remove manifest");
        std::fs::write(tmp.join(project::IPE_TOML), b"").expect("write legacy manifest");
        let with_toml = prebuilt_artifact_dir(Some(dir.as_str())).is_some();
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(
            bare,
            "a wrapper-bearing dir with no manifest is an artifact dir"
        );
        assert!(!with_package, "a dir with package.ipe is a project");
        assert!(!with_toml, "a dir with ipe.toml is a project");
    }

    /// Every app argument reaches the embed-mode app, wrapper flags and a
    /// second `--` included.
    #[test]
    fn wrapper_argv_puts_every_app_argument_behind_the_separator() {
        let os = |words: &[&str]| -> Vec<std::ffi::OsString> {
            words.iter().map(std::ffi::OsString::from).collect()
        };
        let argv = wrapper_argv(&os(&["--show-profile", "a", "--", "b"]));
        let expected = os(&["--", "--show-profile", "a", "--", "b"]);
        assert_eq!(argv, expected);
        assert_eq!(wrapper_argv(&[]), vec![std::ffi::OsString::from("--")]);
    }
}
