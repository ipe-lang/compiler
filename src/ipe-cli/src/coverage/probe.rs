//! The per-symbol probe: generate a minimal program that references a symbol,
//! and lower / build / run it.
//!
//! A symbol that type-checks but does not lower, or lowers but does not build or
//! run, is the seam the dynamic columns close. The generator emits the smallest
//! program that forces the symbol through the requested stage: a top-level
//! binding to the symbol as a first-class value (which the resolver must resolve
//! and the lowerer must lower), and — for a higher-order symbol — a nested-in-a-
//! closure form that forces the lowerer to descend into the combinator in a
//! nested position, the shape a composed combinator that type-checked but never
//! lowered failed on.
//!
//! The generator references the symbol as a value rather than fully applying it,
//! so it need not fabricate well-typed arguments from an arbitrary scheme: a
//! point-free reference is enough to force name-resolution and lowering, and it
//! cannot manufacture a spurious type error the way a guessed application could.

use std::fmt::Write as _;
use std::path::Path;

use crate::coverage::contract::StdlibSymbol;

/// The browser web axis a symbol's module discloses, when it lives under a
/// reserved `Ipe.Browser.<Api>` module — the structural property that makes a
/// standalone build+run inapplicable to it.
///
/// A symbol homed under `Ipe.Browser.*` binds client-side browser JavaScript
/// (a `js-port:<axis>` capability): its emitted crate serves JS that runs in a
/// live browser page, and merely referencing it discloses the axis to the
/// app-boundary consent gate (`IPE-S0002`), which a bare single-file probe with
/// no `package.ipe` grant cannot satisfy. Even granted, the axis has no server
/// process to exercise — the effect lives in the page, not in the emitted binary —
/// so a standalone build+run cannot RUN it. The web axis is read from the module
/// path through the compiler-owned reserved-namespace SSOT
/// ([`ipe_kernels::WebCapability::for_browser_module`]), never a hand-kept symbol
/// list, so it derives from a real structural property of the symbol.
#[must_use]
pub fn browser_web_axis(sym: &StdlibSymbol) -> Option<ipe_kernels::WebCapability> {
    let segments: Vec<&str> = sym.module.iter().map(String::as_str).collect();
    ipe_kernels::WebCapability::for_browser_module(&segments)
}

/// Why a probe could not be formed for a symbol — distinct from a stage failure,
/// so a symbol the generator cannot express is reported as inapplicable rather
/// than as a false hole.
#[derive(Clone, Debug)]
pub enum ProbeUnavailable {
    /// The symbol is not a value (a type or constructor) — the value-reference
    /// probe does not apply.
    NotAValue,
    /// The symbol is not reachable by a qualified reference (no compiled-source
    /// module to import it from).
    Unaddressable,
}

/// The outcome of driving a probe through one stage.
#[derive(Clone, Debug)]
pub enum StageOutcome {
    /// The stage succeeded.
    Ok,
    /// The stage failed, carrying the rejecting diagnostic's code (when the
    /// failure is a compiler diagnostic rather than a process/IO error) and its
    /// rendered message. The code lets a column tell a genuine stage gap from a
    /// failure the probe FORM provokes — a point-free reference of a value the
    /// language requires be applied directly, whose diagnostic is a limitation of
    /// the probe, not a gap in the symbol.
    Failed {
        /// The rejecting diagnostic's code, when the failure carried one.
        code: Option<ipe_diagnostics::Code>,
        /// The rendered failure message.
        message: String,
    },
}

/// The diagnostic code a [`crate::CliError`] carries, when it is a pipeline
/// rejection (the only variant framing a compiler diagnostic).
fn cli_error_code(err: &crate::CliError) -> Option<ipe_diagnostics::Code> {
    match err {
        crate::CliError::Pipeline { diag, .. } => Some(diag.code()),
        _ => None,
    }
}

/// Whether a lowering rejection is a limitation of the probe FORM for the symbol
/// rather than a lowering gap in the symbol.
///
/// A value-reference / nested-reference probe binds the symbol point-free. For a
/// class of symbols the language deliberately refuses a point-free reference — an
/// accessor/spec builder that reads its column from a `.field` at compile time
/// ([`IPE_L0146`]), a committed-literal seal that must see its argument
/// ([`IPE_L0151`]), a handler-wrapping kernel that must see its handler
/// ([`IPE_L0152`]) — or the reference cannot be monomorphized because an unused
/// binding leaves the value fully polymorphic ([`IPE_L0102`]). In each the
/// diagnostic is provoked by the probe form, not by a gap in the symbol's own
/// lowering, so the column reports the symbol inapplicable rather than a false
/// hole. This is exactly the "the resolver refuses to pass point-free" /
/// "fully-polymorphic value with no determinable concrete type" case the columns'
/// contracts name. A non-`Clone` handler capture ([`IPE_L0126`]) is NOT in this
/// class: it is a property of the program, so it stays a hole.
#[must_use]
pub fn is_probe_form_limitation(outcome: &StageOutcome) -> bool {
    use ipe_diagnostics::{IPE_L0102, IPE_L0146, IPE_L0151, IPE_L0152};
    matches!(
        outcome,
        StageOutcome::Failed { code: Some(code), .. }
            if *code == IPE_L0102
                || *code == IPE_L0146
                || *code == IPE_L0151
                || *code == IPE_L0152
    )
}

/// The name-resolution rejection code, when a probe fails to even NAME-RESOLVE
/// because the point-free reference form cannot address the symbol — distinct
/// from a lowering gap.
///
/// A value-reference probe imports the symbol's module qualified and binds it
/// point-free. For a class of symbols that reference form cannot be formed at the
/// name-resolution layer at all:
///
/// * [`IPE_N0020`] / [`IPE_N0004`] — the symbol's module has no standalone
///   importable home on disk (a shape-scoped module reached only through an app
///   shape, e.g. `Ipe.Cmd` / `Ipe.Sub`), so the generated `import` finds nothing.
/// * [`IPE_N0023`] — the module path does not match the probe module name.
///
/// In each the rejection is a property of the point-free probe FORM for that
/// symbol — the reference cannot be addressed — not a build+run gap, so the
/// build+run column reports the symbol inapplicable rather than a false hole. This
/// is the name-resolution sibling of [`is_probe_form_limitation`] (which classifies
/// the lowering-layer point-free limitations), and it carries the offending code so
/// the verdict names exactly why the probe form does not apply.
///
/// [`IPE_N0027`] (a qualified-import qualifier collision) and [`IPE_N0005`] (the
/// module has no member of that name) are deliberately NOT in this set. The probe
/// imports every module under a fixed reserved alias ([`PROBE_ALIAS`]) that cannot
/// collide with any real module qualifier, so a genuine N0027 no longer arises from
/// the probe form; and every kernel's canonical surface is backed by a compiled-source
/// member, so an N0005 here signals a real phantom-surface defect (the class fixed by
/// homing the custom-element node at `CustomElement.node`), not a probe-form
/// limitation. Whitelisting either would mask a real resolution defect rather than
/// name a probe-form limitation.
#[must_use]
pub fn probe_form_unaddressable_code(outcome: &StageOutcome) -> Option<ipe_diagnostics::Code> {
    use ipe_diagnostics::{IPE_N0004, IPE_N0020, IPE_N0023};
    match outcome {
        StageOutcome::Failed {
            code: Some(code), ..
        } if *code == IPE_N0020 || *code == IPE_N0004 || *code == IPE_N0023 => Some(*code),
        _ => None,
    }
}

/// Whether a lowering rejection is an internal compiler error ([`IPE_I0001`]).
///
/// An ICE is a compiler bug the probe surfaced, distinct both from a clean stage
/// gap and from a probe-form limitation. The columns surface it as an advisory, so
/// a pre-existing lowerer defect the probe reaches is reported without being
/// silently passed or miscast as the column's own seam.
#[must_use]
pub fn is_internal_compiler_error(outcome: &StageOutcome) -> bool {
    use ipe_diagnostics::IPE_I0001;
    matches!(
        outcome,
        StageOutcome::Failed { code: Some(code), .. } if *code == IPE_I0001
    )
}

/// The fixed reserved import alias every probe qualifies its symbol under.
///
/// The probe references the symbol qualified (`Probe_q.map`) so it resolves the
/// exact surface member without an `exposing (..)` widening that could mask a
/// resolution gap behind a re-export. The alias must be a single fixed token that
/// cannot collide with any real module qualifier: deriving it from the module's
/// last dotted segment (as an earlier form did) let a deeply-nested module's short
/// qualifier collide with a different real in-scope module and self-report a
/// spurious [`IPE_N0027`] (e.g. `Ipe.Http.Server` → `Server`), which then masked a
/// genuinely build+runnable symbol as inapplicable. A module qualifier must be
/// capitalised (the resolver rejects a lowercase alias), and no real stdlib module
/// leaf is spelled `Probe_q`, so this token addresses every module collision-free.
const PROBE_ALIAS: &str = "Probe_q";

/// A probe's qualified import: the module's dotted path and the fixed reserved
/// alias it is bound under. A typed pair (rather than a bare `(String, &str)`)
/// names each field at every call site, so a probe cannot transpose the dotted
/// path and the alias.
struct ProbeImport {
    /// The symbol's module as a dotted path, e.g. `Ipe.Http.Server`.
    dotted: String,
}

/// The qualified import for a symbol, or `None` when the symbol has no module
/// path to import from.
///
/// The alias is always the fixed collision-proof [`PROBE_ALIAS`]; only the dotted
/// module path varies per symbol.
fn import_header(sym: &StdlibSymbol) -> Option<ProbeImport> {
    let dotted = sym.module.join(".");
    if dotted.is_empty() {
        return None;
    }
    Some(ProbeImport { dotted })
}

/// Generate a minimal module that binds the symbol as a first-class value,
/// forcing the resolver and lowerer to reach it.
///
/// `probe = <Short>.<name>` — a point-free reference. The `main` entry is a
/// minimal valid task so the module is a complete, buildable program when the
/// build column asks for it.
///
/// # Errors
/// [`ProbeUnavailable`] when the symbol is not a value or cannot be addressed by
/// a qualified import.
pub fn reference_program(sym: &StdlibSymbol) -> Result<String, ProbeUnavailable> {
    use crate::coverage::contract::SymbolKind;
    if sym.kind != SymbolKind::Value {
        return Err(ProbeUnavailable::NotAValue);
    }
    let Some(ProbeImport { dotted }) = import_header(sym) else {
        return Err(ProbeUnavailable::Unaddressable);
    };
    let mut out = String::from("module Main exposing (main)\n\n");
    let _ = writeln!(out, "import {dotted} as {PROBE_ALIAS}");
    out.push_str("import Ipe.Io as Io\n\n");
    let _ = writeln!(out, "probe = {PROBE_ALIAS}.{name}", name = sym.name);
    out.push_str("\nmain : Task Error ()\n");
    out.push_str("main = Io.println \"\"\n");
    Ok(out)
}

/// Generate a module that references the symbol in a NESTED closure position.
///
/// This forces the lowerer to descend into the combinator inside another
/// combinator — the composition shape a symbol that type-checked but did not
/// lower failed on.
///
/// `probe = List.map (\_ -> <Short>.<name>) []` nests the reference inside a
/// lambda passed to `List.map`; the lowerer must walk into the lambda body and
/// lower the combinator there. This is a value reference nested two constructs
/// deep, so it stays well-typed for any value symbol without fabricating typed
/// arguments, while still exercising the descend-into-nested-position path.
///
/// # Errors
/// [`ProbeUnavailable`] as for [`reference_program`].
pub fn nested_program(sym: &StdlibSymbol) -> Result<String, ProbeUnavailable> {
    use crate::coverage::contract::SymbolKind;
    if sym.kind != SymbolKind::Value {
        return Err(ProbeUnavailable::NotAValue);
    }
    let Some(ProbeImport { dotted }) = import_header(sym) else {
        return Err(ProbeUnavailable::Unaddressable);
    };
    let mut out = String::from("module Main exposing (main)\n\n");
    let _ = writeln!(out, "import {dotted} as {PROBE_ALIAS}");
    out.push_str("import Ipe.List as List\n");
    out.push_str("import Ipe.Io as Io\n\n");
    let _ = writeln!(
        out,
        "probe = List.map (\\_ -> {PROBE_ALIAS}.{name}) []",
        name = sym.name
    );
    out.push_str("\nmain : Task Error ()\n");
    out.push_str("main = Io.println \"\"\n");
    Ok(out)
}

/// Lower a probe program, returning whether it lowered.
///
/// Writes the source to `snippet` and drives it through the same source-graph
/// lowering pipeline `ipe build --emit-ir` uses (name-resolution + type-check +
/// lower), so a symbol that resolves and type-checks but does not lower is
/// reported as a stage failure.
#[must_use]
pub fn lower(source: &str, snippet: &Path) -> StageOutcome {
    if let Err(message) = write_probe_source(snippet, source) {
        return StageOutcome::Failed {
            code: None,
            message,
        };
    }
    match crate::lower_entry_via_graph(snippet) {
        Ok(_) => StageOutcome::Ok,
        Err(err) => StageOutcome::Failed {
            code: cli_error_code(&err),
            message: err.to_string(),
        },
    }
}

/// Write a probe source file, first ensuring its parent directory exists.
///
/// The parent is a scratch dir shared across a whole column run; recreating it
/// before each write makes a probe resilient to a transient removal (a sibling's
/// cleanup, an emitted-crate step that rewrites the tree) rather than reporting a
/// spurious stage failure.
fn write_probe_source(snippet: &Path, source: &str) -> Result<(), String> {
    if let Some(parent) = snippet.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("could not create the probe scratch directory: {e}"))?;
    }
    std::fs::write(snippet, source).map_err(|e| format!("could not write probe source: {e}"))
}

/// Type-check a probe program, returning whether it type-checks.
///
/// The precondition a generated nested probe relies on: if the value-reference
/// form does not even type-check, the generator (not the symbol) is at fault, so
/// the nested-lowering column reports the symbol inapplicable rather than a false
/// hole.
#[must_use]
pub fn typechecks(source: &str, snippet: &Path) -> StageOutcome {
    if let Err(message) = write_probe_source(snippet, source) {
        return StageOutcome::Failed {
            code: None,
            message,
        };
    }
    match crate::typecheck_entry_via_graph(snippet) {
        Ok(()) => StageOutcome::Ok,
        Err(err) => StageOutcome::Failed {
            code: cli_error_code(&err),
            message: err.to_string(),
        },
    }
}

/// The env var naming the warm shared cargo target the emitted per-probe build
/// links its dependency tree from, set by the CI e2e / seal-slice jobs. Mirrors
/// the golden E2E harness (`tools/e2e-support`), which reads the same variable.
const ORACLE_SHARED_TARGET: &str = "IPE_ORACLE_SHARED_TARGET";

/// The env var naming a unique emitted-crate package name, honoured by the
/// single-file `ipe run` emit ([`crate::driver::single_file_cargo_name_from_env`]).
const EMIT_PACKAGE_NAME: &str = "IPE_EMIT_PACKAGE_NAME";

/// Locate the `ipe` binary the probe drives `ipe run` through.
///
/// Cargo sets `CARGO_BIN_EXE_ipe` in every integration test's environment,
/// pointing at the compiled `ipe` binary — the one that must run the probe. That
/// is preferred over [`std::env::current_exe`], which under an integration test
/// is the TEST-harness binary, not `ipe`: re-invoking the harness with `run`
/// would run libtest (re-entering the very coverage test, or rejecting the
/// arguments) rather than compiling the probe. `current_exe` is the fallback for
/// the case the coverage matrix is driven directly by the `ipe` binary itself
/// (where it already is `ipe`).
///
/// # Errors
/// The rendered failure when neither source yields a path.
fn ipe_binary() -> Result<std::path::PathBuf, String> {
    if let Some(p) = std::env::var_os("CARGO_BIN_EXE_ipe") {
        return Ok(std::path::PathBuf::from(p));
    }
    std::env::current_exe().map_err(|e| format!("could not locate the ipe binary: {e}"))
}

/// The warm shared cargo target for the emitted probe build, or `None` to
/// inherit the ambient env (isolate).
///
/// Returns `Some(path)` only when `IPE_ORACLE_SHARED_TARGET` is a non-empty
/// absolute path; anything else (absent, relative, whitespace) returns `None`.
/// This is the same fail-safe the golden harness applies: a relative or empty
/// value never silently pins the build to a surprising target.
fn shared_dep_target() -> Option<String> {
    let raw = std::env::var(ORACLE_SHARED_TARGET).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() || !Path::new(trimmed).is_absolute() {
        return None;
    }
    Some(trimmed.to_owned())
}

/// A process-monotonic counter giving every probe build a distinct identity.
///
/// The columns share ONE scratch dir across a run, so a per-probe working
/// directory and package name cannot be derived from the (constant) snippet
/// path alone. This counter names each probe's own working subdirectory and
/// emitted crate, so no two probes collide in the shared cargo target.
static PROBE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A cargo-package-safe, unique-per-probe crate name for the probe `seq`.
///
/// `sanitize_cargo_name` maps the token to a valid Cargo package name. The
/// distinct `seq` per probe keeps each emitted app crate's cargo fingerprint on
/// its own package id, so a shared target reuses only dependency artifacts and
/// never masks a broken emit.
fn unique_package_name(seq: u64) -> String {
    ipe_backend_rust::sanitize_cargo_name(&format!("ipe-probe-{seq}"))
}

/// Build and RUN a probe program, returning whether the emitted crate builds and
/// the produced binary runs to a zero exit.
///
/// Re-invokes this binary as `ipe run <snippet>` from a per-probe working
/// directory — the same emit → cargo build → execute path a user's `ipe run`
/// takes — so a symbol whose program emits and type-checks but whose emitted
/// crate does not build or whose binary does not run is a real gap. Heavy: the
/// caller gates this behind the E2E path.
///
/// Each probe runs from its OWN working directory beside the snippet, so the
/// default emitted-project dir (`out/rust`, resolved against the working dir)
/// never collides with a sibling probe nor leaks an `out/` tree into the test's
/// cwd. When the CI warm shared cargo target is offered
/// (`IPE_ORACLE_SHARED_TARGET`) the emitted build links its heavy dependency
/// tree from that pre-built target instead of cold-compiling it per symbol.
/// Soundness is preserved by giving each probe a UNIQUE emitted-crate package
/// name (`IPE_EMIT_PACKAGE_NAME`): cargo fingerprints an app crate on its own
/// source hash under its own package id, so a genuinely broken emit still fails
/// to build even against a warm target — the shared target reuses only
/// DEPENDENCY artifacts, never masking a broken app. Without the shared-target
/// env the build inherits the ambient target unchanged (a local `ipe run` is
/// untouched).
///
/// The emit location is selected by the subprocess working directory rather
/// than a `--out` flag, so the invocation surface stays exactly the plain
/// `ipe run <snippet>` — the entry is passed absolute, and `out/rust` resolves
/// under the per-probe working directory.
#[must_use]
pub fn build_and_run(source: &str, snippet: &Path) -> StageOutcome {
    use std::process::Command;
    if let Err(message) = write_probe_source(snippet, source) {
        return StageOutcome::Failed {
            code: None,
            message,
        };
    }
    let ipe_bin = match ipe_binary() {
        Ok(p) => p,
        Err(message) => {
            return StageOutcome::Failed {
                code: None,
                message,
            };
        }
    };

    // A unique per-probe identity: the columns share ONE scratch dir, so a
    // monotonic sequence names both this probe's own working subdirectory and
    // its emitted crate. The working subdir under the shared scratch keeps the
    // default `out/rust` emit unique per probe (self-cleaning with the scratch
    // dir, never an `out/` tree in the test's cwd), and the crate name keeps the
    // app-crate fingerprint distinct in the shared cargo target.
    let seq = PROBE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let package_name = unique_package_name(seq);
    let work_dir = snippet
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("probe-{seq}"));
    if let Err(e) = std::fs::create_dir_all(&work_dir) {
        return StageOutcome::Failed {
            code: None,
            message: format!("could not create the probe working directory: {e}"),
        };
    }

    // `ipe run` reads the snippet by an absolute path so it resolves regardless
    // of the working directory the subprocess is launched in.
    let entry = match std::path::absolute(snippet) {
        Ok(p) => p,
        Err(e) => {
            return StageOutcome::Failed {
                code: None,
                message: format!("could not resolve the probe snippet path: {e}"),
            };
        }
    };

    let mut cmd = Command::new(&ipe_bin);
    cmd.arg("run")
        .arg(&entry)
        .current_dir(&work_dir)
        .env(EMIT_PACKAGE_NAME, &package_name);
    // Link the heavy dependency tree from the warm shared target when the CI
    // job offers one; otherwise inherit the ambient env (isolate — the default
    // for a local run).
    if let Some(target) = shared_dep_target() {
        cmd.env("CARGO_TARGET_DIR", target);
    }

    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            return StageOutcome::Failed {
                code: None,
                message: format!("ipe run failed to spawn: {e}"),
            };
        }
    };
    if output.status.success() {
        StageOutcome::Ok
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        StageOutcome::Failed {
            code: None,
            message: format!("ipe run exited non-zero: {stderr}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{StageOutcome, is_probe_form_limitation};

    fn failed_with(code: ipe_diagnostics::Code) -> StageOutcome {
        StageOutcome::Failed {
            code: Some(code),
            message: String::new(),
        }
    }

    /// Every point-free refusal the language imposes by design is a probe-form limitation.
    #[test]
    fn point_free_refusals_are_probe_form_limitations() {
        for code in [
            ipe_diagnostics::IPE_L0102,
            ipe_diagnostics::IPE_L0146,
            ipe_diagnostics::IPE_L0151,
            ipe_diagnostics::IPE_L0152,
        ] {
            assert!(
                is_probe_form_limitation(&failed_with(code)),
                "{} must classify as a probe-form limitation",
                code.as_str()
            );
        }
    }

    /// A non-`Clone` capture refusal is a genuine hole, never masked as a probe-form limitation.
    #[test]
    fn non_clone_capture_is_not_a_probe_form_limitation() {
        assert!(!is_probe_form_limitation(&failed_with(
            ipe_diagnostics::IPE_L0126
        )));
    }

    /// A success or a code-less failure is never a probe-form limitation.
    #[test]
    fn ok_and_codeless_failure_are_not_probe_form_limitations() {
        assert!(!is_probe_form_limitation(&StageOutcome::Ok));
        assert!(!is_probe_form_limitation(&StageOutcome::Failed {
            code: None,
            message: String::new(),
        }));
    }
}
