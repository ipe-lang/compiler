//! Whole-program capability inference.
//!
//! [`program_capabilities`] computes, from a lowered [`ipe_ir::Program`] alone,
//! the exact set of security capabilities it exercises: the union over the
//! program's transitively-reachable kernels of [`ipe_ir::KernelFn::capability`],
//! plus [`ipe_ir::Capability::NativeFfi`] when the program crosses into `Rust.`
//! code. The set is generated, not declared, and cannot drift — a kernel with no
//! capability classification is a compile error in `ipe_kernels`.

use std::collections::BTreeSet;

use ipe_ir::{Capability, Program, ServedListener};

pub use crate::lower::{ReachedCapabilities, capabilities_reached_from};

/// The security capabilities a program exercises, inferred from its reachable
/// kernels and any `Rust.` crossing.
///
/// Deterministic: the [`BTreeSet`] orders capabilities by their declared
/// [`Capability`] order, so the reported set is reproducible.
#[must_use]
pub fn program_capabilities(program: &Program) -> BTreeSet<Capability> {
    crate::lower::program_capabilities_scan(program)
}

/// The inbound listener a program opens, folded over its reachable serving
/// kernels.
///
/// Read from the built entry's lowered program, which is pruned to what its
/// `main` reaches: a serving kernel only an unreached function names leaves the
/// program unserved.
#[must_use]
pub fn program_served_listener(program: &Program) -> ServedListener {
    crate::lower::program_served_scan(program)
}

#[cfg(test)]
mod tests {
    use ipe_intern::Interner;
    use ipe_ir::{Capability, Program, ServedListener, ServedPort, SourcePortLiteral};

    use super::{program_capabilities, program_served_listener};

    /// Lower a single-module program and fold its served listener, or `None`
    /// if any pipeline stage rejects it.
    fn served_of(source: &str) -> Option<ServedListener> {
        let mut i = Interner::new();
        let src = ipe_parse::parse_module(source, &mut i).ok()?;
        let m = ipe_canon::canonicalise(&src, &mut i).ok()?;
        let types = ipe_types::infer(&m, &mut i).ok()?;
        let program: Program =
            crate::lower(&m, &types, &mut i, "", "", crate::Roots::Entry).ok()?;
        Some(program_served_listener(&program))
    }

    fn served_literal(n: i64) -> ServedListener {
        ServedListener::Serves(ServedPort::ServerLiteral(SourcePortLiteral::new(n)))
    }

    #[test]
    fn server_literal_port_folds_to_literal() {
        let served = served_of(
            "module Lib exposing (serve)\nimport Ipe.Server.Http as Server\nserve =\n    Server.listen 8000 []\n",
        );
        assert_eq!(served, Some(served_literal(8000)));
    }

    #[test]
    fn computed_port_folds_to_dynamic() {
        let served = served_of(
            "module Lib exposing (serve)\nimport Ipe.Server.Http as Server\nserve base =\n    Server.listen (base + 1) []\n",
        );
        assert_eq!(
            served,
            Some(ServedListener::Serves(ServedPort::ServerDynamic))
        );
    }

    #[test]
    fn two_literals_fold_to_dynamic() {
        let served = served_of(
            "module Lib exposing (a, b)\nimport Ipe.Server.Http as Server\na =\n    Server.listen 8000 []\nb =\n    Server.listen 9000 []\n",
        );
        assert_eq!(
            served,
            Some(ServedListener::Serves(ServedPort::ServerDynamic))
        );
    }

    #[test]
    fn eta_listen_folds_to_dynamic() {
        let served = served_of(
            "module Lib exposing (start)\nimport Ipe.Server.Http as Server\nstart =\n    Server.listen\n",
        );
        assert_eq!(
            served,
            Some(ServedListener::Serves(ServedPort::ServerDynamic))
        );
    }

    /// A `Server.listen` only an unreached function names leaves the entry
    /// unserved; the same call from `main` serves.
    #[test]
    fn unreached_listen_is_not_served() {
        let unreached = served_of(
            "module Main exposing (main)\nimport Ipe.System as System\nimport Ipe.Server.Http as Server\n\nmain =\n    System.setenv \"HOME\" \"x\"\n\nserve =\n    Server.listen 8000 []\n",
        );
        assert_eq!(unreached, Some(ServedListener::NotServed));
        let reached = served_of(
            "module Main exposing (main)\nimport Ipe.Server.Http as Server\n\nmain =\n    Server.listen 8000 []\n",
        );
        assert_eq!(reached, Some(served_literal(8000)));
    }

    /// Lower a free-standing single-module program, or `None` if any pipeline
    /// stage rejects it (the caller's assertions then fail, per the no-panic
    /// gate).
    fn caps_of(source: &str) -> Option<std::collections::BTreeSet<Capability>> {
        let mut i = Interner::new();
        let src = ipe_parse::parse_module(source, &mut i).ok()?;
        let m = ipe_canon::canonicalise(&src, &mut i).ok()?;
        let types = ipe_types::infer(&m, &mut i).ok()?;
        let program: Program =
            crate::lower(&m, &types, &mut i, "", "", crate::Roots::Entry).ok()?;
        Some(program_capabilities(&program))
    }

    #[test]
    fn pure_program_has_no_capabilities() {
        // A pure library module — no effects, no imports → no capabilities. A
        // `Task` `main` would need a Task-producing kernel, all of which are now
        // compiled-source and unresolved by this raw-canon helper.
        let caps = caps_of("module Pure exposing (x)\nx : Int\nx = 5\n");
        assert_eq!(caps, Some(std::collections::BTreeSet::new()));
    }

    #[test]
    fn http_program_infers_network() {
        // `Http.request` is the effect kernel (HttpRequest -> Task Error HttpResponse)
        // that carries the Network capability. Using a library module with a
        // non-`main` entry avoids the entry-point shape check; the capability scan
        // traverses all exposed roots regardless of shape.
        let caps =
            caps_of("module HttpTest exposing (send)\nimport Ipe.Http\nsend = Http.request\n");
        assert_eq!(
            caps,
            Some(std::collections::BTreeSet::from([Capability::Network]))
        );
    }

    /// An EXPOSED library module with no `main`: its exposed functions are the
    /// reachability roots a downstream consumer can call, so their capabilities
    /// must be inferred even though nothing local calls them. The dead-function
    /// prune must never drop an exposed API's effect (fail-closed: no `main` ⇒
    /// every function is a root). This is the honesty invariant the package
    /// audit's sibling-capability check relies on.
    #[test]
    fn exposed_library_module_without_main_infers_network() {
        let caps =
            caps_of("module Extra exposing (fetch)\nimport Ipe.Http\nfetch = Http.request\n");
        assert_eq!(
            caps,
            Some(std::collections::BTreeSet::from([Capability::Network]))
        );
    }

    /// The `unsafe` capability is import-derived, disclosed IFF the program
    /// imports an `Ipe.<M>.Unsafe` submodule. This is the load-bearing half of
    /// the bidirectional partition: importing the escape-hatch submodule MUST
    /// scan the `unsafe` capability. Fails-before if the scan omits the
    /// `program.imports_unsafe_submodule` insert.
    #[test]
    fn importing_an_unsafe_submodule_discloses_unsafe() {
        let caps = caps_of("module Lib exposing (x)\nimport Ipe.Db.Unsafe\nx : Int\nx = 5\n");
        assert!(
            caps.as_ref()
                .is_some_and(|c| c.contains(&Capability::Unsafe)),
            "a program importing an `Ipe.<M>.Unsafe` submodule must disclose the `unsafe` capability, got {caps:?}"
        );
    }

    /// A REAL relocated member's home: importing the shipped `Ipe.Html.Unsafe`
    /// submodule — the raw-HTML XSS escape hatch relocated out of `Ipe.Html` —
    /// discloses `unsafe`. Exercises the import-derived `unsafe` scan on an actual
    /// shipped `.Unsafe` module rather than a bare name, proving the disclosure
    /// fires for the raw-HTML boundary specifically. (Member resolution + the
    /// behaviour-identical `html_raw_node_` output is proved end-to-end in the
    /// negative-suite full-pipeline test, which injects the compiled stdlib.)
    #[test]
    fn importing_ipe_html_unsafe_discloses_unsafe() {
        let caps = caps_of("module Lib exposing (x)\nimport Ipe.Html.Unsafe\nx : Int\nx = 5\n");
        assert!(
            caps.as_ref()
                .is_some_and(|c| c.contains(&Capability::Unsafe)),
            "a program importing `Ipe.Html.Unsafe` must disclose the `unsafe` capability, got {caps:?}"
        );
    }

    /// A REAL relocated member's home: importing the shipped `Ipe.Web.Head.Unsafe`
    /// submodule — the verbatim JSON-LD `<script>` hatch relocated out of
    /// `Ipe.Web.Head` — discloses `unsafe`. Proves the disclosure fires for the
    /// raw-script boundary specifically.
    #[test]
    fn importing_ipe_web_head_unsafe_discloses_unsafe() {
        let caps = caps_of("module Lib exposing (x)\nimport Ipe.Web.Head.Unsafe\nx : Int\nx = 5\n");
        assert!(
            caps.as_ref()
                .is_some_and(|c| c.contains(&Capability::Unsafe)),
            "a program importing `Ipe.Web.Head.Unsafe` must disclose the `unsafe` capability, got {caps:?}"
        );
    }

    /// A REAL relocated member's home: importing the shipped `Ipe.Secret.Unsafe`
    /// submodule — the raw secret-reveal hatch relocated out of `Ipe.Secret` —
    /// discloses `unsafe`. Proves the disclosure fires for the secret-leak
    /// boundary specifically. The scoped `Secret.use` counterpart stays on the
    /// native `Ipe.Secret` surface and discloses nothing (covered by the
    /// capability-neutral negative-suite test).
    #[test]
    fn importing_ipe_secret_unsafe_discloses_unsafe() {
        let caps = caps_of("module Lib exposing (x)\nimport Ipe.Secret.Unsafe\nx : Int\nx = 5\n");
        assert!(
            caps.as_ref()
                .is_some_and(|c| c.contains(&Capability::Unsafe)),
            "a program importing `Ipe.Secret.Unsafe` must disclose the `unsafe` capability, got {caps:?}"
        );
    }

    /// The scoped `Secret.use` is CAPABILITY-NEUTRAL: reaching it off a plain
    /// `import Ipe.Secret` (no `.Unsafe` submodule) discloses nothing on the
    /// `unsafe` axis. This is the whole point of the scoped API — the common
    /// case stays off the `unsafe` axis, so only the blunt `unsafeReveal`
    /// discloses.
    #[test]
    fn using_secret_use_off_plain_secret_discloses_no_unsafe() {
        // The import is the load-bearing part: `caps_of` uses the kernel-qualifier
        // path, which gates on `import Ipe.Secret` (no `.Unsafe`), not on which
        // `Secret.*` member is called.
        let caps = caps_of("module Lib exposing (x)\nimport Ipe.Secret\nx : Int\nx = 5\n");
        assert!(
            caps.as_ref()
                .is_some_and(|c| !c.contains(&Capability::Unsafe)),
            "a program that reaches `Secret.use` off a plain `import Ipe.Secret` must NOT disclose `unsafe` — the scoped consume is capability-neutral, got {caps:?}"
        );
    }

    /// The other half of the partition: a program that imports NO `.Unsafe`
    /// submodule discloses nothing on the `unsafe` axis. Guards against the scan
    /// firing `unsafe` unconditionally — the default path must be untouched.
    #[test]
    fn a_program_without_an_unsafe_import_discloses_no_unsafe() {
        let caps = caps_of("module Lib exposing (x)\nx : Int\nx = 5\n");
        assert_eq!(
            caps,
            Some(std::collections::BTreeSet::new()),
            "a program that imports no `.Unsafe` submodule must disclose no capability, least of all `unsafe`"
        );
    }

    /// The `Unsafe` segment is matched at the END of a dotted `Ipe.<M>.Unsafe`
    /// path, not anywhere: an unrelated stdlib import whose name merely contains
    /// no trailing `Unsafe` segment does not trip the disclosure. A bare
    /// A plain (non-`.Unsafe`) stdlib import discloses nothing on the `unsafe`
    /// axis.
    #[test]
    fn a_plain_stdlib_import_is_not_mistaken_for_unsafe() {
        let caps = caps_of("module Lib exposing (x)\nimport Ipe.Http\nx : Int\nx = 5\n");
        assert!(
            caps.as_ref()
                .is_some_and(|c| !c.contains(&Capability::Unsafe)),
            "a plain `import Ipe.Http` must not disclose `unsafe`, got {caps:?}"
        );
    }

    #[test]
    fn subprocess_and_env_program_infers_both() {
        // `run` reaches both a subprocess kernel (`Process.run`) and an env
        // kernel (`System.getenvOr`) in one def, so the scan must infer both
        // capabilities.
        let caps = caps_of(
            "module Lib exposing (run)\nimport Ipe.Process\nimport Ipe.System\nrun =\n    Process.run (System.getenvOr \"SHELL\" \"sh\")\n",
        );
        assert_eq!(
            caps,
            Some(std::collections::BTreeSet::from([
                Capability::Subprocess,
                Capability::Env,
            ]))
        );
    }

    /// Lower `source` and run the root-seeded reachability scan with every
    /// module a root (`roots`) or none, or `None` if any stage rejects it.
    fn reached_of(source: &str, roots: bool) -> Option<super::ReachedCapabilities> {
        let mut i = Interner::new();
        let src = ipe_parse::parse_module(source, &mut i).ok()?;
        let m = ipe_canon::canonicalise(&src, &mut i).ok()?;
        let types = ipe_types::infer(&m, &mut i).ok()?;
        let program: Program =
            crate::lower(&m, &types, &mut i, "", "", crate::Roots::Entry).ok()?;
        Some(super::capabilities_reached_from(&program, &i, |_| roots))
    }

    const NETWORK_AND_UNSAFE_LIB: &str = "module Lib exposing (fetch, x)\nimport Ipe.Http\nimport Ipe.Html.Unsafe\nfetch = Http.request\nx : Int\nx = 5\n";

    /// A root module's every function is a seed, called locally or not, so its
    /// kernel effect is reached; the import-derived `Unsafe` is left to the
    /// caller.
    #[test]
    fn a_root_module_reaches_its_uncalled_export() {
        let reached = reached_of(NETWORK_AND_UNSAFE_LIB, true);
        assert!(
            reached.as_ref().is_some_and(|r| r.capabilities
                == std::collections::BTreeSet::from([Capability::Network])
                && r.reached_homes.len() == 1),
            "expected exactly `network` from the one root module, got {reached:?}"
        );
    }

    /// With no root module nothing is reached, so a module no root calls into
    /// discloses none of its kernels.
    #[test]
    fn a_module_no_root_reaches_discloses_nothing() {
        let reached = reached_of(NETWORK_AND_UNSAFE_LIB, false);
        assert_eq!(reached, Some(super::ReachedCapabilities::default()));
    }
}
