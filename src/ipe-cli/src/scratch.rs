//! Private scratch paths for temporary I/O, re-exported from the one shared primitive.
//!
//! [`ipe_sandbox::scratch`] owns creation and verification: a private 0700
//! directory under a verified base, files opened `O_EXCL` + `O_NOFOLLOW`, and
//! typed refusals. Read what an external writer wrote through
//! [`ScratchFile::read_all`], never by re-opening the path.

pub use ipe_sandbox::scratch::{LeafName, ScratchDir, ScratchFile};

/// The watcher mirrors the atomic-replace sibling suffix (it cannot depend on
/// the sandbox crate); the build breaks the instant the two drift.
const _: [(); 0] = [(); if bytes_eq(
    ipe_watch::scope::TEMP_SIBLING_SUFFIX.as_bytes(),
    ipe_sandbox::scratch::TEMP_SIBLING_SUFFIX.as_bytes(),
) {
    0
} else {
    1
}];

/// Byte equality usable in a `const` context.
const fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    match (a, b) {
        ([], []) => true,
        ([x, a @ ..], [y, b @ ..]) => *x == *y && bytes_eq(a, b),
        ([], [_, ..]) | ([_, ..], []) => false,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// Two distinct `ScratchDir` names from the same prefix never collide and
    /// neither equals a bare `<prefix>-<pid>` string (the old predictable form).
    #[test]
    fn scratch_dir_names_are_unpredictable_and_unique() {
        let pid_only = format!("ipe-publish-{}", std::process::id());
        let mut seen = std::collections::HashSet::new();
        for _ in 0..20 {
            let sd = ScratchDir::new("ipe-publish").expect("scratch dir");
            let name = sd
                .path()
                .file_name()
                .and_then(|n| n.to_str())
                .expect("utf-8 name")
                .to_owned();
            assert_ne!(
                name, pid_only,
                "name must not equal the predictable pid-only form"
            );
            assert!(seen.insert(name.clone()), "duplicate scratch name: {name}");
            // path is removed on drop — verified by raii_cleanup below
        }
    }

    /// `ScratchDir` is removed on drop.
    #[test]
    fn scratch_dir_raii_cleanup() {
        let path = {
            let sd = ScratchDir::new("ipe-raii-test").expect("scratch dir");
            let p = sd.path().to_path_buf();
            assert!(p.exists(), "dir should exist while live");
            p
        };
        assert!(!path.exists(), "dir should be gone after drop");
    }

    /// `ScratchFile` is removed on drop.
    #[test]
    fn scratch_file_raii_cleanup() {
        let path = {
            let sf = ScratchFile::create("ipe-raii-test").expect("scratch file");
            let p = sf.path().to_path_buf();
            assert!(p.exists(), "file should exist while live");
            p
        };
        assert!(!path.exists(), "file should be gone after drop");
    }

    /// Reading through the retained handle returns the bytes written to the
    /// path, even when the path name is renamed away after writing — the
    /// handle holds the original inode open.
    #[test]
    fn scratch_file_handle_reads_original_inode() {
        let original_bytes = b"original content";
        let decoy_bytes = b"swapped content";

        let mut sf = ScratchFile::create("ipe-inode-test").expect("scratch file");
        sf.file.write_all(original_bytes).expect("write");

        // Rename a decoy file over the scratch path (simulates a name-race).
        let decoy = sf.path().with_extension("decoy");
        std::fs::write(&decoy, decoy_bytes).expect("write decoy");
        std::fs::rename(&decoy, sf.path()).expect("rename decoy over path");

        // Reading through the retained handle still returns the original bytes,
        // not the decoy — the handle is bound to the original inode.
        let read_back = sf.read_all().expect("read_all");
        assert_eq!(
            read_back, original_bytes,
            "retained handle must read the original inode, not the swapped name"
        );
    }

    /// A symlink pre-seeded at the exact scratch path is not followed: the
    /// constructor retries and eventually creates a real file or directory at
    /// a fresh name, leaving the symlink target untouched.
    #[test]
    fn symlink_preseed_is_not_followed() {
        // Create a canary file that a symlink would point to.
        let canary = ipe_test_temp::temp_root().join(format!(
            "ipe-canary-{}-{}",
            std::process::id(),
            "symlink-preseed-test"
        ));
        std::fs::write(&canary, b"canary").expect("write canary");

        // Exhausting retries is hard to do reliably in a unit test because we
        // cannot control the random names.  What we CAN assert is that a
        // successful ScratchFile::create always produces a REGULAR file (not a
        // symlink), and the canary is intact.
        let sf = ScratchFile::create("ipe-preseed-test").expect("scratch file");
        let meta = std::fs::symlink_metadata(sf.path()).expect("metadata");
        assert!(
            meta.file_type().is_file(),
            "scratch file must be a regular file, not a symlink"
        );
        assert_eq!(
            std::fs::read(&canary).expect("canary readable"),
            b"canary",
            "canary must be untouched"
        );

        let _ = std::fs::remove_file(&canary);
    }

    /// The sanctioned scratch modules, by workspace-relative path.
    ///
    /// The places the OS temp root may be named: the scratch primitive and its
    /// re-exports (behind exclusive-create + entropy), and the dev-only test
    /// reader `ipe_test_temp`. Exact paths only — `scratch_helpers.rs` or
    /// another crate's `scratch.rs` is audited like any other file.
    const SANCTIONED_SCRATCH_MODULES: [&str; 6] = [
        "src/compiler/sandbox/src/scratch.rs",
        "src/ipe-cli/src/scratch.rs",
        "src/ipe-wrapper/src/scratch.rs",
        "src/runtime/rust/src/scratch_core.rs",
        "src/runtime/rust/src/scratch_host.rs",
        "tools/test-temp/src/lib.rs",
    ];

    /// Whether workspace-relative `rel` is one of [`SANCTIONED_SCRATCH_MODULES`].
    fn is_sanctioned_scratch_module(rel: &std::path::Path) -> bool {
        SANCTIONED_SCRATCH_MODULES
            .iter()
            .any(|m| rel == std::path::Path::new(m))
    }

    /// Production lines exempt from the literal temp-base rule.
    ///
    /// `(workspace-relative file, trimmed line)`; every entry must still match,
    /// so a stale exemption fails the gate. Empty: every temp path goes through
    /// a scratch constructor.
    const TMP_LITERAL_EXEMPT: [(&str, &str); 0] = [];

    /// Shared temp bases a literal must never build a path from, including the
    /// real macOS paths behind its `/tmp` and `/var/tmp` symlinks.
    const TEMP_BASE_LITERALS: [&str; 5] = [
        "\"/tmp",
        "\"/var/tmp",
        "\"/dev/shm",
        "\"/private/tmp",
        "\"/private/var/tmp",
    ];

    /// `tempfile` constructors that create under the shared temp root (their
    /// `_in` forms take an explicit base and are not listed).
    const SHARED_ROOT_TEMPFILE_CALLS: [&str; 8] = [
        "tempfile::tempdir(",
        "tempfile::tempfile(",
        "TempDir::new(",
        "TempDir::with_prefix(",
        "NamedTempFile::new(",
        "NamedTempFile::with_prefix(",
        ".tempdir()",
        ".tempfile()",
    ];

    /// Environment variables naming the OS temp root.
    const TEMP_ROOT_VARS: [&str; 3] = ["TMPDIR", "TMP", "TEMP"];

    /// The redaction-only handle on the OS temp root.
    const TEMP_ROOT_REDACTOR: &str = "TempRootRedactor";

    /// The one production module, by workspace-relative path, that holds a
    /// [`TEMP_ROOT_REDACTOR`]; it must still name it, so a stale entry fails.
    const TEMP_ROOT_REDACTOR_USERS: [&str; 1] = ["src/ipe-cli/src/cli_transcript.rs"];

    /// Former spellings that handed the temp root out as text or a path.
    const RETIRED_TEMP_ROOT_READERS: [&str; 1] = ["temp_root_text"];

    /// Every workspace member directory, read from the root manifest.
    ///
    /// Fails closed: an unreadable or unparsable manifest, an empty member
    /// list, or a glob member fails the gate rather than shrinking it.
    fn workspace_members(workspace: &std::path::Path) -> Vec<std::path::PathBuf> {
        let manifest = std::fs::read_to_string(workspace.join("Cargo.toml"));
        assert!(
            manifest.is_ok(),
            "cannot read the workspace manifest: {manifest:?}"
        );
        let parsed = manifest.unwrap_or_default().parse::<toml::Table>();
        assert!(
            parsed.is_ok(),
            "cannot parse the workspace manifest: {parsed:?}"
        );
        let parsed = parsed.unwrap_or_default();
        let members = parsed
            .get("workspace")
            .and_then(|w| w.get("members"))
            .and_then(toml::Value::as_array);
        assert!(
            members.is_some_and(|m| !m.is_empty()),
            "the workspace manifest lists no members"
        );
        members
            .into_iter()
            .flatten()
            .map(|member| {
                let member = member.as_str();
                assert!(
                    member.is_some_and(|m| !m.contains(['*', '?', '['])),
                    "workspace member {member:?} is not a literal path"
                );
                workspace.join(member.unwrap_or_default())
            })
            .collect()
    }

    /// The production code roots of every workspace member: its `src` tree
    /// (which must exist), its build script when present, and its `templates`
    /// tree when that holds Rust (the backend's emitted-project sources; a tree
    /// of `.ipe` scaffolds is not Rust code). A `templates` tree that cannot be
    /// walked stays a root, so the audit fails on it rather than skipping it.
    fn workspace_src_roots(workspace: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut roots = Vec::new();
        for member in workspace_members(workspace) {
            roots.push(member.join("src"));
            let build_script = member.join("build.rs");
            if build_script.exists() {
                roots.push(build_script);
            }
            let templates = member.join("templates");
            if templates.exists() {
                let mut rs_files = Vec::new();
                let walked = collect_rs_files(&templates, &mut rs_files);
                if walked.is_err() || !rs_files.is_empty() {
                    roots.push(templates);
                }
            }
        }
        roots
    }

    /// The package the test-only temp-root reader ships as.
    const TEST_TEMP_PACKAGE: &str = "ipe-test-temp";

    /// What the test-temp reach audit reads from one workspace member.
    struct CrateFacts {
        /// Its `[package] name`; empty when the manifest names none.
        name: String,
        /// Every package it links through a normal or build dependency table,
        /// top-level or target-specific, by `package` rename when present.
        linked: Vec<String>,
        /// Whether it declares `publish = false`.
        unpublished: bool,
        /// Whether it builds an artifact beyond a Rust library: a `[[bin]]`, a
        /// `src/main.rs` or `src/bin/` cargo discovers as one, or a `[lib]`
        /// crate type other than `lib`/`rlib`.
        ships_artifact: bool,
    }

    /// Read a member's [`CrateFacts`] from its parsed manifest. `auto_bin`
    /// says whether the member holds a `src/main.rs` or a `src/bin/`, and
    /// `workspace_deps` is the root `[workspace.dependencies]` an inherited
    /// dependency resolves its package through.
    fn crate_facts(
        manifest: &toml::Table,
        auto_bin: bool,
        workspace_deps: Option<&toml::Table>,
    ) -> CrateFacts {
        let package = manifest.get("package").and_then(toml::Value::as_table);
        let name = package
            .and_then(|p| p.get("name"))
            .and_then(toml::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let unpublished = package
            .and_then(|p| p.get("publish"))
            .and_then(toml::Value::as_bool)
            == Some(false);
        let package_of = |key: &str, spec: &toml::Value| {
            let inherited = spec.get("workspace").and_then(toml::Value::as_bool) == Some(true);
            let spec = if inherited {
                workspace_deps
                    .and_then(|deps| deps.get(key))
                    .unwrap_or(spec)
            } else {
                spec
            };
            spec.get("package")
                .and_then(toml::Value::as_str)
                .unwrap_or(key)
                .to_owned()
        };
        let mut linked = Vec::new();
        let mut read_tables = |table: &toml::Table| {
            for kind in ["dependencies", "build-dependencies", "build_dependencies"] {
                if let Some(deps) = table.get(kind).and_then(toml::Value::as_table) {
                    linked.extend(deps.iter().map(|(key, spec)| package_of(key, spec)));
                }
            }
        };
        read_tables(manifest);
        if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
            targets
                .values()
                .filter_map(toml::Value::as_table)
                .for_each(&mut read_tables);
        }
        let declared_bin = manifest
            .get("bin")
            .and_then(toml::Value::as_array)
            .is_some_and(|bins| !bins.is_empty());
        let foreign_crate_type = manifest
            .get("lib")
            .and_then(|lib| lib.get("crate-type").or_else(|| lib.get("crate_type")))
            .and_then(toml::Value::as_array)
            .is_some_and(|types| {
                types
                    .iter()
                    .any(|t| !matches!(t.as_str(), Some("lib" | "rlib")))
            });
        CrateFacts {
            name,
            linked,
            unpublished,
            ships_artifact: auto_bin || declared_bin || foreign_crate_type,
        }
    }

    /// Why the test-only temp-root reader could reach a shipped artifact.
    ///
    /// The reader's reach is every crate that links it through a normal or
    /// build edge, closed over the same edges. A dev-dependency edge never
    /// extends it, since a dev-dependency builds only into its dependent's
    /// tests. Each crate in the reach must be a Rust library that declares
    /// `publish = false`: a crate building a binary or a foreign library ships
    /// what it links, and a publishable crate can leave the workspace. A
    /// shipped crate linking a reached library is itself reached, so it is
    /// refused too.
    fn test_temp_reach_refusals(crates: &[CrateFacts]) -> Vec<String> {
        let mut reach = std::collections::BTreeSet::from([TEST_TEMP_PACKAGE.to_owned()]);
        loop {
            let before = reach.len();
            for krate in crates {
                if krate.linked.iter().any(|dep| reach.contains(dep)) {
                    reach.insert(krate.name.clone());
                }
            }
            if reach.len() == before {
                break;
            }
        }
        let mut refusals = Vec::new();
        for krate in crates.iter().filter(|k| reach.contains(&k.name)) {
            if krate.ships_artifact {
                refusals.push(format!(
                    "`{}` builds a binary or foreign library and links `{TEST_TEMP_PACKAGE}` \
                     outside [dev-dependencies]",
                    krate.name
                ));
            }
            if !krate.unpublished {
                refusals.push(format!(
                    "`{}` links `{TEST_TEMP_PACKAGE}` outside [dev-dependencies] but does not \
                     declare `publish = false`",
                    krate.name
                ));
            }
        }
        refusals
    }

    /// No production code derives a temp path from `temp_dir()`, a shared temp
    /// base, the temp-root environment, or a shared-root `tempfile` constructor.
    ///
    /// A defense-in-depth tripwire, not the proof. The structural guarantee is
    /// elsewhere: `clippy.toml` bans `std::env::temp_dir`, the whole-environment
    /// iterators, and the shared-root `tempfile` constructors (per-site allows
    /// only in the sanctioned modules, pinned by `home_read_scan`), and every
    /// environment reader refuses `TMPDIR`/`TMP`/`TEMP`. This scan is textual:
    /// a spelling it does not list (an alias, a macro-built path) passes it and
    /// is caught by those layers instead.
    ///
    /// Covers every workspace member's `src` tree, build script, and
    /// `templates` tree outside [`SANCTIONED_SCRATCH_MODULES`]: all temporary
    /// paths must go through a `scratch` module's exclusively-created
    /// constructors.
    ///
    /// Any `temp_dir()` call is flagged, and so is the split form (`let base =
    /// <temp base>; base.join(name)`). A shared temp base literal (see
    /// [`TEMP_BASE_LITERALS`]) is flagged when it builds a path (`Path::new`,
    /// `PathBuf::from`, `.join`, `format!`) or is bound and later joined; a read
    /// of `TMPDIR`, `TMP`, or `TEMP` and a [`SHARED_ROOT_TEMPFILE_CALLS`] entry
    /// are flagged outright.
    ///
    /// Test-only items (a test-only `#[cfg(…)]` or `#[test]`, located on the
    /// syntax tree) are exempt: test helpers that use predictable names in
    /// isolated temp dirs do not expose the verify/exec or verify/read identity
    /// gap that the production paths do.
    ///
    /// The walk fails closed: every root must exist and yield `.rs` files, and
    /// any unreadable directory, file, or manifest fails the gate rather than
    /// shrinking it.
    #[test]
    fn no_predictable_temp_names_in_production_code() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest.ancestors().nth(2);
        assert!(
            workspace.is_some(),
            "{} has no workspace root",
            manifest.display()
        );
        let Some(workspace) = workspace else { return };
        let mut exempt_hits = [0_usize; TMP_LITERAL_EXEMPT.len()];
        let mut redactor_hits = [0_usize; TEMP_ROOT_REDACTOR_USERS.len()];

        for src_root in &workspace_src_roots(workspace) {
            let mut rs_files: Vec<std::path::PathBuf> = Vec::new();
            let walked = if src_root.is_file() {
                rs_files.push(src_root.clone());
                Ok(())
            } else {
                collect_rs_files(src_root, &mut rs_files)
            };
            assert!(
                walked.is_ok(),
                "cannot walk {}: {walked:?} — an unwalked tree cannot be audited",
                src_root.display()
            );
            assert!(
                !rs_files.is_empty(),
                "{} yields no .rs files — a vanished root is not a clean one",
                src_root.display()
            );
            for path in &rs_files {
                // A build-script root is a file: it is its own relative path.
                let rel = if src_root.is_file() {
                    src_root.file_name().map(std::path::Path::new)
                } else {
                    path.strip_prefix(src_root).ok()
                };
                let from_workspace = path.strip_prefix(workspace);
                assert!(
                    rel.is_some() && from_workspace.is_ok(),
                    "{} is outside {}",
                    path.display(),
                    src_root.display()
                );
                let (Some(rel), Ok(from_workspace)) = (rel, from_workspace) else {
                    return;
                };
                if is_sanctioned_scratch_module(from_workspace) {
                    continue;
                }
                // An out-of-line test module carries no inline test attribute
                // for the span finder, so a confirmed one is exempt whole; an
                // unconfirmed one stays in scope.
                if src_root.is_dir() && panic_scan::is_verified_test_path(src_root, rel) {
                    continue;
                }
                // An unread file is unaudited, not clean.
                let source = std::fs::read_to_string(path);
                assert!(
                    source.is_ok(),
                    "cannot read {}: {source:?} — an unread file cannot be audited",
                    path.display()
                );
                let Ok(source) = source else { return };
                let exempt: Vec<(usize, &str)> = TMP_LITERAL_EXEMPT
                    .iter()
                    .enumerate()
                    .filter(|(_, (file, _))| from_workspace == std::path::Path::new(file))
                    .map(|(i, (_, line))| (i, *line))
                    .collect();
                let lines: Vec<&str> = exempt.iter().map(|(_, l)| *l).collect();
                for used in audit_predictable_temp(path, &source, &lines) {
                    if let Some((i, _)) = exempt.iter().find(|(_, l)| *l == used)
                        && let Some(hits) = exempt_hits.get_mut(*i)
                    {
                        *hits += 1;
                    }
                }
                let redactor_user = TEMP_ROOT_REDACTOR_USERS
                    .iter()
                    .position(|user| from_workspace == std::path::Path::new(user));
                let named = audit_temp_root_handles(path, &source, redactor_user.is_some());
                if let Some(i) = redactor_user
                    && let Some(hits) = redactor_hits.get_mut(i)
                {
                    *hits += named;
                }
            }
        }
        for ((file, line), hits) in TMP_LITERAL_EXEMPT.iter().zip(exempt_hits) {
            assert!(
                hits > 0,
                "stale temp-base exemption {file}: `{line}` matched no line — remove it"
            );
        }
        for (file, hits) in TEMP_ROOT_REDACTOR_USERS.iter().zip(redactor_hits) {
            assert!(
                hits > 0,
                "stale {TEMP_ROOT_REDACTOR} user {file}: it no longer names it — remove it"
            );
        }
    }

    /// Audit `source` for a handle on the OS temp root outside the scratch
    /// primitive, panicking on the first one in production code; returns how
    /// many production lines name [`TEMP_ROOT_REDACTOR`].
    ///
    /// A [`RETIRED_TEMP_ROOT_READERS`] name is refused everywhere; the
    /// redactor only where `redactor_allowed` (a
    /// [`TEMP_ROOT_REDACTOR_USERS`] module). Test-only items are skipped.
    fn audit_temp_root_handles(
        path: &std::path::Path,
        source: &str,
        redactor_allowed: bool,
    ) -> usize {
        let test_lines = panic_scan::test_only_item_lines(source);
        assert!(
            test_lines.is_ok(),
            "cannot parse {}: {test_lines:?} — an unparsed file cannot be audited",
            path.display()
        );
        let Ok(test_lines) = test_lines else { return 0 };
        let mut named = 0_usize;
        for (i, line) in source.lines().enumerate() {
            let line_no = i + 1;
            if test_lines.iter().any(|span| span.contains(&line_no)) {
                continue;
            }
            assert!(
                !RETIRED_TEMP_ROOT_READERS
                    .iter()
                    .any(|reader| line.contains(reader)),
                "retired temp-root reader in production code at {}:{line_no} — \
                 temporary entries come only from ScratchDir or ScratchFile.\n  line: {}",
                path.display(),
                line.trim()
            );
            if line.contains(TEMP_ROOT_REDACTOR) {
                assert!(
                    redactor_allowed,
                    "{TEMP_ROOT_REDACTOR} outside its sanctioned user at {}:{line_no} — \
                     temporary entries come only from ScratchDir or ScratchFile.\n  line: {}",
                    path.display(),
                    line.trim()
                );
                named += 1;
            }
        }
        named
    }

    /// A temp-root handle outside its sanctioned user, or a retired reader
    /// anywhere, is refused; the sanctioned user passes and is counted, and a
    /// test-only use is exempt.
    #[test]
    fn temp_root_handles_are_pinned_to_their_user() {
        let refuses = |source: &str, allowed: bool| {
            std::panic::catch_unwind(|| {
                audit_temp_root_handles(std::path::Path::new("injected.rs"), source, allowed)
            })
            .is_err()
        };
        let redactor =
            "fn r() {\n    let _ = ipe_sandbox::scratch::TempRootRedactor::current();\n}\n";
        assert!(
            refuses(redactor, false),
            "an unsanctioned redactor is refused"
        );
        assert!(!refuses(redactor, true), "the sanctioned user passes");
        assert_eq!(
            audit_temp_root_handles(std::path::Path::new("user.rs"), redactor, true),
            1
        );
        let retired = "fn r() -> Option<String> {\n    ipe_sandbox::scratch::temp_root_text()\n}\n";
        assert!(refuses(retired, false) && refuses(retired, true));
        let test_only = "#[cfg(test)]\nmod tests {\n    fn r() {\n        \
            let _ = TempRootRedactor::current();\n    }\n}\n";
        assert!(!refuses(test_only, false), "a test-only use is exempt");
        assert_eq!(
            audit_temp_root_handles(std::path::Path::new("t.rs"), test_only, false),
            0
        );
    }

    /// The test-only temp-root reader never reaches production: every crate
    /// that links it outside a dev-dependency table is an unpublished Rust
    /// library, and no crate building an artifact links one.
    #[test]
    fn the_test_temp_reader_reaches_no_shipped_artifact() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let Some(workspace) = manifest.ancestors().nth(2) else {
            return;
        };
        let root = std::fs::read_to_string(workspace.join("Cargo.toml"))
            .map_err(|e| e.to_string())
            .and_then(|text| text.parse::<toml::Table>().map_err(|e| e.to_string()));
        assert!(root.is_ok(), "cannot read the workspace manifest: {root:?}");
        let Ok(root) = root else { return };
        let workspace_deps = root
            .get("workspace")
            .and_then(|w| w.get("dependencies"))
            .and_then(toml::Value::as_table);
        let mut crates = Vec::new();
        for member in workspace_members(workspace) {
            let path = member.join("Cargo.toml");
            let parsed = std::fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|text| text.parse::<toml::Table>().map_err(|e| e.to_string()));
            assert!(parsed.is_ok(), "cannot read {}: {parsed:?}", path.display());
            let Ok(parsed) = parsed else { return };
            let auto_bin = member.join("src/main.rs").exists() || member.join("src/bin").exists();
            let facts = crate_facts(&parsed, auto_bin, workspace_deps);
            assert!(
                !facts.name.is_empty(),
                "{} names no package",
                path.display()
            );
            crates.push(facts);
        }
        assert!(
            crates.iter().any(|k| k.name == TEST_TEMP_PACKAGE),
            "`{TEST_TEMP_PACKAGE}` is no longer a workspace member; the audit has nothing to bound"
        );
        let refusals = test_temp_reach_refusals(&crates);
        assert!(refusals.is_empty(), "{}", refusals.join("\n"));
    }

    /// The facts of one fixture manifest, its source tree holding a
    /// `src/main.rs` when `auto_bin`.
    fn fixture(manifest: &str, auto_bin: bool) -> CrateFacts {
        let parsed = manifest.parse::<toml::Table>();
        assert!(parsed.is_ok(), "fixture must parse: {parsed:?}");
        crate_facts(&parsed.unwrap_or_default(), auto_bin, None)
    }

    /// The reader itself, as its manifest declares it.
    fn reader_fixture() -> CrateFacts {
        fixture(
            "[package]\nname = \"ipe-test-temp\"\npublish = false\n",
            false,
        )
    }

    /// A shipped crate's production, build, or target-specific dependency on
    /// the test reader is refused, by key or by rename; a dev-dependency is not.
    #[test]
    fn a_production_dependency_on_the_test_temp_reader_is_refused() {
        for refused in [
            "[dependencies]\nipe-test-temp = { path = \"../test-temp\" }\n",
            "[build-dependencies]\nipe-test-temp = { path = \"../test-temp\" }\n",
            "[dependencies]\ntt = { package = \"ipe-test-temp\", path = \"x\" }\n",
            "[target.'cfg(unix)'.dependencies]\nipe-test-temp = { path = \"x\" }\n",
        ] {
            let app = fixture(&format!("[package]\nname = \"app\"\n{refused}"), true);
            assert!(
                !test_temp_reach_refusals(&[reader_fixture(), app]).is_empty(),
                "must refuse: {refused}"
            );
        }
        for accepted in [
            "[dev-dependencies]\nipe-test-temp = { path = \"../test-temp\" }\n",
            "[target.'cfg(unix)'.dev-dependencies]\nipe-test-temp = { path = \"x\" }\n",
        ] {
            let app = fixture(&format!("[package]\nname = \"app\"\n{accepted}"), true);
            assert_eq!(
                test_temp_reach_refusals(&[reader_fixture(), app]),
                Vec::<String>::new(),
                "must accept: {accepted}"
            );
        }
    }

    /// A test-support library may link the reader only while no crate that
    /// builds an artifact links that library outside its dev-dependencies, at
    /// any depth; and the library itself must be an unpublished Rust library.
    #[test]
    fn a_shipped_crate_reaching_the_test_temp_reader_is_refused() {
        let support = |extra: &str| {
            fixture(
                &format!(
                    "[package]\nname = \"support\"\npublish = false\n{extra}\n\
                     [dependencies]\nipe-test-temp = {{ path = \"x\" }}\n"
                ),
                false,
            )
        };
        let app = |deps: &str| fixture(&format!("[package]\nname = \"app\"\n{deps}"), true);
        let app_refused = |crates: &[CrateFacts]| {
            test_temp_reach_refusals(crates)
                .iter()
                .any(|r| r.starts_with("`app`"))
        };

        assert_eq!(
            test_temp_reach_refusals(&[
                reader_fixture(),
                support(""),
                app("[dev-dependencies]\nsupport = { path = \"s\" }\n"),
            ]),
            Vec::<String>::new(),
            "a library reached only through a dev-dependency stays in tests"
        );
        for deps in [
            "[dependencies]\nsupport = { path = \"s\" }\n",
            "[build-dependencies]\nsupport = { path = \"s\" }\n",
            "[dependencies]\ns = { package = \"support\", path = \"s\" }\n",
            "[target.'cfg(unix)'.dependencies]\nsupport = { path = \"s\" }\n",
        ] {
            assert!(
                app_refused(&[reader_fixture(), support(""), app(deps)]),
                "a shipped crate linking the library must be refused: {deps}"
            );
        }
        let middle = fixture(
            "[package]\nname = \"middle\"\npublish = false\n\
             [dependencies]\nsupport = { path = \"s\" }\n",
            false,
        );
        assert!(
            app_refused(&[
                reader_fixture(),
                support(""),
                middle,
                app("[dependencies]\nmiddle = { path = \"m\" }\n"),
            ]),
            "a shipped crate two links away must be refused"
        );

        let published = fixture(
            "[package]\nname = \"support\"\n[dependencies]\nipe-test-temp = { path = \"x\" }\n",
            false,
        );
        assert!(
            test_temp_reach_refusals(&[reader_fixture(), published])
                .iter()
                .any(|r| r.contains("publish = false")),
            "a publishable library linking the reader must be refused"
        );
        for artifact in [
            "[[bin]]\nname = \"tool\"\npath = \"src/tool.rs\"\n",
            "[lib]\ncrate-type = [\"cdylib\"]\n",
        ] {
            assert!(
                !test_temp_reach_refusals(&[reader_fixture(), support(artifact)]).is_empty(),
                "a library that also builds an artifact must be refused: {artifact}"
            );
        }
    }

    /// Assert `source` derives no temp path from `temp_dir()`, a shared temp
    /// base, or the temp-root environment in production code.
    fn assert_predictable_temp_free(path: &std::path::Path, source: &str) {
        let _ = audit_predictable_temp(path, source, &[]);
    }

    /// Whether `line` builds a path from a literal shared temp base.
    fn builds_tmp_literal_path(line: &str) -> bool {
        TEMP_BASE_LITERALS.iter().any(|base| line.contains(base))
            && ["Path::new(", "PathBuf::from(", ".join(", "format!("]
                .iter()
                .any(|c| line.contains(c))
    }

    /// Whether `line` reads a temp-root environment variable.
    fn reads_temp_root_var(line: &str) -> bool {
        TEMP_ROOT_VARS.iter().any(|var| {
            ["var(\"", "var_os(\""]
                .iter()
                .any(|read| line.contains(&format!("{read}{var}\")")))
        })
    }

    /// Audit `source`, panicking on the first predictable temp path in
    /// production code. `exempt_tmp` lists trimmed lines allowed to name a
    /// literal temp base; returns the exempt lines that were hit.
    ///
    /// Test-only items are skipped by the syntax tree
    /// ([`panic_scan::test_only_item_lines`]), so a brace inside a string or
    /// comment can neither end a test region early nor carry one past its
    /// item; a file that does not parse fails the gate. Production
    /// `let <ident> = ...temp_dir();` / `let <ident> = ..."/tmp"...` bindings are
    /// tracked so a later `<ident>.join(` (the split form) is caught as well as
    /// the inline forms. `temp_dir` passed as a bare function reference (e.g.
    /// `map_or_else(std::env::temp_dir, ...)`) is caught as the split form's
    /// equivalent.
    fn audit_predictable_temp<'e>(
        path: &std::path::Path,
        source: &str,
        exempt_tmp: &[&'e str],
    ) -> Vec<&'e str> {
        let mut used = Vec::new();
        let test_lines = panic_scan::test_only_item_lines(source);
        assert!(
            test_lines.is_ok(),
            "cannot parse {}: {test_lines:?} — an unparsed file cannot be audited",
            path.display()
        );
        let Ok(test_lines) = test_lines else {
            return used;
        };
        // Production idents currently bound to a temp base.
        let mut temp_bindings: std::collections::HashSet<String> = std::collections::HashSet::new();

        for (i, line) in source.lines().enumerate() {
            let line_no = i + 1;
            if test_lines.iter().any(|span| span.contains(&line_no)) {
                continue;
            }

            // Any `temp_dir()` call: the root is read only by the scratch primitive.
            assert!(
                !line.contains("temp_dir()"),
                "OS temp root read in production code at {}:{line_no} — \
                 use ScratchDir or ScratchFile instead.\n  line: {}",
                path.display(),
                line.trim()
            );

            // A `tempfile` constructor that creates under the shared root.
            assert!(
                !SHARED_ROOT_TEMPFILE_CALLS
                    .iter()
                    .any(|call| line.contains(call)),
                "shared-temp-root tempfile constructor in production code at {}:{line_no} — \
                 use ScratchDir or ScratchFile instead.\n  line: {}",
                path.display(),
                line.trim()
            );

            // Literal temp base building a path, unless exempt.
            if builds_tmp_literal_path(line) {
                let exempt = exempt_tmp.iter().find(|e| line.trim() == **e);
                assert!(
                    exempt.is_some(),
                    "predictable literal temp-base path in production code at {}:{line_no} — \
                     use ScratchDir::new, or ScratchDir::new_fitting for a length-bounded \
                     path, instead.\n  line: {}",
                    path.display(),
                    line.trim()
                );
                if let Some(e) = exempt {
                    used.push(*e);
                }
            }

            // The temp root read from the environment bypasses the verified base.
            assert!(
                !reads_temp_root_var(line),
                "temp-root environment read in production code at {}:{line_no} — \
                 use ScratchDir or ScratchFile instead.\n  line: {}",
                path.display(),
                line.trim()
            );

            // Fn-reference form: `temp_dir` used as a bare callable (without `()`)
            // in a combinator such as `map_or_else(std::env::temp_dir, ...)` or
            // `map_or_else(temp_dir, ...)`.  Both spellings route through `temp_dir`
            // without the `()` that the inline form requires, so they evade that
            // check; this clause closes the gap.
            let is_fn_ref = line.contains("map_or_else(std::env::temp_dir")
                || (line.contains("map_or_else(")
                    && line.contains("temp_dir")
                    && !line.contains("temp_dir()"));
            assert!(
                !is_fn_ref,
                "bare temp_dir fn-reference in production code at {}:{line_no} — \
                 use ScratchDir::new_under with an explicit base instead.\n  line: {}",
                path.display(),
                line.trim()
            );

            // Split form, part 1: record a `let <ident> = ...temp_dir();` or
            // `let <ident> = ..."/tmp"...;` binding (that does not itself `.join`).
            if (line.contains("temp_dir()")
                || TEMP_BASE_LITERALS.iter().any(|base| line.contains(base)))
                && !line.contains(".join")
                && let Some(ident) = binding_ident(line)
            {
                temp_bindings.insert(ident);
            }

            // Split form, part 2: a `.join(` on a recorded temp-derived binding.
            for ident in &temp_bindings {
                let joined = format!("{ident}.join(");
                assert!(
                    !line.contains(&joined),
                    "predictable split-form temp path (`{ident} = <temp base>; {ident}.join(...)`) \
                     in production code at {}:{line_no} — use ScratchDir or ScratchFile instead.\n  line: {}",
                    path.display(),
                    line.trim()
                );
            }
        }
        used
    }

    /// Extract the bound identifier from a `let <ident> = ...;` line, if any.
    fn binding_ident(line: &str) -> Option<String> {
        let after_let = line.trim_start().strip_prefix("let ")?;
        let name = after_let
            .trim_start_matches("mut ")
            .split([' ', ':', '='])
            .next()?
            .trim();
        if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return None;
        }
        Some(name.to_owned())
    }

    /// Collect every `.rs` file under `dir`, failing on any unreadable directory
    /// or entry. Symlinks are not followed (no loop, no escape from the root).
    fn collect_rs_files(
        dir: &std::path::Path,
        out: &mut Vec<std::path::PathBuf>,
    ) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                collect_rs_files(&path, out)?;
            } else if kind.is_file() && path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
        Ok(())
    }

    /// The class gate flags the inline predictable-temp form in production code.
    #[test]
    fn class_gate_flags_inline_predictable_temp() {
        let injected = "fn make() -> std::path::PathBuf {\n    \
            std::env::temp_dir().join(\"predictable-name\")\n}\n";
        let caught = std::panic::catch_unwind(|| {
            assert_predictable_temp_free(std::path::Path::new("injected.rs"), injected);
        })
        .is_err();
        assert!(
            caught,
            "gate must flag inline temp_dir().join in production"
        );
    }

    /// The class gate flags the split predictable-temp form in production code.
    #[test]
    fn class_gate_flags_split_predictable_temp() {
        let injected = "fn make() -> std::path::PathBuf {\n    \
            let base = std::env::temp_dir();\n    \
            base.join(\"predictable-name\")\n}\n";
        let caught = std::panic::catch_unwind(|| {
            assert_predictable_temp_free(std::path::Path::new("injected.rs"), injected);
        })
        .is_err();
        assert!(
            caught,
            "gate must flag split-form temp_dir()+join in production"
        );
    }

    /// The class gate flags `temp_dir` passed as a bare fn reference in a
    /// `map_or_else` combinator (the fn-reference form).
    #[test]
    fn class_gate_flags_map_or_else_temp_dir_fn_ref() {
        let injected = "fn make(home: Option<PathBuf>) -> PathBuf {\n    \
            home.map_or_else(std::env::temp_dir, |h| h.join(\".cache\"))\n}\n";
        let caught = std::panic::catch_unwind(|| {
            assert_predictable_temp_free(std::path::Path::new("injected.rs"), injected);
        })
        .is_err();
        assert!(
            caught,
            "gate must flag map_or_else(std::env::temp_dir, ...) in production"
        );
    }

    /// The class gate flags the short `map_or_else(temp_dir, ...)` form (no
    /// path qualifier) the same way it flags the fully-qualified form.
    #[test]
    fn class_gate_flags_map_or_else_temp_dir_short() {
        let injected = "fn make(home: Option<PathBuf>) -> PathBuf {\n    \
            home.map_or_else(temp_dir, |h| h.join(\".cache\"))\n}\n";
        let caught = std::panic::catch_unwind(|| {
            assert_predictable_temp_free(std::path::Path::new("injected.rs"), injected);
        })
        .is_err();
        assert!(
            caught,
            "gate must flag map_or_else(temp_dir, ...) in production"
        );
    }

    /// The class gate passes on clean production code (a `ScratchDir`-based
    /// construction and an explicit-base `tempfile` constructor) and on
    /// test-region predictable temps.
    #[test]
    fn class_gate_passes_clean_code() {
        let clean = "fn make(base: &Path) -> std::io::Result<()> {\n    \
            let _dir = ScratchDir::new(\"ipe-run\")?;\n    \
            let _t = tempfile::tempdir_in(base)?;\n    \
            let _f = tempfile::NamedTempFile::new_in(base)?;\n    \
            Ok(())\n}\n\
            #[cfg(test)]\nmod tests {\n    \
            fn helper() { let _ = std::env::temp_dir().join(\"ok-in-test\"); }\n}\n";
        // Must not panic.
        assert_predictable_temp_free(std::path::Path::new("clean.rs"), clean);
    }

    /// The class gate passes on `ScratchDir::new_under` usage (the correct
    /// pattern for a caller-supplied base path).
    #[test]
    fn class_gate_passes_new_under() {
        let clean = "fn make(base: &Path) -> std::io::Result<ScratchDir> {\n    \
            ScratchDir::new_under(base, \"ipe-add\")\n}\n";
        // Must not panic.
        assert_predictable_temp_free(std::path::Path::new("clean.rs"), clean);
    }

    /// Whether auditing `source` panics (the gate refuses it).
    fn gate_refuses(source: &str) -> bool {
        std::panic::catch_unwind(|| {
            assert_predictable_temp_free(std::path::Path::new("injected.rs"), source);
        })
        .is_err()
    }

    /// A literal `/tmp` base building a path is refused, inline and split.
    #[test]
    fn class_gate_flags_literal_tmp_paths() {
        for injected in [
            "fn make() -> PathBuf {\n    PathBuf::from(\"/tmp\").join(\"n\")\n}\n",
            "fn make() -> &'static Path {\n    Path::new(\"/tmp/ipe-fixed\")\n}\n",
            "fn make() -> String {\n    format!(\"/tmp/ipe-{}\", 1)\n}\n",
            "fn make() {\n    let root = \"/tmp\";\n    root.join(\"n\");\n}\n",
        ] {
            assert!(gate_refuses(injected), "gate must flag: {injected}");
        }
    }

    /// An exempt temp-base line passes and is reported as used; the same line
    /// not listed is refused.
    #[test]
    fn class_gate_tmp_exemption_is_exact_and_reported() {
        let line = "Path::new(\"/var/tmp\")";
        let source = format!("fn base() -> &'static Path {{\n    {line}\n}}\n");
        let used = audit_predictable_temp(std::path::Path::new("x.rs"), &source, &[line]);
        assert_eq!(used, vec![line]);
        assert!(
            gate_refuses(&source),
            "an unlisted temp-base line is refused"
        );
    }

    /// Every shared temp base building a path is refused, not only `/tmp`:
    /// the macOS `/private` real paths included.
    #[test]
    fn class_gate_flags_every_shared_temp_base() {
        for injected in [
            "fn make() -> PathBuf {\n    PathBuf::from(\"/var/tmp\").join(\"n\")\n}\n",
            "fn make() -> &'static Path {\n    Path::new(\"/dev/shm/ipe-fixed\")\n}\n",
            "fn make() {\n    let root = \"/var/tmp\";\n    root.join(\"n\");\n}\n",
            "fn make() -> PathBuf {\n    PathBuf::from(\"/private/tmp\").join(\"n\")\n}\n",
            "fn make() -> &'static Path {\n    Path::new(\"/private/var/tmp/ipe-fixed\")\n}\n",
            "fn make() -> String {\n    format!(\"/private/tmp/ipe-{}\", 1)\n}\n",
            "fn make() {\n    let root = \"/private/tmp\";\n    root.join(\"n\");\n}\n",
        ] {
            assert!(gate_refuses(injected), "gate must flag: {injected}");
        }
    }

    /// Any read of the OS temp root is refused, bound or not.
    #[test]
    fn class_gate_flags_a_bare_temp_root_read() {
        for injected in [
            "fn base() -> PathBuf {\n    std::env::temp_dir()\n}\n",
            "fn base() {\n    let _base = std::env::temp_dir();\n}\n",
            "fn base() -> PathBuf {\n    temp_dir()\n}\n",
        ] {
            assert!(gate_refuses(injected), "gate must flag: {injected}");
        }
    }

    /// Every shared-root `tempfile` constructor is refused.
    #[test]
    fn class_gate_flags_shared_root_tempfile_constructors() {
        for injected in [
            "fn t() -> io::Result<TempDir> {\n    tempfile::tempdir()\n}\n",
            "fn t() -> io::Result<File> {\n    tempfile::tempfile()\n}\n",
            "fn t() -> io::Result<TempDir> {\n    TempDir::new()\n}\n",
            "fn t() -> io::Result<TempDir> {\n    TempDir::with_prefix(\"x\")\n}\n",
            "fn t() -> io::Result<NamedTempFile> {\n    NamedTempFile::new()\n}\n",
            "fn t() -> io::Result<NamedTempFile> {\n    NamedTempFile::with_prefix(\"x\")\n}\n",
            "fn t() -> io::Result<TempDir> {\n    Builder::new().prefix(\"x\").tempdir()\n}\n",
            "fn t() -> io::Result<NamedTempFile> {\n    Builder::new().tempfile()\n}\n",
        ] {
            assert!(gate_refuses(injected), "gate must flag: {injected}");
        }
    }

    /// A read of the temp-root environment is refused in every spelling.
    #[test]
    fn class_gate_flags_temp_root_env_reads() {
        for injected in [
            "fn base() -> Option<String> {\n    std::env::var(\"TMPDIR\").ok()\n}\n",
            "fn base() -> Option<OsString> {\n    std::env::var_os(\"TMP\")\n}\n",
            "fn base() -> Option<OsString> {\n    env::var_os(\"TEMP\")\n}\n",
        ] {
            assert!(gate_refuses(injected), "gate must flag: {injected}");
        }
        let unrelated = "fn home() -> Option<OsString> {\n    std::env::var_os(\"HOME\")\n}\n";
        assert!(
            !gate_refuses(unrelated),
            "a non-temp variable is not a temp root"
        );
    }

    /// A test-only item is exempt to its real end: a `}` inside one of its
    /// strings neither ends it early nor lets it swallow production code after it.
    #[test]
    fn class_gate_test_items_end_on_the_syntax_tree() {
        let exempt = "#[cfg(all(test, unix))]\nmod tests {\n    const S: &str = \"}\";\n    \
             fn t() { let _ = std::env::temp_dir().join(\"ok-in-test\"); }\n}\n";
        assert!(!gate_refuses(exempt), "a test-only item is exempt");
        let leaked =
            format!("{exempt}fn make() -> PathBuf {{\n    std::env::temp_dir().join(\"n\")\n}}\n");
        assert!(
            gate_refuses(&leaked),
            "code after a test-only item is audited"
        );
    }

    /// Source that does not parse is refused, never passed as empty.
    #[test]
    fn class_gate_refuses_unparsable_source() {
        assert!(gate_refuses("fn make( {\n"));
    }

    /// A braceless `#[cfg(test)]` item and prose naming `mod tests` exempt
    /// nothing after them.
    #[test]
    fn class_gate_test_region_never_leaks_into_production() {
        for injected in [
            "#[cfg(test)]\nuse std::env::temp_dir;\nfn make() -> PathBuf {\n    \
             std::env::temp_dir().join(\"n\")\n}\n",
            "// helpers live in mod tests below\nfn make() -> PathBuf {\n    \
             std::env::temp_dir().join(\"n\")\n}\n",
            "#[cfg(test)]\nmod tests;\nfn make() -> PathBuf {\n    \
             std::env::temp_dir().join(\"n\")\n}\n",
            "#[cfg(test)]\nmod tests {\n    fn t() {}\n}\nfn make() -> PathBuf {\n    \
             std::env::temp_dir().join(\"n\")\n}\n",
        ] {
            assert!(gate_refuses(injected), "gate must flag: {injected}");
        }
    }

    /// Only the exact sanctioned module paths are exempt.
    #[test]
    fn class_gate_sanctions_exact_scratch_modules_only() {
        for ok in SANCTIONED_SCRATCH_MODULES {
            assert!(
                is_sanctioned_scratch_module(std::path::Path::new(ok)),
                "{ok}"
            );
        }
        for audited in [
            "scratch.rs",
            "scratch_core.rs",
            "src/runtime/rust/src/scratch.rs",
            "src/ipe-cli/src/scratch_helpers.rs",
            "src/ipe-cli/src/web/scratch.rs",
            "src/ipe-cli/src/scratch.rs.bak",
        ] {
            assert!(
                !is_sanctioned_scratch_module(std::path::Path::new(audited)),
                "{audited} must be audited"
            );
        }
    }

    /// The roots are every workspace member's `src` tree, build script, and
    /// `templates` tree, read from the manifest.
    #[test]
    fn class_gate_roots_follow_the_workspace_members() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest.ancestors().nth(2).expect("workspace root");
        let roots = workspace_src_roots(workspace);
        for member in ["src/ipe-cli", "src/runtime/rust", "src/compiler/sandbox"] {
            assert!(
                roots.contains(&workspace.join(member).join("src")),
                "{member} must be audited"
            );
        }
        for extra in [
            "src/compiler/backend/rust/templates",
            "src/runtime/rust/build.rs",
            "src/ipe-wrapper/build.rs",
        ] {
            assert!(
                roots.contains(&workspace.join(extra)),
                "{extra} must be audited"
            );
        }
        assert!(
            !roots.contains(&workspace.join("src/ipe-cli/templates")),
            "a tree of `.ipe` scaffolds is not a Rust root"
        );
    }

    /// An emitted-project template is audited like any production source: a
    /// template that reads the OS temp root is refused.
    #[test]
    fn class_gate_flags_a_temp_read_in_a_template() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest.ancestors().nth(2).expect("workspace root");
        let template = workspace.join("src/compiler/backend/rust/templates/main.rs");
        let source = std::fs::read_to_string(&template).expect("template readable");
        assert!(!gate_refuses(&source), "the shipped template is clean");
        let planted = format!(
            "{source}\npub fn scratch() -> std::path::PathBuf {{\n    \
             std::path::PathBuf::from(\"/private/tmp\").join(\"ipe\")\n}}\n"
        );
        assert!(
            gate_refuses(&planted),
            "a planted template temp path is refused"
        );
    }

    /// A missing root fails the walk rather than yielding an empty, clean tree.
    #[test]
    fn class_gate_walk_fails_closed_on_a_missing_root() {
        let root = ScratchDir::new("ipe-gate-walk").expect("scratch dir");
        let mut files = Vec::new();
        assert!(collect_rs_files(&root.path().join("absent"), &mut files).is_err());
        assert!(files.is_empty());
    }
}
