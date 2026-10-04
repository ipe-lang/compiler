//! `ipe clean` — remove a project's build-generated output.
//!
//! Deletes only what `ipe` itself owns — the build output (`out/`, and only
//! while it carries ipe's ownership marker) and the cache subtrees ipe writes in
//! the per-project `.ipe/` namespace — and never user source, `package.ipe`, or
//! anything else a user put in `.ipe/`. The command is fail-closed on three
//! axes: it refuses to run outside an Ipê project (no `package.ipe` at the
//! resolved root), it refuses an `out/` ipe did not create, and every deletion
//! target is lstat'd under the canonicalised project root before a byte is
//! removed, so a symlink or a `..` component can never carry the delete outside
//! the project.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::CliError;
use crate::cli_args::{self, OutputFormat};
use crate::screen::{self, Screen, Stream, Tone};
use crate::style;
use crate::text;

/// A directory `clean` may remove.
///
/// Named relative to the project root, with the proof of ownership it must show
/// first.
struct Generated {
    name: &'static str,
    proof: Proof,
}

/// What proves a [`Generated`] directory is ipe's to delete.
enum Proof {
    /// It carries [`crate::output_dir::OWNERSHIP_MARKER`] and is removed whole.
    ///
    /// `out/` is a common name a user may have chosen for their own files, so
    /// it is removed only when ipe marked it.
    Marker,
    /// It is ipe's namespace, but only the named entries in it are ipe's.
    ///
    /// Those are removed; anything else in it is kept, and the namespace
    /// directory itself goes only once nothing is left in it.
    Namespace(&'static [&'static str]),
}

/// The entries ipe writes in the `.ipe/` namespace: its build caches and the
/// fetched package sources.
const CACHE_NAMESPACE_ENTRIES: &[&str] = &["cache", "packages"];

/// The deletion allowlist — nothing outside it is ever a candidate.
const GENERATED_DIRS: &[Generated] = &[
    Generated {
        name: crate::output_dir::DEFAULT_OUTPUT_DIR,
        proof: Proof::Marker,
    },
    Generated {
        name: crate::output_dir::CACHE_NAMESPACE_DIR,
        proof: Proof::Namespace(CACHE_NAMESPACE_ENTRIES),
    },
];

/// Parsed `ipe clean` arguments.
pub(crate) struct CleanArgs {
    /// The output format for the removal report.
    pub(crate) format: OutputFormat,
}

/// Parse `ipe clean` arguments: only the shared `--json`/`--plain` format flags;
/// the command takes no positional argument.
///
/// # Errors
/// [`CliError::Usage`] on an unknown flag or any positional argument.
pub(crate) fn parse_clean_args(rest: &[String]) -> Result<CleanArgs, CliError> {
    let mut format: Option<OutputFormat> = None;
    for arg in rest {
        if cli_args::consume_format_flag(&mut format, arg, "clean")? {
            continue;
        }
        if arg.starts_with('-') {
            return Err(crate::cli_args::usage_unknown_flag("clean", arg));
        }
        return Err(crate::cli_args::usage_unexpected_argument("clean", arg));
    }
    Ok(CleanArgs {
        format: format.unwrap_or_default(),
    })
}

/// `ipe clean` — remove the current project's generated build output.
///
/// Takes no positional argument: it operates on the project rooted at the
/// current directory. Prints one line per removed directory and a closing
/// summary.
///
/// `--json` emits `{"schema":"ipe.cli.clean/1","removed":[…]}`.
/// `--plain` prints one removed path per line, flush-left.
///
/// # Errors
/// [`CliError::Usage`] on any unrecognised argument or when the current
/// directory is not an Ipê project (no `package.ipe`); [`CliError::Io`] on a
/// filesystem failure while removing a directory.
pub fn run_clean(rest: &[String]) -> Result<(), CliError> {
    let args = parse_clean_args(rest)?;

    let root = project_root()?;
    let removed = clean_root(&root)?;
    print_summary(&removed, args.format);
    Ok(())
}

/// Remove every generated directory under the canonical project `root`.
///
/// Returns the removed paths, relative to `root`, for the summary.
///
/// # Errors
/// As [`remove_generated_dir`].
pub(crate) fn clean_root(root: &Path) -> Result<Vec<String>, CliError> {
    let mut removed: Vec<String> = Vec::new();
    for generated in GENERATED_DIRS {
        removed.extend(remove_generated_dir(root, generated)?);
    }
    Ok(removed)
}

/// Resolve and validate the project root, the current directory holding a `package.ipe`.
///
/// Returns the canonicalised root so every later containment check compares
/// real, symlink-resolved paths.
///
/// # Errors
/// [`CliError::Usage`] when there is no `package.ipe` here (fail-closed: no
/// project, nothing to clean), with the legacy-toml hint when only a legacy
/// `ipe.toml` is present; [`CliError::Io`] when the directory cannot be
/// canonicalised.
fn project_root() -> Result<PathBuf, CliError> {
    let cwd = PathBuf::from(".");
    if crate::project::manifest_in_dir(&cwd).is_none() {
        if crate::project::has_only_legacy_toml(&cwd) {
            return Err(CliError::Usage(text::msg::legacy_toml_hint()));
        }
        return Err(CliError::Usage(text::msg::clean_no_manifest()));
    }
    std::fs::canonicalize(&cwd).map_err(|e| CliError::Io {
        path: cwd,
        source: e,
    })
}

/// Remove one generated directory under `root`, returning what went for the summary.
///
/// Nothing when it is absent or not a directory. Every entry is lstat'd, never
/// followed: a symlinked `out/`/`.ipe/` (or a symlinked entry in `.ipe/`) is
/// refused, its target untouched; an `out/` without ipe's ownership marker is
/// refused untouched; and a removal never follows a symlink met inside the tree.
///
/// Every act goes through held directory handles: the candidate is
/// opened relative to the held root without following a link, the marker is
/// read and the tree emptied through that handle, and the final removal
/// re-proves the name still names it — a level swapped for a link mid-walk is
/// refused, its target untouched.
///
/// # Errors
/// [`CliError::OutputRefused`] for a symlink or an unmarked `out/`;
/// [`CliError::Io`] on a stat or remove failure.
fn remove_generated_dir(root: &Path, generated: &Generated) -> Result<Vec<String>, CliError> {
    use crate::output_dir::OutputRefusal;
    use crate::output_dir::held::{EntryKind, HeldDir, OwnedNow, level_held};
    let name = generated.name;
    let candidate = root.join(name);
    let Some(root_dir) = HeldDir::open_following(root)? else {
        return Ok(Vec::new());
    };
    let os_name = std::ffi::OsStr::new(name);
    match root_dir.kind_of(os_name)? {
        EntryKind::Symlink => return Err(OutputRefusal::Symlink(candidate).into()),
        EntryKind::Absent | EntryKind::Other => return Ok(Vec::new()),
        EntryKind::Directory => {}
    }
    let Some(dir) = root_dir.child(os_name)? else {
        return Ok(Vec::new());
    };
    level_held(dir.path());
    match generated.proof {
        Proof::Marker => {
            match dir.owned_now()? {
                OwnedNow::Owned => {}
                OwnedNow::Claiming => return Err(OutputRefusal::ClaimInFlight(candidate).into()),
                OwnedNow::Unowned => return Err(OutputRefusal::NotIpeOwned(candidate).into()),
            }
            root_dir.remove_proven(os_name, dir)?;
            Ok(vec![format!("{name}/")])
        }
        Proof::Namespace(entries) => {
            let mut removed = Vec::new();
            for entry in entries {
                let os_entry = std::ffi::OsStr::new(entry);
                match dir.kind_of(os_entry)? {
                    EntryKind::Directory => {
                        dir.remove_entry(os_entry)?;
                        removed.push(format!("{name}/{entry}/"));
                    }
                    EntryKind::Symlink => {
                        return Err(OutputRefusal::Symlink(candidate.join(entry)).into());
                    }
                    EntryKind::Absent | EntryKind::Other => {}
                }
            }
            if root_dir.remove_empty_dir(os_name, dir)? {
                return Ok(vec![format!("{name}/")]);
            }
            Ok(removed)
        }
    }
}

/// Print the removal result in the requested format.
///
/// `--json` emits `{"schema":"ipe.cli.clean/1","removed":[…]}`.
/// `--plain` prints one removed path per line, flush-left, with no summary.
/// Human (default) prints a decorated frame with a one-line count.
fn print_summary(removed: &[String], format: OutputFormat) {
    use OutputFormat::{Human, Json, Plain};
    match format {
        Json => {
            use crate::cli_args::json;
            let items: Vec<String> = removed.iter().map(|s| json::string(s)).collect();
            let payload = json::object(&[
                ("schema", json::string("ipe.cli.clean/1")),
                ("removed", json::array(&items)),
            ]);
            screen::emit_machine(Stream::Stdout, &format!("{payload}\n"));
        }
        Plain => {
            let mut lines = String::new();
            for dir in removed {
                lines.push_str(dir);
                lines.push('\n');
            }
            screen::emit_machine(Stream::Stdout, &lines);
        }
        Human => {
            // A completed clean is a success: its glyph and tone come from the
            // style SSOT, not a per-site glyph/colour pairing.
            let glyph = style::outcome_glyph(style::Outcome::Success);
            let mut body = String::new();
            if removed.is_empty() {
                body.push_str("Nothing to clean — no generated output found.\n");
            } else {
                for dir in removed {
                    let _ = writeln!(body, "{glyph} removed {dir}");
                }
                let n = removed.len();
                let noun = if n == 1 { "directory" } else { "directories" };
                let _ = writeln!(body, "\nCleaned {n} generated {noun}.");
            }
            Screen::new(Stream::Stdout)
                .line(Tone::Success, &body)
                .emit();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output_dir::test_links::plant_link;

    const OUT: &Generated = &Generated {
        name: "out",
        proof: Proof::Marker,
    };
    const DOT_IPE: &Generated = &Generated {
        name: ".ipe",
        proof: Proof::Namespace(CACHE_NAMESPACE_ENTRIES),
    };

    /// `remove_generated_dir` deletes an ipe-owned output directory and reports it.
    #[test]
    fn removes_a_generated_subdir() {
        let root = ipe_test_temp::temp_root().join(format!("ipe_clean_ok_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("make root");
        let real_root = std::fs::canonicalize(&root).expect("canonicalize root");
        crate::output_dir::OwnedDir::claim(&real_root.join("out").join("rust"))
            .expect("claim out/rust");

        let removed = remove_generated_dir(&real_root, OUT).expect("remove must succeed");
        assert_eq!(removed, ["out/"]);
        assert!(!real_root.join("out").exists(), "out/ must be gone");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// An `out/` ipe did not create — no ownership marker — is refused and kept.
    #[test]
    fn refuses_an_unowned_out_dir() {
        let root =
            ipe_test_temp::temp_root().join(format!("ipe_clean_unowned_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("out")).expect("make out");
        std::fs::write(root.join("out").join("thesis.tex"), "mine").expect("user file");
        let real_root = std::fs::canonicalize(&root).expect("canonicalize root");

        let result = remove_generated_dir(&real_root, OUT);
        assert!(
            matches!(result, Err(CliError::OutputRefused(_))),
            "an unmarked out/ must be refused, got: {result:?}"
        );
        assert!(
            real_root.join("out").join("thesis.tex").is_file(),
            "user file kept"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A marked `out/` whose claim is still in flight is refused and kept.
    #[test]
    fn clean_refuses_a_claim_in_flight() {
        let root =
            ipe_test_temp::temp_root().join(format!("ipe_clean_claiming_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("make root");
        let real_root = std::fs::canonicalize(&root).expect("canonicalize root");
        let out = real_root.join("out");
        crate::output_dir::OwnedDir::claim(&out).expect("claim out");
        std::fs::write(out.join("keep.txt"), "kept").expect("output file");
        std::fs::write(out.join(crate::output_dir::CLAIM_FILE), b"").expect("claim in flight");

        let result = remove_generated_dir(&real_root, OUT);
        assert!(
            matches!(
                result,
                Err(CliError::OutputRefused(
                    crate::output_dir::OutputRefusal::ClaimInFlight(_)
                ))
            ),
            "a claim in flight must be refused, got: {result:?}"
        );
        assert!(out.join("keep.txt").is_file(), "the output is kept");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// An absent directory is a no-op, not an error.
    #[test]
    fn absent_dir_is_a_noop() {
        let root =
            ipe_test_temp::temp_root().join(format!("ipe_clean_absent_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("make root");
        let real_root = std::fs::canonicalize(&root).expect("canonicalize root");

        let removed = remove_generated_dir(&real_root, DOT_IPE).expect("must succeed");
        assert!(removed.is_empty(), "an absent dir yields no removal");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A generated name that is a symlink escaping the project root is refused,
    /// and the escape target is left intact — the delete never leaves the root.
    #[test]
    fn refuses_a_symlink_escaping_the_root() {
        let base =
            ipe_test_temp::temp_root().join(format!("ipe_clean_escape_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("project");
        let outside = base.join("precious");
        std::fs::create_dir_all(&root).expect("make root");
        std::fs::create_dir_all(&outside).expect("make outside");
        std::fs::write(outside.join("keep.txt"), b"do not delete").expect("write victim");
        let real_root = std::fs::canonicalize(&root).expect("canonicalize root");

        // `out` inside the project is a symlink to the outside directory.
        plant_link(&outside, &root.join("out"));

        let result = remove_generated_dir(&real_root, OUT);
        assert!(
            matches!(result, Err(CliError::OutputRefused(_))),
            "an escaping symlink must be refused, got: {result:?}"
        );
        assert!(
            outside.join("keep.txt").exists(),
            "the escape target must be left untouched"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Planted symlinks in a marked `out/` are removed as links.
    ///
    /// Neither target is followed or touched.
    #[test]
    fn removes_planted_links_without_following_them() {
        let base =
            ipe_test_temp::temp_root().join(format!("ipe_clean_planted_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("project");
        let outside = base.join("precious");
        std::fs::create_dir_all(&root).expect("make root");
        std::fs::create_dir_all(&outside).expect("make outside");
        std::fs::write(outside.join("keep.txt"), b"do not delete").expect("write victim");
        let real_root = std::fs::canonicalize(&root).expect("canonicalize root");
        crate::output_dir::OwnedDir::claim(&real_root.join("out")).expect("claim out");
        plant_link(&outside, &real_root.join("out").join("rust"));
        plant_link(
            &outside.join("keep.txt"),
            &real_root.join("out").join("bin"),
        );

        let removed = remove_generated_dir(&real_root, OUT).expect("remove must succeed");
        assert_eq!(removed, ["out/"]);
        assert_eq!(
            std::fs::read(outside.join("keep.txt")).ok().as_deref(),
            Some(&b"do not delete"[..]),
            "link targets survive byte-for-byte"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// The `.ipe/` cache subtrees go, and an emptied namespace goes with them.
    #[test]
    fn removes_the_cache_namespace_when_only_ipe_entries_are_in_it() {
        let root = ipe_test_temp::temp_root().join(format!("ipe_clean_ns_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".ipe/cache/ffi/rust")).expect("make cache");
        std::fs::create_dir_all(root.join(".ipe/packages/dep-1.0.0")).expect("make packages");
        let real_root = std::fs::canonicalize(&root).expect("canonicalize root");

        let removed = remove_generated_dir(&real_root, DOT_IPE).expect("must succeed");
        assert_eq!(removed, [".ipe/"]);
        assert!(!real_root.join(".ipe").exists(), ".ipe/ must be gone");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Anything in `.ipe/` that ipe did not write survives, and so does `.ipe/`.
    ///
    /// `.ipe/` carries no ownership marker, so only the cache entries ipe
    /// names are proven its own.
    #[test]
    fn keeps_user_files_in_an_unmarked_cache_namespace() {
        let root =
            ipe_test_temp::temp_root().join(format!("ipe_clean_ns_user_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".ipe/cache")).expect("make cache");
        std::fs::create_dir_all(root.join(".ipe/standalone/src")).expect("make user tree");
        std::fs::write(root.join(".ipe/standalone/src/main.rs"), "fn main() {}").expect("user");
        std::fs::write(root.join(".ipe/notes.txt"), "mine").expect("user note");
        let real_root = std::fs::canonicalize(&root).expect("canonicalize root");

        let removed = remove_generated_dir(&real_root, DOT_IPE).expect("must succeed");
        assert_eq!(removed, [".ipe/cache/"]);
        assert!(
            !real_root.join(".ipe/cache").exists(),
            "the cache must be gone"
        );
        assert_eq!(
            std::fs::read_to_string(real_root.join(".ipe/standalone/src/main.rs"))
                .ok()
                .as_deref(),
            Some("fn main() {}"),
            "a user tree in .ipe/ survives"
        );
        assert!(
            real_root.join(".ipe/notes.txt").is_file(),
            "a user file in .ipe/ survives"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A symlinked cache entry is refused, never followed.
    #[test]
    fn refuses_a_symlinked_cache_entry() {
        let base =
            ipe_test_temp::temp_root().join(format!("ipe_clean_ns_link_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("project");
        let outside = base.join("precious");
        std::fs::create_dir_all(root.join(".ipe")).expect("make .ipe");
        std::fs::create_dir_all(&outside).expect("make outside");
        std::fs::write(outside.join("keep.txt"), b"do not delete").expect("write victim");
        plant_link(&outside, &root.join(".ipe").join("cache"));
        let real_root = std::fs::canonicalize(&root).expect("canonicalize root");

        let result = remove_generated_dir(&real_root, DOT_IPE);
        assert!(
            matches!(result, Err(CliError::OutputRefused(_))),
            "a symlinked cache entry must be refused, got: {result:?}"
        );
        assert!(
            outside.join("keep.txt").is_file(),
            "the link target survives"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// An `out/` swapped for a link after clean held it is refused, the link's target untouched.
    #[cfg(unix)]
    #[test]
    fn refuses_an_out_dir_swapped_for_a_link_mid_walk() {
        let base =
            ipe_test_temp::temp_root().join(format!("ipe_clean_swap_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("project");
        let victim = base.join("precious");
        std::fs::create_dir_all(&root).expect("make root");
        std::fs::create_dir_all(&victim).expect("make victim");
        std::fs::write(victim.join("keep.txt"), "keep").expect("write victim");
        let real_root = std::fs::canonicalize(&root).expect("canonicalize root");
        let out = real_root.join("out");
        crate::output_dir::OwnedDir::claim(&out).expect("claim out");
        std::fs::write(out.join("generated.rs"), "gen").expect("generated file");
        let (level, target) = (out.clone(), victim.clone());
        let mut swap = Some(move || {
            std::fs::rename(&level, level.with_extension("aside")).expect("move out aside");
            std::os::unix::fs::symlink(&target, &level).expect("plant link");
        });
        crate::output_dir::held::set_level_hook(Some(Box::new(move |held: &Path| {
            if held == out
                && let Some(swap) = swap.take()
            {
                swap();
            }
        })));
        let result = remove_generated_dir(&real_root, OUT);
        crate::output_dir::held::set_level_hook(None);
        assert!(
            matches!(result, Err(CliError::OutputRefused(_))),
            "a swapped-in link must be refused, got: {result:?}"
        );
        assert_eq!(
            std::fs::read_to_string(victim.join("keep.txt"))
                .ok()
                .as_deref(),
            Some("keep"),
            "the link target must be left untouched"
        );
        assert!(
            real_root.join("out").is_symlink(),
            "the planted link is not removed"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// An `out/` emptied and junctioned in place after clean held it is refused, the target untouched.
    ///
    /// A held level cannot be renamed on this platform, only turned into a
    /// junction once empty.
    #[cfg(windows)]
    #[test]
    fn refuses_an_out_dir_junctioned_in_place_mid_walk() {
        let base =
            ipe_test_temp::temp_root().join(format!("ipe_clean_junction_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("project");
        let victim = base.join("precious");
        std::fs::create_dir_all(&root).expect("make root");
        std::fs::create_dir_all(&victim).expect("make victim");
        std::fs::write(victim.join("keep.txt"), "keep").expect("write victim");
        let real_root = std::fs::canonicalize(&root).expect("canonicalize root");
        let out = real_root.join("out");
        crate::output_dir::OwnedDir::claim(&out).expect("claim out");
        std::fs::write(out.join("generated.rs"), "gen").expect("generated file");
        let (level, target) = (out.clone(), victim.clone());
        let mut swap = Some(move || {
            for entry in std::fs::read_dir(&level).expect("list out") {
                std::fs::remove_file(entry.expect("out entry").path()).expect("empty out");
            }
            crate::output_dir::test_links::junction_in_place(&level, &target);
        });
        crate::output_dir::held::set_level_hook(Some(Box::new(move |held: &Path| {
            if held == out
                && let Some(swap) = swap.take()
            {
                swap();
            }
        })));
        let result = remove_generated_dir(&real_root, OUT);
        crate::output_dir::held::set_level_hook(None);
        assert!(
            result.is_err(),
            "a junctioned out/ must be refused, got: {result:?}"
        );
        assert_eq!(
            std::fs::read_to_string(victim.join("keep.txt"))
                .ok()
                .as_deref(),
            Some("keep"),
            "the junction target must be left untouched"
        );
        assert_eq!(
            std::fs::read_dir(&victim).expect("read victim").count(),
            1,
            "nothing is removed from the junction target"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
