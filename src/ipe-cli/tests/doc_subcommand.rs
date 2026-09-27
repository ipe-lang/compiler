//! End-to-end tests for `ipe doc` — the documentation-generation command.
//!
//! Covers the closed `DocMode` subcommand surface (generate / serve / check,
//! with invalid flag combinations rejected), `docs.json` + Markdown + HTML
//! generation over a real fixture package, cross-reference resolution (an
//! in-package type links, a built-in does not), the coverage gate's exit code on
//! a missing doc-comment, and the `serve` preview binding a free loopback port
//! and returning the index page.
//!
//! Each test returns `io::Result` so filesystem setup propagates with `?` rather
//! than `unwrap`/`expect` (both workspace-denied). A setup failure fails the test
//! by the returned `Err`, exactly as a panic would, without a denied construct.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

mod support;

/// Run `ipe <args>` with `NO_COLOR=1` and return `(exit_success, stdout, stderr)`.
fn run(args: &[&str]) -> (bool, String, String) {
    match Command::new(support::ipe_bin())
        .args(args)
        .env("NO_COLOR", "1")
        .output()
    {
        Ok(o) => (
            o.status.success(),
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        ),
        Err(e) => (false, String::new(), format!("spawn failed: {e}")),
    }
}

/// The `str` form of a path, empty when it is not valid UTF-8 (never the case
/// for the temp paths these tests build).
fn as_str(path: &Path) -> &str {
    path.to_str().unwrap_or_default()
}

/// A fresh, unique temp directory for one test (removed first if present).
fn fresh_dir(tag: &str) -> PathBuf {
    let dir = crate::support::scratch_root().join(format!("ipe_doc_test_{tag}"));
    let _ = fs::remove_dir_all(&dir);
    dir
}

/// Write a fully-documented one-module package under `dir/src` and return `dir`.
fn documented_package(tag: &str) -> io::Result<PathBuf> {
    let dir = fresh_dir(tag);
    let src = dir.join("src");
    fs::create_dir_all(&src)?;
    fs::write(
        src.join("Shapes.ipe"),
        "-- | Shapes — a tiny geometry library.\n\
         module Shapes exposing (Shape, area)\n\n\
         -- | A geometric shape.\n\
         type Shape\n    = Circle Float\n    | Rectangle Float Float\n\n\
         -- | `area shape` — the area of `shape`.\n\
         area : Shape -> Float\n\
         area shape =\n    case shape of\n        \
         Circle r ->\n            r\n\n        \
         Rectangle w h ->\n            w * h\n",
    )?;
    Ok(dir)
}

#[test]
fn generate_writes_docs_json_and_markdown() -> io::Result<()> {
    let pkg = documented_package("generate")?;
    let out = pkg.join("out");
    let (ok, stdout, stderr) = run(&["doc", as_str(&pkg), "--out", as_str(&out)]);
    assert!(ok, "generate must succeed:\n{stdout}\n{stderr}");

    // docs.json lives under the json/ subfolder.
    let json = fs::read_to_string(out.join("json").join("docs.json"))?;
    // The versioned schema and the exposed surface (module, union, value) with
    // its checker-provided signature and its scanned doc-comment.
    assert!(
        json.contains("\"version\": 2"),
        "schema is versioned:\n{json}"
    );
    assert!(json.contains("\"name\": \"Shapes\""));
    assert!(json.contains("\"name\": \"Shape\""));
    assert!(json.contains("\"name\": \"area\""));
    assert!(
        json.contains("Shape -> Float"),
        "the value's checker signature is present:\n{json}"
    );
    assert!(
        json.contains("A geometric shape."),
        "the union's doc-comment is present:\n{json}"
    );

    // Markdown pages live under the markdown/ subfolder.
    let md = fs::read_to_string(out.join("markdown").join("Shapes.md"))?;
    assert!(md.contains("# Shapes"));
    assert!(md.contains("### `area"));
    // The markdown index is also generated.
    assert!(
        out.join("markdown").join("index.md").exists(),
        "markdown index is written"
    );
    Ok(())
}

#[test]
fn generate_writes_a_self_contained_html_site_with_anchors_and_xrefs() -> io::Result<()> {
    let pkg = documented_package("html")?;
    let out = pkg.join("out");
    let (ok, stdout, stderr) = run(&["doc", as_str(&pkg), "--out", as_str(&out)]);
    assert!(ok, "generate must succeed:\n{stdout}\n{stderr}");

    // The HTML site lives under the html/ subfolder.
    let html_dir = out.join("html");
    let index = fs::read_to_string(html_dir.join("index.html"))?;
    assert!(index.contains("<!DOCTYPE html>"));
    assert!(
        index.contains("href=\"style.css\""),
        "the index links the bundled CSS:\n{index}"
    );
    // The landing page is now teach-first; module links live in module/index.html.
    let module_index = fs::read_to_string(html_dir.join("module").join("index.html"))?;
    assert!(
        module_index.contains("href=\"../Shapes.html\""),
        "the module index lists the module:\n{module_index}"
    );
    assert!(
        html_dir.join("style.css").exists(),
        "the CSS is written beside it"
    );

    let page = fs::read_to_string(html_dir.join("Shapes.html"))?;
    // Stable per-entry anchors, identical to the docs.json anchor scheme.
    assert!(
        page.contains("id=\"Shape\""),
        "the type has an anchor:\n{page}"
    );
    assert!(
        page.contains("id=\"area\""),
        "the value has an anchor:\n{page}"
    );
    // A cross-reference: the in-package `Shape` links; the builtin `Float` does
    // not.
    assert!(
        page.contains("<a href=\"Shapes.html#Shape\">"),
        "the in-package type links:\n{page}"
    );
    assert!(
        !page.contains(">Float</a>"),
        "a built-in type is plain text, never a dangling link:\n{page}"
    );
    Ok(())
}

#[test]
fn docs_json_records_resolved_cross_references() -> io::Result<()> {
    let pkg = documented_package("xref_json")?;
    let out = pkg.join("out");
    let (ok, _o, _e) = run(&["doc", as_str(&pkg), "--out", as_str(&out)]);
    assert!(ok);

    // docs.json lives under the json/ subfolder.
    let json = fs::read_to_string(out.join("json").join("docs.json"))?;
    // `area : Shape -> Float` records exactly one reference — the in-package
    // `Shape` — and none for the built-in `Float`.
    assert!(
        json.contains("\"anchor\": \"Shapes#Shape\""),
        "the in-package reference is recorded:\n{json}"
    );
    Ok(())
}

#[test]
fn generate_without_project_documents_stdlib() -> io::Result<()> {
    // In an empty directory (no package manifest), `ipe doc --write-format html`
    // must succeed and produce doc/html/ containing stdlib module pages.
    let dir = fresh_dir("stdlib_no_project");
    fs::create_dir_all(&dir)?;
    let out = dir.join("out");
    let (ok, stdout, stderr) = run_in(
        &dir,
        &["doc", "--write-format", "html", "--out", as_str(&out)],
    );
    assert!(ok, "stdlib-only generate must succeed:\n{stdout}\n{stderr}");

    let html_dir = out.join("html");
    assert!(
        html_dir.exists(),
        "doc/html/ is created even without a project"
    );
    assert!(
        html_dir.join("index.html").exists(),
        "index.html is written"
    );
    // At least one well-known stdlib module page must be present.
    let has_list = html_dir.join("Ipe-List.html").exists();
    let has_string = html_dir.join("Ipe-String.html").exists();
    assert!(
        has_list || has_string,
        "at least one stdlib module page exists in {html_dir:?}"
    );
    // The index must mention at least one stdlib module.
    let index = fs::read_to_string(html_dir.join("index.html"))?;
    assert!(
        index.contains("Ipe.List") || index.contains("Ipe.String"),
        "the index lists stdlib modules:\n{index}"
    );
    Ok(())
}

#[test]
fn serve_binds_a_free_port_and_serves_the_index() -> io::Result<()> {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpStream;

    let pkg = documented_package("serve")?;
    // Spawn `ipe doc serve` with an auto-selected port and read the URL it prints.
    let mut child = Command::new(support::ipe_bin())
        .args(["doc", "serve", as_str(&pkg)])
        .env("NO_COLOR", "1")
        // Never let the preview pop (or spawn) a browser opener under test.
        .env("IPE_DOC_NO_OPEN", "1")
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("serve produced no stdout handle"))?;
    let mut lines = BufReader::new(stdout).lines();
    // The announce is framed (a leading blank line + a 2-space gutter), so scan
    // for the line carrying the URL rather than assuming it is the first line.
    let announce = lines
        .by_ref()
        .map_while(Result::ok)
        .find(|l| l.contains("http://"))
        .ok_or_else(|| io::Error::other("serve printed no URL"))?;

    // Extract `127.0.0.1:<port>` from the announce line.
    let addr = announce
        .split_whitespace()
        .find(|w| w.starts_with("http://"))
        .and_then(|u| u.trim_start_matches("http://").split('/').next())
        .map(str::to_owned);
    let Some(addr) = addr else {
        let _ = child.kill();
        return Err(io::Error::other(format!(
            "no URL in serve announce: {announce}"
        )));
    };

    // Fetch `/` with a hand-rolled HTTP/1.1 GET and confirm it is the index page.
    let result = (|| -> io::Result<String> {
        let mut stream = TcpStream::connect(&addr)?;
        stream.write_all(
            format!("GET / HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes(),
        )?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    })();

    // Always reap the server, whatever the fetch did.
    let _ = child.kill();
    let _ = child.wait();

    let response = result?;
    assert!(
        response.contains("200 OK"),
        "serve returns 200 for /:\n{response}"
    );
    assert!(
        response.contains("text/html"),
        "serve returns HTML content-type for /:\n{response}"
    );
    // The teach-first landing has its own h1 — not the old generated title.
    assert!(
        response.contains("<h1>Documentation</h1>"),
        "serve returns the teach-first landing page:\n{response}"
    );
    // The persistent header is present on the landing.
    assert!(
        response.contains("site-header"),
        "serve landing includes the persistent nav header:\n{response}"
    );
    // Reference (the module index) is one click away via the header link.
    assert!(
        response.contains("module/index.html"),
        "the persistent header links to the module reference index:\n{response}"
    );
    Ok(())
}

#[test]
fn list_groups_project_modules_before_the_standard_library() -> io::Result<()> {
    let pkg = documented_package("list_grouping")?;
    let (ok, stdout, stderr) = run(&["doc", "list", as_str(&pkg)]);
    assert!(ok, "`ipe doc list` must succeed:\n{stdout}\n{stderr}");

    // Both labelled sections are present, project first.
    let project = stdout
        .find("Project modules")
        .expect("a project-modules section label");
    let stdlib = stdout
        .find("Standard library")
        .expect("a standard-library section label");
    assert!(
        project < stdlib,
        "the project section comes before the standard library:\n{stdout}"
    );

    // The user's own module is listed under the project section, ahead of the
    // stdlib section (so a stdlib module name appears only after the label).
    let shapes = stdout.find("Shapes").expect("the project module is listed");
    assert!(
        shapes < stdlib,
        "the project module sorts before the standard library:\n{stdout}"
    );
    Ok(())
}

#[test]
fn deprecated_list_flag_still_lists_and_warns() -> io::Result<()> {
    // `--list` keeps working (never-break-users) but steers the caller to the
    // bare `list` mode via a stderr notice; the listing itself is unchanged.
    let pkg = documented_package("list_alias")?;
    let (ok, stdout, stderr) = run(&["doc", "--list", as_str(&pkg)]);
    assert!(
        ok,
        "the deprecated `--list` alias must still succeed:\n{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("Shapes"),
        "the alias lists the project module:\n{stdout}"
    );
    assert!(
        stderr.contains("deprecated") && stderr.contains("doc list"),
        "the alias prints a deprecation notice on stderr:\n{stderr}"
    );
    Ok(())
}

/// Run `ipe <args>` with `cwd` as the working directory, returning
/// `(exit_success, stdout, stderr)`. `ipe doc --list` / `<module>` resolve the
/// project from the current directory, so running from an empty dir yields the
/// stdlib set alone.
fn run_in(cwd: &Path, args: &[&str]) -> (bool, String, String) {
    match Command::new(support::ipe_bin())
        .args(args)
        .current_dir(cwd)
        .env("NO_COLOR", "1")
        .output()
    {
        Ok(o) => (
            o.status.success(),
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        ),
        Err(e) => (false, String::new(), format!("spawn failed: {e}")),
    }
}

#[test]
fn every_listed_module_is_queryable() -> io::Result<()> {
    // The advertised==available invariant: every name `ipe doc --list` prints
    // must resolve on `ipe doc <name>`. A listed-but-unqueryable module (a
    // `--list` entry that 404s with IPE-N0004) is the exact list-vs-query
    // registry drift this guards against. Run from an empty dir so the listing is
    // stdlib only — no project modules to shadow it, and no path positional (a
    // `<module>` query takes only the module name).
    let dir = fresh_dir("listed_queryable");
    fs::create_dir_all(&dir)?;

    let (ok, listed, stderr) = run_in(&dir, &["doc", "--list", "--plain"]);
    assert!(ok, "`ipe doc --list` must succeed:\n{listed}\n{stderr}");

    let names: Vec<&str> = listed
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    assert!(
        !names.is_empty(),
        "the stdlib listing is non-empty:\n{listed}"
    );

    // Each `ipe doc <name>` is an independent read-only subprocess over the same
    // empty dir, so a bounded worker pool over a shared cursor collapses the
    // ~165 serial spawns into a few parallel waves — same assertion, a fraction
    // of the wall-clock — without changing what is proven.
    let failures = Mutex::new(Vec::<String>::new());
    let cursor = AtomicUsize::new(0);
    let workers = std::thread::available_parallelism()
        .map_or(8, |n| (n.get() * 2).clamp(4, 16))
        .min(names.len().max(1));
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let i = cursor.fetch_add(1, Ordering::Relaxed);
                    let Some(name) = names.get(i) else { break };
                    let (q_ok, q_out, q_err) = run_in(&dir, &["doc", name, "--plain"]);
                    if !q_ok {
                        failures
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(format!(
                                "listed module `{name}` must be queryable (no IPE-N0004):\n{q_out}\n{q_err}"
                            ));
                    }
                }
            });
        }
    });
    let failures = failures
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(
        failures.is_empty(),
        "{} listed module(s) not queryable:\n{}",
        failures.len(),
        failures.join("\n---\n")
    );
    Ok(())
}

#[test]
fn generated_docs_json_is_local_first_and_tags_each_module_kind() -> io::Result<()> {
    let pkg = documented_package("json_kind")?;
    let out = pkg.join("out");
    let (ok, stdout, stderr) = run(&["doc", as_str(&pkg), "--out", as_str(&out)]);
    assert!(ok, "generate must succeed:\n{stdout}\n{stderr}");

    // docs.json lives under the json/ subfolder.
    let json = fs::read_to_string(out.join("json").join("docs.json"))?;
    // Each module carries its group tag.
    assert!(
        json.contains("\"kind\": \"local\""),
        "a local module is tagged:\n{json}"
    );
    assert!(
        json.contains("\"kind\": \"stdlib\""),
        "a stdlib module is tagged:\n{json}"
    );
    // The user's own module is serialized before the first stdlib module.
    let local = json
        .find("\"kind\": \"local\"")
        .expect("a local-kind module");
    let stdlib = json
        .find("\"kind\": \"stdlib\"")
        .expect("a stdlib-kind module");
    assert!(
        local < stdlib,
        "the project module comes before the standard library:\n{json}"
    );
    Ok(())
}

#[test]
fn check_passes_when_every_binding_is_documented() -> io::Result<()> {
    let pkg = documented_package("check_pass")?;
    let (ok, stdout, stderr) = run(&["doc", "check", as_str(&pkg)]);
    assert!(
        ok,
        "check must exit 0 for a fully-documented package:\n{stdout}\n{stderr}"
    );
    Ok(())
}

#[test]
fn check_fails_and_names_the_undocumented_binding() -> io::Result<()> {
    let dir = fresh_dir("check_fail");
    let src = dir.join("src");
    fs::create_dir_all(&src)?;
    // `shout` is exposed but carries no `-- |` comment.
    fs::write(
        src.join("Bare.ipe"),
        "module Bare exposing (greet, shout)\n\n\
         -- | `greet name` — a greeting.\n\
         greet : String -> String\n\
         greet name =\n    name\n\n\
         shout : String -> String\n\
         shout name =\n    name\n",
    )?;

    let (ok, _stdout, stderr) = run(&["doc", "check", as_str(&dir)]);
    assert!(!ok, "check must exit non-zero on a missing doc-comment");
    assert!(
        stderr.contains("Bare.shout"),
        "the report must name the undocumented binding, got:\n{stderr}"
    );
    // The gate reports plainly — it is not a command misuse, so it does not dump
    // the `--help` page.
    assert!(
        !stderr.contains("Options:"),
        "a coverage failure must not print the command help page, got:\n{stderr}"
    );
    Ok(())
}

#[test]
fn check_rejects_the_out_flag() {
    // `--out` is a generate-only flag; under `check` it is unrepresentable in
    // `DocMode` and rejected at the boundary.
    let (ok, _stdout, stderr) = run(&["doc", "check", "--out", "x"]);
    assert!(!ok, "`ipe doc check --out` must be rejected");
    assert!(
        stderr.contains("--out"),
        "the error must mention the offending flag, got:\n{stderr}"
    );
}

#[test]
fn unknown_flag_is_rejected() {
    let (ok, _stdout, stderr) = run(&["doc", "--bogus"]);
    assert!(!ok, "an unknown flag must be rejected");
    assert!(
        stderr.contains("bogus"),
        "the error must name the bad flag, got:\n{stderr}"
    );
}

#[test]
fn help_page_describes_the_shipped_surface() {
    let (ok, stdout, _) = run(&["doc", "--help"]);
    assert!(ok, "`ipe doc --help` exits 0");
    assert!(stdout.contains("ipe doc"), "help names the command");
    assert!(
        stdout.contains("check"),
        "help mentions the check subcommand"
    );
    // The now-shipped surface is advertised: the serve subcommand, the HTML
    // rendering, and the --write-format / --port flags.
    assert!(
        stdout.contains("serve"),
        "help mentions serve, got:\n{stdout}"
    );
    assert!(
        stdout.to_uppercase().contains("HTML"),
        "help mentions HTML, got:\n{stdout}"
    );
    assert!(
        stdout.contains("--write-format") && stdout.contains("--port"),
        "help mentions the generate and serve flags, got:\n{stdout}"
    );
    // The bare-word `list` mode and module-query surface are advertised, and the
    // deprecated `--list` alias is noted (not silently dropped).
    assert!(
        stdout.contains("list"),
        "help mentions list, got:\n{stdout}"
    );
    assert!(
        stdout.contains("--list"),
        "help notes the deprecated --list alias, got:\n{stdout}"
    );
    assert!(
        stdout.contains("--plain") && stdout.contains("--json"),
        "help mentions --plain/--json for queries, got:\n{stdout}"
    );
    // Still-deferred surfaces must not be advertised.
    assert!(
        !stdout.to_lowercase().contains("search"),
        "help must not advertise unshipped full-text search, got:\n{stdout}"
    );
}

/// `ipe doc Module.member` resolves to the member's own doc — a value of a
/// compiled-source stdlib module included — never "unknown module".
#[test]
fn a_qualified_member_resolves_to_its_doc() -> io::Result<()> {
    let dir = fresh_dir("member_lookup");
    fs::create_dir_all(&dir)?;
    for key in ["Ipe.Time.unixMillis", "Time.unixMillis", "Ipe.List.map"] {
        let (ok, stdout, stderr) = run_in(&dir, &["doc", key, "--plain"]);
        assert!(ok, "`ipe doc {key}` must resolve:\n{stdout}\n{stderr}");
        let member = key.rsplit('.').next().unwrap_or(key);
        assert!(
            stdout.contains(member),
            "`ipe doc {key}` shows the member:\n{stdout}"
        );
        assert!(
            !stderr.contains("unknown module"),
            "no unknown-module error:\n{stderr}"
        );
    }
    Ok(())
}

/// A query that names no entry is a miss that never dead-ends.
///
/// It lists the closest entries of any kind as ready-to-run `ipe doc` commands, in the error
/// frame, without the command's usage page.
#[test]
fn a_miss_lists_the_closest_matches_as_commands() -> io::Result<()> {
    let dir = fresh_dir("miss_suggestions");
    fs::create_dir_all(&dir)?;
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "unixMilis"]);
    assert!(!ok, "a miss exits non-zero");
    assert!(
        stdout.is_empty(),
        "a miss writes nothing to stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("no documentation entry is named `unixMilis`"),
        "{stderr}"
    );
    assert!(stderr.contains("Closest matches:"), "{stderr}");
    assert!(
        stderr.contains("ipe doc Ipe.Time.unixMillis"),
        "the typo'd member is suggested as a command:\n{stderr}"
    );
    assert!(
        !stderr.contains("Options:"),
        "a miss is not misuse; no usage page:\n{stderr}"
    );
    assert!(
        !stderr.contains("If you find any bugs, please report them at"),
        "a miss is the user's to fix; no bug footer:\n{stderr}"
    );
    Ok(())
}

/// Even a query close to nothing gets suggestions (bounded), and a bare member
/// name lists every module member of that name.
#[test]
fn every_miss_suggests_something_and_bare_names_find_members() -> io::Result<()> {
    let dir = fresh_dir("miss_nearest");
    fs::create_dir_all(&dir)?;
    let (ok, _stdout, stderr) = run_in(&dir, &["doc", "qqqqzzzzxxxx"]);
    assert!(!ok);
    let suggested = stderr.matches("ipe doc ").count();
    assert!(
        (1..=8).contains(&suggested),
        "a far miss still suggests a bounded list:\n{stderr}"
    );
    let (ok, _stdout, stderr) = run_in(&dir, &["doc", "unixMillis"]);
    assert!(!ok, "a bare member name is not an exact key");
    assert!(
        stderr.contains("ipe doc Ipe.Time.unixMillis"),
        "the bare member name finds the qualified member:\n{stderr}"
    );
    Ok(())
}

/// Under `--json` a miss is a machine outcome: the shared error envelope on
/// stderr, nothing on stdout, never the human frame.
#[test]
fn a_miss_under_json_is_the_machine_error_envelope() -> io::Result<()> {
    let dir = fresh_dir("miss_json");
    fs::create_dir_all(&dir)?;
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "qqqqzzzzxxxx", "--json"]);
    assert!(!ok);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("\"ipe.cli.error/1\""), "{stderr}");
    assert!(stderr.contains("doc-not-found"), "{stderr}");
    assert!(
        !stderr.contains("Ipê language"),
        "no human frame:\n{stderr}"
    );
    Ok(())
}
