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

/// A fresh, unique, existing temp directory for one test (emptied first if
/// present), so a test can run `ipe` in it without creating it first.
fn fresh_dir(tag: &str) -> io::Result<PathBuf> {
    let dir = crate::support::scratch_root().join(format!("ipe_doc_test_{tag}"));
    e2e_support::scratch::fresh(&dir);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Write a fully-documented one-module package under `dir/src` and return `dir`.
fn documented_package(tag: &str) -> io::Result<PathBuf> {
    let dir = fresh_dir(tag)?;
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

/// `ipe doc guide:agents --plain` prints the embedded guide byte for byte, so
/// redirecting it to `AGENTS.md` yields a current guide.
#[test]
fn guide_agents_plain_is_asset_bytes() -> io::Result<()> {
    let dir = fresh_dir("guide_agents_plain")?;
    let (ok, stdout, stderr) = run_in(&dir, &["doc", ipe::agents_guide::GUIDE_TERM, "--plain"]);
    assert!(ok, "doc guide:agents must succeed: {stderr}");
    assert_eq!(stdout, ipe::agents_guide::ASSET);
    Ok(())
}

/// A page's fence info string is markup, never text: `ipe doc IPE-T0018` lays out its
/// `ipe ipe:error` example as code and prints neither the language nor the marker.
#[test]
fn fence_info_never_printed() {
    let (ok, stdout, stderr) = run(&["doc", "IPE-T0018"]);
    assert!(ok, "doc IPE-T0018 must succeed: {stderr}");
    assert!(stdout.contains("IPE-T0018"), "the page opens: {stdout}");
    assert!(!stdout.contains("ipe:error"), "fence info leaked: {stdout}");
    assert!(!stdout.contains("```"), "fence marker leaked: {stdout}");
    assert!(
        !stdout.contains('\u{1b}'),
        "NO_COLOR page carries an escape: {stdout}"
    );
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
    let dir = fresh_dir("stdlib_no_project")?;
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
    let dir = fresh_dir("listed_queryable")?;

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
            std::thread::Builder::new().spawn_scoped(scope, || {
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
            }).expect("spawn test thread");
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
    let dir = fresh_dir("check_fail")?;
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
    let dir = fresh_dir("member_lookup")?;
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
    let dir = fresh_dir("miss_suggestions")?;
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

/// A query that matches no entry lists none, and a bare member name that one
/// module alone exposes opens that member.
#[test]
fn a_far_miss_lists_nothing_and_a_unique_bare_member_opens() -> io::Result<()> {
    let dir = fresh_dir("miss_nearest")?;
    let (ok, _stdout, stderr) = run_in(&dir, &["doc", "qqqqzzzzxxxx"]);
    assert!(!ok);
    assert!(
        !stderr.contains("1. ipe doc "),
        "a far miss lists no unrelated entry:\n{stderr}"
    );
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "unixMillis", "--plain"]);
    assert!(ok, "a bare member name one module exposes opens:\n{stderr}");
    assert!(
        stdout.starts_with("Ipe.Time.unixMillis : "),
        "the bare member name opens the qualified member:\n{stdout}"
    );
    Ok(())
}

/// The first line a documented member prints is its checked signature, the
/// same under every format.
#[test]
fn documented_member_shows_signature_first() -> io::Result<()> {
    let dir = fresh_dir("signature_first")?;
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "String.toInt"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("Ipe.String.toInt : String -> Maybe Int"),
        "{stdout}"
    );
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "String.toInt", "--plain"]);
    assert!(ok, "{stderr}");
    assert_eq!(
        stdout.lines().next(),
        Some("Ipe.String.toInt : String -> Maybe Int"),
        "{stdout}"
    );
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "String.toInt", "--json"]);
    assert!(ok, "{stderr}");
    let value: serde_json::Value = serde_json::from_str(stdout.trim())
        .map_err(|e| io::Error::other(format!("{e}: {stdout}")))?;
    let field = |name: &str| value.get(name).and_then(serde_json::Value::as_str);
    assert_eq!(field("signature"), Some("String -> Maybe Int"), "{stdout}");
    assert_eq!(field("key"), Some("Ipe.String.toInt"), "{stdout}");
    Ok(())
}

/// A member with no doc comment is still a row: bare, module-qualified and
/// fully qualified, it opens with its signature.
#[test]
fn undocumented_member_resolves_bare_and_qualified() -> io::Result<()> {
    let dir = fresh_dir("undocumented_member")?;
    for key in ["readFile", "File.readFile", "Ipe.File.readFile"] {
        let (ok, stdout, stderr) = run_in(&dir, &["doc", key, "--plain"]);
        assert!(ok, "`{key}` must open:\n{stderr}");
        assert!(
            stdout.starts_with("Ipe.File.readFile : "),
            "`{key}`:\n{stdout}"
        );
    }
    Ok(())
}

/// A member opens under the alias `import … as` binds by default for a nested
/// module, its last path segment.
#[test]
fn nested_alias_resolves() -> io::Result<()> {
    let dir = fresh_dir("nested_alias")?;
    for (key, qualified) in [
        ("Input.labelHidden", "Ipe.Ui.Input.labelHidden"),
        ("Region.heading", "Ipe.Ui.Region.heading"),
    ] {
        let (ok, stdout, stderr) = run_in(&dir, &["doc", key, "--plain"]);
        assert!(ok, "`{key}` must open:\n{stderr}");
        assert!(
            stdout.starts_with(&format!("{qualified} : ")),
            "`{key}`:\n{stdout}"
        );
    }
    Ok(())
}

/// A key two modules' members share opens neither: the run exits non-zero
/// and lists every owner as the term that opens it.
#[test]
fn shared_suffix_is_ambiguous_not_first() -> io::Result<()> {
    let dir = fresh_dir("shared_suffix")?;
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "Parser.int", "--plain"]);
    assert!(!ok, "`Parser.int` names two members:\n{stdout}");
    assert!(stdout.is_empty(), "{stdout}");
    for owner in ["Ipe.Parser.int", "Ipe.Url.Parser.int"] {
        assert!(
            stderr
                .lines()
                .any(|line| line.starts_with(&format!("{owner}\t"))),
            "the miss names {owner}:\n{stderr}"
        );
    }
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "Url.Parser.int", "--plain"]);
    assert!(ok, "a longer suffix names one member:\n{stderr}");
    assert!(stdout.starts_with("Ipe.Url.Parser.int : "), "{stdout}");
    Ok(())
}

/// A query no entry matches lists nothing, under every format.
#[test]
fn nothing_matched_lists_nothing() -> io::Result<()> {
    let dir = fresh_dir("nothing_matched")?;
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "zzqqxx"]);
    assert!(!ok);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(!stderr.contains("1. ipe doc "), "{stderr}");
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "zzqqxx", "--json"]);
    assert!(!ok);
    assert!(stdout.is_empty(), "{stdout}");
    let parsed: serde_json::Value = serde_json::from_str(stderr.trim())
        .map_err(|e| io::Error::other(format!("{e}: {stderr}")))?;
    let Some(payload) = parsed.get("payload") else {
        return Err(io::Error::other(format!("no payload: {stderr}")));
    };
    assert_eq!(
        payload
            .get("results")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0),
        "{stderr}"
    );
    assert_eq!(
        payload.get("closeness").and_then(serde_json::Value::as_str),
        Some("nothing"),
        "{stderr}"
    );
    Ok(())
}

/// A human miss that matched nothing still names the next step.
#[test]
fn a_far_miss_names_the_next_step() -> io::Result<()> {
    let dir = fresh_dir("far_miss_next_step")?;
    let (ok, _stdout, stderr) = run_in(&dir, &["doc", "zzqqxx"]);
    assert!(!ok);
    assert!(stderr.contains("`ipe doc list`"), "{stderr}");
    Ok(())
}

/// `->` is a syntax token, not a flag: it opens the lambda construct page.
#[test]
fn arrow_is_a_term_not_a_flag() -> io::Result<()> {
    let dir = fresh_dir("arrow_term")?;
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "->", "--plain"]);
    assert!(ok, "`ipe doc ->` opens a page:\n{stderr}");
    let (ok, expected, stderr) = run_in(&dir, &["doc", "construct:lambda", "--plain"]);
    assert!(ok, "{stderr}");
    assert_eq!(stdout, expected);
    Ok(())
}

/// `\` is a syntax token, not a path: it opens the lambda construct page.
#[test]
fn backslash_is_a_term_not_a_path() -> io::Result<()> {
    let dir = fresh_dir("backslash_term")?;
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "\\", "--plain"]);
    assert!(ok, "`ipe doc \\` opens a page:\n{stderr}");
    let (ok, expected, stderr) = run_in(&dir, &["doc", "construct:lambda", "--plain"]);
    assert!(ok, "{stderr}");
    assert_eq!(stdout, expected);
    Ok(())
}

/// A term routes by its spelling alone: a directory of the same name in the
/// working directory changes nothing.
#[test]
fn route_ignores_disk() -> io::Result<()> {
    let empty = fresh_dir("route_disk_empty")?;
    let shadowed = fresh_dir("route_disk_shadowed")?;
    for term in ["case", "List", "Read"] {
        fs::create_dir_all(shadowed.join(term))?;
    }
    for term in ["case", "List", "Read"] {
        let in_empty = run_in(&empty, &["doc", term, "--plain"]);
        let in_shadowed = run_in(&shadowed, &["doc", term, "--plain"]);
        assert_eq!(in_empty, in_shadowed, "{term:?} routed by disk");
    }
    Ok(())
}

/// An unquoted multi-word query is refused with the quoted command as the fix.
#[test]
fn unquoted_two_words_names_the_quote_fix() -> io::Result<()> {
    let dir = fresh_dir("unquoted_words")?;
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "read", "file"]);
    assert!(!ok);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("`ipe doc \"read file\"`"), "{stderr}");
    Ok(())
}

/// A path after a query keeps the single-key refusal: quoting would not make
/// a path part of the query.
#[test]
fn a_path_after_a_query_is_not_quoted_into_it() -> io::Result<()> {
    let dir = fresh_dir("path_after_query")?;
    let (ok, _stdout, stderr) = run_in(&dir, &["doc", "List", "src/x"]);
    assert!(!ok);
    assert!(!stderr.contains("ipe doc \""), "{stderr}");
    assert!(stderr.contains("single <key>"), "{stderr}");
    Ok(())
}

/// The quote fix is offered only when the quoted query routes as a lookup:
/// an operator or `kind:key` beside a word makes the joined text a path, so
/// echoing it quoted would name a different command.
#[test]
fn a_quote_fix_that_would_route_as_a_path_is_not_offered() -> io::Result<()> {
    let dir = fresh_dir("quote_fix_routes_as_path")?;
    for args in [
        ["doc", "read", "//"],
        ["doc", "//", "read"],
        ["doc", "read", "construct:case"],
    ] {
        let (ok, stdout, stderr) = run_in(&dir, &args);
        assert!(!ok, "{args:?}");
        assert!(stdout.is_empty(), "{args:?}:\n{stdout}");
        assert!(!stderr.contains("ipe doc \""), "{args:?}:\n{stderr}");
        assert!(stderr.contains("single <key>"), "{args:?}:\n{stderr}");
    }
    Ok(())
}

/// A hazardous second word is refused by the query parse, never echoed in the
/// quote fix.
#[test]
fn a_hazardous_extra_word_is_never_echoed() -> io::Result<()> {
    let dir = fresh_dir("hazardous_extra_word")?;
    for word in ["file\u{1b}[31m", "file\u{7}", "file\u{202e}"] {
        let (ok, stdout, stderr) = run_in(&dir, &["doc", "read", word]);
        assert!(!ok, "{word:?}");
        assert!(stdout.is_empty(), "{word:?}:\n{stdout}");
        assert!(!stderr.contains(word), "{word:?}:\n{stderr}");
        assert!(!stderr.contains("ipe doc \""), "{word:?}:\n{stderr}");
    }
    Ok(())
}

/// The quote fix is offered only when it is read back unchanged: a shell
/// would expand or split `$`, `` ` ``, `"`, `!` or `%` inside the quotes, a
/// leading `-` reads as a flag, and a query that trims to a mode word opens
/// that mode, so each keeps the single-key refusal.
#[test]
fn a_quote_fix_not_read_back_unchanged_is_not_offered() -> io::Result<()> {
    let dir = fresh_dir("quote_fix_read_back")?;
    for args in [
        ["doc", "read", "$(id)"],
        ["doc", "read", "`id`"],
        ["doc", "read", "a\"b"],
        ["doc", "read", "x!"],
        ["doc", "read", "%PATH%"],
        ["doc", "-", "x"],
        ["doc", " list", ""],
    ] {
        let (ok, stdout, stderr) = run_in(&dir, &args);
        assert!(!ok, "{args:?}");
        assert!(stdout.is_empty(), "{args:?}:\n{stdout}");
        assert!(!stderr.contains("ipe doc \""), "{args:?}:\n{stderr}");
        assert!(stderr.contains("single <key>"), "{args:?}:\n{stderr}");
    }
    Ok(())
}

/// A malformed query is refused with a typed usage error before any lookup:
/// no stack trace, and the hazardous text is never echoed raw.
#[test]
fn malformed_query_refused() -> io::Result<()> {
    let dir = fresh_dir("malformed_query")?;
    let long = "a".repeat(4096);
    for query in ["", "   ", "map\u{7}", "map\u{1b}[31m", long.as_str()] {
        let (ok, stdout, stderr) = run_in(&dir, &["doc", query]);
        assert!(!ok, "{query:?} must be refused");
        assert!(stdout.is_empty(), "{query:?}:\n{stdout}");
        assert!(!stderr.contains("panicked"), "{query:?}:\n{stderr}");
        assert!(!stderr.contains('\u{7}'), "{query:?}:\n{stderr}");
        assert!(!stderr.contains('\u{1b}'), "{query:?}:\n{stderr}");
        assert!(
            !stderr.contains(&long),
            "the long query is not echoed whole"
        );
        assert!(stderr.contains("ipe doc: the term"), "{query:?}:\n{stderr}");
    }
    Ok(())
}

/// Every member hit under `--json` is one object of one shape, whichever
/// route found it and whether or not the member is documented.
#[test]
fn json_member_shape_single() -> io::Result<()> {
    let dir = fresh_dir("json_member_shape")?;
    let shape = [
        "contract",
        "examples",
        "key",
        "kind",
        "module",
        "name",
        "see_also",
        "signature",
    ];
    for key in ["String.toInt", "readFile", "Input.labelHidden"] {
        let (ok, stdout, stderr) = run_in(&dir, &["doc", key, "--json"]);
        assert!(ok, "`{key}`:\n{stderr}");
        let value: serde_json::Value = serde_json::from_str(stdout.trim())
            .map_err(|e| io::Error::other(format!("{e}: {stdout}")))?;
        let Some(object) = value.as_object() else {
            return Err(io::Error::other(format!("not an object: {stdout}")));
        };
        let mut fields: Vec<&str> = object.keys().map(String::as_str).collect();
        fields.sort_unstable();
        assert_eq!(fields, shape, "`{key}`:\n{stdout}");
        assert_eq!(
            object.get("kind").and_then(serde_json::Value::as_str),
            Some("symbol")
        );
    }
    Ok(())
}

/// A bare `ipe doc --json` names the command as typed and the command that
/// would run, never the internal default action, and exits non-zero.
#[test]
fn bare_json_error_names_typed_command() -> io::Result<()> {
    let dir = fresh_dir("bare_json")?;
    for flag in ["--json", "--plain"] {
        let (ok, stdout, stderr) = run_in(&dir, &["doc", flag]);
        assert!(!ok, "`ipe doc {flag}` must exit non-zero");
        assert!(stdout.is_empty(), "{stdout}");
        let refusal = stderr
            .lines()
            .find(|line| line.contains(&format!("ipe doc {flag}:")))
            .unwrap_or_default();
        assert!(!refusal.is_empty(), "{stderr}");
        assert!(
            refusal.contains(&format!("ipe doc list {flag}")),
            "{stderr}"
        );
        assert!(!refusal.contains("generate"), "{stderr}");
    }
    Ok(())
}

/// Under `--json` a miss is a machine outcome: the shared error envelope on
/// stderr, nothing on stdout, never the human frame.
#[test]
fn a_miss_under_json_is_the_machine_error_envelope() -> io::Result<()> {
    let dir = fresh_dir("miss_json")?;
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

/// Off a terminal a human miss is the numbered list and never a prompt: the
/// run ends at once with the entries listed, each as the command that opens it.
#[test]
fn a_piped_miss_lists_numbered_entries_without_prompting() -> io::Result<()> {
    let dir = fresh_dir("miss_numbered")?;
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "unixMilis"]);
    assert!(!ok, "a miss exits non-zero");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        stderr.contains("1. ipe doc "),
        "the entries are numbered:\n{stderr}"
    );
    assert!(
        !stderr.contains("Open which entry?"),
        "no prompt without a terminal:\n{stderr}"
    );
    Ok(())
}

/// Under `--plain` a miss is one `term<TAB>kind<TAB>summary` line per closest
/// entry on stderr, and the first field passed back to `ipe doc` opens it.
#[test]
fn a_plain_miss_lists_terms_that_rerun() -> io::Result<()> {
    let dir = fresh_dir("miss_plain")?;
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "unixMilis", "--plain"]);
    assert!(!ok, "a miss exits non-zero");
    assert!(stdout.is_empty(), "{stdout}");
    let lines: Vec<&str> = stderr.lines().collect();
    assert!((1..=10).contains(&lines.len()), "a bounded list:\n{stderr}");
    for line in &lines {
        assert_eq!(
            line.split('\t').count(),
            3,
            "term, kind, summary:\n{line:?}"
        );
    }
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("Ipe.Time.unixMillis\t")),
        "the typo'd member is listed by its term:\n{stderr}"
    );
    for line in &lines {
        let term = line.split('\t').next().unwrap_or_default();
        let (ok, stdout, stderr) = run_in(&dir, &["doc", term, "--plain"]);
        assert!(
            ok,
            "listed term `{term}` must open its entry:\n{stdout}\n{stderr}"
        );
    }
    Ok(())
}

/// Under `--json` a miss carries the ranked terms in the error envelope's
/// payload: `query`, `closeness`, `truncated`, and `results` in order.
#[test]
fn a_json_miss_carries_the_ranked_terms() -> io::Result<()> {
    let dir = fresh_dir("miss_json_results")?;
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "unixMilis", "--json"]);
    assert!(!ok);
    assert!(stdout.is_empty(), "{stdout}");
    let parsed: serde_json::Value = serde_json::from_str(stderr.trim())
        .map_err(|e| io::Error::other(format!("{e}: {stderr}")))?;
    let Some(payload) = parsed.get("payload") else {
        return Err(io::Error::other(format!("no payload: {stderr}")));
    };
    let text = |field: &str| payload.get(field).and_then(serde_json::Value::as_str);
    assert_eq!(text("kind"), Some("doc-not-found"), "{stderr}");
    assert_eq!(text("query"), Some("unixMilis"), "{stderr}");
    assert_eq!(text("closeness"), Some("match"), "{stderr}");
    assert!(
        payload
            .get("truncated")
            .is_some_and(serde_json::Value::is_boolean),
        "{stderr}"
    );
    let Some(results) = payload.get("results").and_then(serde_json::Value::as_array) else {
        return Err(io::Error::other(format!("no results array: {stderr}")));
    };
    assert!(
        (1..=10).contains(&results.len()),
        "a bounded list:\n{stderr}"
    );
    assert!(
        results.iter().any(|hit| {
            hit.get("term").and_then(serde_json::Value::as_str) == Some("Ipe.Time.unixMillis")
                && hit.get("kind").and_then(serde_json::Value::as_str) == Some("symbol")
        }),
        "{stderr}"
    );
    Ok(())
}

/// A `kind:key` term opens that entry directly, never a generate run.
#[test]
fn a_qualified_term_opens_its_entry() -> io::Result<()> {
    let dir = fresh_dir("qualified_term")?;
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "construct:case", "--plain"]);
    assert!(ok, "`construct:case` must open:\n{stdout}\n{stderr}");
    assert!(!stdout.is_empty(), "the entry is printed:\n{stderr}");
    Ok(())
}

/// A blank term, bare or after a `kind:` qualifier, is refused as a usage
/// error before any lookup runs.
#[test]
fn a_blank_term_is_refused() -> io::Result<()> {
    let dir = fresh_dir("blank_term")?;
    for term in ["", "   ", "topic:", "topic:   "] {
        let (ok, stdout, stderr) = run_in(&dir, &["doc", term]);
        assert!(!ok, "{term:?} must be refused");
        assert!(stdout.is_empty(), "{term:?}:\n{stdout}");
        assert!(
            stderr.contains("ipe doc: the term is empty"),
            "{term:?}:\n{stderr}"
        );
    }
    Ok(())
}

// ── #3198: one qualifier rule for every doc-key kind ──────────────────────

/// A project module's short name shadows the stdlib module of the same short
/// name, while the stdlib module's own full dotted name still reaches it —
/// short and full forms name two different, independently reachable entries.
#[test]
fn a_project_module_shadows_stdlib_by_short_name_only() -> io::Result<()> {
    let dir = package_dir("shadow_list")?;
    let src = dir.join("src");
    fs::write(
        src.join("List.ipe"),
        "-- | A project module that shadows the stdlib `List` by short name.\n\
         module List exposing (shadowMarker)\n\n\
         -- | A marker value unique to this project's `List` module.\n\
         shadowMarker : Int\n\
         shadowMarker =\n    1\n",
    )?;

    let (ok, stdout, stderr) = run_in(&dir, &["doc", "List", "--plain"]);
    assert!(ok, "`ipe doc List` must resolve:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("shadowMarker"),
        "the short name `List` resolves to the PROJECT module, not stdlib:\n{stdout}"
    );

    let (ok, stdout, stderr) = run_in(&dir, &["doc", "Ipe.List", "--plain"]);
    assert!(
        ok,
        "`ipe doc Ipe.List` must still resolve:\n{stdout}\n{stderr}"
    );
    assert!(
        !stdout.contains("shadowMarker"),
        "the full name `Ipe.List` still reaches the STDLIB module:\n{stdout}"
    );
    Ok(())
}

/// A project module's member answers its `Module.member` key before a stdlib
/// member filed under the same suffix key: `Input.labelHidden` (one stdlib
/// owner) and `Parser.int` (two stdlib owners) open the project's member,
/// while the full stdlib name still opens the stdlib one.
#[test]
fn a_project_member_shadows_a_stdlib_suffix_key() -> io::Result<()> {
    let dir = package_dir("shadow_suffix")?;
    let src = dir.join("src");
    fs::write(
        src.join("Input.ipe"),
        "module Input exposing (labelHidden)\n\n\
         -- | A project marker.\n\
         labelHidden : Int\n\
         labelHidden =\n    1\n",
    )?;
    fs::write(
        src.join("Parser.ipe"),
        "module Parser exposing (int)\n\n\
         -- | A project marker.\n\
         int : Int\n\
         int =\n    2\n",
    )?;
    for key in ["Input.labelHidden", "Parser.int"] {
        let (ok, stdout, stderr) = run_in(&dir, &["doc", key, "--plain"]);
        assert!(ok, "`{key}` opens the project member:\n{stdout}\n{stderr}");
        assert!(
            stdout.starts_with(&format!("{key} : Int")),
            "`{key}` is the project's `Int` member:\n{stdout}"
        );
    }
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "Ipe.Ui.Input.labelHidden", "--plain"]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.starts_with("Ipe.Ui.Input.labelHidden : "),
        "{stdout}"
    );
    Ok(())
}

/// A package at a fresh directory: a manifest and a `src/Main.ipe` entry, the
/// shape `ipe doc` reads as the current directory's package.
fn package_dir(tag: &str) -> io::Result<PathBuf> {
    let dir = fresh_dir(tag)?;
    fs::write(
        dir.join("package.ipe"),
        support::package_ipe(&tag.replace('_', "-")),
    )?;
    let src = dir.join("src");
    fs::create_dir_all(&src)?;
    fs::write(
        src.join("Main.ipe"),
        "module Main exposing (main)\n\nimport Ipe.Io\n\nmain = Io.println \"hi\"\n",
    )?;
    Ok(dir)
}

/// A documented project module whose one member `shapeMarker` is unique to it.
const SHAPES: &str = "-- | Project shapes.\n\
                      module Shapes exposing (shapeMarker)\n\n\
                      -- | A marker unique to this project.\n\
                      shapeMarker : Int\n\
                      shapeMarker =\n    1\n";

/// Outside a package (no `package.ipe`), a lookup reads the stdlib alone: an
/// `.ipe` tree in the current directory is never read as a project.
#[test]
fn a_lookup_outside_a_package_never_reads_the_cwd_as_a_project() -> io::Result<()> {
    let dir = fresh_dir("outside_package")?;
    let src = dir.join("src");
    fs::create_dir_all(&src)?;
    fs::write(src.join("Shapes.ipe"), SHAPES)?;
    fs::write(
        src.join("Broken.ipe"),
        "module Broken exposing (x)\n\nx = \n",
    )?;
    for key in ["Shapes", "Shapes.shapeMarker", "Broken"] {
        let (ok, stdout, stderr) = run_in(&dir, &["doc", key, "--plain"]);
        assert!(
            !ok,
            "`ipe doc {key}` outside a package must miss:\n{stdout}"
        );
        assert!(stdout.is_empty(), "{stdout}");
        let project_terms = ["Shapes", "Shapes.shapeMarker", "Broken", "Broken.x"];
        assert!(
            stderr
                .lines()
                .filter_map(|line| line.split('\t').next())
                .all(|term| !project_terms.contains(&term)),
            "no candidate comes from the cwd tree:\n{stderr}"
        );
        assert!(
            !stderr.contains("A marker unique to this project"),
            "{stderr}"
        );
    }
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "Ipe.List", "--plain"]);
    assert!(ok, "the stdlib still resolves:\n{stderr}");
    assert!(stdout.contains("map"), "{stdout}");
    Ok(())
}

/// Inside a package, a lookup reads its `src/` modules and their members.
#[test]
fn a_lookup_in_a_package_reads_its_src() -> io::Result<()> {
    let dir = package_dir("inside_package")?;
    fs::write(dir.join("src").join("Shapes.ipe"), SHAPES)?;
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "Shapes", "--plain"]);
    assert!(
        ok,
        "`ipe doc Shapes` resolves the package module:\n{stderr}"
    );
    assert!(stdout.contains("shapeMarker"), "{stdout}");
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "Shapes.shapeMarker", "--plain"]);
    assert!(ok, "`ipe doc Shapes.shapeMarker` resolves:\n{stderr}");
    assert!(stdout.contains("shapeMarker"), "{stdout}");
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "--list", "--plain"]);
    assert!(ok, "{stderr}");
    assert!(stdout.lines().any(|line| line == "Shapes"), "{stdout}");
    Ok(())
}

/// A package module that does not type-check is reported, never answered as
/// a miss that hides the real error.
#[test]
fn a_project_module_that_does_not_type_check_is_reported_not_missed() -> io::Result<()> {
    let dir = package_dir("ill_typed_package")?;
    fs::write(
        dir.join("src").join("Shapes.ipe"),
        "module Shapes exposing (shapeMarker)\n\nshapeMarker : Int\nshapeMarker =\n    \"not an int\"\n",
    )?;
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "Shapes", "--plain"]);
    assert!(!ok, "an ill-typed package module must fail:\n{stdout}");
    assert!(
        !stderr.contains("no documentation entry is named `Shapes`"),
        "the type error is reported, not a miss:\n{stderr}"
    );
    Ok(())
}

/// A reserved-namespace miss never resolves the package, so a package that
/// cannot resolve (here: a manifest with no `src/`) still misses cleanly,
/// while a project-shaped name in the same directory reports the refusal.
#[test]
fn a_reserved_miss_in_an_unresolvable_package_still_misses_cleanly() -> io::Result<()> {
    let dir = fresh_dir("unresolvable_package")?;
    fs::write(
        dir.join("package.ipe"),
        support::package_ipe("unresolvable-package"),
    )?;
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "Ipe.Nope"]);
    assert!(!ok, "`ipe doc Ipe.Nope` must miss:\n{stdout}");
    assert!(
        stderr.contains("no documentation entry is named `Ipe.Nope`"),
        "{stderr}"
    );
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "Shapes"]);
    assert!(!ok, "`ipe doc Shapes` must fail:\n{stdout}");
    assert!(
        !stderr.contains("no documentation entry is named `Shapes`"),
        "the unresolvable package is reported, not read as a miss:\n{stderr}"
    );
    Ok(())
}

/// Under `--json`/`--plain`, a package that cannot be read or typed is
/// refused through the machine error envelope, never the human frame.
#[test]
fn a_package_refusal_under_a_machine_format_is_the_machine_envelope() -> io::Result<()> {
    let ill_typed = package_dir("machine_refusal_ill_typed")?;
    fs::write(
        ill_typed.join("src").join("Shapes.ipe"),
        "module Shapes exposing (shapeMarker)\n\nshapeMarker : Int\nshapeMarker =\n    \"not an int\"\n",
    )?;
    let unresolvable = fresh_dir("machine_refusal_unresolvable")?;
    fs::write(
        unresolvable.join("package.ipe"),
        support::package_ipe("machine-refusal-unresolvable"),
    )?;
    let cases: [(&Path, &[&str]); 4] = [
        (&ill_typed, &["Shapes"]),
        (&ill_typed, &["--type", "List a -> Int"]),
        (&unresolvable, &["Shapes"]),
        (&unresolvable, &["list"]),
    ];
    for (dir, query) in cases {
        for format in ["--json", "--plain"] {
            let mut args = vec!["doc"];
            args.extend(query);
            args.push(format);
            let (ok, stdout, stderr) = run_in(dir, &args);
            assert!(!ok, "{args:?} must fail:\n{stdout}");
            assert!(stdout.is_empty(), "{args:?}:\n{stdout}");
            assert!(
                !stderr.contains("Ipê language"),
                "{args:?} wrote the human frame:\n{stderr}"
            );
            if format == "--json" {
                assert!(
                    stderr.contains("\"ipe.cli.error/1\""),
                    "{args:?}:\n{stderr}"
                );
            }
        }
    }
    Ok(())
}

/// Outside a package, a type search ranks the stdlib alone.
#[test]
fn type_search_outside_a_package_searches_the_stdlib() -> io::Result<()> {
    let dir = fresh_dir("type_search_outside")?;
    fs::write(
        dir.join("Broken.ipe"),
        "module Broken exposing (x)\n\nx = \n",
    )?;
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "--type", "List a -> Int", "--plain"]);
    assert!(ok, "the stdlib type search succeeds:\n{stderr}");
    assert!(stdout.contains("length"), "{stdout}");
    Ok(())
}

/// Outside a package, `--list` lists the stdlib alone.
#[test]
fn list_outside_a_package_lists_the_stdlib_alone() -> io::Result<()> {
    let dir = fresh_dir("list_outside")?;
    let src = dir.join("src");
    fs::create_dir_all(&src)?;
    fs::write(src.join("Shapes.ipe"), SHAPES)?;
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "--list", "--plain"]);
    assert!(ok, "{stderr}");
    assert!(stdout.lines().any(|line| line == "Ipe.List"), "{stdout}");
    assert!(!stdout.lines().any(|line| line == "Shapes"), "{stdout}");
    Ok(())
}

/// Off a terminal, no output format paints progress: stderr carries no
/// carriage return, line clear, or spinner frame.
#[test]
fn a_lookup_writes_no_progress_bytes_off_a_terminal() -> io::Result<()> {
    let dir = package_dir("no_progress_bytes")?;
    fs::write(dir.join("src").join("Shapes.ipe"), SHAPES)?;
    for format in [None, Some("--plain"), Some("--json")] {
        for query in [
            &["Ipe.Nope"][..],
            &["Shapes"][..],
            &["--type", "List a -> Int"][..],
        ] {
            let mut args = vec!["doc"];
            args.extend(query);
            args.extend(format);
            let output = Command::new(support::ipe_bin())
                .args(&args)
                .current_dir(&dir)
                .env_remove("NO_COLOR")
                .output()?;
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                !stderr.contains('\r') && !stderr.contains("\x1b[0K"),
                "{args:?} wrote progress bytes:\n{stderr:?}"
            );
            assert!(
                !ipe::style::SPINNER_FRAMES
                    .iter()
                    .any(|frame| stderr.contains(*frame)),
                "{args:?} painted a spinner frame:\n{stderr:?}"
            );
        }
    }
    Ok(())
}

/// An unknown module-shaped key misses cleanly with the same suggestion frame
/// every other key kind uses — never a silent empty page, never "unknown
/// module".
#[test]
fn an_unknown_module_key_misses_with_a_suggestion() -> io::Result<()> {
    let dir = fresh_dir("unknown_module")?;
    for key in ["NotAModule", "Ipe.Nope"] {
        let (ok, stdout, stderr) = run_in(&dir, &["doc", key]);
        assert!(!ok, "`ipe doc {key}` must miss:\n{stdout}\n{stderr}");
        assert!(
            stderr.contains(&format!("no documentation entry is named `{key}`")),
            "{stderr}"
        );
    }
    Ok(())
}

/// The text between `label` and the next `)` — the worked example named after
/// a key kind in `help/doc.md`'s Arguments paragraph, e.g.
/// `extract_paren_example(text, "module (")` on `…module (List), member
/// (…)…` returns `"List"`. An `Err` names the missing landmark rather than
/// panicking, so a drifted `help/doc.md` fails the test with a clear cause
/// (helpers reached only through a `#[test]` fn are still workspace-denied
/// `unwrap`/`expect`, same as the file's own tests).
fn extract_paren_example(text: &str, label: &str) -> io::Result<String> {
    let start = text
        .find(label)
        .ok_or_else(|| io::Error::other(format!("`help/doc.md` has no `{label}` example")))?;
    let after = &text[start + label.len()..];
    let end = after.find(')').ok_or_else(|| {
        io::Error::other(format!("no closing `)` after `{label}` in help/doc.md"))
    })?;
    Ok(after[..end].to_owned())
}

/// The key inside the worked `` `ipe doc <key>` `` backtick example.
fn extract_backtick_example(text: &str) -> io::Result<String> {
    let marker = "`ipe doc ";
    let start = text
        .find(marker)
        .ok_or_else(|| io::Error::other("`help/doc.md` has no worked `ipe doc` example"))?;
    let after = &text[start + marker.len()..];
    let end = after
        .find('`')
        .ok_or_else(|| io::Error::other("no closing backtick after the `ipe doc` example"))?;
    Ok(after[..end].to_owned())
}

/// Every worked example `help/doc.md`'s Arguments paragraph names — one per
/// key kind — actually resolves. The help text and the resolver are proven
/// against each other, so they cannot silently drift apart.
#[test]
fn help_doc_examples_all_resolve() -> io::Result<()> {
    let help_path = e2e_support::manifest_dir!().join("help/doc.md");
    let help = fs::read_to_string(&help_path)?;

    let examples = [
        extract_paren_example(&help, "diagnostic code (")?,
        extract_paren_example(&help, "symbol (")?,
        extract_paren_example(&help, "module (")?,
        extract_paren_example(&help, "member (")?,
        extract_paren_example(&help, "language construct (")?,
        extract_paren_example(&help, "CLI command (")?,
        extract_backtick_example(&help)?,
    ];

    let dir = fresh_dir("help_examples")?;
    for key in &examples {
        let (ok, stdout, stderr) = run_in(&dir, &["doc", key]);
        assert!(
            ok,
            "help/doc.md's worked example `{key}` must resolve:\n{stdout}\n{stderr}"
        );
    }
    Ok(())
}

// ── toFloat discoverability (basics-to-float-kernel-spec.md §3, Slice B) ──

/// The prelude's `toFloat` is reachable both as its own member page (the
/// `Int`/`2^53` doc-comment and its checked example) and, for the full
/// `Int -> Float` signature, from `Basics`'s module page — the two surfaces
/// `ipe doc` splits a symbol lookup across (comment prose vs. signature
/// listing).
#[test]
fn doc_basics_to_float_member_page_renders_int_to_float() -> io::Result<()> {
    let dir = fresh_dir("basics_to_float_member")?;

    let (ok, stdout, stderr) = run_in(&dir, &["doc", "Basics.toFloat", "--plain"]);
    assert!(
        ok,
        "`ipe doc Basics.toFloat` must resolve:\n{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("2^53"),
        "the member page states the exactness boundary:\n{stdout}"
    );
    assert!(
        stdout.contains("toFloat 3 --> 3.0"),
        "the member page's checked example shows an `Int` becoming a `Float`:\n{stdout}"
    );

    let (ok, stdout, stderr) = run_in(&dir, &["doc", "Basics", "--plain"]);
    assert!(ok, "`ipe doc Basics` must resolve:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("toFloat : Int -> Float"),
        "the module page lists `toFloat`'s full signature:\n{stdout}"
    );
    Ok(())
}

/// A bare `toFloat` is ambiguous across three modules and must resolve to
/// none of them alone, listing every home as a ready-to-run key.
///
/// Guards 12a: deleting the qualified-only keying in `ipe-docs/src/lib.rs`
/// (inserting a bare `toFloat` key) would resolve this query to a single
/// entry, and this test would go red.
#[test]
fn doc_bare_to_float_lists_every_home() -> io::Result<()> {
    let dir = fresh_dir("bare_to_float")?;
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "toFloat", "--plain"]);
    assert!(!ok, "a bare `toFloat` must not resolve to a single home");
    assert!(stdout.is_empty(), "{stdout}");
    for home in [
        "Ipe.Basics.toFloat",
        "Ipe.String.toFloat",
        "Ipe.Decimal.toFloat",
    ] {
        assert!(
            stderr
                .lines()
                .any(|line| line.starts_with(&format!("{home}\t"))),
            "the ranked miss list must name {home}:\n{stderr}"
        );
    }
    Ok(())
}

/// `Ipe.Math`'s module page names `toFloat` for the `Int -> Float` direction
/// in its header prose, and never points a reader at `Decimal.fromInt` —
/// Decimal stays the exact-arithmetic route, not the conversion route.
#[test]
fn doc_math_header_names_to_float() -> io::Result<()> {
    let dir = fresh_dir("math_header_to_float")?;
    let (ok, stdout, stderr) = run_in(&dir, &["doc", "Math"]);
    assert!(ok, "`ipe doc Math` must resolve:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("toFloat"),
        "the header names `toFloat` for the reverse direction:\n{stdout}"
    );
    assert!(
        stdout.contains("2^53"),
        "the header states the same exactness boundary as the prelude:\n{stdout}"
    );
    assert!(
        !stdout.contains("Decimal.fromInt"),
        "the header must not point to the old Decimal route:\n{stdout}"
    );
    Ok(())
}

/// The doc help names the term that opens the coding-agent guide.
#[test]
fn help_doc_names_guide_term() {
    let (ok, stdout, stderr) = run(&["doc", "--help"]);
    assert!(ok, "stderr: {stderr}");
    assert!(
        stdout.contains(ipe::agents_guide::GUIDE_TERM),
        "stdout: {stdout}"
    );
}
