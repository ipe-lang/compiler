//! The ten stdlib modules whose runtime kernels exist and are registered in the
//! compiler's `Ffi.kernel`-resolvable registry. Without registration,
//! `import`/member-use fails closed (IPE-N0028 unknown kernel, IPE-N0026
//! reserved-type collision, or IPE-T0001 annotation mismatch).
//!
//! Each module below is a byte-identical reference Layer-3 port whose members
//! are point-free `Ffi.kernel "Mod_fn"` aliases. Registering each family's
//! kernels (variant + `decl` + type-scheme + arity + naming + pretty) closes the
//! resolution hole; the runtime fns already exist and are re-exported into the
//! emitted crate unconditionally, so ipe-0 implies cargo-0 (THE SEAL).
//!
//! Two invariants, one per module:
//!
//! * **Resolution + emit** (always): `import <Module>` and a member call resolve
//!   and the frontend emits clean Rust (ipe exit 0). A resolution regression
//!   (IPE-N0028 / N0026 / T0001) fails HERE — never a silent skip.
//! * **Seal** (`IPE_E2E`): the emitted crate `cargo build`s AND runs cleanly.
//!   ipe exit 0 AND cargo exit 0 — no exit-0-then-cargo-fail.
//!
//! ```text
//! cargo test -p ipe --test golden_stdlib_module_seal
//! IPE_E2E=1 cargo test -p ipe --test golden_stdlib_module_seal
//! ```

use std::fs;
use std::path::{Path, PathBuf};

fn write_project(dir: &Path, main: &str) -> bool {
    let src = dir.join("src");
    let _ = fs::remove_dir_all(dir);
    if fs::create_dir_all(&src).is_err() {
        return false;
    }
    fs::write(src.join("Main.ipe"), main).is_ok()
}

/// Compile `main` (a full `Main.ipe` program) through the ipe frontend into an
/// emitted Rust project rooted at a per-`slug` temp dir. Asserts ipe exit 0 —
/// a resolution/seal regression fails loudly. Returns the emitted-project dir.
#[allow(clippy::panic)] // a refused well-formed program is the test failure
fn compile_module_probe(slug: &str, main: &str) -> PathBuf {
    // Unique dir PER CALL AND PER PROCESS: the `_resolves_and_emits` and
    // `_builds_and_runs` tests for one module share a slug and run concurrently under
    // nextest, so a shared temp dir races (write vs remove_dir_all) and flakily fails
    // write_project. The per-call counter alone is per-process, so two parallel test
    // binaries restart at 0 and collide on the same path under the shared temp_dir;
    // folding the PID in makes the path unforgeably unique across processes too.
    // Declared at scope top (before any statement) to satisfy
    // clippy::items_after_statements.
    static PROBE_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let uid = PROBE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pid = std::process::id();
    let tmp = crate::support::scratch_root().join(format!("ipec_stdlib_seal_{slug}_{pid}_{uid}"));
    assert!(
        write_project(&tmp, main),
        "must write the {slug} fixture project"
    );
    let entry = tmp.join("src").join("Main.ipe");
    // Fold the PID into the emitted-project path too (as the source `tmp` above
    // already does): a module's `_resolves_and_emits` and `_builds_and_runs`
    // tests share a slug and the per-process `uid` counter both restart at 0, so
    // without the PID two parallel test binaries collide on one `_out` path and
    // one test's start-of-run teardown unlinks the cwd of the other's live
    // `cargo build`, whose `rustc` then cannot locate its working directory.
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("stdlib_seal_{slug}_{pid}_{uid}_out"));
    let _ = fs::remove_dir_all(&out);

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    if let Err(e) = built {
        panic!("module `{slug}` must resolve + emit through ipec (exit 0), got: {e:?}");
    }
    out
}

/// Full end-to-end seal for one module: ipe emits, then the emitted crate
/// `cargo build`s + runs, and stdout matches `expected`.
fn seal_module(slug: &str, main: &str, expected: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = compile_module_probe(slug, main);
    let out = crate::support::build_and_run_emitted(slug, &dir);
    assert_eq!(
        out.exit_code,
        Some(0),
        "emitted `{slug}` crate must build + run cleanly, got exit {:?}",
        out.exit_code
    );
    assert_eq!(
        out.stdout.trim(),
        expected,
        "module `{slug}` stdout mismatch"
    );
}

// ── Ipe.Regex ─────────────────────────────────────────────────────

const REGEX_MAIN: &str = "module Main exposing (main)\n\
    import Ipe.Io as Io\n\
    import Ipe.String as String\n\
    import Ipe.Regex as Regex\n\n\
    digits : Result Error Regex\n\
    digits = Regex.compile \"\\\\d+\"\n\n\
    hit : String\n\
    hit = case digits of\n\
    \x20   Ok re -> if Regex.match re \"a1\" then \"MATCH\" else \"NOMATCH\"\n\
    \x20   Err _ -> \"COMPILE-ERR\"\n\n\
    invalid : String\n\
    invalid = case Regex.compile \"(\" of\n\
    \x20   Ok _ -> \"COMPILED\"\n\
    \x20   Err _ -> \"INVALID\"\n\n\
    sub : String\n\
    sub = case Regex.compile \"\\\\d\" of\n\
    \x20   Ok re -> Regex.replace re \"#\" \"a1b2\"\n\
    \x20   Err _ -> \"-\"\n\n\
    firstDigits : String\n\
    firstDigits = case digits of\n\
    \x20   Ok re -> (case Regex.find re \"abc42\" of\n\
    \x20       Just d -> d\n\
    \x20       Nothing -> \"-\")\n\
    \x20   Err _ -> \"-\"\n\n\
    allDigits : String\n\
    allDigits = case Regex.compile \"\\\\d\" of\n\
    \x20   Ok re -> String.join \",\" (Regex.findAll re \"a1b2c3\")\n\
    \x20   Err _ -> \"-\"\n\n\
    parts : String\n\
    parts = case Regex.compile \",\" of\n\
    \x20   Ok re -> String.join \"|\" (Regex.split re \"a,b,c\")\n\
    \x20   Err _ -> \"-\"\n\n\
    main = Io.println (hit ++ \" \" ++ invalid ++ \" \" ++ sub ++ \" \" ++ firstDigits ++ \" \" ++ allDigits ++ \" \" ++ parts)\n";

#[test]
fn regex_resolves_and_emits() {
    let _ = compile_module_probe("regex", REGEX_MAIN);
}

#[test]
fn regex_builds_and_runs() {
    // hit=MATCH; the invalid pattern `(` surfaces as a typed Err → INVALID
    // (NOT a silent NOMATCH); sub=a#b#, first=42, all=1,2,3, parts=a|b|c.
    seal_module("regex", REGEX_MAIN, "MATCH INVALID a#b# 42 1,2,3 a|b|c");
}

/// `IPE_REGEX_MAX_INPUT_BYTES` reaches `Regex.compile` and every handle it builds.
///
/// A malformed or zero value makes each `Regex.compile` an `Err`; a one-byte
/// ceiling turns back every subject the program scans. Both outputs differ from
/// the default run's, so the variable is read and applied, never ignored.
#[test]
fn regex_ceiling_env_reaches_compile_and_the_handle() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = compile_module_probe("regex_ceiling", REGEX_MAIN);
    for (raw, expected) in [
        ("abc", "COMPILE-ERR INVALID - - - -"),
        ("0", "COMPILE-ERR INVALID - - - -"),
        ("1", "NOMATCH INVALID a1b2 -  a,b,c"),
    ] {
        let out = crate::support::build_and_run_emitted_capturing_stderr_with_env(
            "regex_ceiling",
            &dir,
            &[("IPE_REGEX_MAX_INPUT_BYTES", raw)],
        );
        assert_eq!(
            out.exit_code,
            Some(0),
            "IPE_REGEX_MAX_INPUT_BYTES={raw:?}: the program must run\n--- stderr ---\n{}",
            out.stderr
        );
        assert_eq!(
            out.stdout.trim(),
            expected,
            "IPE_REGEX_MAX_INPUT_BYTES={raw:?}: stdout mismatch"
        );
    }
}

// ── Ipe.Path ──────────────────────────────────────────────────────

const PATH_MAIN: &str = "module Main exposing (main)\n\
    import Ipe.Io as Io\n\
    import Ipe.Path as Path\n\n\
    render : Path.Path -> Path.Path -> String\n\
    render dirP fileP =\n\
    \x20   let\n\
    \x20       abs = if Path.isAbsolute dirP then \"ABS\" else \"REL\"\n\
    \x20   in\n\
    \x20   Path.base fileP ++ \" \" ++ Path.dir fileP ++ \" \" ++ Path.ext fileP ++ \" \" ++ abs\n\n\
    main =\n\
    \x20   case (Path.fromString \"/a/b\", Path.fromString \"/a/b/c.txt\") of\n\
    \x20       (Ok dirP, Ok fileP) -> Io.println (render dirP fileP)\n\
    \x20       _ -> Io.println \"PATH_ERR\"\n";

#[test]
fn path_resolves_and_emits() {
    let _ = compile_module_probe("path", PATH_MAIN);
}

#[test]
fn path_builds_and_runs() {
    seal_module("path", PATH_MAIN, "c.txt /a/b .txt ABS");
}

// `Path.under` joins a relative child beneath a root and fails closed on the
// typed `Err` channel for an absolute, empty (`.`), or `..`-escaping child
// (the last refused by the seal itself); `Path.absolute` roots a relative path.

const PATH_UNDER_MAIN: &str = "module Main exposing (main)\n\
    import Ipe.Task as Task\n\
    import Ipe.Io as Io\n\
    import Ipe.Path as Path\n\n\
    join : String -> String -> String\n\
    join r c =\n\
    \x20   case (Path.fromString r, Path.fromString c) of\n\
    \x20       (Ok rootP, Ok childP) ->\n\
    \x20           (case Path.under rootP childP of\n\
    \x20               Ok p -> Path.toString p\n\
    \x20               Err _ -> \"REFUSED\")\n\
    \x20       _ -> \"SEAL\"\n\n\
    joins : String\n\
    joins = join \"/repo\" \"src/Main.ipe\" ++ \" \" ++ join \"/repo/\" \"a/\" ++ \" \" ++ join \"/repo\" \"/etc/passwd\" ++ \" \" ++ join \"/repo\" \".\" ++ \" \" ++ join \"/repo\" \"../etc\"\n\n\
    main =\n\
    \x20   case Path.fromString \"a/b\" of\n\
    \x20       Ok rel ->\n\
    \x20           Path.absolute rel\n\
    \x20               |> Task.andThen (\\p -> Io.println (joins ++ \" \" ++ (if Path.isAbsolute p then \"ABS\" else \"REL\")))\n\
    \x20       Err _ -> Io.println \"PATH_ERR\"\n";

#[test]
fn path_under_resolves_and_emits() {
    let _ = compile_module_probe("path_under", PATH_UNDER_MAIN);
}

#[test]
fn path_under_builds_and_runs() {
    seal_module(
        "path_under",
        PATH_UNDER_MAIN,
        "/repo/src/Main.ipe /repo/a REFUSED REFUSED SEAL ABS",
    );
}

// ── Ipe.Url — typed, validated URLs (parse-don't-validate) ─────────
// A valid URL parses and its typed accessors read back; an unparseable /
// relative URL surfaces as a typed `Err` (NOT a silent accept); the builder
// percent-encodes a value carrying `&`/` ` so it cannot split off a new query
// parameter (an injection).
const URL_MAIN: &str = "module Main exposing (main)\n\
    import Ipe.Io as Io\n\
    import Ipe.Url as Url\n\n\
    scheme : String\n\
    scheme = case Url.fromString \"https://example.com:8443/a?q=1\" of\n\
    \x20   Ok u -> Url.scheme u\n\
    \x20   Err _ -> \"URL_ERR\"\n\n\
    invalid : String\n\
    invalid = case Url.fromString \"/just/a/path\" of\n\
    \x20   Ok _ -> \"ACCEPTED\"\n\
    \x20   Err _ -> \"REJECTED\"\n\n\
    query : String\n\
    query = Url.buildQuery [ ( \"q\", \"a b&c\" ) ]\n\n\
    main = Io.println (scheme ++ \" \" ++ invalid ++ \" \" ++ query)\n";

#[test]
fn url_resolves_and_emits() {
    let _ = compile_module_probe("url", URL_MAIN);
}

#[test]
fn url_builds_and_runs() {
    // scheme=https; the relative URL is a typed Err → REJECTED (never a silent
    // accept); the builder encodes `&` and ` ` so the value stays one param.
    seal_module("url", URL_MAIN, "https REJECTED q=a+b%26c");
}

// ── Ipe.Process — subprocess execution (no shell) ──────────────────
// `Process.run` runs `printf %s SEALED` with a DIRECT argv (never `sh -c`),
// captures its stdout, and prints it. A resolution/scheme/emit regression
// fails at `_resolves_and_emits`; the seal runs the child and asserts stdout.

const PROCESS_MAIN: &str = "module Main exposing (main)\n\
    import Ipe.Task as Task\n\
    import Ipe.Io as Io\n\
    import Ipe.Process as Process\n\n\
    run : Task Error String\n\
    run = Process.run \"printf\" [ \"%s\", \"SEALED\" ]\n\n\
    main =\n\
    \x20   Task.andThen (\\out -> Io.println out) run\n";

#[test]
fn process_resolves_and_emits() {
    let _ = compile_module_probe("process", PROCESS_MAIN);
}

#[test]
fn process_builds_and_runs() {
    seal_module("process", PROCESS_MAIN, "SEALED");
}

// ── Ipe.Process.runInPty — run a child under a real pseudo-terminal ──────
// The child checks `isatty(stdout)` (`[ -t 1 ]`): under the pty it is a
// terminal, so it prints `PTY_TTY`. Under a plain pipe (`Process.run`) the same
// probe would print `PTY_NOTTY`, so a green seal proves the pty path attaches a
// terminal. A resolution/scheme/emit regression fails at `_resolves_and_emits`.
const PROCESS_PTY_MAIN: &str = "module Main exposing (main)\n\
    import Ipe.Task as Task\n\
    import Ipe.Io as Io\n\
    import Ipe.Process as Process\n\n\
    run : Task Error { exitCode : Int, output : String }\n\
    run =\n\
    \x20   Process.runInPty\n\
    \x20       { command = \"sh\"\n\
    \x20       , args = [ \"-c\", \"if [ -t 1 ]; then printf PTY_TTY; else printf PTY_NOTTY; fi\" ]\n\
    \x20       , cwd = Nothing\n\
    \x20       , env = []\n\
    \x20       , cols = 80\n\
    \x20       , rows = 24\n\
    \x20       }\n\n\
    main =\n\
    \x20   Task.andThen (\\r -> Io.println r.output) run\n";

#[test]
fn process_run_in_pty_resolves_and_emits() {
    let _ = compile_module_probe("process_pty", PROCESS_PTY_MAIN);
}

#[test]
fn process_run_in_pty_builds_and_runs() {
    seal_module("process_pty", PROCESS_PTY_MAIN, "PTY_TTY");
}

// ── Arity-0 effect kernel applied to unit ──────────────────────────────
// An arity-0 kernel whose scheme is `() -> Task Error a` (e.g. `Uuid.v4`) is
// called with an explicit `()`. We only need it to RESOLVE + EMIT — a runtime
// UUID is nondeterministic so we do not assert a concrete E2E stdout; we assert
// the program builds+runs (exit 0) via a fixed printed marker.

const NULLARY_KERNEL_MAIN: &str = "module Main exposing (main)\n\
    import Ipe.Task as Task\n\
    import Ipe.Io as Io\n\
    import Ipe.Uuid as Uuid\n\n\
    genId : Task Error String\n\
    genId = Uuid.v4 ()\n\n\
    main =\n\
    \x20   do\n\
    \x20       genId\n\
    \x20       Io.println \"NULLARY_OK\"\n";

#[test]
fn nullary_kernel_resolves_and_emits() {
    let _ = compile_module_probe("nullary_kernel", NULLARY_KERNEL_MAIN);
}

#[test]
fn nullary_kernel_builds_and_runs() {
    seal_module("nullary_kernel", NULLARY_KERNEL_MAIN, "NULLARY_OK");
}

// ── Ipe.Trace ──────────────────────────────────────────────────────────

const TRACE_MAIN: &str = "module Main exposing (main)\n\
    import Ipe.Task as Task\n\
    import Ipe.Io as Io\n\
    import Ipe.Trace as Trace\n\n\
    work : Task Error String\n\
    work = Trace.span \"unit\" (Task.succeed \"TRACE_OK\")\n\n\
    main =\n\
    \x20   do\n\
    \x20       Trace.event \"start\"\n\
    \x20       Trace.attr \"k\" \"v\"\n\
    \x20       work\n\
    \x20       Io.println \"TRACE_OK\"\n";

#[test]
fn trace_resolves_and_emits() {
    let _ = compile_module_probe("trace", TRACE_MAIN);
}

#[test]
fn trace_builds_and_runs() {
    seal_module("trace", TRACE_MAIN, "TRACE_OK");
}

// ── Ipe.Compression ────────────────────────────────────────────────────

const COMPRESSION_MAIN: &str = "module Main exposing (main)\n\
    import Ipe.Task as Task\n\
    import Ipe.Bytes as Bytes\n\
    import Ipe.Io as Io\n\
    import Ipe.Compression as Compression\n\n\
import Ipe.Maybe
    roundTrip : Task Error Bytes\n\
    roundTrip =\n\
    \x20   Compression.gzip (Bytes.fromString \"hello\") |> Task.andThen Compression.gunzip\n\n\
    main =\n\
    \x20   Task.map (\\b -> \"GZ:\" ++ Maybe.withDefault \"?\" (Bytes.toString b)) roundTrip\n\
    \x20       |> Task.andThen (\\msg -> Io.println msg)\n";

#[test]
fn compression_resolves_and_emits() {
    let _ = compile_module_probe("compression", COMPRESSION_MAIN);
}

#[test]
fn compression_builds_and_runs() {
    seal_module("compression", COMPRESSION_MAIN, "GZ:hello");
}

// ── Ipe.Csv ────────────────────────────────────────────────────────────

const CSV_MAIN: &str = "module Main exposing (main)\n\
    import Ipe.Io as Io\n\
    import Ipe.Csv as Csv\n\n\
import Ipe.String
    headerLine : String\n\
    headerLine =\n\
    \x20   case Csv.parse \"a,b\\n1,2\" of\n\
    \x20       Ok doc -> String.join \"|\" doc.header\n\
    \x20       Err _ -> \"ERR\"\n\n\
    main = Io.println headerLine\n";

#[test]
fn csv_resolves_and_emits() {
    let _ = compile_module_probe("csv", CSV_MAIN);
}

#[test]
fn csv_builds_and_runs() {
    seal_module("csv", CSV_MAIN, "a|b");
}

// ── Ipe.Cache ──────────────────────────────────────────────────────────
// Exercises the full surface example 36-composite-server uses: `defaultCfg` +
// `withMaxEntries`/`withTTL` builders → `new` (a `CacheCfg` record literal
// consumed by `Cache_newRaw`), `put`, then `get` (a `Cache String String`
// value pattern-matched through the `Cache k v` ADT). Proves the three emit
// fixes together: the phantom `k`/`v` enum params (E0392), the `CacheCfg`
// record → runtime-struct fold (E0308), and the `PartialEq` generic bound the
// runtime `cache_put`/`cache_get` require.

const CACHE_MAIN: &str = "module Main exposing (main)\n\
    import Ipe.Task as Task\n\
    import Ipe.Io as Io\n\
    import Ipe.Cache as Cache\n\
    import Ipe.Duration as Duration\n\n\
import Ipe.Maybe
    program : Task Error String\n\
    program =\n\
    \x20   let\n\
    \x20       cfg = Cache.defaultCfg |> Cache.withMaxEntries 64 |> Cache.withTTL (Duration.millis 30000)\n\
    \x20   in\n\
    \x20   Cache.new cfg\n\
    \x20       |> Task.andThen\n\
    \x20           (\\cache ->\n\
    \x20               Cache.put cache \"k\" \"hit\"\n\
    \x20                   |> Task.andThen (\\_ -> Cache.get cache \"k\")\n\
    \x20                   |> Task.map (\\found -> Maybe.withDefault \"miss\" found)\n\
    \x20           )\n\n\
    main =\n\
    \x20   program |> Task.andThen (\\v -> Io.println (\"CACHE:\" ++ v))\n";

#[test]
fn cache_resolves_and_emits() {
    let _ = compile_module_probe("cache", CACHE_MAIN);
}

#[test]
fn cache_builds_and_runs() {
    // put "k"="hit" then get "k" → Just "hit"; withDefault → "hit".
    seal_module("cache", CACHE_MAIN, "CACHE:hit");
}

// ── Ipe.PubSub ─────────────────────────────────────────────────────────
// PubSub.publish : Topic a -> a -> Task Error Int.  No Web.tea runs in this
// probe so publish resolves to Err(Unavailable) — Task.onError swallows it and
// the program prints the marker.  The test asserts ipe-0 ⇒ cargo-0 ⇒ exit-0.

const PUBSUB_MAIN: &str = "module Main exposing (main)\n\
    import Ipe.Task as Task\n\
    import Ipe.Json.Encode as JsonEnc\n\
    import Ipe.PubSub as PubSub\n\
    import Ipe.Io as Io\n\n\
    main =\n\
    \x20   do\n\
    \x20       PubSub.publish (PubSub.topic \"t\") (JsonEnc.string \"hi\")\n\
    \x20           |> Task.onError (\\_ -> Task.succeed 0)\n\
    \x20       Io.println \"PUBSUB_OK\"\n";

#[test]
fn pubsub_resolves_and_emits() {
    let _ = compile_module_probe("pubsub", PUBSUB_MAIN);
}

#[test]
fn pubsub_builds_and_runs() {
    seal_module("pubsub", PUBSUB_MAIN, "PUBSUB_OK");
}

// ── Ipe.PubSub typed-topic contract tests ──────────────────────────────
//
// Positive: publisher and subscriber share the SAME `Topic a` handle — the
// payload type `a` unifies at compile time.  This must compile cleanly.
//
// Negative: publisher uses `Topic Int`, subscriber expects `Topic String` on
// the same topic name — different `Topic a` handles, so `a` cannot unify.
// Must be rejected as IPE-T0001.

const PUBSUB_TYPED_SHARED_TOPIC: &str = "module Main exposing (main)\n\
    import Ipe.Tea.Web.Cmd as Cmd\n\
    import Ipe.Tea.Web.Sub as Sub\n\
    import Ipe.PubSub as PubSub exposing (Topic)\n\
    import Ipe.Tea.Web as Web\n\
    import Ipe.Ui as Ui\n\
    import Ipe.Io as Io\n\
    type Msg = Got Int | Send\n\
    type alias Model = { last : Int }\n\
    scoreTopic : Topic Int\n\
    scoreTopic = PubSub.topic \"score\"\n\
    init _req = ( { last = 0 }, Cmd.none )\n\
    update msg model = case msg of\n\
    \x20   Got n -> ( { model | last = n }, Cmd.none )\n\
    \x20   Send -> ( model, Cmd.publish scoreTopic 42 )\n\
    subscriptions _m = Sub.subscribeTopic scoreTopic Got\n\
    view _m = Ui.html (Ui.layout [] (Ui.text \"ok\"))\n\
    main = Web.tea { init = init, update = update, view = view\n\
    \x20            , subscriptions = subscriptions, routes = [], notFound = Send }\n";

/// Positive: publisher and subscriber both use `scoreTopic : Topic Int`.
/// The shared `Topic a` enforces `a = Int` for both — must compile cleanly.
#[test]
fn pubsub_typed_shared_topic_resolves_and_emits() {
    let _ = compile_module_probe("pubsub_typed_shared", PUBSUB_TYPED_SHARED_TOPIC);
}

/// Positive with E2E build: compiles and links.
#[test]
fn pubsub_typed_shared_topic_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let _ = compile_module_probe("pubsub_typed_shared_e2e", PUBSUB_TYPED_SHARED_TOPIC);
}

// Negative: one shared `t : Topic Int` used to `publish` an `Int` and to
// `subscribeTopic` a `String` handler (`GotStr`). Sharing the topic value ties
// the payload type on both sides, so `Int` (publish) and `String` (handler)
// cannot unify → IPE-T0001.
const PUBSUB_TOPIC_MISMATCH: &str = "module Main exposing (main)\n\
    import Ipe.Tea.Web.Cmd as Cmd\n\
    import Ipe.Tea.Web.Sub as Sub\n\
    import Ipe.PubSub as PubSub exposing (Topic)\n\
    import Ipe.Tea.Web as Web\n\
    import Ipe.Ui as Ui\n\
    type Msg = GotStr String | SendInt\n\
    type alias Model = { x : Int }\n\
    t : Topic Int\n\
    t = PubSub.topic \"t\"\n\
    init _req = ( { x = 0 }, Cmd.none )\n\
    update msg model = case msg of\n\
    \x20   GotStr _ -> ( model, Cmd.none )\n\
    \x20   SendInt  -> ( model, Cmd.publish t 1 )\n\
    subscriptions _m = Sub.subscribeTopic t GotStr\n\
    view _m = Ui.html (Ui.layout [] (Ui.text \"bad\"))\n\
    main = Web.tea { init = init, update = update, view = view\n\
    \x20            , subscriptions = subscriptions, routes = [], notFound = SendInt }\n";

/// Negative: `Cmd.publish intTopic 1` with `intTopic : Topic Int` and
/// `Sub.subscribeTopic strTopic GotStr` with `strTopic : Topic String`.
/// `Int` and `String` do not unify — must be rejected as IPE-T0001.
#[test]
fn pubsub_topic_type_mismatch_is_rejected() {
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let uid = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // Fold the PID in so two parallel test binaries never collide on the shared
    // temp_dir (the per-process counter alone restarts at 0 in each binary).
    let pid = std::process::id();
    let tmp = crate::support::scratch_root().join(format!("ipec_pubsub_mismatch_{pid}_{uid}"));
    assert!(
        write_project(&tmp, PUBSUB_TOPIC_MISMATCH),
        "must write the pubsub_mismatch fixture"
    );
    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("pubsub_mismatch_{uid}_out"));
    let _ = fs::remove_dir_all(&out);
    let res = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        res.is_err(),
        "mismatched Topic types (Int vs String) must be rejected; got Ok(_)"
    );
}

// ── Ipe.Config ─────────────────────────────────────────────────────────
// Exercises the 16 `Config_*` kernels over the SHARED `Decoder` carrier: the
// four primitives (string/int/float/bool), `field`/`at`/`list`/`nullable`,
// `map`/`andThen`/`succeed`/`fail`, and all three format front-ends
// (`decodeToml`/`decodeYaml`/`decodeJson`). Proves two properties together:
// the `type Decoder a` re-declaration resolves (IPE-N0026 carrier exemption) with
// no competing enum emitted, and every kernel emits the shared JSON `decode_*` /
// `config_decode_*` runtime fns (ipe-0 ⇒ cargo-0). Uses SINGLE-decoder
// composition — the multi-parameter applicative `succeed (\a b -> …)` builder is
// the same documented distinct surface `Ipe.Json.Decode` has (divergences
// §A8), not a Config-specific gap.

const CONFIG_MAIN: &str = "module Main exposing (main)\n\
    import Ipe.Config as Config\n\
    import Ipe.Io as Io\n\n\
import Ipe.List
import Ipe.Maybe
import Ipe.Result
import Ipe.String
    hostD : Config.Decoder String\n\
    hostD = Config.field \"host\" Config.string\n\n\
    portD : Config.Decoder Int\n\
    portD = Config.at [\"db\", \"port\"] Config.int\n\n\
    tagsD : Config.Decoder (List String)\n\
    tagsD = Config.field \"tags\" (Config.list Config.string)\n\n\
    noteD : Config.Decoder (Maybe String)\n\
    noteD = Config.nullable (Config.field \"note\" Config.string)\n\n\
    ratioD : Config.Decoder Float\n\
    ratioD = Config.map (\\r -> r) (Config.field \"ratio\" Config.float)\n\n\
    checkedPortD : Config.Decoder Int\n\
    checkedPortD =\n\
    \x20   Config.andThen\n\
    \x20       (\\p -> if p > 0 then Config.succeed p else Config.fail \"bad\")\n\
    \x20       portD\n\n\
    main =\n\
    \x20   let\n\
    \x20       toml = \"host = \\\"h\\\"\\ntags = [\\\"a\\\"]\\nratio = 1.0\\n\\n[db]\\nport = 5\\n\"\n\
    \x20       yaml = \"note: hi\\n\"\n\
    \x20       json = \"{\\\"host\\\": \\\"j\\\"}\"\n\
    \x20       h = Result.withDefault \"?\" (Config.decodeToml toml hostD)\n\
    \x20       p = Result.withDefault 0 (Config.decodeToml toml checkedPortD)\n\
    \x20       t = String.fromInt (List.length (Result.withDefault [] (Config.decodeToml toml tagsD)))\n\
    \x20       n = Maybe.withDefault \"none\" (Result.withDefault Nothing (Config.decodeYaml yaml noteD))\n\
    \x20       j = Result.withDefault \"?\" (Config.decodeJson json hostD)\n\
    \x20   in\n\
    \x20   Io.println (\"CONFIG:\" ++ h ++ \":\" ++ String.fromInt p ++ \":\" ++ t ++ \":\" ++ n ++ \":\" ++ j)\n";

#[test]
fn config_resolves_and_emits() {
    let _ = compile_module_probe("config", CONFIG_MAIN);
}

#[test]
fn config_builds_and_runs() {
    seal_module("config", CONFIG_MAIN, "CONFIG:h:5:1:hi:j");
}

// ── Ipe.Markdown ───────────────────────────────────────────────────────────
// Exercises the whole public surface:
//   * `Markdown.render` — a document touching every block renderer (heading,
//     paragraph with a bold span, fenced code block, horizontal rule, table,
//     bullet list, link) so the `msg`-generic UI-carrier `'static` bound and
//     the theme-token chrome are both under seal.
//   * `Markdown.renderInline` — single inline line with a code span.
//   * `Markdown.parseBlocks` / `parseSpans` with `Block(..)` / `Span(..)` — the
//     public parser (a caller walking the parse tree itself).
//
// The render output is `Element msg`, not a `String`, so we pipe through
// `Html.htmlRender (Ui.layout [] …)` and `Io.println` — the same pattern the
// `golden_stdui_grid_seal` uses.  The `_resolves_and_emits` test asserts ipe
// exit 0 (no IPE-N0004 / N0028 regression).  The `_builds_and_runs` seal
// asserts cargo exit 0 (no E0310 on a boxed leaf renderer) AND that the
// rendered HTML carries theme-token chrome (`color-mix(... currentColor ...)`)
// and NONE of the old fixed dark palette.

const MARKDOWN_MAIN: &str = "module Main exposing (main)\n\
    import Ipe.Io as Io\n\
    import Ipe.Html as Html\n\
    import Ipe.Ui as Ui\n\
    import Ipe.Markdown as Markdown\n\n\
    doc : String\n\
    doc = \"# Hello\\n\\nThis is **bold** text.\\n\\n```\\ncode\\n```\\n\\n---\\n\\n| a | b |\\n|---|---|\\n| 1 | 2 |\\n\\n- one\\n- two\\n\\nA [link](https://x.dev) here.\"\n\n\
    inline : String\n\
    inline = \"Use `render` for blocks\"\n\n\
    main =\n\
    \x20   let\n\
    \x20       blockEl  = Markdown.render doc\n\
    \x20       inlineEl = Markdown.renderInline inline\n\
    \x20       page = Ui.column [] [ blockEl, inlineEl ]\n\
    \x20   in\n\
    \x20   Io.println (Html.htmlRender (Ui.layout [] page))\n";

// The public parser: extract fenced code bodies via `parseBlocks` + `Block(..)`
// and count code spans via `parseSpans` + `Span(..)`.  A closed union forbids a
// catch-all arm, so every constructor is matched explicitly.
const MARKDOWN_PARSER_MAIN: &str = "module Main exposing (main)\n\
    import Ipe.Io as Io\n\
    import Ipe.List as List\n\
    import Ipe.String as String\n\
    import Ipe.Markdown as Markdown exposing (Block(..), Span(..))\n\n\
    keepCode : Block -> Maybe String\n\
    keepCode block =\n\
    \x20   case block of\n\
    \x20       CodeBlock body -> Just body\n\
    \x20       HeaderBlock _ _ -> Nothing\n\
    \x20       ParaBlock _ -> Nothing\n\
    \x20       BulletBlock _ -> Nothing\n\
    \x20       NumberedBlock _ -> Nothing\n\
    \x20       TableBlock _ _ -> Nothing\n\
    \x20       RuleBlock -> Nothing\n\
    \x20       BlockquoteBlock _ -> Nothing\n\n\
    isCode : Span -> Bool\n\
    isCode span =\n\
    \x20   case span of\n\
    \x20       CodeSpan _ -> True\n\
    \x20       PlainSpan _ -> False\n\
    \x20       BoldSpan _ -> False\n\
    \x20       ItalicSpan _ -> False\n\
    \x20       LinkSpan _ _ -> False\n\
    \x20       ImageSpan _ _ -> False\n\
    \x20       HardBreakSpan -> False\n\n\
    main =\n\
    \x20   let\n\
    \x20       blocks = Markdown.parseBlocks \"# H\\n\\ntext\\n\\n```\\nbody\\n```\"\n\
    \x20       bodies = List.filterMap keepCode blocks\n\
    \x20       spans  = List.filter isCode (Markdown.parseSpans \"a `x` b `y`\")\n\
    \x20   in\n\
    \x20   Io.println (String.join \",\" bodies ++ \"|\" ++ String.fromInt (List.length spans))\n";

#[test]
fn markdown_resolves_and_emits() {
    let _ = compile_module_probe("markdown", MARKDOWN_MAIN);
}

#[test]
fn markdown_parser_resolves_and_emits() {
    let _ = compile_module_probe("markdown_parser", MARKDOWN_PARSER_MAIN);
}

#[test]
fn markdown_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = compile_module_probe("markdown_e2e", MARKDOWN_MAIN);
    let out = crate::support::build_and_run_emitted("markdown", &dir);
    assert_eq!(
        out.exit_code,
        Some(0),
        "emitted `markdown` crate must build + run cleanly, got exit {:?}",
        out.exit_code
    );
    // The rendered HTML must carry the heading text and bold styling.
    assert!(
        out.stdout.contains("Hello"),
        "rendered HTML must contain heading text 'Hello':\n{}",
        out.stdout
    );
    assert!(
        out.stdout.contains("font-weight"),
        "rendered HTML must carry bold styling (font-weight) for **bold**:\n{}",
        out.stdout
    );
    // Chrome (code block, rule, table, bullet marker, inline code) draws from
    // the theme foreground via `color-mix(... currentColor ...)` — no fixed hex.
    assert!(
        out.stdout.contains("color-mix(in srgb, currentColor"),
        "rendered HTML must carry theme-token chrome (currentColor color-mix):\n{}",
        out.stdout
    );
    for dark_hex in ["#101116", "#2A2A33", "#2a2a33", "#1c1c23", "#1f1f27"] {
        assert!(
            !out.stdout.contains(dark_hex),
            "rendered HTML must NOT carry the old fixed dark hex `{dark_hex}`:\n{}",
            out.stdout
        );
    }
}

#[test]
fn markdown_parser_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = compile_module_probe("markdown_parser_e2e", MARKDOWN_PARSER_MAIN);
    let out = crate::support::build_and_run_emitted("markdown_parser", &dir);
    assert_eq!(
        out.exit_code,
        Some(0),
        "emitted `markdown_parser` crate must build + run cleanly, got exit {:?}",
        out.exit_code
    );
    // `parseBlocks` yields one code block body `body`; `parseSpans` finds 2 code
    // spans — the public parser walks the tree the caller reached itself.
    assert!(
        out.stdout.trim() == "body|2",
        "parser output must be `body|2`, got:\n{}",
        out.stdout
    );
}

// ── Ipe.Markdown — blockquote, image, hard-break feature tests ─────────────
//
// Blockquote: `> quote` renders with a left-rule border using `dividerColor`
// (theme-derived `color-mix(... currentColor ...)`).
//
// Image: `![alt](url)` renders an `<img>` with the given src; a
// `javascript:` src is neutralised by the runtime attribute sink.
//
// Hard break: a line ending in two spaces emits a `<br>`.
//
// All three are exercised through the public parse+render surface so the
// test is a full pipeline proof, not just a unit assertion.

const MARKDOWN_FEATURES_MAIN: &str = "module Main exposing (main)\n\
    import Ipe.Io as Io\n\
    import Ipe.Html as Html\n\
    import Ipe.Ui as Ui\n\
    import Ipe.Markdown as Markdown\n\n\
    bq : String\n\
    bq = \"> This is a blockquote\"\n\n\
    img : String\n\
    img = \"![alt text](https://example.com/img.png)\"\n\n\
    imgJs : String\n\
    imgJs = \"![x](javascript:alert(1))\"\n\n\
    hb : String\n\
    hb = \"line one  \\nline two\"\n\n\
    main =\n\
    \x20   let\n\
    \x20       bqEl   = Markdown.render bq\n\
    \x20       imgEl  = Markdown.render img\n\
    \x20       imgJsEl = Markdown.render imgJs\n\
    \x20       hbEl   = Markdown.render hb\n\
    \x20       page   = Ui.column [] [ bqEl, imgEl, imgJsEl, hbEl ]\n\
    \x20   in\n\
    \x20   Io.println (Html.htmlRender (Ui.layout [] page))\n";

#[test]
fn markdown_features_resolves_and_emits() {
    let _ = compile_module_probe("markdown_features", MARKDOWN_FEATURES_MAIN);
}

#[test]
fn markdown_features_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = compile_module_probe("markdown_features_e2e", MARKDOWN_FEATURES_MAIN);
    let out = crate::support::build_and_run_emitted("markdown_features", &dir);
    assert_eq!(
        out.exit_code,
        Some(0),
        "emitted `markdown_features` crate must build + run cleanly, got exit {:?}",
        out.exit_code
    );
    // Blockquote renders with a left-rule border using the theme-derived color.
    assert!(
        out.stdout.contains("border-left"),
        "blockquote must render with a left-rule border:\n{}",
        out.stdout
    );
    assert!(
        out.stdout.contains("color-mix(in srgb, currentColor"),
        "blockquote left-rule must use theme-derived color-mix(currentColor):\n{}",
        out.stdout
    );
    // Image renders with <img> and the correct src.
    assert!(
        out.stdout.contains("<img"),
        "image must render an <img> element:\n{}",
        out.stdout
    );
    assert!(
        out.stdout.contains("https://example.com/img.png"),
        "image src must contain the original URL:\n{}",
        out.stdout
    );
    assert!(
        out.stdout.contains("alt text"),
        "image must carry the alt attribute text:\n{}",
        out.stdout
    );
    // javascript: src is neutralised by the runtime attribute sink
    // (sanitise_url_attr): the dangerous scheme never reaches the output.
    assert!(
        !out.stdout.contains("javascript:"),
        "javascript: must not appear in rendered output:\n{}",
        out.stdout
    );
    // Hard break renders a <br> (the runtime emits self-closing `<br />`).
    assert!(
        out.stdout.contains("<br"),
        "trailing double-space must render a <br>:\n{}",
        out.stdout
    );
}
