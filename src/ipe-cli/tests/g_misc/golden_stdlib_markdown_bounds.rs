//! `Ipe.Markdown` parses adversarial input in linear time on a bounded stack.
//!
//! Quotes nest at most `MAX_BLOCKQUOTE_DEPTH` deep. One Ipê program, built
//! once per test, reads a single `case n` line from stdin, builds the input
//! with `String.repeat`, parses it, and prints a digest
//! `case:count:firstTag:lastTag:lastSize[:depth]`. The expected digest comes
//! from the `ipe_docs` port on the identical input (the port is pinned equal to
//! the Ipê source by the parity snapshot), and the count, tags and depth are
//! also derived from the parser's rule. Every run is deadline-bounded: a
//! superlinear parse or a recursion-guard trip fails the test, never hangs it.
//! Linearity is judged on the child's CPU time, which the host's load does not
//! inflate, never on its wall time.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ipe_docs::markdown::MAX_BLOCKQUOTE_DEPTH;
use ipe_docs::markdown::parse::{parse_blocks, parse_spans};
use ipe_docs::markdown::{Block, Span};

#[cfg(target_os = "linux")]
use crate::support::CpuTime;
use crate::support::{TimedRunOutcome, build_emitted_binary_checked, run_with_stdin_deadline};

/// Wall-time ceiling for one run of the emitted binary.
const DEADLINE: Duration = Duration::from_secs(20);

/// One past the runtime's default recursion limit (10 000).
const PAST_GUARD: usize = 10_001;

const BOUNDS_MAIN: &str = r#"module Main exposing (main)

import Ipe.Html as Html
import Ipe.Io as Io
import Ipe.List as List
import Ipe.Markdown as Markdown exposing (Block(..), Span(..))
import Ipe.Maybe as Maybe
import Ipe.String as String
import Ipe.Task as Task
import Ipe.Ui as Ui


blockTag : Block -> String
blockTag block =
    case block of
        HeaderBlock _ _ ->
            "header"

        ParaBlock _ ->
            "para"

        CodeBlock _ ->
            "code"

        BulletBlock _ ->
            "bullets"

        NumberedBlock _ ->
            "numbered"

        TableBlock _ _ ->
            "table"

        RuleBlock ->
            "rule"

        BlockquoteBlock _ ->
            "quote"


blockSize : Block -> Int
blockSize block =
    case block of
        HeaderBlock _ text ->
            String.length text

        ParaBlock text ->
            String.length text

        CodeBlock text ->
            String.length text

        BulletBlock items ->
            List.length items

        NumberedBlock items ->
            List.length items

        TableBlock _ rows ->
            List.length rows

        RuleBlock ->
            0

        BlockquoteBlock inner ->
            List.length inner


quoteDepth : Block -> Int
quoteDepth block =
    case block of
        BlockquoteBlock inner ->
            1 + deepest inner

        HeaderBlock _ _ ->
            0

        ParaBlock _ ->
            0

        CodeBlock _ ->
            0

        BulletBlock _ ->
            0

        NumberedBlock _ ->
            0

        TableBlock _ _ ->
            0

        RuleBlock ->
            0


deepest : List Block -> Int
deepest blocks =
    List.foldl (\b acc -> max (quoteDepth b) acc) 0 blocks


spanTag : Span -> String
spanTag span =
    case span of
        PlainSpan _ ->
            "plain"

        BoldSpan _ ->
            "bold"

        ItalicSpan _ ->
            "italic"

        CodeSpan _ ->
            "code"

        LinkSpan _ _ ->
            "link"

        ImageSpan _ _ ->
            "image"

        HardBreakSpan ->
            "break"


spanSize : Span -> Int
spanSize span =
    case span of
        PlainSpan text ->
            String.length text

        BoldSpan text ->
            String.length text

        ItalicSpan text ->
            String.length text

        CodeSpan text ->
            String.length text

        LinkSpan text _ ->
            String.length text

        ImageSpan alt _ ->
            String.length alt

        HardBreakSpan ->
            0


ends : (a -> String) -> (a -> Int) -> List a -> String
ends tag size xs =
    let
        first =
            Maybe.withDefault "none" (Maybe.map tag (List.head xs))

        lastOne =
            List.head (List.reverse xs)
    in
    first
        ++ ":"
        ++ Maybe.withDefault "none" (Maybe.map tag lastOne)
        ++ ":"
        ++ String.fromInt (Maybe.withDefault 0 (Maybe.map size lastOne))


blockDigest : String -> String
blockDigest src =
    let
        blocks =
            Markdown.parseBlocks src
    in
    String.fromInt (List.length blocks)
        ++ ":"
        ++ ends blockTag blockSize blocks
        ++ ":"
        ++ String.fromInt (deepest blocks)


spanDigest : String -> String
spanDigest src =
    let
        spans =
            Markdown.parseSpans src
    in
    String.fromInt (List.length spans) ++ ":" ++ ends spanTag spanSize spans


renderLength : String -> String
renderLength src =
    String.fromInt (String.length (Html.htmlRender (Ui.layout [] (Markdown.render src))))


runCase : String -> Int -> String
runCase name n =
    case name of
        "blanks" ->
            blockDigest (String.repeat n "\n" ++ "x")

        "rules" ->
            blockDigest (String.repeat n "---\n")

        "bullets" ->
            blockDigest (String.repeat n "- a\n")

        "numbered" ->
            blockDigest (String.repeat n "1. a\n")

        "para-lines" ->
            blockDigest (String.repeat n "a\n")

        "table-rows" ->
            blockDigest ("|h|\n|-|\n" ++ String.repeat n "|a|\n")

        "quote" ->
            let
                src =
                    String.repeat n "> " ++ "x"
            in
            blockDigest src ++ ":" ++ renderLength src

        "fence" ->
            blockDigest ("```\n" ++ String.repeat n "a\n")

        "stars" ->
            spanDigest (String.repeat n "*")

        "brackets" ->
            spanDigest (String.repeat n "[")

        "bangs" ->
            spanDigest (String.repeat n "![")

        "ticks" ->
            spanDigest (String.repeat n "`")

        "line" ->
            let
                src =
                    String.repeat n "ab "
            in
            blockDigest src ++ "|" ++ spanDigest src

        "trailing-sp" ->
            spanDigest ("a" ++ String.repeat n " " ++ "\nb")

        _ ->
            "unknown"


runLine : String -> String
runLine line =
    let
        parts =
            String.words line

        name =
            Maybe.withDefault "" (List.head parts)

        size =
            Maybe.withDefault 0 (Maybe.andThen String.toInt (List.head (List.drop 1 parts)))
    in
    name ++ ":" ++ runCase name size


main =
    Io.readLine ()
        |> Task.andThen (\line -> Io.println (runLine line))
"#;

/// One input family of the bounds program; `name` is its stdin selector.
#[derive(Clone, Copy)]
enum Case {
    Blanks,
    Rules,
    Bullets,
    Numbered,
    ParaLines,
    TableRows,
    Quote,
    Fence,
    Stars,
    Brackets,
    Bangs,
    Ticks,
    Line,
    TrailingSpaces,
}

impl Case {
    const fn name(self) -> &'static str {
        match self {
            Self::Blanks => "blanks",
            Self::Rules => "rules",
            Self::Bullets => "bullets",
            Self::Numbered => "numbered",
            Self::ParaLines => "para-lines",
            Self::TableRows => "table-rows",
            Self::Quote => "quote",
            Self::Fence => "fence",
            Self::Stars => "stars",
            Self::Brackets => "brackets",
            Self::Bangs => "bangs",
            Self::Ticks => "ticks",
            Self::Line => "line",
            Self::TrailingSpaces => "trailing-sp",
        }
    }

    /// The exact source the Ipê program builds for `n`.
    fn source(self, n: usize) -> String {
        match self {
            Self::Blanks => "\n".repeat(n) + "x",
            Self::Rules => "---\n".repeat(n),
            Self::Bullets => "- a\n".repeat(n),
            Self::Numbered => "1. a\n".repeat(n),
            Self::ParaLines => "a\n".repeat(n),
            Self::TableRows => "|h|\n|-|\n".to_owned() + &"|a|\n".repeat(n),
            Self::Quote => "> ".repeat(n) + "x",
            Self::Fence => "```\n".to_owned() + &"a\n".repeat(n),
            Self::Stars => "*".repeat(n),
            Self::Brackets => "[".repeat(n),
            Self::Bangs => "![".repeat(n),
            Self::Ticks => "`".repeat(n),
            Self::Line => "ab ".repeat(n),
            Self::TrailingSpaces => "a".to_owned() + &" ".repeat(n) + "\nb",
        }
    }

    /// The digest the port computes, without the quote case's render length.
    fn port_digest(self, n: usize) -> String {
        let src = self.source(n);
        let digest = match self {
            Self::Blanks
            | Self::Rules
            | Self::Bullets
            | Self::Numbered
            | Self::ParaLines
            | Self::TableRows
            | Self::Quote
            | Self::Fence => block_digest(&src),
            Self::Stars | Self::Brackets | Self::Bangs | Self::Ticks | Self::TrailingSpaces => {
                span_digest(&src)
            }
            Self::Line => format!("{}|{}", block_digest(&src), span_digest(&src)),
        };
        format!("{}:{digest}", self.name())
    }
}

const fn block_tag(block: &Block) -> &'static str {
    match block {
        Block::Header(..) => "header",
        Block::Para(_) => "para",
        Block::Code(_) => "code",
        Block::Bullet(_) => "bullets",
        Block::Numbered(_) => "numbered",
        Block::Table(..) => "table",
        Block::Rule => "rule",
        Block::Blockquote(_) => "quote",
    }
}

const fn block_size(block: &Block) -> usize {
    match block {
        Block::Header(_, text) | Block::Para(text) | Block::Code(text) => text.len(),
        Block::Bullet(items) | Block::Numbered(items) => items.len(),
        Block::Table(_, rows) => rows.len(),
        Block::Rule => 0,
        Block::Blockquote(inner) => inner.len(),
    }
}

fn deepest(blocks: &[Block]) -> usize {
    blocks.iter().map(quote_depth).max().unwrap_or(0)
}

fn quote_depth(block: &Block) -> usize {
    match block {
        Block::Blockquote(inner) => 1 + deepest(inner),
        Block::Header(..)
        | Block::Para(_)
        | Block::Code(_)
        | Block::Bullet(_)
        | Block::Numbered(_)
        | Block::Table(..)
        | Block::Rule => 0,
    }
}

const fn span_tag(span: &Span) -> &'static str {
    match span {
        Span::Plain(_) => "plain",
        Span::Bold(_) => "bold",
        Span::Italic(_) => "italic",
        Span::Code(_) => "code",
        Span::Link(..) => "link",
        Span::Image(..) => "image",
        Span::HardBreak => "break",
    }
}

const fn span_size(span: &Span) -> usize {
    match span {
        Span::Plain(text)
        | Span::Bold(text)
        | Span::Italic(text)
        | Span::Code(text)
        | Span::Link(text, _)
        | Span::Image(text, _) => text.len(),
        Span::HardBreak => 0,
    }
}

fn ends<T>(xs: &[T], tag: fn(&T) -> &'static str, size: fn(&T) -> usize) -> String {
    let first = xs.first().map_or("none", tag);
    let last = xs.last();
    format!(
        "{first}:{}:{}",
        last.map_or("none", tag),
        last.map_or(0, size)
    )
}

fn block_digest(src: &str) -> String {
    let blocks = parse_blocks(src);
    format!(
        "{}:{}:{}",
        blocks.len(),
        ends(&blocks, block_tag, block_size),
        deepest(&blocks)
    )
}

fn span_digest(src: &str) -> String {
    let spans = parse_spans(src);
    format!("{}:{}", spans.len(), ends(&spans, span_tag, span_size))
}

/// Emit the bounds program through ipe into a fresh per-call output dir.
fn emit_bounds_program(slug: &str) -> Option<PathBuf> {
    static PROBE_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let uid = PROBE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pid = std::process::id();
    let fixture = ipe::RootFixture::main(BOUNDS_MAIN);
    assert!(
        fixture.is_ok(),
        "the bounds fixture project must resolve: {:?}",
        fixture.as_ref().err()
    );
    let fixture = fixture.ok()?;
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("markdown_bounds_{slug}_{pid}_{uid}_out"));
    let _ = fs::remove_dir_all(&out);
    let built = ipe::build_fixture(&fixture, &out, &runtime);
    assert!(
        built.is_ok(),
        "the bounds program must resolve and emit (ipe exit 0), got: {:?}",
        built.err()
    );
    Some(out)
}

/// The built bounds binary for `slug`.
///
/// A failure names the stage (emit or build) that failed; the caller has
/// already gated the unit tier.
#[allow(clippy::expect_used)] // a bounds program that fails to emit or build fails the test
fn bounds_binary(slug: &str) -> e2e_support::SharedBuild {
    let dir = emit_bounds_program(slug).expect("the bounds program must emit");
    build_emitted_binary_checked(&format!("markdown_bounds_{slug}"), &dir)
        .expect("the bounds program must build")
}

fn run_case(exe: &Path, case: Case, n: usize) -> TimedRunOutcome {
    let stdin = format!("{} {n}\n", case.name());
    run_with_stdin_deadline(
        &format!("markdown_bounds_{}", case.name()),
        exe,
        stdin.as_bytes(),
        DEADLINE,
    )
}

/// Run one case, require a clean exit, and return its trimmed digest line.
fn digest_of(exe: &Path, case: Case, n: usize) -> String {
    let out = run_case(exe, case, n);
    assert_eq!(
        out.exit_code,
        Some(0),
        "`{} {n}` must exit 0 (a recursion-guard trip exits 1); stderr:\n{}",
        case.name(),
        out.stderr
    );
    out.stdout.trim().to_owned()
}

/// The `count:firstTag:lastTag:lastSize:depth` fields of a block digest.
fn block_fields(digest: &str) -> Vec<&str> {
    digest.split(':').skip(1).collect()
}

#[test]
fn bounds_program_resolves_and_emits() {
    let _ = emit_bounds_program("emit");
}

#[test]
fn every_block_run_does_not_trip_guard() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let exe = bounds_binary("blocks");
    let lines = PAST_GUARD.to_string();
    let lines = lines.as_str();
    // (case, block count, first tag, last tag, last block's size where the rule fixes it)
    let rows: [(Case, &str, &str, &str, Option<&str>); 7] = [
        (Case::Blanks, "1", "para", "para", Some("1")),
        (Case::Rules, lines, "rule", "rule", Some("0")),
        (Case::Bullets, "1", "bullets", "bullets", Some(lines)),
        (Case::Numbered, "1", "numbered", "numbered", Some(lines)),
        (Case::ParaLines, "1", "para", "para", None),
        (Case::TableRows, "1", "table", "table", Some(lines)),
        (Case::Fence, "1", "code", "code", None),
    ];
    for (case, count, first, last, size) in rows {
        let got = digest_of(&exe, case, PAST_GUARD);
        assert_eq!(got, case.port_digest(PAST_GUARD), "port digest");
        let fields = block_fields(&got);
        assert_eq!(
            fields.get(..3),
            Some([count, first, last].as_slice()),
            "`{}`: the parser's rule fixes count and tags: {got}",
            case.name()
        );
        if let Some(size) = size {
            assert_eq!(fields.get(3), Some(&size), "`{}`: size: {got}", case.name());
        }
        assert_eq!(
            fields.get(4),
            Some(&"0"),
            "`{}`: no quote: {got}",
            case.name()
        );
    }
}

#[test]
fn quote_depth_ceiling() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let exe = bounds_binary("quote");
    let ceiling = MAX_BLOCKQUOTE_DEPTH.to_string();
    for n in [MAX_BLOCKQUOTE_DEPTH + 1, PAST_GUARD] {
        let got = digest_of(&exe, Case::Quote, n);
        let split = got.rsplit_once(':');
        assert!(split.is_some(), "`quote {n}`: malformed digest {got}");
        let (digest, render_len) = split.unwrap_or_default();
        assert_eq!(digest, Case::Quote.port_digest(n), "port digest");
        let fields = block_fields(digest);
        assert_eq!(fields.first().copied(), Some("1"), "`quote {n}`: one block");
        assert_eq!(
            fields.get(4).copied(),
            Some(ceiling.as_str()),
            "`quote {n}`: nesting stops at the ceiling: {got}"
        );
        assert!(
            render_len.parse::<usize>().is_ok_and(|len| len > 0),
            "`quote {n}`: the tree renders: {got}"
        );
    }
}

#[test]
fn span_runs_finish_in_deadline() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let exe = bounds_binary("spans");
    let rows = [
        (Case::Stars, 100_000),
        (Case::Brackets, 100_000),
        (Case::Bangs, 50_000),
        (Case::Ticks, 100_000),
        (Case::Line, 350_000),
        (Case::TrailingSpaces, 100_000),
    ];
    for (case, n) in rows {
        let got = digest_of(&exe, case, n);
        assert_eq!(got, case.port_digest(n), "port digest");
    }
}

/// Largest `w(4n)/w(n)` a linear parse may show: `n log n` gives about 4.5,
/// `n^1.5` gives 8 and `n^2` gives 16.
const LINEAR_CEILING: f64 = 6.0;

/// Work below which a reading is clock-tick noise, not growth.
const WORK_FLOOR: Duration = Duration::from_millis(200);

/// `w(4n)/w(n)` when it shows growth past linear, else `None`.
///
/// A base under `WORK_FLOOR` is read as `WORK_FLOOR`, so tick noise at a small
/// size never reads as growth.
fn superlinear_ratio(base: Duration, quadrupled: Duration) -> Option<f64> {
    let ratio = quadrupled.as_secs_f64() / base.max(WORK_FLOOR).as_secs_f64();
    (ratio > LINEAR_CEILING).then_some(ratio)
}

/// CPU time of one run, the minimum of three; the measure of the parse's work.
///
/// CPU time, never wall time: a wall clock also counts the time the child
/// waited for a core while sibling tests ran, which reads as growth.
#[cfg(target_os = "linux")]
fn parse_work(exe: &Path, case: Case, n: usize) -> CpuTime {
    let runs = (0..3).map(|_| {
        let out = run_case(exe, case, n);
        assert_eq!(out.exit_code, Some(0), "`{} {n}` must exit 0", case.name());
        assert!(
            out.cpu.is_some(),
            "`{} {n}`: the child's CPU time must be readable from `/proc`",
            case.name()
        );
        out.cpu
    });
    runs.flatten().min().unwrap_or_default()
}

#[cfg(target_os = "linux")]
#[test]
fn doubling_is_linear() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let exe = bounds_binary("doubling");
    let startup = parse_work(&exe, Case::Brackets, 0);
    let work = |case: Case, n: usize| {
        parse_work(&exe, case, n)
            .saturating_sub(startup)
            .as_duration()
    };
    let cap = 1 << 20;
    for case in [Case::Brackets, Case::Stars, Case::ParaLines, Case::Line] {
        let mut n = 2_000;
        let mut base = work(case, n);
        while base < WORK_FLOOR && n < cap {
            n *= 2;
            base = work(case, n);
        }
        let quadrupled = work(case, 4 * n);
        let ratio = superlinear_ratio(base, quadrupled);
        assert!(
            ratio.is_none(),
            "`{}`: w(4n)/w(n) = {:.2} at n = {n} (CPU {base:?} -> {quadrupled:?}); linear is about 4",
            case.name(),
            ratio.unwrap_or_default()
        );
    }
}

/// Synthetic `w(4n)` for a base of one second under each growth law.
fn quadrupled_under(exponent: f64) -> Duration {
    Duration::from_secs_f64(4.0_f64.powf(exponent))
}

#[test]
fn the_linearity_judge_admits_linear_and_n_log_n_growth() {
    let base = Duration::from_secs(1);
    assert!(
        superlinear_ratio(base, quadrupled_under(1.0)).is_none(),
        "n"
    );
    // `n log n` at n = 2 000: 4 * log(8 000) / log(2 000) is about 4.73.
    assert!(
        superlinear_ratio(base, Duration::from_millis(4_730)).is_none(),
        "n log n"
    );
    assert!(
        superlinear_ratio(base, Duration::from_secs(6)).is_none(),
        "the ceiling itself"
    );
}

#[test]
fn the_linearity_judge_refuses_superlinear_growth() {
    let base = Duration::from_secs(1);
    for (law, exponent) in [("n^1.5", 1.5), ("n^2", 2.0), ("n^3", 3.0)] {
        assert!(
            superlinear_ratio(base, quadrupled_under(exponent)).is_some(),
            "{law} must read as superlinear"
        );
    }
    assert!(
        superlinear_ratio(base, Duration::from_millis(6_010)).is_some(),
        "one step past the ceiling"
    );
    assert!(
        superlinear_ratio(Duration::from_millis(50), Duration::from_millis(1_250)).is_some(),
        "a base under the floor still refuses growth past the ceiling over the floor"
    );
}

#[test]
fn the_linearity_judge_reads_tick_noise_under_the_floor_as_no_growth() {
    // 10 ms -> 120 ms is a ratio of 12, but both sit under the floor.
    assert!(
        superlinear_ratio(Duration::from_millis(10), Duration::from_millis(120)).is_none(),
        "noise under the floor"
    );
}

/// Run `script` under `/bin/sh` through the deadline-bounded runner.
#[cfg(target_os = "linux")]
fn run_shell(name: &str, script: &str) -> TimedRunOutcome {
    let dir = ipe_test_temp::temp_root().join(format!("ipe-cpu-{name}-{}", std::process::id()));
    assert!(fs::create_dir_all(&dir).is_ok(), "scratch dir");
    let path = dir.join(name);
    assert!(
        fs::write(&path, format!("#!/bin/sh\n{script}\n")).is_ok(),
        "write script"
    );
    {
        use std::os::unix::fs::PermissionsExt;
        assert!(
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).is_ok(),
            "chmod script"
        );
    }
    let out = run_with_stdin_deadline(name, &path, b"", DEADLINE);
    let _ = fs::remove_dir_all(&dir);
    out
}

/// A child that only waits uses almost no CPU, however long its wall time:
/// the measure counts work, not the time a run spends off a core.
#[cfg(target_os = "linux")]
#[test]
fn the_work_measure_does_not_count_waiting() {
    let out = run_shell("waits", "exec sleep 1");
    assert_eq!(out.exit_code, Some(0), "stderr:\n{}", out.stderr);
    assert!(
        out.elapsed >= Duration::from_secs(1),
        "wall {:?}",
        out.elapsed
    );
    assert!(
        out.cpu.is_some(),
        "the CPU time of an exited child is read on Linux"
    );
    let cpu = out.cpu.map_or(Duration::MAX, CpuTime::as_duration);
    assert!(
        cpu < Duration::from_millis(500),
        "a sleeping child read {cpu:?} of CPU over {:?} of wall time",
        out.elapsed
    );
}

/// A child that computes reads its CPU time, so the measure is never vacuously zero.
#[cfg(target_os = "linux")]
#[test]
fn the_work_measure_counts_computation() {
    let out = run_shell("spins", "i=0; while [ $i -lt 300000 ]; do i=$((i+1)); done");
    assert_eq!(out.exit_code, Some(0), "stderr:\n{}", out.stderr);
    let cpu = out.cpu.map_or(Duration::ZERO, CpuTime::as_duration);
    assert!(
        cpu >= Duration::from_millis(100),
        "a spinning child read only {cpu:?} of CPU over {:?} of wall time",
        out.elapsed
    );
}

/// A child that never reads its stdin and never exits is killed at the
/// deadline: the stdin write cannot hold the runner past it. The input is
/// larger than any pipe buffer and the child sleeps 30 s, so a runner that
/// writes stdin before it polls blocks until the sleep ends.
#[cfg(unix)]
#[test]
fn a_child_that_never_reads_stdin_is_killed_at_the_deadline() {
    use std::os::unix::fs::PermissionsExt;

    let dir = ipe_test_temp::temp_root().join(format!("ipe-stdin-deadline-{}", std::process::id()));
    assert!(fs::create_dir_all(&dir).is_ok(), "scratch dir");
    let script = dir.join("never-reads");
    assert!(
        fs::write(&script, "#!/bin/sh\nexec sleep 30\n").is_ok(),
        "write script"
    );
    assert!(
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).is_ok(),
        "chmod script"
    );
    let input = vec![b'x'; 4 << 20];
    let started = std::time::Instant::now();
    let run = std::panic::catch_unwind(|| {
        run_with_stdin_deadline("never_reads", &script, &input, Duration::from_millis(300))
    });
    let took = started.elapsed();
    let _ = fs::remove_dir_all(&dir);
    let message = run
        .err()
        .and_then(|payload| payload.downcast::<String>().ok())
        .map(|text| *text)
        .unwrap_or_default();
    assert!(
        message.contains("no exit within"),
        "the runner must refuse the hung child, got: {message:?}"
    );
    assert!(
        took < Duration::from_secs(15),
        "the runner returned after {took:?}; the stdin write held it past the deadline"
    );
}
