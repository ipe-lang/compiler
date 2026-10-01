//! Ipe.Csv — CSV parse / encode via the `csv` crate.
//!
//! The Ipê `Csv` record (`{ header : List String, rows : List (List String) }`)
//! is mapped to `CsvDoc` below via the runtimeOpaqueTypes registry, so the
//! generated `StdCsvCsv` is a `pub use` alias of this struct. That lets the
//! kernels return/take the record DIRECTLY (no kernel can name a generated
//! per-project struct), and Ipê field access (`doc.header`) + the synthesized
//! record constructor resolve straight onto these `pub` fields.

use super::*;

// ── shared blocking-pool helper ───────────────────────────────────────
//
// `csv_parse_stream_from_file` does a blocking `std::fs::File::open` +
// incremental CSV read (bounded by `IPE_CSV_MAX_ROWS`, default 10M rows, AND
// `IPE_CSV_MAX_BYTES`, default 512 MiB of decoded field bytes) inline. Pre-fix
// that work ran EAGERLY, before `Box::pin` was even
// constructed — i.e. calling the kernel function itself blocked the caller,
// not just polling the returned future. Offload to tokio's blocking pool so
// a large/slow file can't stall the tokio worker thread. This module is
// gated on the raw `csv` Cargo feature (`#[cfg(feature = "csv")]` in
// `mod.rs`), NOT the composite `csv_kernel = ["csv", "tokio"]` feature, so
// `tokio` is not guaranteed present — same constraint `file.rs` documents
// for its own `run_blocking` helper (see
// `docs/adr/0003-security-render-and-data-access-invariants.md` §2.2).
#[cfg(feature = "tokio")]
async fn run_blocking<T, F>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r,
        Err(_) => Err("background csv task panicked".to_string()),
    }
}

#[cfg(not(feature = "tokio"))]
async fn run_blocking<T, F>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    f()
}

/// Runtime representation of the Ipê `Ipe.Csv.Csv` record. Field names + types
/// must match the Ipê alias exactly (List String -> Vec<String>, etc.).
#[derive(Clone, Debug, PartialEq)]
pub struct CsvDoc {
    pub header: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

/// Validate that `delim` is exactly one ASCII byte, as required by the csv
/// crate. A multi-byte string (e.g. a UTF-8 character) or an empty string is
/// silently mishandled by the old `first_byte` helper — the multi-byte case
/// takes only the first (possibly continuation) byte, producing a nonsense
/// delimiter; the empty case silently falls back to `,`, which is wrong for
/// callers that passed an explicit delimiter. Return `Err` for both cases.
fn validated_delimiter<E: From<String>>(delim: &str) -> IpeResult<E, u8> {
    match delim.as_bytes() {
        [b] if b.is_ascii() => IpeResult::Ok(*b),
        _ => IpeResult::Err(
            format!(
                "Csv: delimiter must be a single ASCII byte, got {:?}",
                delim
            )
            .into(),
        ),
    }
}

/// Row-count ceiling (default 10M). A large/untrusted input would otherwise
/// accumulate rows unbounded; past the cap the parse `Err`s rather than OOMs.
/// Overridable via `IPE_CSV_MAX_ROWS`.
fn csv_max_rows() -> usize {
    crate::system::read_env_var("IPE_CSV_MAX_ROWS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(10_000_000)
}

/// Total-decoded-bytes ceiling (default 512 MiB, the same default as `File.readFile`'s
/// `READ_FILE_DEFAULT_CEILING`). The row cap alone does NOT bound memory: a single huge
/// record (one row of gigabytes) or a file of oversized fields slips under any
/// row count while exhausting the heap. Bounded by construction (PRINCIPLES §3,
/// and §1's exhaustion clause when the CSV arrives over the network): the sum of
/// decoded field bytes is tracked and the parse `Err`s the moment it exceeds the
/// ceiling, never OOMs. Overridable via `IPE_CSV_MAX_BYTES`.
fn csv_max_bytes() -> u64 {
    crate::system::read_env_var("IPE_CSV_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(512 * 1024 * 1024)
}

/// Add this record's decoded field bytes to `seen`, returning `Err` when the
/// running total would exceed `cap`. The count is the sum of field lengths (the
/// bytes actually retained in the returned rows), so the ceiling bounds the
/// heap the parsed document occupies — the real exhaustion vector — rather than
/// the on-wire size. Saturating so the accumulator itself cannot overflow.
fn accrue_record_bytes(seen: &mut u64, rec: &::csv::StringRecord, cap: u64) -> Result<(), String> {
    let record_bytes: u64 = rec.iter().map(|f| f.len() as u64).sum();
    *seen = seen.saturating_add(record_bytes);
    if *seen > cap {
        return Err(format!(
            "exceeds byte cap of {cap} (raise IPE_CSV_MAX_BYTES)"
        ));
    }
    Ok(())
}

fn parse_delim<E: From<String>>(text: &str, delim: u8) -> IpeResult<E, CsvDoc> {
    let mut rdr = ::csv::ReaderBuilder::new()
        .delimiter(delim)
        .has_headers(true)
        .flexible(true)
        .from_reader(text.as_bytes());
    // Row cap AND byte cap: a large/untrusted input would otherwise accumulate
    // unbounded into `rows` — either by row COUNT (many small rows) or by decoded
    // BYTES (one huge record / oversized fields that slips under any row count).
    // Bound both → Err rather than OOM. Mirrors csv_parse_stream_from_file's caps.
    let max_rows = csv_max_rows();
    let max_bytes = csv_max_bytes();
    let mut seen_bytes: u64 = 0;
    let header: Vec<String> = match rdr.headers() {
        Ok(h) => {
            if let Err(e) = accrue_record_bytes(&mut seen_bytes, h, max_bytes) {
                return IpeResult::Err(format!("Csv.parse: {e}").into());
            }
            h.iter().map(|s| s.to_string()).collect()
        }
        Err(e) => return IpeResult::Err(format!("Csv.parse: {}", e).into()),
    };
    let mut rows = Vec::new();
    for rec in rdr.records() {
        match rec {
            Ok(r) => {
                if rows.len() >= max_rows {
                    return IpeResult::Err(
                        format!(
                            "Csv.parse: exceeds row cap of {} (raise IPE_CSV_MAX_ROWS)",
                            max_rows
                        )
                        .into(),
                    );
                }
                if let Err(e) = accrue_record_bytes(&mut seen_bytes, &r, max_bytes) {
                    return IpeResult::Err(format!("Csv.parse: {e}").into());
                }
                rows.push(r.iter().map(|s| s.to_string()).collect());
            }
            Err(e) => return IpeResult::Err(format!("Csv.parse: {}", e).into()),
        }
    }
    IpeResult::Ok(CsvDoc { header, rows })
}

/// Spreadsheet formula-injection guard (CWE-1236 / OWASP). A cell beginning with
/// `=`, `+`, `-`, `@`, TAB, or CR is interpreted as a FORMULA by Excel/Sheets when
/// the CSV is opened — an injection vector for attacker-controlled cell data.
/// OPT-IN via `IPE_CSV_SANITIZE_FORMULAS` because the only mitigation (prefix the
/// cell with `'`) is LOSSY: it alters exported data (e.g. `-5` → `'-5`) and breaks
/// the lossless parse↔encode round-trip. Default OFF preserves round-trip; the
/// caller opts in when serving CSV to spreadsheet users, accepting the tradeoff.
fn csv_formula_guard_enabled() -> bool {
    matches!(
        crate::system::read_env_var("IPE_CSV_SANITIZE_FORMULAS")
            .ok()
            .as_deref(),
        Some("1") | Some("on") | Some("true") | Some("yes")
    )
}

fn guard_formula(cell: &str) -> std::borrow::Cow<'_, str> {
    match cell.as_bytes().first() {
        Some(b'=') | Some(b'+') | Some(b'-') | Some(b'@') | Some(b'\t') | Some(b'\r') => {
            std::borrow::Cow::Owned(format!("'{}", cell))
        }
        _ => std::borrow::Cow::Borrowed(cell),
    }
}

#[allow(clippy::disallowed_methods)] // the writer is fed only `String` fields, so its bytes are UTF-8
fn encode_delim(doc: &CsvDoc, delim: u8) -> String {
    // flexible(true): a parsed-then-encoded doc may carry ragged rows (row width ≠
    // header width) since the reader is flexible. Without this the writer errors on
    // the first mismatch and the swallowed error silently DROPS that row — breaking
    // lossless round-trip. Flexible emits every row verbatim.
    let mut wtr = ::csv::WriterBuilder::new()
        .delimiter(delim)
        .flexible(true)
        .from_writer(vec![]);
    let guard = csv_formula_guard_enabled();
    for row in std::iter::once(&doc.header).chain(doc.rows.iter()) {
        if guard {
            let safe: Vec<String> = row.iter().map(|c| guard_formula(c).into_owned()).collect();
            let _ = wtr.write_record(&safe);
        } else {
            let _ = wtr.write_record(row);
        }
    }
    let bytes = wtr.into_inner().unwrap_or_default();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Csv.parse : String -> Result Error Csv
pub fn csv_parse<E: From<String>>(text: String) -> IpeResult<E, CsvDoc> {
    parse_delim(&text, b',')
}

/// Csv.parseWithDelimiter : String -> String -> Result Error Csv
pub fn csv_parse_with_delimiter<E: From<String>>(
    delim: String,
    text: String,
) -> IpeResult<E, CsvDoc> {
    let byte = match validated_delimiter::<E>(&delim) {
        IpeResult::Ok(b) => b,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    parse_delim(&text, byte)
}

/// Csv.encode : Csv -> String
pub fn csv_encode(doc: CsvDoc) -> String {
    encode_delim(&doc, b',')
}

/// Csv.encodeWithDelimiter : String -> Csv -> String
pub fn csv_encode_with_delimiter(delim: String, doc: CsvDoc) -> String {
    // Ipê's `encodeWithDelimiter` returns `String` (no Result), so on an
    // invalid delimiter we fall back to the standard comma rather than
    // silently taking a partial/wrong byte. This matches  behaviour
    // (a non-ASCII Comma degrades gracefully).
    let byte = match validated_delimiter::<String>(&delim) {
        IpeResult::Ok(b) => b,
        IpeResult::Err(_) => b',',
    };
    encode_delim(&doc, byte)
}

fn csv_parse_stream_from_file_sync(path: &str) -> Result<Vec<Vec<String>>, String> {
    // Stream rows from a BufReader<File> rather than slurping the whole file
    // into a String first — the csv reader pulls records incrementally, so a
    // large/untrusted file no longer forces a full-file in-memory copy.
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut rdr = ::csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(std::io::BufReader::new(file));
    // Row cap AND byte cap: although rows stream in, they all accumulate in
    // `out`, so an untrusted huge file is still an unbounded allocation — whether
    // by row COUNT or by decoded BYTES (a single monster record / oversized
    // fields slips under any row count). Bound both (IPE_CSV_MAX_ROWS default 10M,
    // IPE_CSV_MAX_BYTES default 512 MiB) → Err rather than OOM.
    let max_rows = csv_max_rows();
    let max_bytes = csv_max_bytes();
    let mut seen_bytes: u64 = 0;
    let mut out = Vec::new();
    for rec in rdr.records() {
        let r = rec.map_err(|e| e.to_string())?;
        if out.len() >= max_rows {
            return Err(format!(
                "exceeds row cap of {} (raise IPE_CSV_MAX_ROWS)",
                max_rows
            ));
        }
        accrue_record_bytes(&mut seen_bytes, &r, max_bytes)?;
        out.push(r.iter().map(|s| s.to_string()).collect());
    }
    Ok(out)
}

/// Csv.parseStreamFromFile : Path -> Task Error (List (List String))
/// Returns every row (including the header).
///
/// The `Path` argument carries the NUL-byte and `..`-traversal guards
/// enforced at construction by `Path.fromString`; the validated string is
/// extracted once before the async move.
///
/// file I/O + incremental CSV parsing (bounded by `IPE_CSV_MAX_ROWS` AND
/// `IPE_CSV_MAX_BYTES`) is offloaded to tokio's blocking pool via `run_blocking`
/// — see the module-level doc comment on `run_blocking` above.
pub fn csv_parse_stream_from_file<E: From<String> + Send + 'static>(
    path: crate::path::Path,
) -> IpeTask<E, Vec<Vec<String>>> {
    let path = path.into_string();
    Box::pin(async move {
        match run_blocking(move || csv_parse_stream_from_file_sync(&path)).await {
            Ok(v) => ok_res(v),
            Err(e) => IpeResult::Err(format!("Csv.parseStreamFromFile: {}", e).into()),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formula_guard_is_opt_in() {
        let doc = CsvDoc {
            header: vec!["a".into()],
            rows: vec![vec!["=SUM(A1)".into()]],
        };
        // Default OFF: lossless (formula cell emitted verbatim, just CSV-quoted).
        crate::system::locked_remove_var("IPE_CSV_SANITIZE_FORMULAS");
        assert!(encode_delim(&doc, b',').contains("=SUM(A1)"));
        // ON: dangerous-leading cell is prefixed with a single quote.
        crate::system::locked_set_var("IPE_CSV_SANITIZE_FORMULAS", "1");
        assert!(encode_delim(&doc, b',').contains("'=SUM(A1)"));
        crate::system::locked_remove_var("IPE_CSV_SANITIZE_FORMULAS");
    }

    /// Bounded by construction (PRINCIPLES §3): a CSV whose decoded field bytes
    /// exceed `IPE_CSV_MAX_BYTES` is turned back with a typed `Err` — a single
    /// huge record (one row, many bytes) that slips UNDER the row cap still
    /// cannot exhaust the heap. The reject fires at the byte bound, not on OOM.
    #[test]
    fn parse_respects_byte_cap_on_a_single_huge_record() {
        // One data row whose single field is 1000 bytes — far under any row cap,
        // but over a deliberately tiny byte cap.
        let big_field = "x".repeat(1000);
        let text = format!("h\n{big_field}\n");
        crate::system::locked_set_var("IPE_CSV_MAX_BYTES", "100");
        let res: IpeResult<String, CsvDoc> = csv_parse(text);
        crate::system::locked_remove_var("IPE_CSV_MAX_BYTES");
        assert!(
            matches!(res, IpeResult::Err(_)),
            "a record past the byte cap must Err, not accumulate unboundedly"
        );
    }

    /// A CSV within the byte cap still parses cleanly — the ceiling rejects only
    /// the over-large input, never a legitimate document.
    #[test]
    fn parse_under_byte_cap_still_succeeds() {
        crate::system::locked_set_var("IPE_CSV_MAX_BYTES", "100");
        let res: IpeResult<String, CsvDoc> = csv_parse("a,b\n1,2\n3,4".to_string());
        crate::system::locked_remove_var("IPE_CSV_MAX_BYTES");
        assert!(matches!(res, IpeResult::Ok(_)));
    }

    #[test]
    fn parse_then_encode_roundtrip() {
        let doc: IpeResult<String, CsvDoc> = csv_parse("a,b\n1,2\n3,4".to_string());
        let d = match doc {
            IpeResult::Ok(d) => d,
            _ => panic!("parse failed"),
        };
        assert_eq!(d.header, vec!["a", "b"]);
        assert_eq!(d.rows, vec![vec!["1", "2"], vec!["3", "4"]]);
        let out = csv_encode(d);
        assert_eq!(out, "a,b\n1,2\n3,4\n");
    }

    #[test]
    fn quoting() {
        let doc = CsvDoc {
            header: vec!["x".into()],
            rows: vec![vec!["a,b".into()]],
        };
        assert_eq!(csv_encode(doc), "x\n\"a,b\"\n");
    }

    fn block<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    /// Seal a test fixture path through the runtime's one constructor.
    pub fn make_path(s: &str) -> crate::path::Path {
        let sealed: Result<_, crate::IpeError> = match crate::path::path_from_string(s.to_string())
        {
            IpeResult::Ok(p) => Ok(p),
            IpeResult::Err(e) => Err(e),
        };
        #[allow(clippy::expect_used)] // fixture paths are absolute temp paths the seal accepts
        sealed.expect("test fixture path passes the seal")
    }

    /// Functional correctness (independent of whether `run_blocking` takes
    /// the real `spawn_blocking` path or the no-tokio-feature fallback —
    /// both paths must return the same rows).
    #[test]
    fn parse_stream_from_file_reads_all_rows() {
        let p = crate::scratch_core::test_temp_root()
            .join(format!("ipe_csv_stream_{}.csv", std::process::id()));
        std::fs::write(&p, "a,b\n1,2\n3,4\n").unwrap();
        let res: IpeResult<String, Vec<Vec<String>>> =
            block(csv_parse_stream_from_file(make_path(&p.to_string_lossy())));
        let _ = std::fs::remove_file(&p);
        match res {
            IpeResult::Ok(rows) => {
                assert_eq!(
                    rows,
                    vec![
                        vec!["a".to_string(), "b".to_string()],
                        vec!["1".to_string(), "2".to_string()],
                        vec!["3".to_string(), "4".to_string()],
                    ]
                );
            }
            IpeResult::Err(e) => panic!("unexpected Err: {e}"),
        }
    }

    #[test]
    fn parse_stream_from_file_missing_file_errs() {
        let res: IpeResult<String, Vec<Vec<String>>> = block(csv_parse_stream_from_file(
            make_path("/nonexistent/ipe/csv/path/does-not-exist.csv"),
        ));
        assert!(matches!(res, IpeResult::Err(_)));
    }

    #[test]
    fn parse_stream_from_file_respects_row_cap() {
        let p = crate::scratch_core::test_temp_root()
            .join(format!("ipe_csv_stream_cap_{}.csv", std::process::id()));
        std::fs::write(&p, "a\n1\n2\n3\n4\n5\n").unwrap();
        crate::system::locked_set_var("IPE_CSV_MAX_ROWS", "2");
        let res: IpeResult<String, Vec<Vec<String>>> =
            block(csv_parse_stream_from_file(make_path(&p.to_string_lossy())));
        crate::system::locked_remove_var("IPE_CSV_MAX_ROWS");
        let _ = std::fs::remove_file(&p);
        assert!(
            matches!(res, IpeResult::Err(_)),
            "6-row file under a 2-row cap must Err"
        );
    }

    /// Bounded by construction (PRINCIPLES §3): the streaming file path caps
    /// decoded bytes too, so a file of oversized records that stays UNDER the row
    /// cap still cannot exhaust the heap — it `Err`s at the byte bound.
    #[test]
    fn parse_stream_from_file_respects_byte_cap() {
        let p = crate::scratch_core::test_temp_root()
            .join(format!("ipe_csv_stream_bytes_{}.csv", std::process::id()));
        // 3 rows, each field 1000 bytes — well under any row cap, over a tiny byte cap.
        let big = "y".repeat(1000);
        std::fs::write(&p, format!("{big}\n{big}\n{big}\n")).unwrap();
        crate::system::locked_set_var("IPE_CSV_MAX_BYTES", "100");
        let res: IpeResult<String, Vec<Vec<String>>> =
            block(csv_parse_stream_from_file(make_path(&p.to_string_lossy())));
        crate::system::locked_remove_var("IPE_CSV_MAX_BYTES");
        let _ = std::fs::remove_file(&p);
        assert!(
            matches!(res, IpeResult::Err(_)),
            "a file past the byte cap must Err, not accumulate unboundedly"
        );
    }
}

#[cfg(all(test, feature = "tokio"))]
mod stream_from_file_spawn_blocking_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Reactor-starvation guard: on a SINGLE-WORKER (current_thread) runtime, the
    /// blocking file read + CSV parse inside `csv_parse_stream_from_file`
    /// would starve every other task on that runtime until it completes
    /// (worse still, pre-fix this work ran EAGERLY before the returned
    /// future was even polled — see the module-level doc comment on
    /// `run_blocking` above). This proves the work is offloaded to tokio's
    /// blocking-thread pool: a concurrently-spawned cheap ticker task must
    /// make progress (ticks > 0) WHILE the parse is in flight.
    ///
    /// Pre-fix this is NOT a flaky race: the ticker makes EXACTLY zero
    /// progress deterministically, because the worker thread never yields
    /// back to the executor until the parse completes.
    #[test]
    fn csv_parse_stream_from_file_does_not_starve_concurrent_async_work() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let p = crate::scratch_core::test_temp_root().join(format!(
            "ipe_csv_spawn_blocking_probe_{}.csv",
            std::process::id()
        ));
        // A large CSV file so the read + parse takes measurable wall time.
        {
            let mut content = String::from("a,b\n");
            for i in 0..500_000 {
                content.push_str(&format!("{},{}\n", i, i * 2));
            }
            std::fs::write(&p, content).unwrap();
        }
        let path = super::tests::make_path(&p.to_string_lossy());

        let ticks = rt.block_on(async move {
            let counter = Arc::new(AtomicU64::new(0));
            let counter2 = counter.clone();
            let ticker = tokio::spawn(async move {
                loop {
                    counter2.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            });
            let parse_fut: IpeTask<String, Vec<Vec<String>>> = csv_parse_stream_from_file(path);
            let _res: IpeResult<String, Vec<Vec<String>>> = parse_fut.await;
            ticker.abort();
            counter.load(Ordering::Relaxed)
        });

        let _ = std::fs::remove_file(&p);

        assert!(
            ticks > 0,
            "concurrent ticker task made ZERO progress while csv_parse_stream_from_file ran — \
             the blocking read+parse is starving the single-threaded executor \
             (spawn_blocking missing or not taking effect)"
        );
    }
}
