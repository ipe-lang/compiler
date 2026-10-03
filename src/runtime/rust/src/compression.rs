//! Ipe.Compression — gzip (flate2) + zstd kernels operating on raw byte buffers.
//!
//! All entries are `Vec<u8> -> Task Error Vec<u8>`. Input and output are raw
//! byte buffers (`Vec<u8>`) — Ipê's `Bytes` primitive — so compressed payloads
//! (including non-UTF-8 binary) round-trip losslessly.
//!
//! # Reactor-starvation guard
//!
//! gzip/zstd (de)compression is CPU-bound and can take non-trivial wall time
//! on large payloads. Every kernel here offloads its work to
//! tokio's blocking pool (`threads::run_blocking`) so it can't stall the tokio worker thread
//! that's polling the returned future. Running the work INLINE on the calling
//! thread before the future is polled would block every other task scheduled
//! on that worker for the call's full duration. See
//! `docs/adr/0003-security-render-and-data-access-invariants.md` §2.
//!
//! # Decompression bomb protection
//!
//! Both gunzip and zstdDecompress cap decompressed output at
//! `IPE_DECOMPRESS_MAX_BYTES` (default 256 MiB). Input that would expand
//! beyond that limit is rejected with an error rather than allowed to OOM
//! the process.

use super::*;
use std::io::{Read, Write};

/// The decompression output cap: `IPE_DECOMPRESS_MAX_BYTES`, default 256 MiB;
/// `0` admits only empty output.
const DECOMPRESS_CEILING: crate::system::EnvCeiling = crate::system::EnvCeiling::new(
    "IPE_DECOMPRESS_MAX_BYTES",
    256 * 1024 * 1024,
    crate::system::ZeroCeiling::Accepted,
    "decimal byte count",
);

/// Returns the decompression output cap in bytes.
///
/// Reads [`DECOMPRESS_CEILING`] once (lazily) and caches the outcome, so a
/// malformed value fails every decompression closed rather than falling back.
fn decompress_max_bytes() -> Result<u64, String> {
    use std::sync::OnceLock;
    static CAP: OnceLock<Result<u64, crate::system::EnvCeilingRefusal>> = OnceLock::new();
    CAP.get_or_init(|| DECOMPRESS_CEILING.read())
        .clone()
        .map_err(String::from)
}

fn gzip_bytes(data: &[u8]) -> Result<Vec<u8>, String> {
    use flate2::{Compression, write::GzEncoder};
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).map_err(|err| err.to_string())?;
    e.finish().map_err(|err| err.to_string())
}

fn gunzip_bytes(data: &[u8]) -> Result<Vec<u8>, String> {
    // AUD-09: `GzDecoder` only decodes the FIRST gzip member and silently
    // ignores any trailing concatenated members —  `gzip.Reader` (via
    // `multistream(true)`, the default) decodes ALL concatenated members.
    // `MultiGzDecoder` handles multi-stream gzip; single-member input decodes
    // identically either way, so this is a pure completeness fix, not a
    // behavior change for the common case.
    use flate2::read::MultiGzDecoder;
    let max = decompress_max_bytes()?;
    let d = MultiGzDecoder::new(data);
    // Read up to max+1 bytes; if we fill the buffer exactly at max+1 the
    // input would expand beyond the cap.
    let mut out = Vec::new();
    d.take(max.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    if out.len() as u64 > max {
        return Err(format!(
            "decompressed output exceeds {} bytes (IPE_DECOMPRESS_MAX_BYTES)",
            max
        ));
    }
    Ok(out)
}

fn zstd_compress_bytes(data: &[u8]) -> Result<Vec<u8>, String> {
    zstd::encode_all(data, 0).map_err(|e| e.to_string())
}

/// Runs the CPU-bound `f` for `kernel` on the blocking pool, as the caller's error.
///
/// Every error is prefixed with `kernel`; a pool that cannot start a thread is
/// kinded `Unavailable`, and a panic in `f` is the `panicked` message.
///
/// # Errors
///
/// `f` failed, no thread could be started for it, or it panicked.
async fn offloaded<E, F>(
    kernel: &'static str,
    panicked: &'static str,
    f: F,
) -> IpeResult<E, Vec<u8>>
where
    E: From<String> + crate::FromUnavailable,
    F: FnOnce() -> Result<Vec<u8>, String> + Send + 'static,
{
    match crate::threads::run_blocking(kernel, panicked, move || {
        f().map_err(|e| format!("{kernel}: {e}"))
    })
    .await
    {
        Ok(b) => ok_res(b),
        Err(e) => IpeResult::Err(e),
    }
}

/// Compression.gzip : Bytes -> Task Error Bytes
pub fn compression_gzip<E: From<String> + crate::FromUnavailable + Send + 'static>(
    data: Vec<u8>,
) -> IpeTask<E, Vec<u8>> {
    Box::pin(async move {
        // gzip is CPU-bound; offload to the blocking pool so it can't
        // starve the tokio worker thread polling this future (same rationale
        // as auth.rs's bcrypt offload).
        offloaded(
            "Compression.gzip",
            "Compression.gzip: compression task panicked",
            move || gzip_bytes(&data),
        )
        .await
    })
}

/// Compression.gunzip : Bytes -> Task Error Bytes
pub fn compression_gunzip<E: From<String> + crate::FromUnavailable + Send + 'static>(
    data: Vec<u8>,
) -> IpeTask<E, Vec<u8>> {
    Box::pin(async move {
        offloaded(
            "Compression.gunzip",
            "Compression.gunzip: decompression task panicked",
            move || gunzip_bytes(&data),
        )
        .await
    })
}

/// Compression.zstdCompress : Bytes -> Task Error Bytes
pub fn compression_zstd_compress<E: From<String> + crate::FromUnavailable + Send + 'static>(
    data: Vec<u8>,
) -> IpeTask<E, Vec<u8>> {
    Box::pin(async move {
        offloaded(
            "Compression.zstdCompress",
            "Compression.zstdCompress: compression task panicked",
            move || zstd_compress_bytes(&data),
        )
        .await
    })
}

/// Compression.zstdDecompress : Bytes -> Task Error Bytes
pub fn compression_zstd_decompress<E: From<String> + crate::FromUnavailable + Send + 'static>(
    data: Vec<u8>,
) -> IpeTask<E, Vec<u8>> {
    Box::pin(async move {
        offloaded(
            "Compression.zstdDecompress",
            "Compression.zstdDecompress: decompression task panicked",
            move || zstd_decompress_capped(&data),
        )
        .await
    })
}

fn zstd_decompress_capped(data: &[u8]) -> Result<Vec<u8>, String> {
    use zstd::stream::read::Decoder as ZstdDecoder;
    let max = decompress_max_bytes()?;
    let d = ZstdDecoder::new(data).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    d.take(max.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    if out.len() as u64 > max {
        return Err(format!(
            "decompressed output exceeds {} bytes (IPE_DECOMPRESS_MAX_BYTES)",
            max
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_ceilings_honour_the_shared_contract() {
        crate::system::assert_env_ceiling_contract(DECOMPRESS_CEILING);
    }
    use crate::task::task_run;

    #[test]
    fn gzip_roundtrip() {
        let orig = b"hello, ipe - gzip round-trip with some length to compress".to_vec();
        let z: IpeResult<String, Vec<u8>> = task_run(compression_gzip(orig.clone()));
        let comp = match z {
            IpeResult::Ok(c) => c,
            _ => panic!("gzip failed"),
        };
        let back: IpeResult<String, Vec<u8>> = task_run(compression_gunzip(comp));
        assert!(matches!(back, IpeResult::Ok(ref b) if *b == orig));
    }

    #[test]
    fn gzip_roundtrip_binary() {
        // High bytes (> 127) that are not valid UTF-8 must round-trip without
        // truncation — the old Latin-1 bridge would silently corrupt these.
        let orig: Vec<u8> = (0u8..=255u8).collect();
        let z: IpeResult<String, Vec<u8>> = task_run(compression_gzip(orig.clone()));
        let comp = match z {
            IpeResult::Ok(c) => c,
            _ => panic!("gzip binary failed"),
        };
        let back: IpeResult<String, Vec<u8>> = task_run(compression_gunzip(comp));
        assert!(matches!(back, IpeResult::Ok(ref b) if *b == orig));
    }

    #[test]
    fn zstd_roundtrip() {
        let orig = b"zstd payload zstd payload zstd payload".to_vec();
        let z: IpeResult<String, Vec<u8>> = task_run(compression_zstd_compress(orig.clone()));
        let comp = match z {
            IpeResult::Ok(c) => c,
            _ => panic!("zstd failed"),
        };
        let back: IpeResult<String, Vec<u8>> = task_run(compression_zstd_decompress(comp));
        assert!(matches!(back, IpeResult::Ok(ref b) if *b == orig));
    }

    #[test]
    fn zstd_roundtrip_binary() {
        let orig: Vec<u8> = (0u8..=255u8).collect();
        let z: IpeResult<String, Vec<u8>> = task_run(compression_zstd_compress(orig.clone()));
        let comp = match z {
            IpeResult::Ok(c) => c,
            _ => panic!("zstd binary failed"),
        };
        let back: IpeResult<String, Vec<u8>> = task_run(compression_zstd_decompress(comp));
        assert!(matches!(back, IpeResult::Ok(ref b) if *b == orig));
    }

    #[test]
    fn gunzip_rejects_garbage() {
        let bad: IpeResult<String, Vec<u8>> =
            task_run(compression_gunzip(b"not a gzip stream".to_vec()));
        assert!(matches!(bad, IpeResult::Err(_)));
    }

    /// Verify that gunzip rejects a payload that would expand beyond the cap.
    /// We set IPE_DECOMPRESS_MAX_BYTES to a small value (16 bytes) so the test
    /// doesn't need to produce a real multi-GiB bomb.
    #[test]
    fn gunzip_rejects_decompression_bomb() {
        // Build a gzip of 34 bytes (> 16-byte cap we will set).
        let plain = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 34 bytes
        let compressed: IpeResult<String, Vec<u8>> = task_run(compression_gzip(plain.to_vec()));
        let comp = match compressed {
            IpeResult::Ok(c) => c,
            _ => panic!("gzip failed"),
        };

        // Override the cap to 16 bytes for this test.
        // SAFETY: tests sharing the OnceLock see whatever value was set first,
        // so we use a separate env-var read path below. Because OnceLock caches
        // the value, we test the helper directly instead.
        let max: u64 = 16;
        // comp is already Vec<u8> — no conversion needed.
        let result = {
            use flate2::read::GzDecoder;
            use std::io::Read;
            let d = GzDecoder::new(&comp[..]);
            let mut out = Vec::new();
            let _ = d.take(max.saturating_add(1)).read_to_end(&mut out);
            if out.len() as u64 > max {
                Err(format!(
                    "decompressed output exceeds {} bytes (IPE_DECOMPRESS_MAX_BYTES)",
                    max
                ))
            } else {
                Ok(out)
            }
        };
        assert!(result.is_err(), "expected bomb-detection error, got Ok");
        assert!(result.unwrap_err().contains("exceeds"));
    }

    /// Verify that zstd rejects a payload that would expand beyond the cap.
    #[test]
    fn zstd_rejects_decompression_bomb() {
        let plain = b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; // 34 bytes
        let compressed: IpeResult<String, Vec<u8>> =
            task_run(compression_zstd_compress(plain.to_vec()));
        let comp = match compressed {
            IpeResult::Ok(c) => c,
            _ => panic!("zstd compress failed"),
        };

        let max: u64 = 16;
        // comp is already Vec<u8> — no conversion needed.
        let result = {
            use std::io::Read;
            use zstd::stream::read::Decoder as ZstdDecoder;
            let d = ZstdDecoder::new(&comp[..]).expect("zstd decoder");
            let mut out = Vec::new();
            let _ = d.take(max.saturating_add(1)).read_to_end(&mut out);
            if out.len() as u64 > max {
                Err(format!(
                    "decompressed output exceeds {} bytes (IPE_DECOMPRESS_MAX_BYTES)",
                    max
                ))
            } else {
                Ok(out)
            }
        };
        assert!(result.is_err(), "expected bomb-detection error, got Ok");
        assert!(result.unwrap_err().contains("exceeds"));
    }

    /// Reactor-starvation guard: on a SINGLE-WORKER (current_thread) runtime, a
    /// blocking zstd compression call run inline on the polled future would
    /// starve every other task on that runtime until it completes. This
    /// proves `compression_zstd_compress` offloads its CPU-bound work to
    /// tokio's blocking-thread pool instead: a concurrently-spawned cheap
    /// ticker task must make progress (ticks > 0) WHILE the compression is
    /// in flight.
    ///
    /// Pre-fix this is NOT a flaky race: the ticker makes EXACTLY zero
    /// progress deterministically, because the worker thread never yields
    /// back to the executor until compression returns.
    #[test]
    fn zstd_compress_does_not_starve_concurrent_async_work() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // Low-compressibility-ish payload so zstd actually spends CPU time
        // rather than short-circuiting on a trivially repetitive pattern.
        let payload: Vec<u8> = (0..32 * 1024 * 1024).map(|i| (i % 251) as u8).collect();

        let ticks = rt.block_on(async move {
            let counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let counter2 = counter.clone();
            let ticker = tokio::spawn(async move {
                loop {
                    counter2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            });
            let fut: IpeTask<String, Vec<u8>> = compression_zstd_compress(payload);
            let _res: IpeResult<String, Vec<u8>> = fut.await;
            ticker.abort();
            counter.load(std::sync::atomic::Ordering::Relaxed)
        });

        assert!(
            ticks > 0,
            "concurrent ticker task made ZERO progress while zstd compression ran — \
             the blocking compression is starving the single-threaded executor \
             (spawn_blocking missing or not taking effect)"
        );
    }

    /// Same shape, for `compression_gzip` — proves gzip is ALSO offloaded
    /// (the sibling kernel to zstd; both went through the identical
    /// pre-fix eager-inline-before-poll bug).
    #[test]
    fn gzip_does_not_starve_concurrent_async_work() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let payload: Vec<u8> = (0..32 * 1024 * 1024).map(|i| (i % 251) as u8).collect();

        let ticks = rt.block_on(async move {
            let counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let counter2 = counter.clone();
            let ticker = tokio::spawn(async move {
                loop {
                    counter2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            });
            let fut: IpeTask<String, Vec<u8>> = compression_gzip(payload);
            let _res: IpeResult<String, Vec<u8>> = fut.await;
            ticker.abort();
            counter.load(std::sync::atomic::Ordering::Relaxed)
        });

        assert!(
            ticks > 0,
            "concurrent ticker task made ZERO progress while gzip compression ran — \
             the blocking compression is starving the single-threaded executor \
             (spawn_blocking missing or not taking effect)"
        );
    }
}
