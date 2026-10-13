#![allow(clippy::type_complexity)]
// Ipe.Config — typed TOML / YAML / JSON config decoders.
//
// Config reuses the JSON Decoder representation (`Decoder<E, T>` over a
// `serde_json::Value`): TOML and YAML are parsed into the same `Value`, then the
// decoder runs unchanged. The combinators (string / int / float / bool / field /
// at / list / map / andThen / succeed / fail) ARE the shared `decode_*` kernels — the
// Ipê codegen maps `Config.*` straight onto them. Only the format front-ends,
// `nullable`, and `loadFromFile` live here, because Config's signatures put the
// source `String` FIRST (`decodeToml : String -> Decoder a -> Result Error a`),
// the opposite of `decode_from_json_string`'s decoder-first argument order.
use super::json::{Decoder, JsonVal};
use super::*;

// Config.nullable : Decoder a -> Decoder (Maybe a)
// The Config surface reuses the one shared nullable builder in `json` — the
// combinator is JSON-shaped (null => Nothing, else Just, inner error
// propagated) and lives once, in the always-available `json` module, so
// JsonDec / Config / Db.Decode share a single implementation.
pub fn config_nullable<E: From<String> + 'static, T: 'static + Send>(
    decoder: Decoder<E, T>,
) -> Decoder<E, IpeMaybe<T>> {
    super::json::decode_nullable(decoder)
}

// Config.maybe : Decoder a -> Decoder (Maybe a)
// Unlike `nullable` (which only tolerates null/missing), `maybe` catches ANY
// decode failure: `Just` on success, `Nothing` on any error. Never fails.
pub fn config_maybe<E: From<String> + 'static, T: 'static + Send>(
    decoder: Decoder<E, T>,
) -> Decoder<E, IpeMaybe<T>> {
    let inner_fields = decoder.fields.clone();
    Decoder::new(
        Box::new(move |v| match (decoder.run)(v) {
            IpeResult::Ok(t) => IpeResult::Ok(IpeMaybe::Just(t)),
            IpeResult::Err(_) => IpeResult::Ok(IpeMaybe::Nothing),
        }),
        inner_fields,
    )
}

// Config.dict : Decoder a -> Decoder (Dict String a)
// Decode every object entry into a `Dict String a` (runtime `IpeDict<T>`),
// applying `decoder` to each value. Non-object input is `Err`; the first entry
// whose value fails short-circuits with its real error.
pub fn config_dict<E: From<String> + 'static, T: 'static + Send>(
    decoder: Decoder<E, T>,
) -> Decoder<E, IpeDict<T>> {
    Decoder::new(
        Box::new(move |v| match v.as_object() {
            Some(obj) => {
                let d = &decoder;
                let mut out: IpeDict<T> = IpeDict::new();
                for (key, val) in obj {
                    match (d.run)(val) {
                        IpeResult::Ok(t) => {
                            out.insert(key.clone(), t);
                        }
                        IpeResult::Err(e) => return IpeResult::Err(e),
                    }
                }
                IpeResult::Ok(out)
            }
            None => IpeResult::Err(str_err("expected object")),
        }),
        vec![],
    )
}

fn run_decoder<E: From<String> + 'static, T>(
    parsed: Result<JsonVal, String>,
    decoder: Decoder<E, T>,
) -> IpeResult<E, T> {
    match parsed {
        Ok(v) => (decoder.run)(&v),
        Err(e) => IpeResult::Err(str_err(&e)),
    }
}

// Config.decodeJson : String -> Decoder a -> Result Error a
pub fn config_decode_json<E: From<String> + 'static, T>(
    s: String,
    decoder: Decoder<E, T>,
) -> IpeResult<E, T> {
    run_decoder(
        serde_json::from_str(&s).map_err(|e| format!("json parse: {}", e)),
        decoder,
    )
}

// Config.decodeToml : String -> Decoder a -> Result Error a
pub fn config_decode_toml<E: From<String> + 'static, T>(
    s: String,
    decoder: Decoder<E, T>,
) -> IpeResult<E, T> {
    run_decoder(
        toml::from_str(&s).map_err(|e| format!("toml parse: {}", e)),
        decoder,
    )
}

/// Default cap on a YAML source string parsed directly via `Config.decodeYaml`
/// (the file-load path enforces its own `IPE_CONFIG_MAX_BYTES` cap before reading).
/// 4 MiB; override via `IPE_YAML_MAX_BYTES`.
const YAML_SOURCE_CEILING: crate::system::EnvCeiling = crate::system::EnvCeiling::new(
    "IPE_YAML_MAX_BYTES",
    4 * 1024 * 1024,
    crate::system::ZeroCeiling::Refused,
    "decimal byte count",
);

/// Cap on a file read by `Config.loadFromFile`: `IPE_CONFIG_MAX_BYTES`, default 16 MiB.
const CONFIG_FILE_CEILING: crate::system::EnvCeiling = crate::system::EnvCeiling::new(
    "IPE_CONFIG_MAX_BYTES",
    16 * 1024 * 1024,
    crate::system::ZeroCeiling::Refused,
    "decimal byte count",
);

// Config.decodeYaml : String -> Decoder a -> Result Error a
pub fn config_decode_yaml<E: From<String> + FromLimitExceeded + 'static, T>(
    s: String,
    decoder: Decoder<E, T>,
) -> IpeResult<E, T> {
    // Defence-in-depth against YAML "billion laughs" / anchor-alias bombs:
    //   1. Bound the SOURCE size so a huge input can't be parsed at all (this is
    //      the cheap, behaviour-preserving guard the audit asks for).
    //   2. serde_yaml 0.9 itself bounds alias/anchor EXPANSION — a recursive
    //      anchor bomb trips its built-in "repetition limit exceeded" (verified),
    //      so a small-but-exponential input cannot expand without bound.
    let cap: usize = match YAML_SOURCE_CEILING.read() {
        Ok(cap) => cap,
        Err(refusal) => return IpeResult::Err(str_err(&format!("yaml parse: {refusal}"))),
    };
    if s.len() > cap {
        return IpeResult::Err(
            LimitRefusal::new(format!(
                "yaml parse: input is {} bytes, over the {} byte cap (IPE_YAML_MAX_BYTES)",
                s.len(),
                cap
            ))
            .into_error(),
        );
    }
    run_decoder(
        serde_yaml::from_str(&s).map_err(|e| format!("yaml parse: {}", e)),
        decoder,
    )
}

// ── shared blocking-pool helper ───────────────────────────────────────
//
// `config_load_from_file` does a blocking `std::fs::File::open` + capped
// `read_to_string` (up to `IPE_CONFIG_MAX_BYTES`, default 16 MiB) inline.
// Offload it to tokio's blocking pool so a large/slow-filesystem config read
// can't stall the tokio worker thread polling this future. This module is
// gated on the `config` Cargo feature (`config = ["json", "toml",
// "serde_yaml"]`, runtime/Cargo.toml), which does NOT pull in `tokio`, so
// `tokio` is not guaranteed present here (see
// `docs/adr/0003-security-render-and-data-access-invariants.md` §2.2).
// The offload is `threads::join_blocking`: a pool that cannot start a thread is
// an `Unavailable` error, and a build without the pool reads inline.

fn config_read_capped(path: &str, cap: u64) -> Result<String, KernelFailure> {
    // Open first, then enforce the cap THROUGH a capped reader rather than
    // trusting a metadata-only precheck: std::fs::metadata reports len()==0
    // for non-regular files (FIFO, /dev/zero, char devices), so a metadata
    // gate would pass and the subsequent slurp would read unbounded bytes.
    // Reject non-regular files outright, then bound the read at cap+1 bytes.
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| format!("{}", e))?;
    let meta = file.metadata().map_err(|e| format!("{}", e))?;
    if !meta.file_type().is_file() {
        return Err(format!("config file {:?} is not a regular file", path).into());
    }
    if meta.len() > cap {
        return Err(LimitRefusal::new(format!(
            "config file {:?} is {} bytes, over the {} byte cap (IPE_CONFIG_MAX_BYTES)",
            path,
            meta.len(),
            cap
        ))
        .into());
    }
    let mut contents = String::new();
    // take(cap+1): if the file grew between the metadata check and the read,
    // or reports a misleading size, the read still can't exceed cap+1 bytes.
    file.take(cap.saturating_add(1))
        .read_to_string(&mut contents)
        .map_err(|e| format!("{}", e))?;
    if contents.len() as u64 > cap {
        return Err(LimitRefusal::new(format!(
            "config file {:?} exceeds the {} byte cap (IPE_CONFIG_MAX_BYTES)",
            path, cap
        ))
        .into());
    }
    Ok(contents)
}

// Config.loadFromFile : String -> Decoder a -> Task Error a
// Extension dispatch: .toml / .yaml|.yml / .json (default json).
//
// the file read is offloaded via `threads::join_blocking` (see the module-level
// comment above) so a large/slow config read can't stall the tokio
// worker thread. The decode dispatch itself runs back on the calling task
// after the read completes — decoding an already-in-memory, size-capped
// (≤16 MiB default) string is fast enough not to warrant its own offload.
pub fn config_load_from_file<
    E: From<String> + FromLimitExceeded + crate::FromUnavailable + Send + 'static,
    T: Send + 'static,
>(
    path: crate::path::Path,
    decoder: Decoder<E, T>,
) -> IpeTask<E, T> {
    // `Path` is already NUL-byte- and `..`-traversal-checked by construction;
    // extract the validated string once and use it for both the I/O and the
    // extension dispatch below.
    let path = path.into_string();
    Box::pin(async move {
        // Cap the file size before slurping it into memory so a Config.loadFromFile
        // on an attacker-influenced path can't force an unbounded in-memory copy
        // (memory DoS). Default 16 MiB; override via IPE_CONFIG_MAX_BYTES.
        let cap: u64 = match CONFIG_FILE_CEILING.read() {
            Ok(cap) => cap,
            Err(refusal) => return IpeResult::Err(str_err(&refusal.to_string())),
        };
        let contents = match crate::threads::join_blocking("Config.loadFromFile", {
            let path = path.clone();
            move || config_read_capped(&path, cap)
        })
        .await
        {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => return IpeResult::Err(e.into_error()),
            Err(failure) => {
                return IpeResult::Err(failure.into_error("background config-file task panicked"));
            }
        };
        let lower = path.to_ascii_lowercase();
        if lower.ends_with(".toml") {
            config_decode_toml(contents, decoder)
        } else if lower.ends_with(".yaml") || lower.ends_with(".yml") {
            config_decode_yaml(contents, decoder)
        } else {
            config_decode_json(contents, decoder)
        }
    })
}

#[cfg(test)]
mod load_from_file_tests {
    use super::*;

    #[test]
    fn env_ceilings_honour_the_shared_contract() {
        crate::system::assert_env_ceiling_contract(YAML_SOURCE_CEILING);
        crate::system::assert_env_ceiling_contract(CONFIG_FILE_CEILING);
    }
    use crate::json::{decode_field, json_decode_string};

    fn block<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    fn name_decoder() -> Decoder<String, String> {
        decode_field("name".to_string(), json_decode_string::<String>())
    }

    fn kinded_name_decoder() -> Decoder<crate::IpeError, String> {
        decode_field("name".to_string(), json_decode_string::<crate::IpeError>())
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

    /// Functional correctness (independent of whether the offload takes
    /// the blocking pool or the no-tokio-feature inline fallback —
    /// both paths must return the same decoded result).
    #[test]
    fn loads_and_decodes_json() {
        let p = crate::scratch_core::test_temp_root()
            .join(format!("ipe_cfg_json_{}.json", std::process::id()));
        std::fs::write(&p, r#"{"name": "ipe"}"#).unwrap();
        let res: IpeResult<String, String> = block(config_load_from_file(
            make_path(&p.to_string_lossy()),
            name_decoder(),
        ));
        let _ = std::fs::remove_file(&p);
        match res {
            IpeResult::Ok(s) => assert_eq!(s, "ipe"),
            IpeResult::Err(e) => panic!("unexpected Err: {e}"),
        }
    }

    #[test]
    fn loads_and_decodes_toml() {
        let p = crate::scratch_core::test_temp_root()
            .join(format!("ipe_cfg_toml_{}.toml", std::process::id()));
        std::fs::write(&p, "name = \"ipe\"\n").unwrap();
        let res: IpeResult<String, String> = block(config_load_from_file(
            make_path(&p.to_string_lossy()),
            name_decoder(),
        ));
        let _ = std::fs::remove_file(&p);
        match res {
            IpeResult::Ok(s) => assert_eq!(s, "ipe"),
            IpeResult::Err(e) => panic!("unexpected Err: {e}"),
        }
    }

    #[test]
    fn over_cap_file_errs() {
        let p = crate::scratch_core::test_temp_root()
            .join(format!("ipe_cfg_over_cap_{}.json", std::process::id()));
        std::fs::write(&p, vec![b'a'; 8192]).unwrap();
        crate::system::locked_set_var("IPE_CONFIG_MAX_BYTES", "1024");
        let res: IpeResult<crate::IpeError, String> = block(config_load_from_file(
            make_path(&p.to_string_lossy()),
            kinded_name_decoder(),
        ));
        crate::system::locked_remove_var("IPE_CONFIG_MAX_BYTES");
        let _ = std::fs::remove_file(&p);
        assert!(
            matches!(&res, IpeResult::Err(crate::IpeError::Error(crate::IpeErrorKind::LimitExceeded, info))
                if info.message.ends_with("is 8192 bytes, over the 1024 byte cap (IPE_CONFIG_MAX_BYTES)")),
            "8 KiB config file under a 1 KiB cap must be a LimitExceeded refusal: {res:?}"
        );
    }

    /// A YAML source one byte over `IPE_YAML_MAX_BYTES` is a `LimitExceeded`
    /// refusal; a source at the cap parses.
    #[test]
    fn yaml_source_past_the_cap_is_limit_exceeded() {
        crate::system::locked_set_var("IPE_YAML_MAX_BYTES", "13");
        let at_cap: IpeResult<crate::IpeError, String> =
            config_decode_yaml("name: abcdefg".to_string(), kinded_name_decoder());
        let past: IpeResult<crate::IpeError, String> =
            config_decode_yaml("name: abcdefgh".to_string(), kinded_name_decoder());
        crate::system::locked_remove_var("IPE_YAML_MAX_BYTES");
        assert_eq!(at_cap, IpeResult::Ok("abcdefg".to_string()));
        assert_eq!(
            past,
            IpeResult::Err(crate::IpeError::limit_exceeded(
                "yaml parse: input is 14 bytes, over the 13 byte cap (IPE_YAML_MAX_BYTES)"
            ))
        );
    }

    #[test]
    fn missing_file_errs() {
        let res: IpeResult<String, String> = block(config_load_from_file(
            make_path("/nonexistent/ipe/config/path/does-not-exist.json"),
            name_decoder(),
        ));
        assert!(matches!(res, IpeResult::Err(_)));
    }
}

#[cfg(all(test, feature = "tokio"))]
mod load_from_file_spawn_blocking_tests {
    use super::*;
    use crate::json::{decode_field, json_decode_string};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Reactor-starvation guard: on a SINGLE-WORKER (current_thread) runtime, the
    /// blocking file read inside `config_load_from_file` would starve every
    /// other task on that runtime until the read completes. This proves the
    /// read is offloaded to tokio's blocking-thread pool: a concurrently-
    /// spawned cheap ticker task must make progress (ticks > 0) WHILE the
    /// read is in flight.
    ///
    /// Pre-fix this is NOT a flaky race: the ticker makes EXACTLY zero
    /// progress deterministically, because the worker thread never yields
    /// back to the executor until the read completes.
    #[test]
    fn config_load_from_file_does_not_starve_concurrent_async_work() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let p = crate::scratch_core::test_temp_root().join(format!(
            "ipe_cfg_spawn_blocking_probe_{}.json",
            std::process::id()
        ));
        // A big JSON string value, large enough that the read takes
        // measurable (not instant) wall time. Stays under the default 16 MiB
        // cap.
        let big = "x".repeat(12 * 1024 * 1024);
        std::fs::write(&p, format!(r#"{{"name": "{}"}}"#, big)).unwrap();
        let path = super::load_from_file_tests::make_path(&p.to_string_lossy());

        let ticks = rt.block_on(async move {
            let counter = Arc::new(AtomicU64::new(0));
            let counter2 = counter.clone();
            let ticker = tokio::spawn(async move {
                loop {
                    counter2.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            });
            let decoder =
                decode_field::<String, String>("name".to_string(), json_decode_string::<String>());
            let load_fut: IpeTask<String, String> = config_load_from_file(path, decoder);
            let _res: IpeResult<String, String> = load_fut.await;
            ticker.abort();
            counter.load(Ordering::Relaxed)
        });

        let _ = std::fs::remove_file(&p);

        assert!(
            ticks > 0,
            "concurrent ticker task made ZERO progress while config_load_from_file ran — \
             the blocking file read is starving the single-threaded executor \
             (spawn_blocking missing or not taking effect)"
        );
    }
}

#[cfg(test)]
mod yaml_tests {
    use super::*;
    use crate::json::decode_value_identity;
    use serde_json::json;

    fn yaml(src: &str) -> IpeResult<crate::IpeError, JsonVal> {
        config_decode_yaml(src.to_string(), decode_value_identity::<crate::IpeError>())
    }

    /// The `(kind, message)` of a refusal, or `None` when the source decoded.
    fn refusal(src: &str) -> Option<(crate::IpeErrorKind, String)> {
        match yaml(src) {
            IpeResult::Ok(_) => None,
            IpeResult::Err(crate::IpeError::Error(kind, info)) => Some((kind, info.message)),
        }
    }

    fn field(src: &str) -> JsonVal {
        let decoded = yaml(src);
        assert!(
            matches!(decoded, IpeResult::Ok(_)),
            "{src:?} must decode: {decoded:?}"
        );
        let IpeResult::Ok(value) = decoded else {
            return JsonVal::Null;
        };
        value.get("a").cloned().unwrap_or(JsonVal::Null)
    }

    fn nested_flow(depth: usize) -> String {
        format!("{}{}", "[".repeat(depth), "]".repeat(depth))
    }

    fn nested_block(depth: usize) -> String {
        let mut src = String::new();
        for level in 0..depth {
            src.push_str(&"  ".repeat(level));
            src.push_str("a:\n");
        }
        src.push_str(&"  ".repeat(depth));
        src.push_str("x\n");
        src
    }

    /// `levels` anchors, each a list of nine aliases of the one before.
    fn alias_bomb(levels: usize) -> String {
        let names = ["a", "b", "c", "d", "e", "f", "g", "h", "i"];
        let mut src = String::from("a: &a [x, x, x, x, x, x, x, x, x]\n");
        for pair in names.windows(2).take(levels.saturating_sub(1)) {
            let (prev, next) = (pair[0], pair[1]);
            let items = vec![format!("*{prev}"); 9].join(", ");
            src.push_str(&format!("{next}: &{next} [{items}]\n"));
        }
        src
    }

    #[test]
    fn yaml_11_booleans_stay_strings() {
        for word in ["yes", "no", "on", "off", "y", "n"] {
            assert_eq!(field(&format!("a: {word}")), json!(word), "{word}");
        }
    }

    #[test]
    fn core_booleans_decode() {
        for (word, value) in [
            ("true", true),
            ("True", true),
            ("TRUE", true),
            ("false", false),
            ("False", false),
            ("FALSE", false),
        ] {
            assert_eq!(field(&format!("a: {word}")), json!(value), "{word}");
        }
    }

    #[test]
    fn mixed_case_bool() {
        assert_eq!(field("a: tRuE"), json!("tRuE"));
    }

    #[test]
    fn nulls_decode() {
        for src in ["a: null", "a: Null", "a: NULL", "a: ~", "a:"] {
            assert_eq!(yaml(src), IpeResult::Ok(json!({"a": null})), "{src:?}");
        }
    }

    #[test]
    fn leading_zero_is_string() {
        assert_eq!(field("a: 012"), json!("012"));
    }

    #[test]
    fn prefixed_ints() {
        assert_eq!(field("a: 0x1F"), json!(31));
        assert_eq!(field("a: 0o17"), json!(15));
        assert_eq!(field("a: 0b11"), json!(3));
    }

    #[test]
    fn non_finite_floats_decode_as_null() {
        for word in [".nan", ".inf", "-.inf"] {
            assert_eq!(field(&format!("a: {word}")), JsonVal::Null, "{word}");
        }
    }

    #[test]
    fn duplicate_key_last_wins() {
        assert_eq!(yaml("a: 1\na: 2"), IpeResult::Ok(json!({"a": 2})));
    }

    #[test]
    fn merge_key_is_a_literal_key() {
        assert_eq!(
            yaml("base: &b {x: 1}\nm: {<<: *b}"),
            IpeResult::Ok(json!({"base": {"x": 1}, "m": {"<<": {"x": 1}}}))
        );
    }

    #[test]
    fn multi_document_refused() {
        assert!(refusal("--- a\n--- b").is_some());
        assert_eq!(yaml("--- a"), IpeResult::Ok(json!("a")));
    }

    #[test]
    fn local_tag_refused() {
        assert!(refusal("a: !foo x").is_some());
    }

    #[test]
    fn include_tag_refused() {
        assert!(refusal("a: !include /etc/passwd").is_some());
    }

    #[test]
    fn env_interpolation_literal() {
        assert_eq!(field("a: ${HOME}"), json!("${HOME}"));
    }

    #[test]
    fn core_tags() {
        assert_eq!(field("a: !!str 1"), json!("1"));
        assert_eq!(field("a: !!int \"1\""), json!(1));
    }

    #[test]
    fn empty_document() {
        for src in ["", "   \n\n"] {
            assert_eq!(yaml(src), IpeResult::Ok(JsonVal::Null), "{src:?}");
        }
    }

    #[test]
    fn alias_bomb_refused() {
        assert!(refusal(&alias_bomb(9)).is_some());
        assert!(matches!(yaml(&alias_bomb(2)), IpeResult::Ok(_)));
    }

    #[test]
    fn depth_at_ceiling_accepted() {
        assert!(matches!(yaml(&nested_flow(128)), IpeResult::Ok(_)));
        assert!(matches!(yaml(&nested_block(128)), IpeResult::Ok(_)));
    }

    #[test]
    fn depth_ceiling_plus_one_refused() {
        assert!(refusal(&nested_flow(129)).is_some());
        assert!(refusal(&nested_block(129)).is_some());
    }

    #[test]
    fn syntax_error_refused() {
        assert!(refusal("a: [1,").is_some());
    }
}
