#![allow(clippy::type_complexity)]
// Ipe.Config — typed TOML / YAML / JSON config decoders.
//
// Config reuses the JSON Decoder representation (`Decoder<E, T>` over a
// `JsonVal`): TOML and YAML are parsed into the same `JsonVal`, then the
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
pub fn config_nullable<E: DecodeErrorSink + 'static, T: 'static + Send>(
    decoder: Decoder<E, T>,
) -> Decoder<E, IpeMaybe<T>> {
    super::json::decode_nullable(decoder)
}

// Config.maybe : Decoder a -> Decoder (Maybe a)
// Unlike `nullable` (which only tolerates null/missing), `maybe` catches ANY
// decode failure: `Just` on success, `Nothing` on any error. Never fails.
pub fn config_maybe<E: DecodeErrorSink + 'static, T: 'static + Send>(
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
pub fn config_dict<E: DecodeErrorSink + 'static, T: 'static + Send>(
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
            None => IpeResult::Err(E::from_decode_failure("expected object".to_owned())),
        }),
        vec![],
    )
}

fn run_decoder<E: DecodeErrorSink + 'static, T>(
    parsed: Result<JsonVal, String>,
    decoder: Decoder<E, T>,
) -> IpeResult<E, T> {
    match parsed {
        Ok(v) => (decoder.run)(&v),
        Err(e) => IpeResult::Err(E::from_decode_failure(e)),
    }
}

// Config.decodeJson : String -> Decoder a -> Result Error a
pub fn config_decode_json<E: DecodeErrorSink + 'static, T>(
    s: String,
    decoder: Decoder<E, T>,
) -> IpeResult<E, T> {
    run_decoder(
        serde_json::from_str(&s).map_err(|e| format!("json parse: {}", e)),
        decoder,
    )
}

// Config.decodeToml : String -> Decoder a -> Result Error a
pub fn config_decode_toml<E: DecodeErrorSink + 'static, T>(
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
pub fn config_decode_yaml<E: DecodeErrorSink + FromLimitExceeded + FromIpeError + 'static, T>(
    s: String,
    decoder: Decoder<E, T>,
) -> IpeResult<E, T> {
    // Two bounds, in order: the source byte cap refuses a huge input before any
    // parse, then `yaml_options`' finite budget bounds what a small input can
    // expand into (aliases, events, nodes, depth, documents).
    let cap: usize = match YAML_SOURCE_CEILING.read() {
        Ok(cap) => cap,
        Err(refusal) => {
            return IpeResult::Err(E::from_ipe_error(IpeError::invalid_input(format!(
                "yaml parse: {refusal}"
            ))));
        }
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
    match yaml_to_value(&s, yaml_options()) {
        Ok(value) => (decoder.run)(&value),
        Err(refusal) => IpeResult::Err(refusal.into_error()),
    }
}

/// Deepest container nesting a YAML source may reach.
const YAML_MAX_DEPTH: usize = 128;

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a YAML document the budget admits could pass the `JsonVal` serde backstop [ledger #boundary]
const _: () = assert!(YAML_MAX_DEPTH < crate::json_val::JSON_SERDE_NESTING_BACKSTOP);

/// Most times one anchor may be replayed through its aliases.
const YAML_MAX_EXPANSIONS_PER_ANCHOR: usize = 10_000;

/// The one parser configuration every YAML source is read under.
///
/// Every budget is finite. YAML 1.1 booleans (`yes`, `on`, `y`) stay strings,
/// tags outside the core schema refuse, duplicate and merge keys refuse, a
/// non-finite float refuses, and an error never carries an input snippet. The
/// source byte cap (`IPE_YAML_MAX_BYTES`, 4 MiB) is below the 64 MiB scalar-byte
/// budget, so the cap always fires first on a large scalar.
fn yaml_options() -> serde_saphyr::Options {
    let mut budget = serde_saphyr::Budget::default();
    budget.max_depth = YAML_MAX_DEPTH;
    budget.max_documents = 1;
    let mut options = serde_saphyr::Options::default();
    options.budget = Some(budget);
    options.alias_limits.max_alias_expansions_per_anchor = YAML_MAX_EXPANSIONS_PER_ANCHOR;
    options.strict_booleans = true;
    options.reject_unsupported_tags = true;
    options.with_snippet = false;
    options.emit_comments = false;
    options.duplicate_keys = serde_saphyr::DuplicateKeyPolicy::Error;
    options.merge_keys = serde_saphyr::MergeKeyPolicy::Error;
    options.legacy_octal_numbers = false;
    options.reject_non_finite_typeless_float = true;
    options
}

/// Parse a YAML source into a JSON value under `options`.
///
/// An error raised while an alias replays an anchor reaches the caller flattened
/// to text, so the budget breach that caused it is read from the parser's typed
/// budget report instead.
fn yaml_to_value(source: &str, options: serde_saphyr::Options) -> Result<JsonVal, YamlRefusal> {
    let breach = std::rc::Rc::new(std::cell::RefCell::new(None));
    let sink = std::rc::Rc::clone(&breach);
    let options = options.with_budget_report(move |report: serde_saphyr::budget::BudgetReport| {
        *sink.borrow_mut() = report.breached;
    });
    serde_saphyr::from_str_with_options::<JsonVal>(source, options)
        .map_err(|error| classify_yaml_error(&error, breach.borrow().as_ref()))
}

/// Why a YAML source was refused, and where.
///
/// Rendered from these fields alone: the parser's own text, which can quote the
/// input, never crosses the boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct YamlRefusal {
    kind: YamlRefusalKind,
    at: Option<(u64, u64)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum YamlRefusalKind {
    Limit(YamlLimit),
    Syntax,
    MultipleDocuments,
    DuplicateKey,
    MergeKey,
    UnsupportedTag,
    NonFiniteFloat,
    Other,
}

/// The parser ceiling a source ran past.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum YamlLimit {
    Depth,
    Events,
    Aliases,
    Anchors,
    Nodes,
    ScalarBytes,
    CommentBytes,
    MergeKeys,
    AliasRatio,
    InclusionDepth,
    InputBytes,
    AnchorEvents,
    AnchorBytes,
    PropertyDepth,
    PropertyWork,
    AliasReplay,
    AliasExpansions,
    AliasReplayDepth,
}

impl YamlLimit {
    const fn label(self) -> &'static str {
        match self {
            Self::Depth => "nesting depth",
            Self::Events => "event count",
            Self::Aliases => "alias count",
            Self::Anchors => "anchor count",
            Self::Nodes => "node count",
            Self::ScalarBytes => "scalar byte",
            Self::CommentBytes => "comment byte",
            Self::MergeKeys => "merge key count",
            Self::AliasRatio => "alias-to-anchor ratio",
            Self::InclusionDepth => "inclusion depth",
            Self::InputBytes => "input byte",
            Self::AnchorEvents => "anchor event",
            Self::AnchorBytes => "anchor byte",
            Self::PropertyDepth => "property expansion depth",
            Self::PropertyWork => "property interpolation",
            Self::AliasReplay => "alias replay",
            Self::AliasExpansions => "alias expansion",
            Self::AliasReplayDepth => "alias replay depth",
        }
    }
}

impl YamlRefusalKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Limit(limit) => limit.label(),
            Self::Syntax => "syntax error",
            Self::MultipleDocuments => "more than one document",
            Self::DuplicateKey => "duplicate mapping key",
            Self::MergeKey => "merge key not supported",
            Self::UnsupportedTag => "unsupported tag",
            Self::NonFiniteFloat => "non-finite float",
            Self::Other => "unsupported content",
        }
    }
}

impl YamlRefusal {
    fn message(self) -> String {
        let what = match self.kind {
            YamlRefusalKind::Limit(limit) => format!("{} limit exceeded", limit.label()),
            other => other.label().to_owned(),
        };
        self.at.map_or_else(
            || format!("yaml: {what}"),
            |(line, column)| format!("yaml: {what} at line {line}, column {column}"),
        )
    }

    /// A ceiling breach is `LimitExceeded`; every other refusal is a decode error.
    fn into_error<E: DecodeErrorSink + FromLimitExceeded>(self) -> E {
        match self.kind {
            YamlRefusalKind::Limit(_) => LimitRefusal::new(self.message()).into_error(),
            YamlRefusalKind::Syntax
            | YamlRefusalKind::MultipleDocuments
            | YamlRefusalKind::DuplicateKey
            | YamlRefusalKind::MergeKey
            | YamlRefusalKind::UnsupportedTag
            | YamlRefusalKind::NonFiniteFloat
            | YamlRefusalKind::Other => E::from_decode_failure(self.message()),
        }
    }
}

fn classify_budget_breach(breach: &serde_saphyr::budget::BudgetBreach) -> YamlRefusalKind {
    use serde_saphyr::budget::BudgetBreach as B;
    let limit = match breach {
        B::Depth { .. } => YamlLimit::Depth,
        B::Events { .. } => YamlLimit::Events,
        B::Aliases { .. } => YamlLimit::Aliases,
        B::Anchors { .. } => YamlLimit::Anchors,
        B::Nodes { .. } => YamlLimit::Nodes,
        B::ScalarBytes { .. } => YamlLimit::ScalarBytes,
        B::CommentBytes { .. } => YamlLimit::CommentBytes,
        B::MergeKeys { .. } => YamlLimit::MergeKeys,
        B::AliasAnchorRatio { .. } => YamlLimit::AliasRatio,
        B::InclusionDepth { .. } => YamlLimit::InclusionDepth,
        B::InputBytes { .. } => YamlLimit::InputBytes,
        B::RecordedAnchorEvents { .. } => YamlLimit::AnchorEvents,
        B::RecordedAnchorBytes { .. } => YamlLimit::AnchorBytes,
        B::PropertyExpansionDepth { .. } => YamlLimit::PropertyDepth,
        B::PropertyInterpolationWork { .. } => YamlLimit::PropertyWork,
        // The one-document budget is how a second document is refused.
        B::Documents { .. } => return YamlRefusalKind::MultipleDocuments,
        B::SequenceUnbalanced => return YamlRefusalKind::Syntax,
        // non_exhaustive foreign enum: unknown variants refuse as Other
        _ => return YamlRefusalKind::Other,
    };
    YamlRefusalKind::Limit(limit)
}

/// Map a parser error to its refusal by variant, never by its text. `breach` is
/// the budget breach the parser reported for the same parse, if any.
#[allow(clippy::match_same_arms)] // known variants named for review; the wildcard is for future ones
fn classify_yaml_error(
    error: &serde_saphyr::Error,
    breach: Option<&serde_saphyr::budget::BudgetBreach>,
) -> YamlRefusal {
    use serde_saphyr::Error as Y;
    let error = error.without_snippet();
    let kind = match error {
        Y::Budget { breach, .. } => classify_budget_breach(breach),
        Y::AliasReplayCounterOverflow { .. } | Y::AliasReplayLimitExceeded { .. } => {
            YamlRefusalKind::Limit(YamlLimit::AliasReplay)
        }
        Y::AliasExpansionLimitExceeded { .. } => YamlRefusalKind::Limit(YamlLimit::AliasExpansions),
        Y::AliasReplayStackDepthExceeded { .. } => {
            YamlRefusalKind::Limit(YamlLimit::AliasReplayDepth)
        }
        Y::ExternalMessage { .. }
        | Y::Eof { .. }
        | Y::Unexpected { .. }
        | Y::UnexpectedSequenceEnd { .. }
        | Y::UnexpectedMappingEnd { .. }
        | Y::UnexpectedContainerEndWhileSkippingNode { .. }
        | Y::UnexpectedContainerEndWhileReadingKeyNode { .. }
        | Y::ContainerEndMismatch { .. }
        | Y::FoldedBlockScalarMustIndentContent { .. }
        | Y::IndentationError { .. }
        | Y::QuotingRequired { .. }
        | Y::UnknownAnchor { .. }
        | Y::InvalidUtf8Input => YamlRefusalKind::Syntax,
        Y::AliasError { .. } => breach.map_or(YamlRefusalKind::Syntax, classify_budget_breach),
        Y::MultipleDocuments { .. } => YamlRefusalKind::MultipleDocuments,
        Y::DuplicateMappingKey { .. } => YamlRefusalKind::DuplicateKey,
        Y::MergeKeyNotAllowed { .. } | Y::MergeValueNotMapOrSeqOfMaps { .. } => {
            YamlRefusalKind::MergeKey
        }
        Y::UnsupportedTag { .. }
        | Y::TaggedScalarCannotDeserializeIntoString { .. }
        | Y::CyclicInclude { .. }
        | Y::UnsupportedIncludeForm { .. }
        | Y::ResolverError { .. } => YamlRefusalKind::UnsupportedTag,
        Y::NonFiniteFloat { .. } => YamlRefusalKind::NonFiniteFloat,
        Y::Message { .. }
        | Y::InvalidOptions { .. }
        | Y::InvalidBinaryBase64 { .. }
        | Y::BinaryNotUtf8 { .. }
        | Y::InvalidBooleanStrict { .. }
        | Y::InvalidCharNull { .. }
        | Y::InvalidCharNotSingleScalar { .. }
        | Y::NullIntoString { .. }
        | Y::BytesNotSupportedMissingBinaryTag { .. }
        | Y::UnexpectedValueForUnit { .. }
        | Y::ExpectedEmptyMappingForUnitStruct { .. }
        | Y::InternalSeedReusedForMapKey { .. }
        | Y::ValueRequestedBeforeKey { .. }
        | Y::ExpectedStringKeyForExternallyTaggedEnum { .. }
        | Y::ExternallyTaggedEnumExpectedScalarOrMapping { .. }
        | Y::UnexpectedValueForUnitEnumVariant { .. }
        | Y::InternalDepthUnderflow { .. }
        | Y::InternalRecursionStackEmpty { .. }
        | Y::RecursiveReferencesRequireWeakTypes { .. }
        | Y::InvalidScalar { .. }
        | Y::SerdeInvalidType { .. }
        | Y::SerdeInvalidValue { .. }
        | Y::SerdeUnknownVariant { .. }
        | Y::SerdeUnknownField { .. }
        | Y::SerdeMissingField { .. }
        | Y::TaggedEnumMismatch { .. }
        | Y::SerdeVariantId { .. }
        | Y::ExpectedMappingEndAfterEnumVariantValue { .. }
        | Y::HookError { .. }
        | Y::UnresolvedProperty { .. }
        | Y::InvalidPropertyName { .. }
        | Y::PropertyRequiredButUnset { .. }
        | Y::PropertyRequiredButEmpty { .. }
        | Y::IOError { .. }
        | Y::CannotBorrowTransformedString { .. }
        | Y::WithSnippet { .. } => YamlRefusalKind::Other,
        // non_exhaustive foreign enum: unknown variants refuse as Other
        _ => YamlRefusalKind::Other,
    };
    YamlRefusal {
        kind,
        at: error
            .location()
            .map(|location| (location.line(), location.column())),
    }
}

// ── shared blocking-pool helper ───────────────────────────────────────
//
// `config_load_from_file` does a blocking `std::fs::File::open` + capped
// `read_to_string` (up to `IPE_CONFIG_MAX_BYTES`, default 16 MiB) inline.
// Offload it to tokio's blocking pool so a large/slow-filesystem config read
// can't stall the tokio worker thread polling this future. This module is
// gated on the `config` Cargo feature (`config = ["json", "toml",
// "dep:serde-saphyr"]`, runtime/Cargo.toml), which does NOT pull in `tokio`, so
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
    let failed =
        |e: std::io::Error| KernelFailure::from(IoFailure::on_path("read config file", path, &e));
    let file = std::fs::File::open(path).map_err(failed)?;
    let meta = file.metadata().map_err(failed)?;
    if !meta.file_type().is_file() {
        return Err(failed(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        )));
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
        .map_err(failed)?;
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
    E: crate::KernelErrorSink + crate::FromDecodeFailure + Send + 'static,
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
            Err(refusal) => {
                return IpeResult::Err(E::from_ipe_error(IpeError::invalid_input(
                    refusal.to_string(),
                )));
            }
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

    /// A malformed `IPE_CONFIG_MAX_BYTES` is the operator's `InvalidInput`
    /// naming the variable, never an `Unexpected` failure.
    #[test]
    fn malformed_config_ceiling_is_invalid_input() {
        let p = crate::scratch_core::test_temp_root()
            .join(format!("ipe_cfg_bad_cap_{}.json", std::process::id()));
        std::fs::write(&p, r#"{"name": "ipe"}"#).unwrap();
        crate::system::locked_set_var("IPE_CONFIG_MAX_BYTES", "abc");
        let res: IpeResult<crate::IpeError, String> = block(config_load_from_file(
            make_path(&p.to_string_lossy()),
            kinded_name_decoder(),
        ));
        crate::system::locked_remove_var("IPE_CONFIG_MAX_BYTES");
        let _ = std::fs::remove_file(&p);
        assert!(
            matches!(&res, IpeResult::Err(crate::IpeError::Error(crate::IpeErrorKind::InvalidInput, info))
                if info.message.contains("IPE_CONFIG_MAX_BYTES")),
            "a malformed config ceiling must be InvalidInput: {res:?}"
        );
    }

    /// A malformed `IPE_YAML_MAX_BYTES` is `InvalidInput`, never `Unexpected`.
    #[test]
    fn malformed_yaml_ceiling_is_invalid_input() {
        crate::system::locked_set_var("IPE_YAML_MAX_BYTES", "abc");
        let res: IpeResult<crate::IpeError, String> =
            config_decode_yaml("name: ipe".to_string(), kinded_name_decoder());
        crate::system::locked_remove_var("IPE_YAML_MAX_BYTES");
        assert!(
            matches!(&res, IpeResult::Err(crate::IpeError::Error(crate::IpeErrorKind::InvalidInput, info))
                if info.message.starts_with("yaml parse: ") && info.message.contains("IPE_YAML_MAX_BYTES")),
            "a malformed YAML ceiling must be InvalidInput: {res:?}"
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
    use crate::json_val::json_val as json;

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

    /// The refusal class of `src` under the pinned options, or `None` when it parsed.
    fn kind(src: &str) -> Option<YamlRefusalKind> {
        yaml_to_value(src, yaml_options())
            .err()
            .map(|refusal| refusal.kind)
    }

    /// The pinned options with one setting changed, for the accepting controls.
    fn lifted(change: impl FnOnce(&mut serde_saphyr::Options)) -> serde_saphyr::Options {
        let mut options = yaml_options();
        change(&mut options);
        options
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
        for (prev, next) in names
            .iter()
            .zip(names.iter().skip(1))
            .take(levels.saturating_sub(1))
        {
            let items = std::iter::repeat_n(format!("*{prev}"), 9)
                .collect::<Vec<_>>()
                .join(", ");
            src.push_str(&format!("{next}: &{next} [{items}]\n"));
        }
        src
    }

    /// `count` distinct anchors, one per sequence item.
    fn anchors(count: usize) -> String {
        let mut src = String::new();
        for n in 0..count {
            src.push_str(&format!("- &a{n} 1\n"));
        }
        src
    }

    #[test]
    fn yaml_11_booleans_stay_strings() {
        for word in ["yes", "no", "on", "off", "y", "n"] {
            assert_eq!(field(&format!("a: {word}")), json!(word), "{word}");
        }
        let yaml_11 = lifted(|options| options.strict_booleans = false);
        assert_eq!(yaml_to_value("a: yes", yaml_11), Ok(json!({"a": true})));
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

    /// Core booleans match in any letter case.
    #[test]
    fn mixed_case_bool_decodes() {
        assert_eq!(field("a: tRuE"), json!(true));
        assert_eq!(field("a: \"tRuE\""), json!("tRuE"));
    }

    #[test]
    fn nulls_decode() {
        for src in ["a: null", "a: Null", "a: NULL", "a: ~", "a:"] {
            assert_eq!(yaml(src), IpeResult::Ok(json!({"a": null})), "{src:?}");
        }
    }

    /// `null` matches in any letter case; quoting keeps the string.
    #[test]
    fn mixed_case_null_decodes() {
        assert_eq!(yaml("a: nUlL"), IpeResult::Ok(json!({"a": null})));
        assert_eq!(field("a: \"nUlL\""), json!("nUlL"));
    }

    /// A plain leading-zero number is a number; quoting keeps the string.
    #[test]
    fn leading_zero_decodes_as_number() {
        assert_eq!(field("a: 012").as_f64(), Some(12.0));
        assert_eq!(field("a: \"012\""), json!("012"));
    }

    #[test]
    fn prefixed_ints() {
        assert_eq!(field("a: 0x1F"), json!(31));
        assert_eq!(field("a: 0o17"), json!(15));
        assert_eq!(field("a: 0b11"), json!(3));
    }

    #[test]
    fn non_finite_float_refused() {
        for word in [".nan", ".inf", "-.inf"] {
            assert_eq!(
                kind(&format!("a: {word}")),
                Some(YamlRefusalKind::NonFiniteFloat),
                "{word}"
            );
        }
        assert_eq!(field("a: 1.5"), json!(1.5));
    }

    #[test]
    fn duplicate_key_refused() {
        assert_eq!(kind("a: 1\na: 2"), Some(YamlRefusalKind::DuplicateKey));
        let last_wins = lifted(|options| {
            options.duplicate_keys = serde_saphyr::DuplicateKeyPolicy::LastWins;
        });
        assert_eq!(yaml_to_value("a: 1\na: 2", last_wins), Ok(json!({"a": 2})));
    }

    #[test]
    fn merge_key_refused() {
        let src = "base: &b {x: 1}\nm: {<<: *b}";
        assert_eq!(kind(src), Some(YamlRefusalKind::MergeKey));
        let ordinary = lifted(|options| {
            options.merge_keys = serde_saphyr::MergeKeyPolicy::AsOrdinary;
        });
        assert_eq!(
            yaml_to_value(src, ordinary),
            Ok(json!({"base": {"x": 1}, "m": {"<<": {"x": 1}}}))
        );
    }

    #[test]
    fn multi_document_refused() {
        assert_eq!(
            kind("--- a\n--- b"),
            Some(YamlRefusalKind::MultipleDocuments)
        );
        assert_eq!(yaml("--- a"), IpeResult::Ok(json!("a")));
    }

    #[test]
    fn local_tag_refused() {
        assert_eq!(kind("a: !foo x"), Some(YamlRefusalKind::UnsupportedTag));
        let permissive = lifted(|options| options.reject_unsupported_tags = false);
        assert_eq!(
            yaml_to_value("a: !foo x", permissive),
            Ok(json!({"a": "x"}))
        );
    }

    /// An include tag refuses without reading the file or naming it.
    #[test]
    fn include_tag_refused() {
        let src = "a: !include /etc/passwd";
        assert_eq!(kind(src), Some(YamlRefusalKind::UnsupportedTag));
        let refused = refusal(src);
        assert!(refused.is_some(), "{src:?} must refuse");
        let Some((_, message)) = refused else {
            return;
        };
        assert!(!message.contains("/etc/passwd"), "{message}");
        assert!(!message.contains("root:"), "{message}");
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
    fn alias_bomb_is_limit_refusal() {
        assert!(
            matches!(kind(&alias_bomb(9)), Some(YamlRefusalKind::Limit(_))),
            "a nine-level alias bomb must hit a parser ceiling"
        );
        assert!(matches!(
            refusal(&alias_bomb(9)),
            Some((crate::IpeErrorKind::LimitExceeded, _))
        ));
        assert!(matches!(yaml(&alias_bomb(2)), IpeResult::Ok(_)));
    }

    #[test]
    fn depth_at_ceiling_accepted() {
        assert!(matches!(
            yaml(&nested_flow(YAML_MAX_DEPTH)),
            IpeResult::Ok(_)
        ));
        assert!(matches!(
            yaml(&nested_block(YAML_MAX_DEPTH)),
            IpeResult::Ok(_)
        ));
    }

    #[test]
    fn depth_ceiling_plus_one_is_limit_refusal() {
        let past = YAML_MAX_DEPTH + 1;
        for src in [nested_flow(past), nested_block(past)] {
            assert_eq!(kind(&src), Some(YamlRefusalKind::Limit(YamlLimit::Depth)));
            assert!(matches!(
                refusal(&src),
                Some((crate::IpeErrorKind::LimitExceeded, _))
            ));
            let deeper = lifted(|options| {
                let mut budget = serde_saphyr::Budget::default();
                budget.max_depth = 2 * YAML_MAX_DEPTH;
                budget.max_documents = 1;
                options.budget = Some(budget);
            });
            assert!(yaml_to_value(&src, deeper).is_ok());
        }
    }

    /// Depth composed through an alias counts: a 99-deep anchor replayed under
    /// a 99-deep sequence nests past the ceiling although neither half does.
    #[test]
    fn alias_composed_depth_is_limit_refusal() {
        let open = "[".repeat(99);
        let close = "]".repeat(99);
        let src = format!("a: &a {open}{close}\nb: {open}*a{close}\n");
        assert_eq!(kind(&src), Some(YamlRefusalKind::Limit(YamlLimit::Depth)));
        assert!(matches!(
            refusal(&src),
            Some((crate::IpeErrorKind::LimitExceeded, _))
        ));
        let deeper = lifted(|options| {
            let mut budget = serde_saphyr::Budget::default();
            budget.max_depth = 2 * YAML_MAX_DEPTH;
            budget.max_documents = 1;
            options.budget = Some(budget);
        });
        assert!(yaml_to_value(&src, deeper).is_ok());
    }

    #[test]
    fn anchor_count_is_limit_refusal() {
        assert!(yaml_to_value(&anchors(50_000), yaml_options()).is_ok());
        assert_eq!(
            kind(&anchors(50_001)),
            Some(YamlRefusalKind::Limit(YamlLimit::Anchors))
        );
    }

    /// A syntax error renders only its class and position, never the source text.
    #[test]
    fn syntax_error_message_closed() {
        let src = "zq: [17,";
        let refused = yaml_to_value(src, yaml_options());
        assert!(
            matches!(
                refused,
                Err(YamlRefusal {
                    kind: YamlRefusalKind::Syntax,
                    ..
                })
            ),
            "{refused:?}"
        );
        let Err(syntax) = refused else {
            return;
        };
        let expected = syntax.at.map_or_else(
            || "yaml: syntax error".to_owned(),
            |(line, column)| format!("yaml: syntax error at line {line}, column {column}"),
        );
        assert_eq!(syntax.message(), expected);
        assert!(!expected.contains("zq"), "{expected}");
        assert!(!expected.contains("17"), "{expected}");
        assert_eq!(refusal(src), Some((crate::IpeErrorKind::Decode, expected)));
    }

    #[test]
    fn error_never_echoes_input() {
        for src in [
            "password: \"hunter2",
            "password: hunter2\npassword: hunter2",
        ] {
            let refused = refusal(src);
            assert!(refused.is_some(), "{src:?} must refuse");
            let Some((_, message)) = refused else {
                return;
            };
            assert!(!message.contains("hunter2"), "{message}");
            assert!(!message.contains("password"), "{message}");
        }
    }

    #[test]
    fn yaml_options_are_pinned() {
        let options = yaml_options();
        assert!(options.strict_booleans);
        assert!(options.reject_unsupported_tags);
        assert!(!options.with_snippet);
        assert!(!options.emit_comments);
        assert!(!options.legacy_octal_numbers);
        assert!(options.reject_non_finite_typeless_float);
        assert!(matches!(
            options.duplicate_keys,
            serde_saphyr::DuplicateKeyPolicy::Error
        ));
        assert!(matches!(
            options.merge_keys,
            serde_saphyr::MergeKeyPolicy::Error
        ));
        assert_eq!(
            options.alias_limits.max_alias_expansions_per_anchor,
            YAML_MAX_EXPANSIONS_PER_ANCHOR
        );
        let budget = options.budget.as_ref();
        assert_eq!(budget.map(|b| b.max_depth), Some(YAML_MAX_DEPTH));
        assert_eq!(budget.map(|b| b.max_documents), Some(1));
    }
}
