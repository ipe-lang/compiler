//! Every cfg name an emitted crate's sources test is one its manifest declares.
//!
//! rustc evaluates a `feature = "x"` predicate naming an undeclared feature to
//! false, with only an `unexpected_cfgs` warning, so a gate naming a feature the
//! vendored `Cargo.toml` never declares compiles its code out of every vendored
//! build without a word. The scan lexes each vendored source (the runtime tree
//! the driver copies into `src/ipe_runtime/`, the trimmed `ipe_runtime/mod.rs`
//! and stub `config.rs` templates, and the `RUNTIME_MOD_RS_*` appends) and
//! refuses any feature name the BASE vendored manifest leaves undeclared. The
//! augmenters never declare a name, only promote or upgrade one the base
//! declares inert, so the base table is the declared set of every augmenter
//! combination. Custom cfg names (`ipe_asan`) are held to the manifest's
//! `check-cfg` list, itself held equal to the runtime build script's. The
//! emitted `main.rs` text tests only features every native app manifest
//! declares. The converse holds too: every feature an app manifest declares is
//! read by some compiled gate, so none is selected for nothing.

#![cfg(test)]

use super::{
    CARGO_DEP_TOML, CARGO_TOML, CARGO_WASM_DEP_TOML, GOLDEN as MAIN_RS, RUNTIME_CONFIG_RS,
    RUNTIME_MOD_RS, WASM_CARGO_TOML, async_runtime_cargo_toml, compression_cargo_toml,
    config_cargo_toml, crypto_cargo_toml, crypto_core_heavy_cargo_toml, csv_cargo_toml,
    db_cargo_toml, dev_posture_cargo_toml, email_cargo_toml, http_client_cargo_toml,
    jwt_cargo_toml, locale_cargo_toml, promote_declared_feature, secret_cargo_toml,
    server_cargo_toml, tui_cargo_toml, url_cargo_toml, vendored_tokio_for, web_cargo_toml,
    websocket_cargo_toml, webview_cargo_toml,
};
use crate::crate_specs::tokio_base_features;
use crate::runtime_features::{RuntimeFeature, RuntimeFeatureSet};
use ipe_diagnostics::{DResult, Diagnostic};
use ipe_ir::Target;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[path = "../../tests/support/rust_lex.rs"]
mod rust_lex;

use rust_lex::{Tok, gate_features, lex, test_only_item_end};

/// Runtime source files the driver copies but no vendored module tree declares.
///
/// Each entry names the file (relative to the runtime `src/`) and why rustc never
/// compiles it in a vendored build. The stale-entry check refuses an entry whose
/// file is gone, is declared by the vendored module tree, or no longer names an
/// undeclared feature.
const EXCLUDED: &[(&str, &str)] = &[(
    "clippy_paths_resolve.rs",
    "declared only by the runtime crate's own `mod.rs` under `cfg(test)`; the \
     trimmed vendored `mod.rs` never declares it",
)];

/// Runtime files the emitter overwrites in EVERY vendored emit, so their
/// runtime copies never reach a vendored build (the template replaces them).
///
/// `config.rs` is absent on purpose: a sqlite db emit vendors the runtime copy
/// verbatim, so it is scanned like any other file.
const REPLACED: &[&str] = &["mod.rs"];

/// The backend source, lexed for its `RUNTIME_MOD_RS_*` append constants.
const PROJECT_RS: &str = include_str!("../project.rs");

/// The runtime crate's `src/` directory, the tree the driver vendors.
fn runtime_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../runtime/rust/src")
}

/// Every `feature = "name"` inside a `cfg` / `cfg_attr` attribute or a `cfg!`
/// macro, with the line it sits on. Items gated by `#[cfg(test)]` are skipped.
fn cfg_features(src: &str) -> Vec<(usize, String)> {
    gate_features(src, false)
}

/// The feature names a manifest's `[features]` table declares.
fn declared_features(manifest: &str) -> BTreeSet<String> {
    manifest
        .lines()
        .skip_while(|l| l.trim() != "[features]")
        .skip(1)
        .take_while(|l| !l.trim_start().starts_with('['))
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('=').map(|(name, _)| name.trim().to_owned()))
        .collect()
}

/// The string contents of every `const RUNTIME_MOD_RS*` item in `project.rs`.
fn mod_rs_appends() -> Vec<(String, String)> {
    let toks = lex(PROJECT_RS);
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some((_, tok)) = toks.get(i) {
        if let (Tok::Ident(kw), Some((_, Tok::Ident(name)))) = (tok, toks.get(i + 1))
            && kw == "const"
            && name.starts_with("RUNTIME_MOD_RS")
        {
            let mut body = String::new();
            let mut j = i + 2;
            while let Some((_, t)) = toks.get(j) {
                match t {
                    Tok::Punct(';') => break,
                    Tok::Str(s) => body.push_str(s),
                    _ => {}
                }
                j += 1;
            }
            out.push((name.clone(), body));
            i = j;
        }
        i += 1;
    }
    out
}

/// Every `.rs` file under `root`, as paths relative to it, or a failed test.
///
/// The walk lists the tree whole: an unreadable directory, entry, or entry type
/// fails the test, and a symlinked directory is refused rather than followed, so
/// the scan never certifies a tree it could not read.
fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir)
            .map_err(|error| format!("{}: {error}", dir.display()))
            .expect("the runtime tree is listed whole");
        for entry in entries {
            let entry = entry
                .map_err(|error| format!("{}: {error}", dir.display()))
                .expect("the runtime tree is listed whole");
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| format!("{}: {error}", path.display()))
                .expect("every runtime tree entry has a readable type");
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if file_type.is_symlink() {
                let target = std::fs::metadata(&path)
                    .map_err(|error| format!("{}: {error}", path.display()))
                    .expect("every runtime tree symlink resolves");
                assert!(
                    !target.is_dir(),
                    "{}: symlinked directory under the runtime tree; the scan does not follow it",
                    path.display()
                );
            }
            if path.extension().is_some_and(|e| e == "rs") {
                let rel = path
                    .strip_prefix(root)
                    .expect("a walked file lies under its root");
                out.push(rel.to_path_buf());
            }
        }
    }
    out.sort();
    out
}

/// The features every vendored emit declares: the base template's own table.
///
/// No augmenter declares a name (see `augmenters_declare_no_feature`), so this
/// is the declared set of every augmenter combination, and a gate the base
/// leaves undeclared warns in the emits that skip its augmenter.
fn vendored_declared() -> BTreeSet<String> {
    declared_features(CARGO_TOML)
}

/// The vendored runtime tree, the `mod.rs` template and every append name only
/// declared features; the exclusion list carries no stale entry.
#[test]
fn vendored_cfg_features_are_declared() {
    let declared = vendored_declared();
    let root = runtime_src();
    let files = rust_files(&root);
    assert!(
        files.len() > 50,
        "the runtime tree at {} must be scanned, found {} files",
        root.display(),
        files.len()
    );

    let mut drift = Vec::new();
    let mut scanned = 0usize;
    for rel in &files {
        let rel_s = rel.to_string_lossy().replace('\\', "/");
        if REPLACED.contains(&rel_s.as_str()) || EXCLUDED.iter().any(|(f, _)| *f == rel_s) {
            continue;
        }
        let src = std::fs::read_to_string(root.join(rel)).expect("runtime source must read");
        for (line, name) in cfg_features(&src) {
            scanned += 1;
            if !declared.contains(&name) {
                drift.push(format!("{rel_s}:{line}: feature {name:?}"));
            }
        }
    }
    for (template, text) in [
        ("templates/ipe_runtime/mod.rs", RUNTIME_MOD_RS),
        ("templates/ipe_runtime/config.rs", RUNTIME_CONFIG_RS),
    ] {
        for (line, name) in cfg_features(text) {
            scanned += 1;
            if !declared.contains(&name) {
                drift.push(format!("{template}:{line}: feature {name:?}"));
            }
        }
    }
    let appends = mod_rs_appends();
    assert!(
        appends
            .iter()
            .any(|(n, _)| n == "RUNTIME_MOD_RS_WEB_APPEND"),
        "the append scan must find the RUNTIME_MOD_RS_* constants: {:?}",
        appends.iter().map(|(n, _)| n).collect::<Vec<_>>()
    );
    for (const_name, body) in &appends {
        for (_, name) in cfg_features(body) {
            scanned += 1;
            if !declared.contains(&name) {
                drift.push(format!("project.rs {const_name}: feature {name:?}"));
            }
        }
    }
    assert!(
        scanned > 100,
        "the scan must read the gates, read {scanned}"
    );
    assert!(
        drift.is_empty(),
        "vendored sources name features the base vendored Cargo.toml never declares, \
         so rustc warns on their gates in every emit that skips the promoting \
         augmenter; declare each inert in templates/Cargo.toml (its augmenter only \
         promotes it) or restate the gate:\n{}",
        drift.join("\n")
    );
}

/// Every exclusion still names a file the vendored module tree never declares
/// and that names an undeclared feature; every replacement is still emitted.
#[test]
fn exclusion_and_replacement_lists_are_current() {
    let declared = vendored_declared();
    let root = runtime_src();
    let appends = mod_rs_appends();
    for (file, why) in EXCLUDED {
        let path = root.join(file);
        let src = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            !src.is_empty(),
            "stale exclusion: {file} ({why}) is not in the runtime tree"
        );
        let module = file.trim_end_matches(".rs");
        let names_module = |text: &str| {
            let toks = lex(text);
            toks.windows(2).any(|w| {
                matches!(
                    (w.first(), w.get(1)),
                    (Some((_, Tok::Ident(m))), Some((_, Tok::Ident(n)))) if m == "mod" && n == module
                )
            })
        };
        assert!(
            !names_module(RUNTIME_MOD_RS) && !appends.iter().any(|(_, body)| names_module(body)),
            "stale exclusion: the vendored module tree declares {file}, so it must be scanned"
        );
        assert!(
            cfg_features(&src)
                .iter()
                .any(|(_, name)| !declared.contains(name)),
            "stale exclusion: {file} names only declared features, so it needs no exclusion"
        );
    }
    for file in REPLACED {
        assert!(
            root.join(file).is_file(),
            "stale replacement entry: runtime {file} is gone"
        );
        let emitted = format!("src/ipe_runtime/{file}");
        assert!(
            lex(PROJECT_RS)
                .iter()
                .any(|(_, t)| matches!(t, Tok::Str(s) if *s == emitted)),
            "stale replacement entry: the backend no longer emits {emitted}"
        );
    }
}

/// The scan reads gates in every `cfg` form and nothing in comments, strings,
/// or char literals.
#[test]
fn cfg_scan_reads_gates_and_skips_prose() {
    let src = r##"
        // #[cfg(feature = "line_comment")]
        /// #[cfg(feature = "doc_comment")]
        /* outer /* #[cfg(feature = "nested")] */ still comment */
        const S: &str = "#[cfg(feature = \"in_string\")]";
        const R: &str = r#"#[cfg(feature = "in_raw")]"#;
        const Q: char = '"';
        const E: [char; 2] = ['\'','"'];
        #[cfg(feature = "after_escaped_quote")]
        fn c() {}
        fn lt<'a>(x: &'a str) -> &'a str { x }
        #[cfg(all(feature = "attr", not(feature = "negated")))]
        fn a() {}
        #[cfg_attr(feature = "attr_pred", allow(dead_code))]
        fn b() { if cfg!(feature = "mac") {} }
        #![cfg(feature = "inner")]
        fn cfg(feature: u8) {}
    "##;
    let names: Vec<String> = cfg_features(src).into_iter().map(|(_, n)| n).collect();
    assert_eq!(
        names,
        [
            "after_escaped_quote",
            "attr",
            "negated",
            "attr_pred",
            "mac",
            "inner"
        ],
        "only real gates are read"
    );
}

/// The appended `mod.rs` text is decoded through its escapes and continuations,
/// so a gate inside an append constant is read like one in a file.
#[test]
fn cfg_scan_reads_escaped_append_strings() {
    let decoded = lex(
        "const X: &str = \"#[cfg(feature = \\\"web\\\")]\\npub mod a;\\n\\\n     #[cfg(feature = \\\"tui\\\")]\\npub mod b;\\n\";",
    );
    let body = decoded
        .iter()
        .find_map(|(_, t)| match t {
            Tok::Str(s) => Some(s.clone()),
            _ => None,
        })
        .unwrap_or_default();
    let names: Vec<String> = cfg_features(&body).into_iter().map(|(_, n)| n).collect();
    assert_eq!(names, ["web", "tui"]);
}

/// A gate naming an undeclared feature is reported, which is what makes the
/// class check go red.
#[test]
fn undeclared_feature_is_drift() {
    let declared = declared_features("[features]\ndefault = [\"json\"]\njson = []\n\n[deps]\n");
    assert_eq!(
        declared,
        BTreeSet::from(["default".to_owned(), "json".to_owned()])
    );
    let gates =
        cfg_features("#[cfg(all(feature = \"json\", feature = \"http_client\"))]\nfn f() {}");
    let undeclared: Vec<&str> = gates
        .iter()
        .filter(|(_, n)| !declared.contains(n))
        .map(|(_, n)| n.as_str())
        .collect();
    assert_eq!(undeclared, ["http_client"]);
}

/// A `#[cfg(test)]` item, body or bodiless, is never read, while a gate before
/// or after it, and a `cfg(not(test))` item, still are.
#[test]
fn cfg_scan_skips_test_only_items() {
    let src = r#"
        #[cfg(feature = "before")]
        fn a() {}
        #[cfg(test)]
        mod tests {
            #[cfg(feature = "in_test_mod")]
            #[test]
            fn t() { if true { let _ = 1; } }
        }
        #[cfg(test)]
        mod external;
        #[cfg(not(test))]
        #[cfg(feature = "not_test")]
        fn b() {}
        #[cfg(all(test, feature = "mixed"))]
        fn c() {}
        #[cfg(feature = "after")]
        fn d() {}
    "#;
    let names: Vec<String> = cfg_features(src).into_iter().map(|(_, n)| n).collect();
    assert_eq!(names, ["before", "not_test", "mixed", "after"]);
}

/// Every feature a vendored build reads in a `cfg`: the scanned runtime tree,
/// the `mod.rs` / `config.rs` / `main.rs` templates, and every string the
/// backend source emits outside its `#[cfg(test)]` items.
///
/// The vendored sources' own `#[cfg(test)]` items count: a test build of the
/// emitted crate compiles them, and rustc's check-cfg reads their gates.
fn vendored_reads() -> BTreeSet<String> {
    let root = runtime_src();
    let mut reads = BTreeSet::new();
    for rel in rust_files(&root) {
        let rel_s = rel.to_string_lossy().replace('\\', "/");
        if REPLACED.contains(&rel_s.as_str()) || EXCLUDED.iter().any(|(f, _)| *f == rel_s) {
            continue;
        }
        let src = std::fs::read_to_string(root.join(rel)).expect("runtime source must read");
        reads.extend(gate_features(&src, true).into_iter().map(|(_, n)| n));
    }
    for text in [RUNTIME_MOD_RS, RUNTIME_CONFIG_RS, MAIN_RS] {
        reads.extend(gate_features(text, true).into_iter().map(|(_, n)| n));
    }
    for body in emitted_strings(PROJECT_RS) {
        reads.extend(gate_features(&body, true).into_iter().map(|(_, n)| n));
    }
    reads
}

/// The contents of every string literal in `src` outside a `#[cfg(test)]` item.
fn emitted_strings(src: &str) -> Vec<String> {
    let toks = lex(src);
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some((_, tok)) = toks.get(i) {
        if let Some(end) = test_only_item_end(&toks, i) {
            i = end + 1;
            continue;
        }
        if let Tok::Str(s) = tok {
            out.push(s.clone());
        }
        i += 1;
    }
    out
}

/// The features `manifest` declares that no read in `reads` names.
///
/// `default` is exempt: it is the crate's baseline, never a gate.
fn unread_features(manifest: &str, reads: &BTreeSet<String>) -> Vec<String> {
    declared_features(manifest)
        .into_iter()
        .filter(|name| name != "default" && !reads.contains(name))
        .collect()
}

/// Every feature an emitted app manifest declares is read by a `cfg` the build
/// compiles, so selecting it always changes what compiles.
#[test]
fn app_manifest_features_are_read() {
    let reads = vendored_reads();
    assert!(
        reads.contains("time-core") && reads.contains("alloc_mimalloc"),
        "precondition: the read scan sees runtime and `main.rs` gates: {reads:?}"
    );
    let async_base = async_runtime_cargo_toml(CARGO_TOML, &tokio_base_features())
        .expect("async base must build");
    let manifests = [
        ("templates/Cargo.toml", CARGO_TOML.to_owned()),
        (
            "server augmenter",
            server_cargo_toml(&async_base).expect("server manifest must build"),
        ),
        (
            "jwt augmenter",
            jwt_cargo_toml(CARGO_TOML).expect("jwt manifest must build"),
        ),
        (
            "locale augmenter",
            locale_cargo_toml(CARGO_TOML).expect("locale manifest must build"),
        ),
        ("WASM_CARGO_TOML", WASM_CARGO_TOML.to_owned()),
        ("templates/Cargo.dep.toml", CARGO_DEP_TOML.to_owned()),
        (
            "templates/Cargo.wasm-dep.toml",
            CARGO_WASM_DEP_TOML.to_owned(),
        ),
    ];
    let mut dead = Vec::new();
    for (name, manifest) in &manifests {
        assert!(
            declared_features(manifest).contains("default"),
            "precondition: {name} declares a `[features]` table"
        );
        for feature in unread_features(manifest, &reads) {
            dead.push(format!("{name}: feature {feature:?}"));
        }
    }
    assert!(
        dead.is_empty(),
        "app manifests declare features no compiled `cfg` reads, so selecting one \
         changes nothing; drop the declaration or gate the code it claims:\n{}",
        dead.join("\n")
    );
}

/// A declared feature no gate reads is reported, and a read revives it.
#[test]
fn unread_declared_feature_is_refused() {
    const MANIFEST: &str =
        "[features]\ndefault = [\"time-core\"]\ntime-core = []\ntime = []\n\n[dependencies]\n";
    let reads: BTreeSet<String> = cfg_features("#[cfg(feature = \"time-core\")]\npub mod time;\n")
        .into_iter()
        .map(|(_, n)| n)
        .collect();
    assert_eq!(unread_features(MANIFEST, &reads), ["time"]);
    let mut revived = reads;
    revived.insert("time".to_owned());
    assert!(unread_features(MANIFEST, &revived).is_empty());
}

/// A reactor flag that disagrees with the tokio projection is a compiler bug.
///
/// Reactor on with no tokio-enabling feature, or reactor off with a feature
/// needing tokio beyond the base set, refuses at `ipe` time; the agreeing
/// shapes resolve to the projected set or to no line.
#[test]
fn vendored_tokio_disagreement_is_a_compiler_bug() {
    fn set(members: &[RuntimeFeature]) -> RuntimeFeatureSet {
        members.iter().copied().collect()
    }
    fn bug<T>(r: &DResult<T>) -> bool {
        matches!(r, Err(Diagnostic::CompilerBug { .. }))
    }
    let reactor_without_tokio = vendored_tokio_for(Target::Native, true, &set(&[]));
    assert!(
        bug(&reactor_without_tokio),
        "a reactor program with no tokio feature must refuse: {reactor_without_tokio:?}"
    );
    let server_without_reactor =
        vendored_tokio_for(Target::Native, false, &set(&[RuntimeFeature::Server]));
    assert!(
        bug(&server_without_reactor),
        "a tokio surface without the reactor must refuse: {server_without_reactor:?}"
    );
    assert!(matches!(
        vendored_tokio_for(Target::Native, false, &set(&[RuntimeFeature::Compression])),
        Ok(None)
    ));
    assert!(matches!(
        vendored_tokio_for(Target::Native, false, &set(&[])),
        Ok(None)
    ));
    let async_only = vendored_tokio_for(Target::Native, true, &set(&[RuntimeFeature::Async]));
    assert!(
        matches!(async_only, Ok(Some(ref tokio)) if *tokio == tokio_base_features()),
        "an async-only program declares the base set: {async_only:?}"
    );
}

/// A wasip1 vendored emit declares no tokio line, reactor or not.
///
/// The wasip1 reactor spine is the std-only `block_on`: a program reaching
/// `File`, `Time.sleep` or `Task` on wasip1 sets the reactor flag with an empty
/// tokio projection, and must emit, not refuse. A wasip1 feature set that
/// enables tokio, and the browser target, refuse at `ipe` time.
#[test]
fn wasip1_vendored_tokio_is_never_declared() {
    fn set(members: &[RuntimeFeature]) -> RuntimeFeatureSet {
        members.iter().copied().collect()
    }
    for reactor in [true, false] {
        let resolved = vendored_tokio_for(Target::WasmWasi, reactor, &set(&[]));
        assert!(
            matches!(resolved, Ok(None)),
            "a wasip1 program (reactor {reactor}) declares no tokio line: {resolved:?}"
        );
        let server = vendored_tokio_for(Target::WasmWasi, reactor, &set(&[RuntimeFeature::Server]));
        assert!(
            matches!(server, Err(Diagnostic::CompilerBug { .. })),
            "a wasip1 feature set enabling tokio must refuse: {server:?}"
        );
        let browser = vendored_tokio_for(Target::WasmClient, reactor, &set(&[]));
        assert!(
            matches!(browser, Err(Diagnostic::CompilerBug { .. })),
            "the browser target never resolves a vendored tokio line: {browser:?}"
        );
    }
}

/// The db augmenter for the sqlite driver, as a one-argument augmenter.
fn sqlite_db_cargo_toml(base: &str) -> DResult<String> {
    db_cargo_toml(base, crate::DbDriver::Sqlite)
}

/// One vendored manifest augmenter, named for its failure messages.
type Augmenter = (&'static str, fn(&str) -> DResult<String>);

/// Every vendored `Cargo.toml` augmenter in its emit order (`ffi_cargo_toml`,
/// which only splices dependency lines, needs an emit context and is absent).
const AUGMENTERS: &[Augmenter] = &[
    ("db", sqlite_db_cargo_toml),
    ("server", server_cargo_toml),
    ("web", web_cargo_toml),
    ("tui", tui_cargo_toml),
    ("webview", webview_cargo_toml),
    ("websocket", websocket_cargo_toml),
    ("email", email_cargo_toml),
    ("locale", locale_cargo_toml),
    ("http_client", http_client_cargo_toml),
    ("url", url_cargo_toml),
    ("config", config_cargo_toml),
    ("compression", compression_cargo_toml),
    ("csv", csv_cargo_toml),
    ("crypto", crypto_cargo_toml),
    ("jwt", jwt_cargo_toml),
    ("crypto_core_heavy", crypto_core_heavy_cargo_toml),
    ("secret", secret_cargo_toml),
    ("dev_posture", dev_posture_cargo_toml),
];

/// The feature names `augmented` declares that `base` does not.
fn augmenter_introduced(base: &str, augmented: &str) -> Vec<String> {
    let before = declared_features(base);
    declared_features(augmented)
        .into_iter()
        .filter(|name| !before.contains(name))
        .collect()
}

/// The names a manifest's `default = [...]` line lists.
fn default_features(manifest: &str) -> Vec<String> {
    manifest
        .lines()
        .find_map(|l| l.strip_prefix("default = ["))
        .and_then(|rest| rest.split_once(']'))
        .map(|(list, _)| {
            list.split(',')
                .map(|n| n.trim().trim_matches('"').to_owned())
                .filter(|n| !n.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// No augmenter declares a feature, alone or composed in emit order, and every
/// name an augmented `default` lists is declared.
///
/// The base manifest is therefore the declared set of every augmenter
/// combination, which is what lets `vendored_cfg_features_are_declared` judge
/// the base alone.
#[test]
fn augmenters_declare_no_feature() {
    let async_base = async_runtime_cargo_toml(CARGO_TOML, &tokio_base_features())
        .expect("async base must build");
    assert!(
        augmenter_introduced(CARGO_TOML, &async_base).is_empty(),
        "the tokio restore declares no feature"
    );
    let mut drift = Vec::new();
    let mut composed = async_base.clone();
    for (name, augment) in AUGMENTERS {
        let alone = augment(&async_base);
        assert!(alone.is_ok(), "{name} augments the async base: {alone:?}");
        let Ok(alone) = alone else { return };
        for feature in augmenter_introduced(&async_base, &alone) {
            drift.push(format!("{name} (alone): declares {feature:?}"));
        }
        let next = augment(&composed);
        assert!(next.is_ok(), "{name} composes in emit order: {next:?}");
        let Ok(next) = next else { return };
        for feature in augmenter_introduced(&composed, &next) {
            drift.push(format!("{name} (composed): declares {feature:?}"));
        }
        composed = next;
    }
    let declared = declared_features(&composed);
    for feature in default_features(&composed) {
        if !declared.contains(&feature) {
            drift.push(format!("composed default lists undeclared {feature:?}"));
        }
    }
    assert!(
        default_features(&composed).len() > 10,
        "precondition: the composition promotes the augmenters' features: {composed}"
    );
    assert!(
        drift.is_empty(),
        "an augmenter declares a feature the base manifest does not, so the emits \
         that skip it test that gate as an unknown name; declare it inert in \
         templates/Cargo.toml and only promote it:\n{}",
        drift.join("\n")
    );
}

/// An augmenter that declares a name is reported, and promoting a name the base
/// does not declare refuses at `ipe` time.
#[test]
fn augmenter_declaring_a_feature_is_refused() {
    const BASE: &str = "[features]\ndefault = []\njson = []\n\n[dependencies]\n";
    let declaring = BASE.replacen("json = []\n", "json = []\nserver = []\n", 1);
    assert_eq!(augmenter_introduced(BASE, &declaring), ["server"]);
    assert!(augmenter_introduced(BASE, BASE).is_empty());
    let undeclared = promote_declared_feature(BASE, "server", "test");
    assert!(
        matches!(undeclared, Err(Diagnostic::CompilerBug { .. })),
        "promoting an undeclared feature must refuse: {undeclared:?}"
    );
    let promoted = promote_declared_feature(&declaring, "server", "test");
    assert!(
        matches!(&promoted, Ok(m) if default_features(m) == ["server"]),
        "promoting a declared feature lists it in default: {promoted:?}"
    );
    let without = CARGO_TOML.replacen("\nserver = []\n", "\n", 1);
    assert_ne!(
        without, CARGO_TOML,
        "precondition: the base declares server"
    );
    assert!(
        matches!(
            server_cargo_toml(&without),
            Err(Diagnostic::CompilerBug { .. })
        ),
        "the server augmenter refuses a base that does not declare server"
    );
    let without = CARGO_TOML.replacen("\nlocale = []\n", "\n", 1);
    assert_ne!(
        without, CARGO_TOML,
        "precondition: the base declares locale"
    );
    assert!(
        matches!(
            locale_cargo_toml(&without),
            Err(Diagnostic::CompilerBug { .. })
        ),
        "the locale augmenter refuses a base that does not declare locale"
    );
}

/// The base manifest declares the augmenter-promoted gates inert and off.
///
/// A non-server, non-jwt, non-locale emit tests each as a known name without
/// switching its code on.
#[test]
fn base_manifest_declares_gates_inert() {
    let declared = declared_features(CARGO_TOML);
    for gate in ["server", "jwt", "db", "locale"] {
        assert!(
            declared.contains(gate),
            "templates/Cargo.toml must declare {gate:?}"
        );
        assert!(
            CARGO_TOML.lines().any(|l| l == format!("{gate} = []")),
            "templates/Cargo.toml must declare {gate:?} inert"
        );
    }
    assert_eq!(default_features(CARGO_TOML), ["json"]);
    assert!(
        check_cfg_names(CARGO_TOML).contains("ipe_asan"),
        "templates/Cargo.toml must declare the `ipe_asan` check-cfg"
    );
    let jwt = jwt_cargo_toml(CARGO_TOML).expect("jwt manifest must build");
    assert!(
        !default_features(&jwt).contains(&"server".to_owned()),
        "a jwt emit leaves server off"
    );
    let locale = locale_cargo_toml(CARGO_TOML).expect("locale manifest must build");
    assert!(
        locale
            .lines()
            .any(|l| l == r#"locale = ["dep:icu_casemap", "dep:icu_locale_core"]"#)
            && !locale.lines().any(|l| l == "locale = []")
            && default_features(&locale).contains(&"locale".to_owned()),
        "the locale augmenter upgrades the inert entry and promotes it: {locale}"
    );
}

/// The cfg option names rustc knows without a `check-cfg` declaration.
const WELL_KNOWN_CFGS: &[&str] = &[
    "clippy",
    "debug_assertions",
    "doc",
    "doctest",
    "feature",
    "fmt_debug",
    "miri",
    "overflow_checks",
    "panic",
    "proc_macro",
    "relocation_model",
    "rustfmt",
    "sanitize",
    "sanitizer_cfi_generalize_pointers",
    "sanitizer_cfi_normalize_integers",
    "target_abi",
    "target_arch",
    "target_endian",
    "target_env",
    "target_family",
    "target_feature",
    "target_has_atomic",
    "target_has_atomic_equal_alignment",
    "target_has_atomic_load_store",
    "target_os",
    "target_pointer_width",
    "target_thread_local",
    "target_vendor",
    "test",
    "ub_checks",
    "unix",
    "windows",
];

/// Every cfg option name a `cfg` / `cfg_attr` predicate or a `cfg!` macro in
/// `src` tests, `feature` included, with its line.
///
/// A `cfg_attr` contributes only its predicate, never the attributes it
/// applies. A `cfg` whose body holds a `macro_rules!` metavariable (`$cfg`) is a
/// template, not a predicate, and is skipped. `#[cfg(test)]` items are read: a
/// test build of the emitted crate compiles them.
fn cfg_names(src: &str) -> Vec<(usize, String)> {
    let toks = lex(src);
    let mut found = Vec::new();
    let mut i = 0usize;
    while let Some((_, tok)) = toks.get(i) {
        let is_cfg = matches!(tok, Tok::Ident(w) if w == "cfg" || w == "cfg_attr");
        let in_attr = i
            .checked_sub(1)
            .is_some_and(|prev| matches!(toks.get(prev), Some((_, Tok::Punct('[')))));
        let as_macro = matches!(toks.get(i + 1), Some((_, Tok::Punct('!'))));
        let open = if as_macro { i + 2 } else { i + 1 };
        if is_cfg && (in_attr || as_macro) && matches!(toks.get(open), Some((_, Tok::Punct('(')))) {
            let close = matching_paren(&toks, open);
            let body = toks.get(open + 1..close).unwrap_or(&[]);
            if !body.iter().any(|(_, t)| matches!(t, Tok::Punct('$'))) {
                predicate_names(body, &mut found);
            }
            i = close;
        }
        i += 1;
    }
    found
}

/// The index of the `)` closing the `(` at `open`, or the token count when the
/// source ends first.
fn matching_paren(toks: &[(usize, Tok)], open: usize) -> usize {
    let mut depth = 0usize;
    for (k, (_, tok)) in toks.iter().enumerate().skip(open) {
        match tok {
            Tok::Punct('(') => depth += 1,
            Tok::Punct(')') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return k;
                }
            }
            _ => {}
        }
    }
    toks.len()
}

/// The option names of the first predicate in `body`: every identifier that is
/// not an `all` / `any` / `not` combinator, up to the first top-level comma.
fn predicate_names(body: &[(usize, Tok)], found: &mut Vec<(usize, String)>) {
    let mut depth = 0usize;
    for (k, (line, tok)) in body.iter().enumerate() {
        match tok {
            Tok::Punct('(') => depth += 1,
            Tok::Punct(')') => depth = depth.saturating_sub(1),
            Tok::Punct(',') if depth == 0 => return,
            Tok::Ident(name) => {
                let combinator = matches!(body.get(k + 1), Some((_, Tok::Punct('('))));
                if !combinator {
                    found.push((*line, name.clone()));
                }
            }
            _ => {}
        }
    }
}

/// The custom cfg names a manifest's `[lints.rust] unexpected_cfgs` entry
/// declares through `check-cfg`.
fn check_cfg_names(manifest: &str) -> BTreeSet<String> {
    manifest
        .lines()
        .filter(|l| l.trim_start().starts_with("unexpected_cfgs"))
        .flat_map(|l| l.split("cfg(").skip(1))
        .filter_map(|rest| rest.split_once(')').map(|(name, _)| name.trim().to_owned()))
        .collect()
}

/// The custom cfg names the runtime crate's build script declares.
fn runtime_build_check_cfg_names() -> BTreeSet<String> {
    let path = runtime_src().join("../build.rs");
    let build_rs = std::fs::read_to_string(&path)
        .map_err(|error| format!("{}: {error}", path.display()))
        .expect("the runtime build script reads");
    build_rs
        .lines()
        .filter(|l| l.contains("rustc-check-cfg="))
        .flat_map(|l| l.split("cfg(").skip(1))
        .filter_map(|rest| rest.split_once(')').map(|(name, _)| name.trim().to_owned()))
        .collect()
}

/// The names in `found` that are neither well-known nor in `declared`.
fn undeclared_custom_cfgs(
    found: &[(usize, String)],
    declared: &BTreeSet<String>,
) -> Vec<(usize, String)> {
    found
        .iter()
        .filter(|(_, n)| !WELL_KNOWN_CFGS.contains(&n.as_str()) && !declared.contains(n))
        .cloned()
        .collect()
}

/// Every custom cfg name a vendored source tests is in the vendored manifests'
/// `check-cfg` list, and that list is the runtime build script's.
#[test]
fn vendored_custom_cfgs_are_declared() {
    let from_build = runtime_build_check_cfg_names();
    assert!(
        from_build.contains("ipe_asan"),
        "precondition: the runtime build script declares `ipe_asan`: {from_build:?}"
    );
    for (name, manifest) in [
        ("templates/Cargo.toml", CARGO_TOML),
        ("WASM_CARGO_TOML", WASM_CARGO_TOML),
    ] {
        assert_eq!(
            check_cfg_names(manifest),
            from_build,
            "{name}: the check-cfg list must equal the runtime build script's"
        );
    }
    let declared = check_cfg_names(CARGO_TOML);
    let root = runtime_src();
    let mut drift = Vec::new();
    let mut custom = 0usize;
    for rel in rust_files(&root) {
        let rel_s = rel.to_string_lossy().replace('\\', "/");
        if REPLACED.contains(&rel_s.as_str()) || EXCLUDED.iter().any(|(f, _)| *f == rel_s) {
            continue;
        }
        let src = std::fs::read_to_string(root.join(rel)).expect("runtime source must read");
        let found = cfg_names(&src);
        custom += found.iter().filter(|(_, n)| declared.contains(n)).count();
        for (line, name) in undeclared_custom_cfgs(&found, &declared) {
            drift.push(format!("{rel_s}:{line}: cfg {name:?}"));
        }
    }
    for (template, text) in [
        ("templates/ipe_runtime/mod.rs", RUNTIME_MOD_RS),
        ("templates/ipe_runtime/config.rs", RUNTIME_CONFIG_RS),
        ("templates/main.rs", MAIN_RS),
    ] {
        for (line, name) in undeclared_custom_cfgs(&cfg_names(text), &declared) {
            drift.push(format!("{template}:{line}: cfg {name:?}"));
        }
    }
    for body in emitted_strings(PROJECT_RS) {
        for (_, name) in undeclared_custom_cfgs(&cfg_names(&body), &declared) {
            drift.push(format!("project.rs emitted string: cfg {name:?}"));
        }
    }
    assert!(
        custom > 0,
        "precondition: the scan reads the runtime's `ipe_asan` gates"
    );
    assert!(
        drift.is_empty(),
        "vendored sources test cfg names the vendored manifests never declare; add \
         each to the runtime build script's check-cfg and to the vendored \
         manifests' `[lints.rust]` check-cfg list:\n{}",
        drift.join("\n")
    );
}

/// The cfg-name scan reads predicates only, skips macro templates, and an
/// undeclared custom name is reported.
#[test]
fn custom_cfg_scan_reads_predicates() {
    let src = r#"
        #[cfg_attr(ipe_asan, sanitize(address = "off"), inline(never))]
        #[cfg_attr(not(ipe_asan), inline)]
        fn f() { if cfg!(unix) {} }
        #[cfg(all(target_os = "linux", feature = "web", not(custom_flag)))]
        fn g() {}
        macro_rules! m { ($(#[cfg($cfg:meta)])? $v:ident) => { $(#[cfg($cfg)])? fn $v() {} }; }
        // #[cfg(in_comment)]
    "#;
    let names: Vec<String> = cfg_names(src).into_iter().map(|(_, n)| n).collect();
    assert_eq!(
        names,
        [
            "ipe_asan",
            "ipe_asan",
            "unix",
            "target_os",
            "feature",
            "custom_flag"
        ]
    );
    let declared = check_cfg_names(
        "[lints.rust]\nunexpected_cfgs = { level = \"warn\", check-cfg = [\"cfg(ipe_asan)\"] }\n",
    );
    assert_eq!(declared, BTreeSet::from(["ipe_asan".to_owned()]));
    let undeclared: Vec<String> = undeclared_custom_cfgs(&cfg_names(src), &declared)
        .into_iter()
        .map(|(_, n)| n)
        .collect();
    assert_eq!(undeclared, ["custom_flag"]);
    let none = undeclared_custom_cfgs(&cfg_names(src), &BTreeSet::new());
    assert!(
        none.iter().any(|(_, n)| n == "ipe_asan"),
        "a manifest without the check-cfg leaves `ipe_asan` undeclared"
    );
}

/// The string literals of `project.rs` that reach the emitted app crate's own
/// sources (`main.rs` and its split modules), outside `#[cfg(test)]` items.
///
/// The vendored `ipe_runtime/mod.rs` texts (`RUNTIME_MOD_RS*`,
/// `WASM_RUNTIME_MOD_RS`) and the manifest texts (`*CARGO_TOML`) are excluded:
/// the first are read by the vendored scan, the second are not Rust.
fn app_crate_strings(src: &str) -> Vec<String> {
    let toks = lex(src);
    let mut out = Vec::new();
    let mut current_const: Option<&str> = None;
    let mut i = 0usize;
    while let Some((_, tok)) = toks.get(i) {
        if let Some(end) = test_only_item_end(&toks, i) {
            i = end + 1;
            continue;
        }
        match tok {
            Tok::Ident(kw) if kw == "const" => {
                if let (Some((_, Tok::Ident(name))), Some((_, Tok::Punct(':')))) =
                    (toks.get(i + 1), toks.get(i + 2))
                {
                    current_const = Some(name.as_str());
                }
            }
            Tok::Punct(';') => current_const = None,
            Tok::Str(s) => {
                let excluded = current_const.is_some_and(|name| {
                    name.starts_with("RUNTIME_MOD_RS")
                        || name.starts_with("WASM_RUNTIME_MOD_RS")
                        || name.ends_with("CARGO_TOML")
                });
                if !excluded {
                    out.push(s.clone());
                }
            }
            _ => {}
        }
        i += 1;
    }
    out
}

/// Every feature the emitted `main.rs` text tests is declared by both native
/// app manifests.
///
/// The dependency-model app crate declares only its allocator features, so a
/// runtime feature gate in emitted app code (such as `db` over the db-backed
/// auth wrappers) is an unknown name there and compiles its code out; the
/// emitter selects such code at emit time instead.
#[test]
fn app_crate_gates_are_declared() {
    let declared: BTreeSet<String> = declared_features(CARGO_TOML)
        .intersection(&declared_features(CARGO_DEP_TOML))
        .cloned()
        .collect();
    assert!(
        declared.contains("alloc_dlmalloc") && declared.contains("alloc_mimalloc"),
        "precondition: both native manifests declare the allocator features: {declared:?}"
    );
    let strings = app_crate_strings(PROJECT_RS);
    assert!(
        strings.iter().any(|s| s.contains("fn auth_hash_password")),
        "precondition: the scan reads the emitted wrapper texts"
    );
    let mut drift = Vec::new();
    let mut scanned = 0usize;
    let texts = std::iter::once(("templates/main.rs", MAIN_RS.to_owned())).chain(
        strings
            .into_iter()
            .map(|s| ("project.rs emitted string", s)),
    );
    for (origin, text) in texts {
        for (line, name) in gate_features(&text, true) {
            scanned += 1;
            if !declared.contains(&name) {
                drift.push(format!("{origin}:{line}: feature {name:?}"));
            }
        }
        for (line, name) in undeclared_custom_cfgs(&cfg_names(&text), &BTreeSet::new()) {
            drift.push(format!("{origin}:{line}: cfg {name:?}"));
        }
    }
    assert!(
        scanned >= 2,
        "precondition: the scan reads `main.rs`'s allocator gates"
    );
    assert!(
        drift.is_empty(),
        "emitted app code tests a name a native app manifest does not declare; \
         select the code at emit time instead of gating it:\n{}",
        drift.join("\n")
    );
}

/// A runtime feature gate in an emitted app text is reported, and a manifest
/// const's text is not read as app code.
#[test]
fn app_crate_feature_gate_is_refused() {
    let src = concat!(
        "const W: &str = \"#[cfg(feature = \\\"db\\\")]\\npub fn w() {}\\n\";\n",
        "const X_CARGO_TOML: &str = \"#[cfg(feature = \\\"web\\\")]\";\n",
        "const RUNTIME_MOD_RS_Y: &str = \"#[cfg(feature = \\\"tui\\\")]\";\n",
    );
    let strings = app_crate_strings(src);
    assert_eq!(strings.len(), 1, "only the app text is read: {strings:?}");
    let gates: Vec<String> = strings
        .iter()
        .flat_map(|s| gate_features(s, true))
        .map(|(_, n)| n)
        .collect();
    assert_eq!(gates, ["db"]);
    assert!(
        !declared_features(CARGO_DEP_TOML).contains("db"),
        "the dependency-model app crate declares no `db` feature"
    );
}

/// The db-backed Auth wrappers are emitted exactly when the program uses both
/// Auth and Db; Auth alone emits only the Db-free wrappers.
#[test]
fn auth_wrappers_follow_auth_and_db() {
    let text = |auth, db| super::auth_wrapper_texts(auth, db).concat();
    let db_backed = ["fn auth_register(", "fn auth_login(", "fn auth_set_role("];
    assert!(text(false, true).is_empty());
    assert!(text(false, false).is_empty());
    let auth_only = text(true, false);
    assert!(auth_only.contains("fn auth_hash_password("));
    for name in db_backed {
        assert!(!auth_only.contains(name), "{name} emitted without Db");
    }
    let auth_db = text(true, true);
    assert!(auth_db.contains("fn auth_hash_password("));
    for name in db_backed {
        assert!(auth_db.contains(name), "{name} missing with Auth and Db");
    }
}
