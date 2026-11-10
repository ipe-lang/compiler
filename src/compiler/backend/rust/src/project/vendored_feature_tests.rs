//! Every cargo feature a vendored runtime file names in a `cfg` is one the
//! vendored manifest declares.
//!
//! rustc evaluates a `feature = "x"` predicate naming an undeclared feature to
//! false, with only an `unexpected_cfgs` warning, so a gate naming a feature the
//! vendored `Cargo.toml` never declares compiles its code out of every vendored
//! build without a word. The scan lexes each vendored source (the runtime tree
//! the driver copies into `src/ipe_runtime/`, the trimmed `ipe_runtime/mod.rs`
//! and stub `config.rs` templates, and the `RUNTIME_MOD_RS_*` appends) and
//! refuses any feature name outside the set the vendored manifest and its
//! augmenters declare. The converse holds too: every feature an app manifest
//! declares is read by some compiled gate, so none is selected for nothing.

#![cfg(test)]

use super::{
    CARGO_DEP_TOML, CARGO_TOML, CARGO_WASM_DEP_TOML, GOLDEN as MAIN_RS, RUNTIME_CONFIG_RS,
    RUNTIME_MOD_RS, WASM_CARGO_TOML, async_runtime_cargo_toml, jwt_cargo_toml, locale_cargo_toml,
    server_cargo_toml,
};
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

/// The union of features the vendored manifest declares in any emit: the
/// template's own table plus the entries the augmenters insert.
fn vendored_declared() -> BTreeSet<String> {
    let async_base = async_runtime_cargo_toml(CARGO_TOML).expect("async base must build");
    let mut declared = declared_features(CARGO_TOML);
    for manifest in [
        server_cargo_toml(&async_base).expect("server manifest must build"),
        jwt_cargo_toml(CARGO_TOML).expect("jwt manifest must build"),
        locale_cargo_toml(CARGO_TOML).expect("locale manifest must build"),
    ] {
        declared.extend(declared_features(&manifest));
    }
    declared
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
        "vendored sources name features the vendored Cargo.toml never declares, so \
         rustc compiles their gates off in every vendored build; declare each in \
         templates/Cargo.toml (or the augmenter that promotes it) or restate the gate:\n{}",
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
    let async_base = async_runtime_cargo_toml(CARGO_TOML).expect("async base must build");
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
