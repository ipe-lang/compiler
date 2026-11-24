//! No emitted manifest or vendored source raises a rustc lint above its default.
//!
//! An emitted project builds on whatever toolchain its user has. A newer release may add a deprecation or a lint the pinned CI toolchain never
//! sees: at `warn` it only prints, while an emitted `deny`/`forbid` would turn
//! that user's build red. A `clippy::` lint never fires in a plain build, so a
//! clippy raise is outside the rule. The runtime manifest a dependency-model
//! emit bundles is held to the same rule where it is bundled
//! (`ipe-cli`'s `runtime_embed`). The other direction holds too:
//! the workspace lint policy refuses, on the pinned toolchain, every std item
//! deprecated now or scheduled for deprecation, and every emitted manifest
//! declares `rust-version` equal to the pin.

#![cfg(test)]

use super::{
    CARGO_DEP_TOML, CARGO_TOML, CARGO_WASM_DEP_TOML, EMITTED_MANIFESTS, GOLDEN as MAIN_RS,
    RUNTIME_CONFIG_RS, RUNTIME_MOD_RS, RUST_TOOLCHAIN_TOML, WASM_CARGO_TOML,
    async_runtime_cargo_toml, compression_cargo_toml, config_cargo_toml, crypto_cargo_toml,
    crypto_core_heavy_cargo_toml, csv_cargo_toml, db_cargo_toml, dev_posture_cargo_toml,
    email_cargo_toml, every_manifest_declares_the_pin, http_client_cargo_toml, jwt_cargo_toml,
    locale_cargo_toml, secret_cargo_toml, server_cargo_toml, substitute_dep_manifest_anchors,
    tui_cargo_toml, url_cargo_toml, web_cargo_toml, websocket_cargo_toml, webview_cargo_toml,
};
use crate::crate_specs::tokio_base_features;
use ipe_diagnostics::DResult;
use proc_macro2::{Delimiter, TokenStream, TokenTree};
use std::path::{Path, PathBuf};

/// The lint levels a manifest may set: the ones that never fail a build.
const BUILD_SAFE_LEVELS: &[&str] = &["allow", "warn"];

/// The lints the workspace denies against deprecated std items.
///
/// The pinned toolchain then refuses an item deprecated now or scheduled for
/// deprecation.
const DEPRECATION_LINTS: &[&str] = &["deprecated", "deprecated_in_future"];

/// The db augmenter for the sqlite driver, as a one-argument augmenter.
fn sqlite_db_cargo_toml(base: &str) -> DResult<String> {
    db_cargo_toml(base, crate::DbDriver::Sqlite)
}

/// One vendored manifest augmenter, named for its failure messages.
type Augmenter = (&'static str, fn(&str) -> DResult<String>);

/// Every vendored `Cargo.toml` augmenter, in emit order.
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

/// The level a `[lints.<tool>]` entry sets.
///
/// Either form: `lint = "level"` or `lint = { level = "level", ... }`.
fn entry_level(value: &toml::Value) -> Option<&str> {
    value
        .as_str()
        .map_or_else(|| value.get("level").and_then(toml::Value::as_str), Some)
}

/// Every `[lints.<tool>]` entry of `manifest` set above `allow`/`warn`.
///
/// Each is rendered `tool.lint = level`, sorted; `[lints.rust]` names in
/// `exempt` are skipped. The count of entries read rides along so a scan is
/// never vacuous.
fn raised_lints(manifest: &str, exempt: &[&str]) -> Result<(Vec<String>, usize), String> {
    let doc: toml::Table = manifest.parse().map_err(|e| format!("{e}"))?;
    let mut raised = Vec::new();
    let mut read = 0usize;
    let Some(lints) = doc.get("lints").and_then(toml::Value::as_table) else {
        return Ok((raised, read));
    };
    for (tool, entries) in lints {
        let Some(entries) = entries.as_table() else {
            if tool != "workspace" {
                raised.push(format!("lints.{tool} is not a table"));
            }
            continue;
        };
        for (lint, value) in entries {
            read += 1;
            if tool == "rust" && exempt.contains(&lint.as_str()) {
                continue;
            }
            match entry_level(value) {
                Some(level) if BUILD_SAFE_LEVELS.contains(&level) => {}
                level => raised.push(format!("{tool}.{lint} = {level:?}")),
            }
        }
    }
    raised.sort();
    Ok((raised, read))
}

/// Every manifest an emit writes.
///
/// The templates (dependency-model anchors substituted) and the vendored base
/// under each augmenter, alone and composed.
#[allow(clippy::expect_used)] // test scaffolding: every augmenter composes on the async base
fn emitted_manifest_renders() -> Vec<(String, String)> {
    let mut renders = vec![
        ("templates/Cargo.toml".to_owned(), CARGO_TOML.to_owned()),
        ("WASM_CARGO_TOML".to_owned(), WASM_CARGO_TOML.to_owned()),
        (
            "templates/Cargo.dep.toml".to_owned(),
            substitute_dep_manifest_anchors(CARGO_DEP_TOML, &["json"], "lint-level test")
                .expect("the dep template carries its anchor"),
        ),
        (
            "templates/Cargo.wasm-dep.toml".to_owned(),
            substitute_dep_manifest_anchors(CARGO_WASM_DEP_TOML, &["json"], "lint-level test")
                .expect("the wasm dep template carries its anchor"),
        ),
    ];
    let async_base = async_runtime_cargo_toml(CARGO_TOML, &tokio_base_features())
        .expect("the async base builds");
    let mut composed = async_base.clone();
    for (name, augment) in AUGMENTERS {
        renders.push((
            format!("{name} (alone)"),
            augment(&async_base).expect("the augmenter applies alone"),
        ));
        composed = augment(&composed).expect("the augmenter composes in emit order");
    }
    renders.push(("every augmenter composed".to_owned(), composed));
    renders
}

/// No emitted manifest sets a lint above `warn`.
#[test]
fn emitted_manifests_raise_no_lint_level() {
    let mut drift = Vec::new();
    let mut read = 0usize;
    for (name, manifest) in emitted_manifest_renders() {
        match raised_lints(&manifest, &[]) {
            Ok((raised, entries)) => {
                read += entries;
                drift.extend(raised.into_iter().map(|r| format!("{name}: {r}")));
            }
            Err(error) => drift.push(format!("{name}: does not parse: {error}")),
        }
    }
    assert!(read > 0, "precondition: the scan reads `unexpected_cfgs`");
    assert!(
        drift.is_empty(),
        "an emitted manifest raises a lint a newer toolchain can fire on, failing \
         the user's build; keep it at `warn`:\n{}",
        drift.join("\n")
    );
}

/// A manifest raising a rustc or clippy lint is refused, in either entry form.
#[test]
fn a_raised_manifest_lint_is_refused() {
    let fixture = "[package]\nname = \"x\"\n\n[lints.rust]\ndeprecated = \"deny\"\n\
                   unexpected_cfgs = { level = \"warn\", check-cfg = [] }\n\n\
                   [lints.clippy]\npedantic = { level = \"forbid\", priority = -1 }\n";
    let raised = raised_lints(fixture, &[]);
    assert_eq!(
        raised,
        Ok((
            vec![
                "clippy.pedantic = Some(\"forbid\")".to_owned(),
                "rust.deprecated = Some(\"deny\")".to_owned(),
            ],
            3
        ))
    );
    let exempt = raised_lints(fixture, &["deprecated"]);
    assert_eq!(
        exempt.map(|(raised, _)| raised),
        Ok(vec!["clippy.pedantic = Some(\"forbid\")".to_owned()])
    );
}

/// Every `.rs` file under `dir`, sorted.
#[allow(clippy::expect_used)] // test scaffolding: the runtime tree is readable
fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(at) = stack.pop() {
        for entry in std::fs::read_dir(&at).expect("the runtime tree reads") {
            let path = entry.expect("the runtime entry reads").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// The tokens of `stream` split at its top-level commas.
fn comma_split(stream: TokenStream) -> Vec<Vec<TokenTree>> {
    let mut parts = vec![Vec::new()];
    for tree in stream {
        if matches!(&tree, TokenTree::Punct(p) if p.as_char() == ',') {
            parts.push(Vec::new());
        } else if let Some(last) = parts.last_mut() {
            last.push(tree);
        }
    }
    parts.retain(|part| !part.is_empty());
    parts
}

/// The identifier `tokens` consists of, when it is exactly one.
fn sole_ident(tokens: &[TokenTree]) -> Option<String> {
    match tokens {
        [TokenTree::Ident(ident)] => Some(ident.to_string()),
        _ => None,
    }
}

/// Every non-`clippy::` lint the attribute body `attr` denies or forbids.
///
/// Read at any `cfg_attr` depth except under a bare `test` or `clippy`
/// predicate.
fn attribute_raises(attr: &[TokenTree], out: &mut Vec<String>) {
    let (Some(TokenTree::Ident(name)), Some(TokenTree::Group(args))) = (attr.first(), attr.get(1))
    else {
        return;
    };
    if args.delimiter() != Delimiter::Parenthesis {
        return;
    }
    let name = name.to_string();
    let parts = comma_split(args.stream());
    if name == "deny" || name == "forbid" {
        for lint in parts {
            let is_clippy =
                matches!(lint.first(), Some(TokenTree::Ident(tool)) if tool == "clippy");
            if !is_clippy {
                let path: String = lint.iter().map(ToString::to_string).collect();
                out.push(format!("{name}({path})"));
            }
        }
    } else if name == "cfg_attr" {
        let mut parts = parts.into_iter();
        let predicate = parts.next().unwrap_or_default();
        if matches!(sole_ident(&predicate).as_deref(), Some("test" | "clippy")) {
            return;
        }
        for inner in parts {
            attribute_raises(&inner, out);
        }
    }
}

/// Every rustc lint raise in an attribute anywhere in `stream`, with its line.
fn stream_raises(stream: TokenStream, out: &mut Vec<String>) {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    for (at, tree) in trees.iter().enumerate() {
        let TokenTree::Group(group) = tree else {
            continue;
        };
        let punct_before = |back: usize, ch: char| {
            matches!(
                at.checked_sub(back).and_then(|k| trees.get(k)),
                Some(TokenTree::Punct(p)) if p.as_char() == ch
            )
        };
        let is_attribute = group.delimiter() == Delimiter::Bracket
            && (punct_before(1, '#') || (punct_before(1, '!') && punct_before(2, '#')));
        if is_attribute {
            let body: Vec<TokenTree> = group.stream().into_iter().collect();
            let mut found = Vec::new();
            attribute_raises(&body, &mut found);
            let line = group.span().start().line;
            out.extend(
                found
                    .into_iter()
                    .map(|raise| format!("line {line}: {raise}")),
            );
        } else {
            stream_raises(group.stream(), out);
        }
    }
}

/// Every rustc lint raise in an attribute of the Rust source `src`.
fn source_raises(src: &str) -> Result<Vec<String>, String> {
    let stream: TokenStream = src.parse().map_err(|e| format!("{e:?}"))?;
    let mut out = Vec::new();
    stream_raises(stream, &mut out);
    Ok(out)
}

/// No vendored source or emitted template raises a rustc lint level.
#[test]
#[allow(clippy::expect_used)] // test scaffolding: the runtime sources are readable
fn vendored_sources_raise_no_rustc_lint() {
    let runtime_src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../runtime/rust/src");
    let mut sources: Vec<(String, String)> = rust_files(&runtime_src)
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path).expect("runtime source reads");
            (path.display().to_string(), text)
        })
        .collect();
    assert!(
        sources.iter().any(|(path, _)| path.ends_with("mod.rs")),
        "precondition: the scan reads the runtime crate root"
    );
    for (name, text) in [
        ("templates/ipe_runtime/mod.rs", RUNTIME_MOD_RS),
        ("templates/ipe_runtime/config.rs", RUNTIME_CONFIG_RS),
        ("templates/main.rs", MAIN_RS),
    ] {
        sources.push((name.to_owned(), text.to_owned()));
    }
    let mut drift = Vec::new();
    for (name, text) in &sources {
        match source_raises(text) {
            Ok(raises) => drift.extend(raises.into_iter().map(|r| format!("{name}: {r}"))),
            Err(error) => drift.push(format!("{name}: does not lex: {error}")),
        }
    }
    assert!(
        drift.is_empty(),
        "a vendored source denies or forbids a rustc lint, so a newer toolchain \
         that starts firing it fails the user's build; leave it at its default \
         (a `clippy::` lint, or a `cfg_attr(test|clippy, ...)` raise, is outside \
         the rule):\n{}",
        drift.join("\n")
    );
}

/// The attribute scan refuses a rustc raise at any `cfg_attr` depth.
///
/// Clippy-only, test-only and clippy-run-only raises pass.
#[test]
fn a_rustc_lint_raise_in_source_is_refused() {
    let src = "#![deny(warnings)]\n\
               #![cfg_attr(not(test), deny(clippy::panic, clippy::todo))]\n\
               #![cfg_attr(test, deny(unused))]\n\
               #![cfg_attr(clippy, forbid(dead_code))]\n\
               mod m {\n\
                   #[cfg_attr(feature = \"x\", forbid(rust_2018_idioms, clippy::unwrap_used))]\n\
                   fn f() { #[deny(deprecated)] let _x = 1; }\n\
               }\n";
    assert_eq!(
        source_raises(src),
        Ok(vec![
            "line 1: deny(warnings)".to_owned(),
            "line 6: forbid(rust_2018_idioms)".to_owned(),
            "line 7: deny(deprecated)".to_owned(),
        ])
    );
}

/// The root lint table and every own `[lints.rust]` deny both deprecation lints.
#[test]
#[allow(clippy::expect_used)] // test scaffolding: the repository manifests are readable
fn workspace_denies_every_deprecation_lint() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..");
    for (rel, table_path) in [
        ("Cargo.toml", &["workspace", "lints", "rust"][..]),
        ("tools/ipe-ffi-inspector/Cargo.toml", &["lints", "rust"][..]),
        ("tools/ipe-index/Cargo.toml", &["lints", "rust"][..]),
        ("src/runtime/rust/Cargo.toml", &["lints", "rust"][..]),
    ] {
        let text = std::fs::read_to_string(repo.join(rel)).expect("manifest reads");
        let doc: toml::Table = text.parse().expect("manifest parses");
        let mut table = Some(&doc);
        for key in table_path {
            table = table
                .and_then(|t| t.get(*key))
                .and_then(toml::Value::as_table);
        }
        for lint in DEPRECATION_LINTS {
            let level = table.and_then(|t| t.get(*lint)).and_then(entry_level);
            assert_eq!(
                level,
                Some("deny"),
                "{rel}: `{lint}` must be denied so the pinned toolchain refuses a \
                 deprecated or deprecation-scheduled std item"
            );
        }
    }
}

/// Every emitted manifest's `rust-version` is the pinned channel.
///
/// A drift, a missing declaration or an unnamed channel is refused.
#[test]
fn emitted_rust_version_is_the_pin() {
    assert!(every_manifest_declares_the_pin(
        RUST_TOOLCHAIN_TOML.as_bytes(),
        EMITTED_MANIFESTS
    ));
    let toolchain = b"[toolchain]\nchannel = \"1.98.1\"\n".as_slice();
    let pinned = b"[package]\nname = \"x\"\nrust-version = \"1.98.1\"\n".as_slice();
    let drifted = b"[package]\nname = \"x\"\nrust-version = \"1.98\"\n".as_slice();
    let missing = b"[package]\nname = \"x\"\n".as_slice();
    let unterminated = b"[package]\nrust-version = \"1.98.1\nx = 1\"\n".as_slice();
    assert!(every_manifest_declares_the_pin(toolchain, &[pinned]));
    assert!(!every_manifest_declares_the_pin(
        toolchain,
        &[pinned, drifted]
    ));
    assert!(!every_manifest_declares_the_pin(toolchain, &[missing]));
    assert!(!every_manifest_declares_the_pin(toolchain, &[unterminated]));
    assert!(!every_manifest_declares_the_pin(
        b"[toolchain]\nchannel = \"\"\n",
        &[pinned]
    ));
    assert!(!every_manifest_declares_the_pin(
        b"[toolchain]\n",
        &[pinned]
    ));
}
