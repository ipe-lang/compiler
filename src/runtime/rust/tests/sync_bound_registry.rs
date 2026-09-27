//! Drift gate: every runtime `Sync` bound on a value type parameter is owned by a kernel `Sync` registry.
//!
//! A runtime function that bounds a value type parameter `Sync`
//! (`input_checkbox_<M: Clone + Send + Sync + 'static>`) obliges the caller's
//! instantiation `Sync`. The lowerer derives that obligation from the kernel
//! registries `StdlibKernel::sync_captured_args` (an argument moved into a
//! `Send + Sync` carrier) and `StdlibKernel::sync_obliged_scheme_vars` (a scheme
//! variable no argument exposes bare). A runtime bound neither registry records
//! leaves a generic caller `Send`-only: `ipe` accepts the program and the
//! emitted crate fails `cargo build` with E0277.
//!
//! This test parses every runtime signature, collects the functions whose
//! generics or `where` clause put `Sync` on a non-closure type parameter, and
//! requires each to be classified in [`SYNC_SITES`] — a kernel symbol whose
//! registries cover exactly its `Sync` parameters, a program-entry symbol whose
//! kernels are all app entries (`StdlibKernel::is_app_entry`, which the lowerer
//! refuses with a non-concrete `Model` / `Msg`), or a runtime-internal helper.
//! A new `Sync`-bounded runtime function, a registry entry dropped from a
//! kernel, or a program entry no longer gated fails here.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ipe_kernels::StdlibKernel;

/// How a runtime function with a `Sync`-bounded value type parameter is accounted for.
enum SyncSite {
    /// An emitted kernel symbol; each kernel's registries list one entry per `Sync` parameter.
    Kernels(&'static [StdlibKernel]),
    /// A program-entry symbol emitted for these app-entry kernels.
    ///
    /// Its `Model` / `Msg` reach the call only through the app cfg record and are
    /// also bounded `Serialize + DeserializeOwned + PartialEq + IpeStringify`, so
    /// no `Sync` registry covers them: every listed kernel must instead be an
    /// app entry, whose reference the lowerer refuses unless `Model` / `Msg` are
    /// concrete (IPE-N0051) — a concrete type carries every derived bound.
    ProgramEntry(&'static [StdlibKernel]),
    /// A runtime-internal helper no kernel emits by name.
    Internal,
}

/// Every runtime function whose signature bounds a value type parameter `Sync`, classified.
const SYNC_SITES: &[(&str, SyncSite)] = &[
    (
        "html_on_raw_fixed_",
        SyncSite::Kernels(&[StdlibKernel::HtmlOnSubmit]),
    ),
    (
        "ui_on_submit_fixed_",
        SyncSite::Kernels(&[StdlibKernel::UiOnSubmit]),
    ),
    (
        "db_decode_optional",
        SyncSite::Kernels(&[StdlibKernel::DbDecOptional]),
    ),
    (
        "decode_pipeline_optional",
        SyncSite::Kernels(&[StdlibKernel::JsonDecPOptional]),
    ),
    (
        "input_checkbox_",
        SyncSite::Kernels(&[StdlibKernel::InputCheckbox]),
    ),
    (
        "input_radio_",
        SyncSite::Kernels(&[StdlibKernel::InputRadio]),
    ),
    (
        "input_radio_row_",
        SyncSite::Kernels(&[StdlibKernel::InputRadioRow]),
    ),
    (
        "web_app",
        SyncSite::ProgramEntry(&[StdlibKernel::WebApp, StdlibKernel::WebEmbed]),
    ),
    (
        "web_app_routed",
        SyncSite::ProgramEntry(&[StdlibKernel::WebApp, StdlibKernel::WebAppRouted]),
    ),
    (
        "web_embed_router",
        SyncSite::ProgramEntry(&[StdlibKernel::WebEmbed]),
    ),
    (
        "web_embed_router_routed",
        SyncSite::ProgramEntry(&[StdlibKernel::WebEmbed]),
    ),
    ("choose_store", SyncSite::Internal),
    ("proxy_routes", SyncSite::Internal),
];

/// `src` with every `//` line comment removed, so a comment inside a `where` clause cannot split a predicate.
fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The byte offset of the `>` closing a generic list whose opening `<` precedes `s`.
fn closing_angle(s: &str) -> Option<usize> {
    let mut depth = 1_usize;
    let mut prev = ' ';
    for (i, c) in s.char_indices() {
        match c {
            '<' => depth += 1,
            '>' if prev != '-' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        prev = c;
    }
    None
}

/// The byte offset where a signature ends: the body's `{` or a `;`, outside any parentheses.
fn signature_end(s: &str) -> usize {
    let mut depth = 0_usize;
    for (i, c) in s.char_indices() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth = depth.saturating_sub(1),
            '{' | ';' if depth == 0 => return i,
            _ => {}
        }
    }
    s.len()
}

/// `s` split on the commas outside every `<>`, `()`, and `[]` group.
fn split_top_level(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0_usize;
    let mut start = 0;
    let mut prev = ' ';
    for (i, c) in s.char_indices() {
        match c {
            '<' | '(' | '[' => depth += 1,
            '>' if prev != '-' => depth = depth.saturating_sub(1),
            ')' | ']' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(s.get(start..i).unwrap_or_default().trim());
                start = i + 1;
            }
            _ => {}
        }
        prev = c;
    }
    parts.push(s.get(start..).unwrap_or_default().trim());
    parts.retain(|part| !part.is_empty());
    parts
}

/// The signature patterns the scan matches, compiled once per test run.
struct Patterns {
    fn_re: regex::Regex,
    where_re: regex::Regex,
    sync_re: regex::Regex,
    closure_re: regex::Regex,
}

impl Patterns {
    fn new() -> Result<Self, regex::Error> {
        Ok(Self {
            fn_re: regex::Regex::new(r"\bpub (?:async )?fn ([a-z_][a-z0-9_]*)\s*<")?,
            where_re: regex::Regex::new(r"\bwhere\b")?,
            sync_re: regex::Regex::new(r"\bSync\b")?,
            closure_re: regex::Regex::new(r"\bFn(?:Mut|Once)?\s*\(")?,
        })
    }
}

/// The number of value type parameters each runtime function in `src` bounds `Sync`, by name.
fn sync_value_params(patterns: &Patterns, src: &str) -> BTreeMap<String, usize> {
    let Patterns {
        fn_re,
        where_re,
        sync_re,
        closure_re,
    } = patterns;
    let src = strip_line_comments(src);
    let mut found = BTreeMap::new();
    for cap in fn_re.captures_iter(&src) {
        let (Some(whole), Some(name)) = (cap.get(0), cap.get(1)) else {
            continue;
        };
        let rest = src.get(whole.end()..).unwrap_or_default();
        let Some(close) = closing_angle(rest) else {
            continue;
        };
        let generics = rest.get(..close).unwrap_or_default();
        let after = rest.get(close + 1..).unwrap_or_default();
        let signature = after.get(..signature_end(after)).unwrap_or_default();

        let mut bounds: BTreeMap<&str, String> = BTreeMap::new();
        for param in split_top_level(generics) {
            if param.starts_with('\'') || param.starts_with("const ") {
                continue;
            }
            let (ident, bound) = param.split_once(':').unwrap_or((param, ""));
            bounds.entry(ident.trim()).or_default().push_str(bound);
        }
        if let Some(clause) = where_re.find(signature) {
            let predicates = signature.get(clause.end()..).unwrap_or_default();
            for predicate in split_top_level(predicates) {
                if let Some((ident, bound)) = predicate.split_once(':')
                    && let Some(slot) = bounds.get_mut(ident.trim())
                {
                    slot.push(' ');
                    slot.push_str(bound);
                }
            }
        }
        let count = bounds
            .values()
            .filter(|bound| sync_re.is_match(bound) && !closure_re.is_match(bound))
            .count();
        if count > 0 {
            let slot = found.entry(name.as_str().to_owned()).or_insert(0);
            *slot = (*slot).max(count);
        }
    }
    found
}

fn walk(dir: &Path, patterns: &Patterns, out: &mut BTreeMap<String, usize>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, patterns, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs")
            && let Ok(content) = std::fs::read_to_string(&path)
        {
            for (name, count) in sync_value_params(patterns, &content) {
                let slot = out.entry(name).or_insert(0);
                *slot = (*slot).max(count);
            }
        }
    }
}

/// The number of `Sync` obligations `kernel`'s registries record.
const fn registry_len(kernel: StdlibKernel) -> usize {
    kernel.sync_captured_args().len() + kernel.sync_obliged_scheme_vars().len()
}

#[test]
fn every_sync_bounded_runtime_fn_is_owned_by_a_registry() {
    let runtime_src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut scanned = BTreeMap::new();
    let patterns = Patterns::new().expect("the scan patterns compile");
    walk(&runtime_src, &patterns, &mut scanned);

    let scanned_names: BTreeSet<&str> = scanned.keys().map(String::as_str).collect();
    let listed_names: BTreeSet<&str> = SYNC_SITES.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        scanned_names, listed_names,
        "the runtime functions bounding a value type parameter `Sync` must equal SYNC_SITES; \
         classify a new one (and record its kernel's obligation in \
         `sync_captured_args` / `sync_obliged_scheme_vars`), or drop a stale entry"
    );

    for (name, site) in SYNC_SITES {
        let params = scanned.get(*name).copied().unwrap_or_default();
        match site {
            SyncSite::Kernels(kernels) => {
                for &kernel in *kernels {
                    assert_eq!(
                        registry_len(kernel),
                        params,
                        "{kernel:?}: `{name}` bounds {params} value type parameter(s) `Sync`, \
                         so its `sync_captured_args` + `sync_obliged_scheme_vars` must record \
                         exactly that many obligations"
                    );
                }
            }
            SyncSite::ProgramEntry(kernels) => {
                for &kernel in *kernels {
                    assert!(
                        kernel.is_app_entry(),
                        "{kernel:?}: `{name}` is classified a program entry, so the kernel must be \
                         `StdlibKernel::is_app_entry` for the concrete Model / Msg gate to cover it"
                    );
                }
            }
            SyncSite::Internal => {
                let emitters: Vec<StdlibKernel> = StdlibKernel::ALL
                    .iter()
                    .copied()
                    .filter(|k| k.def().runtime_fn == *name)
                    .collect();
                assert!(
                    emitters.is_empty(),
                    "`{name}` is classified runtime-internal but {emitters:?} emit it"
                );
            }
        }
    }

    for &kernel in StdlibKernel::ALL {
        let runtime_fn = kernel.def().runtime_fn;
        let Some((_, site)) = SYNC_SITES.iter().find(|(name, _)| *name == runtime_fn) else {
            continue;
        };
        let owned = match site {
            SyncSite::Kernels(kernels) | SyncSite::ProgramEntry(kernels) => {
                kernels.contains(&kernel)
            }
            SyncSite::Internal => false,
        };
        assert!(
            owned,
            "{kernel:?} emits `{runtime_fn}`, which bounds a value type parameter `Sync`, \
             but SYNC_SITES does not list it for that symbol"
        );
    }
}
