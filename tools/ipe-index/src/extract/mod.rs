pub mod ipe;
pub mod treesitter;
pub mod view;

use crate::model::{Kind, Lang, facing_of};
use crate::static_re::StaticRegex;
use crate::store::{Store, unit_uid};
use anyhow::{Context, Result};
use std::collections::HashMap;

static RE_SH_SOURCE: StaticRegex = StaticRegex::new(r"^\s*(?:source|\.)\s+(\S+)");
static RE_SH_FUNC: StaticRegex =
    StaticRegex::new(r"^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*\{?");

/// The crate-root segment of a Rust `qualified` name: the directory that owns
/// the crate's `src/` (its basename), so two crates each defining `parse` yield
/// distinct roots (`backend::parse`, `ffi::parse`) instead of a colliding
/// `crate::parse`. Falls back to `crate` when no `src/` ancestor is found.
pub fn rust_crate_root(rel: &str) -> String {
    let parts: Vec<&str> = rel.split('/').collect();
    // The crate root is the directory owning the deepest `src/` — the same
    // anchor `module_path` uses for the module chain, so a nested crate roots
    // at its own directory, not an ancestor's.
    match parts.iter().rposition(|p| *p == "src") {
        Some(0) | None => "crate".to_string(),
        Some(i) => parts[i - 1].to_string(),
    }
}

/// Language-aware module path for a repo-tagged file path:
/// - Ipe: dotted module name (`Ipe.Core.List`), stripping `src/stdlib/`/`src/` roots
/// - Rust: `<crate>::a::b` chain rooted at the crate's directory basename so
///   identical module chains in different crates stay distinct
/// - Ts: file path, separators as dots, minus tag + extension
/// - Bash: the bare relative path
pub fn module_path(path: &str, lang: Lang) -> String {
    let (_tag, rel) = crate::model::split_tag(path);
    match lang {
        Lang::Ipe => {
            let rel = rel
                .strip_prefix("src/stdlib/")
                .or_else(|| rel.strip_prefix("src/"))
                .unwrap_or(rel);
            rel.strip_suffix(".ipe").unwrap_or(rel).replace('/', ".")
        }
        Lang::Rust => {
            let root = rust_crate_root(rel);
            let mut parts: Vec<&str> = rel.split('/').collect();
            parts.pop(); // the file itself
            let chain = match parts.iter().rposition(|p| *p == "src") {
                Some(i) => &parts[i + 1..],
                None => &parts[..],
            };
            if chain.is_empty() {
                root
            } else {
                format!("{root}::{}", chain.join("::"))
            }
        }
        Lang::Ts => {
            let rel = rel
                .strip_suffix(".ts")
                .or_else(|| rel.strip_suffix(".tsx"))
                .or_else(|| rel.strip_suffix(".mts"))
                .or_else(|| rel.strip_suffix(".js"))
                .or_else(|| rel.strip_suffix(".jsx"))
                .or_else(|| rel.strip_suffix(".mjs"))
                .unwrap_or(rel);
            rel.replace('/', ".")
        }
        _ => rel.to_string(),
    }
}

/// Bundled `emit_unit` inputs. The old positional signature exceeded clippy's
/// `too_many_arguments` limit, so the unit's identity + span travel as one spec.
pub struct UnitSpec<'a> {
    pub path: &'a str,
    pub kind: Kind,
    pub name: &'a str,
    pub qualified: &'a str,
    pub line_start: i64,
    pub line_end: i64,
    pub facing: crate::model::Facing,
    pub purpose: Option<String>,
    pub updated_sha: &'a str,
}

/// The text a unit's `body_hash` attests.
pub enum UnitBody<'a> {
    /// Lines `line_start..=line_end` of the source (`view::view_text`).
    Span,
    /// A `file` unit's residual (`residual_text`): the lines no child covers.
    Residual(&'a str),
}

/// Emit one `units` row whose body is its span.
///
/// Duplicate `(path, kind, qualified)` identities (e.g. several `impl` blocks
/// of the same type in one file) get an ordinal suffix (`#2`) so each keeps a
/// distinct, stable uid. A span outside `src` is an extractor bug and refuses
/// the file. Returns the unit's uid.
pub fn emit_unit(
    store: &Store,
    src: &str,
    spec: UnitSpec,
    ord: &mut HashMap<(String, String), i64>,
) -> Result<String> {
    emit_attested_unit(store, src, spec, &UnitBody::Span, ord)
}

/// Emit one `units` row attesting `body`.
///
/// The body hash is computed here and only here, as `view::attest` of the
/// text `body` names, so a row's hash and the text it attests cannot be chosen
/// apart.
fn emit_attested_unit(
    store: &Store,
    src: &str,
    spec: UnitSpec,
    body: &UnitBody,
    ord: &mut HashMap<(String, String), i64>,
) -> Result<String> {
    let UnitSpec {
        path,
        kind,
        name,
        qualified,
        line_start,
        line_end,
        facing,
        purpose,
        updated_sha,
    } = spec;
    let text = match body {
        UnitBody::Span => view::view_text(src, line_start, line_end).with_context(|| {
            format!("{path}: unit `{qualified}` span {line_start}..={line_end}")
        })?,
        UnitBody::Residual(residual) => (*residual).to_string(),
    };
    let key = (path.to_string(), format!("{}|{qualified}", kind.as_str()));
    let n = ord.entry(key).or_insert(0);
    let q = if *n == 0 {
        qualified.to_string()
    } else {
        format!("{qualified}#{}", *n + 1)
    };
    *n += 1;
    let unit = crate::model::Unit {
        path: path.to_string(),
        kind,
        name: name.to_string(),
        qualified: q.clone(),
        line_start,
        line_end,
        facing,
        purpose,
        body_hash: view::attest(&text),
        updated_sha: updated_sha.to_string(),
    };
    store.put_unit(&unit)?;
    Ok(unit_uid(path, kind, &q))
}

/// First line of the leading `#` comment block directly above `line` in `src`
/// (walked upward; stops at the first non-comment line), with the `#` stripped.
/// No comment block → `None` (never fabricates).
fn bash_doc_purpose(src: &str, line: i64) -> Option<String> {
    let lines: Vec<&str> = src.lines().collect();
    let mut top: Option<String> = None;
    let above = usize::try_from(line.saturating_sub(1)).unwrap_or(0);
    for l in lines.iter().take(above).rev() {
        let t = l.trim_start();
        if let Some(rest) = t.strip_prefix('#') {
            // The FIRST line of the block is the topmost (last visited).
            top = Some(rest.trim_start().to_string());
        } else {
            break;
        }
    }
    top.filter(|s| !s.is_empty())
}

/// Extract symbols + import edges + units for one file's contents. Bounded:
/// caller passes the already-read `src`; tree-sitter trees are created + dropped
/// inside. `updated_sha` is the git sha the extraction is attributed to.
pub fn extract_file(
    store: &Store,
    path: &str,
    lang: Lang,
    src: &str,
    updated_sha: &str,
) -> Result<()> {
    let line_count = view::view_line_count(src);
    let mut ord: HashMap<(String, String), i64> = HashMap::new();
    match lang {
        Lang::Ipe => {
            let r = ipe::scan_ipe(src)?;
            for i in r.imports {
                store.put_edge(path, &i, "import")?;
            }
            let base = r.module.clone().unwrap_or_else(|| module_path(path, lang));
            for b in &r.bindings {
                store.put_symbol(path, &b.name, "binding", b.line, 0)?;
                emit_unit(
                    store,
                    src,
                    UnitSpec {
                        path,
                        kind: Kind::Binding,
                        name: &b.name,
                        qualified: &format!("{base}.{}", b.name),
                        line_start: b.line,
                        line_end: b.line_end,
                        facing: facing_of(path, ipe::is_pub(&r.exposing, &b.name)),
                        purpose: ipe::doc_purpose(src, b.line),
                        updated_sha,
                    },
                    &mut ord,
                )?;
            }
        }
        Lang::Bash => {
            let (re_source, re_func) = (RE_SH_SOURCE.get()?, RE_SH_FUNC.get()?);
            let mut funcs: Vec<(String, i64)> = Vec::new();
            for (i, line) in src.lines().enumerate() {
                if let Some(m) = re_source.captures(line).and_then(|c| c.get(1)) {
                    store.put_edge(path, m.as_str(), "import")?;
                } else if let Some(m) = re_func.captures(line).and_then(|c| c.get(1)) {
                    let name = m.as_str().to_string();
                    store.put_symbol(path, &name, "def", i as i64 + 1, 0)?;
                    funcs.push((name, i as i64 + 1));
                }
            }
            for (idx, (name, line)) in funcs.iter().enumerate() {
                let end = funcs.get(idx + 1).map_or(line_count, |(_, l)| l - 1);
                emit_unit(
                    store,
                    src,
                    UnitSpec {
                        path,
                        kind: Kind::Fn,
                        name,
                        qualified: &format!("{}::{name}", module_path(path, lang)),
                        line_start: *line,
                        line_end: end,
                        facing: facing_of(path, false),
                        purpose: bash_doc_purpose(src, *line),
                        updated_sha,
                    },
                    &mut ord,
                )?;
            }
        }
        Lang::Rust | Lang::Ts => {
            treesitter::extract(store, path, lang, src, updated_sha, &mut ord)?
        }
        Lang::Other => return Ok(()),
    }
    // Whole-file unit: the lines no other unit of the file covers. A file whose
    // children cover every non-blank line leaves nothing to review and gets no
    // file unit.
    let residual = residual_text(src, &store.child_spans(path)?);
    if residual.is_empty() {
        return Ok(());
    }
    let name = crate::model::split_tag(path)
        .1
        .rsplit('/')
        .next()
        .unwrap_or(path)
        .to_string();
    let base = module_path(path, lang);
    emit_attested_unit(
        store,
        src,
        UnitSpec {
            path,
            kind: Kind::File,
            name: &name,
            qualified: &format!("{base}::FILE"),
            line_start: 1,
            line_end: line_count,
            facing: facing_of(path, false),
            purpose: None,
            updated_sha,
        },
        &UnitBody::Residual(&residual),
        &mut ord,
    )?;
    Ok(())
}

/// The lines of `src` no span in `spans` covers, blank lines dropped, each run
/// of covered lines marked by one `"\0"` line: the content a `file` unit
/// reviews beyond its children.
///
/// A file unit's `body_hash` attests it, so editing a child queues the child
/// alone while editing an import, attribute or other top-level line queues
/// the file. Spans are 1-based inclusive; a span outside `src` covers only its
/// in-range part. The rule is pinned for both sides by
/// `tests/residual_vectors.json`.
pub fn residual_text(src: &str, spans: &[(i64, i64)]) -> String {
    let lines = view::view_lines(src);
    let mut covered = vec![false; lines.len()];
    for &(start, end) in spans {
        let first = usize::try_from(start.saturating_sub(1)).unwrap_or(0);
        let Ok(last) = usize::try_from(end) else {
            continue;
        };
        for slot in covered.iter_mut().take(last).skip(first) {
            *slot = true;
        }
    }
    let mut out: Vec<&str> = Vec::new();
    let mut gap = false;
    for (line, is_covered) in lines.into_iter().zip(covered) {
        if is_covered {
            gap = true;
        } else if !line.trim().is_empty() {
            if gap && !out.is_empty() {
                out.push("\0");
            }
            gap = false;
            out.push(line);
        }
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    #[test]
    fn built_in_shell_patterns_compile() {
        assert!(RE_SH_SOURCE.get().is_ok());
        assert!(RE_SH_FUNC.get().is_ok());
    }

    const RESIDUAL_VECTORS: &str = include_str!("../../tests/residual_vectors.json");

    #[test]
    fn residual_text_matches_the_shared_vectors() {
        let rows: Vec<serde_json::Value> = serde_json::from_str(RESIDUAL_VECTORS).unwrap();
        assert!(
            rows.len() >= 15,
            "the shared residual vector file lost rows"
        );
        for row in rows {
            let name = row["name"].as_str().unwrap();
            let src = row["src"].as_str().unwrap();
            let spans: Vec<(i64, i64)> = row["spans"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| (s[0].as_i64().unwrap(), s[1].as_i64().unwrap()))
                .collect();
            let residual = row["residual"].as_str().unwrap();
            assert_eq!(residual_text(src, &spans), residual, "{name}: residual");
            assert_eq!(
                view::attest(residual),
                row["hash"].as_str().unwrap(),
                "{name}: hash"
            );
        }
    }

    #[test]
    fn residual_keeps_uncovered_lines_and_marks_gaps() {
        let src = "use a;\n\nfn f() {\n}\nconst X: u8 = 1;\nfn g() {}\n";
        assert_eq!(
            residual_text(src, &[(3, 4), (6, 6)]),
            "use a;\n\0\nconst X: u8 = 1;"
        );
        // No spans: every non-blank line.
        assert_eq!(residual_text(src, &[]).lines().count(), 5);
        // Out-of-range and inverted spans cover nothing past the source.
        assert_eq!(
            residual_text("a\nb\n", &[(i64::MIN, 0), (2, i64::MAX), (5, 1)]),
            "a"
        );
    }

    fn file_key(store: &Store, path: &str) -> String {
        store
            .conn
            .query_row(
                "SELECT body_hash FROM units WHERE path=? AND kind='file'",
                [path],
                |r| r.get(0),
            )
            .unwrap()
    }

    // A file unit attests its residual, never its whole file, and leaves the
    // legacy residual column unwritten.
    #[test]
    fn a_file_unit_hash_is_its_residual() {
        let store = Store::open(":memory:").unwrap();
        let src = "use a;\n\nfn f() -> u8 {\n    1\n}\n";
        extract_file(&store, "m.rs", Lang::Rust, src, "sha").unwrap();
        let residual = residual_text(src, &store.child_spans("m.rs").unwrap());
        assert_eq!(residual, "use a;");
        assert_eq!(file_key(&store, "m.rs"), view::attest(&residual));
        assert_ne!(
            file_key(&store, "m.rs"),
            view::attest(&view::view_text(src, 1, view::view_line_count(src)).unwrap())
        );
        let legacy: Option<String> = store
            .conn
            .query_row(
                "SELECT residual_hash FROM units WHERE kind='file'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(legacy, None);
    }

    fn file_units(store: &Store) -> i64 {
        store
            .conn
            .query_row("SELECT COUNT(*) FROM units WHERE kind='file'", [], |r| {
                r.get(0)
            })
            .unwrap()
    }

    // A file its children cover entirely has nothing left to review: no file
    // unit, so a first index queues only the children.
    #[test]
    fn a_file_with_no_residual_emits_no_unit_and_no_queue_row() {
        let store = Store::open(":memory:").unwrap();
        extract_file(&store, "m.rs", Lang::Rust, "pub fn f() {}\n\n", "sha").unwrap();
        assert_eq!(file_units(&store), 0);
        assert!(store.count("units").unwrap() > 0);
        let after = store.snapshot_path("m.rs").unwrap();
        let ops = crate::diff::reconcile(&crate::diff::Snapshot::new(), &after);
        assert_eq!(
            i64::try_from(ops.len()).unwrap(),
            store.count("units").unwrap()
        );
    }

    // A top-level line added to a fully covered file brings its file unit, and
    // the queue gains it as `new`.
    #[test]
    fn adding_a_top_level_line_queues_the_file_unit_new() {
        let extracted = |src: &str| {
            let store = Store::open(":memory:").unwrap();
            extract_file(&store, "m.rs", Lang::Rust, src, "sha").unwrap();
            store
        };
        let before_store = extracted("pub fn f() {}\n");
        assert_eq!(file_units(&before_store), 0);
        let before = before_store.snapshot_path("m.rs").unwrap();
        let after_store = extracted("use a;\npub fn f() {}\n");
        let after = after_store.snapshot_path("m.rs").unwrap();
        let file_uid: String = after_store
            .conn
            .query_row("SELECT uid FROM units WHERE kind='file'", [], |r| r.get(0))
            .unwrap();
        let ops: Vec<_> = crate::diff::reconcile(&before, &after)
            .into_iter()
            .filter(|op| op.uid == file_uid)
            .collect();
        let new_hash = after.get(&file_uid).map(|s| s.body_hash.clone()).unwrap();
        assert_eq!(new_hash, view::attest("use a;"));
        assert_eq!(
            ops.into_iter().map(|op| op.change).collect::<Vec<_>>(),
            vec![crate::diff::Change::New { new_hash }]
        );
    }

    // The file unit's change key moves with its own lines only.
    #[test]
    fn file_key_ignores_child_bodies() {
        let key = |src: &str| {
            let store = Store::open(":memory:").unwrap();
            extract_file(&store, "m.rs", Lang::Rust, src, "sha").unwrap();
            file_key(&store, "m.rs")
        };
        let base = key("use a;\n\nfn f() -> u8 {\n    1\n}\n");
        assert_eq!(key("use a;\n\nfn f() -> u8 {\n    2\n}\n"), base);
        assert_eq!(key("use a;\n\n\nfn f() -> u8 {\n    1\n}\n"), base);
        assert_ne!(key("use b;\n\nfn f() -> u8 {\n    1\n}\n"), base);
    }

    // A line past the end of the script, or before its start, slices nothing
    // out of bounds.
    #[test]
    fn bash_doc_purpose_line_out_of_range() {
        let src = "# helper\nf() {\n";
        assert_eq!(bash_doc_purpose(src, 2), Some("helper".to_string()));
        assert_eq!(bash_doc_purpose(src, 50), None);
        assert_eq!(bash_doc_purpose(src, i64::MIN), None);
    }

    fn defs(store: &Store, path: &str) -> Vec<(String, i64)> {
        let mut st = store
            .conn
            .prepare("SELECT name,line FROM symbols WHERE file=? AND kind='def' ORDER BY line")
            .unwrap();
        st.query_map([path], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap()
    }

    // Rust impl-target capture stored as kind `impl`.
    #[test]
    fn rust_captures_impl_target() {
        let store = Store::open(":memory:").unwrap();
        let src = "struct Foo;\nimpl Foo { fn a(&self) {} }\nimpl std::fmt::Debug for Foo { }\n";
        extract_file(&store, "m.rs", Lang::Rust, src, "sha").unwrap();
        let mut st = store
            .conn
            .prepare("SELECT name,kind FROM symbols WHERE file='m.rs'")
            .unwrap();
        let rows: Vec<(String, String)> = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert!(rows.contains(&("Foo".to_string(), "def".to_string())));
        // Both impl blocks target Foo → two `impl` rows.
        assert_eq!(
            rows.iter()
                .filter(|(n, k)| n == "Foo" && k == "impl")
                .count(),
            2
        );
    }

    #[test]
    fn bash_captures_functions() {
        let store = Store::open(":memory:").unwrap();
        // Both the `name()` and `function name()` forms carry the `()` the
        // column-0 scanner keys on.
        let src = "helper() {\n  :\n}\nfunction other() {\n  :\n}\n";
        extract_file(&store, "x.sh", Lang::Bash, src, "sha").unwrap();
        let names: Vec<String> = defs(&store, "x.sh").into_iter().map(|(n, _)| n).collect();
        assert!(names.contains(&"helper".to_string()));
        assert!(names.contains(&"other".to_string()));
    }

    #[test]
    fn rust_module_path_is_crate_rooted_by_directory() {
        // A crate-root file with no owning directory (`src/…` at the top) keeps
        // the bare `crate` root; a file inside a named crate directory roots at
        // that directory so two crates never collide on a shared module chain.
        assert_eq!(module_path("ipe:src/lib.rs", Lang::Rust), "crate");
        assert_eq!(
            module_path("ipe:src/compiler/backend/src/lib.rs", Lang::Rust),
            "backend"
        );
        assert_eq!(
            module_path("ipe:src/compiler/backend/src/lower/mod.rs", Lang::Rust),
            "backend::lower"
        );
        assert_eq!(
            module_path("ipe:src/compiler/ffi/src/lib.rs", Lang::Rust),
            "ffi"
        );
    }

    #[test]
    fn rust_unit_span_covers_whole_fn() {
        let store = Store::open(":memory:").unwrap();
        let src = "pub fn list_head(xs: Vec<i64>) -> i64 {\n    0\n}\n";
        extract_file(&store, "src/lib.rs", Lang::Rust, src, "sha").unwrap();
        let row: (String, i64, i64, String) = store
            .conn
            .query_row(
                "SELECT qualified,line_start,line_end,body_hash FROM units WHERE kind='fn'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(row.0, "crate::list_head");
        assert_eq!((row.1, row.2), (1, 3)); // whole fn incl. body
        // One-byte edit → hash changes.
        let store2 = Store::open(":memory:").unwrap();
        extract_file(
            &store2,
            "src/lib.rs",
            Lang::Rust,
            "pub fn list_head(xs: Vec<i64>) -> i64 {\n    1\n}\n",
            "sha",
        )
        .unwrap();
        let h2: String = store2
            .conn
            .query_row("SELECT body_hash FROM units WHERE kind='fn'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_ne!(row.3, h2);
    }

    #[test]
    fn file_unit_exists_for_unknown_langs_only() {
        // `Other` is skipped entirely (no file unit); every indexed lang gets one.
        let store = Store::open(":memory:").unwrap();
        extract_file(&store, "foo.txt", Lang::Other, "x", "sha").unwrap();
        assert_eq!(store.count("units").unwrap(), 0);
        let store = Store::open(":memory:").unwrap();
        extract_file(
            &store,
            "src/lib.rs",
            Lang::Rust,
            "use a;\npub fn f() {}\n",
            "sha",
        )
        .unwrap();
        assert_eq!(store.count("units").unwrap(), 2); // fn + FILE
        let store = Store::open(":memory:").unwrap();
        extract_file(
            &store,
            "src/a.ipe",
            Lang::Ipe,
            "module A exposing (x)\n\nx = 1\n",
            "sha",
        )
        .unwrap();
        assert_eq!(store.count("units").unwrap(), 2); // binding + FILE
    }

    fn unit_rows(store: &Store) -> Vec<(String, i64, i64, String)> {
        let mut st = store
            .conn
            .prepare("SELECT qualified,line_start,line_end,body_hash FROM units")
            .unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn every_unit_hash_is_its_body() {
        let fixtures = [
            (
                "src/lib.rs",
                Lang::Rust,
                "struct Foo;\nimpl Foo {\n    fn a(&self) {}\n}\npub fn f() -> i64 {\n    0\n}\n",
            ),
            (
                "web/a.ts",
                Lang::Ts,
                "export function g(x: number): number {\n  return x;\n}\nclass K {}\n",
            ),
            (
                "src/A.ipe",
                Lang::Ipe,
                "module A exposing (..)\n\nhead xs = xs\n\nmap f xs = xs\n",
            ),
            (
                "tools/x.sh",
                Lang::Bash,
                "helper() {\n  :\n}\nfunction other() {\n  :\n}\n",
            ),
        ];
        for (path, lang, src) in fixtures {
            let store = Store::open(":memory:").unwrap();
            extract_file(&store, path, lang, src, "sha").unwrap();
            let rows = unit_rows(&store);
            assert!(rows.len() >= 2, "{path}: expected units");
            let residual = residual_text(src, &store.child_spans(path).unwrap());
            for (qualified, start, end, hash) in rows {
                let body = if qualified.ends_with("::FILE") {
                    residual.clone()
                } else {
                    view::view_text(src, start, end).unwrap()
                };
                assert_eq!(hash, view::attest(&body), "{path}: {qualified}");
            }
        }
        // A file no extractor yields units for gets its FILE unit, whose
        // residual is every non-blank line of the file.
        let store = Store::open(":memory:").unwrap();
        let src = "# only a comment\r\nexport X=1\n";
        extract_file(&store, "tools/env.sh", Lang::Bash, src, "sha").unwrap();
        let rows = unit_rows(&store);
        assert_eq!(rows.len(), 1);
        for (qualified, start, end, hash) in rows {
            assert!(qualified.ends_with("::FILE"), "{qualified}");
            assert_eq!((start, end), (1, 2));
            assert_eq!(hash, view::attest("# only a comment\r\nexport X=1"));
        }
        // A file of an unknown language is not indexed, so it has no unit
        // whose hash could drift from its view.
        let store = Store::open(":memory:").unwrap();
        extract_file(&store, "notes/a.txt", Lang::Other, "text\n", "sha").unwrap();
        assert!(unit_rows(&store).is_empty());
    }

    #[test]
    fn crlf_file_hash_keeps_cr() {
        let store = Store::open(":memory:").unwrap();
        let src = "use a;\r\npub fn f() {\r\n    0\r\n}\r\n";
        extract_file(&store, "src/lib.rs", Lang::Rust, src, "sha").unwrap();
        let rows = unit_rows(&store);
        let file = rows.iter().find(|r| r.0.ends_with("::FILE")).unwrap();
        assert_eq!((file.1, file.2), (1, 4));
        assert_eq!(file.3, view::attest("use a;\r"));
        assert_ne!(file.3, view::attest("use a;"));
    }

    // An empty file has an empty residual, so nothing of it is queued.
    #[test]
    fn an_empty_file_emits_no_unit() {
        let store = Store::open(":memory:").unwrap();
        extract_file(&store, "tools/empty.sh", Lang::Bash, "", "sha").unwrap();
        assert!(unit_rows(&store).is_empty());
    }
}
