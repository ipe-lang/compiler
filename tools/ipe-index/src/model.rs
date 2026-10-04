use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Rust,
    Bash,
    Ts,
    Ipe,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    // Full-Rust compiler + runtime + tooling, plus the `.ipe` stdlib/examples.
    CompilerRs,
    RuntimeRs,
    StdlibIpe,
    ToolRs,
    ScriptSh,
    ConsoleTs,
    Example,
    Fixture,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Parse,
    Canonicalise,
    Type,
    Build,
    Generate,
}

/// Unit kinds stored in `units.kind` — a closed set mirrored by the DB CHECK
/// constraint, so an invalid kind is unrepresentable at both layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Module,
    File,
    Fn,
    Struct,
    Enum,
    Impl,
    Const,
    Binding,
    Block,
    Trait,
}

/// `units.facing` — closed set mirrored by the DB CHECK constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Facing {
    User,
    Internal,
    Test,
}

/// A reviewable source unit: a content-stable id (`uid` = blake3 of
/// `path|kind|qualified`), a span, classification, and a body hash binding
/// the row to the exact source bytes it describes: `body_hash` is the
/// `sha256:` attestation of the unit's whole-line view (`extract::view`).
pub struct Unit {
    pub path: String,
    pub kind: Kind,
    pub name: String,
    pub qualified: String,
    pub line_start: i64,
    pub line_end: i64,
    pub facing: Facing,
    pub purpose: Option<String>,
    pub body_hash: String,
    pub updated_sha: String,
}

/// A repository tag: the `tag` of every stored `tag:relpath` path.
///
/// `parse` is the only constructor, so a tag is never empty and holds no `/`
/// and no `:` — exactly the tags `split_tag` reads back from a stored path.
/// The code-review app's `RepoPath.parseTag` admits the same set; both sides
/// are pinned by `tests/repo_tag_vectors.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoTag(String);

/// Why a repository tag was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagError {
    /// The tag is empty: `split_tag` reads `":rel"` as untagged.
    Empty,
    /// The tag holds a `/`: `split_tag` reads `"a/b:rel"` as untagged.
    Slash,
    /// The tag holds a `:`: `split_tag` splits `"a:b:rel"` at the first `:`.
    Colon,
}

impl std::fmt::Display for TagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Empty => "the tag is empty",
            Self::Slash => "the tag holds a `/`",
            Self::Colon => "the tag holds a `:`",
        })
    }
}

impl std::error::Error for TagError {}

impl RepoTag {
    /// Parses `raw` as a tag, refusing every spelling `split_tag` misreads.
    pub fn parse(raw: &str) -> Result<Self, TagError> {
        if raw.is_empty() {
            Err(TagError::Empty)
        } else if raw.contains('/') {
            Err(TagError::Slash)
        } else if raw.contains(':') {
            Err(TagError::Colon)
        } else {
            Ok(Self(raw.to_string()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The stored form of `rel` under this tag: `tag:rel`.
    pub fn tagged(&self, rel: &str) -> String {
        format!("{}:{rel}", self.0)
    }

    /// The `meta` key recording the HEAD sha this tag was last indexed at.
    pub fn last_sha_key(&self) -> String {
        format!("last_sha:{}", self.0)
    }
}

/// One `--repo tag:path` entry as given: the tag every stored path of the repo
/// carries and the directory spelling its sources are read from, before
/// [`crate::repo_set::RepoSet::parse`] resolves it to a directory identity.
#[derive(Debug, Clone)]
pub struct RepoSpec {
    pub tag: RepoTag,
    pub root: String,
}

/// Split a repo-tagged path (`"ipe:crates/foo.rs"`) into `(tag, relpath)`.
/// Untagged paths (no `:` before the first `/`) return `("", path)`.
pub fn split_tag(path: &str) -> (&str, &str) {
    // Only treat a `:` that precedes the first path separator as a repo tag —
    // never mis-split a path that legitimately contains a colon in a segment.
    match path.find('/') {
        Some(slash) => match path[..slash].find(':') {
            Some(colon) => (&path[..colon], &path[colon + 1..]),
            None => ("", path),
        },
        None => match path.find(':') {
            Some(colon) => (&path[..colon], &path[colon + 1..]),
            None => ("", path),
        },
    }
}

pub fn lang_of(path: &str) -> Lang {
    let (_, rel) = split_tag(path);
    match Path::new(rel).extension().and_then(|e| e.to_str()) {
        Some("rs") => Lang::Rust,
        Some("sh") => Lang::Bash,
        Some("ts") | Some("tsx") | Some("mjs") | Some("js") => Lang::Ts,
        Some("ipe") => Lang::Ipe,
        _ => Lang::Other,
    }
}

pub fn role_of(path: &str) -> Role {
    let (_tag, rel) = split_tag(path);
    // Any `.ipe` source (compiled-in stdlib, examples, fixtures) classifies as
    // stdlib-ipe; the `example` overlay below refines example trees so coverage
    // edges attribute back to the example that exercises a module.
    if rel.starts_with("examples/") {
        Role::Example
    } else if rel.ends_with(".ipe") {
        Role::StdlibIpe
    } else if rel.starts_with("src/compiler/") && rel.ends_with(".rs") {
        Role::CompilerRs
    } else if rel.starts_with("src/runtime/") && rel.ends_with(".rs") {
        Role::RuntimeRs
    } else if rel.starts_with("tools/") && rel.ends_with(".rs") {
        Role::ToolRs
    } else if rel.ends_with(".sh") {
        Role::ScriptSh
    } else if matches!(lang_of(rel), Lang::Ts) {
        Role::ConsoleTs
    } else {
        Role::Other
    }
}

pub fn stage_of(path: &str) -> Option<Stage> {
    let (_tag, rel) = split_tag(path);
    if rel.starts_with("src/compiler/parse/") {
        Some(Stage::Parse)
    } else if rel.starts_with("src/compiler/canon/") {
        Some(Stage::Canonicalise)
    } else if rel.starts_with("src/compiler/types/") {
        Some(Stage::Type)
    } else if rel.starts_with("src/compiler/lower/") {
        Some(Stage::Build)
    } else if rel.starts_with("src/compiler/ir/") || rel.starts_with("src/compiler/backend") {
        Some(Stage::Generate)
    } else {
        None
    }
}

/// Classify a unit's facing: `test` for anything under a test path, `user`
/// for a public binding in a public (stdlib/example) surface, else `internal`.
pub fn facing_of(path: &str, is_pub: bool) -> Facing {
    let (_tag, rel) = split_tag(path);
    if rel.contains("/tests/")
        || rel.contains("/test/")
        || rel.ends_with("_test.rs")
        || rel.ends_with("_test.ipe")
        || rel.ends_with(".test.ts")
    {
        return Facing::Test;
    }
    if is_pub {
        let role = role_of(path);
        if role == Role::StdlibIpe || role == Role::Example {
            return Facing::User;
        }
    }
    Facing::Internal
}

impl Lang {
    pub fn as_str(&self) -> &'static str {
        use Lang::*;
        match self {
            Rust => "rs",
            Bash => "sh",
            Ts => "ts",
            Ipe => "ipe",
            Other => "other",
        }
    }

    /// Every `Lang` variant — read by `tests/lang_vectors.json`'s own test, the
    /// shared fixture code-review's `Highlight.langFor` is pinned against.
    ///
    /// Built from an exhaustive match (no wildcard): a new `Lang` variant
    /// fails this build until it is listed here too.
    #[cfg(test)]
    pub(crate) const ALL: [Lang; 5] = match Lang::Rust {
        Lang::Rust | Lang::Bash | Lang::Ts | Lang::Ipe | Lang::Other => {
            [Lang::Rust, Lang::Bash, Lang::Ts, Lang::Ipe, Lang::Other]
        }
    };
}
impl Role {
    pub fn as_str(&self) -> &'static str {
        use Role::*;
        match self {
            CompilerRs => "compiler-rs",
            RuntimeRs => "runtime-rs",
            StdlibIpe => "stdlib-ipe",
            ToolRs => "tool-rs",
            ScriptSh => "script-sh",
            ConsoleTs => "console-ts",
            Example => "example",
            Fixture => "fixture",
            Other => "other",
        }
    }
}
impl Stage {
    pub fn as_str(&self) -> &'static str {
        use Stage::*;
        match self {
            Parse => "parse",
            Canonicalise => "canonicalise",
            Type => "type",
            Build => "build",
            Generate => "generate",
        }
    }
}
impl Kind {
    pub fn as_str(&self) -> &'static str {
        use Kind::*;
        match self {
            Module => "module",
            File => "file",
            Fn => "fn",
            Struct => "struct",
            Enum => "enum",
            Impl => "impl",
            Const => "const",
            Binding => "binding",
            Block => "block",
            Trait => "trait",
        }
    }
}
impl Facing {
    pub fn as_str(&self) -> &'static str {
        use Facing::*;
        match self {
            User => "user",
            Internal => "internal",
            Test => "test",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classifies_paths() {
        assert_eq!(lang_of("src/compiler/lower/src/compile.rs"), Lang::Rust);
        assert_eq!(lang_of("a.ipe"), Lang::Ipe);
        assert_eq!(role_of("examples/wasm/counter/src/Main.ipe"), Role::Example);
        assert_eq!(role_of("src/compiler/parse/src/lexer.rs"), Role::CompilerRs);
        assert_eq!(role_of("src/runtime/rust/src/list.rs"), Role::RuntimeRs);
        assert_eq!(role_of("tools/ipe-index/src/main.rs"), Role::ToolRs);
        assert_eq!(role_of("scripts/lib/wasm-verify.mjs"), Role::ConsoleTs); // JS/TS/MJS not Other
        assert_eq!(lang_of("scripts/x.mjs"), Lang::Ts);
        assert_eq!(
            stage_of("src/compiler/canon/src/module.rs"),
            Some(Stage::Canonicalise)
        );
        assert_eq!(
            stage_of("src/compiler/backend/rust/src/builder.rs"),
            Some(Stage::Generate)
        );
    }

    const LANG_VECTORS: &str = include_str!("../tests/lang_vectors.json");

    // The fixture's `stored` set must equal `Lang::as_str` over every
    // variant — exactly once each — so a parser reading it is never fed a
    // value outside ipe-index's vocabulary, and `Lang::ALL` growing without
    // the fixture growing too goes red here.
    #[test]
    fn lang_vectors_list_every_language() {
        let rows: Vec<serde_json::Value> = serde_json::from_str(LANG_VECTORS).unwrap();
        let stored: Vec<&str> = rows
            .iter()
            .map(|row| row["stored"].as_str().unwrap())
            .collect();
        let want: Vec<&str> = Lang::ALL.iter().map(Lang::as_str).collect();
        let mut sorted_stored = stored.clone();
        sorted_stored.sort_unstable();
        sorted_stored.dedup();
        assert_eq!(
            stored.len(),
            sorted_stored.len(),
            "lang_vectors.json has a duplicate `stored` value: {stored:?}"
        );
        let mut sorted_want = want.clone();
        sorted_want.sort_unstable();
        assert_eq!(
            sorted_stored, sorted_want,
            "lang_vectors.json must list exactly ipe-index's Lang vocabulary \
             ({want:?}), got {stored:?}"
        );
    }

    const TAG_VECTORS: &str = include_str!("../tests/repo_tag_vectors.json");

    fn tag_refusal_name(e: TagError) -> &'static str {
        match e {
            TagError::Empty => "Empty",
            TagError::Slash => "Slash",
            TagError::Colon => "Colon",
        }
    }

    // Every vector row: `RepoTag::parse` accepts exactly the rows with no
    // refusal, an accepted tag reads back through `split_tag` unchanged under
    // nested, top-level and colon-holding relpaths, and a refused tag never
    // reads back as itself.
    #[test]
    fn repo_tag_vectors_agree_with_split_tag() {
        let rows: Vec<serde_json::Value> = serde_json::from_str(TAG_VECTORS).unwrap();
        assert!(rows.len() >= 6, "the shared tag vector file lost rows");
        for row in rows {
            let raw = row["raw"].as_str().unwrap();
            let want = row["refusal"].as_str().map_or(Ok(raw), Err);
            let parsed = RepoTag::parse(raw);
            assert_eq!(
                parsed
                    .as_ref()
                    .map(RepoTag::as_str)
                    .map_err(|e| tag_refusal_name(*e)),
                want,
                "{raw:?}"
            );
            match parsed {
                Ok(tag) => {
                    for rel in ["a/b.rs", "c.rs", "d:e/f.rs"] {
                        assert_eq!(split_tag(&tag.tagged(rel)), (raw, rel), "{raw:?} {rel}");
                    }
                }
                Err(_) => {
                    let stored = format!("{raw}:x/y.rs");
                    let (back, _) = split_tag(&stored);
                    assert!(back.is_empty() || back != raw, "{raw:?} reads back tagged");
                }
            }
        }
    }

    #[test]
    fn repo_tag_refuses_each_misread_spelling() {
        assert_eq!(RepoTag::parse(""), Err(TagError::Empty));
        assert_eq!(RepoTag::parse("a/b"), Err(TagError::Slash));
        assert_eq!(RepoTag::parse("a:b"), Err(TagError::Colon));
        assert_eq!(
            RepoTag::parse("ipe").map(|t| t.tagged("x")),
            Ok("ipe:x".to_string())
        );
    }

    #[test]
    fn facing_classifies_pub_test_internal() {
        // Public binding under the stdlib surface → user-facing.
        assert_eq!(facing_of("ipe:src/stdlib/Ipe/List.ipe", true), Facing::User);
        // Public binding in an example → user-facing.
        assert_eq!(
            facing_of("ipe:examples/wasm/counter/src/Main.ipe", true),
            Facing::User
        );
        // Public but internal surface (compiler) → internal.
        assert_eq!(
            facing_of("ipe:src/compiler/parse/src/lexer.rs", true),
            Facing::Internal
        );
        // Non-public anywhere → internal.
        assert_eq!(
            facing_of("ipe:src/stdlib/Ipe/List.ipe", false),
            Facing::Internal
        );
        // Test paths win regardless of visibility.
        assert_eq!(
            facing_of("ipe:src/compiler/parse/tests/lex.rs", true),
            Facing::Test
        );
        assert_eq!(
            facing_of("ipe:src/stdlib/Ipe/parser_test.ipe", false),
            Facing::Test
        );
    }
}
