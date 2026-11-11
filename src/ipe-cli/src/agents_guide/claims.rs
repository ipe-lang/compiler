//! The guide's checkable claims, each resolved through the CLI's own producer.
//!
//! The extractor reads the whole [`ASSET`] into a closed set of [`Claim`]s:
//! every inline backtick span outside a fence, every `ipe` line of an `sh`
//! fence, every diagnostic code and every `IPE_*` name anywhere in the text. A
//! claim is true only when the producer that serves it accepts it: the help
//! registry for a command and its flags, the delivery parser for a build's
//! words, `ipe doc`'s own parse and lookup for a term, the diagnostic registry
//! for a code, the environment registry for a variable, and the canonical
//! operator, builtin-type and builtin-union tables for an ambient name. A span
//! shaped like a reference that fits none of those shapes is refused, never
//! skipped.
#![cfg(test)]

use std::cell::OnceCell;

use ipe_canon::builtins::BUILTIN_UNIONS;
use ipe_kernels::BuiltinType;
use ipe_syntax::BinOp;

use super::ASSET;
use crate::delivery::{DeliveryTokens, Shape};
use crate::doc::{
    DocMode, LookupTerm, MemberResolution, ModuleDoc, ModuleQuery, build_doc_bundle_over,
    build_index, parse_doc, project_modules_at, resolve_member, resolve_module_query, resolve_term,
};
use crate::doc_bundle::{DocBundle, DocKind, DocsOverlay};
use crate::help::{CommandSpec, FlagSpec, all_command_specs, group_member, is_command, is_group};

/// The names the guide states do not exist; each must stay unresolvable.
const ABSENT: &[&str] = &["Result.fromTask", "Ipe.Prelude"];

/// The bullet listing the operators, types and values every module sees.
const TIER_A: &str = "- **Tier A (ambient):**";

/// The bullet listing the builtin types and constructors every module sees.
const TIER_B: &str = "- **Tier B (ambient):**";

/// How much of a command claim's argument list is judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArgScope {
    /// The verb, every flag, and the positional words.
    Whole,
    /// The verb and the flags only: the positionals hold a placeholder, or a
    /// flag span borrowed the command of its line or section.
    VerbAndFlags,
}

/// One checkable statement the guide makes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Claim {
    /// An `ipe` invocation, as the words after `ipe`.
    Command {
        /// The words after `ipe`, quotes stripped.
        argv: Vec<String>,
        /// How much of `argv` is judged.
        scope: ArgScope,
    },
    /// A module name or a `kind:key` term `ipe doc` opens.
    DocTerm(String),
    /// A diagnostic code.
    Code(String),
    /// A qualified value `ipe doc` opens, such as `List.map`.
    Qualified(String),
    /// A name the guide says every module sees without an import.
    Unqualified {
        /// The operator, type, constructor or value.
        name: String,
        /// The module a lowercase value is an export of, from the same bullet.
        basics: Option<String>,
    },
    /// An environment variable.
    EnvVar(String),
    /// A placeholder such as `<dir>` or `...`, which claims nothing.
    Placeholder(String),
}

/// The claims of a text and the spans refused before any lookup.
#[derive(Debug, Default)]
struct Extracted {
    /// Every claim, in text order.
    claims: Vec<Claim>,
    /// Every malformed span or fence, with its line.
    refusals: Vec<String>,
}

/// The language of an open fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fence {
    /// A shell fence; each line is an `ipe` command.
    Sh,
    /// An Ipê fence; `tests/explain_examples.rs` judges its body.
    Ipe,
    /// A refused fence language; its body is not read.
    Other,
}

/// The fence an opening info string selects, or `None` for a refused language.
fn fence_language(info: &str) -> Option<Fence> {
    match info {
        "sh" => Some(Fence::Sh),
        "ipe" => Some(Fence::Ipe),
        _ => info.strip_prefix("ipe ").map(|_| Fence::Ipe),
    }
}

/// Whether `token` is a placeholder: `<name>`, `[<name>]` or `...`.
fn is_placeholder(token: &str) -> bool {
    let bare = token.trim_start_matches('[').trim_end_matches(']');
    bare == "..." || (bare.len() > 2 && bare.starts_with('<') && bare.ends_with('>'))
}

/// Whether a command word holds a placeholder, whole or as a `kind:<key>` key.
fn holds_placeholder(word: &str) -> bool {
    is_placeholder(word)
        || word
            .split_once(':')
            .is_some_and(|(_, key)| is_placeholder(key))
}

/// Whether `token` is spelled like a diagnostic code: `IPE-` then a letter and
/// four digits.
fn is_code_shape(token: &str) -> bool {
    token.strip_prefix("IPE-").is_some_and(|tail| {
        let mut chars = tail.chars();
        chars.next().is_some_and(|c| c.is_ascii_uppercase())
            && chars.clone().count() == 4
            && chars.all(|c| c.is_ascii_digit())
    })
}

/// Whether `segment` is a non-empty identifier.
fn is_ident(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Whether `segment` starts with an uppercase letter.
fn is_upper(segment: &str) -> bool {
    segment.starts_with(|c: char| c.is_ascii_uppercase())
}

/// The command claim of the words after `ipe`.
fn command_claim(words: &str) -> Claim {
    let argv: Vec<String> = words
        .split_whitespace()
        .map(|word| word.trim_matches('"').to_owned())
        .collect();
    let scope = if argv.iter().any(|word| holds_placeholder(word)) {
        ArgScope::VerbAndFlags
    } else {
        ArgScope::Whole
    };
    Claim::Command { argv, scope }
}

/// The words after `ipe` when `span` is an `ipe` invocation.
fn ipe_words(span: &str) -> Option<&str> {
    if span == "ipe" {
        return Some("");
    }
    span.strip_prefix("ipe ")
}

/// The claim one prose token makes, or why the token is refused; `None` when
/// the token is code that claims nothing.
fn classify(token: &str) -> Option<Result<Claim, String>> {
    if is_placeholder(token) {
        return Some(Ok(Claim::Placeholder(token.to_owned())));
    }
    if token.starts_with("IPE-") {
        return Some(if is_code_shape(token) {
            Ok(Claim::Code(token.to_owned()))
        } else {
            Err(format!("`{token}` is not a diagnostic code"))
        });
    }
    if let Some((kind, key)) = token.split_once(':')
        && !kind.is_empty()
        && !key.is_empty()
        && kind.chars().all(|c| c.is_ascii_lowercase())
    {
        return Some(match DocKind::from_prefix(kind) {
            Some(_) if is_placeholder(key) => Ok(Claim::Placeholder(token.to_owned())),
            Some(_) => Ok(Claim::DocTerm(token.to_owned())),
            None => Err(format!("`{token}` names no doc kind")),
        });
    }
    if token.len() > 1
        && is_upper(token)
        && token
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return Some(Ok(Claim::EnvVar(token.to_owned())));
    }
    if is_upper(token) && token.contains('.') {
        return Some(dotted(token));
    }
    None
}

/// The claim of a dotted uppercase-led token: a qualified value or a module.
fn dotted(token: &str) -> Result<Claim, String> {
    let segments: Vec<&str> = token.split('.').collect();
    let refused = || format!("`{token}` is neither a module nor a qualified value");
    let Some((last, owners)) = segments.split_last() else {
        return Err(refused());
    };
    if !segments.iter().all(|segment| is_ident(segment))
        || !owners.iter().all(|segment| is_upper(segment))
    {
        return Err(refused());
    }
    Ok(if is_upper(last) {
        Claim::DocTerm(token.to_owned())
    } else {
        Claim::Qualified(token.to_owned())
    })
}

/// Read one prose line's spans into claims.
fn prose_line(
    line: &str,
    lineno: usize,
    heading_command: &mut Option<Vec<String>>,
    out: &mut Extracted,
) {
    let is_heading = line.starts_with('#');
    if is_heading {
        *heading_command = None;
    }
    let pieces: Vec<&str> = line.split('`').collect();
    if pieces.len().is_multiple_of(2) {
        out.refusals
            .push(format!("line {lineno}: an unclosed backtick span"));
        return;
    }
    let spans: Vec<&str> = pieces.iter().skip(1).step_by(2).copied().collect();
    if line.starts_with(TIER_A) || line.starts_with(TIER_B) {
        tier_spans(&spans, lineno, out);
        return;
    }
    let mut line_command: Option<Vec<String>> = None;
    for span in spans {
        if let Some(words) = ipe_words(span) {
            let claim = command_claim(words);
            if let Claim::Command { argv, .. } = &claim {
                line_command = Some(argv.clone());
                if is_heading {
                    *heading_command = Some(argv.clone());
                }
            }
            out.claims.push(claim);
        } else if span.starts_with("--") {
            let base = line_command.clone().or_else(|| heading_command.clone());
            match base {
                Some(mut argv) => {
                    argv.extend(span.split_whitespace().map(str::to_owned));
                    out.claims.push(Claim::Command {
                        argv,
                        scope: ArgScope::VerbAndFlags,
                    });
                }
                None => out
                    .refusals
                    .push(format!("line {lineno}: `{span}` belongs to no command")),
            }
        } else {
            for token in span
                .split(|c: char| c.is_whitespace() || "()[]{},=".contains(c))
                .filter(|token| !token.is_empty())
            {
                match classify(token) {
                    Some(Ok(claim)) => out.claims.push(claim),
                    Some(Err(why)) => out.refusals.push(format!("line {lineno}: {why}")),
                    None => {}
                }
            }
        }
    }
}

/// Read a Tier A or Tier B bullet: its module span names where lowercase values
/// live, and every token of its other spans is an ambient name.
fn tier_spans(spans: &[&str], lineno: usize, out: &mut Extracted) {
    let module = spans
        .iter()
        .find(|span| matches!(dotted(span), Ok(Claim::DocTerm(_))))
        .map(|span| (*span).to_owned());
    if let Some(module) = &module {
        out.claims.push(Claim::DocTerm(module.clone()));
    }
    for span in spans {
        if module.as_deref() == Some(*span) {
            continue;
        }
        for name in span.split_whitespace() {
            out.claims.push(Claim::Unqualified {
                name: name.to_owned(),
                basics: module.clone(),
            });
        }
    }
    if spans.is_empty() {
        out.refusals
            .push(format!("line {lineno}: an ambient bullet names nothing"));
    }
}

/// Every claim of `text`, and every span or fence refused before any lookup.
fn extract(text: &str) -> Extracted {
    let mut out = Extracted::default();
    let mut fence: Option<Fence> = None;
    let mut heading_command: Option<Vec<String>> = None;
    for (index, line) in text.lines().enumerate() {
        let lineno = index.saturating_add(1);
        if let Some(info) = line.trim_start().strip_prefix("```") {
            let info = info.trim();
            fence = match fence {
                Some(_) => {
                    if !info.is_empty() {
                        out.refusals
                            .push(format!("line {lineno}: a closing fence carries `{info}`"));
                    }
                    None
                }
                None => Some(fence_language(info).unwrap_or_else(|| {
                    out.refusals.push(format!(
                        "line {lineno}: fence language `{info}` is neither `sh` nor `ipe`"
                    ));
                    Fence::Other
                })),
            };
            continue;
        }
        match fence {
            None => prose_line(line, lineno, &mut heading_command, &mut out),
            Some(Fence::Sh) => sh_line(line, lineno, &mut out),
            Some(Fence::Ipe | Fence::Other) => {}
        }
    }
    if fence.is_some() {
        out.refusals.push("an unclosed fence".to_owned());
    }
    scan_codes(text, &mut out);
    scan_env_vars(text, &mut out);
    out
}

/// Read one `sh` fence line: an `ipe` command, its `#` comment dropped.
fn sh_line(line: &str, lineno: usize, out: &mut Extracted) {
    let command = line
        .split_once('#')
        .map_or(line, |(command, _)| command)
        .trim();
    if command.is_empty() {
        return;
    }
    match ipe_words(command) {
        Some(words) => out.claims.push(command_claim(words)),
        None => out.refusals.push(format!(
            "line {lineno}: `{command}` is not an `ipe` command"
        )),
    }
}

/// Every code-shaped `IPE-` word anywhere in `text`, fences and prose alike.
fn scan_codes(text: &str, out: &mut Extracted) {
    for (at, _) in text.match_indices("IPE-") {
        let word: String = text
            .get(at..)
            .unwrap_or_default()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        if is_code_shape(&word) {
            out.claims.push(Claim::Code(word));
        }
    }
}

/// Every `IPE_` name anywhere in `text`, fences and prose alike.
fn scan_env_vars(text: &str, out: &mut Extracted) {
    for (at, _) in text.match_indices("IPE_") {
        let glued = text
            .get(..at)
            .and_then(|before| before.chars().next_back())
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        if glued {
            continue;
        }
        let name: String = text
            .get(at..)
            .unwrap_or_default()
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
            .collect();
        out.claims.push(Claim::EnvVar(name));
    }
}

/// The embedded docs a lookup reads.
type Docs = Result<(ipe_docs::Index, DocBundle), String>;

/// The CLI's producers, each built on first use.
struct Producers {
    /// Every command's help entry.
    specs: Vec<CommandSpec>,
    /// The content index and the doc bundle over it.
    docs: OnceCell<Docs>,
    /// The modules of a freshly scaffolded project.
    project: OnceCell<Vec<ModuleDoc>>,
}

impl Producers {
    /// Producers with nothing built yet.
    fn new() -> Self {
        Self {
            specs: all_command_specs(),
            docs: OnceCell::new(),
            project: OnceCell::new(),
        }
    }

    /// The embedded docs, built once.
    fn docs(&self) -> &Docs {
        self.docs.get_or_init(|| {
            let index = build_index().map_err(|e| format!("{e:?}"))?;
            let bundle = build_doc_bundle_over(&index, &DocsOverlay::Embedded)
                .map_err(|e| format!("{e:?}"))?;
            Ok((index, bundle))
        })
    }

    /// The modules of the project `ipe init` scaffolds, the context of the
    /// guide's "a project module" lookup.
    fn project(&self) -> &[ModuleDoc] {
        self.project.get_or_init(|| {
            let dir = ipe_test_temp::temp_root()
                .join(format!("ipe-agents-guide-claims-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let scaffolded = crate::init::run_init(&[dir.display().to_string(), "web".to_owned()]);
            let modules = scaffolded.map_or_else(|_| Vec::new(), |()| project_modules_at(&dir));
            let _ = std::fs::remove_dir_all(&dir);
            modules
        })
    }

    /// Whether `term` opens an entry exactly as `ipe doc <term>` routes it.
    fn lookup(&self, term: &str) -> bool {
        let Ok(mode) = parse_doc(&[term.to_owned()]) else {
            return false;
        };
        self.opens(&mode)
    }

    /// Whether a parsed `ipe doc` lookup or module query opens an entry; every
    /// other mode opens none.
    fn opens(&self, mode: &DocMode) -> bool {
        match mode {
            DocMode::Lookup { key, .. } => self.looks_up(key),
            DocMode::Query { module, .. } => matches!(
                resolve_module_query(module.text(), || self.project().to_vec()),
                Ok(ModuleQuery::Module(_) | ModuleQuery::Member(..))
            ),
            DocMode::Generate { .. }
            | DocMode::Serve { .. }
            | DocMode::Check { .. }
            | DocMode::List { .. }
            | DocMode::CheckExamples
            | DocMode::TypeSearch { .. } => false,
        }
    }

    /// Whether a lookup term opens an entry in `ipe doc`'s order: a `kind:key`
    /// term within its kind; a bare term as an index key, then a module member,
    /// then a unique bundle key.
    fn looks_up(&self, term: &LookupTerm) -> bool {
        let LookupTerm::Bare(query) = term else {
            return self.resolves(term);
        };
        let indexed = self
            .docs()
            .as_ref()
            .is_ok_and(|(index, _)| index.resolve(query.text()).is_some());
        indexed
            || match resolve_member(query.text()) {
                Ok(MemberResolution::Found(..)) => true,
                Ok(MemberResolution::Ambiguous(_)) | Err(_) => false,
                Ok(MemberResolution::Miss) => self.resolves(term),
            }
    }

    /// Whether `term` opens an entry of the embedded docs.
    fn resolves(&self, term: &LookupTerm) -> bool {
        self.docs()
            .as_ref()
            .is_ok_and(|(index, bundle)| resolve_term(bundle, index, term).is_ok())
    }

    /// Judge one claim; `absent` names the terms judged by [`Self::absent`].
    fn judge(&self, claim: &Claim, absent: &[&str]) -> Result<(), String> {
        let held = |ok: bool, what: &str| if ok { Ok(()) } else { Err(what.to_owned()) };
        match claim {
            Claim::Command { argv, scope } => self.command(argv, *scope),
            Claim::DocTerm(term) | Claim::Qualified(term) => held(
                absent.contains(&term.as_str()) || self.lookup(term),
                &format!("`ipe doc {term}` opens nothing"),
            ),
            Claim::Code(code) => held(
                ipe_diagnostics::ALL_CODES
                    .iter()
                    .any(|known| known.as_str() == code),
                &format!("`{code}` is no diagnostic code"),
            ),
            Claim::EnvVar(name) => held(
                ipe_docs::env_vars::ENV_VARS
                    .iter()
                    .any(|var| var.name == name),
                &format!("`{name}` is no registered environment variable"),
            ),
            Claim::Unqualified { name, basics } => held(
                self.ambient(name, basics.as_deref()),
                &format!("`{name}` is not in scope without an import"),
            ),
            Claim::Placeholder(_) => Ok(()),
        }
    }

    /// Whether `name` is in every module's scope: an operator of the closed
    /// set, a builtin type, an unqualified builtin constructor, or an export of
    /// the ambient `basics` module.
    fn ambient(&self, name: &str, basics: Option<&str>) -> bool {
        if let Some(op) = BinOp::from_text(name) {
            return !matches!(op, BinOp::ParserKeeper | BinOp::ParserIgnorer);
        }
        if is_upper(name) {
            return BuiltinType::of_head(&[], name).is_some()
                || BUILTIN_UNIONS
                    .iter()
                    .filter(|union| union.qualified_home.is_none())
                    .any(|union| {
                        union.type_name == name
                            || union.ctors.iter().any(|(ctor, _, _)| *ctor == name)
                    });
        }
        is_ident(name) && basics.is_some_and(|module| self.lookup(&format!("{module}.{name}")))
    }

    /// Judge an `ipe` invocation: its verb, its flags, and, in scope, its
    /// positional words.
    fn command(&self, argv: &[String], scope: ArgScope) -> Result<(), String> {
        let shown = argv.join(" ");
        let Some((head, rest)) = argv.split_first() else {
            return Err("a bare `ipe` claims no command".to_owned());
        };
        let (name, rest) = if is_group(head) {
            let Some((sub, tail)) = rest.split_first() else {
                return Ok(());
            };
            if group_member(head, sub).is_none() {
                return Err(format!("`ipe {shown}`: `{head} {sub}` is no command"));
            }
            (format!("{head} {sub}"), tail)
        } else if is_command(head) {
            (head.clone(), rest)
        } else {
            return Err(format!("`ipe {shown}`: `{head}` is no command"));
        };
        let Some(spec) = self.specs.iter().find(|spec| spec.name == name) else {
            return Err(format!("`ipe {shown}`: `{name}` has no help entry"));
        };
        for flag in rest.iter().filter(|word| word.starts_with('-')) {
            let flag_name = flag.split_once('=').map_or(flag.as_str(), |(name, _)| name);
            if !spec
                .options
                .iter()
                .flat_map(FlagSpec::names)
                .any(|known| known == flag_name)
            {
                return Err(format!("`ipe {shown}`: `{name}` takes no `{flag_name}`"));
            }
        }
        if scope == ArgScope::VerbAndFlags {
            return Ok(());
        }
        let positionals: Vec<String> = rest
            .iter()
            .filter(|word| !word.starts_with('-'))
            .cloned()
            .collect();
        if head == "doc" {
            let mode = parse_doc(rest).map_err(|e| format!("`ipe {shown}`: {e:?}"))?;
            return match mode {
                DocMode::Lookup { .. } | DocMode::Query { .. } if !self.opens(&mode) => {
                    Err(format!("`ipe {shown}` opens nothing"))
                }
                _ => Ok(()),
            };
        }
        if is_group(head) {
            let tail = match positionals.split_first() {
                Some((first, tail)) if Shape::from_word(first).is_some() => tail,
                _ => positionals.as_slice(),
            };
            return DeliveryTokens::parse(tail)
                .map(drop)
                .map_err(|e| format!("`ipe {shown}`: {e:?}"));
        }
        if !positionals.is_empty() && spec.args.is_empty() {
            return Err(format!("`ipe {shown}`: `{name}` takes no positional"));
        }
        Ok(())
    }

    /// Judge the names `text` says do not exist: each must occur as a claim of
    /// `text` and must open nothing.
    fn absent(&self, text: &str, absent: &[&str]) -> Vec<String> {
        let claims = extract(text).claims;
        let mut failures = Vec::new();
        for term in absent {
            let named = claims
                .iter()
                .any(|claim| matches!(claim, Claim::DocTerm(t) | Claim::Qualified(t) if t == term));
            if !named {
                failures.push(format!("absent `{term}` is not named by the text"));
            }
            if self.lookup(term) {
                failures.push(format!("absent `{term}` opens an entry"));
            }
        }
        failures
    }

    /// Every refusal and every false claim of `text`; `absent` names the terms
    /// judged by [`Self::absent`] instead.
    fn check(&self, text: &str, absent: &[&str]) -> Vec<String> {
        let extracted = extract(text);
        let mut failures = extracted.refusals;
        failures.extend(
            extracted
                .claims
                .iter()
                .filter_map(|claim| self.judge(claim, absent).err()),
        );
        failures
    }
}

/// Every false claim of `text` with no absent terms.
fn failures(text: &str) -> Vec<String> {
    Producers::new().check(text, &[])
}

/// Every claim the guide makes resolves, each kind of claim occurs, both
/// ambient bullets are present once, and every absent name stays absent.
#[test]
fn every_guide_claim_resolves() {
    let producers = Producers::new();
    let mut found = producers.check(ASSET, ABSENT);
    found.extend(producers.absent(ASSET, ABSENT));
    for bullet in [TIER_A, TIER_B] {
        let count = ASSET
            .lines()
            .filter(|line| line.starts_with(bullet))
            .count();
        if count != 1 {
            found.push(format!("`{bullet}` occurs {count} times"));
        }
    }
    assert!(
        found.is_empty(),
        "false guide claims:\n{}",
        found.join("\n")
    );

    let claims = extract(ASSET).claims;
    let kinds: [(&str, fn(&Claim) -> bool); 7] = [
        ("command", |c| matches!(c, Claim::Command { .. })),
        ("doc term", |c| matches!(c, Claim::DocTerm(_))),
        ("code", |c| matches!(c, Claim::Code(_))),
        ("qualified", |c| matches!(c, Claim::Qualified(_))),
        ("unqualified", |c| matches!(c, Claim::Unqualified { .. })),
        ("env var", |c| matches!(c, Claim::EnvVar(_))),
        ("placeholder", |c| matches!(c, Claim::Placeholder(_))),
    ];
    for (kind, is_kind) in kinds {
        assert!(
            claims.iter().any(is_kind),
            "the guide makes no {kind} claim"
        );
    }
}

/// An unknown verb is refused; a known one is not.
#[test]
fn an_unknown_verb_is_refused() {
    assert!(!failures("`ipe frobnicate`").is_empty());
    assert!(failures("`ipe fmt`").is_empty());
}

/// A flag the verb's help does not advertise is refused, in a span and in an
/// `sh` fence.
#[test]
fn an_unadvertised_flag_is_refused() {
    assert!(!failures("`ipe doc --frob`").is_empty());
    assert!(!failures("```sh\nipe lint --frob   # x\n```").is_empty());
    assert!(failures("`ipe doc list --plain`").is_empty());
    assert!(failures("```sh\nipe lint --fix   # x\n```").is_empty());
}

/// A flag span with no command on its line or in its section is refused; one
/// under a section naming the command is judged against it.
#[test]
fn a_flag_with_no_command_is_refused() {
    assert!(!failures("`--plain`").is_empty());
    assert!(failures("## `ipe doc`\n\n- `--plain`: one per line.").is_empty());
    assert!(!failures("## `ipe doc`\n\n- `--frob`: nothing.").is_empty());
}

/// A delivery word the delivery parser refuses is refused.
#[test]
fn an_unknown_delivery_word_is_refused() {
    assert!(!failures("`ipe dev build web toaster`").is_empty());
    assert!(failures("`ipe dev build web client`").is_empty());
}

/// A `kind:key` term with no entry, or with no such kind, is refused.
#[test]
fn an_unknown_doc_term_is_refused() {
    assert!(!failures("`guide:no-such`").is_empty());
    assert!(!failures("`nokind:thing`").is_empty());
    assert!(failures("`guide:db-store`").is_empty());
}

/// An unregistered diagnostic code is refused in a span and in plain prose.
#[test]
fn an_unknown_code_is_refused() {
    assert!(!failures("`IPE-Z9999`").is_empty());
    assert!(!failures("see IPE-Z9999 here").is_empty());
    assert!(!failures("`IPE-N33`").is_empty());
    assert!(failures("see IPE-N0033 here").is_empty());
}

/// A qualified value `ipe doc` cannot open is refused.
#[test]
fn an_unknown_qualified_value_is_refused() {
    assert!(!failures("`Ipe.Db.unsafeExecRaw`").is_empty());
    assert!(failures("`List.map`").is_empty());
}

/// A name outside the ambient tables and the ambient module is refused.
#[test]
fn a_name_outside_the_prelude_is_refused() {
    let bullet = |names: &str| format!("{TIER_A} `+ |>`, `Ipe.Basics`'s own exports — `{names}`.");
    assert!(!failures(&bullet("frobnicate")).is_empty());
    assert!(!failures(&format!("{TIER_B} `Frobnicate`")).is_empty());
    assert!(!failures(&format!("{TIER_A} `|=`")).is_empty());
    assert!(failures(&bullet("identity")).is_empty());
    assert!(failures(&format!("{TIER_B} `Just Nothing`")).is_empty());
}

/// An unregistered environment variable is refused, prefixed or not.
#[test]
fn an_unknown_env_var_is_refused() {
    assert!(!failures("set `IPE_NOPE`").is_empty());
    assert!(!failures("set IPE_NOPE=1").is_empty());
    assert!(!failures("set `ENV=production`").is_empty());
    assert!(failures("set `IPE_ENV=production`").is_empty());
}

/// A span shaped like a reference but fitting no claim is refused.
#[test]
fn a_malformed_span_is_refused() {
    assert!(!failures("`Debug.*`").is_empty());
    assert!(!failures("`Ipe.lower.Upper`").is_empty());
    assert!(!failures("an `unclosed span").is_empty());
    assert!(failures("`Ipe.Debug`").is_empty());
}

/// A fence whose language is neither `sh` nor `ipe` is refused.
#[test]
fn a_foreign_fence_is_refused() {
    assert!(!failures("```elm\nx = 1\n```").is_empty());
    assert!(!failures("```\nx = 1\n```").is_empty());
    assert!(!failures("```sh\nls\n```").is_empty());
    assert!(failures("```ipe\nx = 1\n```").is_empty());
    assert!(failures("```ipe ipe:skip a fragment\nx\n```").is_empty());
}

/// An absent name that resolves, or that the text never names, is refused.
#[test]
fn an_absent_name_is_pinned_both_ways() {
    let producers = Producers::new();
    assert!(!producers.absent("`List.map`", &["List.map"]).is_empty());
    assert!(
        !producers
            .absent("no names here", &["Result.fromTask"])
            .is_empty()
    );
    assert!(
        producers
            .absent("`Result.fromTask`", &["Result.fromTask"])
            .is_empty()
    );
    assert!(!producers.check("`Result.fromTask`", &[]).is_empty());
}
