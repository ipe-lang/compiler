//! How each version-control tool consumes each configuration setting it reads.
//!
//! One table per tool maps a setting, spelled as the tool's documentation
//! spells it (`diff.<driver>.textconv`, `alias.*`), to the one way the tool
//! consumes its value: through a shell, as one program run without a shell,
//! composed into a program name, as a path it loads, as a URL, or as data.
//! Every tool reading a value runs in the working tree, a directory under it,
//! or the carved metadata directory, and each reading's judge relies on that.
//!
//! A spelling parses to the triple the configuration parser produces: the
//! section, the subsection, and the key. A setting takes the row that matches
//! it most specifically; a const assertion breaks the build when a spelling is
//! malformed, the rows are out of order, or two rows that decide differently
//! match one setting with neither more specific than the other.

/// How a tool consumes a setting's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consume {
    /// Never names code, so it is not judged: a refspec, a user name, a branch's settings.
    Exempt,
    /// Read as data; its words are still judged as a shell's would be.
    Inert,
    /// One leading `!` makes the rest a shell command; otherwise the value is data.
    Bang,
    /// Run without a shell as one program: a `~`, a quote, or a space is part of its path.
    Exec,
    /// Composed into a program name before it runs.
    Composed(Compose),
    /// A path the tool loads.
    Load(Load),
    /// A URL.
    Url {
        /// Whether Git's `host:path` form counts as a network URL.
        scp: bool,
    },
    /// A Mercurial `[paths]` value, read as one URL or as a list of them.
    UrlList,
    /// The name of a Git remote.
    RemoteName,
    /// A Mercurial `[hooks]` value: `python:<file>:<fn>` loads the file, anything else runs.
    PythonHook,
}

/// How a tool composes a program name from a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compose {
    /// A Git alias: a leading `!` runs the rest through a shell, otherwise the first word after Git's options runs as `git-<word>`.
    Alias,
    /// A Git credential helper: a leading `!` runs the rest through a shell, an absolute path runs as written, anything else runs as `git-credential-<value>`.
    CredentialHelper,
    /// A Git remote helper: run without a shell as `git-remote-<value>`.
    RemoteHelper,
}

/// How a tool loads a value as a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Load {
    /// A configuration file the tool then reads.
    Include(Include),
    /// A directory whose hooks the tool runs.
    HooksPath,
    /// A path the tool runs or loads whatever its shape.
    Forced,
    /// A path the tool runs whatever its shape, unless the value is a Git boolean.
    ForcedUnlessBool,
    /// A path the tool loads whatever its shape, after a leading `!` that disables it.
    ForcedUnbanged,
}

/// When the tool reads an included file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Include {
    /// Every time it reads the including file.
    Always,
    /// Only when the include's condition holds.
    Conditional,
}

/// What a row decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rule {
    /// The setting is consumed so.
    Consume(Consume),
    /// The setting is consumed as the same key without its subsection, which scopes it to a URL or an identity.
    AsUnscoped,
}

/// The number naming a rule, equal exactly when the rules are.
const fn code(rule: Rule) -> u8 {
    match rule {
        Rule::Consume(Consume::Exempt) => 0,
        Rule::Consume(Consume::Inert) => 1,
        Rule::Consume(Consume::Bang) => 2,
        Rule::Consume(Consume::Exec) => 3,
        Rule::Consume(Consume::Composed(Compose::Alias)) => 4,
        Rule::Consume(Consume::Composed(Compose::CredentialHelper)) => 5,
        Rule::Consume(Consume::Composed(Compose::RemoteHelper)) => 6,
        Rule::Consume(Consume::Load(Load::Include(Include::Always))) => 7,
        Rule::Consume(Consume::Load(Load::Include(Include::Conditional))) => 8,
        Rule::Consume(Consume::Load(Load::HooksPath)) => 9,
        Rule::Consume(Consume::Load(Load::Forced)) => 10,
        Rule::Consume(Consume::Load(Load::ForcedUnlessBool)) => 11,
        Rule::Consume(Consume::Load(Load::ForcedUnbanged)) => 12,
        Rule::Consume(Consume::Url { scp: false }) => 13,
        Rule::Consume(Consume::Url { scp: true }) => 14,
        Rule::Consume(Consume::UrlList) => 15,
        Rule::Consume(Consume::RemoteName) => 16,
        Rule::Consume(Consume::PythonHook) => 17,
        Rule::AsUnscoped => 18,
    }
}

const EXEMPT: Rule = Rule::Consume(Consume::Exempt);
const BANG: Rule = Rule::Consume(Consume::Bang);
const EXEC: Rule = Rule::Consume(Consume::Exec);
const ALIAS: Rule = Rule::Consume(Consume::Composed(Compose::Alias));
const HELPER: Rule = Rule::Consume(Consume::Composed(Compose::CredentialHelper));
const REMOTE_HELPER: Rule = Rule::Consume(Consume::Composed(Compose::RemoteHelper));
const INCLUDE: Rule = Rule::Consume(Consume::Load(Load::Include(Include::Always)));
const INCLUDE_IF: Rule = Rule::Consume(Consume::Load(Load::Include(Include::Conditional)));
const HOOKS_PATH: Rule = Rule::Consume(Consume::Load(Load::HooksPath));
const FORCED: Rule = Rule::Consume(Consume::Load(Load::Forced));
const FORCED_UNLESS_BOOL: Rule = Rule::Consume(Consume::Load(Load::ForcedUnlessBool));
const FORCED_UNBANGED: Rule = Rule::Consume(Consume::Load(Load::ForcedUnbanged));
const URL: Rule = Rule::Consume(Consume::Url { scp: false });
const URL_SCP: Rule = Rule::Consume(Consume::Url { scp: true });
const URL_LIST: Rule = Rule::Consume(Consume::UrlList);
const REMOTE_NAME: Rule = Rule::Consume(Consume::RemoteName);
const PYTHON_HOOK: Rule = Rule::Consume(Consume::PythonHook);

/// A setting's spelling and what it decides.
type Row = (&'static str, Rule);

/// Every Git setting with a decided consumption, sorted ignoring ASCII case.
///
/// An alias under a subsection (`[alias "x"] command`) is judged as an alias:
/// one Git does not read runs nothing, one it reads runs so.
const GIT: &[Row] = &[
    ("alias.*", ALIAS),
    ("alias.<name>.*", ALIAS),
    ("blame.ignoreRevsFile", EXEMPT),
    ("branch.*", EXEMPT),
    ("branch.<name>.*", EXEMPT),
    ("branch.<name>.pushRemote", REMOTE_NAME),
    ("branch.<name>.remote", REMOTE_NAME),
    ("browser.<tool>.path", EXEC),
    ("commit.template", EXEMPT),
    ("core.askPass", EXEC),
    ("core.attributesFile", EXEMPT),
    ("core.excludesFile", EXEMPT),
    ("core.fsmonitor", FORCED_UNLESS_BOOL),
    ("core.gitProxy", EXEC),
    ("core.hooksPath", HOOKS_PATH),
    ("core.worktree", EXEMPT),
    ("credential.<url>.helper", HELPER),
    ("credential.helper", HELPER),
    ("difftool.<tool>.path", EXEC),
    ("gpg.<format>.defaultKeyCommand", EXEC),
    ("gpg.<format>.program", EXEC),
    ("gpg.defaultKeyCommand", EXEC),
    ("gpg.program", EXEC),
    ("include.path", INCLUDE),
    ("includeIf.<condition>.path", INCLUDE_IF),
    ("init.templateDir", FORCED),
    ("man.<tool>.path", EXEC),
    ("mergetool.<tool>.path", EXEC),
    ("remote.<name>.fetch", EXEMPT),
    ("remote.<name>.push", EXEMPT),
    ("remote.<name>.pushurl", URL_SCP),
    ("remote.<name>.url", URL_SCP),
    ("remote.<name>.vcs", REMOTE_HELPER),
    ("remote.pushDefault", REMOTE_NAME),
    ("sendemail.<identity>.smtpServer", EXEC),
    ("sendemail.smtpServer", EXEC),
    ("submodule.<name>.update", BANG),
    ("submodule.<name>.url", URL_SCP),
    ("url.<base>.insteadOf", EXEMPT),
    ("url.<base>.pushInsteadOf", EXEMPT),
    ("user.*", EXEMPT),
    ("user.<name>.*", EXEMPT),
];

/// Every Mercurial setting with a decided consumption, sorted ignoring ASCII case.
///
/// A Mercurial key is everything after the section's `.`; `<name>` matches a
/// key holding no `:`, and `*:<option>` a key whose part after its last `:`
/// is that sub-option. Mercurial runs an `[alias]` after one `!` through a
/// shell; a `[schemes]` template or a `[subpaths]` replacement is the URL it
/// reads in place of one it was given, `.hgsub` sources included.
const HG: &[Row] = &[
    ("alias.*", BANG),
    ("extensions.*", FORCED_UNBANGED),
    ("hooks.*", PYTHON_HOOK),
    ("paths.*:pushrev", EXEMPT),
    ("paths.*:pushurl", URL_LIST),
    ("paths.<name>", URL_LIST),
    ("schemes.*", URL),
    ("subpaths.*", URL),
    ("ui.username", EXEMPT),
];

/// The Jujutsu top-level tables whose values never name code.
const JJ_EXEMPT: &[&str] = &[
    "--when",
    "colors",
    "revset-aliases",
    "template-aliases",
    "templates",
    "user",
];

/// How a tool spells and compares its settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// `section.subsection.key`: the subsection is everything between the
    /// first and the last `.`; the section and key compare ignoring ASCII
    /// case, the subsection exactly.
    Git,
    /// `section.key`: the key is everything after the first `.` and compares exactly.
    Hg,
}

/// Which subsections a row matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sub {
    /// Only a setting with no subsection.
    Absent,
    /// Any subsection (`<name>`).
    Present,
    /// A subsection that is this text, compared ignoring ASCII case, then a
    /// name (`customtransfer.<name>`): the tools reading such settings fold
    /// the whole key.
    Prefixed(&'static [u8]),
    /// Exactly this subsection.
    Named(&'static [u8]),
}

/// Which keys a row matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyPat {
    /// Every key (`*`, or Git's `<name>`).
    Any,
    /// A Mercurial key holding no `:` (`<name>`).
    Unsuffixed,
    /// A Mercurial key whose part after its last `:` is this sub-option (`*:<option>`).
    Suboption(&'static [u8]),
    /// Exactly this key.
    Named(&'static [u8]),
}

/// A row with its spelling parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Parsed {
    /// The section.
    section: &'static [u8],
    /// The subsections matched.
    sub: Sub,
    /// The keys matched.
    key: KeyPat,
    /// What the row decides.
    rule: Rule,
    /// The run of rows sharing the section, ignoring ASCII case.
    group: u32,
}

/// The parse of a row that failed to parse.
const BLANK: Parsed = Parsed {
    section: b"",
    sub: Sub::Absent,
    key: KeyPat::Any,
    rule: Rule::AsUnscoped,
    group: 0,
};

/// A table's rows parsed, and whether every spelling parsed and the spellings are strictly sorted.
#[derive(Debug, Clone, Copy)]
struct Table<const N: usize> {
    /// The parsed rows, in the table's order.
    rows: [Parsed; N],
    /// Whether every spelling parsed, in strictly ascending order ignoring ASCII case.
    ok: bool,
}

const GIT_TABLE: Table<{ GIT.len() }> = parse_table(GIT, Shape::Git);
const HG_TABLE: Table<{ HG.len() }> = parse_table(HG, Shape::Hg);

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a Git row's spelling is malformed or out of order, or two Git rows decide one setting differently at equal specificity [ledger #boundary]
const _: () = assert!(GIT_TABLE.ok && rows_disjoint(&GIT_TABLE.rows, Shape::Git));
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a Mercurial row's spelling is malformed or out of order, or two Mercurial rows decide one setting differently at equal specificity [ledger #boundary]
const _: () = assert!(HG_TABLE.ok && rows_disjoint(&HG_TABLE.rows, Shape::Hg));

/// The parsed Git rows.
static GIT_ROWS: [Parsed; GIT.len()] = GIT_TABLE.rows;
/// The parsed Mercurial rows.
static HG_ROWS: [Parsed; HG.len()] = HG_TABLE.rows;

/// How Git consumes `section.subsection.key`, or `None` when no row decides it.
///
/// `section` is lowercase, as Git's parser leaves it; `key` is as written.
pub fn git(section: &str, subsection: Option<&str>, key: &str) -> Option<Consume> {
    let setting = (
        section.as_bytes(),
        subsection.map(str::as_bytes),
        key.as_bytes(),
    );
    match lookup(&GIT_ROWS, Shape::Git, setting)? {
        Rule::Consume(consume) => Some(consume),
        Rule::AsUnscoped => match lookup(&GIT_ROWS, Shape::Git, (setting.0, None, setting.2))? {
            Rule::Consume(consume) => Some(consume),
            Rule::AsUnscoped => None,
        },
    }
}

/// How Mercurial consumes `section.key`, or `None` when no row decides it.
pub fn hg(section: &str, key: &str) -> Option<Consume> {
    match lookup(
        &HG_ROWS,
        Shape::Hg,
        (section.as_bytes(), None, key.as_bytes()),
    )? {
        Rule::Consume(consume) => Some(consume),
        Rule::AsUnscoped => None,
    }
}

/// Whether Jujutsu's top-level `table` never names code.
pub fn jj_exempt(table: &str) -> bool {
    JJ_EXEMPT.contains(&table)
}

/// The rule of the most specific row of `rows` matching `setting`.
fn lookup(rows: &[Parsed], shape: Shape, setting: (&[u8], Option<&[u8]>, &[u8])) -> Option<Rule> {
    let (section, sub, key) = setting;
    let mut best: Option<(Rule, (u8, u8))> = None;
    for row in rows {
        let fits = bytes_eq(row.section, section, folds(shape))
            && sub_fits(row.sub, sub)
            && key_fits(row.key, key, shape);
        let rank = (sub_rank(row.sub), key_rank(row.key));
        if fits && best.is_none_or(|(_, held)| rank > held) {
            best = Some((row.rule, rank));
        }
    }
    best.map(|(rule, _)| rule)
}

/// Whether `shape` compares sections and keys ignoring ASCII case.
const fn folds(shape: Shape) -> bool {
    matches!(shape, Shape::Git)
}

/// How specific a subsection pattern is; only patterns that can match one setting are compared.
const fn sub_rank(sub: Sub) -> u8 {
    match sub {
        Sub::Absent | Sub::Named(_) => 3,
        Sub::Prefixed(_) => 2,
        Sub::Present => 1,
    }
}

/// How specific a key pattern is.
const fn key_rank(key: KeyPat) -> u8 {
    match key {
        KeyPat::Named(_) => 3,
        KeyPat::Unsuffixed | KeyPat::Suboption(_) => 2,
        KeyPat::Any => 1,
    }
}

/// Whether `pattern` matches the subsection `sub`.
const fn sub_fits(pattern: Sub, sub: Option<&[u8]>) -> bool {
    match (pattern, sub) {
        (Sub::Absent, None) | (Sub::Present, Some(_)) => true,
        (Sub::Absent, Some(_)) | (Sub::Present | Sub::Prefixed(_) | Sub::Named(_), None) => false,
        (Sub::Prefixed(prefix), Some(sub)) => {
            sub.len() > prefix.len() && starts_with(sub, prefix, true)
        }
        (Sub::Named(name), Some(sub)) => bytes_eq(sub, name, false),
    }
}

/// Whether `pattern` matches `key` as `shape` compares keys.
const fn key_fits(pattern: KeyPat, key: &[u8], shape: Shape) -> bool {
    match pattern {
        KeyPat::Any => true,
        KeyPat::Unsuffixed => find(key, b':', false).is_none(),
        KeyPat::Suboption(option) => match split_once(key, b':', true) {
            Some((_, after)) => bytes_eq(after, option, false),
            None => false,
        },
        KeyPat::Named(name) => bytes_eq(key, name, folds(shape)),
    }
}

/// Whether some subsection matches both patterns.
const fn subs_overlap(a: Sub, b: Sub) -> bool {
    match (a, b) {
        (Sub::Absent, other) | (other, Sub::Absent) => matches!(other, Sub::Absent),
        (Sub::Present, _) | (_, Sub::Present) => true,
        (Sub::Prefixed(x), Sub::Prefixed(y)) => starts_with(x, y, true) || starts_with(y, x, true),
        (Sub::Prefixed(prefix), Sub::Named(name)) | (Sub::Named(name), Sub::Prefixed(prefix)) => {
            sub_fits(Sub::Prefixed(prefix), Some(name))
        }
        (Sub::Named(x), Sub::Named(y)) => bytes_eq(x, y, false),
    }
}

/// Whether some key matches both patterns as `shape` compares keys.
const fn keys_overlap(a: KeyPat, b: KeyPat, shape: Shape) -> bool {
    match (a, b) {
        (KeyPat::Any, _) | (_, KeyPat::Any) | (KeyPat::Unsuffixed, KeyPat::Unsuffixed) => true,
        (KeyPat::Named(x), KeyPat::Named(y)) => bytes_eq(x, y, folds(shape)),
        (KeyPat::Named(name), other) | (other, KeyPat::Named(name)) => key_fits(other, name, shape),
        (KeyPat::Suboption(x), KeyPat::Suboption(y)) => bytes_eq(x, y, false),
        (KeyPat::Unsuffixed, KeyPat::Suboption(_)) | (KeyPat::Suboption(_), KeyPat::Unsuffixed) => {
            false
        }
    }
}

/// Whether some setting matches both rows.
const fn rows_overlap(a: &Parsed, b: &Parsed, shape: Shape) -> bool {
    bytes_eq(a.section, b.section, folds(shape))
        && subs_overlap(a.sub, b.sub)
        && keys_overlap(a.key, b.key, shape)
}

/// Whether `a` is more specific than `b` in one part and no less in the other.
const fn dominates(a: &Parsed, b: &Parsed) -> bool {
    let (sub_a, sub_b) = (sub_rank(a.sub), sub_rank(b.sub));
    let (key_a, key_b) = (key_rank(a.key), key_rank(b.key));
    sub_a >= sub_b && key_a >= key_b && (sub_a > sub_b || key_a > key_b)
}

/// Whether a row matches more than one setting: a pattern subsection or key.
///
/// Two rows matching one setting each have the same section, subsection,
/// and key, so their spellings fold equal, which the strict order refuses.
const fn wild(row: &Parsed) -> bool {
    !matches!(row.sub, Sub::Absent | Sub::Named(_)) || !matches!(row.key, KeyPat::Named(_))
}

/// Whether every setting two of `rows` match is decided once: the rows agree, or one is more specific.
const fn rows_disjoint(rows: &[Parsed], shape: Shape) -> bool {
    let mut outer = rows;
    while let Some((first, rest)) = outer.split_first() {
        let mut inner = rest;
        while let Some((other, more)) = inner.split_first() {
            if other.group != first.group {
                break;
            }
            let decided = code(first.rule) == code(other.rule)
                || dominates(first, other)
                || dominates(other, first);
            if (wild(first) || wild(other)) && rows_overlap(first, other, shape) && !decided {
                return false;
            }
            inner = more;
        }
        outer = rest;
    }
    true
}

/// Every row of `source` parsed as `shape` spells settings.
const fn parse_table<const N: usize>(source: &[Row], shape: Shape) -> Table<N> {
    let mut rows = [BLANK; N];
    let mut ok = source.len() == N;
    let mut slots: &mut [Parsed] = &mut rows;
    let mut pending = source;
    let mut previous: Option<&[u8]> = None;
    let mut section: Option<&[u8]> = None;
    let mut group = 0_u32;
    while let Some((slot, more_slots)) = slots.split_first_mut() {
        let Some(((spelling, rule), more)) = pending.split_first() else {
            ok = false;
            break;
        };
        let spelling = spelling.as_bytes();
        if let Some(previous) = previous
            && !fold_less(previous, spelling)
        {
            ok = false;
        }
        match parse(spelling, *rule, shape) {
            Some(parsed) => {
                if let Some(held) = section
                    && !bytes_eq(held, parsed.section, true)
                {
                    group = group.saturating_add(1);
                }
                section = Some(parsed.section);
                *slot = Parsed { group, ..parsed };
            }
            None => ok = false,
        }
        previous = Some(spelling);
        slots = more_slots;
        pending = more;
    }
    Table { rows, ok }
}

/// The row spelled `spelling`, as `shape` spells settings, or `None` when the spelling is malformed.
const fn parse(spelling: &'static [u8], rule: Rule, shape: Shape) -> Option<Parsed> {
    let Some((section, rest)) = split_once(spelling, b'.', false) else {
        return None;
    };
    if !is_plain(section, false) {
        return None;
    }
    let (sub, key) = match shape {
        Shape::Hg => (Sub::Absent, rest),
        Shape::Git => match split_once(rest, b'.', true) {
            Some((middle, key)) => match sub_pattern(middle) {
                Some(sub) => (sub, key),
                None => return None,
            },
            None => (Sub::Absent, rest),
        },
    };
    let Some(key) = key_pattern(key, shape) else {
        return None;
    };
    Some(Parsed {
        section,
        sub,
        key,
        rule,
        group: 0,
    })
}

/// The subsection pattern Git's middle spelling `middle` names.
const fn sub_pattern(middle: &'static [u8]) -> Option<Sub> {
    if is_placeholder(middle) {
        return Some(Sub::Present);
    }
    if let Some(at) = find(middle, b'<', true) {
        let Some((prefix, placeholder)) = middle.split_at_checked(at) else {
            return None;
        };
        let Some((dot, stem)) = prefix.split_last() else {
            return None;
        };
        return if *dot == b'.' && is_plain(stem, true) && is_placeholder(placeholder) {
            Some(Sub::Prefixed(prefix))
        } else {
            None
        };
    }
    if is_plain(middle, true) {
        Some(Sub::Named(middle))
    } else {
        None
    }
}

/// The key pattern `key` names, as `shape` spells keys.
const fn key_pattern(key: &'static [u8], shape: Shape) -> Option<KeyPat> {
    if bytes_eq(key, b"*", false) {
        return Some(KeyPat::Any);
    }
    if is_placeholder(key) {
        return Some(match shape {
            Shape::Git => KeyPat::Any,
            Shape::Hg => KeyPat::Unsuffixed,
        });
    }
    if matches!(shape, Shape::Hg)
        && let Some((star, option)) = split_once(key, b':', false)
        && bytes_eq(star, b"*", false)
    {
        return if is_plain(option, false) && find(option, b':', false).is_none() {
            Some(KeyPat::Suboption(option))
        } else {
            None
        };
    }
    if is_plain(key, key_dots(shape)) {
        Some(KeyPat::Named(key))
    } else {
        None
    }
}

/// Whether a `shape` key may hold a `.`, as a Mercurial key may.
const fn key_dots(shape: Shape) -> bool {
    matches!(shape, Shape::Hg)
}

/// Whether `text` is a `<name>` placeholder.
const fn is_placeholder(text: &[u8]) -> bool {
    let Some((&b'<', rest)) = text.split_first() else {
        return false;
    };
    let Some((&b'>', name)) = rest.split_last() else {
        return false;
    };
    is_plain(name, false)
}

/// Whether `text` is non-empty literal spelling: no `<`, `>`, `*`, and, unless `dots`, no `.`; with `dots`, no empty `.`-separated part.
const fn is_plain(text: &[u8], dots: bool) -> bool {
    if text.is_empty() {
        return false;
    }
    let mut rest = text;
    let mut after_dot = true;
    while let Some((byte, more)) = rest.split_first() {
        match *byte {
            b'<' | b'>' | b'*' => return false,
            b'.' if !dots || after_dot => return false,
            b'.' => after_dot = true,
            _ => after_dot = false,
        }
        rest = more;
    }
    !after_dot
}

/// The index of the first (or, when `last`, the last) `byte` in `text`.
const fn find(text: &[u8], byte: u8, last: bool) -> Option<usize> {
    let mut rest = text;
    let mut at = 0_usize;
    let mut found = None;
    while let Some((head, more)) = rest.split_first() {
        if *head == byte {
            found = Some(at);
            if !last {
                return found;
            }
        }
        at = at.saturating_add(1);
        rest = more;
    }
    found
}

/// `text` split around its first (or, when `last`, its last) `byte`, the byte dropped.
const fn split_once(text: &[u8], byte: u8, last: bool) -> Option<(&[u8], &[u8])> {
    let Some(at) = find(text, byte, last) else {
        return None;
    };
    let Some((before, from)) = text.split_at_checked(at) else {
        return None;
    };
    match from.split_first() {
        Some((_, after)) => Some((before, after)),
        None => None,
    }
}

/// Whether `a` and `b` are equal, ignoring ASCII case when `fold`.
const fn bytes_eq(a: &[u8], b: &[u8], fold: bool) -> bool {
    a.len() == b.len() && starts_with(a, b, fold)
}

/// Whether `text` starts with `prefix`, ignoring ASCII case when `fold`.
const fn starts_with(text: &[u8], prefix: &[u8], fold: bool) -> bool {
    let (mut text, mut prefix) = (text, prefix);
    while let Some((want, more_prefix)) = prefix.split_first() {
        let Some((have, more_text)) = text.split_first() else {
            return false;
        };
        let same = if fold {
            have.eq_ignore_ascii_case(want)
        } else {
            *have == *want
        };
        if !same {
            return false;
        }
        text = more_text;
        prefix = more_prefix;
    }
    true
}

/// Whether `a` sorts strictly before `b`, comparing bytes ignoring ASCII case.
const fn fold_less(a: &[u8], b: &[u8]) -> bool {
    let (mut a, mut b) = (a, b);
    loop {
        match (a.split_first(), b.split_first()) {
            (Some((x, more_a)), Some((y, more_b))) => {
                let (x, y) = (x.to_ascii_lowercase(), y.to_ascii_lowercase());
                if x != y {
                    return x < y;
                }
                a = more_a;
                b = more_b;
            }
            (None, Some(_)) => return true,
            (Some(_) | None, None) => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether `rows` parse, in order, and decide every setting once.
    fn decided<const N: usize>(rows: &[Row; N], shape: Shape) -> bool {
        let table: Table<N> = parse_table(rows, shape);
        table.ok && rows_disjoint(&table.rows, shape)
    }

    #[test]
    fn rows_disjoint_rejects_overlap() {
        // `a.b.k` matches both, and neither row is more specific in both parts.
        assert!(!decided(
            &[("a.<n>.k", EXEC), ("a.b.*", EXEMPT)],
            Shape::Git
        ));
        // Controls: the rows agree, or one is more specific in both parts.
        assert!(decided(&[("a.<n>.k", EXEC), ("a.b.*", EXEC)], Shape::Git));
        assert!(decided(
            &[("a.<n>.*", EXEMPT), ("a.<n>.k", EXEC)],
            Shape::Git
        ));
        assert!(decided(&[("a.<n>.k", EXEC), ("b.c.*", EXEMPT)], Shape::Git));
        // A prefixed subsection is more specific than any subsection.
        assert!(decided(
            &[("a.<n>.*", EXEMPT), ("a.p.<n>.k", EXEC)],
            Shape::Git
        ));
        assert!(!decided(
            &[("a.p.<n>.k", EXEMPT), ("a.p.q.*", EXEC)],
            Shape::Git
        ));
        assert!(decided(
            &[("a.p.<n>.k", EXEMPT), ("a.pq.*", EXEC)],
            Shape::Git
        ));
        // A Mercurial `<name>` key and a `*:<option>` key never match one key, and a named key is more specific than either.
        assert!(decided(
            &[("p.*:x", EXEMPT), ("p.<name>", URL_LIST)],
            Shape::Hg
        ));
        assert!(decided(
            &[("p.*:x", EXEMPT), ("p.k:x", URL_LIST)],
            Shape::Hg
        ));
        assert!(decided(
            &[("p.*:x", EXEMPT), ("p.k:y", URL_LIST)],
            Shape::Hg
        ));
    }

    #[test]
    fn malformed_or_unordered_rows_refused() {
        assert!(!decided(&[("a.z", EXEC), ("a.b", EXEC)], Shape::Git));
        assert!(!decided(&[("a.B", EXEC), ("a.b", EXEMPT)], Shape::Git));
        for spelling in [
            "a..b",
            "a.<n.k",
            "nodot",
            ".k",
            "a.",
            "a.<n>x.k",
            "a.<n>.<m>.k",
        ] {
            assert!(!decided(&[(spelling, EXEC)], Shape::Git), "{spelling}");
        }
        for spelling in ["a.*:", "a.*:x:y", "a.<n"] {
            assert!(!decided(&[(spelling, EXEC)], Shape::Hg), "{spelling}");
        }
        // Controls.
        assert!(decided(&[("a.b", EXEC), ("a.z", EXEC)], Shape::Git));
        assert!(decided(&[("a.p.<n>.k", EXEC)], Shape::Git));
        assert!(decided(&[("a.b.c", EXEC)], Shape::Hg));
    }

    #[test]
    fn most_specific_row_wins() {
        let branch = |key| git("branch", Some("main"), key);
        assert_eq!(branch("remote"), Some(Consume::RemoteName));
        assert_eq!(branch("pushremote"), Some(Consume::RemoteName));
        assert_eq!(branch("merge"), Some(Consume::Exempt));
        assert_eq!(git("branch", None, "sort"), Some(Consume::Exempt));
        assert_eq!(
            git("core", None, "HOOKSPATH"),
            Some(Consume::Load(Load::HooksPath))
        );
        assert_eq!(git("core", Some("x"), "hookspath"), None);
        assert_eq!(hg("paths", "default"), Some(Consume::UrlList));
        assert_eq!(hg("paths", "default:pushurl"), Some(Consume::UrlList));
        assert_eq!(hg("paths", "default:pushrev"), Some(Consume::Exempt));
        assert_eq!(hg("paths", "default:bookmarks.mode"), None);
        assert_eq!(hg("UI", "username"), None);
        assert!(jj_exempt("templates"));
        assert!(!jj_exempt("ui"));
    }
}
