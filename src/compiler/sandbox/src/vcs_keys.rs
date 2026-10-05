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
    /// Run through a shell as a command line.
    Shell,
    /// One leading `!` makes the rest a shell command; otherwise the value is data.
    Bang,
    /// Run without a shell as one program: a `~`, a quote, or a space is part of its path.
    Exec,
    /// Composed into a program name before it runs.
    Composed(Compose),
    /// A name the tool resolves inside its own directory or table (`merge.tool` sources `<exec-path>/mergetools/<name>`).
    ToolName,
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
        Rule::Consume(Consume::Shell) => 7,
        Rule::Consume(Consume::ToolName) => 8,
        Rule::Consume(Consume::Load(Load::Include(Include::Always))) => 9,
        Rule::Consume(Consume::Load(Load::Include(Include::Conditional))) => 10,
        Rule::Consume(Consume::Load(Load::HooksPath)) => 11,
        Rule::Consume(Consume::Load(Load::Forced)) => 12,
        Rule::Consume(Consume::Load(Load::ForcedUnlessBool)) => 13,
        Rule::Consume(Consume::Load(Load::ForcedUnbanged)) => 14,
        Rule::Consume(Consume::Url { scp: false }) => 15,
        Rule::Consume(Consume::Url { scp: true }) => 16,
        Rule::Consume(Consume::UrlList) => 17,
        Rule::Consume(Consume::RemoteName) => 18,
        Rule::Consume(Consume::PythonHook) => 19,
        Rule::AsUnscoped => 20,
    }
}

const EXEMPT: Rule = Rule::Consume(Consume::Exempt);
const INERT: Rule = Rule::Consume(Consume::Inert);
const SHELL: Rule = Rule::Consume(Consume::Shell);
const TOOL_NAME: Rule = Rule::Consume(Consume::ToolName);
const UNSCOPED: Rule = Rule::AsUnscoped;
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
/// Every spelling of the snapshot in `data/git-config-keys.txt` has a row, as
/// does every setting `GIT_UNDOCUMENTED` names with its source: one an
/// in-repository writer (git-lfs, git-flow, the GitHub CLI) or a later Git
/// release reads. An alias under a subsection (`[alias "x"] command`) is
/// judged as an alias: one Git does not read runs nothing, one it reads runs
/// so.
const GIT: &[Row] = &[
    ("add.ignoreErrors", INERT),
    ("add.interactive.useBuiltin", INERT),
    ("advice.*", INERT),
    ("advice.addEmbeddedRepo", INERT),
    ("advice.addEmptyPathspec", INERT),
    ("advice.addIgnoredFile", INERT),
    ("advice.amWorkDir", INERT),
    ("advice.checkoutAmbiguousRemoteBranchName", INERT),
    ("advice.commitBeforeMerge", INERT),
    ("advice.detachedHead", INERT),
    ("advice.fetchShowForcedUpdates", INERT),
    ("advice.graftFileDeprecated", INERT),
    ("advice.ignoredHook", INERT),
    ("advice.implicitIdentity", INERT),
    ("advice.nestedTag", INERT),
    ("advice.objectNameWarning", INERT),
    ("advice.pushAlreadyExists", INERT),
    ("advice.pushFetchFirst", INERT),
    ("advice.pushNeedsForce", INERT),
    ("advice.pushNonFastForward", INERT),
    ("advice.pushNonFFCurrent", INERT),
    ("advice.pushNonFFMatching", INERT),
    ("advice.pushRefNeedsUpdate", INERT),
    ("advice.pushUnqualifiedRefName", INERT),
    ("advice.pushUpdateRejected", INERT),
    ("advice.resetQuiet", INERT),
    ("advice.resolveConflict", INERT),
    ("advice.rmHints", INERT),
    ("advice.sequencerInUse", INERT),
    ("advice.setUpstreamFailure", INERT),
    ("advice.skippedCherryPicks", INERT),
    ("advice.statusAheadBehindWarning", INERT),
    ("advice.statusHints", INERT),
    ("advice.statusUoption", INERT),
    ("advice.submoduleAlternateErrorStrategyDie", INERT),
    ("advice.updateSparsePath", INERT),
    ("advice.waitingForEditor", INERT),
    ("alias.*", ALIAS),
    ("alias.<name>.*", ALIAS),
    ("am.keepcr", INERT),
    ("am.threeWay", INERT),
    ("apply.ignoreWhitespace", INERT),
    ("apply.whitespace", INERT),
    ("author.email", INERT),
    ("author.name", INERT),
    ("blame.blankBoundary", INERT),
    ("blame.coloring", INERT),
    ("blame.date", INERT),
    ("blame.ignoreRevsFile", EXEMPT),
    ("blame.markIgnoredLines", INERT),
    ("blame.markUnblamableLines", INERT),
    ("blame.showEmail", INERT),
    ("blame.showRoot", INERT),
    ("branch.*", EXEMPT),
    ("branch.<name>.*", EXEMPT),
    ("branch.<name>.description", EXEMPT),
    ("branch.<name>.merge", EXEMPT),
    ("branch.<name>.mergeOptions", EXEMPT),
    ("branch.<name>.pushRemote", REMOTE_NAME),
    ("branch.<name>.rebase", EXEMPT),
    ("branch.<name>.remote", REMOTE_NAME),
    ("branch.autoSetupMerge", EXEMPT),
    ("branch.autoSetupRebase", EXEMPT),
    ("branch.sort", EXEMPT),
    ("browser.<tool>.cmd", SHELL),
    ("browser.<tool>.path", EXEC),
    ("checkout.defaultRemote", INERT),
    ("checkout.guess", INERT),
    ("checkout.thresholdForParallelism", INERT),
    ("checkout.workers", INERT),
    ("clean.requireForce", INERT),
    ("clone.defaultRemoteName", INERT),
    ("clone.rejectShallow", INERT),
    ("color.advice", INERT),
    ("color.advice.hint", INERT),
    ("color.blame.highlightRecent", INERT),
    ("color.blame.repeatedLines", INERT),
    ("color.branch", INERT),
    ("color.branch.<slot>", INERT),
    ("color.branch.current", INERT),
    ("color.branch.local", INERT),
    ("color.branch.plain", INERT),
    ("color.branch.remote", INERT),
    ("color.branch.reset", INERT),
    ("color.branch.upstream", INERT),
    ("color.branch.worktree", INERT),
    ("color.decorate.<slot>", INERT),
    ("color.decorate.branch", INERT),
    ("color.decorate.grafted", INERT),
    ("color.decorate.HEAD", INERT),
    ("color.decorate.remoteBranch", INERT),
    ("color.decorate.stash", INERT),
    ("color.decorate.tag", INERT),
    ("color.diff", INERT),
    ("color.diff.<slot>", INERT),
    ("color.diff.commit", INERT),
    ("color.diff.context", INERT),
    ("color.diff.contextBold", INERT),
    ("color.diff.contextDimmed", INERT),
    ("color.diff.frag", INERT),
    ("color.diff.func", INERT),
    ("color.diff.meta", INERT),
    ("color.diff.new", INERT),
    ("color.diff.newBold", INERT),
    ("color.diff.newDimmed", INERT),
    ("color.diff.newMoved", INERT),
    ("color.diff.newMovedAlternative", INERT),
    ("color.diff.newMovedAlternativeDimmed", INERT),
    ("color.diff.newMovedDimmed", INERT),
    ("color.diff.old", INERT),
    ("color.diff.oldBold", INERT),
    ("color.diff.oldDimmed", INERT),
    ("color.diff.oldMoved", INERT),
    ("color.diff.oldMovedAlternative", INERT),
    ("color.diff.oldMovedAlternativeDimmed", INERT),
    ("color.diff.oldMovedDimmed", INERT),
    ("color.diff.plain", INERT),
    ("color.diff.whitespace", INERT),
    ("color.grep", INERT),
    ("color.grep.<slot>", INERT),
    ("color.grep.column", INERT),
    ("color.grep.context", INERT),
    ("color.grep.filename", INERT),
    ("color.grep.function", INERT),
    ("color.grep.lineNumber", INERT),
    ("color.grep.match", INERT),
    ("color.grep.matchContext", INERT),
    ("color.grep.matchSelected", INERT),
    ("color.grep.selected", INERT),
    ("color.grep.separator", INERT),
    ("color.interactive", INERT),
    ("color.interactive.<slot>", INERT),
    ("color.interactive.error", INERT),
    ("color.interactive.header", INERT),
    ("color.interactive.help", INERT),
    ("color.interactive.plain", INERT),
    ("color.interactive.prompt", INERT),
    ("color.interactive.reset", INERT),
    ("color.pager", INERT),
    ("color.push", INERT),
    ("color.push.error", INERT),
    ("color.remote", INERT),
    ("color.remote.<slot>", INERT),
    ("color.remote.error", INERT),
    ("color.remote.hint", INERT),
    ("color.remote.success", INERT),
    ("color.remote.warning", INERT),
    ("color.showBranch", INERT),
    ("color.status", INERT),
    ("color.status.<slot>", INERT),
    ("color.status.added", INERT),
    ("color.status.branch", INERT),
    ("color.status.changed", INERT),
    ("color.status.header", INERT),
    ("color.status.localBranch", INERT),
    ("color.status.noBranch", INERT),
    ("color.status.remoteBranch", INERT),
    ("color.status.unmerged", INERT),
    ("color.status.untracked", INERT),
    ("color.status.updated", INERT),
    ("color.transport", INERT),
    ("color.transport.rejected", INERT),
    ("color.ui", INERT),
    ("column.branch", INERT),
    ("column.clean", INERT),
    ("column.status", INERT),
    ("column.tag", INERT),
    ("column.ui", INERT),
    ("commit.cleanup", INERT),
    ("commit.gpgSign", INERT),
    ("commit.status", INERT),
    ("commit.template", EXEMPT),
    ("commit.verbose", INERT),
    ("commitGraph.generationVersion", INERT),
    ("commitGraph.maxNewFilters", INERT),
    ("commitGraph.readChangedPaths", INERT),
    ("committer.email", INERT),
    ("committer.name", INERT),
    ("completion.commands", INERT),
    ("core.abbrev", INERT),
    ("core.alternateRefsCommand", SHELL),
    ("core.alternateRefsPrefixes", INERT),
    ("core.askPass", EXEC),
    ("core.attributesFile", EXEMPT),
    ("core.autocrlf", INERT),
    ("core.bare", INERT),
    ("core.bigFileThreshold", INERT),
    ("core.checkRoundtripEncoding", INERT),
    ("core.checkStat", INERT),
    ("core.commentChar", INERT),
    ("core.commitGraph", INERT),
    ("core.compression", INERT),
    ("core.createObject", INERT),
    ("core.deltaBaseCacheLimit", INERT),
    ("core.editor", SHELL),
    ("core.eol", INERT),
    ("core.excludesFile", EXEMPT),
    ("core.fileMode", INERT),
    ("core.filesRefLockTimeout", INERT),
    ("core.fsmonitor", FORCED_UNLESS_BOOL),
    ("core.fsmonitorHookVersion", INERT),
    ("core.fsyncObjectFiles", INERT),
    ("core.gitProxy", EXEC),
    ("core.hideDotFiles", INERT),
    ("core.hooksPath", HOOKS_PATH),
    ("core.ignoreCase", INERT),
    ("core.ignoreStat", INERT),
    ("core.logAllRefUpdates", INERT),
    ("core.looseCompression", INERT),
    ("core.multiPackIndex", INERT),
    ("core.notesRef", INERT),
    ("core.packedGitLimit", INERT),
    ("core.packedGitWindowSize", INERT),
    ("core.packedRefsTimeout", INERT),
    ("core.pager", SHELL),
    ("core.precomposeUnicode", INERT),
    ("core.preferSymlinkRefs", INERT),
    ("core.preloadIndex", INERT),
    ("core.protectHFS", INERT),
    ("core.protectNTFS", INERT),
    ("core.quotePath", INERT),
    ("core.repositoryFormatVersion", INERT),
    ("core.restrictinheritedhandles", INERT),
    ("core.safecrlf", INERT),
    ("core.sharedRepository", INERT),
    ("core.sparseCheckout", INERT),
    ("core.sparseCheckoutCone", INERT),
    ("core.splitIndex", INERT),
    ("core.sshCommand", SHELL),
    ("core.symlinks", INERT),
    ("core.trustctime", INERT),
    ("core.unsetenvvars", INERT),
    ("core.untrackedCache", INERT),
    ("core.useReplaceRefs", INERT),
    ("core.warnAmbiguousRefs", INERT),
    ("core.whitespace", INERT),
    ("core.worktree", EXEMPT),
    ("credential.<url>.*", UNSCOPED),
    ("credential.helper", HELPER),
    ("credential.protectProtocol", INERT),
    ("credential.sanitizePrompt", INERT),
    ("credential.useHttpPath", INERT),
    ("credential.username", INERT),
    ("credentialCache.ignoreSIGHUP", INERT),
    ("credentialStore.lockTimeoutMS", INERT),
    ("diff.<driver>.binary", INERT),
    ("diff.<driver>.cachetextconv", INERT),
    ("diff.<driver>.command", SHELL),
    ("diff.<driver>.textconv", SHELL),
    ("diff.<driver>.wordRegex", INERT),
    ("diff.<driver>.xfuncname", INERT),
    ("diff.algorithm", INERT),
    ("diff.autoRefreshIndex", INERT),
    ("diff.colorMoved", INERT),
    ("diff.colorMovedWS", INERT),
    ("diff.context", INERT),
    ("diff.dirstat", INERT),
    ("diff.external", SHELL),
    ("diff.guitool", TOOL_NAME),
    ("diff.ignoreSubmodules", INERT),
    ("diff.indentHeuristic", INERT),
    ("diff.interHunkContext", INERT),
    ("diff.mnemonicPrefix", INERT),
    ("diff.noprefix", INERT),
    ("diff.orderFile", INERT),
    ("diff.relative", INERT),
    ("diff.renameLimit", INERT),
    ("diff.renames", INERT),
    ("diff.statGraphWidth", INERT),
    ("diff.submodule", INERT),
    ("diff.suppressBlankEmpty", INERT),
    ("diff.tool", TOOL_NAME),
    ("diff.wordRegex", INERT),
    ("diff.wsErrorHighlight", INERT),
    ("difftool.<tool>.cmd", SHELL),
    ("difftool.<tool>.path", EXEC),
    ("difftool.prompt", INERT),
    ("extensions.*", INERT),
    ("extensions.objectFormat", INERT),
    ("fastimport.unpackLimit", INERT),
    ("feature.*", INERT),
    ("feature.experimental", INERT),
    ("feature.manyFiles", INERT),
    ("fetch.bundleURI", URL),
    ("fetch.fsck.<msg-id>", INERT),
    ("fetch.fsck.skipList", INERT),
    ("fetch.fsckObjects", INERT),
    ("fetch.negotiationAlgorithm", INERT),
    ("fetch.output", INERT),
    ("fetch.parallel", INERT),
    ("fetch.prune", INERT),
    ("fetch.pruneTags", INERT),
    ("fetch.recurseSubmodules", INERT),
    ("fetch.showForcedUpdates", INERT),
    ("fetch.unpackLimit", INERT),
    ("fetch.writeCommitGraph", INERT),
    ("filter.<driver>.clean", SHELL),
    ("filter.<driver>.process", SHELL),
    ("filter.<driver>.required", INERT),
    ("filter.<driver>.smudge", SHELL),
    ("format.attach", INERT),
    ("format.cc", INERT),
    ("format.coverFromDescription", INERT),
    ("format.coverLetter", INERT),
    ("format.encodeEmailHeaders", INERT),
    ("format.filenameMaxLength", INERT),
    ("format.from", INERT),
    ("format.headers", INERT),
    ("format.notes", INERT),
    ("format.numbered", INERT),
    ("format.outputDirectory", INERT),
    ("format.pretty", INERT),
    ("format.signature", INERT),
    ("format.signatureFile", INERT),
    ("format.signOff", INERT),
    ("format.subjectPrefix", INERT),
    ("format.suffix", INERT),
    ("format.thread", INERT),
    ("format.to", INERT),
    ("format.useAutoBase", INERT),
    ("fsck.<msg-id>", INERT),
    ("fsck.badDate", INERT),
    ("fsck.badDateOverflow", INERT),
    ("fsck.badEmail", INERT),
    ("fsck.badFilemode", INERT),
    ("fsck.badName", INERT),
    ("fsck.badObjectSha1", INERT),
    ("fsck.badParentSha1", INERT),
    ("fsck.badTagName", INERT),
    ("fsck.badTagObject", INERT),
    ("fsck.badTimezone", INERT),
    ("fsck.badTree", INERT),
    ("fsck.badTreeSha1", INERT),
    ("fsck.badType", INERT),
    ("fsck.duplicateEntries", INERT),
    ("fsck.emptyName", INERT),
    ("fsck.extraHeaderEntry", INERT),
    ("fsck.fullPathname", INERT),
    ("fsck.gitattributesSymlink", INERT),
    ("fsck.gitignoreSymlink", INERT),
    ("fsck.gitmodulesBlob", INERT),
    ("fsck.gitmodulesLarge", INERT),
    ("fsck.gitmodulesMissing", INERT),
    ("fsck.gitmodulesName", INERT),
    ("fsck.gitmodulesParse", INERT),
    ("fsck.gitmodulesPath", INERT),
    ("fsck.gitmodulesSymlink", INERT),
    ("fsck.gitmodulesUpdate", INERT),
    ("fsck.gitmodulesUrl", INERT),
    ("fsck.hasDot", INERT),
    ("fsck.hasDotdot", INERT),
    ("fsck.hasDotgit", INERT),
    ("fsck.mailmapSymlink", INERT),
    ("fsck.missingAuthor", INERT),
    ("fsck.missingCommitter", INERT),
    ("fsck.missingEmail", INERT),
    ("fsck.missingNameBeforeEmail", INERT),
    ("fsck.missingObject", INERT),
    ("fsck.missingSpaceBeforeDate", INERT),
    ("fsck.missingSpaceBeforeEmail", INERT),
    ("fsck.missingTag", INERT),
    ("fsck.missingTagEntry", INERT),
    ("fsck.missingTaggerEntry", INERT),
    ("fsck.missingTree", INERT),
    ("fsck.missingTreeObject", INERT),
    ("fsck.missingType", INERT),
    ("fsck.missingTypeEntry", INERT),
    ("fsck.multipleAuthors", INERT),
    ("fsck.nulInCommit", INERT),
    ("fsck.nulInHeader", INERT),
    ("fsck.nullSha1", INERT),
    ("fsck.skipList", INERT),
    ("fsck.treeNotSorted", INERT),
    ("fsck.unknownType", INERT),
    ("fsck.unterminatedHeader", INERT),
    ("fsck.zeroPaddedDate", INERT),
    ("fsck.zeroPaddedFilemode", INERT),
    ("gc.<pattern>.reflogExpire", INERT),
    ("gc.<pattern>.reflogExpireUnreachable", INERT),
    ("gc.aggressiveDepth", INERT),
    ("gc.aggressiveWindow", INERT),
    ("gc.auto", INERT),
    ("gc.autoDetach", INERT),
    ("gc.autoPackLimit", INERT),
    ("gc.bigPackThreshold", INERT),
    ("gc.logExpiry", INERT),
    ("gc.packRefs", INERT),
    ("gc.pruneExpire", INERT),
    ("gc.reflogExpire", INERT),
    ("gc.reflogExpireUnreachable", INERT),
    ("gc.rerereResolved", INERT),
    ("gc.rerereUnresolved", INERT),
    ("gc.worktreePruneExpire", INERT),
    ("gc.writeCommitGraph", INERT),
    ("gitcvs.allBinary", INERT),
    ("gitcvs.commitMsgAnnotation", INERT),
    ("gitcvs.dbDriver", TOOL_NAME),
    ("gitcvs.dbName", INERT),
    ("gitcvs.dbPass", INERT),
    ("gitcvs.dbTableNamePrefix", INERT),
    ("gitcvs.dbUser", INERT),
    ("gitcvs.enabled", INERT),
    ("gitcvs.logFile", INERT),
    ("gitcvs.usecrlfattr", INERT),
    ("gitflow.*", INERT),
    ("gitflow.<section>.*", INERT),
    ("gitflow.path.hooks", HOOKS_PATH),
    ("gitweb.avatar", INERT),
    ("gitweb.blame", INERT),
    ("gitweb.category", INERT),
    ("gitweb.description", INERT),
    ("gitweb.grep", INERT),
    ("gitweb.highlight", INERT),
    ("gitweb.owner", INERT),
    ("gitweb.patches", INERT),
    ("gitweb.pickaxe", INERT),
    ("gitweb.remote_heads", INERT),
    ("gitweb.showSizes", INERT),
    ("gitweb.snapshot", INERT),
    ("gitweb.url", INERT),
    ("gpg.<format>.program", EXEC),
    ("gpg.format", INERT),
    ("gpg.minTrustLevel", INERT),
    ("gpg.program", EXEC),
    ("gpg.ssh.allowedSignersFile", INERT),
    ("gpg.ssh.defaultKeyCommand", EXEC),
    ("gpg.ssh.revocationFile", INERT),
    ("grep.column", INERT),
    ("grep.extendedRegexp", INERT),
    ("grep.fallbackToNoIndex", INERT),
    ("grep.lineNumber", INERT),
    ("grep.patternType", INERT),
    ("grep.threads", INERT),
    ("gui.*", INERT),
    ("gui.blamehistoryctx", INERT),
    ("gui.commitMsgWidth", INERT),
    ("gui.copyBlameThreshold", INERT),
    ("gui.diffContext", INERT),
    ("gui.displayUntracked", INERT),
    ("gui.encoding", INERT),
    ("gui.fastCopyBlame", INERT),
    ("gui.matchTrackingBranch", INERT),
    ("gui.newBranchTemplate", INERT),
    ("gui.pruneDuringFetch", INERT),
    ("gui.spellingDictionary", INERT),
    ("gui.trustmtime", INERT),
    ("guitool.<name>.argPrompt", INERT),
    ("guitool.<name>.cmd", SHELL),
    ("guitool.<name>.confirm", INERT),
    ("guitool.<name>.needsFile", INERT),
    ("guitool.<name>.noConsole", INERT),
    ("guitool.<name>.noRescan", INERT),
    ("guitool.<name>.prompt", INERT),
    ("guitool.<name>.revPrompt", INERT),
    ("guitool.<name>.revUnmerged", INERT),
    ("guitool.<name>.title", INERT),
    ("help.autoCorrect", INERT),
    ("help.browser", TOOL_NAME),
    ("help.format", INERT),
    ("help.htmlPath", INERT),
    ("hook.<name>.command", SHELL),
    ("hook.<name>.event", INERT),
    ("http.<url>.*", UNSCOPED),
    ("http.cookieFile", INERT),
    ("http.delegation", INERT),
    ("http.emptyAuth", INERT),
    ("http.extraHeader", INERT),
    ("http.followRedirects", INERT),
    ("http.lowSpeedLimit", INERT),
    ("http.lowSpeedTime", INERT),
    ("http.maxRequests", INERT),
    ("http.minSessions", INERT),
    ("http.noEPSV", INERT),
    ("http.pinnedpubkey", INERT),
    ("http.postBuffer", INERT),
    ("http.proxy", INERT),
    ("http.proxyAuthMethod", INERT),
    ("http.proxySSLCAInfo", INERT),
    ("http.proxySSLCert", INERT),
    ("http.proxySSLCertPasswordProtected", INERT),
    ("http.proxySSLKey", INERT),
    ("http.saveCookies", INERT),
    ("http.schannelCheckRevoke", INERT),
    ("http.schannelUseSSLCAInfo", INERT),
    ("http.sslBackend", INERT),
    ("http.sslCAInfo", INERT),
    ("http.sslCAPath", INERT),
    ("http.sslCert", INERT),
    ("http.sslCertPasswordProtected", INERT),
    ("http.sslCipherList", INERT),
    ("http.sslKey", INERT),
    ("http.sslTry", INERT),
    ("http.sslVerify", INERT),
    ("http.sslVersion", INERT),
    ("http.userAgent", INERT),
    ("http.version", INERT),
    ("i18n.commitEncoding", INERT),
    ("i18n.logOutputEncoding", INERT),
    ("imap.authMethod", INERT),
    ("imap.folder", INERT),
    ("imap.host", INERT),
    ("imap.pass", INERT),
    ("imap.port", INERT),
    ("imap.preformattedHTML", INERT),
    ("imap.sslverify", INERT),
    ("imap.tunnel", SHELL),
    ("imap.user", INERT),
    ("include.path", INCLUDE),
    ("includeIf.<condition>.path", INCLUDE_IF),
    ("index.recordEndOfIndexEntries", INERT),
    ("index.recordOffsetTable", INERT),
    ("index.sparse", INERT),
    ("index.threads", INERT),
    ("index.version", INERT),
    ("init.defaultBranch", INERT),
    ("init.templateDir", FORCED),
    ("instaweb.browser", TOOL_NAME),
    ("instaweb.httpd", SHELL),
    ("instaweb.local", INERT),
    ("instaweb.modulePath", FORCED),
    ("instaweb.port", INERT),
    ("interactive.diffFilter", SHELL),
    ("interactive.singleKey", INERT),
    ("lfs.<url>.access", INERT),
    ("lfs.<url>.contenttype", INERT),
    ("lfs.<url>.locksverify", INERT),
    ("lfs.activitytimeout", INERT),
    ("lfs.allowincompletepush", INERT),
    ("lfs.basictransfersonly", INERT),
    ("lfs.cachecredentials", INERT),
    ("lfs.concurrenttransfers", INERT),
    ("lfs.contenttype", INERT),
    ("lfs.customtransfer.<name>.args", SHELL),
    ("lfs.customtransfer.<name>.concurrent", INERT),
    ("lfs.customtransfer.<name>.direction", INERT),
    ("lfs.customtransfer.<name>.path", EXEC),
    ("lfs.defaulttokenttl", INERT),
    ("lfs.dialtimeout", INERT),
    ("lfs.extension.<name>.clean", SHELL),
    ("lfs.extension.<name>.priority", INERT),
    ("lfs.extension.<name>.smudge", SHELL),
    ("lfs.fetchexclude", INERT),
    ("lfs.fetchinclude", INERT),
    ("lfs.fetchrecentalways", INERT),
    ("lfs.fetchrecentcommitsdays", INERT),
    ("lfs.fetchrecentrefsdays", INERT),
    ("lfs.fetchrecentremoterefs", INERT),
    ("lfs.keepalive", INERT),
    ("lfs.lockignoredfiles", INERT),
    ("lfs.locksverify", INERT),
    ("lfs.pruneoffsetdays", INERT),
    ("lfs.pruneremotetocheck", INERT),
    ("lfs.pruneverifyremotealways", INERT),
    ("lfs.pruneverifyunreachablealways", INERT),
    ("lfs.pushurl", URL),
    ("lfs.repositoryformatversion", INERT),
    ("lfs.setlockablereadonly", INERT),
    ("lfs.skipdownloaderrors", INERT),
    ("lfs.ssh.automultiplex", INERT),
    ("lfs.ssh.retries", INERT),
    ("lfs.standalonetransferagent", TOOL_NAME),
    ("lfs.storage", INERT),
    ("lfs.tlstimeout", INERT),
    ("lfs.transfer.enablehrefrewrite", INERT),
    ("lfs.transfer.maxretries", INERT),
    ("lfs.transfer.maxretrydelay", INERT),
    ("lfs.transfer.maxverifies", INERT),
    ("lfs.tustransfers", INERT),
    ("lfs.url", URL),
    ("log.abbrevCommit", INERT),
    ("log.date", INERT),
    ("log.decorate", INERT),
    ("log.diffMerges", INERT),
    ("log.excludeDecoration", INERT),
    ("log.follow", INERT),
    ("log.graphColors", INERT),
    ("log.mailmap", INERT),
    ("log.showRoot", INERT),
    ("log.showSignature", INERT),
    ("lsrefs.unborn", INERT),
    ("mailinfo.scissors", INERT),
    ("mailmap.blob", INERT),
    ("mailmap.file", INERT),
    ("maintenance.<task>.enabled", INERT),
    ("maintenance.<task>.schedule", INERT),
    ("maintenance.auto", INERT),
    ("maintenance.commit-graph.auto", INERT),
    ("maintenance.incremental-repack.auto", INERT),
    ("maintenance.loose-objects.auto", INERT),
    ("maintenance.strategy", INERT),
    ("man.<tool>.cmd", SHELL),
    ("man.<tool>.path", EXEC),
    ("man.viewer", TOOL_NAME),
    ("merge.<driver>.driver", SHELL),
    ("merge.<driver>.name", INERT),
    ("merge.<driver>.recursive", INERT),
    ("merge.autoStash", INERT),
    ("merge.branchdesc", INERT),
    ("merge.conflictStyle", INERT),
    ("merge.defaultToUpstream", INERT),
    ("merge.directoryRenames", INERT),
    ("merge.ff", INERT),
    ("merge.guitool", TOOL_NAME),
    ("merge.log", INERT),
    ("merge.renameLimit", INERT),
    ("merge.renames", INERT),
    ("merge.renormalize", INERT),
    ("merge.stat", INERT),
    ("merge.suppressDest", INERT),
    ("merge.tool", TOOL_NAME),
    ("merge.verbosity", INERT),
    ("merge.verifySignatures", INERT),
    ("mergetool.<tool>.cmd", SHELL),
    ("mergetool.<tool>.hideResolved", INERT),
    ("mergetool.<tool>.path", EXEC),
    ("mergetool.<tool>.trustExitCode", INERT),
    ("mergetool.hideResolved", INERT),
    ("mergetool.keepBackup", INERT),
    ("mergetool.keepTemporaries", INERT),
    ("mergetool.meld.hasOutput", INERT),
    ("mergetool.meld.useAutoMerge", INERT),
    ("mergetool.prompt", INERT),
    ("mergetool.writeToTemp", INERT),
    ("notes.<name>.mergeStrategy", INERT),
    ("notes.displayRef", INERT),
    ("notes.mergeStrategy", INERT),
    ("notes.rewrite.<command>", INERT),
    ("notes.rewriteMode", INERT),
    ("notes.rewriteRef", INERT),
    ("pack.allowPackReuse", INERT),
    ("pack.compression", INERT),
    ("pack.deltaCacheLimit", INERT),
    ("pack.deltaCacheSize", INERT),
    ("pack.depth", INERT),
    ("pack.indexVersion", INERT),
    ("pack.island", INERT),
    ("pack.islandCore", INERT),
    ("pack.packSizeLimit", INERT),
    ("pack.preferBitmapTips", INERT),
    ("pack.threads", INERT),
    ("pack.useBitmaps", INERT),
    ("pack.useSparse", INERT),
    ("pack.window", INERT),
    ("pack.windowMemory", INERT),
    ("pack.writeBitmapHashCache", INERT),
    ("pack.writeReverseIndex", INERT),
    ("pager.<cmd>", SHELL),
    ("pretty.<name>", INERT),
    ("protocol.<name>.allow", INERT),
    ("protocol.allow", INERT),
    ("protocol.version", INERT),
    ("pull.ff", INERT),
    ("pull.octopus", INERT),
    ("pull.rebase", INERT),
    ("pull.twohead", INERT),
    ("push.default", INERT),
    ("push.followTags", INERT),
    ("push.gpgSign", INERT),
    ("push.negotiate", INERT),
    ("push.pushOption", INERT),
    ("push.recurseSubmodules", INERT),
    ("push.useForceIfIncludes", INERT),
    ("rebase.abbreviateCommands", INERT),
    ("rebase.autoSquash", INERT),
    ("rebase.autoStash", INERT),
    ("rebase.backend", INERT),
    ("rebase.forkPoint", INERT),
    ("rebase.instructionFormat", INERT),
    ("rebase.missingCommitsCheck", INERT),
    ("rebase.rescheduleFailedExec", INERT),
    ("rebase.stat", INERT),
    ("receive.advertiseAtomic", INERT),
    ("receive.advertisePushOptions", INERT),
    ("receive.autogc", INERT),
    ("receive.certNonceSeed", INERT),
    ("receive.certNonceSlop", INERT),
    ("receive.denyCurrentBranch", INERT),
    ("receive.denyDeleteCurrent", INERT),
    ("receive.denyDeletes", INERT),
    ("receive.denyNonFastForwards", INERT),
    ("receive.fsck.<msg-id>", INERT),
    ("receive.fsck.badDate", INERT),
    ("receive.fsck.badDateOverflow", INERT),
    ("receive.fsck.badEmail", INERT),
    ("receive.fsck.badFilemode", INERT),
    ("receive.fsck.badName", INERT),
    ("receive.fsck.badObjectSha1", INERT),
    ("receive.fsck.badParentSha1", INERT),
    ("receive.fsck.badTagName", INERT),
    ("receive.fsck.badTagObject", INERT),
    ("receive.fsck.badTimezone", INERT),
    ("receive.fsck.badTree", INERT),
    ("receive.fsck.badTreeSha1", INERT),
    ("receive.fsck.badType", INERT),
    ("receive.fsck.duplicateEntries", INERT),
    ("receive.fsck.emptyName", INERT),
    ("receive.fsck.extraHeaderEntry", INERT),
    ("receive.fsck.fullPathname", INERT),
    ("receive.fsck.gitattributesSymlink", INERT),
    ("receive.fsck.gitignoreSymlink", INERT),
    ("receive.fsck.gitmodulesBlob", INERT),
    ("receive.fsck.gitmodulesLarge", INERT),
    ("receive.fsck.gitmodulesMissing", INERT),
    ("receive.fsck.gitmodulesName", INERT),
    ("receive.fsck.gitmodulesParse", INERT),
    ("receive.fsck.gitmodulesPath", INERT),
    ("receive.fsck.gitmodulesSymlink", INERT),
    ("receive.fsck.gitmodulesUpdate", INERT),
    ("receive.fsck.gitmodulesUrl", INERT),
    ("receive.fsck.hasDot", INERT),
    ("receive.fsck.hasDotdot", INERT),
    ("receive.fsck.hasDotgit", INERT),
    ("receive.fsck.mailmapSymlink", INERT),
    ("receive.fsck.missingAuthor", INERT),
    ("receive.fsck.missingCommitter", INERT),
    ("receive.fsck.missingEmail", INERT),
    ("receive.fsck.missingNameBeforeEmail", INERT),
    ("receive.fsck.missingObject", INERT),
    ("receive.fsck.missingSpaceBeforeDate", INERT),
    ("receive.fsck.missingSpaceBeforeEmail", INERT),
    ("receive.fsck.missingTag", INERT),
    ("receive.fsck.missingTagEntry", INERT),
    ("receive.fsck.missingTaggerEntry", INERT),
    ("receive.fsck.missingTree", INERT),
    ("receive.fsck.missingTreeObject", INERT),
    ("receive.fsck.missingType", INERT),
    ("receive.fsck.missingTypeEntry", INERT),
    ("receive.fsck.multipleAuthors", INERT),
    ("receive.fsck.nulInCommit", INERT),
    ("receive.fsck.nulInHeader", INERT),
    ("receive.fsck.nullSha1", INERT),
    ("receive.fsck.skipList", INERT),
    ("receive.fsck.treeNotSorted", INERT),
    ("receive.fsck.unknownType", INERT),
    ("receive.fsck.unterminatedHeader", INERT),
    ("receive.fsck.zeroPaddedDate", INERT),
    ("receive.fsck.zeroPaddedFilemode", INERT),
    ("receive.fsckObjects", INERT),
    ("receive.hideRefs", INERT),
    ("receive.keepAlive", INERT),
    ("receive.maxInputSize", INERT),
    ("receive.procReceiveRefs", INERT),
    ("receive.shallowUpdate", INERT),
    ("receive.unpackLimit", INERT),
    ("receive.updateServerInfo", INERT),
    ("remote.<name>.fetch", EXEMPT),
    ("remote.<name>.gh-resolved", INERT),
    ("remote.<name>.lfspushurl", URL),
    ("remote.<name>.lfsurl", URL),
    ("remote.<name>.mirror", INERT),
    ("remote.<name>.partialclonefilter", INERT),
    ("remote.<name>.promisor", INERT),
    ("remote.<name>.proxy", INERT),
    ("remote.<name>.proxyAuthMethod", INERT),
    ("remote.<name>.prune", INERT),
    ("remote.<name>.pruneTags", INERT),
    ("remote.<name>.push", EXEMPT),
    ("remote.<name>.pushurl", URL_SCP),
    ("remote.<name>.receivepack", SHELL),
    ("remote.<name>.skipDefaultUpdate", INERT),
    ("remote.<name>.skipFetchAll", INERT),
    ("remote.<name>.tagOpt", INERT),
    ("remote.<name>.uploadpack", SHELL),
    ("remote.<name>.url", URL_SCP),
    ("remote.<name>.vcs", REMOTE_HELPER),
    ("remote.lfsdefault", REMOTE_NAME),
    ("remote.lfspushdefault", REMOTE_NAME),
    ("remote.pushDefault", REMOTE_NAME),
    ("remotes.<group>", INERT),
    ("repack.packKeptObjects", INERT),
    ("repack.useDeltaBaseOffset", INERT),
    ("repack.useDeltaIslands", INERT),
    ("repack.writeBitmaps", INERT),
    ("rerere.autoUpdate", INERT),
    ("rerere.enabled", INERT),
    ("reset.quiet", INERT),
    ("safe.directory", INERT),
    ("sendemail.<identity>.*", UNSCOPED),
    ("sendemail.aliasesFile", INERT),
    ("sendemail.aliasFileType", INERT),
    ("sendemail.annotate", INERT),
    ("sendemail.bcc", INERT),
    ("sendemail.cc", INERT),
    ("sendemail.ccCmd", SHELL),
    ("sendemail.chainReplyTo", INERT),
    ("sendemail.confirm", INERT),
    ("sendemail.envelopeSender", INERT),
    ("sendemail.forbidSendmailVariables", INERT),
    ("sendemail.from", INERT),
    ("sendemail.identity", INERT),
    ("sendemail.multiEdit", INERT),
    ("sendemail.sendmailCmd", SHELL),
    ("sendemail.signedoffbycc", INERT),
    ("sendemail.smtpBatchSize", INERT),
    ("sendemail.smtpDomain", INERT),
    ("sendemail.smtpEncryption", INERT),
    ("sendemail.smtpPass", INERT),
    ("sendemail.smtpReloginDelay", INERT),
    ("sendemail.smtpServer", EXEC),
    ("sendemail.smtpServerOption", INERT),
    ("sendemail.smtpServerPort", INERT),
    ("sendemail.smtpsslcertpath", INERT),
    ("sendemail.smtpUser", INERT),
    ("sendemail.suppresscc", INERT),
    ("sendemail.suppressFrom", INERT),
    ("sendemail.thread", INERT),
    ("sendemail.to", INERT),
    ("sendemail.tocmd", SHELL),
    ("sendemail.transferEncoding", INERT),
    ("sendemail.validate", INERT),
    ("sendemail.xmailer", INERT),
    ("sequence.editor", SHELL),
    ("showBranch.default", INERT),
    ("splitIndex.maxPercentChange", INERT),
    ("splitIndex.sharedIndexExpire", INERT),
    ("ssh.variant", INERT),
    ("stash.showIncludeUntracked", INERT),
    ("stash.showPatch", INERT),
    ("stash.showStat", INERT),
    ("stash.useBuiltin", INERT),
    ("status.aheadBehind", INERT),
    ("status.branch", INERT),
    ("status.displayCommentPrefix", INERT),
    ("status.relativePaths", INERT),
    ("status.renameLimit", INERT),
    ("status.renames", INERT),
    ("status.short", INERT),
    ("status.showStash", INERT),
    ("status.showUntrackedFiles", INERT),
    ("status.submoduleSummary", INERT),
    ("submodule.<name>.active", INERT),
    ("submodule.<name>.branch", INERT),
    ("submodule.<name>.fetchRecurseSubmodules", INERT),
    ("submodule.<name>.ignore", INERT),
    ("submodule.<name>.path", INERT),
    ("submodule.<name>.shallow", INERT),
    ("submodule.<name>.update", BANG),
    ("submodule.<name>.url", URL_SCP),
    ("submodule.active", INERT),
    ("submodule.alternateErrorStrategy", INERT),
    ("submodule.alternateLocation", INERT),
    ("submodule.fetchJobs", INERT),
    ("submodule.recurse", INERT),
    ("svn-remote.<name>.*", INERT),
    ("tag.forceSignAnnotated", INERT),
    ("tag.gpgSign", INERT),
    ("tag.sort", INERT),
    ("tar.<format>.command", SHELL),
    ("tar.<format>.remote", INERT),
    ("tar.umask", INERT),
    ("trace2.configParams", INERT),
    ("trace2.destinationDebug", INERT),
    ("trace2.envVars", INERT),
    ("trace2.eventBrief", INERT),
    ("trace2.eventNesting", INERT),
    ("trace2.eventTarget", INERT),
    ("trace2.maxFiles", INERT),
    ("trace2.normalBrief", INERT),
    ("trace2.normalTarget", INERT),
    ("trace2.perfBrief", INERT),
    ("trace2.perfTarget", INERT),
    ("trailer.<token>.cmd", SHELL),
    ("trailer.<token>.command", SHELL),
    ("trailer.<token>.ifexists", INERT),
    ("trailer.<token>.ifmissing", INERT),
    ("trailer.<token>.key", INERT),
    ("trailer.<token>.where", INERT),
    ("trailer.ifexists", INERT),
    ("trailer.ifmissing", INERT),
    ("trailer.separators", INERT),
    ("trailer.where", INERT),
    ("transfer.advertiseSID", INERT),
    ("transfer.fsckObjects", INERT),
    ("transfer.hideRefs", INERT),
    ("transfer.unpackLimit", INERT),
    ("uploadarchive.allowUnreachable", INERT),
    ("uploadpack.allowAnySHA1InWant", INERT),
    ("uploadpack.allowFilter", INERT),
    ("uploadpack.allowReachableSHA1InWant", INERT),
    ("uploadpack.allowRefInWant", INERT),
    ("uploadpack.allowTipSHA1InWant", INERT),
    ("uploadpack.hideRefs", INERT),
    ("uploadpack.keepAlive", INERT),
    ("uploadpack.packObjectsHook", SHELL),
    ("uploadpackfilter.<filter>.allow", INERT),
    ("uploadpackfilter.allow", INERT),
    ("uploadpackfilter.tree.maxDepth", INERT),
    ("url.<base>.insteadOf", EXEMPT),
    ("url.<base>.pushInsteadOf", EXEMPT),
    ("user.*", EXEMPT),
    ("user.<name>.*", EXEMPT),
    ("user.email", EXEMPT),
    ("user.name", EXEMPT),
    ("user.signingKey", EXEMPT),
    ("user.useConfigOnly", EXEMPT),
    ("versionsort.suffix", INERT),
    ("web.browser", TOOL_NAME),
    ("worktree.guessRemote", INERT),
];

/// The Git rows Git's own documentation of the snapshot's release does not list, each with the source it was decided from.
#[cfg(test)]
const GIT_UNDOCUMENTED: &[(&str, &str)] = &[
    (
        "alias.<name>.*",
        "the scan: an alias under a subsection is judged as an alias",
    ),
    ("branch.*", "the scan: no branch setting names code"),
    ("branch.<name>.*", "the scan: no branch setting names code"),
    (
        "extensions.*",
        "gitrepository-layout(5), section extensions",
    ),
    ("fetch.bundleURI", "git-config(1) of a later Git release"),
    (
        "filter.<driver>.process",
        "gitattributes(5), long running filter process",
    ),
    ("filter.<driver>.required", "gitattributes(5)"),
    ("gitflow.*", "git-flow (AVH edition), git flow init"),
    (
        "gitflow.<section>.*",
        "git-flow (AVH edition), git flow init",
    ),
    (
        "gitflow.path.hooks",
        "git-flow (AVH edition), git flow init",
    ),
    (
        "gpg.ssh.defaultKeyCommand",
        "git-config(1) of a later Git release",
    ),
    ("gui.*", "git-gui(1), which keeps its own state there"),
    (
        "hook.<name>.command",
        "git-config(1) of a later Git release",
    ),
    ("hook.<name>.event", "git-config(1) of a later Git release"),
    ("include.path", "git-config(1), section INCLUDES"),
    (
        "includeIf.<condition>.path",
        "git-config(1), section CONDITIONAL INCLUDES",
    ),
    ("lfs.<url>.access", "git-lfs-config(5)"),
    ("lfs.<url>.contenttype", "git-lfs-config(5)"),
    ("lfs.<url>.locksverify", "git-lfs-config(5)"),
    ("lfs.activitytimeout", "git-lfs-config(5)"),
    ("lfs.allowincompletepush", "git-lfs-config(5)"),
    ("lfs.basictransfersonly", "git-lfs-config(5)"),
    ("lfs.cachecredentials", "git-lfs-config(5)"),
    ("lfs.concurrenttransfers", "git-lfs-config(5)"),
    ("lfs.contenttype", "git-lfs-config(5)"),
    ("lfs.customtransfer.<name>.args", "git-lfs-config(5)"),
    ("lfs.customtransfer.<name>.concurrent", "git-lfs-config(5)"),
    ("lfs.customtransfer.<name>.direction", "git-lfs-config(5)"),
    ("lfs.customtransfer.<name>.path", "git-lfs-config(5)"),
    ("lfs.defaulttokenttl", "git-lfs-config(5)"),
    ("lfs.dialtimeout", "git-lfs-config(5)"),
    ("lfs.extension.<name>.clean", "git-lfs-config(5)"),
    ("lfs.extension.<name>.priority", "git-lfs-config(5)"),
    ("lfs.extension.<name>.smudge", "git-lfs-config(5)"),
    ("lfs.fetchexclude", "git-lfs-config(5)"),
    ("lfs.fetchinclude", "git-lfs-config(5)"),
    ("lfs.fetchrecentalways", "git-lfs-config(5)"),
    ("lfs.fetchrecentcommitsdays", "git-lfs-config(5)"),
    ("lfs.fetchrecentrefsdays", "git-lfs-config(5)"),
    ("lfs.fetchrecentremoterefs", "git-lfs-config(5)"),
    ("lfs.keepalive", "git-lfs-config(5)"),
    ("lfs.lockignoredfiles", "git-lfs-config(5)"),
    ("lfs.locksverify", "git-lfs-config(5)"),
    ("lfs.pruneoffsetdays", "git-lfs-config(5)"),
    ("lfs.pruneremotetocheck", "git-lfs-config(5)"),
    ("lfs.pruneverifyremotealways", "git-lfs-config(5)"),
    ("lfs.pruneverifyunreachablealways", "git-lfs-config(5)"),
    ("lfs.pushurl", "git-lfs-config(5)"),
    ("lfs.repositoryformatversion", "git-lfs-config(5)"),
    ("lfs.setlockablereadonly", "git-lfs-config(5)"),
    ("lfs.skipdownloaderrors", "git-lfs-config(5)"),
    ("lfs.ssh.automultiplex", "git-lfs-config(5)"),
    ("lfs.ssh.retries", "git-lfs-config(5)"),
    ("lfs.standalonetransferagent", "git-lfs-config(5)"),
    ("lfs.storage", "git-lfs-config(5)"),
    ("lfs.tlstimeout", "git-lfs-config(5)"),
    ("lfs.transfer.enablehrefrewrite", "git-lfs-config(5)"),
    ("lfs.transfer.maxretries", "git-lfs-config(5)"),
    ("lfs.transfer.maxretrydelay", "git-lfs-config(5)"),
    ("lfs.transfer.maxverifies", "git-lfs-config(5)"),
    ("lfs.tustransfers", "git-lfs-config(5)"),
    ("lfs.url", "git-lfs-config(5)"),
    (
        "remote.<name>.gh-resolved",
        "GitHub CLI, gh repo set-default",
    ),
    ("remote.<name>.lfspushurl", "git-lfs-config(5)"),
    ("remote.<name>.lfsurl", "git-lfs-config(5)"),
    ("remote.lfsdefault", "git-lfs-config(5)"),
    ("remote.lfspushdefault", "git-lfs-config(5)"),
    (
        "sendemail.sendmailCmd",
        "git-config(1) of a later Git release",
    ),
    ("submodule.<name>.path", "gitmodules(5)"),
    ("submodule.<name>.shallow", "gitmodules(5)"),
    ("svn-remote.<name>.*", "git-svn(1)"),
    ("tar.<format>.command", "git-archive(1)"),
    ("tar.<format>.remote", "git-archive(1)"),
    ("trailer.<token>.cmd", "git-interpret-trailers(1)"),
    ("trailer.<token>.command", "git-interpret-trailers(1)"),
    ("trailer.<token>.ifexists", "git-interpret-trailers(1)"),
    ("trailer.<token>.ifmissing", "git-interpret-trailers(1)"),
    ("trailer.<token>.key", "git-interpret-trailers(1)"),
    ("trailer.<token>.where", "git-interpret-trailers(1)"),
    ("trailer.ifexists", "git-interpret-trailers(1)"),
    ("trailer.ifmissing", "git-interpret-trailers(1)"),
    ("trailer.separators", "git-interpret-trailers(1)"),
    ("trailer.where", "git-interpret-trailers(1)"),
    ("user.*", "the scan: no user setting names code"),
    ("user.<name>.*", "the scan: no user setting names code"),
];

/// Every Mercurial setting with a decided consumption, sorted ignoring ASCII case.
///
/// A Mercurial key is everything after the section's `.`; `<name>` matches a
/// key holding no `:`, `*:<option>` a key whose part after its last `:` is
/// that sub-option, `opts.<name>` a key starting with `opts.`, and
/// `<name>.args` a key ending with `.args`. Each row cites where Mercurial
/// 7.2.4 reads the setting. Mercurial runs an `[alias]` after one `!` through
/// a shell; a `[schemes]` template or a `[subpaths]` replacement is the URL it
/// reads in place of one it was given, `.hgsub` sources included. A setting no
/// row decides is unknown.
const HG: &[Row] = &[
    ("absorb.add-noise", INERT),          // hgext/absorb.py:928 configbool
    ("absorb.max-stack-size", INERT),     // hgext/absorb.py:1021 configint
    ("acl.sources", INERT),               // hgext/acl.py:380 configlist
    ("alias.*", BANG),                    // mercurial/dispatch.py:765
    ("alias.*:category", INERT),          // mercurial/dispatch.py:647 alias help text
    ("alias.*:doc", INERT),               // mercurial/dispatch.py:647 alias help text
    ("alias.*:help", INERT),              // mercurial/dispatch.py:647 alias help text
    ("annotate.git", INERT),              // mercurial/diffutil.py:73 difffeatureopts
    ("annotate.ignoreblanklines", INERT), // mercurial/diffutil.py:73 difffeatureopts
    ("annotate.ignorews", INERT),         // mercurial/diffutil.py:73 difffeatureopts
    ("annotate.ignorewsamount", INERT),   // mercurial/diffutil.py:73 difffeatureopts
    ("annotate.ignorewseol", INERT),      // mercurial/diffutil.py:73 difffeatureopts
    ("annotate.nobinary", INERT),         // mercurial/diffutil.py:73 difffeatureopts
    ("annotate.nodates", INERT),          // mercurial/diffutil.py:73 difffeatureopts
    ("annotate.noprefix", INERT),         // mercurial/diffutil.py:73 difffeatureopts
    ("annotate.showfunc", INERT),         // mercurial/diffutil.py:73 difffeatureopts
    ("annotate.unified", INERT),          // mercurial/diffutil.py:73 difffeatureopts
    ("annotate.word-diff", INERT),        // mercurial/diffutil.py:73 difffeatureopts
    ("auth.cookiefile", INERT),           // mercurial/url.py:473 config
    ("automv.similarity", INERT),         // hgext/automv.py:64 configint
    ("blackbox.date-format", INERT),      // hgext/blackbox.py:102 config
    ("blackbox.debug.to-stderr", INERT),  // hgext/blackbox.py:103 configbool
    ("blackbox.dirty", INERT),            // hgext/blackbox.py:117 configbool
    ("blackbox.ignore", INERT),           // hgext/blackbox.py:78 configlist
    ("blackbox.logsource", INERT),        // hgext/blackbox.py:121 configbool
    ("blackbox.maxfiles", INERT),         // hgext/blackbox.py:79 configint
    ("blackbox.maxsize", INERT),          // hgext/blackbox.py:80 configbytes
    ("blackbox.track", INERT),            // hgext/blackbox.py:77 configlist
    ("bookmarks.pushing", INERT),         // mercurial/discovery.py:420 configlist
    ("bugzilla.apikey", INERT),           // hgext/bugzilla.py:973 config
    ("bugzilla.bzdir", SHELL), // hgext/bugzilla.py:588 popen, substituted into bugzilla.notify
    ("bugzilla.bzemail", INERT), // hgext/bugzilla.py:896 config
    ("bugzilla.bzurl", INERT), // hgext/bugzilla.py:789 config
    ("bugzilla.bzuser", SHELL), // hgext/bugzilla.py:588 popen, substituted into bugzilla.notify
    ("bugzilla.db", INERT),    // hgext/bugzilla.py:515 config
    ("bugzilla.fixresolution", INERT), // hgext/bugzilla.py:796 config
    ("bugzilla.fixstatus", INERT), // hgext/bugzilla.py:795 config
    ("bugzilla.host", INERT),  // hgext/bugzilla.py:512 config
    ("bugzilla.notify", SHELL), // hgext/bugzilla.py:588 popen
    ("bugzilla.password", INERT), // hgext/bugzilla.py:514 config
    ("bugzilla.strip", INERT), // hgext/bugzilla.py:1195 configint
    ("bugzilla.style", INERT), // hgext/bugzilla.py:1208 config
    ("bugzilla.template", INERT), // hgext/bugzilla.py:1206 config
    ("bugzilla.timeout", INERT), // hgext/bugzilla.py:516 configint
    ("bugzilla.user", INERT),  // hgext/bugzilla.py:513 config
    ("bugzilla.version", INERT), // hgext/bugzilla.py:1115 config
    ("bundle.mainreporoot", INERT), // mercurial/bundlerepo.py:599 config
    ("censor.policy", INERT),  // mercurial/repo/vfs_options.py:287 config
    ("chgserver.idletimeout", INERT), // mercurial/chgserver.py:681 configint
    ("chgserver.skiphash", INERT), // mercurial/chgserver.py:693 configbool
    ("clone-bundles.auto-generate.formats", INERT), // hgext/clonebundles.py:844 configlist
    ("clone-bundles.auto-generate.on-change", INERT), // hgext/clonebundles.py:971 configbool
    ("clone-bundles.auto-generate.serve-inline", INERT), // hgext/clonebundles.py:775 config
    ("clone-bundles.delete-command", SHELL), // hgext/clonebundles.py:825 ui.system
    ("clone-bundles.trigger.below-bundled-ratio", INERT), // hgext/clonebundles.py:846 config
    ("clone-bundles.trigger.revs", INERT), // hgext/clonebundles.py:848 configint
    ("clone-bundles.upload-command", SHELL), // hgext/clonebundles.py:786 ui.system
    ("clone-bundles.url-template", INERT), // hgext/clonebundles.py:787 config
    ("cmdserver.log", INERT),  // mercurial/commandserver.py:253 config
    ("cmdserver.max-log-files", INERT), // mercurial/commandserver.py:448 configint
    ("cmdserver.max-log-size", INERT), // mercurial/commandserver.py:450 configbytes
    ("cmdserver.max-repo-cache", INERT), // mercurial/commandserver.py:637 configint
    ("cmdserver.message-encodings", INERT), // mercurial/commandserver.py:204 configlist
    ("cmdserver.shutdown-on-interrupt", INERT), // mercurial/commandserver.py:272 configbool
    ("cmdserver.track-log", INERT), // mercurial/commandserver.py:439 configlist
    ("color.*", INERT),        // mercurial/color.py:169 configitems
    ("color.mode", INERT),     // mercurial/color.py:241 config
    ("color.pagermode", INERT), // mercurial/color.py:245 config
    ("command-templates.graphnode", INERT), // mercurial/logcmdutil.py:1248 config
    ("command-templates.log", INERT), // mercurial/logcmdutil.py:693 config
    ("command-templates.mergemarker", INERT), // mercurial/filemerge.py:879 config
    ("command-templates.oneline-summary", INERT), // mercurial/cmdutil.py:1224 config
    ("command-templates.oneline-summary.<name>", INERT), // mercurial/cmdutil.py:1221 config
    ("command-templates.pre-merge-tool-output", INERT), // mercurial/filemerge.py:696 config
    ("commands.commit.interactive.git", INERT), // mercurial/diffutil.py:73 difffeatureopts
    ("commands.commit.interactive.ignoreblanklines", INERT), // mercurial/diffutil.py:73 difffeatureopts
    ("commands.commit.interactive.ignorews", INERT), // mercurial/diffutil.py:73 difffeatureopts
    ("commands.commit.interactive.ignorewsamount", INERT), // mercurial/diffutil.py:73 difffeatureopts
    ("commands.commit.interactive.ignorewseol", INERT), // mercurial/diffutil.py:73 difffeatureopts
    ("commands.commit.interactive.nobinary", INERT),    // mercurial/diffutil.py:73 difffeatureopts
    ("commands.commit.interactive.nodates", INERT),     // mercurial/diffutil.py:73 difffeatureopts
    ("commands.commit.interactive.noprefix", INERT),    // mercurial/diffutil.py:73 difffeatureopts
    ("commands.commit.interactive.showfunc", INERT),    // mercurial/diffutil.py:73 difffeatureopts
    ("commands.commit.interactive.unified", INERT),     // mercurial/diffutil.py:73 difffeatureopts
    ("commands.commit.interactive.word-diff", INERT),   // mercurial/diffutil.py:73 difffeatureopts
    ("commands.commit.post-status", INERT),             // mercurial/commands.py:2078 configbool
    ("commands.commit.report-head-changes", INERT),     // mercurial/commands.py:1960 configbool
    ("commands.merge.require-rev", INERT),              // mercurial/commands.py:4497 configbool
    ("commands.push.require-revs", INERT),              // mercurial/commands.py:5358 configbool
    ("commands.rebase.requiredest", INERT),             // hgext/rebase.py:1286 configbool
    ("commands.resolve.confirm", INERT),                // mercurial/commands.py:5644 configbool
    ("commands.resolve.explicit-re-merge", INERT),      // mercurial/commands.py:5651 configbool
    ("commands.resolve.mark-check", INERT),             // mercurial/commands.py:5743 config
    ("commands.revert.interactive.git", INERT),         // mercurial/diffutil.py:73 difffeatureopts
    ("commands.revert.interactive.ignoreblanklines", INERT), // mercurial/diffutil.py:73 difffeatureopts
    ("commands.revert.interactive.ignorews", INERT), // mercurial/diffutil.py:73 difffeatureopts
    ("commands.revert.interactive.ignorewsamount", INERT), // mercurial/diffutil.py:73 difffeatureopts
    ("commands.revert.interactive.ignorewseol", INERT), // mercurial/diffutil.py:73 difffeatureopts
    ("commands.revert.interactive.nobinary", INERT),    // mercurial/diffutil.py:73 difffeatureopts
    ("commands.revert.interactive.nodates", INERT),     // mercurial/diffutil.py:73 difffeatureopts
    ("commands.revert.interactive.noprefix", INERT),    // mercurial/diffutil.py:73 difffeatureopts
    ("commands.revert.interactive.showfunc", INERT),    // mercurial/diffutil.py:73 difffeatureopts
    ("commands.revert.interactive.unified", INERT),     // mercurial/diffutil.py:73 difffeatureopts
    ("commands.revert.interactive.word-diff", INERT),   // mercurial/diffutil.py:73 difffeatureopts
    ("commands.show.aliasprefix", INERT),               // hgext/show.py:469 configlist
    ("commands.status.relative", INERT),                // mercurial/commands.py:6542 configbool
    ("commands.status.skipstates", INERT),              // mercurial/state.py:378 configlist
    ("commands.status.terse", INERT),                   // mercurial/commands.py:6527 config
    ("commands.status.verbose", INERT),                 // mercurial/commands.py:6607 configbool
    ("commands.update.check", INERT),                   // mercurial/cmd_impls/update.py:76 config
    ("commands.update.requiredest", INERT),             // mercurial/cmdutil.py:4160 configbool
    ("committemplate.*", INERT),                        // mercurial/cmdutil.py:3234 configitems
    ("convert.bzr.saverev", INERT),                     // hgext/convert/bzr.py:88 configbool
    ("convert.cvsps.cache", INERT),                     // hgext/convert/cvs.py:88 configbool
    ("convert.cvsps.fuzz", INERT),                      // hgext/convert/cvs.py:94 configint
    ("convert.cvsps.logencoding", INERT),               // hgext/convert/cvsps.py:539 configlist
    ("convert.cvsps.mergefrom", INERT),                 // hgext/convert/cvs.py:96 config
    ("convert.cvsps.mergeto", INERT),                   // hgext/convert/cvs.py:95 config
    ("convert.git.committeractions", INERT),            // hgext/convert/git.py:120 configlist
    ("convert.git.extrakeys", INERT),                   // hgext/convert/git.py:112 configlist
    ("convert.git.findcopiesharder", INERT),            // hgext/convert/git.py:94 configbool
    ("convert.git.remoteprefix", INERT),                // hgext/convert/git.py:504 config
    ("convert.git.renamelimit", INERT),                 // hgext/convert/git.py:100 configint
    ("convert.git.saverev", INERT),                     // hgext/convert/git.py:419 configbool
    ("convert.git.similarity", INERT),                  // hgext/convert/git.py:89 configint
    ("convert.git.skipsubmodules", INERT),              // hgext/convert/git.py:306 configbool
    ("convert.hg.clonebranches", INERT),                // hgext/convert/hg.py:64 configbool
    ("convert.hg.ignoreerrors", INERT),                 // hgext/convert/hg.py:528 configbool
    ("convert.hg.preserve-hash", INERT),                // hgext/convert/hg.py:400 config
    ("convert.hg.revs", INERT),                         // hgext/convert/hg.py:546 config
    ("convert.hg.saverev", INERT),                      // hgext/convert/hg.py:530 configbool
    ("convert.hg.sourcename", INERT),                   // hgext/convert/hg.py:330 config
    ("convert.hg.startrev", INERT),                     // hgext/convert/hg.py:545 config
    ("convert.hg.tagsbranch", INERT),                   // hgext/convert/hg.py:65 config
    ("convert.hg.usebranchnames", INERT),               // hgext/convert/hg.py:63 configbool
    ("convert.ignoreancestorcheck", INERT),             // hgext/convert/filemap.py:237 configbool
    ("convert.localtimezone", INERT),                   // hgext/convert/cvs.py:106 configbool
    ("convert.p4.encoding", INERT),                     // hgext/convert/p4.py:74 config
    ("convert.p4.startrev", INERT),                     // hgext/convert/p4.py:161 config
    ("convert.skiptags", INERT),                        // hgext/convert/convcmd.py:611 configbool
    ("convert.svn.branches", INERT),                    // hgext/convert/subversion.py:626 config
    ("convert.svn.dangerous-set-commit-dates", INERT), // hgext/convert/subversion.py:1485 configbool
    ("convert.svn.debugsvnlog", INERT), // hgext/convert/subversion.py:1360 configbool
    ("convert.svn.startrev", INERT),    // hgext/convert/subversion.py:563 config
    ("convert.svn.tags", INERT),        // hgext/convert/subversion.py:626 config
    ("convert.svn.trunk", INERT),       // hgext/convert/subversion.py:559 config
    ("debug.bundling-stats", INERT),    // mercurial/changegroup.py:1824 configbool
    ("debug.revlog.debug-delta", INERT), // mercurial/repo/vfs_options.py:176 configbool
    ("debug.revlog.verifyposition.changelog", INERT), // mercurial/revlogutils/concurrency_checker.py:23 config
    ("debug.unbundling-stats", INERT),                // mercurial/changegroup.py:677 configbool
    ("devel.all-warnings", INERT),                    // mercurial/localrepo.py:1128 configbool
    ("devel.bundle.delta", INERT),                    // mercurial/changegroup.py:1459 config
    ("devel.bundle2.debug", INERT),                   // mercurial/bundle2.py:1317 configbool
    ("devel.cache-vfs", INERT),                       // mercurial/ui.py:2387 configbool
    ("devel.check-locks", INERT),                     // mercurial/localrepo.py:1128 configbool
    ("devel.check-relroot", INERT),                   // mercurial/logcmdutil.py:122 configbool
    ("devel.clonebundles.override-operation-id", INERT), // hgext/clonebundles.py:1040 config
    ("devel.copy-tracing.multi-thread", INERT),       // mercurial/copies.py:271 configbool
    ("devel.copy-tracing.trace-all-files", INERT),    // mercurial/copies.py:150 configbool
    ("devel.debug.abort-transaction", INERT),         // mercurial/localrepo.py:2455 config
    ("devel.debug.abort-update", INERT),              // mercurial/merge.py:1036 configbool
    ("devel.debug.clonebundles", INERT),              // hgext/clonebundles.py:1039 configbool
    ("devel.debug.copies", INERT),                    // mercurial/copies.py:128 configbool
    ("devel.debug.extensions", INERT),                // mercurial/extensions.py:159 configbool
    ("devel.debug.peer-request", INERT),              // mercurial/httppeer.py:296 configbool
    ("devel.debug.repo-filters", INERT),              // mercurial/repoview.py:228 configbool
    ("devel.default-date", INERT),                    // hgext/blackbox.py:101 configdate
    ("devel.deprec-warn", INERT),                     // mercurial/ui.py:2435 configbool
    ("devel.dirstate.v2.data_update_mode", INERT),    // mercurial/dirstatemap.py:99 config
    ("devel.disableloaddefaultcerts", INERT),         // mercurial/sslutil.py:173 configbool
    ("devel.discovery.exchange-heads", INERT),        // mercurial/setdiscovery.py:316 configbool
    ("devel.discovery.grow-sample", INERT),           // mercurial/setdiscovery.py:436 configbool
    ("devel.discovery.grow-sample.dynamic", INERT),   // mercurial/setdiscovery.py:436 configbool
    ("devel.discovery.grow-sample.rate", INERT),      // mercurial/setdiscovery.py:299 config
    ("devel.discovery.randomize", INERT),             // mercurial/setdiscovery.py:442 configbool
    ("devel.discovery.sample-size", INERT),           // mercurial/setdiscovery.py:318 configint
    ("devel.discovery.sample-size.initial", INERT),   // mercurial/setdiscovery.py:317 configint
    ("devel.fileindex.garbage-timestamp", INERT),     // mercurial/repo/vfs_options.py:124 configint
    ("devel.fileindex.vacuum-mode", INERT),           // mercurial/repo/vfs_options.py:66 config
    ("devel.legacy.exchange", INERT),                 // mercurial/bundlerepo.py:761 configlist
    ("devel.lock-wait-sync-file", INERT),             // mercurial/localrepo.py:2907 config
    ("devel.persistent-nodemap", INERT), // mercurial/repo/vfs_options.py:357 configbool
    ("devel.rebase.force-in-memory-merge", INERT), // hgext/rebase.py:1119 configbool
    ("devel.remotefilelog.bg-wait", INERT), // hgext/remotefilelog/repack.py:46 configbool
    ("devel.server-insecure-exact-protocol", INERT), // mercurial/sslutil.py:525 config
    ("devel.servercafile", INERT),       // mercurial/hgweb/server.py:329 config
    ("devel.serverrequirecert", INERT),  // mercurial/hgweb/server.py:330 configbool
    ("devel.strip-obsmarkers", INERT),   // mercurial/repair.py:179 configbool
    ("devel.sync.dirstate.post-docket-read-file", INERT), // mercurial/testing/__init__.py:21 a file waited on
    ("devel.sync.dirstate.post-docket-read-file-timeout", INERT), // mercurial/testing/__init__.py:21 a file waited on
    ("devel.sync.dirstate.pre-read-file", INERT), // mercurial/testing/__init__.py:21 a file waited on
    ("devel.sync.dirstate.pre-read-file-timeout", INERT), // mercurial/testing/__init__.py:21 a file waited on
    ("devel.sync.fileindex.pre-read-data-files", INERT), // mercurial/testing/__init__.py:21 a file waited on
    ("devel.sync.fileindex.pre-read-data-files-timeout", INERT), // mercurial/testing/__init__.py:21 a file waited on
    ("devel.sync.status.pre-dirstate-write-file", INERT), // mercurial/testing/__init__.py:21 a file waited on
    ("devel.sync.status.pre-dirstate-write-file-timeout", INERT), // mercurial/testing/__init__.py:21 a file waited on
    ("devel.update.abort-on-dirstate-change", INERT), // mercurial/merge.py:1686 configbool
    ("devel.user.obsmarker", INERT),                  // mercurial/obsolete.py:1097 config
    ("devel.warn-config", INERT),                     // mercurial/ui.py:2387 configbool
    ("devel.warn-config-default", INERT),             // mercurial/ui.py:2387 configbool
    ("devel.warn-config-unknown", INERT),             // mercurial/ui.py:2387 configbool
    ("devel.warn-empty-changegroup", INERT),          // mercurial/ui.py:2387 configbool
    ("diff-tools.<name>.diffargs", SHELL), // hgext/extdiff.py:801 appended to the command line
    ("diff-tools.<name>.gui", INERT),      // hgext/extdiff.py:808 configbool
    ("diff.git", INERT),                   // mercurial/diffutil.py:73 difffeatureopts
    ("diff.ignoreblanklines", INERT),      // mercurial/diffutil.py:73 difffeatureopts
    ("diff.ignorews", INERT),              // mercurial/diffutil.py:73 difffeatureopts
    ("diff.ignorewsamount", INERT),        // mercurial/diffutil.py:73 difffeatureopts
    ("diff.ignorewseol", INERT),           // mercurial/diffutil.py:73 difffeatureopts
    ("diff.merge", INERT),                 // mercurial/merge_utils/diff.py:26 configbool
    ("diff.nobinary", INERT),              // mercurial/diffutil.py:73 difffeatureopts
    ("diff.nodates", INERT),               // mercurial/diffutil.py:73 difffeatureopts
    ("diff.noprefix", INERT),              // mercurial/diffutil.py:73 difffeatureopts
    ("diff.showfunc", INERT),              // mercurial/diffutil.py:73 difffeatureopts
    ("diff.unified", INERT),               // mercurial/diffutil.py:73 difffeatureopts
    ("diff.word-diff", INERT),             // mercurial/diffutil.py:73 difffeatureopts
    ("email.bcc", INERT),                  // hgext/patchbomb.py:890 addresses
    ("email.cc", INERT),                   // hgext/patchbomb.py:890 addresses
    ("email.charsets", INERT),             // mercurial/mail.py:335 configlist
    ("email.from", INERT),                 // hgext/hooklib/changeset_obsoleted.py:115 config
    ("email.method", SHELL),               // mercurial/mail.py:201 popen
    ("email.reply-to", INERT),             // hgext/patchbomb.py:890 addresses
    ("email.to", INERT),                   // hgext/patchbomb.py:890 addresses
    ("eol.fix-trailing-newline", INERT),   // hgext/eol.py:152 configbool
    ("eol.native", INERT),                 // hgext/eol.py:212 config
    ("eol.only-consistent", INERT),        // hgext/eol.py:149 configbool
    ("experimental.archivemetatemplate", INERT), // mercurial/archival.py:119 config
    ("experimental.auto-publish", INERT),  // mercurial/exchange.py:236 config
    ("experimental.branch-cache-v3", INERT), // mercurial/branchmap.py:1059 configbool
    ("experimental.bundle-phases", INERT), // mercurial/cmd_impls/bundle.py:214 configbool
    ("experimental.bundle2-advertise", INERT), // mercurial/localrepo.py:1286 configbool
    ("experimental.bundle2-output-capture", INERT), // mercurial/exchange.py:2834 configbool
    ("experimental.bundle2.pushback", INERT), // mercurial/exchange.py:1238 configbool
    ("experimental.bundle2lazylocking", INERT), // mercurial/bundle2_part_handlers.py:295 configbool
    ("experimental.bundlecomplevel", INERT), // mercurial/cmd_impls/bundle.py:192 configint
    ("experimental.bundlecomplevel.bzip2", INERT), // mercurial/cmd_impls/bundle.py:189 configint
    ("experimental.bundlecomplevel.gzip", INERT), // mercurial/cmd_impls/bundle.py:189 configint
    ("experimental.bundlecomplevel.none", INERT), // mercurial/cmd_impls/bundle.py:189 configint
    ("experimental.bundlecomplevel.zstd", INERT), // mercurial/cmd_impls/bundle.py:189 configint
    ("experimental.bundlecompthreads", INERT), // mercurial/cmd_impls/bundle.py:200 configint
    ("experimental.bundlecompthreads.bzip2", INERT), // mercurial/cmd_impls/bundle.py:197 configint
    ("experimental.bundlecompthreads.gzip", INERT), // mercurial/cmd_impls/bundle.py:197 configint
    ("experimental.bundlecompthreads.none", INERT), // mercurial/cmd_impls/bundle.py:197 configint
    ("experimental.bundlecompthreads.zstd", INERT), // mercurial/cmd_impls/bundle.py:197 configint
    ("experimental.changegroup4", INERT),  // mercurial/changegroup.py:2633 configbool
    ("experimental.changegroup5", INERT),  // mercurial/changegroup.py:2614 configbool
    ("experimental.changelog-v2.compute-rank", INERT), // mercurial/repo/vfs_options.py:147 configbool
    ("experimental.cleanup-as-archived", INERT),       // mercurial/cmdutil.py:934 config
    ("experimental.clientcompressionengines", INERT),  // mercurial/wireprototypes.py:412 configlist
    ("experimental.copies.read-from", INERT),          // mercurial/cmdutil.py:2994 config
    ("experimental.copies.write-to", INERT),           // mercurial/commit.py:35 config
    ("experimental.copytrace", INERT),                 // mercurial/copies.py:707 config
    ("experimental.copytrace.movecandidateslimit", INERT), // mercurial/copies.py:1225 configint
    ("experimental.copytrace.sourcecommitlimit", INERT), // mercurial/copies.py:862 configint
    ("experimental.crecordtest", INERT),               // mercurial/cmdutil.py:266 config
    ("experimental.directaccess", INERT),              // mercurial/scmutil.py:2292 configbool
    ("experimental.directaccess.revnums", INERT),      // mercurial/scmutil.py:2341 configbool
    ("experimental.editortmpinhg", INERT),             // mercurial/ui.py:2144 configbool
    ("experimental.evolution", INERT),                 // mercurial/obsolete.py:123 configbool/list
    ("experimental.evolution.allowdivergence", INERT), // mercurial/obsolete.py:110 configbool
    ("experimental.evolution.allowunstable", INERT),   // mercurial/obsolete.py:110 configbool
    ("experimental.evolution.bundle-obsmarker", INERT), // mercurial/cmd_impls/bundle.py:206 configbool
    ("experimental.evolution.bundle-obsmarker:mandatory", INERT), // mercurial/cmd_impls/bundle.py:206 configbool
    ("experimental.evolution.createmarkers", INERT), // mercurial/obsolete.py:133 config
    ("experimental.evolution.effect-flags", INERT),  // mercurial/obsolete.py:1109 configbool
    ("experimental.evolution.exchange", INERT),      // mercurial/obsolete.py:110 configbool
    ("experimental.evolution.report-instabilities", INERT), // mercurial/scmutil.py:2137 configbool
    ("experimental.evolution.track-operation", INERT), // mercurial/obsolete.py:1102 configbool
    ("experimental.exportableenviron", INERT),       // mercurial/ui.py:361 configlist
    ("experimental.extendedheader.index", INERT),    // mercurial/diffutil.py:115 config
    ("experimental.extendedheader.similarity", INERT), // mercurial/diffutil.py:109 configbool
    ("experimental.extra-filter-revs", INERT),       // mercurial/repoview.py:200 config
    ("experimental.fsmonitor.transaction_notify", INERT), // hgext/fsmonitor/__init__.py:991 configbool
    ("experimental.graphshorten", INERT),                 // mercurial/logcmdutil.py:1297 configbool
    ("experimental.graphstyle.grandparent", INERT),       // mercurial/logcmdutil.py:1291 config
    ("experimental.graphstyle.missing", INERT),           // mercurial/logcmdutil.py:1291 config
    ("experimental.graphstyle.parent", INERT),            // mercurial/logcmdutil.py:1291 config
    ("experimental.histedit.autoverb", INERT),            // hgext/histedit.py:2394 configbool
    ("experimental.hook-track-tags", INERT),              // mercurial/localrepo.py:2334 configbool
    ("experimental.httppostargs", INERT), // mercurial/wireprotoserver.py:150 configbool
    ("experimental.lfs.disableusercache", INERT), // hgext/lfs/blobstore.py:124 configbool
    ("experimental.lfs.serve", INERT),    // hgext/lfs/wireprotolfsserver.py:44 configbool
    ("experimental.lfs.user-agent", INERT), // hgext/lfs/blobstore.py:321 config
    ("experimental.lfs.worker-enable", INERT), // hgext/lfs/blobstore.py:608 configbool
    ("experimental.log.topo", INERT),     // mercurial/logcmdutil.py:810 configbool
    ("experimental.maxdeltachainspan", INERT), // mercurial/repo/vfs_options.py:202 configbytes
    ("experimental.merge-track-salvaged", INERT), // mercurial/commit.py:426 configbool
    ("experimental.merge.checkpathconflicts", INERT), // mercurial/context.py:2398 configbool
    ("experimental.narrow", INERT),       // mercurial/localrepo.py:1292 configbool
    ("experimental.narrowservebrokenellipses", INERT), // hgext/narrow/narrowbundle2.py:308 configbool
    ("experimental.nointerrupt", INERT),               // mercurial/ui.py:452 configbool
    ("experimental.nointerrupt-interactiveonly", INERT), // mercurial/ui.py:453 configbool
    ("experimental.obsmarkers-exchange-debug", INERT), // mercurial/bundle2_part_handlers.py:543 config
    ("experimental.rebaseskipobsolete", INERT),        // hgext/rebase.py:345 configbool
    ("experimental.relaxed-block-sync-merge", INERT),  // mercurial/debugcommands.py:274 configbool
    ("experimental.remotenames", INERT), // mercurial/cmd_impls/clone.py:485 configbool
    ("experimental.removeemptydirs", INERT), // mercurial/cmdutil.py:1760 configbool
    ("experimental.revert.interactive.select-to-keep", INERT), // mercurial/cmdutil.py:3808 configbool
    ("experimental.revisions.disambiguatewithin", INERT),      // mercurial/scmutil.py:633 config
    ("experimental.revisions.prefixhexnode", INERT), // mercurial/scmutil.py:686 configbool
    ("experimental.revlogv2", INERT),                // mercurial/repo/creation.py:183 config
    ("experimental.rust.index", INERT),              // mercurial/repo/vfs_options.py:290 configbool
    ("experimental.server.allow-hidden-access", INERT), // mercurial/commands.py:6216 configlist
    ("experimental.server.stream-narrow-clones", INERT), // mercurial/bundle2.py:1926 configbool
    ("experimental.single-head-per-branch", INERT),  // mercurial/localrepo.py:2381 configsuboptions
    (
        "experimental.single-head-per-branch:account-closed-heads",
        INERT,
    ), // mercurial/localrepo.py:2381 configsuboptions
    (
        "experimental.single-head-per-branch:public-changes-only",
        INERT,
    ), // mercurial/localrepo.py:2381 configsuboptions
    ("experimental.sparse-read", INERT),             // mercurial/repo/vfs_options.py:213 configbool
    ("experimental.sparse-read.density-threshold", INERT), // mercurial/repo/vfs_options.py:215 config
    ("experimental.sparse-read.min-gap-size", INERT), // mercurial/repo/vfs_options.py:217 configbytes
    ("experimental.stream-v3", INERT), // mercurial/exchanges/bundle_caps.py:82 configbool
    ("experimental.treemanifest", INERT), // mercurial/repo/creation.py:176 configbool
    ("experimental.uncommit.keep", INERT), // hgext/uncommit.py:214 configbool
    ("experimental.uncommitondirtywdir", INERT), // hgext/uncommit.py:163 configbool
    ("experimental.update.atomic-file", INERT), // mercurial/merge.py:1780 configbool
    ("experimental.web.full-garbage-collection-rate", INERT), // mercurial/hgweb/hgwebdir_mod_inner.py:357 configint
    ("experimental.worker.repository-upgrade", INERT), // mercurial/upgrade_utils/engine.py:50 configbool
    ("experimental.worker.wdir-get-thread-safe", INERT), // mercurial/merge_utils/update.py:145 configbool
    ("experimental.xdiff", INERT),                       // mercurial/diffutil.py:102 configbool
    ("extdiff.*", SHELL),                                // hgext/extdiff.py:788 the command line
    ("extdiff.cmd.<name>", FORCED),                      // hgext/extdiff.py:772 expandpath
    ("extdiff.gui.<name>", INERT),                       // hgext/extdiff.py:782 configbool
    ("extdiff.opts.<name>", SHELL), // hgext/extdiff.py:779 appended to the command line
    ("extensions.*:required", INERT), // mercurial/extensions.py:344 parsebool
    ("extensions.<name>", FORCED_UNBANGED), // mercurial/extensions.py:303 loadall
    ("factotum.executable", SHELL), // hgext/factotum.py:94 os.system
    ("factotum.mountpoint", INERT), // hgext/factotum.py:159 config
    ("factotum.service", INERT),    // hgext/factotum.py:161 config
    ("fastannotate.client", INERT), // hgext/fastannotate/__init__.py:174 configbool
    ("fastannotate.clientfetchthreshold", INERT), // hgext/fastannotate/protocol.py:222 configint
    ("fastannotate.defaultformat", INERT), // hgext/fastannotate/commands.py:201 configlist
    ("fastannotate.forcefollow", INERT), // hgext/fastannotate/context.py:865 configbool
    ("fastannotate.forcetext", INERT), // hgext/fastannotate/commands.py:275 configbool
    ("fastannotate.mainbranch", INERT), // hgext/fastannotate/commands.py:217 config
    ("fastannotate.modes", INERT),  // hgext/fastannotate/__init__.py:145 configlist
    ("fastannotate.perfhack", INERT), // hgext/fastannotate/commands.py:39 configbool
    ("fastannotate.server", INERT), // hgext/fastannotate/__init__.py:163 configbool
    ("fastannotate.serverbuildondemand", INERT), // hgext/fastannotate/protocol.py:59 configbool
    ("fastannotate.unfilteredrepo", INERT), // hgext/fastannotate/commands.py:178 configbool
    ("fastexport.on-pre-existing-gitmodules", INERT), // hgext/fastexport.py:149 config
    ("fix.*:command", SHELL),       // hgext/fix.py:741 Popen shell=True
    ("fix.*:enabled", INERT),       // hgext/fix.py:940 configitems
    ("fix.*:linerange", SHELL),     // hgext/fix.py:741 Popen shell=True
    ("fix.*:metadata", INERT),      // hgext/fix.py:940 configitems
    ("fix.*:pattern", INERT),       // hgext/fix.py:940 configitems
    ("fix.*:priority", INERT),      // hgext/fix.py:940 configitems
    ("fix.*:skipclean", INERT),     // hgext/fix.py:940 configitems
    ("fix.failure", INERT),         // hgext/fix.py:206 config
    ("fix.maxfilesize", INERT),     // hgext/fix.py:421 configbytes
    ("format.bookmarks-in-store", INERT), // mercurial/repo/creation.py:204 configbool
    ("format.chunkcachesize", INERT), // mercurial/repo/vfs_options.py:158 configint
    ("format.dotencode", INERT),    // mercurial/repo/creation.py:86 configbool
    ("format.exp-archived-phase", INERT), // mercurial/repo/creation.py:195 configbool
    ("format.exp-use-changelog-v2", INERT), // mercurial/repo/creation.py:179 config
    ("format.exp-use-copies-side-data-changeset", INERT), // mercurial/repo/creation.py:173 configbool
    (
        "format.exp-use-very-fragile-and-unsafe-plain-store-encoding",
        INERT,
    ), // mercurial/repo/creation.py:89 configbool
    ("format.generaldelta", INERT),                       // mercurial/scmutil.py:1921 configbool
    ("format.manifestcachesize", INERT), // mercurial/repo/vfs_options.py:39 configint
    ("format.maxchainlen", INERT),       // mercurial/repo/vfs_options.py:232 configint
    ("format.obsstore-version", INERT),  // mercurial/obsolete.py:833 configint
    ("format.revlog-compression", INERT), // mercurial/repo/creation.py:111 configlist
    ("format.sparse-revlog", INERT),     // mercurial/repo/creation.py:139 configbool
    ("format.use-delta-info-flags", INERT), // mercurial/repo/creation.py:155 configbool
    ("format.use-dirstate-tracked-hint", INERT), // mercurial/repo/creation.py:249 configbool
    (
        "format.use-dirstate-tracked-hint.automatic-upgrade-of-mismatching-repositories",
        INERT,
    ), // mercurial/upgrade_utils/auto_upgrade.py:111 configbool
    (
        "format.use-dirstate-tracked-hint.automatic-upgrade-of-mismatching-repositories:quiet",
        INERT,
    ), // mercurial/upgrade_utils/auto_upgrade.py:115 configbool
    ("format.use-dirstate-tracked-hint.version", INERT), // mercurial/repo/creation.py:250 configint
    ("format.use-dirstate-v2", INERT),   // mercurial/repo/creation.py:152 configbool
    (
        "format.use-dirstate-v2.automatic-upgrade-of-mismatching-repositories",
        INERT,
    ), // mercurial/upgrade_utils/auto_upgrade.py:167 configbool
    (
        "format.use-dirstate-v2.automatic-upgrade-of-mismatching-repositories:quiet",
        INERT,
    ), // mercurial/upgrade_utils/auto_upgrade.py:171 configbool
    ("format.use-fileindex-v1", INERT),  // mercurial/repo/creation.py:82 configbool
    ("format.use-internal-phase", INERT), // mercurial/repo/creation.py:191 configbool
    ("format.use-persistent-nodemap", INERT), // mercurial/repo/creation.py:209 configbool
    ("format.use-share-safe", INERT),    // mercurial/repo/creation.py:216 configbool
    (
        "format.use-share-safe.automatic-upgrade-of-mismatching-repositories",
        INERT,
    ), // mercurial/upgrade_utils/auto_upgrade.py:54 configbool
    (
        "format.use-share-safe.automatic-upgrade-of-mismatching-repositories:quiet",
        INERT,
    ), // mercurial/upgrade_utils/auto_upgrade.py:58 configbool
    ("format.usefncache", INERT),        // mercurial/repo/creation.py:84 configbool
    ("format.usegeneraldelta", INERT),   // mercurial/scmutil.py:1921 configbool
    ("format.usestore", INERT),          // mercurial/repo/creation.py:80 configbool
    ("fsmonitor.blacklistusers", INERT), // hgext/fsmonitor/watchmanclient.py:53 configlist
    ("fsmonitor.mode", INERT),           // hgext/fsmonitor/state.py:34 config
    ("fsmonitor.timeout", INERT),        // hgext/fsmonitor/state.py:38 config
    ("fsmonitor.verbose", INERT),        // hgext/fsmonitor/__init__.py:232 configbool
    ("fsmonitor.walk_on_invalidate", INERT), // hgext/fsmonitor/state.py:35 configbool
    ("fsmonitor.warn_update_file_count", INERT), // mercurial/merge.py:1210 configint
    ("fsmonitor.warn_update_file_count_rust", INERT), // mercurial/merge.py:1218 configint
    ("fsmonitor.warn_when_unused", INERT), // mercurial/merge.py:1209 configbool
    ("fsmonitor.watchman_exe", FORCED),  // hgext/fsmonitor/watchmanclient.py:99 configpath
    ("git.log-index-cache-miss", INERT), // hgext/git/__init__.py:307 configbool
    ("gpg.*", INERT),                    // hgext/gpg.py:260 a key comment
    ("gpg.cmd", SHELL),                  // hgext/gpg.py:74 the gpg command line
    ("gpg.key", SHELL),                  // hgext/gpg.py:74 the gpg command line
    ("help.hidden-command.<name>", INERT), // mercurial/help.py:280 configbool
    ("help.hidden-topic.<name>", INERT), // mercurial/help.py:287 configbool
    ("hgk.path", SHELL),                 // hgext/hgk.py:386 ui.system
    ("histedit.defaultrev", INERT),      // mercurial/destutil.py:409 config
    ("histedit.dropmissing", INERT),     // hgext/histedit.py:2506 configbool
    ("histedit.later-commits-first", INERT), // hgext/histedit.py:1263 configbool
    ("histedit.linelen", INERT),         // hgext/histedit.py:564 configint
    ("histedit.singletransaction", INERT), // hgext/histedit.py:2085 configbool
    ("histedit.summary-template", INERT), // hgext/histedit.py:1196 config
    ("hooks.*:run-with-plain", INERT),   // mercurial/hook.py:166 configbool
    ("hooks.<name>", PYTHON_HOOK),       // mercurial/hook.py:236 hooks
    ("hooks.priority.<name>", INERT),    // mercurial/hook.py:249 configint
    ("hooks.tonative.<name>", INERT),    // mercurial/hook.py:183 configbool
    ("hostfingerprints.*", INERT),       // mercurial/sslutil.py:153 configlist
    ("hostsecurity.*:ciphers", INERT),   // mercurial/sslutil.py:120 config
    ("hostsecurity.*:fingerprints", INERT), // mercurial/sslutil.py:136 configlist
    ("hostsecurity.*:minimumprotocol", INERT), // mercurial/sslutil.py:116 config
    ("hostsecurity.*:verifycertsfile", INERT), // mercurial/sslutil.py:179 a CA bundle read as data
    ("hostsecurity.ciphers", INERT),     // mercurial/sslutil.py:119 config
    ("hostsecurity.minimumprotocol", INERT), // mercurial/sslutil.py:116 config
    ("http.timeout", INERT),             // hgext/phabricator.py:441 configwith
    ("http_proxy.always", INERT),        // mercurial/url.py:162 configbool
    ("http_proxy.host", INERT),          // mercurial/url.py:133 config
    ("http_proxy.no", INERT),            // mercurial/url.py:152 configlist
    ("http_proxy.passwd", INERT),        // mercurial/url.py:147 config
    ("http_proxy.user", INERT),          // mercurial/url.py:146 config
    ("keywordset.svn", INERT),           // hgext/keyword.py:223 configbool
    ("largefiles.minsize", INERT),       // hgext/largefiles/lfutil.py:57 config
    ("largefiles.patterns", INERT),      // hgext/largefiles/lfutil.py:93 configlist
    ("largefiles.usercache", INERT),     // hgext/largefiles/lfutil.py:83 a cache directory
    ("lfs.retry", INERT),                // hgext/lfs/blobstore.py:326 configint
    ("lfs.threshold", INERT),            // hgext/lfs/__init__.py:303 configbytes
    ("lfs.track", INERT),                // hgext/lfs/__init__.py:300 config
    ("lfs.url", URL),                    // hgext/lfs/blobstore.py:750 the blob store URL
    ("lfs.usercache", INERT),            // hgext/largefiles/lfutil.py:83 a cache directory
    ("logtoprocess.*", SHELL),           // hgext/logtoprocess.py:79 runbgcommand shell=True
    ("logtoprocess.command", SHELL),     // hgext/logtoprocess.py:79 runbgcommand shell=True
    ("logtoprocess.commandexception", SHELL), // hgext/logtoprocess.py:79 runbgcommand shell=True
    ("logtoprocess.commandfinish", SHELL), // hgext/logtoprocess.py:79 runbgcommand shell=True
    ("logtoprocess.develwarn", SHELL),   // hgext/logtoprocess.py:79 runbgcommand shell=True
    ("logtoprocess.uiblocked", SHELL),   // hgext/logtoprocess.py:79 runbgcommand shell=True
    ("merge-patterns.*", FORCED),        // mercurial/filemerge.py:227 findexternaltool
    ("merge-tools.<name>.args", SHELL),  // mercurial/filemerge.py:765 appended to the command line
    ("merge-tools.<name>.binary", INERT), // mercurial/filemerge.py:188 _toolstr
    ("merge-tools.<name>.check", INERT), // mercurial/filemerge.py:1251 _toolstr
    ("merge-tools.<name>.checkchanged", INERT), // mercurial/filemerge.py:1270 _toolstr
    ("merge-tools.<name>.diffargs", SHELL), // hgext/extdiff.py:801 appended to the command line
    ("merge-tools.<name>.executable", FORCED), // mercurial/filemerge.py:162 findexe(expandpath)
    ("merge-tools.<name>.fixeol", INERT), // mercurial/filemerge.py:1286 _toolstr
    ("merge-tools.<name>.gui", INERT),   // mercurial/filemerge.py:194 _toolstr
    ("merge-tools.<name>.mergemarkers", INERT), // mercurial/filemerge.py:43 _toolstr
    ("merge-tools.<name>.mergemarkertemplate", INERT), // mercurial/filemerge.py:43 _toolstr
    ("merge-tools.<name>.premerge", INERT), // mercurial/filemerge.py:421 _toolstr
    ("merge-tools.<name>.priority", INERT), // mercurial/filemerge.py:249 _toolstr
    ("merge-tools.<name>.regappend", INERT), // mercurial/filemerge.py:159 _toolstr
    ("merge-tools.<name>.symlink", INERT), // mercurial/filemerge.py:186 _toolstr
    ("merge.checkignored", INERT),       // mercurial/merge.py:1705 config
    ("merge.checkunknown", INERT),       // mercurial/merge.py:1706 config
    ("merge.disable-partial-tools", INERT), // mercurial/filemerge.py:1145 configbool
    ("merge.followcopies", INERT),       // mercurial/merge.py:1422 configbool
    ("merge.on-failure", INERT),         // mercurial/filemerge.py:1221 config
    ("merge.preferancestor", INERT),     // mercurial/context.py:830 configlist
    ("merge.strict-capability-check", INERT), // mercurial/filemerge.py:167 configbool
    ("mq.git", INERT),                   // hgext/mq.py:532 config
    ("mq.keepchanges", INERT),           // hgext/mq.py:2565 configbool
    ("mq.plain", INERT),                 // hgext/mq.py:541 configbool
    ("mq.secret", INERT),                // hgext/mq.py:1218 configbool
    ("notify.changegroup", INERT),       // hgext/notify.py:352 a template
    ("notify.diffstat", INERT),          // hgext/notify.py:559 configbool
    ("notify.domain", INERT),            // hgext/hooklib/changeset_obsoleted.py:66 config
    ("notify.fromauthor", INERT),        // hgext/notify.py:633 config
    ("notify.incoming", INERT),          // hgext/notify.py:352 a template
    ("notify.maxdiff", INERT),           // hgext/notify.py:548 configint
    ("notify.maxdiffstat", INERT),       // hgext/notify.py:560 configint
    ("notify.maxsubject", INERT),        // hgext/notify.py:488 configint
    ("notify.mbox", INERT),              // hgext/notify.py:331 config
    ("notify.merge", INERT),             // hgext/notify.py:335 configbool
    ("notify.messageidseed", INERT),     // hgext/hooklib/changeset_obsoleted.py:71 config
    ("notify.outgoing", INERT),          // hgext/notify.py:352 a template
    ("notify.reply-to-predecessor", INERT), // hgext/notify.py:338 configbool
    ("notify.showfunc", INERT),          // hgext/notify.py:336 configbool
    ("notify.sources", INERT),           // hgext/notify.py:427 config
    ("notify.strip", INERT),             // hgext/notify.py:328 configint
    ("notify.style", INERT),             // hgext/notify.py:356 config
    ("notify.template", INERT),          // hgext/notify.py:352 config
    ("notify.test", INERT),              // hgext/hooklib/changeset_obsoleted.py:122 configbool
    ("notify_obsoleted.domain", INERT),  // hgext/hooklib/changeset_obsoleted.py:66 config
    ("notify_obsoleted.messageidseed", INERT), // hgext/hooklib/changeset_obsoleted.py:69 config
    ("notify_obsoleted.template", INERT), // hgext/hooklib/changeset_obsoleted.py:72 config
    ("notify_published.domain", INERT),  // hgext/hooklib/changeset_published.py:65 config
    ("notify_published.messageidseed", INERT), // hgext/hooklib/changeset_published.py:68 config
    ("notify_published.template", INERT), // hgext/hooklib/changeset_published.py:71 config
    ("packs.maxchainlen", INERT),        // hgext/remotefilelog/repack.py:591 configint
    ("packs.maxpacksize", INERT),        // hgext/remotefilelog/repack.py:181 configbytes
    ("pager.attend", INERT),             // hgext/pager.py:56 configlist
    ("pager.attend-<name>", INERT),      // mercurial/ui.py:1587 configbool
    ("pager.ignore", INERT),             // hgext/pager.py:57 configlist
    ("pager.pager", SHELL),              // mercurial/ui.py:1610 the pager command
    ("partial-merge-tools.<name>.args", SHELL), // mercurial/filemerge.py:1167 appended to the command line
    ("partial-merge-tools.<name>.disable", INERT), // mercurial/filemerge.py:1163 configbool
    ("partial-merge-tools.<name>.executable", EXEC), // mercurial/filemerge.py:1166 shellquote
    ("partial-merge-tools.<name>.order", INERT), // mercurial/filemerge.py:1165 configint
    ("partial-merge-tools.<name>.patterns", INERT), // mercurial/filemerge.py:1155 configlist
    ("patch.eol", INERT),                       // mercurial/patch.py:2390 config
    ("patch.fuzz", INERT),                      // mercurial/patch.py:876 configint
    ("patchbomb.bcc", INERT),                   // hgext/patchbomb.py:890 addresses
    ("patchbomb.bundletype", INERT),            // hgext/patchbomb.py:387 config
    ("patchbomb.cc", INERT),                    // hgext/patchbomb.py:890 addresses
    ("patchbomb.confirm", INERT),               // hgext/patchbomb.py:925 configbool
    ("patchbomb.flagtemplate", INERT),          // hgext/patchbomb.py:230 config
    ("patchbomb.from", INERT),                  // hgext/patchbomb.py:875 config
    ("patchbomb.intro", INERT),                 // hgext/patchbomb.py:210 config
    ("patchbomb.publicurl", INERT),             // hgext/patchbomb.py:181 config
    ("patchbomb.reply-to", INERT),              // hgext/patchbomb.py:890 addresses
    ("patchbomb.to", INERT),                    // hgext/patchbomb.py:890 addresses
    ("paths.*:bookmarks.mode", INERT),          // mercurial/utils/urlutil.py:747 pathsuboption
    ("paths.*:multi-urls", INERT),              // mercurial/utils/urlutil.py:790 pathsuboption
    ("paths.*:pulled-delta-reuse-policy", INERT), // mercurial/utils/urlutil.py:772 pathsuboption
    ("paths.*:pushrev", EXEMPT),                // mercurial/utils/urlutil.py:735 a revset
    ("paths.*:pushurl", URL_LIST),              // mercurial/utils/urlutil.py:710 pathsuboption
    ("paths.<name>", URL_LIST),                 // mercurial/utils/urlutil.py:834 path
    ("paths.default", URL_LIST),                // mercurial/utils/urlutil.py:834 path
    ("paths.default-push", URL_LIST),           // mercurial/utils/urlutil.py:834 path
    ("phabimport.obsolete", INERT),             // hgext/phabricator.py:2202 configbool
    ("phabimport.secret", INERT),               // hgext/phabricator.py:2200 configbool
    ("phabricator.batchsize", INERT),           // hgext/phabricator.py:1909 configint
    ("phabricator.callsign", INERT),            // hgext/phabricator.py:503 config
    ("phabricator.curlcmd", SHELL),             // hgext/phabricator.py:429 popen2
    ("phabricator.debug", INERT),               // hgext/phabricator.py:345 configbool
    ("phabricator.repophid", INERT),            // hgext/phabricator.py:500 config
    ("phabricator.retry", INERT),               // hgext/phabricator.py:440 configint
    ("phabricator.retry.interval", INERT),      // hgext/phabricator.py:457 configint
    ("phabricator.url", INERT),                 // hgext/phabricator.py:2332 config
    ("phabsend.confirm", INERT),                // hgext/phabricator.py:1429 configbool
    ("phases.checksubrepos", INERT),            // mercurial/subrepoutil.py:491 config
    ("phases.new-commit", INERT),               // mercurial/phases.py:1249 config
    ("phases.publish", INERT),                  // mercurial/localrepo.py:2065 configbool
    ("profiling.enabled", INERT),               // mercurial/dispatch.py:967 configbool
    ("profiling.format", INERT),                // mercurial/profiling.py:42 config
    ("profiling.freq", INERT),                  // mercurial/profiling.py:111 configint
    ("profiling.limit", INERT),                 // mercurial/profiling.py:44 configint
    ("profiling.nested", INERT),                // mercurial/profiling.py:45 configint
    ("profiling.output", INERT),                // mercurial/profiling.py:304 config
    ("profiling.output-dir", INERT),            // mercurial/profiling.py:311 config
    ("profiling.output-dir:create", INERT),     // mercurial/profiling.py:314 configbool
    ("profiling.py-spy.exe", EXEC),             // mercurial/profiling.py:203 Popen
    ("profiling.py-spy.format", INERT),         // mercurial/profiling.py:207 config
    ("profiling.py-spy.freq", INERT),           // mercurial/profiling.py:205 configint
    ("profiling.showmax", INERT),               // mercurial/profiling.py:188 configwith
    ("profiling.showmin", INERT),               // mercurial/profiling.py:187 configwith
    ("profiling.showtime", INERT),              // mercurial/profiling.py:194 configbool
    ("profiling.sort", INERT),                  // mercurial/profiling.py:43 config
    ("profiling.statformat", INERT),            // mercurial/profiling.py:157 config
    ("profiling.time-track", INERT),            // mercurial/profiling.py:147 config
    ("profiling.type", INERT),                  // mercurial/profiling.py:294 config
    ("progress.assume-tty", INERT),             // mercurial/progress.py:23 configbool
    ("progress.changedelay", INERT),            // mercurial/progress.py:88 config
    ("progress.clear-complete", INERT),         // mercurial/progress.py:184 configbool
    ("progress.debug", INERT),                  // mercurial/scmutil.py:1870 configbool
    ("progress.delay", INERT),                  // mercurial/progress.py:81 config
    ("progress.disable", INERT),                // mercurial/ui.py:2282 configbool
    ("progress.estimateinterval", INERT),       // mercurial/progress.py:91 configwith
    ("progress.format", INERT),                 // mercurial/progress.py:90 configlist
    ("progress.refresh", INERT),                // mercurial/progress.py:86 config
    ("progress.width", INERT),                  // mercurial/progress.py:198 configint
    ("pull.confirm", INERT),                    // mercurial/exchange.py:1800 configbool
    ("push.pushvars.server", INERT),            // mercurial/bundle2_part_handlers.py:610 configbool
    ("rebase.experimental.inmemory", INERT),    // hgext/rebase.py:1057 configbool
    ("rebase.singletransaction", INERT),        // hgext/rebase.py:1261 configbool
    ("rebase.store-source", INERT),             // hgext/rebase.py:541 configbool
    ("remotefilelog.backgroundprefetch", INERT), // hgext/remotefilelog/__init__.py:1060 configbool
    ("remotefilelog.backgroundrepack", INERT),  // hgext/remotefilelog/__init__.py:1040 configbool
    ("remotefilelog.batchsize", INERT), // hgext/remotefilelog/fileserverclient.py:449 configint
    ("remotefilelog.bgprefetchrevs", INERT), // hgext/remotefilelog/__init__.py:1034 config
    ("remotefilelog.cachegroup", INERT), // hgext/remotefilelog/shallowutil.py:486 config
    ("remotefilelog.cachelimit", INERT), // hgext/remotefilelog/basestore.py:373 configbytes
    ("remotefilelog.cachepath", INERT), // hgext/remotefilelog/shallowutil.py:51 config
    ("remotefilelog.cacheprocess", SHELL), // hgext/remotefilelog/fileserverclient.py:317 popen4
    ("remotefilelog.cacheprocess.includepath", INERT), // hgext/remotefilelog/fileserverclient.py:323 configbool
    ("remotefilelog.data.gencountlimit", INERT), // hgext/remotefilelog/repack.py:273 configint
    ("remotefilelog.data.generations", INERT),   // hgext/remotefilelog/repack.py:274 configlist
    ("remotefilelog.data.maxrepackpacks", INERT), // hgext/remotefilelog/repack.py:275 configint
    ("remotefilelog.data.repackmaxpacksize", INERT), // hgext/remotefilelog/repack.py:278 configbytes
    ("remotefilelog.data.repacksizelimit", INERT), // hgext/remotefilelog/repack.py:281 configbytes
    ("remotefilelog.debug", INERT), // hgext/remotefilelog/fileserverclient.py:327 configbool
    ("remotefilelog.excludepattern", INERT), // hgext/remotefilelog/shallowrepo.py:335 configlist
    ("remotefilelog.fetchwarning", INERT), // hgext/remotefilelog/fileserverclient.py:634 config
    ("remotefilelog.gcrepack", INERT), // hgext/remotefilelog/__init__.py:926 configbool
    ("remotefilelog.getfilesstep", INERT), // hgext/remotefilelog/fileserverclient.py:426 configint
    ("remotefilelog.getfilestype", INERT), // hgext/remotefilelog/fileserverclient.py:429 config
    ("remotefilelog.history.gencountlimit", INERT), // hgext/remotefilelog/repack.py:294 configint
    ("remotefilelog.history.generations", INERT), // hgext/remotefilelog/repack.py:297 configlist
    ("remotefilelog.history.maxrepackpacks", INERT), // hgext/remotefilelog/repack.py:300 configint
    ("remotefilelog.history.repackmaxpacksize", INERT), // hgext/remotefilelog/repack.py:303 configbytes
    ("remotefilelog.history.repacksizelimit", INERT), // hgext/remotefilelog/repack.py:306 configbytes
    ("remotefilelog.includepattern", INERT), // hgext/remotefilelog/shallowrepo.py:332 configlist
    ("remotefilelog.nodettl", INERT),        // hgext/remotefilelog/repack.py:408 configint
    ("remotefilelog.prefetchdays", INERT),   // hgext/remotefilelog/__init__.py:1004 configint
    ("remotefilelog.prefetchdelay", INERT),  // hgext/remotefilelog/__init__.py:1015 configint
    ("remotefilelog.pullprefetch", INERT),   // hgext/remotefilelog/__init__.py:1058 config
    ("remotefilelog.repackonhggc", INERT),   // hgext/remotefilelog/__init__.py:925 configbool
    ("remotefilelog.reponame", INERT),       // hgext/remotefilelog/shallowrepo.py:147 config
    ("remotefilelog.server", INERT),         // hgext/remotefilelog/__init__.py:459 configbool
    ("remotefilelog.servercachepath", INERT), // hgext/remotefilelog/remotefilelogserver.py:304 config
    ("remotefilelog.serverexpiration", INERT), // hgext/remotefilelog/remotefilelogserver.py:428 configint
    ("remotefilelog.strip.includefiles", INERT), // hgext/remotefilelog/shallowbundle.py:97 config
    ("remotefilelog.validatecache", INERT),    // hgext/remotefilelog/basestore.py:43 config
    ("remotefilelog.validatecachelog", INERT), // hgext/remotefilelog/basestore.py:40 config
    ("remotenames.bookmarks", INERT),          // hgext/remotenames.py:272 configbool
    ("remotenames.branches", INERT),           // hgext/remotenames.py:308 configbool
    ("remotenames.hoistedpeer", INERT),        // hgext/remotenames.py:289 config
    ("repack.chainorphansbysize", INERT),      // hgext/remotefilelog/repack.py:701 configbool
    ("revsetalias.*", INERT),                  // mercurial/revset.py:584 configitems
    ("rewrite.backup-bundle", INERT),          // hgext/histedit.py:2022 configbool
    ("rewrite.empty-successor", INERT),        // mercurial/rewriteutil.py:198 config
    ("rewrite.update-timestamp", INERT),       // hgext/histedit.py:604 configbool
    ("rhg.cat", INERT),                        // rust/rhg/src/main.rs:374 config
    ("rhg.fallback-executable", EXEC),         // rust/rhg/src/main.rs:967 Command::new
    ("rhg.fallback-immediately", INERT),       // rust/rhg/src/main.rs:374 config
    ("rhg.ignored-extensions", INERT),         // rust/rhg/src/main.rs:374 config
    ("rhg.on-unsupported", INERT),             // rust/rhg/src/main.rs:374 config
    ("rust.update-from-clean", INERT),         // mercurial/merge.py:1651 configbool
    ("rust.update-from-null", INERT),          // mercurial/merge.py:1665 configbool
    ("schemes.*", URL),                        // hgext/schemes.py:156 a URL template
    ("server.bookmarks-pushkey-compat", INERT), // mercurial/bundle2_part_handlers.py:474 configbool
    ("server.bundle1", INERT),                 // mercurial/wireprotov1server.py:116 configbool
    ("server.bundle1.pull", INERT),            // mercurial/wireprotov1server.py:116 configbool
    ("server.bundle1.push", INERT),            // mercurial/wireprotov1server.py:116 configbool
    ("server.bundle1gd", INERT),               // mercurial/wireprotov1server.py:116 configbool
    ("server.bundle1gd.pull", INERT),          // mercurial/wireprotov1server.py:116 configbool
    ("server.bundle1gd.push", INERT),          // mercurial/wireprotov1server.py:116 configbool
    ("server.bundle2.stream", INERT),          // mercurial/exchanges/bundle_caps.py:75 configbool
    ("server.compressionengines", INERT),      // mercurial/wireprototypes.py:404 configlist
    ("server.concurrent-push-mode", INERT),    // mercurial/exchanges/bundle_caps.py:64 config
    ("server.disablefullbundle", INERT),       // mercurial/wireprotov1server.py:563 configbool
    ("server.maxhttpheaderlen", INERT),        // mercurial/wireprotoserver.py:148 configint
    ("server.peer-bundle-cache-root", INERT),  // hgext/clonebundles.py:778 config
    ("server.preferuncompressed", INERT),      // mercurial/wireprotov1server.py:386 configbool
    ("server.pullbundle", INERT),              // mercurial/wireprotov1server.py:553 configbool
    ("server.streamunbundle", INERT),          // mercurial/wireprotov1server.py:702 configbool
    ("server.uncompressed", INERT),            // mercurial/exchanges/bundle_caps.py:72 configbool
    ("server.uncompressedallowsecret", INERT), // mercurial/streamclone.py:288 configbool
    ("server.validate", INERT),                // mercurial/changegroup.py:808 configbool
    ("server.view", INERT),                    // mercurial/exchanges/peer.py:78 config
    ("server.zliblevel", INERT),               // mercurial/wireprotoserver.py:288 configint
    ("server.zstdlevel", INERT),               // mercurial/wireprotoserver.py:276 configint
    ("share.pool", INERT),                     // hgext/share.py:156 config
    ("share.poolnaming", INERT),               // hgext/share.py:162 config
    ("share.safe-mismatch.source-not-safe", INERT), // mercurial/localrepo.py:609 config
    ("share.safe-mismatch.source-not-safe.warn", INERT), // mercurial/localrepo.py:606 configbool
    ("share.safe-mismatch.source-not-safe:verbose-upgrade", INERT), // mercurial/localrepo.py:612 configbool
    ("share.safe-mismatch.source-safe", INERT), // mercurial/localrepo.py:649 config
    ("share.safe-mismatch.source-safe.warn", INERT), // mercurial/localrepo.py:650 configbool
    ("share.safe-mismatch.source-safe:verbose-upgrade", INERT), // mercurial/localrepo.py:653 configbool
    ("shelve.maxbackups", INERT),                               // mercurial/shelve.py:433 configint
    ("shelve.store", INERT),                                    // mercurial/shelve.py:116 config
    ("smtp.host", INERT),                                       // mercurial/mail.py:122 config
    ("smtp.local_hostname", INERT),                             // mercurial/mail.py:115 config
    ("smtp.password", INERT),                                   // mercurial/mail.py:174 config
    ("smtp.port", INERT),                                       // mercurial/mail.py:136 config
    ("smtp.tls", INERT),                                        // mercurial/mail.py:116 config
    ("smtp.username", INERT),                                   // mercurial/mail.py:173 config
    ("sparse.missingwarning", INERT), // mercurial/sparse.py:162 configbool
    ("storage.all-slow-path", INERT), // mercurial/repo/vfs_options.py:297 config
    ("storage.delta-fold-estimate", INERT), // mercurial/repo/vfs_options.py:242 config
    ("storage.delta-fold-tolerance-percentage", INERT), // mercurial/repo/vfs_options.py:253 configint
    ("storage.dirstate-v2.slow-path", INERT),           // mercurial/repo/vfs_options.py:328 config
    ("storage.fileindex.gc-retention-seconds", INERT), // mercurial/repo/vfs_options.py:121 configint
    ("storage.fileindex.max-unused-percentage", INERT), // mercurial/repo/vfs_options.py:79 configint
    ("storage.fileindex.slow-path", INERT),             // mercurial/repo/vfs_options.py:93 config
    ("storage.filelog.expected-max-compression-ratio", INERT), // mercurial/repo/vfs_options.py:236 configint
    ("storage.new-repo-backend", INERT), // mercurial/repo/creation.py:30 config
    ("storage.revbranchcache.mmap", INERT), // mercurial/branching/rev_cache.py:188 configbool
    (
        "storage.revlog.delta-parent-search.candidate-group-chunk-size",
        INERT,
    ), // mercurial/repo/vfs_options.py:172 configint
    ("storage.revlog.exchange-compressed-delta", INERT), // mercurial/exchanges/bundle_caps.py:56 configbool
    ("storage.revlog.issue6528.fix-incoming", INERT), // mercurial/repo/vfs_options.py:178 configbool
    ("storage.revlog.mmap.index", INERT), // mercurial/repo/vfs_options.py:207 configbool
    ("storage.revlog.mmap.index:size-threshold", INERT), // mercurial/repo/vfs_options.py:208 configbytes
    ("storage.revlog.optimize-delta-parent-choice", INERT), // mercurial/repo/vfs_options.py:169 configbool
    ("storage.revlog.persistent-nodemap.mmap", INERT), // mercurial/repo/vfs_options.py:355 configbool
    ("storage.revlog.persistent-nodemap.slow-path", INERT), // mercurial/repo/vfs_options.py:293 config
    ("storage.revlog.record-delta-quality", INERT), // mercurial/repo/vfs_options.py:199 configbool
    ("storage.revlog.reuse-external-delta", INERT), // mercurial/repo/vfs_options.py:181 configbool
    ("storage.revlog.reuse-external-delta-compression", INERT), // mercurial/repo/vfs_options.py:195 configbool
    ("storage.revlog.reuse-external-delta-parent", INERT), // mercurial/repo/vfs_options.py:184 configbool
    (
        "storage.revlog.reuse-external-suspicious-delta-parent",
        INERT,
    ), // mercurial/repo/vfs_options.py:191 configbool
    ("storage.revlog.validate-delta-base", INERT), // mercurial/repo/vfs_options.py:360 configbool
    ("storage.revlog.zlib.level", INERT),          // mercurial/repo/vfs_options.py:271 configint
    ("storage.revlog.zstd.level", INERT),          // mercurial/repo/vfs_options.py:277 configint
    ("subpaths.*", URL),                           // mercurial/subrepoutil.py:108 a source URL
    ("subrepos.allowed", INERT),                   // mercurial/subrepo.py:207 configbool
    ("subrepos.git:allowed", INERT),               // mercurial/subrepo.py:214 configbool
    ("subrepos.hg:allowed", INERT),                // mercurial/subrepo.py:214 configbool
    ("subrepos.svn:allowed", INERT),               // mercurial/subrepo.py:214 configbool
    ("templatealias.*", INERT),                    // mercurial/formatter.py:672 configitems
    ("templateconfig.*", INERT), // mercurial/templatefuncs.py:363 the config() template function
    ("templates.*", INERT),      // mercurial/formatter.py:677 configitems
    ("transplant.filter", SHELL), // hgext/transplant.py:806 ui.system
    ("transplant.log", INERT),   // hgext/transplant.py:803 config
    ("trusted.groups", INERT),   // mercurial/ui.py:673 configlist
    ("trusted.users", INERT),    // mercurial/ui.py:672 configlist
    ("ui._usedassubrepo", INERT), // mercurial/exchange.py:1352 configbool
    ("ui.allowemptycommit", INERT), // hgext/rebase.py:1482 configbool
    ("ui.archivemeta", INERT),   // hgext/largefiles/overrides.py:1292 configbool
    ("ui.askusername", INERT),   // mercurial/ui.py:1236 configbool
    ("ui.available-memory", INERT), // mercurial/ui.py:2475 config
    ("ui.clonebundlefallback", INERT), // mercurial/exchange.py:3007 configbool
    ("ui.clonebundleprefers", INERT), // mercurial/bundlecaches.py:631 configlist
    ("ui.clonebundles", INERT),  // mercurial/exchange.py:2919 configbool
    ("ui.color", INERT),         // mercurial/color.py:217 config
    ("ui.commitsubrepos", INERT), // mercurial/commands.py:2008 configbool
    ("ui.debug", INERT),         // mercurial/ui.py:658 configbool
    ("ui.detailed-exit-code", INERT), // mercurial/chgserver.py:552 configbool
    ("ui.editor", SHELL),        // mercurial/ui.py:2273 ui.system
    ("ui.fallbackencoding", INERT), // mercurial/dispatch.py:998 config
    ("ui.forcecwd", INERT),      // mercurial/dirstate.py:592 config
    ("ui.forcemerge", FORCED),   // mercurial/filemerge.py:202 findexternaltool
    ("ui.formatdebug", INERT),   // mercurial/formatter.py:841 configbool
    ("ui.formatjson", INERT),    // mercurial/formatter.py:844 configbool
    ("ui.formatted", INERT),     // hgext/mq.py:2257 configbool/plain
    ("ui.interactive", INERT),   // hgext/mq.py:2263 configbool/plain
    ("ui.interface", INERT),     // mercurial/ui.py:1787 config
    ("ui.interface.chunkselector", INERT), // mercurial/ui.py:1792 config
    ("ui.interface.histedit", INERT), // mercurial/ui.py:1792 config
    ("ui.large-file-limit", INERT), // mercurial/context.py:1841 configbytes
    ("ui.logblockedtimes", INERT), // mercurial/ui.py:668 configbool
    ("ui.merge", FORCED),        // mercurial/filemerge.py:256 findexternaltool
    ("ui.mergemarkers", INERT),  // mercurial/filemerge.py:1070 config
    ("ui.message-output", INERT), // mercurial/commandserver.py:260 config
    ("ui.nontty", INERT),        // mercurial/ui.py:1525 configbool
    ("ui.origbackuppath", INERT), // mercurial/merge.py:1779 config
    ("ui.paginate", INERT),      // mercurial/ui.py:1586 configbool
    ("ui.patch", SHELL),         // mercurial/patch.py:2458 popen
    ("ui.portablefilenames", INERT), // mercurial/scmutil.py:384 config
    ("ui.promptecho", INERT),    // mercurial/ui.py:1977 configbool
    ("ui.quiet", INERT),         // mercurial/ui.py:660 configbool
    ("ui.quietbookmarkmove", INERT), // mercurial/bookmarks.py:720 configbool
    ("ui.relative-paths", INERT), // mercurial/scmutil.py:1029 config
    ("ui.remotecmd", SHELL),     // mercurial/sshpeer.py:687 the ssh command line
    ("ui.report_untrusted", INERT), // mercurial/ui.py:663 configbool
    ("ui.rollback", INERT),      // mercurial/commands.py:6031 configbool
    ("ui.signal-safe-lock", INERT), // mercurial/localrepo.py:2906 configbool
    ("ui.slash", INERT),         // mercurial/debugcommands.py:4430 configbool
    ("ui.ssh", SHELL),           // mercurial/sshpeer.py:686 the ssh command line
    ("ui.ssherrorhint", INERT),  // mercurial/sshpeer.py:270 config
    ("ui.statuscopies", INERT),  // mercurial/commands.py:6596 configbool
    ("ui.strict", INERT),        // mercurial/dispatch.py:790 configbool
    ("ui.style", INERT),         // mercurial/logcmdutil.py:697 config
    ("ui.supportcontact", INERT), // mercurial/dispatch.py:1225 config
    ("ui.textwidth", INERT),     // mercurial/help.py:1262 configint
    ("ui.timeout", INERT),       // hgext/journal.py:368 configint
    ("ui.timeout.warn", INERT),  // mercurial/localrepo.py:2904 configint
    ("ui.timestamp-output", INERT), // mercurial/ui.py:666 configbool
    ("ui.traceback", INERT),     // mercurial/ui.py:667 configbool
    ("ui.tweakdefaults", INERT), // mercurial/ui.py:404 configbool
    ("ui.username", EXEMPT),     // mercurial/ui.py:1229 the committer name
    ("ui.verbose", INERT),       // mercurial/ui.py:659 configbool
    ("usage.resources", INERT),  // mercurial/scmutil.py:2423 config
    ("usage.resources.bandwidth", INERT), // mercurial/scmutil.py:2423 config
    ("usage.resources.cpu", INERT), // mercurial/scmutil.py:2423 config
    ("usage.resources.disk", INERT), // mercurial/scmutil.py:2423 config
    ("usage.resources.memory", INERT), // mercurial/scmutil.py:2423 config
    ("verify.skipflags", INERT), // hgext/lfs/__init__.py:463 configint
    ("web.accesslog", INERT),    // mercurial/hgweb/server.py:383 config
    ("web.address", INERT),      // mercurial/hgweb/server.py:419 config
    ("web.allow-archive", INERT), // mercurial/hgweb/webcommands.py:1263 configlist
    ("web.allow-pull", INERT),   // mercurial/hgweb/hgweb_mod_inner.py:150 configbool
    ("web.allow-push", INERT),   // mercurial/hgweb/common.py:220 configlist
    ("web.allow_read", INERT),   // mercurial/hgweb/common.py:192 configlist
    ("web.allowbz2", INERT),     // mercurial/hgweb/webutil.py:71 configbool
    ("web.allowgz", INERT),      // mercurial/hgweb/webutil.py:71 configbool
    ("web.allowzip", INERT),     // mercurial/hgweb/webutil.py:71 configbool
    ("web.archivesubrepos", INERT), // mercurial/hgweb/webcommands.py:1337 configbool
    ("web.baseurl", INERT),      // hgext/bugzilla.py:1221 config
    ("web.cacerts", INERT),      // mercurial/repo/factory.py:108 config
    ("web.cache", INERT),        // mercurial/hgweb/hgweb_mod_inner.py:460 configbool
    ("web.certificate", INERT),  // mercurial/hgweb/server.py:325 config
    ("web.collapse", INERT),     // mercurial/hgweb/hgwebdir_mod_inner.py:132 configbool
    ("web.comparisoncontext", INERT), // mercurial/hgweb/webcommands.py:919 config
    ("web.contact", INERT),      // mercurial/hgweb/common.py:367 get_contact
    ("web.csp", INERT),          // mercurial/hgweb/common.py:408 config
    ("web.deny_push", INERT),    // mercurial/hgweb/common.py:216 configlist
    ("web.deny_read", INERT),    // mercurial/hgweb/common.py:188 configlist
    ("web.descend", INERT),      // mercurial/hgweb/hgwebdir_mod_inner.py:131 configbool
    ("web.description", INERT),  // hgext/zeroconf/__init__.py:140 config
    ("web.encoding", INERT),     // mercurial/hgweb/hgweb_mod_inner.py:379 config
    ("web.errorlog", INERT),     // mercurial/hgweb/server.py:384 config
    ("web.guessmime", INERT),    // mercurial/hgweb/webcommands.py:116 configbool
    ("web.hidden", INERT),       // mercurial/hgweb/hgwebdir_mod_inner.py:217 configbool
    ("web.ipv6", INERT),         // mercurial/hgweb/server.py:409 configbool
    ("web.labels", INERT),       // mercurial/hgweb/hgwebdir_mod_inner.py:241 configlist
    ("web.logoimg", INERT),      // mercurial/hgweb/hgweb_mod_inner.py:190 config
    ("web.logourl", INERT),      // mercurial/hgweb/hgweb_mod_inner.py:189 config
    ("web.maxchanges", INERT),   // mercurial/hgweb/hgweb_mod_inner.py:146 configint
    ("web.maxfiles", INERT),     // mercurial/hgweb/hgweb_mod_inner.py:149 configint
    ("web.maxshortchanges", INERT), // mercurial/hgweb/hgweb_mod_inner.py:148 configint
    ("web.motd", INERT),         // mercurial/hgweb/hgweb_mod_inner.py:243 config
    ("web.name", INERT),         // mercurial/hgweb/hgweb_mod_inner.py:211 config
    ("web.port", INERT),         // mercurial/hgweb/server.py:420 config
    ("web.prefix", INERT),       // hgext/zeroconf/__init__.py:139 config
    ("web.push_ssl", INERT),     // mercurial/hgweb/common.py:213 configbool
    ("web.refreshinterval", INERT), // mercurial/hgweb/hgwebdir_mod_inner.py:307 configint
    ("web.server-header", INERT), // mercurial/hgweb/server.py:391 config
    ("web.static", INERT),       // mercurial/hgweb/hgwebdir_mod_inner.py:446 config
    ("web.staticurl", INERT),    // mercurial/hgweb/hgweb_mod_inner.py:192 config
    ("web.stripes", INERT),      // mercurial/hgweb/hgweb_mod_inner.py:147 configint/plain
    ("web.style", INERT),        // mercurial/hgweb/hgwebdir_mod_inner.py:362 config
    ("web.templates", INERT),    // mercurial/hgweb/hgweb_mod_inner.py:155 config
    ("web.view", INERT),         // mercurial/hgweb/hgweb_mod_inner.py:531 config
    ("win32mbcs.encoding", INERT), // hgext/win32mbcs.py:204 config
    ("win32text.warn", INERT),   // hgext/win32text.py:242 configbool
    ("worker.backgroundclose", INERT), // mercurial/vfs.py:914 configbool
    ("worker.backgroundclosemaxqueue", INERT), // mercurial/vfs.py:928 configint
    ("worker.backgroundcloseminfilecount", INERT), // mercurial/vfs.py:922 configint
    ("worker.backgroundclosethreadcount", INERT), // mercurial/vfs.py:929 configint
    ("worker.enabled", INERT),   // mercurial/dirstate.py:1599 configbool
    ("worker.numcpus", INERT),   // mercurial/dirstate.py:1595 configint/plain
    ("worker.parallel-stream-bundle-processing", INERT), // mercurial/streamclone.py:1163 configbool
    (
        "worker.parallel-stream-bundle-processing.memory-target",
        INERT,
    ), // mercurial/streamclone.py:1172 configbytes
    ("worker.parallel-stream-bundle-processing.num-writer", INERT), // mercurial/streamclone.py:1166 configint
];

/// The Mercurial rows the snapshot does not list, each with where Mercurial reads it.
#[cfg(test)]
const HG_UNDOCUMENTED: &[(&str, &str)] = &[
    (
        "alias.*:category",
        "mercurial/dispatch.py:647 alias help text",
    ),
    ("alias.*:doc", "mercurial/dispatch.py:647 alias help text"),
    ("alias.*:help", "mercurial/dispatch.py:647 alias help text"),
    ("extdiff.*", "hgext/extdiff.py:788 the command line"),
    ("extdiff.cmd.<name>", "hgext/extdiff.py:772 expandpath"),
    ("hooks.priority.<name>", "mercurial/hook.py:249 configint"),
    ("hooks.tonative.<name>", "mercurial/hook.py:183 configbool"),
    (
        "logtoprocess.*",
        "hgext/logtoprocess.py:79 runbgcommand shell=True",
    ),
    (
        "merge-patterns.*",
        "mercurial/filemerge.py:227 findexternaltool",
    ),
    (
        "merge-tools.<name>.diffargs",
        "hgext/extdiff.py:801 appended to the command line",
    ),
    ("revsetalias.*", "mercurial/revset.py:584 configitems"),
    (
        "rhg.fallback-executable",
        "rust/rhg/src/main.rs:967 Command::new",
    ),
    ("schemes.*", "hgext/schemes.py:156 a URL template"),
    ("subpaths.*", "mercurial/subrepoutil.py:108 a source URL"),
    ("templatealias.*", "mercurial/formatter.py:672 configitems"),
];

/// The settings the Mercurial snapshot lists that no row decides, each with why.
#[cfg(test)]
const HG_UNDECIDED: &[(&str, &str)] = &[
    ("absorb.amend-flag", "no reader in Mercurial 7.2.4 is cited"),
    (
        "acl.allow.*",
        "the section holds a `.`, which a spelling cannot separate from its key",
    ),
    (
        "acl.allow.branches.*",
        "the section holds a `.`, which a spelling cannot separate from its key",
    ),
    (
        "acl.config",
        "names a further file Mercurial reads settings from",
    ),
    (
        "acl.deny.*",
        "the section holds a `.`, which a spelling cannot separate from its key",
    ),
    (
        "acl.deny.branches.*",
        "the section holds a `.`, which a spelling cannot separate from its key",
    ),
    (
        "acl.groups.*",
        "the section holds a `.`, which a spelling cannot separate from its key",
    ),
    (
        "bugzilla.usermap",
        "names a further file Mercurial reads settings from",
    ),
    (
        "commands.grep.all-files",
        "no reader in Mercurial 7.2.4 is cited",
    ),
    (
        "debug.dirstate.delaywrite",
        "no reader in Mercurial 7.2.4 is cited",
    ),
    (
        "defaults.*",
        "options prepended to a command, some naming programs (`--ssh`, `--tool`)",
    ),
    (
        "devel.serverexactprotocol",
        "no reader in Mercurial 7.2.4 is cited",
    ),
    (
        "experimental.nonnormalparanoidcheck",
        "no reader in Mercurial 7.2.4 is cited",
    ),
    (
        "experimental.server.filesdata.recommended-batch-size",
        "no reader in Mercurial 7.2.4 is cited",
    ),
    (
        "experimental.server.manifestdata.recommended-batch-size",
        "no reader in Mercurial 7.2.4 is cited",
    ),
    (
        "extdata.*",
        "a `shell:` prefix runs the rest through a shell",
    ),
    (
        "fastannotate.remotepath",
        "a `[paths]` name or a URL; neither reading is decided",
    ),
    (
        "fix.extra-bin-paths",
        "directories added to the search path of fixer commands",
    ),
    (
        "hgweb-paths.*",
        "repositories hgweb serves, whose own settings it then reads",
    ),
    (
        "merge-tools.*",
        "a generic registration; each key Mercurial reads has its own row",
    ),
    (
        "notify.config",
        "names a further file Mercurial reads settings from",
    ),
    (
        "partial-merge-tools.*",
        "a generic registration; each key Mercurial reads has its own row",
    ),
    (
        "remotefilelog.fallbackpath",
        "a `[paths]` name or a URL; neither reading is decided",
    ),
    (
        "rhg.fallback-exectutable",
        "no reader in Mercurial 7.2.4 is cited",
    ),
    ("ui.debugger", "names a Python module Mercurial imports"),
    (
        "usage.repository-role",
        "no reader in Mercurial 7.2.4 is cited",
    ),
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
    /// A Mercurial key that is this text, then more (`opts.<name>`, `attend-<name>`).
    Prefixed(&'static [u8]),
    /// A Mercurial key that is more, then this text (`<name>.args`).
    Suffixed(&'static [u8]),
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

/// Whether every Git row parses, in order, and the Git rows decide every setting once.
const fn git_rows_sound() -> bool {
    let table = parse_table::<{ GIT.len() }>(GIT, Shape::Git);
    table.ok && rows_disjoint(&table.rows, Shape::Git)
}

/// Whether every Mercurial row parses, in order, and the Mercurial rows decide every setting once.
const fn hg_rows_sound() -> bool {
    let table = parse_table::<{ HG.len() }>(HG, Shape::Hg);
    table.ok && rows_disjoint(&table.rows, Shape::Hg)
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a Git row's spelling is malformed or out of order, or two Git rows decide one setting differently at equal specificity [ledger #boundary]
const _: () = assert!(git_rows_sound());
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a Mercurial row's spelling is malformed or out of order, or two Mercurial rows decide one setting differently at equal specificity [ledger #boundary]
const _: () = assert!(hg_rows_sound());

/// The parsed Git rows.
static GIT_ROWS: [Parsed; GIT.len()] = parse_table::<{ GIT.len() }>(GIT, Shape::Git).rows;
/// The parsed Mercurial rows.
static HG_ROWS: [Parsed; HG.len()] = parse_table::<{ HG.len() }>(HG, Shape::Hg).rows;

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
        KeyPat::Named(_) => 4,
        KeyPat::Prefixed(_) | KeyPat::Suffixed(_) => 3,
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
        KeyPat::Prefixed(prefix) => key.len() > prefix.len() && starts_with(key, prefix, false),
        KeyPat::Suffixed(suffix) => key.len() > suffix.len() && ends_with(key, suffix),
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
        // A prefix with a suffix or a sub-option counts as overlapping: such rows must agree or be ranked apart.
        (KeyPat::Any, _)
        | (_, KeyPat::Any)
        | (KeyPat::Unsuffixed, KeyPat::Unsuffixed)
        | (KeyPat::Prefixed(_), KeyPat::Suffixed(_) | KeyPat::Suboption(_))
        | (KeyPat::Suffixed(_), KeyPat::Prefixed(_) | KeyPat::Suboption(_))
        | (KeyPat::Suboption(_), KeyPat::Prefixed(_) | KeyPat::Suffixed(_)) => true,
        (KeyPat::Named(x), KeyPat::Named(y)) => bytes_eq(x, y, folds(shape)),
        (KeyPat::Named(name), other) | (other, KeyPat::Named(name)) => key_fits(other, name, shape),
        (KeyPat::Suboption(x), KeyPat::Suboption(y)) => bytes_eq(x, y, false),
        (KeyPat::Unsuffixed, KeyPat::Suboption(_)) | (KeyPat::Suboption(_), KeyPat::Unsuffixed) => {
            false
        }
        (KeyPat::Prefixed(x), KeyPat::Prefixed(y)) => {
            starts_with(x, y, false) || starts_with(y, x, false)
        }
        (KeyPat::Suffixed(x), KeyPat::Suffixed(y)) => ends_with(x, y) || ends_with(y, x),
        (KeyPat::Prefixed(affix) | KeyPat::Suffixed(affix), KeyPat::Unsuffixed)
        | (KeyPat::Unsuffixed, KeyPat::Prefixed(affix) | KeyPat::Suffixed(affix)) => {
            find(affix, b':', false).is_none()
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
        return if is_plain(option, true) && find(option, b':', false).is_none() {
            Some(KeyPat::Suboption(option))
        } else {
            None
        };
    }
    if matches!(shape, Shape::Hg)
        && let Some(at) = find(key, b'<', false)
    {
        return affix_pattern(key, at);
    }
    if is_plain(key, key_dots(shape)) {
        Some(KeyPat::Named(key))
    } else {
        None
    }
}

/// The Mercurial key pattern `key` names, its placeholder starting at `at`.
///
/// A prefix ending in `.` or `-` before the placeholder spells a prefixed
/// key; a suffix starting with `.` after it spells a suffixed key.
const fn affix_pattern(key: &'static [u8], at: usize) -> Option<KeyPat> {
    let Some((before, from)) = key.split_at_checked(at) else {
        return None;
    };
    let Some(close) = find(from, b'>', false) else {
        return None;
    };
    let Some((placeholder, after)) = from.split_at_checked(close.saturating_add(1)) else {
        return None;
    };
    if !is_placeholder(placeholder) {
        return None;
    }
    match (before.split_last(), after.split_first()) {
        (Some((&(b'.' | b'-'), stem)), None) if is_plain(stem, true) => {
            Some(KeyPat::Prefixed(before))
        }
        (None, Some((&b'.', stem))) if is_plain(stem, true) => Some(KeyPat::Suffixed(after)),
        _ => None,
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

/// Whether `text` ends with `suffix`, comparing bytes exactly.
const fn ends_with(text: &[u8], suffix: &[u8]) -> bool {
    let Some(at) = text.len().checked_sub(suffix.len()) else {
        return false;
    };
    match text.split_at_checked(at) {
        Some((_, tail)) => bytes_eq(tail, suffix, false),
        None => false,
    }
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
        // `p.x.y.k` has both prefixes, `p.x.b.a` both suffixes, `p.x.<n>.a` a prefix and a suffix.
        assert!(!decided(
            &[("p.x.<n>", EXEC), ("p.x.y.<n>", EXEMPT)],
            Shape::Hg
        ));
        assert!(!decided(
            &[("p.<n>.a", EXEC), ("p.<n>.b.a", EXEMPT)],
            Shape::Hg
        ));
        assert!(!decided(
            &[("p.<n>.a", EXEC), ("p.x.<n>", EXEMPT)],
            Shape::Hg
        ));
        // Controls: no key has both affixes, or one row is more specific.
        assert!(decided(
            &[("p.x.<n>", EXEC), ("p.xy.<n>", EXEMPT)],
            Shape::Hg
        ));
        assert!(decided(
            &[("p.<n>.a", EXEC), ("p.<n>.ba", EXEMPT)],
            Shape::Hg
        ));
        assert!(decided(&[("p.<n>", EXEMPT), ("p.x.<n>", EXEC)], Shape::Hg));
        assert!(decided(&[("p.<n>.a", EXEC), ("p.k.a", EXEMPT)], Shape::Hg));
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
        for spelling in [
            "a.*:",
            "a.*:x:y",
            "a.<n",
            "a.x<n>",
            "a.<n>x",
            "a.x.<n>.y",
            "a.<n>.",
            "a..<n>",
            "a.x.<>",
            "a.x.<n>.<m>",
        ] {
            assert!(!decided(&[(spelling, EXEC)], Shape::Hg), "{spelling}");
        }
        // Controls.
        assert!(decided(&[("a.b", EXEC), ("a.z", EXEC)], Shape::Git));
        assert!(decided(&[("a.p.<n>.k", EXEC)], Shape::Git));
        assert!(decided(&[("a.b.c", EXEC)], Shape::Hg));
        for spelling in ["a.x.<n>", "a.x-<n>", "a.<n>.y.z", "a.*:y.z"] {
            assert!(decided(&[(spelling, EXEC)], Shape::Hg), "{spelling}");
        }
    }

    /// The spellings the Git snapshot lists, without its header line.
    fn snapshot() -> Vec<&'static str> {
        listed(include_str!("../data/git-config-keys.txt"))
    }

    /// The spellings the Mercurial snapshot lists, without its header line.
    fn hg_snapshot() -> Vec<&'static str> {
        listed(include_str!("../data/hg-config-keys.txt"))
    }

    /// The spellings a snapshot's `text` lists, without its header line.
    fn listed(text: &'static str) -> Vec<&'static str> {
        text.lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .collect()
    }

    #[test]
    fn every_documented_git_key_has_one_row() {
        let documented = snapshot();
        let undocumented: Vec<&str> = GIT_UNDOCUMENTED.iter().map(|(name, _)| *name).collect();
        let rowed: Vec<&str> = GIT
            .iter()
            .map(|(spelling, _)| *spelling)
            .filter(|spelling| !undocumented.contains(spelling))
            .collect();
        let unrowed: Vec<&&str> = documented
            .iter()
            .filter(|key| !rowed.contains(key))
            .collect();
        let undecided: Vec<&&str> = rowed
            .iter()
            .filter(|row| !documented.contains(row))
            .collect();
        assert!(unrowed.is_empty(), "documented without a row: {unrowed:?}");
        assert!(
            undecided.is_empty(),
            "rowed without a source: {undecided:?}"
        );
        assert!(documented.len() > 800, "{}", documented.len());
    }

    #[test]
    fn no_row_without_a_source() {
        let documented = snapshot();
        for (name, source) in GIT_UNDOCUMENTED {
            assert!(!source.is_empty(), "{name}");
            assert!(!documented.contains(name), "{name} is documented");
            assert!(
                GIT.iter().any(|(spelling, _)| spelling == name),
                "{name} has no row"
            );
        }
        // A setting no row decides is left to the caller to judge under every reading.
        assert_eq!(git("frob", None, "cmd"), None);
        assert_eq!(git("core", None, "frobnicate"), None);
        assert_eq!(git("http", Some("https://h"), "frobnicate"), None);
    }

    #[test]
    fn every_documented_hg_key_has_one_row_or_a_reason() {
        let documented = hg_snapshot();
        let undocumented: Vec<&str> = HG_UNDOCUMENTED.iter().map(|(name, _)| *name).collect();
        let undecided: Vec<&str> = HG_UNDECIDED.iter().map(|(name, _)| *name).collect();
        let rowed: Vec<&str> = HG
            .iter()
            .map(|(spelling, _)| *spelling)
            .filter(|spelling| !undocumented.contains(spelling))
            .collect();
        let unrowed: Vec<&&str> = documented
            .iter()
            .filter(|key| !rowed.contains(key) && !undecided.contains(key))
            .collect();
        let unsourced: Vec<&&str> = rowed
            .iter()
            .filter(|row| !documented.contains(row))
            .collect();
        let both: Vec<&&str> = undecided.iter().filter(|key| rowed.contains(key)).collect();
        assert!(unrowed.is_empty(), "documented without a row: {unrowed:?}");
        assert!(
            unsourced.is_empty(),
            "rowed without a source: {unsourced:?}"
        );
        assert!(both.is_empty(), "undecided yet rowed: {both:?}");
        assert!(documented.len() > 800, "{}", documented.len());
    }

    #[test]
    fn undecided_hg_settings_stay_unknown() {
        let documented = hg_snapshot();
        for (name, why) in HG_UNDECIDED {
            assert!(!why.is_empty(), "{name}");
            assert!(documented.contains(name), "{name} is not documented");
        }
        for (name, source) in HG_UNDOCUMENTED {
            assert!(!source.is_empty(), "{name}");
            assert!(!documented.contains(name), "{name} is documented");
            assert!(
                HG.iter().any(|(spelling, _)| spelling == name),
                "{name} has no row"
            );
        }
        // A setting no row decides is left to the caller to judge as unknown.
        assert_eq!(hg("frob", "x"), None);
        assert_eq!(hg("ui", "frobnicate"), None);
        assert_eq!(hg("acl.allow", "alice"), None);
        assert_eq!(hg("defaults", "pull"), None);
        assert_eq!(hg("ui", "debugger"), None);
        assert_eq!(hg("fix", "extra-bin-paths"), None);
        assert_eq!(hg("merge-tools", "kdiff3.regkey"), None);
        assert_eq!(hg("hooks", "commit:frob"), None);
        assert_eq!(hg("pager", "attend-"), None);
    }

    #[test]
    fn scoped_key_takes_the_unscoped_row() {
        assert_eq!(
            git("sendemail", Some("work"), "tocmd"),
            Some(Consume::Shell)
        );
        assert_eq!(
            git("credential", Some("https://h"), "helper"),
            Some(Consume::Composed(Compose::CredentialHelper))
        );
        assert_eq!(
            git("credential", Some("https://h"), "username"),
            Some(Consume::Inert)
        );
        assert_eq!(git("merge", None, "TOOL"), Some(Consume::ToolName));
        assert_eq!(
            git("lfs", Some("customtransfer.x"), "path"),
            Some(Consume::Exec)
        );
        assert_eq!(
            git("gitflow", Some("path"), "hooks"),
            Some(Consume::Load(Load::HooksPath))
        );
        assert_eq!(
            git("gitflow", Some("prefix"), "feature"),
            Some(Consume::Inert)
        );
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
        assert_eq!(hg("paths", "default:bookmarks.mode"), Some(Consume::Inert));
        assert_eq!(hg("merge-tools", "kdiff3.args"), Some(Consume::Shell));
        assert_eq!(
            hg("merge-tools", "kdiff3.executable"),
            Some(Consume::Load(Load::Forced))
        );
        assert_eq!(hg("merge-tools", "kdiff3.priority"), Some(Consume::Inert));
        assert_eq!(hg("extdiff", "opts.vd"), Some(Consume::Shell));
        assert_eq!(hg("extdiff", "gui.vd"), Some(Consume::Inert));
        assert_eq!(hg("extdiff", "cmd.vd"), Some(Consume::Load(Load::Forced)));
        assert_eq!(hg("extdiff", "vd"), Some(Consume::Shell));
        assert_eq!(hg("hooks", "commit"), Some(Consume::PythonHook));
        assert_eq!(hg("hooks", "priority.commit"), Some(Consume::Inert));
        assert_eq!(hg("hooks", "commit:run-with-plain"), Some(Consume::Inert));
        assert_eq!(hg("alias", "st"), Some(Consume::Bang));
        assert_eq!(hg("alias", "st:doc"), Some(Consume::Inert));
        assert_eq!(
            hg("extensions", "rebase"),
            Some(Consume::Load(Load::ForcedUnbanged))
        );
        assert_eq!(hg("extensions", "rebase:required"), Some(Consume::Inert));
        assert_eq!(hg("pager", "attend-log"), Some(Consume::Inert));
        assert_eq!(hg("fix", "black:command"), Some(Consume::Shell));
        assert_eq!(hg("ui", "mergemarkers"), Some(Consume::Inert));
        assert_eq!(hg("UI", "username"), None);
        assert!(jj_exempt("templates"));
        assert!(!jj_exempt("ui"));
    }
}
