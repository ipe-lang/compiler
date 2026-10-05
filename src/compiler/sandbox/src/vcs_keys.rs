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

    /// The spellings the Git snapshot lists, without its header line.
    fn snapshot() -> Vec<&'static str> {
        include_str!("../data/git-config-keys.txt")
            .lines()
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
        assert_eq!(hg("paths", "default:bookmarks.mode"), None);
        assert_eq!(hg("UI", "username"), None);
        assert!(jj_exempt("templates"));
        assert!(!jj_exempt("ui"));
    }
}
