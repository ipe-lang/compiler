#!/usr/bin/env python3
"""Quote-removing POSIX shell lexer for the CI verifiers' `run:` checks.

`split_commands` turns shell text into simple commands: each a list of words
with quotes and backslashes removed exactly as the shell removes them, plus
the targets of its output redirections. A check that asks "which file does
this command write" then matches on the word the shell will see
(`".github/"ci/x` is `.github/ci/x`), never on the spelling in the source.

Words split on `BLANKS` (space and tab, bash's own blank set). Command
separators are `;`, `&`, `|`, `(`, `)`, newline, `$(`, and a
backtick; a command substitution inside double quotes or a here-document
body is lexed again from its own start, so a command nested there is seen as
a command (a backtick in a comment or in single quotes starts none). A
`#` at word start is a comment. A here-document body is data to its command
and is skipped; a command fed one carries `heredoc`, a command fed a
here-string (`<<<`) carries `herestring`, and a command on the right of a
pipe (`|` or `|&`, never `||`) carries in `pipe_source` the words of the
command feeding it. Each command carries in `subshell` the subshells open
around it (`(`, `$(`, a backtick), outermost first, each a number unique to
its lexing, so a `cd` inside one is seen not to reach a command outside it.
Unterminated quotes run to the end of the text — the lexer never raises, it
only ever sees more text as one word.

`literal_words` parses words into `LiteralWord`s: words the shell passes on
exactly as written, so a check on their spelling is a check on the argv.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class Command:
    """One simple command: quote-removed words, output-redirect targets, and
    what feeds its standard input when that is shell-visible."""

    words: list[str] = field(default_factory=list)
    writes: list[str] = field(default_factory=list)
    heredoc: bool = False
    herestring: bool = False
    pipe_source: list[str] | None = None
    subshell: tuple[int, ...] = ()


# The characters bash's parser splits words on (`blank` in bash(1)): space and
# tab only. A newline ends the command instead; every other character, `\r`,
# `\v`, `\f`, and non-ASCII spaces included, is part of the word. This is the
# one blank set: the lexer and every word-shape check built on it use it.
BLANKS = frozenset(" \t")
_SEPARATORS = frozenset(";&|()\n`")


def _substitutions(text: str, lo: int, hi: int, subs: list[int] | None) -> None:
    """Record in `subs` the start of every command substitution in
    `text[lo:hi]` (a double-quoted span or a here-document body, where
    quotes do not delimit it)."""
    if subs is None:
        return
    opening = True
    for j in range(lo, hi):
        if text[j] == "`":
            # Backticks pair up: only an opening one starts a substitution.
            if opening:
                subs.append(j + 1)
            opening = not opening
        elif text.startswith("$(", j):
            subs.append(j + 2)


# How deep `"$(".."$(".."$(` may nest inside double quotes before the rest of
# the text is read as one word.
SUBSTITUTION_NESTING_LIMIT = 32


def _substitution_end(text: str, i: int, nesting: int = 0) -> int:
    """The index just past the `)` closing the command substitution whose
    body starts at `text[i]`, or `len(text)` when it never closes or nests
    past `SUBSTITUTION_NESTING_LIMIT`. Inside the body quotes delimit again
    (`"$(sed 's/"//')"` is one word), so a quote there neither ends nor opens
    the enclosing double-quoted span."""
    depth, n = 1, len(text)
    if nesting >= SUBSTITUTION_NESTING_LIMIT:
        return n
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
        elif c == "'":
            j = text.find("'", i + 1)
            i = n if j < 0 else j + 1
        elif c == '"':
            i += 1
            while i < n and text[i] != '"':
                if text[i] == "\\":
                    i += 2
                elif text.startswith("$(", i):
                    i = _substitution_end(text, i + 2, nesting + 1)
                else:
                    i += 1
            i += 1
        elif text.startswith("$(", i):
            depth += 1
            i += 2
        elif c == "(":
            depth += 1
            i += 1
        elif c == ")":
            depth -= 1
            i += 1
            if depth == 0:
                return i
        else:
            i += 1
    return n


def _lex(
    text: str, bodies: list[tuple[int, int]] | None = None, subs: list[int] | None = None,
    closer: str | None = None,
) -> list[Command]:
    """The commands of `text`; with `closer` (`)` or a backtick), `text` is
    the inside of a substitution and lexing stops at its unmatched closer."""
    cmds: list[Command] = []
    cur = Command()
    buf: list[str] | None = None
    pending: str | None = None  # "write" | "read" | "herestring" | "heredoc"
    heredocs: list[tuple[str, bool]] = []
    scope: list[int] = []
    opened = 0
    in_backtick = False
    i, n = 0, len(text)

    def open_subshell() -> None:
        nonlocal opened
        opened += 1
        scope.append(opened)

    def close_subshell() -> None:
        if scope:
            scope.pop()

    def end_word() -> None:
        nonlocal buf, pending
        if buf is None:
            return
        word = "".join(buf)
        buf = None
        if pending == "write":
            cur.writes.append(word)
        elif pending == "heredoc":
            heredocs.append((word, pending_strip))
            cur.heredoc = True
        elif pending == "herestring":
            cur.herestring = True
        elif pending is None:
            cur.words.append(word)
        pending = None

    def end_command(piped: bool = False) -> None:
        nonlocal cur
        end_word()
        # An empty command (`a |` then a newline) hands its pipe source on.
        carry = cur.pipe_source
        if cur.words or cur.writes or cur.heredoc or cur.herestring:
            cur.subshell = tuple(scope)
            cmds.append(cur)
            carry = None
        if piped:
            carry = list(cmds[-1].words) if cmds else []
        cur = Command()
        cur.pipe_source = carry

    pending_strip = False
    while i < n:
        c = text[i]
        if c == "\n":
            end_command()
            i += 1
            while heredocs:
                delim, strip = heredocs.pop(0)
                body_start = i
                while i < n:
                    j = text.find("\n", i)
                    line = text[i : n if j < 0 else j]
                    i = n if j < 0 else j + 1
                    if (line.lstrip("\t") if strip else line) == delim:
                        break
                if bodies is not None:
                    bodies.append((body_start, i))
                _substitutions(text, body_start, i, subs)
            continue
        if c in BLANKS:
            end_word()
            i += 1
            continue
        if c == "$" and text.startswith("$(", i):
            end_command()
            open_subshell()
            i += 2
            continue
        if c == "|":
            if text.startswith("||", i):
                end_command()
                cur.pipe_source = None
                i += 2
            else:
                end_command(piped=True)
                i += 2 if text.startswith("|&", i) else 1
            continue
        if c in _SEPARATORS:
            end_command()
            cur.pipe_source = None
            if c == "(":
                open_subshell()
            elif c == ")":
                if not scope and closer == ")":
                    return cmds
                close_subshell()
            elif c == "`":
                if closer == "`" and not in_backtick:
                    return cmds
                if in_backtick:
                    close_subshell()
                else:
                    open_subshell()
                in_backtick = not in_backtick
            i += 1
            continue
        if c in "<>":
            fd = buf is not None and "".join(buf).isdigit()
            if fd:
                buf = None
            else:
                end_word()
            if text.startswith("<<<", i):
                pending, i = "herestring", i + 3
            elif text.startswith("<<", i):
                i += 2
                pending_strip = text.startswith("-", i)
                if pending_strip:
                    i += 1
                pending = "heredoc"
            elif c == "<" and text.startswith("<>", i):
                pending, i = "write", i + 2
            elif c == "<":
                pending, i = "read", i + 1
            else:
                i += 2 if text.startswith((">>", ">|", ">&"), i) else 1
                pending = "write"
            continue
        if c == "#" and buf is None:
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if text.startswith("\\\n", i):
            # A line continuation joins lines; it starts no word.
            i += 2
            continue
        if buf is None:
            buf = []
        if c == "\\":
            if i + 1 < n:
                buf.append(text[i + 1])
            i += 2
            continue
        if c == "'":
            j = text.find("'", i + 1)
            j = n if j < 0 else j
            buf.append(text[i + 1 : j])
            i = j + 1
            continue
        if c == '"':
            i += 1
            quote_start = i
            while i < n and text[i] != '"':
                if text[i] == "\\" and i + 1 < n and text[i + 1] in '"\\$`\n':
                    if text[i + 1] != "\n":
                        buf.append(text[i + 1])
                    i += 2
                    continue
                if text.startswith("$(", i):
                    end = min(_substitution_end(text, i + 2), n)
                    buf.append(text[i:end])
                    i = end
                    continue
                buf.append(text[i])
                i += 1
            _substitutions(text, quote_start, i, subs)
            i += 1
            continue
        buf.append(c)
        i += 1
    end_command()
    return cmds


# The characters of a `LiteralWord`. None of them starts an expansion (`$`, a
# backtick), a glob (`*`, `?`, `[`), a brace or tilde expansion (`{`, `~`),
# quoting (a quote, a backslash), a separator, a redirection or a comment.
LITERAL_WORD_CHARS = "A-Za-z0-9_.,=/:+@-"
_LITERAL_WORD = re.compile(f"[{LITERAL_WORD_CHARS}]+")


@dataclass(frozen=True)
class LiteralWord:
    """A word bash passes to its command unchanged: one argument, spelled as
    in the source, with no expansion, word splitting, glob or quote removal
    between the source and the argv. Built only by `literal_words`."""

    text: str


def literal_words(words: list[str]) -> tuple[LiteralWord, ...] | str:
    """`words` as `LiteralWord`s, else the first word that is none."""
    out: list[LiteralWord] = []
    for word in words:
        if _LITERAL_WORD.fullmatch(word) is None:
            return word
        out.append(LiteralWord(word))
    return tuple(out)


def trim(text: str) -> str:
    """`text` without the blanks and newlines bash ignores around a command.

    Only `BLANKS` and newline are trimmed: any other leading or trailing
    character (`\\r`, `\\v`, a non-ASCII space) is part of a word to bash.
    """
    return text.strip("".join(sorted(BLANKS)) + "\n")


def split_commands(text: str) -> list[Command]:
    """Every simple command in `text`, command substitutions included: the
    text is lexed from its start and again from the start of every
    substitution the lexer finds inside double quotes or a here-document
    body (each offset once, so at most `len(text) + 1` passes). A command
    of such a substitution sits in a subshell numbered `-offset`, outside
    every subshell its own lexing opens; its lexing ends at the substitution's
    own closer, so the text after it is never read from inside the quotes."""
    out: list[Command] = []
    todo, seen = [0], {0}
    while todo:
        start = todo.pop()
        found: list[int] = []
        closer = None if not start else ("`" if text[start - 1] == "`" else ")")
        for cmd in _lex(text[start:], None, found, closer):
            if start:
                cmd.subshell = (-start, *cmd.subshell)
            out.append(cmd)
        for off in found:
            if start + off not in seen:
                seen.add(start + off)
                todo.append(start + off)
    return out


def heredoc_bodies(text: str) -> list[str]:
    """Every here-document body in `text`, in order."""
    bodies: list[tuple[int, int]] = []
    _lex(text, bodies)
    return [text[lo:hi] for lo, hi in bodies]


def without_heredoc_bodies(text: str) -> str:
    """`text` with every here-document body (data, not shell) removed."""
    bodies: list[tuple[int, int]] = []
    _lex(text, bodies)
    out, at = [], 0
    for lo, hi in bodies:
        out.append(text[at:lo])
        at = hi
    out.append(text[at:])
    return "".join(out)
