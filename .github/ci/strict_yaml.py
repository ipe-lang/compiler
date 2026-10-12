#!/usr/bin/env python3
"""Shared strict YAML loader: exactly the document GitHub Actions runs, and
nothing looser.

A YAML document with a duplicate mapping key, a `<<` merge key, or an anchor/
alias has no single canonical parse under `yaml.safe_load`: a duplicate key
silently keeps the last occurrence and drops every earlier one, a merge key
splices in a payload that never appears at the parsed key's own location, and
an alias resolves to whatever its anchor happened to capture; an explicit tag
(`!!null`, `!!binary`, `!!omap`) swaps the scalar text for whatever PyYAML's
tag table constructs. A CI verifier
loading a workflow that way can certify a value GitHub never runs — the first,
discarded copy of a duplicate `run:`/`env:` key. `StrictSafeLoader` makes each
of those shapes unrepresentable instead of silently resolved, so the parsed
value and the value GitHub executes are the same document by construction.

LIMIT: this loader guards YAML's structural ambiguities only. A workflow
expression (`${{ ... }}`) built by string assembly — `format(`, `join(`,
`toJSON(`, or `fromJSON(` over a literal, in any letter case — inside a `run:`/`env:` value is syntactically unambiguous YAML
that still hides its assembled target (e.g. an env-var name built as
`format('RUSTC_{0}', 'WRAPPER')`) from a literal-text scan for that name.
`refuse_expression_assembly` below is the separate, blanket check for that
class; every verifier that scans `run:`/`env:` text for a sensitive name must
also run it, not rely on this loader alone.
"""

from __future__ import annotations

import re

import yaml

import gha_expr

# GitHub Actions expression functions that assemble a string at run time
# rather than naming one literally: `format`/`join`/`toJSON` build text out of
# pieces, and `fromJSON` over a string literal decodes JSON `\uXXXX` escapes
# that spell a name no literal scan matches (`fromJSON('"RUSTC\u005fWRAPPER"')`).
# `fromJSON` in an expression that holds ANY string literal is refused (the
# literal may reach it through parentheses or `&&`/`||`); `fromJSON` over
# context values only (`fromJSON(needs.x.outputs.y)`) decodes run-time data,
# not author-assembled text, and is not this class.
# Refused wherever they appear inside a `${{ ... }}` expression in a `run:` or
# `env:` value: any such value can assemble a sensitive target name (an
# env-var key, `$GITHUB_ENV`, `$GITHUB_PATH`, an `RUSTC*` wrapper var) out of
# pieces no single literal scan will ever match. Refused unconditionally
# rather than only when a sensitive name is *also* literally present — a
# scoped check is exactly the gap this closes, since the whole point of
# assembly is to keep the sensitive name out of the literal text. Matched
# case-insensitively: the Actions evaluator resolves function names ignoring
# case (`FORMAT(` runs `format(`). Bodies are parsed by `gha_expr`, so a call
# name inside a string literal is data and a body outside the grammar is
# refused.
_ASSEMBLY_CALLS = frozenset({"format", "join", "tojson"})
_FROMJSON = "fromjson"


# The plain scalar spellings YAML 1.2's core schema (GitHub Actions' reading)
# and PyYAML's YAML 1.1 resolver read alike. A plain value outside them is
# refused: `yes`/`on`/`off` are booleans to PyYAML and strings to GitHub;
# `0x2`, `0o7`, `010`, `1_000` and `1:30` are numbers to one reader and text
# or another number to the other; `2026-01-01` is a date to PyYAML only; `1e3`
# is text to PyYAML and a float to YAML 1.2. Either way the parsed value is
# not the value GitHub runs, so a compare or a scan on it certifies nothing.
_CORE_BOOL = frozenset({"true", "True", "TRUE", "false", "False", "FALSE"})
_CORE_NULL = frozenset({"", "~", "null", "Null", "NULL"})
_CORE_INT = re.compile(r"[-+]?(?:0|[1-9][0-9]*)")
_CORE_FLOAT = re.compile(r"[-+]?(?:\.[0-9]+|[0-9]+\.[0-9]*)(?:[eE][-+]?[0-9]+)?|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)")
# Spellings YAML 1.2 reads as a number but PyYAML leaves as text.
_CORE_ONLY_NUMBER = re.compile(r"0o[0-7]+|0x[0-9a-fA-F]+|[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)[eE][-+]?[0-9]+")
_YAML_TAG = "tag:yaml.org,2002:"


def _version_split_refusal(node: yaml.ScalarNode) -> str | None:
    """Why the plain value `node` reads differently under YAML 1.1 and 1.2,
    or None."""
    if node.style is not None:
        return None
    text, tag = node.value, node.tag
    kind = tag[len(_YAML_TAG) :] if tag.startswith(_YAML_TAG) else tag
    agreed = (
        (kind == "bool" and text in _CORE_BOOL)
        or (kind == "null" and text in _CORE_NULL)
        or (kind == "int" and _CORE_INT.fullmatch(text) is not None)
        or (kind == "float" and _CORE_FLOAT.fullmatch(text) is not None)
        or (kind == "str" and _CORE_ONLY_NUMBER.fullmatch(text) is None)
    )
    return None if agreed else f"plain value {text!r} reads as {kind} under YAML 1.1 but not alike under YAML 1.2"


class StrictYAMLError(yaml.YAMLError):
    """A structurally ambiguous YAML document: duplicate key, merge key,
    anchor/alias, explicit tag, or nesting past the recursion limit. Subclasses `yaml.YAMLError` so an existing
    `except yaml.YAMLError` callsite catches it with no per-site change."""


class StrictSafeLoader(yaml.SafeLoader):
    """`yaml.SafeLoader` with every structurally ambiguous construct refused
    instead of resolved."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()
            raise StrictYAMLError(
                f"alias {event.anchor!r} at line {event.start_mark.line + 1}: "
                "aliases are refused; write the value out in full"
            )
        event = self.peek_event()
        if event.anchor is not None:
            raise StrictYAMLError(
                f"anchor {event.anchor!r} at line {event.start_mark.line + 1}: "
                "anchors are refused; write the value out in full"
            )
        tag = getattr(event, "tag", None)
        if tag is not None:
            # An explicit tag (`!!null`, `!!binary`, `!!omap`, `!foo`, even
            # `!!str`) makes the constructed value depend on PyYAML's tag
            # table: `X: !!null "text"` loads as `None` and hides its text
            # from every scan, `!!omap`/`!!pairs` carry duplicate keys as a
            # list. GitHub Actions workflows never need one, so none is
            # accepted — the scanned value is always the plain scalar text.
            raise StrictYAMLError(
                f"explicit tag {tag!r} at line {event.start_mark.line + 1}: "
                "tags are refused; write the plain value"
            )
        node = super().compose_node(parent, index)
        # A mapping key is composed with `index` None; every other scalar is
        # a value. Keys keep PyYAML's reading (`on:` is the trigger key).
        is_key = isinstance(parent, yaml.MappingNode) and index is None
        if isinstance(node, yaml.ScalarNode) and not is_key:
            why = _version_split_refusal(node)
            if why is not None:
                raise StrictYAMLError(
                    f"{why} at line {node.start_mark.line + 1}: quote it, or spell it as YAML 1.2 does"
                )
        return node

    def flatten_mapping(self, node):
        for key_node, _value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise StrictYAMLError(
                    f"merge key '<<' at line {key_node.start_mark.line + 1}: "
                    "merge keys are refused; write the mapping out in full"
                )
        super().flatten_mapping(node)

    def construct_mapping(self, node, deep=False):
        if isinstance(node, yaml.MappingNode):
            self.flatten_mapping(node)
        mapping: dict = {}
        # Source spellings seen so far: `1` and `'1'` (or `on` and `'on'`)
        # construct distinct Python keys but are one key to a YAML 1.2
        # reader, so a repeated spelling is a duplicate too.
        spellings: set[str] = set()
        for key_node, value_node in node.value:
            if isinstance(key_node, yaml.ScalarNode):
                if key_node.value in spellings:
                    raise StrictYAMLError(
                        f"duplicate key {key_node.value!r} at line "
                        f"{key_node.start_mark.line + 1}: the first occurrence "
                        "already set this key"
                    )
                spellings.add(key_node.value)
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as e:
                raise StrictYAMLError(
                    f"unhashable key at line {key_node.start_mark.line + 1}: {e}"
                ) from e
            if duplicate:
                raise StrictYAMLError(
                    f"duplicate key {key!r} at line {key_node.start_mark.line + 1}: "
                    "the first occurrence already set this key"
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def safe_load(stream):
    """Strict drop-in for `yaml.safe_load`: same success shape and the same
    `yaml.YAMLError` on malformed YAML, but additionally refuses duplicate
    keys (by value and by source spelling), merge keys, anchors/aliases,
    explicit tags, and over-deep nesting instead of silently resolving
    them."""
    try:
        return yaml.load(stream, Loader=StrictSafeLoader)
    except RecursionError as e:
        # PyYAML composes and constructs recursively: nesting past the
        # interpreter's recursion limit is a typed refusal, not a traceback.
        raise StrictYAMLError(f"document nested too deeply to load: {e}") from e


def refuse_expression_assembly(text: str | None, loc: str) -> str | None:
    """`None` if `text` is absent or its `${{ }}` expressions parse and hold
    no expression-assembly call; otherwise an error message naming `loc`.

    Expressions are read by `gha_expr`, so a call name inside a string
    literal is data, and an expression outside the grammar is refused."""
    if text is None:
        return None
    parsed = gha_expr.parse_template(text)
    if isinstance(parsed, gha_expr.Refusal):
        return (
            f"{loc}: a `${{{{ }}}}` expression is outside the expression grammar ({parsed.why}) "
            "— what it assembles cannot be established; refused"
        )
    for e in parsed.exprs:
        nodes = list(gha_expr.walk(e))
        has_literal = any(isinstance(n, gha_expr.Literal) and n.is_string for n in nodes)
        for n in nodes:
            if not isinstance(n, gha_expr.Call):
                continue
            name = n.name.casefold()
            if name in _ASSEMBLY_CALLS or (name == _FROMJSON and has_literal):
                return (
                    f"{loc}: expression-assembly call {n.name}(...) "
                    "in a run:/env:/with:/shell: value — a value built from string-assembly "
                    "functions (format/join/toJSON, fromJSON over a literal) can hide a target name "
                    "from any literal-text scan; write the value as a literal instead"
                )
    return None
