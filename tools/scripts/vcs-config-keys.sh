#!/bin/sh
# Print the configuration-key snapshot one version-control tool documents.
#
# Usage: tools/scripts/vcs-config-keys.sh git <git-source-checkout> > src/compiler/sandbox/data/git-config-keys.txt
#        tools/scripts/vcs-config-keys.sh hg <mercurial-source-release> > src/compiler/sandbox/data/hg-config-keys.txt
#
# Git: the keys Git's own `generate-configlist.sh` rule extracts from the
# checkout's `Documentation/*config.txt` and `Documentation/config/*.txt`,
# unioned with the keys `git help --config` of the `git` on PATH lists, which
# must be the checkout's tagged release. The first line names both sources; the rest is
# one spelling per line, byte-sorted. The `vcs_keys` coverage test compares the
# snapshot with the key table, so a refreshed snapshot lists every key the
# table has yet to decide.
#
# Mercurial: the items `mercurial/configitems.toml` declares, its templates
# expanded per application, unioned with the `configitem(...)` calls of
# `hgext/*.py` whose section and name are literals, from an unpacked source
# release (its `PKG-INFO` names the version). The release's code is read as
# text, never run. A generic item's regular expression is spelled as the key
# table spells patterns (`.*` as `*`, `[^:]*` as `<name>`, `.*\.args$` as
# `<name>.args`, `.*:pushurl` as `*:pushurl`, `opts\..*` as `opts.<name>`);
# an expression no rule spells stops the script.
set -eu

usage() {
	echo "usage: $0 git <git-source-checkout> | hg <mercurial-source-release>" >&2
	exit 2
}

hg_keys() {
	version=$(sed -n 's/^Version: //p' "$1/PKG-INFO")
	[ -n "$version" ] || {
		echo "$0: $1/PKG-INFO names no version" >&2
		exit 1
	}
	echo "# Mercurial $version: mercurial/configitems.toml items and hgext configitem() calls."
	python3 - "$1" <<'PY'
import pathlib, re, sys

root = pathlib.Path(sys.argv[1])
fields = re.compile(r"""^(section|name|suffix|template|prefix|generic)\s*=\s*('[^']*'|"(?:[^"\\]|\\.)*"|\w+)\s*(?:#.*)?$""", re.M)


def unquote(text):
    if len(text) < 2 or text[0] not in "'\"" or text[-1] != text[0]:
        sys.exit(f"unquoted TOML string: {text}")
    if text[0] == "'":
        return text[1:-1]
    if re.search(r"\\[^\\]", text):
        sys.exit(f"an unmodelled TOML escape: {text}")
    return text[1:-1].replace("\\\\", "\\")


toml = (root / "mercurial/configitems.toml").read_text()
parts = re.split(r"^\[\[([a-z.-]+)\]\]\s*$|^\[[a-z.-]+\]\s*$", toml, flags=re.M)
items, templates, applications = [], {}, []
for kind, body in zip(parts[1::2], parts[2::2]):
    got = {key: value for key, value in fields.findall(body or "")}
    if kind == "items":
        items.append((unquote(got["section"]), unquote(got["name"]), got.get("generic") == "true"))
    elif kind is not None and kind.startswith("templates."):
        templates.setdefault(kind[len("templates."):], []).append(unquote(got["suffix"]))
    elif kind == "template-applications":
        prefix = unquote(got["prefix"]) + "." if "prefix" in got else ""
        applications.append((unquote(got["template"]), unquote(got["section"]), prefix))
for template, section, prefix in applications:
    items.extend((section, prefix + suffix, False) for suffix in templates[template])

literal = r"[rb]{0,2}(['\"])((?:(?!\Q).)*)\Q"
call = re.compile(r"configitem\(\s*" + literal.replace("Q", "1") + r"\s*,\s*" + literal.replace("Q", "3") + r"((?:[^()]|\([^()]*\))*)\)", re.S)
fixer = re.compile(r"^FIXER_ATTRS = \{(.*?)^\}", re.S | re.M)
for path in sorted((root / "hgext").rglob("*.py")):
    text = path.read_text()
    for match in call.finditer(text):
        section, name, rest = match.group(2), match.group(4), match.group(5)
        generic = "generic=True" in rest.replace(" ", "")
        if name.endswith("%s$"):
            attrs = fixer.search(text)
            if attrs is None or not rest.lstrip().startswith("% key"):
                sys.exit(f"{path}: an unexpanded configitem name: {name}")
            for attr in re.findall(r"^\s*b'([a-z-]+)':", attrs.group(1), re.M):
                items.append((section, name.replace("%s", attr), generic))
        else:
            items.append((section, name, generic))

word = r"[a-z][a-z0-9_.-]*[a-z0-9]"
rules = [
    (r"\.\*", lambda m: "*"),
    (r"\[\^:\]\*", lambda m: "<name>"),
    (r"(?:\.\*|\[\^:\]\*):(" + word + r")\$?", lambda m: "*:" + m.group(1)),
    (r"\.\*\\\.(" + word + r")\$?", lambda m: "<name>." + m.group(1)),
    (r"(" + word + r")\\\.\.\*", lambda m: m.group(1) + ".<name>"),
    (r"(" + word + r"-)\.\*", lambda m: m.group(1) + "<name>"),
    (r"(" + word + r")\.\*", lambda m: m.group(1) + ".<name>"),
]
spellings = set()
for section, name, generic in items:
    if generic:
        for pattern, spell in rules:
            match = re.fullmatch(pattern, name)
            if match:
                name = spell(match)
                break
        else:
            sys.exit(f"no spelling for the generic item {section}.{name}")
    elif re.search(r"[][*\\$^]", name):
        sys.exit(f"a pattern in the plain item {section}.{name}")
    spellings.add(f"{section}.{name}".encode())
sys.stdout.buffer.write(b"".join(spelling + b"\n" for spelling in sorted(spellings)))
PY
}

[ "$#" -eq 2 ] || usage
tool=$1
checkout=$2

case "$tool" in
git) ;;
hg)
	hg_keys "$checkout"
	exit 0
	;;
darcs)
	echo "$0: no $tool snapshot yet" >&2
	exit 2
	;;
*) usage ;;
esac

tag=$(git -C "$checkout" describe --tags --exact-match)
installed=$(git --version | sed 's/^git version //')
if [ "v$installed" != "$tag" ]; then
	echo "$0: git on PATH is $installed, the checkout is $tag" >&2
	exit 1
fi

echo "# Git $tag: Documentation config keys (generate-configlist.sh rule) and \`git help --config\`."
{
	cat "$checkout"/Documentation/*config.txt "$checkout"/Documentation/config/*.txt |
		sed -n '/^[a-zA-Z].*\..*::$/{/deprecated/d;s/::$//;s/,  */\n/g;p;}'
	git help --config
} | sed -n '/^[a-zA-Z][a-zA-Z0-9-]*\.[^ ]*$/p' | LC_ALL=C sort -u
