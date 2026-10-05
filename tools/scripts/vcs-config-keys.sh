#!/bin/sh
# Print the configuration-key snapshot one version-control tool documents.
#
# Usage: tools/scripts/vcs-config-keys.sh git <git-source-checkout> > src/compiler/sandbox/data/git-config-keys.txt
#
# Git: the keys Git's own `generate-configlist.sh` rule extracts from the
# checkout's `Documentation/*config.txt` and `Documentation/config/*.txt`,
# unioned with the keys `git help --config` of the `git` on PATH lists, which
# must be the checkout's tagged release. The first line names both sources; the rest is
# one spelling per line, byte-sorted. The `vcs_keys` coverage test compares the
# snapshot with the key table, so a refreshed snapshot lists every key the
# table has yet to decide.
set -eu

usage() {
	echo "usage: $0 git <git-source-checkout>" >&2
	exit 2
}

[ "$#" -eq 2 ] || usage
tool=$1
checkout=$2

case "$tool" in
git) ;;
hg | darcs)
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
