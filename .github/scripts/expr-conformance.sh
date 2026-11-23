#!/usr/bin/env bash
# Checks the runner's expression evaluator (runner/src/expr.zig) against GitHub's own test cases:
# the ones actions/languageservices keeps in expressions/testdata (MIT, Copyright GitHub), fetched
# at the commit pinned below. runner/tools/exprcorpus.zig runs them.
#
# The cases the runner does not pass yet are listed in runner/tools/exprcorpus-failing.txt. This
# fails when a case outside that list fails (a regression) and when a listed case passes (take it
# off the list), so the list is always exactly what is left to do.
#
#   expr-conformance.sh            check against the list
#   expr-conformance.sh --report   every disagreement, with what GitHub expects and what the runner gives
#   expr-conformance.sh --update   rewrite the list from this run
set -euo pipefail
cd "$(dirname "$0")/../../runner"

LANGUAGESERVICES_REV=8e5973b4c9a14ebd526a44799823ac168dbcd291

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
git init -q "$scratch/ls"
git -C "$scratch/ls" fetch -q --depth 1 --filter=blob:none https://github.com/actions/languageservices "$LANGUAGESERVICES_REV"
git -C "$scratch/ls" sparse-checkout set --no-cone /expressions/testdata/ >/dev/null
git -C "$scratch/ls" checkout -q FETCH_HEAD
cases=$scratch/ls/expressions/testdata

zig build-exe --dep expr -Mroot=tools/exprcorpus.zig -Mexpr=src/expr.zig --name exprcorpus \
	-femit-bin="$scratch/exprcorpus"

list=tools/exprcorpus-failing.txt
case ${1:-} in
--report)
	"$scratch/exprcorpus" "$cases"
	exit
	;;
--update)
	"$scratch/exprcorpus" "$cases" --failing | LC_ALL=C sort >"$list"
	echo "$(wc -l <"$list") cases listed in $list"
	exit
	;;
esac

"$scratch/exprcorpus" "$cases" --failing | LC_ALL=C sort >"$scratch/failing"
new=$(LC_ALL=C comm -13 "$list" "$scratch/failing")
fixed=$(LC_ALL=C comm -23 "$list" "$scratch/failing")
total=$(cat "$cases"/*.json | grep -c '"expr"')
echo "GitHub's expression cases: $((total - $(wc -l <"$scratch/failing")))/$total pass"
if [[ -n $new ]]; then
	echo "Failing now, and not before (run with --report for details):"
	while IFS= read -r l; do echo "  $l"; done <<<"$new"
fi
if [[ -n $fixed ]]; then
	echo "Passing now: take these off $list (or run with --update):"
	while IFS= read -r l; do echo "  $l"; done <<<"$fixed"
fi
[[ -z $new && -z $fixed ]]
