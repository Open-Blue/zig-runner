#!/usr/bin/env bash
# A ratchet on the casts and assertions that skip Zig's checks, in runner/src: how many times each
# appears may go down, never up, without unsafe-ratchet.baseline (beside this script) being
# raised in the same change, where a reviewer sees it. CI's "Workflows" job runs this.
#
#   .github/scripts/unsafe-ratchet.sh            check the counts against the baseline
#   .github/scripts/unsafe-ratchet.sh --update   write the current counts as the baseline
#
# Whole-line comments are left out, so a comment may name a construct; code is counted per
# occurrence, not per line.
set -euo pipefail
cd "$(dirname "$0")/../.."

baseline=.github/scripts/unsafe-ratchet.baseline
constructs=('@bitCast' '@ptrCast' '@alignCast' '@intCast' 'catch unreachable')

count() {
	find runner/src -name '*.zig' -type f -print0 |
		xargs -0 grep -h -v -E '^[[:space:]]*//' -- |
		grep -o -F -- "$1" |
		wc -l
}

if [[ ${1:-} == --update ]]; then
	{
		echo "# How many times each construct appears in runner/src's code (.github/scripts/unsafe-ratchet.sh)."
		for c in "${constructs[@]}"; do
			printf '%s\t%d\n' "$c" "$(count "$c")"
		done
	} >"$baseline"
	cat "$baseline"
	exit 0
fi

status=0
for c in "${constructs[@]}"; do
	have=$(count "$c")
	want=$(awk -F '\t' -v c="$c" '$1 == c { print $2 }' "$baseline")
	if [[ -z $want ]]; then
		echo "::error file=$baseline::no baseline for '$c'"
		status=1
	elif ((have > want)); then
		echo "::error file=$baseline::'$c' appears $have times in runner/src, more than the baseline's $want: use a checked alternative, or raise the baseline (--update) and say why in the pull request"
		status=1
	elif ((have < want)); then
		echo "'$c': $have, down from $want: lower the baseline (--update) to keep it"
	else
		echo "'$c': $have"
	fi
done
exit "$status"
