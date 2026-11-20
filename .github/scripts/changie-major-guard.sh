#!/usr/bin/env bash
# A pull request may not bring a change entry whose kind bumps the major version (.changie.yaml's
# `auto: major`: Changed and Removed) unless it carries the `breaking` label. #610 merged with a
# Changed entry for a fix, and the next release would have been v1.0.0 (#643 refiled it).
#
#   changie-major-guard.sh BASE [LABELS]
#
# BASE is the commit the pull request is compared with; LABELS its labels, as JSON or one per line.
# Only entries the pull request adds or changes count: a major entry already on main, labelled when
# it merged, does not fail every later pull request.
set -euo pipefail
base=${1:?BASE}
labels=${2:-}
cd "$(dirname "$0")/../.."
# The kinds whose `auto` is major, from the file changie itself reads.
mapfile -t major < <(awk '/^ *- label:/ { label = $3 } /^ *auto: *major/ { print label }' .changie.yaml)
((${#major[@]} > 0)) || {
	echo "changie-major-guard: no major kind in .changie.yaml" >&2
	exit 1
}
git cat-file -e "$base^{commit}" 2>/dev/null || git fetch -q --depth=1 --no-tags origin "$base"
bad=()
while IFS= read -r f; do
	[[ -f $f ]] || continue
	kind=$(sed -n 's/^kind: *//p' "$f" | head -n1)
	for k in "${major[@]}"; do
		[[ $kind == "$k" ]] && bad+=("$f ($kind)")
	done
done < <(git diff --name-only --diff-filter=AM "$base" HEAD -- .changes/unreleased/)
if ((${#bad[@]} == 0)); then
	echo "changie-major-guard: no entry of a major kind (${major[*]}) in this change"
	exit 0
fi
if grep -qE '(^|[^a-z-])breaking([^a-z-]|$)' <<<"$labels"; then
	echo "changie-major-guard: a major bump, and the pull request is labelled breaking: ${bad[*]}"
	exit 0
fi
for b in "${bad[@]}"; do
	echo "::error::$b bumps the major version (.changie.yaml: auto: major); refile it with changie new --kind Fixed or Added, or label the pull request breaking if it is one, then re-run this check"
done
exit 1
