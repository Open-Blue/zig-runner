#!/usr/bin/env bash
# changie-major-guard.sh against a throwaway repository: a pull request that adds a major-kind entry
# fails unless it is labelled breaking; a Fixed entry passes; a major entry already on the base, or
# one only touched by a later change of kind, is judged by what the pull request changes.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(mktemp -d)
trap 'rm -rf "$repo"' EXIT
mkdir -p "$repo/.github/scripts" "$repo/.changes/unreleased"
cp "$here/changie-major-guard.sh" "$repo/.github/scripts/"
cp "$here/../../.changie.yaml" "$repo/"
cd "$repo"
git init -q && git config user.email t@t && git config user.name t
entry() { printf 'kind: %s\nbody: %s\n' "$2" "$3" >".changes/unreleased/$1.yaml"; }
commit() { git add -A && git commit -qm "$1" && git rev-parse HEAD; }
fail() {
	echo "changie-major-guard-test: $*" >&2
	exit 1
}
guard() { .github/scripts/changie-major-guard.sh "$@" >/dev/null 2>&1; }
entry old Changed "a breaking change that merged labelled"
base=$(commit base)

entry fix Fixed "a fix"
commit fix >/dev/null
guard "$base" "" || fail "a Fixed entry failed"
entry brk Changed "a fix filed as Changed"
commit brk >/dev/null
guard "$base" "" && fail "an unlabelled Changed entry passed"
guard "$base" '["breaking"]' || fail "a Changed entry labelled breaking failed"
guard "$base" '["not-breaking"]' && fail "a label that only contains the word passed"
git rm -q .changes/unreleased/brk.yaml && commit drop >/dev/null
guard "$base" "" || fail "the base's own Changed entry failed a pull request that did not touch it"
entry fix Removed "a fix re-kinded"
commit rekind >/dev/null
guard "$base" "" && fail "an entry changed to Removed passed"
echo "changie-major-guard-test: unlabelled major entries fail, labelled ones and fixes pass, the base's own entries are not judged"
