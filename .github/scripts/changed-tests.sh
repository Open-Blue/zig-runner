#!/usr/bin/env bash
# The names of the tests in runner/src that a change adds or edits, one a line: those whose
# `test "name" {` ... `}` holds a line the change touched, so a pull request's new test is run
# under Valgrind (analysis.yml's Valgrind job) the night before it would otherwise be.
#
#   changed-tests.sh BASE      the tests changed between the commit BASE and HEAD
#
# A name is a --test-filter for zig-valgrind.sh, which matches it anywhere in a test's full name.
# Only tests with a quoted name are found. A name that is empty (it would match every test), or
# holds a backslash or a quote (the filter could not be written back), is left out. A change to
# the code a test calls, and not to the test, is not found; the nightly run is for that. A file
# renamed unchanged has no hunk, so none of its tests run; a line deleted inside a test counts as
# a change to it. Names are the test authors' text: print them under stop-commands, as the
# workflow does, never bare.
set -euo pipefail
cd "$(dirname "$0")/../.."

base=${1:?usage: changed-tests.sh BASE}
git cat-file -e "$base^{commit}" 2>/dev/null ||
	git fetch -q --depth=1 --no-tags origin "$base"

# The new side's line ranges of every hunk: file, first line, last line. -U0: the hunks are the
# changed lines alone. A hunk that only deletes (`+N,0`) sits between lines N and N+1.
git diff -U0 -M --diff-filter=AMR "$base" HEAD -- 'runner/src/*.zig' |
	awk '
		/^\+\+\+ b\// { file = substr($0, 7); next }
		/^@@/ {
			split($3, range, ",")
			first = substr(range[1], 2) + 0
			count = (range[2] == "" ? 1 : range[2] + 0)
			if (count == 0) print file "\t" first "\t" first + 1
			else print file "\t" first "\t" first + count - 1
		}
	' |
	while IFS=$'\t' read -r file first last; do
		awk -v first="$first" -v last="$last" '
			/^test "/ {
				name = $0
				sub(/^test "/, "", name)
				sub(/" *\{.*$/, "", name)
				start = NR
				inside = 1
				# `test "x" { ... }` on one line ends there.
				closing = ($0 ~ /\}[ \t]*$/)
			}
			inside && (closing || /^}/) {
				if (start <= last && NR >= first && name != "" && name !~ /[\\"]/) print name
				inside = 0
				closing = 0
			}
		' "$file"
	done | sort -u
