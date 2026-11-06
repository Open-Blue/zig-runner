#!/usr/bin/env bash
# Checks that every `test` in runner/src is one the test binary has. Zig compiles a file's tests
# only when something reaches them: main.zig's test block lists the files that nothing else
# imports, and a file left off it compiles and passes with its tests never run (github/http.zig's
# were, for as long as it was missing). The binary says which tests it holds (`test_shards --names`);
# a file's are named after its path (`github.http.test.name`), so each file's count in the
# binary is compared with its count in the source. A file whose tests are missing, or whose count
# differs, fails, naming it; the fix is its import in main.zig's test block. CI's "Format, build and
# test" job and the pre-push hook run this, after the tests, where zig-test.sh has cached the compile.
set -euo pipefail
cd "$(dirname "$0")/../../runner"

# shellcheck source=.github/scripts/zig-modules.sh
. ../.github/scripts/zig-modules.sh

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
git describe --tags --always --dirty --abbrev=8 >"$scratch/version"
zig_modules "$scratch" "$scratch/version"
zig test "${modules[@]}" --test-no-exec -femit-bin="$scratch/tests"
zig build-exe tools/test_shards.zig -femit-bin="$scratch/test_shards"
"$scratch/test_shards" --names "$scratch/tests" >"$scratch/names"

status=0
while IFS= read -r file; do
	want=$(grep -c -E '^[[:space:]]*test\b' "$file" || true)
	((want > 0)) || continue
	module=${file#src/}
	module=${module%.zig}
	module=${module//\//.}
	have=$(grep -c -- "^${module//./\\.}\\.test\\." "$scratch/names" || true)
	if ((have != want)); then
		echo "::error file=runner/$file::$want tests in the source, $have in the test binary: import it in the test block of runner/src/main.zig"
		status=1
	fi
done < <(find src -name '*.zig' -type f | sort)
if ((status == 0)); then
	echo "every test in runner/src is in the test binary ($(wc -l <"$scratch/names") tests)"
fi
exit "$status"
