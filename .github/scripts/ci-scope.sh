#!/usr/bin/env bash
# Whether a pull request or a merge group can change what a group of CI's checks checks:
#
#   ci-scope.sh tests        Format, build and test; Database tests (ci.yml)
#   ci-scope.sh binaries     Release builds (ci.yml)
#   ci-scope.sh e2e          End to end (ci.yml)
#   ci-scope.sh proofs       Proofs (proofs.yml)
#   ci-scope.sh packaging    Binaries (check), Binaries (same as zig build), Image (release.yml)
#
# Sets `run=true` or `run=false` in GITHUB_OUTPUT, and says why. The jobs still run, and report,
# either way: a required check that never reports holds the merge queue forever, which a
# workflow-level path filter would do, and a job left out by its `if:` or by a `needs:` reports as
# skipped, which counts as passed whatever it would have found. So the jobs run this first and skip
# their own steps on `run=false`.
#
# Each scope's list below is of the files that can change what its checks find; a check is skipped
# only when no changed file is on it. `tests` also lists the files that cannot change the build or
# the tests, and runs everything for a file on neither list: most new files are the runner's. The
# proofs and the packaging read a few files, named, so a file not on their list is one they do not
# read. Every scope runs everything for anything that is not a pull request or a merge group (a push
# to main, a tag, a schedule, a run by hand), and for anything this cannot work out (no base
# commit, a failed fetch).
#
# BASE is the commit the change is compared with: the pull request's base, or the merge group's.
# A pull request is tested merged into main, which may since have moved past its base: the diff
# then holds main's changes too, which only ever means running more.
set -euo pipefail
cd "$(dirname "$0")/../.."

scope=${1:-}
out=${GITHUB_OUTPUT:-/dev/stdout}
decide() {
	echo "run=$1" >>"$out"
	echo "$2"
	exit 0
}

# needed FILE: whether a change to FILE can change what the scope's checks find. Every scope lists
# this script, which decides it, and install-zig.sh, whose Zig compiles what each of them checks.
needed() {
	case $scope in
	tests)
		case $1 in
		# What the build and the tests read (db/: the database tests' migrations), and what runs them.
		runner/* | db/* | .github/workflows/ci.yml | .github/scripts/ci-scope.sh | \
			.github/scripts/install-zig.sh | .github/scripts/ci-database.sh | \
			.github/scripts/zig-test.sh | .github/scripts/zig-modules.sh | \
			.github/scripts/expr-conformance.sh) return 0 ;;
		# Cannot change the runner's build or tests. The Workflows job checks the workflows, scripts
		# and deployment scripts on every change; proofs and packaging check theirs.
		*.md | docs/* | .changes/* | .changie.yaml | proofs/* | deploy/* | LICENSE | renovate.json | \
			.trivyignore.yaml | .githooks/* | .github/CODEOWNERS | .github/workflows/* | \
			.github/scripts/*) return 1 ;;
		*) return 0 ;;
		esac
		;;
	binaries)
		# The release's binaries as build-binaries.sh compiles them: runner/src through the module
		# graph zig-modules.sh gives the compiler, from the packages build.zig.zon pins (build.zig
		# is listed too, so a change to the graph there builds them as well), and the hardening
		# checksec.sh checks them for.
		case $1 in
		runner/src/* | runner/build.zig | runner/build.zig.zon | .github/workflows/ci.yml | \
			.github/scripts/ci-scope.sh | .github/scripts/install-zig.sh | \
			.github/scripts/build-binaries.sh | .github/scripts/zig-modules.sh | \
			.github/scripts/checksec.sh) return 0 ;;
		*) return 1 ;;
		esac
		;;
	e2e)
		# The runner as the suite builds and runs it (e2e.sh: compiled as build-binaries.sh compiles
		# it, against the engine deploy/compose.yaml runs, with deploy/engine.json), and the harness.
		# The workflows it runs are runner-bench's, outside this repository.
		case $1 in
		runner/src/* | runner/build.zig | runner/build.zig.zon | deploy/engine.json | \
			.github/workflows/ci.yml | .github/scripts/ci-scope.sh | \
			.github/scripts/install-zig.sh | .github/scripts/zig-modules.sh | \
			.github/scripts/e2e.sh) return 0 ;;
		*) return 1 ;;
		esac
		;;
	proofs)
		# `lake build` reads proofs/ alone (its lakefile, manifest and toolchain included); the
		# hashFiles model's comparison (glob-lean-diff.sh) builds proofs/Oracle.lean and runs it
		# against glob.zig, compiled by itself (it imports only std) into globleancorpus.zig; and
		# key-vectors.sh compares the native key's vectors with `keyoracle`'s output. Lean's
		# version is install-lean.sh's, checked against proofs/lean-toolchain.
		case $1 in
		proofs/* | runner/src/glob.zig | runner/tools/globleancorpus.zig | \
			runner/src/native/testdata/step_keys.tsv | \
			.github/workflows/proofs.yml | .github/scripts/ci-scope.sh | \
			.github/scripts/install-zig.sh | .github/scripts/install-lean.sh | \
			.github/scripts/glob-lean-diff.sh | .github/scripts/key-vectors.sh) return 0 ;;
		*) return 1 ;;
		esac
		;;
	packaging)
		# How the release is built, not what: build-binaries.sh compiles runner/src through the module
		# graph zig-modules.sh gives the compiler, from the packages build.zig.zon pins (a tls bump
		# skipped these checks before it was listed, #107), and checked against build.zig's and for
		# their hardening (checksec.sh); sbom.sh reads build.zig.zon too. The image is the Dockerfile's, from a context .dockerignore trims,
		# scanned with .trivyignore.yaml's exceptions. deploy/, which runs the image (compose.yaml)
		# and installs the binaries (zig-runner-deploy), is read by none of them, and listed as
		# release.yml's path filter listed it. runner/src is ci.yml's: its tests, and the release's
		# builds for both targets (Release builds, `binaries`).
		case $1 in
		runner/build.zig | runner/build.zig.zon | runner/Dockerfile | runner/.dockerignore | \
			deploy/* | .trivyignore.yaml | .github/workflows/release.yml | \
			.github/scripts/ci-scope.sh | .github/scripts/install-zig.sh | \
			.github/scripts/build-binaries.sh | .github/scripts/zig-modules.sh | \
			.github/scripts/sbom.sh | .github/scripts/checksec.sh) return 0 ;;
		*) return 1 ;;
		esac
		;;
	esac
}

case $scope in
tests | binaries | e2e | proofs | packaging) ;;
*)
	echo "usage: ci-scope.sh tests|binaries|e2e|proofs|packaging" >&2
	exit 2
	;;
esac
case ${GITHUB_EVENT_NAME:-} in
pull_request | merge_group) ;;
*) decide true "${GITHUB_EVENT_NAME:-no event}: everything runs" ;;
esac
[[ ${BASE:-} =~ ^[0-9a-f]{40}$ ]] || decide true "no base commit to compare with: everything runs"
git cat-file -e "$BASE^{commit}" 2>/dev/null ||
	git fetch -q --depth=1 --no-tags origin "$BASE" ||
	decide true "could not fetch the base commit $BASE: everything runs"
# --no-renames: a file moved out of runner/ counts as a change to runner/.
changed=$(git diff --name-only --no-renames "$BASE" HEAD) ||
	decide true "could not compare with $BASE: everything runs"

while IFS= read -r file; do
	[[ -n $file ]] || continue
	! needed "$file" || decide true "$scope: $file changed: everything runs"
done <<<"$changed"
decide false "$scope: nothing these checks read changed since $BASE: skipped"
