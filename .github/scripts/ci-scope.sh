#!/usr/bin/env bash
# Whether a pull request or a merge group can change what a group of CI's checks checks:
#
#   ci-scope.sh tests        Tests (x86_64), Tests (arm64), Native tests as root; Database tests;
#                            Workflows' ZLint steps (ci.yml)
#   ci-scope.sh binaries     Release builds; Release builds (arm64) (ci.yml)
#   ci-scope.sh e2e          End to end (ci.yml)
#   ci-scope.sh proofs       Proofs (proofs.yml)
#   ci-scope.sh packaging    Binaries (check), Binaries (same as zig build), Image (release.yml)
#   ci-scope.sh go           Workflows' Go tools steps (ci.yml)
#   ci-scope.sh apt          Workflows' apt mirror fallback step (ci.yml)
#   ci-scope.sh analysis     Fuzz, Valgrind, Stress, ZLint (suppressed-errors) (analysis.yml)
#   ci-scope.sh tsan         ThreadSanitizer, native; ThreadSanitizer, end to end (analysis.yml)
#   ci-scope.sh store        Store stress, Store crash (analysis.yml)
#   ci-scope.sh coverage     Coverage's own tooling (analysis.yml)
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
# proofs, the packaging and the Go tools read a few files, named, so a file not on their list is one they do not
# read. Every scope runs everything for anything that is not a pull request or a merge group (a push
# to main, a tag, a schedule, a run by hand), and for anything this cannot work out (no base
# commit, a failed fetch). The codeql scopes alone also compare a push to main with the commit
# before it (BASE is the push's `before`); codeql.yml's weekly run and a run by hand run in full.
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
# this script, which decides it, and each but `go` lists install-zig.sh, whose Zig compiles what
# its checks check.
needed() {
	case $scope in
	tests)
		case $1 in
		# What the build and the tests read (db/: the database tests' migrations), and what runs them.
		runner/* | db/* | .github/workflows/ci.yml | .github/scripts/ci-scope.sh | \
			.github/scripts/install-zig.sh | .github/scripts/ci-database.sh | \
			.github/scripts/zig-test.sh | .github/scripts/zig-modules.sh | \
			.github/scripts/expr-conformance.sh | .github/scripts/zlint.sh | \
			.github/scripts/zlint-suppressed.baseline | \
			.github/scripts/native-service-images.sh) return 0 ;;
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
	go)
		# go-lint.sh lints the comparison tools' modules under runner/tools (each with its own go.mod
		# and go.sum), with the Go each go.mod names; nothing else it reads is in this repository.
		case $1 in
		runner/tools/* | .github/workflows/ci.yml | .github/scripts/ci-scope.sh | \
			.github/scripts/go-lint.sh) return 0 ;;
		*) return 1 ;;
		esac
		;;
	apt)
		# apt-test.sh runs apt.sh's mirror fallback in a container, against the real mirrors.
		case $1 in
		.github/scripts/apt.sh | .github/scripts/apt-test.sh | .github/workflows/ci.yml | \
			.github/scripts/ci-scope.sh) return 0 ;;
		*) return 1 ;;
		esac
		;;
	analysis)
		# Only the searches themselves, on a pull request: a change to the runner's code is the
		# nightly run's to search, not every pull request's (each costs minutes per target).
		# The decoders (libzstd and zlib-ng, which read every layer a registry sends, and the Zig
		# decoders they are held to) are the exception, with their corpora: a change to them is
		# fuzzed before it merges, as is `native/tarball.zig`, which reads the first bytes of an
		# archive a server sent.
		case $1 in
		.github/workflows/analysis.yml | .github/scripts/ci-scope.sh | \
			.github/scripts/zig-fuzz.sh | .github/scripts/zig-valgrind.sh | \
			.github/scripts/changed-tests.sh | \
			.github/scripts/zig-race-tests.sh | .github/scripts/zig-stress.sh | \
			.github/scripts/zlint.sh | .github/scripts/zlint-suppressed.baseline | \
			runner/src/native/oci/zstd.zig | runner/src/native/oci/libzstd.zig | \
			runner/src/vendor/zstd/* | runner/src/fuzz_corpus/zstd/* | \
			runner/src/native/oci/zlibng.zig | runner/src/vendor/zlib-ng/* | \
			runner/src/fuzz_corpus/gzip/* | \
			runner/src/native/tarball.zig | \
			.github/valgrind.supp) return 0 ;;
		*) return 1 ;;
		esac
		;;
	tsan)
		# Every change to the runner's code: a race is a property of the code that changed, which no
		# test that changed has to name, and the night is too late to learn of one.
		case $1 in
		runner/src/* | runner/build.zig | .github/workflows/analysis.yml | \
			.github/scripts/ci-scope.sh) return 0 ;;
		*) return 1 ;;
		esac
		;;
	store)
		# What its jobs run through: the store and its layers, the key locks and publishes in
		# Backend, the mounts in sandbox. A change there can lose a layer in ways ci's 30 s of
		# the same test rarely shows, so it is searched before it merges, not only that night.
		case $1 in
		runner/src/native/Store.zig | runner/src/native/store_stress.zig | \
			runner/src/native/layers.zig | runner/src/native/Backend.zig | \
			runner/src/native/sandbox.zig | .github/workflows/analysis.yml | \
			.github/scripts/ci-scope.sh | .github/scripts/install-zig.sh | \
			.github/scripts/zig-test.sh | runner/src/native/store_crash.zig | \
			runner/src/native/oci/Store.zig | runner/src/native/volumes.zig | \
			runner/src/native/evict.zig | \
			.github/scripts/store-crash.sh | .github/scripts/zig-modules.sh) return 0 ;;
		*) return 1 ;;
		esac
		;;
	codeql-actions)
		# The workflows are what it reads, and nothing says which of the repository's files they
		# run (a script a workflow calls, an action's pin): every change is read.
		return 0
		;;
	codeql-go)
		# What it builds and reads: the comparison tools' sources and modules under runner/tools,
		# and the workflow and this script, which decide what runs.
		case $1 in
		runner/tools/*.go | runner/tools/*/go.mod | runner/tools/*/go.sum | \
			.github/workflows/codeql.yml | .github/scripts/ci-scope.sh) return 0 ;;
		*) return 1 ;;
		esac
		;;
	codeql-python)
		case $1 in
		*.py | .github/workflows/codeql.yml | .github/scripts/ci-scope.sh) return 0 ;;
		*) return 1 ;;
		esac
		;;
	coverage)
		# What runs the measurement, not what it measures: a pull request that changes the runner's
		# code is measured by the night's run (about 1 GB of raw reports a part, over an hour of
		# runner time), so only a change to this job's own tooling runs the four parts, to see them
		# work (they report nothing and merge nothing on a pull request).
		case $1 in
		.github/workflows/analysis.yml | \
			.github/scripts/ci-scope.sh | .github/scripts/install-zig.sh | \
			.github/scripts/zig-modules.sh | .github/scripts/zig-coverage.sh | \
			.github/scripts/native-service-images.sh) return 0 ;;
		*) return 1 ;;
		esac
		;;
	esac
}

case $scope in
tests | binaries | e2e | proofs | packaging | go | apt | analysis | tsan | store | coverage | \
	codeql-actions | codeql-go | codeql-python) ;;
*)
	echo "usage: ci-scope.sh tests|binaries|e2e|proofs|packaging|go|apt|analysis|tsan|store|coverage|codeql-actions|codeql-go|codeql-python" >&2
	exit 2
	;;
esac
case ${GITHUB_EVENT_NAME:-} in
pull_request | merge_group) ;;
push)
	case $scope in
	codeql-*) ;;
	*) decide true "push: everything runs" ;;
	esac
	;;
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
