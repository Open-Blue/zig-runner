# shellcheck shell=bash
# The runner's concurrency-sensitive tests, which the `analysis` workflow's Stress job runs again and
# again under load (zig-stress.sh): the ones whose outcome hangs on which thread gets there first or
# how long something took. Sourced from runner/, after zig-modules.sh.
#
# Each filter is a part of a test's name (Zig matches any one; a test's name is its file's module
# path and the test's string, `pg.test.a server that accepts and never answers ...`), so a new test
# named in the same terms is hunted too.
race_filters=(
	# Cancellation: a job's cancel and its grace, a stop, a cancel watch, a native step's processes.
	cancel
	# Deadlines and timeouts: a peer that accepts and never answers, or goes silent.
	deadline timeout 'never answer' silent silence 'stops answering'
	# The memory gate: admission, its reservations and the pre-warm through it.
	admission.test 'memory gate' 'the gate'
	# The native store and its locks; a job's directory and lock, volumes taken in turn.
	'native store' 'native volumes' 'directory and lock'
	# The database: pg's connect and statements, the log writer and its flusher, the state store.
	pg.test. pgsink.test. db.test.
	# The broker's long-poll, a job's cancel watch over it, the poll loop.
	broker.test. poll
	# Log uploads, each step's as it ends and the rest at the job's end.
	upload
)

# race_build SCRATCH [FLAG...]: compiles the runner (for the native backend's tests, which run steps
# through it: zig-test.sh) and only the tests race_filters names, each module with FLAG...; sets
# race_test to the test binary and exports ZIG_RUNNER_TEST_EXE.
race_build() {
	local scratch=$1 f
	shift
	git describe --tags --always --dirty --abbrev=8 >"$scratch/version"
	zig_modules "$scratch" "$scratch/version" "$@"
	local filters=()
	for f in "${race_filters[@]}"; do filters+=(--test-filter "$f"); done
	# shellcheck disable=SC2154 # zig_modules sets it
	zig build-exe "${modules[@]}" --name runner -femit-bin="$scratch/runner"
	zig test "${modules[@]}" "${filters[@]}" --test-no-exec -femit-bin="$scratch/test"
	export ZIG_RUNNER_TEST_EXE="$scratch/runner"
	# shellcheck disable=SC2034 # for the caller
	race_test=$scratch/test
}
