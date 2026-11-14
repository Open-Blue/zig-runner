#!/usr/bin/env bash
# Tests deploy/zig-runner-deploy's channels against fake release feeds: the real agent runs with a
# fake gh (deployments, releases, downloads and `gh attestation verify`, which compares the
# workflow, ref and commit a binary's fake provenance names with what the agent asks for) and a
# fake systemctl, in a scratch directory. Nothing touches GitHub or a real service. CI's
# "Workflows" job runs it.
#
#   deploy-test.sh
set -uo pipefail
agent=$(realpath "$(dirname "$0")/../../deploy/zig-runner-deploy")
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
fake=$root/fake
fx=$root/fx
arch=$(uname -m)
asset=zig-runner-linux-$arch
passed=0 failed=0

mkdir -p "$fake"

# The fake gh. Fixtures live under $FX: dep/ (ids, ID.ref, ID.state), releases.tsv (tag, prerelease),
# rel/TAG/ (the asset, SHA256SUMS, prov = "workflow ref commit"), commit/TAG. Every call is logged.
cat >"$fake/gh" <<'EOF'
#!/usr/bin/env bash
echo "$*" >>"$FX/calls"
args=("$@")
if [[ $1 == --version ]]; then echo "gh version fake"; exit 0; fi
if [[ $1 == attestation ]]; then
	case $2 in
	verify)
		if [[ ${args[*]} == *--help* ]]; then
			echo "--signer-workflow --source-ref --source-digest --deny-self-hosted-runners --custom-trusted-root"
			exit 0
		fi
		file=${args[2]} bundle='' signer='' ref='' digest=''
		for ((i = 3; i < ${#args[@]}; i++)); do
			case ${args[i]} in
			--bundle) bundle=${args[++i]} ;;
			--signer-workflow) signer=${args[++i]} ;;
			--source-ref) ref=${args[++i]} ;;
			--source-digest) digest=${args[++i]} ;;
			esac
		done
		read -r p_workflow p_ref p_commit <"$bundle"
		[[ $signer == "o/r/.github/workflows/$p_workflow" && $ref == "$p_ref" ]] || exit 1
		[[ -z $digest || $digest == "$p_commit" ]] || exit 1
		exit 0
		;;
	download)
		tag=$(<"$FX/last_tag")
		cp "$FX/rel/$tag/prov" "sha256:$(sha256sum "${args[2]}" | cut -d' ' -f1).jsonl"
		exit 0
		;;
	trusted-root) echo '{}'; exit 0 ;;
	esac
fi
if [[ $1 == release && $2 == download ]]; then
	tag=${args[2]} dir=''
	for ((i = 3; i < ${#args[@]}; i++)); do [[ ${args[i]} == -D ]] && dir=${args[i + 1]}; done
	[[ -d $FX/rel/$tag ]] || { echo "release not found" >&2; exit 1; }
	echo "$tag" >"$FX/last_tag"
	cp "$FX/rel/$tag/$ASSET" "$FX/rel/$tag/SHA256SUMS" "$dir/"
	exit 0
fi
if [[ $1 == api ]]; then
	if [[ $2 == -X ]]; then echo "${args[*]:3}" >>"$FX/reports"; exit 0; fi
	path=$2
	case $path in
	*/releases\?*) cat "$FX/releases.tsv" ;;
	*/deployments\?*) cat "$FX/dep/ids" 2>/dev/null ;;
	*/statuses*) id=${path#*/deployments/}; id=${id%%/*}; cat "$FX/dep/$id.state" 2>/dev/null ;;
	*/deployments/*) id=${path##*/}; cat "$FX/dep/$id.ref" ;;
	*/git/ref/tags/*) cat "$FX/commit/${path##*/}" 2>/dev/null || { echo "HTTP 404" >&2; exit 1; } ;;
	*) exit 1 ;;
	esac
	exit 0
fi
echo "fake gh: unexpected $*" >&2
exit 2
EOF
cat >"$fake/systemctl" <<'EOF'
#!/usr/bin/env bash
case $1 in
show) case $3 in LoadState) echo loaded ;; MainPID) echo 123 ;; InvocationID) echo inv ;; esac ;;
is-active) exit 0 ;;
restart) echo "restart $2 $("$BIN" --version)" >>"$FX/restarts" ;;
list-units) ;;
esac
EOF
# A binary that says "bad" never comes up listening.
cat >"$fake/journalctl" <<'EOF'
#!/usr/bin/env bash
grep -q bad "$BIN" || echo "listening for jobs"
EOF
cat >"$fake/readlink" <<'EOF'
#!/usr/bin/env bash
echo "$BIN"
EOF
chmod +x "$fake"/*

# --- fixtures -------------------------------------------------------------------------------

setup() {
	rm -rf "$root/sandbox" "$fx"
	mkdir -p "$root/sandbox/bin" "$root/sandbox/state" "$fx/dep" "$fx/rel" "$fx/commit"
	: >"$fx/releases.tsv"
	: >"$fx/calls"
	: >"$fx/restarts"
	: >"$fx/reports"
	: >"$fx/dep/ids"
	unset CHANNEL DRY_RUN ALLOW_DOWNGRADE
	export FX=$fx ASSET=$asset BIN=$root/sandbox/bin/zig-runner
}

# binary VERSION [PATH [extra]]: a "binary" that says its version.
binary() {
	# shellcheck disable=SC2016 # $1 is the fake binary's own
	printf '#!/bin/sh\n[ "$1" = --version ] && echo "zig-runner %s"\n# %s\n' "$1" "${3:-}" >"${2:-$BIN}"
	chmod +x "${2:-$BIN}"
}

# release TAG VERSION WORKFLOW REF [COMMIT]: the files of a published release.
release() {
	local tag=$1 d=$fx/rel/$1
	mkdir -p "$d"
	binary "$2" "$d/$asset" "${EXTRA:-}"
	(cd "$d" && sha256sum "$asset" >SHA256SUMS)
	echo "$3 $4 ${5:--}" >"$d/prov"
}
feed() { printf '%s\t%s\n' "$1" "$2" >>"$fx/releases.tsv"; }
sha_of() { printf '%s%028d' "$1" 0; }

# stable_release vX.Y.Z: in the feed and a release.yml-attested release.
stable_release() {
	release "$1" "$1" release.yml "refs/tags/$1"
	feed "$1" false
}
rc_release() {
	release "$1" "$1" candidate.yml "refs/tags/$1"
	feed "$1" true
}
# main_candidate N SHA12 [BASE]: main-N-SHA12, version vBASE-main.N+SHA12.
main_candidate() {
	local tag=main-$1-$2
	release "$tag" "v${3:-1.2.4}-main.$1+$2" candidate.yml refs/heads/main "$(sha_of "$2")"
	sha_of "$2" >"$fx/commit/$tag"
	feed "$tag" true
}
deployment() {
	echo "$1" >>"$fx/dep/ids"
	echo "$2" >"$fx/dep/$1.ref"
	echo "${3:-}" >"$fx/dep/$1.state"
}

# channel NAME: the machine follows NAME and has been, so the next install is no switch.
channel() {
	export CHANNEL=$1
	echo "$1" >"$root/sandbox/state/channel"
}

# run_agent: the agent, its output in $out and status in $status.
run_agent() {
	out=$(
		PATH=$fake:$PATH GH_TOKEN=x REPO=o/r UNITS=zig-runner@t.service \
			STATE_DIR=$root/sandbox/state HEALTH_SECONDS=0 "$agent" 2>&1
	)
	status=$?
}
installed() { "$BIN" --version | awk '{print $2}'; }
downloads() { grep -c '^release download' "$fx/calls"; }
rejected() { grep -qxF "$1" "$root/sandbox/state/rejected" 2>/dev/null; }

check() {
	local name=$1
	shift
	if "$@"; then
		passed=$((passed + 1))
	else
		failed=$((failed + 1))
		echo "ERROR $CURRENT: $name"
		printf '    %s\n' "${out//$'\n'/$'\n'    }"
	fi
}
installed_is() { [[ $(installed) == "$1" ]]; }
status_is() { [[ $status == "$1" ]]; }
out_has() { [[ $out == *"$1"* ]]; }
not() { ! "$@"; }
prev_is() { [[ -x $BIN.prev && $("$BIN.prev" --version | awk '{print $2}') == "$1" ]]; }
no_downloads() { [[ $(downloads) == 0 ]]; }

# --- tests ----------------------------------------------------------------------------------

t_stable_installs_the_deployed_release() {
	setup
	binary v1.2.2
	stable_release v1.2.3
	deployment 1 v1.2.3
	run_agent
	check "exit 0" status_is 0
	check "v1.2.3 installed" installed_is v1.2.3
	check "previous binary kept" prev_is v1.2.2
	check "restarted onto it" grep -q 'restart zig-runner@t.service zig-runner v1.2.3' "$fx/restarts"
	check "reported success" grep -q 'state=success' "$fx/reports"
}

t_stable_refuses_a_main_candidate() {
	setup
	binary v1.2.3
	main_candidate 5 abcdef012345
	deployment 1 main-5-abcdef012345
	run_agent
	check "exit 1" status_is 1
	check "still v1.2.3" installed_is v1.2.3
	check "nothing downloaded" no_downloads
	check "reported failure" grep -q 'state=failure' "$fx/reports"
	check "says why" out_has "not a version tag: main-5-abcdef012345"
}

t_stable_refuses_a_release_candidate() {
	setup
	binary v1.2.3
	rc_release v1.3.0-rc1
	deployment 1 v1.3.0-rc1
	run_agent
	check "exit 1" status_is 1
	check "still v1.2.3" installed_is v1.2.3
	check "nothing downloaded" no_downloads
}

t_stable_ignores_candidates_in_the_feed() {
	setup
	binary v1.2.3
	main_candidate 9 abcdef012345 1.9.9
	rc_release v1.9.0-rc1
	run_agent
	check "exit 0" status_is 0
	check "still v1.2.3" installed_is v1.2.3
	check "nothing downloaded" no_downloads
	check "feed never read" not grep -q 'releases' "$fx/calls"
}

t_stable_refuses_a_candidate_posing_as_a_release() {
	setup
	binary v1.2.3
	release v1.3.0 v1.3.0 candidate.yml refs/tags/v1.3.0
	deployment 1 v1.3.0
	run_agent
	check "exit 1" status_is 1
	check "still v1.2.3" installed_is v1.2.3
	check "provenance named" out_has "no provenance from release.yml"
}

t_stable_version_is_monotonic() {
	setup
	binary v1.2.3
	stable_release v1.2.2
	deployment 1 v1.2.2
	run_agent
	check "older refused" status_is 1
	check "still v1.2.3" installed_is v1.2.3
	check "says why" out_has "older than the installed v1.2.3"
	ALLOW_DOWNGRADE=v1.2.2
	export ALLOW_DOWNGRADE
	setup_keep_state
	run_agent
	check "ALLOW_DOWNGRADE allows it" installed_is v1.2.2
	unset ALLOW_DOWNGRADE
}
# Runs the same deployment again.
setup_keep_state() {
	: >"$fx/dep/1.state"
	: >"$fx/reports"
}

t_stable_rejects_a_bad_checksum() {
	setup
	binary v1.2.2
	stable_release v1.2.3
	echo "0000000000000000000000000000000000000000000000000000000000000000  $asset" >"$fx/rel/v1.2.3/SHA256SUMS"
	deployment 1 v1.2.3
	run_agent
	check "exit 1" status_is 1
	check "still v1.2.2" installed_is v1.2.2
	check "checksum named" out_has "does not match v1.2.3's SHA256SUMS"
}

t_main_installs_a_newer_candidate() {
	setup
	binary v1.2.4-main.3+aaaaaaaaaaaa
	main_candidate 4 bbbbbbbbbbbb
	main_candidate 2 cccccccccccc
	# Newer-looking things that are not main candidates.
	stable_release v1.9.0
	rc_release v1.9.1-rc1
	channel main
	run_agent
	check "exit 0" status_is 0
	check "main.4 installed" installed_is v1.2.4-main.4+bbbbbbbbbbbb
	check "previous binary kept" prev_is v1.2.4-main.3+aaaaaaaaaaaa
	check "restarted" grep -q 'restart zig-runner@t.service' "$fx/restarts"
	check "channel recorded" grep -qx main "$root/sandbox/state/channel"
	check "provenance asked for the commit" grep -q 'source-digest bbbbbbbbbbbb0000' "$fx/calls"
}

t_main_installs_the_highest_number_not_rejected() {
	setup
	binary v1.2.4-main.3+aaaaaaaaaaaa
	main_candidate 9 999999999999
	main_candidate 12 121212121212
	main_candidate 10 101010101010
	echo main-12-121212121212 >"$root/sandbox/state/rejected"
	channel main
	run_agent
	check "main.10 installed (12 rejected, 9 older)" installed_is v1.2.4-main.10+101010101010
}

t_main_does_not_install_an_older_or_equal_candidate() {
	setup
	binary v1.2.4-main.5+aaaaaaaaaaaa
	main_candidate 4 bbbbbbbbbbbb
	main_candidate 5 cccccccccccc
	channel main
	run_agent
	check "exit 0" status_is 0
	check "still main.5" installed_is v1.2.4-main.5+aaaaaaaaaaaa
	check "nothing downloaded" no_downloads
	check "channel unchanged: nothing recorded as installed" not test -e "$root/sandbox/state/channel.bad"
}

t_main_already_installed_does_nothing() {
	setup
	main_candidate 5 aaaaaaaaaaaa
	binary v1.2.4-main.5+aaaaaaaaaaaa
	channel main
	run_agent
	check "exit 0" status_is 0
	check "nothing downloaded" no_downloads
	check "nothing restarted" test ! -s "$fx/restarts"
}

t_main_refuses_wrong_provenance() {
	local case
	for case in "workflow:release.yml refs/heads/main" "ref:candidate.yml refs/heads/other" "ref:candidate.yml refs/tags/v1.2.3" "commit:candidate.yml refs/heads/main ffffffffffffffffffffffffffffffffffffffff"; do
		setup
		binary v1.2.4-main.3+aaaaaaaaaaaa
		main_candidate 4 bbbbbbbbbbbb
		echo "${case#*:}" >"$fx/rel/main-4-bbbbbbbbbbbb/prov"
		channel main
		run_agent
		check "${case%%:*}: exit 1" status_is 1
		check "${case%%:*}: still main.3" installed_is v1.2.4-main.3+aaaaaaaaaaaa
		check "${case%%:*}: remembered as rejected" rejected main-4-bbbbbbbbbbbb
		local before
		before=$(downloads)
		run_agent
		check "${case%%:*}: not fetched again" test "$(downloads)" = "$before"
		check "${case%%:*}: second run quiet" status_is 0
	done
}

t_main_refuses_a_bad_checksum_and_a_wrong_version() {
	setup
	binary v1.2.4-main.3+aaaaaaaaaaaa
	main_candidate 4 bbbbbbbbbbbb
	echo "0000000000000000000000000000000000000000000000000000000000000000  $asset" >"$fx/rel/main-4-bbbbbbbbbbbb/SHA256SUMS"
	channel main
	run_agent
	check "checksum: exit 1" status_is 1
	check "checksum: still main.3" installed_is v1.2.4-main.3+aaaaaaaaaaaa

	setup
	binary v1.2.4-main.3+aaaaaaaaaaaa
	main_candidate 4 bbbbbbbbbbbb
	release main-4-bbbbbbbbbbbb v1.2.4-main.7+bbbbbbbbbbbb candidate.yml refs/heads/main "$(sha_of bbbbbbbbbbbb)"
	channel main
	run_agent
	check "version: exit 1" status_is 1
	check "version: still main.3" installed_is v1.2.4-main.3+aaaaaaaaaaaa
	check "version: says why" out_has "does not say it is main-4-bbbbbbbbbbbb"
}

t_main_ignores_a_tag_that_is_not_a_pre_release() {
	setup
	binary v1.2.4-main.3+aaaaaaaaaaaa
	main_candidate 4 bbbbbbbbbbbb
	: >"$fx/releases.tsv"
	feed main-4-bbbbbbbbbbbb false
	channel main
	run_agent
	check "still main.3" installed_is v1.2.4-main.3+aaaaaaaaaaaa
	check "nothing downloaded" no_downloads
}

t_main_refuses_a_tag_at_another_commit() {
	setup
	binary v1.2.4-main.3+aaaaaaaaaaaa
	main_candidate 4 bbbbbbbbbbbb
	sha_of dddddddddddd >"$fx/commit/main-4-bbbbbbbbbbbb"
	channel main
	run_agent
	check "exit 1" status_is 1
	check "still main.3" installed_is v1.2.4-main.3+aaaaaaaaaaaa
}

t_main_rolls_back() {
	setup
	binary v1.2.4-main.3+aaaaaaaaaaaa
	main_candidate 4 bbbbbbbbbbbb
	EXTRA=bad main_candidate 4 bbbbbbbbbbbb
	sed -i '$d' "$fx/releases.tsv"
	export CHANNEL=main
	run_agent
	check "exit 1" status_is 1
	check "back on main.3" installed_is v1.2.4-main.3+aaaaaaaaaaaa
	check "restarted onto the old one again" grep -q 'restart zig-runner@t.service zig-runner v1.2.4-main.3' "$fx/restarts"
	check "rejected" rejected main-4-bbbbbbbbbbbb
	check "channel not recorded" test ! -e "$root/sandbox/state/channel"
}

t_rc_installs_rc_and_release() {
	setup
	binary v1.2.3
	rc_release v1.3.0-rc1
	rc_release v1.3.0-rc2
	main_candidate 50 eeeeeeeeeeee 1.9.0
	channel rc
	run_agent
	check "rc2 installed (rc1 older, main ignored)" installed_is v1.3.0-rc2
	check "channel recorded" grep -qx rc "$root/sandbox/state/channel"
	check "provenance from candidate.yml at the tag" grep -q 'signer-workflow o/r/.github/workflows/candidate.yml --source-ref refs/tags/v1.3.0-rc2' "$fx/calls"

	stable_release v1.3.0
	run_agent
	check "the release replaces its rc" installed_is v1.3.0
	check "release verified as release.yml" grep -q 'signer-workflow o/r/.github/workflows/release.yml --source-ref refs/tags/v1.3.0' "$fx/calls"

	rc_release v1.3.1-rc1
	run_agent
	check "a later rc replaces the release" installed_is v1.3.1-rc1
}

t_rc_is_monotonic() {
	setup
	binary v1.3.1-rc2
	rc_release v1.3.1-rc1
	stable_release v1.3.0
	channel rc
	run_agent
	check "exit 0" status_is 0
	check "older rc and release not installed" installed_is v1.3.1-rc2
	check "nothing downloaded" no_downloads
}

t_rc_checks_each_kind_against_its_workflow() {
	setup
	binary v1.2.3
	rc_release v1.3.0-rc1
	echo "release.yml refs/tags/v1.3.0-rc1 -" >"$fx/rel/v1.3.0-rc1/prov"
	channel rc
	run_agent
	check "an rc built by release.yml: exit 1" status_is 1
	check "still v1.2.3" installed_is v1.2.3

	setup
	binary v1.2.3
	stable_release v1.3.0
	echo "candidate.yml refs/tags/v1.3.0 -" >"$fx/rel/v1.3.0/prov"
	channel rc
	run_agent
	check "a release built by candidate.yml: exit 1" status_is 1
	check "still v1.2.3" installed_is v1.2.3
}

t_switching_channels_is_explicit() {
	setup
	binary v1.5.0
	main_candidate 4 bbbbbbbbbbbb 1.2.4
	export CHANNEL=main
	run_agent
	check "stable -> main installs an older-versioned candidate" installed_is v1.2.4-main.4+bbbbbbbbbbbb
	check "the switch is logged" out_has "channel switch: stable -> main"
	check "recorded" grep -qx main "$root/sandbox/state/channel"

	stable_release v1.2.0
	deployment 1 v1.2.0 success
	export CHANNEL=stable
	run_agent
	check "main -> stable installs the deployed release, though handled and older" installed_is v1.2.0
	check "the switch is logged" out_has "channel switch: main -> stable"
	check "recorded" grep -qx stable "$root/sandbox/state/channel"

	# Back on stable, the order is checked again.
	stable_release v1.1.0
	deployment 2 v1.1.0
	run_agent
	check "older refused again" installed_is v1.2.0
}

t_stable_installs_nothing_on_a_handled_deployment() {
	setup
	binary v1.2.3
	stable_release v1.3.0
	deployment 1 v1.3.0 success
	run_agent
	check "exit 0" status_is 0
	check "still v1.2.3" installed_is v1.2.3
}

t_dry_run_installs_nothing() {
	setup
	binary v1.2.3-main.3+aaaaaaaaaaaa
	main_candidate 4 bbbbbbbbbbbb
	export CHANNEL=main DRY_RUN=1
	run_agent
	check "exit 0" status_is 0
	check "still main.3" installed_is v1.2.3-main.3+aaaaaaaaaaaa
	check "nothing restarted" test ! -s "$fx/restarts"
	check "no state written" test ! -e "$root/sandbox/state/channel"
	check "it did check" downloads_one
}
downloads_one() { [[ $(downloads) == 1 ]]; }

t_an_unknown_channel_fails() {
	setup
	binary v1.2.3
	export CHANNEL=nightly
	run_agent
	check "exit 1" status_is 1
	check "says why" out_has "not stable, rc or main"
}

# The candidate workflow's two helpers, with a gh that lists tags and releases and logs deletions.
scripts=$(realpath "$(dirname "$0")")
helper_gh() {
	mkdir -p "$root/helper"
	cat >"$root/helper/gh" <<'EOF'
#!/usr/bin/env bash
case $1 in
api) printf 'refs/tags/v0.9.0\nrefs/tags/v0.34.0\nrefs/tags/v0.4.0\nrefs/tags/v0.35.0-rc1\n' ;;
release)
	case $2 in
	list) cat "$FX/list" ;;
	delete) echo "$3" >>"$FX/deleted" ;;
	esac
	;;
esac
EOF
	chmod +x "$root/helper/gh"
}

t_candidate_names() {
	setup
	helper_gh
	out=$(PATH=$root/helper:$PATH GH_REPO=o/r "$scripts/candidate-version.sh" main 77 0123456789abcdef0123456789abcdef01234567 2>&1)
	status=$?
	check "main candidate" test "$out" = "v0.34.1-main.77+0123456789ab main-77-0123456789ab"
	out=$("$scripts/candidate-version.sh" tag v0.35.0-rc2 2>&1)
	check "rc candidate" test "$out" = "v0.35.0-rc2 v0.35.0-rc2"
	out=$("$scripts/candidate-version.sh" tag v0.35.0 2>&1)
	status=$?
	check "a release is no rc" status_is 1
	out=$("$scripts/candidate-version.sh" tag v0.35.0-rc1+x 2>&1)
	status=$?
	check "build metadata is no rc" status_is 1
}

# The pruning script, against a fake gh that serves a release list and the pool's deployments, and
# logs what is deleted. NOW is 2026-11-14; ages are in days.
now=1794614400
prune_fixture() {
	helper_gh
	cat >"$root/helper/gh" <<'EOF2'
#!/usr/bin/env bash
case $1 in
api)
	[[ -e $FX/deployments-fail ]] && exit 1
	cat "$FX/deployed" 2>/dev/null
	;;
release)
	case $2 in
	list) cat "$FX/list.json" ;;
	delete) echo "$3" >>"$FX/deleted" ;;
	esac
	;;
esac
EOF2
	chmod +x "$root/helper/gh"
	: >"$fx/deleted"
	local rows=() entry tag age pre draft
	# tag age-in-days prerelease draft
	for entry in \
		"main-1-000000000001 30 true false" "main-2-000000000002 20 true false" \
		"main-3-000000000003 10 true false" "main-4-000000000004 40 true false" \
		"main-5-000000000005 50 true false" "main-6-000000000006 60 true false" \
		"main-9-000000000009 90 true true" "main-7-short 90 true false" \
		"v0.35.0-rc1 30 true false" "v0.35.0-rc2 30 true false" \
		"v0.35.0-rc3 30 true false" "v0.35.0-rc4 30 true false" \
		"v0.36.0 90 true false" "v0.34.0 100 false false" "v0.33.0 400 false false"; do
		read -r tag age pre draft <<<"$entry"
		rows+=("$(jq -n --arg t "$tag" --argjson age "$age" --argjson pre "$pre" --argjson draft "$draft" --argjson now "$now" \
			'{tagName: $t, isPrerelease: $pre, isDraft: $draft, publishedAt: (($now - $age * 86400) | todate)}')")
	done
	printf '%s\n' "${rows[@]}" | jq -s . >"$fx/list.json"
	echo v0.35.0-rc1 >"$fx/deployed"
}
prune() { PATH=$root/helper:$PATH GH_REPO=o/r NOW=$now "$scripts/prune-candidates.sh" "$@" 2>&1; }
deleted() { sort "$fx/deleted" | tr '\n' ' '; }

t_prune_deletes_old_candidates_only() {
	setup
	prune_fixture
	# Window 14 days, newest 2 of each kind: main-6 and main-5 are the newest (by number, not age),
	# rc3 and rc4 the newest rcs, rc1 is what the pool is deployed from, main-3 is young.
	out=$(prune --days 14 --keep 2)
	status=$?
	check "exit 0" status_is 0
	check "the old, undeployed, unheld candidates are deleted; nothing else" \
		test "$(deleted)" = "main-1-000000000001 main-2-000000000002 main-4-000000000004 v0.35.0-rc2 "
	check "says what it did" out_has "pruned 4"
}

t_prune_never_touches_releases_drafts_or_odd_tags() {
	setup
	prune_fixture
	out=$(prune --days 0 --keep 1)
	check "no release, draft, non-candidate pre-release or malformed tag" \
		not grep -qE '^(v0\.34\.0|v0\.33\.0|v0\.36\.0|main-9-000000000009|main-7-short)$' "$fx/deleted"
	check "the newest of each kind and the deployed one stay" \
		not grep -qE '^(main-6-000000000006|v0\.35\.0-rc4|v0\.35\.0-rc1)$' "$fx/deleted"
	check "the others go, window 0" test "$(deleted)" = "main-1-000000000001 main-2-000000000002 main-3-000000000003 main-4-000000000004 main-5-000000000005 v0.35.0-rc2 v0.35.0-rc3 "
}

t_prune_dry_run_deletes_nothing() {
	setup
	prune_fixture
	out=$(prune --dry-run --days 14 --keep 2)
	check "nothing deleted" test ! -s "$fx/deleted"
	check "lists what it would delete" out_has "would prune main-1-000000000001"
	check "lists the release candidate" out_has "would prune v0.35.0-rc2"
	check "does not list a kept one" not out_has "would prune main-3-"
	check "counts" out_has "would have pruned 4"
}

t_prune_protects_what_it_is_told_to() {
	setup
	prune_fixture
	out=$(prune --days 14 --keep 2 --protect main-4-000000000004 --protect v0.35.0-rc2)
	check "held tags stay" test "$(deleted)" = "main-1-000000000001 main-2-000000000002 "
}

t_prune_deletes_nothing_when_deployments_are_unreadable() {
	setup
	prune_fixture
	: >"$fx/deployments-fail"
	status=0
	out=$(prune --days 0 --keep 1) || status=$?
	check "fails" test "$status" != 0
	check "nothing deleted" test ! -s "$fx/deleted"
}

t_prune_refuses_nonsense_settings() {
	setup
	prune_fixture
	status=0
	out=$(prune --keep 0) || status=$?
	check "keep 0 refused" test "$status" != 0
	status=0
	out=$(prune --days soon) || status=$?
	check "days must be a number" test "$status" != 0
	check "nothing deleted" test ! -s "$fx/deleted"
}

# The hard requirement: a machine on `stable` never installs a candidate (a pre-release, a release
# candidate or a main build), whatever the tags, the releases feed or the deployments' order say.
t_stable_never_installs_a_candidate() {
	setup
	binary v1.2.3
	# The feed, newest first, full of candidates with higher versions, some labelled as releases.
	main_candidate 999 abcdef012345 9.9.9
	rc_release v9.0.0-rc1
	release v9.9.9 v9.9.9 candidate.yml refs/tags/v9.9.9
	feed v9.9.9 false
	release v9.9.8 v9.9.8-main.5+aaaaaaaaaaaa candidate.yml refs/heads/main
	feed v9.9.8 true
	# The deployments API: a candidate first, then a candidate posing as a release, then an older
	# release candidate, in this order and in the reverse one.
	deployment 4 main-999-abcdef012345
	deployment 3 v9.9.9
	deployment 2 v9.0.0-rc1
	run_agent
	check "newest deployment a main candidate: refused" status_is 1
	check "nothing installed" installed_is v1.2.3
	check "nothing downloaded" no_downloads

	setup
	binary v1.2.3
	main_candidate 999 abcdef012345 9.9.9
	release v9.9.9 v9.9.9 candidate.yml refs/tags/v9.9.9
	feed v9.9.9 false
	deployment 3 v9.9.9
	run_agent
	check "a candidate named like a release: refused" status_is 1
	check "still v1.2.3" installed_is v1.2.3
	check "its provenance is not a release's" out_has "no provenance from release.yml"

	setup
	binary v1.2.3
	rc_release v9.0.0-rc1
	deployment 2 v9.0.0-rc1
	deployment 1 main-999-abcdef012345
	run_agent
	check "a release candidate: refused" status_is 1
	check "still v1.2.3 again" installed_is v1.2.3
	check "nothing downloaded again" no_downloads

	# A genuine release first, candidates behind it: the release is installed, the candidates never.
	setup
	binary v1.2.3
	stable_release v1.2.4
	main_candidate 999 abcdef012345 9.9.9
	rc_release v9.0.0-rc1
	deployment 3 v1.2.4
	deployment 2 v9.0.0-rc1
	deployment 1 main-999-abcdef012345
	run_agent
	check "the release is installed" installed_is v1.2.4
	check "only the release was downloaded" test "$(downloads)" = 1
	check "no candidate fetched" not grep -qE 'release download (main-|v9)' "$fx/calls"
}

for t in $(declare -F | awk '$3 ~ /^t_/ {print $3}'); do
	CURRENT=${t#t_}
	"$t"
done

echo "deploy-test: $passed passed; 0 skipped; $failed failed"
((failed == 0))
