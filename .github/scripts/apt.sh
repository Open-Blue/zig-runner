#!/usr/bin/env bash
# apt for CI, which keeps working when Ubuntu's own archive does not (archive.ubuntu.com,
# azure.archive.ubuntu.com, security.ubuntu.com and ports.ubuntu.com all failed to resolve for
# hours on 2026-11-11, and every job that used apt failed with them).
#
#   sudo .github/scripts/apt.sh install [apt-get options] PACKAGE[=VERSION]...
#       apt-get update and install against the sources the machine has. If either fails, the
#       sources are pointed at the first fallback mirror for the machine's architecture, main
#       archive and -security alike, and both are run again; then at the next one. When none
#       works the sources are put back as they were and the script fails.
#   apt.sh mirror-prefix ARCH CODENAME
#       For a container build, which has no apt.sh: prints a shell command, ending in "&& ", that
#       repoints the container's sources at a fallback mirror, or prints nothing when the primary
#       archive answers (or no mirror does). A caller puts it in front of the build's own script.
#   apt.sh mirror-suffix
#       The command, starting with " && ", that undoes mirror-prefix: after the build's script, so a
#       published image's sources are exactly what they would be without the fallback.
#   apt.sh probe ARCH CODENAME
#       One line on how the primary archive answers now (status and time, or curl's error), for a
#       job waiting on a build to log. Always exits 0.
#
# Every choice, and every probe behind it, is said on stderr (`apt.sh: …`), so a job's log names a
# slow or silent archive and the mirror taken instead of showing a build that seems to hang.
#
# The trust is unchanged. Only the URIs are rewritten: the keyrings (Signed-By) stay Ubuntu's, and
# apt checks every index and package against them, so a mirror can serve only what Ubuntu signed.
# The mirrors are plain http as Ubuntu's own archive is: a fresh container has no ca-certificates
# to check https with. They carry the same pockets as the archive (release, -updates, -security),
# so a pinned package=version resolves as it does there.
#
# Environment, for the test (apt-test.sh): APT_DIR (default /etc/apt), APT_MIRRORS (space
# separated, replaces the list for the architecture), APT_PRIMARY_PROBE (the URL that tells whether
# the primary archive answers).
set -euo pipefail

apt_dir=${APT_DIR:-/etc/apt}
# Where mirror-prefix keeps the container's own sources, until mirror-suffix puts them back.
backup=/var/tmp/zig-runner-apt-orig

# The first mirror that answers is used. Kept to ones that carry every pocket (checked 2026-11-11
# for noble and resolute); ubuntu-ports (arm64) is not on kernel.org.
amd64_mirrors="http://mirrors.edge.kernel.org/ubuntu/ http://mirror.us.leaseweb.net/ubuntu/"
arm64_mirrors="http://mirrors.ocf.berkeley.edu/ubuntu-ports/ http://ftp.tu-chemnitz.de/pub/linux/ubuntu-ports/"

# GitHub's hosted runners list the archive in /etc/apt/apt-mirrors.txt (azure.archive first, then
# archive and security, which sources.list.d/ubuntu.sources names as mirror+file:), so that file is
# rewritten too.
#
# The hosts of Ubuntu's own archive, as they appear in a source's URI (regional and cloud names
# included), and nothing else: other repositories on the machine are left alone.
official='https?://[A-Za-z0-9.]*(archive|security|ports)[.]ubuntu[.]com/ubuntu(-ports)?/?'

mirrors_for() {
	if [[ -n ${APT_MIRRORS:-} ]]; then
		echo "$APT_MIRRORS"
		return
	fi
	case $1 in
	amd64) echo "$amd64_mirrors" ;;
	arm64) echo "$arm64_mirrors" ;;
	esac
}

# The path of the archive's own index for CODENAME, on the primary archive of ARCH.
primary_probe() {
	if [[ -n ${APT_PRIMARY_PROBE:-} ]]; then
		echo "$APT_PRIMARY_PROBE"
	elif [[ $1 == amd64 ]]; then
		echo "http://archive.ubuntu.com/ubuntu/dists/$2/InRelease"
	else
		echo "http://ports.ubuntu.com/ubuntu-ports/dists/$2/InRelease"
	fi
}

# Whether URL answers within seconds. apt itself is slow to give up on a name that does not
# resolve (minutes, with its retries), so each archive and mirror is asked with curl first. With no
# curl (a bare container) everything is taken to answer, and apt's own failure decides.
#
# What it found is left in `probe_said` (the URL, its HTTP status and time, or curl's error), for the
# job's log: a slow or silent archive is then named there, not left to look like a hung build.
answers() {
	if ! command -v curl >/dev/null; then
		probe_said="$1: not probed (no curl), taken to answer"
		return 0
	fi
	local said errors rc=0
	errors=$(mktemp)
	said=$(curl -fsS -o /dev/null -w '%{http_code} in %{time_total} s' --max-time 10 --retry 2 --retry-delay 1 "$1" 2>"$errors") || rc=$?
	if ((rc == 0)); then
		probe_said="$1 answered: $said"
	else
		# curl says its error once per try: the last is enough. It retries only what may pass (a
		# timeout, a refused connection, 5xx), so a 404 is one try.
		probe_said="$1 failed (curl exit $rc, last try $said: $(tail -n 1 "$errors")); up to 3 tries of at most 10 s each"
	fi
	rm -f "$errors"
	return "$rc"
}

# The sed command that points every Ubuntu archive URI at MIRROR, over the source files in DIR.
rewrite_command() {
	printf '%s' "mkdir -p $backup && cp -a --parents $2/sources.list $2/sources.list.d $2/apt-mirrors.txt $backup 2>/dev/null; " \
		"for f in $2/sources.list $2/sources.list.d/*.sources $2/sources.list.d/*.list $2/apt-mirrors.txt; do " \
		"[ -f \"\$f\" ] && sed -i -E 's#$official#$1#g' \"\$f\"; done; true"
}

# The command that puts a container's sources back as mirror-prefix found them, for the end of a
# build whose image is published: the image must not keep the mirror (only the lists, which the
# provision script removes itself). Printed with its " && ", to go after the build's own script.
mirror_suffix() {
	printf ' && %s' "cp -a $backup/${1:?apt dir}/. $1/ && rm -rf $backup"
}

# Its choice and every probe behind it are said on stderr, in the job's log; stdout is the command.
mirror_prefix() {
	local arch=${1:?arch} codename=${2:?codename} mirror
	if answers "$(primary_probe "$arch" "$codename")"; then
		echo "apt.sh: $probe_said; the container keeps its own sources" >&2
		return 0
	fi
	echo "apt.sh: $probe_said" >&2
	for mirror in $(mirrors_for "$arch"); do
		if answers "${mirror}dists/$codename/InRelease"; then
			echo "apt.sh: $probe_said; the container's sources are pointed at $mirror" >&2
			printf '%s && ' "$(rewrite_command "$mirror" /etc/apt)"
			return 0
		fi
		echo "apt.sh: $probe_said" >&2
	done
	echo "apt.sh: no fallback mirror answered either; the container keeps its own sources" >&2
}

# One line on how the primary archive of ARCH answers now, for a waiting job's log; never fails.
probe_primary() {
	answers "$(primary_probe "${1:?arch}" "${2:?codename}")" || true
	echo "$probe_said"
}

apt_install() {
	local flags=() arch codename mirror saved sources
	while [[ ${1:-} == -* ]]; do
		flags+=("$1")
		shift
	done
	(($# > 0)) || {
		echo "apt.sh install: no packages" >&2
		exit 2
	}
	arch=$(dpkg --print-architecture)

	# One apt-get update and install, each bounded, so a dead archive costs minutes, not the job.
	attempt() {
		local opts=(-o Acquire::Retries=2 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20)
		timeout 300 apt-get update -q --error-on=any "${opts[@]}" &&
			DEBIAN_FRONTEND=noninteractive timeout 600 apt-get install -y -q "${flags[@]}" "${opts[@]}" "$@"
	}

	codename=$(sed -n 's/^VERSION_CODENAME=//p' /etc/os-release)

	# The sources as configured, when their archive answers.
	if answers "$(primary_probe "$arch" "$codename")"; then
		echo "apt.sh: $probe_said; installing from the configured sources" >&2
		attempt "$@" && return 0
		echo "apt.sh: apt-get failed against the configured sources" >&2
	else
		echo "apt.sh: $probe_said" >&2
	fi

	# The originals, kept so each mirror is tried from them, and put back when none works.
	saved=$(mktemp -d)
	sources=("$apt_dir/sources.list" "$apt_dir"/sources.list.d/*.sources "$apt_dir"/sources.list.d/*.list "$apt_dir/apt-mirrors.txt")
	local f
	for f in "${sources[@]}"; do
		[[ -f $f ]] && cp -p "$f" "$saved/$(echo "$f" | tr / _)"
	done
	for mirror in $(mirrors_for "$arch"); do
		if ! answers "${mirror}dists/$codename/InRelease"; then
			echo "apt.sh: $probe_said" >&2
			continue
		fi
		echo "apt.sh: $probe_said" >&2
		echo "::warning::apt failed against the configured sources: trying $mirror"
		for f in "${sources[@]}"; do
			[[ -f $f ]] && sed -E "s#$official#$mirror#g" "$saved/$(echo "$f" | tr / _)" >"$f"
		done
		if attempt "$@"; then
			rm -rf "$saved"
			return 0
		fi
	done
	for f in "${sources[@]}"; do
		[[ -f $f ]] && cp -p "$saved/$(echo "$f" | tr / _)" "$f"
	done
	rm -rf "$saved"
	echo "apt.sh: no archive or mirror worked" >&2
	return 1
}

case ${1:-} in
install)
	shift
	apt_install "$@"
	;;
mirror-prefix)
	shift
	mirror_prefix "$@"
	;;
mirror-suffix)
	mirror_suffix /etc/apt
	;;
probe)
	shift
	probe_primary "$@"
	;;
mirror-list)
	# The default mirrors of ARCH, one per line (apt-test.sh --real-mirrors probes them).
	APT_MIRRORS='' mirrors_for "${2:?ARCH}" | tr ' ' '\n'
	;;
*)
	echo "usage: apt.sh install [apt-get options] PACKAGE... | apt.sh mirror-prefix ARCH CODENAME | apt.sh probe ARCH CODENAME | apt.sh mirror-list ARCH" >&2
	exit 2
	;;
esac
