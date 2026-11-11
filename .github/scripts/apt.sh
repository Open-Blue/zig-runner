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

# The first mirror that answers is used. Kept to ones that carry every pocket (checked 2026-11-11
# for noble and resolute); ubuntu-ports (arm64) is not on kernel.org.
amd64_mirrors="http://mirrors.edge.kernel.org/ubuntu/ http://mirror.us.leaseweb.net/ubuntu/"
arm64_mirrors="http://mirrors.ocf.berkeley.edu/ubuntu-ports/ http://ftp.tu-chemnitz.de/pub/linux/ubuntu-ports/"

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

answers() {
	curl -fsS -o /dev/null --max-time 10 --retry 2 --retry-delay 1 "$1" 2>/dev/null
}

# The sed command that points every Ubuntu archive URI at MIRROR, over the source files in DIR.
rewrite_command() {
	printf '%s' "for f in $2/sources.list $2/sources.list.d/*.sources $2/sources.list.d/*.list; do " \
		"[ -f \"\$f\" ] && sed -i -E 's#$official#$1#g' \"\$f\"; done; true"
}

mirror_prefix() {
	local arch=${1:?arch} codename=${2:?codename} mirror
	answers "$(primary_probe "$arch" "$codename")" && return 0
	for mirror in $(mirrors_for "$arch"); do
		if answers "${mirror}dists/$codename/InRelease"; then
			printf '%s && ' "$(rewrite_command "$mirror" /etc/apt)"
			return 0
		fi
	done
}

apt_install() {
	local flags=() arch mirror saved sources
	while [[ ${1:-} == -* ]]; do
		flags+=("$1")
		shift
	done
	(($# > 0)) || {
		echo "apt.sh install: no packages" >&2
		exit 2
	}
	arch=$(dpkg --print-architecture)

	# One apt-get update and install, with its own timeouts: a host that does not answer fails in
	# a minute, not in apt's default of several.
	attempt() {
		local opts=(-o Acquire::Retries=3 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20)
		apt-get update -q --error-on=any "${opts[@]}" &&
			DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${flags[@]}" "${opts[@]}" "$@"
	}

	attempt "$@" && return 0

	# The originals, kept so each mirror is tried from them, and put back when none works.
	saved=$(mktemp -d)
	sources=("$apt_dir/sources.list" "$apt_dir"/sources.list.d/*.sources "$apt_dir"/sources.list.d/*.list)
	local f
	for f in "${sources[@]}"; do
		[[ -f $f ]] && cp -p "$f" "$saved/$(echo "$f" | tr / _)"
	done
	for mirror in $(mirrors_for "$arch"); do
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
*)
	echo "usage: apt.sh install [apt-get options] PACKAGE... | apt.sh mirror-prefix ARCH CODENAME" >&2
	exit 2
	;;
esac
