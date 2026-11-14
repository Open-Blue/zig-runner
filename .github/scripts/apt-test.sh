#!/usr/bin/env bash
# Tests apt.sh against an archive that is down, in a container of the runner's default image
# (ubuntu:24.04, as pinned in runner/src/dagger.zig): the four hosts of Ubuntu's archive are made to
# refuse connections, as they failed on 2026-11-11, and the script must fall back to a mirror, keep
# apt's keyrings, and install.
#
# Hermetic: the archive and the mirror are one signed repository (a test key, one tiny package named
# tree) served by a busybox container on a private --internal Docker network, which the test
# containers join alone, so nothing here reaches the internet (the image must be present or
# pullable). The test key replaces Ubuntu's keyring in the throwaway test containers, so apt.sh's
# promise, that the sources keep their Signed-By keyring and it is never touched, is still checked.
# The network aliases make the four archive hosts answer (the "archive up" case); --add-host makes
# them refuse (the "down" cases). Needs Docker, gpg and dpkg-deb on the host. The server answers at
# /ubuntu/ and /ubuntu-ports/ (the image's architecture picks which the mirror URL uses), so an
# arm64 image's ports.ubuntu.com sources work as the amd64 image's.
#
# apt-test.sh --real-mirrors does the one thing this test no longer does: probe, with curl, the
# InRelease of every suite (release, -updates, -backports, -security of noble and resolute) on every
# default mirror of apt.sh, for both architectures. It needs the internet and a public mirror may be
# down, so it is not part of CI's pull requests: analysis.yml runs it every night, and a failure
# there means a mirror dropped a pocket (or is out), to be looked at, not a broken change.
set -euo pipefail
cd "$(dirname "$0")/../.."

if [[ ${1:-} == --real-mirrors ]]; then
	failed=0
	for arch in amd64 arm64; do
		for mirror in $(.github/scripts/apt.sh mirror-list "$arch"); do
			for codename in noble resolute; do
				for suite in "$codename" "$codename-updates" "$codename-backports" "$codename-security"; do
					url=${mirror}dists/$suite/InRelease
					if curl -fsS -o /dev/null --max-time 15 --retry 2 --retry-delay 2 "$url"; then
						echo "ok   $url"
					else
						echo "FAIL $url" >&2
						failed=1
					fi
				done
			done
		done
	done
	exit "$failed"
fi

image=$(tr -d '\n' <runner/src/dagger.zig |
	grep -oE '"ubuntu:[A-Za-z0-9._-]+" *\+\+ *"@sha256:[a-f0-9]{64}"' | tr -d '" +')
# The server's image: tiny, and already on the runners (alpine and busybox are both small).
server_image=busybox:1.38@sha256:a46257e06c82ad85242d0d38077d0a52d9896389ca60a1a59d3463db586e5fa4
archive_hosts=(archive.ubuntu.com azure.archive.ubuntu.com security.ubuntu.com ports.ubuntu.com)
down=()
for host in "${archive_hosts[@]}"; do
	down+=(--add-host "$host:127.0.0.1")
done

work=$(mktemp -d)
net=apt-test-$$
server=apt-test-server-$$
# Every container this run starts carries the label, so an interrupt mid-test leaves none behind.
label=apt-test=$$
cleanup() {
	trap - EXIT INT TERM
	local ids
	ids=$(docker ps -aq --filter "label=$label" 2>/dev/null || true)
	# shellcheck disable=SC2086 # ids are hex words
	[[ -z $ids ]] || docker rm -f $ids >/dev/null 2>&1 || echo "apt-test: could not remove containers: $ids" >&2
	if docker network inspect "$net" >/dev/null 2>&1; then
		docker network rm "$net" >/dev/null || echo "apt-test: could not remove network $net" >&2
	fi
	GNUPGHOME=$work/gnupg gpgconf --kill all >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# The repository, for every suite and component of the image's sources (apt updates them all and
# --error-on=any fails on a missing one); only main carries a package.
codename=noble
arch=$(docker run --rm --network none "$image" dpkg --print-architecture)
# Ubuntu serves arm64 (and the other non-amd64) from ubuntu-ports.
mirror_path=ubuntu
[[ $arch == amd64 ]] || mirror_path=ubuntu-ports
repo=$work/repo/ubuntu
export GNUPGHOME=$work/gnupg
mkdir -m 700 "$GNUPGHOME"
gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
	--quick-generate-key 'apt-test <apt-test@example.invalid>' ed25519 sign never
gpg --batch --export >"$work/test-keyring.gpg"

mkdir -p "$work/pkg/DEBIAN" "$work/pkg/usr/bin" "$repo/pool/main/t/tree"
# One tree, under both names the archives use.
ln -s ubuntu "$work/repo/ubuntu-ports"
printf '%s\n' 'Package: tree' 'Version: 99.0-apt-test' 'Architecture: all' \
	'Maintainer: apt-test <apt-test@example.invalid>' 'Description: apt-test stand-in for tree' \
	>"$work/pkg/DEBIAN/control"
printf '%s\n' '#!/bin/sh' 'echo "tree v99.0-apt-test"' >"$work/pkg/usr/bin/tree"
chmod 755 "$work/pkg/usr/bin/tree"
dpkg-deb --root-owner-group -Zgzip -b "$work/pkg" "$repo/pool/main/t/tree/tree_99.0-apt-test_all.deb" >/dev/null
deb=pool/main/t/tree/tree_99.0-apt-test_all.deb

for suite in "$codename" "$codename-updates" "$codename-backports" "$codename-security"; do
	dir=$repo/dists/$suite
	hashes=
	for component in main universe restricted multiverse; do
		mkdir -p "$dir/$component/binary-$arch"
		index=$dir/$component/binary-$arch/Packages
		if [[ $component == main ]]; then
			{
				cat "$work/pkg/DEBIAN/control"
				printf '%s\n' "Filename: $deb" "Size: $(stat -c %s "$repo/$deb")" \
					"SHA256: $(sha256sum "$repo/$deb" | cut -d' ' -f1)"
			} >"$index"
		else
			: >"$index"
		fi
		hashes+=" $(sha256sum "$index" | cut -d' ' -f1) $(stat -c %s "$index") $component/binary-$arch/Packages"$'\n'
	done
	{
		printf '%s\n' "Origin: apt-test" "Suite: $suite" "Codename: $suite" "Date: $(date -u -R)" \
			"Architectures: $arch" "Components: main universe restricted multiverse" "SHA256:"
		printf '%s' "$hashes"
	} >"$dir/Release"
	gpg --batch --quiet --pinentry-mode loopback --passphrase '' --clearsign -o "$dir/InRelease" "$dir/Release"
done

docker network create --internal "$net" >/dev/null
alias_args=()
for host in "${archive_hosts[@]}"; do
	alias_args+=(--network-alias "$host")
done
docker run -d --name "$server" --label "$label" --network "$net" "${alias_args[@]}" -v "$work/repo:/www:ro" \
	"$server_image" httpd -f -p 80 -h /www >/dev/null
# The server's address on the private network: the mirror's URL, for the test containers and, for
# the host-side mirror-prefix, from the host (which can reach its own bridge).
mirror_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$net\").IPAddress}}" "$server")
mirror=http://$mirror_ip/$mirror_path/
mirror_re=${mirror_ip//./[.]}
curl -fsS -o /dev/null --max-time 5 --retry 20 --retry-connrefused --retry-delay 1 "${mirror}dists/$codename/InRelease"

# run_in NAME [docker options]: the checks in the container (stdin), as root, on a copy of apt.sh,
# on the private network, with the test key as the archive keyring.
run_in() {
	local name=$1
	shift
	echo "== $name"
	docker run --rm -i --label "$label" --network "$net" "$@" -e MIRROR="$mirror" \
		-v "$PWD/.github/scripts/apt.sh:/apt.sh:ro" \
		-v "$work/test-keyring.gpg:/usr/share/keyrings/ubuntu-archive-keyring.gpg:ro" \
		"$image" bash -euo pipefail
}

# The archive down and the first mirror too: install falls back to the second, the package arrives,
# the sources name it and keep their keyring (untouched), and no source still names the archive.
run_in "archive down, first mirror down" "${down[@]}" -e "APT_MIRRORS=http://127.0.0.1:9/$mirror_path/ $mirror" <<IN
sha256sum /usr/share/keyrings/ubuntu-archive-keyring.gpg >/before-keyring
/apt.sh install tree
tree --version | grep -q v99.0-apt-test
grep -qE '^URIs: http://$mirror_re/$mirror_path/' /etc/apt/sources.list.d/ubuntu.sources
grep -q '^Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' /etc/apt/sources.list.d/ubuntu.sources
! grep -E '^URIs:.*ubuntu[.]com' /etc/apt/sources.list.d/ubuntu.sources
sha256sum -c /before-keyring
IN

# The archive down, the first mirror up.
run_in "archive down" "${down[@]}" -e "APT_MIRRORS=$mirror" <<IN
sha256sum /usr/share/keyrings/ubuntu-archive-keyring.gpg >/before-keyring
/apt.sh install tree
tree --version | grep -q v99.0-apt-test
grep -qE '^URIs: http://$mirror_re/$mirror_path/' /etc/apt/sources.list.d/ubuntu.sources
grep -q '^Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' /etc/apt/sources.list.d/ubuntu.sources
! grep -E '^URIs:.*ubuntu[.]com' /etc/apt/sources.list.d/ubuntu.sources
sha256sum -c /before-keyring
IN

# The archive up (the server answers as its four hosts): nothing is rewritten.
run_in "archive up" -e "APT_MIRRORS=$mirror" <<'IN'
cp /etc/apt/sources.list.d/ubuntu.sources /before
/apt.sh install tree
tree --version | grep -q v99.0-apt-test
cmp /etc/apt/sources.list.d/ubuntu.sources /before
IN

# The hosted runners' layout: the sources name a mirror list (mirror+file:), which names the archive.
run_in "archive down, hosted runner layout" "${down[@]}" -e "APT_MIRRORS=$mirror" <<IN
sed -i 's#^URIs: .*#URIs: mirror+file:/etc/apt/apt-mirrors.txt#' /etc/apt/sources.list.d/ubuntu.sources
printf '%s\n' 'http://azure.archive.ubuntu.com/ubuntu/	priority:1' \
	'https://archive.ubuntu.com/ubuntu/	priority:2' \
	'https://security.ubuntu.com/ubuntu/	priority:3' >/etc/apt/apt-mirrors.txt
/apt.sh install tree
tree --version | grep -q v99.0-apt-test
grep -qE '$mirror_re' /etc/apt/apt-mirrors.txt
! grep -E 'ubuntu[.]com' /etc/apt/apt-mirrors.txt
IN

# Nothing works: the script fails and puts the sources back.
run_in "nothing works" "${down[@]}" <<'IN'
cp /etc/apt/sources.list.d/ubuntu.sources /before
if APT_MIRRORS="http://127.0.0.1:9/ubuntu/" /apt.sh install tree; then
	echo "install should have failed" >&2
	exit 1
fi
cmp /etc/apt/sources.list.d/ubuntu.sources /before
IN

# The container builds' prefix, computed on the host: empty with the archive up (the server, from the
# host, standing in for it); with it down (the probe pointed at a closed port) a rewrite, which a
# container's `sh -c` runs before its script.
echo "== prefix, archive up"
test -z "$(APT_PRIMARY_PROBE=${mirror}dists/$codename/InRelease APT_MIRRORS=$mirror .github/scripts/apt.sh mirror-prefix "$arch" "$codename")"
prefix=$(APT_PRIMARY_PROBE=http://127.0.0.1:9/InRelease APT_MIRRORS=$mirror .github/scripts/apt.sh mirror-prefix "$arch" "$codename")
test -n "$prefix"
echo "== prefix, archive down"
suffix=$(.github/scripts/apt.sh mirror-suffix)
# The build's script here is an install plus the lists' removal, as the runner's; afterwards the
# sources must be byte-identical to the image's, with no backup left.
docker run --rm --label "$label" --network "$net" "${down[@]}" \
	-v "$work/test-keyring.gpg:/usr/share/keyrings/ubuntu-archive-keyring.gpg:ro" "$image" \
	sh -c "cp -a /etc/apt /before-apt && ${prefix}apt-get update -q &&
	apt-get install -y -q tree >/dev/null && tree --version && rm -rf /var/lib/apt/lists/*${suffix} &&
	diff -r /before-apt /etc/apt && test ! -e /var/tmp/zig-runner-apt-orig && echo sources-restored" | grep -q sources-restored
echo "apt-test: ok"
