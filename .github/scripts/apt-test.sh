#!/usr/bin/env bash
# Tests apt.sh against an archive that is down, in a container of the runner's default image
# (ubuntu:24.04, as pinned in runner/src/dagger.zig): the four hosts of Ubuntu's archive are made to
# refuse connections, as they failed on 2026-11-11, and the script must fall back to a mirror, keep
# apt's keyrings, and install. It needs Docker and the network (the mirrors are real).
set -euo pipefail
cd "$(dirname "$0")/../.."

image=$(tr -d '\n' <runner/src/dagger.zig |
	grep -oE '"ubuntu:[A-Za-z0-9._-]+" *\+\+ *"@sha256:[a-f0-9]{64}"' | tr -d '" +')
down=()
for host in archive.ubuntu.com azure.archive.ubuntu.com security.ubuntu.com ports.ubuntu.com; do
	down+=(--add-host "$host:127.0.0.1")
done

# run_in NAME [docker options]: the checks in the container (stdin), as root, on a copy of apt.sh.
run_in() {
	local name=$1
	shift
	echo "== $name"
	docker run --rm -i "$@" -v "$PWD/.github/scripts/apt.sh:/apt.sh:ro" "$image" bash -euo pipefail
}

# The archive down: install falls back, the package arrives, the sources name a mirror and keep
# their keyring, and no source still names the archive.
run_in "archive down" "${down[@]}" <<'IN'
/apt.sh install tree
tree --version
grep -qE '^URIs: .*(kernel[.]org|leaseweb)' /etc/apt/sources.list.d/ubuntu.sources
grep -q '^Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' /etc/apt/sources.list.d/ubuntu.sources
! grep -E '^URIs:.*ubuntu[.]com' /etc/apt/sources.list.d/ubuntu.sources
IN

# The archive up: nothing is rewritten.
run_in "archive up" <<'IN'
cp /etc/apt/sources.list.d/ubuntu.sources /before
/apt.sh install tree
tree --version
cmp /etc/apt/sources.list.d/ubuntu.sources /before
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

# The container builds' prefix, computed on the host: empty with the archive up; with it down (the
# probe pointed at a closed port) a rewrite, which a container's `sh -c` runs before its script.
echo "== prefix, archive up"
test -z "$(.github/scripts/apt.sh mirror-prefix amd64 noble)"
prefix=$(APT_PRIMARY_PROBE=http://127.0.0.1:9/InRelease .github/scripts/apt.sh mirror-prefix amd64 noble)
test -n "$prefix"
echo "== prefix, archive down"
docker run --rm "${down[@]}" "$image" sh -c "${prefix}apt-get update -q && apt-get install -y -q tree >/dev/null && tree --version"
echo "apt-test: ok"
