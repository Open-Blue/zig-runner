#!/usr/bin/env bash
# Compares the native Dockerfile builder (runner/src/native/dockerfile.zig) with BuildKit: every
# fixture of runner/tools/dockerfile_oracle built by `docker build` and by the runner, the
# filesystems (paths, modes, owners, sizes, content hashes, link targets) and the image configs
# (env, entrypoint, cmd, working directory, user) compared. A fixture's differences.txt lists what
# the native build does differently on purpose (docs/native-backend.md); any other difference
# fails. The comparison itself is runner/src/native/dockerfile_oracle.zig's test, which needs
# root (owners): this prepares what it reads, then runs it as root with sudo, or does only the
# first half with PREPARE_ONLY=1 and says where it left it, for a container to run the second.
#
#   dockerfile-diff.sh [name filter]    needs Docker, Python 3 and (for the second half) sudo
#
# DOCKERFILE_ORACLE_DIR says where to prepare (default a new temporary directory, removed after).
set -euo pipefail
cd "$(dirname "$0")/../.."

fixtures=runner/tools/dockerfile_oracle
only=${1:-}
work=${DOCKERFILE_ORACLE_DIR:-}
if [[ -z $work ]]; then
	work=$(mktemp -d)
	trap 'sudo rm -rf "$work"' EXIT
fi
mkdir -p "$work/bases" "$work/cases"
export DOCKER_BUILDKIT=1

# What `ADD <url>` downloads: a server on the host's docker0 address, one process for all cases.
addr_ip=$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')
mkdir -p "$work/www/dir"
head -c 3000 /dev/urandom >"$work/www/tool.bin"
echo "other file" >"$work/www/dir/other.txt"
python3 -u -m http.server 0 --bind "$addr_ip" --directory "$work/www" >"$work/www.log" 2>&1 &
server=$!
trap 'kill $server 2>/dev/null || true; [[ -n ${DOCKERFILE_ORACLE_DIR:-} ]] || sudo rm -rf "$work"' EXIT
for _ in $(seq 50); do
	port=$(sed -n 's/.*port \([0-9]*\).*/\1/p' "$work/www.log" | head -n 1)
	[[ -n $port ]] && break
	sleep 0.1
done
addr="$addr_ip:$port"

# The bases: each image's filesystem and config, from the same image the build starts from.
n=0
: >"$work/bases.txt"
while read -r ref; do
	[[ -n $ref ]] || continue
	n=$((n + 1))
	docker pull -q "$ref" >/dev/null
	printf 'FROM %s\n' "$ref" | docker build -q --output "type=tar,dest=$work/bases/$n.tar" - >/dev/null
	docker image inspect --format '{{json .}}' "$ref" >"$work/bases/$n.json"
	echo "$ref $n" >>"$work/bases.txt"
done <"$fixtures/bases.txt"

# The cases: BuildKit's filesystem and config for each.
for dir in "$fixtures"/*/; do
	name=$(basename "$dir")
	[[ $name == *"$only"* ]] || continue
	rm -rf "${work:?}/cases/$name"
	cp -r "$dir" "$work/cases/$name"
	sed -i "s/@ADDR@/$addr/g" "$work/cases/$name/ctx/Dockerfile"
	tag="zr-dockerfile-oracle-$name"
	docker build -q --no-cache --output "type=tar,dest=$work/cases/$name/expected.tar" "$work/cases/$name/ctx" >/dev/null
	docker build -q --no-cache -t "$tag" "$work/cases/$name/ctx" >/dev/null
	docker image inspect --format '{{json .}}' "$tag" >"$work/cases/$name/expected.json"
	docker rmi -f "$tag" >/dev/null
done

if [[ ${PREPARE_ONLY:-} == 1 ]]; then
	echo "prepared in $work (the server on $addr stops with this script)"
	trap - EXIT
	exit 0
fi

# The runner's builds, compared; as root. The test's own filter, so it is the only test run.
cd runner
sudo sysctl -q -w kernel.apparmor_restrict_unprivileged_userns=0 || true
ZIG_RUNNER_DOCKERFILE_ORACLE="$work" ZIG_RUNNER_DOCKERFILE_ORACLE_ONLY="$only" \
	ZIG_RUNNER_REQUIRE_NATIVE=1 ZIG_TEST_NATIVE_AS_ROOT=1 ZIG_TEST_SHARDS=1 \
	ZIG_TEST_FILTER="oracle: the Dockerfile builder" ../.github/scripts/zig-test.sh
