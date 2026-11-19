#!/usr/bin/env bash
# What the runner image gives a job, said in its log as facts, one line each, and a failure that
# names every tool the job needs and the image lacks (a missing tool otherwise fails as the test
# that uses it, which gets the blame):
#
#   image-preflight.sh TOOL...    TOOL must be there; TOOL? is printed, and its absence is no failure
#
# The runner image (ImageOS, ImageVersion), the kernel, the page size, whether /sys/fs/cgroup is
# cgroup v2, then each tool's path and version. The native backend's tests use `ip netns`,
# unshare, python3 (the services' and the network tests' helpers) and nsenter; docker is the
# overlayfs step's, the database's and the image builds'. nft is printed where asked: the backend
# speaks netlink itself, so the binary is a fact to know, not a need.
set -uo pipefail

# tool_version TOOL: the first line of the tool's own version output.
tool_version() {
	case $1 in
	ip) ip -V 2>&1 ;;
	docker) docker version --format 'client {{.Client.Version}}, server {{.Server.Version}}' 2>&1 ||
		docker --version 2>&1 ;;
	*) "$1" --version 2>&1 ;;
	esac | head -n 1
}

echo "preflight: image ${ImageOS:-unknown} ${ImageVersion:-unknown} (runner ${RUNNER_ENVIRONMENT:-unknown}, ${RUNNER_ARCH:-$(uname -m)})"
echo "preflight: kernel $(uname -r)"
echo "preflight: page size $(getconf PAGESIZE 2>/dev/null || echo unknown) bytes"
echo "preflight: cgroup filesystem $(stat -fc %T /sys/fs/cgroup 2>/dev/null || echo missing) (cgroup2fs is v2)"

missing=()
for spec in "$@"; do
	tool=${spec%\?}
	optional=false
	[[ $spec == *'?' ]] && optional=true
	if path=$(command -v "$tool"); then
		echo "preflight: $tool $path: $(tool_version "$tool")"
	elif $optional; then
		echo "preflight: $tool not installed (optional)"
	else
		echo "preflight: $tool MISSING"
		missing+=("$tool")
	fi
done

if ((${#missing[@]} > 0)); then
	echo "::error title=Runner image lacks a tool::${missing[*]} not installed on this runner (image ${ImageOS:-unknown} ${ImageVersion:-unknown}); the tests that need it would fail naming themselves, not the image"
	echo "preflight: missing: ${missing[*]}" >&2
	exit 1
fi
echo "preflight: all required tools present"
