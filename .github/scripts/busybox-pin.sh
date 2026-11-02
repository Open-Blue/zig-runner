#!/usr/bin/env bash
# Checks the busybox the runner puts into job containers, named in runner/src/dagger.zig
# (busybox_image) and run by Docker actions, service containers and output keys: CI's "Workflows"
# job runs this on every pull request. The pin must be the shape Renovate's manager reads
# (renovate.json; the literal is split over two lines with ++), still pullable, a multi-arch index
# covering both machines the runner deploys to (linux/amd64 and linux/arm64), and carry the applets
# the runner's scripts use. So a Renovate busybox pull request, or a re-wrapped literal that would
# blind Renovate, fails here, not on a runner. The address is read from the source: no second copy
# to keep in step. A fetch that fails exits 75 (EX_TEMPFAIL), which the CI step tries again.
set -euo pipefail
cd "$(dirname "$0")/../.."

source=runner/src/dagger.zig
# The constant's two lines joined, then the quotes, spaces and ++ dropped: busybox:<tag>@sha256:<hex>.
mapfile -t found < <(tr -d '\n' <"$source" |
	grep -oE '"busybox:[A-Za-z0-9._-]+" *\+\+ *"@sha256:[a-f0-9]{64}"' | tr -d '" +')
if ((${#found[@]} != 1)); then
	echo "busybox-pin: expected exactly one busybox_image in $source of the shape" \
		"\"busybox:<tag>\" ++ \"@sha256:<64 hex>\", as renovate.json reads it; found ${#found[@]}" >&2
	exit 1
fi
address=${found[0]}
echo "busybox-pin: $address"

# The index itself: the engine picks its platform from it, so both deploy targets must be listed.
index=$(docker buildx imagetools inspect --raw "$address") || {
	echo "busybox-pin: could not fetch $address from Docker Hub" >&2
	exit 75
}
if ! jq -e '
	(.mediaType == "application/vnd.oci.image.index.v1+json"
	 or .mediaType == "application/vnd.docker.distribution.manifest.list.v2+json")
	and ([.manifests[].platform | select(. != null) | "\(.os)/\(.architecture)/\(.variant // "")"]
	     | (index("linux/amd64/") != null and index("linux/arm64/v8") != null))' \
	<<<"$index" >/dev/null; then
	echo "busybox-pin: $address is not a multi-arch index listing linux/amd64 and linux/arm64/v8;" \
		"pin the index digest, which \`docker buildx imagetools inspect busybox:<tag>\` prints" >&2
	exit 1
fi

# The applets the runner's scripts run (dagger/docker.zig, services.zig, output_keys.zig), and
# mv -T, which the output store relies on.
applets=$(docker run --rm "$address" sh -c 'busybox --list && mkdir /a /b && mv -T /a /b') || {
	echo "busybox-pin: could not run $address (pull failed, or an applet the runner uses is missing)" >&2
	exit 75
}
for applet in sh mkdir printf env tcpsvd nc find mv rm cp touch chown cat wc; do
	grep -qx "$applet" <<<"$applets" || {
		echo "busybox-pin: $address has no $applet applet, which the runner's scripts use" >&2
		exit 1
	}
done
echo "busybox-pin: a multi-arch index with the applets the runner uses"
