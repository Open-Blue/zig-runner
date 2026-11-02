#!/usr/bin/env bash
# Fills a native image store's stand-in (runner/src/native/images.zig) with the images the native
# services test runs (runner/src/native/services.zig, "postgres and redis from real images"):
# each image's filesystem, as `docker export` gives it, under <dir>/<reference>/rootfs, and its
# configuration under <dir>/<reference>/config.json. Until phase 3's native pull, this is how an
# operator makes one too (docs/native-backend.md, P6). CI's hosted test job runs it before the
# native tests' root pass and points ZIG_RUNNER_SERVICE_IMAGES at <dir>.
#
# The images are pinned by their multi-arch index digests and filed under their tags, which is
# what the test names. The filesystem is unpacked as root (sudo when not), so its files keep the
# image's owners: a service's entrypoint changes to its own user (postgres, redis) and must find
# its files as the image has them.
set -euo pipefail

dir=${1:?usage: native-service-images.sh <dir>}
images=(
	"postgres:17-alpine@sha256:266d3c257594e195b309ae9d1805e54c788f1d7b375f56bf6c367aac6c917e7b"
	"redis:7-alpine@sha256:8da19c7399dca900c6822a1cf30f9d2285585e2c4b457ff4095b0f4500054d3f"
)
as_root=()
if [[ $(id -u) != 0 ]]; then as_root=(sudo); fi

mkdir -p "$dir"
for pinned in "${images[@]}"; do
	tag=${pinned%@*}
	entry="$dir/${tag//\//+}"
	docker pull -q "$pinned" >/dev/null
	container=$(docker create "$pinned")
	"${as_root[@]}" mkdir -p "$entry/rootfs"
	docker export "$container" | "${as_root[@]}" tar -x -C "$entry/rootfs"
	docker rm -f "$container" >/dev/null
	docker image inspect --format '{{json .}}' "$pinned" | "${as_root[@]}" tee "$entry/config.json" >/dev/null
	echo "native-service-images: $tag in $entry"
done
