#!/usr/bin/env bash
# The libzstd the runner decompresses zstd layers with (runner/src/vendor/zstd), vendored from the
# release tarball, pinned by version and SHA-256 here. Only the decompressor's files, as upstream
# has them (lib/ is the directory's root); the shims for a build without a libc are the runner's
# own (runner/src/vendor/shim).
#
#   vendor-zstd.sh           replaces runner/src/vendor/zstd with the pinned release's files
#   vendor-zstd.sh --check   fails when the vendored files differ from it (CI's "Workflows" job)
#
# To update: change `version` and `sha256` (the release's own .sha256 file has it), run this, and
# build both targets (zig-modules.sh and runner/build.zig list the C files). A fetch that fails
# exits 75 (EX_TEMPFAIL), which the CI step tries again.
set -euo pipefail
cd "$(dirname "$0")/../.."

version=1.5.7
sha256=eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3
dest=runner/src/vendor/zstd
files=(
	LICENSE COPYING
	lib/zstd.h lib/zstd_errors.h
	lib/common/{allocations.h,bits.h,bitstream.h,compiler.h,cpu.h,debug.c,debug.h,entropy_common.c}
	lib/common/{error_private.c,error_private.h,fse.h,fse_decompress.c,huf.h,mem.h,portability_macros.h}
	lib/common/{xxhash.c,xxhash.h,zstd_common.c,zstd_deps.h,zstd_internal.h,zstd_trace.h}
	lib/decompress/{huf_decompress.c,zstd_ddict.c,zstd_ddict.h,zstd_decompress.c,zstd_decompress_block.c}
	lib/decompress/{zstd_decompress_block.h,zstd_decompress_internal.h}
)

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
curl -fsSL --retry 2 -o "$scratch/zstd.tar.gz" \
	"https://github.com/facebook/zstd/releases/download/v$version/zstd-$version.tar.gz" || {
	echo "vendor-zstd: could not fetch zstd $version" >&2
	exit 75
}
echo "$sha256  $scratch/zstd.tar.gz" | sha256sum -c --quiet - || {
	echo "vendor-zstd: the zstd $version tarball is not the one pinned here" >&2
	exit 1
}
tar -xzf "$scratch/zstd.tar.gz" -C "$scratch"
src=$scratch/zstd-$version

# Where upstream's file lands: lib/ is the directory's root.
vendored() { echo "$dest/${1#lib/}"; }

if [[ ${1:-} == --check ]]; then
	status=0
	for f in "${files[@]}"; do
		cmp -s "$src/$f" "$(vendored "$f")" || {
			echo "vendor-zstd: $(vendored "$f") is not zstd $version's $f" >&2
			status=1
		}
	done
	# Nothing else may be in the directory.
	expected=$(for f in "${files[@]}"; do vendored "$f"; done | sort)
	found=$(find "$dest" -type f | sort)
	[[ $expected == "$found" ]] || {
		echo "vendor-zstd: $dest holds files other than the pinned list:" >&2
		diff <(echo "$expected") <(echo "$found") >&2 || true
		status=1
	}
	((status == 0)) && echo "vendor-zstd: $dest is zstd $version"
	exit "$status"
fi
rm -rf "$dest"
for f in "${files[@]}"; do
	mkdir -p "$(dirname "$(vendored "$f")")"
	cp "$src/$f" "$(vendored "$f")"
done
echo "vendor-zstd: $dest is zstd $version"
