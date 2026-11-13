#!/usr/bin/env bash
# The zlib-ng the runner inflates gzip layers with (runner/src/vendor/zlib-ng), vendored from its git
# repository, pinned by tag and commit here (a commit names its tree: git checks it). Only the
# inflater's files and the headers they include, copied unchanged, and three headers zlib-ng's
# CMake would generate, made here as it makes them: zconf-ng.h and zlib_name_mangling-ng.h from
# their templates with nothing set, and zlib-ng.h from its template without a symbol prefix. The
# shims for a build without a libc are the runner's own (runner/src/vendor/shim).
#
#   vendor-zlib-ng.sh           replaces runner/src/vendor/zlib-ng with the pinned release's files
#   vendor-zlib-ng.sh --check   fails when the vendored files differ from it (CI's "Workflows" job)
#
# To update: change `tag` and `commit` (`git ls-remote https://github.com/zlib-ng/zlib-ng 2.3.3`),
# run this, and build both targets (zig-modules.sh and runner/build.zig list the C files, which
# arch_functions.h and functable.c may change). A fetch that fails exits 75 (EX_TEMPFAIL), which
# the CI step tries again.
set -euo pipefail
cd "$(dirname "$0")/../.."

tag=2.3.3
commit=12731092979c6d07f42da27da673a9f6c7b13586
dest=runner/src/vendor/zlib-ng
files=(
	adler32.c adler32_p.h arch/arm/acle_intrins.h arch/arm/adler32_neon.c arch/arm/arm_features.h
	arch/arm/arm_functions.h arch/arm/chunkset_neon.c arch/arm/neon_intrins.h arch_functions.h
	arch/generic/adler32_c.c arch/generic/adler32_fold_c.c arch/generic/chunk_128bit_perm_idx_lut.h
	arch/generic/chunk_256bit_perm_idx_lut.h arch/generic/chunk_permute_table.h
	arch/generic/compare256_p.h arch/generic/crc32_braid_c.c arch/generic/crc32_chorba_c.c
	arch/generic/crc32_fold_c.c arch/generic/generic_functions.h arch/x86/adler32_avx2_p.h
	arch/x86/adler32_avx512_p.h arch/x86/adler32_ssse3_p.h arch/x86/chorba_sse2.c
	arch/x86/chunkset_sse2.c arch/x86/crc32_fold_pclmulqdq_tpl.h arch/x86/crc32_fold_vpclmulqdq_tpl.h
	arch/x86/crc32_pclmulqdq_tpl.h arch/x86/x86_features.h arch/x86/x86_functions.h
	arch/x86/x86_intrins.h chunkset_tpl.h compare256_rle.h cpu_features.h crc32_braid_comb.c
	crc32_braid_comb_p.h crc32_braid_p.h crc32_braid_tbl.h crc32.c crc32.h deflate.h deflate_p.h
	fallback_builtins.h functable.c functable.h inffast_tpl.h inffixed_tbl.h inflate.c inflate.h
	inflate_p.h inftrees.c inftrees.h insert_string_tpl.h LICENSE.md match_tpl.h trees_emit.h trees.h
	trees_tbl.h zbuild.h zendian.h zmemory.h zutil.c zutil.h zutil_p.h
)

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
src=$scratch/zlib-ng
git init -q "$src"
git -C "$src" fetch -q --depth 1 https://github.com/zlib-ng/zlib-ng "$commit" || {
	echo "vendor-zlib-ng: could not fetch zlib-ng $tag" >&2
	exit 75
}
git -C "$src" checkout -q FETCH_HEAD
[[ $(git -C "$src" rev-parse HEAD) == "$commit" ]] || {
	echo "vendor-zlib-ng: the commit fetched is not $commit" >&2
	exit 1
}

# The generated headers, as CMake makes them for this build (no symbol prefix, nothing configured).
generated="$scratch/generated"
mkdir -p "$generated"
cp "$src/zconf-ng.h.in" "$generated/zconf-ng.h"
sed 's/@ZLIB_SYMBOL_PREFIX@//g' "$src/zlib-ng.h.in" >"$generated/zlib-ng.h"
cp "$src/zlib_name_mangling.h.empty" "$generated/zlib_name_mangling-ng.h"
if grep -q '@[A-Z_]*@' "$generated"/*.h; then
	echo "vendor-zlib-ng: a generated header still holds a template variable" >&2
	exit 1
fi

if [[ ${1:-} == --check ]]; then
	status=0
	for f in "${files[@]}"; do
		cmp -s "$src/$f" "$dest/$f" || {
			echo "vendor-zlib-ng: $dest/$f is not zlib-ng $tag's $f" >&2
			status=1
		}
	done
	for f in zconf-ng.h zlib-ng.h zlib_name_mangling-ng.h; do
		cmp -s "$generated/$f" "$dest/$f" || {
			echo "vendor-zlib-ng: $dest/$f is not the header zlib-ng $tag's template gives" >&2
			status=1
		}
	done
	# Nothing else may be in the directory.
	expected=$(printf '%s\n' "${files[@]}" zconf-ng.h zlib-ng.h zlib_name_mangling-ng.h | sort)
	found=$(cd "$dest" && find . -type f | sed 's|^\./||' | sort)
	[[ $expected == "$found" ]] || {
		echo "vendor-zlib-ng: $dest holds files other than the pinned list:" >&2
		diff <(echo "$expected") <(echo "$found") >&2 || true
		status=1
	}
	((status == 0)) && echo "vendor-zlib-ng: $dest is zlib-ng $tag"
	exit "$status"
fi
rm -rf "$dest"
for f in "${files[@]}"; do
	mkdir -p "$dest/$(dirname "$f")"
	cp "$src/$f" "$dest/$f"
done
cp "$generated"/*.h "$dest/"
echo "vendor-zlib-ng: $dest is zlib-ng $tag"
