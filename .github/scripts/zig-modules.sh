# shellcheck shell=bash
# The runner's module graph as runner/build.zig makes it, for compiling with the compiler directly
# instead of `zig build`, whose first step on a machine with an empty cache is compiling Zig's own
# build system, about 100 s on one core (docs/BENCHMARKS.md). Sourced by zig-test.sh (CI's tests) and
# build-binaries.sh (the release's binaries), from runner/.
#
# The graph must match build.zig's: src/main.zig as the root; build_version, a file holding the
# version. (No packages: build.zig.zon's one, tls.zig, is lazy and only the TLS oracle's, `zig build
# test-tls-oracle -Dtls-oracle`, since the database's TLS moved to the network
# library, runner/rust/zr-net.) And the executable is a position-independent
# one (-fPIE, build.zig's `pie`, on by default): static, it loads at a random address (README,
# "Hardening"). "Binaries (same as zig build)" in release.yml,
# on pull requests that touch the packaging, builds the x86_64 binary both ways and compares the two
# byte for byte, so a difference between the graphs fails there.
#
# zig_modules SCRATCH VERSION_FILE [FLAG...]: sets
# `modules` to the arguments that declare the graph, each module preceded by FLAG... (per-module
# flags such as -OReleaseSafe, -target or -fsanitize-thread, which the compiler takes before each
# module they apply to), after -fPIE, which applies to the whole executable.
zig_modules() {
	local scratch=$1 version=$2
	shift 2
	# The libc is musl whatever the machine's: the network library is built for musl (below), and a
	# glibc test binary with a musl-built Rust archive in it is two libcs in one process (it failed
	# `Thread.spawn` with EINVAL in 36 tests). `native` keeps the machine's CPU and OS. Except
	# under ThreadSanitizer, whose runtime needs glibc's dynamic loader (zig-test.sh): there the
	# archive is built for glibc, to match, and instrumented too (`tsan`: nightly Rust with
	# -Zsanitizer=thread, build-zr-net.sh), so TSan sees the library's synchronisation.
	local libc=musl a
	for a in "$@"; do [[ $a == -fsanitize-thread ]] && libc=tsan; done
	if [[ $(zig_target_arch "$@") == native && $libc == musl ]]; then set -- "$@" -target native-native-musl; fi
	local arch
	arch=$(zig_target_arch "$@")
	[[ $arch != native ]] || arch=$(uname -m)
	zig_libzstd_args
	zig_libzlibng_args "$arch"
	zig_zr_net_args "$scratch" "$arch" "$libc"
	# shellcheck disable=SC2034,SC2154 # for the caller; the C and Rust arguments are set above
	modules=(-fPIE "$@" --dep build_version -Mroot=src/main.zig "${libzstd_args[@]}" "${libzlibng_args[@]}"
		"$@" -Mbuild_version="$version" "${zr_net_args[@]}")
}

# zig_zr_net_args SCRATCH ARCH LIBC: sets `zr_net_args` to the link inputs of the network library
# (runner/rust/zr-net) for ARCH and LIBC (musl; tsan for the ThreadSanitizer builds): runner/build.zig's
# `addZrNet`, the same archive from the same script, and libc and libunwind, which Rust's standard library needs (Zig's bundled musl and
# libunwind; docs/rust-net.md). The archive is built once per SCRATCH and architecture. From runner/.
zig_zr_net_args() {
	local scratch=$1 arch=$2 libc=$3
	[[ -f $scratch/libzr_net-$arch-$libc.a ]] || ../.github/scripts/build-zr-net.sh "$arch" "$scratch/libzr_net-$arch-$libc.a" "$libc" || return 1
	# shellcheck disable=SC2034 # for the caller
	zr_net_args=(-lc -lunwind "$scratch/libzr_net-$arch-$libc.a")
}

# zig_target_arch FLAG...: the architecture the compiler is asked for (`-target x86_64-linux-musl`),
# or `native` when it is not asked for.
zig_target_arch() {
	local prev=""
	for a in "$@"; do
		if [[ $prev == -target ]]; then
			if [[ ${a%%-*} == native ]]; then uname -m; else echo "${a%%-*}"; fi
			return
		fi
		prev=$a
	done
	echo native
}

# zig_libzstd_args: sets `libzstd_args` to the arguments that add libzstd's decompressor to the
# module before them: runner/build.zig's `addLibzstd`, the same files and flags ("Binaries (same as
# zig build)" compares the two builds byte for byte). From runner/.
#
# `-fno-sanitize=undefined`: Zig's trapping checks cost libzstd a fifth of its speed. No
# coverage instrumentation: Zig's fuzzer asks for it of C code too and then cannot link it (or
# panics at start when the counters and the pc table disagree).
zig_libzstd_args() {
	local zstd=src/vendor/zstd
	# shellcheck disable=SC2034 # for the caller
	libzstd_args=(-cflags -O3 -ffreestanding -fno-sanitize=undefined
		-fno-sanitize-coverage=edge,trace-pc-guard,inline-8bit-counters,pc-table,trace-cmp,trace-div,trace-gep
		-DDEBUGLEVEL=0 -DZSTD_LEGACY_SUPPORT=0 -DZSTD_DISABLE_ASM -DXXH_NAMESPACE=ZSTD_
		-Isrc/vendor/shim -I"$zstd" -I"$zstd"/common --
		"$zstd"/common/{debug,entropy_common,error_private,fse_decompress,xxhash,zstd_common}.c
		"$zstd"/decompress/{huf_decompress,zstd_ddict,zstd_decompress,zstd_decompress_block}.c)
}

# zig_libzlibng_args ARCH: sets `libzlibng_args` to the arguments that add zlib-ng's inflater for
# ARCH (x86_64 or aarch64) to the module before them: runner/build.zig's `addLibzlibng`, the same
# files and flags. From runner/.
zig_libzlibng_args() {
	local z=src/vendor/zlib-ng arch_files arch_flags
	case $1 in
	x86_64)
		arch_files=("$z"/arch/x86/{chunkset_sse2,chorba_sse2}.c)
		arch_flags=(-DX86_FEATURES -DX86_SSE2)
		;;
	aarch64)
		arch_files=("$z"/arch/arm/{chunkset_neon,adler32_neon}.c)
		arch_flags=(-DARM_FEATURES -DARM_NEON -DARM_NEON_HASLD4)
		;;
	*)
		echo "zig_libzlibng_args: zlib-ng is vendored for x86_64 and aarch64, not $1" >&2
		return 1
		;;
	esac
	# shellcheck disable=SC2034 # for the caller
	libzlibng_args=(-cflags -O3 -ffreestanding -fno-sanitize=undefined
		-fno-sanitize-coverage=edge,trace-pc-guard,inline-8bit-counters,pc-table,trace-cmp,trace-div,trace-gep
		-DNDEBUG -DZLIBNG_NATIVE_API -DDISABLE_RUNTIME_CPU_DETECTION -DWITH_OPTIM -DHAVE_ATTRIBUTE_ALIGNED
		-DHAVE_BUILTIN_ASSUME_ALIGNED -DHAVE_BUILTIN_CTZ -DHAVE_BUILTIN_CTZLL -DHAVE_VISIBILITY_HIDDEN
		"${arch_flags[@]}" -Isrc/vendor/shim -I"$z" --
		"$z"/{adler32,crc32_braid_comb,crc32,functable,inflate,inftrees,zutil}.c
		"$z"/arch/generic/{adler32_c,adler32_fold_c,crc32_braid_c,crc32_chorba_c,crc32_fold_c}.c
		"${arch_files[@]}")
}
