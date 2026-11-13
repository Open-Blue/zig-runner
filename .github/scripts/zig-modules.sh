# shellcheck shell=bash
# The runner's module graph as runner/build.zig makes it, for compiling with the compiler directly
# instead of `zig build`, whose first step on a machine with an empty cache is compiling Zig's own
# build system, about 100 s on one core (docs/BENCHMARKS.md). Sourced by zig-test.sh (CI's tests) and
# build-binaries.sh (the release's binaries), from runner/.
#
# The graph must match build.zig's: src/main.zig as the root; build_version, a file holding the
# version. (No packages: build.zig.zon has none since the database's TLS moved to the network
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
	a=$(zig_target_arch "$@")
	zig_zr_net_args "$scratch" "$([[ $a == native ]] && uname -m || echo "$a")" "$libc"
	# shellcheck disable=SC2034,SC2154 # for the caller; zr_net_args is set above
	modules=(-fPIE "$@" --dep build_version -Mroot=src/main.zig
		"$@" -Mbuild_version="$version" "${zr_net_args[@]}")
}

# zig_zr_net_args SCRATCH ARCH LIBC: sets `zr_net_args` to the link inputs of the network library
# (runner/rust/zr-net) for ARCH and LIBC (musl; tsan for the ThreadSanitizer builds): runner/build.zig's `addZrNet`, the same archive from the same
# script, and libc and libunwind, which Rust's standard library needs (Zig's bundled musl and
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
