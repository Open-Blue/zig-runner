# Sourced by build-zr-net.sh and cargo-test.sh: every C compile, link and archive of a cargo build
# goes through the pinned Zig (install-zig.sh), the target's and the host's (build scripts and
# proc-macros are built for the host, and cargo links them with `cc` unless told otherwise), so no
# build output depends on the runner image's compiler, linker, ar or glibc, and the Rust cache's
# keys need not hold the image (docs/rust-net.md, "The build cache").
#
#   zig_cc_env TARGET_TRIPLE
#
# TARGET_TRIPLE is cargo's target (x86_64-unknown-linux-musl). A gnu target, which is the host's
# triple, is built for glibc 2.28 (Debian 10, RHEL 8: older than any distro the runner supports),
# so what is made on one machine runs on every newer one. Zig links its own glibc stubs for that
# version: the machine's libc and its headers are not read.
zig_glibc=2.28
zig_cc_env() {
	local triple=$1 here host host_upper upper
	here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
	host=$(uname -m)-unknown-linux-gnu
	host_upper=$(tr a-z- A-Z_ <<<"$host")
	upper=$(tr a-z- A-Z_ <<<"$triple")
	ZR_ZIG_HOST_TARGET=$(uname -m)-linux-gnu.$zig_glibc
	if [[ $triple == "$host" ]]; then
		ZR_ZIG_TARGET=$ZR_ZIG_HOST_TARGET
	else
		ZR_ZIG_TARGET=${triple%%-*}-linux-${triple##*-}
	fi
	export ZR_ZIG_TARGET ZR_ZIG_HOST_TARGET
	export "CC_${triple//-/_}=$here/zig-cc.sh"
	export "AR_${triple//-/_}=$here/zig-ar.sh"
	export "CARGO_TARGET_${upper}_LINKER=$here/zig-cc.sh"
	if [[ $triple != "$host" ]]; then
		# The host's own, for the build scripts and proc-macros of a musl build.
		export "CC_${host//-/_}=$here/zig-cc-host.sh"
		export "AR_${host//-/_}=$here/zig-ar.sh"
		export "CARGO_TARGET_${host_upper}_LINKER=$here/zig-cc-host.sh"
	fi
}
