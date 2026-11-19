#!/usr/bin/env bash
# ThreadSanitizer's runtime cannot place its shadow memory with Ubuntu's 32 bits of address-space
# randomness, so its jobs lower vm.mmap_rnd_bits. This reads the key, prints it before, writes the
# value (sudo sysctl), reads it back and fails, saying why, when the key is missing, the write is
# refused, or the value read back is not the one written (a quiet failure here shows up later as
# a TSan crash far from its cause).
#
#   .github/scripts/mmap-rnd-bits.sh BITS
#
# PROC_SYS replaces /proc/sys, and SYSCTL the write command (mmap-rnd-bits-test.sh).
set -uo pipefail

bits=${1:?usage: mmap-rnd-bits.sh BITS}
key=${PROC_SYS:-/proc/sys}/vm/mmap_rnd_bits
write=${SYSCTL:-sudo sysctl}

die() {
	echo "::error title=vm.mmap_rnd_bits::$*"
	exit 1
}

before=$(cat "$key" 2>/dev/null) || die "$key cannot be read (kernel $(uname -r), $(getconf PAGESIZE)-byte pages): the kernel lacks the key, so ThreadSanitizer's address layout cannot be set"
echo "mmap_rnd_bits: before: $before"
# shellcheck disable=SC2086 # $write is a command and its arguments
$write -q -w "vm.mmap_rnd_bits=$bits" || die "writing vm.mmap_rnd_bits=$bits was refused (was $before, the kernel's range is in $(dirname "$key")/mmap_rnd_bits: the value may be out of range)"
after=$(cat "$key") || die "$key cannot be read back"
echo "mmap_rnd_bits: after: $after (wanted $bits)"
[[ $after == "$bits" ]] || die "wrote $bits and read back $after"
