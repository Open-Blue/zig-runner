# shellcheck shell=bash
# The runner's module graph as runner/build.zig makes it, for compiling with the compiler directly
# instead of `zig build`, whose first step on a machine with an empty cache is compiling Zig's own
# build system, about 100 s on one core (BENCHMARKS.md). Sourced by zig-test.sh (CI's tests) and
# build-binaries.sh (the release's binaries), from runner/.
#
# The graph must match build.zig's: src/main.zig as the root; build_version, a file holding the
# version; and tls, the package build.zig.zon pins. And the executable is a position-independent
# one (-fPIE, build.zig's `pie`, on by default): static, it loads at a random address (README,
# "Hardening"). "Binaries (same as zig build)" in release.yml,
# on pull requests that touch the packaging, builds the x86_64 binary both ways and compares the two
# byte for byte, so a difference between the graphs fails there.
#
# The package comes from git, not `zig fetch`: in Zig 0.17 fetching runs in the build system too, and
# costs the same 100 s. build.zig.zon pins it by a GitHub archive URL that names the commit, and git
# checks the commit hash, so the pin stays in build.zig.zon alone. Its `.hash` is checked here too
# (zig_package_hash), so a new commit fails until the hash is updated, as `zig build` would.

# zig_modules SCRATCH VERSION_FILE [FLAG...]: fetches the tls package into SCRATCH/tls (once) and sets
# `modules` to the arguments that declare the graph, each module preceded by FLAG... (per-module
# flags such as -OReleaseSafe, -target or -fsanitize-thread, which the compiler takes before each
# module they apply to), after -fPIE, which applies to the whole executable.
zig_modules() {
	local scratch=$1 version=$2
	shift 2
	local url rev want got
	if [[ ! -d $scratch/tls ]]; then
		url=$(sed -n 's|^ *\.url = "\(https://github\.com/.*/archive/[0-9a-f]\{40\}\.tar\.gz\)",$|\1|p' build.zig.zon)
		[[ $(wc -l <<<"$url") == 1 && -n $url ]] || { echo "expected one GitHub archive URL in build.zig.zon" >&2; return 1; }
		want=$(sed -n 's|^ *\.hash = "\([^"]*\)",$|\1|p' build.zig.zon)
		[[ $(wc -l <<<"$want") == 1 && -n $want ]] || { echo "expected one .hash in build.zig.zon" >&2; return 1; }
		rev=${url##*/}
		git init -q "$scratch/tls"
		git -C "$scratch/tls" fetch -q --depth 1 "${url%/archive/*}" "${rev%.tar.gz}"
		git -C "$scratch/tls" checkout -q FETCH_HEAD
		got=$(zig_package_hash "$scratch/tls") || return 1
		if [[ $got != "$want" ]]; then
			echo "build.zig.zon: tls at ${rev%.tar.gz} hashes to $got, not $want: update its .hash" >&2
			return 1
		fi
	fi
	# shellcheck disable=SC2034 # for the caller
	modules=(-fPIE "$@" --dep build_version --dep tls -Mroot=src/main.zig
		"$@" -Mbuild_version="$version" "$@" -Mtls="$scratch/tls/src/root.zig")
}

# zig_package_hash DIR: the hash `zig fetch` gives the package checked out in DIR, as Zig 0.17
# computes it (lib/compiler/Maker/Fetch.zig, computeHash; Package.zig, Hash.init):
# NAME-VERSION-BASE64URL of the fingerprint's low 32 bits and the files' total size (each a
# little-endian u32), then the first 25 bytes of the SHA-256 of each file's SHA-256 in path order,
# a file's being of its path, two zero bytes (Zig takes no file as executable) and its contents (a
# symlink's: its path and target). Only the files under the package's own `.paths` count. Zig hashes
# the GitHub archive and this the git checkout, which hold the same files unless the package's
# .gitattributes marks some of them export-ignore or export-subst.
zig_package_hash() {
	local dir=$1 zon name version fingerprint paths p f d digests="" size=0 hex
	zon=$(tr '\n' ' ' <"$dir/build.zig.zon")
	name=$(sed -n 's/.*\.name = \.\([A-Za-z0-9_]*\),.*/\1/p' <<<"$zon")
	version=$(sed -n 's/.*\.version = "\([^"]*\)",.*/\1/p' <<<"$zon")
	fingerprint=$(sed -n 's/.*\.fingerprint = \(0x[0-9a-fA-F]*\),.*/\1/p' <<<"$zon")
	paths=$(sed -n 's/.*\.paths = \.{\([^}]*\)}.*/\1/p' <<<"$zon" | grep -o '"[^"]*"' | tr -d '"') || true
	if [[ -z $name || -z $version || -z $fingerprint || -z $paths ]]; then
		echo "$dir/build.zig.zon: expected .name, .version, .fingerprint and .paths" >&2
		return 1
	fi
	while IFS= read -r -d '' f; do
		f=${f#./}
		if [[ -L $dir/$f ]]; then
			d=$({ printf '%s' "$f"; readlink "$dir/$f" | tr -d '\n'; } | sha256sum)
		else
			d=$({ printf '%s\0\0' "$f"; cat "$dir/$f"; } | sha256sum)
			size=$((size + $(wc -c <"$dir/$f")))
		fi
		digests+=${d%% *}
	done < <(
		cd "$dir" || exit 1
		while IFS= read -r p; do
			case $p in
			"" | .) find . -path ./.git -prune -o \( -type f -o -type l \) -print0 ;;
			*) if [[ -e $p || -L $p ]]; then find "$p" \( -type f -o -type l \) -print0; fi ;;
			esac
		done <<<"$paths" | LC_ALL=C sort -zu
	)
	((size <= 0xffffffff)) || size=0xffffffff
	d=$(sed 's/../\\x&/g' <<<"$digests")
	d=$(printf '%b' "$d" | sha256sum)
	hex=$(printf '%08x%08x' $((fingerprint & 0xffffffff)) "$size")
	hex=${hex:6:2}${hex:4:2}${hex:2:2}${hex:0:2}${hex:14:2}${hex:12:2}${hex:10:2}${hex:8:2}${d:0:50}
	printf '%s-%s-%s\n' "$name" "$version" \
		"$(printf '%b' "$(sed 's/../\\x&/g' <<<"$hex")" | base64 | tr -d '\n' | tr '+/' '-_')"
}
