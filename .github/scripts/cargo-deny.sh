#!/usr/bin/env bash
# cargo-deny over runner/rust (deny.toml: licenses, advisories, sources, bans; docs/rust-net.md),
# security.yml's "Rust dependencies" job. The download is checked against a pinned checksum, as
# gitleaks' is (install-gitleaks.sh); cargo-deny's releases publish none, so the pin is the SHA-256
# of the tarball as fetched when the version was chosen. Fetches the advisory database from GitHub.
#
#   cargo-deny.sh
set -euo pipefail
version=0.20.2
arch=$(uname -m)
case $arch in
x86_64) sum=9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f ;;
aarch64) sum=995c82be0defc7a025cae49a2aa2644ce8245c9a3318fc4103907c6a285e8c7d ;;
*)
	echo "no cargo-deny checksum for $arch" >&2
	exit 1
	;;
esac
dir=${RUNNER_TEMP:-/tmp}/cargo-deny-$version
mkdir -p "$dir"
curl -fsSL -o "$dir/cargo-deny.tar.gz" \
	"https://github.com/EmbarkStudios/cargo-deny/releases/download/$version/cargo-deny-$version-$arch-unknown-linux-musl.tar.gz"
echo "$sum  $dir/cargo-deny.tar.gz" | sha256sum --check --quiet --status || {
	echo "cargo-deny $version does not match its pinned checksum" >&2
	exit 1
}
tar -xzf "$dir/cargo-deny.tar.gz" -C "$dir" --strip-components=1 "cargo-deny-$version-$arch-unknown-linux-musl/cargo-deny"
cd "$(dirname "$0")/../../runner/rust/zr-net"
"$dir/cargo-deny" --manifest-path Cargo.toml --config ../deny.toml check
