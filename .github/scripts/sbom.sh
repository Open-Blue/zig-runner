#!/usr/bin/env bash
# Writes the release's SBOM (SPDX 2.3, JSON) to stdout: the release binaries listed in SHA256SUMS
# with their digests, and what is compiled into them: the Rust crates runner/rust/zr-net/Cargo.lock pins,
# musl and libunwind (Zig's bundled copies), and Zig's standard library, from the Zig on PATH that built them.
# The runner links nothing else, so that is everything. release.yml attests it for each binary and attaches it to
# the release.
#
#   .github/scripts/sbom.sh v0.12.0 dist/SHA256SUMS > zig-runner.spdx.json
#
# Licenses are the ones docs/THIRD_PARTY.md gives; a package missing below is NOASSERTION until added.
set -euo pipefail

tag=${1:?usage: sbom.sh TAG SHA256SUMS}
sums=${2:?usage: sbom.sh TAG SHA256SUMS}
repo=${GITHUB_REPOSITORY:-Open-Blue/zig-runner}
lock="$(dirname "$0")/../../runner/rust/zr-net/Cargo.lock"

# Cargo.lock's crates as "name version checksum" lines (the runner's own crate has no checksum).
crates=$(awk '
	/^\[\[package\]\]/ { name = ""; version = ""; sum = "" }
	/^name = / { name = $3; gsub(/"/, "", name) }
	/^version = / { version = $3; gsub(/"/, "", version) }
	/^checksum = / { sum = $3; gsub(/"/, "", sum); print name, version, sum }
' "$lock")
zig_version=$(zig version)

{
	while read -r digest file; do
		jq -n --arg file "$file" --arg digest "$digest" --arg tag "$tag" --arg repo "$repo" '{
			kind: "binary", SPDXID: ("SPDXRef-Binary-" + ($file | gsub("[^A-Za-z0-9.-]"; "-"))), name: $file, versionInfo: $tag,
			packageFileName: $file, primaryPackagePurpose: "APPLICATION",
			downloadLocation: ("https://github.com/" + $repo + "/releases/download/" + $tag + "/" + $file),
			checksums: [{algorithm: "SHA256", checksumValue: $digest}],
			filesAnalyzed: false, licenseConcluded: "MIT", licenseDeclared: "MIT", copyrightText: "NOASSERTION"
		}'
	done <"$sums"
	while read -r name version sum; do
		[[ -n $name ]] || continue
		jq -n --arg name "$name" --arg version "$version" --arg sum "$sum" '{
			kind: "dep", SPDXID: ("SPDXRef-Crate-" + ($name | gsub("[^A-Za-z0-9.-]"; "-")) + "-" + ($version | gsub("[^A-Za-z0-9.-]"; "-"))), name: $name,
			versionInfo: $version, downloadLocation: ("https://crates.io/crates/" + $name + "/" + $version),
			primaryPackagePurpose: "LIBRARY", checksums: [{algorithm: "SHA256", checksumValue: $sum}],
			comment: "Rust crate (runner/rust/zr-net/Cargo.lock); the license is in the crate",
			filesAnalyzed: false, licenseConcluded: "NOASSERTION", licenseDeclared: "NOASSERTION", copyrightText: "NOASSERTION"
		}'
	done <<<"$crates"
	jq -n '{
		kind: "dep", SPDXID: "SPDXRef-musl", name: "musl", versionInfo: "bundled with Zig",
		downloadLocation: "https://musl.libc.org", primaryPackagePurpose: "LIBRARY",
		comment: "The libc Rust and the runner link, built by the Zig that built the binaries.",
		filesAnalyzed: false, licenseConcluded: "MIT", licenseDeclared: "MIT", copyrightText: "NOASSERTION"
	}'
	jq -n '{
		kind: "dep", SPDXID: "SPDXRef-libunwind", name: "libunwind", versionInfo: "bundled with Zig",
		downloadLocation: "https://github.com/llvm/llvm-project", primaryPackagePurpose: "LIBRARY",
		comment: "LLVMs unwinder, which Rust standard library references.",
		filesAnalyzed: false, licenseConcluded: "Apache-2.0 WITH LLVM-exception", licenseDeclared: "Apache-2.0 WITH LLVM-exception", copyrightText: "NOASSERTION"
	}'
	jq -n --arg v "$zig_version" '{
		kind: "dep", SPDXID: "SPDXRef-Zig-std", name: "zig", versionInfo: $v,
		downloadLocation: ("https://ziglang.org/download/" + $v + "/"), primaryPackagePurpose: "LIBRARY",
		comment: "The compiler that built the binaries; its standard library is compiled into them.",
		filesAnalyzed: false, licenseConcluded: "MIT", licenseDeclared: "MIT", copyrightText: "NOASSERTION"
	}'
} | jq -s --arg tag "$tag" --arg repo "$repo" --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
	--arg run "${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}" '
	[.[] | select(.kind == "binary")] as $bins | [.[] | select(.kind == "dep")] as $deps | {
		spdxVersion: "SPDX-2.3", dataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT",
		name: ("zig-runner " + $tag),
		documentNamespace: ("https://github.com/" + $repo + "/releases/tag/" + $tag + "/sbom/" + $run),
		creationInfo: {created: $now, creators: ["Tool: zig-runner .github/scripts/sbom.sh"]},
		packages: [($bins + $deps)[] | del(.kind)],
		relationships: (
			[$bins[] | {spdxElementId: "SPDXRef-DOCUMENT", relationshipType: "DESCRIBES", relatedSpdxElement: .SPDXID}] +
			[$bins[] as $b | $deps[] | {spdxElementId: $b.SPDXID, relationshipType: "STATIC_LINK", relatedSpdxElement: .SPDXID}] +
			[$bins[] | {spdxElementId: "SPDXRef-Zig-std", relationshipType: "BUILD_TOOL_OF", relatedSpdxElement: .SPDXID}]
		)
	}'
