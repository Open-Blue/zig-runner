#!/usr/bin/env bash
# Writes the release's SBOM (SPDX 2.3, JSON) to stdout: the release binaries listed in SHA256SUMS
# with their digests, and what is compiled into them: the packages runner/build.zig.zon pins, and
# Zig's standard library, from the Zig on PATH that built them. The runner links no libc and
# nothing else, so that is everything. release.yml attests it for each binary and attaches it to
# the release.
#
#   .github/scripts/sbom.sh v0.12.0 dist/SHA256SUMS > zig-runner.spdx.json
#
# Licenses are the ones docs/THIRD_PARTY.md gives; a package missing below is NOASSERTION until added.
set -euo pipefail

tag=${1:?usage: sbom.sh TAG SHA256SUMS}
sums=${2:?usage: sbom.sh TAG SHA256SUMS}
repo=${GITHUB_REPOSITORY:-Open-Blue/zig-runner}
zon="$(dirname "$0")/../../runner/build.zig.zon"

declare -A licenses=([tls]=MIT)

# build.zig.zon's dependencies as "name url hash" lines.
deps=$(awk '
	/^    \.dependencies = \.\{/ { in_deps = 1; next }
	in_deps && /^    \},/ { exit }
	in_deps && /^        \.[A-Za-z0-9_]+ = \.\{/ { name = $1; sub(/^\./, "", name); url = ""; hash = "" }
	in_deps && /\.url = "/ { url = $0; sub(/.*\.url = "/, "", url); sub(/".*/, "", url) }
	in_deps && /\.hash = "/ { hash = $0; sub(/.*\.hash = "/, "", hash); sub(/".*/, "", hash) }
	in_deps && /^        \},/ { print name, url, hash }
' "$zon")
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
	while read -r name url hash; do
		[[ -n $name ]] || continue
		jq -n --arg name "$name" --arg url "$url" --arg hash "$hash" --arg license "${licenses[$name]:-NOASSERTION}" '{
			kind: "dep", SPDXID: ("SPDXRef-Zig-" + ($name | gsub("[^A-Za-z0-9.-]"; "-"))), name: $name,
			versionInfo: ($url | capture("/(?<v>[^/]+)\\.tar\\.gz$").v // "NOASSERTION"),
			downloadLocation: $url, primaryPackagePurpose: "LIBRARY",
			comment: ("Zig package hash " + $hash + " (runner/build.zig.zon)"),
			filesAnalyzed: false, licenseConcluded: $license, licenseDeclared: $license, copyrightText: "NOASSERTION"
		}'
	done <<<"$deps"
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
