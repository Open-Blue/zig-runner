#!/usr/bin/env bash
# Compares the runner's regular expressions (runner/src/regex.zig) with .NET's, as GitHub's runner
# compiles problem matchers (RegexOptions.CultureInvariant | ECMAScript), on two sets of patterns:
#
#   - every "regexp" in the problem matchers listed in runner/tools/regexdiff/matchers.txt
#     (published on GitHub; fetched now, read-only, and not kept);
#   - random patterns over what .NET's ECMAScript mode takes (runner/tools/regexdiff, Go).
#
# Each with inputs the patterns were built to match, mutations of them, and log lines. .NET runs in
# the dotnet SDK container (runner/tools/regexdiff/reference); runner/tools/regexcorpus.zig runs
# regex.zig and prints every disagreement. Needs Go, Docker and network access; CI runs it weekly
# (compare.yml), not on pull requests.
#
#   regex-diff.sh [random patterns] [seed]     defaults: 2000, 1
set -euo pipefail
cd "$(dirname "$0")/../../runner"

s=$(mktemp -d)
trap 'rm -rf "$s"' EXIT
mkdir "$s/matchers"
zig build-exe -OReleaseSafe --dep regex --dep corpus -Mroot=tools/regexcorpus.zig -Mregex=src/regex.zig -Mcorpus=tools/corpus.zig \
	--name regexcorpus -femit-bin="$s/regexcorpus" &

n=0
while read -r repo file; do
	[[ -z $repo ]] && continue
	n=$((n + 1))
	curl -fsSL --max-time 15 "https://raw.githubusercontent.com/$repo/HEAD/$file" -o "$s/matchers/$n.json" 2>/dev/null ||
		rm -f "$s/matchers/$n.json" &
	while (($(jobs -r | wc -l) > 16)); do wait -n; done
done <tools/regexdiff/matchers.txt
wait

(cd tools/regexdiff && go run . -out "$s/cases.json" -matchers "$s/matchers" -n "${1:-2000}" -seed "${2:-1}")
docker run --rm -e DOTNET_CLI_TELEMETRY_OPTOUT=1 -e DOTNET_NOLOGO=1 \
	-v "$PWD/tools/regexdiff/reference:/src:ro" -v "$s/cases.json:/cases.json:ro" \
	mcr.microsoft.com/dotnet/sdk:8.0@sha256:ff39a765f04619c8d146796fc09b38499ae5984f4a2a4c3a0a57d0022855daee sh -c 'cp -r /src /tmp/ref && cd /tmp/ref && dotnet run -c Release -- /cases.json' \
	>"$s/reference.jsonl"
"$s/regexcorpus" "$s/cases.json" "$s/reference.jsonl"
