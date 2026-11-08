#!/usr/bin/env bash
# Compares the runner's YAML reader (runner/src/yaml.zig, which reads action.yml files) with
# go.yaml.in/yaml/v3 (what nektos/act and Gitea's actionslib use), in two ways:
#
#   - the action.yml of every repository in runner/tools/yamldiff/repos.txt, fetched now from
#     GitHub (read-only, unauthenticated) and not kept;
#   - random YAML that runner/tools/yamldiff writes, as many files with Go's encoder (in every
#     style it has) as written as text (multi-line quoted scalars and flow collections, explicit
#     keys, and some files that are not YAML at all).
#
# runner/tools/yamlcorpus.zig compares the trees. yaml.zig may refuse what is outside its subset
# (it says so); reading something differently, or reading what Go refuses, fails. Needs Go and
# network access; CI runs it weekly (compare.yml), not on pull requests.
#
#   yaml-diff.sh [random files of each kind] [seed]     defaults: 2000, 1
set -euo pipefail
cd "$(dirname "$0")/../../runner"

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
mkdir "$scratch/real" "$scratch/random"
zig build-exe -OReleaseSafe --dep yaml -Mroot=tools/yamlcorpus.zig -Myaml=src/yaml.zig \
	--name yamlcorpus -femit-bin="$scratch/yamlcorpus" &

echo "== fetching the action.yml files"
fetch() {
	local name=${1//\//__}
	for f in action.yml action.yaml; do
		curl -fsSL --max-time 15 "https://raw.githubusercontent.com/$1/HEAD/$f" \
			-o "$scratch/real/$name.yml" 2>/dev/null && return
	done
	rm -f "$scratch/real/$name.yml"
}
while read -r repo; do
	[[ -n $repo ]] && fetch "$repo" &
	while (($(jobs -r | wc -l) > 16)); do wait -n; done
done <tools/yamldiff/repos.txt
wait

cd tools/yamldiff
echo "== parsing with Go"
go run . -gen "${1:-2000}" -seed "${2:-1}" -out "$scratch/random"
go run . "$scratch"/real/*.yml >"$scratch/real.jsonl"
go run . "$scratch"/random/*.yml >"$scratch/random.jsonl"
status=0
echo "== action.yml files from GitHub"
"$scratch/yamlcorpus" "$scratch/real.jsonl" "$scratch/real" || status=1
echo "== random YAML"
"$scratch/yamlcorpus" "$scratch/random.jsonl" "$scratch/random" | grep -v '^refused' || status=1
exit $status
