#!/usr/bin/env bash
# Compares the runner's hashFiles() (runner/src/glob.zig, the search; the hash as the runner computes
# it) with GitHub's on a test tree of awkward paths and random pattern sets, down to the hash:
#
#   - GitHub's: actions/runner's hashFiles script on @actions/glob 0.7, in a node container
#     (runner/tools/hashfilesdiff/reference.mjs), installed from its package-lock.json by npm ci;
#   - the runner's: glob.zig on the same tree, read from the local disk
#     (runner/tools/hashfilescorpus.zig);
#   - the native backend's: native/hash_files.zig on the same tree as a layer (its hash and its
#     failures; it gives no file list).
#
# Both read the same directories, so the files must be the same, in the same order, with the same
# hash. In a job, glob.zig reads the container through Dagger's API instead (Fs, in
# dagger/hash_files.zig).
# Needs Go and Docker. CI runs it weekly (compare.yml), not on pull requests.
#
#   hashfiles-diff.sh [cases] [seed]     defaults: 400, 1
set -euo pipefail
cd "$(dirname "$0")/../../runner"

s=$(mktemp -d)
trap 'rm -rf "$s"' EXIT
zig build-exe --dep runner -Mroot=tools/hashfilescorpus.zig -Mrunner=src/hashfiles_corpus.zig \
	--name hashfilescorpus -femit-bin="$s/hashfilescorpus" &
(cd tools/hashfilesdiff && go run . -out "$s" -n "${1:-400}" -seed "${2:-1}")
wait

mkdir "$s/node"
cp tools/hashfilesdiff/reference.mjs tools/hashfilesdiff/package.json tools/hashfilesdiff/package-lock.json "$s/node/"
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$s/node:/app" -v "$s/tree:/tree:ro" \
	-v "$s/cases.json:/cases.json:ro" -w /app node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 sh -c 'npm ci --silent --ignore-scripts &&
		node reference.mjs /cases.json /tree' >"$s/reference.jsonl"

"$s/hashfilescorpus" "$s/cases.json" /tree "$s" "$s/reference.jsonl"
