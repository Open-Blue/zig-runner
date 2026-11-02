#!/usr/bin/env bash
# Runs shellcheck over every shell script in the repository: CI's "Workflows" job and the pre-push hook
# run this. The scripts are found by their #! line, so a new one is checked without being listed.
# The checker itself runs from its image, pinned by digest, so every run uses the same version.
set -euo pipefail
cd "$(dirname "$0")/../.."

mapfile -t scripts < <(
	git ls-files -z | xargs -0 grep -lsE '^#!/usr/bin/env (bash|sh)|^#!/bin/(ba)?sh' -- 2>/dev/null
	echo .githooks/common.sh
)
docker run --rm -v "$PWD:/mnt:ro" -w /mnt koalaman/shellcheck:v0.11.0@sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d -x "${scripts[@]}"
echo "shellcheck: ${#scripts[@]} scripts, no findings"
