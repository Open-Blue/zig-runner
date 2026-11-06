#!/usr/bin/env bash
# Runs zizmor, the workflow security linter, with the arguments given: CI's "Workflows" job and the
# pre-push hook run this. It is installed from PyPI into a virtual environment, from
# .github/zizmor-requirements.txt, which pins the version and the hash of every file: pip refuses
# anything else (--require-hashes, wheels only), so a package swapped on PyPI cannot run here. The
# environment is kept in $ZIZMOR_VENV (default: under $RUNNER_TEMP, else ~/.cache) and made again
# when the requirements change. Needs python3 with venv.
#
#   zizmor.sh --format github .github/workflows
set -euo pipefail
cd "$(dirname "$0")/../.."

requirements=.github/zizmor-requirements.txt
venv=${ZIZMOR_VENV:-${RUNNER_TEMP:-${XDG_CACHE_HOME:-$HOME/.cache}}/zizmor-venv}
want=$(sha256sum <"$requirements")
if [[ ! -x $venv/bin/zizmor || $(cat "$venv/.requirements" 2>/dev/null) != "$want" ]]; then
	rm -rf "$venv"
	python3 -m venv "$venv"
	"$venv/bin/pip" install --quiet --disable-pip-version-check --require-hashes --only-binary=:all: \
		-r "$requirements"
	printf '%s\n' "$want" >"$venv/.requirements"
fi
exec "$venv/bin/zizmor" "$@"
