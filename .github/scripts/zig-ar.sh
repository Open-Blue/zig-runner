#!/usr/bin/env bash
# `zig ar` as the archiver of cargo's builds (cc-rs's AR) and of build-zr-net.sh's checks: the
# machine's `ar` is not used.
set -euo pipefail
exec zig ar "$@"
