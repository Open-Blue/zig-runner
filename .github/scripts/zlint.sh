#!/usr/bin/env bash
# Lints the runner's Zig with ZLint (https://github.com/DonIsaac/zlint), an unofficial linter that
# reads Zig's syntax tree and its own semantic analysis: CI's "Lint" job. CodeQL and Semgrep read
# no Zig, so this is the runner's own code's only static analysis besides the compiler.
#
# The rules are runner/zlint.json's (JSON, which takes no comments, so the reasons are here). A
# finding is fixed, or kept with `// zlint-disable <rule> -- <why>` before the file's first
# declaration: v0.10.0 parses `zlint-disable-next-line` but does not apply it yet (its linter.zig,
# "TODO: support next-line diagnostics"), so a directive covers a whole file.
#
# Errors, the rules that find bugs:
#   homeless-try              a `try` where no error can be returned
#   no-unresolved             an @import of a file that is not there
#   unused-decls              declarations nothing uses: dead code, or a name meant to be used
#   must-return-ref           a method returning a copy of what it should point to
#   returned-stack-reference  a pointer to a local, returned
#   useless-error-return      a function declared to return errors that never does
# Off:
#   suppressed-errors         `catch {}` and `catch unreachable`. Its first run found 124: 8 bugs,
#                             fixed (a lost `error.Canceled`, which std.Io delivers once; dropped
#                             outputs and masks on out-of-memory), and 116 meant (best-effort
#                             cleanup and logs, timer tasks, buffers sized for their output), each
#                             read. Without line-level directives the 116 can only be kept by
#                             turning it off for most of the files; turn it on again, with a
#                             directive per kept line, once ZLint applies them.
#   duplicate-case            v0.10.0 takes prongs with several ranges or items for duplicates (18
#                             false findings, none real); the compiler refuses a real duplicate
#   unsafe-undefined          `undefined` as a field's default is how this code declares buffers
#                             and state filled before use; Debug's safety checks and Valgrind
#                             (zig-valgrind.sh) catch a read of it
#   no-print                  the tests and corpus tools print with std.debug.print on purpose
#   avoid-as, case-convention, empty-file, line-length, no-catch-return, no-return-try,
#   allocator-first-param     style: Zig's style guide (docs/STYLE.md) and `zig fmt` decide it
#
# The binary is the release's, checked against the SHA-256 pinned here (GitHub's own digest of the
# release asset), as install-zig.sh checks Zig: a new version means new checksums, from
# `gh release view vX.Y.Z -R DonIsaac/zlint --json assets`. v0.10.0 is built with Zig 0.16 and
# reads this repository's Zig 0.17 sources without a parse error; a newer Zig whose syntax it
# cannot read fails here, loudly, as a parse error.
set -euo pipefail
cd "$(dirname "$0")/../../runner"

version=0.10.0
case $(uname -m) in
x86_64) sum=0b331646d5e40bec3cfcb0694c5da0b13b9de8b10af12937a777ab3144b70b65 asset=zlint-linux-x86_64 ;;
aarch64) sum=ec5e31eacc889540dbfa0a32f0e694199d06c16f640b832bf2a3bd8ecc07c3e3 asset=zlint-linux-aarch64 ;;
*)
	echo "no ZLint $version checksum for $(uname -m)" >&2
	exit 1
	;;
esac

dir="${RUNNER_TOOL_CACHE:-${RUNNER_TEMP:-/tmp}}/zlint/$version"
bin="$dir/$asset"
verified() { echo "$sum  $bin" | sha256sum --check --quiet --status; }
if ! verified 2>/dev/null; then
	mkdir -p "$dir"
	curl -fsSL -o "$bin.part" "https://github.com/DonIsaac/zlint/releases/download/v$version/$asset"
	mv "$bin.part" "$bin"
	if ! verified; then
		echo "ZLint $version ($asset) does not match its pinned checksum" >&2
		rm -f "$bin"
		exit 1
	fi
fi
chmod +x "$bin"

# `github`: each finding an annotation on its line, outside a terminal too.
format=default
[[ -n ${GITHUB_ACTIONS:-} ]] && format=github
"$bin" --deny-warnings --format "$format" src tools build.zig
