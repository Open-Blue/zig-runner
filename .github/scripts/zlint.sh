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
#                             read. Without line-level directives the meant ones can only be kept
#                             by turning it off for most of the files, so it is off here and runs
#                             nightly instead (`zlint.sh suppressed-errors`, below); turn it on
#                             here, with a directive per kept line, once ZLint applies them
#                             (v0.10.0 is still the newest release on 2026-11-02).
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
#
#   zlint.sh                              the rules above, as CI's "Lint (ZLint)" job runs them
#   zlint.sh suppressed-errors            that rule alone, against zlint-suppressed.baseline
#   zlint.sh suppressed-errors --update   the baseline rewritten from what it finds now
#
# suppressed-errors alone is analysis.yml's nightly "ZLint (suppressed-errors)" job. The baseline
# lists the sites read and meant, each by its file and a fingerprint of its line (the line's text,
# its whitespace collapsed, hashed), so a line that only moves stays known. A site not in it fails
# the job, listed and annotated on its line: it is fixed, or added with --update in a pull request
# that says why it is meant. Identical lines in one file share a fingerprint and are counted, so a
# new one names all of them. A listed site no longer found (fixed, or its line edited) is
# reported, not failed; --update drops it.
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
if ! verified &>/dev/null; then
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

lint=(src tools build.zig)

suppressed_errors() {
	local update=$1 baseline=../.github/scripts/zlint-suppressed.baseline scratch status=0
	scratch=$(mktemp -d)
	# shellcheck disable=SC2064 # the path is known now
	trap "rm -rf '$scratch'" EXIT
	# runner/zlint.json with every rule off but this one.
	jq '.rules |= (map_values("off") + {"suppressed-errors": "error"})' zlint.json >"$scratch/config.json"
	"$bin" --config "$scratch/config.json" --format json --no-summary "${lint[@]}" >"$scratch/found.json" || status=$?
	# Anything else (a syntax error, a rule a new version turns on by default) is not this check's.
	if ((status > 1)) || jq -e 'select(.code != "suppressed-errors")' "$scratch/found.json" >/dev/null; then
		jq -r 'select(.code != "suppressed-errors") | "\(.source_name):\(.labels[0].start.line): \(.code): \(.message)"' \
			"$scratch/found.json" >&2 || true
		echo "ZLint did not run cleanly (exit $status): see above" >&2
		exit 1
	fi
	# One finding a line: file, line, column, fingerprint, text.
	jq -r 'select(.code == "suppressed-errors") | [.source_name, .labels[0].start.line, .labels[0].start.column] | @tsv' \
		"$scratch/found.json" |
		while IFS=$'\t' read -r file line column; do
			text=$(sed -n "${line}p" "$file" | tr -s ' \t' ' ' | sed 's/^ //; s/ $//')
			printf '%s\t%s\t%s\t%s\t%s\n' "$file" "$line" "$column" \
				"$(printf '%s' "$text" | sha256sum | cut -c1-16)" "$text"
		done | sort -t$'\t' -k1,1 -k2,2n >"$scratch/found.tsv"
	local found
	found=$(wc -l <"$scratch/found.tsv")

	if [[ $update == --update ]]; then
		{
			echo "# ZLint's suppressed-errors sites, each read and meant: file, fingerprint, the line."
			echo "# Written by \`.github/scripts/zlint.sh suppressed-errors --update\`; zlint.sh says how."
			cut -f1,4,5 "$scratch/found.tsv" | LC_ALL=C sort
		} >"$baseline"
		echo "zlint-suppressed.baseline: $found sites"
		return
	fi

	# Each baseline entry used up once; what is left over on either side is new, or gone.
	awk -F'\t' -v gone="$scratch/gone.tsv" '
		NR == FNR { if ($0 !~ /^#/ && NF) { kept[$1 FS $2]++; texts[$1 FS $2] = $3 }; next }
		{ key = $1 FS $4; if (kept[key] > 0) kept[key]--; else print }
		END { for (key in kept) for (i = 0; i < kept[key]; i++) print key FS texts[key] >gone }
	' "$baseline" "$scratch/found.tsv" >"$scratch/new.tsv"

	if [[ -s $scratch/gone.tsv ]]; then
		echo "In the baseline but not found (fixed, or the line edited; --update drops them):"
		while IFS=$'\t' read -r file _ text; do
			echo "  runner/$file: $text"
		done <"$scratch/gone.tsv"
	fi
	if [[ ! -s $scratch/new.tsv ]]; then
		echo "suppressed-errors: $found sites, all in the baseline"
		return
	fi
	echo "suppressed-errors: not in the baseline (fix each, or --update and say why it is meant):" >&2
	local line column fingerprint same
	while IFS=$'\t' read -r file line column fingerprint text; do
		same=$(awk -F'\t' -v f="$file" -v p="$fingerprint" '$1 == f && $4 == p' "$scratch/found.tsv" | wc -l)
		echo "  runner/$file:$line:$column: $text" >&2
		if ((same > 1)); then
			echo "    (or another of the $same lines with this text in the file)" >&2
		fi
		if [[ -n ${GITHUB_ACTIONS:-} ]]; then
			echo "::error file=runner/$file,line=$line,col=$column,title=ZLint suppressed-errors::${text//%/%25}"
		fi
	done <"$scratch/new.tsv"
	exit 1
}

case ${1:-} in
"")
	# `github`: each finding an annotation on its line, outside a terminal too.
	format=default
	[[ -n ${GITHUB_ACTIONS:-} ]] && format=github
	"$bin" --deny-warnings --format "$format" "${lint[@]}"
	;;
suppressed-errors) suppressed_errors "${2:-}" ;;
*)
	echo "usage: zlint.sh [suppressed-errors [--update]]" >&2
	exit 2
	;;
esac
