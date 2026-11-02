#!/usr/bin/env bash
# The runner's hot paths (runner/tools/hotbench.zig: expressions, YAML, HPACK, the hashFiles() glob,
# SHA-256) as a position-independent executable against the same code without, in ReleaseSafe for
# x86_64-linux-musl as the release builds it (BENCHMARKS.md, "Position-independent executable").
# The two builds run in turn, RUNS times each, so drift in the machine (heat, other load) falls on
# both alike; each run times ROUNDS rounds of every benchmark. Prints, per benchmark and build, the
# median round, its interquartile range and its fastest, then the median's change from no-PIE.
#
#   hotbench.sh [ROUNDS] [RUNS]      by default 21 rounds, 10 runs: 210 rounds per benchmark and build
set -euo pipefail
rounds=${1:-21}
runs=${2:-10}
cd "$(dirname "$0")/../../runner"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

flags=(-OReleaseSafe -fstrip -target x86_64-linux-musl)
for pie in no-PIE PIE; do
	zig build-exe "-f$pie" "${flags[@]}" --dep expr --dep yaml --dep hpack --dep glob -Mroot=tools/hotbench.zig \
		"${flags[@]}" -Mexpr=src/expr.zig "${flags[@]}" -Myaml=src/yaml.zig \
		"${flags[@]}" -Mhpack=src/hpack.zig "${flags[@]}" -Mglob=src/glob.zig \
		--name "hotbench-$pie" -femit-bin="$scratch/hotbench-$pie"
done
for ((run = 1; run <= runs; run++)); do
	for pie in no-PIE PIE; do
		"$scratch/hotbench-$pie" "$rounds" ../.github/workflows/ci.yml ../.github/workflows/release.yml |
			sed "s/^/$pie\t/" >>"$scratch/rounds.tsv"
	done
done

# Per benchmark and build: the rounds sorted, then their quartiles. Times in milliseconds.
printf '%-8s %-7s %10s %21s %10s %9s\n' benchmark build median "IQR" fastest change
LC_ALL=C sort -t$'\t' -k2,2 -k1,1r -k3,3n "$scratch/rounds.tsv" | awk -F'\t' '
	function flush() {
		if (n == 0) return
		med = (n % 2) ? t[(n + 1) / 2] : (t[n / 2] + t[n / 2 + 1]) / 2
		q1 = t[int((n + 3) / 4)]; q3 = t[int((3 * n + 1) / 4)]
		if (build == "no-PIE") { base = med; change = "" } else { change = sprintf("%+.2f%%", (med / base - 1) * 100) }
		printf "%-8s %-7s %10.3f %10.3f-%-10.3f %10.3f %9s\n", bench, build, med / 1e6, q1 / 1e6, q3 / 1e6, t[1] / 1e6, change
		n = 0
	}
	$1 != build || $2 != bench { flush(); build = $1; bench = $2 }
	{ t[++n] = $3 }
	END { flush() }'
