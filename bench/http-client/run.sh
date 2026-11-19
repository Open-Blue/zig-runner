#!/bin/sh
# Runs every candidate x mode, REPS times; needs server-bin running (see README in docs/http-client-study.md).
# $m is split on purpose: it holds a mode and its counts.
# shellcheck disable=SC2086
cd "$(dirname "$0")" || exit 1
U1=https://localhost:8444/json
U2=https://localhost:8443/json
R=rust/target/release/bench_hyper
for rep in 1 2 3; do
	echo "rep $rep"
	for m in "warm 2000" "cold 300" "conc 3200 16"; do
		./bench_std "$U1" $m 2>&1 | grep '^std'
		NODELAY=1 ./bench_std "$U1" $m 2>&1 | grep '^std' | sed 's/^std/std+nodelay/'
		./bench_curl "$U1" $m
		"$R" "$U1" $m
	done
	./bench_curl "$U2" warm 2000 1 h2
	./bench_curl "$U2" conc 3200 16 h2
	"$R" "$U2" warm 2000 1 h2
	"$R" "$U2" conc 3200 16 h2
done
