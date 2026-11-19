#!/bin/bash
# A handful of unauthenticated requests to api.github.com/zen (60/h limit: ~40 requests in all).
# $m is split on purpose: it holds a mode and its request count.
# shellcheck disable=SC2086
cd "$(dirname "$0")" || exit 1
export CA_FILE=/etc/ssl/certs/ca-certificates.crt
U=https://api.github.com/zen
R=rust/target/release/bench_hyper
for m in "cold 4" "warm 5"; do
	./bench_std "$U" $m 2>&1 | grep '^std'
	NODELAY=1 ./bench_std "$U" $m 2>&1 | grep '^std' | sed 's/^std/std+nodelay/'
	./bench_curl "$U" $m
	"$R" "$U" $m
done
