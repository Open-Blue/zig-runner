#!/usr/bin/env bash
# The Database tests job's database: TimescaleDB, as deployments use, pinned by digest. Started in
# the background at the job's start and waited for only once the tests are compiled (zig-test.sh,
# ZIG_TEST_WAIT_FOR_DB=1), so pulling and starting it (about 25 s) overlaps the compile instead of
# coming before it, as a service container's would: GitHub starts those before the first step.
# Reachable on 127.0.0.1 only, with the job's PGPORT, PGPASSWORD and PGDATABASE. It also does TLS
# with client certificates for pg.zig's TLS tests (pg-tls-fixture.sh: a private CA, users `pgecdsa`
# and `pgrsa` that only their certificates let in); plain connections as `postgres` work as before,
# and the files' directory reaches the tests as ZIG_TEST_PG_TLS_DIR (through GITHUB_ENV).
#
#   ci-database.sh start   pull and start it, in the background
#   ci-database.sh wait    wait until it accepts connections over TCP (up to 3 minutes)
set -euo pipefail

name=zig-runner-ci-db
image=timescale/timescaledb:latest-pg17@sha256:b56a3f51991df1f79d0c1a0841cad5c5fa8058fdd6a3ee6886394a6d4c174538
log=${RUNNER_TEMP:-/tmp}/$name.log

case ${1:-} in
start)
	: "${PGPORT:?}" "${PGPASSWORD:?}" "${PGDATABASE:?}"
	tls=${RUNNER_TEMP:-/tmp}/pg-tls
	"$(dirname "$0")/pg-tls-fixture.sh" "$tls"
	echo "ZIG_TEST_PG_TLS_DIR=$tls" >>"${GITHUB_ENV:-/dev/null}"
	nohup docker run -d --name "$name" -p "127.0.0.1:$PGPORT:5432" \
		-e POSTGRES_PASSWORD="$PGPASSWORD" -e POSTGRES_DB="$PGDATABASE" \
		-v "$tls:/pg-tls:ro" -v "$tls/init.sh:/docker-entrypoint-initdb.d/zz-tls.sh:ro" "$image" >"$log" 2>&1 &
	echo "starting $image in the background"
	;;
wait)
	# Over TCP from inside the container: during its first start the image runs a temporary server
	# for its init scripts that listens on the socket only, and is not yet the database.
	for _ in $(seq 180); do
		if docker exec "$name" pg_isready -q -h 127.0.0.1 -U postgres 2>/dev/null; then exit 0; fi
		sleep 1
	done
	echo "the database did not come up within 3 minutes" >&2
	cat "$log" >&2 || true
	docker logs "$name" >&2 || true
	exit 1
	;;
*)
	echo "usage: ci-database.sh start|wait" >&2
	exit 2
	;;
esac
