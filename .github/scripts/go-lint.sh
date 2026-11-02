#!/usr/bin/env bash
# Lints the comparison tools' Go: every module under runner/tools (each *diff directory has a
# go.mod of its own), with `go vet` and staticcheck. They are test oracles, so a bug in one hides a
# bug in the runner. CI runs this on a pull request that changes them (ci.yml, "Go tools") and
# weekly (compare.yml). A finding fails; one that is wrong for this code is silenced where it is,
# with `//lint:ignore <check> <reason>` on the line before.
#
#   go-lint.sh          go vet and staticcheck
#   go-lint.sh vuln     govulncheck instead: known vulnerabilities in what the tools call. Weekly
#                       and informational, as the tools only read inputs CI makes or pins.
#
# staticcheck and govulncheck are built at the versions pinned below, by Go's module proxy and
# checked against its checksum database, with the newest toolchain any go.mod names (fetched and
# checked the same way): one built with an older Go cannot type-check code for a newer one.
set -euo pipefail
cd "$(dirname "$0")/../../runner/tools"

# Staticcheck's releases are named by year, its module versions by semver: v0.8.2 is 2026.2.2.
staticcheck=honnef.co/go/tools/cmd/staticcheck@v0.8.2
govulncheck=golang.org/x/vuln/cmd/govulncheck@v1.9.0

mode=${1:-lint}
case $mode in
lint) tool=$staticcheck ;;
vuln) tool=$govulncheck ;;
*)
	echo "usage: go-lint.sh [vuln]" >&2
	exit 2
	;;
esac

mapfile -t modules < <(git ls-files -- '*/go.mod' | xargs -n1 dirname)
((${#modules[@]} > 0)) || {
	echo "no Go modules under runner/tools" >&2
	exit 1
}
toolchain=$(for m in "${modules[@]}"; do sed -n 's/^go \([0-9.]*\)$/\1/p' "$m/go.mod"; done | sort -V | tail -n1)
export GOTOOLCHAIN=go$toolchain

bin=$(mktemp -d)
trap 'rm -rf "$bin"' EXIT
GOBIN=$bin go install "$tool"
go version

status=0
for m in "${modules[@]}"; do
	echo "== $m"
	case $mode in
	lint)
		(cd "$m" && go vet ./...) || status=1
		(cd "$m" && "$bin/staticcheck" ./...) || status=1
		;;
	vuln) (cd "$m" && "$bin/govulncheck" ./...) || status=1 ;;
	esac
done
((status == 0)) && echo "go-lint $mode: ${#modules[@]} modules, no findings"
exit "$status"
