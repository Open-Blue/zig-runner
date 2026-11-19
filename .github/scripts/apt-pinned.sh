#!/usr/bin/env bash
# apt.sh install for packages pinned to an exact version (PACKAGE=VERSION), which keeps the pin and
# says what changed when it fails: the archive's versions of each pinned package (apt-cache policy
# and madison), so the log shows what the archive has now, not only that the pin is gone. The pin
# stays on purpose: a new version fails here until it has been checked.
#
#   sudo .github/scripts/apt-pinned.sh [apt-get options] PACKAGE=VERSION...
#
# APT_SH replaces apt.sh (apt-pinned-test.sh).
set -uo pipefail

apt_sh=${APT_SH:-$(dirname "$0")/apt.sh}
status=0
"$apt_sh" install "$@" || status=$?
((status == 0)) && exit 0

echo "::group::apt-pinned: what the archive offers"
for arg in "$@"; do
	[[ $arg == *=* ]] || continue
	pkg=${arg%%=*}
	echo "apt-pinned: pinned $arg"
	apt-cache policy "$pkg" 2>&1 || true
	apt-cache madison "$pkg" 2>&1 || true
done
echo "::endgroup::"
pins=()
for arg in "$@"; do [[ $arg == *=* ]] && pins+=("$arg"); done
echo "::error title=Pinned apt package failed to install::${pins[*]} (exit $status): the archive's versions are in the log above; check the new one and update the pin"
exit "$status"
