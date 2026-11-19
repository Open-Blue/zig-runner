#!/usr/bin/env bash
# Lets an unprivileged user create user namespaces, which the runner's native backend does for every
# rootless sandbox. Ubuntu's AppArmor (24.04 on) refuses them by default
# (`kernel.apparmor_restrict_unprivileged_userns=1`), so CI's throwaway VMs lift that before their
# native tests. The key is the kernel's, not ours: a runner image whose kernel lacks it made the bare
# `sysctl -w` this replaces fail every native job with "cannot stat /proc/sys/...", which says
# nothing of the cause. So this says which kernel it found, whether the key exists, and its value
# before and after, and a kernel without the key (nothing there restricts user namespaces through
# AppArmor) is a note, not a failure. If user namespaces are refused anyway, the log then holds the
# other switches that can do it.
#
#   allow-userns.sh
#
# Writes with sudo (nothing when already root); fails if the value is not 0 afterwards. Never run
# it on a machine you use for other things: it lifts a protection. ALLOW_USERNS_PROC_SYS (default
# /proc/sys) and ALLOW_USERNS_SUDO (default sudo) exist for allow-userns-test.sh alone.
set -euo pipefail

proc=${ALLOW_USERNS_PROC_SYS:-/proc/sys}
if [[ -n ${ALLOW_USERNS_SUDO+set} ]]; then
	read -r -a as_root <<<"$ALLOW_USERNS_SUDO"
elif ((EUID == 0)); then
	as_root=()
else
	as_root=(sudo)
fi
key=$proc/kernel/apparmor_restrict_unprivileged_userns

# value FILE: its content, or "absent" when the kernel has no such file.
value() {
	if [[ -r $1 ]]; then cat "$1"; else echo absent; fi
}

echo "allow-userns: kernel $(uname -r)"
if [[ ! -e $key ]]; then
	echo "allow-userns: kernel.apparmor_restrict_unprivileged_userns does not exist on this kernel;" \
		"AppArmor restricts nothing here, so there is nothing to lift"
	echo "allow-userns: kernel.unprivileged_userns_clone=$(value "$proc/kernel/unprivileged_userns_clone")" \
		"user.max_user_namespaces=$(value "$proc/user/max_user_namespaces")"
	exit 0
fi

before=$(cat "$key")
echo "allow-userns: kernel.apparmor_restrict_unprivileged_userns exists, before: $before"
if ! echo 0 | "${as_root[@]}" tee "$key" >/dev/null; then
	echo "allow-userns: could not write 0 to $key" >&2
	exit 1
fi
after=$(cat "$key")
echo "allow-userns: kernel.apparmor_restrict_unprivileged_userns after: $after"
if [[ $after != 0 ]]; then
	echo "allow-userns: wrote 0 but the kernel still says $after; rootless native tests will fail" >&2
	exit 1
fi
