# shellcheck shell=bash
# Shared by the hooks (CONTRIBUTING.md, "Git hooks"): what they print, and finding the Zig the project
# builds with. The hook that sources this sets `hook` to its own name first.
: "${hook:?set by the hook that sources this}"

fail() {
	printf '\033[31m%s:\033[0m %s\n' "$hook" "$*" >&2
	printf '(git %s --no-verify skips the hooks, and CI will check the same things)\n' "${hook#pre-}" >&2
	exit 1
}

say() { printf '\033[2m%s: %s\033[0m\n' "$hook" "$*" >&2; }

# Zig as runner/build.zig.zon's minimum_zig_version names it, first on PATH: from $ZIG when set (a
# path to the zig binary), else whatever `zig` is. Another version formats and compiles
# differently, which is a CI failure the hook would not have caught.
use_zig() {
	local want have
	want=$(sed -n 's/^ *\.minimum_zig_version = "\(.*\)",$/\1/p' "$1/runner/build.zig.zon")
	if [[ -n ${ZIG:-} ]]; then PATH="$(dirname "$ZIG"):$PATH"; fi
	have=$(zig version 2>/dev/null || true)
	[[ $have == "$want" ]] ||
		fail "the project builds with Zig $want, and \`zig\` here is ${have:-missing}; put Zig $want first on PATH or set ZIG=/path/to/zig"
}
