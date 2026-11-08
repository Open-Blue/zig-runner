#!/usr/bin/env bash
# The pre-provisioned default images (runner/src/dagger/provisioned.zig) and their pin
# (runner/src/dagger/provisioned_pin.zig): the one place that reads and writes both.
#
#   provisioned-pin.sh check         what CI's "Workflows" job runs: the pin, if there is one, names an
#                                    index on ghcr.io that covers linux/amd64 and linux/arm64, whose
#                                    bytes hash to the pinned digest, and whose images carry the label
#                                    the workflow gave them: the fingerprint the pin says. (That the
#                                    fingerprint is this build's, the script's and the base image's, is
#                                    a unit test's; this is that the registry holds what the pin says.)
#   provisioned-pin.sh fingerprints  JSON for the workflow: per variant (root, runner), the image to build
#                                    on, the fingerprint to tag with, and the script to run, all printed
#                                    by the runner itself, so no second copy of the script exists.
#   provisioned-pin.sh update        writes the pin from ghcr.io's tags of the current fingerprints:
#                                    run it after the "provisioned image" workflow published them.
#
# `fingerprints` and `update` compile the runner (ZIG_RUNNER_BIN names one already built).
# A registry that cannot be reached exits 75 (EX_TEMPFAIL), which CI tries again.
set -euo pipefail
cd "$(dirname "$0")/../.."

pin_file=runner/src/dagger/provisioned_pin.zig
registry=https://ghcr.io/v2/open-blue/zig-runner-base
label=dev.zig-runner.provision-fingerprint
accept='application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json'
variants=(root runner)

# pin_of VARIANT FIELD: the field (fingerprint or digest) of the variant's pin.
pin_of() {
	awk -v v="$1" -v f="$2" '
		$0 ~ "^pub const " v ": Pin" { inside = 1; next }
		inside && $0 ~ "^    \\." f " = " { gsub(/^[^"]*"|",?$/, ""); print; exit }
		inside && /^};/ { inside = 0 }' "$pin_file"
}

runner_bin() {
	if [[ -n ${ZIG_RUNNER_BIN:-} ]]; then
		echo "$ZIG_RUNNER_BIN"
		return
	fi
	local scratch
	scratch=$(mktemp -d)
	trap 'rm -rf "$scratch"' EXIT
	# The module graph is zig-modules.sh's, as for every build here; the version is no matter.
	(
		cd runner
		# shellcheck source=.github/scripts/zig-modules.sh
		. ../.github/scripts/zig-modules.sh
		printf 'provisioned-pin' >"$scratch/version"
		zig_modules "$scratch" "$scratch/version" -OReleaseSafe
		zig build-exe "${modules[@]}" --name runner -femit-bin="$scratch/runner" >&2
	)
	echo "$scratch/runner"
}

fingerprints() {
	local bin
	bin=$(runner_bin)
	local out='{}' v base fp script
	for v in "${variants[@]}"; do
		read -r base fp < <("$bin" "--provisioned-image=$v")
		script=$("$bin" "--provision-script=$v")
		out=$(jq -c --arg v "$v" --arg base "$base" --arg fp "$fp" --arg script "$script" \
			'.[$v] = {base: $base, fingerprint: $fp, script: $script}' <<<"$out")
	done
	echo "$out"
}

get_token() {
	curl -fsS --retry 2 'https://ghcr.io/token?service=ghcr.io&scope=repository:open-blue/zig-runner-base:pull' |
		jq -r .token
}

token=''
# fetch REF OUT: a manifest or blob by tag or digest, anonymously (the token asked for once).
fetch() {
	if [[ -z $token ]]; then
		token=$(get_token) || {
			echo "provisioned-pin: could not get an anonymous token from ghcr.io" >&2
			return 75
		}
	fi
	curl -fsS --retry 2 -o "$2" -H "Authorization: Bearer $token" -H "Accept: $accept" "$registry/$1"
}

check_variant() {
	local v=$1 fp digest
	fp=$(pin_of "$v" fingerprint)
	digest=$(pin_of "$v" digest)
	if [[ -z $digest ]]; then
		echo "provisioned-pin: $v: nothing pinned (jobs provision with apt-get)"
		return 0
	fi
	if [[ ! $digest =~ ^sha256:[a-f0-9]{64}$ || ! $fp =~ ^[a-f0-9]{12}$ ]]; then
		echo "provisioned-pin: $v: the pin is malformed ($fp, $digest)" >&2
		return 1
	fi
	local dir
	dir=$(mktemp -d)
	trap 'rm -rf "$dir"' RETURN
	fetch "manifests/$digest" "$dir/index" || {
		echo "provisioned-pin: $v: could not fetch $registry/manifests/$digest" >&2
		return 75
	}
	# The registry is trusted for nothing: the bytes must be the pinned digest's.
	if [[ sha256:$(sha256sum <"$dir/index" | cut -d' ' -f1) != "$digest" ]]; then
		echo "provisioned-pin: $v: what ghcr.io returned for $digest does not hash to it" >&2
		return 1
	fi
	if ! jq -e '.mediaType == "application/vnd.oci.image.index.v1+json"
		and ([.manifests[].platform | select(. != null) | "\(.os)/\(.architecture)"]
		     | (index("linux/amd64") != null and index("linux/arm64") != null))' "$dir/index" >/dev/null; then
		echo "provisioned-pin: $v: $digest is not an index listing linux/amd64 and linux/arm64" >&2
		return 1
	fi
	local arch m cfg got
	for arch in amd64 arm64; do
		m=$(jq -r --arg a "$arch" '.manifests[] | select(.platform.os == "linux" and .platform.architecture == $a) | .digest' "$dir/index" | head -n1)
		fetch "manifests/$m" "$dir/manifest" || return 75
		cfg=$(jq -r .config.digest "$dir/manifest")
		fetch "blobs/$cfg" "$dir/config" || return 75
		got=$(jq -r --arg l "$label" '.config.Labels[$l] // ""' "$dir/config")
		if [[ $got != "$fp-$v" ]]; then
			echo "provisioned-pin: $v: the $arch image says it is for '$got', the pin for '$fp-$v'" >&2
			return 1
		fi
	done
	echo "provisioned-pin: $v: $fp-$v@$digest, an index for linux/amd64 and linux/arm64, labelled for it"
}

update() {
	local plan v fp digest
	token=$(get_token) || {
		echo "provisioned-pin: could not get an anonymous token from ghcr.io" >&2
		return 75
	}
	plan=$(fingerprints)
	for v in "${variants[@]}"; do
		fp=$(jq -r --arg v "$v" '.[$v].fingerprint' <<<"$plan")
		# The tag's index digest, as the registry reports it.
		digest=$(curl -fsS --retry 2 -o /dev/null -D - -H "Authorization: Bearer $token" -H "Accept: $accept" \
			"$registry/manifests/$fp-$v" | tr -d '\r' | awk 'tolower($1) == "docker-content-digest:" { print $2 }') || digest=''
		if [[ -z $digest ]]; then
			echo "provisioned-pin: no image $fp-$v on ghcr.io: run the 'provisioned image' workflow" \
				"(workflow_dispatch, on this branch) first" >&2
			return 1
		fi
		sed -i "/^pub const $v: Pin/,/^};/{
			s|\.fingerprint = \".*\"|.fingerprint = \"$fp\"|
			s|\.digest = \".*\"|.digest = \"$digest\"|
		}" "$pin_file"
		echo "provisioned-pin: $v: $fp-$v@$digest"
	done
	echo "provisioned-pin: written to $pin_file; run 'provisioned-pin.sh check' and commit it"
}

case ${1:-} in
fingerprints) fingerprints ;;
update) update ;;
check)
	# An unpinned variant needs no registry at all.
	for v in "${variants[@]}"; do
		status=0
		check_variant "$v" || status=$?
		((status == 0)) || exit "$status"
	done
	;;
*)
	echo "usage: provisioned-pin.sh check | fingerprints | update" >&2
	exit 2
	;;
esac
