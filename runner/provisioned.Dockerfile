# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# The default job image with the runner's packages installed: what the runner provisions every
# new machine with (set_up.zig, `provision_script` and `provision_runner_script`), built once here
# and pulled instead (runner/src/dagger/provisioned.zig). It holds no copy of that script: the
# "provisioned image" workflow gets the base image, the script and the fingerprint from the runner
# binary itself (`--provisioned-image=VARIANT`, `--provision-script=VARIANT`) and passes them in.
#
#   docker build -f runner/provisioned.Dockerfile \
#     --build-arg BASE="$(runner --provisioned-image=root | cut -d' ' -f1)" \
#     --build-arg SCRIPT="$(runner --provision-script=root)" \
#     --build-arg VARIANT=root --build-arg FINGERPRINT=... <empty directory>
#
# No build context: nothing is copied in.

# hadolint ignore=DL3006
ARG BASE
# The default image, by digest, from the runner.
# hadolint ignore=DL3006
FROM ${BASE}
ARG SCRIPT
ARG VARIANT
ARG FINGERPRINT
# What provisioned-pin.sh checks the registry's copy against: the pin's tag.
LABEL dev.zig-runner.provision-fingerprint="${FINGERPRINT}-${VARIANT}" \
      org.opencontainers.image.source="https://github.com/Open-Blue/zig-runner" \
      org.opencontainers.image.description="The runner's default job image, provisioned (${VARIANT})"
# The runner's own script, run as the runner runs it: `sh -c`, as root.
RUN sh -c "$SCRIPT"
