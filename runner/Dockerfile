# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# The runner as a container image: one static binary and the CA certificates it verifies GitHub and
# the database with, nothing else (about 2 MB). The image is built from the release's own binaries
# (checked and attested) in prebuilt/runner-<amd64|arm64>, so it holds exactly the binaries the
# release does, without compiling them a second time:
#
#   docker buildx build --target prebuilt --platform linux/amd64,linux/arm64 -t <registry>/zig-runner runner/
#
# (after `.github/scripts/build-binaries.sh <version> dist` and copying dist/zig-runner-linux-x86_64
# and -aarch64 to runner/prebuilt/runner-amd64 and runner-arm64). There is no from-source stage:
# the runner's build needs Rust and Zig (docs/rust-net.md), neither of which an Alpine stage has.
# deploy/compose.yaml pulls the published image.
#
# Steps run in the Dagger engine, not here; deploy/compose.yaml runs the two together.

# Pinned by digest, which a moved tag cannot change; Renovate moves the pin.
FROM --platform=$BUILDPLATFORM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS certs
# Packages unversioned (hadolint DL3018): the image's digest pins the release, and Alpine keeps
# only the newest build of each package in it, so a pinned version stops installing at its next
# security fix.
# And an empty /tmp for the image, which has none: each job's log is spooled there
# (`RUNNER_LOG_SPOOL_DIR`). Without it every job kept its log in memory instead, up to 64 MB of
# lines and as much again in bookkeeping: a job that logged 200 MB grew the runner by 170 MB.
# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates \
 && mkdir -m 1777 /image-tmp

FROM scratch AS prebuilt
ARG TARGETARCH
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=certs --chmod=1777 /image-tmp /tmp
COPY prebuilt/runner-${TARGETARCH} /runner
STOPSIGNAL SIGTERM
ENTRYPOINT ["/runner"]
