# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# The runner as a container image: one static binary and the CA certificates it verifies GitHub and
# the database with, nothing else (about 2 MB). Zig cross-compiles, so the build stage runs on the
# build machine's platform for every target platform.
#
#   docker build -t zig-runner runner/
#   docker buildx build --platform linux/amd64,linux/arm64 -t <registry>/zig-runner runner/
#
# Steps run in the Dagger engine, not here; deploy/compose.yaml runs the two together.
#
# The release workflow builds `--target prebuilt` instead, from the release's own binaries
# (checked and attested) in prebuilt/runner-<amd64|arm64>, so the image holds exactly the binaries
# the release does, without compiling them a second time.

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

# From source, the default.
FROM --platform=$BUILDPLATFORM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS build
# The checksums ziglang.org publishes for this version (.github/scripts/install-zig.sh has the same).
ARG ZIG_VERSION=0.17.0
ARG ZIG_SHA256_X86_64=1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026
ARG ZIG_SHA256_AARCH64=9e8d11661d4ae3bd57702a3832781e23ad151dde5798e16a5ccd503f65234ff8
ARG TARGETARCH
# What `--version` and every job's "Set up job" report. The build context holds no `.git`, so the
# version cannot be derived here: unset, the binary falls back to the package version, which says
# nothing about which build it is. Pass `--build-arg VERSION=...`; the release's image is
# `prebuilt`, whose binaries carry theirs.
ARG VERSION=
# Unversioned, as in `certs` above.
# hadolint ignore=DL3018
RUN apk add --no-cache curl xz ca-certificates
# A failed command anywhere in a pipeline fails the step (busybox's ash has pipefail).
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
RUN arch="$(uname -m)" \
 && case "$arch" in \
      x86_64) sum="$ZIG_SHA256_X86_64" ;; \
      aarch64) sum="$ZIG_SHA256_AARCH64" ;; \
      *) echo "no Zig checksum for $arch" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/zig.tar.xz "https://ziglang.org/download/${ZIG_VERSION}/zig-${arch}-linux-${ZIG_VERSION}.tar.xz" \
 && echo "$sum  /tmp/zig.tar.xz" | sha256sum -c - \
 && tar -xJf /tmp/zig.tar.xz -C /opt \
 && rm /tmp/zig.tar.xz \
 && ln -s "/opt/zig-${arch}-linux-${ZIG_VERSION}/zig" /usr/local/bin/zig
WORKDIR /src
COPY build.zig build.zig.zon ./
COPY src ./src
RUN case "$TARGETARCH" in \
      amd64) target=x86_64-linux-musl ;; \
      arm64) target=aarch64-linux-musl ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
 && zig build -Doptimize=ReleaseSafe -Dstrip -Dtarget="$target" ${VERSION:+-Dversion="$VERSION"} --prefix /out

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=certs --chmod=1777 /image-tmp /tmp
COPY --from=build /out/bin/runner /runner
# SIGTERM (docker stop) lets running jobs finish; give it time (see stop_grace_period in compose).
STOPSIGNAL SIGTERM
ENTRYPOINT ["/runner"]
