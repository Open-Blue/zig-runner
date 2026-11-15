FROM alpine:3.22
COPY --from=busybox:1.37 /bin/busybox /opt/busybox
COPY --from=busybox:1.37 /etc/passwd /etc/passwd-busybox
COPY --from=busybox:1.37 /home /home-busybox/
COPY --chown=5:6 --from=busybox:1.37 /bin/true /opt/true
