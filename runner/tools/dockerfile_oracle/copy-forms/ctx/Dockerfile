FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
COPY f /usr
COPY f /newname
COPY f /tmp/
COPY f /tmp/q/r/s/f
COPY f /var/run/
COPY d /opt/app
COPY d /opt/app
COPY d/sub /tmp/sub
COPY d/ /dest-slash/
COPY lnk /alias/
COPY lnk /alias2
COPY dlnk /dlnk/
COPY f d/x /multi/
COPY --chmod=640 d /chmodded
COPY --chown=1000:1001 f /owned
COPY --chown=1000 d /owned-dir/
COPY . /everything/
COPY ./f ./w/../d/x /dots/
COPY --chmod=640 f /cm1/f
COPY --chmod=640 d /cm2/deeper
COPY --chmod=600 f /cm3/
