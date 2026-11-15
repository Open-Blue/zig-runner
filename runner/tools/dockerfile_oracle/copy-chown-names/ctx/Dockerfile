FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN adduser -D -u 4000 app && addgroup -g 4001 team
COPY --chown=app f /by-user
COPY --chown=app:team f /by-both
COPY --chown=nobody f /by-nobody
COPY --chown=1234:team f /mixed
