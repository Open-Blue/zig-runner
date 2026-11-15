FROM alpine:3.22
RUN adduser -D -u 4000 app && addgroup -g 4001 team
COPY --chown=app f /by-user
COPY --chown=app:team f /by-both
COPY --chown=nobody f /by-nobody
COPY --chown=1234:team f /mixed
