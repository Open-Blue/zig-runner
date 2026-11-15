FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
RUN adduser -D -u 4000 app && addgroup -g 4001 team
COPY --chown=app f /by-user
COPY --chown=app:team f /by-both
COPY --chown=nobody f /by-nobody
COPY --chown=1234:team f /mixed
