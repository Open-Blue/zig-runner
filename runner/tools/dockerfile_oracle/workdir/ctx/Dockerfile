FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
RUN adduser -D -u 4000 app
WORKDIR /w/ork/sub
RUN pwd > /pwd1
USER app
WORKDIR /as-app/deep
WORKDIR ../other
WORKDIR /w/ork/sub
WORKDIR /var/run/x
USER root
RUN pwd > /pwd2
