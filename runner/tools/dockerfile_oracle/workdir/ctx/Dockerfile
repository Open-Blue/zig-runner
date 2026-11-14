FROM alpine:3.22
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
