FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
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
