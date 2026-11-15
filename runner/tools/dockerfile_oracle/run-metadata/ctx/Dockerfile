FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN echo a > /1 && chmod 600 /1 && mkdir -p /d/e && chmod 750 /d/e && ln -s /1 /link && chown 5:6 /1
RUN rm /link && echo b > /2 && mkdir /gone && echo g > /gone/x
RUN rm -r /gone && rm /etc/motd
COPY f /1
