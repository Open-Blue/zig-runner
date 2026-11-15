FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
RUN echo a > /1 && chmod 600 /1 && mkdir -p /d/e && chmod 750 /d/e && ln -s /1 /link && chown 5:6 /1
RUN rm /link && echo b > /2 && mkdir /gone && echo g > /gone/x
RUN rm -r /gone && rm /etc/motd
COPY f /1
