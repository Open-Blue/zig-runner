FROM alpine:3.22
RUN echo a > /1 && chmod 600 /1 && mkdir -p /d/e && chmod 750 /d/e && ln -s /1 /link && chown 5:6 /1
RUN rm /link && echo b > /2 && mkdir /gone && echo g > /gone/x
RUN rm -r /gone && rm /etc/motd
COPY f /1
