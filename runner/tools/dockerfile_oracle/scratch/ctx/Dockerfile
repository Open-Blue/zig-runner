FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f AS build
RUN mkdir /out && echo static > /out/bin && chmod 755 /out/bin
FROM scratch
COPY --from=build /out/bin /bin-static
COPY ca.txt /etc/ssl/ca.txt
ENTRYPOINT ["/bin-static"]
