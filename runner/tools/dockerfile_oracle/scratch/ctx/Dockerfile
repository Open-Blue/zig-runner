FROM alpine:3.22 AS build
RUN mkdir /out && echo static > /out/bin && chmod 755 /out/bin
FROM scratch
COPY --from=build /out/bin /bin-static
COPY ca.txt /etc/ssl/ca.txt
ENTRYPOINT ["/bin-static"]
