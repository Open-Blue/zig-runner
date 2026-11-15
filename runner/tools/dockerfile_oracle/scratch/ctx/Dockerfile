FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS build
RUN mkdir /out && echo static > /out/bin && chmod 755 /out/bin
FROM scratch
COPY --from=build /out/bin /bin-static
COPY ca.txt /etc/ssl/ca.txt
ENTRYPOINT ["/bin-static"]
