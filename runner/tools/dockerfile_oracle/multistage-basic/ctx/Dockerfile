FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f AS build
WORKDIR /src
COPY app.sh .
RUN mkdir -p /out/bin /out/share && cp app.sh /out/bin/app && chmod 755 /out/bin/app && echo data > /out/share/data && ln -s bin/app /out/app-link
RUN echo second > /out/second

FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f AS unused
RUN echo never > /never

FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
ENV MODE=final
COPY --from=build /out/bin/app /usr/local/bin/app
COPY --from=build /out/share /usr/share/app/
COPY --from=build /out/app-link /app-link
COPY --from=build /out/* /everything/
COPY --from=0 /src/app.sh /app.sh
COPY --from=BUILD /etc/os-release /build-os-release
ENTRYPOINT ["/usr/local/bin/app"]
