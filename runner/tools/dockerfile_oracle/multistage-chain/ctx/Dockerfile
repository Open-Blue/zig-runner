ARG BASE=alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
FROM ${BASE} AS base
ENV A=1 PATH="/base/bin:$PATH"
WORKDIR /work
USER root
RUN echo base > base-file
FROM base AS mid
ENV B=2
RUN echo mid > mid-file && pwd > pwd-mid
CMD ["mid"]
FROM mid
ARG BASE
ENV C=$A$B
RUN echo "$C $BASE" > final-file
COPY --from=base /work/base-file /copied-base
ENTRYPOINT ["/bin/sh", "-c", "echo hi"]
