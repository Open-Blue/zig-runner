ARG BASE=alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
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
