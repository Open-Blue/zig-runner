FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
RUN echo $0 > /shell-name
RUN echo one | cat > /piped
SHELL ["/bin/sh", "-c"]
RUN echo $0 > /shell-name2
CMD echo shell form
ENTRYPOINT echo entry
