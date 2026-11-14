FROM alpine:3.22
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
RUN echo $0 > /shell-name
RUN echo one | cat > /piped
SHELL ["/bin/sh", "-c"]
RUN echo $0 > /shell-name2
CMD echo shell form
ENTRYPOINT echo entry
