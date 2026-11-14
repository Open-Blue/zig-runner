FROM alpine:3.22
LABEL org.example.name="basic"
ENV TOOL_HOME=/opt/tool PATH="/opt/tool/bin:$PATH"
WORKDIR /opt
WORKDIR tool
COPY entrypoint.sh /opt/tool/bin/entrypoint.sh
RUN echo built > /opt/tool/built && chmod 700 /opt/tool/built && pwd > /opt/tool/cwd
CMD ["default", "args"]
ENTRYPOINT ["/opt/tool/bin/entrypoint.sh"]
