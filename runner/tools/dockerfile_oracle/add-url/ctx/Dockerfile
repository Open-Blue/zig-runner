FROM alpine:3.22
ADD http://@ADDR@/tool.bin /opt/
ADD http://@ADDR@/tool.bin /opt/renamed.bin
ADD http://@ADDR@/dir/other.txt?query=1 /opt/other/
ADD --chmod=755 http://@ADDR@/tool.bin /opt/exec.bin
ADD local.txt /opt/local.txt
