FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
ADD http://@ADDR@/tool.bin /opt/
ADD http://@ADDR@/tool.bin /opt/renamed.bin
ADD http://@ADDR@/dir/other.txt?query=1 /opt/other/
ADD --chmod=755 http://@ADDR@/tool.bin /opt/exec.bin
ADD local.txt /opt/local.txt
