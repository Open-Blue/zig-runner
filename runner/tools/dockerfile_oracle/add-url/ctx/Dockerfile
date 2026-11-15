FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
ADD http://@ADDR@/tool.bin /opt/
ADD http://@ADDR@/tool.bin /opt/renamed.bin
ADD http://@ADDR@/dir/other.txt?query=1 /opt/other/
ADD --chmod=755 http://@ADDR@/tool.bin /opt/exec.bin
ADD local.txt /opt/local.txt
