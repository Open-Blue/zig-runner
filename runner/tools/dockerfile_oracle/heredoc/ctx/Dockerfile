FROM alpine:3.22
ENV WHO=world
RUN <<EOF
set -e
echo "hello $WHO" > /greeting
echo second line >> /greeting
EOF
RUN cat <<EOF > /from-shell
shell $WHO
EOF
COPY <<EOF /etc/copied
copy $WHO
EOF
COPY <<'EOF' /etc/raw
raw $WHO
EOF
COPY --chmod=755 <<EOF /usr/local/bin/script.sh
echo script
EOF
COPY <<A <<B /docs/
a file
A
b file
B
COPY <<-EOF /etc/tabs
		tabbed
	EOF
