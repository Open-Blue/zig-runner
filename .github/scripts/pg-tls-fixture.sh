#!/usr/bin/env bash
# The files for a Postgres that requires TLS and client certificates, for pg.zig's TLS tests
# (docs/rust-net.md, R2): a private CA, a server certificate for localhost and 127.0.0.1 (ECDSA),
# client certificates for two users, one with an ECDSA key (`pgecdsa`) and one with an RSA key
# (`pgrsa`, in PKCS#8 and in PKCS#1 form), a second, unrelated CA, the two certificates rustls refuses
# (a CA used as a leaf, a name only in the subject), and an init script for the
# container that installs them and makes the server demand them. Nothing here is secret: the keys
# exist for the test only and are generated afresh each time.
#
#   pg-tls-fixture.sh DIR
#
# Mounted by ci-database.sh at /docker-entrypoint-initdb.d for the Database tests job; used the
# same way by hand.
set -euo pipefail
dir=$(realpath -m "${1:?usage: pg-tls-fixture.sh DIR}")
mkdir -p "$dir"
cd "$dir"
days=2

# The CA, and a CA nobody trusts, to see the refusal.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days $days -subj "/CN=zig-runner test CA" \
	-addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
	-keyout ca-key.pem -out ca.pem 2>/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days $days -subj "/CN=another CA" \
	-addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
	-keyout other-ca-key.pem -out other-ca.pem 2>/dev/null

# leaf NAME CN KEYARGS... [-- extra extensions]: a key and a certificate signed by the CA.
leaf() {
	local name=$1 cn=$2 ext=$3
	shift 3
	openssl req -new -newkey "$@" -nodes -subj "/CN=$cn" -keyout "$name-key.pem" -out "$name.csr" 2>/dev/null
	printf '%s\n' "basicConstraints=critical,CA:FALSE" "$ext" >"$name.ext"
	openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days $days -extfile "$name.ext" \
		-out "$name.pem" 2>/dev/null
	rm -f "$name.csr" "$name.ext"
}
leaf server localhost "subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth" ec -pkeyopt ec_paramgen_curve:prime256v1
leaf client-ecdsa pgecdsa "extendedKeyUsage=clientAuth" ec -pkeyopt ec_paramgen_curve:prime256v1
leaf client-rsa pgrsa "extendedKeyUsage=clientAuth" rsa:2048
# The same RSA key in PKCS#1 form ("BEGIN RSA PRIVATE KEY"), which older tools write.
openssl rsa -in client-rsa-key.pem -traditional -out client-rsa-pkcs1-key.pem 2>/dev/null
# The ECDSA key in SEC1 form ("BEGIN EC PRIVATE KEY").
openssl ec -in client-ecdsa-key.pem -out client-ecdsa-sec1-key.pem 2>/dev/null
# A server certificate with the name only in the subject (no subjectAltName): rustls refuses it, the
# old client accepted it (the TLS oracle, runner/tls_oracle.zig).
leaf subject-only localhost "extendedKeyUsage=serverAuth" ec -pkeyopt ec_paramgen_curve:prime256v1
# A certificate for a CA used as a leaf (basicConstraints CA:TRUE, signed by the CA, for localhost): what
# rustls refuses and the old client accepted.
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=localhost" \
	-keyout ca-leaf-key.pem -out ca-leaf.csr 2>/dev/null
printf '%s\n' "basicConstraints=critical,CA:TRUE" "keyUsage=critical,digitalSignature,keyCertSign" \
	"subjectAltName=DNS:localhost,IP:127.0.0.1" >ca-leaf.ext
openssl x509 -req -in ca-leaf.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days $days -extfile ca-leaf.ext \
	-out ca-leaf.pem 2>/dev/null
rm -f ca-leaf.csr ca-leaf.ext
chmod 644 ./*.pem

# For the container: the files go into PGDATA (the key must be the server's own, mode 0600), the
# server turns TLS on and asks every client for a certificate it checks against the CA, and the two
# users may only come in by their certificates. The others keep their passwords, over TLS or not.
cat >init.sh <<'INIT'
#!/usr/bin/env bash
set -euo pipefail
src=/pg-tls
cp "$src/ca.pem" "$src/server.pem" "$src/server-key.pem" "$PGDATA/"
chmod 600 "$PGDATA/server-key.pem"
cat >>"$PGDATA/postgresql.conf" <<CONF
ssl = on
ssl_cert_file = 'server.pem'
ssl_key_file = 'server-key.pem'
ssl_ca_file = 'ca.pem'
CONF
psql -v ON_ERROR_STOP=1 -U postgres -d "$POSTGRES_DB" <<SQL
CREATE ROLE pgecdsa LOGIN;
CREATE ROLE pgrsa LOGIN;
GRANT ALL ON DATABASE $POSTGRES_DB TO pgecdsa, pgrsa;
SQL
{
	echo "hostssl all pgecdsa,pgrsa all cert"
	echo "host all pgecdsa,pgrsa all reject"
	cat "$PGDATA/pg_hba.conf"
} >"$PGDATA/pg_hba.new"
mv "$PGDATA/pg_hba.new" "$PGDATA/pg_hba.conf"
INIT
chmod 755 init.sh
