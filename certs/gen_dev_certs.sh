#!/usr/bin/env bash
set -e
export MSYS2_ARG_CONV_EXCL="*"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "=== Generating CLICOM Development Test Certificates ==="

# 1. Valid Root CA
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout ca.key -out ca.crt \
    -subj "/CN=CLICOM Dev Root CA/O=CLICOM Test/C=US" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

# 2. Server Key & CSR
openssl req -newkey rsa:2048 -nodes \
    -keyout server.key -out server.csr \
    -subj "/CN=localhost/O=CLICOM Server/C=US"

cat << 'EOF' > server_ext.cnf
basicConstraints = CA:FALSE
nsCertType = server
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 -extfile server_ext.cnf

rm -f server.csr server_ext.cnf

# 3. Untrusted Root CA (for negative security test)
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout untrusted_ca.key -out untrusted_ca.crt \
    -subj "/CN=Untrusted Rogue CA/O=Attacker Org/C=XX" \
    -addext "basicConstraints=critical,CA:TRUE"

# 4. Untrusted Server Cert
openssl req -newkey rsa:2048 -nodes \
    -keyout untrusted_server.key -out untrusted_server.csr \
    -subj "/CN=localhost/O=Untrusted Server/C=XX"

cat << 'EOF' > untrusted_ext.cnf
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in untrusted_server.csr -CA untrusted_ca.crt -CAkey untrusted_ca.key -CAcreateserial \
    -out untrusted_server.crt -days 365 -extfile untrusted_ext.cnf

rm -f untrusted_server.csr untrusted_ext.cnf

echo "=== Development Certificates Generated Successfully ==="
ls -l *.crt *.key
