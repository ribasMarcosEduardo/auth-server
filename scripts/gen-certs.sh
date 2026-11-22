#!/usr/bin/env bash
# Gera o certificado TLS autoassinado do servidor de autorização (somente desenvolvimento).
# Uso: AUTH_KEYSTORE_PASSWORD=xxx ./scripts/gen-certs.sh
set -euo pipefail
: "${AUTH_KEYSTORE_PASSWORD:?Defina AUTH_KEYSTORE_PASSWORD (mesmo valor do .env)}"
mkdir -p certs
keytool -genkeypair -alias auth-server -keyalg RSA -keysize 2048 -validity 365 \
  -dname "CN=localhost,O=Trabalho Cyber Security" -ext "SAN=dns:localhost,ip:127.0.0.1" \
  -storetype PKCS12 -keystore certs/auth-server.p12 -storepass "$AUTH_KEYSTORE_PASSWORD"
keytool -exportcert -alias auth-server -keystore certs/auth-server.p12 \
  -storepass "$AUTH_KEYSTORE_PASSWORD" -rfc -file certs/auth-server.crt
echo "OK: certs/auth-server.p12 e certs/auth-server.crt (este .crt vai para o truststore da aplicação)"
