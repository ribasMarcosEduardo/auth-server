@echo off
REM Uso: set AUTH_KEYSTORE_PASSWORD=xxx && scripts\gen-certs.cmd
if "%AUTH_KEYSTORE_PASSWORD%"=="" (echo Defina AUTH_KEYSTORE_PASSWORD & exit /b 1)
if not exist certs mkdir certs
keytool -genkeypair -alias auth-server -keyalg RSA -keysize 2048 -validity 365 -dname "CN=localhost,O=Trabalho Cyber Security" -ext "SAN=dns:localhost,ip:127.0.0.1" -storetype PKCS12 -keystore certs\auth-server.p12 -storepass %AUTH_KEYSTORE_PASSWORD%
keytool -exportcert -alias auth-server -keystore certs\auth-server.p12 -storepass %AUTH_KEYSTORE_PASSWORD% -rfc -file certs\auth-server.crt
