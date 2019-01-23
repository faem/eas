#!/usr/bin/env bash
openssl genrsa -des3 -out as1-ca.key 2048
openssl req -x509 -new -nodes -key as1-ca.key -sha256 -days 1825 -out as1-ca.crt

openssl genrsa -out as1-tls.key 2048
openssl req -new -key as1-tls.key -out as1-tls.csr
openssl x509 -req -in as1-tls.csr -CA as1-ca.crt -CAkey as1-ca.key -CAcreateserial -out as1-tls.crt -days 1825

openssl genrsa -des3 -out as2-ca.key 2048
openssl req -x509 -new -nodes -key as2-ca.key -sha256 -days 1825 -out as2-ca.crt

openssl genrsa -out as2-tls.key 2048
openssl req -new -key as2-tls.key -out as2-tls.csr
openssl x509 -req -in as2-tls.csr -CA as2-ca.crt -CAkey as2-ca.key -CAcreateserial -out as2-tls.crt -days 1825






