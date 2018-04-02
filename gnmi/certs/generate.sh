#!/bin/sh

rm -f *.key *.csr *.crt *.pem *.srl

SUBJ="/C=NZ/ST=Test/L=Test/O=Test/OU=Test/CN=ca"

# Generate CA Private Key
openssl req \
        -newkey rsa:2048 \
        -nodes \
        -keyout ca.key \
        -subj $SUBJ

# Generate Req
openssl req \
        -key ca.key \
        -new -out ca.csr \
        -subj $SUBJ

# Generate self signed x509
openssl x509 \
        -signkey ca.key \
        -in ca.csr \
        -req \
        -days 365 -out ca.crt 

SUBJ="/C=NZ/ST=Test/L=Test/O=Test/OU=Test/CN=server.com"

# Generate Server Private Key
openssl req \
        -newkey rsa:2048 \
        -nodes \
        -keyout server.key \
        -subj $SUBJ

# Generate Req
openssl req \
        -key server.key \
        -new -out server.csr \
        -subj $SUBJ

# Generate x509 with signed CA
openssl x509 \
        -req \
        -in server.csr \
        -CA ca.crt \
        -CAkey ca.key \
        -CAcreateserial \
        -out server.crt

SUBJ="/C=NZ/ST=Test/L=Test/O=Test/OU=Test/CN=client.com"

# Generate Client Private Key
openssl req \
        -newkey rsa:2048 \
        -nodes \
        -keyout client.key \
        -subj $SUBJ

# Generate Req
openssl req \
        -key client.key \
        -new -out client.csr \
        -subj $SUBJ

# Generate x509 with signed CA
openssl x509 \
        -req \
        -in client.csr \
        -CA ca.crt \
        -CAkey ca.key \
        -out client.crt

echo ""
echo " == Validate Server"
openssl verify -verbose -CAfile ca.crt server.crt
echo ""
echo " == Validate Client"
openssl verify -verbose -CAfile ca.crt client.crt

