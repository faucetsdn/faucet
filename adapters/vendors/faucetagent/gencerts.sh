#!/bin/sh

# Simple helper script for generating certs, assumes you have openssl.

# set hostname to generate the certificates with
if [ -n "$1" ]; then
  if [ $1 = "-h" ]; then
    echo "gencerts.sh HOSTNAME CERT_DIR DAYS"
    exit 0
  else
    HOSTNAME=$2
  fi
else
  HOSTNAME="localhost"
fi

# set cert directory
if [ -n "$2" ]; then
  CERT_DIR=$1
else
  CERT_DIR=certs
fi

# set number of days until certs expire
if [ -n "$2" ]; then
  DAYS=$3
else
  DAYS=2
fi

mkdir -p $CERT_DIR

echo "Generating CA certs..."
openssl req -x509 -sha256 -nodes -days $DAYS -newkey rsa:2048 -keyout $CERT_DIR/ca.key -out $CERT_DIR/ca.crt -subj /CN=$HOSTNAME

echo "Generating server certs..."
openssl genrsa -out $CERT_DIR/server.key 2048
openssl req -new -key $CERT_DIR/server.key -out $CERT_DIR/server.csr -subj /CN=$HOSTNAME
openssl x509 -req -days $DAYS -in $CERT_DIR/server.csr -CA $CERT_DIR/ca.crt -CAkey $CERT_DIR/ca.key -set_serial 01 -out $CERT_DIR/server.crt

echo "Generating client certs (self-signed)..."
openssl req -x509 -sha256 -nodes -days $DAYS -newkey rsa:2048 -keyout $CERT_DIR/client.key -out $CERT_DIR/client.crt -subj /CN=$HOSTNAME
