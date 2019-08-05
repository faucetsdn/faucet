#!/bin/bash

# Example client, assumes you have client certs, go, gnmi_get, and gnmi_set
HOSTNAME=$1
OPERATION=$2
NEW_CONFIG=$3

export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$PATH

if [ $OPERATION = "get" ]; then
  gnmi_get -ca /opt/faucetagent/certs/ca.crt -cert /opt/faucetagent/certs/client.crt -key /opt/faucetagent/certs/client.key -target_addr $HOSTNAME:10161 -target_name $HOSTNAME -xpath=/
elif [ $OPERATION = "set" ]; then
  CONFIG=$(cat $NEW_CONFIG)
  gnmi_set -ca /opt/faucetagent/certs/ca.crt -cert /opt/faucetagent/certs/client.crt -key /opt/faucetagent/certs/client.key -target_addr $HOSTNAME:10161 -target_name $HOSTNAME -replace=/:"$CONFIG"
else
  echo "Operation unknown"
fi
