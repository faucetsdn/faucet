#!/bin/sh
gnmi_get \
  -target_addr $GNMI_TARGET:$GNMI_PORT \
  -key $HOME/certs/client.key \
  -cert $HOME/certs/client.crt \
  -ca $HOME/certs/ca.crt \
  -target_name server.com \
  -alsologtostderr \
  -xpath "/system/openflow/agent/config/datapath-id" \
  -xpath "/system/openflow/controllers/controller[name=main]/connections/connection[aux-id=0]/config/address"
