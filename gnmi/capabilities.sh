#!/bin/sh
gnmi_capabilities \
  -target_addr $GNMI_TARGET:$GNMI_PORT \
  -key $HOME/certs/client.key \
  -cert $HOME/certs/client.crt \
  -ca $HOME/certs/ca.crt \
  -target_name server.com \
  -alsologtostderr
