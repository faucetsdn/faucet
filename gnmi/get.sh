#!/bin/sh
gnmi_get \
  -target_address $GNMI_TARGET:$GNMI_PORT \
  -key $HOME/certs/client.key \
  -cert $HOME/certs/client.crt \
  -ca $HOME/certs/ca.crt \
  -target_name server \
  -alsologtostderr \
  -query $GNMI_QUERY
