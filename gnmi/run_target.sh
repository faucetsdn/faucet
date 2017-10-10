#!/bin/sh
gnmi_target \
  -bind_address :$GNMI_PORT \
  -key $HOME/certs/server.key \
  -cert $HOME/certs/server.crt \
  -ca $HOME/certs/ca.crt \
  -alsologtostderr \
  -config target_configs/typical_ofsw_config.json
