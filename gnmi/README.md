# gNMI

A docker image that facilitates testing the gNMI protocol using Openconfig models.

*  See [gNMI Protocol documentation](https://github.com/openconfig/reference/tree/master/rpc/gnmi).
*  See [Openconfig documentation](http://www.openconfig.net/).

## How to build

From FAUCET root:

```
docker build -t faucet/gnmi -f Dockerfile.gnmi .
```

When building the image, a set of helper certificates is generated and added to `$HOME/certs/` folder:

*  Self signed CA Certificates
*  Client Certificates signed by the CA
*  Server Certificates signed by the CA

## How to run

```
docker run -ti faucet/gnmi:latest
```

When running the docker image a default test gNMI target is initiated:
```
root@090fe3d66fe7:~# cat run_target.sh 
#!/bin/sh
gnmi_target \
  -bind_address :$GNMI_PORT \
  -key $HOME/certs/server.key \
  -cert $HOME/certs/server.crt \
  -ca $HOME/certs/ca.crt \
  -alsologtostderr \
  &

root@090fe3d66fe7:~# set | grep GNMI
GNMI_PORT=32123
GNMI_QUERY='system/openflow/controllers/controller[name=main]/connections/connection[aux-id=0]/state/address'
GNMI_TARGET=localhost
```

Run a gNMI Get:
```
root@090fe3d66fe7:~# cat get.sh 
#!/bin/sh
gnmi_get \
  -target_address $GNMI_TARGET:$GNMI_PORT \
  -key $HOME/certs/client.key \
  -cert $HOME/certs/client.crt \
  -ca $HOME/certs/ca.crt \
  -target_name server \
  -alsologtostderr \
  -query $GNMI_QUERY
```

Override GNMI_TARGET, GNMI_PORT and GNMI_QUERY to perform the gNMI Get against other targets.

## Used gNMI tools:

*  [gNMI get](https://github.com/google/gnxi/tree/master/gnmi_get)
*  [gNMI target](https://github.com/google/gnxi/tree/master/gnmi_target)
