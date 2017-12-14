gNMI - gRPC Network Management Interface
========================================

A docker image that facilitates testing the gNMI protocol using Openconfig models.

*  See `gNMI Protocol documentation <https://github.com/openconfig/reference/tree/master/rpc/gnmi>`_.
*  See `Openconfig documentation <http://www.openconfig.net/>`_.

How to build
------------

From the gnmi directory:

.. code:: bash

  docker build -t faucet/gnmi -f Dockerfile .

When building the image, a set of helper certificates is generated and added to ``$HOME/certs/`` folder:

*  Self signed CA Certificates
*  Client Certificates signed by the CA
*  Server Certificates signed by the CA

How to run
----------

.. code:: bash

  docker run -ti faucet/gnmi:latest

When running the docker image a default test gNMI target is initiated with a default mock configuration defined in json:

.. code:: bash

  root@090fe3d66fe7:~# cat run_target.sh
  #!/bin/sh
  gnmi_target \
    -bind_address :$GNMI_PORT \
    -key $HOME/certs/server.key \
    -cert $HOME/certs/server.crt \
    -ca $HOME/certs/ca.crt \
    -alsologtostderr \
    -config target_configs/typical_ofsw_config.json

  root@090fe3d66fe7:~# set | grep GNMI
  GNMI_PORT=32123
  GNMI_TARGET=localhost

Run a gNMI Get:

.. code:: bash

  root@090fe3d66fe7:~# cat get.sh
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

Run gNMI Capabilities:

.. code:: bash

  root@090fe3d66fe7:~# cat capabilities.sh
  #!/bin/sh
  gnmi_capabilities \
    -target_addr $GNMI_TARGET:$GNMI_PORT \
    -key $HOME/certs/client.key \
    -cert $HOME/certs/client.crt \
    -ca $HOME/certs/ca.crt \
    -target_name server.com \
    -alsologtostderr

Override ``GNMI_TARGET`` and ``GNMI_PORT`` to perform the gNMI Get against other targets, or use the binaries directly.

gNxI tools
----------

*  `gNxI <https://github.com/google/gnxi>`_
