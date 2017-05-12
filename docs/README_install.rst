=========================
Common Installation Tasks
=========================

You will need to provide an initial configuration file for FAUCET, and create a directory for FAUCET to log to.

.. code:: bash

  mkdir -p /etc/ryu/faucet
  mkdir -p /var/log/ryu/faucet
  $EDITOR /etc/ryu/faucet/faucet.yaml

This example config file creates an untagged VLAN between ports 1 and 2 on DP 0x1. See ``README_config.rst`` for
more advanced configuration. See `vendors <vendors>`_ for how to configure your switch.

.. code:: yaml

  vlans:
      100:
          name: "dev VLAN"
  dps:
      switch-1:
          dp_id: 0x1
          interfaces:
              1:
                  native_vlan: 100
              2:
                  native_vlan: 100


===============================================
Installation with Docker on Ubuntu with systemd
===============================================

We provide official automated builds on `Docker Hub <https://hub.docker.com/r/faucet/>`_ so that you can easily
run Faucet and it's components in a self-contained environment without installing on the main host system.
See ``README.docker.md`` for more advanced usage.

path-to-config-dir (containing faucet.yaml) and path-to-logging-dir should be the directories you created, above.

.. code:: bash

    docker pull faucet/faucet:latest
    docker run -d \
        --name faucet \
        -v <path-to-config-dir>:/etc/ryu/faucet/ \
        -v <path-to-logging-dir>:/var/log/ryu/faucet/ \
        -p 6653:6653 \
        faucet/faucet
    $EDITOR /etc/systemd/system/faucet.service
    systemctl enable /etc/systemd/system/faucet.service
    systemctl restart faucet

/etc/systemd/system/faucet.service should contain:

.. code:: bash

    [Unit]
    description="FAUCET OpenFlow switch controller"
    After=network-online.target
    Wants=network-online.target
    After=docker.service

    [Service]
    Restart=always
    ExecStart=/usr/bin/docker start -a faucet 
    ExecStop=/usr/bin/docker stop -t 2 faucet

    [Install]
    WantedBy=multi-user.target

.. code:: bash

    service faucet status
