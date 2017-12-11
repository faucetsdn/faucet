Installation
============

Common Installation Tasks
-------------------------

These tasks are required by all installation methods.

You will need to provide an initial configuration files for FAUCET and Gauge, and create directores for FAUCET and Gauge to log to.

.. code:: console

  mkdir -p /etc/ryu/faucet
  mkdir -p /var/log/ryu/faucet
  mkdir -p /var/log/ryu/gauge
  $EDITOR /etc/ryu/faucet/faucet.yaml
  $EDITOR /etc/ryu/faucet/gauge.yaml

This example ``faucet.yaml`` file creates an untagged VLAN between ports 1 and 2 on DP 0x1. See :doc:`configuration` for
more advanced configuration. See :doc:`vendors/index` for how to configure your switch.

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


This example ``gauge.yaml`` file instructs Gauge to poll the switch at 10s intervals and store the results in InfluxDB.
See :doc:`configuration` for more advanced configuration.

.. code:: yaml

  faucet_configs:
      - '/etc/ryu/faucet/faucet.yaml'
  watchers:
      port_stats:
          dps: ['switch-1']
          type: 'port_stats'
          interval: 10
          db: 'influx'
      port_state:
          dps: ['switch-1']
          type: 'port_state'
          interval: 10
          db: 'influx'
  dbs:
      influx:
          type: 'influx'
          influx_db: 'faucet'
          influx_host: '172.17.0.1'
          influx_port: 8086
          influx_user: 'faucet'
          influx_pwd: ''
          influx_timeout: 10

Encrypted Control Channel
-------------------------

This section outlines the steps needed to test that a switch supports self-signed certificates for TLS based Openflow connections.

Prepare the keys and certificates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Generate key pairs for the controller.

.. code:: console

    /usr/bin/openssl genrsa -out /etc/ryu/ctrlr.key 2048
    /usr/bin/openssl req -new -x509 -nodes -days 3650 -subj '/C=US/ST=CA/L=Mountain View/O=Faucet/OU=Faucet/CN=CTRLR_1' -key /etc/ryu/ctrlr.key -out /etc/ryu/ctrlr.cert

Generate key pairs for the switch.

.. code:: console

    /usr/bin/openssl genrsa -out /etc/ryu/sw.key 2048
    /usr/bin/openssl req -new -x509 -nodes -days 3650 -subj '/C=US/ST=CA/L=Mountain View/O=Faucet/OU=Faucet/CN=SW_1' -key /etc/ryu/sw.key -out /etc/ryu/sw.cert

Push key pairs to the switch
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Copy ``/etc/ryu/ctrlr.cert`` ``/etc/ryu/sw.key`` and ``/etc/ryu/sw.cert`` to the switch. Configure the switch to use the keys.

For example, the command for OVS would be:

.. code:: console

    ovs-vsctl set-ssl  /etc/ryu/sw.key /etc/ryu/sw.cert  /etc/ryu/ctrlr.cert
    ovs-vsctl set-controller br0 ssl:<ctrlr_ip>:6653

Start Faucet with the keys (make sure the keys are readable by the user that
starts the faucet process)

.. code:: console

    ryu-manager --ctl-privkey /etc/ryu/ctrlr.key --ctl-cert /etc/ryu/ctrlr.cert  --ca-certs /etc/ryu/sw.cert faucet.faucet --verbose

Support multiple switches
~~~~~~~~~~~~~~~~~~~~~~~~~

To support multiple switches, generate key pairs for each switch, and concatenate their certificates into one file and use that file as */etc/ryu/sw.cert*.

Installation with Docker on Ubuntu with systemd
-----------------------------------------------

We provide official automated builds on `Docker Hub <https://hub.docker.com/r/faucet/>`_ so that you can easily
run Faucet and it's components in a self-contained environment without installing on the main host system.

See :doc:`docker` for how to install the FAUCET and Gauge images.

You can configure systemd to start the containers automatically:

.. code:: console

    $EDITOR /etc/systemd/system/faucet.service
    $EDITOR /etc/systemd/system/gauge.service
    systemctl daemon-reload
    systemctl enable faucet.service
    systemctl enable gauge.service
    systemctl restart faucet
    systemctl restart gauge

``/etc/systemd/system/faucet.service`` should contain:

.. code:: shell

    [Unit]
    Description="FAUCET OpenFlow switch controller"
    After=network-online.target
    Wants=network-online.target
    After=docker.service

    [Service]
    Restart=always
    ExecStart=/usr/bin/docker start -a faucet
    ExecStop=/usr/bin/docker stop -t 2 faucet

    [Install]
    WantedBy=multi-user.target

``/etc/systemd/system/gauge.service`` should contain:

.. code:: shell

    [Unit]
    Description="Gauge OpenFlow switch controller"
    After=network-online.target
    Wants=network-online.target
    After=docker.service

    [Service]
    Restart=always
    ExecStart=/usr/bin/docker start -a gauge
    ExecStop=/usr/bin/docker stop -t 2 gauge

    [Install]
    WantedBy=multi-user.target

You can check that FAUCET and Gauge are running via systemd or via docker:

.. code:: console

    service faucet status
    service gauge status
    docker ps

Installation with pip
---------------------

You can install the latest pip package, or you can install directly from git via pip.

To install the latest pip package:

.. code:: console

  apt-get install python3-pip
  pip3 install faucet

To install the latest code from git, via pip:

.. code:: console

  pip3 install git+https://github.com/faucetsdn/faucet.git

You can then start FAUCET manually:

.. code:: console

  ryu-manager faucet.faucet --verbose

Or, you can configure systemd to start the containers automatically:

.. code:: console

    $EDITOR /etc/systemd/system/faucet.service
    $EDITOR /etc/systemd/system/gauge.service
    systemctl daemon-reload
    systemctl enable faucet.service
    systemctl enable gauge.service
    systemctl restart faucet
    systemctl restart gauge

``/etc/systemd/system/faucet.service`` should contain:

.. literalinclude:: ../etc/systemd/system/faucet.service
  :language: shell
  :caption: faucet.service
  :name: faucet.service

``/etc/systemd/system/gauge.service`` should contain:

.. literalinclude:: ../etc/systemd/system/gauge.service
  :language: shell
  :caption: gauge.service
  :name: gauge.service
