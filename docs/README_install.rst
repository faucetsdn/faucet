=========================
Common Installation Tasks
=========================

These tasks are required by all installation methods.

You will need to provide an initial configuration files for FAUCET and Gauge, and create directores for FAUCET and Gauge to log to.

.. code:: bash

  mkdir -p /etc/ryu/faucet
  mkdir -p /var/log/ryu/faucet
  mkdir -p /var/log/ryu/gauge
  $EDITOR /etc/ryu/faucet/faucet.yaml
  $EDITOR /etc/ryu/faucet/gauge.yaml

This example ``faucet.yaml`` file creates an untagged VLAN between ports 1 and 2 on DP 0x1. See `README_config.rst` for
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


This example ``gauge.yaml`` file instructs Gauge to poll the switch at 10s intervals and store the results in InfluxDB.
See `README_config.rst` for more advanced configuration.

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



===============================================
Installation with Docker on Ubuntu with systemd
===============================================

We provide official automated builds on `Docker Hub <https://hub.docker.com/r/faucet/>`_ so that you can easily
run Faucet and it's components in a self-contained environment without installing on the main host system.
See `README.docker.md` for more advanced usage.

``path-to-config-dir`` (containing ``faucet.yaml``), ``path-to-faucet-logging-dir``, and ``path-to-gauge-logging-dir`` should be the directories you created, above.

.. code:: bash

    docker pull faucet/gauge:latest
    docker pull faucet/faucet:latest
    docker run -d \
        --name faucet \
        -v <path-to-config-dir>:/etc/ryu/faucet/ \
        -v <path-to-faucet-logging-dir>:/var/log/ryu/faucet/ \
        -p 6653:6653 \
        faucet/faucet
    docker run -d \
        --name faucet \
        -v <path-to-config-dir>:/etc/ryu/faucet/ \
        -v <path-to-gauge-logging-dir>:/var/log/ryu/faucet/ \
        -p 6654:6653 \
        faucet/gauge
    $EDITOR /etc/systemd/system/faucet.service
    $EDITOR /etc/systemd/system/gauge.service
    systemctl enable /etc/systemd/system/faucet.service
    systemctl enable /etc/systemd/system/gauge.service
    systemctl restart faucet
    systemctl restart gauge

``/etc/systemd/system/faucet.service`` should contain:

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

``/etc/systemd/system/gauge.service`` should contain:

.. code:: bash

    [Unit]
    description="Gauge OpenFlow switch controller"
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

.. code:: bash

    service faucet status
    service gauge status
    docker ps
