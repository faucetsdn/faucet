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
          description: "dev VLAN"
  dps:
      switch-1:
          dp_id: 0x1
          interfaces:
              1:
                  native_vlan: 100
              2:
                  native_vlan: 100


This example ``gauge.yaml`` file instructs Gauge to poll the switch at 10s intervals and make the results available to Prometheus.
See :doc:`configuration` for more advanced configuration.

.. code:: yaml

  faucet_configs:
      - '/etc/ryu/faucet/faucet.yaml'
  watchers:
    port_stats:
        dps: ['switch-1']
        type: 'port_stats'
        interval: 10
        db: 'prometheus'
    flow_table:
        dps: ['switch-1']
        type: 'flow_table'
        interval: 10
        db: 'prometheus'
  dbs:
    prometheus:
        type: 'prometheus'
        prometheus_port: 9303
        prometheus_addr: ''


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

    faucet --ryu-ctl-privkey /etc/ryu/ctrlr.key --ryu-ctl-cert /etc/ryu/ctrlr.cert --ryu-ca-certs /etc/ryu/sw.cert --verbose

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

  apt-get install python3-dev python3-pip
  pip3 install setuptools
  pip3 install wheel
  pip3 install faucet

To install the latest code from git, via pip:

.. code:: console

  pip3 install git+https://github.com/faucetsdn/faucet.git

You can then start FAUCET manually:

.. code:: console

  faucet --verbose

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

Virtual Machine Image
---------------------

We provide a VM image for running FAUCET for development and learning purposes.
The VM comes pre-installed with FAUCET, GAUGE, prometheus and grafana.

Openstack's `diskimage-builder <https://docs.openstack.org/diskimage-builder/latest/>`_
(DIB) is used to build the VM images in many formats (qcow2,tgz,squashfs,vhd,raw).

We provide `DIB elements <elements>`_ for configuring each component installed in the VM.

Pre-built images are available on our build host `<https://builder.faucet.nz>`_.

Building the images
~~~~~~~~~~~~~~~~~~~

If you don't want to use our `pre-built images <https://builder.faucet.nz>`_, you can build them yourself:

1. `Install the latest disk-image-builder <https://docs.openstack.org/diskimage-builder/latest/user_guide/installation.html>`_
2. `Install a patched vhd-util <https://launchpad.net/~openstack-ci-core/+archive/ubuntu/vhd-util>`_
3. Run build-faucet-vm.sh

Security Considerations
~~~~~~~~~~~~~~~~~~~~~~~

This VM is not secure by default, it includes no firewall and has a number of
network services listening on all interfaces with weak passwords. It also
includes a backdoor user (faucet) with weak credentials.

**Services**

The VM exposes a number of ports listening on all interfaces by default:

======================== ====
Service                  Port
======================== ====
SSH                      22
Faucet OpenFlow Channel  6653
Gauge OpenFlow Channel   6654
Grafana Web Interface    3000
Prometheus Web Interface 3000
======================== ====

**Default Credentials**

===================== ======== ========
Service               Username Password
===================== ======== ========
VM TTY Console        faucet   faucet
SSH                   faucet   faucet
Grafana Web Interface admin    admin
===================== ======== ========

Post-Install Steps
~~~~~~~~~~~~~~~~~~

Grafana comes installed but unconfigured, you will need to login to the grafana
web interface at ``http://VM_IP:3000`` and configure a data source and some dashboards.

After logging in with the default credentials shown above, the first step is to add a `prometheus data source <https://prometheus.io/docs/visualization/grafana/#creating-a-prometheus-data-source>`_,
please add ``http://localhost:9090`` as your data source.
Next step is to configure some dashboards, you can add some we have `prepared earlier <https://monitoring.redcables.wand.nz/grafana-dashboards/>`_
or `create your own <http://docs.grafana.org/features/datasources/prometheus/>`_.

You will need to supply your own faucet.yaml and gauge.yaml configuration in the VM.
There are samples provided at /etc/ryu/faucet/faucet.yaml and /etc/ryu/faucet/gauge.yaml.

Finally you will need to point one of the supported OpenFlow vendors at the controller VM,
port 6653 is the Faucet OpenFlow control channel and 6654 is the Gauge OpennFlow control channel for monitoring.
