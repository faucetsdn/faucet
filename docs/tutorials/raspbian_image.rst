Configuring with the facuet Raspbian image
------------------------------------------

This tutorial will go through the steps of installing the faucet
raspbian image onto a Raspberry Pi and configuring the main components.

Components:

       ==========  ========================================
       Component   Purpose
       ==========  ========================================
       faucet      Network controller
       gauge       Monitoring controller
       prometheus  Monitoring system & time series database
       grafana     Monitoring dashboard
       ==========  ========================================

.. note::
    It is strongly recommended to use a Raspberry Pi 3 or better.

.. _tutorial-pi-image:

Downloading & installing the image on a Raspberry Pi
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

First we need to get the faucet raspbian image onto our computer from the 
`latest faucet Raspbian image download <https://github.com/faucetsdn/faucet/releases/latest>`_.

The image can then be copied onto an SD card following the same steps from the official 
`Raspberry Pi installation guide <https://www.raspberrypi.org/documentation/installation/installing-images/linux.md>`_.

You should now have the faucet image installed onto an SD card.
Just plug the SD card into the Raspberry Pi and it will boot up.
Use the default login credentials to login to the Pi.

**Default Pi Login Credentials**

======== =========
Username Password
======== =========
pi       raspberry
======== =========

The image already contains faucet and the other components pre-installed.
Next we will be going through and configuring each component for use.

Configure prometheus
^^^^^^^^^^^^^^^^^^^^

We need to configure prometheus to tell it how to scrape metrics from both the
faucet and gauge controllers. To help make life easier faucet ships a sample
configuration file for prometheus which sets it up to scrape a single faucet
and gauge controller running on the same machine as prometheus. The
configuration file we ship looks like:

.. literalinclude:: ../../etc/prometheus/prometheus.yml

  :language: shell
  :caption: prometheus.yml
  :name: prometheus.yml

To learn more about what this configuration file does you can look at the
`Prometheus Configuration Documentation <https://prometheus.io/docs/prometheus/latest/configuration/configuration/>`_.
The simple explanation is that it includes an additional ``faucet.rules.yml``
file that performs some automatic queries in prometheus for generating some
additional metrics as well as setting up scrape jobs every 15 seconds for faucet
listening on ``localhost:9302`` and gauge listening on ``localhost:9303``.

Steps to make prometheus use the configuration file shipped with faucet:

    1. Change the configuration file prometheus loads by editing the file
       ``/etc/default/prometheus`` to look like:

       .. code-block:: bash

          :caption: /etc/default/prometheus
          :name: default-prometheus

          # Set the command-line arguments to pass to the server.
          ARGS="--config.file=/etc/faucet/prometheus/prometheus.yml"

    2. Restart prometheus to apply the changes:

       .. code:: console

           sudo systemctl restart prometheus

Configure grafana
^^^^^^^^^^^^^^^^^

Grafana running in it's default configuration will work just fine for our needs.
We will however need to make it start on boot, configure prometheus as a data
source and add our first dashboard:

    1. Make grafana start on boot and then start it manually for the first time:

       .. code:: console

           sudo systemctl daemon-reload
           sudo systemctl enable grafana-server
           sudo systemctl start grafana-server

    2. To finish setup we will configure grafana via the web interface.
       First find the IP address of your Raspberry Pi

       .. code:: console
       
           hostname -I

       Next load ``http://<Raspberry Pi IP address>:3000`` in your web browser (by default both the
       username and password are ``admin``).

    3. The web interface will first prompt us to add a data source. Use the
       following settings then click ``Save & Test``:

       ::

           Name:   Prometheus
           Type:   Prometheus
           URL:    http://localhost:9090

    4. Next we want to add some dashboards so that we can later view the metrics
       from faucet.

       Hover over the ``+`` button on the left sidebar in the web interface
       and click ``Import``.

       We will import the following dashboards, just download the following
       links and upload them through the grafana dashboard import screen:

       * `Instrumentation <../_static/grafana-dashboards/faucet_instrumentation.json>`_
       * `Inventory <../_static/grafana-dashboards/faucet_inventory.json>`_
       * `Port Statistics <../_static/grafana-dashboards/faucet_port_statistics.json>`_

Configure faucet
^^^^^^^^^^^^^^^^

For this tutorial we will configure a very simple network topology consisting
of a single switch with two ports.

    1. Configure faucet

       We need to tell faucet about our topology and VLAN information, we can do
       this by editing the faucet configuration ``/etc/faucet/faucet.yaml`` to
       look like:

       .. code-block:: yaml

          :caption: /etc/faucet/faucet.yaml
          :name: tutorial-faucet.yaml

          vlans:
              office:
                  vid: 100
                  description: "office network"

          dps:
              sw1:
                  dp_id: 0x1
                  hardware: "Open vSwitch"
                  interfaces:
                      1:
                          name: "host1"
                          description: "host1 network namespace"
                          native_vlan: office
                      2:
                          name: "host2"
                          description: "host2 network namespace"
                          native_vlan: office

       .. note::
          Tabs are forbidden in the YAML language, please use only spaces for
          indentation.

       This will create a single VLAN and a single datapath with two ports.

    2. Verify configuration

       The ``check_faucet_config`` command can be used to verify faucet has
       correctly interpreted your configuration before loading it. This can
       avoid shooting yourself in the foot by applying configuration with typos.
       We recommend either running this command by hand or with automation each
       time before loading configuration.

       .. code:: console

           check_faucet_config /etc/faucet/faucet.yaml

       This script will either return an error, or in the case of successfully
       parsing the configuration it will return a JSON object containing the
       entire faucet configuration that would be loaded (including any default
       settings), for example:

       .. code:: json

           {'drop_spoofed_faucet_mac': True, 'hardware': 'Open vSwitch', 'lowest_priority': 0, 'highest_priority': 9099, 'faucet_dp_mac': '0e:00:00:00:00:01', 'metrics_rate_limit_sec': 0, 'use_idle_timeout': False, 'max_resolve_backoff_time': 32, 'high_priority': 9001, 'timeout': 300, 'drop_lldp': True, 'learn_ban_timeout': 10, 'ofchannel_log': None, 'drop_broadcast_source_address': True, 'max_hosts_per_resolve_cycle': 5, 'proactive_learn': True, 'lldp_beacon': {}, 'cookie': 1524372928, 'stack': None, 'dp_id': 1, 'priority_offset': 0, 'description': 'sw1', 'max_host_fib_retry_count': 10, 'learn_jitter': 10, 'interfaces': {'p1': {'lldp_beacon': {}, 'unicast_flood': True, 'enabled': True, 'tagged_vlans': [], 'number': 1, 'description': 'port1', 'acls_in': None, 'mirror': None, 'acl_in': None, 'opstatus_reconf': True, 'hairpin': False, 'native_vlan': VLAN office vid:100 ports:Port 1,Port 2, 'loop_protect': False, 'stack': None, 'lacp': 0, 'override_output_port': None, 'receive_lldp': False, 'max_hosts': 255, 'permanent_learn': False, 'output_only': False}, 'p2': {'lldp_beacon': {}, 'unicast_flood': True, 'enabled': True, 'tagged_vlans': [], 'number': 2, 'description': 'port2', 'acls_in': None, 'mirror': None, 'acl_in': None, 'opstatus_reconf': True, 'hairpin': False, 'native_vlan': VLAN office vid:100 ports:Port 1,Port 2, 'loop_protect': False, 'stack': None, 'lacp': 0, 'override_output_port': None, 'receive_lldp': False, 'max_hosts': 255, 'permanent_learn': False, 'output_only': False}}, 'combinatorial_port_flood': True, 'packetin_pps': 0, 'ignore_learn_ins': 10, 'interface_ranges': {}, 'group_table_routing': False, 'advertise_interval': 30, 'group_table': False, 'low_priority': 9000, 'arp_neighbor_timeout': 250, 'drop_bpdu': True}

    3. Reload faucet

       To apply this configuration we can reload faucet which will cause it to
       compute the difference between the old and new configuration and apply
       the minimal set of changes to the network in a hitless fashion (where
       possible).

       .. code:: console

           sudo systemctl reload faucet

    4. Check logs

       To verify the configuration reload was successful we can check
       ``/var/log/faucet/faucet.log`` and make sure faucet successfully loaded
       the configuration we can check the faucet log file
       ``/var/log/faucet/faucet.log``:

       .. code-block:: console

          :caption: /var/log/faucet/faucet.log
          :name: tutorial-faucet.log

           faucet INFO     Loaded configuration from /etc/faucet/faucet.yaml
           faucet INFO     Add new datapath DPID 1 (0x1)
           faucet INFO     Add new datapath DPID 2 (0x2)
           faucet INFO     configuration /etc/faucet/faucet.yaml changed, analyzing differences
           faucet INFO     Reconfiguring existing datapath DPID 1 (0x1)
           faucet.valve INFO     DPID 1 (0x1) skipping configuration because datapath not up
           faucet INFO     Deleting de-configured DPID 2 (0x2)

       If there were any issues (say faucet wasn't able to find a valid pathway
       from the old config to the new config) we could issue a faucet restart
       now which will cause a cold restart of the network.

Configure gauge
^^^^^^^^^^^^^^^

We will not need to edit the default gauge configuration that is shipped with
faucet as it will be good enough to complete the rest of this tutorial. If you
did need to modify it the path is ``/etc/faucet/gauge.yaml`` and the default
configuration looks like:

.. literalinclude:: ../../etc/faucet/gauge.yaml

  :language: yaml
  :caption: gauge.yaml
  :name: tutorial-gauge.yaml

This default configuration will setup a prometheus exporter listening on
port ``0.0.0.0:9303`` and write all the different kind of gauge metrics to this
exporter.

We will however need to restart the current gauge instance so it can pick up
our new faucet configuration:

    .. code:: console

        sudo systemctl restart gauge

Last Steps
^^^^^^^^^^

Faucet and the other components should now be properly configured and running on your Raspberry Pi.
You can now connect a software switch up to faucet using :ref:`tutorial-first-datapath-connection`.

It is also possible to add hardware into your network, see the :doc:`../vendors/index` section 
for more information on how to configure the different vendor devices to faucet.

Click the faucet :doc:`../tutorials` document to find more tutorials for setting up Access Control Lists, 
VLANs, and more.
