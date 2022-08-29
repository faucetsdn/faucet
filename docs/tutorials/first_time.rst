Installing faucet for the first time
------------------------------------

This tutorial will run you through the steps of installing a complete faucet
system for the first time.

We will be installing and configuring the following components:

       ==========  ========================================
       Component   Purpose
       ==========  ========================================
       faucet      Network controller
       gauge       Monitoring controller
       prometheus  Monitoring system & time series database
       grafana     Monitoring dashboard
       ==========  ========================================

This tutorial was written for Ubuntu 16.04, however the steps should work fine
on any newer supported version of Ubuntu or Debian.

.. _tutorial-package-installation:

Package installation
^^^^^^^^^^^^^^^^^^^^

    1. Add the faucet official repo to our system:

       .. code:: console

           sudo apt-get install curl gnupg apt-transport-https lsb-release
           sudo mkdir -p /etc/apt/keyrings/
           curl -1sLf https://packagecloud.io/faucetsdn/faucet/gpgkey | sudo gpg --dearmor -o /etc/apt/keyrings/faucet.gpg
           echo "deb [signed-by=/etc/apt/keyrings/faucet.gpg] https://packagecloud.io/faucetsdn/faucet/$(lsb_release -si | awk '{print tolower($0)}')/ $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/faucet.list
           sudo apt-get update

    2. Install the required packages, we can use the ``faucet-all-in-one``
       metapackage which will install all the correct dependencies.

       .. code:: console

           sudo apt-get install faucet-all-in-one

.. _tutorial-configure-prometheus:

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

       First load ``http://localhost:3000`` in your web browser (by default both the
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

       .. code:: yaml

           [{'advertise_interval': 30,
             'arp_neighbor_timeout': 30,
             'cache_update_guard_time': 150,
             'combinatorial_port_flood': False,
             'cookie': 1524372928,
             'description': 'sw1',
             'dot1x': None,
             'dp_acls': None,
             'dp_id': 1,
             'drop_broadcast_source_address': True,
             'drop_spoofed_faucet_mac': True,
             'egress_pipeline': False,
             'fast_advertise_interval': 5,
             'faucet_dp_mac': '0e:00:00:00:00:01',
             'global_vlan': 0,
             'group_table': False,
             'hardware': 'Open vSwitch',
             'high_priority': 9001,
             'highest_priority': 9099,
             'idle_dst': True,
             'ignore_learn_ins': 10,
             'interface_ranges': OrderedDict(),
             'interfaces': {'host1': {'acl_in': None,
                                      'acls_in': None,
                                      'description': 'host1 network namespace',
                                      'dot1x': False,
                                      'enabled': True,
                                      'hairpin': False,
                                      'hairpin_unicast': False,
                                      'lacp': 0,
                                      'lacp_active': False,
                                      'lldp_beacon': OrderedDict(),
                                      'loop_protect': False,
                                      'loop_protect_external': False,
                                      'max_hosts': 255,
                                      'max_lldp_lost': 3,
                                      'mirror': None,
                                      'native_vlan': 'office',
                                      'number': 1,
                                      'opstatus_reconf': True,
                                      'output_only': False,
                                      'permanent_learn': False,
                                      'receive_lldp': False,
                                      'stack': OrderedDict(),
                                      'tagged_vlans': [],
                                      'unicast_flood': True},
                            'host2': {'acl_in': None,
                                      'acls_in': None,
                                      'description': 'host2 network namespace',
                                      'dot1x': False,
                                      'enabled': True,
                                      'hairpin': False,
                                      'hairpin_unicast': False,
                                      'lacp': 0,
                                      'lacp_active': False,
                                      'lldp_beacon': OrderedDict(),
                                      'loop_protect': False,
                                      'loop_protect_external': False,
                                      'max_hosts': 255,
                                      'max_lldp_lost': 3,
                                      'mirror': None,
                                      'native_vlan': 'office',
                                      'number': 2,
                                      'opstatus_reconf': True,
                                      'output_only': False,
                                      'permanent_learn': False,
                                      'receive_lldp': False,
                                      'stack': OrderedDict(),
                                      'tagged_vlans': [],
                                      'unicast_flood': True}},
             'lacp_timeout': 30,
             'learn_ban_timeout': 51,
             'learn_jitter': 51,
             'lldp_beacon': OrderedDict(),
             'low_priority': 9000,
             'lowest_priority': 0,
             'max_host_fib_retry_count': 10,
             'max_hosts_per_resolve_cycle': 5,
             'max_resolve_backoff_time': 64,
             'max_wildcard_table_size': 1280,
             'metrics_rate_limit_sec': 0,
             'min_wildcard_table_size': 32,
             'multi_out': True,
             'nd_neighbor_timeout': 30,
             'ofchannel_log': None,
             'packetin_pps': None,
             'slowpath_pps': None,
             'priority_offset': 0,
             'proactive_learn_v4': True,
             'proactive_learn_v6': True,
             'stack': None,
             'strict_packet_in_cookie': True,
             'table_sizes': OrderedDict(),
             'timeout': 300,
             'use_classification': False,
             'use_idle_timeout': False}]



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

.. _tutorial-first-datapath-connection:

Connect your first datapath
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Now that we've set up all the different components let's connect our first
switch (which we call a ``datapath``) to faucet. We will be using
`Open vSwitch <http://www.openvswitch.org/>`_ for this which is a
production-grade software switch with very good OpenFlow support.

    1. Install Open vSwitch

       .. code:: console

           sudo apt-get install openvswitch-switch

    2. Add network namespaces to simulate hosts

       We will use two linux network namespaces to simulate hosts and this will
       allow us to generate some traffic on our network.

       First let's define some useful bash functions by coping and pasting the
       following definitions into our bash terminal:

       .. literalinclude:: ../_static/tutorial/as_ns
          :language: bash

       .. literalinclude:: ../_static/tutorial/create_ns
          :language: bash

       NOTE: all the tutorial helper functions can be defined by sourcing
       ``helper-funcs`` into your shell enviroment.

       Now we will create ``host1`` and ``host2`` and assign them some IPs:

       .. code:: bash

           create_ns host1 192.168.0.1/24
           create_ns host2 192.168.0.2/24

    3. Configure Open vSwitch

       We will now configure a single Open vSwitch bridge (which will act as our
       datapath) and add two ports to this bridge:

       .. code:: console

         sudo ovs-vsctl add-br br0 \
         -- set bridge br0 other-config:datapath-id=0000000000000001 \
         -- set bridge br0 other-config:disable-in-band=true \
         -- set bridge br0 fail_mode=secure \
         -- add-port br0 veth-host1 -- set interface veth-host1 ofport_request=1 \
         -- add-port br0 veth-host2 -- set interface veth-host2 ofport_request=2 \
         -- set-controller br0 tcp:127.0.0.1:6653 tcp:127.0.0.1:6654

       The
       `Open vSwitch documentation <http://docs.openvswitch.org/en/latest/>`_
       is very good if you wish to find out more about configuring Open vSwitch.

    4. Verify datapath is connected to faucet

       At this point everything should be working, we just need to verify that
       is the case. If we now load up some of the grafana dashboards we imported
       earlier, we should see the datapath is now listed in the
       ``Faucet Inventory`` dashboard.

       If you don't see the new datapath listed you can look at the faucet log
       files ``/var/log/faucet/faucet.log`` or the Open vSwitch log
       ``/var/log/openvswitch/ovs-vswitchd.log`` for clues.

    5. Generate traffic between virtual hosts

       With ``host1`` and ``host2`` we can now test our network works and start
       generating some traffic which will show up in grafana.

       Let's start simple with a ping:

       .. code:: console

           as_ns host1 ping 192.168.0.2

       If this test is successful this shows our Open vSwitch is forwarding
       traffic under faucet control, ``/var/log/faucet/faucet.log`` should now
       indicate those two hosts have been learnt:

       .. code-block:: console
          :caption: /var/log/faucet/faucet.log
          :name: tutorial-learning-faucet.log

          faucet.valve INFO     DPID 1 (0x1) L2 learned 22:a6:c7:20:ff:3b (L2 type 0x0806, L3 src 192.168.0.1, L3 dst 192.168.0.2) on Port 1 on VLAN 100 (1 hosts total)
          faucet.valve INFO     DPID 1 (0x1) L2 learned 36:dc:0e:b2:a3:4b (L2 type 0x0806, L3 src 192.168.0.2, L3 dst 192.168.0.1) on Port 2 on VLAN 100 (2 hosts total)

       We can also use iperf to generate a large amount of traffic which will
       show up on the ``Port Statistics`` dashboard in grafana, just select
       ``sw1`` as the Datapath Name and ``All`` for the Port.

       .. code:: console

           sudo apt-get install iperf3
           as_ns host1 iperf3 --server --pidfile /run/iperf3-host1.pid --daemon
           as_ns host2 iperf3 --client 192.168.0.1

Further steps
^^^^^^^^^^^^^

Now that you know how to setup and run faucet in a self-contained virtual
environment you can build on this tutorial and start to make more interesting
topologies by adding more Open vSwitch bridges, ports and network namespaces.
Check out the faucet :doc:`../configuration` document for more information on
features you can turn on and off. In future we will publish additional tutorials
on layer 3 routing, inter-VLAN routing, ACLs.

You can also easily add real hardware into the mix as well instead of using
a software switch. See the :doc:`../vendors/index` section for information on how
to configure a wide variety of different vendor devices for faucet.
