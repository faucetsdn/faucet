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

Package installation
^^^^^^^^^^^^^^^^^^^^

    1. Add the faucet official repo to our system:

       .. code:: console

           sudo apt-get install curl gnupg apt-transport-https lsb-release
           echo "deb https://packagecloud.io/faucetsdn/faucet/$(lsb_release -si | awk '{print tolower($0)}')/ $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/faucet.list
           curl -L https://packagecloud.io/faucetsdn/faucet/gpgkey | sudo apt-key add -
           sudo apt-get update

    2. Install the required packages, we can use the ``faucet-all-in-one``
       metapackage which will install all the correct dependencies.

       .. code:: console

           sudo apt-get install faucet-all-in-one

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

       .. code:: json

           {'drop_spoofed_faucet_mac': True, 'hardware': 'Open vSwitch', 'lowest_priority': 0, 'highest_priority': 9099, 'faucet_dp_mac': '0e:00:00:00:00:01', 'metrics_rate_limit_sec': 0, 'use_idle_timeout': False, 'max_resolve_backoff_time': 32, 'high_priority': 9001, 'timeout': 300, 'pipeline_config_dir': '/etc/faucet', 'drop_lldp': True, 'learn_ban_timeout': 10, 'ofchannel_log': None, 'drop_broadcast_source_address': True, 'max_hosts_per_resolve_cycle': 5, 'proactive_learn': True, 'lldp_beacon': {}, 'cookie': 1524372928, 'stack': None, 'dp_id': 1, 'priority_offset': 0, 'description': 'sw1', 'max_host_fib_retry_count': 10, 'learn_jitter': 10, 'interfaces': {'p1': {'lldp_beacon': {}, 'unicast_flood': True, 'enabled': True, 'tagged_vlans': [], 'number': 1, 'description': 'port1', 'acls_in': None, 'mirror': None, 'acl_in': None, 'opstatus_reconf': True, 'hairpin': False, 'native_vlan': VLAN office vid:100 ports:Port 1,Port 2, 'loop_protect': False, 'stack': None, 'lacp': 0, 'override_output_port': None, 'receive_lldp': False, 'max_hosts': 255, 'permanent_learn': False, 'output_only': False}, 'p2': {'lldp_beacon': {}, 'unicast_flood': True, 'enabled': True, 'tagged_vlans': [], 'number': 2, 'description': 'port2', 'acls_in': None, 'mirror': None, 'acl_in': None, 'opstatus_reconf': True, 'hairpin': False, 'native_vlan': VLAN office vid:100 ports:Port 1,Port 2, 'loop_protect': False, 'stack': None, 'lacp': 0, 'override_output_port': None, 'receive_lldp': False, 'max_hosts': 255, 'permanent_learn': False, 'output_only': False}}, 'combinatorial_port_flood': True, 'packetin_pps': 0, 'ignore_learn_ins': 10, 'interface_ranges': {}, 'group_table_routing': False, 'advertise_interval': 30, 'group_table': False, 'low_priority': 9000, 'arp_neighbor_timeout': 250, 'drop_bpdu': True}

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

Connect your first datapath
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Now that we've set up all the different components let's connect our first
switch (which we call a ``datapath``) to faucet. We will be using
`Open vSwitch <http://www.openvswitch.org/>`_ for this which is a
production-grade software switch with very good OpenFlow support.

    1. Add WAND Open vSwitch repo

       The bundled version of Open vSwitch in Ubuntu 16.04 is quite old so we
       will use `WAND's package repo <https://packages.wand.net.nz>`_ to
       install a newer version (if you're using a more recent debian or ubuntu
       release you can skip this step).

       .. note::
          If you're using a more recent debian or ubuntu release you can skip
          this step

       .. code:: console

           sudo apt-get install apt-transport-https
           echo "deb https://packages.wand.net.nz $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/wand.list
           sudo curl https://packages.wand.net.nz/keyring.gpg -o /etc/apt/trusted.gpg.d/wand.gpg
           sudo apt-get update

    2. Install Open vSwitch

       .. code:: console

           sudo apt-get install openvswitch-switch

    3. Add network namespaces to simulate hosts

       We will use two linux network namespaces to simulate hosts and this will
       allow us to generate some traffic on our network.

       First let's define some useful bash functions by coping and pasting the
       following definitions into our bash terminal:

       .. code:: bash

           create_ns () {
               NETNS=$1
               IP=$2
               sudo ip netns add ${NETNS}
               sudo ip link add dev veth-${NETNS} type veth peer name veth0 netns $NETNS
               sudo ip link set dev veth-${NETNS} up
               sudo ip netns exec $NETNS ip link set dev veth0 up
               sudo ip netns exec $NETNS ip addr add dev veth0 $IP
               sudo ip netns exec $NETNS ip link set dev lo up
           }

           as_ns () {
               NETNS=$1
               shift
               sudo ip netns exec $NETNS $@
           }

       Now we will create ``host1`` and ``host2`` and assign them some IPs:

       .. code:: bash

           create_ns host1 192.168.0.1/24
           create_ns host2 192.168.0.2/24

    2. Configure Open vSwitch

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

    3. Verify datapath is connected to faucet

       At this point everything should be working, we just need to verify that
       is the case. If we now load up some of the grafana dashboards we imported
       earlier, we should see the datapath is now listed in the
       ``Faucet Inventory`` dashboard.

       If you don't see the new datapath listed you can look at the faucet log
       files ``/var/log/faucet/faucet.log`` or the Open vSwitch log
       ``/var/log/openvswitch/ovs-vswitchd.log`` for clues.

    4. Generate traffic between virtual hosts

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
           as_ns host1 iperf3 -s &
           as_ns host2 iperf3 -c 192.168.0.1

Further steps
^^^^^^^^^^^^^

Now that you know how to setup and run faucet in a self-contained virtual
environment you can build on this tutorial and start to make more interesting
topologies by adding more Open vSwitch bridges, ports and network namespaces.
Check out the faucet :doc:`../configuration` document for more information on
features you can turn on and off. In future we will publish additional tutorials
on layer 3 routing, inter-vlan routing, ACLs.

You can also easily add real hardware into the mix as well instead of using
a software switch. See the :doc:`../vendors/index` section for information on how
to configure a wide variety of different vendor devices for faucet.
