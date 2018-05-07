===========================================================================
TODO this is just copied from the original routing. it needs to be updated.
===========================================================================


Routing 2 Tutorial
==================

This tutorial expands on the `routing tutorial <routing.html>`_ and will add route policy via an external BGP service.

Prerequisites:
^^^^^^^^^^^^^^

- Faucet `Package installation steps 1 & 2 <https://faucet.readthedocs.io/en/latest/tutorials.html#package-installation>`__
- OpenVSwitch `Connect your first datapath steps 1 & 2 <https://faucet.readthedocs.io/en/latest/tutorials.html#connect-your-first-datapath>`__
- Useful Bash Functions (`create_ns <_static/tutorial/create_ns>`_, `as_ns <_static/tutorial/as_ns>`_, `cleanup <_static/tutorial/cleanup>`_). To make these functions persistent between sessions add them to the bottom of your .bashrc and run 'source .bashrc'

Run the cleanup script to remove old namespaces and switches:

.. code:: console

    cleanup

.. note:: For this tutorial it is a good idea to use a terminal multiplexer (screen, tmux or just multiple terminal sessions), as we will be running multiple applications at the same time.



BGP Routing
^^^^^^^^^^^

For this section we are going create two Autonomous Systems (AS).
Each system will contain one switch, and each switch will be controlled by a separate instance of Faucet.

BGP (and other routing) is provided by a NFV service, here we will use `BIRD <http://bird.network.cz/>`_.
Other applications such as ExaBGP & Quagga could be used.

If you are NOT using the workshop VM you will need to install BIRD.

To install BIRD:

.. code:: console

    apt-get install bird


Network Set-up
--------------

Our data plane will end up looking like this:

.. image:: _static/images/routing2-bgp-dataplane.svg
    :alt: BGP network diagram

Create 4 hosts, in two different subnets:

.. code:: console

    create_ns host1 10.0.0.1/24
    create_ns host2 10.0.0.2/24
    create_ns host3 10.0.1.3/24
    create_ns host4 10.0.1.4/24

And add a default route for each host to it's gateway router.

.. code:: console

    as_ns host1 ip route add default via 10.0.0.254
    as_ns host2 ip route add default via 10.0.0.254
    as_ns host3 ip route add default via 10.0.1.254
    as_ns host4 ip route add default via 10.0.1.254

Create the 2 bridges and add hosts 1 & 2 to br1 and 3 & 4 to br2

.. code:: console

    sudo ovs-vsctl add-br br1 \
    -- set bridge br1 other-config:datapath-id=0000000000000001 \
    -- set bridge br1 other-config:disable-in-band=true \
    -- set bridge br1 fail_mode=secure \
    -- add-port br1 veth-host1 -- set interface veth-host1 ofport_request=2 \
    -- add-port br1 veth-host2 -- set interface veth-host2 ofport_request=3 \
    -- set-controller br1 tcp:127.0.0.1:6653 tcp:127.0.0.1:6654

    sudo ovs-vsctl add-br br2 \
    -- set bridge br2 other-config:datapath-id=0000000000000002 \
    -- set bridge br2 other-config:disable-in-band=true \
    -- set bridge br2 fail_mode=secure \
    -- add-port br2 veth-host3 -- set interface veth-host3 ofport_request=2 \
    -- add-port br2 veth-host4 -- set interface veth-host4 ofport_request=3 \
    -- set-controller br2 tcp:127.0.0.1:6650 tcp:127.0.0.1:6654

.. note:: When using BGP and Faucet, if changing Faucet's routing configuration (routers, static routes, or a VLAN's BGP config) the Faucet application must be restarted to reload the configuration (not sighup reloaded).


First we will add the basic vlan and dp configuration for each datapath in their own files.
They should look like this.

.. code-block:: yaml
    :caption: sw1-faucet.yaml

    vlans:
        br1-hosts:
            vid: 100
            description: "h1 & h2's vlan"
            faucet_mac: "00:00:00:00:00:11"
            faucet_vips: ["10.0.0.254/24"]

        br1-peer:
            vid: 200
            description: "vlan for peering port"
            faucet_mac: "00:00:00:00:00:22"
            faucet_vips: ["192.168.1.1/24"]

    dps:
        br1:
            dp_id: 0x1
            hardware: "Open vSwitch"
            interfaces:
                1:
                    name: "br2"
                    description: "connects to br2"
                    native_vlan: br1-peer
                2:
                    name: "host1"
                    description: "host1 network namespace"
                    native_vlan: br1-hosts

                3:
                    name: "host2"
                    description: "host2 network namespace"
                    native_vlan: br1-hosts

.. code-block:: yaml
    :caption: sw2-faucet.yaml

    vlans:
        br2-peer:
            vid: 300
            description: "vlan for peering port"
            faucet_mac: "00:00:00:00:00:33"
            faucet_vips: ["192.168.1.2/24"]

        br2-hosts:
            vid: 400
            description: "h3 & h4's vlan"
            faucet_mac: "00:00:00:00:00:44"
            faucet_vips: ["10.0.1.254/24"]
    dps:
        br2:
            dp_id: 0x2
            hardware: "Open vSwitch"
            interfaces:
                1:
                    name: "br2"
                    description: "connects to br2"
                    native_vlan: br2-peer
                2:
                    name: "host1"
                    description: "host1 network namespace"
                    native_vlan: br2-hosts

                3:
                    name: "host2"
                    description: "host2 network namespace"
                    native_vlan: br2-hosts


If the system Faucet is running stop it.

.. code:: console

    sudo systemctl stop faucet


Now we can start the Faucets (**start them in different terminals, we will need to restart them later**).

.. code:: console

    sudo env FAUCET_CONFIG=$HOME/sw1-faucet.yaml FAUCET_LOG=/var/log/faucet/sw1-faucet.log faucet
    sudo env FAUCET_CONFIG=$HOME/sw2-faucet.yaml FAUCET_LOG=/var/log/faucet/sw2-faucet.log  FAUCET_PROMETHEUS_PORT=9304 faucet --ryu-ofp-tcp-listen-port=6650


Check the logs to confirm the two switches have connected to the correct Faucet.

.. code:: console

    cat /var/log/faucet/sw2-faucet.log

.. code::

    May 03 10:51:57 faucet INFO     Loaded configuration from /home/ubuntu/sw2-faucet.yaml
    May 03 10:51:57 faucet INFO     Add new datapath DPID 2 (0x2)
    May 03 10:51:58 faucet.valve INFO     DPID 2 (0x2) Cold start configuring DP
    May 03 10:51:58 faucet.valve INFO     DPID 2 (0x2) Configuring VLAN br2-hosts vid:400 ports:Port 2,Port 3
    May 03 10:51:58 faucet.valve INFO     DPID 2 (0x2) Configuring VLAN br2-peer vid:300 ports:Port 1
    May 03 10:51:58 faucet.valve INFO     DPID 2 (0x2) Port 1 configured
    May 03 10:51:58 faucet.valve INFO     DPID 2 (0x2) Port 2 configured
    May 03 10:51:58 faucet.valve INFO     DPID 2 (0x2) Port 3 configured
    May 03 10:51:58 faucet.valve INFO     DPID 2 (0x2) Ignoring port:4294967294 not present in configuration file


And check that host1 can ping host2 but not host3 or host4.

.. code:: console

    as_ns host1 ping 10.0.0.2
    as_ns host1 ping 10.0.1.3


Next we will add a new host to run our BGP service on, connect it to the switch's dataplane and create a virtual link for it to be able to communicate with Faucet.

.. image:: _static/images/routing2-bgp-routing-ns.svg
    :alt: BGP Routing Namespace Diagram

.. code:: console

    create_ns bgphost1 192.168.1.3/24
    sudo ovs-vsctl add-port br1 veth-bgphost1 -- set interface veth-bgphost1 ofport_request=4
    sudo ip link add name veth-bgphost1-0 type veth peer name vethbgpctrl0
    sudo ip link set vethbgpctrl0 netns bgphost1
    sudo ip addr add 172.16.1.1/24 dev veth-bgphost1-0
    as_ns bgphost1 ip addr add 172.16.1.2/24 dev vethbgpctrl0
    sudo ip link set veth-bgphost1-0 up
    as_ns bgphost1 ip link set vethbgpctrl0 up

And repeat for the other side:

.. code:: console

    create_ns bgphost2 192.168.1.4/24
    sudo ovs-vsctl add-port br2 veth-bgphost2 -- set interface veth-bgphost2 ofport_request=4
    sudo ip link add name veth-bgphost2-0 type veth peer name vethbgpctrl0
    sudo ip link set vethbgpctrl0 netns bgphost2
    sudo ip addr add 172.16.2.1/24 dev veth-bgphost2-0
    as_ns bgphost2 ip addr add 172.16.2.2/24 dev vethbgpctrl0
    sudo ip link set veth-bgphost2-0 up
    as_ns bgphost2 ip link set vethbgpctrl0 up


Now bgphost1 should be able to ping 172.16.1.1 & bgphost2 should be able to ping 172.16.2.1

.. code:: console

    as_ns bgphost1 ping 172.16.1.1


To configure BIRD1
Create bird1.conf on $HOME

.. code-block:: cfg
    :caption: $HOME/bird1.conf

    protocol kernel {
        scan time 60;
        import none;
    }

    protocol device {
        scan time 60;
    }

    protocol static {
        route 10.0.0.0/24 via 192.168.1.1;
        route 192.168.1.0/24 unreachable;
    }

    protocol bgp faucet {
        local as 64512;
        neighbor 172.16.1.1 port 9179 as 64512;
        export all;
        import all;
    }

    protocol bgp kiwi {
        local as 64512;
        neighbor 192.168.1.4 port 179 as 64513;
        export all;
        import all;
    }


and for BIRD2:

.. code-block:: cfg
    :caption: $HOME/bird.conf

    protocol kernel {
        scan time 60;
        import none;
    }

    protocol device {
        scan time 60;
    }

    protocol static {
        route 10.0.1.0/24 via 192.168.1.2;
        route 192.168.1.0/24 unreachable;
    }

    protocol bgp faucet {
        local as 64512;
        neighbor 172.16.2.1 port 9179 as 64512;
        export all;
        import all;
    }

    protocol bgp fruit {
        local as 64513;
        neighbor 192.168.1.3 port 179 as 64512;
        export all;
        import all;
    }


Start the two BIRDs

.. code:: console

    as_ns bgphost1 bird -s /var/run/bird1.ctl -c $HOME/bird1.conf

and

.. code:: console

    as_ns bgphost2 bird -s /var/run/bird2.ctl -c $HOME/bird2.conf


We'll configure the Faucets by adding the BGP configuration to the \*-peer VLAN.

.. code-block:: yaml
    :caption: $HOME/sw1-faucet.yaml

    vlans:
        br1-hosts:
            vid: 100
            description: "h1 & h2's vlan"
            faucet_mac: "00:00:00:00:00:11"
            faucet_vips: ["10.0.0.254/24"]

        br1-peer:
            vid: 200
            description: "vlan for peering port"
            faucet_mac: "00:00:00:00:00:22"
            faucet_vips: ["192.168.1.1/24"]
            bgp_port: 9179
            bgp_as: 64512
            bgp_routerid: '172.16.1.1'
            bgp_neighbor_addresses: ['172.16.1.2', '::1']
            bgp_connect_mode: active
            bgp_neighbor_as: 64512

    routers:
        br1-router:
            vlans: [br1-hosts, br1-peer]

.. code-block:: yaml
    :caption: $HOME/sw2-faucet.yaml

    vlans:
        br2-peer:
            vid: 300
            description: "vlan for peering port"
            faucet_mac: "00:00:00:00:00:33"
            faucet_vips: ["192.168.1.2/24"]
            bgp_port: 9180
            bgp_as: 64512
            bgp_routerid: '172.16.2.1'
            bgp_neighbor_addresses: ['172.16.2.2', '::1']
            bgp_connect_mode: active
            bgp_neighbor_as: 64512

        br2-hosts:
            vid: 400
            description: "h3 & h4's vlan"
            faucet_mac: "00:00:00:00:00:44"
            faucet_vips: ["10.0.1.254/24"]

    routers:
        br2-router:
            vlans: [br2-hosts, br2-peer]

And finally add the port configuration for the bgphost.

.. code-block:: yaml
    :caption: sw1-facuet.yaml

    dps:
        br1:
            ...
            interfaces:
                ...
                4:
                    native_vlan: br1-peer

and

.. code-block:: yaml
    :caption: sw2-facuet.yaml

    dps:
        br2:
            ...
            interfaces:
                ...
                4:
                    native_vlan: br2-peer

Now stop (ctrl + c) and start the Faucets.

.. code:: console

    sudo env FAUCET_CONFIG=$HOME/sw1-faucet.yaml FAUCET_LOG=/var/log/faucet/sw1-faucet.log faucet
    sudo env FAUCET_CONFIG=$HOME/sw2-faucet.yaml FAUCET_LOG=/var/log/faucet/sw2-faucet.log  FAUCET_PROMETHEUS_PORT=9304 faucet --ryu-ofp-tcp-listen-port=6650

and our logs should show us BGP peer router up.

.. code:: console

    cat /var/log/faucet/sw1-faucet.log

    ...
    May 03 11:23:40 faucet INFO     BGP peer router ID 172.16.1.2 AS 64512 up
    May 03 11:23:40 faucet ERROR    BGP nexthop 192.168.1.1 for prefix 10.0.0.0/24 cannot be us
    May 03 11:23:40 faucet ERROR    BGP nexthop 172.16.1.2 for prefix 192.168.1.0/24 is not a connected network

Now we should be able to ping from host1 to host3.

.. code:: console

    as_ns host1 ping 10.0.1.3

To confirm we are getting the routes from BGP we can query BIRD:

.. code:: console

    birdc -s /var/run/bird2.ctl show route
    BIRD 1.6.4 ready.
    10.0.0.0/24        via 192.168.1.1 on veth0 [fruit 11:38:47 from 192.168.1.3] * (100) [AS64512i]
    10.0.1.0/24        via 192.168.1.2 on veth0 [static1 11:31:29] * (200)
    192.168.1.0/24     unreachable [static1 11:31:29] * (200)
                       unreachable [faucet 11:48:05 from 172.16.2.1] (100/-) [i]
                       via 192.168.1.3 on veth0 [fruit 11:38:47] (100) [AS64512i]

And we can see 10.0.0.0/24 is coming from our fruit peer.

Advertise new route
-------------------
Next we will move host2 into a different subnet and add a route for it to be advertised via BGP.

Remove the old 10.0.0.0/24 IP address and add the new one.

.. code:: console

    as_ns host2 ip addr flush dev veth0
    as_ns host2 ip addr add 10.0.2.2/24 dev veth0
    as_ns host2 ip route add default via 10.0.2.254

And configure Faucet to put host 2 in a new VLAN.

.. code-block:: yaml
    :caption: /etc/faucet/sw1-faucet.yaml

    vlans:
        ...
        br1-host2:
            vid: 300
            faucet_mac: "00:00:00:00:00:34"
            faucet_vips: ["10.0.2.254/24"]

Add the VLAN to the Inter VLAN router:

.. code-block:: yaml
    :caption: /etc/faucet/sw1-faucet.yaml

    routers:
        router-br1:
            vlans: [br1-hosts, br1-peer, br1-host2]

And change port 2's native VLAN, so the final configuration should look like:

.. code-block:: yaml
    :caption: /etc/faucet/sw1-faucet.yaml

    vlans:
        br1-hosts:
            vid: 100
            description: "h1 & h2's vlan"
            faucet_mac: "00:00:00:00:00:11"
            faucet_vips: ["10.0.0.254/24"]
        br1-peer:
            vid: 200
            description: "vlan for peering port"
            faucet_mac: "00:00:00:00:00:22"
            faucet_vips: ["192.168.1.1/24"]
            bgp_port: 9179
            bgp_as: 64512
            bgp_routerid: '172.16.1.1'
            bgp_neighbor_addresses: ['172.16.1.2', '::1']
            bgp_connect_mode: active
            bgp_neighbor_as: 64512
        br1-host2:
            vid: 300
            faucet_mac: "00:00:00:00:00:34"
            faucet_vips: ["10.0.2.1/24"]

    routers:
        router-br1:
            vlans: [br1-hosts, br1-peer, br1-host2]
    dps:
        br1:
            dp_id: 0x1
            hardware: "Open vSwitch"
            interfaces:
                1:
                    name: "br2"
                    description: "connects to br2"
                    native_vlan: br1-peer
                2:
                    name: "host1"
                    description: "host1 network namespace"
                    native_vlan: br1-host2
                3:
                    name: "host2"
                    description: "host2 network namespace"
                    native_vlan: br1-hosts

Restart Faucet 1 to reload our config and host2 should be able to ping host1, but not host3 & host4.

We need to advertise our new 10.0.2.0/24 via bgp.
So in the 'protocol static' section of bird.conf add the new route.

.. code-block:: cfg
    :caption: /etc/bird.conf

    protocol static {
        route 10.0.0.0/24 via 192.168.1.1;
        route 10.0.2.0/24 via 192.168.1.1
        route 192.168.1.0/24 unreachable;
    }

reload bird:

.. code:: console

    sudo birdc configure

And in bird2 we can view the routing table

.. code:: console

    sudo birdc -s /var/run/bird2.ctl show route
    BIRD 1.6.4 ready.
    10.0.2.0/24        via 192.168.1.1 on veth0 [fruit 12:04:36 from 192.168.1.3] * (100) [AS64512i]
    10.0.0.0/24        via 192.168.1.1 on veth0 [fruit 11:38:47 from 192.168.1.3] * (100) [AS64512i]
    10.0.1.0/24        via 192.168.1.2 on veth0 [static1 11:31:29] * (200)
    192.168.1.0/24     unreachable [static1 11:31:29] * (200)
                       unreachable [faucet 11:48:05 from 172.16.2.1] (100/-) [i]
                       via 192.168.1.3 on veth0 [fruit 11:38:47] (100) [AS64512i]
