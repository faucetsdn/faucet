Stacking tutorial
=================

This tutorial will cover Faucet's stacking feature.

Prerequisites
^^^^^^^^^^^^^

- Knowledge of the VLAN and routing tutorial topics (:doc:`vlans`, :doc:`routing`)
- Install Faucet - :ref:`tutorial-package-installation` steps 1 & 2
- Install Open vSwitch - :ref:`tutorial-first-datapath-connection` steps 1 & 2
- Useful Bash Functions - Copy and paste the following definitions into your
  bash terminal, or to make them persistent between sessions add them to the
  bottom of your .bashrc and run 'source .bashrc'.

    .. literalinclude::  ../_static/tutorial/create_ns
       :language: bash

    .. literalinclude:: ../_static/tutorial/as_ns
       :language: bash

    .. literalinclude:: ../_static/tutorial/cleanup
       :language: bash

- Run the cleanup script to remove old namespaces and switches:

    .. code:: console

        cleanup

.. _tutorial-stacking:

Basic Stacking
^^^^^^^^^^^^^^

We can start by considering two switches with one host on each switch on the same VLAN.

.. figure:: ../_static/images/tutorial-stack.svg
    :alt: stacking diagram
    :align: center
    :width: 80%

.. code-block:: yaml
    :caption: /etc/faucet/faucet.yaml
    :name: multiple-switches-yaml

    vlans:
        hosts:
            vid: 100
    dps:
        sw1:
            dp_id: 0x1
            hardware: "Open vSwitch"
            interfaces:
                1:
                    name: "host1"
                    description: "host1 network namespace"
                    native_vlan: hosts
        sw2:
            dp_id: 0x2
            hardware: "Open vSwitch"
            interfaces:
                1:
                    name: "host2"
                    description: "host2 network namespace"
                    native_vlan: hosts

Now lets signal faucet to reload the configuration file.

.. code:: console

    sudo systemctl reload faucet

To setup multiple switches in Open vSwitch we can define two bridges with different datapath-ids and names.
We'll be using br1 and br2.

.. code:: console

   create_ns host1 10.0.1.1/24
   create_ns host2 10.0.1.2/24

   sudo ovs-vsctl add-br br1 \
   -- set bridge br1 other-config:datapath-id=0000000000000001 \
   -- set bridge br1 other-config:disable-in-band=true \
   -- set bridge br1 fail_mode=secure \
   -- add-port br1 veth-host1 -- set interface veth-host1 ofport_request=1 \
   -- set-controller br1 tcp:127.0.0.1:6653 tcp:127.0.0.1:6654

   sudo ovs-vsctl add-br br2 \
   -- set bridge br2 other-config:datapath-id=0000000000000002 \
   -- set bridge br2 other-config:disable-in-band=true \
   -- set bridge br2 fail_mode=secure \
   -- add-port br2 veth-host2 -- set interface veth-host2 ofport_request=1 \
   -- set-controller br2 tcp:127.0.0.1:6653 tcp:127.0.0.1:6654

Since the switches are not connected it will be impossible to ping between the two hosts.

.. code:: console

   as_ns host1 ping 10.0.1.2

To properly connect the switches we can use the Faucet switch stacking feature.
This will be configured by defining a stack on a DP interface.
The dp and port values of the stack configuration refer to the dp and port that are connected to the interface.

.. code-block:: yaml
    :caption: /etc/faucet/faucet.yaml
    :name: switch-stacking-yaml

    vlans:
        hosts:
            vid: 100
    dps:
        sw1:
            dp_id: 0x1
            hardware: "Open vSwitch"
            stack:
                priority: 1
            interfaces:
                1:
                    name: "host1"
                    description: "host1 network namespace"
                    native_vlan: hosts
                2:
                    name: "stack_to_sw2"
                    description: "sw1 stack link to sw2"
                    stack:
                        dp: sw2
                        port: 2
        sw2:
            dp_id: 0x2
            hardware: "Open vSwitch"
            interfaces:
                1:
                    name: "host2"
                    description: "host2 network namespace"
                    native_vlan: hosts
                2:
                    name: "stack_to_sw1"
                    description: "sw2 stack link to sw1"
                    stack:
                       dp: sw1
                       port: 2

To connect two Open vSwitch bridges we can use a patch interface type.
We will create a patch named patch1_2 from br1 to br2 and likewise a patch from br2 to br1 named patch2_1.
This is accomplished with the following command:

.. code:: console

   sudo ovs-vsctl add-port br1 patch1_2 \
    -- set interface patch1_2 type=patch options:peer=patch2_1 ofport_request=2
   sudo ovs-vsctl add-port br2 patch2_1 \
    -- set interface patch2_1 type=patch options:peer=patch1_2 ofport_request=2

Let's reload Faucet and see what happens.

.. code:: console

   sudo systemctl reload faucet

Faucet will start sending out LLDP beacons to connect up the stack ports.
We can see this happening in the log file when the switches report that port 2 (the stack port) is UP.

.. code-block::
   :caption: /var/log/faucet/faucet.yaml
   :name: lldp-stack-log

   DPID 2 (0x2) sw2 LLDP on 0e:00:00:00:00:01, Port 2 from 0e:00:00:00:00:01 (remote DPID 1 (0x1), port 2) state 2
   DPID 2 (0x2) sw2 Stack Port 2 INIT
   DPID 1 (0x1) sw1 LLDP on 0e:00:00:00:00:01, Port 2 from 0e:00:00:00:00:01 (remote DPID 2 (0x2), port 2) state 2
   DPID 1 (0x1) sw1 Stack Port 2 INIT
   DPID 2 (0x2) sw2 LLDP on 0e:00:00:00:00:01, Port 2 from 0e:00:00:00:00:01 (remote DPID 1 (0x1), port 2) state 1
   DPID 2 (0x2) sw2 Stack Port 2 UP
   DPID 2 (0x2) sw2 1 stack ports changed state
   DPID 1 (0x1) sw1 LLDP on 0e:00:00:00:00:01, Port 2 from 0e:00:00:00:00:01 (remote DPID 2 (0x2), port 2) state 1
   DPID 1 (0x1) sw1 Stack Port 2 UP
   DPID 1 (0x1) sw1 1 stack ports changed state
   DPID 2 (0x2) sw2 LLDP on 0e:00:00:00:00:01, Port 2 from 0e:00:00:00:00:01 (remote DPID 1 (0x1), port 2) state 3
   DPID 1 (0x1) sw1 LLDP on 0e:00:00:00:00:01, Port 2 from 0e:00:00:00:00:01 (remote DPID 2 (0x2), port 2) state 3

Now the two switches are connected so we can ping between the two hosts.

.. code:: console
   
   as_ns host1 ping 10.0.1.2

Inter-VLAN Routing with Stacking
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For this task we will see that inter-VLAN routing can work between hosts on different switches. 

.. figure:: ../_static/images/tutorial-stackwithivr.svg
    :alt: Stacking with inter-VLAN routing diagram
    :align: center
    :width: 80%

First run the cleanup.

.. code:: console

   cleanup

We can accomplish inter-VLAN routing between different switches by using the stacking feature.
To do this we will be combining the methods from the :ref:`tutorial-stacking` and the :ref:`tutorial-ivr` tutorials.
However, we need to set 'drop_spoofed_faucet_mac' to false on each DP. Doing this will prevent a packet that has been routed and come from a stack port from being dropped.

.. code-block:: yaml
    :caption: /etc/faucet/faucet.yaml
    :name: ivr-switch-stacking-yaml

    vlans:
        hosts:
            vid: 100
            faucet_vips: ["10.0.1.254/24"]
            faucet_mac: "00:00:00:00:00:11"
        servers:
            vid: 200
            faucet_vips: ["10.0.2.254/24"]
            faucet_mac: "00:00:00:00:00:22"
    routers:
        router-1:
            vlans: [hosts, servers]
    dps:
        sw1:
            dp_id: 0x1
            hardware: "Open vSwitch"
            stack: {priority: 1}
            drop_spoofed_faucet_mac: False
            interfaces:
                1:
                    name: "host1"
                    description: "host1 network namespace"
                    native_vlan: hosts
                2:
                    name: "stack_to_sw2"
                    description: "sw1 stack link to sw2"
                    stack:
                        dp: sw2
                        port: 2
                3:
                    name: "server1"
                    description: "server1 network namespace"
                    native_vlan: servers

        sw2:
            dp_id: 0x2
            hardware: "Open vSwitch"
            drop_spoofed_faucet_mac: False
            interfaces:
                1:
                    name: "host2"
                    description: "host2 network namespace"
                    native_vlan: hosts
                2:
                    name: "stack_to_sw1"
                    description: "sw2 stack link to sw1"
                    stack:
                       dp: sw1
                       port: 2
                3:
                    name: "server2"
                    description: "server2 network namespace"
                    native_vlan: servers

Reload faucet to enable inter-VLAN routing.

.. code:: console

    sudo systemctl reload faucet

As we have learnt previously. First, set up the hosts:

.. code:: console

    create_ns host1 10.0.1.1/24
    create_ns host2 10.0.1.2/24
    create_ns server1 10.0.2.1/24
    create_ns server2 10.0.2.2/24

Now we can set-up the default routes for each host.

.. code:: console

   as_ns host1 ip route add default via 10.0.1.254
   as_ns host2 ip route add default via 10.0.1.254
   as_ns server1 ip route add default via 10.0.2.254
   as_ns server2 ip route add default via 10.0.2.254

Next, we can create the bridges.

.. code:: console

  sudo ovs-vsctl add-br br1 \
  -- set bridge br1 other-config:datapath-id=0000000000000001 \
  -- set bridge br1 other-config:disable-in-band=true \
  -- set bridge br1 fail_mode=secure \
  -- add-port br1 veth-host1 -- set interface veth-host1 ofport_request=1 \
  -- add-port br1 veth-server1 -- set interface veth-server1 ofport_request=3 \
  -- set-controller br1 tcp:127.0.0.1:6653 tcp:127.0.0.1:6654

  sudo ovs-vsctl add-br br2 \
  -- set bridge br2 other-config:datapath-id=0000000000000002 \
  -- set bridge br2 other-config:disable-in-band=true \
  -- set bridge br2 fail_mode=secure \
  -- add-port br2 veth-host2 -- set interface veth-host2 ofport_request=1 \
  -- add-port br2 veth-server2 -- set interface veth-server2 ofport_request=3 \
  -- set-controller br2 tcp:127.0.0.1:6653 tcp:127.0.0.1:6654

And finally, we can create the patches to connect the bridges to each other.

.. code:: console

   sudo ovs-vsctl add-port br1 patch1_2 \
    -- set interface patch1_2 type=patch options:peer=patch2_1 ofport_request=2
   sudo ovs-vsctl add-port br2 patch2_1 \
    -- set interface patch2_1 type=patch options:peer=patch1_2 ofport_request=2

Now it should be possible to ping between any combination of hosts on any VLAN after the LLDP has configured the stack ports as UP.
For example host1 can ping to server1 on the same switch as well as server2 on the other switch via the use of the stack link.

.. code:: console

   as_ns host1 ping 10.0.2.1
   as_ns host1 ping 10.0.2.2
