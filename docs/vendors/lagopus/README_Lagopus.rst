:Authors: - Josh Bailey

Faucet on Lagopus
=================

Introduction
------------

`Lagopus <http://www.lagopus.org/>`_ is a software OpenFlow 1.3 switch, that also supports DPDK.

FAUCET is supported as of Lagopus 0.2.11 (https://github.com/lagopus/lagopus/issues/107).

Setup
-----

Lagopus install on a supported Linux distribution
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Install Lagopus according to the `quickstart guide <https://github.com/lagopus/lagopus/blob/master/QUICKSTART.md>`_.
You don't need to install Ryu since we will be using FAUCET and FAUCET's installation takes care of that dependency.

These instructions are for Ubuntu 16.0.4 (without DPDK). In theory any distribution, with or without DPDK, that Lagopus supports 
will work with FAUCET.

Create lagopus.dsl configuration file
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In this example, Lagopus is controlling two ports, enp1s0f0 and enp1s0f1, which will be known as OpenFlow ports 1 and 2 on DPID 0x1. FAUCET and Lagopus are running on the same host (though of course, they don't need to be).

.. code-block:: shell
  :caption: /usr/local/etc/lagopus/lagopus.dsl
  :name: lagopus.dsl

    channel channel01 create -dst-addr 127.0.0.1 -protocol tcp

    controller controller01 create -channel channel01 -role equal -connection-type main

    interface interface01 create -type ethernet-rawsock -device enp1s0f0

    interface interface02 create -type ethernet-rawsock -device enp1s0f1

    port port01 create -interface interface01

    port port02 create -interface interface02

    bridge bridge01 create -controller controller01 -port port01 1 -port port02 2 -dpid 0x1
    bridge bridge01 enable


Create faucet.yaml
^^^^^^^^^^^^^^^^^^

.. code-block:: yaml
  :caption: /etc/faucet/faucet.yaml
  :name: lagopus/faucet.yaml

    vlans:
        100:
            name: "test"
    dps:
        lagopus-1:
            dp_id: 0x1
            hardware: "Lagopus"
            interfaces:
                1:
                    native_vlan: 100
                2:
                    native_vlan: 100

Start Lagopus
^^^^^^^^^^^^^

Start in debug mode, in a dedicated terminal.

.. code:: console

    lagopus -d

Run FAUCET
^^^^^^^^^^

.. code:: console

    faucet --verbose --ryu-ofp-listen-host=127.0.0.1


Test connectivity
^^^^^^^^^^^^^^^^^

Host(s) on enp1s0f0 and enp1s0f1 in the same IP subnet, should now be able to communicate, and FAUCET's log file should indicate learning is occurring:

.. code-block:: shell
  :caption: /var/log/faucet/faucet.log
  :name: lagopus/faucet.log

    May 11 13:04:57 faucet.valve INFO     DPID 1 (0x1) Configuring DP
    May 11 13:04:57 faucet.valve INFO     DPID 1 (0x1) Delete VLAN vid:100 ports:1,2
    May 11 13:04:57 faucet.valve INFO     DPID 1 (0x1) VLANs changed/added: [100]
    May 11 13:04:57 faucet.valve INFO     DPID 1 (0x1) Configuring VLAN vid:100 ports:1,2
    May 11 13:04:57 faucet.valve INFO     DPID 1 (0x1) Configuring VLAN vid:100 ports:1,2
    May 11 13:04:57 faucet.valve INFO     DPID 1 (0x1) Port 1 added
    May 11 13:04:57 faucet.valve INFO     DPID 1 (0x1) Sending config for port 1
    May 11 13:04:57 faucet.valve INFO     DPID 1 (0x1) Port 2 added
    May 11 13:04:57 faucet.valve INFO     DPID 1 (0x1) Sending config for port 2
    May 11 13:04:57 faucet.valve INFO     DPID 1 (0x1) Packet_in src:00:16:41:6d:87:28 in_port:1 vid:100
    May 11 13:04:57 faucet.valve INFO     learned 1 hosts on vlan 100
    May 11 13:04:57 faucet.valve INFO     DPID 1 (0x1) Packet_in src:00:16:41:32:87:e0 in_port:2 vid:100
    May 11 13:04:57 faucet.valve INFO     learned 2 hosts on vlan 100
