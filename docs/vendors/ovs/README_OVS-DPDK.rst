:Authors: - Josh Bailey

Faucet on OVS with DPDK
=======================

Introduction
------------

`Open vSwitch <http://openvswitch.org/>`_ is a software OpenFlow switch, that supports DPDK. It is also the reference switching
platform for FAUCET.

Setup
-----

Install OVS on a supported Linux distribution
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Install OVS and DPDK per the `official OVS instructions <http://docs.openvswitch.org/en/latest/intro/install/dpdk/>`_, including enabling DPDK at compile time and in OVS's initial configuration.

These instructions are known to work for Ubuntu 16.0.4, with OVS 2.7.0 and DPDK 16.11.1, kernel 4.4.0-77. In theory later versions of these components should work without changes. A multiport NIC was used, based on the Intel 82580 chipset.

Bind NIC ports to DPDK
^^^^^^^^^^^^^^^^^^^^^^

.. note::

    If you have a multiport NIC, you must bind all the ports on the NIC to DPDK, even if you do not use them all.

From the DPDK source directory, determine the relationship between the interfaces you want to use with DPDK and their PCI IDs:

.. code:: console

    export DPDK_DIR=`pwd`
    $DPDK_DIR/tools/dpdk-devbind.py --status

In this example, we want to use enp1s0f0 and enp1s0f1.

.. code:: console

    $ ./tools/dpdk-devbind.py --status

    Network devices using DPDK-compatible driver
    ============================================
    <none>

    Network devices using kernel driver
    ===================================
    0000:01:00.0 '82580 Gigabit Network Connection' if=enp1s0f0 drv=igb unused=
    0000:01:00.1 '82580 Gigabit Network Connection' if=enp1s0f1 drv=igb unused=
    0000:01:00.2 '82580 Gigabit Network Connection' if=enp1s0f2 drv=igb unused=
    0000:01:00.3 '82580 Gigabit Network Connection' if=enp1s0f3 drv=igb unused=

Still from the DPDK source directory:

.. code:: console

    export DPDK_DIR=`pwd`
    modprobe vfio-pci
    chmod a+x /dev/vfio
    chmod 0666 /dev/vfio/*
    $DPDK_DIR/tools/dpdk-devbind.py --bind=vfio-pci 0000:01:00.0 0000:01:00.1 0000:01:00.2 0000:01:00.3
    $DPDK_DIR/tools/dpdk-devbind.py --status

Confirm OVS has been configured to use DPDK
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: console

    $ sudo /usr/local/share/openvswitch/scripts/ovs-ctl stop
    * Exiting ovs-vswitchd (20510)
    * Exiting ovsdb-server (20496)
    $ sudo /usr/local/share/openvswitch/scripts/ovs-ctl start
    * Starting ovsdb-server
    * system ID not configured, please use --system-id
    * Configuring Open vSwitch system IDs
    EAL: Detected 4 lcore(s)
    EAL: Probing VFIO support...
    EAL: VFIO support initialized
    EAL: PCI device 0000:01:00.0 on NUMA socket -1
    EAL:   probe driver: 8086:150e net_e1000_igb
    EAL:   using IOMMU type 1 (Type 1)
    EAL: PCI device 0000:01:00.1 on NUMA socket -1
    EAL:   probe driver: 8086:150e net_e1000_igb
    EAL: PCI device 0000:01:00.2 on NUMA socket -1
    EAL:   probe driver: 8086:150e net_e1000_igb
    EAL: PCI device 0000:01:00.3 on NUMA socket -1
    EAL:   probe driver: 8086:150e net_e1000_igb
    EAL: PCI device 0000:02:00.0 on NUMA socket -1
    EAL:   probe driver: 8086:150e net_e1000_igb
    EAL: PCI device 0000:02:00.1 on NUMA socket -1
    EAL:   probe driver: 8086:150e net_e1000_igb
    EAL: PCI device 0000:02:00.2 on NUMA socket -1
    EAL:   probe driver: 8086:150e net_e1000_igb
    EAL: PCI device 0000:02:00.3 on NUMA socket -1
    EAL:   probe driver: 8086:150e net_e1000_igb
    Zone 0: name:<rte_eth_dev_data>, phys:0x7ffced40, len:0x30100, virt:0x7f843ffced40, socket_id:0, flags:0
    * Starting ovs-vswitchd
    * Enabling remote OVSDB managers

Configure an OVS bridge with the DPDK ports
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: console

    ovs-vsctl add-br br0 -- set bridge br0 datapath_type=netdev protocols=OpenFlow13
    ovs-vsctl add-port br0 dpdk0 -- set interface enp1s0f0 type=dpdk options:dpdk-devargs=0000:01:00.0
    ovs-vsctl add-port br0 dpdk1 -- set interface enp1s0f1 type=dpdk options:dpdk-devargs=0000:01:00.1
    ovs-vsctl set-fail-mode br0 secure
    ovs-vsctl set-controller br0 tcp:127.0.0.1:6653
    ovs-ofctl show br0
    ovs-vsctl get bridge br0 datapath_id

Create faucet.yaml
^^^^^^^^^^^^^^^^^^

.. note::

    Change dp_id, to the value reported above, prefaced with "0x".

.. code-block:: yaml
  :caption: /etc/faucet/faucet.yaml
  :name: ovs/faucet.yaml

    vlans:
        100:
            name: "test"
    dps:
        ovsdpdk-1:
            dp_id: 0x000090e2ba7e7564
            hardware: "Open vSwitch"
            interfaces:
                1:
                    native_vlan: 100
                2:
                    native_vlan: 100

Run FAUCET
^^^^^^^^^^

.. code:: console

    faucet --verbose --ryu-ofp-listen-host=127.0.0.1


Test connectivity
^^^^^^^^^^^^^^^^^

Host(s) on enp1s0f0 and enp1s0f1 in the same IP subnet, should now be able to communicate, and FAUCET's log file should indicate learning is occurring:

.. code-block:: shell
  :caption: /var/log/faucet/faucet.log
  :name: ovs/faucet.log

    May 11 14:53:32 faucet.valve INFO     DPID 159303465858404 (0x90e2ba7e7564) Configuring DP
    May 11 14:53:32 faucet.valve INFO     DPID 159303465858404 (0x90e2ba7e7564) Delete VLAN vid:100 ports:1,2
    May 11 14:53:32 faucet.valve INFO     DPID 159303465858404 (0x90e2ba7e7564) VLANs changed/added: [100]
    May 11 14:53:32 faucet.valve INFO     DPID 159303465858404 (0x90e2ba7e7564) Configuring VLAN vid:100 ports:1,2
    May 11 14:53:32 faucet.valve INFO     DPID 159303465858404 (0x90e2ba7e7564) Configuring VLAN vid:100 ports:1,2
    May 11 14:53:32 faucet.valve INFO     DPID 159303465858404 (0x90e2ba7e7564) Port 1 added
    May 11 14:53:32 faucet.valve INFO     DPID 159303465858404 (0x90e2ba7e7564) Sending config for port 1
    May 11 14:53:32 faucet.valve INFO     DPID 159303465858404 (0x90e2ba7e7564) Port 2 added
    May 11 14:53:32 faucet.valve INFO     DPID 159303465858404 (0x90e2ba7e7564) Sending config for port 2
    May 11 14:53:33 faucet.valve INFO     DPID 159303465858404 (0x90e2ba7e7564) Packet_in src:00:16:41:6d:87:28 in_port:1 vid:100
    May 11 14:53:33 faucet.valve INFO     learned 1 hosts on vlan 100
    May 11 14:53:33 faucet.valve INFO     DPID 159303465858404 (0x90e2ba7e7564) Packet_in src:00:16:41:32:87:e0 in_port:2 vid:100
    May 11 14:53:33 faucet.valve INFO     learned 2 hosts on vlan 100
