:Authors: - Josh Bailey

=======================
FAUCET on NoviFlow 1248
=======================

------------
Introduction
------------

NoviFlow provide a range of switches known to work with FAUCET.

These instructions are known to work with a NoviFlow 1248 and NS-2116, software NW400.1.8 and NW400.2.1, running with FAUCET 1.5.2.
In theory later versions should work, taking care to update the table configuration.


-----
Setup
-----

**Configure the CPN on the switch**

In this example, the server running FAUCET is 10.0.1.8; configuration for CPN interfaces is not shown.

.. code:: bash

  set config controller controllergroup 1 controllerid 1 priority 1 ipaddr 10.0.1.8 port 6653 security none
  set config switch dpid 0x1

**Configure the tables**

  These matches are known to pass the unit tests as of FAUCET 1.5.2, but take care to adjust
  ACL table matches and any changes for future versions.

.. code:: bash
  
   set config table tableid 0 matchfields 0 3 4 5 6 10 14 16 18 23
   set config table tableid 1 matchfields 0 3 4 5 6
   set config table tableid 2 matchfields 0 5 6 10 14
   set config table tableid 3 matchfields 0 3 4 5 6 10 23 29
   set config table tableid 4 matchfields 5 6 10 11 12
   set config table tableid 5 matchfields 5 6 10 27 29
   set config table tableid 6 matchfields 3 6
   set config table tableid 7 matchfields 0 3 6

**Create faucet.yaml**

::

    $ cat /etc/ryu/faucet/faucet.yaml
    vlans:
        100:
            name: "test"
    dps:
        noviflow-1:
            dp_id: 0x1
            hardware: "NoviFlow"
            interfaces:
                1:
                    native_vlan: 100
                2:
                    native_vlan: 100

**Run FAUCET**

::

    $ ryu-manager faucet.faucet --verbose

**Test connectivity**

Host(s) on ports 1 and 2 should now be able to communicate, and FAUCET's log file should indicate learning is occurring:

::

    May 14 17:06:15 faucet DEBUG    DPID 1 (0x1) connected
    May 14 17:06:15 faucet.valve INFO     DPID 1 (0x1) Configuring DP
    May 14 17:06:15 faucet.valve INFO     DPID 1 (0x1) Delete VLAN vid:100 ports:1,2,3,4
    May 14 17:06:15 faucet.valve INFO     DPID 1 (0x1) VLANs changed/added: [100]
    May 14 17:06:15 faucet.valve INFO     DPID 1 (0x1) Configuring VLAN vid:100 ports:1,2,3,4
    May 14 17:06:15 faucet.valve INFO     DPID 1 (0x1) Configuring VLAN vid:100 ports:1,2,3,4
    May 14 17:06:15 faucet.valve INFO     DPID 1 (0x1) Port 1 added
    May 14 17:06:15 faucet.valve INFO     DPID 1 (0x1) Sending config for port 1
    May 14 17:06:15 faucet.valve INFO     DPID 1 (0x1) Port 2 added
    May 14 17:06:15 faucet.valve INFO     DPID 1 (0x1) Sending config for port 2
    May 14 17:06:15 faucet.valve INFO     DPID 1 (0x1) Port 3 added
    May 14 17:06:15 faucet.valve INFO     DPID 1 (0x1) Sending config for port 3
    May 14 17:06:15 faucet.valve INFO     DPID 1 (0x1) Port 4 added
    May 14 17:06:15 faucet.valve INFO     DPID 1 (0x1) Sending config for port 4
    May 14 17:06:15 faucet.valve INFO     DPID 1 (0x1) Packet_in src:62:4c:f5:bb:33:3c in_port:2 vid:100
    May 14 17:06:15 faucet.valve INFO     learned 1 hosts on vlan 100
    May 14 17:06:15 faucet.valve INFO     DPID 1 (0x1) Packet_in src:62:4c:f5:bb:33:3c in_port:2 vid:100
    May 14 17:06:15 faucet.valve INFO     DPID 1 (0x1) Packet_in src:2a:e1:65:3c:49:e4 in_port:3 vid:100
    May 14 17:06:15 faucet.valve INFO     DPID 1 (0x1) Packet_in src:2a:e1:65:3c:49:e4 in_port:3 vid:100
    May 14 17:06:15 faucet.valve INFO     learned 2 hosts on vlan 100
