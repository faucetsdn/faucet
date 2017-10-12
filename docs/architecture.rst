:copyright: 2015--2017 The Contributors
:Authors: - Shivaram Mysore

.. meta::
   :keywords: Openflow, Ryu, Faucet, VLAN, SDN

==============================
Faucet Design and Architecture
==============================

Faucet enables providing L2 Switches for the masses not classes

---------------------------------
Terminology used in this document
---------------------------------

Switch and Dataplane or Data Plane are used interchangeably

===============================
Faucet Openflow Switch Pipeline
===============================
::

    PACKETS IN                  +-------------------------+  +-------------------------------------+
      +                         |                         |  |                                     |
      |                         |                         |  |            +------------------------|--+
      |                         |                         |  |            |              +---------|--|----------+
      |                         |                         v  |      +-----+----+         |         V  V          V
      |     +----------+  +-----+----+  +----------+  +---+--+---+  |4:IPv4_FIB|  +------+---+  +----------+  +----------+
      |     |0:PORT_ACL|  |1:VLAN    |  |2:VLAN_ACL|  |3:ETH_SRC +->+          +->+6:VIP     +->|7:ETH_DST |  |8:FLOOD   |
      +---->+          |  |          |  |          |  |          |  |          |  |          |  |          |  |          |
            |          |  |          |  |          |  |          |  +----------+  |          |  |          |  |          |
            |          |  |          |  |          |  |          |                |          |  |          |  |          |
            |          +->+          +->+          +->+          +--------------->+          |  |          +->+          |
            |          |  |          |  |          |  |          |                |          |  |          |  |          |
            |          |  |          |  |          |  |          |  +----------+  |          |  |          |  |          |
            |          |  |          |  |          |  |          |  |5:IPv6_FIB|  |          |  |          |  |          |
            |          |  |          |  |          |  |          +->+          +->+          |  |          |  |          |
            +----------+  +----------+  +----------+  +-----+----+  |          |  +----------+  +------+---+  +--+-------+
                                                            |       +-----+----+                     ^ |         |
                                                            v             |                          | v         v
                                                       CONTROLLER         +--------------------------+ PACKETS OUT
------------
Table 0: PORT_ACL
------------
- Apply user supplied ACLs to a port and send to next table

-------------
Table 1: VLAN
-------------

- Match fields: ``in_port, vlan_vid, eth_src, eth_dst, eth_type``
- Operations:
    - Drop STP BPDUs
    - Drop LLDP
    - Drop broadcast sourced traffic
    - Drop traffic from sources spoofing Faucet's magic MAC address
    - For tagged ports
       - Match VLAN_VID and send to next table
    - For untagged ports
        - Push VLAN frame onto packet with VLAN_VID representing ports native VLAN and send to next table
    - Unknown traffic is dropped

------------
Table 2: VLAN_ACL
------------
- Apply user supplied ACLs to a VLAN and send to next table

----------------
Table 3: ETH_SRC
----------------
- Match fields: ``in_port, vlan_vid, eth_src, eth_dst, eth_type, ip_proto, icmpv6_type, arp_tpa``
- Operations:
    - Handle layer 3 traffic by sending to IPv4 or IPv6 FIB table
    - For source MAC addresses we have learned send to ETH_DST
        - Unknown traffic is sent to controller via packet in (for learning)
        - Sent to ETH_DST table

-----------------
Table 4: IPV4_FIB
-----------------
- Match fields: ``vlan_vid, eth_type, ip_proto, ipv4_dst``
- Operations:
    - Route IP traffic to a next-hop for each route we have learned
    - Set eth_src to Faucet's magic MAC address
    - Set eth_dst to the resolved MAC address for the next-hop
    - Decrement TTL
    - Send to ETH_DST table
    - Unknown traffic is dropped

-----------------
Table 5: IPV6_FIB
-----------------
- Match fields: ``vlan_vid, eth_type, ip_proto, ipv6_dst``
- Operations:
    - Route IP traffic to a next-hop for each route we have learned
    - Set eth_src to Faucet's magic MAC address
    - Set eth_dst to the resolved MAC address for the next-hop
    - Decrement TTL
    - Send to ETH_DST table
    - Unknown traffic is dropped

----------------
Table 6: VIP
----------------

- Operations:
    - Send traffic destined for FAUCET VIPs to the controller

----------------
Table 7: ETH_DST
----------------
- Match fields: ``vlan_vid, eth_dst``
- Operations:
    - For destination MAC addresses we have learned output packet towards that host (popping VLAN frame if we are outputting on an untagged port)
    - Unknown traffic is sent to FLOOD table

--------------
Table 8: FLOOD
--------------
- Match fields: ``vlan_vid, eth_dst``
- Operations:
    - Flood broadcast within VLAN
    - Flood multicast within VLAN
    - Unknown traffic is flooded within VLAN

===================
Faucet Architecture
===================
.. image:: /docs/images/faucet-architecture.png


-----------------
Design Principles
-----------------

1.  Migration Use Case: The system as a whole MUST be able to do a 1:1 replacement for an existing enterprise L2 switch with a whitebox (ex. x86 based 1U server with lots of ethernet ports).  Additionally, Ryu controller with Faucet is run on a different machine (VM or physical hardware with at least 2 ethernet ports) from the replacement switch.
2.  Switch requirements - OpenFlow (OF) v1.3 support. OF-Config support is not required.
3.  OF v1.3 requirements - Both IPv4 & IPv6 support, push/pop/swap VLAN Tags, Multi-table support (ability to support multiple actions and better use of limited TCAM support), Group Table support is nice to have - if available, optimizations can be deployed.
4.  No SNMP is required or used as it is reactive for NMS system.
5.  Uses Carbon (JSON) to communicate to Network Management System (NMS).  Currently One specified controller is allowed to interact with the switch for telemetry data and switch responds the last 30 seconds of data so that data plane processing performance is consistent.

    1.  Hardware data planes needs to push telemetry data to only one end point (unsolicited) and every other client will talk to that one end point.
6.  Controller:

    1.  Support for multiple controllers for HA (Roadmap)
    2.  Controllers to control multiple switches (Roadmap)
    3.  Faucet does not use Master/Slave/Equal Controller roles (Roadmap)
    4.  Option for Data Plane port to dedicated Controller - Controller channel - slow path
    5.  Option for Data Plane port to dedicated Controller - pure open flow - fast path  - offload processing


Access Control List
-------------------
*  We use Ryu’s OpenFlow parser to handle ACLs
*  This means you can define very fine-grained security policy on a port
*  Rules are applied in order so you have control over how they apply to traffic

Faucet Flooding
---------------
*  Configurable flooding modes
*  Default flooding behaviour
   *  Flood all unknown unicast packets to VLAN
*  Secure flooding
   *  Can disable unicast flooding on a port, so that it doesn’t receive unknown unicast traffic
   *  Broadcast/multicast is still flooded so ND and ARP will continue to work

Faucet Learning
---------------
*  Configurable learning modes
*  Default learning behaviour
   *  Send traffic for unknown MACs to controller to learn SRC_MAC and DST_MAC
   *  Use hard_timeout for ETH_SRC table and idle_timeout for ETH_DST table to expire learned MAC addresses
   *  Relearn when MAC moves
*  Permanent learn
   *  Never timeout ETH_SRC or ETH_DST MAC rules
   *  Hosts can’t move ports once learned
*  Max hosts
   *  Limit how many MAC addresses may be learned on a port

----------------------------------------
Configuring OVS to stream telemetry data
----------------------------------------

How-To instructions go here


-------------
Faucet on Ryu
-------------

Ryu provides
------------

1.  Library to serialize and unserialize OpenFlow messages
2.  Event handling framework - port changes call me, switch changes call me, etc
3.  Python - programming language favorable to DevOps folks is used.
4.  Faucet is an application for Ryu controller


Faucet Application
------------------

*  Reads one simple config file (YAML file) that provides switch information such as ports and hosts connected to specific ports.
*  Config file can be used to hardcode a network configuration that can specify what hosts are connected to what ports.  Alternatively, the system can dynamically do MAC learning and discover hosts.
*  Both tagged and untagged VLAN is supported
*  Ability to push statistics via Carbon to a NMS system
*  Currently supports 1 controller/1switch
*  MAC learning supported
*  ACL support (Roadmap): Cisco ACL functionality such as permit/deny access list on a port; firewall style rules on a per port basis

============
UML Diagrams
============
.. image:: /docs/images/faucet-classes.png


=======================
Deployment Architecture
=======================
.. image:: /docs/deployments/simple.png

-------------
Roadmap Items
-------------

*  Cisco style ACL support
*  HA support
*  Support for using OF Controller Roles
*  Support for Controller only port/channel
*  Support for Controller port/channel wherein only OF messages are exchanged without Ethernet headers and use of naked OF messages to enable fast-path processing.
*  DHCP Server with Faucet:
    1. Possibly done either in user space in Ryu itself (ie. Python code that runs it) or (for example) using VANDERVECKEN/RouteFlow style VMs (the controller tells the switch to intercept certain packets - like it already does for ARP - and give them to a helper application that runs inside  VM/namespace). RouteFlow already does this for Quagga.
    2. Integrate with enterprise infrastructure's DHCP server
    3. Integrating DHCP with Faucet means that it can prevent address conflicts. For example, the switch can enforce policy
    4. Faucet specific: Possibly add additional config options in the YAML file (so there is no need for an operator who doesn't care about the implementation to know).
