Faucet on Cisco Switches
========================

Introduction
------------

Cisco supports Openflow with faucet pipeline on the Catalyst 9000 Series switches.

Cisco IOS XE first introduced faucet support in version 16.9.1, however since
faucet support is being continually improved on Cisco platforms we recommend
running the latest stable release. Currently we would recommend running 16.12.1c or later.

For official Cisco documentation on OpenFlow and faucet support see the following configuration guide:

- `Programmability Configuration Guide, Cisco IOS XE Gibraltar 16.12.x <https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/1612/b_1612_programmability_cg/openflow.html>`_

Setup
-----

Boot up in Openflow Mode
^^^^^^^^^^^^^^^^^^^^^^^^

The Catalyst 9K will be in traditional switching mode by default.  The below command will enable Openflow mode on the switch.

.. code-block:: console

	Switch-C9300#
	Switch-C9300#configure terminal
	Switch-C9300(config)#boot mode ?
	openflow  openflow forwarding mode

	Switch-C9300(config)#boot mode openflow
	Changes to the boot mode preferences have been stored,
	but it cannot take effect until the next reload.
	Use "show boot mode" to check the boot mode currently
	active.
	Switch-C9300(config)#end

	Switch-C9300#show boot mode
	System initialized in normal switching mode
	System configured to boot in openflow forwarding mode

	Reload required to boot switch in configured boot mode.

	Switch-C9300#reload


Configure Openflow
^^^^^^^^^^^^^^^^^^

** Configure the Management interface communicate with controller. **

.. code-block:: console

	Switch-C9300#
	Switch-C9300#configure terminal
	Switch-C9300(config)#interface GigabitEthernet0/0
	Switch-C9300(config-if)#vrf forwarding Mgmt-vrf
	Switch-C9300(config-if)#ip address 192.168.0.41 255.255.255.0
	Switch-C9300(config-if)#negotiation auto
	Switch-C9300(config-if)#end
	Switch-C9300#

** Configure the Openflow feature and controller connectivity. **

.. code-block::  console

	Switch-C9300#
	Switch-C9300#configure terminal
	Switch-C9300(config)#feature openflow
	Switch-C9300(config)#openflow
	Switch-C9300(config-openflow)#switch 1 pipeline 1
	Switch-C9300(config-openflow-switch)#controller ipv4 192.168.0.91 port 6653 vrf Mgmt-vrf security none
	Switch-C9300(config-openflow-switch)#controller ipv4 192.168.0.91 port 6654 vrf Mgmt-vrf security none
	Switch-C9300(config-openflow-switch)#datapath-id 0xABCDEF1234
	Switch-C9300(config-openflow-switch)#end
	Switch-C9300#

** Disable DTP/keepalive on OpenFlow ports which may interfere with FAUCET. **

        The following example will disable DTP and keepalives for TenGigabitEthernet1/0/1-24; adjust the range as necessary.

.. code-block::  console

        Switch-C9300(config)#interface range TenGigabitEthernet1/0/1-24
        Switch-C9300(config-if-range)#switchport mode trunk
        Switch-C9300(config-if-range)#switchport nonegotiate
        Switch-C9300(config-if-range)#spanning-tree bpdufilter enable
        Switch-C9300(config-if-range)#no keepalive
        Switch-C9300(config-if-range)#exit

** Configure TCP window. **

        Configure a larger than default TCP window, so that the switch can output OpenFlow messages to controllers more efficiently.

        See https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipapp/configuration/xe-3s/iap-xe-3s-book/iap-tcp.html#GUID-69BF753F-A478-4B38-808F-D7830EB7B70F

.. code-block::  console

        Switch-C9300#configure terminal
        Switch-C9300(config)#ip tcp window-size 65535
        Switch-C9300(config)#exit
        Switch-C9300#

Faucet
^^^^^^

On the FAUCET configuration file (``/etc/faucet/faucet.yaml``), add the datapath of the switch you wish to be managed by FAUCET. The device type (hardware) should be set to ``CiscoC9K`` in the configuration file.

.. code-block:: yaml
  :caption: /etc/faucet/faucet.yaml
  :name: cisco/faucet.yaml

	dps:
	    Cisco-C9K:
	        dp_id: 0xABCDEF1234
	        hardware: "CiscoC9K"
	        interfaces:
	            1:
	                native_vlan: 100
	                name: "port1"
	            2:
	                native_vlan: 100
	                name: "port2"


Troubleshooting
^^^^^^^^^^^^^^^

Command to check overall openflow configuration

.. code-block:: console

	Switch-C9300#
	Switch-C9300#show openflow switch 1
	Logical Switch Context
	  Id: 1
	  Switch type: Forwarding
	  Pipeline id: 1
	  Data plane: secure
	  Table-Miss default: drop
	  Configured protocol version: Negotiate
	  Config state: no-shutdown
	  Working state: enabled
	  Rate limit (packet per second): 0
	  Burst limit: 0
	  Max backoff (sec): 8
	  Probe interval (sec): 5
	  TLS local trustpoint name: not configured
	  TLS remote trustpoint name: not configured
	  Logging flow changes: Disabled
	  Stats collect interval (sec): 5
	  Stats collect Max flows: 9216
	  Stats collect period (sec):  1
	  Minimum flow idle timeout (sec):  10
	  OFA Description:
		 Manufacturer: Cisco Systems, Inc.
		 Hardware: C9300-48P
		 Software: Cisco IOS Software [Fuji], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 16.8.1GO3, RELEASE SOFTWARE (fc1)| openvswitch 2.1
		 Serial Num: FCW2145L0FP
		 DP Description: Faucet-C9300:sw1
	  OF Features:
		 DPID: 0x000000ABCDEF1234
		 Number of tables: 9
		 Number of buffers: 256
		 Capabilities: FLOW_STATS TABLE_STATS PORT_STATS
	  Controllers:
		 192.168.0.91:6653, Protocol: TCP, VRF: Mgmt-vrf
		 192.168.0.91:6654, Protocol: TCP, VRF: Mgmt-vrf
	  Interfaces:
		 GigabitEthernet1/0/1
		 GigabitEthernet1/0/2
		 ....

Command to check the openflow flows installed

.. code-block:: console

    Switch-C9300#
    Switch-C9300#show openflow switch 1 flow list
	Logical Switch Id: 1
	Total flows: 9

	Flow: 1 Match: any Actions: drop, Priority: 0, Table: 0, Cookie: 0x0, Duration: 33812.029s, Packets: 46853, Bytes: 3636857
	...

Command to check the state of the port status

.. code-block:: console

    Switch-C9300#
    Switch-C9300#show openflow switch 1 ports
	Logical Switch Id: 1
	Port    Interface Name   Config-State     Link-State  Features
	   1           Gi1/0/1        PORT_UP        LINK_UP  1GB-HD
	   2           Gi1/0/2        PORT_UP      LINK_DOWN  1GB-HD
	   3           Gi1/0/3        PORT_UP      LINK_DOWN  1GB-HD
	   4           Gi1/0/4        PORT_UP      LINK_DOWN  1GB-HD

Command to check the status of the controller

.. code-block:: console

    Switch-C9300#
    Switch-C9300#show openflow switch 1 controller
    Logical Switch Id: 1
    Total Controllers: 2

      Controller: 1
        192.168.0.91:6653
        Protocol: tcp
        VRF: Mgmt-vrf
        Connected: Yes
        Role: Equal
        Negotiated Protocol Version: OpenFlow 1.3
        Last Alive Ping: 2018-10-03 18:43:07 NZST
        state: ACTIVE
        sec_since_connect: 13150

      Controller: 2
        192.16.0.91:6654
        Protocol: tcp
        VRF: Mgmt-vrf
        Connected: Yes
        Role: Equal
        Negotiated Protocol Version: OpenFlow 1.3
        Last Alive Ping: 2018-10-03 18:43:07 NZST
        state: ACTIVE
        sec_since_connect: 12960


Command to check controller statistics

.. code-block:: console

    Switch-C9300#
    Switch-C9300#show openflow switch 1 controller stats
    Logical Switch Id: 1
    Total Controllers: 2

      Controller: 1
        address                         :  tcp:192.168.0.91:6653%Mgmt-vrf
        connection attempts             :  165
        successful connection attempts  :  61
        flow adds                       :  1286700
        flow mods                       :  645
        flow deletes                    :  909564
        flow removals                   :  0
        flow errors                     :  45499
        flow unencodable errors         :  0
        total errors                    :  45499
        echo requests                   :  rx: 842945, tx:205
        echo reply                      :  rx: 140, tx:842945
        flow stats                      :  rx: 0, tx:0
        barrier                         :  rx: 8324752, tx:8324737
        packet-in/packet-out            :  rx: 29931732, tx:8772758

      Controller: 2
        address                         :  tcp:192.168.0.91:6654%Mgmt-vrf
        connection attempts             :  11004
        successful connection attempts  :  3668
        flow adds                       :  0
        flow mods                       :  0
        flow deletes                    :  0
        flow removals                   :  0
        flow errors                     :  0
        flow unencodable errors         :  0
        total errors                    :  0
        echo requests                   :  rx: 946257, tx:1420
        echo reply                      :  rx: 1420, tx:946257
        flow stats                      :  rx: 47330, tx:57870
        barrier                         :  rx: 0, tx:0
        packet-in/packet-out            :  rx: 377, tx:0

References
^^^^^^^^^^

- `Catalyst 9K at-a-glance <https://www.cisco.com/c/dam/en/us/products/collateral/switches/catalyst-9300-series-switches/nb-09-cat-9k-aag-cte-en.pdf>`_
- `Catalyst 9400 SUP1 <https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9400-series-switches/datasheet-c78-739055.html>`_
- `Catalyst 9400 Linecard <https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9400-series-switches/datasheet-c78-739054.html>`_
