:Authors: - Rahul Gupta

=================================
FAUCET on Allied Telesis products
=================================

------------
Introduction
------------
Allied Telesis has a wide portfolio of OpenFlow enabled switches that all support the Faucet pipeline.
These OpenFlow enabled switches come in various port configurations of 10/18/28/52 with POE+ models as well.
Here is a list of some of our most popular switches:

- `AT-x930 <http://www.alliedtelesis.com/products/x930-series/>`_
- `AT-x510 <http://www.alliedtelesis.com/products/x510-series/>`_
- `AT-x230 <http://www.alliedtelesis.com/products/x230-series/>`_

-----
Setup
-----

^^^^^^
Switch
^^^^^^

**OpenFlow supported Firmware**

OpenFlow has been supported since AlliedWarePlus version 5.4.6 onwards.
To inquire more about compatibility of versions, you can contact our customer support team `here <http://www.alliedtelesis.com/services-and-support>`_.

**OpenFlow configuration**

For a **Pure OpenFlow** deployment, we recommend the following configurations on the switch.
Most of these configuration steps will be shown with an example.

::

    /* Create an OpenFlow native VLAN */
    awplus (config)# vlan database
    awplus (config-vlan)# vlan 4090

    /* Set an IP address for Control Plane(CP)
     * Here we will use vlan1 for Management/Control Plane */
    awplus (config)# interface vlan1
    awplus (config-if)# ip address 192.168.1.1/24

    /* Configure the FAUCET controller
     * Let's use TCP port 6653 for connection to Faucet */
    awplus (config)# openflow controller tcp 192.168.1.10 6653

    /* (OPTIONAL) Configure GAUGE controller
     * Let's use TCP port 6654 for connection to Gauge */
    awplus (config)# openflow controller tcp 192.168.1.10 6654

    /* User must set a dedicated native VLAN for OpenFlow ports
     * OpenFlow native VLAN MUST be created before it is set!
     * VLAN ID for this native VLAN must be different from the native VLAN for control plane */
    awplus (config)# openflow native vlan 4090

    /* Enable OpenFlow on desired ports */
    awplus (config)# interface port1.0.1-1.0.46
    awplus (config-if)# openflow

    /* Disable Spanning Tree Globally */
    awplus (config)# no spanning-tree rstp enable

    /* OpenFlow requires that ports under its control do not send any control traffic
     * So it is better to disable RSTP and IGMP Snooping TCN Query Solicitation.
     * Disable IGMP Snooping TCN Query Solicitation on the OpenFlow native VLAN */
    awplus (config)# interface vlan4090
    awplus (config-if)# no ip igmp snooping tcn query solicit


Once OpenFlow is up and running and connected to Faucet/Gauge controller, you should be able to verify the operation using some of our show commands.

::

    /* To check contents of the DP flows */
    awplus# show openflow flows

    /* To check the actual rules as pushed by the controller */
    awplus# show openflow rules

    /* To check the OpenFlow configuration and other parameters */
    awplus# show openflow status
    awplus# show openflow config
    awplus# show openflow coverage

Some other OPTIONAL configuration commands, that may be useful to modify some parameters, if needed.

::
    
    /* Set the OpenFlow version other than default version(v1.3) */
    awplus (config)# openflow version 1.0

    /* Set IPv6 hardware filter size
     * User needs to configure the following command if a packet needs to be forwarded by IPv6 address matching!
     * Please note that this command is supported on AT-x510 and AT-x930 only */
    awplus (config)# platform hwfilter-size ipv4-full-ipv6

    /* Set the datapath ID(DPID)
     * By default, we use the switch MAC address for datapath-ID.
     * To change the DPID to a hex value 0x1, use the following */
    awplus (config)# openflow datapath-id 1

    /* NOTE - For all software versions prior to 5.4.7, all VLAN(s) must be included in the vlan database config
     * on the switch before they can be used by OpenFlow.
     * Here is an example to create DP VLANs 2-100 */
    awplus (config)# vlan database
    awplus (config-vlan)# vlan 2-100

^^^^^^
Faucet
^^^^^^

Edit the faucet configuration file (/etc/ryu/faucet/faucet.yaml) to add the datapath of the switch you wish to be managed by faucet.
This yaml file also contains the interfaces that need to be seen by Faucet as openflow ports.
The device type (hardware) should be set to **Allied-Telesis** in the configuration file.

::

	dps:
	    allied-telesis:
	        dp_id: 0x0000eccd6d123456
	        hardware: "Allied-Telesis"
	        interfaces:
	            1:
	                native_vlan: 100
	                name: "port1.0.1"
	            2:
	                tagged_vlans: [2001,2002,2003]
	                name: "port1.0.2"
	                description: "windscale"

----------
References
----------

- `Allied Telesis x930 <https://www.sdxcentral.com/products/x930-gigabit-layer-3-stackable-switches/>`_
- `OpenFlow Configuration Guide <http://www.alliedtelesis.com/documents/openflow-feature-overview-and-configuration-guide/>`_

