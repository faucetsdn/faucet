:Authors: - Rahul Gupta

Faucet on Allied Telesis products
=================================

Introduction
------------
Allied Telesis has a wide portfolio of OpenFlow enabled switches that all support the Faucet pipeline.
These OpenFlow enabled switches come in various port configurations of 10/18/28/52/96 with POE+ models as well.
Here is a list of some of our most popular switches:

- `AT-x930 <https://www.alliedtelesis.com/products/x930-series/>`_
- `SBx908Gen2 <https://www.alliedtelesis.com/products/switches/x908-gen2/>`_
- `AT-x950 <https://www.alliedtelesis.com/products/switches/x950-series/>`_
- `AT-x510 <https://www.alliedtelesis.com/products/x510-series/>`_
- `AT-x230 <https://www.alliedtelesis.com/products/x230-series/>`_

Setup
-----

Switch
^^^^^^

**OpenFlow supported Firmware**

OpenFlow has been supported since AlliedWarePlus version 5.4.6 onwards.
To inquire more about compatibility of versions, you can contact our `customer support team <http://www.alliedtelesis.com/services-and-support>`_.

**OpenFlow configuration**

For a **Pure OpenFlow** deployment, we recommend the following configurations on the switch.
Most of these configuration steps will be shown with an example.

.. code-block:: none

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

    /* NOTE - Starting from AlliedWarePlus version 5.4.8-2, we have added support for controller name. 
     * You can specify a controller name with the optional <name> parameter.
     * Users can still use the previous controller commands (without the name parameter) and the switch will auto-generate
     * a suitable name (starting with "oc") in that case.
     * Here is an example to add a controller with name 'faucet' using TCP port 6653 */
    awplus (config)# openflow controller faucet tcp 192.168.1.10 6653

    /* User must set a dedicated native VLAN for OpenFlow ports
     * OpenFlow native VLAN MUST be created before it is set!
     * VLAN ID for this native VLAN must be different from the native VLAN for control plane */
    awplus (config)# openflow native vlan 4090

    /* Enable OpenFlow on desired ports */
    awplus (config)# interface port1.0.1-1.0.46
    awplus (config-if)# openflow

    /* Disable Spanning Tree Globally */
    awplus (config)# no spanning-tree rstp enable

    /* Disable Loop protection detection Globally */
    awplus (config)# no loop-protection loop-detect

    /* OpenFlow requires that ports under its control do not send any control traffic
     * So it is better to disable RSTP and IGMP Snooping TCN Query Solicitation.
     * Disable IGMP Snooping TCN Query Solicitation on the OpenFlow native VLAN */
    awplus (config)# interface vlan4090
    awplus (config-if)# no ip igmp snooping tcn query solicit


Once OpenFlow is up and running and connected to Faucet/Gauge controller, you should be able to verify the operation using some of our show commands.

.. code-block:: none

    /* To check contents of the DP flows */
    awplus# show openflow flows

    /* To check the actual rules as pushed by the controller */
    awplus# show openflow rules

    /* To check the OpenFlow configuration and other parameters */
    awplus# show openflow status
    awplus# show openflow config
    awplus# show openflow coverage

Some other OPTIONAL configuration commands, that may be useful to modify some parameters, if needed.

.. code-block:: none

    /* Set the OpenFlow version other than default version(v1.3) */
    awplus (config)# openflow version 1.0

    /* Set IPv6 hardware filter size
     * User needs to configure the following command if a packet needs to be forwarded by IPv6 address matching! */
    awplus (config)# platform hwfilter-size ipv4-full-ipv6

    /* Set the datapath ID(DPID)
     * By default, we use the switch MAC address for datapath-ID.
     * To change the DPID to a hex value 0x1, use the following */
    awplus (config)# openflow datapath-id 1

    /* NOTE - For all software versions prior to 5.4.7, all data VLAN(s) must be included in the vlan database config
     * on the switch before they can be used by OpenFlow.
     * Here is an example to create DP VLANs 2-100 */
    awplus (config)# vlan database
    awplus (config-vlan)# vlan 2-100

    /* NOTE - Starting from software version 5.4.8-2, in order to negate a controller, you need to specify the controller name.
     * In case you add the controller the legacy way (without the name), the newer software will auto-generate a name which can be
     * used to delete the controller.
     * Here is an example to delete a controller with auto-generated name oc1 */
    awplus (config)# no openflow controller oc1

**Useful Switch related configurations**

.. note::

    If the Openflow controller is located in a different VLAN or Network segment, routing needs to be configured so that the switch can talk to the controller.

.. code-block:: none

    /* To set Timezone: Codes - https://www.timeanddate.com/time/zones/ */
    /* For US Pacific Time zone */
    awplus (config)# clock timezone NAPST minus 8

    /* To set DNS, say a local Gateway also acting as a DNS forwarder 10.20.0.1 */
    awplus (config)# ip name-server 10.20.0.1

    /* To make sure that DNS and routing correctly work, Gateway address needs to be set.
     * Here, Gateway is set only to the management VLAN, vlan1; 255 is the max depth allowed */
    awplus (config)# ip route 0.0.0.0/0 vlan1 255
    awplus (config)# ip route 0.0.0.0/0 10.20.0.1

    /* To see the configured Route database */
    awplus# show ip route database

    /* To test routing, ping Google.com - note the name to ip resolution */
    awplus# ping google.com 

**Setting up PKI Certs for secure connectivity between Switch and Openflow Controller**

.. note::

    There are many ways to get the keys and certificates into the box.
    Here, both private key (unencrypted PEM formatted) and corresponding Certificate (PEM) as trusted by the Openflow Controller is provided to the Switch Admin for installation.

Getting keys into the Switch flash partition

.. code-block:: none

    /* Here SCP is used to copy.  TFTP, USB, etc are other supported methods */
    awplus# copy scp://user@10.20.5.5/home/user/switch-cert.pem switch-cert.pem
    awplus# copy scp://user@10.20.5.5/home/user/switch-key_nopass.pem switch-key_nopass.pem

    /* Showing only relevant files */
    awplus# dir
           1679 -rw- Dec 20 2017 09:04:35  switch-key_nopass.pem
          11993 -rw- Dec 20 2017 09:04:03  switch-cert.pem

Setting up Trustpoint for SSL connectivity to Openflow Controller

.. code-block:: none

    /* Create a local trustpoint */
    awplus (config)# crypto pki trustpoint local

    /* Point the switch to the OF controller */
    awplus (config)# openflow controller ssl 192.168.1.10 6653

    /* Allow OpenFlow to use local trustpoint */
    awplus (config)# openflow ssl trustpoint local

    /* Copy the new key and pvt keys to local trustpoint directory */
    awplus# copy switch-key_nopass.pem .certs/pki/local/cakey.pem

    Overwrite flash:/.certs/pki/local/cakey.pem (y/n)[n]:y
    Copying...
    Successful operation

    awplus# copy switch-cert.pem .certs/pki/local/cacert.pem

    Overwrite flash:/.certs/pki/local/cacert.pem (y/n)[n]:y
    Copying...
    Successful operation    

**Enabling SNMP for monitoring Management/Control Plane Port**

Openflow enabled ports are monitored via Openflow Stats request/response protocol.
This means that Management port (and if Openflow control channel port is separate), are not monitored on the switch.
Hence, SNMP is used to monitor the same. SNMP v2 is the most widely used.
As an example below, let us assume NMS is @ 10.20.30.71

.. code-block:: none

    /* Check contents of existing access-list */
    awplus# show access-list

    /* Enable the SNMP agent and enable the generation of authenticate
     * failure traps to monitor unauthorized SNMP access. */
    awplus (config)# snmp-server enable trap auth

    /* Creating a write access community called sfractalonprem1rw for use by
     * the central network management station at 10.20.30.71 */
    awplus (config)# access-list 96 permit 10.20.30.71
    awplus (config)# snmp-server community sfractalonprem1rw rw view atview 96

    /* Enable link traps on VLANs or specific interfaces (in our case management port) */
    awplus (config)# interface port1.0.1
    awplus (config-if)# snmp trap link-status

    /* Configuring Trap Hosts */
    awplus (config)# snmp-server host 10.20.30.71 version 2c sfractalonprem1rw

    /* Confirm all SNMP settings */
    awplus# show snmp-server
    SNMP Server .......................... Enabled
    IP Protocol .......................... IPv4, IPv6
    SNMP Startup Trap Delay .............. 30 Seconds
    SNMPv3 Engine ID (configured name) ... Not set
    SNMPv3 Engine ID (actual) ............ 0x80001f8880a2977c410e3bb658

    awplus# show snmp-server community
    SNMP community information:
      Community Name ........... sfractalonprem1rw
        Access ................. Read-write
        View ................... atview

    awplus# show run snmp
    snmp-server
    snmp-server enable trap auth
    snmp-server community sfractalonprem1rw rw view atview 96
    snmp-server host 10.20.30.71 version 2c sfractalonprem1rw
    !

    /* Check if the interface is configured for SNMP */
    awplus# show interface port1.0.1
    Interface port1.0.1
      Scope: both
      Link is UP, administrative state is UP
      Thrash-limiting
        Status Not Detected, Action learn-disable, Timeout 1(s)
      Hardware is Ethernet, address is 001a.eb96.6ef2
      index 5001 metric 1 mru 1500
      current duplex full, current speed 1000, current polarity mdi
      configured duplex auto, configured speed auto, configured polarity auto
      <UP,BROADCAST,RUNNING,MULTICAST>
      SNMP link-status traps: Sending (suppressed after 20 traps in 60 sec)
        Link-status trap delay: 0 sec
        input packets 14327037, bytes 3727488153, dropped 0, multicast packets 440768
        output packets 11172202, bytes 2028940085, multicast packets 233192 broadcast packets 1889
      Time since last state change: 40 days 00:48:38
    
    awplus# show access-list
    Standard IP access list 96
       10 permit 10.20.30.71

**Enabling sFlow for monitoring Management/Control Port**

Openflow enabled ports are monitored via Openflow Stats request/response protocol.
This means that Management port (and if Openflow control channel port is separate), are not monitored on the switch.
Hence, sFlow is used to monitor the same.  
At this time, no TLS/SSL support is seen on the sFlow Controller channel.

.. code-block:: none

    /* Check for any existing sFlow configuration */
    awplus# show running-config sflow
    !

    /* Enable sFlow globally */
    awplus (config)# sflow enable
    % INFO: sFlow will not function until collector address is non-zero
    % INFO: sFlow will not function until agent address is set
    awplus# show running-config sflow
    !
    sflow enable
    !

    /* Confirm the new sFlow settings */
    awplus# show sflow
    sFlow Agent Configuration:                    Default Values
      sFlow Admin Status ........ Enabled         [Disabled]
      sFlow Agent Address ....... [not set]       [not set]
      Collector Address ......... 0.0.0.0         [0.0.0.0]
      Collector UDP Port ........ 6343            [6343]
      Tx Max Datagram Size ...... 1400            [1400]

    sFlow Agent Status:
      Polling/sampling/Tx ....... Inactive because:
                                    - Agent Addr is not set
                                    - Collector Addr is 0.0.0.0
                                    - Polling & sampling disabled on all ports

    /* Agent IP MUST be the IP address of the management port of this switch */
    awplus (config)# sflow agent ip 192.0.2.23

    /* Default sFlow UDP collector port is 6343 */
    awplus (config)# sflow collector ip 192.0.2.25 port 6343
    awplus (config)# interface port1.0.1
    awplus (config-if)# sflow polling-interval 120
    awplus (config-if)# sflow sampling-rate 512

    awplus# show running-config sflow
    !
    sflow agent ip 192.0.2.23
    sflow collector ip 192.0.2.25
    sflow enable
    !
    interface port1.0.1
     sflow polling-interval 120
     sflow sampling-rate 512
    !
    awplus#

Faucet
^^^^^^

Edit the faucet configuration file (/etc/faucet/faucet.yaml) to add the datapath of the switch you wish to be managed by faucet.
This yaml file also contains the interfaces that need to be seen by Faucet as openflow ports.
The device type (hardware) should be set to ``Allied-Telesis`` in the configuration file.

.. code-block:: yaml
  :caption: /etc/faucet/faucet.yaml
  :name: allied-telesis/faucet.yaml

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

References
----------

- `Allied Telesis x930 <https://www.sdxcentral.com/products/x930-gigabit-layer-3-stackable-switches/>`_
- `OpenFlow Configuration Guide <https://www.alliedtelesis.com/documents/openflow-feature-overview-and-configuration-guide>`_
- `Chapter 61 (SNMP) <https://www.alliedtelesis.com/sites/default/files/documents/manuals/x930_command_ref.4.8-1.x.pdf/>`_
- `SNMP Feature Guide <https://www.alliedtelesis.com/documents/snmp-feature-overview-and-configuration-guide/>`_

