:Authors: - Abhay B

============================
FAUCET on HPE-Aruba Switches
============================

------------
Introduction
------------
All the Aruba's v3 generation of wired switches support the FAUCET pipeline.
These switches include:

- `5400R <http://www.arubanetworks.com/products/networking/switches/5400r-series/>`_
- `3810 <http://www.arubanetworks.com/products/networking/switches/3810-series/>`_
- `2930F <http://www.arubanetworks.com/products/networking/switches/2930f-series/>`_

The FAUCET pipeline is only supported from **16.03** release of the firmware onwards.

For any queries, please post your question on HPE's `SDN forum <https://community.hpe.com/t5/SDN-Discussions/bd-p/sdn-discussions>`_.

-----
Setup
-----

^^^^^^
Switch
^^^^^^

**VLAN/PORT configuration**

To ensure any port/vlan configuration specified in the *faucet.yaml* file works, one needs to pre-configure all vlans on the switch. Every dataplane port on the switch is made a tagged member of every vlan. This permits FAUCET to perform flow matching and packet-out on any port/vlan combination. The control-plane port (either OOBM or a front-panel port) is kept separate, so that FAUCET does not attempt to modify the control-plane port state.

* Using OOBM control-plane (3810, 5400R)

::

	// Increase the maximum number of allowed VLANs on the box and save the configuration.
	switch (config)# max-vlans 4094
	switch (config)# write mem

	// Reboot the box for the new max-vlan configuration to take affect.
	switch (config)# boot system
	
	// Configure the control-plane IP address
	switch (config)# oobm ip address 20.0.0.1/24 

	// Create maximum number of VLANs and tag every dataplane port available to each vlan. Takes up to 30 minutes.
	switch (config)# vlan 2-4094 tagged all

* Using VLAN control-plane (2930)

::

	// Increase the maximum number of allowed VLANs on the box and save the configuration.
	switch (config)# max-vlans 2048
	switch (config)# write mem

	// Reboot the box for the new max-vlan configuration to take affect.
	switch (config)# boot system

	// Create a control-plane vlan and add a single control-plane port (port 48)
	switch (config)# vlan 2048 untagged 48
	
	// Configure the control-plane IP address
	switch (config)# vlan 2048 ip address 20.0.0.1/24

	// Create maximum number of VLANs and tag every dataplane port available to each vlan,
	// except for the control-plane vlan (above). Note that the command below assumes it
	// is run on a 52-port switch, with port 48 as the control-plane. Takes up to 20 minutes.
	switch (config)# vlan 2-2047 tagged 1-47,49-52

**OpenFlow configuration**

Aruba switches reference a controller by ID, so first configure the controllers which will be used. The controller-interface matches the control-plane configuration above.

* Using OOBM control-plane (3810, 5400R)

::

	// Enter OpenFlow context
	switch (config)# openflow

	// Configure an OpenFlow controller connection for FAUCET over tcp-port 6653
	switch(openflow)# controller-id 1 ip 20.0.0.2 port 6653 controller-interface oobm

	// Configure an OpenFlow controller connection for Gauge over tcp-port 6654
	switch(openflow)# controller-id 2 ip 20.0.0.2 port 6654 controller-interface oobm

* Using VLAN control-plane (2930)

::

	// Enter OpenFlow context
	switch (config)# openflow

	// Configure an OpenFlow controller connection for FAUCET over tcp-port 6653
	switch(openflow)# controller-id 1 ip 20.0.0.2 port 6653 controller-interface vlan 2048

	// Configure an OpenFlow controller connection for Gauge over tcp-port 6654
	switch(openflow)# controller-id 2 ip 20.0.0.2 port 6654 controller-interface vlan 2048

Aruba switches support two OpenFlow instance types:

- **Aggregate** - Every VLAN on the switch apart from the controller/management VLANs are OpenFlow managed.
- **Virtualization** - A set of VLANs configured as members are OpenFlow managed.

Since FAUCET is designed for a pure OpenFlow environment, we choose the "**aggregate**" instance type.

::

	// Enter the OpenFlow instance context
	switch(openflow)# instance aggregate

	// Associate the controllers to the instance
	switch(of-inst-aggregate)# controller-id 1
	switch(of-inst-aggregate)# controller-id 2

	// Configure the OpenFlow version to be 1.3
	switch(of-inst-aggregate)# version 1.3 only

	// Configure the pipeline model type of the instance. It is a must to set it to custom.
	switch(of-inst-aggregate)# pipeline-model custom

	// Configure the payload in the packet-ins message to be sent in its original form.
	switch(of-inst-aggregate)# packet-in vlan-tagging input-form

	// Ensure the switch re-attempts an OpenFlow connection at least once
	// every 10 seconds when connection is dropped/inactive.
	switch(of-inst-aggregate)# max-backoff-interval 10

	// Allow OpenFlow to override some protocols which are otherwise excluded from OpenFlow processing in switch CPU.
	switch(of-inst-aggregate)# override-protocol all
	WARNING: Overriding the protocol can also potentially lead to control packets
	         of the protocol to bypass any of the security policies like ACL(s).
	Continue (y/n)? y

	// Enable the instance
	switch(of-inst-aggregate)# enable
	switch(of-inst-aggregate)# exit

	// Enable OpenFlow globally
	switch(openflow)# enable
	switch(openflow)# exit

	// Check the OpenFlow instance configuration (includes Datapath ID associated)
	switch# show openflow instance aggregate
	...

	// Easier way to get the Datapath ID associated with the OpenFlow instance
	switch# show openflow instance aggregate | include Datapath ID
	...

At this point, OpenFlow is enabled and running on the switch. If the FAUCET controller is running and has connected to the switch successfully, you should see the FAUCET pipeline programmed on the switch.

::

	switch# show openflow instance aggregate flow-table

	 OpenFlow Instance Flow Table Information

         Table                       Flow     Miss
         ID    Table Name            Count    Count         Goto Table
         ----- --------------------- -------- ------------- -------------
         0     Port ACL              5        0             1, 2, 3, 4...
         1     VLAN                  10       0             2, 3, 4, 5...
         2     VLAN ACL              1        0             3, 4, 5, 6...
         3     Ethernet Source       2        0             4, 5, 6, 7, 8
         4     IPv4 FIB              1        0             5, 6, 7, 8
         5     IPv6 FIB              1        0             6, 7, 8
         6     VIP                   1        0             7, 8
         7     Ethernet Destination  2        0             8
         8     Flood                 21       0             *


         Table
         ID    Table Name            Available Free Flow Count
         ----- --------------------- ------------------------------
         0     Port ACL              Ports 1-52          : 46
         1     VLAN                  Ports 1-52          : 91
         2     VLAN ACL              Ports 1-52          : 50
         3     Ethernet Source       Ports 1-52          : 99
         4     IPv4 FIB              Ports 1-52          : 100
         5     IPv6 FIB              Ports 1-52          : 100
         6     VIP                   Ports 1-52          : 20
         7     Ethernet Destination  Ports 1-52          : 99
         8     Flood                 Ports 1-52          : 280

         * Denotes that the pipeline could end here.


^^^^^^
Faucet
^^^^^^

On the FAUCET configuration file (*/etc/ryu/faucet/faucet.yaml*), add the datapath of the switch you wish to be managed by FAUCET. The device type (hardware) should be set to **Aruba** in the configuration file.

::

	dps:
	    aruba-3810:
	        dp_id: 0x00013863bbc41800
	        hardware: "Aruba"
	        interfaces:
	            1:
	                native_vlan: 100
	                name: "port1"
	            2:
	                native_vlan: 100
	                name: "port2"


You will also need to install pipeline configuration files (these files instruct FAUCET to configure the switch
with the right OpenFlow tables - these files and FAUCET's pipeline must match).

::

       sudo cp etc/ryu/faucet/ofproto_to_ryu.json /etc/ryu/faucet
       sudo cp etc/ryu/faucet/aruba_pipeline.json /etc/ryu/faucet


-----
Scale
-----

Most tables in the current FAUCET pipeline need wildcards and hence use TCAMs in hardware.
There are 2000 entries available globally for the whole pipeline. Currently, it has been
distributed amongst the 9 tables as follows:

+----------------+------------------+
| Table          | Maximum Entries  |
+================+==================+
| Port ACL       | 50               |
+----------------+------------------+
| VLAN           | 300              |
+----------------+------------------+
| VLAN ACL       | 50               |
+----------------+------------------+
| ETH_SRC        | 500              |
+----------------+------------------+
| IPv4 FIB       | 300              |
+----------------+------------------+
| IPv6 FIB       | 10               |
+----------------+------------------+
| VIP            | 10               |
+----------------+------------------+
| ETH_DST        | 500              |
+----------------+------------------+
| FLOOD          | 300              |
+----------------+------------------+

Based on one's deployment needs, these numbers can be updated for each table (update max_entries in $(REPO_ROOT)/faucet/aruba/aruba_pipeline.json).

::

	NOTE: The summation of max entries across all 9 tables cannot cross 2000 and the minimum size of a given table has to be 2.
	You need to restart FAUCET for the new numbers to reflect on the switch.

-----------
Limitations
-----------

- Aruba switches currently does not support all the IPv6 related functionality inside FAUCET
- Aruba switches currently does not support the OFPAT_DEC_NW_TTL action (so when routing, TTL will not be decremented).

-----
Debug
-----

If you encounter a failure or unexpected behavior, it may help to enable debug output
on Aruba switches. Debug output displays information about what OpenFlow is doing on
the switch at message-level granularity.

::

	switch# debug openflow
	switch# debug destination session
	switch# show debug

	 Debug Logging

	  Source IP Selection: Outgoing Interface
	  Origin identifier: Outgoing Interface IP
	  Destination:
	   Session

	  Enabled debug types:
	   openflow
	   openflow packets
	   openflow events
	   openflow errors
	   openflow packets tx
	   openflow packets rx
	   openflow packets tx pkt_in
	   openflow packets rx pkt_out
	   openflow packets rx flow_mod

----------
References
----------

- `Aruba OpenFlow Administrator Guide (16.03) <http://h20565.www2.hpe.com/hpsc/doc/public/display?sp4ts.oid=1008605435&docLocale=en_US&docId=emr_na-c05365339>`_
- `Aruba Switches <http://www.arubanetworks.com/products/networking/switches/>`_
- `FAUCET <https://github.com/faucetsdn/faucet>`_

