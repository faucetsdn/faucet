:Authors: - Abhay B

============================
FAUCET on HPE-Aruba Switches
============================

------------
Introduction
------------
All the Aruba's v3 generation of wired switches support the faucet pipeline.
These switches include:

- `5400R <http://www.arubanetworks.com/products/networking/switches/5400r-series/>`_
- `3810 <http://www.arubanetworks.com/products/networking/switches/3810-series/>`_
- `2930F <http://www.arubanetworks.com/products/networking/switches/2930f-series/>`_

The faucet pipeline is only supported from **16.03** release of the firmware onwards.

For any queries, please post your question on HPE's `SDN forum <https://community.hpe.com/t5/SDN-Discussions/bd-p/sdn-discussions>`_.

-----
Setup
-----

^^^^^^
Switch
^^^^^^

**VLAN/PORT configuration**

To ensure any sort of port/vlan configuration specified in the *faucet.yaml* file works, one needs to create all the vlans that is planned to be used in the configuration on the switch tagging every dataplane port on the switch to each of those.

::

	// Increase the maximum number of allowed VLANs on the box to 4094 and save the configuration.
	// NOTE: On 2930F, the maximum number of VLANs allowed is 2048
	switch (config)# max-vlans 4094
	switch (config)# write mem
	
	// Reboot the box for the new max-vlan configuration to take affect.
	switch (config)# boot system
	
	// Create VLANs 2 to 4094 and tag every dataplane port available to each of those (Takes up to 30 minutes)
	switch (config)# vlan 2-4094 tagged all

**OpenFlow configuration**

Aruba switches support OpenFlow instance of 2 types:

- **Aggregate** - Every VLAN on the switch apart from the controller/management VLANs are OpenFlow manageed.
- **Virtualization** - A set of VLANs configured as members are OpenFlow managed.

Since faucet is desgined for a pure OpenFlow switch, we choose the "**aggregate**" instance type.

::

	// Enter OpenFlow context
	switch (config)# openflow
	
	// Configure an OpenFlow controller connection for faucet over tcp-port 6633 
	NOTE: We choose to connect the controller over the out of band management port in this example.
	switch(openflow)# controller-id 1 ip 20.0.0.2 controller-interface oobm
	
	// Configure an OpenFlow controller connection for gauge (optional) over tcp-port 6644
	switch(openflow)# controller-id 2 ip 20.0.0.2 port 6644 controller-interface oobm
	
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

At this point, OpenFlow is enabled and running on the switch. If the faucet controller is running and has connected to the switch successfully, you should see the faucet pipeline programmed on the switch.

::

	switch# show openflow instance aggregate flow-table
	
	 OpenFlow Instance Flow Table Information
	
	 Table                       Flow     Miss
	 ID    Table Name            Count    Count         Goto Table
	 ----- --------------------- -------- ------------- -------------
	 0     Port ACL              3        0             1, 2, 3, 4...
	 1     VLAN                  8        0             2, 3, 4, 5...
	 2     VLAN ACL              1        0             3, 4, 5, 6, 7
	 3     Ethernet Source       2        0             4, 5, 6, 7
	 4     IPv4 FIB              1        0             5, 6, 7
	 5     IPv6 FIB Table        1        0             6, 7
	 6     Ethernet Destination  2        0             7
	 7     Flood                 11       0             *
	
	
	 Table
	 ID    Table Name            Available Free Flow Count
	 ----- --------------------- ------------------------------
	 0     Port ACL              Ports 1-24,A        : 48
	 1     VLAN                  Ports 1-24,A        : 293
	 2     VLAN ACL              Ports 1-24,A        : 50
	 3     Ethernet Source       Ports 1-24,A        : 499
	 4     IPv4 FIB              Ports 1-24,A        : 300
	 5     IPv6 FIB Table        Ports 1-24,A        : 10
	 6     Ethernet Destination  Ports 1-24,A        : 499
	 7     Flood                 Ports 1-24,A        : 290
	
	 * Denotes that the pipeline could end here.

^^^^^^
Faucet
^^^^^^

On the faucet configuration file (*/etc/ryu/faucet/faucet.yaml*), add the datapath of the switch you wish to be managed by faucet. The device type (hardware) should be set to **Aruba** in the configuration file.

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

All tables in the current faucet pipeline need wildcards and hence use TCAMs in hardware.
There are 2000 entries available globally for the whole pipeline. Currently, it has been distributed amongst the 8 tables as follows:

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
| ETH_DST        | 500              |
+----------------+------------------+
| FLOOD          | 300              |
+----------------+------------------+

Based on one's deployment needs, these numbers can be updated for each table (update max_entries in $(REPO_ROOT)/faucet/aruba/aruba_pipeline.json).

::

	NOTE: The summation of max entries across all 8 tables cannot cross 2000 and the minimum size of a given table has to be 2.
	You need to restart faucet for the new numbers to reflect on the switch.

-----------
Limitations
-----------

- Aruba switches currently does not support all the IPv6 related functionality inside faucet.
- Aruba switches currently does not support the OFPAT_DEC_NW_TTL action which is used by faucet's route manager code to perform a route operation. To use IPv4 routing feature in faucet with Aruba switches, the use of dec_nw_ttl action has to be removed in the route manager code. The following diff shows the change required. This implies the ttl count will not be decremented when faucet routes a packet to a next hop.

::

	diff --git a/faucet/valve_route.py b/faucet/valve_route.py
	index 0c6a27c..6513556 100644
	--- a/src/ryu_faucet/org/onfsdn/faucet/valve_route.py
	+++ b/src/ryu_faucet/org/onfsdn/faucet/valve_route.py
	@@ -114,8 +114,7 @@ class ValveRouteManager(object):
	                 priority=priority,
	                 inst=[valve_of.apply_actions(
	                     [valve_of.set_eth_src(self.faucet_mac),
	-                     valve_of.set_eth_dst(eth_dst),
	-                     valve_of.dec_ip_ttl()])] +
	+                     valve_of.set_eth_dst(eth_dst)])] +
	                 [valve_of.goto_table(self.eth_dst_table)]))
	         now = time.time()

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
- `FAUCET <https://github.com/REANNZ/faucet>`_

