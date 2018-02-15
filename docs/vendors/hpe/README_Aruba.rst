:Authors: - Abhay B, Shivaram Mysore

Faucet on HPE-Aruba Switches
============================

Introduction
------------
All the Aruba's v3 generation of wired switches support the FAUCET pipeline.
These switches include:

- `5400R <http://www.arubanetworks.com/products/networking/switches/5400r-series/>`_
- `3810 <http://www.arubanetworks.com/products/networking/switches/3810-series/>`_
- `2930F <http://www.arubanetworks.com/products/networking/switches/2930f-series/>`_

The FAUCET pipeline is only supported from ``16.03`` release of the firmware onwards.

For any queries, please post your question on HPE's `SDN forum <https://community.hpe.com/t5/SDN-Discussions/bd-p/sdn-discussions>`_.

Setup
-----

System & Network Requirements
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

 * Use Serial Console cable to login to the box.
 * Use ``minicom`` for serial terminal @ 115Kbps.  Minicom is available on Linux and MacOS (macports) systems.
 * Connected Port 1 of Switch to Top of the Rack (TOR) switch which had DHCP and DNS enabled.  Mac Address was programmed into DNS/DHCP Server so that IP address of 10.20.5.11 was provided to this box.
 * Need a TFTP Server on the network with write access so that we can store system software for upgrade and also certificates.  The switch can copy files from a TFTP Server.

.. tip::

	How to clear the password settings

	Simultaneously press "Reset" and "Clear" buttons using a paper clip.  Release "Reset" button only first.  Once the orange power light comes up (after ~5 seconds), release the "Clear" button.


Switch
^^^^^^

**VLAN/PORT configuration**

To ensure any port/vlan configuration specified in the *faucet.yaml* file works, one needs to pre-configure all ``vlans`` on the switch. Every dataplane port on the switch is made a tagged member of every vlan. This permits FAUCET to perform flow matching and packet-out on any port/vlan combination. The control-plane port (either OOBM or a front-panel port) is kept separate, so that FAUCET does not attempt to modify the control-plane port state.

* *Using OOBM control-plane (3810, 5400R)*

.. code-block:: none

	// Increase the maximum number of allowed VLANs on the box and save the configuration.
	switch (config)# max-vlans 4094
	switch (config)# write mem

	// Reboot the box for the new max-vlan configuration to take affect.
	switch (config)# boot system

	// Configure the control-plane IP address
	switch (config)# oobm ip address 20.0.0.1/24

	// Create maximum number of VLANs and tag every dataplane port available to each vlan. Takes up to 30 minutes.
	switch (config)# vlan 2-4094 tagged all

* *Using VLAN control-plane (2930)*

.. code-block:: none

	// Increase the maximum number of allowed VLANs on the box and save the configuration.
	switch (config)# max-vlans 2048
	switch (config)# write mem

	// Reboot the box for the new max-vlan configuration to take affect.
	switch (config)# boot system

	// If you have mixed both management and control-plane vlan to a single port (port 1)
	switch (config)# vlan 2048 untagged 1

	// Alternatively, you can have a separate port for control plane traffic
	// Create a control-plane vlan and add a single control-plane port (port 48)
	switch (config)# vlan 2048 untagged 48

	// Configure the control-plane IP address
	// May Not be needed if you have port 1 set to DHCP/Bootp/DNS IP address of 10.20.5.11
	switch (config)# vlan 2048 ip address 10.20.5.11/16

	// Alternatively, to configure only the control-plane IP address
	switch (config)# vlan 2048 ip address 20.0.0.1/24

	// Create maximum number of VLANs and tag every dataplane port available to each vlan,
	// except for the control-plane vlan (above). Note that the command below assumes it
	// is run on a 52-port switch, with port 48 as the control-plane. Takes up to 20 minutes.
	switch (config)# vlan 2-2047 tagged 1-47,49-52

	// Configure DNS.  Here DNS is set to a local LAN DNS server
	switch (config)# ip dns server-address priority 1 10.20.0.1

**OpenFlow configuration**

Aruba switches reference a controller by ID, so first configure the controllers which will be used. The controller-interface matches the control-plane configuration above.

* *Using OOBM control-plane (3810, 5400R)*

.. code-block:: none

	// Enter OpenFlow context
	switch (config)# openflow

	// Configure an OpenFlow controller connection for FAUCET over tcp-port 6653
	switch(openflow)# controller-id 1 ip 20.0.0.2 port 6653 controller-interface oobm

	// Faucet Controller name can be FQDN
	switch(openflow)# controller-id 1 hostname controller-1.tenant1.tenants.servicefractal.com port 6653 controller-interface oobm

	// Configure an OpenFlow controller connection for Gauge over tcp-port 6654
	switch(openflow)# controller-id 2 ip 20.0.0.2 port 6654 controller-interface oobm

	// Gauge Controller name can be FQDN
	switch(openflow)# controller-id 2 hostname controller-1.tenant1.tenants.servicefractal.com port 6654 controller-interface oobm

* *Using VLAN control-plane (2930)*

.. code-block:: none

	// Enter OpenFlow context
	switch (config)# openflow

	// Configure an OpenFlow controller connection for FAUCET over tcp-port 6653
	switch(openflow)# controller-id 1 ip 20.0.0.2 port 6653 controller-interface vlan 2048

	// Faucet Controller name can be FQDN
	switch(openflow)# controller-id 1 hostname controller-1.tenant1.tenants.servicefractal.com port 6653 controller-interface vlan 2048

	// Configure an OpenFlow controller connection for Gauge over tcp-port 6654
	switch(openflow)# controller-id 2 ip 20.0.0.2 port 6654 controller-interface vlan 2048

	// Gauge Controller name can be FQDN
	switch(openflow)# controller-id 2 hostname controller-1.tenant1.tenants.servicefractal.com port 6654 controller-interface vlan 2048

Aruba switches support two OpenFlow instance types:

- **Aggregate** - Every VLAN on the switch apart from the controller/management VLANs are OpenFlow managed.
- **Virtualization** - A set of VLANs configured as members are OpenFlow managed.

Since FAUCET is designed for a pure OpenFlow environment, we choose the "**aggregate**" instance type.

.. code-block:: none

	// Enter the OpenFlow instance context
	switch(openflow)# instance aggregate

	// Associate the controllers to the instance
	switch(of-inst-aggregate)# controller-id 1
	switch(of-inst-aggregate)# controller-id 2

	// Associate the controllers in secure mode to the instance
	switch(of-inst-aggregate)# controller-id 1 secure
	switch(of-inst-aggregate)# controller-id 2 secure


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

	// To save the Configuration
	switch# save
	switch# write mem

	// Show running Configuration
	switch# show running-config

	// Check the OpenFlow instance configuration (includes Datapath ID associated)
	switch# show openflow instance aggregate
	...

	// Easier way to get the Datapath ID associated with the OpenFlow instance
	switch# show openflow instance aggregate | include Datapath ID
			Datapath ID                   : 00013863bbc41800

At this point, OpenFlow is enabled and running on the switch. If the FAUCET controller is running and has connected to the switch successfully, you should see the FAUCET pipeline programmed on the switch.

.. code-block:: none

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

	switch# show openflow instance aggregate
			Configured OF Version         : 1.3 only
			Negotiated OF Version         : 1.3
			Instance Name                 : aggregate
			Data-path Description         : aggregate
			Administrator Status          : Enabled
			Member List                   : VLAN 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
			............
			..............

			Controller Id Connection Status Connection State Secure Role
			------------- ----------------- ---------------- ------ ------
			1             Connected         Active           Yes    Equal
			2             Connected         Active           Yes    Equal

	// To just get openflow controllers
	switch (openflow)# show openflow controllers

			Controller Information

			Controller Id IP Address        Hostname          Port   Interface
			------------- ----------------- ----------------- ------ --------------
			1             0.0.0.0           controller-1.t... 6653   VLAN 2048
			2             0.0.0.0           controller-1.t... 6654   VLAN 2048


	// Copy Running Config to a TFTP Server
	// (first enable TFTP client)
	switch (config)# tftp client


PKI Setup on switch
^^^^^^^^^^^^^^^^^^^

.. note::

	Root certificate container supports only one root certificate not a chain.  So, install the one that the CSR (Certificate Signing Request) is signed with.

.. code-block:: none

		switch# show crypto pki application

			Certificate Extension Validation :

			Application      SAN/CN
			---------------- ------------
			openflow         Disabled
			syslog           Disabled

		// Here, we create Service Fractal CA profile
		switch (config)# crypto pki ta-profile SERVICEFRACTAL_CA

		// Copy the root certificate for the SERVICEFRACTAL_CA from a tftp server
		switch#  copy tftp ta-certificate SERVICEFRACTAL_CA 10.10.22.15 tenant1.tenants.servicefractal.com.cert.pem

		switch# show crypto pki ta-profile SERVICEFRACTAL_CA
			Profile Name    Profile Status                 CRL Configured  OCSP Configured
			--------------- ------------------------------ --------------- ---------------
			SERVICEFRACTAL_CA 1 certificate installed         No              No

			Trust Anchor:
			Version: 3 (0x2)
			Serial Number: 4096 (0x1000)
			Signature Algorithm: sha256withRSAEncryption
			...
			......

			// Now we are ready to create a CSR so that a switch identity certificate that is accepted by the controller can be setup.

		switch (config)# crypto pki identity-profile hpe_sf_switch1 subject common-name myswitch.tenant1.tenants.servicefractal.com org ServiceFractal org-unit vendor-test locality MyCity state CA country US

 		switch (config)# show crypto pki identity-profile
			Switch Identity:
			  ID Profile Name    : hpe_sf_switch1
			  Common Name (CN) : myswitch.tenant1.tenants.servicefractal.com
  			Org Unit (OU)    : vendor-test
  			Org Name (O)     : ServiceFractal
  			Locality (L)     : MyCity
  			State (ST)       : CA
  			Country (C)      : US

		// Generate CSR
		switch (config)# crypto pki create-csr certificate-name hpeswt_switch1_crt ta-profile SERVICEFRACTAL_CA usage openflow

		// Copy the printed CSR request and send it to "SERVICEFRACTAL_CA"

		switch (config)# show crypto pki local-certificate summary
			Name                 Usage         Expiration     Parent / Profile
			-------------------- ------------- -------------- --------------------
			hpeswt_switch1_crt   Openflow      CSR            SERVICEFRACTAL_CA

		// Once the signed certificate is received, copy the same to switch.
		switch (config)# copy tftp local-certificate 10.10.22.15 myswitch.tenant1.tenants.servicefractal.com.cert.pem
			000M Transfer is successful

		switch (config)# show crypto pki local-certificate summary
			Name                 Usage         Expiration     Parent / Profile
			-------------------- ------------- -------------- --------------------
			hpeswt_switch1_crt   Openflow      2019/01/02     SERVICEFRACTAL_CA


Faucet
^^^^^^

On the FAUCET configuration file (``/etc/faucet/faucet.yaml``), add the datapath of the switch you wish to be managed by FAUCET. The device type (hardware) should be set to ``Aruba`` in the configuration file.

.. code-block:: yaml
  :caption: /etc/faucet/faucet.yaml
  :name: hpe/faucet.yaml

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


You will also need to install pipeline configuration files (these files instruct FAUCET to configure the switch with the right OpenFlow tables - these files and FAUCET's pipeline must match).

.. code:: console

       $ sudo cp etc/faucet/ofproto_to_ryu.json /etc/faucet
       $ sudo cp etc/faucet/aruba_pipeline.json /etc/faucet


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

Based on one's deployment needs, these numbers can be updated for each table (update max_entries in ``$(REPO_ROOT)/faucet/aruba/aruba_pipeline.json``).

.. note::

    The summation of max entries across all 9 tables cannot cross 2000 and the minimum size of a given table has to be 2.
    You need to restart FAUCET for the new numbers to reflect on the switch.

Limitations
-----------

- Aruba switches currently does not support all the ``IPv6`` related functionality inside FAUCET
- Aruba switches currently does not support the ``OFPAT_DEC_NW_TTL`` action (so when routing, TTL will not be decremented).

Debug
-----

If you encounter a failure or unexpected behavior, it may help to enable debug output
on Aruba switches. Debug output displays information about what OpenFlow is doing on
the switch at message-level granularity.

.. code-block:: none

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

References
----------

- `Aruba OpenFlow Administrator Guide (16.03) <http://h20565.www2.hpe.com/hpsc/doc/public/display?sp4ts.oid=1008605435&docLocale=en_US&docId=emr_na-c05365339>`_
-  `Aruba OS version as of Dec 2017 is 16.05 <https://h10145.www1.hpe.com/downloads/DownloadSoftware.aspx?SoftwareReleaseUId=23120&ProductNumber=JL261A&lang=&cc=&prodSeriesId=&SaidNumber=/>`_
- `Aruba Switches <http://www.arubanetworks.com/products/networking/switches/>`_
- `FAUCET <https://github.com/faucetsdn/faucet>`_
-  `Model 2390F Product Site <https://www.hpe.com/us/en/product-catalog/networking/networking-switches/pip.aruba-2930f-switch-series.1008995294.html/>`_
-  `2930F top level documentation <https://support.hpe.com/hpesc/public/home/productSelector?sp4ts.oid=1008995294/>`_
- `Password settings  <https://community.arubanetworks.com/t5/Campus-Switching-and-Routing/Aruba-2930F-Web-GUI/td-p/308371/>`_
- `PKI Setup <http://h22208.www2.hpe.com/eginfolib/networking/docs/switches/WB/15-18/5998-8152_wb_2920_asg/content/ch17.html>`_
