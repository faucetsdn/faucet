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

The FAUCET pipeline is only supported from ``16.03`` release of the
firmware onwards. HPE Aruba recommends use of the latest available
firmware, which can be downloaded from `HPE Support
<https://www.hpe.com/networking/support>`_.

For any queries, please post your question on HPE's `SDN forum <https://community.hpe.com/t5/SDN-Discussions/bd-p/sdn-discussions>`_.

Caveats
--------

- IPv6 management of the switch, together OpenFlow is not supported.
- The ``OFPAT_DEC_NW_TTL`` action is not supported (when FAUCET is configured as a router, IP TTL will not be decremented).


Setup
-----

In all configuration examples following, substitute 10.0.0.1 for your
controller IP address, and 10.0.0.2 for your switch IP address, as
appropriate.  VLAN 2048 is used for the control plane - you can
substitute this for another VID.  In any case, the control plane VLAN
VID you reserve cannot be used in FAUCET's configuration file (ie.  it
cannot be controlled by OpenFlow).


Switch
^^^^^^

**Chassis configuration (5400R only)**

Skip this step if you have a fixed configuration system (2930 or 3810).

On a chassis system with insertable cards, new cards are
configured to work in a backwards-compatible way (with reduced
functionality) unless older cards are disabled in the chassis. To
disable older (V2) cards and enable all functionality necessary to
operate FAUCET, put the chassis into a mode where only V3 cards are
allowed.

.. code-block:: none

	// Disable backwards compatibility, enable full Openflow flexibility
	switch (config)# no allow-v2-modules

**VLAN/port configuration**

Aruba switches require the reservation of each VLAN VID you wish to
use in FAUCET, on the switch.  Some Aruba switches will allow you to
reserve a large range of VIDs at once.  If your switch has limited
resources, then reserve just the VIDs you need.

The reservation of a VID is accomplished by defining a tagged VLAN.
Note even you are using that VLAN VID untagged on a port in FAUCET, it
must be reserved as tagged on the switch


* *Using OOBM control-plane (3810, 5400R)*

.. code-block:: none

	// Increase the maximum number of allowed VLANs on the box and save the configuration.
	// If the switch cannot reserve the full range, reserve only the maximum you need.
	switch (config)# max-vlans 4094
	switch (config)# write mem

	// Reboot the box for the new max-vlan configuration to take affect.
	switch (config)# boot system

	// Configure the control-plane IP address
	switch (config)# oobm ip address 10.0.0.2/24

	// Create maximum number of VLANs and tag every dataplane port available to each vlan. Takes up to 30 minutes.
        // If the switch cannot reserve the full range, reserve only the VLANs needed individually.
	switch (config)# vlan 2-4094 tagged all

* *Using VLAN control-plane (2930)*

.. code-block:: none

	// Increase the maximum number of allowed VLANs on the box and save the configuration.
        // If the switch cannot reserve the full range, reserve only the maximum you need.
	switch (config)# max-vlans 2048
	switch (config)# write mem

	// Reboot the box for the new max-vlan configuration to take affect.
	switch (config)# boot system

	// Create a control-plane vlan and add a single control-plane port (port 48)
	switch (config)# vlan 2048 untagged 48
	switch (config)# vlan 2048 ip address 10.0.0.2/24

	// Create maximum number of VLANs and tag every dataplane port available to each vlan,
	// except for the control-plane vlan (above). Note that the command below assumes it
	// is run on a 52-port switch, with port 48 as the control-plane. Takes up to 20 minutes.
	// If the switch cannot reserve the full range, reserve only the VLANs needed individually.
	switch (config)# vlan 2-2047 tagged 1-47,49-52


**OpenFlow configuration**

Aruba switches reference a controller by ID, so first configure the
controllers which will be used. The controller-interface matches the
control-plane configuration above.

* *Using OOBM control-plane (3810, 5400R)*

.. code-block:: none

	// Enter OpenFlow context
	switch (config)# openflow

	// Configure an OpenFlow controller connection for FAUCET over tcp-port 6653
	switch(openflow)# controller-id 1 ip 10.0.0.1 port 6653 controller-interface oobm

	// Configure an OpenFlow controller connection for Gauge over tcp-port 6654
	switch(openflow)# controller-id 2 ip 10.0.0.1 port 6654 controller-interface oobm


* *Using VLAN control-plane (2930)*

.. code-block:: none

	// Enter OpenFlow context
	switch (config)# openflow

	// Configure an OpenFlow controller connection for FAUCET over tcp-port 6653
	switch(openflow)# controller-id 1 ip 10.0.0.1 port 6653 controller-interface vlan 2048

	// Configure an OpenFlow controller connection for Gauge over tcp-port 6654
	switch(openflow)# controller-id 2 ip 10.0.0.1 port 6654 controller-interface vlan 2048

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

At this point, OpenFlow is enabled and running on the switch. If the
FAUCET controller is running and has connected to the switch
successfully, you should see the FAUCET pipeline programmed on the
switch.

NOTE: following is an example only, and may look different depending
on FAUCET version and which FAUCET features have been enabled.

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

Faucet
^^^^^^

On the FAUCET configuration file (``/etc/faucet/faucet.yaml``), add
the datapath of the switch you wish to be managed by FAUCET. The
device type (hardware) MUST be set to ``Aruba`` in the configuration
file.

.. code-block:: yaml
  :caption: /etc/faucet/faucet.yaml

	dps:
	    aruba-3810:
		dp_id: <DP ID from *show openflow instance aggregate | include Datapath ID*>
		hardware: "Aruba"
		interfaces:
		    1:
			native_vlan: 100
		    2:
			native_vlan: 100


Debug
-----

If you encounter a failure or unexpected behavior, it may help to
enable debug output on Aruba switches. Debug output displays
information about what OpenFlow is doing on the switch at
message-level granularity.

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


PKI setup on switch (OPTIONAL)
------------------------------

Only complete this section if you wish to secure the OpenFlow connection between switch and FAUCET with certificates.

.. note::

	The root certificate container supports only one root
	certificate not a chain.  So, install the one that the CSR
	(Certificate Signing Request) is signed with.



.. code-block:: none

		// Configure DNS.  Here DNS is set to a local LAN DNS server
		switch (config)# ip dns server-address priority 1 10.0.0.1

		switch# show crypto pki application

			Certificate Extension Validation :

			Application      SAN/CN
			---------------- ------------
			openflow         Disabled
			syslog           Disabled

		// Here, we create CA profile
		switch (config)# crypto pki ta-profile EXAMPLE_CA

		// Copy the root certificate for the EXAMPLE_CA from a tftp server
		switch#  copy tftp ta-certificate EXAMPLE_CA 10.0.0.1 myswitch.cert.pem

		switch# show crypto pki ta-profile EXAMPLE_CA
			Profile Name    Profile Status                 CRL Configured  OCSP Configured
			--------------- ------------------------------ --------------- ---------------
			EXAMPLE_CA 1 certificate installed         No              No

			Trust Anchor:
			Version: 3 (0x2)
			Serial Number: 4096 (0x1000)
			Signature Algorithm: sha256withRSAEncryption
			...
			......

			// Now we are ready to create a CSR so that a switch identity certificate that is accepted by the controller can be set up.

		switch (config)# crypto pki identity-profile hpe_sf_switch1 subject common-name myswitch org MyOrgName org-unit MyOrgUnit locality MyCity state CA country US

		switch (config)# show crypto pki identity-profile
			Switch Identity:
			  ID Profile Name    : hpe_sf_switch1
			  Common Name (CN) : myswitch
			Org Unit (OU)    : MyOrgUnit
			Org Name (O)     : MyOrgName
			Locality (L)     : MyCity
			State (ST)       : CA
			Country (C)      : US

		// Generate CSR
		switch (config)# crypto pki create-csr certificate-name hpeswt_switch1_crt ta-profile EXAMPLE_CA usage openflow

		// Copy the printed CSR request and send it to "EXAMPLE_CA"

		switch (config)# show crypto pki local-certificate summary
			Name                 Usage         Expiration     Parent / Profile
			-------------------- ------------- -------------- --------------------
			hpeswt_switch1_crt   Openflow      CSR            EXAMPLE_CA

		// Once the signed certificate is received, copy the same to switch.
		switch (config)# copy tftp local-certificate 10.0.0.1  myswitch.cert.pem
			000M Transfer is successful

		switch (config)# show crypto pki local-certificate summary
			Name                 Usage         Expiration     Parent / Profile
			-------------------- ------------- -------------- --------------------
			hpeswt_switch1_crt   Openflow      2019/01/02     EXAMPLE_CA


References
----------

- `Aruba OpenFlow Administrator Guide (16.03) <http://h20565.www2.hpe.com/hpsc/doc/public/display?sp4ts.oid=1008605435&docLocale=en_US&docId=emr_na-c05365339>`_
- `Aruba OS version as of Dec 2017 is 16.05 <https://h10145.www1.hpe.com/downloads/DownloadSoftware.aspx?SoftwareReleaseUId=23120&ProductNumber=JL261A&lang=&cc=&prodSeriesId=&SaidNumber=/>`_
- `Aruba Switches <http://www.arubanetworks.com/products/networking/switches/>`_
- `FAUCET <https://github.com/faucetsdn/faucet>`_
- `Model 2390F Product Site <https://www.hpe.com/us/en/product-catalog/networking/networking-switches/pip.aruba-2930f-switch-series.1008995294.html/>`_
-  `2930F top level documentation <https://support.hpe.com/hpesc/public/home/productSelector?sp4ts.oid=1008995294/>`_
- `Password settings  <https://community.arubanetworks.com/t5/Campus-Switching-and-Routing/Aruba-2930F-Web-GUI/td-p/308371/>`_
- `PKI Setup <http://h22208.www2.hpe.com/eginfolib/networking/docs/switches/WB/15-18/5998-8152_wb_2920_asg/content/ch17.html>`_
