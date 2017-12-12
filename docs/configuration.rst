Configuration
=============

Faucet is configured with a YAML-based configuration file, ``faucet.yaml``.
The following is example demonstrating a few common features:

.. literalinclude:: ../etc/ryu/faucet/faucet.yaml
  :language: yaml
  :caption: faucet.yaml
  :name: faucet.yaml

The datapath ID may be specified as an integer or hex string (beginning with 0x).

A port not explicitly defined in the YAML configuration file will be left down and will drop all packets.

Gauge is configured similarly with, ``gauge.yaml``.
The following is example demonstrating a few common features:

.. literalinclude:: ../etc/ryu/faucet/gauge.yaml
  :language: yaml
  :caption: gauge.yaml
  :name: gauge.yaml

Verifying configuration
-----------------------

You can verify that your configuration is correct with the ``check_faucet_config`` script:

.. code:: console

  check_faucet_config /etc/ryu/faucet/faucet.yaml

Configuration examples
----------------------

For complete working examples of configuration features, see the unit tests, ``tests/faucet_mininet_test.py``.
For example, ``FaucetUntaggedACLTest`` shows how to configure an ACL to block a TCP port,
``FaucetTaggedIPv4RouteTest`` shows how to configure static IPv4 routing.

Applying configuration updates
------------------------------

You can update FAUCET's configuration by sending it a HUP signal.
This will cause it to apply the minimum number of flow changes to the switch(es), to implement the change.

.. code:: console

  pkill -HUP -f faucet.faucet

Configuration in separate files
-------------------------------

Extra DP, VLAN or ACL data can also be separated into different files and included into the main configuration file, as shown below. The ``include`` field is used for configuration files which are required to be loaded, and Faucet will log an error if there was a problem while loading a file. Files listed on ``include-optional`` will simply be skipped and a warning will be logged instead.

Files are parsed in order, and both absolute and relative (to the configuration file) paths are allowed. DPs, VLANs or ACLs defined in subsequent files overwrite previously defined ones with the same name.

``faucet.yaml``

.. code:: yaml

  include:
      - /etc/ryu/faucet/dps.yaml
      - /etc/ryu/faucet/vlans.yaml

  include-optional:
      - acls.yaml

``dps.yaml``

.. code:: yaml

  # Recursive include is allowed, if needed.
  # Again, relative paths are relative to this configuration file.
  include-optional:
      - override.yaml

  dps:
      test-switch-1:
          ...
      test-switch-2:
          ...

Configuration options
---------------------

Top Level
~~~~~~~~~
.. list-table:: Faucet.yaml
    :widths: 31 15 15 60
    :header-rows: 1


    * - Attribute
      - Type
      - Default
      - Description
    * - acls
      - dictionary
      - {}
      - Configuration specific to acls. The keys are names of each acl, and the
        values are config dictionaries holding the acl's configuration (see
        below).
    * - dps
      - dictionary
      - {}
      - Configuration specific to datapaths. The keys are names or dp_ids
        of each datapath, and the values are config dictionaries holding the
        datapath's configuration (see below).
    * - routers
      - dictionary
      - {}
      - Configuration specific to routers. The keys are names of each router,
        and the values are config dictionaries holding the router's
        configuration (see below).
    * - version
      - integer
      - 2
      - The config version. 2 is the only supported version.
    * - vlans
      - dictionary
      - {}
      - Configuration specific to vlans. The keys are names or vids of each
        vlan, and the values are config dictionaries holding the
        vlan's configuration (see below).

DP
~~
DP configuration is entered in the 'dps' configuration block. The 'dps'
configuration contains a dictionary of configuration blocks each
containing the configuration for one datapath. The keys can either be
string names given to the datapath, or the OFP datapath id.

.. list-table:: dps/<dp name or id>/
    :widths: 31 15 15 60
    :header-rows: 1

    * - Attribute
      - Type
      - Default
      - Description
    * - arp_neighbor_timeout
      - type
      - 500
      - ARP and neighbour timeout in seconds
    * - description
      - string
      - None
      - Description of this datapath, strictly informational
    * - dp_id
      - integer
      - The configuration key
      - the OFP datapath-id of this datapath
    * - drop_bpdu
      - boolean
      - True
      - If True, Faucet will drop all STP BPDUs arriving at the datapath. NB:
        Faucet does not handle BPDUs itself, if you disable this then you
        either need to configure an ACL to catch BDPUs or Faucet will forward
        them as though they were normal traffic.
    * - drop_broadcast_source_address
      - boolean
      - True
      - If True, Faucet will drop any packet from a broadcast source address
    * - drop_lldp
      - boolean
      - True
      - If True, Faucet will drop all STP BPDUs arriving at the datapath. NB:
        Faucet does not handle BPDUs itself, if you disable this then you
        either need to configure an ACL to catch BDPUs or Faucet will forward
        them as though they were normal traffic.
    * - drop_spoofed_faucet_mac
      - bool
      - True
      - If True, Faucet will drop any packet it receives with an ethernet
        source address equal to a MAC address that Faucet is using.
    * - group_table
      - bool
      - False
      - If True, Faucet will use the OpenFlow Group tables to flood packets.
        This is an experimental feature that is not fully supported by all
        devices and may not interoperate with all features of faucet.
    * - hardware
      - string
      - "Open vSwitch"
      - The hardware model of the datapath. Defaults to "Open vSwitch". Other
        options can be seen in the documentation for valve.py
    * - ignore_learn_ins
      - integer
      - 3
      - Ignore every approx nth packet for learning. 2 will ignore 1 out of 2
        packets; 3 will ignore 1 out of 3 packets. This limits control plane
        activity when learning new hosts rapidly. Flooding will still be done
        by the dataplane even with a packet is ignored for learning purposes.
    * - interfaces
      - dictionary
      - {}
      - configuration block for interface specific config (see below)
    * - interface_ranges
      - dictionary
      - {}
      - contains the config blocks for sets of multiple interfaces. The
        configuration entered here will be used as the defaults for these
        interfaces. This can be overwritten by configuring those interfaces
        directly. The format for the configuration key is a comma separated
        string.  The elements can either be the name or number of an interface
        or a range of port numbers eg: "1-6,8,port9".
    * - learn_ban_timeout
      - integer
      - 10
      - When a host is rapidly moving between ports Faucet will stop learning
        mac addresses on one of the ports for this number of seconds.
    * - learn_jitter
      - integer
      - 10
      - In order to reduce load on the controller Faucet will randomly vary the
        timeout for learnt mac addresses by up to this number of seconds.
    * - max_host_fib_retry_count
      - integer
      - 10
      - Limit the number of times Faucet will attempt to resolve a next-hop's
        l2 address.
    * - max_hosts_per_resolve_cycle
      - integer
      - 5
      - Limit the number of hosts resolved per cycle.
    * - max_resolve_backoff_time
      - integer
      - 32
      - When resolving next hop l2 addresses, Faucet will back off
        exponentially until it reaches this value.
    * - name
      - string
      - The configuration key
      - A name to reference the datapath by.
    * - stack
      - dictionary
      - {}
      - configuration block for stacking config, for loop protection (see
        below)
    * - timeout
      - integer
      - 300
      - timeout for MAC address learning

Stacking (DP)
~~~~~~~~~~~~~
Stacking is configured in the dp configuration block and in the interface
configuration block. At the dp level the following attributes can be configured
withing the configuration block 'stack':

.. list-table:: dps/<dp name or id>/stack/
    :widths: 31 15 15 60
    :header-rows: 1

    * - Attribute
      - Type
      - Default
      - Description
    * - priority
      - integer
      - 0
      - setting any value for stack priority indicates that this datapath
        should be the root for the stacking topology.


Interfaces
~~~~~~~~~~
Configuration for each interface is entered in the 'interfaces' configuration
block withing the config for the datapath. Each interface configuration block
is a dictionary keyed by the interface name.

Defaults for groups of interfaces can also be configured under the
'interface-ranges' attribute within the datapath configuration block. These
provide default values for a number of interfaces which can be overwritten with
the config block for an individual interface. These are keyed with a string
containing a comma separated list of OFP port numbers, interface names or with
OFP port number ranges (eg. 1-6).

.. list-table:: dps/<dp name or id>/interfaces/<interface name or OFP port number>/
    :widths: 31 15 15 60
    :header-rows: 1

    * - Attribute
      - Type
      - Default
      - Description
    * - acl_in
      - integer or string
      - None
      - The acl that should be applied to all packets arriving on this port.
        referenced by name or list index
    * - description
      - string
      - None
      - Description, purely informational
    * - enabled
      - boolean
      - True
      - Allow packets to be forwarded through this port.
    * - hairpin
      - boolean
      - True
      - If True it allows packets arriving on this port to be output to this
        port. This is necessary to allow routing between two vlans on this
        port, or for use with a WIFI radio port.
    * - max_hosts
      - integer
      - 255
      - the maximum number of mac addresses that can be learnt on this port.
    * - mirror
      - integer or string
      - None
      - Mirror all packets recieved and transmitted on this port to the port
        specified (by name or by port number)
    * - name
      - string
      - The configuration key.
      - a name to reference this port by.
    * - native_vlan
      - integer
      - None
      - The vlan associated with untagged packets arriving and leaving this
        interface.
    * - number
      - integer
      - The configuration key.
      - The OFP port number for this port.
    * - permanent_learn
      - boolean
      - False
      - When True Faucet will only learn the first MAC address on this
        interface. All packets with an ethernet src address not equal to that
        MAC address will be dropped.
    * - stack
      - dictionary
      - None
      - configuration block for interface level stacking configuration
    * - tagged_vlans
      - list of integers or strings
      - None
      - The vlans associated with tagged packets arriving and leaving this
        interfaces.
    * - unicast_flood
      - boolean
      - True
      - If False unicast packets will not be flooded to this port.

Stacking (Interfaces)
~~~~~~~~~~~~~~~~~~~~~
Stacking port configuration indicates how datapaths are connected when using
stacking. The configuration is found under the 'stack' attribute of an
interface configuration block. The following attributes can be configured:

.. list-table:: dps/<dp name or id>/interfaces/<interface name or port number/stack/
    :widths: 31 15 15 60
    :header-rows: 1

    * - Attribute
      - Type
      - Default
      - Description
    * - dp
      - integer or string
      - None
      - the name of dp_id of the dp connected to this port
    * - port
      - integer or string
      - None
      - the name or OFP port number of the interface on the remote dp connected
        to this interface.

Router
~~~~~~
Routers config is used to allow routing between vlans. Routers configuration
is entered in the 'routers' configuration block at the top level of the faucet
configuration file. Configuration for each router is an entry in the routers
dictionary and is keyed by a name for the router. The following attributes can
be configured:

.. list-table:: routers/<router name>/:
    :widths: 31 15 15 60
    :header-rows: 1

    * - Attribute
      - Type
      - Default
      - Description
    * - vlans
      - list of integers or strings
      - None
      - Enables inter-vlan routing on the given vlans


VLAN
~~~~

VLANs are configured in the 'vlans' configuration block at the top level of
the faucet config file. The config for each vlan is an entry keyed by its vid
or a name. The following attributes can be configured:

.. list-table:: vlans/<vlan name or vid>/:
    :widths: 31 15 15 60
    :header-rows: 1

    * - Attribute
      - Type
      - Default
      - Description
    * - acl_in
      - string or integer
      - None
      - The acl to be applied to all packets arriving on this vlan.
    * - bgp_as
      - integer
      - 0
      - The local AS number to used when speaking BGP
    * - bgp_local_address
      - string (IP Address)
      - None
      - The local address to use when speaking BGP
    * - bgp_neighbour_addresses
      - list of strings (IP Addresses)
      - None
      - The list of BGP neighbours
    * - bgp_neighbour_as
      - integer
      - 0
      - The AS Number for the BGP neighbours
    * - bgp_port
      - integer
      - 9179
      - Port to use for bgp sessions
    * - description
      - string
      - None
      - Strictly informational
    * - faucet_vips
      - list of strings (IP address prefixes)
      - None
      - The IP Address for Faucet's routing interface on this vlan
    * - max_hosts
      - integer
      - 255
      - The maximum number of hosts that can be learnt on this vlan.
    * - name
      - string
      - the configuration key
      - A name that can be used to refer to this vlan.
    * - proactive_arp_limit
      - integer
      - None
      - Do not proactively ARP for hosts once this value has been reached
        (unlimited by default)
    * - proactive_nd_limit
      - integer
      - None
      - Don't proactively discover IPv6 hosts once this value has been reached
        (unlimited by default)
    * - routes
      - list of routes
      - None
      - static routes configured on this vlan (see below)
    * - unicast_flood
      - boolean
      - True
      - If False packets to unknown ethernet destination MAC addresses will be
        dropped rather than flooded.
    * - vid
      - integer
      - the configuration key
      - The vid for the vlan.

Static Routes
~~~~~~~~~~~~~

Static routes are given as a list. Each entry in the list contains a dictionary
keyed with the keyword 'route' and contains a dictionary configuration block as
follows:

.. list-table:: vlans/<vlan name or vid>/routes/[list]/route/:
    :widths: 31 15 15 60
    :header-rows: 1

    * - Attribute
      - Type
      - Default
      - Description
    * - ip_dst
      - string (IP subnet)
      - None
      - The destination subnet.
    * - ip_gw
      - string (IP address)
      - None
      - The next hop for this route

ACLs
~~~~

ACLs are configured under the 'acls' configuration block. The acls block
contains a dictionary of individual acls each keyed by its name.

Each acl contains a list of rules, a packet will have the first matching rule
applied to it.

Each rule is a dictionary containing the single key 'rule' with the value the
matches and actions for the rule.

The matches are key/values based on the ryu RESTFul API.

.. list-table:: /acls/<acl name>/[list]/rule/actions
    :widths: 31 15 15 60
    :header-rows: 1

    * - Attribute
      - Type
      - Default
      - Description
    * - allow
      - boolean
      - False
      - If True allow the packet to continue through the Faucet pipeline, if
        False drop the packet.
    * - meter
      - string
      - None
      - meter to apply to the packet
    * - output
      - dict
      - None
      - used to output a packet directly. Details below.

The output action contains a dictionary with the following elements:

.. list-table:: /acls/<acl name>/[list]/rule/actions/output/
    :widths: 31 15 15 60
    :header-rows: 1

    * - Attribute
      - Type
      - Default
      - Description
    * - port
      - integer or string
      - None
      - The port to output the packet to.
    * - swap_vid
      - integer
      - None
      - Rewrite the vlan vid of the packet when outputting
    * - failover
      - dict
      - None
      - Output with a failover port (see below).

Failover is an experimental option, but can be configured as follows:

.. list-table:: /acls/<acl name>/[list]/rule/actions/output/failover/
    :widths: 31 15 15 60
    :header-rows: 1

    * - Attribute
      - Type
      - Default
      - Description
    * - group_id
      - integer
      - None
      - The OFP group id to use for the failover group
    * - ports
      - list
      - None
      - The list of ports the packet can be output through.

