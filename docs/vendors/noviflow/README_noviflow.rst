:Authors: - Josh Bailey, Davide Trentin

Faucet on NoviFlow
==================

Introduction
------------

NoviFlow provide a range of switches known to work with FAUCET.

These instructions have been tested on NS1248, NS1132, NS2116, NS2128, NS2122, NS2150, NS21100 switches,
using NoviWare versions starting from NW400.5.4, running with FAUCET v1.8.14.

Compared to older versions of NoviWare and Faucet, where manual pipeline configuration was required,
it is possible to use the ``GenericTFM`` Hardware type to make Faucet automatically program the tables
based on the needs of its current configuration.

Setup
-----

Configure the CPN on the switch
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The only configuration required in the switch is the definition of the IP and ports on which the Faucet
controller must be reached. Optionally it is also possible to change the switch DPID.
In this example, the server running FAUCET is 10.0.1.8; configuration for CPN interfaces is not shown.

.. code-block:: none

  set config controller controllergroup faucet controllerid 1 priority 1 ipaddr 10.0.1.8 port 6653 security none
  set config controller controllergroup gauge controllerid 1 priority 1 ipaddr 10.0.1.8 port 6654 security none
  set config switch dpid 0x1

Create faucet.yaml
^^^^^^^^^^^^^^^^^^

In order to exploit the automatic pipeline configuration, the hardware specified in
``faucet.yaml`` must be ``GenericTFM``

.. code-block:: yaml

    vlans:
        100:
            name: "test"
    dps:
        noviflow-1:
            dp_id: 0x1
            hardware: "GenericTFM"
            interfaces:
                1:
                    native_vlan: 100
                2:
                    native_vlan: 100
            etc...

Run FAUCET
^^^^^^^^^^

.. code:: console

    faucet --verbose

Using Older Faucet and NoviWare versions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Before the introduction of GenericTFM, Faucet used a static pipeline which needed to be
configured in the switch before connecting to the controller.
The following match configuration is known to pass the unit tests using NW400.4.3 with FAUCET 1.6.18,
but take care to adjust ACL tables matches based on the type of ACL rules defined in the configuration file.
Different FAUCET releases may also use different match fields in the other tables.

.. code-block:: none

   set config pipeline tablesizes 1524 1024 1024 5000 3000 1024 1024 5000 1024 tablewidths 80 40 40 40 40 40 40 40 40
   set config table tableid 0 matchfields 0 3 4 5 6 10 11 12 13 14 23 29 31
   set config table tableid 1 matchfields 0 3 4 5 6
   set config table tableid 2 matchfields 0 5 6 10 11 12 14
   set config table tableid 3 matchfields 0 3 4 5 6 10
   set config table tableid 4 matchfields 5 6 12
   set config table tableid 5 matchfields 5 6 27
   set config table tableid 6 matchfields 3 5 10 23 29
   set config table tableid 7 matchfields 3 6
   set config table tableid 8 matchfields 0 3 6

Note that this table configuration will allow most of the automated test cases to pass, except FaucetIPv6TupleTest
(which requires IPv6 Src and Dst matching in the ACL table). In order to run this test, table 0 must be
configured as follows:

.. code-block:: none

  set config table tableid 0 matchfields 0 5 6 10 26 27 13 14
