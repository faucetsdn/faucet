====================
FAUCET Configuration
====================

Faucet is configured with a YAML-based configuration file, typically ``faucet.yaml`` Following is example.

.. code:: yaml

  dps:
      switch-1:
          dp_id: 0x1
          interfaces:
              1:
                  native_vlan: 2040
                  acl_in: 1
              2:
                  native_vlan: 2040
  vlans:
      2040:
          name: "dev VLAN"
  acls:
      1:
          - rule:
              nw_dst: "172.0.0.0/8"
              dl_type: 0x800
              actions:
                  allow: 1

          - rule:
              dl_type: 0x0806
              actions:
                  allow: 1

          - rule:
              nw_dst: "10.0.0.0/16"
              dl_type: 0x800
              actions:
                  allow: 0

The datapath ID may be specified as an integer or hex string (beginning with 0x).

A port not explicitly defined in the YAML configuration file will be left down and will drop all packets.

=======================
Verifying configuration
=======================

You can verify that your configuration is correct with the `../faucet/check_faucet_config.py <../faucet/check_faucet_config.py>`_ script:

.. code:: bash

  check_faucet_config.py /etc/ryu/faucet.yaml

======================
Configuration examples
======================

For complete working examples of configuration features, see the unit tests, `../tests/faucet_mininet_test.py <../tests/faucet_mininet_test.py>`_. For example, `FaucetUntaggedACLTest` shows how to configure an ACL to block a TCP port, `FaucetTaggedIPv4RouteTest` shows
how to configure static IPv4 routing.

==============================
Applying configuration updates
==============================

You can update FAUCET's configuration by sending it a HUP signal. This will cause it to apply the minimum number of flow changes to the switch(es), to implement the change.

.. code:: bash

  pkill -HUP -f faucet.faucet

===============================
Configuration in separate files
===============================

Extra DP, VLAN or ACL data can also be separated into different files and included into the main configuration file, as shown below. The ``include`` field is used for configuration files which are required to be loaded, and Faucet will log an error if there was a problem while loading a file. Files listed on ``include-optional`` will simply be skipped and a warning will be logged instead.

Files are parsed in order, and both absolute and relative (to the configuration file) paths are allowed. DPs, VLANs or ACLs defined in subsequent files overwrite previously defined ones with the same name.

``faucet.yaml``

.. code:: yaml

  include:
      - /etc/ryu/faucet/dps.yaml
      - /etc/ryu/faucet/vlans.yaml

  include-optional:
      - acls.yaml

``dps.yaml``:

.. code:: yaml

  ---
  # Recursive include is allowed, if needed.
  # Again, relative paths are relative to this configuration file.
  include-optional:
      - override.yaml

  dps:
      test-switch-1:
          ...
      test-switch-2:
          ...
