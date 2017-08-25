:version: 1.5.8

.. meta::
   :keywords: OpenFlow, Ryu, Faucet, VLAN, SDN

======
Faucet
======

FAUCET is an OpenFlow controller for multi table OpenFlow 1.3 switches, that implements layer 2 switching, VLANs, ACLs, and layer 3 IPv4 and IPv6 routing, static and via BGP. It is based on Waikato University's `Valve <https://github.com/wandsdn/valve>`_ and the `Ryu OpenFlow Controller <http://osrg.github.io/ryu/>`_. FAUCET's design and background is described in `ACM Queue <https://queue.acm.org/detail.cfm?id=3015763>`_.

It supports:

- OpenFlow v1.3 (multi table) switches (including optional table features), hardware and software
- Multiple datapaths and distributed switching under a single controller
- VLANs, mixed tagged/untagged ports
- ACLs matching layer 2 and layer 3 fields
- IPv4 and IPv6 routing, static and via BGP
- Policy based forwarding to offload to external NFV applications (Eg 802.1x via hostapd, DHCP to isc DHCPD)
- Port and flow statistics via InfluxDB/Grafana and CouchDB/CouchApp
- Controller health and statistics via Prometheus
- Unit and systems tests run under Travis based on mininet and OVS


====================================
Hardware and software switch support
====================================

Detailed guides for some switches are available in `docs/vendors <docs/vendors>`_.

FAUCET has been tested against the following switches (see also SUPPORTED_HARDWARE in `faucet/valve.py <faucet/valve.py>`_):

- `Open vSwitch v2.1+ <http://www.openvswitch.org>`_
- `Lagopus Openflow Switch <https://lagopus.github.io>`_
- Allied Telesis `x510 <https://www.alliedtelesis.com/products/x510-series>`_ and `x930 <https://www.alliedtelesis.com/products/x930-series>`_ series
- `NoviFlow 1248 <http://noviflow.com/products/noviswitch>`_
- Northbound Networks - `Zodiac FX <http://northboundnetworks.com/collections/zodiac-fx>`_
- Hewlett Packard Enterprise - `Aruba 5400R, 3810 and 2930F <http://www.arubanetworks.com/products/networking/switches/>`_
- Netronome produces PCIe adaptors, via OVS - `Agilio CX 2x10GbE card <https://www.netronome.com/products/agilio-cx/>`_

Faucet's design principle is to be as hardware agnostic as possible and not require Table Type Patterns. This means that Faucet expects the hardware Open Flow Agent (OFA) to hide implementation details, including which tables are best for certain matches or whether there is special support for multicast - Faucet expects the OFA to leverage the right hardware transparently.

If you are a hardware vendor wanting to support FAUCET, you need to support all the matches in `faucet/valve.py <faucet/valve.py>`_ valve_in_match() and pass all tests.


============
Installation
============

Please see `docs/README_install.rst <docs/README_install.rst>`_


=============
Configuration
=============

Please see `docs/README_config.rst <docs/README_config.rst>`_


=======================
Development and testing
=======================

Please see `docs/README.developerguide.rst <docs/README.developerguide.rst>`_


=======
Support
=======

We run a number of mailing lists for communication between users and developers of Faucet, as well as a low traffic mailing list for announcements of new versions:

- https://list.waikato.ac.nz/mailman/listinfo/faucet-announce
- https://list.waikato.ac.nz/mailman/listinfo/faucet-dev
- https://lists.geant.org/sympa/info/faucet-users

Additional documentation is available under the `docs <docs>`_ directory.

Faucet blog by Josh Bailey available at http://faucet-sdn.blogspot.co.nz.

To create a issue, use `GitHub Issues <https://github.com/REANNZ/faucet/issues>`_.


==================================
Faucet deployment around the world
==================================
   https://www.google.com/maps/d/u/0/viewer?mid=1MZ0M9ZtZOp2yHWS0S-BQH0d3e4s&hl=en

.. raw:: html

  <div class="figure">
  <iframe src="https://www.google.com/maps/d/u/0/embed?mid=1MZ0M9ZtZOp2yHWS0S-BQH0d3e4s" width="640" height="480"></iframe>
  </div>


.. Comment- TBD Code not working - embed:: https://www.google.com/maps/d/u/0/viewer?mid=1MZ0M9ZtZOp2yHWS0S-BQH0d3e4s&hl=en
