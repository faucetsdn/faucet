Faucet
======

.. image:: https://github.com/faucetsdn/faucet/workflows/Unit%20tests/badge.svg?branch=master
    :target: https://github.com/faucetsdn/faucet/actions?query=workflow%3A%22Unit+tests%22

.. image:: https://github.com/faucetsdn/faucet/workflows/Integration%20tests/badge.svg?branch=master
    :target: https://github.com/faucetsdn/faucet/actions?query=workflow%3A%22Integration+tests%22

.. image:: https://codecov.io/gh/faucetsdn/faucet/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/faucetsdn/faucet


FAUCET is an OpenFlow controller for multi table OpenFlow 1.3 switches, that implements layer 2 switching, VLANs, ACLs, and layer 3 IPv4 and IPv6 routing, static and via BGP. It is based on Waikato University's `Valve <https://github.com/wandsdn/valve>`_ and the `Ryu OpenFlow Controller <http://osrg.github.io/ryu/>`_. FAUCET's design and background is described in `ACM Queue <https://queue.acm.org/detail.cfm?id=3015763>`_.

It supports:

- OpenFlow v1.3 (multi table) switches (including optional table features), hardware and software
- Multiple datapaths and distributed switching under a single controller
- VLANs, mixed tagged/untagged ports
- ACLs matching layer 2 and layer 3 fields
- IPv4 and IPv6 routing, static and via BGP
- Policy based forwarding to offload to external NFV applications (Eg 802.1x via hostapd, DHCP to isc DHCPD)
- Port and flow statistics via InfluxDB/Grafana
- Controller health and statistics via Prometheus
- Unit and systems tests run under Travis based on mininet and OVS

Hardware and software switch support
------------------------------------

Detailed guides for some switches are available on `readthedocs <http://docs.faucet.nz/en/latest/vendors/index.html>`_.

Faucet's design principle is to be as hardware agnostic as possible and not require Table Type Patterns. This means that Faucet expects the hardware Open Flow Agent (OFA) to hide implementation details, including which tables are best for certain matches or whether there is special support for multicast - Faucet expects the OFA to leverage the right hardware transparently.

If you are a hardware vendor wanting to support FAUCET, you need to support all the matches in `faucet/faucet_pipeline.py <faucet/faucet_pipeline.py>`_ and pass all tests.

Installation
------------

Please see the `installation guide <http://docs.faucet.nz/en/latest/installation.html>`_.

Configuration
-------------

Please see the `configuration guide <http://docs.faucet.nz/en/latest/configuration.html>`_
for documentation regarding the general configuration of faucet and the
`recipe book <http://docs.faucet.nz/en/latest/recipe_book/index.html>`_
for configuration snippets for common use cases.

Development and testing
-----------------------

Please see the `developer guide <http://docs.faucet.nz/en/latest/developer_guide.html>`_.

Getting Help
------------

We use maintain a number of mailing lists for communicating with users and
developers:

 * `faucet-announce <https://list.waikato.ac.nz/mailman/listinfo/faucet-announce>`_
 * `faucet-dev <https://list.waikato.ac.nz/mailman/listinfo/faucet-dev>`_
 * `faucet-users <https://lists.geant.org/sympa/info/faucet-users>`_

We also have the #faucet IRC channel on
`libera <https://web.libera.chat/?channels=#faucet>`_.

A few tutorial videos are available on our
`YouTube channel <https://www.youtube.com/channel/UChRZ5O2diT7QREazfQX0stQ>`_.

The
`faucet dev blog <https://www.vandervecken.com/faucet>`_
and
`faucetsdn twitter <https://twitter.com/faucetsdn>`_
are good places to keep up with the latest news about faucet.

If you find bugs, or if have feature requests, please create an issue on our
`bug tracker <https://github.com/faucetsdn/faucet/issues>`_.
