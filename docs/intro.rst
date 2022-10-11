Introduction to Faucet
======================

What is Faucet?
---------------

Faucet is a compact open source OpenFlow controller, which enables network
operators to run their networks the same way they do server clusters.
Faucet moves network control functions (like routing protocols,
neighbor discovery, and switching algorithms) to vendor independent
server-based software, versus traditional router or switch embedded firmware,
where those functions are easy to manage, test, and extend with modern systems
management best practices and tools. Faucet controls OpenFlow 1.3 hardware
which delivers high forwarding performance.

You can read more about our approach to networking by reading our ACM Queue article
`Faucet: Deploying SDN in the Enterprise <https://queue.acm.org/detail.cfm?id=3015763>`_.

What is Gauge?
---------------

Faucet has two main OpenFlow controller components, Faucet itself, and Gauge.
Faucet controls all forwarding and switch state, and exposes its internal state,
e.g. learned hosts, via Prometheus (so that an open source NMS such as
Grafana graph it).

Gauge also has an OpenFlow connection to the switch and monitors port and flow
state (exporting it to Prometheus or InfluxDB, or even flat text log files).
Gauge, however, does not ever modify the switch's state, so that switch
monitoring functions can be upgraded, restarted, without impacting forwarding.

Why Faucet?
-----------

Design
^^^^^^

Faucet is designed to be very small, simple (1000s of lines of code, versus
millions in other systems), and keep relatively little state.
Faucet does not have any implementation-specific or vendor driver code,
which considerably reduces complexity. Faucet does not need connectivity to
external databases for forwarding decisions. Faucet provides "hot/hot" high
availability and scales through the provisioning of multiple Faucets with the
same configuration - Faucet controllers are not inter-dependent.

Performance and scaling
^^^^^^^^^^^^^^^^^^^^^^^
As well as being compact, Faucet offloads all forwarding to the OpenFlow switch,
including flooding if emulating a traditional switch. Faucet programs the switch
pre-emptively, though will receive packet headers from the switch if, for
example, a host moves ports so that the switch's OpenFlow FIB can be updated
(again, if traditional switching is being emulated). In production, Faucet
controllers have been observed to go many seconds without needing to process a
packet from a switch. In cold start scenarios, Faucet has been observed to
completely program a switch and learn connected hosts within a few seconds.

Faucet uses a multi-table packet processing pipeline as shown in
:ref:`faucet-pipeline`. Using multiple flow tables over a single table allows
Faucet to implement more complicated flow-based logic while maintaining a
smaller number of total flows. Using dedicated flow tables with a narrow number
of match fields, or limiting a table to exact match only, such as the
IPv4 or IPv6 FIB tables allows us to achieve greater scalability over the number
of flow entries we can install on a datapath.

A large network with many devices would run many Faucets, which can be spread
over as many (or as few) machines as required. This approach scales well because
each Faucet uses relatively few server resources and Faucet controllers do not
have to be centralized - they can deploy as discrete switching or routing
functional units, incrementally replacing (for example) non-SDN switches or
routers.

An operator might have a controller for an entire rack, or just a few switches,
which also reduces control plane complexity and latency by keeping control
functions simple and local.

Testing
^^^^^^^
Faucet follows open source software engineering best practices, including unit
and systems testing (python unittest based), as well static analysis
(pytype, pylint, and codecov) and fuzzing (python-afl). Faucet's systems tests
test all Faucet features, from switching algorithms to routing, on virtual
topologies. However, Faucet's systems tests can also be configured to run the
same feature tests on real OpenFlow hardware. Faucet developers also host
regular PlugFest events specifically to keep switch implementations broadly
synchronized in capabilities and compatibility.

Release Notes
-------------

.. toctree::
   :maxdepth: 2

   release_notes/1.7.0
   release_notes/1.9.0

Getting Help
------------

We use a mailing list on google groups for announcing new versions and
communicating with users and developers:

 * `faucetsdn <https://groups.google.com/g/faucetsdn>`_

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
