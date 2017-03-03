:version: 1.4.0
:copyright: 2016 `REANNZ <http://www.reannz.co.nz/>`_.  All Rights Reserved.

.. meta::
  :keywords: OpenFlow, Ryu, Faucet, VLAN, SDN

===================
Faucet Applications
===================

Faucet allows apps that can be written to CouchDB (flows) and InfluxDB (stats).  The information in these databases are near real-time data from actual switches collected by Gauge controller.  Flows are collected every 60 seconds and stats are collected every 10 seconds.
          .
List of Applications:

   1. `Flowinfo <flowinfo/>`_ - provides flows on different switches across various tables.



