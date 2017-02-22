:version: 1.3.2
:copyright: 2016 `REANNZ <http://www.reannz.co.nz/>`_.  All Rights Reserved.

.. meta::
  :keywords: OpenFlow, Ryu, Faucet, VLAN, SDN

=====================
Faucet App: Flow Info
=====================

Flowinfo provides a view of flows on different switches across various tables.

=====================
Installation with pip
=====================

* You have to run this as ``root`` or use ``sudo``

  .. code:: bash

    pip install couchapp

===================
Configuration steps
===================
* Edit the ``.couchapprc`` file

 - Couchapp uses a db to save the website static files and hosts them from this location.
 - ``.couchapprc`` file is used to name that db apart from other config options.

* Push the couchapp to db.

  .. code:: bash

    couchapp push . http://couch:123@127.0.0.1:5984/flowinfodb/
* Site can now be accessed at `<http://127.0.0.1:5984/flowinfodb/_design/flow-info/index.html>`_
