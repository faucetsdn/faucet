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
 - Replace the following placeholders with the couchdb credentials on the host machine:

  + ``<username> and <password>`` with the username/password set on couchdb.
  + ``<couchdb_ip>`` with the IP address where the db is located.
  + ``<couchdb_port>`` with the port number.

* Push the couchapp to db again replacing the <username> <password> placeholders as above.

  .. code:: bash

    couchapp push . http://<username>:<password>@localhost:5984/flowinfodb/
* Site can now be accessed at ``<http://<couchdb_ip>:<couchdb_port>/flowinfodb/_design/flow-info/index.html>``
