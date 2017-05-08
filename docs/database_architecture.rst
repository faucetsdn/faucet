:copyright: 2015--2017 The Contributors

.. meta::
   :keywords: Openflow, Ryu, Faucet, VLAN, SDN, Couchdb, NoSQL

=======================================
Faucet Database Design and Architecture
=======================================

Faucet can use a database to store all the flows pushed to switches.

--------------
Prerequisites:
--------------
1. faucet controller
2. couchdb

-------
Details
-------
Faucet_db helps us in storing installed flows on database so that application can request and get flows data directly from database. 

State of currently installed flows can be requested by large number of applications written to a controller. If they would request directly it from the switch it would be overloaded and will lead to performance degradation. So we store information in a database corresponding to a datapath_id (UID) of the switch, then the database can provide the switch information at that point in time. Corresponding to the switch dpid, flows are also stored.

.. image:: /docs/images/db-architecture.png

We have created a generic database driver(nsodbc) to support document databases. We have tested and validated those APIs with couchDB.
Using those APIs we can do following operations on database.
* Connect
* Insert
* Update
* Delete
* Get

Real-time database updation is getting supported.
