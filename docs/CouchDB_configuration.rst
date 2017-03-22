:copyright: 2016 `Open Networking Foundation <http://opennetworking.org/>`_.  All Rights Reserved.
:author: shivaram.mysore@gmail.com

.. meta::
   :keywords: Openflow, Ryu, Faucet, CouchDB, Database, Gauge, Grafana

=====================
CouchDB Configuration
=====================

============================
Platform: MacOS X El Capitan
============================

.. code:: bash

  # sudo port install couchdb
  # sudo port load couchdb

On a Web Browser, go to: http://127.0.0.1:5984/_utils/config.html

This should tell you everything is working correctly.

We need to find the location of ``local.ini`` configuration file and modify it.

.. code:: bash

  # couchdb -c
  # sudo vi /opt/local/etc/couchdb/local.ini

In the above ``local.ini`` file, the following modifications are made:
    1. add line --> ``bind_address=0.0.0.0``
    2. Uncomment next line to trigger basic-auth popup on unauthorized requests.
       ``WWW-Authenticate = Basic realm="administrator"``
    3. add line --> ``require_valid_user = true``

Alternatively, you can:

.. code:: bash

  # curl -X PUT http://localhost:5984/_config/httpd/bind_address -d '"0.0.0.0"'

By doing this, you will be able to access couch db from an external box

.. code:: bash

    # curl http://10.0.0.141:5984/
    {"couchdb":"Welcome","uuid":"b08ca21a473a68cf133e95d4ce926044","version":"1.6.1","vendor":{"name":"The Apache Software Foundation","version":"1.6.1"}}

    # curl -X GET http://10.0.0.141:5984/_all_dbs
    ["_replicator","_users"]

I created a user ``"couch"`` with password ``"123"`` with *Admin* role & then restarted CouchDB

Test User Auth - Basic Auth
---------------------------
.. code:: bash

    # curl -X PUT http://10.0.0.141:5984/somedatabase
    {"error":"unauthorized","reason":"You are not a server admin."}


Cookie Authentication
---------------------
.. code:: bash

    # curl -vX POST http://10.0.0.141:5984/_session -H 'Content-Type:application/x-www-form-urlencoded' -d 'name=couch&password=123'

Performance Tuning
==================
Additional changes to ``default.ini`` - TBD

============================
Platform: DEBIAN OS
============================


Commands for installation
-------------------------

.. code:: bash

    # pip install couchdb (installs couchdb python module)


On a Web Browser, go to: http://127.0.0.1:5984/_utils/config.html
It should display all configuration parameters.

To enable compaction for couchdb we have to enable settings in local.ini in [compactions] section by uncommenting this:

.. code:: bash 

    _default = [{db_fragmentation, "70%"}, {view_fragmentation, "60%"}]
  
After enabling the fragmentation make sure Couchdb has been restarted. Also DB fragmentation value can be configured based on your need.

.. code:: bash

    # service couchdb restart
