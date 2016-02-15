:version: 0.29
:copyright: 2015 `REANNZ <http://www.reannz.co.nz/>`_.  All Rights Reserved.

.. meta::
   :keywords: Openflow, Ryu, Faucet, VLAN, SDN

======
Faucet
======

Faucet is an Openflow controller for a layer 2 switch based on OpenvApour's Valve. It handles MAC learning and supports VLANs.  It is developed as an application for the `Ryu Open Flow Controller <http://osrg.github.io/ryu/>`_
.

It supports:

- OpenFlow v1.3
- Multiple datapaths
- Mixed tagged/untagged ports
- Port statistics
- Coexisting with other OpenFlow controllers

=============
Configuration
=============

Faucet is configured with a YAML-based configuration file. A sample configuration file is supplied in ``faucet.yaml``.

The datapath ID may be specified as an integer or hex string (beginning with 0x).

A port not explicitly defined in the YAML configuration file will be set down and will drop all packets.

============
Installation
============
You have run this as ``root`` or use ``sudo``

``# pip install https://pypi.python.org/packages/source/r/ryu-faucet/ryu-faucet-0.29.tar.gz``

``# pip show ryu-faucet``

Uninstall
---------
To Uninstall the package

``# pip uninstall ryu-faucet``

==========
Deployment
==========
.. image:: src/docs/faucet_deployment.png

=======
Running
=======

Note: On your system, depending on how Python is installed, you may have to install some additional packages to run faucet.

Run with ``ryu-manager`` (uses ``/etc/ryu/faucet/faucet.yaml`` as configuration by default):


    ``# export FAUCET_CONFIG=/etc/ryu/faucet/faucet.yaml``
    
    ``# export GAUGE_CONFIG=/etc/ryu/faucet/gauge.conf``
    
    ``# export FAUCET_LOG_DIR=/var/log/ryu``
    
    ``# $EDITOR /etc/ryu/faucet/faucet.yaml``
    
    ``# ryu-manager --verbose faucet.py``


To find the location of ``faucet.py``, run 

``# pip show ryu-faucet`` to get Location path.  Then run:

``# ryu-manager --verbose <Location_Path>/ryu_faucet/org/onfsdn/faucet/faucet.py``

  Alternatively, if OF Controller is using a non-default port of 6633, for example 6653, then:

``# ryu-manager --verbose  --ofp-tcp-listen-port 6653 <Location_Path>/ryu_faucet/org/onfsdn/faucet/faucet.py``

On MacOS X, for example, one would run this as:

``#  ryu-manager --verbose /opt/local/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/site-packages/ryu_faucet/org/onfsdn/faucet/faucet.py``

To specify a different configuration file set the ``FAUCET_CONFIG`` environment variable.

Faucet will log to ``/var/log/ryu/faucet/`` by default, this can be changed with the ``FAUCET_LOG_DIR`` environment variable.

To tell Faucet to reload its configuration file after you've changed it, simply send it a ``SIGHUP``:

``# pkill -SIGHUP -f "ryu-manager faucet.py"``

=======
Testing
=======

Before issuing a Pull-Request
-----------------------------
Run the tests to make sure everything works!
Mininet test actually spins up virtual hosts and a switch, and a test FAUCET controller, and checks connectivity between all the hosts given a test config.  If you send a patch, this mininet test must pass.::

    # git clone https://github.com/onfsdn/faucet
    # cd faucet/tests
    (As namespace, etc needs to be setup, run the next command as root)
    # sudo ./faucet_mininet_test.py
    # ./test_config.py

Working with Real Hardware
--------------------------

If you are a hardware vendor wanting to support FAUCET, you need to support all the matches in src/ryu_faucet/org/onfsdn/faucet/valve.py:valve_in_match().

Faucet has been tested against the following switches:
(Hint: look at src/ryu_faucet/org/onfsdn/faucet/dp.py to add your switch)

    1. Open vSwitch v2.1+ - Open Source available at http://www.OpenVSwitch.Org
    2. Lagopus Openflow Switch - Open Source available at https://lagopus.github.io/
    3. Allied Telesis x510
    4. NoviFlow   
    5. Pica8

On the Allied Telesis all vlans must be included in the vlan database config on the switch before they can be used by Openflow.

================================================
Buying Commerical Switches supporting ryu-faucet
================================================

Allied Telesis
--------------

 `Allied Telesis <http://www.alliedtelesis.com/sdn` sells their products via distributors and resellers. To order in USA call `ProVantage <http://www.provantage.com/allied-telesis-splx10~7ALL912L.htm>`.  To find a sales office near you, visit `Allied Telesis <http://www.AlliedTelesis.com>`

Pica8
-----
 `Pica8 <http://www.pica8.com/products/pre-loaded-switches>` provides white box network switches which work with Ryu/Faucet controller.  To order Pica8 switches, please refer to `buy page <http://www.pica8.com/partners/where-to-buy>`

NoviFlow
--------
`NoviFlow <http://noviflow.com/>`

Running with another controller
-------------------------------

It is possible to use Faucet to add layer 2 features to another OpenFlow controller by running Faucet in parallel with that controller. Faucet will only ever modify/remove OpenFlow rules added by itself (identified by a special OpenFlow cookie unique to Faucet), this means the rules installed by the other controller/application will be left untouched.

Simply add Faucet as a second primary OpenFlow controller to your datapath element. You will also probably need to tweak the OpenFlow priority values Faucet uses by modifying `priority_offset` in the configuration file so that rules installed by the other controller don't override those installed by Faucet.

=====
Gauge
=====

Gauge is the monitoring application. It polls each port for statistics and periodically dumps the flow table for statistics.

Gauge reads the faucet yaml configuration files of the datapaths it monitors. Which datapaths to monitor is provided in a configuration file containing a list of faucet yaml files, one per line.

The list of faucet yaml config is by default read from ``/etc/ryu/faucet/gauge.conf``. This can be set with the ``GAUGE_CONFIG`` environment variable. Exceptions are logged to the same file as faucet's exceptions.

Gauge is run with ``ryu-manager``:

``$ $EDITOR /etc/ryu/faucet/gauge.conf``

``$ ryu-manager gauge.py``

=======
Support
=======

If you have any technical questions, problems or suggestions regarding Faucet please send them to `faucet-dev@OpenflowSDN.Org <mailto:faucet-dev@openflowsdn.org>`.  Mailing list archives are available `here <https://groups.google.com/a/openflowsdn.org/forum/#!forum/faucet-dev>`.

To create a issue, use `Github issues <https://github.com/onfsdn/faucet/issues>`

