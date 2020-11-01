Faucet on OpenBSD
=================

Introduction
------------
OpenBSD has built in `OpenFlow 1.3 support <https://man.openbsd.org/switch.4>`_ since OpenBSD 6.1,
with switchofp providing the dataplane and switchd the controller. switchd communicates with
switchofp through a /dev interface. switchd can also relay messages between the /dev interface
and TCP, which makes Faucet support possible.

There are some limitations (see below) and support has not yet been integrated mainline OpenBSD as of 6.8.

Installation
------------

- On an existing OpenBSD installation running the current release (6.8), check out the faucet
  branch:

.. code-block::  console

        cd /usr
        git clone https://github.com/anarkiwi/src -b faucet

- `Build and install your kernel <https://www.openbsd.org/faq/faq5.html#Custom>`_

- Create an OpenBSD OpenFlow switch with a DPID (example 1), and add existing interfaces to it (example axen0 and axen1).

.. code-block::  console

        ifconfig axen0 up
        ifconfig axen1 up
        ifconfig switch0 create datapath 1
        ifconfig add axen0
        ifconfig add axen1
        ifconfig switch0 up

- Create ``/etc/switchd.conf`` (6699 is unused - it just moves switchd's built in controller out of the way of Faucet which will use 6653).

.. code-block::  console

        listen on 127.0.0.1 port 6699
        device "/dev/switch0" forward to tcp:127.0.0.1

- Start switchd.

- Install and configure Faucet (via pip install). Python3.8 can be added with ``pkg_add python``. Use hardware ``Open vSwitch``.

Known issues
------------

* Single controller only (cannot use Gauge, and not possible to use switchctl to debug the switch while switchd/Faucet are running).
* No OFPort notifications - switchofp will not tell Faucet that a interface has come up or come down (``opstatus_reconf: false`` must be set on Faucet interfaces to cause Faucet to configure OpenFlow interfaces regardless of interface status).
* No Async message configuration (SET_ASYNC) support. Faucet uses this to switch packet in off and on during start up. It causes the switch to report an OpenFlow error related to SET_ASYNC and potentially some unnecessary packet ins during start up, but otherwise does not impact operation.

References
----------

* https://man.openbsd.org/switchd.conf.5
* https://www.openbsd.org/papers/bsdcan2016-switchd.pdf (https://av.tib.eu/media/45487)
