Testing
=======

Installing docker
-----------------

First, get yourself setup with docker based on our :ref:`docker-install` documentation.

.. _docker-sw-testing:

Software switch testing with docker
-----------------------------------

You can build and run the mininet tests with the following commands:

.. code:: console

  sudo docker build --pull -t faucet/tests -f Dockerfile.tests .
  sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.tcpdump
  sudo modprobe openvswitch
  sudo docker run --name=faucet-tests \
                  --sysctl net.ipv6.conf.all.disable_ipv6=0 --privileged --rm \
                  -v /var/local/lib/docker:/var/lib/docker \
                  -v /tmp/faucet-pip-cache:/var/tmp/pip-cache \
                  -ti faucet/tests

The apparmor command is currently required on Ubuntu hosts to allow the use of
tcpdump inside the container.

If you need to use a proxy, the following to your docker run command.

.. code:: console

  --build-arg http_proxy=http://your.proxy:port


.. _docker-hw-testing:

Hardware switch testing with docker
-----------------------------------

.. code-block:: none

                       +--------------------------+
                       |                          |
                       |         FAUCET CPN       |
                       |                          |
                       |                          |
  +------------------------------+     +-------------------------+
  |                    |         |     |          |              |
  |                    |    +--+ |     | +--+     |              |
  |                    |    |  +---------+  |     |              |
  |   FAUCET test host |    +--+ |     | +--+     |              |
  |                    +--------------------------+              |
  |                              |     |                         |
  |                              |     |                         |
  |                              |     |                         |
  |                              |     |                         |
  |          +---------------------+   |                         |
  |          |   +------+   +--+ | |   | +--+                    |
  |          |   |VM 1  |   |  +---------+  |                    |
  |          |   +------+   +--+ | |   | +--+                    |
  |          |                   | |   |                         |
  |          |   +------+   +--+ | |   | +--+  OpenFlow switch   |
  |          |   |VM 2  |   |  +---------+  |  under test        |
  |          |   +------+   +--+ | |   | +--+                    |
  |          |                   | |   |                         |
  |          |   +------+   +--+ | |   | +--+                    |
  |          |   |VM 3  |   |  +---------+  |                    |
  |          |   +------+   +--+ | |   | +--+                    |
  |          |                   | |   |                         |
  |          |   +------+   +--+ | |   | +--+                    |
  |          |   |VM 4  |   |  +---------+  |                    |
  |          |   +------+   +--+ | |   | +--+                    |
  |          |                   | |   |                         |
  |          |                   | |   |                         |
  +------------------------------+ |   +-------------------------+
             |                     |
             |    MININET          |
             |                     |
             |                     |
             +---------------------+


Requirements
~~~~~~~~~~~~

Your test host, requires at least 5 interfaces. 4 interfaces to connect
to the dataplane, and one for the CPN for OpenFlow. You will need to assign
an IP address to the CPN interface on the host, and configure the switch
with a CPN IP address and establish that they can reach each other (eg via ping).

You will need to configure the switch with two OpenFlow controllers, both
with the host's CPN IP address, but with different ports (defaults are given
below for *of_port* and *gauge_of_port*).

  .. note::
     It is very important to disable any process that could cause any
     traffic on the dataplane test interfaces, and the test interfaces
     should have all IPv4/IPv6 dynamic address assignment disabled.
     To achieve this, on Ubuntu for example, you can set the interfaces
     to "unmanaged" in Network Manager, and make sure processes like
     `Avahi <http://manpages.ubuntu.com/manpages/xenial/en/man5/avahi-daemon.conf.5.html>`_
     ignores the test interfaces.

  .. note::
     Hardware tests must not be run from virtualized hosts (such as under
     VMware). The tests need to control physical port status, and need
     low level L2 packet access (eg. to rewrite Ethernet source and
     destination addresses) which virtualization may interfere with.

  .. note::
     Hardware tests require the test switch to have all non-OpenFlow
     switching/other features (eg. RSTP, DHCP) disabled on the
     dataplane test interfaces. These features will conflict with
     the functions FAUCET itself provides (and in turn the tests).


It is assumed that you execute all following commands from your FAUCET
source code directory (eg one you have git cloned).

Test configuration
~~~~~~~~~~~~~~~~~~

Create a directory for the test configuration:

.. code:: console

  mkdir -p /etc/faucet
  $EDITOR /etc/faucet/hw_switch_config.yaml

``hw_switch_config.yaml`` should contain the correct configuration for your
switch:

.. code:: yaml

  hw_switch: true
  hardware: 'Open vSwitch'
  # Map ports on the hardware switch, to physical ports on this machine.
  dp_ports:
    1: enp1s0f0
    2: enp1s0f1
    3: enp1s0f2
    4: enp1s0f3
  # Hardware switch's DPID
  dpid: 0xeccd6d9936ed
  # Port on this machine that connects to hardware switch's CPN port.
  # Hardware switch must use IP address of this port as controller IP.
  cpn_intf: enp5s0
  # There must be two controllers configured on the hardware switch,
  # with same IP (see cpn_intf), but different ports - one for FAUCET,
  # one for Gauge.
  of_port: 6636
  gauge_of_port: 6637
  # If you wish to test OF over TLS to the hardware switch,
  # set the following parameters per Ryu documentation.
  # https://github.com/osrg/ryu/blob/master/doc/source/tls.rst
  # ctl_privkey: ctl-privkey.pem
  # ctl_cert: ctl-cert.pem
  # ca_certs: /usr/local/var/lib/openvswitch/pki/switchca/cacert.pem

.. _docker-hw-testing-running:

Running the tests
~~~~~~~~~~~~~~~~~

Before starting the hardware test suite for the first time, you will need to
install ebtables on the host machine:

.. code:: console

  sudo apt-get install ebtables

After every reboot of your host machine you will also need to manually load the
``openvswitch`` and ``ebtables`` kernel modules. If using apparmor you will also
need to disable the profile for tcpdump:

.. code:: console

  sudo modprobe openvswitch
  sudo modprobe ebtables
  sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.tcpdump

Then you can build and run the test suite:

.. code:: console

  sudo docker build --pull -t faucet/tests -f Dockerfile.tests .
  sudo docker run --name=faucet-tests \
                  --privileged --rm --net=host --cap-add=NET_ADMIN \
                  -v /var/local/lib/docker:/var/lib/docker \
                  -v /tmp/faucet-pip-cache:/var/tmp/pip-cache \
                  -v /etc/faucet:/etc/faucet \
                  -v /var/tmp:/var/tmp \
                  -ti faucet/tests

Test suite options
------------------

In both the software and hardware version of the test suite we can provide
flags inside the ``FAUCET_TESTS`` environment variable to run specific parts of
the test suite.

  .. note::
     Multiple flags can be added to FAUCET_TESTS, below are just some examples
     of  how individual flags work.

To find the full list of options you can pass to the test suite, set
``FAUCET_TESTS`` to ``--help``.

.. code:: console

      -e FAUCET_TESTS="--help"

Running specific integration tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If specific test names are listed in the ``FAUCET_TESTS`` environment then only
these integration tests will be run and all others skipped.

If we add the following to either of the previous docker run commands then only
the ``FaucetUntaggedTest`` will be run.

.. code:: console

      -e FAUCET_TESTS="FaucetUntaggedTest"

Running only the integration tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sometimes you will want to skip the pytype, linting and documentation tests
in order to complete a faucet test suite run against hardware quicker.

.. code:: console

      -e FAUCET_TESTS="-i"

Skip code checks
~~~~~~~~~~~~~~~~

Sometimes you will want to skip the pytype, linting and documentation tests.

This can be done with with the ``-n`` flag:

.. code:: console

      -e FAUCET_TESTS="-n"

Skip unit tests
~~~~~~~~~~~~~~~

Sometimes you will want to skip the unit tests which are small tests that verify
small chunks of the code base return the correct values. If these are skipped
the integration tests (which spin up virtual networks and tests faucet
controllers under different configurations) will still be run.

This can be done with with the ``-u`` flag:

.. code:: console

      -e FAUCET_TESTS="-u"

Checking test results
~~~~~~~~~~~~~~~~~~~~~

If a test fails, you can look in /var/tmp - there will be subdirectories created
for each test, which will contain all the logs and debug information
(including tcpdumps).

By default the test suite cleans up these files but if we use the ``-k`` flag
the test suite will keep these files.

.. code:: console

      -e FAUCET_TESTS="-k"

Repeatedly running tests until failure
--------------------------------------

You can run tests until a failure is detected (eg, to diagnose an unreliable test).
Tests will continue to run forever until at least one fails or the test is interrupted.

.. code:: console

      -e FAUCET_TESTS="-r"

Test debugging
--------------

Often while debugging a failed integration test it can be useful to pause the
test suite at the point of the failure. The test can then be inspected live to
narrow down the exact issue. To do this, run your test with the ``--debug``
flag (replace `TEST_NAME` with actual name of test).

.. code:: console

      -e FAUCET_TESTS="--debug TEST_NAME"

The test suite will now run in a mode where it ignores successful tests and
drops into a pdb shell when a failure occurs inside a test.
There are a number of different
`pdb commands <https://docs.python.org/3/library/pdb.html#debugger-commands>`_
that can be run to check the actual test code.

It is also possible to login to the virtual container environment to run
interactive debug commands to inspect the state of the system.

.. code:: console

      sudo sudo docker exec -it faucet-tests /bin/bash

One useful thing can be to find the running mininet containers and execute
commands inside of them, e.g ping:

.. code:: console

      root@35b98943f736:/faucet-src# ps w | grep mininet:

        995 pts/1    Ss+    0:00 bash --norc --noediting -is mininet:faucet-637
        997 pts/2    Ss+    0:00 bash --norc --noediting -is mininet:u021
       1001 pts/3    Ss+    0:00 bash --norc --noediting -is mininet:u022
       1005 pts/4    Ss+    0:00 bash --norc --noediting -is mininet:u023
       1009 pts/5    Ss+    0:00 bash --norc --noediting -is mininet:u024
       1013 pts/6    Ss+    0:00 bash --norc --noediting -is mininet:s02
       1077 pts/7    Ss+    0:00 bash --norc --noediting -is mininet:gauge-637

      root@35b98943f736:/faucet-src# m u021 ping 127.0.0.1
