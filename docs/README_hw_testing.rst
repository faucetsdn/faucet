===================================
Hardware switch testing with docker
===================================

::

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
------------

Your test host, requires at least 5 interfaces. 4 interfaces to connect
to the dataplane, and one for the CPN for OpenFlow. You will need to assign
an IP address to the CPN interface on the host, and configure the switch
with a CPN IP address and establish that they can reach each other (eg via ping).

You will need to configure the switch with two OpenFlow controllers, both
with the host's CPN IP address, but with different ports (defaults are given
below for *of_port* and *gauge_of_port*).

It is assumed that you execute all following commands from your FAUCET
source code directory (eg one you have git cloned).

Test configuration
------------------

Create a directory for the test configuration:

.. code:: bash

  mkdir -p /etc/ryu/faucet
  $EDITOR /etc/ryu/faucet/hw_switch_config.yaml

`hw_switch_config.yaml` should contain the correct configuration for your
switch:

.. code:: yaml

  hw_switch: True 
  hardware: 'Open vSwitch'
  # Map ports on the hardware switch, to physical ports on this machine.
  # If using a switch with less than 4 dataplane ports available, run
  # FaucetZodiac tests only. A 4th port must still be defined here and
  # must exist, but will not be used.
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

Running the tests
-----------------

.. code:: bash

  docker build -t faucet/tests -f Dockerfile.tests .
  apparmor_parser -R /etc/apparmor.d/usr.sbin.tcpdump
  modprobe openvswitch
  sudo docker run --privileged --net=host \
      -v /etc/ryu/faucet:/etc/ryu/faucet \
      -v /tmp:/tmp \
      -ti faucet/tests

Running a single test
---------------------

.. code:: bash

  sudo docker run --privileged --net=host \
      -e FAUCET_TESTS="FaucetUntaggedTest" \
      -v /etc/ryu/faucet:/etc/ryu/faucet \
      -v /tmp:/tmp \
      -ti faucet/tests

Checking test results
---------------------

If a test fails, you can look in /tmp - there will be subdirectories created for each test, which
will contain all the logs and debug information (including tcpdumps).


