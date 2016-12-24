:version: 1.3
:copyright: 2016 `Shivaram.Mysore@gmail.com`.  All Rights Reserved.

.. meta::
   :keywords: OpenFlow, Ryu, Faucet, VLAN, SDN, Open vSwitch, OVS, vSwitch

========================================================================
Setting up Software switch - OVS & Lagopus on Ubuntu with a 4-port QOTOM
========================================================================

Hardware:
========
QOTOM - https://www.amazon.com/gp/product/B01JZ5WMC4/ref=oh_aui_detailpage_o07_s00?ie=UTF8&psc=1
or https://www.amazon.com/gp/product/B01KZ853Y4/ref=od_aui_detailpages00?ie=UTF8&psc=1
QOTOM-Q310G4 Fanless 3215U Slim 4 LAN desktop computer 8G/{1T HDD or 128GB SSD} ,WIFI
Intel Celeron Processor 3215U Dual core (2M Cache, 1.70 GHz, Broadwell)
8GB DDR3 Ram,{1TB HDD,300M or 128GB MSATA SSD}, WIFI
4 Intel RJ45 Lan+2 USB 2.0+2 USB 3.0+HD Video+COM Port

Software:
========

Open vSwitch Installation:
-------------------------
Ubuntu 16.10 Server used
(You can do either do PXE or USB disk image or Network install to get the OS up and running)

After Ubuntu installation, the following scripts need to be run in sequence:

    1. Run `install_dpdk_pkgs.sh <install_dpdk_pkgs.sh>`_
    2. Update ``/etc/default/grub`` with ``GRUB_CMDLINE_LINUX_DEFAULT=quiet default_hugepagesz=1G hugepagesz=1G hugepages=4``
    3. Run ``update-grub`` from the command line
    4. ``reboot`` the system
    5. Modify `ovswitch.properties <ovswitch.properties>`_ file to suit your requirements
    6. To test if everything is working, you can run `setup_ovs_wo_dpdk.sh <setup_ovs_wo_dpdk.sh >`_ script.
    7. Deleting OVS Setup is easy.  Just run ``ovs-vsctl del-br ovs-br0`` where ``ovs-br0`` is the name of the bridge
    8. To setup DPDK enabled OVS, run the script `setup_dpdk_enabled_ovs.sh <setup_dpdk_enabled_ovs.sh>`_

Lagopus raw-socket Switch Installation:
--------------------------------------
Ubuntu 16.10 Server used
(You can do either do PXE or USB disk image or Network install to get the OS up and running)

After Ubuntu installation, the following scripts need to be run in sequence:

    1.  Run `install_dpdk_pkgs_4lagopus.sh <install_dpdk_pkgs_4lagopus.sh>`_
    2.  Update ``/etc/default/grub`` with ``GRUB_CMDLINE_LINUX_DEFAULT=quiet default_hugepagesz=1G hugepagesz=1G hugepages=4``
    3.  Run ``update-grub`` from the command line
    4.  ``reboot`` the system
    5.  Modify `lagopus.properties <lagopus.properties>`_ file to suit your requirements
    6.  Run `setup_lagopus.sh <setup_lagopus.sh>`_ - this will create necessary config files and directories
    7.  Run ``git clone https://github.com/lagopus/lagopus``
    8.  ``cd lagopus; ./configure --disable-dpdk; make; sudo make install``
    9.  Copy `lagopus.dsl.example <lagopus.dsl.example>`_ file to ``/usr/local/etc/lagopus/lagopus.dsl`` and modify controller and port settings as appropriate
    10. Start Lagopus without DPDK support - ``/usr/local/sbin/lagopus --config /usr/local/etc/lagopus/lagopus.dsl``
    11. You can run ``lagosh`` command to open shell to Switch to``stop`` the Switch service - more info http://www.lagopus.org/lagopus-book/en/html/lagosh.html


Faucet Controller Installation
------------------------------

The simplest is to use a MAC or Linux box and run as ``root``:

.. code:: bash

    # pip install ryu-faucet

Edit the ``/etc/ryu/faucet/faucet.yaml`` file to look like this:

.. code:: yaml

    version: 2
    vlans:
        500:
            name: "clock"
            unicast_flood: True
        600:
            name: "foobar"
            unicast_flood: True
    dps:
        ovs-qotom-1:
            dp_id: 0x0000000ec4ce7e31
            hardware: "Open vSwitch"
            interfaces:
                1:
                    native_vlan: 500
                    name: "enp2s0"
                2:
                    native_vlan: 500
                    name: "enp3s0"
                3:
                    native_vlan: 500
                    name: "enp5s0"
        ovs-qotom-2:
            dp_id: 0xec4ce22221010
            hardware: "Lagopus"
            interfaces:
                1:
                    native_vlan: 500
                    name: "enp2s0"
                2:
                    native_vlan: 500
                    name: "enp3s0"
                3:
                    native_vlan: 500
                    name: "enp5s0"

TODO:
====
- Add wireless interface to the OVS and Lagopus bridge ports
- Add instructions for running Lagopus with DPDK support

References:
==========

    1. Ubuntu DPDK related information: https://help.ubuntu.com/16.04/serverguide/DPDK.html
    2. DPDK Documentation: http://dpdk.org/doc/guides-16.07/index.html
    3. Intel OVS with DPDK information: https://software.intel.com/en-us/articles/using-open-vswitch-with-dpdk-for-inter-vm-nfv-applications
    4. DPDK supported NICs: http://dpdk.org/doc/nics
    5. Lagopus Installation - http://www.lagopus.org/lagopus-book/en/html/installation-rawsocket.html
