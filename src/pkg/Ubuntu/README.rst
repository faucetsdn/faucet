:version: 1.2
:copyright: 2016 `Shivaram.Mysore@gmail.com`.  All Rights Reserved.

.. meta::
   :keywords: OpenFlow, Ryu, Faucet, VLAN, SDN, Open vSwitch, OVS, vSwitch


============================================
Setting up OVS on Ubuntu with a 4-port QOTOM
============================================

Hardware:
========
QOTOM - https://www.amazon.com/gp/product/B01JZ5WMC4/ref=oh_aui_detailpage_o07_s00?ie=UTF8&psc=1
QOTOM-Q310G4 Fanless 3215U Slim 4 LAN desktop computer 8G/1T HDD ,WIFI
Intel Celeron Processor 3215U Dual core (2M Cache, 1.70 GHz, Broadwell)
8GB DDR3 Ram,1TB HDD,300M WIFI
4 Intel RJ45 Lan+2 USB 2.0+2 USB 3.0+HD Video+COM Port

Software:
========
Open vSwitch Installation:
-------------------------
Ubuntu 16.04 Server LTS used
(You can do either do PXE or USB disk image or Network install to get the OS up and running)

After Ubuntu installation, the following scripts need to be run in sequence:

    1. `install_dpdk_pkgs.sh <install_dpdk_pkgs.sh>_`
    2. Update ``/etc/default/grub`` with ``GRUB_CMDLINE_LINUX_DEFAULT`` and then run ``update-grub``
    3. ``reboot`` the system
    4. Modify `ovswitch.properties <ovswitch.properties>_` file to suit your requirements
    5. To test if everything is working, you can run `setup_ovs_wo_dpdk.sh <setup_ovs_wo_dpdk.sh >_` script.
    6. Deleting OVS Setup is easy.  Just run ``ovs-vsctl del-br ovs-br0`` where ``ovs-br0`` is the name of the bridge
    7. To setup DPDK enabled OVS, run the script `setup_dpdk_enabled_ovs.sh <setup_dpdk_enabled_ovs.sh>_`

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

TODO:
====
- Add wireless interface to the OVS bridge port

References:
==========

    1. Ubuntu DPDK related information: https://help.ubuntu.com/16.04/serverguide/DPDK.html
    2. DPDK Documentation: http://dpdk.org/doc/guides-16.07/index.html
    3. Intel OVS with DPDK information: https://software.intel.com/en-us/articles/using-open-vswitch-with-dpdk-for-inter-vm-nfv-applications
    4. DPDK supported NICs: http://dpdk.org/doc/nics
