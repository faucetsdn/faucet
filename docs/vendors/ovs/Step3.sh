#!/bin/sh
## @author: Shivaram.Mysore@gmail.com

#DPDK_DIR=/usr/share/dpdk/tools
DPDK_DIR=/sbin

modprobe vfio-pci

$DPDK_DIR/dpdk-devbind --status
$DPDK_DIR/dpdk-devbind --bind=vfio-pci 0000:82:00.0 0000:82:00.1 0000:82:00.2 0000:82:00.3 0000:83:00.0 0000:83:00.1 0000:83:00.2 0000:83:00.3
$DPDK_DIR/dpdk-devbind.py --status

# By default, OVS sets other_config:dpdk-socket-mem to "1024,0". 
# This will give one 1GB hugepage to CPU0 and none to CPU1
# On this box, network interfaces are connected physically via a PCI-E bus to CPU1.
# So, assign a hugepage to CPU1
ovs-vsctl --no-wait set Open_vSwitch . other_config:dpdk-socket-mem="1024,1024"
ovs-vsctl --no-wait set Open_vSwitch . other_config:dpdk-init=true
update-alternatives --set ovs-vswitchd /usr/lib/openvswitch-switch-dpdk/ovs-vswitchd-dpdk
ovs-vsctl add-br ovs-ip64-br0 -- set bridge ovs-ip64-br0 datapath_type=netdev protocols=OpenFlow13 other_config:datapath-id=fa:ce:de:af:ca:fe:ba:be
ip addr add 10.20.8.8 dev ovs-ip64-br0
ovs-vsctl show
## http://docs.openvswitch.org/en/latest/howto/dpdk/

#ovs-vsctl add-port ovs-ip64-br0 dpdk-p0 -- set Interface dpdk-p0 type=dpdk options:dpdk-devargs=0000:82:00.0
#ovs-vsctl add-port ovs-ip64-br0 dpdk-p1 -- set Interface dpdk-p1 type=dpdk options:dpdk-devargs=0000:82:00.1
#ovs-vsctl add-port ovs-ip64-br0 dpdk-p2 -- set Interface dpdk-p2 type=dpdk options:dpdk-devargs=0000:82:00.2
#ovs-vsctl add-port ovs-ip64-br0 dpdk-p3 -- set Interface dpdk-p3 type=dpdk options:dpdk-devargs=0000:82:00.3
#ovs-vsctl add-port ovs-ip64-br0 dpdk-p4 -- set Interface dpdk-p4 type=dpdk options:dpdk-devargs=0000:83:00.0
#ovs-vsctl add-port ovs-ip64-br0 dpdk-p5 -- set Interface dpdk-p5 type=dpdk options:dpdk-devargs=0000:83:00.1
#ovs-vsctl add-port ovs-ip64-br0 dpdk-p6 -- set Interface dpdk-p6 type=dpdk options:dpdk-devargs=0000:83:00.2
#ovs-vsctl add-port ovs-ip64-br0 dpdk-p7 -- set Interface dpdk-p7 type=dpdk options:dpdk-devargs=0000:83:00.3

ovs-vsctl add-port ovs-ip64-br0 enp130s0f0 -- set Interface enp130s0f0 type=dpdk options:dpdk-devargs=0000:82:00.0
ovs-vsctl add-port ovs-ip64-br0 enp130s0f1 -- set Interface enp130s0f1 type=dpdk options:dpdk-devargs=0000:82:00.1
ovs-vsctl add-port ovs-ip64-br0 enp130s0f2 -- set Interface enp130s0f2 type=dpdk options:dpdk-devargs=0000:82:00.2
ovs-vsctl add-port ovs-ip64-br0 enp130s0f3 -- set Interface enp130s0f3 type=dpdk options:dpdk-devargs=0000:82:00.3
ovs-vsctl add-port ovs-ip64-br0 ens2f0 -- set Interface ens2f0 type=dpdk options:dpdk-devargs=0000:83:00.0
ovs-vsctl add-port ovs-ip64-br0 ens2f1 -- set Interface ens2f1 type=dpdk options:dpdk-devargs=0000:83:00.1
ovs-vsctl add-port ovs-ip64-br0 ens2f2 -- set Interface ens2f2 type=dpdk options:dpdk-devargs=0000:83:00.2
ovs-vsctl add-port ovs-ip64-br0 ens2f3 -- set Interface ens2f3 type=dpdk options:dpdk-devargs=0000:83:00.3

echo "DPID of OVS Switch ovs-ip64-br0 ..."
ovs-vsctl get bridge ovs-ip64-br0 datapath_id

ovs-vsctl set-controller ovs-ip64-br0 tcp:10.20.5.5:6653 tcp:10.20.5.5:6654 

