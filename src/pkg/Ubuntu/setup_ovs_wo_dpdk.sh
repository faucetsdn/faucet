#!/bin/sh
## @author: Shivaram.Mysore@gmail.com

### Configuration Settings ###
MGMT_IFACE=enp1s0

CNTRL_IFACE_1=enp5s0
CNTRL_IP=10.10.11.19
CNTRL_PORT=6653

## Note: one of the host ports connected to the Bridge works as Uplink port
##  - possibly connected to the same switch as your DHCP server or has 
##    visibility to the same via DHCP Relay or helper
BRIDGE_NAME=ovs-br0
BRIDGE_IP=10.10.8.8/16
HOST_IFACE_1=enp2s0
HOST_IFACE_2=enp3s0
HOST_IFACE_3=enp5s0
WIRELESS_HOST_IFACE_1=wlp4s0

DATAPATH_ID=ce:ba:e9:4a:ed:44

## Commands
IFCONFIG=ifconfig
IP=ip
OVS_VSCTL=ovs-vsctl
OVS_DPCTL=ovs-dpctl
OVS_OFCTL=ovs-ofctl

### End Configuration ###

echo "This script sets up OVS Switch on this Linux box"

$OVS_VSCTL add-br $BRIDGE_NAME
$OVS_VSCTL list-br
$OVS_VSCTL add-port $BRIDGE_NAME $HOST_IFACE_1 -- set Interface $HOST_IFACE_1 type=system
$OVS_VSCTL add-port $BRIDGE_NAME $HOST_IFACE_2 -- set Interface $HOST_IFACE_2 type=system
$OVS_VSCTL add-port $BRIDGE_NAME $HOST_IFACE_3 -- set Interface $HOST_IFACE_3 type=system
#$OVS_VSCTL add-port $BRIDGE_NAME $WIRELESS_HOST_IFACE_1 -- set Interface $WIRELESS_HOST_IFACE_1 type=system

## Zero out your host interfaces that are attached to the bridge
$IFCONFIG $HOST_IFACE_1 0
$IFCONFIG $HOST_IFACE_2 0
$IFCONFIG $HOST_IFACE_3 0


$OVS_VSCTL set bridge $BRIDGE_NAME protocols=OpenFlow13 other_config:datapath-id=$DATAPATH_ID

$OVS_VSCTL set-controller $BRIDGE_NAME tcp:$CNTRL_IP:$CNTRL_PORT

$OVS_VSCTL show
$IFCONFIG $BRIDGE_NAME $BRIDGE_IP

echo "Network interface info ..."
$IP link

echo "To get a dump of flows on the switch run:"
echo "$OVS_OFCTL -O OpenFlow13 dump-flows $BRIDgE_NAME"
echo ""

echo "For Port information, run:"
echo "$OVS_OFCTL -O OpenFlow13 dump-ports-desc $BRIDGE_NAME"
