#!/bin/bash
## @author: Shivaram.Mysore@gmail.com

ENV=${1:-ovswitch}

## Function to get the property value for the provided key
function prop {
  grep "^${1}" ${ENV}.properties|cut -d'=' -f2
}

## Function to count the number of keys given the start of a key
function countprop {
  grep "^${1}" ${ENV}.properties | wc -l
}

### End Configuration ###

echo "This script sets up OVS Switch on this Linux box"

ovs-vsctl add-br $(prop 'BRIDGE_NAME')
ovs-vsctl list-br

for ((i=1;i<=$(countprop 'HOST_IFACE');i++));
do
  IFACE=HOST_IFACE_$i
  ovs-vsctl add-port $(prop 'BRIDGE_NAME') "$(prop "${IFACE}")" -- set Interface "$(prop "${IFACE}")" type=system
done

# to add a wireless interface uncomment the next line.
#ovs-vsctl add-port $BRIDGE_NAME $WIRELESS_HOST_IFACE_1 -- set Interface $WIRELESS_HOST_IFACE_1 type=system

## Zero out your host interfaces that are attached to the bridge
for ((i=1;i<=$(countprop 'HOST_IFACE');i++));
do
  IFACE=HOST_IFACE_$i
  ip addr add 0 dev "$(prop "${IFACE}")"
done

## Set OVS Bridge properties
ovs-vsctl set bridge $(prop 'BRIDGE_NAME') protocols=OpenFlow13 other_config:datapath-id=$(prop 'DATAPATH_ID')

## Assign Openflow Controller IP and Port number to the OVS Bridge
ovs-vsctl set-controller $(prop 'BRIDGE_NAME') tcp:$(prop 'CNTRL_IP'):$(prop 'CNTRL_PORT')

## Show OVS brige information
ovs-vsctl show
ip addr add $(prop 'BRIDGE_IP') dev $(prop 'BRIDGE_NAME')

## Show network interface information
echo "Network interface info ..."
ip link

echo "To get a dump of flows on the switch run:"
echo "ovs-ofctl -O OpenFlow13 dump-flows $(prop 'BRIDGE_NAME')"
echo ""

echo "For Port information, run:"
echo "ovs-ofctl -O OpenFlow13 dump-ports-desc $(prop 'BRIDGE_NAME')"
