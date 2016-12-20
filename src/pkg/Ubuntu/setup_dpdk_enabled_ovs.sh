#!/bin/bash
## @author: Shivaram.Mysore@gmail.com

## Functions to read Properties file

ENV=${1:-ovswitch}

## Function to get the property value for the provided key
function prop {
  grep "^${1}" ${ENV}.properties|cut -d'=' -f2
}

## Function to count the number of keys given the start of a key
function countprop {
  grep "^${1}" ${ENV}.properties | wc -l
}

## End Functions

## Check if user is root
if [ "$EUID" -ne 0 ]
  then echo "Please run this script $0 as root"
  exit
fi

modprobe uio
modprobe igb_uio
echo "Listing Network devices using DPDK-compatible driver"
/usr/share/dpdk/tools/dpdk_nic_bind.py --status

echo "Perform the dpdk_nic_bind with the PCI IDs to be unbounded from Linux kernel."
/usr/share/dpdk/tools/dpdk-devbind.py --bind=igb_uio 0000:02:00.0 0000:03:00.0 0000:05:00.0

update-alternatives --set ovs-vswitchd /usr/lib/openvswitch-switch-dpdk/ovs-vswitchd-dpdk

if [ ! -f /etc/openvswitch/conf.db ]
then
  ovsdb-tool create /etc/openvswitch/conf.db /usr/share/openvswitch/vswitch.ovsschema
fi

if [ -z ${DB_SOCK+x} ]; then export DB_SOCK=/var/run/openvswitch/db.sock; else echo "env DB_SOCK is set to '$DB_SOCK'"; fi
ovs-vsctl --no-wait set Open_vSwitch . other_config:dpdk-init=true
/usr/sbin/ovs-vswitchd unix:$DB_SOCK --pidfile --detach

# /usr/sbin/ovs-vswitchd -c 0x1 unix:$DB_SOCK --pidfile --detach

# ovs-vswitchd unix:/var/run/openvswitch/db.sock -vconsole:emer -vsyslog:err -vfile:info --mlockall --no-chdir --log-file=/var/log/openvswitch/ovs-vswitchd.log --pidfile=/var/run/openvswitch/ovs-vswitchd.pid --detach --monitor
####################################


echo "This script sets up OVS Switch with DPDK support on this Ubuntu 16.10 box"

ovs-vsctl del-br $(prop 'BRIDGE_NAME')
ovs-vsctl add-br $(prop 'BRIDGE_NAME') -- set bridge $(prop 'BRIDGE_NAME') datapath_type=netdev
ovs-vsctl list-br

for ((i=0;i<$(countprop 'HOST_IFACE');i++));
do
  ovs-vsctl add-port $(prop 'BRIDGE_NAME') dpdk$i -- set Interface dpdk$i type=dpdk
done

## DELETE this before checkin
# ovs-vsctl del-br ovs-br0
# ovs-vsctl add-br ovs-br0 -- set bridge ovs-br0 datapath_type=netdev
# ovs-vsctl list-br
# ovs-vsctl add-port ovs-br0 dpdk0 -- set Interface dpdk0 type=dpdk
# ovs-vsctl add-port ovs-br0 dpdk1 -- set Interface dpdk1 type=dpdk
# ovs-vsctl add-port ovs-br0 dpdk2 -- set Interface dpdk2 type=dpdk

# ovs-vsctl del-br ovsdpdkbr0
# ovs-vsctl add-br ovsdpdkbr0 -- set bridge ovsdpdkbr0 datapath_type=netdev
# ovs-vsctl list-br
# ovs-vsctl add-port ovsdpdkbr0 dpdk0 -- set Interface dpdk0 type=dpdk
# ovs-vsctl add-port ovsdpdkbr0 dpdk1 -- set Interface dpdk1 type=dpdk
# ovs-vsctl add-port ovsdpdkbr0 dpdk2 -- set Interface dpdk2 type=dpdk

# to add a wireless interface uncomment the next line.
#ovs-vsctl add-port $BRIDGE_NAME $WIRELESS_HOST_IFACE_1 -- set Interface $WIRELESS_HOST_IFACE_1 type=system

## Zero out your host interfaces that are attached to the bridge
##for ((i=0;i<=$(countprop 'HOST_IFACE');i++));
##do
##  ip addr add 0 dev dpdk$i
##done

## Set OVS Bridge properties
ovs-vsctl set bridge $(prop 'BRIDGE_NAME') protocols=OpenFlow13 other_config:datapath-id=$(prop 'DATAPATH_ID')
#  ovs-vsctl set bridge ovsdpdkbr0  protocols=OpenFlow13 other_config:datapath-id=ce:ba:e9:4a:ed:44:01:f4

## Assign Openflow Controller IP and Port number to the OVS Bridge
ovs-vsctl set-controller $(prop 'BRIDGE_NAME') tcp:$(prop 'CNTRL_IP'):$(prop 'CNTRL_PORT')
# ovs-vsctl set-controller ovsdpdkbr0 tcp:10.10.11.19:6653 tcp:10.10.11.20:6654

## Show OVS brige information
ovs-vsctl show
ip addr add $(prop 'BRIDGE_IP') dev $(prop 'BRIDGE_NAME')


echo "Network interface info ..."
ip link

eecho "To get a dump of flows on the switch run:"
echo "ovs-ofctl -O OpenFlow13 dump-flows $(prop 'BRIDGE_NAME')"
echo ""

echo "For Port information, run:"
echo "ovs-ofctl -O OpenFlow13 dump-ports-desc $(prop 'BRIDGE_NAME')"
