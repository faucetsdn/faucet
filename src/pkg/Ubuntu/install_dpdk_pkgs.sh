#!/bin/sh
## @author: Shivaram.Mysore@gmail.com

## Check if user is root
if [ "$EUID" -ne 0 ]
  then echo "Please run this script $0 as root"
  exit
fi

echo "OVS related packages installation ..."
apt-get install make gcc openvswitch-common openvswitch-switch openvswitch-switch-dpdk python-openvswitch openvswitch-pki openvswitch-test openvswitch-testcontroller

echo ""
echo "You can install DPDK kernel mode drivers even if you are not using DPDK immediately."
echo "Now downloading and installing the same in /usr/local/src/ directory ..."
echo ""
mkdir -p /usr/local/src/
cd /usr/local/src/; wget http://fast.dpdk.org/rel/dpdk-16.07.1.tar.xz; tar -xJf /usr/local/src/dpdk-16.07.1.tar.xz; cd /usr/local/src/dpdk-stable-16.07.1;
make config T=x86_64-native-linuxapp-gcc && make; cd ~/;
modprobe uio
insmod /usr/local/src/dpdk-stable-16.07.1/build/kmod/igb_uio.ko
lsmod | egrep 'uio'

## https://help.ubuntu.com/16.04/serverguide/DPDK.html
echo "Listing Network devices using DPDK-compatible driver"
/sbin/dpdk_nic_bind --status
