#!/bin/sh
## @author: Shivaram.Mysore@gmail.com

## Check if user is root
if [ "$EUID" -ne 0 ]
    then echo "Run $0 script as root after a fresh install of Ubuntu 17.04"
    exit
fi



apt-get install apt-transport-https
echo "deb https://packages.wand.net.nz $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/wand.list
echo "deb https://packages.wand.net.nz $(lsb_release -sc)-testing main" | sudo tee /etc/apt/sources.list.d/wand.list
curl https://packages.wand.net.nz/keyring.gpg -o /etc/apt/trusted.gpg.d/wand.gpg
apt-get update

apt-get install software-properties-common git wget curl unzip bzip2 screen minicom make gcc dpdk dpdk-dev dpdk-doc dpdk-igb-uio-dkms openvswitch-common openvswitch-switch python-openvswitch openvswitch-pki openvswitch-testcontroller python2.7 libpython2.7 python-pip linux-image-extra-$(uname -r) linux-image-extra-virtual apt-transport-https ca-certificates vlan
apt-get install openvswitch-switch-dpdk

echo "Check installed versions of OpenVSwitch ..."
dpkg -l openvswitch-common openvswitch-pki openvswitch-switch python-openvswitch openvswitch-switch-dpdk

## Optionally add sensors package for finding out temperature
apt-get install hwinfo lm-sensors  hddtemp
service kmod start
sensors-detect --auto
sensors
hddtemp /dev/sda

# enable IPv6
sysctl net.ipv6.conf.all.disable_ipv6=0
## fix interface name to suit your machine
echo  "#iface enp1s0f0 inet6 dhcp" >> /etc/network/interfaces
## enable interafce config changes by: systemctl restart networking
## Zero out interface (ex. eth5) attached to the bridge
# ip addr add 0 dev eth5

echo "Loading the 8021q module into the kernel."
modprobe 8021q
echo "Adding 8021q module to the kernel on boot"
echo "8021q" >> /etc/modules



#update-alternatives: using /usr/lib/openvswitch-switch-dpdk/ovs-vswitchd-dpdk to provide /usr/sbin/ovs-vswitchd (ovs-vswitchd) in manual mode
sudo update-alternatives --set ovs-vswitchd /usr/lib/openvswitch-switch-dpdk/ovs-vswitchd-dpdk

# ovs-vswitchd --version
### ovs-vswitchd (Open vSwitch) 2.7.0
