#!/bin/sh
## @author: Shivaram.Mysore@gmail.com

## Check if user is root
if [ "$EUID" -ne 0 ]
    then echo "Please run this script $0 as root"
    exit
fi

DPDK_DIR=/usr/share/dpdk/tools
echo -e "pci\t0000:04:00.0\tvfio-pci\npci\t0000:04:00.1\tuio_pci_generic" >> /etc/dpdk/interfaces

echo "vfio-pci" >> /etc/modules
#modprobe vfio-pci
#modprobe uio_pci_generic
lsmod | egrep 'vfio'

echo "Listing Network devices using DPDK-compatible driver"
$DPDK_DIR/dpdk-devbind.py --status

echo "Setting environment variable DB_SOCK in /etc/environment file ..."
/bin/echo -en "DB_SOCK=/var/run/openvswitch/db.sock" >> /etc/environment

echo ""
echo "Modify /etc/default/grub to include hugepages settings."
echo "Reserve 1G huge pages via grub configurations. For example:"
echo " to reserve 4 huge pages of 1G size - add parameters: default_hugepagesz=1G hugepagesz=1G hugepages=4"
echo " For 2 CPU cores, Isolate CPU cores which will be used for DPDK - add parameters: isolcpus=2"
echo " To use VFIO - add parameters: iommu=pt intel_iommu=on"
echo "Note: If you are not sure about something, leave it asis!!"
echo "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet intel_iommu=on iommu=pt default_hugepagesz=1G hugepagesz=1G hugepages=4\""
echo ""
echo "After changing /etc/default/grub, run command: update-grub"
echo "reboot to take effect."

