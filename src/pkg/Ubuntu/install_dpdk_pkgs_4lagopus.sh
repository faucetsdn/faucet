#!/bin/sh
## @author: Shivaram.Mysore@gmail.com

## Check if user is root
if [ "$EUID" -ne 0 ]
  then echo "Please run this script $0 as root"
  exit
fi

echo "OVS related packages installation ... for Ubuntu 16.10"
apt-get install make gcc dpdk dpdk-dev dpdk-doc dpdk-igb-uio-dkms build-essential libexpat-dev libgmp-dev libssl-dev libpcap-dev byacc flex git python-dev python-pastedeploy python-paste python-twisted


modprobe uio
modprobe igb_uio
lsmod | egrep 'uio'
echo -e "pci\t0000:04:00.1\tuio_pci_generic\npci\t0000:05:00.0\tigb_uio" >> /etc/dpdk/interfaces

echo "Listing Network devices using DPDK-compatible driver"
/usr/share/dpdk/tools/dpdk_nic_bind.py --status


echo ""
echo "Hugepage size: "
awk '/Hugepagesize/ {print $2}' /proc/meminfo

echo ""
echo "Total huge page numbers: "
awk '/HugePages_Total/ {print $2} ' /proc/meminfo

echo ""
echo "Unmount the hugepages"
umount `awk '/hugetlbfs/ {print $2}' /proc/mounts`

echo ""
echo "Creating the hugepage mount folder ... /mnt/huge_1GB for 1GB pages"
#mkdir -p /mnt/huge
mkdir -p /mnt/huge_1GB

echo ""
echo " Mount to the specific folder - hugetlbfs and make it permanent in /etc/fstab"
# mount -t hugetlbfs nodev /mnt/huge
echo -e "nodev\t/mnt/huge_1GB\thugetlbfs\tpagesize=1GB\t0\t0" >> /etc/fstab
echo "Listing contents of /etc/fstab"
cat /etc/fstab

echo ""
echo "Listing CPU Layout via lscpu"
lscpu

echo ""
echo "Modify /etc/default/grub to include hugepages settings."
echo "Reserve 1G huge pages via grub configurations. For example:"
echo " to reserve 4 huge pages of 1G size - add parameters: default_hugepagesz=1G hugepagesz=1G hugepages=4"
echo " For 2 CPU cores, Isolate CPU cores which will be used for DPDK - add parameters: isolcpus=2"
echo " To use VFIO - add parameters: iommu=pt intel_iommu=on"
echo "Note: If you are not sure about something, leave it asis!!"
echo "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet default_hugepagesz=1G hugepagesz=1G hugepages=4\""
echo ""
echo "After changing /etc/default/grub, run command: update-grub"
echo "reboot to take effect."
