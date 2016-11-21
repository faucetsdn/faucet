#!/bin/sh
## @author: Shivaram.Mysore@gmail.com

## Check if user is root
if [ "$EUID" -ne 0 ]
  then echo "Please run this script $0 as root"
  exit
fi

echo "OVS related packages installation ..."
apt-get install make gcc openvswitch-common openvswitch-switch openvswitch-switch-dpdk python-openvswitch openvswitch-pki openvswitch-test openvswitch-testcontroller

# http://dpdk.org/doc/guides-16.04/linux_gsg/nic_perf_intel_platform.html

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
echo "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet default_hugepagesz=1G hugepagesz=1G hugepages=4 isolcpus=2 \""
echo ""
echo "After changing /etc/default/grub, run command: update-grub"
echo "reboot to take effect."
