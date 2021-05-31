#!/bin/bash -e
echo "Installing Faucet"

ID="$(grep -Po '(?<=^ID=).*' "${ROOTFS_DIR}/etc/os-release" | awk '{print tolower($0)}')"
CODE="$(grep -Po -m 1 '(?<=\()[^\)]+' "${ROOTFS_DIR}/etc/os-release" | awk '{print tolower($0)}')"
on_chroot << EOF
apt-get install -y curl apt-transport-https lsb-release tcpdump
echo "deb https://packagecloud.io/faucetsdn/faucet/${ID}/ ${CODE} main" | tee /etc/apt/sources.list.d/faucet.list
curl -L https://packagecloud.io/faucetsdn/faucet/gpgkey | apt-key add -
apt-get update
apt-get install -y --fix-missing faucet-all-in-one
apt-get clean
EOF
