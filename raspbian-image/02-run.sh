#!/bin/bash -e
echo "Installing Faucet"

ID="$(grep -Po '(?<=^ID=).*' ${ROOTFS_DIR}/etc/os-release | awk '{print tolower($0)}')"
CODE="$(grep -Po -m 1 '(?<=\()[^\)]+' ${ROOTFS_DIR}/etc/os-release | awk '{print tolower($0)}')"
on_chroot << EOF
apt-get install curl gnupg apt-transport-https lsb-release -y
echo "deb https://packagecloud.io/faucetsdn/faucet/${ID}/ ${CODE} main" | sudo tee /etc/apt/sources.list.d/faucet.list
curl -L https://packagecloud.io/faucetsdn/faucet/gpgkey | sudo apt-key add -
apt-get update
apt-get install faucet-all-in-one --fix-missing -y
EOF
