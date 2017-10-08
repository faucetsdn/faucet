#!/bin/bash

export DIB_RELEASE=xenial
export ELEMENTS_PATH=elements

# Copy faucet source code into build environment
rm -rf elements/faucet/install.d/faucet-src/
rsync -a --exclude 'vm/' ../ elements/faucet/install.d/faucet-src/

GIT_ID=$(git describe --tags)

disk-image-create --checksum -a amd64 -o faucet-amd64-$GIT_ID \
    -t qcow2,tgz,squashfs,vhd,raw \
    vm ubuntu-minimal cloud-init-nocloud \
    stable-interface-names dhcp-all-interfaces \
    openssh-server runtime-ssh-host-keys \
    faucet gauge \
    prometheus grafana
