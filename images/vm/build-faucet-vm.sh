#!/bin/bash

export DIB_RELEASE=xenial
export ELEMENTS_PATH=elements

GIT_ID=$(git describe --tags)

if [ ! -d "/dev/loop0" ]; then
    echo "Creating a loop device"
    losetup -D
    mknod -m 0660 /dev/loop0 b 7 0
fi

disk-image-create -x -x --checksum -a amd64 -o faucet-amd64-$GIT_ID \
    -t qcow2 \
    vm ubuntu-minimal cloud-init-nocloud \
    stable-interface-names dhcp-all-interfaces \
    openssh-server runtime-ssh-host-keys \
    faucet-all-in-one
