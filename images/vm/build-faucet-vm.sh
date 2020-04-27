#!/bin/bash

export DIB_RELEASE=focal
export ELEMENTS_PATH=elements

GIT_ID=$(git describe --tags)

disk-image-create -x -x --checksum -a amd64 -o faucet-amd64-$GIT_ID \
    -t qcow2 \
    vm ubuntu-minimal cloud-init-nocloud dhcp-all-interfaces \
    openssh-server runtime-ssh-host-keys \
    faucet-all-in-one
