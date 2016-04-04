#!/bin/sh

# expected hostname
HOST="faucet-1"

# expected file to install from
BLOB="ryu-faucet-0.30.tar.gz"

# config file location for swapping
CONFIGLOC="/etc/ryu/faucet/"
CONFIG="faucet.yaml"

if [ $HOST != `hostname` ]
then
    echo "Not running on $HOST, aborting"
    exit 1
fi

# do a reinstall
if [ ! -f $BLOB ]
then
    echo "No file to install from, aborting"
    exit 1
fi

sudo pip uninstall ryu-faucet
sudo pip install $BLOB

if [ ! -f ${CONFIGLOC}$CONFIG ]
then
    echo "Config file ${CONFIGLOC}$CONFIG does not exist, aborting"
    exit 1
fi

echo "Copying in alternative config file"
sudo cp $CONFIG ${CONFIGLOC}.
