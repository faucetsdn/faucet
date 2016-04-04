#!/bin/sh

# expected hostname
HOST="faucet-1"

if [ $HOST != `hostname` ]
then
    echo "Not running on $HOST, aborting"
    exit 1
fi

# faucet needs these env variables
export FAUCET_CONFIG=/etc/ryu/faucet/faucet.yaml
export GAUGE_CONFIG=/etc/ryu/faucet/gauge.conf
ryu-manager --verbose /usr/local/lib/python2.7/dist-packages/ryu_faucet/org/onfsdn/faucet/gauge.py 
# /usr/local/lib/python2.7/dist-packages/ryu_faucet/org/onfsdn/faucet/gauge.py
