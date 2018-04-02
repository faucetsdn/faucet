#!/bin/sh

./sysctls_for_tests.sh

export OVS_LOGDIR=/usr/local/var/log
export PYTHONPATH=$PWD/..
rm -rf /tmp/faucet*log /tmp/gauge*log /tmp/faucet-tests* /var/tmp/faucet-tests* $OVS_LOGDIR/* ; killall ryu-manager ; ./faucet_mininet_test.py -c ; /usr/local/share/openvswitch/scripts/ovs-ctl stop ; /usr/local/share/openvswitch/scripts/ovs-ctl start ; ./faucet_mininet_test.py $*
