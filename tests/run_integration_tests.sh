#!/bin/sh

./sysctls_for_tests.sh

export OVS_LOGDIR=/usr/local/var/log
export FAUCET_DIR=$PWD/../faucet
export PYTHONPATH=$PWD/..

cd integration
rm -rf /tmp/faucet*log /tmp/gauge*log /tmp/faucet-tests* /var/tmp/faucet-tests* $OVS_LOGDIR/* ; killall ryu-manager ; python2 ./mininet_main.py -c ; /usr/local/share/openvswitch/scripts/ovs-ctl stop ; /usr/local/share/openvswitch/scripts/ovs-ctl start ; python2 ./mininet_main.py $*
