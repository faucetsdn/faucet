#!/bin/sh

sysctl -w net.netfilter.nf_conntrack_tcp_timeout_time_wait=10
sysctl -w net.ipv4.tcp_fin_timeout=10
sysctl -w net.ipv4.tcp_tw_recycle=1
sysctl -w net.ipv4.tcp_tw_reuse=1

export OVS_LOGDIR=/usr/local/var/log
rm -rf /tmp/faucet*log /tmp/gauge*log /tmp/faucet-tests* /var/tmp/faucet-tests* $OVS_LOGDIR/* ; killall ryu-manager ; ./faucet_mininet_test.py -c ; /usr/local/share/openvswitch/scripts/ovs-ctl stop ; /usr/local/share/openvswitch/scripts/ovs-ctl start ; ./faucet_mininet_test.py $*
