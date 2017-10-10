#!/bin/bash

DEPCHECK=1

# if -n passed, don't check dependencies/lint/type.
# wrapper script only cares about -n, others passed to test suite.
while getopts "cdknsx" o $FAUCET_TESTS; do
  case "${o}" in
        n)
            DEPCHECK=0
            ;;
        *)
            ;;
    esac
done

echo "========== checking IPv4/v6 localhost is up ====="
ping6 -c 1 ::1 || exit 1
ping -c 1 127.0.0.1 || exit 1

echo "========== Starting OVS ========================="
export OVS_LOGDIR=/usr/local/var/log/openvswitch
/usr/local/share/openvswitch/scripts/ovs-ctl start || exit 1
ovs-vsctl show || exit 1
ovs-vsctl --no-wait set Open_vSwitch . other_config:max-idle=50000

# enable fast reuse of ports.
sysctl -w net.netfilter.nf_conntrack_tcp_timeout_time_wait=10
sysctl -w net.ipv4.tcp_fin_timeout=10
sysctl -w net.ipv4.tcp_tw_recycle=1
sysctl -w net.ipv4.tcp_tw_reuse=1
# minimize TCP connection timeout so application layer timeouts are quicker to test.
sysctl -w net.ipv4.tcp_syn_retries=4

cd /faucet-src/tests

if [ "$DEPCHECK" == 1 ] ; then
    echo "============ Running pytype analyzer ============"
    # TODO: pytype doesn't completely understand py3 yet.
    ls -1 ../faucet/*py | parallel pytype -d import-error || exit 1
fi

echo "========== Running faucet unit tests =========="
python3 -m pytest ./test_*.py --cov faucet --doctest-modules -v --cov-report term-missing || exit 1

echo "========== Running faucet system tests =========="
python2 ./faucet_mininet_test.py -c
http_proxy="" python2 ./faucet_mininet_test.py $FAUCET_TESTS || exit 1
