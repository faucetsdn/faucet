#!/bin/bash
echo "========== Starting OVS ========================="
service openvswitch-switch start

ovs-vsctl show || exit 1

cd /faucet-src/tests

echo "========== Running faucet unit tests =========="
py.test ./test_check_config.py ./test_config.py ./test_valve.py --cov faucet --doctest-modules -v --cov-report term-missing

echo "============ Running pytype analyzer ============"
# TODO: pytype doesn't completely understand py3 yet.
ls -1 ../faucet/*py | parallel --bar pytype -d import-error || exit 1

echo "========== Running faucet system tests =========="
python2 ./faucet_mininet_test.py -c
time python2 ./faucet_mininet_test.py $FAUCET_TESTS || exit 1
