#!/bin/bash
echo "================= Starting OVS =================="
service openvswitch-switch start

cd /faucet-src/tests

echo "========== Running faucet config tests =========="
python3 ./test_config.py || exit 1
python3 ./test_check_config.py || exit 1

echo "=========== Running faucet unit tests ==========="
python3 ./test_valve.py || exit 1

echo "=========== Running faucet system tests ==========="
python2 ./faucet_mininet_test.py -c
time ./faucet_mininet_test.py $FAUCET_TESTS || exit 1
