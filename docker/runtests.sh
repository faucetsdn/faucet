#!/bin/bash
echo "================= Starting OVS =================="
service openvswitch-switch start

cd /faucet-src/tests

echo "=========== Running faucet unit tests ==========="
./faucet_mininet_test.py -c
time ./faucet_mininet_test.py

echo "========== Running faucet config tests =========="
./test_config.py
