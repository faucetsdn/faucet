#!/bin/bash
echo "================= Starting OVS =================="
service openvswitch-switch start

cd /faucet-src/tests

echo "=========== Running faucet unit tests ==========="
time python -m unittest -v faucet_mininet_test

echo "========== Running faucet config tests =========="
python test_config.py
