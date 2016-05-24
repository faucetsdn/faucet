#!/bin/bash
service openvswitch-switch start
cd /tests
time python -m unittest -v faucet_mininet_test
echo "======================================"
export PYTHONPATH=$PYTHONPATH:/usr/local/lib/python2.7/dist-packages/ryu_faucet/org/onfsdn/faucet/
python test_config.py
