#!/bin/sh
# @author Shivaram Mysore <shivaram.mysore@gmail.com>

pip install networkx
pip install ovs ryu
pip install ryu-faucet
pip show ryu_faucet

echo "Showing all network interfaces that are up ..."
ip link ls up
echo "Modify dpid and ports in files:"
echo "1.  /etc/ryu/faucet/faucet.yaml"
