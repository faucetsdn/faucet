#!/bin/sh
# @author Shivaram Mysore <shivaram.mysore@gmail.com>

pip install --upgrade pip
pip install networkx ovs ryu ryu-faucet
pip show ryu-faucet

echo "Showing all network interfaces that are up ..."
ip link ls up
echo "Modify dpid and ports in files:"
echo "1.  /etc/ryu/faucet/faucet.yaml"
