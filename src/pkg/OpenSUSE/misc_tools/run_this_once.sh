#!/bin/sh
# @author Shivaram Mysore <shivaram.mysore@gmail.com>

pip install networkx
pip install ovs ryu
pip install https://pypi.python.org/packages/77/ba/1bf4547a58dfc41f502c0ad640d282c44d63be26f7d852dae5bc04904a51/ryu-faucet-1.2.tar.gz
pip show ryu_faucet

echo "Showing all network interfaces that are up ..."
ip link ls up
echo "Modify dpid and ports in files:"
echo "1.  /etc/ryu/faucet/faucet.yaml"

