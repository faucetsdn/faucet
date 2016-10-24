#!/bin/sh
# @author Shivaram Mysore <shivaram.mysore@gmail.com>

pip install networkx
pip install ovs ryu
pip install https://pypi.python.org/packages/f5/f3/a8c4e72b4218be5aa84378eb57d89cfc8153efdb4df998cd2a0c544a878a/ryu-faucet-1.2.tar.gz
pip show ryu_faucet

echo "Showing all network interfaces that are up ..."
ip link ls up
echo "Modify dpid and ports in files:"
echo "1.  /etc/ryu/faucet/faucet.yaml"

