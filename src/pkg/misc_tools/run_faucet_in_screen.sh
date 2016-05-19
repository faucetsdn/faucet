#!/bin/sh
# @author Shivaram Mysore <shivaram.mysore@gmail.com>
echo " Starting Faucet Controller ..."
screen -S FaucetController -d -m /usr/bin/ryu-manager --verbose --ofp-tcp-listen-port 6653 /usr/lib/python2.7/site-packages/ryu_faucet/org/onfsdn/faucet/faucet.py
echo " Starting Gauge Controller ..."
screen -S GaugeController -d -m /usr/bin/ryu-manager --verbose --ofp-tcp-listen-port 6654 /usr/lib/python2.7/site-packages/ryu_faucet/org/onfsdn/faucet/gauge.py
echo "Listing Screen process ..."
screen -list
echo "To attach to a running screen process run:"
echo "  screen -r FaucetController"
echo "  screen -r GaugeController"

