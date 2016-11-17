#!/bin/sh
# @author Shivaram Mysore <shivaram.mysore@gmail.com>
# path to Ryu manager (likely local)
RYU_MANAGER=/usr/bin/ryu-manager
#VERBOSE=--verbose
VERBOSE=
# directory containing FAUCET application code
PYTHON_PKG_DIR=/usr/lib/python2.7/site-packages
FAUCET_APP_DIR=$PYTHON_PKG_DIR/ryu_faucet/org/onfsdn/faucet
# TCP port controller should listen on for OpenFlow switch
CONTROLLER_LISTEN_PORT=6653

echo " Starting Faucet Controller ..."
# user to run FAUCET as (must already exist)
#FAUCET_USER=faucet
# runuser does not work correctly.  Hence commenting the same out for future use
#/usr/sbin/runuser -l faucet -m -c 'screen -S FaucetController -d -m $RYU_MANAGER $VERBOSE --ofp-tcp-listen-port $CONTROLLER_LISTEN_PORT $FAUCET_APP_DIR/faucet.py'
screen -S FaucetController -d -m $RYU_MANAGER $VERBOSE --ofp-tcp-listen-port $CONTROLLER_LISTEN_PORT $FAUCET_APP_DIR/faucet.py
echo "Listing Screen process ..."
screen -list
echo "To attach to a running screen process run:"
echo "  screen -r FaucetController"
