#!/bin/sh
## @author shivaram.mysore@gmail.com

# path to Ryu manager (likely local)
RYU_MANAGER=/usr/bin/ryu-manager
#VERBOSE=--verbose
VERBOSE=
# directory containing FAUCET application code
PYTHON_PKG_DIR=/usr/lib/python2.7/site-packages
FAUCET_APP_DIR=$PYTHON_PKG_DIR/ryu_faucet/org/onfsdn/faucet
# TCP port controller should listen on for OpenFlow switch
CONTROLLER_LISTEN_PORT=6653

SCREEN="screen -S FaucetController"

RYU_CMD="$RYU_MANAGER $VERBOSE --ofp-tcp-listen-port $CONTROLLER_LISTEN_PORT $FAUCET_APP_DIR/faucet.py"

$SCREEN -X stuff 'command ^C'

echo "Clearing log files ..."
rm -f /var/log/ryu/faucet/faucet.log

echo " Starting Faucet Controller ..."
$SCREEN -d -m $RYU_CMD
#$RYU_CMD

echo "Listing Screen process ..."
screen -list
echo "To attach to a running screen process run:"
echo "  $SCREEN"
