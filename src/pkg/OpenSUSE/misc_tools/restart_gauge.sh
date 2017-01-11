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
CONTROLLER_LISTEN_PORT=6654
OFP_LISTEN_PORT=--ofp-tcp-listen-port
#OFP_LISTEN_PORT=--ofp-ssl-listen-port

SCREEN=screen
SCR_CONTRL_NAME=GaugeController

#VERBOSE=--verbose
VERBOSE=

RYU_CMD="$RYU_MANAGER $VERBOSE $OFP_LISTEN_PORT $CONTROLLER_LISTEN_PORT $FAUCET_APP_DIR/gauge.py"

$SCREEN -S $SCR_CONTRL_NAME -X stuff 'command ^C'

echo "Clearing log files ..."
rm -f /var/log/ryu/faucet/gauge.log

echo " Starting Faucet Controller ..."
$SCREEN -S $SCR_CONTRL_NAME -d -m $RYU_CMD
#$RYU_CMD

echo "Listing Screen process ..."
screen -list
echo "To attach to a running screen process run:"
echo "  $SCREEN -r $SCR_CONTRL_NAME"
