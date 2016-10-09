#!/bin/sh
## @author shivaram.mysore@gmail.com

SCREEN="screen -S GaugeController"

#VERBOSE=--verbose
VERBOSE=

RYU_CMD="/usr/bin/ryu-manager $VERBOSE --ofp-tcp-listen-port 6654 /usr/lib/python2.7/site-packages/ryu_faucet/org/onfsdn/faucet/gauge.py"

$SCREEN -X stuff 'command ^C'

echo "Clearing log files ..."
rm -f /var/log/ryu/faucet/gauge.log

echo " Starting Faucet Controller ..."
$SCREEN -d -m $RYU_CMD
#$RYU_CMD

echo "Listing Screen process ..."
screen -list
echo "To attach to a running screen process run:"
echo "  screen -r GaugeController"

