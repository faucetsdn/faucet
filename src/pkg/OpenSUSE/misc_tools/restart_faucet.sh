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

RYU_CFG_DIR=/etc/ryu
CNTLR_PRIV_KEY=$RYU_CFG_DIR/cntlr-privkey.pem
CNTLR_CERT=$RYU_CFG_DIR/cntlr-cert.pem
SWITCH_CACERT=$RYU_CFG_DIR/switchca-cert.pem
#TLS="--ctl-privkey $CNTLR_PRIV_KEY --ctl-cert $CNTLR_CERT --ca-certs $SWITCH_CACERT"
TLS=
OFP_LISTEN_PORT=--ofp-tcp-listen-port
#OFP_LISTEN_PORT=--ofp-ssl-listen-port

SCREEN="screen -S FaucetController"

$SCREEN -X stuff 'command ^C'

echo "Clearing log files ..."
rm -f /var/log/ryu/faucet/faucet.log

echo " Starting Faucet Controller ..."
$SCREEN -d -m $RYU_MANAGER $VERBOSE $TLS $OFP_LISTEN_PORT $CONTROLLER_LISTEN_PORT $FAUCET_APP_DIR/faucet.py
#$RYU_CMD

echo "Listing Screen process ..."
screen -list
echo "To attach to a running screen process run:"
echo "  $SCREEN"
