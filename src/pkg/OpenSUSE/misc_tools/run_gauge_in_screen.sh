#!/bin/sh
# @author Shivaram Mysore <shivaram.mysore@gmail.com>
# path to Ryu manager (likely local)
RYU_MANAGER=/usr/bin/ryu-manager
VERBOSE=--verbose
#VERBOSE=
# user to run FAUCET as (must already exist)
FAUCET_USER=faucet
# directory containing FAUCET application code
FAUCET_APP_DIR=/usr/lib/python2.7/site-packages/ryu_faucet/org/onfsdn/faucet
# host address FAUCET controller should listen on for OpenFlow switch
CONTROLLER_LISTEN_HOST=127.0.0.1
# TCP port controller should listen on for OpenFlow switch
CONTROLLER_LISTEN_PORT=6654
# location of FAUCET's configuration file.
CONFIG_DIR=/etc/ryu/faucet
GAUGE_CONFIG=$CONFIG_DIR/gauge.conf
# where FAUCET should log to (directory must exist and be writable by FAUCET_USER)
FAUCET_LOG_DIR=/var/log/ryu/faucet
GAUGE_LOG=$FAUCET_LOG_DIR/gauge.log
# where FAUCET should log exceptions to (directory must exist as above)
GAUGE_EXCEPTION_LOG=$FAUCET_LOG_DIR/gauge_exception.log


echo " Starting Gauge Controller ..."
/usr/sbin/runuser -l faucet -m -c 'screen -S GaugeController -d -m $RYU_MANAGER $VERBOSE --ofp-tcp-listen-port $CONTROLLER_LISTEN_PORT $FAUCET_APP_DIR/gauge.py'
echo "Listing Screen process ..."
screen -list
echo "To attach to a running screen process run:"
echo "  screen -r GaugeController"

