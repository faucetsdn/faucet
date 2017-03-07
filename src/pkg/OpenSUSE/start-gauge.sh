#!/bin/sh
## Sample start-gauge script for reference
#T_L_S="--ctl-privkey /etc/ryu/cntlr-privkey.pem --ctl-cert /etc/ryu/cntlr-cert.pem --ca-certs /etc/ryu/switchca-cert.pem"
T_L_S=

/usr/bin/ryu-manager $T_L_S --ofp-tcp-listen-port 6654  /usr/lib/python2.7/site-packages/ryu_faucet/org/onfsdn/faucet/gauge.py
