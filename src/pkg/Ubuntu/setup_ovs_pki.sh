#!/bin/sh
## @author shivaram.mysore@gmail.com

OPENSSL=/usr/bin/openssl
PYTHON_PKG_DIR=/opt/local/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/site-packages
FAUCET_APP_DIR=$PYTHON_PKG_DIR/ryu_faucet/org/onfsdn/faucet
APP_FAUCET=$FAUCET_APP_DIR/faucet.py
# TCP port controller should listen on for OpenFlow switch
CONTROLLER_LISTEN_PORT=6653
CONTROLLER_HOST=127.0.0.1

## Default directory is /usr/local/var/lib/openvswitch/pki
## pki directory consists of controllerca and switchca subdirectories.
## Each directory contains CA files.
DEF_OVS_PKI_DIR=/var/lib/openvswitch/pki
ETC_OVS_DIR=/etc/openvswitch


echo "Initializing new PKI ... in $DEF_OVS_PKI_DIR directory"
ovs-pki init
echo ""
echo "files $DEF_OVS_PKI_DIR/controllerca/cacert.pem and $DEF_OVS_PKI_DIR/switchca/cacert.pem produced"
echo "will need to be  copied to the OpenFlow switches and controllers, respectively"
echo ""

echo "Creating controller private key and certificate ..."
cd $ETC_OVS_DIR; ovs-pki req+sign cntlr controller
## cntlr-privkey.pem and cntlr-cert.pem are generated in $ETC_OVS_DIR directory.
echo "Printing Controller Cert ..."
$OPENSSL x509 -in $ETC_OVS_DIR/cntlr-cert.pem -text -noout

echo "Creating Switch private key and certificate ..."
cd $ETC_OVS_DIR; ovs-pki req+sign switch switch
## switch-privkey.pem and switch-cert.pem are generated in the current directory.
$OPENSSL x509 -in $ETC_OVS_DIR/switch-cert.pem -text -noout

echo "Configuring ovs-vswitchd to use CA files using the ovs-vsctl  ..."
ovs-vsctl set-ssl $ETC_OVS_DIR/switch-privkey.pem $ETC_OVS_DIR/openvswitch/switch-cert.pem $DEF_OVS_PKI_DIR/controllerca/cacert.pem

echo ""
echo "Configure OVS connect to controller via TLS"
echo "ex: ovs-vsctl set-controller ovs-br0 ssl:$CONTROLLER_HOST:$CONTROLLER_LISTEN_PORT"
echo ""

echo "Running faucet with TLS"
echo "Copy $ETC_OVS_DIR/cntlr-privkey.pem, $ETC_OVS_DIR/cntlr-cert.pem and $DEF_OVS_PKI_DIR/switchca/cacert.pem files to"
echo " /etc/ryu/ directory on the controller host"
echo "ryu-manager --cntlr-privkey /etc/ryu/cntlr-privkey.pem --cntlr-cert /etc/ryu/cntlr-cert.pem \ "
echo "            --ca-certs /etc/ryu/switchca-cert.pem \ "
echo "            --ofp-tcp-listen-port $CONTROLLER_LISTEN_PORT $APP_FAUCET"
