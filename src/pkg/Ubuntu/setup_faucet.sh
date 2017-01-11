#!/bin/sh
## @authors: joshb@google.com, shivaram.mysore@gmail.com

echo "Run this program $0 as root"
pip install ryu-faucet

FAUCET_USER=faucet
FAUCET_SERVICE=/etc/systemd/system/faucet.service
FAUCET_START_SCRIPT=~$FAUCET_USER/start-faucet.sh

FAUCET_PKG_LOC=`pip show ryu-faucet | grep Location | cut -d':' -f2`
FAUCET_PY=`pip show -f ryu-faucet | grep -w "faucet.py" | sed -e 's/^[ \t]*//'`
FAUCET_APP=$FAUCET_LOC/$FAUCET_PY

RYU_MANAGER=ryu-manager
CONTROLLER_LISTEN_PORT=6653


useradd $FAUCET_USER
sudo -E -u echo -e "#!/bin/sh\nRYU_MANAGER=ryu-manager\nCONTROLLER_LISTEN_PORT=6653\nFAUCET_APP=$FAUCET_APP\n$RYU_MANAGER --ofp-tcp-listen-port $CONTROLLER_LISTEN_PORT $FAUCET_APP" >> $FAUCET_START_SCRIPT

touch $FAUCET_SERVICE
echo -e "[Unit]\ndescription="FAUCET OpenFlow switch controller"\nAfter=network-online.target\nWants=network-online.target" >> $FAUCET_SERVICE
echo -e "\n[Service]\nExecStart=$FAUCET_START_SCRIPT\nRestart=always" >> $FAUCET_SERVICE
echo -e "\n[Install]\nWantedBy=multi-user.target" >> $FAUCET_SERVICE

systemctl enable systemd-networkd-wait-online.service
systemctl enable faucet

echo -e "\nFaucet service usage: systemctl [start|status] faucet"
