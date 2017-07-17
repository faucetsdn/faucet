# Test Faucet TLS using self-signed certificates on the switch

This document outlines the steps needed to test that a switch supports self-signed certificates for TLS based Openflow connections.

## Prepare the keys and certificates.
### Generate key pairs for the controller.
    /usr/bin/openssl genrsa -out /etc/ryu/ctrlr.key 2048
    /usr/bin/openssl req -new -x509 -nodes -days 3650 -subj '/C=US/ST=CA/L=Mountain View/O=Faucet/OU=Faucet/CN=CTRLR_1' -key /etc/ryu/ctrlr.key -out /etc/ryu/ctrlr.cert
### Generate key pairs for the switch.
    /usr/bin/openssl genrsa -out /etc/ryu/sw.key 2048
    /usr/bin/openssl req -new -x509 -nodes -days 3650 -subj '/C=US/ST=CA/L=Mountain View/O=Faucet/OU=Faucet/CN=SW_1' -key /etc/ryu/sw.key -out /etc/ryu/sw.cert

## Push the key pairs to the switch.
Copy /etc/ryu/ctrlr.cert /etc/ryu/sw.key and /etc/ryu/sw.cert to the switch. Configure the switch to use the keys. For example, the command for OVS would be:

    ovs-vsctl set-ssl  /etc/ryu/sw.key /etc/ryu/sw.cert  /etc/ryu/ctrlr.cert
    ovs-vsctl set-controller br0 ssl:<ctrlr_ip>:6653

## Start Faucet with the keys (make sure the keys are readable by the user that
starts the faucet process)

    ryu-manager --ctl-privkey /etc/ryu/ctrlr.key --ctl-cert /etc/ryu/ctrlr.cert  --ca-certs /etc/ryu/sw.cert faucet.faucet --verbose

## Support multiple switches
To support multiple switches, generate key pairs for each switch, and concatenate their certificates into one file and use that file as */etc/ryu/sw.cert*.
