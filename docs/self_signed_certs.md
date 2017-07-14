# Test Faucet TLS using self-signed certificates on the switch

This document outlines the steps needed to test that a switch supports self-signed certificates for TLS based Openflow connections.

## Prepare the keys and certificates.
### Generate key pairs for the controller.
    /usr/bin/openssl genrsa -out /tmp/ctrlr.key 2048
    /usr/bin/openssl req -new -x509 -nodes -days 3650 -subj '/C=US/ST=CA/L=Mountain View/O=Faucet/OU=Faucet/CN=CTRLR_1' -key /tmp/ctrlr.key -out /tmp/ctrlr.cert
### Generate key pairs for the switch.
    /usr/bin/openssl genrsa -out /tmp/sw.key 2048
    /usr/bin/openssl req -new -x509 -nodes -days 3650 -subj '/C=US/ST=CA/L=Mountain View/O=Faucet/OU=Faucet/CN=SW_1' -key /tmp/sw.key -out /tmp/sw.cert

## Push the key pairs to the switch.
Copy /tmp/ctrlr.cert /tmp/sw.key and /tmp/sw.cert to the switch. Configure the switch to use the keys. For example, the command for OVS would be:

    ovs-vsctl set-ssl  /tmp/sw.key /tmp/sw.cert  /tmp/ctrlr.cert
    ovs-vsctl set-controller br0 ssl:<ctrlr_ip>:6653

## Start Faucet with the keys:
    ryu-manager --ctl-privkey /tmp/ctrlr.key --ctl-cert /tmp/ctrlr.cert  --ca-certs /tmp/sw.cert faucet.faucet --verbose 
