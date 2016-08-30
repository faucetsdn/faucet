Faucet Test tool
------------------------

This tool is to test Faucet functions using OpenFlow 1.3 OpenVSwitch on Mininet.

If you interrupt the test process or it crashes during testing interfaces, processes and openvswitch configuration used for testing
may be left over on the system. You can run the test script in cleanup mode to tidy the system of leftover mininet objects:

```$ sudo ./faucet_mininet_test.py --clean```


Requirement(s)
------------------------
Ryu_faucet

Mininet 2.2.1


Procedure
------------------------
**FaucetUntaggedTest:**
        Test reachability of 4 hosts on untagged vlan 100 using different physical port using pingall.

        Pass Condition : Every hosts can reach the every other hosts using ARP.

**FaucetUntaggedNoVLanUnicaseFloodTest:**
        Test reachability of 4 hosts on untagged vlan 100 using different physical port using pingall with unicast_flood disabled.

        Pass Condition : Every hosts can reach the every other hosts using ARP.

**FaucetUntaggedHostMoveTest:**
        Test reachability of two hosts on untagged vlan 100 when their Mac addresses are swapped over.

        Pass Condition: Every hosts can reach to every other hosts initially using ARP and after their mac addresses are swapped.

**FaucetUntaggedHostPermanentLearnTest:**
        Test reachability of four hosts on untagged vlan 100 when one hosts have permanent_learn and another host uses the one's mac address.

        Pass Condition: Every hosts can reach to every other hosts initially using ARP and after the thrid host changed the mac address to the first host, the secon\
d host cannot reach the thrid host but the first host can reach the second host.

**FaucetUntaggedControlPlaneTest:**
        Test reachablility of the controller from one of the host.

        Pass Condition : The first host can ping the controller, which uses 10.0.0.254.

**FaucetTaggedAndUntaggedTest:**
        Test reachability of 4 hosts where 2 hosts are in vlan 100 tagged and vlan 101 untagged.

        Pass Condition : Hosts within the same vlan can reach each other using ARP, but not to hosts in other vlan.

**FaucetUntaggedACLTest:**
        Test reachability of two hosts where one of the port connected to the host has acl applied to drop IPv4 packet with destination port is 5001, but allow all \
other ports.

        Pass Condition: The second host cannot receive TCP message to the first host on port 5001, but can receive TCP message on port 5002.

**FaucetUntaggedMirrorTest:**
        Test Mirror port functionality.

        Pass Condition: A mirror port can receive ARP packets that are sent from two other hosts connected to the switch.

**FaucetTaggedTest:**
        Test reachability of 4 hosts on tagged vlan 100 using different physical port using pingall.

        Pass Condition : Every hosts can reach the every other hosts using ARP.
