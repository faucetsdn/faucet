Continues on from https://faucet.readthedocs.io/en/latest/tutorials.html
Next we are going to introduce ACLs.

ETA: ~25 mins.

Note:
tcpdump is used to capture packets, sometimes it may be nescessary to exit tcpdump (ctrl + c) before packet output is shown.
unless stated tcpdump will be used with ping and it should only be nescassry to run both for ~10 seconds.


First we will add two new hosts to our network:
```bash
create_ns host3 192.168.0.3/24
create_ns host4 192.168.0.4/24
```
and connect them to br0
```bash
sudo ovs-vsctl add-port br0 veth-host3 -- set interface veth-host3 ofport_request=3 -- add-port br0 veth-host4 -- set interface veth-host4 ofport_request=4
```

The configurtaion below will block ICMP on traffic coming in on port 3, and allow everything else.
Add this to /etc/faucet/faucet.yaml below the 'dps'.
```yaml
            3:
                name: "host3"
                native_vlan: office
                acls_in: [block-ping, allow-all]
            4:
                name: "host4"
                native_vlan: office


acls:
    block-ping:
        - rule:
            dl_type: 0x800      # IPv4
            ip_proto: 1         # ICMP
            actions:
                allow: False
        - rule:
            dl_type: 0x86dd     # IPv6
            ip_proto: 58        # ICMPv6
            actions:
                allow: False

    allow-all:
        - rule:
            actions:
                allow: True
```

Faucet ACLs are made up of lists of rules.
The order of the rules in the list denote the prioirty with the first rules being highest and last lowest.
Each of these lists has a name (e.g. 'block-ping'), and can be used on multiple port or VLAN 'acls_in' fields.
Again these are applied in order so all of 'block-ping' rules will be higher than 'allow-all'.

Each rule contains two main items 'matches' and 'actions'.
Matches are any packet field such as MAC/IP/transport source/destination fields.
For a full list visit https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#flow-match-structure
Actions are used to control what the packet does, for example normal l2 forwarding ('allow'). apply a 'meter' to rate limit traffic, and manpulation of the packet contents and output.
Full list https://faucet.readthedocs.io/en/latest/configuration.html#id13

The above example has defined two ACLs 'block-ping' & 'allow-all' these can be used on any and multiple ports or VLANs (more on VLANs later) using the 'acls_in' key.
The block-ping ACL has two rules, one to block ICMP on IPv4 and another for ICMPv6 on IPv6.
The allow-all ACL has one rule, which specifies no match fields, and therefore matches all packets, and the action 'allow'.
The 'allow' action is a boolean, if it's True allow the packet to continue through the Faucet pipeline, if False drop the packet.
'allow' can be used in conjunction with the other actions to let the traffic flow with the expected layer 2 forwarding behaviour AND be mirrored to another port.


Now tell Faucet to reload its configuration, this can be done be restarting the application.
But a better way is to send Faucet a SIGHUP signal.

```bash
check_faucet_config /etc/faucet/faucet.yaml
```

```bash
pkill -HUP -f faucet.faucet
```

Now pings to/from host3 should fail, but the other three hosts should be fine.

Test this with
```bash
as_ns host1 ping 192.168.0.3
as_ns host1 ping 192.168.0.4
```



Mirror:
Mirroring traffic is useful if we want to send it to an out of band NFV service (e.g. Intrusion Detection System, packet capture the traffic).
To do this Faucet provides two ACL actions: mirror & output.

The mirror action copies the packet, before any modifications, to the specified port (NOTE: mirroring is done in input direction only).

Let's add the mirror action to our block-ping ACL /etc/faucet/faucet.yaml
```yaml
...
block-ping:
    - rule:
        dl_type: 0x800
        ip_proto: 1
        actions:
            allow: False
            mirror: 4
    - rule:
        dl_type: 0x86dd
        ip_proto: 58
        actions:
            allow: False
            mirror: 4
```

And again send the sighup signal to Faucet
```bash
pkill -HUP -f faucet.faucet
```

To check this we will ping from host1 to host3, while performing a tcpdump on host4 who should receive the ping replies.
It is a good idea to run each from a different terminal (screen, tmux, ...)

```bash
as_ns host1 ping 192.168.0.3
```
Ping should have 100% packet loss.

```bash
as_ns host4 tcpdump -e -n -i veth0
```
```bash
$ as_ns host4 tcpdump -e -n -i veth0
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on veth0, link-type EN10MB (Ethernet), capture size 262144 bytes
13:24:36.848331 2e:d4:1a:ca:54:4b > 06:5f:14:fc:47:02, ethertype IPv4 (0x0800), length 98: 192.168.0.3 > 192.168.0.1: ICMP echo reply, id 23660, seq 16, length 64
13:24:37.857024 2e:d4:1a:ca:54:4b > 06:5f:14:fc:47:02, ethertype IPv4 (0x0800), length 98: 192.168.0.3 > 192.168.0.1: ICMP echo reply, id 23660, seq 17, length 64
13:24:38.865005 2e:d4:1a:ca:54:4b > 06:5f:14:fc:47:02, ethertype IPv4 (0x0800), length 98: 192.168.0.3 > 192.168.0.1: ICMP echo reply, id 23660, seq 18, length 64
13:24:39.873377 2e:d4:1a:ca:54:4b > 06:5f:14:fc:47:02, ethertype IPv4 (0x0800), length 98: 192.168.0.3 > 192.168.0.1: ICMP echo reply, id 23660, seq 19, length 64
13:24:40.881129 2e:d4:1a:ca:54:4b > 06:5f:14:fc:47:02, ethertype IPv4 (0x0800), length 98: 192.168.0.3 > 192.168.0.1: ICMP echo reply, id 23660, seq 20, length 64
```


There is also the 'output' action which can be used to acheive the same thing.

```yaml
block-ping:
    - rule:
        dl_type: 0x800
        ip_proto: 1
        actions:
            allow: False
            output:
                port: 4
    - rule:
        dl_type: 0x86dd
        ip_proto: 58
        actions:
            allow: False
            output:
                port: 4
```



The output action also allows us to change the packet by setting fields (mac/ip addresses, ...), VLAN operations (push/pop/swap VIDs).
It can be used in conjunction with the other actions, e.g. output directly and but do not allow through the Faucet pipeline (allow: false).

Let's create a new ACL for host2's port that will change the MAC source address.

/etc/faucet/faucet.yaml
```yaml
dps:
    sw1:
        ...
        2:
            name: "host2"
            description: "host2 network namespace"
            native_vlan: office
            acls_in: [rewrite-mac, allow-all]

        ...

acls:
    rewrite-mac:
        - rule:
            actions:
                allow: True
                output:
                    set_fields:
                        - eth_src: "00:00:00:00:00:02"
...
```

again reload Faucet.

Start tcpdump on host1
```bash
as_ns host1 tcpdump -e -n -i veth0
```
ping host1 from host2
```bash
as_ns host2 ping 192.168.0.1
```
Here we can see ICMP echo requests are coming from the MAC address "00:00:00:00:00:02" that we set in our output ACL.
(The reply is destined to the actual MAC address of host2 thanks to ARP) [TODO i think].
```bash
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on veth0, link-type EN10MB (Ethernet), capture size 262144 bytes
13:53:41.248235 00:00:00:00:00:02 > 06:5f:14:fc:47:02, ethertype IPv4 (0x0800), length 98: 192.168.0.2 > 192.168.0.1: ICMP echo request, id 23711, seq 1, length 64
13:53:41.248283 06:5f:14:fc:47:02 > ce:bb:23:ce:d5:a0, ethertype IPv4 (0x0800), length 98: 192.168.0.1 > 192.168.0.2: ICMP echo reply, id 23711, seq 1, length 64
13:53:42.247106 00:00:00:00:00:02 > 06:5f:14:fc:47:02, ethertype IPv4 (0x0800), length 98: 192.168.0.2 > 192.168.0.1: ICMP echo request, id 23711, seq 2, length 64
13:53:42.247154 06:5f:14:fc:47:02 > ce:bb:23:ce:d5:a0, ethertype IPv4 (0x0800), length 98: 192.168.0.1 > 192.168.0.2: ICMP echo reply, id 23711, seq 2, length 64
13:53:43.249726 00:00:00:00:00:02 > 06:5f:14:fc:47:02, ethertype IPv4 (0x0800), length 98: 192.168.0.2 > 192.168.0.1: ICMP echo request, id 23711, seq 3, length 64
13:53:43.249757 06:5f:14:fc:47:02 > ce:bb:23:ce:d5:a0, ethertype IPv4 (0x0800), length 98: 192.168.0.1 > 192.168.0.2: ICMP echo reply, id 23711, seq 3, length 64
13:53:44.248713 00:00:00:00:00:02 > 06:5f:14:fc:47:02, ethertype IPv4 (0x0800), length 98: 192.168.0.2 > 192.168.0.1: ICMP echo request, id 23711, seq 4, length 64
13:53:44.248738 06:5f:14:fc:47:02 > ce:bb:23:ce:d5:a0, ethertype IPv4 (0x0800), length 98: 192.168.0.1 > 192.168.0.2: ICMP echo reply, id 23711, seq 4, length 64
```


With the output action we could also use it to mirror traffic to a NFV server (like our fake mirror output action above), and use a VLAN tag to identify what port the traffic originated on on the switch.
To do this we will use both the 'port' & 'vlan_vid' output fields.

```yaml
block-ping:
    - rule:
        dl_type: 0x800
        ip_proto: 1
        actions:
            allow: False
            output:
                vlan_vid: 3
                port: 4
    - rule:
        dl_type: 0x86dd
        ip_proto: 58
        actions:
            allow: False
            output:
                vlan_vid: 3
                port: 4
```

Again reload Faucet, start a tcpdump on host4, and ping from host1 to host3.
Ping should still not be allowed through and the TCPDump output should be similar to below (Note the 802.1Q tag and vlan 3):
```bash
$ as_ns host4 tcpdump -e -n -i veth0
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on veth0, link-type EN10MB (Ethernet), capture size 262144 bytes
14:14:15.285329 2e:d4:1a:ca:54:4b > 06:5f:14:fc:47:02, ethertype 802.1Q (0x8100), length 102: vlan 3, p 0, ethertype IPv4, 192.168.0.3 > 192.168.0.1: ICMP echo reply, id 23747, seq 1, length 64
14:14:16.293016 2e:d4:1a:ca:54:4b > 06:5f:14:fc:47:02, ethertype 802.1Q (0x8100), length 102: vlan 3, p 0, ethertype IPv4, 192.168.0.3 > 192.168.0.1: ICMP echo reply, id 23747, seq 2, length 64
14:14:17.300898 2e:d4:1a:ca:54:4b > 06:5f:14:fc:47:02, ethertype 802.1Q (0x8100), length 102: vlan 3, p 0, ethertype IPv4, 192.168.0.3 > 192.168.0.1: ICMP echo reply, id 23747, seq 3, length 64
```
