#TODO maybe setup everything and config except the routing stuff first. and show cannot ping between the two subnets?

This tutorial will cover routing with Faucet.

There are three types of routing we can use.
- Inter VLAN routing
- Static routing
- BGP via an external application (Quagga, Bird, EXABGP, ...)

This tutorial expands on [installing Faucet for the first time](https://faucet.readthedocs.io/en/latest/tutorials.html).
See there for how to install and setup Faucet and OVS.

For this tutorial it is a good idea to use a terminal multiplexer (screen, tmux or just multiple terminal sessions), as we will be running multiple applications at the same time.
# TODO maybe add a prefix to the code block on which terminal it should be executed??

## Routing between vlans
Let's start with a single switch connected to two hosts in two different vlans.
![vlan routing diagram](vlan-routing.svg)
```bash
create_ns host1 10.0.0.254/24
create_ns host2 10.0.1.254/24
sudo ovs-vsctl add-br br1 \
-- set bridge br1 other-config:datapath-id=0000000000000001 \
-- set bridge br1 other-config:disable-in-band=true \
-- set bridge br1 fail_mode=secure \
-- add-port br1 veth-host1 -- set interface veth-host1 ofport_request=2 \
-- add-port br1 veth-host2 -- set interface veth-host2 ofport_request=3 \
-- set-controller br1 tcp:127.0.0.1:6653 tcp:127.0.0.1:6654
```


To allow traffic between vlans we use a router, and assign each VLAN at least one IP address (gateway IP address).
Lets add the routers and vlans section like so.

/etc/faucet/faucet.yaml
```yaml
vlans:
    vlan100:
        vid: 100
        faucet_vips: ["10.0.0.254/24"]
    vlan200:
        vid: 200
        faucet_vips: ["10.0.1.254/24"]

routers:
    router-1:
        vlans: [vlan100, vlan200]

dps:
    sw1:
        dp_id: 0x1
        hardware: "Open vSwitch"
        interfaces:
            1:
                name: "host1"
                description: "host1 network namespace"
                native_vlan: vlan100
            2:
                name: "host2"
                description: "host2 network namespace"
                native_vlan: vlan200
```
Send SIGHUP signal to reload the configuration file.
```
sudo pkill -HUP -f faucet.faucet
```
Add the default route to the 'faucet_vips' as above.
```bash
as_ns host1 ip route add default via 10.0.0.254 veth0
as_ns host2 ip route add default via 10.0.1.254 veth0
```
Then make some traffic between our two hosts.
```bash
as_ns host1 ping 10.0.1.2
```
It should work and traffic should go through.


## Static Routing
For this we will setup two Faucet switches with two hosts each

h1 --- sw1 --- sw2 --- h3
h2 ---/           \--- h4
![static routing network diagram](./static-routing.svg)
Run the cleanup script to remove old namespaces and switches.
```bash
cleanup
```

Create 4 hosts, in 2 diffferent subnets:
```bash
create_ns host1 10.0.0.1/24
create_ns host2 10.0.0.2/24
create_ns host3 10.0.1.3/24
create_ns host4 10.0.1.4/24
```

And add a default route for each host to it's gateway router.
```bash
as_ns host1 ip route add default via 10.0.0.254
as_ns host2 ip route add default via 10.0.0.254
as_ns host3 ip route add default via 10.0.1.254
as_ns host4 ip route add default via 10.0.1.254
```

Create the 2 bridges and add hosts 1 & 2 to br1 and 3 & 4 to br2.
```bash
sudo ovs-vsctl add-br br1 \
-- set bridge br1 other-config:datapath-id=0000000000000001 \
-- set bridge br1 other-config:disable-in-band=true \
-- set bridge br1 fail_mode=secure \
-- add-port br1 veth-host1 -- set interface veth-host1 ofport_request=2 \
-- add-port br1 veth-host2 -- set interface veth-host2 ofport_request=3 \
-- set-controller br1 tcp:127.0.0.1:6653 tcp:127.0.0.1:6654

sudo ovs-vsctl add-br br2 \
-- set bridge br2 other-config:datapath-id=0000000000000002 \
-- set bridge br2 other-config:disable-in-band=true \
-- set bridge br2 fail_mode=secure \
-- add-port br2 veth-host3 -- set interface veth-host3 ofport_request=2 \
-- add-port br2 veth-host4 -- set interface veth-host4 ofport_request=3 \
-- set-controller br2 tcp:127.0.0.1:6653 tcp:127.0.0.1:6654
```

Finally connect the two bridges together with an OVS 'patch-port'
```bash
sudo ovs-vsctl add-port br1 br1-br2 -- set interface br1-br2 ofport_request=1 \
-- set interface br1-br2 type=patch -- set interface br1-br2 options:peer=br2-br1 \
-- add-port br2 br2-br1 -- set interface br2-br1 ofport_request=1 \
-- set interface br2-br1 type=patch -- set interface br2-br1 options:peer=br1-br2
```

For this Faucet configuration we will start from scratch.
First we need to define 4 VLANs.
1. br1's hosts.
2. br1's link local address to the 'remote' router (br2)
3. br2's link local address to the 'remote' router (br1)
4. br2's hosts.

Here we have 3 new options:
- faucet_mac: The MAC address of Faucet's routing interface on this VLAN.
If we do not set faucet_mac for each VLAN, routed packets will be dropped unless 'drop_spoofed_faucet_mac' is set to false.
TODO explain above more.
- faucet_vips: The IP address for Faucet's routing interface on this VLAN.
Multiple IP addresses (IPv4 & IPv6) can be used.
- routes: Static routes for this VLAN.


```yaml
vlans:
    br1-hosts:
        vid: 100
        description: "h1 & h2's vlan"
        faucet_mac: "00:00:00:00:00:11"
        faucet_vips: ["10.0.0.254/24"]

    br1-peer:
        vid: 200
        description: "vlan for peering port"
        faucet_mac: "00:00:00:00:00:22"
        faucet_vips: ["192.168.1.1/24"]
        routes:
            - route:
                ip_dst: "10.0.1.0/24"
                ip_gw: '192.168.1.2'

    br2-peer:
        vid: 300
        description: "vlan for peering port"
        faucet_mac: "00:00:00:00:00:33"
        faucet_vips: ["192.168.1.2/24"]
        routes:
            - route:
                ip_dst: "10.0.0.0/24"
                ip_gw: "192.168.1.1"

    br2-hosts:
        vid: 400
        description: "h3 & h4's vlan"
        faucet_mac: "00:00:00:00:00:44"
        faucet_vips: ["10.0.1.254/24"]
```

As our routing interface is in a different VLAN, we will want to route between the two VLANs on the switch (br1-hosts & br1-peer).
So as with inter VLAN routing we will create a router for each switch.
```yaml
routers:
    router-br1:
        vlans: [br1-hosts, br1-peer]
    router-br2:
        vlans: [br2-hosts, br2-peer]
```
And the rest of the config looks like this:
```yaml
dps:
    br1:
        dp_id: 0x1
        hardware: "Open vSwitch"
        interfaces:
            1:
                name: "br2"
                description: "connects to br2"
                native_vlan: br1-peer
            2:
                name: "host1"
                description: "host1 network namespace"
                native_vlan: br1-hosts
            3:
                name: "host2"
                description: "host2 network namespace"
                native_vlan: br1-hosts
    br2:
        dp_id: 0x2
        hardware: "Open vSwitch"
        interfaces:
            1:
                name: "br1"
                description: "connects to br1"
                native_vlan: br2-peer
            2:
                name: 'host3'
                description: "host3 network namespace"
                native_vlan: br2-hosts
            3:
                name: "host4"
                description: "host4 network namespace"
                native_vlan: br2-hosts
```



Start/reload Faucet.
```
sudo systemctl restart faucet
```

and we should now be able to ping (the first few packets may get lost as ?arp? does it's thing).
```bash
root@ubuntu:~# as_ns host1 ping 10.0.1.3
PING 10.0.1.3 (10.0.1.3) 56(84) bytes of data.
64 bytes from 10.0.1.3: icmp_seq=2 ttl=62 time=0.625 ms
64 bytes from 10.0.1.3: icmp_seq=3 ttl=62 time=0.133 ms
64 bytes from 10.0.1.3: icmp_seq=4 ttl=62 time=0.064 ms
64 bytes from 10.0.1.3: icmp_seq=5 ttl=62 time=0.090 ms
```

## BGP Routing
For this section we are going to change our static routes from above into BGP routes.
To do this each switch will become it's own Autonomous System (AS).
Each switch will therefore be controlled by a separate Faucet.

BGP (and other routing) is provided by a NFV service, here we will use [BIRD](http://bird.network.cz/).
Other applications such as ExaBGP & Quagga could be used.

If you are NOT using the workshop VM you will need to install BIRD.

To install BIRD:
```bash
apt-get install flex bison libncurses5-dev libreadline-dev
wget ftp://bird.network.cz/pub/bird/bird-1.6.4.tar.gz
tar -xf bird-1.6.4.tar.gz
cd bird1.6.4
 ./configure
make
make install
```

Our dataplane will end up looking like this:
![BGP network diagram](bgp-dataplane.svg)

Note 1:
When using BGP and Faucet, if changing Faucet's routing configuration (routers, static routes, or a VLAN's BGP config) the Faucet application must be restarted to reload the configuration (not sighup reloaded).


First we will remove the routing configuration and separate the two datapath configs into there own files.
They should look like this.

sw1-faucet.yaml
```yaml
vlans:
    br1-hosts:
        vid: 100
        description: "h1 & h2's vlan"
        faucet_mac: "00:00:00:00:00:11"
        faucet_vips: ["10.0.0.254/24"]

    br1-peer:
        vid: 200
        description: "vlan for peering port"
        faucet_mac: "00:00:00:00:00:22"
        faucet_vips: ["192.168.1.1/24"]

dps:
    br1:
        dp_id: 0x1
        hardware: "Open vSwitch"
        interfaces:
            1:
                name: "br2"
                description: "connects to br2"
                native_vlan: br1-peer
            2:
                name: "host1"
                description: "host1 network namespace"
                native_vlan: br1-hosts

            3:
                name: "host2"
                description: "host2 network namespace"
                native_vlan: br1-hosts
```

sw2-faucet.yaml
```yaml
vlans:
    br2-peer:
        vid: 300
        description: "vlan for peering port"
        faucet_mac: "00:00:00:00:00:33"
        faucet_vips: ["192.168.1.2/24"]

    br2-hosts:
        vid: 400
        description: "h3 & h4's vlan"
        faucet_mac: "00:00:00:00:00:44"
        faucet_vips: ["10.0.1.254/24"]
dps:
    br2:
        dp_id: 0x2
        hardware: "Open vSwitch"
        interfaces:
            1:
                name: "br2"
                description: "connects to br2"
                native_vlan: br2-peer
            2:
                name: "host1"
                description: "host1 network namespace"
                native_vlan: br2-hosts

            3:
                name: "host2"
                description: "host2 network namespace"
                native_vlan: br2-hosts
```


Before we start the Faucets, we will need to change the OpenFlow port for sw2 to the port Faucet2 will be listening on.
```bash
sudo ovs-vsctl set-controller br2 tcp:127.0.0.1:6650
```
And stop the system Faucet
```bsah
sudo systemctl stop faucet
```

And now we can start the Faucets (start them in different terminals, we will need to restart them later).
```bash
$ sudo env FAUCET_CONFIG=/home/ubuntu/sw1-faucet.yaml FAUCET_LOG=/var/log/faucet/sw1-faucet.log faucet
$ sudo env FAUCET_CONFIG=/home/ubuntu/sw2-faucet.yaml FAUCET_LOG=/var/log/faucet/sw2-faucet.log  FAUCET_PROMETHEUS_PORT=9304 faucet --ryu-ofp-tcp-listen-port=6650
```

Check the logs to confirm the two switches have connected to the correct Faucet.
```bash
$ cat /var/log/faucet/sw2-faucet.log

May 03 10:51:57 faucet INFO     Loaded configuration from /home/ubuntu/sw2-faucet.yaml
May 03 10:51:57 faucet INFO     Add new datapath DPID 2 (0x2)
May 03 10:51:58 faucet.valve INFO     DPID 2 (0x2) Cold start configuring DP
May 03 10:51:58 faucet.valve INFO     DPID 2 (0x2) Configuring VLAN br2-hosts vid:400 ports:Port 2,Port 3
May 03 10:51:58 faucet.valve INFO     DPID 2 (0x2) Configuring VLAN br2-peer vid:300 ports:Port 1
May 03 10:51:58 faucet.valve INFO     DPID 2 (0x2) Port 1 configured
May 03 10:51:58 faucet.valve INFO     DPID 2 (0x2) Port 2 configured
May 03 10:51:58 faucet.valve INFO     DPID 2 (0x2) Port 3 configured
May 03 10:51:58 faucet.valve INFO     DPID 2 (0x2) Ignoring port:4294967294 not present in configuration file
```

And check that host1 can ping host2 but not host3 or host4.
```bash
$ as_ns host1 ping 10.0.0.2
$ as_ns host1 ping 10.0.1.3
```

Next we will add a new host to run our BGP service on, connect it to the switch's dataplane and create a virtual link for it to be able to communicate with Faucet.

![BGP Routing Namespace Diagram](bgp-routing-ns.svg)
```bash
create_ns bgphost1 192.168.1.3/24
ovs-vsctl add-port br1 veth-bgphost1 -- set interface veth-bgphost1 ofport_request=4
ip link add name veth-bgphost1-0 type veth peer name vethbgpctrl0
ip link set vethbgpctrl0 netns bgphost1
ip addr add 172.16.1.1/24 dev veth-bgphost1-0
as_ns bgphost1 ip addr add 172.16.1.2/24 dev vethbgpctrl0
ip link set veth-bgphost1-0 up
as_ns bgphost1 ip link set vethbgpctrl0 up
```
And repeat for the other side.
```bash
create_ns bgphost2 192.168.1.4/24
ovs-vsctl add-port br2 veth-bgphost2 -- set interface veth-bgphost2 ofport_request=4
ip link add name veth-bgphost2-0 type veth peer name vethbgpctrl0
ip link set vethbgpctrl0 netns bgphost2
ip addr add 172.16.2.1/24 dev veth-bgphost2-0
as_ns bgphost2 ip addr add 172.16.2.2/24 dev vethbgpctrl0
ip link set veth-bgphost2-0 up
as_ns bgphost2 ip link set vethbgpctrl0 up
```

Now bgphost1 should be able to ping 172.16.1.1 & bgphost2 should be able to ping 172.16.2.1
```bash
$ as_ns bgphost1 ping 172.16.1.1
```

To configure BIRD1
bird1.conf
```
protocol kernel {
    scan time 60;
    import none;
}

protocol device {
    scan time 60;
}

protocol static {
    route 10.0.0.0/24 via 192.168.1.1;
    route 192.168.1.0/24 unreachable;
}

protocol bgp faucet {
    local as 64512;
    neighbor 172.16.1.1 port 9179 as 64512;
    export all;
    import all;
}

protocol bgp kiwi {
    local as 64512;
    neighbor 192.168.1.4 port 179 as 64513;
    export all;
    import all;
}
```
and for BIRD2:
bird2.conf
```
protocol kernel {
    scan time 60;
    import none;
}

protocol device {
    scan time 60;
}

protocol static {
    route 10.0.1.0/24 via 192.168.1.2;
    route 192.168.1.0/24 unreachable;
}

protocol bgp faucet {
    local as 64512;
    neighbor 172.16.2.1 port 9179 as 64512;
    export all;
    import all;
}

protocol bgp fruit {
    local as 64513;
    neighbor 192.168.1.3 port 179 as 64512;
    export all;
    import all;
}
```

Start the two BIRDs
```bash
$ as_ns bgphost1 bird -s /var/run/bird1.ctl-c /home/ubuntu/bird1.conf
```
and
```bash
$ as_ns bgphost2 bird -s /var/run/bird2.ctl -c /home/ubuntu/bird2.conf
```

We'll configure the Faucets by adding the BGP configuration to the \*-peer VLAN.
/etc/faucet/br1-faucet.yaml
```yaml
vlans:
    br1-hosts:
        vid: 100
        description: "h1 & h2's vlan"
        faucet_mac: "00:00:00:00:00:11"
        faucet_vips: ["10.0.0.254/24"]

    br1-peer:
        vid: 200
        description: "vlan for peering port"
        faucet_mac: "00:00:00:00:00:22"
        faucet_vips: ["192.168.1.1/24"]
        bgp_port: 9179
        bgp_as: 64512
        bgp_routerid: '172.16.1.1'
        bgp_neighbor_addresses: ['172.16.1.2', '::1']
        bgp_connect_mode: active
        bgp_neighbor_as: 64512

routers:
    br1-router:
        vlans: [br1-hosts, br1-peer]
```

/etc/faucet/br2-faucet.yaml
```yaml
vlans:
    br2-peer:
        vid: 300
        description: "vlan for peering port"
        faucet_mac: "00:00:00:00:00:33"
        faucet_vips: ["192.168.1.2/24"]
        bgp_port: 9180
        bgp_as: 64512                                                                                      
        bgp_routerid: '172.16.2.1'                                                                         
        bgp_neighbor_addresses: ['172.16.2.2', '::1']                                                      
        bgp_connect_mode: active
        bgp_neighbor_as: 64512

    br2-hosts:
        vid: 400
        description: "h3 & h4's vlan"
        faucet_mac: "00:00:00:00:00:44"
        faucet_vips: ["10.0.1.254/24"]

routers:
    br2-router:
        vlans: [br2-hosts, br2-peer]
```

And finally add the port configuration for the bgphost.
sw1-facuet.yaml
```yaml
dps:
    br1:
        ...
        interfaces:
            ...
            4:
                native_vlan: br1-peer

```
and
sw2-facuet.yaml
```yaml
dps:
    br2:
        ...
        interfaces:
            ...
            4:
                native_vlan: br2-peer
```
Now restart the Faucets.
```bash
$ sudo env FAUCET_CONFIG=/home/ubuntu/sw1-faucet.yaml FAUCET_LOG=/var/log/faucet/sw1-faucet.log faucet &
$ sudo env FAUCET_CONFIG=/home/ubuntu/sw2-faucet.yaml FAUCET_LOG=/var/log/faucet/sw2-faucet.log  FAUCET_PROMETHEUS_PORT=9304 faucet --ryu-ofp-tcp-listen-port=6650 &
```

and our logs should show us BGP peer router up.

/var/log/faucet/sw1-faucet.log
```
...
May 03 11:23:40 faucet INFO     BGP peer router ID 172.16.1.2 AS 64512 up
May 03 11:23:40 faucet ERROR    BGP nexthop 192.168.1.1 for prefix 10.0.0.0/24 cannot be us
May 03 11:23:40 faucet ERROR    BGP nexthop 172.16.1.2 for prefix 192.168.1.0/24 is not a connected network
```
Now we should be able to ping from host1 to host3.

To confirm we are getting the routes from BGP we can query BIRD:
```bash
$ birdcl -s /var/run/bird2.ctl show route
BIRD 1.6.4 ready.
10.0.0.0/24        via 192.168.1.1 on veth0 [fruit 11:38:47 from 192.168.1.3] * (100) [AS64512i]
10.0.1.0/24        via 192.168.1.2 on veth0 [static1 11:31:29] * (200)
192.168.1.0/24     unreachable [static1 11:31:29] * (200)
                   unreachable [faucet 11:48:05 from 172.16.2.1] (100/-) [i]
                   via 192.168.1.3 on veth0 [fruit 11:38:47] (100) [AS64512i]
```
And we can see 10.0.0.0/24 is coming from our fruit peer.



Next we will move host2 into a different subnet and add a route for it to be advertised via BGP.

Remove the old 10.0.0.0/24 IP address and add the new one.

```bash
$ as_ns host2 ip addr flush dev veth0
$ as_ns host2 ip addr add 10.0.2.2/24 dev veth0
$ as_ns host2 ip route add default via 10.0.2.254
```

And configure Faucet to put host 2 in a new VLAN.
```yaml
vlans:
    ...
    br1-host2:
        vid: 300
        faucet_mac: "00:00:00:00:00:34"
        faucet_vips: ["10.0.2.254/24"]
```

Add the VLAN to the Inter VLAN router:
```yaml
routers:
    router-br1:
        vlans: [br1-hosts, br1-peer, br1-host2]
```

And change port 2's native VLAN, so the final configuration should look like:
```yaml
vlans:
    br1-hosts:
        vid: 100
        description: "h1 & h2's vlan"
        faucet_mac: "00:00:00:00:00:11"
        faucet_vips: ["10.0.0.254/24"]
    br1-peer:
        vid: 200
        description: "vlan for peering port"
        faucet_mac: "00:00:00:00:00:22"
        faucet_vips: ["192.168.1.1/24"]
        bgp_port: 9179
        bgp_as: 64512
        bgp_routerid: '172.16.1.1'
        bgp_neighbor_addresses: ['172.16.1.2', '::1']
        bgp_connect_mode: active
        bgp_neighbor_as: 64512
    br1-host2:
        vid: 300
        faucet_mac: "00:00:00:00:00:34"
        faucet_vips: ["10.0.2.1/24"]

routers:
    router-br1:
        vlans: [br1-hosts, br1-peer, br1-host2]
dps:
    br1:
        dp_id: 0x1
        hardware: "Open vSwitch"
        interfaces:
            1:
                name: "br2"
                description: "connects to br2"
                native_vlan: br1-peer
            2:
                name: "host1"
                description: "host1 network namespace"
                native_vlan: br1-host2
            3:
                name: "host2"
                description: "host2 network namespace"
                native_vlan: br1-hosts
```

Restart Faucet 1 to reload our config and host2 should be able to ping host1, but not host3 & host4.

We need to advertise our new 10.0.2.0/24 via bgp.
So in the 'protocol static' section of bird1.conf add the new route.
```
protocol static {
    route 10.0.0.0/24 via 192.168.1.1;
    route 10.0.2.0/24 via 192.168.1.1
    route 192.168.1.0/24 unreachable;
}
```
reload bird:
```bash
$ sudo birdcl configure
```

And in bird2 we can view the routing table
```bash
$ sudo birdcl -s /var/run/bird2.ctl show route
BIRD 1.6.4 ready.
10.0.2.0/24        via 192.168.1.1 on veth0 [fruit 12:04:36 from 192.168.1.3] * (100) [AS64512i]
10.0.0.0/24        via 192.168.1.1 on veth0 [fruit 11:38:47 from 192.168.1.3] * (100) [AS64512i]
10.0.1.0/24        via 192.168.1.2 on veth0 [static1 11:31:29] * (200)
192.168.1.0/24     unreachable [static1 11:31:29] * (200)
                   unreachable [faucet 11:48:05 from 172.16.2.1] (100/-) [i]
                   via 192.168.1.3 on veth0 [fruit 11:38:47] (100) [AS64512i]
```
