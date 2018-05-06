This tutorial will conver using faucet with NFV services. 

NFV services that will be built in this tutorial are:
- DHCP server
- NAT Gateway
- BRO IDS

This tutorial expands on [installing Faucet for the first time](https://faucet.readthedocs.io/en/latest/tutorials.html).
See there for how to install and setup Faucet and OVS.
## Network setup 
Let's start by run the cleanup script to remove old namespaces and switches.
```
cleanup 
```
Then we will create a switch with five hosts as following
```
create_ns host1 192.168.0.1/24 # BRO
create_ns host2 192.168.0.2/24 # DHCP server
create_ns host3 192.168.0.3/24 # Gateway
create_ns host4 0              # normal host
create_ns host5 0              # normal host
```
Then create an open vswtich and connect all hosts to it. 
```
sudo ovs-vsctl add-br br0 -- set bridge br0 other-config:datapath-id=0000000000000001 \
                          -- set bridge br0 other-config:disable-in-band=true \
                          -- set bridge br0 fail_mode=secure \
                          -- add-port br0 veth-host1 -- set interface veth-host1 ofport_request=1 \
                          -- add-port br0 veth-host2 -- set interface veth-host2 ofport_request=2 \
                          -- add-port br0 veth-host3 -- set interface veth-host3 ofport_request=3 \
                          -- add-port br0 veth-host4 -- set interface veth-host4 ofport_request=4 \
                          -- add-port br0 veth-host5 -- set interface veth-host5 ofport_request=5 \
                          -- set-controller br0 tcp:127.0.0.1:6653 tcp:127.0.0.1:6654
```
## DHCP server

We will run install dnsmasq and run DHCP service on host2
```
sudo apt-get install dnsmasq

as_ns host2 dnsmasq --no-ping -p 0 -k  \
                                 --dhcp-range=192.168.0.10,192.168.0.20  \
                                 --dhcp-option=option:router,192.168.0.3 -O option:dns-server,8.8.8.8  \
                                 -I lo -z -l /tmp/nfv-dhcp.leases -8 /tmp/nfv.dhcp.log -i veth0  --conf-file= &               
```
Now let's configure faucet yaml file (/etc/faucet/faucet.yaml)
```
vlans:
    office:
        vid: 100
        description: "office network"
dps:
    sw1:
        dp_id: 0x1
        hardware: "Open vSwitch"
        interfaces:
            1:
                name: "host1"
                description: "BRO network namespace"
                native_vlan: office
            2:
                name: "host2"
                description: "DHCP server  network namespace"
                native_vlan: office
            3:
                name: "host3"
                description: "gateway network namespace"
                native_vlan: office
            4:
                name: "host4"
                description: "host4 network namespace"
                native_vlan: office
            5:
                name: "host5"
                description: "host5 network namespace"
                native_vlan: office
```
now restart faucet
```
sudo systemctl restart faucet
```
Use dhclint to configure host4 and host4 using DHCP (it may take few seconds). 
```
as_ns host4 dhclient veth0
as_ns host5 dhclient veth0
```
You can check */tmp/nfv-dhcp.leases* and */tmp/nfv.dhcp.log* to find what ip assinged to host4 and host5. 
Alternatively, 
```
as_ns host4 ip add show
as_ns host5 ip add show
```
Try to ping between them 
```
as_ns host4 ping <ip of host5>
```
It should work fine. 

# Gateway 
In this section we will configure host3 as a gateway (NAT)to provide internet connection for our network. 
```
NS=host3        # gateway host namespace 
TO_DEF=to_def   # to the internet
TO_NS=to_${NS}  # to gw (host3) 
OUT_INTF=enp0s3 # host machine interface for internet connection. 

# enable forwarding in the hosted machine and in the host3 namespace. 
sudo sysctl net.ipv4.ip_forward=1
sudo ip netns exec ${NS} sysctl net.ipv4.ip_forward=1

# create veth pair
sudo ip link add name ${TO_NS} type veth peer name ${TO_DEF} netns ${NS}

# configure interfaces and routes
sudo ip addr add 192.168.100.1/30 dev ${TO_NS}
sudo ip link set ${TO_NS} up

# sudo ip route add 192.168.100.0/30 dev ${TO_NS}
sudo ip netns exec ${NS} ip addr add 192.168.100.2/30 dev ${TO_DEF}
sudo ip netns exec ${NS} ip link set ${TO_DEF} up
sudo ip netns exec ${NS} ip route add default via 192.168.100.1

# NAT in ${NS} 
sudo ip netns exec ${NS} iptables -t nat -F
sudo ip netns exec ${NS} iptables -t nat -A POSTROUTING -o ${TO_DEF} -j MASQUERADE
# NAT in default
sudo iptables -P FORWARD DROP
sudo iptables -F FORWARD

# Assuming the host does not have other NAT rules.
sudo iptables -t nat -F
sudo iptables -t nat -A POSTROUTING -s 192.168.100.0/30 -o ${OUT_INTF} -j MASQUERADE
sudo iptables -A FORWARD -i ${OUT_INTF} -o ${TO_NS} -j ACCEPT
sudo iptables -A FORWARD -i ${TO_NS} -o ${OUT_INTF} -j ACCEPT
```

Now try to ping google from host4 or host5, it should work as the gateway is now configured. 
```
as_ns host4 ping www.google.com
as_ns host5 ping www.google.com
```

# BRO IDS
## BRO installation
We need first to install bro. We will use the binary backage version 2.5.3 for this test. 
```
# install the prerequisits
sudo apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev
# install the binary package
wget https://www.bro.org/downloads/bro-2.5.3.tar.gz -P $HOME
tar -xf bro-2.5.3.tar.gz 
cd bro-2.5.3/
# configure, make and install 
./configure
make
sudo make install
```
Add bro location to the PATH directory and export PREFIX
```
export PATH=/usr/local/bro/bin:$PATH
export PREFIX=/usr/local/bro
```
## Configure BRO
In $PREFIX/etc/node.cfg, set veth0 as the interface to monitor 
```
[bro]
type=standalone
host=localhost
interface=veth0
```
Comment mailto in $PREFIX/etc/broctl.cfg
```
# Recipient address for all emails sent out by Bro and BroControl.
# MailTo = root@localhost
```
## Run bro in host2
Let's now run bro in host2 namespace. 
```
cd /usr/local/bro/bin
as_ns host1 ./broctl
```
Since this is the first-time use of the shell, perform an initial installation of the BroControl configuration:
```
[BroControl] > install
```
Then start bro instant 
```
[BroControl] > start
```
Check bro status 
```
[BroControl] > status
Name         Type       Host          Status    Pid    Started
bro          standalone localhost     running   15052  07 May 09:03:59
```
Now let's put BRO in different vlan and mirror the office vlan traffic to BRO. 

We will use vlan acls (more about acl and vlan check vlan and acl tutorials). 

```
vlans:
    BROvlan:
        vid: 200
        description: "bro vlan"
    office:
        vid: 100
        description: "office network"
        acls_in: [mirror-acl]
acls:
    mirror-acl:
        - rule:
            actions:
                allow: true
                mirror: 1 
dps:
    sw1:
        dp_id: 0x1
        hardware: "Open vSwitch"
        interfaces:
            1:
                name: "host1"
                description: "BRO network namespace"
                native_vlan: BROvlan
            2:
                name: "host2"
                description: "DHCP server  network namespace"
                native_vlan: office
            3:
                name: "host3"
                description: "gateway network namespace"
                native_vlan: office
            4:
                name: "host4"
                description: "host4 network namespace"
                native_vlan: office
            5:
                name: "host5"
                description: "host5 network namespace"
                native_vlan: office
```
As usual reload faucet configuration file. 
```
sudo systemctl restart faucet
```
To check BRO log files go to *$PREFIX/logs*. 
