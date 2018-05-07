NFV Services Tutorial
=====================

This tutorial will cover using Faucet with Network Function Virtualisation (NFV) services.

NFV services that will be demonstrated in this tutorial are:

- DHCP server
- NAT Gateway
- `BRO <https://www.bro.org/>`_ Intrusion Detection System (IDS)

This tutorial demonstrates how the previous topics in this tutorial series can be integrated with other services on our network.


Prerequisites:
^^^^^^^^^^^^^^

- Good understanding of the previous tutorial series topics (`ACLs <ACLs.html>`_, `VLANs <vlan_tutorial.html>`_, `Routing <routing.html>`_)
- Faucet `Steps 1 & 2 <https://faucet.readthedocs.io/en/latest/tutorials.html#package-installation>`__
- OpenVSwitch `Steps 1 & 2 <https://faucet.readthedocs.io/en/latest/tutorials.html#connect-your-first-datapath>`__
- Useful Bash Functions (`create_ns <_static/tutorial/create_ns>`_, `as_ns <_static/tutorial/as_ns>`_, `cleanup <_static/tutorial/cleanup>`_, `add_tagged_dev_ns <_static/tutorial/add_tagged_dev_ns>`_, `clear_ns <_static/tutorial/clear_ns>`_)

Let's start by run the cleanup script to remove old namespaces and switches.

.. code:: console

    cleanup

Network setup
^^^^^^^^^^^^^

Then we will create a switch with five hosts as following

.. code:: console

    create_ns host1 192.168.0.1/24 # BRO
    create_ns host2 0              # DHCP server
    add_tagged_dev_ns host2 192.168.2.2/24 200 # to serve vlan 200
    add_tagged_dev_ns host2 192.168.3.2/24 300 # to serve vlan 300

    create_ns host3 0              # Gateway
    add_tagged_dev_ns host3 192.168.2.3/24 200 # to serve vlan 200
    add_tagged_dev_ns host3 192.168.3.3/24 300 # to serve vlan 200

    create_ns host4 0              # normal host, will be in native vlan 200
    create_ns host5 0              # normal host, will be in native vlan 300

Then create an OpenvSwitch and connect all hosts to it.

.. code:: console

    sudo ovs-vsctl add-br br0 \
    -- set bridge br0 other-config:datapath-id=0000000000000001 \
    -- set bridge br0 other-config:disable-in-band=true \
    -- set bridge br0 fail_mode=secure \
    -- add-port br0 veth-host1 -- set interface veth-host1 ofport_request=1 \
    -- add-port br0 veth-host2 -- set interface veth-host2 ofport_request=2 \
    -- add-port br0 veth-host3 -- set interface veth-host3 ofport_request=3 \
    -- add-port br0 veth-host4 -- set interface veth-host4 ofport_request=4 \
    -- add-port br0 veth-host5 -- set interface veth-host5 ofport_request=5 \
    -- set-controller br0 tcp:127.0.0.1:6653 tcp:127.0.0.1:6654


DHCP Server
^^^^^^^^^^^

We will use `dnsmasq <http://www.thekelleys.org.uk/dnsmasq/doc.html>`_ as our DHCP server.

First install dnsmasq:

.. code:: console

    sudo apt-get install dnsmasq

Let's run two services one for vlan 200 and another for vlan 300 as following

.. code:: console

    # 192.168.2.0/24 for vlan 200
    as_ns host2 dnsmasq --no-ping -p 0 -k \
                        --dhcp-range=192.168.2.10,192.168.2.20 \
                        --dhcp-option=option:router,192.168.2.3 \
                        -O option:dns-server,8.8.8.8 \
                        -I lo -z -l /tmp/nfv-dhcp-vlan200.leases \
                        -8 /tmp/nfv.dhcp-vlan200.log -i veth0.200  --conf-file= &
    # 192.168.3.0/24 for vlan 300
    as_ns host2 dnsmasq --no-ping -p 0 -k \
                        --dhcp-range=192.168.3.10,192.168.3.20 \
                        --dhcp-option=option:router,192.168.3.3 \
                        -O option:dns-server,8.8.8.8 \
                        -I lo -z -l /tmp/nfv-dhcp-vlan300.leases \
                        -8 /tmp/nfv.dhcp-vlan300.log -i veth0.300  --conf-file= &

Now let's configure faucet yaml file (/etc/faucet/faucet.yaml)

.. code-block:: yaml
    :caption: /etc/faucet/faucet.yaml

    vlans:
        bro-vlan:
            vid: 100
            description: "bro network"
        vlan200:
            vid: 200
            description: "192.168.2.0/24 network"
        vlan300:
            vid: 300
            description: "192.168.3.0/24 network"
    dps:
        sw1:
            dp_id: 0x1
            hardware: "Open vSwitch"
            interfaces:
                1:
                    name: "host1"
                    description: "BRO network namespace"
                    native_vlan: bro-vlan
                2:
                    name: "host2"
                    description: "DHCP server  network namespace"
                    tagged_vlans: [vlan200, vlan300]
                3:
                    name: "host3"
                    description: "gateway network namespace"
                    tagged_vlans: [vlan200, vlan300]
                4:
                    name: "host4"
                    description: "host4 network namespace"
                    native_vlan: vlan200
                5:
                    name: "host5"
                    description: "host5 network namespace"
                    native_vlan: vlan300

Now restart faucet

.. code:: console

    sudo systemctl restart faucet

Use dhclient to configure host4 and host4 using DHCP (it may take few seconds, but should return when successful).

.. code:: console

    as_ns host4 dhclient veth0
    as_ns host5 dhclient veth0

You can check */tmp/nfv-dhcp-<vlan>.leases* and */tmp/nfv.dhcp-<vlan>.log* to find what ip assinged to host4 and host5. Alternatively:

.. code:: console

    as_ns host4 ip addr show
    as_ns host5 ip addr show

Try to ping between them

.. code:: console

    as_ns host4 ping <ip of host5>

If the ping is successful great our DHCP works, however Faucet is not doing the routing (we have not defined a router).
If ping fails you can add a router to check or just look at the output from the above commands.
So we will fix this for the next sections by changing iptables on host3 (gateway) to not route traffic by default.

.. code:: console

    as_ns host3 iptables -P FORWARD DROP

Now the ping should fail

.. code:: console

    as_ns host4 ping <host5 ip addr>


Gateway (NAT)
^^^^^^^^^^^^^

In this section we will configure host3 as a gateway (NAT) to provide internet connection for our network.

.. code:: console

    NS=host3        # gateway host namespace
    TO_DEF=to_def   # to the internet
    TO_NS=to_${NS}  # to gw (host3)
    OUT_INTF=enp0s3 # host machine interface for internet connection.

    # enable forwarding in the hosted machine and in the host3 namespace.
    sudo sysctl net.ipv4.ip_forward=1
    as_ns ${NS} sysctl net.ipv4.ip_forward=1

    # create veth pair
    sudo ip link add name ${TO_NS} type veth peer name ${TO_DEF} netns ${NS}

    # configure interfaces and routes
    sudo ip addr add 192.168.100.1/30 dev ${TO_NS}
    sudo ip link set ${TO_NS} up

    # sudo ip route add 192.168.100.0/30 dev ${TO_NS}
    as_ns ${NS} ip addr add 192.168.100.2/30 dev ${TO_DEF}
    as_ns ${NS} ip link set ${TO_DEF} up
    as_ns ${NS} ip route add default via 192.168.100.1

    # do not allow routing between vlan300 & vlan200 on the gateway host.
    as_ns ${NS} iptables -P FORWARD DROP

    # allow each vlan to be sent to and from the gateway interface
    as_ns ${NS} iptables -A FORWARD -i veth0.200 -o ${TO_DEF} -j ACCEPT
    as_ns ${NS} iptables -A FORWARD -i veth0.300 -o ${TO_DEF} -j ACCEPT
    as_ns ${NS} iptables -A FORWARD -i ${TO_DEF} -o veth0.200 -j ACCEPT
    as_ns ${NS} iptables -A FORWARD -i ${TO_DEF} -o veth0.300 -j ACCEPT

    # NAT in ${NS}
    as_ns ${NS} iptables -t nat -F
    as_ns ${NS} iptables -t nat -A POSTROUTING -o ${TO_DEF} -j MASQUERADE
    # NAT in default
    sudo iptables -P FORWARD DROP
    sudo iptables -F FORWARD

    # Assuming the host does not have other NAT rules.
    sudo iptables -t nat -F
    sudo iptables -t nat -A POSTROUTING -s 192.168.100.0/30 -o ${OUT_INTF} -j MASQUERADE
    sudo iptables -A FORWARD -i ${OUT_INTF} -o ${TO_NS} -j ACCEPT
    sudo iptables -A FORWARD -i ${TO_NS} -o ${OUT_INTF} -j ACCEPT


.. note:: To clear the iptables rules run:

    .. code::

        sudo iptables -F


Now try to ping google.com from host4 or host5, it should work as the gateway is now configured.

.. code:: console

    as_ns host4 ping www.google.com
    as_ns host5 ping www.google.com


BRO IDS
^^^^^^^

BRO installation
----------------

We need first to install bro. We will use the binary package version 2.5.3 for this test.

.. code:: console

    sudp apt-get install bro broctl


Configure BRO
-------------

In /etc/bro/node.cfg, set veth0 as the interface to monitor

.. code-block:: cfg
    :caption: /etc/bro/node.cfg

    [bro]
    type=standalone
    host=localhost
    interface=veth0

Comment out MailTo in /etc/bro/broctl.cfg

.. code-block:: cfg
    :caption: /etc/bro/broctl.cfg

    # Recipient address for all emails sent out by Bro and BroControl.
    # MailTo = root@localhost

Run bro in host2
++++++++++++++++

Since this is the first-time use of the bro command shell application, perform an initial installation of the BroControl configuration:

.. code:: console

    as_ns host1 broctl install


Then start bro instant

.. code:: console

    as_ns host1 broctl start

Check bro status

.. code:: console

    as_ns host1 broctl status
    Name         Type       Host          Status    Pid    Started
    bro          standalone localhost     running   15052  07 May 09:03:59


Now let's add a mirror ACL so all vlan200 & vlan300 traffic is sent to BRO.

We will use vlan acls (more about acl and vlan check vlan and acl tutorials).

.. code-block:: yaml
    :caption: /etc/faucet/faucet.yaml

    acls:
        mirror-acl:
            - rule:
                actions:
                    allow: true
                    mirror: 1
    vlans:
        bro-vlan:
            vid: 100
            description: "bro network"
        vlan200:
            vid: 200
            description: "192.168.2.0/24 network"
            acls_in: [mirror-acl]
        vlan300:
            vid: 300
            description: "192.168.3.0/24 network"
            acls_in: [mirror-acl]
    dps:
        sw1:
            dp_id: 0x1
            hardware: "Open vSwitch"
            interfaces:
                1:
                    name: "host1"
                    description: "BRO network namespace"
                    native_vlan: bro-vlan
                2:
                    name: "host2"
                    description: "DHCP server  network namespace"
                    tagged_vlans: [vlan200, vlan300]
                3:
                    name: "host3"
                    description: "gateway network namespace"
                    tagged_vlans: [vlan200, vlan300]
                4:
                    name: "host4"
                    description: "host4 network namespace"
                    native_vlan: vlan200
                5:
                    name: "host5"
                    description: "host5 network namespace"
                    native_vlan: vlan300

As usual reload faucet configuration file.

.. code:: console

    sudo pkill -HUP -f "faucet\.faucet"


If we generate some DHCP traffic on either of the hosts VLANs

.. code:: console

    as_ns host4 dhclient veth0

and then inspect the bro logs, we should see that bro has learnt about the two DHCP Servers

.. code::

    sudo cat /var/log/bro/current/known_services.log

.. code-block:: txt
    :caption: output:

    #separator \x09
    #set_separator  ,
    #empty_field    (empty)
    #unset_field    -
    #path   known_services
    #open   2018-05-10-12-09-05
    #fields ts      host    port_num        port_proto      service
    #types  time    addr    port    enum    set[string]
    1525910945.405356       192.168.3.2     67      udp     DHCP
    1525910975.329404       192.168.2.2     67      udp     DHCP
