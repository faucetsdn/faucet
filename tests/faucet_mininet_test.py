#!/usr/bin/python

# mininet tests for FAUCET
#
# * must be run as root
# * you can run a specific test case only, by adding the class name of the test
#   case to the command. Eg ./faucet_mininet_test.py FaucetUntaggedIPv4RouteTest
#
# TODO:
#
# * bridge hardware OF switch for comparison with OVS

import os
import re
import shutil
import tempfile
import time
import unittest
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Controller
from mininet.node import Host
from mininet.topo import Topo
from mininet.util import dumpNodeConnections, pmonitor

FAUCET_DIR = '../src/ryu_faucet/org/onfsdn/faucet'

CONFIG_HEADER = '''
---
dp_id: 0x1
name: "faucet-1"
hardware: "Open vSwitch"
'''


class VLANHost(Host):

    def config(self, vlan=100, **params):
        """Configure VLANHost according to (optional) parameters:
           vlan: VLAN ID for default interface"""
        r = super(Host, self).config(**params)
        intf = self.defaultIntf()
        self.cmd('ifconfig %s inet 0' % intf)
        self.cmd('vconfig add %s %d' % (intf, vlan))
        self.cmd('ifconfig %s.%d inet %s' % (intf, vlan, params['ip']))
        newName = '%s.%d' % (intf, vlan)
        intf.name = newName
        self.nameToIntf[newName] = intf
        return r


class FAUCET(Controller):

    def __init__(self, name, cdir=FAUCET_DIR,
                 command='ryu-manager faucet.py',
                 cargs='--ofp-tcp-listen-port=%s --verbose',
                 **kwargs):
        Controller.__init__(self, name, cdir=cdir,
                            command=command,
                            cargs=cargs, **kwargs)


class FaucetSwitchTopo(Topo):

    def build(self, n_tagged=0, tagged_vid=100, n_untagged=0):
        switch = self.addSwitch('s1')
        for h in range(n_tagged):
            host = self.addHost('ht_%s' % (h + 1),
                cls=VLANHost, vlan=tagged_vid)
            self.addLink(host, switch)
        for h in range(n_untagged):
            host = self.addHost('hu_%s' % (h + 1))
            self.addLink(host, switch)


class FaucetTest(unittest.TestCase):

    CONFIG = ''

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        os.environ['FAUCET_CONFIG'] = os.path.join(self.tmpdir,
             'faucet.yaml')
        os.environ['FAUCET_LOG'] = os.path.join(self.tmpdir,
             'faucet.log')
        os.environ['FAUCET_EXCEPTION_LOG'] = os.path.join(self.tmpdir,
            'faucet-exception.log')
        open(os.environ['FAUCET_CONFIG'], 'w').write(self.CONFIG)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)


class FaucetUntaggedTest(FaucetTest):

    CONFIG = CONFIG_HEADER + """
interfaces:
    1:
        native_vlan: 100
        description: "b1"
    2:
        native_vlan: 100
        description: "b2"
    3:
        native_vlan: 100
        description: "b3"
    4:
        native_vlan: 100
        description: "b4"
vlans:
    100:
        description: "untagged"
"""

    def setUp(self):
        super(FaucetUntaggedTest, self).setUp()
        self.topo = FaucetSwitchTopo(n_untagged=4)
        self.net = Mininet(self.topo, controller=FAUCET)
        self.net.start()
        dumpNodeConnections(self.net.hosts)
        self.net.waitConnected()

    def test_untagged(self):
        self.assertEquals(0, self.net.pingAll())

    def tearDown(self):
        self.net.stop()
        super(FaucetUntaggedTest, self).tearDown()


class FaucetUntaggedNoVLanUnicastFloodTest(FaucetUntaggedTest):

    CONFIG = CONFIG_HEADER + """
interfaces:
    1:
        native_vlan: 100
        description: "b1"
    2:
        native_vlan: 100
        description: "b2"
    3:
        native_vlan: 100
        description: "b3"
    4:
        native_vlan: 100
        description: "b4"
vlans:
    100:
        description: "untagged"
        unicast_flood: False
"""

    def test_untagged(self):
        self.assertEquals(0, self.net.pingAll())


class FaucetUntaggedHostMoveTest(FaucetUntaggedTest):

    def swap_host_macs(self, first_host, second_host):
        first_host_mac = first_host.MAC()
        second_host_mac = second_host.MAC()
        first_host.setMAC(second_host_mac)
        second_host.setMAC(first_host_mac)
        first_host.cmd('arp -d %s' % second_host.IP())
        second_host.cmd('arp -d %s' % first_host.IP())

    def test_untagged(self):
        first_host, second_host = self.net.hosts[0:2]
        self.assertEqual(0, self.net.ping((first_host, second_host)))
        for i in range(3):
            self.swap_host_macs(first_host, second_host)
            # TODO: sometimes slow to relearn
            self.assertTrue(self.net.ping((first_host, second_host)) <= 50)


class FaucetUntaggedHostPermanentLearnTest(FaucetUntaggedTest):

    CONFIG = CONFIG_HEADER + """
interfaces:
    1:
        native_vlan: 100
        description: "b1"
        permanent_learn: True
    2:
        native_vlan: 100
        description: "b2"
    3:
        native_vlan: 100
        description: "b3"
    4:
        native_vlan: 100
        description: "b4"
vlans:
    100:
        description: "untagged"
"""

    def test_untagged(self):
        first_host, second_host, third_host = self.net.hosts[0:3]
        self.assertEqual(0, self.net.pingAll())
        # 3rd host impersonates 1st, 3rd host breaks but 1st host still OK
        original_third_host_mac = third_host.MAC()
        third_host.setMAC(first_host.MAC())
        self.assertEqual(100.0, self.net.ping((second_host, third_host)))
        self.assertEqual(0, self.net.ping((first_host, second_host)))
        # 3rd host stops impersonating, now everything fine again.
        third_host.setMAC(original_third_host_mac)
        self.assertEqual(0, self.net.pingAll())


class FaucetUntaggedControlPlaneTest(FaucetUntaggedTest):

    CONFIG = CONFIG_HEADER + """
interfaces:
    1:
        native_vlan: 100
        description: "b1"
    2:
        native_vlan: 100
        description: "b2"
    3:
        native_vlan: 100
        description: "b3"
    4:
        native_vlan: 100
        description: "b4"
vlans:
    100:
        description: "untagged"
        ip: "10.0.0.254/24"
"""

    def test_ping_controller(self):
        ping_result = self.net.hosts[0].cmd('ping -c1 10.0.0.254')
        self.assertTrue(re.search(
            '1 packets transmitted, 1 received, 0\% packet loss', ping_result))


class FaucetTaggedAndUntaggedTest(FaucetTest):

    CONFIG = CONFIG_HEADER + """
interfaces:
    1:
        tagged_vlans: [100]
        description: "b1"
    2:
        tagged_vlans: [100]
        description: "b2"
    3:
        native_vlan: 101
        description: "b3"
    4:
        native_vlan: 101
        description: "b4"
vlans:
    100:
        description: "tagged"
    101:
        description: "untagged"
"""

    def setUp(self):
        super(FaucetTaggedAndUntaggedTest, self).setUp()
        self.topo = FaucetSwitchTopo(n_tagged=2, n_untagged=2)
        self.net = Mininet(self.topo, controller=FAUCET)
        self.net.start()
        dumpNodeConnections(self.net.hosts)
        self.net.waitConnected()

    def test_seperate_untagged_tagged(self):
        tagged_host_pair = self.net.hosts[0:1]
        untagged_host_pair = self.net.hosts[2:3]
        # hosts within VLANs can ping each other
        self.assertEquals(0, self.net.ping(tagged_host_pair))
        self.assertEquals(0, self.net.ping(untagged_host_pair))
        # hosts cannot ping hosts in other VLANs
        self.assertEquals(100,
            self.net.ping([tagged_host_pair[0], untagged_host_pair[0]]))

    def tearDown(self):
        self.net.stop()
        super(FaucetTaggedAndUntaggedTest, self).tearDown()
        time.sleep(1)


class FaucetUntaggedACLTest(FaucetUntaggedTest):

    CONFIG = CONFIG_HEADER + """
interfaces:
    1:
        native_vlan: 100
        description: "b1"
        acl_in: 1
    2:
        native_vlan: 100
        description: "b2"
    3:
        native_vlan: 100
        description: "b3"
    4:
        native_vlan: 100
        description: "b4"
vlans:
    100:
        description: "untagged"
acls:
    1:
        - rule:
            dl_type: 0x800
            nw_proto: 6
            tp_dst: 5001
            allow: 0

        - rule:
            allow: 1
"""

    def test_port5001_blocked(self):
        self.assertEquals(0, self.net.pingAll())
        first_host = self.net.hosts[0]
        second_host = self.net.hosts[1]
        second_host.sendCmd('echo hello | nc -l 5001')
        second_host.waiting = False
        self.assertEquals('',
            first_host.cmd('nc -w 3 %s 5001' % second_host.IP()))
        second_host.sendInt()

    def test_port5002_unblocked(self):
        self.assertEquals(0, self.net.pingAll())
        first_host = self.net.hosts[0]
        second_host = self.net.hosts[1]
        second_host.sendCmd('echo hello | nc -l 5002')
        second_host.waiting = False
        self.assertEquals('hello\r\n',
            first_host.cmd('nc -w 3 %s 5002' % second_host.IP()))
        second_host.sendInt()


class FaucetUntaggedMirrorTest(FaucetUntaggedTest):

    CONFIG = CONFIG_HEADER + """
interfaces:
    1:
        native_vlan: 100
        description: "b1"
    2:
        native_vlan: 100
        description: "b2"
    3:
        native_vlan: 100
        description: "b3"
        mirror: 1
    4:
        native_vlan: 100
        description: "b4"
vlans:
    100:
        description: "untagged"
"""

    def test_untagged(self):
        first_host = self.net.hosts[0]
        second_host = self.net.hosts[1]
        mirror_host = self.net.hosts[2]
        mirror_mac = mirror_host.MAC()
        tcpdump_filter = 'not ether src %s and icmp' % mirror_mac
        tcpdump_out = mirror_host.popen(
            'timeout 10s tcpdump -n -v -c 2 -U %s' % tcpdump_filter)
        # wait for tcpdump to start
        time.sleep(1)
        popens = {mirror_host: tcpdump_out}
        first_host.cmd('ping -c1  %s' % second_host.IP())
        tcpdump_txt = ''
        for host, line in pmonitor(popens):
            if host == mirror_host:
                tcpdump_txt += line.strip()
        self.assertFalse(tcpdump_txt == '')
        self.assertTrue(re.search(
            '%s: ICMP echo request' % second_host.IP(), tcpdump_txt))
        self.assertTrue(re.search(
            '%s: ICMP echo reply' % first_host.IP(), tcpdump_txt))


class FaucetTaggedTest(FaucetTest):

    CONFIG = CONFIG_HEADER + """
interfaces:
    1:
        tagged_vlans: [100]
        description: "b1"
    2:
        tagged_vlans: [100]
        description: "b2"
    3:
        tagged_vlans: [100]
        description: "b3"
    4:
        tagged_vlans: [100]
        description: "b4"
vlans:
    100:
        description: "tagged"
"""

    def setUp(self):
        super(FaucetTaggedTest, self).setUp()
        self.topo = FaucetSwitchTopo(n_tagged=4)
        self.net = Mininet(self.topo, controller=FAUCET)
        self.net.start()
        dumpNodeConnections(self.net.hosts)
        self.net.waitConnected()

    def test_tagged(self):
        self.assertEquals(0, self.net.pingAll())

    def tearDown(self):
        self.net.stop()
        super(FaucetTaggedTest, self).tearDown()
        time.sleep(1)


if __name__ == '__main__':
    setLogLevel('info')
    unittest.main()
