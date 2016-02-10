#!/usr/bin/python

import os
import unittest
import shutil
import tempfile
import time
from mininet.node import Controller
from mininet.node import Host
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel

FAUCET_DIR = '../'

class VLANHost(Host):

    def config(self, vlan=100, **params):
        """Configure VLANHost according to (optional) parameters:
           vlan: VLAN ID for default interface"""
        r = super(Host, self).config(**params)
        intf = self.defaultIntf()
        # remove IP from default, "physical" interface
        self.cmd('ifconfig %s inet 0' % intf)
        # create VLAN interface
        self.cmd('vconfig add %s %d' % (intf, vlan))
        # assign the host's IP to the VLAN interface
        self.cmd('ifconfig %s.%d inet %s' % (intf, vlan, params['ip']))
        # update the intf name and host's intf map
        newName = '%s.%d' % (intf, vlan)
        # update the (Mininet) interface to refer to VLAN interface name
        intf.name = newName
        # add VLAN interface to host's name to intf map
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
            host = self.addHost('hu_%s' % (h + 1),
                cls=VLANHost, vlan=tagged_vid)
            self.addLink(host, switch)
        for h in range(n_untagged):
            host = self.addHost('ht_%s' % (h + 1))
            self.addLink(host, switch)


class FaucetTest(unittest.TestCase):

    CONFIG = ""

    def setUp(self):
        self.tmpdir = '/tmp' # tempfile.mkdtemp()
        os.environ['FAUCET_CONFIG'] = os.path.join(self.tmpdir,
             'faucet.yaml')
        os.environ['FAUCET_LOG'] = os.path.join(self.tmpdir,
             'faucet.log')
        os.environ['FAUCET_EXCEPTION_LOG'] = os.path.join(self.tmpdir,
            'faucet-exception.log')
        open(os.environ['FAUCET_CONFIG'], 'w').write(self.CONFIG)

    def tearDown(self):
        #shutil.rmtree(self.tmpdir)
        pass


class FaucetUntaggedTest(FaucetTest):

    CONFIG = """
---
dp_id: 0x1
name: "untagged-faucet-1"
hardware: "Allied-Telesis"
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


class FaucetTaggedAndUntaggedTest(FaucetTest):

    CONFIG = """
---
dp_id: 0x1
name: "tagged-and-untagged-faucet-1"
hardware: "Allied-Telesis"
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


class FaucetUntaggedACLTest(FaucetUntaggedTest):

    CONFIG = """
---
dp_id: 0x1
name: "untagged-faucet-1"
hardware: "Allied-Telesis"
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
        self.assertEquals('',
            first_host.cmd('nc -w 3 %s 5001' % second_host.IP()))

    def test_port5002_unblocked(self):
        self.assertEquals(0, self.net.pingAll())
        first_host = self.net.hosts[0]
        second_host = self.net.hosts[1]
        second_host.sendCmd('echo hello | nc -l 5002')
        self.assertEquals('hello\r\n',
            first_host.cmd('nc -w 3 %s 5002' % second_host.IP()))


class FaucetTaggedTest(FaucetTest):

    CONFIG = """
---
dp_id: 0x1
name: "tagged-faucet-1"
hardware: "Allied-Telesis"
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


if __name__ == '__main__':
    setLogLevel('info')
    unittest.main()
