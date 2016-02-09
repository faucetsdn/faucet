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


class SingleSwitchUntaggedTopo(Topo):

    def build(self, n):
        switch = self.addSwitch('s1')
        for h in range(n):
            host = self.addHost('h%s' % (h + 1))
            self.addLink(host, switch)


class SingleSwitchTaggedTopo(Topo):

    def build(self, n):
        switch = self.addSwitch('s1')
        for h in range(n):
            host = self.addHost('h%s' % (h + 1), cls=VLANHost, vlan=100)
            self.addLink(host, switch)


class FaucetTest(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        os.environ['FAUCET_CONFIG'] = os.path.join(self.tmpdir,
             'faucet.yaml')
        os.environ['FAUCET_LOG'] = os.path.join(self.tmpdir,
             'faucet.log')
        os.environ['FAUCET_EXCEPTION_LOG'] = os.path.join(self.tmpdir,
            'faucet-exception.log')

    def tearDown(self):
        shutil.rmtree(self.tmpdir)


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
        description: "b3"
        native_vlan: 100
    4:
        description: "b4"
        native_vlan: 100
vlans:
    100:
        description: "test"
"""

    def setUp(self):
        super(FaucetUntaggedTest, self).setUp()
        open(os.environ['FAUCET_CONFIG'], 'w').write(self.CONFIG)
        self.topo = SingleSwitchUntaggedTopo(n=4)
        self.net = Mininet(self.topo, controller=FAUCET)
        self.net.start()
        dumpNodeConnections(self.net.hosts)
        self.net.waitConnected()

    def test_untagged(self):
        # no lost packets
        self.assertEquals(0, self.net.pingAll())

    def tearDown(self):
        super(FaucetUntaggedTest, self).tearDown()
        self.net.stop()


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
        description: "test"
"""

    def setUp(self):
        super(FaucetTaggedTest, self).setUp()
        open(os.environ['FAUCET_CONFIG'], 'w').write(self.CONFIG)
        self.topo = SingleSwitchTaggedTopo(n=4)
        self.net = Mininet(self.topo, controller=FAUCET)
        self.net.start()
        dumpNodeConnections(self.net.hosts)
        self.net.waitConnected()

    def test_tagged(self):
        # no lost packets
        self.assertEquals(0, self.net.pingAll())

    def tearDown(self):
        super(FaucetTaggedTest, self).tearDown()
        self.net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    unittest.main()
