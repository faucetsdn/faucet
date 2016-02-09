#!/usr/bin/python

import os
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
                 command='/usr/local/bin/ryu-manager faucet.py',
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


class FaucetTest(object):
    pass


class FaucetUntaggedTest(FaucetTest):

    def setUp(self):
        self.tmpdir = '/tmp'
        os.environ['FAUCET_CONFIG'] = os.path.join(self.tmpdir,
             'faucet.yaml')
        os.environ['FAUCET_LOG'] = os.path.join(self.tmpdir,
             'faucet.log')
        os.environ['FAUCET_EXCEPTION_LOG'] = os.path.join(self.tmpdir,
            'faucet-exception.log')
        untagged_config = """
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
        open(os.environ['FAUCET_CONFIG'], 'w').write(untagged_config)
        self.topo = SingleSwitchUntaggedTopo(n=4)
        self.net = Mininet(self.topo, controller=FAUCET)
        self.net.start()
        dumpNodeConnections(self.net.hosts)

    def run(self):
        self.net.pingAll()

    def tearDown(self):
        self.net.stop()


class FaucetTaggedTest(FaucetTest):

    def setUp(self):
        self.tmpdir = '/tmp'
        os.environ['FAUCET_CONFIG'] = os.path.join(self.tmpdir,
             'faucet.yaml')
        os.environ['FAUCET_LOG'] = os.path.join(self.tmpdir,
             'faucet.log')
        os.environ['FAUCET_EXCEPTION_LOG'] = os.path.join(self.tmpdir,
            'faucet-exception.log')
        tagged_config = """
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
        open(os.environ['FAUCET_CONFIG'], 'w').write(tagged_config)
        self.topo = SingleSwitchTaggedTopo(n=4)
        self.net = Mininet(self.topo, controller=FAUCET)
        self.net.start()
        dumpNodeConnections(self.net.hosts)

    def run(self):
        self.net.pingAll()

    def tearDown(self):
        self.net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    untagged_test = FaucetUntaggedTest()
    untagged_test.setUp()
    untagged_test.run()
    untagged_test.tearDown()
    tagged_test = FaucetTaggedTest()
    tagged_test.setUp()
    tagged_test.run()
    tagged_test.tearDown()
