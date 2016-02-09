#!/usr/bin/python

import os
from mininet.node import Controller
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel

FAUCET_DIR = '../'


class FAUCET(Controller):

    def __init__(self, name, cdir=FAUCET_DIR,
                 command='/usr/local/bin/ryu-manager faucet.py',
                 cargs='--ofp-tcp-listen-port=%s',
                 **kwargs):
        Controller.__init__(self, name, cdir=cdir,
                            command=command,
                            cargs=cargs, **kwargs)

class SingleSwitchTopo(Topo):

    def build(self, n):
        switch = self.addSwitch('s1')
        for h in range(n):
            host = self.addHost('h%s' % (h + 1))
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
        descroption: "b1"
    2:
        native_vlan: 100
        descroption: "b2"
    3:
        descroption: "b3"
        native_vlan: 100
    4:
        descroption: "b4"
        native_vlan: 100
vlans:
    100:
        description: "test"
"""
        open(os.environ['FAUCET_CONFIG'], 'w').write(untagged_config)       
        self.topo = SingleSwitchTopo(n=4)
        self.net = Mininet(self.topo, controller=FAUCET)
        self.net.start()

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
